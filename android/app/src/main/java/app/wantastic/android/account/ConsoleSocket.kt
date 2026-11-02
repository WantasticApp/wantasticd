package app.wantastic.android.account

import android.util.Base64
import android.webkit.CookieManager
import com.google.crypto.tink.subtle.Hkdf
import com.google.crypto.tink.subtle.X25519
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withTimeout
import okhttp3.Cookie
import okhttp3.CookieJar
import okhttp3.HttpUrl
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import okhttp3.WebSocket
import okhttp3.WebSocketListener
import org.json.JSONObject
import java.io.IOException
import java.nio.ByteBuffer
import java.security.SecureRandom
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.TimeUnit
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * The console's own channel, spoken natively: wss://console.wantastic.app/ws.
 *
 * The server opens with an X25519 key exchange; both sides derive an
 * AES-256-GCM key (HKDF-SHA256, salt "wantastic-ws-session-v1", info
 * "ws-session:<id>") and every request and reply is sealed as
 * base64(counter u64 BE || nonce(counter || 4 random) || ciphertext+tag),
 * with counters that must only grow. Same as console/src/shared/lib/crypto.ts
 * and internal/crypto/session_keys.go.
 *
 * Cookies are Android's WebView cookies, so this channel and the console
 * mini app are always the same signed-in account.
 */
class ConsoleSocket(private val origin: String) {

    class RpcException(message: String) : IOException(message)

    private val http = OkHttpClient.Builder()
        .cookieJar(WebViewCookies)
        .pingInterval(15, TimeUnit.SECONDS)
        .readTimeout(70, TimeUnit.SECONDS)
        .build()

    private val lock = Mutex()
    private var session: Session? = null

    private class Session(val ready: CompletableDeferred<Unit>) {
        lateinit var ws: WebSocket
        var key: SecretKeySpec? = null
        var sendCounter = 0L
        var recvCounter = 0L
        val pending = ConcurrentHashMap<String, CompletableDeferred<JSONObject>>()
        @Volatile var closed = false
    }

    /** Calls Service.Method; returns the response object or throws [RpcException]. */
    suspend fun call(service: String, method: String, request: JSONObject = JSONObject(), timeoutMs: Long = 30_000): JSONObject {
        val s = open()
        val id = UUID.randomUUID().toString()
        val reply = CompletableDeferred<JSONObject>()
        s.pending[id] = reply
        try {
            val envelope = JSONObject().put("id", id).put("service", service).put("method", method).put("request", request)
            synchronized(s) {
                val sealed = seal(s, envelope.toString())
                if (!s.ws.send(JSONObject().put("type", "encrypted").put("ciphertext", sealed).toString())) throw IOException("Connection lost")
            }
            return withTimeout(timeoutMs) { reply.await() }
        } catch (e: TimeoutCancellationException) {
            throw IOException("Wantastic did not answer in time")
        } finally {
            s.pending.remove(id)
        }
    }

    /** Drops the connection; the next call reconnects with the current cookies (after a sign-in or switch). */
    fun reset() {
        session?.let { it.closed = true; it.ws.close(1000, null) }
        session = null
    }

    private suspend fun open(): Session = lock.withLock {
        session?.takeIf { !it.closed }?.let { s -> s.ready.await(); return s }
        val ready = CompletableDeferred<Unit>()
        val request = Request.Builder()
            .url(origin.replaceFirst("https://", "wss://") + "/ws")
            .header("Origin", origin)
            .build()
        // The session exists before the socket, so the server's first frame always finds it.
        val s = Session(ready)
        synchronized(s) {
            s.ws = http.newWebSocket(request, object : WebSocketListener() {
                override fun onMessage(webSocket: WebSocket, text: String) = synchronized(s) { handle(s, text) }
                override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) = fail(s, t.message ?: "Connection failed")
                override fun onClosed(webSocket: WebSocket, code: Int, reason: String) = fail(s, "Connection closed")
            })
        }
        session = s
        try {
            withTimeout(20_000) { ready.await() }
        } catch (e: Exception) {
            reset()
            throw IOException("Could not reach Wantastic", e)
        }
        s
    }

    private fun handle(s: Session, text: String) {
        var msg = runCatching { JSONObject(text) }.getOrNull() ?: return
        when (msg.optString("type")) {
            "key_exchange" -> {
                val serverKey = msg.optString("server_public_key")
                val sessionId = msg.optString("session_id")
                if (serverKey.isEmpty() || sessionId.isEmpty()) return
                val private = X25519.generatePrivateKey()
                val shared = X25519.computeSharedSecret(private, b64(serverKey))
                val key = Hkdf.computeHkdf("HMACSHA256", shared, SALT, ("ws-session:$sessionId").toByteArray(), 32)
                synchronized(s) { s.key = SecretKeySpec(key, "AES") }
                s.ws.send(JSONObject().put("type", "key_exchange").put("client_public_key", b64(X25519.publicFromPrivate(private))).toString())
                s.ready.complete(Unit)
                return
            }
            "key_exchange_complete", "pong" -> return
            "encrypted" -> {
                val plain = runCatching { unseal(s, msg.getString("ciphertext")) }.getOrNull() ?: return
                msg = runCatching { JSONObject(plain) }.getOrNull() ?: return
            }
        }
        val id = msg.optString("id")
        val reply = s.pending[id] ?: return
        when (msg.optString("type")) {
            "response" -> reply.complete(msg.optJSONObject("response") ?: JSONObject())
            "error" -> reply.completeExceptionally(RpcException(msg.optString("error").ifBlank { "Request failed" }))
        }
    }

    private fun fail(s: Session, why: String) {
        s.closed = true
        s.ready.completeExceptionally(IOException(why))
        s.pending.values.forEach { it.completeExceptionally(IOException(why)) }
        if (session === s) session = null
    }

    private fun seal(s: Session, plaintext: String): String {
        val key = s.key ?: throw IOException("Secure channel not ready")
        s.sendCounter++
        // Nonce: the counter (8 bytes) then 4 random bytes.
        val nonce = ByteArray(12)
        ByteBuffer.wrap(nonce).putLong(s.sendCounter)
        ByteArray(4).also(random::nextBytes).copyInto(nonce, 8)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(128, nonce)) }
        val sealed = cipher.doFinal(plaintext.toByteArray())
        val out = ByteBuffer.allocate(8 + 12 + sealed.size).putLong(s.sendCounter).put(nonce).put(sealed).array()
        return b64(out)
    }

    private fun unseal(s: Session, ciphertext: String): String {
        val key = s.key ?: throw IOException("Secure channel not ready")
        val data = b64(ciphertext)
        if (data.size < 36) throw IOException("short frame")
        val counter = ByteBuffer.wrap(data, 0, 8).long
        synchronized(s) {
            if (counter <= s.recvCounter && s.recvCounter > 0) throw IOException("replayed frame")
            val cipher = Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, data, 8, 12)) }
            val plain = cipher.doFinal(data, 20, data.size - 20)
            s.recvCounter = counter
            return String(plain)
        }
    }

    companion object {
        private val SALT = "wantastic-ws-session-v1".toByteArray()
        private val random = SecureRandom()
        private fun b64(s: String): ByteArray = Base64.decode(s, Base64.DEFAULT)
        private fun b64(b: ByteArray): String = Base64.encodeToString(b, Base64.NO_WRAP)
    }
}

/**
 * OkHttp reads and writes Android's WebView cookie store, so a sign-in here
 * is a sign-in in the console mini app and the other way round.
 */
object WebViewCookies : CookieJar {
    override fun saveFromResponse(url: HttpUrl, cookies: List<Cookie>) {
        val manager = CookieManager.getInstance()
        cookies.forEach { manager.setCookie(url.toString(), it.toString()) }
        manager.flush()
    }

    override fun loadForRequest(url: HttpUrl): List<Cookie> {
        val header = CookieManager.getInstance().getCookie(url.toString()) ?: return emptyList()
        return header.split(";").mapNotNull { Cookie.parse(url, it.trim()) }
    }
}
