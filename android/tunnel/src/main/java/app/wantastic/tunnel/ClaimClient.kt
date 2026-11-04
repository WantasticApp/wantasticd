package app.wantastic.tunnel

import java.io.File
import java.net.HttpURLConnection
import java.net.URL
import java.net.URLEncoder
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * Asks the server whether this phone's key was approved (claimed), the way the
 * Go agent's auth.FetchClaimConfig does: GET /api/agent/claim-config, signed
 * with HMAC-SHA256 over "timestamp:hashed device id".
 */
class ClaimClient(private val stateDir: File) {
    /** The device ID the Go engine kept (.device-id), or a new random one. */
    private val hashedDeviceId: String by lazy {
        val f = File(stateDir, ".device-id")
        val raw = runCatching { f.readText().trim() }.getOrNull()?.takeIf { it.isNotEmpty() } ?: run {
            val id = ByteArray(16).also { random.nextBytes(it) }.joinToString("") { "%02x".format(it) }
            runCatching { stateDir.mkdirs(); f.writeText(id + "\n") }
            id
        }
        hmacHex(raw.lowercase())
    }

    /** The approval JSON once [publicKey] is claimed; null while it is not. Throws on network errors. */
    fun fetch(server: String, publicKey: String): String? {
        val url = URL(server.trimEnd('/') + PATH + "?public_key=" + URLEncoder.encode(publicKey.trim(), "UTF-8"))
        val c = url.openConnection() as HttpURLConnection
        try {
            c.connectTimeout = 15_000
            c.readTimeout = 20_000
            val ts = (System.currentTimeMillis() / 1000).toString()
            c.setRequestProperty("x-wantastic-ts", ts)
            c.setRequestProperty("x-wantastic-device", hashedDeviceId)
            c.setRequestProperty("x-wantastic-sig", hmacHex("$ts:$hashedDeviceId"))
            val code = c.responseCode
            if (code != 200) throw java.io.IOException("claim check: HTTP $code")
            val body = c.inputStream.bufferedReader().use { it.readText() }
            return body.takeIf { org.json.JSONObject(it).optBoolean("claimed") }
        } finally {
            c.disconnect()
        }
    }

    private fun hmacHex(message: String): String {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(BuildConfig.AGENT_SHARED_SECRET.toByteArray(), "HmacSHA256"))
        return mac.doFinal(message.toByteArray()).joinToString("") { "%02x".format(it) }
    }

    companion object {
        private const val PATH = "/api/agent/claim-config"
    }
}
