package app.wantastic.tunnel

import com.google.crypto.tink.aead.internal.InsecureNonceChaCha20Poly1305
import com.google.crypto.tink.aead.internal.InsecureNonceXChaCha20Poly1305
import com.google.crypto.tink.subtle.X25519
import java.security.GeneralSecurityException
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * BLAKE2s (RFC 7693): WireGuard's hash, MAC and (through HMAC) KDF.
 * [outLen] 1..32 bytes; [key] up to 32 bytes makes it a keyed MAC.
 */
class Blake2s(private val outLen: Int = 32, key: ByteArray? = null) {
    private val h = IV.copyOf()
    private val buf = ByteArray(64)
    private var bufLen = 0
    private var t = 0L
    private val m = IntArray(16)
    private val v = IntArray(16)

    init {
        require(outLen in 1..32) { "BLAKE2s output must be 1..32 bytes" }
        val keyLen = key?.size ?: 0
        require(keyLen <= 32) { "BLAKE2s key must be at most 32 bytes" }
        h[0] = h[0] xor (0x01010000 or (keyLen shl 8) or outLen)
        if (key != null && keyLen > 0) {
            key.copyInto(buf)
            bufLen = 64 // the padded key block, compressed before any data
        }
    }

    fun update(data: ByteArray, off: Int = 0, len: Int = data.size - off): Blake2s {
        var o = off
        var n = len
        while (n > 0) {
            if (bufLen == 64) {
                t += 64
                compress(false)
                bufLen = 0
            }
            val take = minOf(64 - bufLen, n)
            System.arraycopy(data, o, buf, bufLen, take)
            bufLen += take
            o += take
            n -= take
        }
        return this
    }

    fun digest(): ByteArray {
        t += bufLen
        buf.fill(0, bufLen, 64)
        compress(true)
        val out = ByteArray(outLen)
        for (i in 0 until outLen) out[i] = (h[i ushr 2] ushr (8 * (i and 3))).toByte()
        return out
    }

    private fun compress(last: Boolean) {
        for (i in 0 until 16) {
            m[i] = (buf[4 * i].toInt() and 0xff) or ((buf[4 * i + 1].toInt() and 0xff) shl 8) or
                ((buf[4 * i + 2].toInt() and 0xff) shl 16) or ((buf[4 * i + 3].toInt() and 0xff) shl 24)
        }
        for (i in 0 until 8) {
            v[i] = h[i]
            v[i + 8] = IV[i]
        }
        v[12] = v[12] xor t.toInt()
        v[13] = v[13] xor (t ushr 32).toInt()
        if (last) v[14] = v[14].inv()
        for (r in 0 until 10) {
            val s = SIGMA[r]
            g(0, 4, 8, 12, m[s[0]], m[s[1]]); g(1, 5, 9, 13, m[s[2]], m[s[3]])
            g(2, 6, 10, 14, m[s[4]], m[s[5]]); g(3, 7, 11, 15, m[s[6]], m[s[7]])
            g(0, 5, 10, 15, m[s[8]], m[s[9]]); g(1, 6, 11, 12, m[s[10]], m[s[11]])
            g(2, 7, 8, 13, m[s[12]], m[s[13]]); g(3, 4, 9, 14, m[s[14]], m[s[15]])
        }
        for (i in 0 until 8) h[i] = h[i] xor v[i] xor v[i + 8]
    }

    private fun g(a: Int, b: Int, c: Int, d: Int, x: Int, y: Int) {
        v[a] += v[b] + x; v[d] = Integer.rotateRight(v[d] xor v[a], 16)
        v[c] += v[d]; v[b] = Integer.rotateRight(v[b] xor v[c], 12)
        v[a] += v[b] + y; v[d] = Integer.rotateRight(v[d] xor v[a], 8)
        v[c] += v[d]; v[b] = Integer.rotateRight(v[b] xor v[c], 7)
    }

    companion object {
        private val IV = intArrayOf(
            0x6A09E667, 0xBB67AE85.toInt(), 0x3C6EF372, 0xA54FF53A.toInt(),
            0x510E527F, 0x9B05688C.toInt(), 0x1F83D9AB, 0x5BE0CD19,
        )
        private val SIGMA = arrayOf(
            intArrayOf(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15),
            intArrayOf(14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3),
            intArrayOf(11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4),
            intArrayOf(7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8),
            intArrayOf(9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13),
            intArrayOf(2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9),
            intArrayOf(12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11),
            intArrayOf(13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10),
            intArrayOf(6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5),
            intArrayOf(10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0),
        )
    }
}

/** WireGuard's primitives (the whitepaper's HASH, MAC, HMAC, KDF, AEAD, DH). */
object WgCrypto {
    fun hash(vararg parts: ByteArray): ByteArray = Blake2s().apply { parts.forEach { update(it) } }.digest()

    /** MAC(key, input): keyed BLAKE2s with a 16-byte output. */
    fun mac(key: ByteArray, input: ByteArray, len: Int = input.size): ByteArray = Blake2s(16, key).update(input, 0, len).digest()

    fun hmac(key: ByteArray, vararg parts: ByteArray): ByteArray {
        val k = ByteArray(64)
        (if (key.size > 64) hash(key) else key).copyInto(k)
        val ipad = ByteArray(64) { (k[it].toInt() xor 0x36).toByte() }
        val opad = ByteArray(64) { (k[it].toInt() xor 0x5c).toByte() }
        val inner = Blake2s().update(ipad).apply { parts.forEach { update(it) } }.digest()
        return Blake2s().update(opad).update(inner).digest()
    }

    /** KDFn(key, input): n 32-byte outputs (n = 1..3). */
    fun kdf(n: Int, key: ByteArray, input: ByteArray): Array<ByteArray> {
        val prk = hmac(key, input)
        val out = ArrayList<ByteArray>(n)
        var prev = ByteArray(0)
        for (i in 1..n) {
            prev = hmac(prk, prev, byteArrayOf(i.toByte()))
            out += prev
        }
        return out.toTypedArray()
    }

    fun generatePrivateKey(): ByteArray = X25519.generatePrivateKey()

    fun publicKey(privateKey: ByteArray): ByteArray = X25519.publicFromPrivate(privateKey)

    /** DH; throws on the all-zero result of a low-order point. */
    fun dh(privateKey: ByteArray, publicKey: ByteArray): ByteArray {
        val s = X25519.computeSharedSecret(privateKey, publicKey)
        if (s.all { it == 0.toByte() }) throw GeneralSecurityException("invalid public key")
        return s
    }

    private fun nonce(counter: Long): ByteArray {
        val n = ByteArray(12)
        for (i in 0 until 8) n[4 + i] = (counter ushr (8 * i)).toByte()
        return n
    }

    // The platform's ChaCha20-Poly1305 (Conscrypt, Android 9+ and any JDK 11+)
    // is native and fast; older phones fall back to Tink's.
    private val platform: Boolean = runCatching { Cipher.getInstance("ChaCha20-Poly1305") }.isSuccess
    // One cipher per direction and thread: a cipher refuses to be re-keyed with
    // the key and nonce it last encrypted with, even to decrypt.
    private val sealer = ThreadLocal.withInitial { if (platform) Cipher.getInstance("ChaCha20-Poly1305") else null }
    private val opener = ThreadLocal.withInitial { if (platform) Cipher.getInstance("ChaCha20-Poly1305") else null }

    /** AEAD(key, counter, plain, aad) as WireGuard frames it (96-bit nonce: 4 zero bytes, LE counter). */
    fun seal(key: ByteArray, counter: Long, plain: ByteArray, aad: ByteArray, plainLen: Int = plain.size): ByteArray {
        val c = sealer.get()
        if (c != null) {
            c.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "ChaCha20"), IvParameterSpec(nonce(counter)))
            if (aad.isNotEmpty()) c.updateAAD(aad)
            return c.doFinal(plain, 0, plainLen)
        }
        return InsecureNonceChaCha20Poly1305(key).encrypt(nonce(counter), plain.copyOf(plainLen), aad)
    }

    /** Opens what [seal] made; null when it does not authenticate. */
    fun open(key: ByteArray, counter: Long, sealed: ByteArray, aad: ByteArray, off: Int = 0, len: Int = sealed.size - off): ByteArray? = try {
        val c = opener.get()
        if (c != null) {
            c.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "ChaCha20"), IvParameterSpec(nonce(counter)))
            if (aad.isNotEmpty()) c.updateAAD(aad)
            c.doFinal(sealed, off, len)
        } else {
            InsecureNonceChaCha20Poly1305(key).decrypt(nonce(counter), sealed.copyOfRange(off, off + len), aad)
        }
    } catch (e: GeneralSecurityException) {
        null
    }

    /** XAEAD for cookie replies (24-byte nonce). */
    fun xopen(key: ByteArray, nonce: ByteArray, sealed: ByteArray, aad: ByteArray): ByteArray? = try {
        InsecureNonceXChaCha20Poly1305(key).decrypt(nonce, sealed, aad)
    } catch (e: GeneralSecurityException) {
        null
    }
}
