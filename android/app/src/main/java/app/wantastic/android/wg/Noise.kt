package app.wantastic.android.wg

import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.SecureRandom

/** WireGuard message types: 1-4 standard; 6-8 Wantastic's (P2P punch, TUN control, WUSP). */
object MessageType {
    const val INITIATION = 1
    const val RESPONSE = 2
    const val COOKIE_REPLY = 3
    const val TRANSPORT = 4
    const val PUNCH = 6
    const val TUN_CONTROL = 7
    const val WUSP = 8

    const val INITIATION_SIZE = 148
    const val RESPONSE_SIZE = 92
    const val COOKIE_REPLY_SIZE = 64
    const val TRANSPORT_HEADER = 16
    const val TAG = 16
}

/** Protocol timing and limits from the WireGuard whitepaper (section 6). */
object WgTimers {
    const val REKEY_AFTER_MESSAGES = 1L shl 60
    const val REJECT_AFTER_MESSAGES = -1L - (1L shl 13) // 2^64 - 2^13 - 1, as unsigned
    const val REKEY_AFTER_TIME_MS = 120_000L
    const val REJECT_AFTER_TIME_MS = 180_000L
    const val REKEY_ATTEMPT_TIME_MS = 90_000L
    const val REKEY_TIMEOUT_MS = 5_000L
    const val KEEPALIVE_TIMEOUT_MS = 10_000L
    const val COOKIE_LIFETIME_MS = 120_000L
}

private val CONSTRUCTION = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s".toByteArray()
private val IDENTIFIER = "WireGuard v1 zx2c4 Jason@zx2c4.com".toByteArray()
private val LABEL_MAC1 = "mac1----".toByteArray()
private val LABEL_COOKIE = "cookie--".toByteArray()
private val INITIAL_CHAIN_KEY = WgCrypto.hash(CONSTRUCTION)
private val INITIAL_HASH = WgCrypto.hash(INITIAL_CHAIN_KEY, IDENTIFIER)
private val ZERO32 = ByteArray(32)
private val EMPTY = ByteArray(0)

internal val random = SecureRandom()

/** A session's transport keys and counters, one direction each. */
class Keypair(
    val sendKey: ByteArray,
    val receiveKey: ByteArray,
    val localIndex: Int,
    val remoteIndex: Int,
    val isInitiator: Boolean,
    val created: Long = System.currentTimeMillis(),
) {
    private var sendCounter = 0L
    val replay = ReplayFilter()

    /** The next send counter, or -1 once the key must not be used any more. */
    @Synchronized
    fun nextCounter(): Long {
        val c = sendCounter
        if (java.lang.Long.compareUnsigned(c, WgTimers.REJECT_AFTER_MESSAGES) >= 0) return -1
        sendCounter = c + 1
        return c
    }

    @get:Synchronized
    val sent: Long get() = sendCounter

    fun expired(now: Long) = now - created >= WgTimers.REJECT_AFTER_TIME_MS
}

/**
 * RFC 6479 sliding window (as wireguard-go's replay.go): accepts each counter
 * once, within about 2000 of the newest. Call only after the packet authenticated.
 */
class ReplayFilter {
    private val ring = LongArray(RING_BLOCKS)
    private var last = 0L

    @Synchronized
    fun check(counter: Long): Boolean {
        if (java.lang.Long.compareUnsigned(counter, WgTimers.REJECT_AFTER_MESSAGES) >= 0) return false
        var indexBlock = counter ushr 6
        if (counter > last) {
            val current = last ushr 6
            var diff = minOf(indexBlock - current, RING_BLOCKS.toLong())
            var i = current + 1
            while (diff > 0) {
                ring[(i and (RING_BLOCKS - 1).toLong()).toInt()] = 0
                i++
                diff--
            }
            last = counter
        } else if (last - counter > WINDOW_SIZE) {
            return false
        }
        indexBlock = indexBlock and (RING_BLOCKS - 1).toLong()
        val bit = 1L shl (counter and 63).toInt()
        val old = ring[indexBlock.toInt()]
        ring[indexBlock.toInt()] = old or bit
        return old and bit == 0L
    }

    companion object {
        private const val RING_BLOCKS = 32 // 2048 bits
        private const val WINDOW_SIZE = (RING_BLOCKS - 1) * 64L
    }
}

/** TAI64N: big-endian seconds since 1970 plus 2^62 + 10, then nanoseconds. */
private const val WHITENER = 0x1000000L

internal fun tai64n(nowMs: Long = System.currentTimeMillis(), nanos: Long = System.nanoTime()): ByteArray {
    val b = ByteBuffer.allocate(12).order(ByteOrder.BIG_ENDIAN)
    b.putLong(0x400000000000000aL + nowMs / 1000)
    // Whitened like wireguard-go (multiples of 2^24 ns): finer precision is
    // not needed and would leak more about the clock.
    val ns = (nowMs % 1000) * 1_000_000L + nanos % 1_000_000L
    b.putInt((ns / WHITENER * WHITENER).toInt())
    return b.array()
}

/**
 * One side's handshake with one peer (Noise IKpsk2). Initiator: [createInitiation],
 * then [consumeResponse]. Responder: [consumeInitiation], then [createResponse].
 */
class Handshake(
    private val staticPrivate: ByteArray,
    val staticPublic: ByteArray,
    val remoteStatic: ByteArray,
    private val presharedKey: ByteArray = ZERO32,
) {
    private var chainKey = ByteArray(0)
    private var hash = ByteArray(0)
    private var ephemeralPrivate = ByteArray(0)
    private var remoteEphemeral = ByteArray(0)
    var localIndex = 0
        private set
    private var remoteIndex = 0
    private val precomputedStatic = WgCrypto.dh(staticPrivate, remoteStatic)
    private var lastTimestamp = ByteArray(12)

    // Cookies: the remote's mac1 key, our last sent mac1 (cookie reply AAD) and
    // a cookie from it, when it is under load.
    private val mac1KeyRemote = WgCrypto.hash(LABEL_MAC1, remoteStatic)
    private val mac1KeyLocal = WgCrypto.hash(LABEL_MAC1, staticPublic)
    private val cookieKeyRemote = WgCrypto.hash(LABEL_COOKIE, remoteStatic)
    private var lastMac1 = ByteArray(16)
    private var cookie: ByteArray? = null
    private var cookieTime = 0L

    private fun mixHash(data: ByteArray) {
        hash = WgCrypto.hash(hash, data)
    }

    private fun mixKey(input: ByteArray) {
        chainKey = WgCrypto.kdf(1, chainKey, input)[0]
    }

    @Synchronized
    fun createInitiation(index: Int): ByteArray {
        localIndex = index
        chainKey = INITIAL_CHAIN_KEY
        hash = WgCrypto.hash(INITIAL_HASH, remoteStatic)
        ephemeralPrivate = WgCrypto.generatePrivateKey()
        val ephemeral = WgCrypto.publicKey(ephemeralPrivate)
        mixKey(ephemeral)
        mixHash(ephemeral)
        var (ck, k) = WgCrypto.kdf(2, chainKey, WgCrypto.dh(ephemeralPrivate, remoteStatic))
        chainKey = ck
        val encStatic = WgCrypto.seal(k, 0, staticPublic, hash)
        mixHash(encStatic)
        WgCrypto.kdf(2, chainKey, precomputedStatic).let { chainKey = it[0]; k = it[1] }
        val encTime = WgCrypto.seal(k, 0, tai64n(), hash)
        mixHash(encTime)

        val msg = ByteBuffer.allocate(MessageType.INITIATION_SIZE).order(ByteOrder.LITTLE_ENDIAN)
        msg.putInt(MessageType.INITIATION).putInt(index).put(ephemeral).put(encStatic).put(encTime)
        return addMacs(msg.array())
    }

    /** Consumes the responder's reply to our initiation; the session keys on success. */
    @Synchronized
    fun consumeResponse(msg: ByteArray): Keypair? {
        if (msg.size != MessageType.RESPONSE_SIZE || !macValid(msg, mac1KeyLocal)) return null
        val b = ByteBuffer.wrap(msg).order(ByteOrder.LITTLE_ENDIAN)
        b.getInt()
        val sender = b.getInt()
        val receiver = b.getInt()
        if (receiver != localIndex || ephemeralPrivate.isEmpty()) return null
        val ephemeral = ByteArray(32).also { b.get(it) }
        val empty = ByteArray(16).also { b.get(it) }

        var ck = chainKey
        var h = hash
        ck = WgCrypto.kdf(1, ck, ephemeral)[0]
        h = WgCrypto.hash(h, ephemeral)
        ck = WgCrypto.kdf(1, ck, WgCrypto.dh(ephemeralPrivate, ephemeral))[0]
        ck = WgCrypto.kdf(1, ck, WgCrypto.dh(staticPrivate, ephemeral))[0]
        val (ck2, tau, k) = WgCrypto.kdf(3, ck, presharedKey)
        h = WgCrypto.hash(h, tau)
        WgCrypto.open(k, 0, empty, h) ?: return null
        h = WgCrypto.hash(h, empty)
        val (send, recv) = WgCrypto.kdf(2, ck2, EMPTY)
        ephemeralPrivate = ByteArray(0) // one response per initiation
        chainKey = ByteArray(0)
        hash = h
        return Keypair(send, recv, localIndex, sender, isInitiator = true)
    }

    /**
     * The responder's view: checks an initiation is from [remoteStatic] and newer
     * than the last one. [createResponse] answers it.
     */
    @Synchronized
    fun consumeInitiation(msg: ByteArray): Boolean {
        if (msg.size != MessageType.INITIATION_SIZE || !macValid(msg, mac1KeyLocal)) return false
        val b = ByteBuffer.wrap(msg).order(ByteOrder.LITTLE_ENDIAN)
        b.getInt()
        val sender = b.getInt()
        val ephemeral = ByteArray(32).also { b.get(it) }
        val encStatic = ByteArray(48).also { b.get(it) }
        val encTime = ByteArray(28).also { b.get(it) }

        var ck = INITIAL_CHAIN_KEY
        var h = WgCrypto.hash(INITIAL_HASH, staticPublic)
        ck = WgCrypto.kdf(1, ck, ephemeral)[0]
        h = WgCrypto.hash(h, ephemeral)
        var kk = WgCrypto.kdf(2, ck, WgCrypto.dh(staticPrivate, ephemeral))
        ck = kk[0]
        val peerStatic = WgCrypto.open(kk[1], 0, encStatic, h) ?: return false
        if (!peerStatic.contentEquals(remoteStatic)) return false
        h = WgCrypto.hash(h, encStatic)
        kk = WgCrypto.kdf(2, ck, precomputedStatic)
        ck = kk[0]
        val timestamp = WgCrypto.open(kk[1], 0, encTime, h) ?: return false
        if (compareUnsigned(timestamp, lastTimestamp) <= 0) return false // replayed initiation
        h = WgCrypto.hash(h, encTime)
        lastTimestamp = timestamp
        chainKey = ck
        hash = h
        remoteEphemeral = ephemeral
        remoteIndex = sender
        return true
    }

    @Synchronized
    fun createResponse(index: Int): Pair<ByteArray, Keypair>? {
        if (remoteEphemeral.isEmpty()) return null
        localIndex = index
        val ePriv = WgCrypto.generatePrivateKey()
        val ephemeral = WgCrypto.publicKey(ePriv)
        var ck = WgCrypto.kdf(1, chainKey, ephemeral)[0]
        var h = WgCrypto.hash(hash, ephemeral)
        ck = WgCrypto.kdf(1, ck, WgCrypto.dh(ePriv, remoteEphemeral))[0]
        ck = WgCrypto.kdf(1, ck, WgCrypto.dh(ePriv, remoteStatic))[0]
        val (ck2, tau, k) = WgCrypto.kdf(3, ck, presharedKey)
        h = WgCrypto.hash(h, tau)
        val empty = WgCrypto.seal(k, 0, EMPTY, h)
        h = WgCrypto.hash(h, empty)
        val msg = ByteBuffer.allocate(MessageType.RESPONSE_SIZE).order(ByteOrder.LITTLE_ENDIAN)
        msg.putInt(MessageType.RESPONSE).putInt(index).putInt(remoteIndex).put(ephemeral).put(empty)
        val (recv, send) = WgCrypto.kdf(2, ck2, EMPTY)
        remoteEphemeral = ByteArray(0)
        chainKey = ByteArray(0)
        hash = h
        return addMacs(msg.array()) to Keypair(send, recv, index, remoteIndex, isInitiator = false)
    }

    /** A cookie reply to our last message: remember the cookie for the next mac2. */
    @Synchronized
    fun consumeCookieReply(msg: ByteArray): Boolean {
        if (msg.size != MessageType.COOKIE_REPLY_SIZE) return false
        val nonce = msg.copyOfRange(8, 32)
        val sealed = msg.copyOfRange(32, 64)
        val c = WgCrypto.xopen(cookieKeyRemote, nonce, sealed, lastMac1) ?: return false
        cookie = c
        cookieTime = System.currentTimeMillis()
        return true
    }

    private fun addMacs(msg: ByteArray): ByteArray {
        val n = msg.size
        val mac1 = WgCrypto.mac(mac1KeyRemote, msg, n - 32)
        mac1.copyInto(msg, n - 32)
        lastMac1 = mac1
        val c = cookie
        if (c != null && System.currentTimeMillis() - cookieTime < WgTimers.COOKIE_LIFETIME_MS) {
            WgCrypto.mac(c, msg, n - 16).copyInto(msg, n - 16)
        }
        return msg
    }

    private fun macValid(msg: ByteArray, key: ByteArray): Boolean {
        val n = msg.size
        val want = WgCrypto.mac(key, msg, n - 32)
        var diff = 0
        for (i in 0 until 16) diff = diff or (want[i].toInt() xor msg[n - 32 + i].toInt())
        return diff == 0
    }

    private fun compareUnsigned(a: ByteArray, b: ByteArray): Int {
        for (i in a.indices) {
            val d = (a[i].toInt() and 0xff) - (b[i].toInt() and 0xff)
            if (d != 0) return d
        }
        return 0
    }
}
