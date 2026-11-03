package app.wantastic.tunnel

import java.io.IOException
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicLong

/** The tunnel interface: one IP packet per read and write. */
interface TunIo {
    /** Blocks for the next packet the phone sends into the tunnel; -1 when closed. */
    fun read(buf: ByteArray): Int
    fun write(buf: ByteArray, len: Int)
    fun close()
}

/**
 * How the engine's UDP socket reaches the internet outside the tunnel: on
 * Android, VpnService.protect plus binding to the active network (protect
 * alone leaves the socket unbound, which fails on some carriers).
 */
fun interface SocketSetup {
    fun prepare(socket: DatagramSocket)
}

/** Resolves the server's host name outside the tunnel (on Android, on the underlying network). */
fun interface Resolver {
    fun resolve(host: String): List<InetAddress>
}

/** What the screens show about the tunnel. */
data class TunnelStats(
    val rxBytes: Long,
    val txBytes: Long,
    /** Last completed handshake with the server, ms since 1970; 0 = never. */
    val lastHandshakeMs: Long,
    val endpoint: String?,
)

/**
 * A WireGuard device with one peer, the server: the UDP socket, the tunnel
 * loop and the protocol timers. Wantastic's message types 6-8 (P2P, TUN
 * control, WUSP) are received and ignored until the engine handles them.
 */
class WireGuardDevice(
    private val config: TunnelConfig,
    private val tun: TunIo,
    private val socketSetup: SocketSetup = SocketSetup {},
    private val resolver: Resolver = Resolver { InetAddress.getAllByName(it).toList() },
    private val log: (String) -> Unit = {},
) {
    private val socket = DatagramSocket(null as java.net.SocketAddress?)
    private val indices = ConcurrentHashMap<Int, Peer>()
    private val peer = Peer(config.server)
    @Volatile private var running = false
    private val threads = ArrayList<Thread>()
    private val rx = AtomicLong()
    private val tx = AtomicLong()

    val stats: TunnelStats
        get() = TunnelStats(rx.get(), tx.get(), peer.lastHandshakeMs, peer.endpoint?.let { "${it.address.hostAddress}:${it.port}" })

    /** The local UDP port (for tests and P2P). */
    val localPort: Int get() = socket.localPort

    fun start() {
        socket.reuseAddress = true
        socket.bind(InetSocketAddress(0))
        socketSetup.prepare(socket)
        running = true
        threads += Thread(::udpLoop, "wg-udp")
        threads += Thread(::tunLoop, "wg-tun")
        threads += Thread(::timerLoop, "wg-timers")
        threads.forEach { it.isDaemon = true; it.start() }
        log("WireGuard device up, local port ${socket.localPort}")
    }

    fun stop() {
        running = false
        socket.close()
        tun.close()
        threads.forEach { it.interrupt() }
        threads.clear()
    }

    private fun send(data: ByteArray, len: Int = data.size) {
        val ep = peer.endpoint ?: return
        try {
            socket.send(DatagramPacket(data, len, ep))
            tx.addAndGet(len.toLong())
        } catch (e: IOException) {
            if (running) log("send to $ep: ${e.message}")
        }
    }

    private fun udpLoop() {
        val buf = ByteArray(65535)
        val pkt = DatagramPacket(buf, buf.size)
        while (running) {
            try {
                pkt.setLength(buf.size)
                socket.receive(pkt)
            } catch (e: IOException) {
                if (running) log("receive: ${e.message}")
                continue
            }
            val n = pkt.length
            if (n < 4) continue
            rx.addAndGet(n.toLong())
            val data = buf.copyOf(n)
            try {
                handleDatagram(data, pkt.socketAddress as InetSocketAddress)
            } catch (e: Exception) {
                log("bad datagram: ${e.message}")
            }
        }
    }

    private fun handleDatagram(data: ByteArray, from: InetSocketAddress) {
        when (data[0].toInt() and 0xff) {
            MessageType.TRANSPORT -> {
                if (data.size < MessageType.TRANSPORT_HEADER + MessageType.TAG) return
                val b = ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN)
                val receiver = b.getInt(4)
                val counter = b.getLong(8)
                val p = indices[receiver] ?: return
                val plain = p.decrypt(receiver, counter, data) ?: return
                p.roam(from)
                if (plain.isEmpty()) return // keepalive
                if (!p.allowsSource(plain)) return
                tun.write(plain, plain.size)
            }
            MessageType.RESPONSE -> {
                val receiver = ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN).getInt(8)
                val p = indices[receiver] ?: return
                if (p.consumeResponse(data)) {
                    p.roam(from)
                    log("handshake with the server complete")
                }
            }
            MessageType.INITIATION -> {
                // The server starts a handshake (e.g. it has traffic for us).
                if (peer.consumeInitiation(data)) {
                    peer.roam(from)
                    peer.respond()
                }
            }
            MessageType.COOKIE_REPLY -> {
                val receiver = ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN).getInt(4)
                indices[receiver]?.consumeCookieReply(data)
            }
            else -> Unit // 6-8: P2P, TUN control, WUSP (later phases)
        }
    }

    private fun tunLoop() {
        val buf = ByteArray(65535)
        while (running) {
            val n = try { tun.read(buf) } catch (e: IOException) { if (running) log("tun read: ${e.message}"); -1 }
            if (n < 0) { if (running) Thread.sleep(50); continue }
            if (n == 0) continue
            peer.sendPacket(buf.copyOf(n))
        }
    }

    private fun timerLoop() {
        resolveEndpoint()
        while (running) {
            try {
                Thread.sleep(TICK_MS)
            } catch (e: InterruptedException) {
                return
            }
            peer.tick(System.currentTimeMillis())
        }
    }

    private fun resolveEndpoint() {
        val host = config.server.endpointHost
        val addrs = runCatching { resolver.resolve(host) }.onFailure { log("resolve $host: ${it.message}") }.getOrDefault(emptyList())
        val addr = addrs.firstOrNull { it is java.net.Inet4Address } ?: addrs.firstOrNull()
        if (addr != null) {
            peer.endpoint = InetSocketAddress(addr, config.server.endpointPort)
            log("server endpoint ${addr.hostAddress}:${config.server.endpointPort}")
        }
    }

    /** One remote: handshakes, keypairs, staged packets and timers. */
    private inner class Peer(val cfg: PeerConfig) {
        private val handshake = Handshake(config.privateKey, config.publicKey, cfg.publicKey)
        @Volatile var endpoint: InetSocketAddress? = null
        @Volatile var lastHandshakeMs = 0L

        private var current: Keypair? = null
        private var previous: Keypair? = null
        private var next: Keypair? = null // responder side, until the initiator uses it
        private val staged = ArrayDeque<ByteArray>()

        private var handshakeStarted = 0L // 0 = none in flight
        private var pendingIndex = 0 // our index in the initiation in flight
        private var lastInitiation = 0L
        private var lastSent = 0L
        private var lastReceived = 0L
        private var lastDataSent = 0L
        private var lastDataReceived = 0L
        private var resolveAgainAt = 0L

        fun allowsSource(packet: ByteArray): Boolean {
            val src = when (packet[0].toInt() ushr 4) {
                4 -> if (packet.size >= 20) packet.copyOfRange(12, 16) else return false
                6 -> if (packet.size >= 40) packet.copyOfRange(8, 24) else return false
                else -> return false
            }
            return cfg.allowedIps.any { it.contains(src) }
        }

        fun roam(from: InetSocketAddress) {
            if (endpoint != from) endpoint = from
        }

        @Synchronized
        fun sendPacket(packet: ByteArray) {
            val kp = current
            val now = System.currentTimeMillis()
            if (kp == null || kp.expired(now)) {
                if (staged.size >= MAX_STAGED) staged.removeFirst()
                staged.addLast(packet)
                initiate(now, force = false)
                return
            }
            encryptAndSend(kp, packet)
            lastDataSent = now
            if (kp.isInitiator && (now - kp.created >= WgTimers.REKEY_AFTER_TIME_MS || kp.sent >= WgTimers.REKEY_AFTER_MESSAGES)) {
                initiate(now, force = false)
            }
        }

        private fun encryptAndSend(kp: Keypair, packet: ByteArray) {
            val counter = kp.nextCounter()
            if (counter < 0) return
            // Pad to a multiple of 16, never past the MTU.
            val padded = minOf(((packet.size + 15) / 16) * 16, maxOf(packet.size, config.mtu))
            val plain = if (padded == packet.size) packet else packet.copyOf(padded)
            val sealed = WgCrypto.seal(kp.sendKey, counter, plain, ByteArray(0))
            val out = ByteBuffer.allocate(MessageType.TRANSPORT_HEADER + sealed.size).order(ByteOrder.LITTLE_ENDIAN)
            out.putInt(MessageType.TRANSPORT).putInt(kp.remoteIndex).putLong(counter).put(sealed)
            send(out.array())
            lastSent = System.currentTimeMillis()
        }

        private fun sendKeepalive() {
            val kp = current ?: return
            encryptAndSend(kp, ByteArray(0))
        }

        @Synchronized
        fun initiate(now: Long, force: Boolean) {
            if (!force && handshakeStarted != 0L && now - lastInitiation < WgTimers.REKEY_TIMEOUT_MS) return
            if (endpoint == null) return
            if (handshakeStarted == 0L) handshakeStarted = now
            val index = newIndex()
            // A new initiation replaces the one in flight: its answer can no longer match.
            if (pendingIndex != 0) indices.remove(pendingIndex)
            val msg = handshake.createInitiation(index)
            indices[index] = this
            pendingIndex = index
            lastInitiation = now
            send(msg)
            lastSent = now
        }

        @Synchronized
        fun consumeResponse(msg: ByteArray): Boolean {
            val kp = handshake.consumeResponse(msg) ?: return false
            pendingIndex = 0 // now the session's index
            install(kp)
            lastHandshakeMs = System.currentTimeMillis()
            handshakeStarted = 0L
            // Send what waited for the session, or a keepalive to confirm it.
            if (staged.isEmpty()) sendKeepalive() else while (staged.isNotEmpty()) encryptAndSend(kp, staged.removeFirst())
            return true
        }

        @Synchronized
        fun consumeInitiation(msg: ByteArray): Boolean = handshake.consumeInitiation(msg)

        @Synchronized
        fun respond() {
            val index = newIndex()
            val (msg, kp) = handshake.createResponse(index) ?: return
            indices[index] = this
            next?.let { indices.remove(it.localIndex) }
            next = kp
            send(msg)
            lastSent = System.currentTimeMillis()
        }

        private fun install(kp: Keypair) {
            previous?.let { indices.remove(it.localIndex) }
            previous = current
            current = kp
        }

        @Synchronized
        fun decrypt(receiver: Int, counter: Long, data: ByteArray): ByteArray? {
            val kp = listOfNotNull(current, previous, next).firstOrNull { it.localIndex == receiver } ?: return null
            val now = System.currentTimeMillis()
            if (kp.expired(now)) return null
            val plain = WgCrypto.open(kp.receiveKey, counter, data, ByteArray(0), MessageType.TRANSPORT_HEADER, data.size - MessageType.TRANSPORT_HEADER)
                ?: return null
            if (!kp.replay.check(counter)) return null
            if (kp === next) {
                // The initiator used the new session: it is confirmed.
                next = null
                install(kp)
                lastHandshakeMs = now
                handshakeStarted = 0L
                while (staged.isNotEmpty()) encryptAndSend(kp, staged.removeFirst())
            }
            lastReceived = now
            if (plain.isNotEmpty()) lastDataReceived = now
            return trimToIpLength(plain)
        }

        @Synchronized
        fun consumeCookieReply(msg: ByteArray) {
            handshake.consumeCookieReply(msg)
        }

        /** The protocol's timers, every [TICK_MS]. */
        @Synchronized
        fun tick(now: Long) {
            if (endpoint == null) {
                if (now >= resolveAgainAt) {
                    resolveAgainAt = now + 10_000
                    resolveEndpoint()
                }
                return
            }
            val kp = current
            // A handshake with no answer: retry every 5 s, give up after 90 s.
            if (handshakeStarted != 0L && now - lastInitiation >= WgTimers.REKEY_TIMEOUT_MS + jitter()) {
                if (now - handshakeStarted >= WgTimers.REKEY_ATTEMPT_TIME_MS) {
                    handshakeStarted = 0L
                    staged.clear()
                    // Persistent keepalive keeps trying: a fresh attempt.
                    if (cfg.persistentKeepaliveSec > 0) initiate(now, force = true)
                } else {
                    initiate(now, force = true)
                }
            }
            if (kp == null || kp.expired(now)) {
                if (handshakeStarted == 0L && (cfg.persistentKeepaliveSec > 0 || staged.isNotEmpty())) initiate(now, force = false)
                return
            }
            // The initiator renews the session before it expires.
            if (kp.isInitiator && now - kp.created >= WgTimers.REKEY_AFTER_TIME_MS && handshakeStarted == 0L) initiate(now, force = false)
            // Sent data but heard nothing back: the session may be gone.
            if (lastDataSent > lastReceived && now - lastDataSent >= WgTimers.KEEPALIVE_TIMEOUT_MS + WgTimers.REKEY_TIMEOUT_MS && handshakeStarted == 0L) {
                initiate(now, force = false)
            }
            // Received data and sent nothing since: a passive keepalive.
            if (lastDataReceived > lastSent && now - lastDataReceived >= WgTimers.KEEPALIVE_TIMEOUT_MS) sendKeepalive()
            if (cfg.persistentKeepaliveSec > 0 && now - lastSent >= cfg.persistentKeepaliveSec * 1000L) sendKeepalive()
        }

        private fun jitter() = random.nextInt(334).toLong()
    }

    private fun newIndex(): Int {
        while (true) {
            val i = random.nextInt()
            if (i != 0 && !indices.containsKey(i)) return i
        }
    }

    companion object {
        private const val TICK_MS = 250L
        private const val MAX_STAGED = 128

        /** Drops WireGuard's padding: the IP header says the real length. */
        internal fun trimToIpLength(p: ByteArray): ByteArray {
            if (p.isEmpty()) return p
            val len = when (p[0].toInt() ushr 4) {
                4 -> if (p.size >= 4) ((p[2].toInt() and 0xff) shl 8) or (p[3].toInt() and 0xff) else return p
                6 -> if (p.size >= 6) 40 + (((p[4].toInt() and 0xff) shl 8) or (p[5].toInt() and 0xff)) else return p
                else -> return p
            }
            return if (len in 1 until p.size) p.copyOf(len) else p
        }
    }
}
