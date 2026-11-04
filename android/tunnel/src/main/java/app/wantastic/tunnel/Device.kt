package app.wantastic.tunnel

import java.io.IOException
import java.net.DatagramSocket
import java.net.Inet4Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.channels.DatagramChannel
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
 * How the engine's UDP sockets reach the internet outside the tunnel: on
 * Android, VpnService.protect plus binding to the active network (protect
 * alone leaves a socket unbound, which fails on some carriers).
 */
fun interface SocketSetup {
    fun prepare(socket: DatagramSocket)
}

/** Resolves the server's host name outside the tunnel (on Android, on the underlying network). */
fun interface Resolver {
    fun resolve(host: String): List<InetAddress>
}

/** A peer reached directly (not through the hub), for the screens. */
data class DirectPeerStats(val vpnIp: String, val endpoint: String, val lastHandshakeMs: Long, val rxBytes: Long, val txBytes: Long)

/** What the screens show about the tunnel. */
data class TunnelStats(
    val rxBytes: Long,
    val txBytes: Long,
    /** Last completed handshake with the server, ms since 1970; 0 = never. */
    val lastHandshakeMs: Long,
    val endpoint: String?,
    val direct: List<DirectPeerStats> = emptyList(),
    val p2p: P2pStatus? = null,
    val exit: ExitStatus? = null,
)

/** Using another device as exit node: its VPN IP, standby | pending | active, and why. */
data class ExitStatus(val vpnIp: String, val phase: String, val reason: String, val offers: Map<String, Boolean>)

/**
 * WireGuard with the hub plus directly reached peers. Each peer sends on its
 * own UDP path (the main socket, or a punch socket that won a NAT race).
 * Encrypted types 4 (data), 7 (TUN control), 8 (WUSP) and 9 (P2P control)
 * share the session; type 6 (punch) is plain and authenticated by its MAC.
 */
class WireGuardDevice(
    private val config: TunnelConfig,
    private val tun: TunIo,
    private val socketSetup: SocketSetup = SocketSetup {},
    private val resolver: Resolver = Resolver { InetAddress.getAllByName(it).toList() },
    private val log: (String) -> Unit = {},
    /** This device's addresses on its networks (P2P candidates); Android can't list them from Java. */
    private val localAddresses: () -> List<InetAddress> = { emptyList() },
) {
    internal val main = UdpPath(DatagramChannel.open())
    private val indices = ConcurrentHashMap<Int, Peer>()
    private val server = Peer(config.server, main, isServer = true)
    private val direct = ConcurrentHashMap<String, Peer>() // VPN IPv4 -> direct peer
    @Volatile private var running = false
    private val threads = ArrayList<Thread>()
    private val rx = AtomicLong()
    private val tx = AtomicLong()
    internal val p2p = P2pClient(this, config, log, localAddresses)

    val stats: TunnelStats
        get() = TunnelStats(
            rx.get(), tx.get(), server.lastHandshakeMs, server.endpoint?.let { "${it.address.hostAddress}:${it.port}" },
            direct.map { (ip, p) -> DirectPeerStats(ip, p.endpoint?.let { "${it.address.hostAddress}:${it.port}" } ?: "", p.lastHandshakeMs, p.rx.get(), p.tx.get()) },
            p2p.status(),
            exitIp?.let { ExitStatus(it, exitPhase, exitReason, HashMap(exitOffers)) },
        )

    // ── exit node (client side) ──────────────────────────────────────────
    @Volatile private var exitIp: String? = null
    @Volatile private var exitGranted = false
    @Volatile private var exitPhase = "standby"
    @Volatile private var exitReason = ""
    private var exitRequestedAt = 0L
    private val exitOffers = ConcurrentHashMap<String, Boolean>()
    /** Called when internet traffic starts or stops going through the exit (the VPN needs its default route). */
    @Volatile var onExitActive: (Boolean) -> Unit = {}

    /** The exit carries the internet only with a granted request over a live direct session. */
    private fun exitActive(): Boolean {
        val ip = exitIp ?: return false
        return exitGranted && directPeer(ip)
    }

    /** Uses the device at [vpnIp] as exit node; null goes back to direct internet. */
    fun useExit(vpnIp: String?) {
        val old = exitIp
        if (old == vpnIp) return
        val wasActive = exitActive()
        if (old != null) direct[old]?.sendEncrypted(MessageType.TUN_CONTROL, frameTun(byteArrayOf(TUN_EXIT_REQUEST, EXIT_OP_RELEASE)))
        exitIp = vpnIp
        exitGranted = false
        exitRequestedAt = 0
        setExitPhase("standby", if (vpnIp == null) "" else "starting")
        if (wasActive) onExitActive(false)
        if (vpnIp != null) p2p.observeDestination(vpnIp)
    }

    private fun setExitPhase(phase: String, reason: String) {
        if (phase != exitPhase || reason != exitReason) log("exit node ${exitIp ?: "-"}: $phase${if (reason.isNotEmpty()) " ($reason)" else ""}")
        exitPhase = phase
        exitReason = reason
    }

    /** Every 2 s: get a direct path, ask the exit to carry us, notice when it stops. */
    private fun exitTick(now: Long) {
        val ip = exitIp ?: return
        val wasActive = exitPhase == "active"
        val peer = direct[ip]
        when {
            peer == null || peer.lastHandshakeMs == 0L -> {
                exitGranted = false
                p2p.observeDestination(ip) // ask the hub to punch (rate-limited)
                setExitPhase("standby", "no direct path to the exit node yet")
            }
            !exitGranted -> {
                if (now - exitRequestedAt >= EXIT_REQUEST_EVERY_MS) {
                    exitRequestedAt = now
                    peer.sendEncrypted(MessageType.TUN_CONTROL, frameTun(byteArrayOf(TUN_EXIT_REQUEST, EXIT_OP_USE)))
                }
                setExitPhase("pending", if (exitOffers[ip] == false) "that device does not share its internet" else "waiting for the exit node to confirm")
            }
            else -> setExitPhase("active", "")
        }
        val active = exitPhase == "active"
        if (active != wasActive) onExitActive(active)
    }

    private fun onTunControl(p: Peer, plain: ByteArray) {
        if (p.isServer) return // negotiation is between devices only
        val m = unframeTun(plain) ?: return
        if (m.size < 2) return
        when (m[0]) {
            TUN_EXIT_STATUS -> {
                val offered = m[1].toInt() and EXIT_FLAG_OFFERED != 0
                val granted = m[1].toInt() and EXIT_FLAG_GRANTED != 0
                exitOffers[p.vpnIp] = offered
                if (p.vpnIp == exitIp) {
                    if (granted) exitGranted = true else if (!offered) exitGranted = false
                }
            }
            TUN_EXIT_REQUEST -> {
                // Sharing this phone comes in a later phase: say it does not offer.
                p.sendEncrypted(MessageType.TUN_CONTROL, frameTun(byteArrayOf(TUN_EXIT_STATUS, 0)))
            }
        }
    }

    /** Destinations outside the networks the hub carries: the internet. */
    private fun isOverlay(dst: ByteArray): Boolean = config.server.allowedIps.any { it.bits > 0 && it.contains(dst) }

    /** The local UDP port of the main socket (for tests and P2P). */
    val localPort: Int get() = main.channel.socket().localPort

    /** A UDP socket the engine owns: protected, bound to the network, read by its own thread. */
    internal inner class UdpPath(val channel: DatagramChannel) {
        fun send(data: ByteArray, to: InetSocketAddress): Boolean = try {
            channel.send(ByteBuffer.wrap(data), to)
            tx.addAndGet(data.size.toLong())
            true
        } catch (e: IOException) {
            if (running) log("send to $to: ${e.message}")
            false
        }

        fun startReading(name: String) {
            val t = Thread({
                val buf = ByteBuffer.allocate(65535)
                while (running && channel.isOpen) {
                    buf.clear()
                    val from = try { channel.receive(buf) as InetSocketAddress? } catch (e: IOException) { if (running && channel.isOpen) log("receive: ${e.message}"); null } ?: continue
                    buf.flip()
                    if (buf.remaining() < 4) continue
                    val data = ByteArray(buf.remaining()).also { buf.get(it) }
                    rx.addAndGet(data.size.toLong())
                    try {
                        handleDatagram(data, from, this)
                    } catch (e: Exception) {
                        log("bad datagram: ${e.message}")
                    }
                }
            }, name)
            t.isDaemon = true
            synchronized(threads) { threads += t }
            t.start()
        }

        fun close() = runCatching { channel.close() }
    }

    /** Opens, protects and binds a new UDP socket (P2P punch sockets). */
    internal fun openChannel(): DatagramChannel {
        val ch = DatagramChannel.open()
        ch.socket().bind(InetSocketAddress(0))
        socketSetup.prepare(ch.socket())
        return ch
    }

    fun start() {
        main.channel.socket().reuseAddress = true
        main.channel.socket().bind(InetSocketAddress(0))
        socketSetup.prepare(main.channel.socket())
        running = true
        main.startReading("wg-udp")
        listOf(Thread(::tunLoop, "wg-tun"), Thread(::timerLoop, "wg-timers")).forEach {
            it.isDaemon = true
            synchronized(threads) { threads += it }
            it.start()
        }
        log("WireGuard device up, local port $localPort")
    }

    fun stop() {
        running = false
        p2p.stop()
        direct.values.forEach { if (it.path !== main) it.path.close() }
        main.close()
        tun.close()
        synchronized(threads) {
            threads.forEach { it.interrupt() }
            threads.clear()
        }
    }

    private fun handleDatagram(data: ByteArray, from: InetSocketAddress, path: UdpPath) {
        val type = data[0].toInt() and 0xff
        val b = ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN)
        when (type) {
            MessageType.TRANSPORT, MessageType.TUN_CONTROL, MessageType.WUSP, MessageType.P2P_CONTROL -> {
                if (data.size < MessageType.TRANSPORT_HEADER + MessageType.TAG) return
                val receiver = b.getInt(4)
                val p = indices[receiver] ?: return
                val plain = p.decrypt(receiver, b.getLong(8), data) ?: return
                p.roam(from, path)
                when (type) {
                    MessageType.TRANSPORT -> {
                        if (plain.isEmpty()) return // keepalive
                        val ip = trimToIpLength(plain)
                        if (p.allowsSource(ip)) tun.write(ip, ip.size)
                    }
                    MessageType.P2P_CONTROL -> if (p.isServer) unframeControl(plain)?.let { p2p.onControl(it) }
                    MessageType.TUN_CONTROL -> onTunControl(p, plain)
                    else -> Unit // 8: WUSP (later phase)
                }
            }
            MessageType.RESPONSE -> {
                val p = indices[b.getInt(8)] ?: return
                if (p.consumeResponse(data)) {
                    p.roam(from, path)
                    log(if (p.isServer) "handshake with the server complete" else "direct handshake with ${p.vpnIp} complete")
                }
            }
            MessageType.INITIATION -> {
                // Whoever it is from: the hub, or a peer we punched to.
                val p = (listOf(server) + direct.values).firstOrNull { it.consumeInitiation(data) } ?: return
                p.roam(from, path)
                p.respond()
            }
            MessageType.COOKIE_REPLY -> indices[b.getInt(4)]?.consumeCookieReply(data)
            MessageType.PUNCH -> p2p.onPunch(data, from, path)
        }
    }

    /** A datagram read outside the path threads (the P2P socket pool). */
    internal fun receive(data: ByteArray, from: InetSocketAddress, path: UdpPath) {
        rx.addAndGet(data.size.toLong())
        handleDatagram(data, from, path)
    }

    /** Sends a P2P control message to the hub (type 9, inside the session). */
    internal fun sendToServer(message: ByteArray) {
        server.sendEncrypted(MessageType.P2P_CONTROL, frameControl(message))
    }

    /**
     * A direct path to a peer won: a WireGuard session with it over [path] to
     * [endpoint]. Its VPN address is routed there once the handshake completes.
     */
    internal fun addDirectPeer(publicKey: ByteArray, vpnIp: String, endpoint: InetSocketAddress, path: UdpPath, initiate: Boolean) {
        val ip = IpPrefix.parse("$vpnIp/32") ?: return
        direct.remove(vpnIp)?.let { old -> if (old.path !== main && old.path !== path) old.path.close() }
        val p = Peer(PeerConfig(publicKey, "", endpoint.port, listOf(ip), P2P_KEEPALIVE_SEC), path, isServer = false, vpnIp = vpnIp)
        p.endpoint = endpoint
        direct[vpnIp] = p
        if (path !== main) path.startReading("wg-p2p-$vpnIp")
        if (initiate) p.initiate(System.currentTimeMillis(), force = true) else p.respondFallbackAt = System.currentTimeMillis() + RESPONDER_FALLBACK_MS
    }

    internal fun removeDirectPeer(vpnIp: String) {
        direct.remove(vpnIp)?.let { if (it.path !== main) it.path.close() }
    }

    /** A direct path to [vpnIp] exists, set up or being set up. */
    internal fun hasDirect(vpnIp: String): Boolean = direct.containsKey(vpnIp)

    /** A direct path carries traffic only while packets keep coming back from it. */
    internal fun directPeer(vpnIp: String): Boolean = direct[vpnIp]?.alive(System.currentTimeMillis()) == true

    private fun tunLoop() {
        val buf = ByteArray(65535)
        while (running) {
            val n = try { tun.read(buf) } catch (e: IOException) { if (running) log("tun read: ${e.message}"); -1 }
            if (n < 0) { if (running) Thread.sleep(50); continue }
            if (n < 20) continue
            val packet = buf.copyOf(n)
            if (packet[0].toInt() ushr 4 != 4) {
                // IPv6 goes to the hub's networks only; with an exit it is dropped (no leak around it).
                if (!exitActive()) server.sendPacket(packet)
                continue
            }
            val dstRaw = packet.copyOfRange(16, 20)
            val dst = InetAddress.getByAddress(dstRaw).hostAddress
            // A direct peer with a live session carries its address; the internet
            // goes to the exit node when one is active; the hub the rest.
            val p = direct[dst]?.takeIf { it.alive(System.currentTimeMillis()) }
            when {
                p != null -> p.sendPacket(packet)
                !isOverlay(dstRaw) && exitActive() -> direct[exitIp]?.sendPacket(packet)
                else -> {
                    server.sendPacket(packet)
                    p2p.observeDestination(dst)
                }
            }
        }
    }

    private fun timerLoop() {
        resolveEndpoint()
        var lastP2p = 0L
        var lastExit = 0L
        while (running) {
            try {
                Thread.sleep(TICK_MS)
            } catch (e: InterruptedException) {
                return
            }
            val now = System.currentTimeMillis()
            server.tick(now)
            direct.values.forEach { it.tick(now) }
            // A direct session that went quiet: back to the hub.
            direct.entries.removeIf { (_, p) ->
                // Both sides keep it alive (the Go agent every 12 s, this side every
                // 25 s): silence means the other side dropped it. Back to the hub.
                val stale = p.lastHandshakeMs > 0 && now - p.lastReceivedMs > DIRECT_SILENT_MS ||
                    p.lastHandshakeMs == 0L && now - p.created > DIRECT_SETUP_TIMEOUT_MS
                if (stale) {
                    log("direct path to ${p.vpnIp} ${if (p.lastHandshakeMs == 0L) "never came up" else "went quiet"}; using the hub")
                    if (p.path !== main) p.path.close()
                    p2p.directLost(p.vpnIp)
                }
                stale
            }
            p2p.fastTick(now)
            if (now - lastExit >= EXIT_TICK_MS) {
                lastExit = now
                exitTick(now)
            }
            if (now - lastP2p >= P2P_TICK_MS && server.lastHandshakeMs > 0) {
                lastP2p = now
                p2p.tick(now)
            }
        }
    }

    private fun resolveEndpoint() {
        val host = config.server.endpointHost
        val addrs = runCatching { resolver.resolve(host) }.onFailure { log("resolve $host: ${it.message}") }.getOrDefault(emptyList())
        val addr = addrs.firstOrNull { it is Inet4Address } ?: addrs.firstOrNull()
        if (addr != null) {
            server.endpoint = InetSocketAddress(addr, config.server.endpointPort)
            log("server endpoint ${addr.hostAddress}:${config.server.endpointPort}")
        }
    }

    /** One remote: handshakes, keypairs, staged packets and timers. */
    private inner class Peer(val cfg: PeerConfig, @Volatile var path: UdpPath, val isServer: Boolean, val vpnIp: String = "") {
        private val handshake = Handshake(config.privateKey, config.publicKey, cfg.publicKey)
        @Volatile var endpoint: InetSocketAddress? = null
        @Volatile var lastHandshakeMs = 0L
        val created = System.currentTimeMillis()
        val rx = AtomicLong()
        val tx = AtomicLong()
        var respondFallbackAt = 0L

        private var current: Keypair? = null
        private var previous: Keypair? = null
        private var next: Keypair? = null // responder side, until the initiator uses it
        private val staged = ArrayDeque<ByteArray>()

        private var handshakeStarted = 0L // 0 = none in flight
        private var pendingIndex = 0 // our index in the initiation in flight
        private var lastInitiation = 0L
        private var lastSent = 0L
        private var lastReceived = 0L
        val lastReceivedMs: Long get() = lastReceived
        private var lastDataSent = 0L
        private var lastDataReceived = 0L
        private var resolveAgainAt = 0L

        fun alive(now: Long): Boolean = lastHandshakeMs > 0 && now - lastReceived < DIRECT_SILENT_MS

        fun allowsSource(packet: ByteArray): Boolean {
            val src = when (packet[0].toInt() ushr 4) {
                4 -> if (packet.size >= 20) packet.copyOfRange(12, 16) else return false
                6 -> if (packet.size >= 40) packet.copyOfRange(8, 24) else return false
                else -> return false
            }
            if (cfg.allowedIps.any { it.contains(src) }) return true
            // The exit node brings the internet's replies.
            return !isServer && vpnIp == exitIp && exitActive()
        }

        fun roam(from: InetSocketAddress, via: UdpPath) {
            if (endpoint != from) endpoint = from
            if (path !== via) path = via
        }

        private fun send(data: ByteArray) {
            val ep = endpoint ?: return
            if (path.send(data, ep)) tx.addAndGet(data.size.toLong())
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
            encryptAndSend(kp, MessageType.TRANSPORT, packet)
            lastDataSent = now
            if (kp.isInitiator && (now - kp.created >= WgTimers.REKEY_AFTER_TIME_MS || kp.sent >= WgTimers.REKEY_AFTER_MESSAGES)) {
                initiate(now, force = false)
            }
        }

        /** A control message (types 7-9) inside the session; dropped while there is none. */
        @Synchronized
        fun sendEncrypted(type: Int, plain: ByteArray) {
            val kp = current ?: return
            if (kp.expired(System.currentTimeMillis())) return
            encryptAndSend(kp, type, plain)
        }

        private fun encryptAndSend(kp: Keypair, type: Int, packet: ByteArray) {
            val counter = kp.nextCounter()
            if (counter < 0) return
            // Pad to a multiple of 16, never past the MTU.
            val padded = minOf(((packet.size + 15) / 16) * 16, maxOf(packet.size, config.mtu))
            val plain = if (padded == packet.size) packet else packet.copyOf(padded)
            val sealed = WgCrypto.seal(kp.sendKey, counter, plain, ByteArray(0))
            val out = ByteBuffer.allocate(MessageType.TRANSPORT_HEADER + sealed.size).order(ByteOrder.LITTLE_ENDIAN)
            out.putInt(type).putInt(kp.remoteIndex).putLong(counter).put(sealed)
            send(out.array())
            lastSent = System.currentTimeMillis()
        }

        private fun sendKeepalive() {
            val kp = current ?: return
            encryptAndSend(kp, MessageType.TRANSPORT, ByteArray(0))
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
            if (staged.isEmpty()) sendKeepalive() else while (staged.isNotEmpty()) encryptAndSend(kp, MessageType.TRANSPORT, staged.removeFirst())
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
            respondFallbackAt = 0L
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
                while (staged.isNotEmpty()) encryptAndSend(kp, MessageType.TRANSPORT, staged.removeFirst())
            }
            lastReceived = now
            rx.addAndGet(data.size.toLong())
            if (plain.isNotEmpty()) lastDataReceived = now
            return plain
        }

        @Synchronized
        fun consumeCookieReply(msg: ByteArray) {
            handshake.consumeCookieReply(msg)
        }

        /** The protocol's timers, every [TICK_MS]. */
        @Synchronized
        fun tick(now: Long) {
            if (endpoint == null) {
                if (isServer && now >= resolveAgainAt) {
                    resolveAgainAt = now + 10_000
                    resolveEndpoint()
                }
                return
            }
            // The waiting side of a direct path initiates itself if nothing came.
            if (respondFallbackAt != 0L && now >= respondFallbackAt && current == null) {
                respondFallbackAt = 0L
                initiate(now, force = true)
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
                if (handshakeStarted == 0L && respondFallbackAt == 0L && (cfg.persistentKeepaliveSec > 0 || staged.isNotEmpty())) initiate(now, force = false)
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
        private const val P2P_TICK_MS = 5_000L
        private const val MAX_STAGED = 128
        private const val P2P_KEEPALIVE_SEC = 25
        /** Like the Go agent's p2pResponderFallback. */
        private const val RESPONDER_FALLBACK_MS = 3_000L
        private const val DIRECT_SILENT_MS = 40_000L
        private const val DIRECT_SETUP_TIMEOUT_MS = 20_000L

        private const val EXIT_TICK_MS = 2_000L
        private const val EXIT_REQUEST_EVERY_MS = 5_000L
        // TUN control (type 7), as the Go agent's tun_control.go / exitnode.go.
        private const val TUN_EXIT_REQUEST: Byte = 10
        private const val TUN_EXIT_STATUS: Byte = 11
        private const val EXIT_OP_RELEASE: Byte = 0
        private const val EXIT_OP_USE: Byte = 1
        private const val EXIT_FLAG_OFFERED = 1
        private const val EXIT_FLAG_GRANTED = 2
        private val TUN_MAGIC = byteArrayOf('W'.code.toByte(), 'T'.code.toByte(), 'C'.code.toByte(), 1)

        /** "WTC\x01" | u16 LE length | payload: the TUN control frame. */
        internal fun frameTun(payload: ByteArray): ByteArray {
            val out = ByteArray(6 + payload.size)
            TUN_MAGIC.copyInto(out)
            out[4] = payload.size.toByte()
            out[5] = (payload.size ushr 8).toByte()
            payload.copyInto(out, 6)
            return out
        }

        internal fun unframeTun(plain: ByteArray): ByteArray? {
            if (plain.size < 6 || !plain.copyOfRange(0, 4).contentEquals(TUN_MAGIC)) return null
            val len = (plain[4].toInt() and 0xff) or ((plain[5].toInt() and 0xff) shl 8)
            if (len > 1200 || len > plain.size - 6) return null
            return plain.copyOfRange(6, 6 + len)
        }

        /** "WPC\x01" | u16 LE length | message: the Go agent's P2P control frame. */
        private val CONTROL_MAGIC = byteArrayOf('W'.code.toByte(), 'P'.code.toByte(), 'C'.code.toByte(), 1)
        private const val MAX_CONTROL = 1200

        internal fun frameControl(message: ByteArray): ByteArray {
            require(message.size <= MAX_CONTROL) { "P2P control message too large" }
            val out = ByteArray(6 + message.size)
            CONTROL_MAGIC.copyInto(out)
            out[4] = message.size.toByte()
            out[5] = (message.size ushr 8).toByte()
            message.copyInto(out, 6)
            return out
        }

        internal fun unframeControl(plain: ByteArray): ByteArray? {
            if (plain.size < 6 || !plain.copyOfRange(0, 4).contentEquals(CONTROL_MAGIC)) return null
            val len = (plain[4].toInt() and 0xff) or ((plain[5].toInt() and 0xff) shl 8)
            if (len > MAX_CONTROL || len > plain.size - 6) return null
            return plain.copyOfRange(6, 6 + len)
        }

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
