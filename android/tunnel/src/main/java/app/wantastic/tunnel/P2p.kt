package app.wantastic.tunnel

import java.io.IOException
import java.net.Inet4Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.channels.DatagramChannel
import java.nio.channels.SelectionKey
import java.nio.channels.Selector
import java.util.concurrent.ConcurrentHashMap

/** P2P state for the screens and logs. */
data class P2pStatus(
    val id: Int, val observed: String?, val nat: String, val discovered: Int, val attempts: Map<String, String>,
    /** VPN IPs of the network's P2P-capable devices. */
    val peers: List<String> = emptyList(),
)

/**
 * Wantastic's P2P coordination, byte-compatible with the Go agent
 * (p2p_message.go, p2p_client.go, p2p_nat.go): register with the hub, learn the
 * peer list, ask the hub to relay a punch, punch, and promote the winning path
 * to a direct WireGuard session.
 *
 * When this side's NAT rewrites ports (carrier NAT on mobile) and the peer's
 * keeps them, the birthday trick: [POOL_SIZE] sockets punch at the peer's
 * fixed endpoint while the peer sprays random ports; the socket that hears
 * back carries the session.
 */
internal class P2pClient(
    private val dev: WireGuardDevice,
    private val config: TunnelConfig,
    private val log: (String) -> Unit,
    private val localAddresses: () -> List<InetAddress>,
) {
    private class Discovered(
        val id: Int, val publicKey: ByteArray, val local: InetSocketAddress?, val observed: InetSocketAddress?,
        val capable: Boolean, val vpnIp: String,
    )

    private class Session(
        val nonce: ByteArray, val targetId: Int, val publicKey: ByteArray, val vpnIp: String,
        val targets: List<InetSocketAddress>, val peerObserved: InetSocketAddress?, val started: Long,
    ) {
        @Volatile var done = false
        var round = 0
        var pool: Pool? = null
    }

    private val myKey = config.publicKey
    @Volatile private var myId = 0
    @Volatile private var observed: InetSocketAddress? = null
    @Volatile private var lastRegister = 0L
    private var lastPeerList = 0L
    private val peers = ConcurrentHashMap<Int, Discovered>()
    private val sessions = ConcurrentHashMap<String, Session>() // by peer VPN IP
    private val attempts = ConcurrentHashMap<String, Int>()
    private val nextTry = ConcurrentHashMap<String, Long>()
    private val state = ConcurrentHashMap<String, String>()
    @Volatile private var stopped = false

    fun status() = P2pStatus(
        myId, observed?.let { "${it.address.hostAddress}:${it.port}" }, selfNat().name.lowercase(), peers.size, HashMap(state),
        peers.values.filter { it.capable }.map { it.vpnIp }.sorted(),
    )

    fun stop() {
        stopped = true
        sessions.values.forEach { it.pool?.close() }
    }

    // ── coordination with the hub ────────────────────────────────────────

    /** Every 5 s once the hub session is up. */
    fun tick(now: Long) {
        if (myId == 0 || now - lastRegister >= REREGISTER_MS) register(now)
        if (myId != 0 && now - lastPeerList >= PEER_LIST_MS) {
            lastPeerList = now
            dev.sendToServer(P2pMessage(SUBTYPE_PEER_LIST, myKey).encode())
        }
        expire(now)
    }

    /** Every engine tick (250 ms): the paced punch rounds. */
    fun fastTick(now: Long) {
        sessions.values.forEach { s -> if (!s.done) punchRound(s, now) }
    }

    private fun expire(now: Long) {
        sessions.entries.removeIf { (ip, s) ->
            val over = now - s.started > SESSION_MS
            if (over && !s.done) {
                s.pool?.close()
                state[ip] = "relay (direct failed)"
                attempts.merge(ip, 1, Int::plus)
            }
            over || s.done
        }
    }

    private fun register(now: Long) {
        lastRegister = now
        val port = dev.localPort
        val candidates = localAddresses().filterIsInstance<Inet4Address>().filter { !it.isLoopbackAddress }.map { InetSocketAddress(it, port) }
        val msg = P2pMessage(SUBTYPE_REGISTER, myKey, payload = encodeCandidates(candidates))
        msg.local = candidates.firstOrNull() ?: InetSocketAddress(InetAddress.getByAddress(ByteArray(4)), port)
        dev.sendToServer(msg.encode())
    }

    fun onControl(data: ByteArray) {
        val m = P2pMessage.decode(data) ?: return
        when (m.subtype) {
            SUBTYPE_REGISTER_ACK -> {
                if (myId != m.targetId) log("P2P: registered as ${m.targetId}, seen at ${m.observed}")
                myId = m.targetId
                observed = m.observed
                lastPeerList = 0
            }
            SUBTYPE_PEER_LIST -> parsePeerList(m.payload)
            SUBTYPE_PUNCH_RELAY -> startSession(m)
            else -> Unit // names, heartbeats
        }
    }

    private fun parsePeerList(p: ByteArray) {
        if (p.size < 4) return
        val b = ByteBuffer.wrap(p).order(ByteOrder.BIG_ENDIAN)
        val count = b.getInt(0)
        if (count < 0 || count > 4096 || p.size < 4 + count * 78) return
        for (i in 0 until count) {
            val o = 4 + i * 78
            val id = b.getInt(o)
            val key = p.copyOfRange(o + 4, o + 36)
            val ip = InetAddress.getByAddress(p.copyOfRange(o + 74, o + 78)).hostAddress ?: continue
            if (key.contentEquals(myKey)) continue
            val prev = peers[id]
            val d = Discovered(id, key, addr(p, o + 36), addr(p, o + 54), p[o + 73].toInt() == 1, ip)
            peers[id] = d
            // A peer that came back at a new public address gets a fresh try.
            if (prev?.observed != null && d.observed != null && prev.observed != d.observed) {
                attempts.remove(ip)
                nextTry.remove(ip)
            }
        }
    }

    /** Traffic for [vpnIp] went through the hub: try a direct path (rate-limited). */
    fun observeDestination(vpnIp: String) {
        if (myId == 0 || dev.directPeer(vpnIp) || sessions.containsKey(vpnIp)) return
        val now = System.currentTimeMillis()
        if (now < (nextTry[vpnIp] ?: 0L)) return
        val peer = peers.values.firstOrNull { it.vpnIp == vpnIp && it.capable } ?: return
        val n = attempts[vpnIp] ?: 0
        nextTry[vpnIp] = now + minOf(RETRY_BASE_MS shl minOf(n, 4), RETRY_MAX_MS)
        state[vpnIp] = "asking the hub to punch"
        dev.sendToServer(P2pMessage(SUBTYPE_PUNCH_REQUEST, myKey, targetId = peer.id).encode())
    }

    fun directLost(vpnIp: String) {
        state[vpnIp] = "relay (direct went quiet)"
        attempts.merge(vpnIp, 1, Int::plus)
    }

    // ── punching ─────────────────────────────────────────────────────────

    private fun startSession(m: P2pMessage) {
        if (m.payload.size < 4) return
        val vpnIp = InetAddress.getByAddress(m.payload.copyOfRange(0, 4)).hostAddress ?: return
        if (dev.directPeer(vpnIp)) return
        val candidates = decodeCandidates(m.payload, 4)
        val targets = LinkedHashSet<InetSocketAddress>()
        m.observed?.let { targets += it }
        candidates.forEach { targets += it }
        m.local?.takeIf { it.port > 0 && !it.address.isAnyLocalAddress }?.let { targets += it }
        if (targets.isEmpty()) return
        sessions[vpnIp]?.pool?.close()
        val s = Session(m.nonce, m.targetId, m.publicKey, vpnIp, targets.toList(), m.observed, System.currentTimeMillis())
        sessions[vpnIp] = s
        val self = selfNat()
        val peerNat = classify(m.observed, m.local, candidates)
        state[vpnIp] = "punching ($self vs $peerNat)"
        log("P2P: punching $vpnIp: this side $self, peer $peerNat, ${targets.size} targets")
        if (self == Nat.REWRITING && peerNat.easy && m.observed != null) {
            // Birthday trick: many mappings toward the peer's fixed endpoint.
            s.pool = runCatching { Pool(s) }.onFailure { log("P2P: socket pool: ${it.message}") }.getOrNull()
        }
        punchRound(s, s.started)
    }

    private fun punchRound(s: Session, now: Long) {
        val elapsed = now - s.started
        while (s.round < ROUNDS_MS.size && elapsed >= ROUNDS_MS[s.round]) {
            val packet = punchPacket(s.nonce, s.publicKey) ?: return
            s.targets.forEach { dev.main.send(packet, it) }
            if (s.round < POOL_ROUNDS) s.pool?.punch(packet)
            s.round++
        }
    }

    /** A punch packet reached a socket: authenticate it, answer, and take that path. */
    fun onPunch(data: ByteArray, from: InetSocketAddress, path: WireGuardDevice.UdpPath) {
        val s = sessionFor(data, from) ?: return
        val reply = punchPacket(s.nonce, s.publicKey) ?: return
        path.send(reply, from)
        promote(s, from, path)
    }

    private fun sessionFor(data: ByteArray, from: InetSocketAddress): Session? {
        if (data.size != 45 || data[4].toInt() != SUBTYPE_PUNCH) return null
        val nonce = data.copyOfRange(5, 13)
        val s = sessions.values.firstOrNull { !it.done && (it.nonce.contentEquals(nonce) || it.peerObserved?.address == from.address) } ?: return null
        return if (verifyPunch(data, s.publicKey)) s else null
    }

    private fun promote(s: Session, from: InetSocketAddress, path: WireGuardDevice.UdpPath) {
        synchronized(s) {
            if (s.done) return
            s.done = true
        }
        s.pool?.close()
        state[s.vpnIp] = "direct via ${from.address.hostAddress}:${from.port}"
        attempts.remove(s.vpnIp)
        log("P2P: direct path to ${s.vpnIp} at $from (${if (path === dev.main) "main socket" else "socket pool"})")
        // The lower public key initiates, as in the Go agent (initiatesHandshake).
        dev.addDirectPeer(s.publicKey, s.vpnIp, from, path, initiate = compareKeys(myKey, s.publicKey) < 0)
    }

    /** The birthday pool: sockets that punch together and wait for the first answer. */
    private inner class Pool(private val s: Session) {
        private val selector = Selector.open()
        private val channels = ArrayList<DatagramChannel>()
        @Volatile private var open = true

        init {
            for (i in 0 until POOL_SIZE) {
                val ch = try { dev.openChannel() } catch (e: IOException) { break }
                ch.configureBlocking(false)
                ch.register(selector, SelectionKey.OP_READ)
                channels += ch
            }
            log("P2P: ${channels.size} punch sockets toward ${s.peerObserved}")
            Thread(::loop, "wg-p2p-pool").apply { isDaemon = true }.start()
        }

        fun punch(packet: ByteArray) {
            val to = s.peerObserved ?: return
            for (ch in channels) runCatching { ch.send(ByteBuffer.wrap(packet), to) }
        }

        private fun loop() {
            val buf = ByteBuffer.allocate(2048)
            val until = s.started + SESSION_MS
            try {
                while (open && !stopped && System.currentTimeMillis() < until) {
                    if (selector.select(200) == 0) continue
                    val it = selector.selectedKeys().iterator()
                    while (it.hasNext()) {
                        val key = it.next()
                        it.remove()
                        val ch = key.channel() as DatagramChannel
                        buf.clear()
                        val from = runCatching { ch.receive(buf) as InetSocketAddress? }.getOrNull() ?: continue
                        buf.flip()
                        val data = ByteArray(buf.remaining()).also { b -> buf.get(b) }
                        if (from.address != s.peerObserved?.address) continue
                        val type = if (data.isNotEmpty()) data[0].toInt() and 0xff else continue
                        // The peer's punch, or its WireGuard handshake: this socket won.
                        val ok = when (type) {
                            MessageType.PUNCH -> sessionFor(data, from) === s
                            MessageType.INITIATION -> true
                            else -> false
                        }
                        if (!ok) continue
                        key.cancel()
                        selector.selectNow()
                        ch.configureBlocking(true)
                        channels.remove(ch)
                        val path = dev.UdpPath(ch)
                        punchPacket(s.nonce, s.publicKey)?.let { path.send(it, from) }
                        promote(s, from, path)
                        // Its handshake came first: answer it now, not at its retry.
                        if (type == MessageType.INITIATION) dev.receive(data, from, path)
                        return
                    }
                }
            } catch (e: IOException) {
                log("P2P: pool: ${e.message}")
            } finally {
                close()
            }
        }

        fun close() {
            if (!open) return
            open = false
            channels.forEach { runCatching { it.close() } }
            channels.clear()
            runCatching { selector.close() }
        }
    }

    // ── NAT classes, as the Go agent's classifyNAT ───────────────────────

    enum class Nat(val easy: Boolean) { UNKNOWN(false), PUBLIC(true), MAPPED(true), PRESERVING(true), REWRITING(false) }

    private fun selfNat(): Nat = classify(observed, InetSocketAddress(InetAddress.getByAddress(ByteArray(4)), dev.localPort), emptyList())

    private fun classify(observed: InetSocketAddress?, local: InetSocketAddress?, candidates: List<InetSocketAddress>): Nat {
        if (observed == null || !isPublic(observed.address)) return Nat.UNKNOWN
        if (local != null && local.address == observed.address && local.port == observed.port) return Nat.PUBLIC
        var listenPort = local?.port ?: 0
        for (c in candidates) {
            if (c.port <= 0 || c == observed) continue
            if (isPublic(c.address)) return Nat.MAPPED
            if (listenPort <= 0) listenPort = c.port
        }
        return when {
            listenPort <= 0 -> Nat.UNKNOWN
            observed.port == listenPort -> Nat.PRESERVING
            else -> Nat.REWRITING
        }
    }

    private fun isPublic(a: InetAddress): Boolean = a is Inet4Address && !a.isSiteLocalAddress && !a.isLoopbackAddress &&
        !a.isLinkLocalAddress && !a.isAnyLocalAddress && !a.isMulticastAddress &&
        // 100.64.0.0/10: carrier-grade NAT space
        !((a.address[0].toInt() and 0xff) == 100 && (a.address[1].toInt() and 0xc0) == 64)

    // ── wire format ──────────────────────────────────────────────────────

    /** Punch: LE u32 6 | subtype 6 | nonce(8) | BLAKE2s-256(key = static-static DH)(nonce). */
    private fun punchPacket(nonce: ByteArray, peerKey: ByteArray): ByteArray? {
        val mac = punchMac(nonce, peerKey) ?: return null
        val out = ByteBuffer.allocate(45).order(ByteOrder.LITTLE_ENDIAN)
        out.putInt(MessageType.PUNCH).put(SUBTYPE_PUNCH.toByte()).put(nonce).put(mac)
        return out.array()
    }

    private fun verifyPunch(data: ByteArray, peerKey: ByteArray): Boolean {
        val mac = punchMac(data.copyOfRange(5, 13), peerKey) ?: return false
        var diff = 0
        for (i in 0 until 32) diff = diff or (mac[i].toInt() xor data[13 + i].toInt())
        return diff == 0
    }

    private fun punchMac(nonce: ByteArray, peerKey: ByteArray): ByteArray? {
        val ss = runCatching { WgCrypto.dh(config.privateKey, peerKey) }.getOrNull() ?: return null
        return Blake2s(32, ss).update(nonce).digest()
    }

    private fun addr(p: ByteArray, o: Int): InetSocketAddress? {
        val port = ((p[o + 16].toInt() and 0xff) shl 8) or (p[o + 17].toInt() and 0xff)
        if (port == 0) return null
        val raw = p.copyOfRange(o, o + 16)
        return InetSocketAddress(InetAddress.getByAddress(raw), port) // v4-mapped becomes an Inet4Address
    }

    companion object {
        const val SUBTYPE_REGISTER = 1
        const val SUBTYPE_REGISTER_ACK = 2
        const val SUBTYPE_PEER_LIST = 3
        const val SUBTYPE_PUNCH_REQUEST = 4
        const val SUBTYPE_PUNCH_RELAY = 5
        const val SUBTYPE_PUNCH = 6

        /** Sockets in the birthday pool: the hard side's half of ~256 x 256. */
        const val POOL_SIZE = 256
        /** Punch rounds after the relay; the pool joins the first [POOL_ROUNDS] (carrier rate limits). */
        private val ROUNDS_MS = longArrayOf(0, 300, 700, 1200, 2000, 3000, 4500, 6500, 9000, 12000)
        private const val POOL_ROUNDS = 6
        private const val SESSION_MS = 15_000L
        private const val REREGISTER_MS = 60_000L
        private const val PEER_LIST_MS = 15_000L
        private const val RETRY_BASE_MS = 10_000L
        private const val RETRY_MAX_MS = 5 * 60_000L

        private val WPC1 = "WPC1".toByteArray()

        /** "WPC1" | count | (16-byte IP, BE port) x count, as EncodeP2PCandidatePayload. */
        fun encodeCandidates(c: List<InetSocketAddress>): ByteArray {
            if (c.isEmpty()) return ByteArray(0)
            val n = minOf(c.size, 255)
            val out = ByteBuffer.allocate(5 + n * 18).order(ByteOrder.BIG_ENDIAN)
            out.put(WPC1).put(n.toByte())
            c.take(n).forEach { out.put(ip16(it.address)).putShort(it.port.toShort()) }
            return out.array()
        }

        fun decodeCandidates(p: ByteArray, offset: Int): List<InetSocketAddress> {
            if (p.size < offset + 5 || !p.copyOfRange(offset, offset + 4).contentEquals(WPC1)) return emptyList()
            val count = p[offset + 4].toInt() and 0xff
            if (p.size < offset + 5 + count * 18) return emptyList()
            return (0 until count).mapNotNull { i ->
                val o = offset + 5 + i * 18
                val port = ((p[o + 16].toInt() and 0xff) shl 8) or (p[o + 17].toInt() and 0xff)
                if (port == 0) null else InetSocketAddress(InetAddress.getByAddress(p.copyOfRange(o, o + 16)), port)
            }
        }

        /** IPv6, or IPv4-mapped IPv6 (::ffff:a.b.c.d) as Go's To16. */
        fun ip16(a: InetAddress): ByteArray {
            val raw = a.address
            if (raw.size == 16) return raw
            return ByteArray(16).also { it[10] = -1; it[11] = -1; raw.copyInto(it, 12) }
        }

        /** Unsigned byte order, as Go's bytes.Compare. */
        fun compareKeys(a: ByteArray, b: ByteArray): Int {
            for (i in a.indices) {
                val d = (a[i].toInt() and 0xff) - (b[i].toInt() and 0xff)
                if (d != 0) return d
            }
            return 0
        }
    }
}

/** The 84-byte P2P message header plus payload (P2PMessage in p2p_message.go). */
internal class P2pMessage(
    val subtype: Int,
    val publicKey: ByteArray,
    var local: InetSocketAddress? = null,
    var observed: InetSocketAddress? = null,
    val targetId: Int = 0,
    val nonce: ByteArray = ByteArray(8),
    val payload: ByteArray = ByteArray(0),
) {
    fun encode(): ByteArray {
        val b = ByteBuffer.allocate(84 + payload.size).order(ByteOrder.BIG_ENDIAN)
        b.put(subtype.toByte()).put(ByteArray(3)).put(publicKey)
        b.put(local?.let { P2pClient.ip16(it.address) } ?: ByteArray(16)).putShort((local?.port ?: 0).toShort())
        b.put(observed?.let { P2pClient.ip16(it.address) } ?: ByteArray(16)).putShort((observed?.port ?: 0).toShort())
        b.putInt(targetId).put(nonce).put(payload)
        return b.array()
    }

    companion object {
        fun decode(d: ByteArray): P2pMessage? {
            if (d.size < 84) return null
            val b = ByteBuffer.wrap(d).order(ByteOrder.BIG_ENDIAN)
            fun ep(o: Int): InetSocketAddress? {
                val port = b.getShort(o + 16).toInt() and 0xffff
                if (port == 0) return null
                return InetSocketAddress(InetAddress.getByAddress(d.copyOfRange(o, o + 16)), port)
            }
            return P2pMessage(
                subtype = d[0].toInt() and 0xff,
                publicKey = d.copyOfRange(4, 36),
                local = ep(36),
                observed = ep(54),
                targetId = b.getInt(72),
                nonce = d.copyOfRange(76, 84),
                payload = d.copyOfRange(84, d.size),
            )
        }
    }
}
