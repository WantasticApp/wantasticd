package app.wantastic.android.engine

import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.util.Log
import app.wantastic.android.account.DeviceSetups
import app.wantastic.android.vpn.WantasticVpnService
import app.wantastic.tunnel.ClaimClient
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * The app's engine, all Kotlin (app.wantastic.tunnel): waits for the active
 * setup's approval, runs the tunnel inside the VPN service, and reports its
 * state to the screens.
 */
class AppEngine private constructor(private val context: Context, private val setups: DeviceSetups) : Engine {
    private val state = MutableStateFlow(initial())
    override val status: StateFlow<EngineStatus> = state.asStateFlow()
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val claims = ClaimClient(context.filesDir.resolve("engine"))
    private val prefs = context.getSharedPreferences("engine", Context.MODE_PRIVATE)
    private var poller: Job? = null
    private var routeJob: Job? = null
    private var since = 0L
    private var last: Triple<Long, Long, Long>? = null // time, rx, tx
    private var service: VpnService? = null
    private var server = ""
    @Volatile private var tunnel: KotlinTunnel? = null
    private var lastP2pLine = ""

    private fun initial() = EngineStatus(claimed = setups.current().claimed, tunnel = TunnelState.Disconnected)

    /** Re-reads the active setup (after a sign-in, switch or add). */
    fun refresh() = state.update { it.copy(claimed = setups.current().claimed) }

    /** The approval of [publicKey], once someone approved it; null until then. */
    suspend fun waitClaim(server: String, publicKey: String): String? = withContext(Dispatchers.IO) {
        runCatching { claims.fetch(server, publicKey) }.onFailure { Log.w(TAG, "claim check: ${it.message}") }.getOrNull()
    }

    /** Keeps waiting for the active setup's approval; follows account switches. Runs while the app is open. */
    suspend fun awaitClaims(server: String) {
        setups.active.collectLatest { account ->
            refresh()
            while (!setups.current().claimed) {
                val claim = waitClaim(server, setups.current().publicKey)
                if (!claim.isNullOrEmpty()) {
                    setups.saveClaim(account, claim)
                    refresh()
                } else {
                    delay(3_000)
                }
            }
        }
    }

    /** The UI asks the VPN service, which owns the interface, to connect. */
    override fun connect() {
        val i = Intent(context, WantasticVpnService::class.java).setAction(WantasticVpnService.ACTION_CONNECT)
        if (Build.VERSION.SDK_INT >= 26) context.startForegroundService(i) else context.startService(i)
    }

    override fun disconnect() {
        context.startService(Intent(context, WantasticVpnService::class.java).setAction(WantasticVpnService.ACTION_DISCONNECT))
    }

    /** Runs the tunnel inside [service]; returns false (with the reason logged) if it cannot. */
    fun startIn(service: VpnService, server: String): Boolean {
        val setup = setups.current()
        val claim = setup.claim ?: return false.also { Log.w(TAG, "not approved yet") }
        state.update { it.copy(tunnel = TunnelState.Connecting) }
        this.service = service
        this.server = server
        return try {
            tunnel?.stop()
            tunnel = KotlinTunnel.start(service, setup.privateKey, claim, prefs.getString(EXIT_IP, null))
            since = System.currentTimeMillis()
            last = null
            poller?.cancel()
            poller = scope.launch {
                while (true) {
                    poll()
                    delay(2_000)
                }
            }
            true
        } catch (e: Exception) {
            Log.e(TAG, "could not start the tunnel", e)
            state.update { it.copy(tunnel = TunnelState.Disconnected) }
            false
        }
    }

    override fun reconnect() {
        val svc = service ?: return
        val t = state.value.tunnel
        if (t !is TunnelState.Connected && t !is TunnelState.Connecting) return
        routeJob?.cancel()
        routeJob = scope.launch {
            Log.i(TAG, "reconnecting on the active setup")
            poller?.cancel()
            tunnel?.stop()
            tunnel = null
            startIn(svc, server)
        }
    }

    fun stop() {
        routeJob?.cancel()
        poller?.cancel()
        tunnel?.stop()
        tunnel = null
        state.update { it.copy(tunnel = TunnelState.Disconnected, peers = emptyList(), downBitsPerSec = 0, upBitsPerSec = 0, downHistory = emptyList(), upHistory = emptyList()) }
    }

    private fun poll() {
        val k = tunnel ?: return
        val s = k.stats
        val now = System.currentTimeMillis()
        s.p2p?.let { p ->
            val line = "P2P id=${p.id} seen=${p.observed} nat=${p.nat} peers=${p.discovered} ${p.attempts}"
            if (line != lastP2pLine) { lastP2pLine = line; Log.i(TAG, line) } // on change only
        }
        val prev = last
        last = Triple(now, s.rxBytes, s.txBytes)
        val secs = prev?.let { (now - it.first) / 1000.0 }?.takeIf { it > 0 }
        val hubAgo = if (s.lastHandshakeMs > 0) (now - s.lastHandshakeMs) / 1000 else null
        val hubAnswers = hubAgo != null && hubAgo < HUB_HANDSHAKE_FRESH_SEC
        val address = k.config.addresses.firstOrNull()?.address?.hostAddress.orEmpty()
        val direct = s.direct.associateBy { it.vpnIp }
        val exit = s.exit
        state.update {
            val down = if (prev != null && secs != null) ((s.rxBytes - prev.second) * 8 / secs).toLong().coerceAtLeast(0) else 0
            val up = if (prev != null && secs != null) ((s.txBytes - prev.third) * 8 / secs).toLong().coerceAtLeast(0) else 0
            it.copy(
                tunnel = if (hubAnswers) TunnelState.Connected(address, since, k.config.server.endpointHost) else TunnelState.Connecting,
                serverSilent = !hubAnswers && now - since > SERVER_SILENT_AFTER_MS,
                // The network's devices, direct or through the relay (the hub's own
                // state shows on Home, as the connection itself).
                peers = (s.p2p?.peers.orEmpty() + s.direct.map { it.vpnIp }).distinct().map { ip ->
                    val d = direct[ip]
                    val live = d != null && d.lastHandshakeMs > 0 && now - d.lastHandshakeMs < HUB_HANDSHAKE_FRESH_SEC * 1000
                    Peer(
                        name = ip, vpnIp = ip, publicIp = d?.endpoint?.substringBeforeLast(':')?.ifBlank { null },
                        direct = live, latencyMs = null,
                        handshakeAgoSec = d?.lastHandshakeMs?.takeIf { it > 0 }?.let { (now - it) / 1000 },
                        rxBytes = d?.rxBytes ?: 0, txBytes = d?.txBytes ?: 0,
                    )
                },
                exitCandidates = (s.p2p?.peers.orEmpty()).map { ip ->
                    ExitCandidate(name = ip, ip = ip, offersExit = exit?.offers?.get(ip) != false, direct = direct[ip]?.lastHandshakeMs?.let { t -> t > 0 } == true)
                },
                usingExit = exit?.vpnIp,
                exitState = exit?.phase,
                exitNotice = exit?.reason?.ifBlank { null },
                offeringExit = false,
                canShareExit = false, // sharing this phone: a later phase of the engine
                downBitsPerSec = down,
                upBitsPerSec = up,
                downHistory = (it.downHistory + down).takeLast(HISTORY),
                upHistory = (it.upHistory + up).takeLast(HISTORY),
            )
        }
    }

    /** Uses [ip] as this phone's exit node; null goes back to direct internet. Kept across restarts. */
    override fun useExit(ip: String?) {
        prefs.edit().apply { if (ip == null) remove(EXIT_IP) else putString(EXIT_IP, ip) }.apply()
        state.update { it.copy(exitNotice = null, usingExit = ip, exitState = ip?.let { "pending" }) }
        tunnel?.useExit(ip)
    }

    override fun offerExit(on: Boolean) {
        state.update { it.copy(offeringExit = false, exitNotice = "Sharing this phone's internet comes in a later version.") }
    }

    /** Pings a peer through the tunnel (the app is inside the VPN). */
    override suspend fun ping(ip: String): String = withContext(Dispatchers.IO) {
        if (!Regex("""^[0-9a-fA-F:.]+$""").matches(ip)) return@withContext "Not an address"
        runCatching {
            val p = ProcessBuilder("/system/bin/ping", "-c", "4", "-W", "2", ip).redirectErrorStream(true).start()
            val out = p.inputStream.bufferedReader().use { it.readText() }
            p.waitFor()
            val got = Regex("""(\d+) packets transmitted, (\d+) received""").find(out)
            val rtt = Regex("""= [\d.]+/([\d.]+)/[\d.]+/([\d.]+) ms""").find(out)
            val path = if (state.value.peers.any { it.vpnIp == ip && it.direct }) "direct" else "relay"
            when {
                got == null -> "No answer"
                got.groupValues[2] == "0" -> "No reply · $path"
                rtt != null -> "${got.groupValues[2]}/${got.groupValues[1]} · ${rtt.groupValues[1].toDouble().toInt()} ms avg · ${rtt.groupValues[2].toDouble().toInt()} ms jitter · $path"
                else -> "${got.groupValues[2]}/${got.groupValues[1]} · $path"
            }
        }.getOrElse { it.message ?: "Ping failed" }
    }

    companion object {
        private const val TAG = "WantasticEngine"
        private const val EXIT_IP = "exit_ip"
        private const val HUB_HANDSHAKE_FRESH_SEC = 180L
        private const val SERVER_SILENT_AFTER_MS = 15_000L
        /** Two minutes of throughput at one sample every 2 s. */
        private const val HISTORY = 60

        /** One engine per process. */
        fun install(context: Context, setups: DeviceSetups): Engine {
            (Engines.current as? AppEngine)?.let { return it }
            return AppEngine(context.applicationContext, setups).also { Engines.current = it }
        }
    }
}
