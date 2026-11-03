package app.wantastic.android.engine

import android.content.Context
import android.util.Log
import app.wantastic.android.account.DeviceSetups
import app.wantastic.android.settings.AppSettings
import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.Build
import app.wantastic.android.MainActivity
import app.wantastic.android.vpn.WantasticVpnService
import app.wantastic.mobile.Mobile
import app.wantastic.mobile.Tunnel
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import org.json.JSONObject
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.withContext

/**
 * The Go engine: the desktop agent's own code (gomobile). It waits for the
 * active account's approval of this phone, builds the agent config from it,
 * and runs the tunnel on the interface the VPN service provides. Status
 * comes from the agent's local API, called in-process.
 */
class GoEngine private constructor(private val context: Context, private val setups: DeviceSetups) : Engine {
    private val state = MutableStateFlow(initial())
    override val status: StateFlow<EngineStatus> = state.asStateFlow()
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var poller: Job? = null
    private var since = 0L
    private var last: Triple<Long, Long, Long>? = null // time, rx, tx
    private var service: VpnService? = null
    private var server = ""
    @Volatile private var fullTunnel = false
    private var routeJob: Job? = null

    private fun initial() = EngineStatus(claimed = setups.current().claimed, tunnel = TunnelState.Disconnected)

    /** Re-reads the active setup (after a sign-in, switch or add). */
    fun refresh() = state.update { it.copy(claimed = setups.current().claimed) }

    /** Keeps waiting for the active setup's approval; follows account switches. Runs while the app is open. */
    suspend fun awaitClaims(server: String) {
        setups.active.collectLatest { account ->
            refresh()
            while (!setups.current().claimed) {
                val key = setups.current().publicKey
                val claim = withContext(Dispatchers.IO) {
                    runCatching { Mobile.waitClaim(server, key, 30) }
                        .onFailure { Log.w(TAG, "claim check: ${it.message}") }
                        .getOrNull()
                }
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
    /** The Kotlin engine's tunnel while it runs (Settings: Kotlin engine). */
    @Volatile private var kotlin: KotlinTunnel? = null

    fun startIn(service: VpnService, server: String): Boolean {
        val setup = setups.current()
        val claim = setup.claim ?: return false.also { Log.w(TAG, "not approved yet") }
        state.update { it.copy(tunnel = TunnelState.Connecting) }
        this.service = service
        this.server = server
        if (AppSettings.get(context).kotlinEngine.value) return startKotlin(service, setup.privateKey, claim)
        return try {
            val config = Mobile.configFromClaim(server, setup.privateKey, setup.publicKey, claim)
            report()
            Mobile.start(config, VpnTunnel(service, fullTunnel, ::defaultRoute))
            protected.clear()
            protectSockets()
            since = System.currentTimeMillis()
            last = null
            poller?.cancel()
            poller = scope.launch {
                var n = 0
                while (true) {
                    protectSockets() // new sockets after a network change
                    poll()
                    if (++n % 30 == 0) report() // the console's device view, once a minute
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

    /**
     * The agent wants the internet in the tunnel (an exit node is carrying it)
     * or not. Android cannot change a live VPN's routes, so the tunnel restarts
     * with the new routes; the agent keeps the exit choice across it. Settled
     * changes only: a brief flap does not restart anything.
     */
    private fun defaultRoute(on: Boolean) {
        routeJob?.cancel()
        routeJob = scope.launch {
            delay(1_500)
            if (on == fullTunnel) return@launch
            fullTunnel = on
            val svc = service ?: return@launch
            Log.i(TAG, if (on) "internet through the exit node" else "internet direct")
            poller?.cancel()
            runCatching { Mobile.stop() }
            startIn(svc, server)
        }
    }

    private fun startKotlin(service: VpnService, privateKey: String, claim: String): Boolean = try {
        kotlin?.stop()
        kotlin = KotlinTunnel.start(service, privateKey, claim)
        since = System.currentTimeMillis()
        last = null
        poller?.cancel()
        poller = scope.launch {
            while (true) {
                pollKotlin()
                delay(2_000)
            }
        }
        true
    } catch (e: Exception) {
        Log.e(TAG, "could not start the Kotlin engine", e)
        state.update { it.copy(tunnel = TunnelState.Disconnected) }
        false
    }

    /** Status from the Kotlin engine: the hub only, until P2P lands (phase 2). */
    private fun pollKotlin() {
        val k = kotlin ?: return
        val s = k.stats
        val now = System.currentTimeMillis()
        val prev = last
        last = Triple(now, s.rxBytes, s.txBytes)
        val secs = prev?.let { (now - it.first) / 1000.0 }?.takeIf { it > 0 }
        val hubAgo = if (s.lastHandshakeMs > 0) (now - s.lastHandshakeMs) / 1000 else null
        val hubAnswers = hubAgo != null && hubAgo < HUB_HANDSHAKE_FRESH_SEC
        val address = k.config.addresses.firstOrNull()?.address?.hostAddress.orEmpty()
        state.update {
            val down = if (prev != null && secs != null) ((s.rxBytes - prev.second) * 8 / secs).toLong().coerceAtLeast(0) else 0
            val up = if (prev != null && secs != null) ((s.txBytes - prev.third) * 8 / secs).toLong().coerceAtLeast(0) else 0
            it.copy(
                tunnel = if (hubAnswers) TunnelState.Connected(address, since, k.config.server.endpointHost) else TunnelState.Connecting,
                serverSilent = !hubAnswers && now - since > SERVER_SILENT_AFTER_MS,
                peers = listOf(
                    Peer(
                        name = "Wantastic hub · Kotlin engine", vpnIp = "", publicIp = s.endpoint?.substringBeforeLast(':'),
                        direct = false, latencyMs = null, handshakeAgoSec = hubAgo, rxBytes = s.rxBytes, txBytes = s.txBytes,
                    ),
                ),
                downBitsPerSec = down,
                upBitsPerSec = up,
                downHistory = (it.downHistory + down).takeLast(HISTORY),
                upHistory = (it.upHistory + up).takeLast(HISTORY),
            )
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
            runCatching { Mobile.stop() }
            kotlin?.stop()
            kotlin = null
            startIn(svc, server)
        }
    }

    fun stop() {
        routeJob?.cancel()
        poller?.cancel()
        kotlin?.stop()
        kotlin = null
        runCatching { Mobile.stop() }
        state.update { it.copy(tunnel = TunnelState.Disconnected, peers = emptyList(), downBitsPerSec = 0, upBitsPerSec = 0, downHistory = emptyList(), upHistory = emptyList()) }
    }

    private val protected = mutableSetOf<Int>()

    /** WireGuard's own UDP sockets must never be routed into the tunnel they carry. */
    private fun protectSockets() {
        val svc = service ?: return
        val fds = runCatching { Mobile.socketFDs() }.getOrDefault("").split(',').mapNotNull { it.trim().toIntOrNull() }
        for (fd in fds) {
            if (fd !in protected && svc.protect(fd)) protected += fd
        }
        protected.retainAll(fds.toSet())
    }

    private fun report() {
        runCatching { Mobile.setDeviceInfo(DeviceReport.read(context)) }.onFailure { Log.w(TAG, "device report: ${it.message}") }
    }

    private fun poll() {
        val json = runCatching { JSONObject(Mobile.api("GET", "/api/status", "")) }.getOrNull() ?: return
        val now = System.currentTimeMillis()
        val rx = json.optLong("rx_bytes"); val tx = json.optLong("tx_bytes")
        val prev = last
        last = Triple(now, rx, tx)
        val secs = prev?.let { (now - it.first) / 1000.0 }?.takeIf { it > 0 }
        val peers = json.optJSONArray("peers")?.let { arr ->
            (0 until arr.length()).map { arr.getJSONObject(it) }.map { p ->
                val handshake = p.optLong("last_handshake")
                Peer(
                    // The hub has no address in the peer table: name it.
                    name = p.optString("hostname").ifBlank { p.optString("assigned_ip") }.ifBlank { "Wantastic hub" },
                    vpnIp = p.optString("assigned_ip"),
                    publicIp = p.optString("endpoint").substringBeforeLast(':').ifBlank { null },
                    // is_p2p only says the peer can go direct; an established
                    // P2P state with a handshake says it does (as `wantasticd peers`).
                    direct = p.optString("p2p_state") == "established" && handshake > 0,
                    latencyMs = null,
                    handshakeAgoSec = if (handshake > 0) now / 1000 - handshake else null,
                    rxBytes = p.optLong("rx_bytes"),
                    txBytes = p.optLong("tx_bytes"),
                )
            }
        }.orEmpty()
        val address = json.optJSONArray("ips")?.optString(0)?.substringBefore('/').orEmpty()
        val exit = json.optJSONObject("exit_node_state")
        val using = exit?.optJSONObject("using")
        val candidates = exit?.optJSONArray("candidates")?.let { arr ->
            (0 until arr.length()).map { arr.getJSONObject(it) }.map { c ->
                ExitCandidate(
                    name = c.optString("hostname").ifBlank { c.optString("ip") },
                    ip = c.optString("ip"),
                    offersExit = c.optString("offers") != "no" && c.optBoolean("online", true),
                    direct = c.optString("path") == "direct",
                )
            }
        }.orEmpty()
        // Connected means the hub answers: a recent handshake with it (WireGuard
        // rekeys every 2 minutes), not only that the interface is up.
        val hubAgo = peers.firstOrNull { it.vpnIp.isBlank() }?.handshakeAgoSec
        val running = json.optBoolean("device_running")
        val hubAnswers = hubAgo != null && hubAgo < HUB_HANDSHAKE_FRESH_SEC
        state.update {
            it.copy(
                tunnel = if (running && hubAnswers) TunnelState.Connected(address, since, json.optString("server_endpoint").substringBefore(':').ifBlank { "Wantastic" })
                else TunnelState.Connecting,
                serverSilent = running && !hubAnswers && now - since > SERVER_SILENT_AFTER_MS,
                peers = peers,
                exitCandidates = candidates,
                usingExit = using?.optString("ip")?.ifBlank { null },
                exitState = using?.optString("state"),
                offeringExit = exit?.optBoolean("offering") == true,
                canShareExit = exit?.optBoolean("supported") == true,
                exitNotice = using?.optString("reason")?.ifBlank { null } ?: exit?.optString("offer_error")?.ifBlank { null } ?: it.exitNotice,
                downHistory = (it.downHistory + (secs?.let { s -> ((rx - prev.second).coerceAtLeast(0) * 8 / s).toLong() } ?: 0)).takeLast(HISTORY),
                upHistory = (it.upHistory + (secs?.let { s -> ((tx - prev.third).coerceAtLeast(0) * 8 / s).toLong() } ?: 0)).takeLast(HISTORY),
                downBitsPerSec = secs?.let { s -> ((rx - prev.second).coerceAtLeast(0) * 8 / s).toLong() } ?: 0,
                upBitsPerSec = secs?.let { s -> ((tx - prev.third).coerceAtLeast(0) * 8 / s).toLong() } ?: 0,
            )
        }
    }

    /** Uses [ip] as this phone's exit node; null goes back to direct internet. */
    override fun useExit(ip: String?) {
        state.update { it.copy(exitNotice = null, usingExit = ip, exitState = ip?.let { "pending" }) }
        scope.launch {
            control(if (ip == null) "/api/exitnode/comeback" else "/api/exitnode/jumpto?wait=0&ip=" + java.net.URLEncoder.encode(ip, "UTF-8"))
            poll()
        }
    }

    /** Shares (or stops sharing) this phone's internet with the network's devices. */
    override fun offerExit(on: Boolean) {
        Log.i(TAG, "share this phone: $on")
        state.update { it.copy(exitNotice = null, offeringExit = on) }
        scope.launch {
            control("/api/exitnode/offer?enabled=" + if (on) "on" else "off")
            poll()
        }
    }

    override suspend fun ping(ip: String): String = withContext(Dispatchers.IO) {
        runCatching {
            val r = JSONObject(Mobile.api("GET", "/api/ping?count=4&target=" + java.net.URLEncoder.encode(ip, "UTF-8"), ""))
            val res = r.optJSONArray("results")?.optJSONObject(0) ?: return@runCatching r.optString("error").ifBlank { "No answer" }
            val got = res.optInt("received"); val sent = res.optInt("sent")
            if (got == 0) "No reply · ${res.optString("path")}"
            else "%d/%d · %.0f ms avg · %.0f ms jitter · %s".format(got, sent, res.optDouble("avg_ms"), res.optDouble("jitter_ms"), res.optString("path"))
        }.getOrElse { it.message ?: "Ping failed" }
    }

    private fun control(path: String) {
        runCatching { Mobile.api("POST", path, "") }.onFailure { e ->
            val msg = e.message.orEmpty().let { runCatching { JSONObject(it).optString("error") }.getOrNull()?.ifBlank { null } ?: it }
            state.update { it.copy(exitNotice = msg.ifBlank { "That did not work" }) }
        }
    }

    /** Builds the Android interface the engine asks for and hands over its descriptor. */
    private class VpnTunnel(
        private val service: VpnService,
        private val full: Boolean,
        private val onDefaultRoute: (Boolean) -> Unit,
    ) : Tunnel {
        override fun defaultRoute(on: Boolean) = onDefaultRoute(on)

        override fun open(mtu: Long, addresses: String, routes: String, dns: String): Long {
            val b = service.Builder()
                .setSession("Wantastic")
                .setMtu(mtu.toInt())
                .setConfigureIntent(
                    PendingIntent.getActivity(service, 0, Intent(service, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE),
                )
            fun prefixes(list: String) = list.split(',').map { it.trim() }.filter { it.contains('/') }
            prefixes(addresses).forEach { b.addAddress(it.substringBefore('/'), it.substringAfter('/').toInt()) }
            prefixes(routes).forEach { b.addRoute(it.substringBefore('/'), it.substringAfter('/').toInt()) }
            val servers = dns.split(',').map { it.trim() }.filter { it.isNotEmpty() }.toMutableList()
            if (full) {
                // Everything through the exit node; IPv6 stays off so it cannot leak around it.
                b.addRoute("0.0.0.0", 0)
                b.addRoute("::", 0)
                // The local network's resolver is not reachable from the exit node.
                if (servers.isEmpty()) servers += listOf("1.1.1.1", "8.8.8.8")
            }
            servers.forEach { runCatching { b.addDnsServer(it) } }
            // The app itself is in the tunnel (peer tools, browser); only WireGuard's
            // own sockets are protected out of it (see protectSockets).
            if (Build.VERSION.SDK_INT >= 29) b.setMetered(false)
            val fd = b.establish() ?: throw IllegalStateException("Android did not allow the VPN")
            return fd.detachFd().toLong()
        }
    }

    companion object {
        private const val TAG = "WantasticEngine"
        private const val HUB_HANDSHAKE_FRESH_SEC = 180L
        private const val SERVER_SILENT_AFTER_MS = 15_000L
        /** Two minutes of throughput at one sample every 2 s. */
        private const val HISTORY = 60

        /** Loads the engine once per process; stays unavailable if the native part can't load. */
        fun install(context: Context, setups: DeviceSetups): Engine {
            (Engines.current as? GoEngine)?.let { return it }
            return runCatching {
                Mobile.init(context.filesDir.resolve("engine").path)
                GoEngine(context.applicationContext, setups).also { Engines.current = it }
            }.onFailure { Log.e(TAG, "engine unavailable", it) }.getOrDefault(Engines.current)
        }
    }
}
