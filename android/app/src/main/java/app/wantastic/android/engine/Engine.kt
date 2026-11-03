package app.wantastic.android.engine

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/** What the tunnel is doing right now. */
sealed interface TunnelState {
    /** No engine in this build yet: the screens say so instead of pretending. */
    data object EngineUnavailable : TunnelState
    data object Disconnected : TunnelState
    data object Connecting : TunnelState
    data class Connected(val address: String, val sinceMillis: Long, val hub: String) : TunnelState
}

data class Peer(
    val name: String,
    val vpnIp: String,
    val publicIp: String?,
    val direct: Boolean,
    val latencyMs: Int?,
    val handshakeAgoSec: Long?,
    val rxBytes: Long,
    val txBytes: Long,
    val online: Boolean = true,
    /** This phone itself, in the account's device list. */
    val self: Boolean = false,
)

data class ExitCandidate(val name: String, val ip: String, val offersExit: Boolean, val direct: Boolean)

data class EngineStatus(
    val tunnel: TunnelState = TunnelState.EngineUnavailable,
    val claimed: Boolean = false,
    val peers: List<Peer> = emptyList(),
    val exitCandidates: List<ExitCandidate> = emptyList(),
    val usingExit: String? = null,
    val offeringExit: Boolean = false,
    val downBitsPerSec: Long = 0,
    val upBitsPerSec: Long = 0,
    /** Recent throughput, oldest first, for the home graphs. */
    val downHistory: List<Long> = emptyList(),
    val upHistory: List<Long> = emptyList(),
    /** pending | active | standby while an exit node is chosen. */
    val exitState: String? = null,
    /** The last exit-node problem, in words (e.g. "that device does not share"). */
    val exitNotice: String? = null,
    /** Whether this phone can share its internet as an exit node. */
    val canShareExit: Boolean = false,
)

/**
 * The networking core behind the screens: WireGuard with Wantastic's P2P,
 * WUSP and exit-node extensions. The UI only talks to this interface, so the
 * engine can be swapped without touching any screen.
 */
interface Engine {
    val status: StateFlow<EngineStatus>
    fun connect()
    fun disconnect()
    /** null stops using an exit node. */
    fun useExit(ip: String?)
    fun offerExit(on: Boolean)
    /** Pings a peer through the tunnel; a short line for the person ("4/4 · 23 ms"). */
    suspend fun ping(ip: String): String = "Not connected"
    /** Restarts a running tunnel on the active setup (after an account switch). */
    fun reconnect() = Unit
}

/** Stands in until the engine lands: everything reports "not available". */
object UnavailableEngine : Engine {
    private val state = MutableStateFlow(EngineStatus())
    override val status: StateFlow<EngineStatus> = state.asStateFlow()
    override fun connect() = Unit
    override fun disconnect() = Unit
    override fun useExit(ip: String?) = Unit
    override fun offerExit(on: Boolean) = Unit
}

object Engines {
    @Volatile
    var current: Engine = UnavailableEngine
}
