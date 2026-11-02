package app.wantastic.android.engine

import android.content.Context
import android.util.Log
import app.wantastic.android.claim.ClaimKey
import app.wantastic.mobile.Mobile
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.withContext

/**
 * The Go engine (the agent's own code, built with gomobile). So far it does
 * the claim: the console approves this phone's key and the engine notices.
 * The tunnel itself comes next, so connecting still reports unavailable.
 */
class GoEngine private constructor(private val identity: ClaimKey) : Engine {
    private val state = MutableStateFlow(EngineStatus(claimed = identity.claim() != null))
    override val status: StateFlow<EngineStatus> = state.asStateFlow()

    /** Waits until the console approves [publicKey]; returns at once if already claimed. */
    suspend fun awaitClaim(server: String, publicKey: String) {
        while (!state.value.claimed) {
            val claim = withContext(Dispatchers.IO) {
                runCatching { Mobile.waitClaim(server, publicKey, 30) }
                    .onFailure { Log.w(TAG, "claim check: ${it.message}") }
                    .getOrNull()
            }
            if (!claim.isNullOrEmpty()) {
                identity.saveClaim(claim)
                state.update { it.copy(claimed = true) }
            } else {
                delay(3_000)
            }
        }
    }

    override fun connect() = Unit
    override fun disconnect() = Unit
    override fun useExit(ip: String?) = Unit
    override fun offerExit(on: Boolean) = Unit

    companion object {
        private const val TAG = "WantasticEngine"

        /** Loads the engine once per process; stays unavailable if the native part can't load. */
        fun install(context: Context, identity: ClaimKey): Engine {
            (Engines.current as? GoEngine)?.let { return it }
            return runCatching {
                Mobile.init(context.filesDir.resolve("engine").path)
                GoEngine(identity).also { Engines.current = it }
            }.onFailure { Log.e(TAG, "engine unavailable", it) }.getOrDefault(Engines.current)
        }
    }
}
