package app.wantastic.android.engine

import android.content.Context
import android.util.Log
import app.wantastic.android.account.DeviceSetups
import app.wantastic.mobile.Mobile
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.withContext

/**
 * The Go engine (the agent's own code, built with gomobile). So far it does
 * the claim: it waits for the active account's approval of this phone's key
 * for that account, and follows account switches. The tunnel itself comes
 * next, so connecting still reports unavailable.
 */
class GoEngine private constructor(private val setups: DeviceSetups) : Engine {
    private val state = MutableStateFlow(EngineStatus(claimed = setups.current().claimed))
    override val status: StateFlow<EngineStatus> = state.asStateFlow()

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

    override fun connect() = Unit
    override fun disconnect() = Unit
    override fun useExit(ip: String?) = Unit
    override fun offerExit(on: Boolean) = Unit

    companion object {
        private const val TAG = "WantasticEngine"

        /** Loads the engine once per process; stays unavailable if the native part can't load. */
        fun install(context: Context, setups: DeviceSetups): Engine {
            (Engines.current as? GoEngine)?.let { return it }
            return runCatching {
                Mobile.init(context.filesDir.resolve("engine").path)
                GoEngine(setups).also { Engines.current = it }
            }.onFailure { Log.e(TAG, "engine unavailable", it) }.getOrDefault(Engines.current)
        }
    }
}
