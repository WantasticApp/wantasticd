package app.wantastic.android.account

import android.util.Log
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

/** Who is signed in, and whether this phone is set up in that account. */
sealed interface AccountState {
    data object Checking : AccountState
    data object SignedOut : AccountState
    /** [needsSetup]: this account has no setup for this phone yet; ask before adding it. */
    data class SignedIn(val tenantId: String, val email: String, val accounts: List<Account>, val needsSetup: Boolean) : AccountState
    /** Wantastic could not be reached; the saved setups still work. */
    data class Offline(val message: String) : AccountState
}

/**
 * Keeps the app, the console mini app and this phone's setups in step. The
 * session is the WebView's, so a sign-in or account switch in either place
 * is the same; [sync] runs on start, after the console closes and after any
 * native sign-in or switch, and moves the phone to that account's setup.
 */
class AccountSync(val client: AccountClient, private val setups: DeviceSetups, private val onSetupChanged: () -> Unit) {
    private val state = MutableStateFlow<AccountState>(AccountState.Checking)
    val account: StateFlow<AccountState> = state.asStateFlow()
    private val lock = Mutex()

    suspend fun sync() = lock.withLock {
        try {
            val tenant = client.activeTenant()
            if (tenant == null) {
                state.value = AccountState.SignedOut
                Log.i(TAG, "signed out")
                return@withLock
            }
            val accounts = runCatching { client.accounts() }.getOrDefault(emptyList())
            val email = accounts.firstOrNull { it.active }?.email ?: runCatching { client.me().optString("email") }.getOrDefault("")
            val own = setups.forAccount(tenant)
            // The device list, fetched only when needed.
            var fetched = false
            var list: org.json.JSONArray? = null
            suspend fun peers(): org.json.JSONArray? {
                if (!fetched) { list = runCatching { client.peers() }.getOrNull(); fetched = true }
                return list
            }
            val ready = when {
                own?.claimed == true -> { setups.activate(tenant); true }
                // Added, approval on its way: the engine picks it up.
                own != null && inPeers(peers(), own.publicKey) -> { setups.activate(tenant); true }
                setups.forAccount(DeviceSetups.UNBOUND)?.let { it.claimed && inPeers(peers(), it.publicKey) } == true -> {
                    setups.bindUnbound(tenant); true
                }
                else -> false
            }
            if (ready) onSetupChanged()
            state.value = AccountState.SignedIn(tenant, email, accounts, needsSetup = !ready)
            Log.i(TAG, "signed in; ${accounts.size} account(s); setup ${if (ready) "ready" else "needed"}")
        } catch (e: Exception) {
            Log.w(TAG, "account sync", e)
            state.value = AccountState.Offline(e.message ?: "Offline")
        }
    }

    private fun inPeers(peers: org.json.JSONArray?, publicKey: String): Boolean =
        peers != null && (0 until peers.length()).any { peers.getJSONObject(it).optString("public_key") == publicKey }

    /**
     * Adds this phone to the active account with a key of its own, as the
     * console's Claim button does, and switches to that setup. The engine
     * then fetches the approval and connects.
     */
    suspend fun addThisPhone(name: String) {
        val s = state.value as? AccountState.SignedIn ?: return
        val setup = setups.ensure(s.tenantId)
        if (!inPeers(runCatching { client.peers() }.getOrNull(), setup.publicKey)) client.claimDevice(name, setup.publicKey)
        setups.activate(s.tenantId)
        onSetupChanged()
        state.value = s.copy(needsSetup = false)
    }

    suspend fun switchTo(slot: Int) {
        client.switchTo(slot)
        sync()
    }

    suspend fun signOut() {
        client.signOut(all = false)
        sync()
    }

    companion object {
        private const val TAG = "WantasticAccount"
    }
}
