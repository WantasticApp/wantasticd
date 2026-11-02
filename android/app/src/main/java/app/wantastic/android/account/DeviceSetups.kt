package app.wantastic.android.account

import android.content.SharedPreferences
import android.util.Base64
import com.google.crypto.tink.subtle.X25519
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import org.json.JSONObject

/**
 * This phone in each account it was added to: its WireGuard key and the
 * account's approval (claim), per account. Switching accounts switches the
 * setup; an account without one asks to add the phone first.
 *
 * [UNBOUND] is a key made before any account was known (the QR/link claim):
 * once an account's device list shows its key, it belongs to that account.
 * Everything lives in the encrypted identity preferences.
 */
class DeviceSetups(private val prefs: SharedPreferences) {

    data class Setup(val account: String, val privateKey: String, val publicKey: String, val claim: String?) {
        val claimed get() = claim != null
    }

    private val all = MutableStateFlow(load())
    private val activeId = MutableStateFlow(prefs.getString(ACTIVE, null) ?: all.value.keys.firstOrNull() ?: UNBOUND)

    /** The setup in use: the active account's, else the unbound one. */
    val active: StateFlow<String> = activeId.asStateFlow()

    fun current(): Setup = all.value[activeId.value] ?: ensure(activeId.value)

    fun forAccount(account: String): Setup? = all.value[account]

    fun accounts(): Set<String> = all.value.keys

    /** The setup for [account], made (with a new key) when there is none. */
    fun ensure(account: String): Setup = all.value[account] ?: run {
        val private = X25519.generatePrivateKey()
        Setup(account, enc(private), enc(X25519.publicFromPrivate(private)), null).also { put(it) }
    }

    fun activate(account: String) {
        ensure(account)
        activeId.value = account
        prefs.edit().putString(ACTIVE, account).apply()
    }

    fun saveClaim(account: String, claim: String) = put(ensure(account).copy(claim = claim))

    /** The unbound key turned out to be in [account]: it becomes that account's setup. */
    fun bindUnbound(account: String) {
        val unbound = all.value[UNBOUND] ?: return
        val next = all.value - UNBOUND + (account to unbound.copy(account = account))
        save(next)
        if (activeId.value == UNBOUND) activate(account)
    }

    private fun put(setup: Setup) = save(all.value + (setup.account to setup))

    private fun save(map: Map<String, Setup>) {
        val json = JSONObject()
        map.values.forEach { s ->
            json.put(s.account, JSONObject().put("private", s.privateKey).put("public", s.publicKey).apply { s.claim?.let { put("claim", it) } })
        }
        prefs.edit().putString(SETUPS, json.toString()).apply()
        all.value = map
    }

    private fun load(): Map<String, Setup> {
        prefs.getString(SETUPS, null)?.let { raw ->
            val json = JSONObject(raw)
            return json.keys().asSequence().associateWith { k ->
                val o = json.getJSONObject(k)
                Setup(k, o.getString("private"), o.getString("public"), o.optString("claim").ifBlank { null })
            }
        }
        // Before accounts: the one key (and claim) becomes the unbound setup.
        val priv = prefs.getString(LEGACY_PRIVATE, null)
        val pub = prefs.getString(LEGACY_PUBLIC, null)
        if (priv != null && pub != null) {
            val legacy = Setup(UNBOUND, priv, pub, prefs.getString(LEGACY_CLAIM, null))
            val json = JSONObject().put(UNBOUND, JSONObject().put("private", priv).put("public", pub).apply { legacy.claim?.let { put("claim", it) } })
            prefs.edit().putString(SETUPS, json.toString()).apply()
            return mapOf(UNBOUND to legacy)
        }
        return emptyMap()
    }

    companion object {
        const val UNBOUND = ""
        private const val SETUPS = "device_setups"
        private const val ACTIVE = "active_setup"
        private const val LEGACY_PRIVATE = "private_key"
        private const val LEGACY_PUBLIC = "public_key"
        private const val LEGACY_CLAIM = "claim_config"

        private fun enc(b: ByteArray) = Base64.encodeToString(b, Base64.NO_WRAP)
    }
}
