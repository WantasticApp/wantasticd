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

        private val claimJson get() = claim?.let { runCatching { JSONObject(it) }.getOrNull() }

        /** This phone's address in that network, once approved. */
        val address: String? get() = claimJson?.optString("assigned_ip")?.substringBefore('/')?.ifBlank { null }

        /** The network's address range: the allowed prefix holding [address]. */
        val network: String? get() {
            val prefixes = claimJson?.optJSONArray("allowed_ips")?.let { a ->
                (0 until a.length()).map { a.optString(it) }.filter { it.contains('/') && it != "0.0.0.0/0" && it != "::/0" }
            } ?: return null
            val ip = address?.let(::ipv4) ?: return prefixes.firstOrNull()
            return prefixes.firstOrNull { p ->
                val base = ipv4(p.substringBefore('/'))
                val bits = p.substringAfter('/').toIntOrNull()
                base != null && bits != null && bits in 0..32 &&
                    (bits == 0 || (ip xor base) ushr (32 - bits) == 0L)
            } ?: prefixes.firstOrNull()
        }
    }

    private val all = MutableStateFlow(load())
    private val activeId = MutableStateFlow(prefs.getString(ACTIVE, null) ?: all.value.keys.firstOrNull() ?: UNBOUND)

    /** The setup in use: the active account's, else the unbound one. */
    val active: StateFlow<String> = activeId.asStateFlow()

    fun current(): Setup = all.value[activeId.value] ?: ensure(activeId.value)

    fun forAccount(account: String): Setup? = all.value[account]

    fun accounts(): Set<String> = all.value.keys

    /** Every saved setup, by account. */
    val setups: StateFlow<Map<String, Setup>> = all.asStateFlow()

    /**
     * Deletes [account]'s setup (key and approval) from this phone. The active
     * one hands over to another approved setup, if there is one.
     */
    fun remove(account: String) {
        if (account !in all.value) return
        val rest = all.value - account
        save(rest)
        if (activeId.value == account) {
            val next = rest.values.firstOrNull { it.claimed }?.account ?: rest.keys.firstOrNull() ?: UNBOUND
            activeId.value = next
            prefs.edit().putString(ACTIVE, next).apply()
        }
    }

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

        /** A dotted IPv4 address as an unsigned 32-bit number, or null. */
        internal fun ipv4(s: String): Long? {
            val parts = s.trim().split('.')
            if (parts.size != 4) return null
            return parts.fold(0L) { acc, p -> (acc shl 8) or (p.toIntOrNull()?.takeIf { it in 0..255 } ?: return null).toLong() }
        }
    }
}
