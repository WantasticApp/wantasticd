package app.wantastic.android.claim

import android.content.Context
import android.content.SharedPreferences
import android.os.Build
import android.provider.Settings
import android.util.Base64
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import com.google.crypto.tink.subtle.X25519

/**
 * This phone's WireGuard key, made on the phone and never sent anywhere: the
 * console approves the device by its public key (the genkey claim flow).
 * Kept in preferences encrypted with a key from the Android Keystore.
 */
class ClaimKey(private val prefs: SharedPreferences) {

    data class KeyPair(val privateKey: String, val publicKey: String)

    fun loadOrCreate(): KeyPair {
        val priv = prefs.getString(PRIVATE, null)
        val pub = prefs.getString(PUBLIC, null)
        if (priv != null && pub != null) return KeyPair(priv, pub)
        val privateBytes = X25519.generatePrivateKey()
        val publicBytes = X25519.publicFromPrivate(privateBytes)
        val pair = KeyPair(encode(privateBytes), encode(publicBytes))
        prefs.edit().putString(PRIVATE, pair.privateKey).putString(PUBLIC, pair.publicKey).apply()
        return pair
    }

    companion object {
        private const val PRIVATE = "private_key"
        private const val PUBLIC = "public_key"

        private fun encode(b: ByteArray) = Base64.encodeToString(b, Base64.NO_WRAP)

        fun open(context: Context): ClaimKey {
            val master = MasterKey.Builder(context).setKeyScheme(MasterKey.KeyScheme.AES256_GCM).build()
            val prefs = EncryptedSharedPreferences.create(
                context, "wantastic_identity", master,
                EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
                EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
            )
            return ClaimKey(prefs)
        }

        /** The name the owner gave the phone, else its model. */
        fun deviceName(context: Context): String {
            val named = if (Build.VERSION.SDK_INT >= 25) {
                Settings.Global.getString(context.contentResolver, Settings.Global.DEVICE_NAME)
            } else null
            return named?.takeIf { it.isNotBlank() } ?: Build.MODEL
        }
    }
}
