package app.wantastic.android.settings

import android.content.Context
import android.content.SharedPreferences
import android.provider.Settings
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/** The app's own preferences (nothing secret: keys and claims live in ClaimKey). */
class AppSettings private constructor(private val prefs: SharedPreferences, systemAnimations: Boolean) {

    private val _autoUpdate = MutableStateFlow(prefs.getBoolean(AUTO_UPDATE, true))
    /** Download and install updates by themselves (direct build). */
    val autoUpdate: StateFlow<Boolean> = _autoUpdate.asStateFlow()

    private val _wifiOnly = MutableStateFlow(prefs.getBoolean(WIFI_ONLY, true))
    /** Download updates only on unmetered networks. */
    val wifiOnly: StateFlow<Boolean> = _wifiOnly.asStateFlow()

    // Off by default when the system has animations turned off.
    private val _motion = MutableStateFlow(prefs.getBoolean(MOTION, systemAnimations))
    /** Drifting light and tilt-following glass. */
    val motion: StateFlow<Boolean> = _motion.asStateFlow()

    fun setAutoUpdate(on: Boolean) = put(AUTO_UPDATE, on) { _autoUpdate.value = it }
    fun setWifiOnly(on: Boolean) = put(WIFI_ONLY, on) { _wifiOnly.value = it }
    fun setMotion(on: Boolean) = put(MOTION, on) { _motion.value = it }


    var lastUpdateCheck: Long
        get() = prefs.getLong(LAST_CHECK, 0L)
        set(value) = prefs.edit().putLong(LAST_CHECK, value).apply()

    private fun put(key: String, on: Boolean, publish: (Boolean) -> Unit) {
        prefs.edit().putBoolean(key, on).apply()
        publish(on)
    }

    companion object {
        private const val AUTO_UPDATE = "auto_update"
        private const val WIFI_ONLY = "update_wifi_only"
        private const val MOTION = "motion"
        private const val LAST_CHECK = "last_update_check"

        @Volatile
        private var instance: AppSettings? = null

        fun get(context: Context): AppSettings = instance ?: synchronized(this) {
            instance ?: run {
                val app = context.applicationContext
                val scale = Settings.Global.getFloat(app.contentResolver, Settings.Global.ANIMATOR_DURATION_SCALE, 1f)
                AppSettings(app.getSharedPreferences("wantastic_settings", Context.MODE_PRIVATE), scale > 0f)
                    .also { instance = it }
            }
        }
    }
}
