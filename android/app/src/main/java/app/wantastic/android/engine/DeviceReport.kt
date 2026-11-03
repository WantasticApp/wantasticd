package app.wantastic.android.engine

import android.app.ActivityManager
import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.wifi.WifiInfo
import android.net.wifi.WifiManager
import android.os.Build
import android.os.SystemClock
import android.provider.Settings
import app.wantastic.android.claim.ClaimKey
import org.json.JSONObject
import java.util.TimeZone

/**
 * This phone as the console's WUSP view shows it, read through Android's own
 * APIs (an app cannot read the system files the Linux collectors use). No
 * extra permission: the Wi-Fi name and BSSID stay hidden without location
 * access, so they are left out rather than asked for.
 */
object DeviceReport {
    fun read(context: Context): String {
        val o = JSONObject()
            .put("manufacturer", Build.MANUFACTURER.replaceFirstChar { it.uppercase() })
            .put("model_name", Build.MODEL)
            .put("model_number", Build.DEVICE)
            .put("hardware_version", Build.HARDWARE)
            .put("software_version", "Android ${Build.VERSION.RELEASE} (API ${Build.VERSION.SDK_INT})")
            .put("description", "Android ${Build.VERSION.RELEASE} · ${Build.DISPLAY}")
            .put("hostname", ClaimKey.deviceName(context))
            .put("architecture", Build.SUPPORTED_ABIS.firstOrNull().orEmpty())
            .put("uptime_seconds", SystemClock.elapsedRealtime() / 1000)
            .put("time_zone", TimeZone.getDefault().id)
            .put("auto_time", Settings.Global.getInt(context.contentResolver, Settings.Global.AUTO_TIME, 1) == 1)
        if (Build.VERSION.SDK_INT >= 31) o.put("processor_model", listOf(Build.SOC_MANUFACTURER, Build.SOC_MODEL).filter { it.isNotBlank() && it != Build.UNKNOWN }.joinToString(" "))
        context.getSystemService(ActivityManager::class.java)?.let { am ->
            val m = ActivityManager.MemoryInfo().also(am::getMemoryInfo)
            o.put("mem_total_kib", m.totalMem / 1024).put("mem_free_kib", m.availMem / 1024)
        }
        wifi(context)?.let { o.put("wifi", it) }
        return o.toString()
    }

    /** The Wi-Fi link, if the phone is on Wi-Fi (looked up beneath the VPN). */
    private fun wifi(context: Context): JSONObject? {
        val cm = context.getSystemService(ConnectivityManager::class.java) ?: return null
        @Suppress("DEPRECATION")
        val caps = cm.allNetworks.mapNotNull { cm.getNetworkCapabilities(it) }
            .firstOrNull { it.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) } ?: return null
        val info: WifiInfo = (if (Build.VERSION.SDK_INT >= 29) caps.transportInfo as? WifiInfo else null)
            ?: @Suppress("DEPRECATION") context.applicationContext.getSystemService(WifiManager::class.java)?.connectionInfo
            ?: return null
        val w = JSONObject().put("connected", true)
        if (info.rssi in -120..0) w.put("rssi", info.rssi)
        val f = info.frequency
        when (f) {
            in 2412..2484 -> w.put("band", "2.4GHz").put("channel", if (f == 2484) 14 else (f - 2407) / 5)
            in 5160..5895 -> w.put("band", "5GHz").put("channel", (f - 5000) / 5)
            in 5925..7125 -> w.put("band", "6GHz").put("channel", (f - 5950) / 5)
        }
        if (Build.VERSION.SDK_INT >= 29) {
            if (info.txLinkSpeedMbps > 0) w.put("tx_rate_kbps", info.txLinkSpeedMbps * 1000L)
            if (info.rxLinkSpeedMbps > 0) w.put("rx_rate_kbps", info.rxLinkSpeedMbps * 1000L)
        } else if (info.linkSpeed > 0) {
            w.put("tx_rate_kbps", info.linkSpeed * 1000L)
        }
        if (Build.VERSION.SDK_INT >= 30) {
            when (info.wifiStandard) {
                4 -> "n"; 5 -> "ac"; 6 -> "ax"; 8 -> "be"; 1 -> "g"; else -> null
            }?.let { w.put("standard", it) }
        }
        // Visible only with location access; never asked for.
        @Suppress("DEPRECATION")
        info.ssid?.trim('"')?.takeIf { it.isNotBlank() && it != "<unknown ssid>" }?.let { w.put("ssid", it) }
        return w
    }
}
