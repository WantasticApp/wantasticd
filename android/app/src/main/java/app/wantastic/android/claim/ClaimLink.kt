package app.wantastic.android.claim

import java.net.URI
import java.net.URLEncoder

/**
 * The claim link the console approves a device with, exactly as the desktop
 * agent builds it (cmd/wantasticd buildClaimURL), so the console's claim
 * screen needs no change for phones.
 */
object ClaimLink {
    const val DEFAULT_SERVER = "https://console.wantastic.app"

    fun normalizeServer(server: String?): String {
        var base = server.orEmpty().trim().trimEnd('/')
        if (base.isEmpty()) return DEFAULT_SERVER
        if (!base.startsWith("http://", ignoreCase = true) && !base.startsWith("https://", ignoreCase = true)) {
            base = "https://$base"
        }
        return runCatching {
            val uri = URI(base)
            if (uri.scheme != null && uri.host != null) {
                uri.scheme + "://" + uri.host + (if (uri.port > 0) ":" + uri.port else "")
            } else base
        }.getOrDefault(base)
    }

    /** The device name pre-filled in the console; stock names say nothing. */
    fun cleanHostname(name: String?): String {
        var host = name.orEmpty().trim()
        for (suffix in listOf(".local", ".lan", ".home", ".localdomain")) {
            if (host.lowercase().endsWith(suffix)) {
                host = host.dropLast(suffix.length)
                break
            }
        }
        if (host.lowercase() in setOf("", "localhost", "android")) return ""
        return host.take(64)
    }

    fun build(server: String?, publicKey: String, deviceName: String?): String {
        val base = normalizeServer(server)
        val sb = StringBuilder(base)
            .append("/#desktop?claim_public_key=").append(escape(publicKey.trim()))
            .append("&wantastic_server=").append(escape(base))
        val host = cleanHostname(deviceName)
        if (host.isNotEmpty()) sb.append("&hostname=").append(escape(host))
        return sb.toString()
    }

    /** Go's url.QueryEscape: spaces become "+". */
    private fun escape(value: String): String = URLEncoder.encode(value, "UTF-8")
}
