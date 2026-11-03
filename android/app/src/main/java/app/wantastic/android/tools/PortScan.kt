package app.wantastic.android.tools

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
import kotlinx.coroutines.withContext
import java.net.InetSocketAddress
import java.net.Socket

/**
 * A light TCP check of the services people reach on their devices, run only
 * when asked, through the tunnel: a few connections at a time, short timeouts.
 */
object PortScan {
    data class Service(val port: Int, val name: String, val web: Boolean = false, val https: Boolean = false)

    val Common = listOf(
        Service(22, "SSH"), Service(23, "Telnet"), Service(53, "DNS"),
        Service(80, "Web", web = true), Service(443, "Web (HTTPS)", web = true, https = true),
        Service(8080, "Web (8080)", web = true), Service(8443, "Web (8443)", web = true, https = true),
        Service(8291, "Winbox"), Service(8728, "RouterOS API"), Service(8729, "RouterOS API (TLS)"),
        Service(3389, "Remote Desktop"), Service(5900, "VNC"), Service(445, "File sharing (SMB)"),
        Service(21, "FTP"), Service(161, "SNMP"), Service(1883, "MQTT"), Service(9100, "Printer"),
    )

    suspend fun scan(ip: String, services: List<Service> = Common): List<Service> = withContext(Dispatchers.IO) {
        val gate = Semaphore(8)
        coroutineScope {
            services.map { s ->
                async {
                    gate.withPermit {
                        runCatching { Socket().use { it.connect(InetSocketAddress(ip, s.port), 900) }; s }.getOrNull()
                    }
                }
            }.awaitAll().filterNotNull()
        }
    }
}
