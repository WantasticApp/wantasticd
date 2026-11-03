package app.wantastic.tunnel

import org.json.JSONObject
import java.net.InetAddress

/** An address range (CIDR), IPv4 or IPv6. */
data class IpPrefix(val address: InetAddress, val bits: Int) {
    private val bytes = address.address

    fun contains(ip: ByteArray): Boolean {
        if (ip.size != bytes.size) return false
        var left = bits
        var i = 0
        while (left > 0) {
            val mask = if (left >= 8) 0xff else (0xff shl (8 - left)) and 0xff
            if ((ip[i].toInt() and mask) != (bytes[i].toInt() and mask)) return false
            left -= 8
            i++
        }
        return true
    }

    override fun toString() = "${address.hostAddress}/$bits"

    companion object {
        /** "10.6.84.192/27", "fd00::/64" or a bare address (a host route). */
        fun parse(s: String): IpPrefix? {
            val t = s.trim()
            if (t.isEmpty()) return null
            val addr = t.substringBefore('/')
            // Literals only: never a DNS lookup here.
            if (!addr.all { it.isDigit() || it == '.' || it == ':' || it in 'a'..'f' || it in 'A'..'F' }) return null
            val ip = runCatching { InetAddress.getByName(addr) }.getOrNull() ?: return null
            val max = ip.address.size * 8
            val bits = if ('/' in t) t.substringAfter('/').toIntOrNull() ?: return null else max
            if (bits !in 0..max) return null
            return IpPrefix(ip, bits)
        }
    }
}

/** The hub (or another peer) this device talks to. */
data class PeerConfig(
    val publicKey: ByteArray,
    val endpointHost: String,
    val endpointPort: Int,
    val allowedIps: List<IpPrefix>,
    val persistentKeepaliveSec: Int,
)

/** Everything the tunnel needs; [fromClaim] builds it the way the Go agent does. */
data class TunnelConfig(
    val privateKey: ByteArray,
    val addresses: List<IpPrefix>,
    val dns: List<String>,
    val mtu: Int,
    val server: PeerConfig,
) {
    val publicKey: ByteArray get() = WgCrypto.publicKey(privateKey)

    companion object {
        const val DEFAULT_PORT = 51820
        const val DEFAULT_MTU = 1420
        const val DEFAULT_KEEPALIVE = 25

        fun key(b64: String): ByteArray = base64Decode(b64.trim()).also {
            require(it.size == 32) { "a WireGuard key is 32 bytes" }
        }

        /**
         * The device's config from the server's approval (claim) JSON, as the Go
         * agent's config.LoadFromClaimConfig: endpoint "host:port" or listen_port,
         * port 51820, MTU 1420 and keepalive 25 s when unset.
         */
        fun fromClaim(privateKeyB64: String, claimJson: String): TunnelConfig {
            val c = JSONObject(claimJson)
            require(c.optBoolean("claimed", true)) { "this device has not been approved yet" }
            val serverKey = c.optString("server_key").trim()
            require(serverKey.isNotEmpty()) { "approval has no server_key" }
            val assigned = IpPrefix.parse(c.optString("assigned_ip")) ?: throw IllegalArgumentException("approval has no assigned_ip")
            var host = c.optString("endpoint").trim()
            var port = c.optInt("listen_port", 0)
            val bracket = Regex("""^\[(.+)]:(\d+)$""").find(host)
            when {
                bracket != null -> { host = bracket.groupValues[1]; port = bracket.groupValues[2].toInt() }
                host.count { it == ':' } == 1 -> { port = host.substringAfter(':').toIntOrNull() ?: port; host = host.substringBefore(':') }
            }
            if (port <= 0) port = DEFAULT_PORT
            val allowed = c.optJSONArray("allowed_ips")?.let { a -> (0 until a.length()).mapNotNull { IpPrefix.parse(a.optString(it)) } }.orEmpty()
            val dns = c.optJSONArray("dns_servers")?.let { a -> (0 until a.length()).map { a.optString(it).trim() }.filter { it.isNotEmpty() } }.orEmpty()
            return TunnelConfig(
                privateKey = key(privateKeyB64),
                addresses = listOf(assigned),
                dns = dns,
                mtu = c.optInt("mtu", 0).takeIf { it > 0 } ?: DEFAULT_MTU,
                server = PeerConfig(
                    publicKey = key(serverKey),
                    endpointHost = host,
                    endpointPort = port,
                    allowedIps = allowed,
                    persistentKeepaliveSec = c.optInt("persistent_keepalive", 0).takeIf { it > 0 } ?: DEFAULT_KEEPALIVE,
                ),
            )
        }
    }
}

private const val B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

/** Standard Base64 (keys); java.util.Base64 needs Android 8 and this runs on 7. */
internal fun base64Decode(s: String): ByteArray {
    val clean = s.trimEnd('=')
    val out = java.io.ByteArrayOutputStream(clean.length * 3 / 4)
    var acc = 0
    var bits = 0
    for (ch in clean) {
        val v = B64.indexOf(ch)
        require(v >= 0) { "not Base64" }
        acc = (acc shl 6) or v
        bits += 6
        if (bits >= 8) {
            bits -= 8
            out.write((acc ushr bits) and 0xff)
        }
    }
    return out.toByteArray()
}

internal fun base64Encode(b: ByteArray): String {
    val sb = StringBuilder()
    var i = 0
    while (i < b.size) {
        val n = minOf(3, b.size - i)
        var acc = 0
        for (j in 0 until 3) acc = (acc shl 8) or (if (j < n) b[i + j].toInt() and 0xff else 0)
        for (j in 0 until 4) sb.append(if (j <= n) B64[(acc ushr (18 - 6 * j)) and 63] else '=')
        i += 3
    }
    return sb.toString()
}
