package app.wantastic.android.engine

import android.app.PendingIntent
import android.content.Intent
import android.net.ConnectivityManager
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.system.ErrnoException
import android.system.Os
import android.system.OsConstants
import android.system.StructPollfd
import android.util.Log
import app.wantastic.android.MainActivity
import app.wantastic.tunnel.Resolver
import app.wantastic.tunnel.SocketSetup
import app.wantastic.tunnel.TunIo
import app.wantastic.tunnel.TunnelConfig
import app.wantastic.tunnel.TunnelStats
import app.wantastic.tunnel.WireGuardDevice
import java.net.InetAddress

/**
 * The tunnel engine (app.wantastic.tunnel) inside the VPN service: builds the
 * interface from the approval and runs WireGuard, P2P and the exit node.
 * Android cannot change a live VPN's routes, so when an exit node starts or
 * stops carrying the internet a new interface replaces the old one under the
 * running engine: sessions and direct paths stay up.
 */
class KotlinTunnel private constructor(
    private val service: VpnService,
    private val tun: SwitchTun,
    private val device: WireGuardDevice,
    val config: TunnelConfig,
) {
    val stats: TunnelStats get() = device.stats

    fun useExit(vpnIp: String?) = device.useExit(vpnIp)

    fun stop() {
        device.stop()
        tun.close()
    }

    /** Rebuilds the interface with or without the default route (exit node). */
    private fun reroute(full: Boolean) {
        val pfd = runCatching { establish(service, config, full) }.onFailure { Log.e(TAG, "re-route", it) }.getOrNull() ?: return
        tun.swap(pfd)
        Log.i(TAG, if (full) "internet through the exit node" else "internet direct")
    }

    /** The interface as the engine's TUN; the descriptor can be swapped while it runs. */
    private class SwitchTun(first: ParcelFileDescriptor) : TunIo {
        @Volatile private var pfd = first
        @Volatile private var closed = false

        fun swap(next: ParcelFileDescriptor) {
            val old = pfd
            pfd = next
            runCatching { old.close() }
        }

        override fun read(buf: ByteArray): Int {
            while (!closed) {
                val cur = pfd
                // Poll with a timeout: a swap or stop() never leaves a read hanging.
                val pollFd = StructPollfd().apply { fd = cur.fileDescriptor; events = OsConstants.POLLIN.toShort() }
                try {
                    if (Os.poll(arrayOf(pollFd), POLL_MS) <= 0) continue
                    if (cur !== pfd) continue
                    return Os.read(cur.fileDescriptor, buf, 0, buf.size)
                } catch (e: ErrnoException) {
                    if (cur !== pfd || e.errno == OsConstants.EINTR || e.errno == OsConstants.EAGAIN) continue
                    return -1
                }
            }
            return -1
        }

        override fun write(buf: ByteArray, len: Int) {
            try {
                Os.write(pfd.fileDescriptor, buf, 0, len)
            } catch (e: ErrnoException) {
                Log.w(TAG, "tun write: ${e.message}")
            }
        }

        override fun close() {
            closed = true
            runCatching { pfd.close() }
        }
    }

    companion object {
        private const val TAG = "WantasticTunnel"
        private const val POLL_MS = 500

        private fun establish(service: VpnService, config: TunnelConfig, full: Boolean): ParcelFileDescriptor {
            val cm = service.getSystemService(ConnectivityManager::class.java)
            val b = service.Builder()
                .setSession("Wantastic")
                .setMtu(config.mtu)
                .setConfigureIntent(PendingIntent.getActivity(service, 0, Intent(service, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE))
            config.addresses.forEach { b.addAddress(it.address, it.bits) }
            config.server.allowedIps.filter { it.bits > 0 }.forEach { b.addRoute(it.address, it.bits) }
            val dns = config.dns.toMutableList()
            if (full) {
                // Everything through the exit node; IPv6 into the tunnel too, where
                // it is dropped, so it cannot leak around the exit.
                b.addRoute("0.0.0.0", 0)
                b.addRoute("::", 0)
                // The local network's resolver is not reachable through the exit.
                if (dns.isEmpty()) dns += listOf("1.1.1.1", "8.8.8.8")
            }
            dns.forEach { runCatching { b.addDnsServer(it) } }
            if (Build.VERSION.SDK_INT >= 29) b.setMetered(false)
            // The tunnel rides this network: Android counts it, and moves it on change.
            cm?.activeNetwork?.let { b.setUnderlyingNetworks(arrayOf(it)) }
            return b.establish() ?: throw IllegalStateException("Android did not allow the VPN")
        }

        /** Starts the tunnel for [privateKey] and its approval [claim] inside [service]. */
        fun start(service: VpnService, privateKey: String, claim: String, exitIp: String?): KotlinTunnel {
            val config = TunnelConfig.fromClaim(privateKey, claim)
            val cm = service.getSystemService(ConnectivityManager::class.java)
            val tun = SwitchTun(establish(service, config, full = false))
            val device = WireGuardDevice(
                config,
                tun,
                socketSetup = SocketSetup { socket ->
                    // protect() keeps the socket out of the tunnel; binding it to the
                    // network makes it leave on that network (some carriers need both).
                    if (!service.protect(socket)) Log.w(TAG, "protect failed")
                    val net = cm?.activeNetwork
                    if (net != null) runCatching { net.bindSocket(socket) }.onFailure { Log.w(TAG, "bindSocket: ${it.message}") }
                },
                resolver = Resolver { host ->
                    // Resolve on the real network, not through the tunnel being built.
                    val net = cm?.activeNetwork
                    (net?.getAllByName(host) ?: InetAddress.getAllByName(host)).toList()
                },
                log = { Log.i(TAG, it) },
                // P2P candidates: this phone's addresses on its real network.
                localAddresses = {
                    val net = cm?.activeNetwork
                    net?.let { cm.getLinkProperties(it) }?.linkAddresses?.map { it.address }.orEmpty()
                },
            )
            val t = KotlinTunnel(service, tun, device, config)
            device.onExitActive = { full -> Thread { t.reroute(full) }.start() }
            device.start()
            if (exitIp != null) device.useExit(exitIp)
            Log.i(TAG, "tunnel up: ${config.addresses.joinToString()} via ${config.server.endpointHost}:${config.server.endpointPort}")
            return t
        }
    }
}
