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
import java.io.FileDescriptor
import java.net.InetAddress

/**
 * The Kotlin engine (app.wantastic.tunnel) inside the VPN service: builds the
 * interface from the approval and runs WireGuard to the server. Phase 1: the
 * tunnel to the hub; P2P, exit node and WUSP come in later phases.
 */
class KotlinTunnel private constructor(
    private val pfd: ParcelFileDescriptor,
    private val device: WireGuardDevice,
    val config: TunnelConfig,
) {
    val stats: TunnelStats get() = device.stats

    fun stop() {
        device.stop()
        runCatching { pfd.close() }
    }

    /** The VPN interface as the engine's TUN: poll with a timeout so stop() never hangs on a read. */
    private class PfdTun(private val fd: FileDescriptor) : TunIo {
        @Volatile private var closed = false

        override fun read(buf: ByteArray): Int {
            val pollFd = StructPollfd().apply { this.fd = this@PfdTun.fd; events = OsConstants.POLLIN.toShort() }
            while (!closed) {
                try {
                    if (Os.poll(arrayOf(pollFd), POLL_MS) <= 0) continue
                    return Os.read(fd, buf, 0, buf.size)
                } catch (e: ErrnoException) {
                    if (e.errno == OsConstants.EINTR || e.errno == OsConstants.EAGAIN) continue
                    return -1
                }
            }
            return -1
        }

        override fun write(buf: ByteArray, len: Int) {
            try {
                Os.write(fd, buf, 0, len)
            } catch (e: ErrnoException) {
                Log.w(TAG, "tun write: ${e.message}")
            }
        }

        override fun close() {
            closed = true
        }
    }

    companion object {
        private const val TAG = "WantasticKotlin"
        private const val POLL_MS = 500

        /** Starts the tunnel for [privateKey] and its approval [claim] inside [service]. */
        fun start(service: VpnService, privateKey: String, claim: String): KotlinTunnel {
            val config = TunnelConfig.fromClaim(privateKey, claim)
            val cm = service.getSystemService(ConnectivityManager::class.java)
            val underlying = cm?.activeNetwork
            val b = service.Builder()
                .setSession("Wantastic")
                .setMtu(config.mtu)
                .setConfigureIntent(PendingIntent.getActivity(service, 0, Intent(service, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE))
            config.addresses.forEach { b.addAddress(it.address, it.bits) }
            config.server.allowedIps.filter { it.bits > 0 }.forEach { b.addRoute(it.address, it.bits) }
            config.dns.forEach { runCatching { b.addDnsServer(it) } }
            if (Build.VERSION.SDK_INT >= 29) b.setMetered(false)
            // The tunnel rides this network: Android counts it, and moves it on change.
            if (underlying != null) b.setUnderlyingNetworks(arrayOf(underlying))
            val pfd = b.establish() ?: throw IllegalStateException("Android did not allow the VPN")

            val device = WireGuardDevice(
                config,
                PfdTun(pfd.fileDescriptor),
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
            )
            device.start()
            Log.i(TAG, "Kotlin engine up: ${config.addresses.joinToString()} via ${config.server.endpointHost}:${config.server.endpointPort}")
            return KotlinTunnel(pfd, device, config)
        }
    }
}
