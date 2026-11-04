package app.wantastic.android.vpn

import android.app.NotificationManager
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.Build
import android.service.quicksettings.TileService
import android.content.ComponentName
import app.wantastic.android.claim.ClaimKey
import app.wantastic.android.claim.ClaimLink
import app.wantastic.android.engine.Engines
import app.wantastic.android.engine.AppEngine
import app.wantastic.android.engine.TunnelState
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch

/**
 * The system VPN entry point, also started by Always-on VPN at boot. It
 * owns the interface: the engine runs the tunnel inside it while it
 * stays in the foreground with the connection notification and tile.
 */
class WantasticVpnService : VpnService() {

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)
    private var watching = false

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        // Always-on VPN may start us before the app ever opened in this process.
        val engine = AppEngine.install(this, ClaimKey.open(this).setups()) as? AppEngine
        if (intent?.action == ACTION_DISCONNECT || engine == null) {
            engine?.stop()
            stopForegroundCompat()
            stopSelf()
            return START_NOT_STICKY
        }
        startForegroundCompat()
        if (engine.status.value.tunnel !is TunnelState.Connected && engine.status.value.tunnel !is TunnelState.Connecting) {
            scope.launch(Dispatchers.IO) {
                if (!engine.startIn(this@WantasticVpnService, ClaimLink.DEFAULT_SERVER)) {
                    launch(Dispatchers.Main) { stopForegroundCompat(); stopSelf() }
                }
            }
        }
        if (!watching) {
            watching = true
            scope.launch {
                engine.status.collect { status ->
                    getSystemService(NotificationManager::class.java)
                        .notify(ConnectionNotification.ID, ConnectionNotification.build(this@WantasticVpnService, status))
                    TileService.requestListeningState(this@WantasticVpnService, ComponentName(this@WantasticVpnService, ConnectTile::class.java))
                }
            }
        }
        return START_STICKY
    }

    private fun startForegroundCompat() {
        val notification = ConnectionNotification.build(this, Engines.current.status.value)
        if (Build.VERSION.SDK_INT >= 34) {
            startForeground(ConnectionNotification.ID, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_SYSTEM_EXEMPTED)
        } else {
            startForeground(ConnectionNotification.ID, notification)
        }
    }

    private fun stopForegroundCompat() {
        stopForeground(STOP_FOREGROUND_REMOVE)
    }

    override fun onDestroy() {
        (Engines.current as? AppEngine)?.stop()
        scope.cancel()
        super.onDestroy()
    }

    override fun onRevoke() {
        // Another VPN took over, or the user revoked it in system settings.
        (Engines.current as? AppEngine)?.stop()
        stopForegroundCompat()
        stopSelf()
        super.onRevoke()
    }

    companion object {
        const val ACTION_CONNECT = "app.wantastic.android.CONNECT"
        const val ACTION_DISCONNECT = "app.wantastic.android.DISCONNECT"
    }
}
