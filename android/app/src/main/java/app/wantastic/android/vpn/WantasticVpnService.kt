package app.wantastic.android.vpn

import android.app.NotificationManager
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.Build
import android.service.quicksettings.TileService
import android.content.ComponentName
import app.wantastic.android.engine.Engines
import app.wantastic.android.engine.TunnelState
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch

/**
 * The system VPN entry point (also started by always-on VPN at boot). While
 * the engine runs the tunnel it stays in the foreground with the connection
 * notification, updated from the engine's status. With no engine in the
 * build there is nothing to run, so it stops at once.
 */
class WantasticVpnService : VpnService() {

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)
    private var watching = false

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val engine = Engines.current
        if (intent?.action == ACTION_DISCONNECT) {
            engine.disconnect()
            stopForegroundCompat()
            stopSelf()
            return START_NOT_STICKY
        }
        if (engine.status.value.tunnel is TunnelState.EngineUnavailable) {
            stopSelf(startId)
            return START_NOT_STICKY
        }
        startForegroundCompat()
        engine.connect()
        if (!watching) {
            watching = true
            scope.launch {
                engine.status.collect { status ->
                    getSystemService(NotificationManager::class.java)
                        .notify(ConnectionNotification.ID, ConnectionNotification.build(this@WantasticVpnService, status))
                    TileService.requestListeningState(this@WantasticVpnService, ComponentName(this@WantasticVpnService, ConnectTile::class.java))
                    if (status.tunnel is TunnelState.Disconnected) {
                        stopForegroundCompat()
                        stopSelf()
                    }
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
        scope.cancel()
        super.onDestroy()
    }

    override fun onRevoke() {
        // Another VPN took over, or the user revoked it in system settings.
        Engines.current.disconnect()
        super.onRevoke()
    }

    companion object {
        const val ACTION_CONNECT = "app.wantastic.android.CONNECT"
        const val ACTION_DISCONNECT = "app.wantastic.android.DISCONNECT"
    }
}
