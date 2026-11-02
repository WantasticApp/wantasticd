package app.wantastic.android.vpn

import android.content.Intent
import android.net.VpnService
import app.wantastic.android.engine.Engines

/**
 * The system VPN entry point (also started by always-on VPN at boot). The
 * engine opens the tunnel through this service; until the engine lands
 * there is nothing to run, so the service stops at once.
 */
class WantasticVpnService : VpnService() {

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_DISCONNECT -> Engines.current.disconnect()
            else -> Engines.current.connect()
        }
        stopSelf(startId)
        return START_NOT_STICKY
    }

    companion object {
        const val ACTION_CONNECT = "app.wantastic.android.CONNECT"
        const val ACTION_DISCONNECT = "app.wantastic.android.DISCONNECT"
    }
}
