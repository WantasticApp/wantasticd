package app.wantastic.android.vpn

import android.annotation.SuppressLint
import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import app.wantastic.android.MainActivity
import app.wantastic.android.engine.Engines
import app.wantastic.android.engine.TunnelState

/** Quick Settings: connect or disconnect without opening the app. */
class ConnectTile : TileService() {

    override fun onStartListening() {
        val tile = qsTile ?: return
        when (val t = Engines.current.status.value.tunnel) {
            is TunnelState.Connected -> { tile.state = Tile.STATE_ACTIVE; setSubtitle(tile, t.address) }
            TunnelState.Connecting -> { tile.state = Tile.STATE_ACTIVE; setSubtitle(tile, "Connecting…") }
            TunnelState.Disconnected -> { tile.state = Tile.STATE_INACTIVE; setSubtitle(tile, "Off") }
            TunnelState.EngineUnavailable -> { tile.state = Tile.STATE_UNAVAILABLE; setSubtitle(tile, "Not available") }
        }
        tile.updateTile()
    }

    override fun onClick() {
        val tunnel = Engines.current.status.value.tunnel
        if (tunnel is TunnelState.Connected || tunnel is TunnelState.Connecting) {
            startService(Intent(this, WantasticVpnService::class.java).setAction(WantasticVpnService.ACTION_DISCONNECT))
            return
        }
        // First use needs the system's VPN consent, which only an activity can ask for.
        if (VpnService.prepare(this) != null) {
            openApp()
            return
        }
        startService(Intent(this, WantasticVpnService::class.java).setAction(WantasticVpnService.ACTION_CONNECT))
    }

    // Before Android 14 the Intent form is the only one there is.
    @SuppressLint("StartActivityAndCollapseDeprecated")
    private fun openApp() {
        val intent = Intent(this, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        if (Build.VERSION.SDK_INT >= 34) {
            startActivityAndCollapse(PendingIntent.getActivity(this, 0, intent, PendingIntent.FLAG_IMMUTABLE))
        } else {
            @Suppress("DEPRECATION") startActivityAndCollapse(intent)
        }
    }

    private fun setSubtitle(tile: Tile, text: String) {
        if (Build.VERSION.SDK_INT >= 29) tile.subtitle = text
    }
}
