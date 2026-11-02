package app.wantastic.android.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.os.Build
import app.wantastic.android.MainActivity
import app.wantastic.android.R
import app.wantastic.android.engine.EngineStatus
import app.wantastic.android.engine.TunnelState

/**
 * One quiet, ongoing notification while the tunnel runs (Android requires it
 * for a foreground VPN): no sound, no vibration, no badge; it shows the state
 * and offers Disconnect, and updates in place.
 */
object ConnectionNotification {
    const val ID = 1
    private const val CHANNEL = "connection"

    fun ensureChannel(context: Context) {
        if (Build.VERSION.SDK_INT < 26) return
        val manager = context.getSystemService(NotificationManager::class.java)
        if (manager.getNotificationChannel(CHANNEL) != null) return
        val channel = NotificationChannel(CHANNEL, context.getString(R.string.vpn_notification_channel), NotificationManager.IMPORTANCE_LOW).apply {
            setShowBadge(false)
            enableVibration(false)
            setSound(null, null)
            description = "Shows while Wantastic is connected"
        }
        manager.createNotificationChannel(channel)
    }

    fun build(context: Context, status: EngineStatus): Notification {
        ensureChannel(context)
        val open = PendingIntent.getActivity(
            context, 0, Intent(context, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        val disconnect = PendingIntent.getService(
            context, 1, Intent(context, WantasticVpnService::class.java).setAction(WantasticVpnService.ACTION_DISCONNECT),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        val (title, text) = when (val t = status.tunnel) {
            is TunnelState.Connected -> "Connected · ${t.address}" to (status.usingExit?.let { "Internet via $it" } ?: "${status.peers.size} peers")
            TunnelState.Connecting -> "Connecting…" to "Reaching your network"
            else -> "Disconnected" to "Tap to open Wantastic"
        }
        val builder = if (Build.VERSION.SDK_INT >= 26) Notification.Builder(context, CHANNEL) else @Suppress("DEPRECATION") Notification.Builder(context)
        return builder
            .setSmallIcon(R.drawable.ic_tile)
            .setContentTitle(title)
            .setContentText(text)
            .setContentIntent(open)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setShowWhen(false)
            .setCategory(Notification.CATEGORY_SERVICE)
            .addAction(Notification.Action.Builder(null as android.graphics.drawable.Icon?, "Disconnect", disconnect).build())
            .build()
    }
}
