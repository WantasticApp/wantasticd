package app.wantastic.android.ui

import android.annotation.SuppressLint
import android.content.Intent
import android.provider.Settings
import android.webkit.WebView
import android.webkit.WebViewClient
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.viewinterop.AndroidView
import app.wantastic.android.BuildConfig
import app.wantastic.android.engine.EngineStatus
import app.wantastic.android.engine.TunnelState

private val Card = RoundedCornerShape(18.dp)

@Composable
private fun ScreenTitle(text: String) {
    Text(text, fontSize = 24.sp, fontWeight = FontWeight.Bold, modifier = Modifier.padding(start = 20.dp, top = 20.dp, bottom = 8.dp))
}

@Composable
private fun Notice(text: String) {
    Text(
        text, color = MaterialTheme.colorScheme.onSurfaceVariant, fontSize = 14.sp, textAlign = TextAlign.Center,
        modifier = Modifier.fillMaxWidth().padding(32.dp),
    )
}

private const val ENGINE_PENDING = "The tunnel engine arrives in the next build. Sign-in and the console already work."

@Composable
fun HomeScreen(status: EngineStatus, deviceName: String, onToggle: () -> Unit, onExitNode: () -> Unit) {
    val tunnel = status.tunnel
    val connected = tunnel is TunnelState.Connected
    Column(Modifier.fillMaxSize().padding(20.dp), verticalArrangement = Arrangement.spacedBy(16.dp)) {
        Column(
            Modifier.fillMaxWidth().background(Brand.Navy, RoundedCornerShape(24.dp)).padding(22.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(14.dp),
        ) {
            Text("$deviceName · this phone", color = Brand.OnNavyMuted, fontSize = 13.sp)
            Box(
                Modifier
                    .size(132.dp)
                    .border(6.dp, if (connected) Color(0xFF22C55E) else Color(0xFF64748B), CircleShape)
                    .background(Brand.NavyRaised, CircleShape)
                    .clickable(enabled = tunnel !is TunnelState.EngineUnavailable, onClick = onToggle),
                contentAlignment = Alignment.Center,
            ) {
                Text(
                    when (tunnel) {
                        is TunnelState.Connected -> "Connected"
                        TunnelState.Connecting -> "Connecting…"
                        TunnelState.Disconnected -> "Tap to connect"
                        TunnelState.EngineUnavailable -> "Not available"
                    },
                    color = Color.White, fontSize = 14.sp, fontWeight = FontWeight.SemiBold, textAlign = TextAlign.Center,
                )
            }
            if (tunnel is TunnelState.Connected) {
                Text(tunnel.address, color = Color.White, fontSize = 18.sp, fontFamily = FontFamily.Monospace)
                Text("via ${tunnel.hub}", color = Brand.OnNavyMuted, fontSize = 12.sp)
            } else if (tunnel is TunnelState.EngineUnavailable) {
                Text(ENGINE_PENDING, color = Brand.OnNavyMuted, fontSize = 12.sp, textAlign = TextAlign.Center)
            }
        }
        Row(
            Modifier.fillMaxWidth().background(MaterialTheme.colorScheme.surface, Card).border(1.dp, MaterialTheme.colorScheme.outline, Card)
                .clickable(onClick = onExitNode).heightIn(min = 56.dp).padding(16.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Column(Modifier.weight(1f)) {
                Text("Exit node", color = MaterialTheme.colorScheme.onSurfaceVariant, fontSize = 12.sp)
                Text(status.usingExit?.let { "Using $it" } ?: "Off · internet goes direct", fontSize = 15.sp, fontWeight = FontWeight.SemiBold)
            }
            Text("›", color = MaterialTheme.colorScheme.onSurfaceVariant, fontSize = 22.sp)
        }
    }
}

@Composable
fun PeersScreen(status: EngineStatus) {
    Column(Modifier.fillMaxSize()) {
        ScreenTitle("Peers")
        if (status.peers.isEmpty()) {
            Notice(if (status.tunnel is TunnelState.EngineUnavailable) ENGINE_PENDING else "No peers yet.")
            return
        }
        LazyColumn(contentPadding = androidx.compose.foundation.layout.PaddingValues(horizontal = 20.dp, vertical = 4.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            items(status.peers, key = { it.vpnIp }) { p ->
                Row(
                    Modifier.fillMaxWidth().background(MaterialTheme.colorScheme.surface, RoundedCornerShape(50)).border(1.dp, MaterialTheme.colorScheme.outline, RoundedCornerShape(50))
                        .heightIn(min = 52.dp).padding(horizontal = 16.dp, vertical = 8.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Text(if (p.direct) "●" else "◌", color = if (p.direct) Brand.Good else Color(0xFF64748B))
                    Spacer(Modifier.size(10.dp))
                    Column(Modifier.weight(1f)) {
                        Text(p.name, fontSize = 15.sp, fontWeight = FontWeight.SemiBold, maxLines = 1)
                        Text(p.vpnIp, fontSize = 12.sp, color = MaterialTheme.colorScheme.onSurfaceVariant, fontFamily = FontFamily.Monospace)
                    }
                    Text((if (p.direct) "direct" else "relay") + (p.latencyMs?.let { " · $it ms" } ?: ""), fontSize = 12.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
            }
        }
    }
}

@Composable
fun ExitNodeScreen(status: EngineStatus, onUse: (String?) -> Unit, onOffer: (Boolean) -> Unit) {
    Column(Modifier.fillMaxSize()) {
        ScreenTitle("Exit node")
        Column(Modifier.padding(horizontal = 20.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
            Text("Send all of this phone's internet through another device in your network.", color = MaterialTheme.colorScheme.onSurfaceVariant, fontSize = 13.sp)
            Column(Modifier.background(MaterialTheme.colorScheme.surface, Card).border(1.dp, MaterialTheme.colorScheme.outline, Card)) {
                ExitRow("None", "Internet goes out directly", status.usingExit == null, true) { onUse(null) }
                status.exitCandidates.forEach { c ->
                    ExitRow(c.name, if (c.direct) "Direct path · offers exit" else "Relayed now — available once direct", status.usingExit == c.ip, c.offersExit && c.direct) { onUse(c.ip) }
                }
            }
            Row(
                Modifier.fillMaxWidth().background(MaterialTheme.colorScheme.surface, Card).border(1.dp, MaterialTheme.colorScheme.outline, Card).padding(16.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Column(Modifier.weight(1f)) {
                    Text("Allow as exit node", fontSize = 15.sp, fontWeight = FontWeight.SemiBold)
                    Text("Other devices may send their internet through this phone. Your LAN and this phone stay unreachable to them.", fontSize = 12.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
                Switch(checked = status.offeringExit, onCheckedChange = onOffer, enabled = status.tunnel is TunnelState.Connected)
            }
        }
    }
}

@Composable
private fun ExitRow(name: String, note: String, selected: Boolean, enabled: Boolean, onClick: () -> Unit) {
    Row(
        Modifier.fillMaxWidth().clickable(enabled = enabled, onClick = onClick).heightIn(min = 56.dp).padding(horizontal = 8.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        RadioButton(selected = selected, onClick = onClick, enabled = enabled)
        Column {
            Text(name, fontSize = 15.sp, fontWeight = FontWeight.SemiBold, color = if (enabled) MaterialTheme.colorScheme.onSurface else MaterialTheme.colorScheme.onSurfaceVariant)
            Text(note, fontSize = 12.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}

/** The portal console, signed in with the same account as the web. */
@SuppressLint("SetJavaScriptEnabled")
@Composable
fun ConsoleScreen(url: String) {
    // imePadding: edge to edge, the window no longer resizes for the keyboard,
    // so the console's sign-in fields would sit under it.
    AndroidView(
        modifier = Modifier.fillMaxSize().imePadding(),
        factory = { ctx ->
            WebView(ctx).apply {
                settings.javaScriptEnabled = true
                settings.domStorageEnabled = true
                webViewClient = WebViewClient()
                loadUrl(url)
            }
        },
    )
}

@Composable
fun SettingsScreen() {
    val context = LocalContext.current
    Column(Modifier.fillMaxSize()) {
        ScreenTitle("Settings")
        Column(Modifier.padding(horizontal = 20.dp), verticalArrangement = Arrangement.spacedBy(14.dp)) {
            SettingsGroup("Connection") {
                SettingsLink("Always-on VPN", "Reconnect after reboot and network changes") {
                    context.startActivity(Intent(Settings.ACTION_VPN_SETTINGS))
                }
            }
            SettingsGroup("Reliability") {
                SettingsLink("Battery optimization", "Keep the tunnel alive on this phone") {
                    context.startActivity(Intent(Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS))
                }
            }
            Text("Version ${BuildConfig.VERSION_NAME}", fontSize = 12.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}

@Composable
private fun SettingsGroup(title: String, content: @Composable () -> Unit) {
    Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
        Text(title.uppercase(), fontSize = 12.sp, fontWeight = FontWeight.SemiBold, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Column(Modifier.background(MaterialTheme.colorScheme.surface, Card).border(1.dp, MaterialTheme.colorScheme.outline, Card)) { content() }
    }
}

@Composable
private fun SettingsLink(label: String, hint: String, onClick: () -> Unit) {
    Row(
        Modifier.fillMaxWidth().clickable(onClick = onClick).heightIn(min = 56.dp).padding(horizontal = 16.dp, vertical = 10.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(Modifier.weight(1f)) {
            Text(label, fontSize = 15.sp, fontWeight = FontWeight.Medium)
            Text(hint, fontSize = 12.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
        Text("›", color = MaterialTheme.colorScheme.onSurfaceVariant, fontSize = 22.sp)
    }
}
