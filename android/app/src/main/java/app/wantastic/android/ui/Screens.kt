package app.wantastic.android.ui

import android.content.Intent
import android.provider.Settings
import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.togetherWith
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.RadioButton
import androidx.compose.material3.RadioButtonDefaults
import androidx.compose.material3.Switch
import androidx.compose.material3.SwitchDefaults
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import app.wantastic.android.BuildConfig
import app.wantastic.android.engine.EngineStatus
import app.wantastic.android.engine.TunnelState

/** Room left for the floating tab bar. */
val NavClearance = PaddingValues(bottom = 104.dp)

private const val ENGINE_PENDING = "The tunnel engine arrives in the next build. Sign-in and the console already work."

@Composable
private fun Dim(text: String, size: Int = 13) = Text(text, color = Glass.TextDim, fontSize = size.sp)

@Composable
fun HomeScreen(status: EngineStatus, deviceName: String, onToggle: () -> Unit, onExitNode: () -> Unit) {
    val tunnel = status.tunnel
    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(NavClearance).padding(horizontal = 20.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(18.dp),
    ) {
        Column(Modifier.fillMaxWidth().padding(top = 12.dp)) {
            Text("Wantastic", color = Glass.Text, fontSize = 34.sp, fontWeight = FontWeight.Bold)
            Dim("$deviceName · this phone", 15)
        }
        ConnectOrb(
            on = tunnel is TunnelState.Connected,
            busy = tunnel is TunnelState.Connecting,
            enabled = tunnel !is TunnelState.EngineUnavailable,
            label = when (tunnel) {
                is TunnelState.Connected -> "Connected"
                TunnelState.Connecting -> "Connecting"
                TunnelState.Disconnected -> "Connect"
                TunnelState.EngineUnavailable -> "Not available"
            },
            onClick = onToggle,
        )
        AnimatedContent(tunnel, transitionSpec = { fadeIn() togetherWith fadeOut() }, label = "state") { t ->
            Column(horizontalAlignment = Alignment.CenterHorizontally) {
                when (t) {
                    is TunnelState.Connected -> {
                        Text(t.address, color = Glass.Text, fontSize = 26.sp, fontFamily = FontFamily.Monospace)
                        Dim("via ${t.hub}")
                    }
                    TunnelState.EngineUnavailable -> Text(ENGINE_PENDING, color = Glass.TextDim, fontSize = 13.sp, textAlign = TextAlign.Center)
                    else -> Dim("Not connected")
                }
            }
        }
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            Metric("Download", rate(status.downBitsPerSec), Modifier.weight(1f))
            Metric("Upload", rate(status.upBitsPerSec), Modifier.weight(1f))
        }
        GlassCard(Modifier.fillMaxWidth(), onClick = onExitNode) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Column(Modifier.weight(1f)) {
                    Dim("Exit node")
                    Text(status.usingExit?.let { "Internet via $it" } ?: "Off · internet goes direct", color = Glass.Text, fontSize = 16.sp, fontWeight = FontWeight.SemiBold)
                }
                Text("›", color = Glass.TextDim, fontSize = 26.sp)
            }
        }
    }
}

@Composable
private fun Metric(label: String, value: String, modifier: Modifier) {
    GlassCard(modifier) {
        Dim(label)
        Text(value, color = Glass.Text, fontSize = 20.sp, fontWeight = FontWeight.SemiBold)
    }
}

private fun rate(bits: Long): String = when {
    bits <= 0 -> "—"
    bits >= 1_000_000 -> "%.1f Mbit/s".format(bits / 1_000_000.0)
    else -> "%.0f kbit/s".format(bits / 1_000.0)
}

@Composable
fun PeersScreen(status: EngineStatus) {
    Column(Modifier.fillMaxSize()) {
        GlassTitle("Peers", if (status.peers.isEmpty()) null else "${status.peers.size} online · ${status.peers.count { it.direct }} direct")
        if (status.peers.isEmpty()) {
            GlassCard(Modifier.fillMaxWidth().padding(horizontal = 20.dp)) {
                Text(if (status.tunnel is TunnelState.EngineUnavailable) ENGINE_PENDING else "No peers yet.", color = Glass.TextDim, fontSize = 14.sp)
            }
            return
        }
        LazyColumn(
            contentPadding = PaddingValues(start = 20.dp, end = 20.dp, top = 4.dp, bottom = 110.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            items(status.peers, key = { it.vpnIp }) { p ->
                GlassCard(Modifier.fillMaxWidth(), shape = RoundedCornerShape(50)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Box(Modifier.size(10.dp).clip(CircleShape).background(if (p.direct) Glass.Green else Color.Transparent).border(2.dp, if (p.direct) Glass.Green else Glass.TextDim, CircleShape))
                        Spacer(Modifier.size(12.dp))
                        Column(Modifier.weight(1f)) {
                            Text(p.name, color = Glass.Text, fontSize = 16.sp, fontWeight = FontWeight.SemiBold, maxLines = 1)
                            Text(p.vpnIp, color = Glass.TextDim, fontSize = 12.sp, fontFamily = FontFamily.Monospace)
                        }
                        Dim((if (p.direct) "direct" else "relay") + (p.latencyMs?.let { " · $it ms" } ?: ""), 12)
                    }
                }
            }
        }
    }
}

@Composable
fun ExitNodeScreen(status: EngineStatus, onUse: (String?) -> Unit, onOffer: (Boolean) -> Unit) {
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(NavClearance)) {
        GlassTitle("Exit node", "Send all of this phone's internet through another device.")
        Column(Modifier.padding(horizontal = 20.dp), verticalArrangement = Arrangement.spacedBy(14.dp)) {
            GlassCard(Modifier.fillMaxWidth()) {
                ExitRow("None", "Internet goes out directly", status.usingExit == null, true) { onUse(null) }
                status.exitCandidates.forEach { c ->
                    ExitRow(c.name, if (c.direct) "Direct path · offers exit" else "Relayed now — available once direct", status.usingExit == c.ip, c.offersExit && c.direct) { onUse(c.ip) }
                }
            }
            GlassCard(Modifier.fillMaxWidth()) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Column(Modifier.weight(1f)) {
                        Text("Share this phone", color = Glass.Text, fontSize = 16.sp, fontWeight = FontWeight.SemiBold)
                        Dim("Other devices may send their internet through this phone. Your LAN and this phone stay unreachable to them.", 12)
                    }
                    Switch(
                        checked = status.offeringExit, onCheckedChange = onOffer, enabled = status.tunnel is TunnelState.Connected,
                        colors = SwitchDefaults.colors(checkedTrackColor = Glass.Blue),
                    )
                }
            }
        }
    }
}

@Composable
private fun ExitRow(name: String, note: String, selected: Boolean, enabled: Boolean, onClick: () -> Unit) {
    Row(
        Modifier.fillMaxWidth().clip(RoundedCornerShape(16.dp)).clickable(enabled = enabled, onClick = onClick).heightIn(min = 56.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        RadioButton(selected = selected, onClick = onClick, enabled = enabled, colors = RadioButtonDefaults.colors(selectedColor = Glass.Cyan, unselectedColor = Glass.TextDim))
        Column {
            Text(name, color = if (enabled) Glass.Text else Glass.TextDim, fontSize = 16.sp, fontWeight = FontWeight.SemiBold)
            Dim(note, 12)
        }
    }
}

@Composable
fun SettingsScreen() {
    val context = LocalContext.current
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(NavClearance)) {
        GlassTitle("Settings")
        Column(Modifier.padding(horizontal = 20.dp), verticalArrangement = Arrangement.spacedBy(14.dp)) {
            Section("Connection")
            GlassCard(Modifier.fillMaxWidth(), onClick = { context.startActivity(Intent(Settings.ACTION_VPN_SETTINGS)) }) {
                SettingsRow("Always-on VPN", "Reconnect after reboot and network changes")
            }
            Section("Reliability")
            GlassCard(Modifier.fillMaxWidth(), onClick = { context.startActivity(Intent(Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS)) }) {
                SettingsRow("Battery optimization", "Keep the tunnel alive on this phone")
            }
            Text("Wantastic ${BuildConfig.VERSION_NAME}", color = Glass.TextDim, fontSize = 12.sp, modifier = Modifier.padding(top = 8.dp))
        }
    }
}

@Composable
private fun Section(title: String) = Text(title.uppercase(), color = Glass.TextDim, fontSize = 12.sp, fontWeight = FontWeight.SemiBold, modifier = Modifier.padding(start = 6.dp))

@Composable
private fun SettingsRow(label: String, hint: String) {
    Row(verticalAlignment = Alignment.CenterVertically) {
        Column(Modifier.weight(1f)) {
            Text(label, color = Glass.Text, fontSize = 16.sp, fontWeight = FontWeight.Medium)
            Dim(hint, 12)
        }
        Text("›", color = Glass.TextDim, fontSize = 26.sp)
    }
}
