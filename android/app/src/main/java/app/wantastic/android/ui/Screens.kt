package app.wantastic.android.ui

import android.content.Intent
import android.provider.Settings
import android.net.Uri
import android.text.format.DateUtils
import androidx.activity.compose.BackHandler
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import app.wantastic.android.settings.AppSettings
import app.wantastic.android.update.UpdateStatus
import app.wantastic.android.update.Updates
import kotlinx.coroutines.launch
import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.togetherWith
import androidx.compose.foundation.background
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
import androidx.compose.foundation.lazy.itemsIndexed
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
import androidx.compose.animation.animateContentSize
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.layout.height
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import app.wantastic.android.BuildConfig
import app.wantastic.android.engine.EngineStatus
import app.wantastic.android.engine.Peer
import androidx.compose.runtime.LaunchedEffect
import app.wantastic.android.engine.TunnelState

/** Room left for the floating tab bar. */
val NavClearance = PaddingValues(bottom = 104.dp)


@Composable
private fun Dim(text: String, size: Int = 13) = Text(text, color = Glass.TextDim, fontSize = size.sp)

@Composable
fun HomeScreen(
    status: EngineStatus, deviceName: String, onToggle: () -> Unit, onLogIn: () -> Unit, onExitNode: () -> Unit,
    accountCard: @Composable () -> Unit,
) {
    val tunnel = status.tunnel
    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(NavClearance).padding(horizontal = 20.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Column(Modifier.fillMaxWidth().padding(top = 12.dp)) {
            Text("Wantastic", color = Glass.Text, fontSize = 28.sp, fontWeight = FontWeight.Bold)
            Dim("$deviceName · this phone", 15)
        }
        // Not approved yet: the button is the way in, straight to the Claim form.
        ConnectOrb(
            on = tunnel is TunnelState.Connected,
            busy = tunnel is TunnelState.Connecting,
            enabled = !status.claimed || tunnel !is TunnelState.EngineUnavailable,
            label = when {
                !status.claimed -> "Log in"
                tunnel is TunnelState.Connected -> "Connected"
                tunnel is TunnelState.Connecting -> "Connecting"
                tunnel is TunnelState.Disconnected -> "Connect"
                else -> "Not available"
            },
            onClick = if (status.claimed) onToggle else onLogIn,
        )
        AnimatedContent(tunnel.takeIf { status.claimed }, transitionSpec = { fadeIn() togetherWith fadeOut() }, label = "state") { t ->
            Column(horizontalAlignment = Alignment.CenterHorizontally) {
                when (t) {
                    null -> Text("Log in to your account and press Claim to add this phone.", color = Glass.TextDim, fontSize = 13.sp, textAlign = TextAlign.Center)
                    is TunnelState.Connected -> {
                        Text(t.address, color = Glass.Text, fontSize = 20.sp, fontFamily = FontFamily.Monospace)
                    }
                    TunnelState.EngineUnavailable -> Text("The tunnel engine could not start on this phone.", color = Glass.TextDim, fontSize = 13.sp, textAlign = TextAlign.Center)
                    else -> Dim("Not connected")
                }
            }
        }
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            Metric("Download", rate(status.downBitsPerSec), status.downHistory, Glass.Cyan, Modifier.weight(1f))
            Metric("Upload", rate(status.upBitsPerSec), status.upHistory, Glass.Blue, Modifier.weight(1f))
        }
        GlassCard(Modifier.fillMaxWidth(), onClick = onExitNode) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Column(Modifier.weight(1f)) {
                    Dim("Exit node")
                    Text(status.usingExit?.let { "Internet via $it" } ?: "Off · internet goes direct", color = Glass.Text, fontSize = 14.sp, fontWeight = FontWeight.SemiBold)
                }
                Text("›", color = Glass.TextDim, fontSize = 26.sp)
            }
        }
        accountCard()
    }
}

/**
 * A throughput card: the value over a live graph of the last two minutes,
 * which shows through the glass behind it. The graph eases between samples.
 */
@Composable
private fun Metric(label: String, value: String, history: List<Long>, color: Color, modifier: Modifier) {
    val peak = (history.maxOrNull() ?: 0L).coerceAtLeast(64_000L).toFloat()
    val scale by androidx.compose.animation.core.animateFloatAsState(peak, androidx.compose.animation.core.tween(600), label = "scale")
    GlassCard(modifier.height(84.dp)) {
        Box(Modifier.fillMaxSize()) {
            Canvas(Modifier.matchParentSize().padding(top = 26.dp)) {
                if (history.size < 2) return@Canvas
                val step = size.width / (HISTORY_POINTS - 1)
                val x0 = size.width - step * (history.size - 1)
                fun y(v: Long) = size.height * (1f - (v / scale).coerceIn(0f, 1f) * 0.92f)
                val line = Path()
                history.forEachIndexed { i, v ->
                    val x = x0 + step * i
                    if (i == 0) line.moveTo(x, y(v)) else {
                        // Smooth: a curve through midpoints.
                        val px = x0 + step * (i - 1)
                        val py = y(history[i - 1])
                        line.cubicTo((px + x) / 2, py, (px + x) / 2, y(v), x, y(v))
                    }
                }
                val area = Path().apply {
                    addPath(line)
                    lineTo(size.width, size.height)
                    lineTo(x0, size.height)
                    close()
                }
                drawPath(area, Brush.verticalGradient(listOf(color.copy(alpha = 0.32f), color.copy(alpha = 0f))))
                drawPath(line, color.copy(alpha = 0.75f), style = Stroke(1.6.dp.toPx(), cap = StrokeCap.Round))
            }
            Column {
                Dim(label)
                Text(value, color = Glass.Text, fontSize = 17.sp, fontWeight = FontWeight.SemiBold)
            }
        }
    }
}

private const val HISTORY_POINTS = 60

// Always a number: the value changes in place, never drops back to a dash.
private fun rate(bits: Long): String = when {
    bits <= 0 -> "0 kbit/s"
    bits >= 1_000_000 -> "%.1f Mbit/s".format(bits / 1_000_000.0)
    else -> "%.0f kbit/s".format(bits / 1_000.0)
}

/**
 * The network: live peers from the tunnel when connected, otherwise the
 * account's devices as the console lists them (refreshed on open).
 */
@Composable
fun PeersScreen(
    status: EngineStatus, devices: List<Peer>, signedIn: Boolean, onRefresh: suspend () -> Unit, onSignIn: () -> Unit,
    onPing: suspend (String) -> String, onBrowse: (String) -> Unit, onTerminal: (String, String) -> Unit,
    onAddDevice: () -> Unit,
) {
    LaunchedEffect(Unit) { onRefresh() }
    // Live peers once the tunnel knows other devices; until then the account's devices (and the hub).
    val live = status.peers.any { it.vpnIp.isNotBlank() }
    val list = if (live) status.peers else status.peers + devices
    Column(Modifier.fillMaxSize()) {
        GlassTitle(
            "Peers",
            when {
                live -> "${list.size} online · ${list.count { it.direct }} direct"
                list.isNotEmpty() -> "${list.count { it.online }} of ${list.size} devices online"
                else -> null
            },
        )
        // Onboarding keys belong to an account: signed out, this signs in first.
        Column(Modifier.padding(start = 20.dp, end = 20.dp, bottom = 10.dp)) {
            GlassButton("Add a device", primary = true, onClick = if (signedIn) onAddDevice else onSignIn)
        }
        if (list.isEmpty()) {
            GlassCard(Modifier.fillMaxWidth().padding(horizontal = 20.dp), onClick = if (signedIn) null else onSignIn) {
                Text(
                    if (signedIn) "No other devices in this account yet." else "Sign in to see your account's devices.",
                    color = Glass.TextDim, fontSize = 14.sp,
                )
            }
            return
        }
        LazyColumn(
            contentPadding = PaddingValues(start = 20.dp, end = 20.dp, top = 4.dp, bottom = 110.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            itemsIndexed(list, key = { i, p -> "$i:${p.vpnIp}" }) { _, p ->
                PeerCard(p, live, connected = status.tunnel is TunnelState.Connected, onPing = onPing, onBrowse = onBrowse, onTerminal = onTerminal)
            }
        }
    }
}

/** A peer: tap to see its details and tools (ping, ports, browser). */
@Composable
private fun PeerCard(p: Peer, live: Boolean, connected: Boolean, onPing: suspend (String) -> String, onBrowse: (String) -> Unit, onTerminal: (String, String) -> Unit) {
    val hub = p.vpnIp.isBlank()
    var open by rememberSaveable(p.vpnIp + p.name) { mutableStateOf(false) }
    var ping by remember { mutableStateOf<String?>(null) }
    var ports by remember { mutableStateOf<List<app.wantastic.android.tools.PortScan.Service>?>(null) }
    var busy by remember { mutableStateOf<String?>(null) }
    val scope = rememberCoroutineScope()
    val reachable = connected && !hub && !p.self
    GlassCard(Modifier.fillMaxWidth().animateContentSize(), onClick = if (hub) null else ({ open = !open })) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            val on = if (live || hub) p.direct || hub else p.online
            Box(Modifier.size(10.dp).clip(CircleShape).background(if (on) Glass.Green else Glass.TextDim.copy(alpha = 0.4f)))
            Spacer(Modifier.size(12.dp))
            Column(Modifier.weight(1f)) {
                Text(p.name + if (p.self) " · this phone" else "", color = Glass.Text, fontSize = 16.sp, fontWeight = FontWeight.SemiBold, maxLines = 1)
                Text(if (hub) "Relays traffic when a direct path isn't possible" else p.vpnIp, color = Glass.TextDim, fontSize = 12.sp, fontFamily = if (hub) null else FontFamily.Monospace)
            }
            Dim(
                if (hub) "connected"
                else if (live) (if (p.direct) "direct" else "relay") + (p.latencyMs?.let { " · $it ms" } ?: "")
                else if (p.online) "online" else "offline",
                12,
            )
        }
        if (open && !hub) {
            Spacer(Modifier.size(12.dp))
            Detail("Address", p.vpnIp)
            p.publicIp?.let { Detail("Public address", it) }
            if (live) Detail("Path", if (p.direct) "Direct (peer to peer)" else "Through the hub")
            p.handshakeAgoSec?.let { Detail("Last handshake", if (it < 120) "$it s ago" else "${it / 60} min ago") }
            if (p.rxBytes + p.txBytes > 0) Detail("Traffic", "↓ ${bytes(p.rxBytes)}  ↑ ${bytes(p.txBytes)}")
            ping?.let { Detail("Ping", it) }
            ports?.let { found ->
                Detail("Open ports", if (found.isEmpty()) "None of the common ones" else found.joinToString { "${it.port} ${it.name}" })
            }
            if (!reachable) {
                Dim(if (p.self) "This is this phone." else "Connect to use the tools.", 12)
            } else {
                Spacer(Modifier.size(10.dp))
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    ToolButton(if (busy == "ping") "Pinging…" else "Ping", Modifier.weight(1f)) {
                        if (busy == null) { busy = "ping"; scope.launch { ping = onPing(p.vpnIp); busy = null } }
                    }
                    ToolButton(if (busy == "scan") "Scanning…" else "Scan ports", Modifier.weight(1f)) {
                        if (busy == null) { busy = "scan"; scope.launch { ports = app.wantastic.android.tools.PortScan.scan(p.vpnIp); busy = null } }
                    }
                }
                Spacer(Modifier.size(8.dp))
                val web = ports?.firstOrNull { it.web }
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    ToolButton("Terminal", Modifier.weight(1f)) { onTerminal(p.vpnIp, p.name) }
                    ToolButton("Open in browser", Modifier.weight(1f)) {
                    onBrowse(when {
                        web == null -> "http://${p.vpnIp}/"
                        web.https -> "https://${p.vpnIp}:${web.port}/"
                        else -> "http://${p.vpnIp}:${web.port}/"
                    })
                    }
                }
            }
        }
    }
}

@Composable
private fun Detail(label: String, value: String) {
    Row(Modifier.fillMaxWidth().padding(vertical = 3.dp)) {
        Text(label, color = Glass.TextDim, fontSize = 13.sp, modifier = Modifier.width(118.dp))
        Text(value, color = Glass.Text, fontSize = 13.sp, fontFamily = FontFamily.Monospace)
    }
}

@Composable
private fun ToolButton(text: String, modifier: Modifier, onClick: () -> Unit) {
    Box(
        modifier.height(40.dp).clip(RoundedCornerShape(Glass.Radius - 2.dp)).background(Glass.FillStrong).clickable(onClick = onClick),
        contentAlignment = Alignment.Center,
    ) { Text(text, color = Glass.Text, fontSize = 14.sp, fontWeight = FontWeight.Medium) }
}

private fun bytes(n: Long): String = when {
    n >= 1L shl 30 -> "%.1f GB".format(n / (1L shl 30).toDouble())
    n >= 1L shl 20 -> "%.1f MB".format(n / (1L shl 20).toDouble())
    n >= 1L shl 10 -> "%.0f KB".format(n / 1024.0)
    else -> "$n B"
}

@Composable
fun ExitNodeScreen(status: EngineStatus, onUse: (String?) -> Unit, onOffer: (Boolean) -> Unit) {
    val connected = status.tunnel is TunnelState.Connected
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(NavClearance)) {
        GlassTitle("Exit node", "Send this phone's internet through another of your devices.")
        Column(Modifier.padding(horizontal = 20.dp), verticalArrangement = Arrangement.spacedBy(14.dp)) {
            if (!connected) {
                GlassCard(Modifier.fillMaxWidth()) { Dim("Connect first; exit nodes are devices in your network.", 14) }
            }
            GlassCard(Modifier.fillMaxWidth()) {
                ExitRow("None", "Internet goes out directly", status.usingExit == null, connected) { onUse(null) }
                if (connected && status.exitCandidates.isEmpty()) Dim("No device in this network shares its internet yet.", 12)
                status.exitCandidates.forEach { c ->
                    val chosen = status.usingExit == c.ip
                    val note = when {
                        chosen && status.exitState == "active" -> "In use · " + if (c.direct) "direct" else "through the hub"
                        chosen && status.exitState == "pending" -> "Connecting…"
                        chosen && status.exitState == "standby" -> "Waiting for it to come back"
                        !c.offersExit -> "Does not share its internet"
                        else -> if (c.direct) "Direct path" else "Through the hub"
                    }
                    ExitRow(c.name, note, chosen, connected && c.offersExit) { onUse(c.ip) }
                }
            }
            status.exitNotice?.let { GlassCard(Modifier.fillMaxWidth()) { Text(it, color = Color(0xFFFFB4A9), fontSize = 13.sp) } }
            GlassCard(Modifier.fillMaxWidth()) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Column(Modifier.weight(1f)) {
                        Text("Share this phone", color = Glass.Text, fontSize = 14.sp, fontWeight = FontWeight.SemiBold)
                        Dim("Your devices may send their internet through this phone. Its own network stays unreachable to them.", 12)
                    }
                    Switch(
                        checked = status.offeringExit, onCheckedChange = onOffer, enabled = connected && status.canShareExit,
                        colors = SwitchDefaults.colors(checkedTrackColor = Glass.Blue, uncheckedTrackColor = Glass.Fill, uncheckedBorderColor = Color.Transparent),
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
            Text(name, color = if (enabled) Glass.Text else Glass.TextDim, fontSize = 14.sp, fontWeight = FontWeight.SemiBold)
            Dim(note, 12)
        }
    }
}

@Composable
fun SettingsScreen(deviceName: String, publicKey: String, onConsole: (path: String) -> Unit, accountCard: @Composable () -> Unit) {
    val context = LocalContext.current
    val settings = remember { AppSettings.get(context) }
    val updates = remember { Updates.get(context) }
    val update by updates.status.collectAsState()
    val autoUpdate by settings.autoUpdate.collectAsState()
    val wifiOnly by settings.wifiOnly.collectAsState()
    val motion by settings.motion.collectAsState()
    val scope = rememberCoroutineScope()
    var licenses by rememberSaveable { mutableStateOf(false) }
    BackHandler(enabled = licenses) { licenses = false }
    if (licenses) {
        LicensesScreen()
        return
    }
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(NavClearance)) {
        GlassTitle("Settings")
        Column(Modifier.padding(horizontal = 20.dp), verticalArrangement = Arrangement.spacedBy(14.dp)) {
            Section("Account")
            accountCard()

            Section("Your network")
            GlassCard(Modifier.fillMaxWidth()) {
                SettingsRow("Console", "Everything in your Wantastic account") { onConsole("/dashboard") }
                SettingsRow("Devices", "Add, approve and manage devices") { onConsole("/devices") }
                SettingsRow("Account", "Profile, security and sessions") { onConsole("/accounts/profile") }
            }

            Section("Connection")
            GlassCard(Modifier.fillMaxWidth()) {
                SettingsRow("Always-on VPN", "Reconnect after reboot and network changes") { context.startActivity(Intent(Settings.ACTION_VPN_SETTINGS)) }
                SettingsRow("Battery optimization", "Keep the tunnel alive on this phone") { context.startActivity(Intent(Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS)) }
            }

            Section("Updates")
            GlassCard(Modifier.fillMaxWidth()) {
                SettingsRow(updateTitle(update), updateHint(update, updates.selfUpdating, settings.lastUpdateCheck)) {
                    val activity = context as? android.app.Activity
                    when (update) {
                        is UpdateStatus.Ready, is UpdateStatus.Available -> if (activity != null) {
                            if (update is UpdateStatus.Available && updates.selfUpdating) scope.launch { updates.check(interactive = true) }
                            else updates.install(activity)
                        }
                        UpdateStatus.Checking, is UpdateStatus.Downloading, UpdateStatus.Installing -> Unit
                        else -> scope.launch { updates.check(interactive = true) }
                    }
                }
                if (updates.selfUpdating) {
                    ToggleRow("Automatic updates", "Download and install new versions by themselves", autoUpdate) {
                        settings.setAutoUpdate(it); Updates.schedule(context)
                    }
                    ToggleRow("Download on Wi-Fi only", "Never use mobile data for updates", wifiOnly, enabled = autoUpdate) {
                        settings.setWifiOnly(it); Updates.schedule(context)
                    }
                }
            }

            Section("Appearance")
            GlassCard(Modifier.fillMaxWidth()) {
                ToggleRow("Motion", "Drifting light and glass that follows the phone's tilt", motion) { settings.setMotion(it) }
            }

            Section("This device")
            GlassCard(Modifier.fillMaxWidth()) {
                InfoRow("Name", deviceName)
                InfoRow("Public key", publicKey, mono = true) { copyText(context, "Wantastic public key", publicKey) }
            }

            Section("About")
            GlassCard(Modifier.fillMaxWidth()) {
                SettingsRow("Privacy policy", "What Wantastic collects and why") { onConsole("/privacy") }
                SettingsRow("Terms of service", "The rules for using Wantastic") { onConsole("/terms") }
                SettingsRow("Source code", "github.com/WantasticApp/wantasticd") {
                    context.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(SOURCE_URL)))
                }
                SettingsRow("Open-source licenses", "The libraries Wantastic is built with") { licenses = true }
            }
            Text(
                "Wantastic ${BuildConfig.VERSION_NAME} (${BuildConfig.VERSION_CODE}) · ${if (updates.selfUpdating) "direct" else "Google Play"}",
                color = Glass.TextDim, fontSize = 12.sp, modifier = Modifier.padding(top = 8.dp, start = 6.dp),
            )
        }
    }
}

const val SOURCE_URL = "https://github.com/WantasticApp/wantasticd"

private fun updateTitle(s: UpdateStatus): String = when (s) {
    UpdateStatus.Idle, UpdateStatus.UpToDate, is UpdateStatus.Failed -> "Check for updates"
    UpdateStatus.Checking -> "Checking…"
    is UpdateStatus.Available -> "Update to ${s.version}"
    is UpdateStatus.Downloading -> "Downloading ${s.version} · ${(s.fraction * 100).toInt()}%"
    is UpdateStatus.Ready -> "Install ${s.version}"
    UpdateStatus.Installing -> "Installing…"
}

private fun updateHint(s: UpdateStatus, self: Boolean, lastCheck: Long): String = when (s) {
    UpdateStatus.UpToDate -> "Wantastic is up to date"
    is UpdateStatus.Failed -> s.message
    is UpdateStatus.Downloading -> if (s.patch) "Downloading only what changed" else "Downloading the full app"
    is UpdateStatus.Ready -> "Restarts Wantastic; the tunnel reconnects by itself"
    is UpdateStatus.Available -> if (self) "Tap to download" else "From Google Play"
    else -> when {
        !self -> "Updates come from Google Play"
        lastCheck > 0 -> "Last checked " + DateUtils.getRelativeTimeSpanString(lastCheck)
        else -> "From get.wantastic.app"
    }
}

private fun copyText(context: android.content.Context, label: String, text: String) {
    (context.getSystemService(android.content.Context.CLIPBOARD_SERVICE) as android.content.ClipboardManager)
        .setPrimaryClip(android.content.ClipData.newPlainText(label, text))
}

@Composable
private fun ToggleRow(label: String, hint: String, checked: Boolean, enabled: Boolean = true, onChange: (Boolean) -> Unit) {
    Row(
        Modifier.fillMaxWidth().heightIn(min = 56.dp).padding(vertical = 8.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(Modifier.weight(1f).padding(end = 12.dp)) {
            Text(label, color = if (enabled) Glass.Text else Glass.TextDim, fontSize = 16.sp, fontWeight = FontWeight.Medium)
            Dim(hint, 12)
        }
        Switch(
            checked = checked, onCheckedChange = onChange, enabled = enabled,
            colors = SwitchDefaults.colors(checkedTrackColor = Glass.Blue, uncheckedTrackColor = Glass.Fill, uncheckedBorderColor = Color.Transparent),
        )
    }
}

@Composable
private fun InfoRow(label: String, value: String, mono: Boolean = false, onClick: (() -> Unit)? = null) {
    Column(
        Modifier.fillMaxWidth().clip(RoundedCornerShape(Glass.Radius - 8.dp))
            .then(if (onClick != null) Modifier.clickable(onClick = onClick) else Modifier)
            .padding(vertical = 8.dp),
    ) {
        Dim(label, 12)
        Text(value, color = Glass.Text, fontSize = if (mono) 13.sp else 16.sp, fontFamily = if (mono) FontFamily.Monospace else null)
    }
}

@Composable
private fun Section(title: String) = Text(title.uppercase(), color = Glass.TextDim, fontSize = 12.sp, fontWeight = FontWeight.SemiBold, modifier = Modifier.padding(start = 6.dp))

@Composable
private fun SettingsRow(label: String, hint: String, onClick: () -> Unit) {
    Row(
        Modifier.fillMaxWidth().clip(RoundedCornerShape(Glass.Radius - 8.dp)).clickable(onClick = onClick).heightIn(min = 56.dp).padding(vertical = 8.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(Modifier.weight(1f)) {
            Text(label, color = Glass.Text, fontSize = 16.sp, fontWeight = FontWeight.Medium)
            Dim(hint, 12)
        }
        Text("›", color = Glass.TextDim, fontSize = 26.sp)
    }
}
