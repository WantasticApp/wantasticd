package app.wantastic.android.ui

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import app.wantastic.android.tools.SshSession
import kotlinx.coroutines.launch
import org.connectbot.terminal.Terminal
import org.connectbot.terminal.TerminalEmulatorFactory
import java.io.File

/**
 * A terminal on a device in the network: SSH through the tunnel, rendered by
 * ConnectBot's terminal (libvterm). Sign in, then it is a full terminal with
 * the keyboard; Back or Close ends the session.
 */
@Composable
fun TerminalScreen(host: String, name: String, onClose: () -> Unit) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var user by rememberSaveable { mutableStateOf("root") }
    var password by remember { mutableStateOf("") }
    var port by rememberSaveable { mutableStateOf("22") }
    var state by remember { mutableStateOf("login") } // login, connecting, open, closed
    var message by remember { mutableStateOf<String?>(null) }
    val ssh = remember { SshSession(File(context.filesDir, "ssh/known_hosts")) }
    var size by remember { mutableStateOf(80 to 24) }
    val emulator = remember {
        TerminalEmulatorFactory.create(
            initialRows = 24, initialCols = 80,
            defaultForeground = Color(0xFFE6EDF3), defaultBackground = Color(0xFF060A16),
            onKeyboardInput = { ssh.send(it) },
            onResize = { d -> size = d.columns to d.rows; ssh.resize(d.columns, d.rows) },
        )
    }
    DisposableEffect(Unit) { onDispose { ssh.close() } }
    BackHandler { onClose() }

    fun connect() {
        state = "connecting"; message = null
        scope.launch {
            runCatching {
                ssh.connect(
                    host, port.toIntOrNull() ?: 22, user.trim(), password, size.first, size.second,
                    onOutput = { buf, n -> emulator.writeInput(buf.copyOf(n)) },
                    onClosed = { reason -> scope.launch { state = "closed"; message = reason ?: "The session ended." } },
                )
            }.onSuccess { state = "open"; password = "" }
                .onFailure { state = "login"; message = it.message ?: "Could not connect" }
        }
    }

    Column(Modifier.fillMaxSize().background(Glass.Ink).statusBarsPadding().imePadding()) {
        Row(Modifier.fillMaxWidth().height(48.dp).padding(horizontal = 16.dp), verticalAlignment = Alignment.CenterVertically) {
            Column(Modifier.weight(1f)) {
                Text(name, color = Glass.Text, fontSize = 15.sp, fontWeight = FontWeight.SemiBold, maxLines = 1)
                Text("$user@$host", color = Glass.TextDim, fontSize = 11.sp, fontFamily = FontFamily.Monospace, maxLines = 1)
            }
            Text("Close", color = Color(0xFF7DB4FF), fontSize = 15.sp, modifier = Modifier.clickable(onClick = onClose).padding(8.dp))
        }
        if (state == "open" || state == "closed") {
            Box(Modifier.fillMaxSize()) {
                Terminal(
                    terminalEmulator = emulator,
                    modifier = Modifier.fillMaxSize(),
                    backgroundColor = Color(0xFF060A16), foregroundColor = Color(0xFFE6EDF3),
                    keyboardEnabled = state == "open", showSoftKeyboard = true, initialFontSize = 12.sp,
                )
                if (state == "closed") {
                    Text(
                        message ?: "The session ended.", color = Glass.Text, fontSize = 13.sp,
                        modifier = Modifier.align(Alignment.BottomCenter).padding(16.dp).background(Glass.FillStrong).padding(10.dp),
                    )
                }
            }
        } else {
            Column(Modifier.fillMaxWidth().padding(20.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Text("Sign in to $name", color = Glass.Text, fontSize = 22.sp, fontWeight = FontWeight.Bold)
                Text("SSH through your Wantastic network. The password is not saved.", color = Glass.TextDim, fontSize = 13.sp)
                GlassField(user, { user = it }, "User", KeyboardType.Text, ImeAction.Next)
                GlassField(password, { password = it }, "Password", KeyboardType.Password, ImeAction.Done, secret = true, onDone = { connect() }, kind = FieldKind.Password)
                GlassField(port, { port = it.filter(Char::isDigit).take(5) }, "Port", KeyboardType.Number, ImeAction.Done)
                message?.let { Text(it, color = Color(0xFFFF8A80), fontSize = 13.sp) }
                PrimaryButton(if (state == "connecting") "Connecting…" else "Connect", busy = state == "connecting", enabled = user.isNotBlank()) { connect() }
            }
        }
    }
}
