package app.wantastic.android.ui

import android.content.Intent
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import app.wantastic.android.account.AccountClient
import app.wantastic.android.account.OnboardingKey
import app.wantastic.android.claim.ClaimLink
import kotlinx.coroutines.launch
import java.text.DateFormat
import java.util.Date

/** Keys made here: valid a week, for one device. Another device takes a new key. */
private const val PHONE_KEY_DAYS = 7
private const val PHONE_KEY_USES = 1

/**
 * "Add a device": an onboarding key as a QR code and a ready install command,
 * to share or copy. The device installed with it joins the account by itself;
 * the same keys and commands as the console's Onboarding keys.
 */
@Composable
fun AddDeviceScreen(client: AccountClient, phoneName: String, onClose: () -> Unit) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var key by remember { mutableStateOf<OnboardingKey?>(null) }
    var error by remember { mutableStateOf<String?>(null) }
    var busy by remember { mutableStateOf(false) }
    var platform by rememberSaveable { mutableStateOf(0) } // 0 Mac & Linux, 1 Windows
    var copied by remember { mutableStateOf(false) }

    suspend fun newKey() {
        busy = true
        error = null
        runCatching { client.createOnboardingKey("Added from $phoneName", PHONE_KEY_DAYS, PHONE_KEY_USES) }
            .onSuccess { key = it; copied = false }
            .onFailure { error = AccountClient.friendly(it.message) }
        busy = false
    }
    LaunchedEffect(Unit) {
        busy = true
        runCatching { client.onboardingKeys() }
            .onSuccess { keys -> key = keys.firstOrNull { it.usable() } }
            .onFailure { error = AccountClient.friendly(it.message) }
        busy = false
        if (key == null && error == null) newKey()
    }

    val command = key?.let { if (platform == 0) unixCommand(it.token) else windowsCommand(it.token) }
    val qr = remember(command) { command?.let { qrBitmap(it, 512) } }

    Column(
        modifier = Modifier.fillMaxSize().safeDrawingPadding().verticalScroll(rememberScrollState())
            .padding(horizontal = 24.dp, vertical = 28.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(14.dp),
    ) {
        Text("Add a device", color = Glass.Text, fontSize = 30.sp, fontWeight = FontWeight.Bold, letterSpacing = (-0.6).sp)
        Text(
            "Run this on the computer or router you want to add. It joins your account by itself.",
            color = Glass.TextDim, fontSize = 15.sp, textAlign = TextAlign.Center,
        )
        GlassSegments(listOf("Mac & Linux", "Windows"), platform) { platform = it; copied = false }
        // Same height whatever the state: the buttons below never move.
        GlassCard(Modifier.fillMaxWidth().height(316.dp)) {
            Column(
                Modifier.fillMaxSize(), horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.spacedBy(10.dp, Alignment.CenterVertically),
            ) {
                when {
                    qr != null && command != null -> {
                        Image(
                            bitmap = qr.asImageBitmap(), contentDescription = "Install command QR code",
                            modifier = Modifier.size(184.dp).background(Color.White, RoundedCornerShape(Glass.Radius - 4.dp)).padding(8.dp),
                        )
                        Text(
                            command, color = Glass.Text, fontSize = 11.sp, fontFamily = FontFamily.Monospace, lineHeight = 15.sp,
                            maxLines = 3, overflow = TextOverflow.Ellipsis, modifier = Modifier.padding(horizontal = 4.dp),
                        )
                    }
                    busy -> CircularProgressIndicator(color = Glass.Blue)
                    else -> Text(error ?: "No onboarding key", color = Glass.TextDim, fontSize = 14.sp, textAlign = TextAlign.Center)
                }
            }
        }
        key?.let { Text(keyLine(it), color = Glass.TextDim, fontSize = 12.sp, textAlign = TextAlign.Center) }
        if (command != null) {
            GlassButton("Share", primary = true) {
                val send = Intent(Intent.ACTION_SEND).setType("text/plain")
                    .putExtra(Intent.EXTRA_SUBJECT, "Add a device to Wantastic")
                    .putExtra(Intent.EXTRA_TEXT, shareText(key!!.token))
                context.startActivity(Intent.createChooser(send, "Share install command"))
            }
            GlassButton(if (copied) "Copied" else "Copy command") {
                copy(context, command, "Wantastic install command")
                copied = true
            }
        } else if (!busy) {
            GlassButton("Try again", primary = true) { scope.launch { newKey() } }
        }
        Text(
            "Anyone with this command can add a device to your account until the key expires or is used.",
            color = Glass.TextDim, fontSize = 12.sp, textAlign = TextAlign.Center,
        )
        TextButton(onClick = { scope.launch { newKey() } }, enabled = !busy) {
            Text("New key", color = Glass.Blue, fontSize = 14.sp)
        }
        TextButton(onClick = onClose) { Text("Done", color = Glass.TextDim, fontSize = 14.sp) }
    }
}

// The console's buildUnixSetupCommand / buildWindowsSetupCommand, for the
// default portal.
internal fun unixCommand(token: String) =
    "curl -fsSL https://get.wantastic.app/install.sh | sudo sh -s -- --login --token ${shellQuote(token)}"

internal fun windowsCommand(token: String) = listOf(
    "\$installer = Join-Path \$env:TEMP 'wantastic-install.ps1'",
    "Invoke-WebRequest -Uri 'https://get.wantastic.app/install.ps1' -OutFile \$installer",
    "powershell.exe -NoProfile -ExecutionPolicy Bypass -File \$installer -Token ${powershellQuote(token)}",
).joinToString("\n")

/** Both commands and the download page, for a message to someone else. */
internal fun shareText(token: String) = buildString {
    appendLine("Add your device to my Wantastic network.")
    appendLine()
    appendLine("Mac or Linux (Terminal):")
    appendLine(unixCommand(token))
    appendLine()
    appendLine("Windows (PowerShell as administrator):")
    appendLine(windowsCommand(token))
    appendLine()
    append("Other devices: ${ClaimLink.DEFAULT_SERVER}")
}

private fun shellQuote(s: String) = "'" + s.replace("'", "'\\''") + "'"

private fun powershellQuote(s: String) = "'" + s.replace("'", "''") + "'"

private fun keyLine(k: OnboardingKey): String {
    val uses = when (val left = k.remaining) {
        null -> "any number of devices"
        1 -> "1 device"
        else -> "$left devices"
    }
    val until = if (k.expiresAtMs == 0L) "never expires" else "until " + DateFormat.getDateInstance(DateFormat.MEDIUM).format(Date(k.expiresAtMs))
    return "${k.name} · $uses · $until"
}
