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
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
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
import app.wantastic.android.account.DeviceSetups
import app.wantastic.android.claim.ClaimLink
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext

/**
 * "Add by link": this phone joins another network without signing in here.
 * A new key's claim link, as a QR code or a link to share: whoever is signed
 * in to that account approves it, and the new config lands on this phone.
 */
@Composable
fun AddByLinkScreen(setups: DeviceSetups, setupId: String, deviceName: String, onUse: () -> Unit, onClose: () -> Unit) {
    val context = LocalContext.current
    val all by setups.setups.collectAsState()
    val setup = all[setupId]
    val claimUrl = remember(setup?.publicKey) { setup?.let { ClaimLink.build(null, it.publicKey, deviceName) } }
    val qr = remember(claimUrl) { claimUrl?.let { qrBitmap(it, 512) } }
    var mode by rememberSaveable { mutableStateOf(0) } // 0 QR, 1 link
    var copied by remember { mutableStateOf(false) }
    val approved = setup?.claimed == true

    // Waits for the approval while the panel is open (each call waits up to 30 s).
    LaunchedEffect(setup?.publicKey, approved) {
        val key = setup?.publicKey ?: return@LaunchedEffect
        while (!approved) {
            val claim = (app.wantastic.android.engine.Engines.current as? app.wantastic.android.engine.AppEngine)?.waitClaim(ClaimLink.DEFAULT_SERVER, key)
            if (!claim.isNullOrEmpty()) {
                setups.saveClaim(setupId, claim)
                return@LaunchedEffect
            }
            delay(3_000)
        }
    }

    Column(
        modifier = Modifier.fillMaxSize().safeDrawingPadding().verticalScroll(rememberScrollState())
            .padding(horizontal = 24.dp, vertical = 24.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text("Add by link", color = Glass.Text, fontSize = 26.sp, fontWeight = FontWeight.Bold, letterSpacing = (-0.5).sp)
        Text(
            if (approved) "Approved. This phone has a new config." else "Someone signed in to the other account scans this or opens the link, then approves it.",
            color = Glass.TextDim, fontSize = 14.sp, textAlign = TextAlign.Center,
        )
        if (!approved) GlassSegments(listOf("QR code", "Link"), mode) { mode = it }
        GlassCard(Modifier.fillMaxWidth().height(244.dp)) {
            Column(Modifier.fillMaxSize(), horizontalAlignment = Alignment.CenterHorizontally, verticalArrangement = Arrangement.Center) {
                when {
                    approved -> {
                        Text(setup?.network?.let { "Network $it" } ?: "New network", color = Glass.Text, fontSize = 17.sp, fontWeight = FontWeight.SemiBold)
                        Text(setup?.address ?: "", color = Glass.TextDim, fontSize = 13.sp, fontFamily = FontFamily.Monospace, modifier = Modifier.padding(top = 6.dp))
                    }
                    claimUrl == null -> Text("This config was deleted.", color = Glass.TextDim, fontSize = 13.sp)
                    mode == 0 && qr != null -> {
                        Image(
                            bitmap = qr.asImageBitmap(), contentDescription = "Claim QR code",
                            modifier = Modifier.size(176.dp).background(Color.White, RoundedCornerShape(Glass.Radius - 4.dp)).padding(8.dp),
                        )
                        Text("Waiting for approval…", color = Glass.TextDim, fontSize = 12.sp, modifier = Modifier.padding(top = 10.dp))
                    }
                    else -> {
                        Text(
                            claimUrl, color = Glass.Text, fontSize = 12.sp, fontFamily = FontFamily.Monospace, lineHeight = 16.sp,
                            maxLines = 7, overflow = TextOverflow.Ellipsis,
                        )
                        Text(if (copied) "Copied" else "Waiting for approval…", color = Glass.TextDim, fontSize = 12.sp, modifier = Modifier.padding(top = 10.dp))
                    }
                }
            }
        }
        when {
            approved -> {
                GlassButton("Use it now", primary = true) { onUse() }
                GlassButton("Later", onClick = onClose)
            }
            claimUrl != null -> {
                GlassButton("Share link", primary = true) {
                    val send = Intent(Intent.ACTION_SEND).setType("text/plain")
                        .putExtra(Intent.EXTRA_SUBJECT, "Add my phone to your Wantastic network")
                        .putExtra(Intent.EXTRA_TEXT, claimUrl)
                    context.startActivity(Intent.createChooser(send, "Share claim link"))
                }
                GlassButton(if (copied) "Copied" else "Copy link") { copy(context, claimUrl); copied = true }
                TextButton(onClick = onClose) { Text("Done", color = Glass.TextDim, fontSize = 14.sp) }
                Text(
                    "It stays on Home as waiting until it is approved; delete it there if it never is.",
                    color = Glass.TextDim, fontSize = 12.sp, textAlign = TextAlign.Center,
                )
            }
            else -> GlassButton("Close", onClick = onClose)
        }
    }
}
