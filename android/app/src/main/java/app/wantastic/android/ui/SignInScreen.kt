package app.wantastic.android.ui

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.graphics.Bitmap
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.google.zxing.BarcodeFormat
import com.google.zxing.qrcode.QRCodeWriter

/**
 * Adds the phone without signing in here (the genkey claim): its key was
 * made on the phone and travels in the QR code or the link; someone signed
 * in to the account approves it, on a computer or another phone. The engine
 * notices the approval and the phone moves on by itself.
 */
@Composable
fun ClaimByLinkScreen(claimUrl: String, onLogIn: () -> Unit, onBack: () -> Unit) {
    val context = LocalContext.current
    var mode by rememberSaveable { mutableStateOf(0) } // 0 QR, 1 link
    val qr = remember(claimUrl) { qrBitmap(claimUrl, 512) }
    var copied by remember { mutableStateOf(false) }
    Column(
        modifier = Modifier.fillMaxSize().safeDrawingPadding().padding(horizontal = 24.dp, vertical = 28.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(14.dp),
    ) {
        Text("Add this phone", color = Glass.Text, fontSize = 30.sp, fontWeight = FontWeight.Bold, letterSpacing = (-0.6).sp)
        Text(
            "Whoever is signed in to the account approves it. Nothing to type here.",
            color = Glass.TextDim, fontSize = 15.sp, textAlign = TextAlign.Center,
        )
        GlassSegments(listOf("QR code", "Link"), mode) { mode = it }
        // Same height in both modes: switching never moves the buttons below.
        GlassCard(Modifier.fillMaxWidth().height(252.dp)) {
            Column(Modifier.fillMaxSize(), horizontalAlignment = Alignment.CenterHorizontally, verticalArrangement = Arrangement.Center) {
                if (mode == 0) {
                    Image(
                        bitmap = qr.asImageBitmap(), contentDescription = "Claim QR code",
                        modifier = Modifier.size(184.dp).background(Color.White, RoundedCornerShape(Glass.Radius - 4.dp)).padding(8.dp),
                    )
                    Text("Scan with a phone or computer that is signed in", color = Glass.TextDim, fontSize = 12.sp, modifier = Modifier.padding(top = 10.dp))
                } else {
                    Text(
                        claimUrl, color = Glass.Text, fontSize = 12.sp, fontFamily = FontFamily.Monospace, lineHeight = 16.sp,
                        maxLines = 7, overflow = TextOverflow.Ellipsis,
                    )
                    Text(if (copied) "Copied" else "Send it to someone signed in to the account", color = Glass.TextDim, fontSize = 12.sp, modifier = Modifier.padding(top = 10.dp))
                }
            }
        }
        if (mode == 1) {
            GlassButton("Share link", primary = true) {
                val send = Intent(Intent.ACTION_SEND).setType("text/plain")
                    .putExtra(Intent.EXTRA_SUBJECT, "Add my phone to Wantastic")
                    .putExtra(Intent.EXTRA_TEXT, claimUrl)
                context.startActivity(Intent.createChooser(send, "Share claim link"))
            }
            GlassButton("Copy link") { copy(context, claimUrl); copied = true }
        } else {
            GlassButton("Approve on this phone", primary = true, onClick = onLogIn)
            GlassButton("Sign in instead", onClick = onBack)
        }
        Text("The phone connects by itself once approved.", color = Glass.TextDim, fontSize = 12.sp, textAlign = TextAlign.Center)
    }
}

internal fun copy(context: Context, text: String, label: String = "Wantastic claim link") {
    val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
    clipboard.setPrimaryClip(ClipData.newPlainText(label, text))
}

internal fun qrBitmap(text: String, size: Int): Bitmap {
    val matrix = QRCodeWriter().encode(text, BarcodeFormat.QR_CODE, size, size)
    val pixels = IntArray(size * size) { i ->
        if (matrix.get(i % size, i / size)) 0xFF0B1226.toInt() else 0xFFFFFFFF.toInt()
    }
    return Bitmap.createBitmap(pixels, size, size, Bitmap.Config.ARGB_8888)
}
