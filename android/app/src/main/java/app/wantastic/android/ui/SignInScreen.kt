package app.wantastic.android.ui

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
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
import androidx.compose.runtime.remember
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
 * Adds the phone by genkey claim: its key was made on the phone; the owner
 * approves it in the console, in this phone's browser or by scanning the QR
 * code on a computer. Nothing to type.
 */
@Composable
fun SignInScreen(claimUrl: String, onLogIn: () -> Unit, onContinue: () -> Unit) {
    val context = LocalContext.current
    val qr = remember(claimUrl) { qrBitmap(claimUrl, 512) }
    Column(
        modifier = Modifier
            .fillMaxSize()
            .safeDrawingPadding()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 24.dp, vertical = 32.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Text("Add this phone to Wantastic", color = Glass.Text, fontSize = 30.sp, fontWeight = FontWeight.Bold, textAlign = TextAlign.Center)
        Text(
            "Approve it in your account and it joins your network. No password or code to type here.",
            color = Color(0xFFB7C6DB), fontSize = 15.sp, textAlign = TextAlign.Center,
        )
        GlassCard {
            Column(horizontalAlignment = Alignment.CenterHorizontally, verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Image(
                    bitmap = qr.asImageBitmap(),
                    contentDescription = "Claim QR code",
                    modifier = Modifier
                        .size(184.dp)
                        .background(Color.White, RoundedCornerShape(16.dp))
                        .padding(8.dp),
                )
                Text("Or scan from a computer that is signed in", color = Color(0xFFB7C6DB), fontSize = 13.sp)
            }
        }
        Spacer(Modifier.height(8.dp))
        Button(
            onClick = onLogIn,
            modifier = Modifier.fillMaxWidth().height(52.dp),
            shape = RoundedCornerShape(50),
            colors = ButtonDefaults.buttonColors(containerColor = Glass.Blue),
        ) { Text("Log in", fontSize = 16.sp, fontWeight = FontWeight.SemiBold) }
        Button(
            onClick = { copy(context, claimUrl) },
            modifier = Modifier.fillMaxWidth().height(48.dp),
            shape = RoundedCornerShape(50),
            colors = ButtonDefaults.buttonColors(containerColor = Glass.Fill, contentColor = Color.White),
        ) { Text("Copy claim link") }
        Text(
            "The phone connects by itself once approved.",
            color = Color(0xFF94A6C1), fontSize = 12.sp, textAlign = TextAlign.Center,
        )
        TextButton(onClick = onContinue) { Text("Look around first", color = Color(0xFF7DB4FF)) }
    }
}

private fun copy(context: Context, text: String) {
    val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
    clipboard.setPrimaryClip(ClipData.newPlainText("Wantastic claim link", text))
}

private fun qrBitmap(text: String, size: Int): Bitmap {
    val matrix = QRCodeWriter().encode(text, BarcodeFormat.QR_CODE, size, size)
    val pixels = IntArray(size * size) { i ->
        if (matrix.get(i % size, i / size)) 0xFF0B1226.toInt() else 0xFFFFFFFF.toInt()
    }
    return Bitmap.createBitmap(pixels, size, size, Bitmap.Config.ARGB_8888)
}
