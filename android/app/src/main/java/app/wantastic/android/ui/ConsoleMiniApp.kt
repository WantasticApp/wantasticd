package app.wantastic.android.ui

import android.annotation.SuppressLint
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.graphics.Bitmap
import android.net.Uri
import android.app.Activity
import android.webkit.WebChromeClient
import android.webkit.WebView
import android.webkit.WebViewClient
import androidx.activity.compose.BackHandler
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalView
import androidx.compose.runtime.DisposableEffect
import androidx.core.view.WindowCompat
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.viewinterop.AndroidView

/**
 * The console's WebView, kept for the life of the app so reopening the
 * console is instant and stays signed in, like a mini program.
 */
class ConsoleWebHolder(context: Context, private val home: String) {
    var progress by mutableIntStateOf(0)
        private set
    var title by mutableStateOf("Console")
        private set

    @SuppressLint("SetJavaScriptEnabled")
    val web: WebView = WebView(context).apply {
        settings.javaScriptEnabled = true
        settings.domStorageEnabled = true
        webViewClient = object : WebViewClient() {
            override fun onPageStarted(view: WebView, url: String?, favicon: Bitmap?) { this@ConsoleWebHolder.progress = 10 }
            override fun onPageFinished(view: WebView, url: String?) {
                this@ConsoleWebHolder.progress = 100
                view.title?.takeIf { it.isNotBlank() }?.let { this@ConsoleWebHolder.title = it.substringBefore(" · ").substringBefore(" | ") }
            }
        }
        webChromeClient = object : WebChromeClient() {
            override fun onProgressChanged(view: WebView, newProgress: Int) { this@ConsoleWebHolder.progress = newProgress }
        }
        loadUrl(home)
    }

    val url: String get() = web.url ?: home

    fun open(url: String) = web.loadUrl(url)
}

/**
 * The console as its own full-screen app over Wantastic, in the mini-program
 * style: the page fills the screen with no header, a floating capsule top
 * right carries the menu and close, Back walks the console's history and
 * then closes it.
 */
@Composable
fun ConsoleMiniApp(holder: ConsoleWebHolder, onClose: () -> Unit) {
    val context = LocalContext.current
    var menu by remember { mutableStateOf(false) }
    // Dark status bar icons over the console's white header, light again after.
    val view = LocalView.current
    DisposableEffect(Unit) {
        val window = (view.context as? Activity)?.window
        val bars = window?.let { WindowCompat.getInsetsController(it, view) }
        val before = bars?.isAppearanceLightStatusBars
        bars?.isAppearanceLightStatusBars = true
        onDispose { if (before != null) bars.isAppearanceLightStatusBars = before }
    }
    BackHandler {
        if (holder.web.canGoBack()) holder.web.goBack() else onClose()
    }
    // The console takes the whole screen; only the capsule floats over it.
    Box(Modifier.fillMaxSize().background(Color(0xFFF4F7FB)).imePadding()) {
        AndroidView(
            factory = { holder.web.also { (it.parent as? android.view.ViewGroup)?.removeView(it) } },
            modifier = Modifier.fillMaxSize().statusBarsPadding(),
        )
        if (holder.progress in 1..99) {
            LinearProgressIndicator(
                progress = { holder.progress / 100f },
                modifier = Modifier.fillMaxWidth().statusBarsPadding().height(2.dp),
                color = Glass.Blue,
            )
        }
        // The capsule: menu · close.
        Row(
            Modifier.align(Alignment.TopEnd)
                .statusBarsPadding()
                .padding(top = 8.dp, end = 12.dp)
                .clip(RoundedCornerShape(50))
                .background(Color(0xE6FFFFFF))
                .height(32.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Box(
                Modifier.width(44.dp).height(32.dp).clickable { menu = true }.semantics { contentDescription = "More" },
                contentAlignment = Alignment.Center,
            ) {
                Canvas(Modifier.size(width = 20.dp, height = 6.dp)) {
                    val r = 2.4.dp.toPx()
                    for (k in 0..2) drawCircle(Color(0xFF0B1226), r, Offset(r + k * (size.width - 2 * r) / 2, size.height / 2))
                }
                DropdownMenu(expanded = menu, onDismissRequest = { menu = false }) {
                    DropdownMenuItem(text = { Text("Reload") }, onClick = { menu = false; holder.web.reload() })
                    DropdownMenuItem(text = { Text("Open in browser") }, onClick = {
                        menu = false
                        context.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(holder.url)))
                    })
                    DropdownMenuItem(text = { Text("Copy link") }, onClick = {
                        menu = false
                        (context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager)
                            .setPrimaryClip(ClipData.newPlainText("Wantastic console", holder.url))
                    })
                }
            }
            Box(Modifier.width(0.5.dp).height(18.dp).background(Color(0x330B1226)))
            Box(
                Modifier.width(44.dp).height(32.dp).clickable(onClick = onClose).semantics { contentDescription = "Close console" },
                contentAlignment = Alignment.Center,
            ) {
                Canvas(Modifier.size(18.dp)) {
                    drawCircle(Color(0xFF0B1226), size.minDimension / 2 - 1.dp.toPx(), style = Stroke(1.8.dp.toPx()))
                    drawCircle(Color(0xFF0B1226), 3.dp.toPx())
                }
            }
        }
    }
}
