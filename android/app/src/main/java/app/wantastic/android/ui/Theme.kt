package app.wantastic.android.ui

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

/** The console's palette: navy, the logo's blue and cyan, slate text. */
object Brand {
    val Navy = Color(0xFF0B1226)
    val NavyRaised = Color(0xFF13203D)
    val Blue = Color(0xFF1677FF)
    val Link = Color(0xFF1668E3)
    val Cyan = Color(0xFF00C2FF)
    val Ground = Color(0xFFF4F7FB)
    val Line = Color(0xFFDCE3EC)
    val Muted = Color(0xFF475569)
    val OnNavyMuted = Color(0xFF9FB3CF)
    val Good = Color(0xFF16A34A)
    val GoodBg = Color(0xFFDCFCE7)
    val Amber = Color(0xFFB45309)
}

@Composable
fun WantasticTheme(content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = lightColorScheme(
            primary = Brand.Blue,
            onPrimary = Color.White,
            secondary = Brand.Cyan,
            background = Brand.Ground,
            surface = Color.White,
            onSurface = Brand.Navy,
            onBackground = Brand.Navy,
            outline = Brand.Line,
        ),
        content = content,
    )
}
