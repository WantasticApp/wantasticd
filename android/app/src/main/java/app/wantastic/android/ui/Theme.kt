package app.wantastic.android.ui

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.material3.Typography
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.Font
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.sp
import app.wantastic.android.R

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

/** Inter: the open typeface closest to Apple's SF Pro (which may not ship on Android). */
val Inter = FontFamily(
    Font(R.font.inter_regular, FontWeight.Normal),
    Font(R.font.inter_medium, FontWeight.Medium),
    Font(R.font.inter_semibold, FontWeight.SemiBold),
    Font(R.font.inter_bold, FontWeight.Bold),
)

/** Every text style in Inter, with SF-like tighter tracking for large text. */
private val InterTypography = Typography().run {
    fun TextStyle.inter(tracking: Float) = copy(fontFamily = Inter, letterSpacing = tracking.sp)
    copy(
        displayLarge = displayLarge.inter(-0.8f), displayMedium = displayMedium.inter(-0.6f), displaySmall = displaySmall.inter(-0.5f),
        headlineLarge = headlineLarge.inter(-0.5f), headlineMedium = headlineMedium.inter(-0.4f), headlineSmall = headlineSmall.inter(-0.3f),
        titleLarge = titleLarge.inter(-0.3f), titleMedium = titleMedium.inter(-0.2f), titleSmall = titleSmall.inter(-0.1f),
        bodyLarge = bodyLarge.inter(-0.2f), bodyMedium = bodyMedium.inter(-0.1f), bodySmall = bodySmall.inter(0f),
        labelLarge = labelLarge.inter(-0.1f), labelMedium = labelMedium.inter(0f), labelSmall = labelSmall.inter(0f),
    )
}

@Composable
fun WantasticTheme(dark: Boolean = isSystemInDarkTheme(), content: @Composable () -> Unit) {
    val colors = if (dark) {
        darkColorScheme(
            primary = Color(0xFF4C9BFF),
            onPrimary = Color.White,
            secondary = Brand.Cyan,
            background = Color(0xFF070C1A),
            surface = Brand.NavyRaised,
            onSurface = Color(0xFFE5ECF5),
            onBackground = Color(0xFFE5ECF5),
            onSurfaceVariant = Color(0xFF9FB3CF),
            outline = Color(0xFF2C3E62),
        )
    } else {
        lightColorScheme(
            primary = Brand.Blue,
            onPrimary = Color.White,
            secondary = Brand.Cyan,
            background = Brand.Ground,
            surface = Color.White,
            onSurface = Brand.Navy,
            onBackground = Brand.Navy,
            onSurfaceVariant = Brand.Muted,
            outline = Brand.Line,
        )
    }
    MaterialTheme(colorScheme = colors, typography = InterTypography, content = content)
}
