package app.wantastic.android.ui

import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.Animatable
import androidx.compose.foundation.interaction.PressInteraction
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.draw.drawBehind
import androidx.compose.ui.geometry.isSpecified
import androidx.compose.ui.graphics.graphicsLayer
import kotlinx.coroutines.launch
import androidx.compose.runtime.collectAsState
import androidx.compose.ui.platform.LocalContext
import app.wantastic.android.settings.AppSettings
import androidx.compose.animation.core.FastOutSlowInEasing
import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.Spring
import androidx.compose.animation.core.animateDpAsState
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.spring
import androidx.compose.animation.core.tween
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.interaction.collectIsPressedAsState
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxScope
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.offset
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Icon
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.scale
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Shape
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.hapticfeedback.HapticFeedbackType
import androidx.compose.ui.platform.LocalHapticFeedback
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

/** Glass on deep navy: the app's one look, light from the logo's blue and cyan. */
object Glass {
    val Ink = Color(0xFF060A16)
    val Fill = Color(0x1AFFFFFF)          // 10% white: frosted surface
    val FillStrong = Color(0x29FFFFFF)    // 16%: raised / selected
    val Edge = Color(0x33FFFFFF)          // 20% hairline
    val Text = Color(0xFFF2F6FC)
    val TextDim = Color(0xFFA9B8CF)       // 7:1 on Ink
    val Blue = Color(0xFF3D8BFF)
    val Cyan = Color(0xFF22D3EE)
    val Green = Color(0xFF34D399)
    /** One corner radius for every surface, as in Apple's apps. */
    val Radius = 24.dp
    val CardShape = RoundedCornerShape(Radius)
}

/** Navy with slowly drifting blue and cyan light behind every screen; glass refracts it. */
@Composable
fun GlassBackground(content: @Composable BoxScope.() -> Unit) {
    val context = LocalContext.current
    val motion by remember { AppSettings.get(context) }.motion.collectAsState()
    val drift = rememberInfiniteTransition(label = "drift")
    val moving by drift.animateFloat(0f, 1f, infiniteRepeatable(tween(18_000, easing = LinearEasing), RepeatMode.Reverse), label = "t")
    val t = if (motion) moving else 0.35f
    val light = rememberBackdrop()
    val tilt = if (motion) rememberTiltLight() else remember { mutableStateOf(Offset(-0.42f, -0.91f)) }
    Box(Modifier.fillMaxSize().background(Glass.Ink)) {
        Canvas(Modifier.fillMaxSize().backdropSource(light)) {
            val w = size.width
            val h = size.height
            drawRect(Glass.Ink)
            drawCircle(
                Brush.radialGradient(listOf(Glass.Blue.copy(alpha = 0.55f), Color.Transparent), center = Offset(w * (0.15f + 0.25f * t), h * 0.18f), radius = w * 0.85f),
                radius = w * 0.85f, center = Offset(w * (0.15f + 0.25f * t), h * 0.18f),
            )
            drawCircle(
                Brush.radialGradient(listOf(Glass.Cyan.copy(alpha = 0.35f), Color.Transparent), center = Offset(w * (0.9f - 0.3f * t), h * (0.55f + 0.1f * t)), radius = w * 0.7f),
                radius = w * 0.7f, center = Offset(w * (0.9f - 0.3f * t), h * (0.55f + 0.1f * t)),
            )
            drawCircle(
                Brush.radialGradient(listOf(Color(0xFF6D5CFF).copy(alpha = 0.22f), Color.Transparent), center = Offset(w * 0.3f, h * (0.95f - 0.1f * t)), radius = w * 0.6f),
                radius = w * 0.6f, center = Offset(w * 0.3f, h * (0.95f - 0.1f * t)),
            )
        }
        CompositionLocalProvider(LocalBackdrops provides Backdrops(light, null), LocalGlassLight provides tilt) {
            content()
        }
    }
}

/** A liquid glass surface: refracts the light behind it, swells and glows under a finger. */
@Composable
fun GlassCard(
    modifier: Modifier = Modifier,
    shape: Shape = Glass.CardShape,
    onClick: (() -> Unit)? = null,
    content: @Composable ColumnScope.() -> Unit,
) {
    val interaction = remember { MutableInteractionSource() }
    val pressed by interaction.collectIsPressedAsState()
    var touch by remember { mutableStateOf(Offset.Unspecified) }
    LaunchedEffect(interaction) {
        interaction.interactions.collect { if (it is PressInteraction.Press) touch = it.pressPosition }
    }
    val swell by animateFloatAsState(if (pressed) 1f else 0f, spring(Spring.DampingRatioMediumBouncy, Spring.StiffnessMediumLow), label = "swell")
    // Cards share one radius; any other shape here is a capsule.
    val corner = if (shape == Glass.CardShape) Glass.Radius else 999.dp
    Column(
        modifier
            .graphicsLayer { scaleX = 1f + 0.02f * swell; scaleY = 1f + 0.02f * swell }
            .liquidGlass(corner, Brush.verticalGradient(listOf(Color(0x24FFFFFF), Color(0x0DFFFFFF))), bulge = { swell })
            .clip(shape)
            .drawBehind {
                if (swell > 0.01f && touch.isSpecified) {
                    drawCircle(
                        Brush.radialGradient(listOf(Color.White.copy(alpha = 0.14f * swell), Color.Transparent), center = touch, radius = size.maxDimension * 0.6f),
                        radius = size.maxDimension * 0.6f, center = touch,
                    )
                }
            }
            .then(if (onClick != null) Modifier.clickable(interaction, indication = null, role = Role.Button, onClick = onClick) else Modifier)
            .padding(18.dp),
        content = content,
    )
}

/** The big connect control: springs when pressed, glows and breathes when on. */
@Composable
fun ConnectOrb(on: Boolean, busy: Boolean, enabled: Boolean, label: String, onClick: () -> Unit) {
    val haptics = LocalHapticFeedback.current
    val interaction = remember { MutableInteractionSource() }
    val pressed by interaction.collectIsPressedAsState()
    val press by animateFloatAsState(if (pressed) 0.92f else 1f, spring(Spring.DampingRatioMediumBouncy, Spring.StiffnessLow), label = "orb")
    val breathe = rememberInfiniteTransition(label = "breathe")
    val pulse by breathe.animateFloat(0.9f, 1.08f, infiniteRepeatable(tween(2200, easing = FastOutSlowInEasing), RepeatMode.Reverse), label = "pulse")
    val glow by animateFloatAsState(if (on) 1f else 0f, spring(stiffness = Spring.StiffnessVeryLow), label = "glow")
    Box(Modifier.size(220.dp), contentAlignment = Alignment.Center) {
        // Halo
        Box(
            Modifier
                .size(220.dp)
                .scale(if (on || busy) pulse else 1f)
                .background(Brush.radialGradient(listOf(Glass.Cyan.copy(alpha = 0.35f * glow + if (busy) 0.15f else 0f), Color.Transparent)), CircleShape),
        )
        Box(
            Modifier
                .size(164.dp)
                .scale(press)
                .liquidGlass(
                    82.dp,
                    Brush.linearGradient(listOf(Glass.Blue.copy(alpha = 0.08f + 0.8f * glow), Glass.Cyan.copy(alpha = 0.06f + 0.75f * glow))),
                    GlassOptics(refraction = 28.dp, zone = 64.dp, blur = 4.dp, dispersion = 0.22f),
                    bulge = { (1f - press) / 0.08f },
                )
                .clip(CircleShape)
                .clickable(interaction, indication = null, enabled = enabled, role = Role.Switch) {
                    haptics.performHapticFeedback(HapticFeedbackType.LongPress)
                    onClick()
                },
            contentAlignment = Alignment.Center,
        ) {
            Column(horizontalAlignment = Alignment.CenterHorizontally) {
                Canvas(Modifier.size(40.dp)) {
                    val stroke = androidx.compose.ui.graphics.drawscope.Stroke(width = 5.dp.toPx(), cap = androidx.compose.ui.graphics.StrokeCap.Round)
                    drawArc(Color.White, startAngle = -60f, sweepAngle = 300f, useCenter = false, style = stroke)
                    drawLine(Color.White, Offset(size.width / 2, 0f), Offset(size.width / 2, size.height * 0.45f), strokeWidth = 5.dp.toPx(), cap = androidx.compose.ui.graphics.StrokeCap.Round)
                }
                Text(label, color = Color.White, fontSize = 15.sp, fontWeight = FontWeight.SemiBold, modifier = Modifier.padding(top = 10.dp))
            }
        }
    }
}

data class PillItem(val label: String, val icon: ImageVector)

/**
 * Floating liquid glass tab bar. The selection is a drop of glass: its
 * leading edge springs to the new tab first and the trailing edge follows,
 * so it stretches, travels and settles like liquid.
 */
@Composable
fun GlassPillNav(items: List<PillItem>, selected: Int, onSelect: (Int) -> Unit, modifier: Modifier = Modifier, sources: List<Backdrop>? = null) {
    val haptics = LocalHapticFeedback.current
    val itemWidth = 78f
    val left = remember { Animatable(itemWidth * selected) }
    val right = remember { Animatable(itemWidth * (selected + 1)) }
    LaunchedEffect(selected) {
        val toLeft = itemWidth * selected
        val forward = toLeft > left.value
        val lead = spring<Float>(Spring.DampingRatioMediumBouncy, Spring.StiffnessMedium)
        val trail = spring<Float>(Spring.DampingRatioLowBouncy, Spring.StiffnessLow)
        launch { left.animateTo(toLeft, if (forward) trail else lead) }
        launch { right.animateTo(toLeft + itemWidth, if (forward) lead else trail) }
    }
    val stretch = ((right.value - left.value) / itemWidth - 1f).coerceAtLeast(0f)
    Box(
        modifier
            .liquidGlass(40.dp, Brush.verticalGradient(listOf(Color(0x1FFFFFFF), Color(0x0FFFFFFF))), GlassOptics(refraction = 14.dp, zone = 26.dp, blur = 14.dp), sources = sources)
            .padding(6.dp),
    ) {
        Box(
            Modifier
                .offset(x = left.value.dp)
                .width((right.value - left.value).dp)
                .height(56.dp)
                .graphicsLayer { scaleY = 1f - 0.12f * stretch.coerceAtMost(1f) }
                .liquidGlass(
                    30.dp, Brush.verticalGradient(listOf(Color(0x33FFFFFF), Color(0x1AFFFFFF))),
                    GlassOptics(refraction = 18.dp, zone = 28.dp, blur = 2.dp, dispersion = 0.25f),
                    sources = sources, bulge = { stretch },
                ),
        )
        Row {
            items.forEachIndexed { i, item ->
                val tint by animateColorAsState(if (i == selected) Glass.Text else Glass.TextDim, label = "tint")
                Column(
                    Modifier
                        .width(itemWidth.dp)
                        .height(56.dp)
                        .clip(RoundedCornerShape(30.dp))
                        .clickable(remember { MutableInteractionSource() }, indication = null, role = Role.Tab) {
                            if (i != selected) haptics.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                            onSelect(i)
                        },
                    horizontalAlignment = Alignment.CenterHorizontally,
                    verticalArrangement = Arrangement.Center,
                ) {
                    Icon(item.icon, contentDescription = null, tint = tint, modifier = Modifier.size(22.dp))
                    Text(item.label, color = tint, fontSize = 11.sp, fontWeight = if (i == selected) FontWeight.SemiBold else FontWeight.Normal)
                }
            }
        }
    }
}

@Composable
fun GlassTitle(text: String, subtitle: String? = null) {
    Column(Modifier.fillMaxWidth().padding(start = 24.dp, end = 24.dp, top = 16.dp, bottom = 12.dp)) {
        Text(text, color = Glass.Text, fontSize = 34.sp, fontWeight = FontWeight.Bold)
        if (subtitle != null) Text(subtitle, color = Glass.TextDim, fontSize = 15.sp)
    }
}
