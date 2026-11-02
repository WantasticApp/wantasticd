package app.wantastic.android.ui

import androidx.compose.animation.animateColorAsState
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
    val CardShape = RoundedCornerShape(28.dp)
}

/** Navy with slowly drifting blue and cyan light behind every screen. */
@Composable
fun GlassBackground(content: @Composable BoxScope.() -> Unit) {
    val drift = rememberInfiniteTransition(label = "drift")
    val t by drift.animateFloat(0f, 1f, infiniteRepeatable(tween(18_000, easing = LinearEasing), RepeatMode.Reverse), label = "t")
    Box(Modifier.fillMaxSize().background(Glass.Ink)) {
        Canvas(Modifier.fillMaxSize()) {
            val w = size.width
            val h = size.height
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
        content()
    }
}

/** A frosted glass surface with a hairline edge. */
@Composable
fun GlassCard(
    modifier: Modifier = Modifier,
    shape: Shape = Glass.CardShape,
    onClick: (() -> Unit)? = null,
    content: @Composable ColumnScope.() -> Unit,
) {
    val interaction = remember { MutableInteractionSource() }
    val pressed by interaction.collectIsPressedAsState()
    val scale by animateFloatAsState(if (pressed) 0.97f else 1f, spring(Spring.DampingRatioMediumBouncy, Spring.StiffnessMedium), label = "press")
    Column(
        modifier
            .scale(scale)
            .clip(shape)
            .background(Brush.verticalGradient(listOf(Glass.FillStrong, Glass.Fill)))
            .border(1.dp, Brush.verticalGradient(listOf(Glass.Edge, Color(0x0DFFFFFF))), shape)
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
    val ring by animateColorAsState(if (on) Glass.Cyan else Glass.Edge, spring(stiffness = Spring.StiffnessLow), label = "ring")
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
                .clip(CircleShape)
                .background(
                    if (on) Brush.linearGradient(listOf(Glass.Blue, Glass.Cyan))
                    else Brush.linearGradient(listOf(Glass.FillStrong, Glass.Fill)),
                )
                .border(2.dp, ring, CircleShape)
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

/** Floating glass tab bar; the highlight springs to the selected tab. */
@Composable
fun GlassPillNav(items: List<PillItem>, selected: Int, onSelect: (Int) -> Unit, modifier: Modifier = Modifier) {
    val haptics = LocalHapticFeedback.current
    val itemWidth: Dp = 78.dp
    val x by animateDpAsState(itemWidth * selected, spring(Spring.DampingRatioLowBouncy, Spring.StiffnessMediumLow), label = "pill")
    Box(
        modifier
            .clip(RoundedCornerShape(40.dp))
            .background(Brush.verticalGradient(listOf(Color(0x33FFFFFF), Color(0x1FFFFFFF))))
            .border(1.dp, Glass.Edge, RoundedCornerShape(40.dp))
            .padding(6.dp),
    ) {
        Box(Modifier.offset(x = x).width(itemWidth).height(56.dp).clip(RoundedCornerShape(30.dp)).background(Glass.FillStrong))
        Row {
            items.forEachIndexed { i, item ->
                val tint by animateColorAsState(if (i == selected) Glass.Text else Glass.TextDim, label = "tint")
                Column(
                    Modifier
                        .width(itemWidth)
                        .height(56.dp)
                        .clip(RoundedCornerShape(30.dp))
                        .clickable(role = Role.Tab) {
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
