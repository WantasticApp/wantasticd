package app.wantastic.android.ui

import android.content.Context
import android.graphics.RenderEffect
import android.graphics.RuntimeShader
import android.graphics.Shader
import android.hardware.Sensor
import android.hardware.SensorEvent
import android.hardware.SensorEventListener
import android.hardware.SensorManager
import android.os.Build
import androidx.annotation.RequiresApi
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.Stable
import androidx.compose.runtime.State
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.drawBehind
import androidx.compose.ui.draw.drawWithContent
import androidx.compose.ui.geometry.CornerRadius
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.RoundRect
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.asComposeRenderEffect
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.drawscope.clipPath
import androidx.compose.ui.graphics.drawscope.translate
import androidx.compose.ui.graphics.layer.GraphicsLayer
import androidx.compose.ui.graphics.layer.drawLayer
import androidx.compose.ui.graphics.rememberGraphicsLayer
import androidx.compose.ui.layout.onGloballyPositioned
import androidx.compose.ui.layout.positionInRoot
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import kotlin.math.atan2
import kotlin.math.cos
import kotlin.math.sin

/*
 * Liquid glass: glass that bends what is behind it, like Apple's.
 *
 * What sits behind glass is recorded once into a GraphicsLayer (a Backdrop).
 * Each glass surface redraws that layer shifted to its own place, through a
 * blur and, on Android 13+, an AGSL lens: the edge refracts inward with a
 * slight colour split, and a specular rim catches a light that follows the
 * phone's tilt. Android 12 gets the blur; older versions the frosted fill.
 * Glass only ever samples layers drawn before it, never itself.
 */

/** Something glass can show through: a recorded layer and where it sits. */
@Stable
class Backdrop internal constructor(val layer: GraphicsLayer) {
    var origin by mutableStateOf(Offset.Zero)
        internal set
}

@Composable
fun rememberBackdrop(): Backdrop {
    val layer = rememberGraphicsLayer()
    return remember(layer) { Backdrop(layer) }
}

/** Records this element's drawing so glass elsewhere can refract it. */
fun Modifier.backdropSource(backdrop: Backdrop): Modifier = this
    .onGloballyPositioned { backdrop.origin = it.positionInRoot() }
    .drawWithContent {
        backdrop.layer.record { this@drawWithContent.drawContent() }
        drawLayer(backdrop.layer)
    }

/** The app's backdrops: the drifting light, and the screens drawn over it. */
class Backdrops(val light: Backdrop, val content: Backdrop?)

val LocalBackdrops = staticCompositionLocalOf<Backdrops?> { null }

/** The glass's light, from the top left, swinging as the phone tilts. */
val LocalGlassLight = staticCompositionLocalOf<State<Offset>> { mutableStateOf(Offset(-0.42f, -0.91f)) }

/** Light direction from gravity, smoothed; listens only while on screen. */
@Composable
fun rememberTiltLight(): State<Offset> {
    val context = LocalContext.current
    val light = remember { mutableStateOf(Offset(-0.42f, -0.91f)) }
    DisposableEffect(context) {
        val sensors = context.getSystemService(Context.SENSOR_SERVICE) as? SensorManager
        val gravity = sensors?.getDefaultSensor(Sensor.TYPE_GRAVITY)
        var angle = BASE_LIGHT_ANGLE
        val listener = object : SensorEventListener {
            override fun onSensorChanged(event: SensorEvent) {
                // Tilting right swings the light left, like a window behind you.
                val target = BASE_LIGHT_ANGLE + (event.values[0] / SensorManager.GRAVITY_EARTH) * 1.1f
                angle += (target - angle) * 0.12f
                // Only real movement (about 2 degrees) moves the light: sensor jitter
                // would otherwise rebuild every glass surface many times a second.
                val shown = atan2(light.value.y, light.value.x)
                if (kotlin.math.abs(angle - shown) > 0.035f) light.value = Offset(cos(angle), sin(angle))
            }
            override fun onAccuracyChanged(sensor: Sensor?, accuracy: Int) = Unit
        }
        if (gravity != null) sensors.registerListener(listener, gravity, SensorManager.SENSOR_DELAY_UI)
        onDispose { sensors?.unregisterListener(listener) }
    }
    return light
}

private val BASE_LIGHT_ANGLE = atan2(-0.91f, -0.42f)

/** How a piece of glass bends light. */
data class GlassOptics(
    /** How far the edge pulls the image inward. */
    val refraction: Dp = 12.dp,
    /** How deep from the edge the bending reaches. */
    val zone: Dp = 20.dp,
    val blur: Dp = 10.dp,
    /** Colour split at the edge, 0..0.3. */
    val dispersion: Float = 0.12f,
    /** Strength of the soft sheen toward the light; 0 for none. */
    val sheen: Float = 1f,
)

/**
 * Draws liquid glass behind this element's content, shaped as a rounded
 * rectangle of [cornerRadius] (half the height makes a capsule or circle).
 * [bulge] (0..1) swells the lens, as under a finger.
 */
@Composable
fun Modifier.liquidGlass(
    cornerRadius: Dp,
    tint: Brush,
    optics: GlassOptics = GlassOptics(),
    sources: List<Backdrop>? = null,
    bulge: () -> Float = { 0f },
): Modifier {
    val backdrops = sources ?: LocalBackdrops.current?.let { listOfNotNull(it.light) } ?: emptyList()
    val light = LocalGlassLight.current
    val glass = rememberGraphicsLayer()
    val lens = remember { if (Build.VERSION.SDK_INT >= 33) Lens() else null }
    var origin by remember { mutableStateOf(Offset.Zero) }
    val cache = remember { EffectKey() }
    return this
        .onGloballyPositioned { origin = it.positionInRoot() }
        .drawBehind {
            val radius = cornerRadius.toPx().coerceAtMost(size.minDimension / 2)
            val shape = Path().apply { addRoundRect(RoundRect(0f, 0f, size.width, size.height, CornerRadius(radius))) }
            val l = light.value
            if (Build.VERSION.SDK_INT >= 31 && backdrops.isNotEmpty()) {
                glass.record {
                    for (b in backdrops) {
                        val shift = origin - b.origin
                        translate(-shift.x, -shift.y) { drawLayer(b.layer) }
                    }
                }
                val swell = bulge().coerceIn(0f, 1f)
                val blur = optics.blur.toPx()
                val key = listOf(size.width, size.height, radius, (swell * 20).toInt(), (l.x * 50).toInt(), (l.y * 50).toInt(), blur, optics)
                if (key != cache.key) {
                    cache.key = key
                    val effect = if (Build.VERSION.SDK_INT >= 33 && lens != null) {
                        lens.effect(
                            width = size.width, height = size.height, radius = radius,
                            refraction = optics.refraction.toPx() * (1f + 0.6f * swell),
                            zone = optics.zone.toPx() * (1f + 0.3f * swell),
                            dispersion = optics.dispersion, light = l, blur = blur, sheen = optics.sheen,
                        )
                    } else if (blur >= 0.5f) {
                        RenderEffect.createBlurEffect(blur, blur, Shader.TileMode.CLAMP)
                    } else {
                        null
                    }
                    glass.renderEffect = effect?.asComposeRenderEffect()
                }
                clipPath(shape) { drawLayer(glass) }
            }
            drawPath(shape, tint)
            if (lens == null) {
                // No shader: a faint rim toward the light only.
                drawPath(
                    shape,
                    Brush.linearGradient(
                        listOf(Color(0x33FFFFFF), Color.Transparent, Color.Transparent),
                        start = Offset(size.width * (0.5f + l.x * 0.5f), size.height * (0.5f + l.y * 0.5f)),
                        end = Offset(size.width * (0.5f - l.x * 0.5f), size.height * (0.5f - l.y * 0.5f)),
                    ),
                    style = Stroke(1.dp.toPx()),
                )
            }
        }
}

/** The inputs the current effect was built from; a new effect only when they change. */
private class EffectKey {
    var key: List<Any>? = null
}

/** The AGSL lens: edge refraction, colour split and a specular rim. */
@RequiresApi(33)
private class Lens {
    private val shader = RuntimeShader(SOURCE)

    fun effect(
        width: Float, height: Float, radius: Float, refraction: Float, zone: Float,
        dispersion: Float, light: Offset, blur: Float, sheen: Float,
    ): RenderEffect {
        shader.setFloatUniform("size", width, height)
        shader.setFloatUniform("radius", radius)
        shader.setFloatUniform("refraction", refraction)
        shader.setFloatUniform("zone", zone.coerceAtLeast(1f))
        shader.setFloatUniform("dispersion", dispersion)
        shader.setFloatUniform("light", light.x, light.y)
        shader.setFloatUniform("sheen", sheen)
        val lensed = RenderEffect.createRuntimeShaderEffect(shader, "content")
        if (blur < 0.5f) return lensed
        // The lens reads the blurred backdrop: chain(outer, inner) runs inner first.
        return RenderEffect.createChainEffect(lensed, RenderEffect.createBlurEffect(blur, blur, Shader.TileMode.CLAMP))
    }

    companion object {
        private const val SOURCE = """
uniform shader content;
uniform float2 size;
uniform float radius;
uniform float refraction;
uniform float zone;
uniform float dispersion;
uniform float2 light;
uniform float sheen;

float box(float2 p, float2 b, float r) {
    float2 q = abs(p) - b + r;
    return length(max(q, 0.0)) + min(max(q.x, q.y), 0.0) - r;
}

half4 main(float2 coord) {
    float2 extent = size * 0.5;
    float2 p = coord - extent;
    float d = box(p, extent, radius);
    float coverage = clamp(0.5 - d, 0.0, 1.0);
    if (coverage <= 0.0) return half4(0.0);

    // Outward normal from the shape's distance field.
    float2 e = float2(1.0, 0.0);
    float2 n = float2(box(p + e.xy, extent, radius) - box(p - e.xy, extent, radius),
                      box(p + e.yx, extent, radius) - box(p - e.yx, extent, radius));
    n = n / max(length(n), 1e-4);

    // Near the edge the glass is curved: pull the image inward, most at the rim.
    float rim = clamp(1.0 + d / zone, 0.0, 1.0);
    float bend = rim * rim * rim;
    float2 shift = -n * bend * refraction;

    half4 c;
    c.r = content.eval(coord + shift * (1.0 + dispersion)).r;
    c.g = content.eval(coord + shift).g;
    c.b = content.eval(coord + shift * (1.0 - dispersion)).b;
    c.a = 1.0;

    // Specular: a soft sheen on the side facing the light; no outline.
    float edge = smoothstep(-6.0, 0.0, d) * (1.0 - smoothstep(-1.0, 0.0, d) * 0.6);
    float facing = max(dot(n, light), 0.0);
    float spec = sheen * pow(facing, 3.0) * (0.32 * edge + 0.12 * bend);
    c.rgb = c.rgb + half3(spec);
    return c * coverage;
}
"""
    }
}
