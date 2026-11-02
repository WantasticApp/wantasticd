package app.wantastic.android.ui

import android.graphics.BitmapFactory
import android.util.Base64
import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.togetherWith
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TextField
import androidx.compose.material3.TextFieldDefaults
import androidx.compose.runtime.Composable
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
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import app.wantastic.android.account.AccountClient
import app.wantastic.android.account.SignIn
import kotlinx.coroutines.launch
import org.json.JSONObject

private enum class AuthPage { SignIn, Register, Reset }

/**
 * Signing in natively, in the console's own steps: email and password, then
 * a 2FA code or a captcha when the server asks. Registration and password
 * reset follow the console too. Passkeys finish in the console mini app,
 * which has WebAuthn. [onSignedIn] runs once the session exists, shared with
 * the console mini app.
 */
@Composable
fun AuthScreen(
    client: AccountClient,
    title: String = "Sign in to Wantastic",
    onSignedIn: () -> Unit,
    onUseConsole: (path: String) -> Unit,
    onClaimByLink: (() -> Unit)?,
    onBrowse: (() -> Unit)?,
    browseLabel: String = "Look around first",
) {
    var page by rememberSaveable { mutableStateOf(AuthPage.SignIn) }
    Column(
        Modifier.fillMaxSize().safeDrawingPadding().imePadding().verticalScroll(rememberScrollState())
            .padding(horizontal = 24.dp, vertical = 28.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(14.dp),
    ) {
        AnimatedContent(page, transitionSpec = { fadeIn() togetherWith fadeOut() }, label = "auth") { p ->
            Column(horizontalAlignment = Alignment.CenterHorizontally, verticalArrangement = Arrangement.spacedBy(14.dp)) {
                when (p) {
                    AuthPage.SignIn -> SignInForm(client, title, onSignedIn, onUseConsole, onRegister = { page = AuthPage.Register }, onForgot = { page = AuthPage.Reset })
                    AuthPage.Register -> RegisterForm(client, onSignedIn, onBack = { page = AuthPage.SignIn })
                    AuthPage.Reset -> ResetForm(client, onDone = { page = AuthPage.SignIn })
                }
            }
        }
        if (page == AuthPage.SignIn) {
            onClaimByLink?.let { TextButton(onClick = it) { Text("Add with a link or QR code instead", color = Color(0xFF7DB4FF)) } }
            onBrowse?.let { TextButton(onClick = it) { Text(browseLabel, color = Glass.TextDim) } }
        }
    }
}

@Composable
private fun SignInForm(
    client: AccountClient, title: String, onSignedIn: () -> Unit, onUseConsole: (String) -> Unit,
    onRegister: () -> Unit, onForgot: () -> Unit,
) {
    val scope = rememberCoroutineScope()
    var email by rememberSaveable { mutableStateOf("") }
    var password by rememberSaveable { mutableStateOf("") }
    var code by rememberSaveable { mutableStateOf("") }
    var captcha by rememberSaveable { mutableStateOf("") }
    var step by remember { mutableStateOf<SignIn?>(null) }
    var loginSession by rememberSaveable { mutableStateOf("") }
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }

    fun submit() {
        if (busy) return
        busy = true; error = null
        scope.launch {
            val r = runCatching {
                client.signIn(email, password, code = code, captchaAnswer = captcha, loginSessionId = loginSession)
            }.getOrElse { SignIn.Failed(AccountClient.friendly(it.message)) }
            busy = false
            when (r) {
                is SignIn.Done -> onSignedIn()
                is SignIn.Failed -> error = r.message
                is SignIn.NeedsCaptcha -> { step = r; loginSession = r.loginSessionId; captcha = "" }
                is SignIn.NeedsCode -> { step = r; code = "" }
                SignIn.NeedsPasskey -> step = r
            }
        }
    }

    AuthTitle(title, "One account for your whole network.")
    when (val s = step) {
        is SignIn.NeedsCode -> {
            Hint(if (s.method == "sms" && s.phoneLast4 != null) "Enter the code sent to your phone ending in ${s.phoneLast4}." else "Enter the 6-digit code from your authenticator app.")
            GlassField(code, { code = it.filter(Char::isDigit).take(8) }, "Code", KeyboardType.NumberPassword, ImeAction.Done, onDone = ::submit)
            if (s.method == "sms") TextButton(onClick = { scope.launch { runCatching { client.sendCode(email) } } }) { Text("Send a new code", color = Color(0xFF7DB4FF)) }
        }
        is SignIn.NeedsCaptcha -> {
            Hint("Type what you see, to show you are not a robot.")
            CaptchaImage(s.imageBase64)
            GlassField(captcha, { captcha = it }, "Answer", KeyboardType.Text, ImeAction.Done, onDone = ::submit)
        }
        SignIn.NeedsPasskey -> {
            Hint("This account signs in with a passkey. Finish in the console; this app signs in with it.")
            PrimaryButton("Continue in the console", busy = false) { onUseConsole("/login?login_hint=" + android.net.Uri.encode(email)) }
            return
        }
        else -> {
            GlassField(email, { email = it }, "Email", KeyboardType.Email, ImeAction.Next)
            GlassField(password, { password = it }, "Password", KeyboardType.Password, ImeAction.Done, secret = true, onDone = ::submit)
        }
    }
    error?.let { ErrorText(it) }
    PrimaryButton(if (step == null) "Sign in" else "Continue", busy, enabled = email.isNotBlank() && password.isNotBlank(), onClick = ::submit)
    if (step == null) {
        TextButton(onClick = onForgot) { Text("Forgot password?", color = Color(0xFF7DB4FF)) }
        SecondaryButton("Create an account", onRegister)
    } else {
        TextButton(onClick = { step = null; error = null }) { Text("Back", color = Glass.TextDim) }
    }
}

@Composable
private fun RegisterForm(client: AccountClient, onSignedIn: () -> Unit, onBack: () -> Unit) {
    val scope = rememberCoroutineScope()
    var name by rememberSaveable { mutableStateOf("") }
    var email by rememberSaveable { mutableStateOf("") }
    var password by rememberSaveable { mutableStateOf("") }
    var phone by rememberSaveable { mutableStateOf("+") }
    var registration by rememberSaveable { mutableStateOf("") }
    var channel by rememberSaveable { mutableStateOf("sms") }
    var captchaId by rememberSaveable { mutableStateOf("") }
    var captchaImage by remember { mutableStateOf("") }
    var answer by rememberSaveable { mutableStateOf("") }
    var code by rememberSaveable { mutableStateOf("") }
    var stage by rememberSaveable { mutableStateOf(0) } // 0 details, 1 captcha, 2 code
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }

    fun run(block: suspend () -> Unit) {
        if (busy) return
        busy = true; error = null
        scope.launch {
            runCatching { block() }.onFailure { error = AccountClient.friendly(it.message) }
            busy = false
        }
    }

    // Where accounts can be made: pre-fill this phone's country code.
    var regions by remember { mutableStateOf("") }
    androidx.compose.runtime.LaunchedEffect(Unit) {
        runCatching { client.phoneRegions() }.onSuccess { r ->
            val list = r.optJSONArray("regions")
            val codes = (0 until (list?.length() ?: 0)).map { list!!.getJSONObject(it) }
            android.util.Log.i("WantasticAccount", "phone regions: ${codes.size}, all=${r.optBoolean("all_regions_allowed")}")
            val country = java.util.Locale.getDefault().country
            codes.firstOrNull { it.optString("country_code").equals(country, true) }?.let { if (phone == "+") phone = it.optString("dial_code").ifBlank { "+" } }
            if (!r.optBoolean("all_regions_allowed") && codes.isNotEmpty()) {
                regions = "Available in " + codes.joinToString { it.optString("flag_emoji") + " " + it.optString("country_name") }
            }
        }.onFailure { android.util.Log.w("WantasticAccount", "phone regions failed: ${it.message}") }
    }

    fun takeCaptcha(r: JSONObject) {
        r.optJSONObject("captcha_challenge")?.let { captchaId = it.optString("problem_id"); captchaImage = it.optString("image_base64") }
    }

    AuthTitle("Create your account", "Free. Your phone number keeps the account yours.")
    when (stage) {
        0 -> {
            GlassField(name, { name = it }, "Full name", KeyboardType.Text, ImeAction.Next)
            GlassField(email, { email = it }, "Email", KeyboardType.Email, ImeAction.Next)
            GlassField(password, { password = it }, "Password", KeyboardType.Password, ImeAction.Next, secret = true)
            GlassField(phone, { v -> phone = "+" + v.filter(Char::isDigit) }, "Phone, with country code", KeyboardType.Phone, ImeAction.Done)
            if (regions.isNotBlank()) Hint(regions)
            error?.let { ErrorText(it) }
            PrimaryButton("Continue", busy, enabled = name.isNotBlank() && email.isNotBlank() && password.length >= 8 && phone.length > 6) {
                run {
                    val r = client.startRegistration(email, password, name, phone, "")
                    registration = r.optString("registration_id")
                    channel = r.optString("verification_channel", "sms")
                    takeCaptcha(r)
                    if (registration.isBlank()) throw IllegalStateException(r.optString("message", "Could not start"))
                    stage = if (captchaId.isNotBlank()) 1 else 2
                }
            }
        }
        1 -> {
            Hint("Type what you see, to show you are not a robot.")
            CaptchaImage(captchaImage)
            GlassField(answer, { answer = it }, "Answer", KeyboardType.Text, ImeAction.Done)
            error?.let { ErrorText(it) }
            PrimaryButton("Continue", busy, enabled = answer.isNotBlank()) {
                run {
                    val r = client.verifyRegistrationCaptcha(registration, captchaId, answer)
                    if (r.optBoolean("verified")) {
                        channel = r.optString("verification_channel", channel)
                        stage = 2
                    } else {
                        answer = ""
                        takeCaptcha(client.refreshRegistrationCaptcha(registration))
                        throw IllegalStateException("That was not right; try this one.")
                    }
                }
            }
        }
        else -> {
            Hint(if (channel == "email") "Enter the code we emailed to $email." else "Enter the code we texted to $phone.")
            GlassField(code, { code = it.filter(Char::isDigit).take(6) }, "6-digit code", KeyboardType.NumberPassword, ImeAction.Done)
            error?.let { ErrorText(it) }
            PrimaryButton("Create account", busy, enabled = code.length == 6) {
                run {
                    when (val r = client.verifyRegistration(registration, code, channel)) {
                        is SignIn.Done -> onSignedIn()
                        is SignIn.Failed -> throw IllegalStateException(r.message)
                        else -> Unit
                    }
                }
            }
            TextButton(onClick = { run { client.resendRegistrationCode(registration) } }) { Text("Send a new code", color = Color(0xFF7DB4FF)) }
        }
    }
    TextButton(onClick = onBack) { Text("I already have an account", color = Glass.TextDim) }
}

@Composable
private fun ResetForm(client: AccountClient, onDone: () -> Unit) {
    val scope = rememberCoroutineScope()
    var email by rememberSaveable { mutableStateOf("") }
    var token by rememberSaveable { mutableStateOf("") }
    var verified by rememberSaveable { mutableStateOf("") }
    var masked by rememberSaveable { mutableStateOf("") }
    var code by rememberSaveable { mutableStateOf("") }
    var password by rememberSaveable { mutableStateOf("") }
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }

    fun run(block: suspend () -> Unit) {
        if (busy) return
        busy = true; error = null
        scope.launch {
            runCatching { block() }.onFailure { error = AccountClient.friendly(it.message) }
            busy = false
        }
    }

    AuthTitle("Reset your password", "We text a code to the phone on your account.")
    when {
        token.isBlank() -> {
            GlassField(email, { email = it }, "Email", KeyboardType.Email, ImeAction.Done)
            error?.let { ErrorText(it) }
            PrimaryButton("Send code", busy, enabled = email.isNotBlank()) {
                run {
                    val r = client.requestReset(email)
                    token = r.optString("reset_token")
                    masked = r.optString("phone_masked")
                    if (token.isBlank()) throw IllegalStateException(r.optString("message", "Could not send a code"))
                }
            }
        }
        verified.isBlank() -> {
            Hint(if (masked.isNotBlank()) "Enter the code sent to $masked." else "Enter the code we sent you.")
            GlassField(code, { code = it.filter(Char::isDigit).take(8) }, "Code", KeyboardType.NumberPassword, ImeAction.Done)
            error?.let { ErrorText(it) }
            PrimaryButton("Continue", busy, enabled = code.isNotBlank()) { run { verified = client.verifyResetCode(token, code).ifBlank { throw IllegalStateException("That code is not right.") } } }
        }
        else -> {
            GlassField(password, { password = it }, "New password", KeyboardType.Password, ImeAction.Done, secret = true)
            error?.let { ErrorText(it) }
            PrimaryButton("Save password", busy, enabled = password.length >= 8) { run { client.resetPassword(verified, password); onDone() } }
        }
    }
    TextButton(onClick = onDone) { Text("Back to sign in", color = Glass.TextDim) }
}

@Composable
private fun AuthTitle(title: String, subtitle: String) {
    Spacer(Modifier.height(12.dp))
    Text(title, color = Glass.Text, fontSize = 30.sp, fontWeight = FontWeight.Bold, textAlign = TextAlign.Center)
    Text(subtitle, color = Glass.TextDim, fontSize = 15.sp, textAlign = TextAlign.Center)
    Spacer(Modifier.height(6.dp))
}

@Composable
private fun Hint(text: String) = Text(text, color = Glass.TextDim, fontSize = 14.sp, textAlign = TextAlign.Center)

@Composable
private fun ErrorText(text: String) = Text(text, color = Color(0xFFFF8A80), fontSize = 13.sp, textAlign = TextAlign.Center)

@Composable
private fun CaptchaImage(base64: String) {
    val bitmap = remember(base64) {
        runCatching {
            val bytes = Base64.decode(base64.substringAfter(","), Base64.DEFAULT)
            BitmapFactory.decodeByteArray(bytes, 0, bytes.size)?.asImageBitmap()
        }.getOrNull()
    }
    if (bitmap != null) {
        Image(bitmap, "Captcha", Modifier.fillMaxWidth().heightIn(max = 120.dp).background(Color.White, RoundedCornerShape(Glass.Radius)).padding(8.dp))
    } else {
        Hint("The picture could not be shown. Continue in the console instead.")
    }
}

@Composable
fun GlassField(
    value: String, onChange: (String) -> Unit, label: String, keyboard: KeyboardType, ime: ImeAction,
    secret: Boolean = false, onDone: (() -> Unit)? = null,
) {
    TextField(
        value = value, onValueChange = onChange, label = { Text(label) }, singleLine = true,
        visualTransformation = if (secret) PasswordVisualTransformation() else androidx.compose.ui.text.input.VisualTransformation.None,
        keyboardOptions = KeyboardOptions(keyboardType = keyboard, imeAction = ime),
        keyboardActions = androidx.compose.foundation.text.KeyboardActions(onDone = { onDone?.invoke() }),
        shape = RoundedCornerShape(Glass.Radius - 8.dp),
        colors = TextFieldDefaults.colors(
            focusedContainerColor = Glass.FillStrong, unfocusedContainerColor = Glass.Fill,
            focusedIndicatorColor = Color.Transparent, unfocusedIndicatorColor = Color.Transparent,
            focusedTextColor = Glass.Text, unfocusedTextColor = Glass.Text,
            focusedLabelColor = Glass.TextDim, unfocusedLabelColor = Glass.TextDim, cursorColor = Glass.Cyan,
        ),
        modifier = Modifier.fillMaxWidth(),
    )
}

@Composable
fun PrimaryButton(text: String, busy: Boolean, enabled: Boolean = true, onClick: () -> Unit) {
    Button(
        onClick = onClick, enabled = enabled && !busy,
        modifier = Modifier.fillMaxWidth().height(52.dp), shape = RoundedCornerShape(50),
        colors = ButtonDefaults.buttonColors(containerColor = Glass.Blue, disabledContainerColor = Glass.Fill),
    ) {
        if (busy) CircularProgressIndicator(Modifier.height(20.dp), color = Color.White, strokeWidth = 2.dp)
        else Text(text, fontSize = 16.sp, fontWeight = FontWeight.SemiBold)
    }
}

@Composable
fun SecondaryButton(text: String, onClick: () -> Unit) {
    Button(
        onClick = onClick, modifier = Modifier.fillMaxWidth().height(48.dp), shape = RoundedCornerShape(50),
        colors = ButtonDefaults.buttonColors(containerColor = Glass.Fill, contentColor = Color.White),
    ) { Text(text) }
}
