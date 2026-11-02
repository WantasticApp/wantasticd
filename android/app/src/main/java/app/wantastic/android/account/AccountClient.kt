package app.wantastic.android.account

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONArray
import org.json.JSONObject
import java.io.IOException
import java.util.concurrent.TimeUnit

/** One account signed in on this phone (the console's account jar). */
data class Account(val slot: Int, val email: String, val name: String, val active: Boolean, val needsReauth: Boolean)

/** Where a sign-in stands; each step asks for exactly one thing. */
sealed interface SignIn {
    data class Done(val tenantId: String, val email: String, val name: String) : SignIn
    /** A 6-digit code from an authenticator app ("totp") or a text message ("sms"). */
    data class NeedsCode(val method: String, val phoneLast4: String?) : SignIn
    data class NeedsCaptcha(val imageBase64: String, val loginSessionId: String) : SignIn
    /** The account uses a passkey; the console (which has WebAuthn) finishes the sign-in. */
    data object NeedsPasskey : SignIn
    data class Failed(val message: String) : SignIn
}

/**
 * Wantastic accounts, natively, with the console's own flow and API: sign-in
 * with 2FA over the console channel, then /api/session for the cookie, which
 * the console mini app shares. See ConsoleSocket.
 */
class AccountClient(val origin: String, private val fingerprint: String) {
    val socket = ConsoleSocket(origin)
    private val http = OkHttpClient.Builder().cookieJar(WebViewCookies).callTimeout(30, TimeUnit.SECONDS).build()
    private val json = "application/json".toMediaType()

    /**
     * One sign-in step. Pass [code], [captchaAnswer] and [loginSessionId]
     * when the previous step asked for them; everything else is resent as is.
     */
    suspend fun signIn(
        email: String, password: String, code: String = "", captchaAnswer: String = "", loginSessionId: String = "",
        remember: Boolean = true,
    ): SignIn {
        val r = try {
            socket.call(
                "TenantPortalService", "TenantLogin",
                JSONObject()
                    .put("email", email.trim()).put("password", password).put("totp_code", code.trim())
                    .put("remember_me", remember).put("fingerprint", fingerprint)
                    .put("session_id", loginSessionId).put("captcha_answer", captchaAnswer.trim()).put("passkey_assertion", ""),
            )
        } catch (e: ConsoleSocket.RpcException) {
            return SignIn.Failed(friendly(e.message))
        }
        if (r.optBoolean("requires_passkey")) return SignIn.NeedsPasskey
        if (r.optBoolean("requires_totp")) return SignIn.NeedsCode(r.optString("two_fa_method", "totp"), r.optString("two_fa_phone_last4").ifBlank { null })
        if (!r.optBoolean("success") && r.optBoolean("captcha_required")) {
            val challenge = r.optJSONObject("captcha_challenge")
            return SignIn.NeedsCaptcha(challenge?.optString("image_base64").orEmpty(), r.optString("session_id"))
        }
        if (!r.optBoolean("success")) return SignIn.Failed(friendly(r.optString("message").ifBlank { r.optString("error_code") }))

        // The cookie the console uses; only the session token is trusted server-side.
        val body = JSONObject()
            .put("tenant_id", r.optString("tenant_id")).put("email", r.optString("email")).put("full_name", r.optString("full_name"))
            .put("tier", r.optString("tier")).put("grpc_session_token", r.optString("session_token"))
            .put("remember_me", remember).put("is_first_login", r.optBoolean("is_first_login"))
        post("/api/session", body)
        // The channel reconnects with the new cookie.
        socket.reset()
        return SignIn.Done(r.optString("tenant_id"), r.optString("email"), r.optString("full_name"))
    }

    /** Asks for a new 2FA code by text message. */
    suspend fun sendCode(email: String) {
        socket.call("TenantPortalService", "Send2FACode", JSONObject().put("email", email.trim()))
    }

    /** The accounts signed in on this phone, active first. */
    suspend fun accounts(): List<Account> {
        val r = get("/api/accounts")
        val arr = r.optJSONArray("accounts") ?: JSONArray()
        return (0 until arr.length()).map { arr.getJSONObject(it) }.map {
            Account(it.optInt("slot"), it.optString("email"), it.optString("name"), it.optBoolean("active"), it.optBoolean("needs_reauth"))
        }.sortedByDescending { it.active }
    }

    /** The active account's tenant id, or null when signed out. */
    suspend fun activeTenant(): String? {
        val r = runCatching { get("/api/accounts?active=1") }.getOrNull() ?: return null
        return r.optString("tenant_id").takeIf { r.optBoolean("authenticated") && it.isNotBlank() }
    }

    suspend fun switchTo(slot: Int) {
        post("/api/accounts/switch", JSONObject().put("slot", slot))
        socket.reset()
    }

    /** Signs the active account out; another signed-in account may become active. */
    suspend fun signOut(all: Boolean = false): Boolean {
        val r = post("/api/logout", JSONObject().put("all", all))
        socket.reset()
        return r.optBoolean("switched")
    }

    /** The signed-in account's profile (email, name, tier). */
    suspend fun me(): JSONObject = socket.call("TenantPortalService", "GetTenantAccount")

    /**
     * Adds this phone to the active account: the same call as the console's
     * Claim button. The server takes the account from the session.
     */
    suspend fun claimDevice(name: String, publicKey: String): JSONObject = socket.call(
        "TenantPeerService", "AddTenantPeer",
        JSONObject().put("name", name).put("public_key", publicKey).put("tenant_id", "").put("assigned_ip", "").put("allowed_ips", JSONArray()),
    )

    /** The active account's devices (the console's Devices list). */
    suspend fun peers(): JSONArray =
        socket.call("TenantPeerService", "ListTenantPeers", JSONObject().put("tenant_id", "")).optJSONArray("peers") ?: JSONArray()

    // Password reset: email -> code by text message -> new password.
    suspend fun requestReset(email: String): JSONObject =
        socket.call("TenantPortalService", "RequestPasswordReset", JSONObject().put("email", email.trim()))

    suspend fun verifyResetCode(resetToken: String, code: String): String =
        socket.call("TenantPortalService", "VerifyResetCode", JSONObject().put("reset_token", resetToken).put("verification_code", code.trim()))
            .optString("verified_token")

    suspend fun resetPassword(verifiedToken: String, newPassword: String) {
        val r = socket.call("TenantPortalService", "ResetPassword", JSONObject().put("verified_token", verifiedToken).put("new_password", newPassword))
        if (!r.optBoolean("success", true)) throw IOException(friendly(r.optString("message")))
    }

    // Registration, step by step as in the console.
    suspend fun startRegistration(email: String, password: String, fullName: String, phoneE164: String, countryCode: String): JSONObject =
        socket.call(
            "TenantRegistrationService", "StartRegistration",
            JSONObject().put("email", email.trim()).put("password", password).put("full_name", fullName.trim())
                .put("phone", phoneE164.trim()).put("country_code", countryCode).put("tier", 0),
        )

    suspend fun verifyRegistrationCaptcha(registrationId: String, problemId: String, answer: String): JSONObject =
        socket.call("TenantRegistrationService", "VerifyCaptcha", JSONObject().put("registration_id", registrationId).put("problem_id", problemId).put("answer", answer.trim()))

    suspend fun refreshRegistrationCaptcha(registrationId: String): JSONObject =
        socket.call("TenantRegistrationService", "RefreshRegistrationCaptcha", JSONObject().put("registration_id", registrationId))

    /** Finishes a free account: the code from the text message (or email). Signs in on success. */
    suspend fun verifyRegistration(registrationId: String, code: String, channel: String): SignIn {
        val r = socket.call(
            "TenantRegistrationService", "VerifyPhone",
            JSONObject().put("registration_id", registrationId).put("verification_code", code.trim())
                .put("verification_channel", channel.ifBlank { "sms" }).put("fingerprint", fingerprint),
        )
        if (!r.optBoolean("success")) return SignIn.Failed(friendly(r.optString("message")))
        if (!r.optBoolean("account_created")) return SignIn.Failed("Finish choosing a plan in the console.")
        post(
            "/api/session",
            JSONObject().put("tenant_id", r.optString("tenant_id")).put("email", r.optString("email")).put("full_name", r.optString("full_name"))
                .put("tier", r.optString("tier")).put("grpc_session_token", r.optString("session_token"))
                .put("remember_me", true).put("is_first_login", true),
        )
        socket.reset()
        return SignIn.Done(r.optString("tenant_id"), r.optString("email"), r.optString("full_name"))
    }

    suspend fun resendRegistrationCode(registrationId: String) {
        socket.call("TenantRegistrationService", "ResendPhoneVerification", JSONObject().put("registration_id", registrationId))
    }

    suspend fun phoneRegions(): JSONObject = socket.call("TenantRegistrationService", "GetAllowedPhoneRegions")

    private suspend fun get(path: String): JSONObject = send(Request.Builder().url(origin + path).get())

    private suspend fun post(path: String, body: JSONObject): JSONObject =
        send(Request.Builder().url(origin + path).post(body.toString().toRequestBody(json)))

    // The console's endpoints accept only same-origin requests: say so.
    private suspend fun send(builder: Request.Builder): JSONObject = withContext(Dispatchers.IO) {
        http.newCall(builder.header("Origin", origin).header("Accept", "application/json").build()).execute().use { res ->
            val text = res.body?.string().orEmpty()
            if (!res.isSuccessful && res.code != 401) {
                val msg = runCatching { JSONObject(text).optString("error") }.getOrNull()
                throw IOException(friendly(msg?.ifBlank { null } ?: "Wantastic answered ${res.code}"))
            }
            runCatching { JSONObject(text) }.getOrDefault(JSONObject())
        }
    }

    companion object {
        /** Plain words for the server's codes. */
        fun friendly(raw: String?): String = when {
            raw.isNullOrBlank() -> "Something went wrong. Try again."
            raw.contains("RATE_LIMIT", true) -> "Too many attempts. Wait a minute and try again."
            raw.contains("INVALID_CREDENTIALS", true) || raw.contains("invalid email or password", true) -> "Email or password is not right."
            raw.contains("INVALID_TOTP", true) || raw.contains("invalid code", true) -> "That code is not right."
            raw.contains("needs_reauth", true) -> "Sign in to this account again."
            raw.contains("PEER_LIMIT", true) -> "This account has no room for another device."
            else -> raw.replace('_', ' ').lowercase().replaceFirstChar { it.uppercase() }.takeIf { raw.uppercase() == raw } ?: raw
        }
    }
}
