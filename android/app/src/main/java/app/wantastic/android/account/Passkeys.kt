package app.wantastic.android.account

import android.content.Context
import androidx.credentials.CredentialManager
import androidx.credentials.GetCredentialRequest
import androidx.credentials.GetPublicKeyCredentialOption
import androidx.credentials.PublicKeyCredential
import androidx.credentials.exceptions.GetCredentialCancellationException
import androidx.credentials.exceptions.GetCredentialException
import androidx.credentials.exceptions.NoCredentialException
import org.json.JSONObject

/**
 * Passkeys on Android through Credential Manager. The server's request is
 * the console's ({"publicKey": PublicKeyCredentialRequestOptionsJSON}) and
 * the answer is the standard WebAuthn JSON the console sends too.
 *
 * Android signs as android:apk-key-hash:<signing key>, which the server must
 * accept, and https://wantastic.app/.well-known/assetlinks.json must name
 * this app for the wantastic.app passkeys to be offered here.
 */
object Passkeys {
    sealed interface Result {
        data class Ok(val json: String) : Result
        data object Cancelled : Result
        data class Failed(val message: String) : Result
    }

    suspend fun assert(context: Context, options: String): Result {
        val request = runCatching {
            val o = JSONObject(options)
            (o.optJSONObject("publicKey") ?: o).toString()
        }.getOrElse { return Result.Failed("The passkey request was not readable.") }
        return try {
            val response = CredentialManager.create(context).getCredential(
                context, GetCredentialRequest(listOf(GetPublicKeyCredentialOption(request))),
            )
            val credential = response.credential as? PublicKeyCredential
                ?: return Result.Failed("No passkey was returned.")
            Result.Ok(credential.authenticationResponseJson)
        } catch (e: GetCredentialCancellationException) {
            Result.Cancelled
        } catch (e: NoCredentialException) {
            Result.Failed("No passkey for this account on this phone. Use the console, or add a passkey there.")
        } catch (e: GetCredentialException) {
            Result.Failed(e.errorMessage?.toString() ?: "Passkey sign-in failed.")
        }
    }
}
