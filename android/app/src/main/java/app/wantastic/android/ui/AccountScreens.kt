package app.wantastic.android.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import app.wantastic.android.account.AccountClient
import app.wantastic.android.account.AccountState
import app.wantastic.android.account.AccountSync
import kotlinx.coroutines.launch

/**
 * The active account has no setup for this phone: ask before adding it
 * (a new key for that account, claimed as the console's Claim button does).
 */
@Composable
fun AddThisPhoneScreen(sync: AccountSync, email: String, deviceName: String, onOtherAccount: () -> Unit, onNotNow: (() -> Unit)?) {
    val scope = rememberCoroutineScope()
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    Column(
        Modifier.fillMaxSize().safeDrawingPadding().padding(horizontal = 24.dp, vertical = 32.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(14.dp, Alignment.CenterVertically),
    ) {
        Text("Add this phone to your account", color = Glass.Text, fontSize = 30.sp, fontWeight = FontWeight.Bold, textAlign = TextAlign.Center)
        Text("$deviceName joins $email's network and connects with it.", color = Glass.TextDim, fontSize = 15.sp, textAlign = TextAlign.Center)
        Spacer(Modifier.size(8.dp))
        error?.let { Text(it, color = Color(0xFFFF8A80), fontSize = 13.sp, textAlign = TextAlign.Center) }
        PrimaryButton("Add this phone", busy) {
            busy = true; error = null
            scope.launch {
                runCatching { sync.addThisPhone(deviceName) }.onFailure { error = AccountClient.friendly(it.message) }
                busy = false
            }
        }
        SecondaryButton("Use another account", onOtherAccount)
        onNotNow?.let { TextButton(onClick = it) { Text("Not now", color = Glass.TextDim) } }
    }
}

/** Settings: who is signed in, switch between accounts, add one, sign out. */
@Composable
fun AccountCard(sync: AccountSync, state: AccountState, onAddAccount: () -> Unit) {
    val scope = rememberCoroutineScope()
    var error by remember { mutableStateOf<String?>(null) }
    GlassCard(Modifier.fillMaxWidth()) {
        when (state) {
            is AccountState.SignedIn -> {
                val accounts = state.accounts.ifEmpty { listOf(app.wantastic.android.account.Account(-1, state.email, "", true, false)) }
                accounts.forEach { a ->
                    Row(
                        Modifier.fillMaxWidth().clip(RoundedCornerShape(Glass.Radius - 8.dp))
                            .clickable(enabled = !a.active && a.slot >= 0) {
                                error = null
                                scope.launch { runCatching { sync.switchTo(a.slot) }.onFailure { error = AccountClient.friendly(it.message) } }
                            }
                            .heightIn(min = 56.dp).padding(vertical = 8.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Avatar(a.name.ifBlank { a.email })
                        Column(Modifier.weight(1f).padding(start = 12.dp)) {
                            Text(a.name.ifBlank { a.email }, color = Glass.Text, fontSize = 16.sp, fontWeight = FontWeight.Medium, maxLines = 1)
                            Text(
                                when { a.active -> "Active"; a.needsReauth -> "Sign in again to use"; else -> a.email },
                                color = Glass.TextDim, fontSize = 12.sp, maxLines = 1,
                            )
                        }
                        if (a.active) Box(Modifier.size(10.dp).clip(CircleShape).background(Glass.Green))
                    }
                }
                Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                    TextButton(onClick = onAddAccount) { Text("Add account", color = Color(0xFF7DB4FF)) }
                    TextButton(onClick = { scope.launch { runCatching { sync.signOut() }.onFailure { error = AccountClient.friendly(it.message) } } }) {
                        Text("Sign out", color = Glass.TextDim)
                    }
                }
            }
            is AccountState.Offline -> Text("Offline. Your saved setups still connect.", color = Glass.TextDim, fontSize = 14.sp)
            AccountState.Checking -> Text("Checking your account…", color = Glass.TextDim, fontSize = 14.sp)
            AccountState.SignedOut -> {
                Text("Not signed in", color = Glass.Text, fontSize = 16.sp, fontWeight = FontWeight.Medium)
                TextButton(onClick = onAddAccount) { Text("Sign in", color = Color(0xFF7DB4FF)) }
            }
        }
        error?.let { Text(it, color = Color(0xFFFF8A80), fontSize = 12.sp) }
    }
}

@Composable
private fun Avatar(name: String) {
    Box(
        Modifier.size(36.dp).clip(CircleShape).background(Brush.linearGradient(listOf(Glass.Blue, Glass.Cyan))),
        contentAlignment = Alignment.Center,
    ) {
        Text(name.trim().take(1).uppercase(), color = Color.White, fontSize = 16.sp, fontWeight = FontWeight.SemiBold)
    }
}
