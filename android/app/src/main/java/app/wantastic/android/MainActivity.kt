package app.wantastic.android

import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.AccountBox
import androidx.compose.material.icons.filled.Home
import androidx.compose.material.icons.filled.Person
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material3.Icon
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import app.wantastic.android.claim.ClaimKey
import app.wantastic.android.claim.ClaimLink
import app.wantastic.android.engine.Engines
import app.wantastic.android.engine.TunnelState
import app.wantastic.android.ui.ConsoleScreen
import app.wantastic.android.ui.ExitNodeScreen
import app.wantastic.android.ui.HomeScreen
import app.wantastic.android.ui.PeersScreen
import app.wantastic.android.ui.SettingsScreen
import app.wantastic.android.ui.SignInScreen
import app.wantastic.android.ui.WantasticTheme
import app.wantastic.android.vpn.WantasticVpnService

private enum class Tab(val label: String, val icon: ImageVector) {
    Network("Network", Icons.Filled.Home),
    Peers("Peers", Icons.Filled.Person),
    Console("Console", Icons.Filled.AccountBox),
    Settings("Settings", Icons.Filled.Settings),
}

class MainActivity : ComponentActivity() {

    // Android asks the user once to allow a VPN; then the service may start.
    private val vpnConsent = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
        if (result.resultCode == RESULT_OK) startTunnel()
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val key = ClaimKey.open(this).loadOrCreate()
        val deviceName = ClaimKey.deviceName(this)
        val claimUrl = ClaimLink.build(null, key.publicKey, deviceName)
        setContent {
            WantasticTheme { App(claimUrl, deviceName, onConnect = ::requestTunnel) }
        }
    }

    private fun requestTunnel() {
        val consent: Intent? = VpnService.prepare(this)
        if (consent != null) vpnConsent.launch(consent) else startTunnel()
    }

    private fun startTunnel() {
        startService(Intent(this, WantasticVpnService::class.java).setAction(WantasticVpnService.ACTION_CONNECT))
    }
}

@Composable
private fun App(claimUrl: String, deviceName: String, onConnect: () -> Unit) {
    val engine = Engines.current
    val status by engine.status.collectAsStateWithLifecycle()
    var browsing by rememberSaveable { mutableStateOf(false) }
    if (!status.claimed && !browsing) {
        SignInScreen(claimUrl, onContinue = { browsing = true })
        return
    }
    var tab by rememberSaveable { mutableStateOf(Tab.Network) }
    var exitOpen by remember { mutableStateOf(false) }
    Scaffold(
        bottomBar = {
            NavigationBar {
                Tab.entries.forEach { t ->
                    NavigationBarItem(
                        selected = tab == t,
                        onClick = { tab = t; exitOpen = false },
                        icon = { Icon(t.icon, contentDescription = null) },
                        label = { Text(t.label) },
                    )
                }
            }
        },
    ) { padding ->
        Box(Modifier.fillMaxSize().padding(padding)) {
            when {
                exitOpen -> ExitNodeScreen(status, onUse = engine::useExit, onOffer = engine::offerExit)
                tab == Tab.Network -> HomeScreen(
                    status, deviceName,
                    onToggle = { if (status.tunnel is TunnelState.Connected) engine.disconnect() else onConnect() },
                    onExitNode = { exitOpen = true },
                )
                tab == Tab.Peers -> PeersScreen(status)
                tab == Tab.Console -> ConsoleScreen(ClaimLink.DEFAULT_SERVER)
                else -> SettingsScreen()
            }
        }
    }
}
