package app.wantastic.android

import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import android.Manifest
import android.content.pm.PackageManager
import android.os.Build
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.ui.Alignment
import androidx.compose.ui.unit.dp
import androidx.activity.compose.BackHandler
import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.core.tween
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.scaleIn
import androidx.compose.animation.togetherWith
import app.wantastic.android.ui.GlassBackground
import app.wantastic.android.ui.GlassPillNav
import app.wantastic.android.ui.PillItem
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.AccountBox
import androidx.compose.material.icons.filled.Home
import androidx.compose.material.icons.filled.Person
import androidx.compose.material.icons.filled.Settings
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
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

    // Asked when the user first connects (not at launch): the connection
    // notification is the only one Wantastic shows. Declining still connects.
    private val notificationConsent = registerForActivityResult(ActivityResultContracts.RequestPermission()) {
        requestVpnConsent()
    }

    // Android asks the user once to allow a VPN; then the service may start.
    private val vpnConsent = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
        if (result.resultCode == RESULT_OK) startTunnel()
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        enableEdgeToEdge()
        super.onCreate(savedInstanceState)
        val key = ClaimKey.open(this).loadOrCreate()
        val deviceName = ClaimKey.deviceName(this)
        val claimUrl = ClaimLink.build(null, key.publicKey, deviceName)
        setContent {
            WantasticTheme { App(claimUrl, deviceName, onConnect = ::requestTunnel) }
        }
    }

    private fun requestTunnel() {
        if (Build.VERSION.SDK_INT >= 33 &&
            checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED &&
            !shouldShowRequestPermissionRationale(Manifest.permission.POST_NOTIFICATIONS)
        ) {
            notificationConsent.launch(Manifest.permission.POST_NOTIFICATIONS)
            return
        }
        requestVpnConsent()
    }

    private fun requestVpnConsent() {
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
    GlassBackground {
        if (!status.claimed && !browsing) {
            SignInScreen(claimUrl, onContinue = { browsing = true })
            return@GlassBackground
        }
        var tab by rememberSaveable { mutableStateOf(Tab.Network) }
        var exitOpen by rememberSaveable { mutableStateOf(false) }
        BackHandler(enabled = exitOpen) { exitOpen = false }
        Box(Modifier.fillMaxSize().statusBarsPadding()) {
            AnimatedContent(
                targetState = if (exitOpen) null else tab,
                transitionSpec = { (fadeIn(tween(220)) + scaleIn(initialScale = 0.98f)) togetherWith fadeOut(tween(160)) },
                label = "screen",
            ) { screen ->
                when (screen) {
                    null -> ExitNodeScreen(status, onUse = engine::useExit, onOffer = engine::offerExit)
                    Tab.Network -> HomeScreen(
                        status, deviceName,
                        onToggle = { if (status.tunnel is TunnelState.Connected) engine.disconnect() else onConnect() },
                        onExitNode = { exitOpen = true },
                    )
                    Tab.Peers -> PeersScreen(status)
                    Tab.Console -> ConsoleScreen(ClaimLink.DEFAULT_SERVER)
                    Tab.Settings -> SettingsScreen()
                }
            }
        }
        GlassPillNav(
            items = Tab.entries.map { PillItem(it.label, it.icon) },
            selected = tab.ordinal,
            onSelect = { tab = Tab.entries[it]; exitOpen = false },
            modifier = Modifier.align(Alignment.BottomCenter).navigationBarsPadding().padding(bottom = 12.dp),
        )
    }
}
