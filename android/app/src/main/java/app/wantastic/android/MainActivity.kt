package app.wantastic.android

import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.SystemBarStyle
import androidx.activity.enableEdgeToEdge
import android.Manifest
import android.content.pm.PackageManager
import android.os.Build
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxScope
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
import app.wantastic.android.ui.LocalBackdrops
import app.wantastic.android.ui.backdropSource
import app.wantastic.android.ui.rememberBackdrop
import app.wantastic.android.ui.GlassPillNav
import app.wantastic.android.ui.PillItem
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.AccountBox
import androidx.compose.material.icons.filled.Home
import androidx.compose.material.icons.filled.Person
import androidx.compose.material.icons.filled.Settings
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import app.wantastic.android.engine.GoEngine
import kotlinx.coroutines.launch
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
import app.wantastic.android.ui.ConsoleMiniApp
import app.wantastic.android.ui.ConsoleWebHolder
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.slideInVertically
import androidx.compose.animation.slideOutVertically
import androidx.compose.animation.core.Spring
import androidx.compose.animation.core.spring
import androidx.compose.ui.platform.LocalContext
import androidx.compose.runtime.remember
import app.wantastic.android.engine.EngineStatus
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

    // Asked at launch: Wantastic is meant to stay on, so get Android's one-time
    // VPN approval up front. Nothing connects from this; declined asks again next launch.
    private val vpnAccess = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) {}

    override fun onCreate(savedInstanceState: Bundle?) {
        // The app is always dark glass: light bar icons whatever the system theme.
        enableEdgeToEdge(
            statusBarStyle = SystemBarStyle.dark(android.graphics.Color.TRANSPARENT),
            navigationBarStyle = SystemBarStyle.dark(android.graphics.Color.TRANSPARENT),
        )
        super.onCreate(savedInstanceState)
        val identity = ClaimKey.open(this)
        val key = identity.loadOrCreate()
        val engine = GoEngine.install(this, identity)
        // While the app is open and not yet approved, wait for the console's claim.
        if (engine is GoEngine) lifecycleScope.launch {
            repeatOnLifecycle(Lifecycle.State.STARTED) { engine.awaitClaim(ClaimLink.DEFAULT_SERVER, key.publicKey) }
        }
        val deviceName = ClaimKey.deviceName(this)
        val claimUrl = ClaimLink.build(null, key.publicKey, deviceName)
        if (savedInstanceState == null) VpnService.prepare(this)?.let(vpnAccess::launch)
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
    val context = LocalContext.current
    // Created on first open, then kept: reopening is instant and signed in.
    var console by remember { mutableStateOf<ConsoleWebHolder?>(null) }
    var consoleOpen by rememberSaveable { mutableStateOf(false) }
    fun openConsole(url: String? = null) {
        val holder = console ?: ConsoleWebHolder(context, url ?: ClaimLink.DEFAULT_SERVER).also { console = it }
        if (url != null && holder.url != url) holder.open(url)
        consoleOpen = true
    }
    // Approved: close the console the claim was made in and show the network.
    LaunchedEffect(status.claimed) { if (status.claimed) consoleOpen = false }
    GlassBackground {
        if (!status.claimed && !browsing) {
            // Approving happens in the console mini app: no outside browser.
            SignInScreen(claimUrl, onLogIn = { openConsole(claimUrl) }, onContinue = { browsing = true })
        } else {
            Tabs(status, deviceName, onConnect, onLogIn = { openConsole(claimUrl) }, onConsole = { openConsole() })
        }
        AnimatedVisibility(
            visible = consoleOpen && console != null,
            enter = slideInVertically(spring(Spring.DampingRatioNoBouncy, Spring.StiffnessMediumLow)) { it } + fadeIn(),
            exit = slideOutVertically(spring(Spring.DampingRatioNoBouncy, Spring.StiffnessMedium)) { it } + fadeOut(),
        ) {
            console?.let { ConsoleMiniApp(it, onClose = { consoleOpen = false }) }
        }
    }
}

@Composable
private fun BoxScope.Tabs(status: EngineStatus, deviceName: String, onConnect: () -> Unit, onLogIn: () -> Unit, onConsole: () -> Unit) {
    val engine = Engines.current
    var tab by rememberSaveable { mutableStateOf(Tab.Network) }
    var exitOpen by rememberSaveable { mutableStateOf(false) }
    BackHandler(enabled = exitOpen) { exitOpen = false }
    // The screens are recorded so the tab bar's glass refracts them as they scroll under it.
    val screens = rememberBackdrop()
    val light = LocalBackdrops.current?.light
    Box(Modifier.fillMaxSize().backdropSource(screens).statusBarsPadding()) {
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
                    onLogIn = onLogIn,
                    onExitNode = { exitOpen = true },
                )
                Tab.Peers -> PeersScreen(status)
                Tab.Settings, Tab.Console -> SettingsScreen()
            }
        }
    }
    GlassPillNav(
        items = Tab.entries.map { PillItem(it.label, it.icon) },
        selected = tab.ordinal,
        onSelect = {
            // The console opens as its own app over this one; the tab under it stays.
            if (Tab.entries[it] == Tab.Console) onConsole() else {
                tab = Tab.entries[it]
                exitOpen = false
            }
        },
        modifier = Modifier.align(Alignment.BottomCenter).navigationBarsPadding().padding(bottom = 12.dp),
        sources = listOfNotNull(light, screens),
    )
}
