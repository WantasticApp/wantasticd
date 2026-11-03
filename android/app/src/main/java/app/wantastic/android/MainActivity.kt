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
import androidx.compose.material.icons.filled.Home
import androidx.compose.material.icons.filled.Person
import androidx.compose.material.icons.filled.Settings
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import app.wantastic.android.engine.GoEngine
import app.wantastic.android.update.Updates
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
import androidx.compose.runtime.rememberCoroutineScope
import app.wantastic.android.account.AccountClient
import app.wantastic.android.account.AccountState
import app.wantastic.android.account.AccountSync
import app.wantastic.android.account.DeviceSetups
import app.wantastic.android.ui.AccountCard
import app.wantastic.android.ui.HomeAccountCard
import app.wantastic.android.ui.HomeConfigsCard
import app.wantastic.android.ui.AddThisPhoneScreen
import app.wantastic.android.ui.AuthScreen
import app.wantastic.android.ui.ClaimByLinkScreen
import app.wantastic.android.ui.WantasticTheme
import app.wantastic.android.vpn.WantasticVpnService

private enum class Tab(val label: String, val icon: ImageVector) {
    Network("Network", Icons.Filled.Home),
    Peers("Peers", Icons.Filled.Person),
    Settings("Settings", Icons.Filled.Settings),
}

/** Sent by the direct build's "update ready" notification. */
const val ACTION_INSTALL_UPDATE = "app.wantastic.android.action.INSTALL_UPDATE"

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
        val setups = ClaimKey.open(this).setups()
        val engine = GoEngine.install(this, setups)
        val deviceName = ClaimKey.deviceName(this)
        // A stable, non-identifying id for the server's sign-in checks.
        val fingerprint = "android:" + setups.current().publicKey.hashCode().toUInt().toString(16)
        val sync = AccountSync(AccountClient(ClaimLink.DEFAULT_SERVER, fingerprint), setups) { (engine as? GoEngine)?.refresh() }
        lifecycleScope.launch {
            repeatOnLifecycle(Lifecycle.State.STARTED) {
                // Each time the app comes back: who is signed in (here or in the console), and that account's setup.
                launch { sync.sync() }
                // Wait for the active setup's approval while open.
                if (engine is GoEngine) engine.awaitClaims(ClaimLink.DEFAULT_SERVER)
            }
        }
        if (savedInstanceState == null) VpnService.prepare(this)?.let(vpnAccess::launch)
        Updates.schedule(this)
        lifecycleScope.launch { Updates.get(this@MainActivity).check(interactive = false) }
        handleUpdateIntent(intent)
        setContent {
            WantasticTheme { App(sync, setups, deviceName, onConnect = ::requestTunnel) }
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        handleUpdateIntent(intent)
    }

    // Tapping "Wantastic X is ready" installs it.
    private fun handleUpdateIntent(intent: Intent?) {
        if (intent?.action == ACTION_INSTALL_UPDATE) Updates.get(this).install(this)
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

    private fun startTunnel() = Engines.current.connect()
}

@Composable
private fun App(sync: AccountSync, setups: DeviceSetups, deviceName: String, onConnect: () -> Unit) {
    val engine = Engines.current
    val status by engine.status.collectAsStateWithLifecycle()
    val account by sync.account.collectAsStateWithLifecycle()
    val activeSetup by setups.active.collectAsStateWithLifecycle()
    val scope = rememberCoroutineScope()
    var browsing by rememberSaveable { mutableStateOf(false) }
    var byLink by rememberSaveable { mutableStateOf(false) }
    var signingIn by rememberSaveable { mutableStateOf(false) }
    var notNow by rememberSaveable { mutableStateOf<String?>(null) }
    val context = LocalContext.current
    // Created on first open, then kept: reopening is instant and signed in.
    var console by remember { mutableStateOf<ConsoleWebHolder?>(null) }
    var consoleOpen by rememberSaveable { mutableStateOf(false) }
    // A peer's web page, through the tunnel; a fresh browser each time.
    var browser by remember { mutableStateOf<ConsoleWebHolder?>(null) }
    // An SSH terminal on a peer (address, name).
    var terminal by remember { mutableStateOf<Pair<String, String>?>(null) }
    // "Add a device": an onboarding key as a QR code and install command.
    var addDevice by rememberSaveable { mutableStateOf(false) }
    BackHandler(enabled = addDevice) { addDevice = false }
    // "Add by link": the id of the config whose claim QR code is showing.
    var byLinkSetup by rememberSaveable { mutableStateOf<String?>(null) }
    BackHandler(enabled = byLinkSetup != null) { byLinkSetup = null }
    fun openConsole(url: String? = null) {
        val holder = console ?: ConsoleWebHolder(context, url ?: ClaimLink.DEFAULT_SERVER).also { console = it }
        if (url != null && holder.url != url) holder.open(url)
        consoleOpen = true
    }
    val publicKey = remember(activeSetup, status.claimed) { setups.current().publicKey }
    val claimUrl = remember(publicKey) { ClaimLink.build(null, publicKey, deviceName) }
    fun signedIn() {
        signingIn = false
        // The console mini app shares the session; show it as the new account.
        console?.web?.reload()
        scope.launch { sync.sync() }
    }
    // Approved: close the console the claim was made in and show the network.
    LaunchedEffect(status.claimed) { if (status.claimed) consoleOpen = false }
    val signedInState = account as? AccountState.SignedIn
    BackHandler(enabled = signingIn || byLink) { signingIn = false; byLink = false }
    GlassBackground {
        when {
            signingIn -> AuthScreen(
                sync.client, title = if (signedInState != null) "Add an account" else "Sign in to Wantastic",
                onSignedIn = ::signedIn, onUseConsole = { path -> openConsole(ClaimLink.DEFAULT_SERVER + path) },
                onClaimByLink = null, onBrowse = { signingIn = false }, browseLabel = "Not now",
            )
            // Signed in to an account this phone is not in yet: ask first.
            signedInState?.needsSetup == true && notNow != signedInState.tenantId -> AddThisPhoneScreen(
                sync, signedInState.email, deviceName,
                onOtherAccount = { signingIn = true },
                onNotNow = if (status.claimed) ({ notNow = signedInState.tenantId }) else null,
            )
            status.claimed || browsing -> Tabs(
                status, sync, setups, account, deviceName, publicKey, onConnect,
                onLogIn = { if (signedInState == null) signingIn = true else notNow = null },
                onAddAccount = { signingIn = true },
                onConsole = { path -> openConsole(ClaimLink.DEFAULT_SERVER + path) },
                onBrowse = { url -> browser = ConsoleWebHolder(context, url) },
                onTerminal = { ip, name -> terminal = ip to name },
                onAddDevice = { addDevice = true },
                onAddByLink = { id ->
                    // One waiting link config at a time: reopen it rather than make another.
                    byLinkSetup = id ?: setups.setups.value.values.firstOrNull { it.account.startsWith(DeviceSetups.LINK_PREFIX) && !it.claimed }?.account
                        ?: setups.newLinkSetup().account
                },
            )
            byLink -> ClaimByLinkScreen(claimUrl, onLogIn = { openConsole(claimUrl) }, onBack = { byLink = false })
            account == AccountState.Checking -> Unit
            else -> AuthScreen(
                sync.client, onSignedIn = ::signedIn, onUseConsole = { path -> openConsole(ClaimLink.DEFAULT_SERVER + path) },
                onClaimByLink = { byLink = true }, onBrowse = { browsing = true },
            )
        }
        AnimatedVisibility(
            visible = consoleOpen && console != null,
            enter = slideInVertically(spring(Spring.DampingRatioNoBouncy, Spring.StiffnessMediumLow)) { it } + fadeIn(),
            exit = slideOutVertically(spring(Spring.DampingRatioNoBouncy, Spring.StiffnessMedium)) { it } + fadeOut(),
        ) {
            // Closing the console may follow a sign-in or account switch made there.
            console?.let { ConsoleMiniApp(it, onClose = { consoleOpen = false; scope.launch { sync.sync() } }) }
        }
        AnimatedVisibility(
            visible = browser != null,
            enter = slideInVertically(spring(Spring.DampingRatioNoBouncy, Spring.StiffnessMediumLow)) { it } + fadeIn(),
            exit = slideOutVertically(spring(Spring.DampingRatioNoBouncy, Spring.StiffnessMedium)) { it } + fadeOut(),
        ) {
            browser?.let { b -> ConsoleMiniApp(b, onClose = { b.web.destroy(); browser = null }) }
        }
        AnimatedVisibility(
            visible = terminal != null,
            enter = slideInVertically(spring(Spring.DampingRatioNoBouncy, Spring.StiffnessMediumLow)) { it } + fadeIn(),
            exit = slideOutVertically(spring(Spring.DampingRatioNoBouncy, Spring.StiffnessMedium)) { it } + fadeOut(),
        ) {
            terminal?.let { (ip, name) -> app.wantastic.android.ui.TerminalScreen(ip, name, onClose = { terminal = null }) }
        }
        AnimatedVisibility(
            visible = addDevice,
            enter = slideInVertically(spring(Spring.DampingRatioNoBouncy, Spring.StiffnessMediumLow)) { it } + fadeIn(),
            exit = slideOutVertically(spring(Spring.DampingRatioNoBouncy, Spring.StiffnessMedium)) { it } + fadeOut(),
        ) {
            GlassBackground { app.wantastic.android.ui.AddDeviceScreen(sync.client, deviceName, onClose = { addDevice = false }) }
        }
        AnimatedVisibility(
            visible = byLinkSetup != null,
            enter = slideInVertically(spring(Spring.DampingRatioNoBouncy, Spring.StiffnessMediumLow)) { it } + fadeIn(),
            exit = slideOutVertically(spring(Spring.DampingRatioNoBouncy, Spring.StiffnessMedium)) { it } + fadeOut(),
        ) {
            byLinkSetup?.let { id ->
                GlassBackground {
                    app.wantastic.android.ui.AddByLinkScreen(
                        setups, id, deviceName,
                        onUse = {
                            setups.activate(id)
                            (engine as? GoEngine)?.refresh()
                            if (status.tunnel is TunnelState.Connected) engine.reconnect() else onConnect()
                            byLinkSetup = null
                        },
                        onClose = { byLinkSetup = null },
                    )
                }
            }
        }
    }
}

@Composable
private fun BoxScope.Tabs(
    status: EngineStatus, sync: AccountSync, setups: DeviceSetups, account: AccountState, deviceName: String, publicKey: String,
    onConnect: () -> Unit, onLogIn: () -> Unit, onAddAccount: () -> Unit, onConsole: (String) -> Unit,
    onBrowse: (String) -> Unit, onTerminal: (String, String) -> Unit, onAddDevice: () -> Unit, onAddByLink: (String?) -> Unit,
) {
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
                ) {
                    val signedIn = account is AccountState.SignedIn
                    HomeConfigsCard(setups, signedIn, onLogIn = onAddAccount, onAddByLink = onAddByLink) {
                        // Another config is in use now: connect on it, or stop if none is approved.
                        (engine as? GoEngine)?.refresh()
                        if (status.tunnel is TunnelState.Connected || status.tunnel is TunnelState.Connecting) {
                            if (setups.current().claimed) engine.reconnect() else engine.disconnect()
                        }
                    }
                    if (signedIn) {
                        HomeAccountCard(
                            sync, account, onSignIn = onLogIn, onAddAccount = onAddAccount,
                            // A ready setup for the new account: connect on it now.
                            onSwitched = { if ((sync.account.value as? AccountState.SignedIn)?.needsSetup == false) engine.reconnect() },
                        )
                    }
                }
                Tab.Peers -> {
                    val devices by sync.devices.collectAsStateWithLifecycle()
                    PeersScreen(
                        status, devices, account is AccountState.SignedIn, onRefresh = sync::refreshDevices, onSignIn = onAddAccount,
                        onPing = engine::ping, onBrowse = onBrowse, onTerminal = onTerminal, onAddDevice = onAddDevice,
                    )
                }
                Tab.Settings -> SettingsScreen(deviceName, publicKey, onConsole = onConsole) {
                    AccountCard(sync, account, onAddAccount)
                }
            }
        }
    }
    GlassPillNav(
        items = Tab.entries.map { PillItem(it.label, it.icon) },
        selected = tab.ordinal,
        onSelect = {
            tab = Tab.entries[it]
            exitOpen = false
        },
        modifier = Modifier.align(Alignment.BottomCenter).navigationBarsPadding().padding(bottom = 12.dp),
        sources = listOfNotNull(light, screens),
    )
}
