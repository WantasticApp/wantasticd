import { useCallback, useEffect, useMemo, useState } from 'react'
import { Events } from '@wailsio/runtime'
import {
  ConfigureLocalAccess,
  GenerateClaimLink,
  GetStatus,
  ImportManualConfig,
  OpenConsole,
  OpenURL,
  PingPeer,
  SetExitNode,
  SetLanguage as SetDesktopLanguage,
  SetOfferExitNode,
  ToggleVPN,
  WindowHide,
} from './bindings/wantastic-agent/app'
import { PeerInfo, PingResult, StatusData } from './bindings/wantastic-agent/models'
import { detectLanguage, I18nContext, Language, languages, translate, Translate, useI18n } from './i18n'
import { formatBytes } from './utils'

type View = 'devices' | 'network' | 'events' | 'settings'
type IconName = 'back' | 'check' | 'chevron' | 'close' | 'copy' | 'device' | 'events' | 'globe' |
  'laptop' | 'more' | 'network' | 'ping' | 'router' | 'search' | 'settings' | 'shield' | 'wifi'

const paths: Record<IconName, string> = {
  back: 'M15 18l-6-6 6-6', check: 'M20 6L9 17l-5-5', chevron: 'M9 18l6-6-6-6',
  close: 'M18 6L6 18M6 6l12 12', copy: 'M8 8h11v11H8zM5 16H4V5h11v1',
  device: 'M6 3h12a2 2 0 012 2v10a2 2 0 01-2 2H6a2 2 0 01-2-2V5a2 2 0 012-2zm3 18h6m-3-4v4',
  events: 'M6 3v3M18 3v3M4 9h16M5 5h14a1 1 0 011 1v14H4V6a1 1 0 011-1zm3 8h3v3H8z',
  globe: 'M12 21a9 9 0 100-18 9 9 0 000 18zm0 0c2.2-2.45 3.4-5.45 3.4-9S14.2 5.45 12 3m0 18c-2.2-2.45-3.4-5.45-3.4-9S9.8 5.45 12 3M3 12h18',
  laptop: 'M4 5h16v11H4zM2 19h20', more: 'M12 5h.01M12 12h.01M12 19h.01',
  network: 'M12 3v6m0 0H6v5m6-5h6v5M3 14h6v6H3zm12 0h6v6h-6zM9 9h6v6H9z',
  ping: 'M3 12h4l2-7 4 14 2-7h6',
  router: 'M4 10h16v9H4zM7 15h.01M10 15h.01M8 10V6m8 4V4m-4 6V7',
  search: 'M21 21l-4.4-4.4m2.4-5.1a7.5 7.5 0 11-15 0 7.5 7.5 0 0115 0z',
  settings: 'M12 15.5a3.5 3.5 0 100-7 3.5 3.5 0 000 7zm0-12l1 2.2 2.4.5.8 2.3-1.6 1.8.8 2.3 2.4.5 1 2.2 2.4-.5.8-2.3-1.6-1.8.8-2.3 2.4-.5 1-2.2-1-2.2-2.4-.5-.8-2.3 1.6-1.8-.8-2.3-2.4-.5z',
  shield: 'M12 3l8 3v6c0 5-3.4 8-8 9-4.6-1-8-4-8-9V6z',
  wifi: 'M4 9a12 12 0 0116 0M7 12.5a7.5 7.5 0 0110 0M10 16a3 3 0 014 0M12 20h.01',
}

function Icon({ name, size = 18 }: { name: IconName; size?: number }) {
  return <svg width={size} height={size} viewBox="0 0 24 24" fill="none" aria-hidden="true">
    <path d={paths[name]} stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" />
  </svg>
}

const emptyStatus = new StatusData({
  configured: false, starting: false, running: false, device_running: false, tun_mode: true, tun_name: '',
  offer_exit_node: false, local_access: false, local_access_routes: [], magic_dns: false,
  dns_servers: [], ips: [], pubkey: '', rx_bytes: 0, tx_bytes: 0, peers: [],
})

const previewStatus = new StatusData({
  ...emptyStatus,
  configured: true, running: true, device_running: true, tun_name: 'wantastic0', magic_dns: true,
  local_access: true, local_access_routes: ['192.168.88.0/24'], dns_servers: ['10.255.255.33', '1.1.1.1'],
  ips: ['10.255.255.35/32'], rx_bytes: 18432120, tx_bytes: 6228410,
  peers: [
    new PeerInfo({ public_key: 'preview-router', hostname: 'MikroTik-RB5009', magic_name: 'mikrotik-rb5009.wantastic', assigned_ip: '10.255.255.36', connection: 'direct', p2p_state: 'established', offers_exit_node: true, rx_bytes: 8240010, tx_bytes: 1902140, last_handshake: Math.floor(Date.now() / 1000) - 14 }),
    new PeerInfo({ public_key: 'preview-office', hostname: 'Office-PC', magic_name: 'office-pc.wantastic', assigned_ip: '10.255.255.37', connection: 'direct', p2p_state: 'established', rx_bytes: 3020110, tx_bytes: 993410, last_handshake: Math.floor(Date.now() / 1000) - 35 }),
    new PeerInfo({ public_key: 'preview-phone', hostname: 'iPhone-15', magic_name: 'iphone-15.wantastic', assigned_ip: '10.255.255.38', connection: 'relay', p2p_state: 'trying', rx_bytes: 840110, tx_bytes: 442180, last_handshake: Math.floor(Date.now() / 1000) - 120 }),
    new PeerInfo({ public_key: 'preview-camera', hostname: 'IoT-Camera', magic_name: 'iot-camera.wantastic', assigned_ip: '10.255.255.39', connection: 'relay', p2p_state: 'failed', rx_bytes: 0, tx_bytes: 0, last_handshake: 0 }),
  ],
})

export default function App() {
  const [language, setLanguageState] = useState<Language>(detectLanguage)
  const t = useMemo(() => translate(language), [language])

  const setLanguage = useCallback((next: Language) => {
    window.localStorage.setItem('wantastic-language', next)
    setLanguageState(next)
  }, [])

  useEffect(() => {
    document.documentElement.lang = language
    document.documentElement.dir = language === 'ar' ? 'rtl' : 'ltr'
  }, [language])

  return <I18nContext.Provider value={{ language, setLanguage, t }}><DesktopApp /></I18nContext.Provider>
}

function DesktopApp() {
  const { language, t } = useI18n()
  const previewParams = new URLSearchParams(window.location.search)
  const preview = previewParams.get('preview') === '1'
  const requestedView = previewParams.get('view')
  const initialView: View = requestedView === 'network' || requestedView === 'events' || requestedView === 'settings'
    ? requestedView
    : 'devices'
  const previewConnected = previewParams.get('offline') !== '1'
  const previewSetup = preview && previewParams.get('setup') === '1'
  const loadingPreview = preview && previewParams.get('loading') === '1'
  const initialStatus = preview
    ? previewSetup
      ? emptyStatus
      : new StatusData({ ...previewStatus, running: previewConnected, device_running: previewConnected })
    : emptyStatus
  const [status, setStatus] = useState<StatusData>(initialStatus)
  const [initializing, setInitializing] = useState(!preview || loadingPreview)
  const [view, setView] = useState<View>(initialView)
  const [selected, setSelected] = useState<PeerInfo | null>(preview && previewParams.get('detail') === '1' ? previewStatus.peers[0] : null)
  const [query, setQuery] = useState('')
  const [busy, setBusy] = useState('')
  const [notice, setNotice] = useState('')
  const [error, setError] = useState('')
  const [manual, setManual] = useState('')
  const [routes, setRoutes] = useState('')

  useEffect(() => {
    document.documentElement.classList.toggle('visual-preview', preview)
    return () => document.documentElement.classList.remove('visual-preview')
  }, [preview])

  useEffect(() => {
    if (!preview) SetDesktopLanguage(language).catch(reason => console.error(reason))
  }, [language, preview])

  const refresh = useCallback(async () => {
    if (preview) return
    try {
      const next = await GetStatus()
      if (next) {
        setStatus(next)
        setInitializing(next.starting)
        if (next.local_access_routes?.length) setRoutes(next.local_access_routes.join(', '))
      }
    } catch (reason) {
      console.error(reason)
      setError(friendlyError(reason, t))
      setInitializing(false)
    }
  }, [preview, t])

  useEffect(() => {
    if (preview) return
    refresh()
    const offStatus = Events.On('status:update', event => {
      const next = StatusData.createFrom(event.data)
      setStatus(next)
      setInitializing(next.starting)
      if (next.local_access_routes?.length) setRoutes(next.local_access_routes.join(', '))
    })
    const offError = Events.On('app:error', event => {
      console.error(event.data)
      setError(friendlyError(event.data, t))
    })
    const offClaim = Events.On('claim:connected', () => {
      setNotice(t('signInComplete'))
      refresh()
    })
    const offNavigate = Events.On('navigate', event => {
      const target = String(event.data)
      if (target === 'devices' || target === 'network' || target === 'events' || target === 'settings') {
        setSelected(null)
        setView(target)
      }
    })
    const timer = window.setInterval(refresh, 6000)
    return () => { offStatus(); offError(); offClaim(); offNavigate(); window.clearInterval(timer) }
  }, [preview, refresh, t])

  const connected = status.running && status.device_running
  const direct = status.peers.filter(peer => peer.connection === 'direct').length
  const filteredPeers = useMemo(() => {
    const needle = query.trim().toLowerCase()
    if (!needle) return status.peers
    return status.peers.filter(peer => [peer.hostname, peer.magic_name, peer.assigned_ip].some(value => value?.toLowerCase().includes(needle)))
  }, [query, status.peers])

  async function run(label: string, action: () => Promise<unknown>, success: string) {
    if (preview) { setNotice(success); return }
    setBusy(label); setError(''); setNotice('')
    try { await action(); setNotice(success); await refresh() }
    catch (reason) { console.error(reason); setError(friendlyError(reason, t)) }
    finally { setBusy('') }
  }

  async function signIn() {
    if (preview) { setNotice(t('previewUnavailable')); return }
    setBusy('signin'); setError(''); setNotice(t('openingBrowser'))
    try {
      const link = await GenerateClaimLink('https://console.wantastic.app', false)
      if (!link?.claim_url) throw new Error('Sign-in page unavailable')
      await OpenURL(link.claim_url)
      setNotice(t('browserOpened'))
    }
    catch (reason) { console.error(reason); setError(friendlyError(reason, t)); setNotice('') }
    finally { setBusy('') }
  }

  if (initializing || status.starting) {
    return <BrandLoader message={status.starting ? t('startingConnection') : t('loadingNetwork')} />
  }

  if (selected) {
    return <DeviceDetail peer={selected} busy={busy} onBack={() => setSelected(null)} run={run} previewPing={preview && previewParams.get('ping') === '1'} />
  }

  return <main className="app-shell">
    <header className="titlebar">
      <div className="brand"><img src="/logo.png" alt="" /><span>Wantastic</span></div>
      <div className="title-actions">
        <button className="icon-button" aria-label={t('settings')} onClick={() => setView('settings')}><Icon name="settings" size={16} /></button>
        <button className="icon-button" aria-label={t('close')} onClick={() => !preview && WindowHide()}><Icon name="close" size={17} /></button>
      </div>
    </header>

    <section className="connection-row">
      <span className="status-symbol"><Icon name={connected ? 'check' : 'shield'} size={25} /></span>
      <div className="connection-copy">
        <strong>{connected ? t('online') : t('offline')}</strong>
        <span>{connected ? t('connectedTo') : status.configured ? t('readyToConnect') : t('signInToContinue')}</span>
      </div>
      <button className={`toggle ${connected ? 'on' : ''}`} aria-label={connected ? t('disconnect') : t('connect')}
        disabled={!status.configured || !!busy} onClick={() => run('toggle', () => ToggleVPN(), connected ? t('disconnected') : t('connected'))}><i /></button>
    </section>

    <button className="self-card" onClick={() => setView('network')}>
      <span className="device-icon"><Icon name="device" /></span>
      <span className="self-copy"><strong>{deviceName(t)}</strong><small>{cleanIP(status.ips[0]) || t('privateAddressUnavailable')}</small></span>
      <span className="self-meta"><small>{t('directSummary', { count: direct, total: status.peers.length })}</small><Icon name="chevron" size={16} /></span>
    </button>

    <nav className="tabs" aria-label={t('mainNavigation')}>
      <Tab active={view === 'devices'} icon="device" label={t('devices')} onClick={() => setView('devices')} />
      <Tab active={view === 'network'} icon="globe" label={t('network')} onClick={() => setView('network')} />
      <Tab active={view === 'events'} icon="events" label={t('activity')} onClick={() => setView('events')} />
    </nav>

    {(error || notice) && <div className={`banner ${error ? 'error' : 'success'}`}>
      <span>{error || notice}</span><button aria-label={t('dismiss')} onClick={() => { setError(''); setNotice('') }}><Icon name="close" size={14} /></button>
    </div>}

    <section className="content">
      {view === 'devices' && <Devices peers={filteredPeers} query={query} setQuery={setQuery} configured={status.configured} onSelect={setSelected} />}
      {view === 'network' && <Network status={status} routes={routes} setRoutes={setRoutes} busy={busy} run={run} />}
      {view === 'events' && <EventsView status={status} />}
      {view === 'settings' && <Settings status={status} signIn={signIn} manual={manual} setManual={setManual} busy={busy} run={run} />}
    </section>

    <footer className="status-footer">
      <span>{status.magic_dns ? t('namesReady') : t('namesPreparing')}</span>
      <span>↓ {formatBytes(status.rx_bytes)} · ↑ {formatBytes(status.tx_bytes)}</span>
    </footer>
  </main>
}

function BrandLoader({ message }: { message: string }) {
  const { t } = useI18n()
  return <main className="app-shell brand-loader" role="status" aria-live="polite">
    <div className="brand-loader-stage">
      <span className="brand-loader-emblem" aria-hidden="true">
        <i className="brand-loader-orbit outer" />
        <i className="brand-loader-orbit inner" />
        <span className="brand-loader-mark"><img src="/logo.png" alt="" /></span>
      </span>
      <span className="brand-loader-kicker">{t('privateNetwork')}</span>
      <strong className="brand-loader-word">Wantastic</strong>
      <span className="brand-loader-message">{message}</span>
      <span className="brand-loader-signal" aria-hidden="true"><i /><i /><i /></span>
    </div>
  </main>
}

function Tab({ active, icon, label, onClick }: { active: boolean; icon: IconName; label: string; onClick: () => void }) {
  return <button className={active ? 'active' : ''} onClick={onClick}><Icon name={icon} /><span>{label}</span></button>
}

function Devices({ peers, query, setQuery, configured, onSelect }: {
  peers: PeerInfo[]; query: string; setQuery: (value: string) => void; configured: boolean; onSelect: (peer: PeerInfo) => void
}) {
  const { t } = useI18n()
  return <div className="view-stack">
    <label className="search"><Icon name="search" size={17} /><input value={query} onChange={event => setQuery(event.target.value)} placeholder={t('searchDevices')} /></label>
    <div className="section-heading"><span>{t('availableDevices')}</span><small>{peers.length}</small></div>
    {!configured && <Empty icon="shield" title={t('joinNetwork')} detail={t('joinNetworkDetail')} />}
    {configured && !peers.length && <Empty icon="device" title={t('noDevices')} detail={query ? t('differentSearch') : t('devicesAppear')} />}
    <div className="device-list">{peers.map(peer => <DeviceRow key={peer.public_key} peer={peer} onClick={() => onSelect(peer)} />)}</div>
  </div>
}

function DeviceRow({ peer, onClick }: { peer: PeerInfo; onClick: () => void }) {
  const { t } = useI18n()
  const online = isOnline(peer)
  return <button className="device-row" onClick={onClick}>
    <span className="device-icon"><Icon name={deviceIcon(peer)} /></span>
    <span className="device-copy"><strong>{peerName(peer)}</strong><small>{peer.assigned_ip || t('waitingAddress')}</small></span>
    <span className="device-state"><span>{online ? peer.connection === 'direct' ? t('direct') : t('protectedRelay') : t('offline')}</span><Icon name="chevron" size={15} /></span>
  </button>
}

function DeviceDetail({ peer, busy, onBack, run, previewPing }: { peer: PeerInfo; busy: string; onBack: () => void; run: Function; previewPing: boolean }) {
  const { language, t } = useI18n()
  const [ping, setPing] = useState<PingResult | null>(previewPing ? new PingResult({
    target: peer.magic_name, ip: peer.assigned_ip, reachable: true, latency_ms: 41, average_ms: 41,
    packet_loss: 0, connection: 'direct', message: 'Preview samples', samples: [32, 44, 38, 61, 35, 36].map(latency_ms => ({ latency_ms, reachable: true })),
  }) : null)
  const name = peerName(peer)
  async function pingPeer() {
    setPing(null)
    await run('ping-' + peer.public_key, async () => setPing(await PingPeer(peer.public_key)), t('pingedDevice', { name }))
  }
  return <main className="app-shell detail-shell">
    <header className="titlebar detail-title"><button className="icon-button" aria-label={t('back')} onClick={onBack}><Icon name="back" /></button>
      <div className="brand"><img src="/logo.png" alt="" /><span>{t('device')}</span></div><button className="icon-button" aria-label={t('more')}><Icon name="more" /></button></header>
    <section className="detail-hero"><span className="device-icon large"><Icon name={deviceIcon(peer)} size={26} /></span>
      <div><h1>{name}</h1><p>{peer.assigned_ip || t('privateAddressUnavailable')}</p><span className="presence">{isOnline(peer) ? t('online') : t('offline')}</span></div></section>
    <nav className="detail-tabs"><button className="active">{t('info')}</button><button>{t('connection')}</button><button>{t('actions')}</button></nav>
    <section className="detail-content">
      <InfoRow label={t('networkName')} value={peer.magic_name || t('notAvailable')} />
      <InfoRow label={t('ipAddress')} value={peer.assigned_ip || '—'} />
      <InfoRow label={t('connection')} value={peer.connection === 'direct' ? t('directConnection') : peer.connection === 'trying' ? t('findingDirect') : t('protectedRelay')} accent={peer.connection === 'direct'} />
      <InfoRow label={t('lastSeen')} value={formatLastSeen(peer.last_handshake, language, t)} />
      <InfoRow label={t('traffic')} value={`↓ ${formatBytes(peer.rx_bytes)}  ↑ ${formatBytes(peer.tx_bytes)}`} />
      <div className="divider" />
      <div className={`path-status ${peer.connection === 'direct' ? 'direct' : ''}`}><Icon name="network" size={15} />
        <span><strong>{peer.connection === 'direct' ? t('directActive') : peer.connection === 'trying' ? t('findingDirectPath') : t('relayActive')}</strong><small>{peer.connection === 'direct' ? t('directAvailable') : t('relayProtected')}</small></span>
      </div>
      <h2>{t('actions')}</h2>
      <div className="ping-block"><button className="action-row" disabled={!!busy || !peer.assigned_ip} onClick={pingPeer}><Icon name="ping" /><span><strong>{t('pingDevice')}</strong><small>{ping ? ping.reachable ? t('pingSummary', { average: ping.average_ms, loss: ping.packet_loss }) : t('noReplies') : t('pingPrompt')}</small></span><Icon name="chevron" size={15} /></button>
        {ping && <PingChart result={ping} />}</div>
      <button className="action-row" disabled={!!busy || !peer.offers_exit_node} onClick={() => run('exit-' + peer.public_key, () => SetExitNode(peer.public_key), t('usingInternetThrough', { name }))}><Icon name="globe" /><span><strong>{t('useInternetThrough')}</strong><small>{peer.offers_exit_node ? t('useInternetDetail') : t('internetUnavailable')}</small></span><Icon name="chevron" size={15} /></button>
      <button className="secondary full" onClick={() => navigator.clipboard.writeText(peer.assigned_ip)}> <Icon name="copy" size={16} /> {t('copyAddress')}</button>
    </section>
  </main>
}

function PingChart({ result }: { result: PingResult }) {
  const { t } = useI18n()
  const samples = result.samples || []
  const maximum = Math.max(1, ...samples.filter(sample => sample.reachable).map(sample => sample.latency_ms))
  return <div className="ping-chart" aria-label={t('pingHistory', { loss: result.packet_loss })}>
    <div className="ping-bars">{samples.map((sample, index) => <i key={index} className={sample.reachable ? '' : 'lost'}
      style={{ height: sample.reachable ? `${Math.max(16, Math.round(sample.latency_ms / maximum * 100))}%` : '8%' }}
      title={sample.reachable ? `${sample.latency_ms} ms` : t('noReply')} />)}</div>
    <div className="ping-scale"><span>{t('samples', { count: samples.length })}</span><span>{result.reachable ? t('average', { value: result.average_ms }) : t('unreachable')}</span></div>
  </div>
}

function Network({ status, routes, setRoutes, busy, run }: { status: StatusData; routes: string; setRoutes: (value: string) => void; busy: string; run: Function }) {
  const { t } = useI18n()
  const parsed = routes.split(',').map(value => value.trim()).filter(Boolean)
  return <div className="view-stack network-view">
    <div className="section-heading"><span>{t('networkControls')}</span><small>{t('privateNetwork')}</small></div>
    <Setting icon="wifi" title={t('deviceNames')} detail={status.magic_dns ? t('namesReadyDetail') : t('namesPreparingDetail')} status={status.magic_dns ? t('ready') : t('settingUp')} active={status.magic_dns} />
    <Setting icon="globe" title={t('shareInternet')} detail={t('shareInternetDetail')}>
      <Switch active={status.offer_exit_node} disabled={!status.configured || !!busy} onClick={() => run('offer', () => SetOfferExitNode(!status.offer_exit_node), status.offer_exit_node ? t('sharingStopped') : t('sharingStarted'))} />
    </Setting>
    <section className="panel local-panel"><div className="panel-title"><span className="setting-icon"><Icon name="network" /></span><div><h2>{t('allowLocal')}</h2><p>{t('allowLocalDetail')}</p></div></div>
      <input className="field" dir="ltr" value={routes} onChange={event => setRoutes(event.target.value)} placeholder={t('localPlaceholder')} />
      <div className="button-row"><button className="primary" disabled={!status.configured || !!busy} onClick={() => run('routes', () => ConfigureLocalAccess(true, parsed), t('localUpdated'))}>{t('enableApply')}</button>
        <button className="secondary" disabled={!status.configured || !!busy} onClick={() => run('routes-off', () => ConfigureLocalAccess(false, []), t('localDisabled'))}>{t('disable')}</button></div>
      {status.local_access && <div className="active-route"><Icon name="check" size={14} />{status.local_access_routes.length ? status.local_access_routes.join(', ') : t('automaticDiscovery')}</div>}
    </section>
    <button className="secondary full" onClick={() => SetExitNode('')}>{t('stopInternetRouting')}</button>
  </div>
}

function EventsView({ status }: { status: StatusData }) {
  const { t } = useI18n()
  const events = [
    { icon: 'shield' as IconName, title: status.running ? t('networkConnected') : t('networkDisconnected'), detail: cleanIP(status.ips[0]) || t('privateAddressUnavailable'), live: status.running },
    { icon: 'network' as IconName, title: t('directPaths', { count: status.peers.filter(peer => peer.connection === 'direct').length }), detail: t('devicesAvailable', { count: status.peers.length }), live: true },
    { icon: 'wifi' as IconName, title: status.magic_dns ? t('namesReady') : t('namesPreparing'), detail: status.magic_dns ? t('namesReadyDetail') : t('waitingNames'), live: status.magic_dns },
    { icon: 'globe' as IconName, title: status.local_access ? t('localShared') : t('localNotShared'), detail: status.local_access_routes.join(', ') || t('noLocalNetworks'), live: status.local_access },
  ]
  return <div className="view-stack"><div className="section-heading"><span>{t('connectionActivity')}</span><small>{t('live')}</small></div>
    <div className="timeline">{events.map(event => <div className="timeline-row" key={event.title}><span className={`timeline-icon ${event.live ? 'active' : ''}`}><Icon name={event.icon} /></span><div><strong>{event.title}</strong><small>{event.detail}</small></div><time>{t('now')}</time></div>)}</div>
  </div>
}

function Settings({ status, signIn, manual, setManual, busy, run }: any) {
  const { language, setLanguage, t } = useI18n()
  return <div className="view-stack settings-view">
    <div className="section-heading"><span>{t('settings')}</span><small>{status.configured ? t('accountReady') : t('setupRequired')}</small></div>
    <section className="panel language-panel"><div className="panel-title"><span className="setting-icon"><Icon name="globe" /></span><div><h2>{t('language')}</h2><p>{t('languageDetail')}</p></div></div>
      <select className="field language-select" value={language} onChange={event => setLanguage(event.target.value as Language)}>
        {languages.map(item => <option key={item.code} value={item.code}>{item.label}</option>)}
      </select>
    </section>
    <section className="panel"><div className="panel-title"><span className="setting-icon"><Icon name="shield" /></span><div><h2>{status.configured ? t('account') : t('signInTitle')}</h2><p>{status.configured ? t('accountReadyDetail') : t('signInDetail')}</p></div></div>
      {status.configured
        ? <button className="primary full" disabled={!!busy} onClick={() => OpenConsole()}>{t('openConsole')}</button>
        : <button className="primary full" disabled={!!busy} onClick={signIn}>{busy === 'signin' ? t('openingBrowser') : t('signIn')}</button>}
    </section>
    <section className="panel"><div className="panel-title"><span className="setting-icon"><Icon name="settings" /></span><div><h2>{t('advancedSetup')}</h2><p>{t('advancedDetail')}</p></div></div>
      <textarea className="field config-field" value={manual} onChange={event => setManual(event.target.value)} placeholder={'[Interface]\nPrivateKey = …\nAddress = 10.255.255.35/32'} />
      <button className="primary full" disabled={!manual.trim() || !!busy} onClick={() => run('manual', () => ImportManualConfig(manual), t('imported'))}>{t('importConnect')}</button>
    </section>
    <button className="action-row console" onClick={() => OpenConsole()}><Icon name="globe" /><span><strong>{t('console')}</strong><small>{t('consoleDetail')}</small></span><Icon name="chevron" size={15} /></button>
  </div>
}

function Setting({ icon, title, detail, status, active, children }: { icon: IconName; title: string; detail: string; status?: string; active?: boolean; children?: React.ReactNode }) {
  return <section className="panel setting-row"><span className="setting-icon"><Icon name={icon} /></span><div><h2>{title}</h2><p>{detail}</p></div>{children || <span className={`badge ${active ? 'active' : ''}`}>{status}</span>}</section>
}

function Switch({ active, disabled, onClick }: { active: boolean; disabled: boolean; onClick: () => void }) {
  const { t } = useI18n()
  return <button className={`toggle compact ${active ? 'on' : ''}`} aria-label={active ? t('disable') : t('enable')} disabled={disabled} onClick={onClick}><i /></button>
}

function InfoRow({ label, value, accent }: { label: string; value: string; accent?: boolean }) {
  return <div className="info-row"><span>{label}</span><strong className={accent ? 'accent' : ''}>{value}</strong></div>
}

function Empty({ icon, title, detail }: { icon: IconName; title: string; detail: string }) {
  return <div className="empty"><span><Icon name={icon} size={28} /></span><h2>{title}</h2><p>{detail}</p></div>
}

function friendlyError(value: unknown, t: Translate) {
  const text = value instanceof Error ? value.message : String(value ?? '')
  if (/operation not permitted|privileged tunnel|administrator|permission/i.test(text)) return t('errorPermission')
  if (/409|conflict/i.test(text)) return t('errorConflict')
  return t('errorUnexpected')
}

function cleanIP(value?: string) { return value?.split('/')[0] || '' }
function peerName(peer: PeerInfo) { return peer.hostname || peer.magic_name || peer.assigned_ip || peer.public_key.slice(0, 10) }
function deviceName(t: Translate) { return window.navigator.platform.includes('Mac') ? t('thisMac') : window.navigator.platform.includes('Win') ? t('thisPC') : t('thisDevice') }
function deviceIcon(peer: PeerInfo): IconName { return /router|mikrotik|gateway|ap/i.test(peerName(peer)) ? 'router' : 'laptop' }
function isOnline(peer: PeerInfo) { return peer.connection === 'direct' || peer.connection === 'trying' || peer.last_handshake > Math.floor(Date.now() / 1000) - 300 }
function formatLastSeen(seconds: number, language: Language, t: Translate) {
  if (!seconds) return t('never')
  const ago = Math.max(0, Math.floor(Date.now() / 1000) - seconds)
  const formatter = new Intl.RelativeTimeFormat(language, { numeric: 'auto' })
  if (ago < 60) return formatter.format(-ago, 'second')
  if (ago < 3600) return formatter.format(-Math.floor(ago / 60), 'minute')
  return formatter.format(-Math.floor(ago / 3600), 'hour')
}
