import type { AccountInfo } from '../App'

interface Props {
  account: AccountInfo | null
  portalHost?: string
  configuring?: boolean      // true while Go is registering device + fetching WireGuard config
  loginPending?: boolean     // true from Sign In click until auth:complete / auth:error
  authError?: string         // set on auth:error event; cleared on next login attempt
  onLogin: () => Promise<void>
  onLogout: () => Promise<void>
  onOpenConsole: () => void
}

export default function AccountTab({
  account,
  portalHost = 'console.wantastic.app',
  configuring,
  loginPending,
  authError,
  onLogin,
  onLogout,
  onOpenConsole,
}: Props) {
  // Show progress while the device is being registered with the backend
  if (configuring) {
    return (
      <div className="login-card">
        <div className="spinner" style={{ width: 32, height: 32, borderWidth: 3, margin: '0 auto 16px' }} />
        <div className="login-title">Setting up your VPN…</div>
        <div className="login-sub">
          Registering this device and fetching your WireGuard configuration from Wantastic.
        </div>
      </div>
    )
  }

  if (!account?.logged_in) {
    return (
      <div>
        {/* Login card with animated border */}
        <div className="login-card">
          <div className="login-logo">🔐</div>
          <div className="login-title">Sign in to Wantastic</div>
          <div className="login-sub">
            Log in with your Wantastic account to access your VPN configuration, manage devices, and open the console.
          </div>

          {/* Error banner */}
          {authError && (
            <div style={{
              color: 'var(--red)',
              fontSize: 13,
              marginBottom: 10,
              textAlign: 'center',
              background: 'rgba(248,81,73,0.1)',
              border: '1px solid rgba(248,81,73,0.3)',
              borderRadius: 6,
              padding: '7px 12px',
            }}>
              ⚠️ {authError}
            </div>
          )}

          <button
            className="cta-btn login"
            onClick={onLogin}
            disabled={loginPending}
          >
            {loginPending ? (
              <>
                <div className="spinner" style={{ width: 16, height: 16, borderWidth: 2 }} />
                Opening sign-in page…
              </>
            ) : (
              <>
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none">
                  <path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2z" fill="rgba(255,255,255,0.2)"/>
                  <path d="M12 6a3.5 3.5 0 1 0 0 7 3.5 3.5 0 0 0 0-7zm0 12c-2.67 0-5.33-1.18-7-3.08C5.7 13.4 8.67 12 12 12s6.3 1.4 7 2.92C17.33 16.82 14.67 18 12 18z" fill="white"/>
                </svg>
                Sign in
              </>
            )}
          </button>
          <div className="login-hint">
            A sign-in page will open in your browser via {portalHost}
          </div>
        </div>
      </div>
    )
  }

  const initials = (account.display_name || account.email || '?')
    .split(' ').map(w => w[0]).join('').toUpperCase().slice(0, 2)

  return (
    <div>
      {/* VPN service error — shown when login succeeded but agent failed to start */}
      {authError && (
        <div style={{
          color: 'var(--red)',
          fontSize: 13,
          margin: '0 0 12px',
          textAlign: 'center',
          background: 'rgba(248,81,73,0.1)',
          border: '1px solid rgba(248,81,73,0.3)',
          borderRadius: 6,
          padding: '7px 12px',
        }}>
          ⚠️ {authError}
        </div>
      )}
      {/* Avatar row */}
      <div className="avatar-row">
        {account.avatar_url ? (
          <img src={account.avatar_url} className="avatar-img" alt={account.display_name} />
        ) : (
          <div className="avatar-placeholder">{initials}</div>
        )}
        <div>
          <div className="account-name">{account.display_name || 'Wantastic User'}</div>
          <div className="account-email">{account.email || '—'}</div>
        </div>
      </div>

      {/* Token info */}
      {account.token && (
        <div className="glass-card" style={{ marginBottom: 10 }}>
          <div className="glass-card-title">Session</div>
          <div className="stat-row">
            <span className="stat-key">Access Token</span>
            <span className="stat-val" style={{ fontFamily: 'monospace', fontSize: 10 }}>
              {account.token.slice(0, 16) + '…'}
            </span>
          </div>
          <div className="stat-row">
            <span className="stat-key">Status</span>
            <span className="stat-val" style={{ color: 'var(--green)' }}>Active ✓</span>
          </div>
        </div>
      )}

      {/* Open Console CTA */}
      <div className="section-title">Console</div>
      <button className="cta-btn console" onClick={onOpenConsole} style={{ marginBottom: 10 }}>
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none">
          <rect x="3" y="4" width="18" height="14" rx="2" stroke="rgba(255,255,255,0.7)" strokeWidth="1.8"/>
          <path d="M7 20h10M12 18v2" stroke="rgba(255,255,255,0.5)" strokeWidth="1.8" strokeLinecap="round"/>
          <path d="M8 10l2 2-2 2M12 14h4" stroke="rgba(255,255,255,0.8)" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round"/>
        </svg>
        Open {portalHost}
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" style={{ marginLeft: 'auto' }}>
          <path d="M7 17L17 7M17 7H7M17 7v10" stroke="rgba(255,255,255,0.5)" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"/>
        </svg>
      </button>
      <div className="login-hint" style={{ marginBottom: 16 }}>
        Opens inside the app with your session already authenticated.
      </div>

      {/* Logout */}
      <button className="secondary-btn" onClick={onLogout}>
        <svg width="15" height="15" viewBox="0 0 24 24" fill="none">
          <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4" stroke="#f85149" strokeWidth="1.8" strokeLinecap="round"/>
          <path d="M16 17l5-5-5-5M21 12H9" stroke="#f85149" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"/>
        </svg>
        <span style={{ color: 'var(--red)' }}>Sign out</span>
      </button>
    </div>
  )
}
