import { useState } from 'react'
import type { StatusData, PeerInfo } from '../App'
// @ts-ignore
import { SetExitNode } from '../../wailsjs/go/main/App'

interface Props {
  status: StatusData | null
}

const COLORS = [
  'linear-gradient(135deg,#3d8ef0,#8b5cf6)',
  'linear-gradient(135deg,#00d97e,#3d8ef0)',
  'linear-gradient(135deg,#f59e0b,#f85149)',
  'linear-gradient(135deg,#8b5cf6,#ec4899)',
  'linear-gradient(135deg,#00d97e,#8b5cf6)',
]

function formatBytes(b: number): string {
  if (b >= 1e9) return (b / 1e9).toFixed(2) + ' GB'
  if (b >= 1e6) return (b / 1e6).toFixed(1) + ' MB'
  if (b >= 1e3) return (b / 1e3).toFixed(0) + ' KB'
  return b + ' B'
}

function shortKey(k: string): string {
  if (!k) return '—'
  const s = k.replace(/=+$/, '')
  return s.slice(0, 7) + '…' + s.slice(-5)
}

function timeSince(ts: string): string {
  if (!ts || ts === '0001-01-01T00:00:00Z') return 'Never'
  const d = new Date(ts)
  if (isNaN(d.getTime())) return ts
  const secs = Math.floor((Date.now() - d.getTime()) / 1000)
  if (secs < 60) return `${secs}s ago`
  if (secs < 3600) return `${Math.floor(secs/60)}m ago`
  if (secs < 86400) return `${Math.floor(secs/3600)}h ago`
  return `${Math.floor(secs/86400)}d ago`
}

function NodeCard({ peer, index, exitNodeKey }: {
  peer: PeerInfo
  index: number
  exitNodeKey: string
}) {
  const [open, setOpen] = useState(false)
  const [settingExit, setSettingExit] = useState(false)

  const label = shortKey(peer.public_key)
  const grad  = COLORS[index % COLORS.length]
  const initial = peer.public_key?.[0]?.toUpperCase() ?? '?'
  const isActiveExit = exitNodeKey === peer.public_key

  const handleSetExit = async (e: React.MouseEvent) => {
    e.stopPropagation()
    setSettingExit(true)
    try { await SetExitNode(isActiveExit ? '' : peer.public_key) } catch {}
    setSettingExit(false)
  }

  return (
    <div
      className="node-card"
      style={{
        borderColor: open ? 'rgba(255,255,255,0.16)' : '',
        boxShadow: open ? '0 4px 24px rgba(0,0,0,0.4)' : '',
      }}
    >
      <div className="node-card-header" onClick={() => setOpen(o => !o)}>
        {/* Avatar */}
        <div className="node-avatar" style={{ background: grad }}>
          {initial}
        </div>

        {/* Meta */}
        <div className="node-meta">
          <div className="node-name">{label}</div>
          <div className="node-sub">{peer.endpoint || 'No endpoint'}</div>
        </div>

        {/* Right side */}
        <div className="node-right">
          <div style={{ display: 'flex', gap: 5 }}>
            {peer.is_relay
              ? <span className="badge badge-relay">Relay</span>
              : <span className="badge badge-p2p">P2P</span>
            }
            {peer.is_exit_node && <span className="badge badge-exit">Exit</span>}
          </div>
          {(peer.rx_bytes > 0 || peer.tx_bytes > 0) && (
            <div className="node-traffic">
              ↓{formatBytes(peer.rx_bytes)} ↑{formatBytes(peer.tx_bytes)}
            </div>
          )}
        </div>

        {/* Chevron */}
        <svg
          width="14" height="14" viewBox="0 0 24 24" fill="none"
          style={{ marginLeft: 8, flexShrink: 0, transition: 'transform 0.3s', transform: open ? 'rotate(180deg)' : '' }}
        >
          <path d="M6 9l6 6 6-6" stroke="rgba(255,255,255,0.4)" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
        </svg>
      </div>

      {/* Expandable details — Apple-store-like spring */}
      <div className={`node-expand ${open ? 'open' : ''}`}>
        <div className="node-expand-inner">
          <div className="expand-row">
            <span className="expand-key">Full Key</span>
            <span className="expand-val" style={{ fontFamily: 'monospace', fontSize: 10 }}>{peer.public_key}</span>
          </div>
          <div className="expand-row">
            <span className="expand-key">Allowed IPs</span>
            <span className="expand-val">{peer.allowed_ips || '—'}</span>
          </div>
          <div className="expand-row">
            <span className="expand-key">Last handshake</span>
            <span className="expand-val">{timeSince(peer.last_handshake)}</span>
          </div>
          {peer.latency_ms > 0 && (
            <div className="expand-row">
              <span className="expand-key">Latency</span>
              <span className="expand-val" style={{ color: peer.latency_ms < 30 ? 'var(--green)' : peer.latency_ms < 80 ? 'var(--yellow)' : 'var(--red)' }}>
                {peer.latency_ms} ms
              </span>
            </div>
          )}
          <div className="expand-row">
            <span className="expand-key">Traffic</span>
            <span className="expand-val">↓ {formatBytes(peer.rx_bytes)} · ↑ {formatBytes(peer.tx_bytes)}</span>
          </div>

          {/* Exit node action */}
          <button
            className={`node-action-btn ${isActiveExit ? 'exit-active' : ''}`}
            onClick={handleSetExit}
            disabled={settingExit}
          >
            {settingExit ? 'Applying…' : isActiveExit ? '✓ Exit Node Active — Remove' : '⬆ Use as Exit Node'}
          </button>
        </div>
      </div>
    </div>
  )
}

export default function NodesTab({ status }: Props) {
  const peers = status?.peers ?? []
  const exitNodeKey = peers.find(p => p.is_exit_node)?.public_key ?? ''

  if (!peers.length) {
    return (
      <div className="empty-nodes">
        <div className="empty-nodes-icon">🌐</div>
        <div>No peers connected</div>
        <div style={{ fontSize: 12, color: 'var(--text-3)' }}>
          Connect to a Wantastic network to see peers
        </div>
      </div>
    )
  }

  const p2pPeers   = peers.filter(p => !p.is_relay)
  const relayPeers = peers.filter(p => p.is_relay)

  return (
    <div>
      {p2pPeers.length > 0 && (
        <>
          <div className="section-title">Direct P2P · {p2pPeers.length}</div>
          {p2pPeers.map((p, i) => (
            <NodeCard key={p.public_key} peer={p} index={i} exitNodeKey={exitNodeKey} />
          ))}
        </>
      )}
      {relayPeers.length > 0 && (
        <>
          <div className="section-title">Via Relay · {relayPeers.length}</div>
          {relayPeers.map((p, i) => (
            <NodeCard key={p.public_key} peer={p} index={p2pPeers.length + i} exitNodeKey={exitNodeKey} />
          ))}
        </>
      )}
    </div>
  )
}
