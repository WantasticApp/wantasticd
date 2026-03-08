import { useRef, useEffect, useState } from 'react'
import * as d3 from 'd3'
import type { StatusData } from '../App'

interface Props {
  status: StatusData | null
  onToggle: () => void
}

type SparkPoint = { i: number; v: number }

const MAX_POINTS = 40

function useSparkline(value: number) {
  const [points, setPoints] = useState<SparkPoint[]>([])
  useEffect(() => {
    setPoints(prev => {
      const next = [...prev, { i: prev.length, v: value }]
      return next.slice(-MAX_POINTS)
    })
  }, [value])
  return points
}

function Sparkline({ points, color }: { points: SparkPoint[]; color: string }) {
  const svgRef = useRef<SVGSVGElement>(null)
  const W = 240, H = 44

  useEffect(() => {
    if (!svgRef.current || points.length < 2) return
    const svg = d3.select(svgRef.current)
    svg.selectAll('*').remove()

    const x = d3.scaleLinear()
      .domain([0, MAX_POINTS - 1])
      .range([0, W])

    const max = d3.max(points, d => d.v) ?? 1
    const y = d3.scaleLinear()
      .domain([0, max * 1.2 || 1])
      .range([H, 2])

    const area = d3.area<SparkPoint>()
      .x(d => x(d.i))
      .y0(H)
      .y1(d => y(d.v))
      .curve(d3.curveCatmullRom.alpha(0.5))

    const line = d3.line<SparkPoint>()
      .x(d => x(d.i))
      .y(d => y(d.v))
      .curve(d3.curveCatmullRom.alpha(0.5))

    const defs = svg.append('defs')
    const grad = defs.append('linearGradient')
      .attr('id', `grad-${color.replace('#','')}`)
      .attr('x1', '0%').attr('y1', '0%')
      .attr('x2', '0%').attr('y2', '100%')
    grad.append('stop').attr('offset', '0%').attr('stop-color', color).attr('stop-opacity', 0.35)
    grad.append('stop').attr('offset', '100%').attr('stop-color', color).attr('stop-opacity', 0.01)

    svg.append('path')
      .datum(points)
      .attr('fill', `url(#grad-${color.replace('#','')})`)
      .attr('d', area)

    svg.append('path')
      .datum(points)
      .attr('fill', 'none')
      .attr('stroke', color)
      .attr('stroke-width', 1.8)
      .attr('d', line)

    // Latest value dot
    const last = points[points.length - 1]
    svg.append('circle')
      .attr('cx', x(last.i))
      .attr('cy', y(last.v))
      .attr('r', 3)
      .attr('fill', color)
      .attr('stroke', 'rgba(255,255,255,0.2)')
      .attr('stroke-width', 1.5)
  }, [points, color])

  return <svg ref={svgRef} width={W} height={H} className="sparkline-svg" />
}

function Row({ label, value }: { label: string; value: string }) {
  return (
    <div className="stat-row">
      <span className="stat-key">{label}</span>
      <span className="stat-val">{value}</span>
    </div>
  )
}

function formatBytes(b: number): string {
  if (b >= 1e9) return (b / 1e9).toFixed(2) + ' GB'
  if (b >= 1e6) return (b / 1e6).toFixed(2) + ' MB'
  if (b >= 1e3) return (b / 1e3).toFixed(1) + ' KB'
  return b + ' B'
}

export default function StatusTab({ status, onToggle }: Props) {
  const rxPoints = useSparkline(status?.rx_bytes ?? 0)
  const txPoints = useSparkline(status?.tx_bytes ?? 0)

  if (!status) return (
    <div className="loading-state"><div className="spinner" /></div>
  )

  const connected = status.running && status.device_running
  const peers = status.peers ?? []
  const p2p   = peers.filter(p => !p.is_relay).length
  const relay = peers.filter(p => p.is_relay).length

  return (
    <div>
      {/* Connection card */}
      <div className="glass-card" style={{ marginBottom: 10 }}>
        <div className="glass-card-title">Connection</div>
        <Row label="State"      value={connected ? '🟢 Connected' : '🔴 Disconnected'} />
        <Row label="Mode"       value={status.tun_mode ? `TUN (${status.tun_name})` : 'Userspace'} />
        <Row label="IP"         value={status.ips?.join(', ') || '—'} />
        <Row label="Public Key" value={
          status.pubkey.length > 20
            ? status.pubkey.slice(0, 10) + '…' + status.pubkey.slice(-6)
            : status.pubkey || '—'
        } />
        <Row label="Peers"      value={`${peers.length} total · ${p2p} P2P · ${relay} relay`} />
      </div>

      {/* Traffic card */}
      <div className="glass-card">
        <div className="glass-card-title">Traffic</div>
        <Row label="Downloaded" value={formatBytes(status.rx_bytes)} />
        <Row label="Uploaded"   value={formatBytes(status.tx_bytes)} />

        <div className="sparkline-wrap" style={{ marginTop: 14 }}>
          <div style={{ fontSize: 10, color: 'var(--text-3)', marginBottom: 4, display: 'flex', gap: 16 }}>
            <span style={{ color: '#3d8ef0' }}>↓ Download</span>
            <span style={{ color: '#00d97e' }}>↑ Upload</span>
          </div>
          <div style={{ position: 'relative' }}>
            <Sparkline points={rxPoints} color="#3d8ef0" />
            <div style={{ position: 'absolute', top: 0, left: 0, opacity: 0.7 }}>
              <Sparkline points={txPoints} color="#00d97e" />
            </div>
          </div>
        </div>
      </div>

      {/* Exit node card */}
      {status.exit_node && (
        <div className="glass-card" style={{ borderColor: 'rgba(139,92,246,0.3)', marginTop: 10 }}>
          <div className="glass-card-title" style={{ color: '#8b5cf6' }}>Exit Node Active</div>
          <Row label="Routing" value="All peers may route through this device" />
        </div>
      )}
    </div>
  )
}
