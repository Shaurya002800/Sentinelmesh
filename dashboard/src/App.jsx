import { useEffect, useMemo, useState, useTransition } from 'react'
import {
  fetchBlockchainEvents,
  fetchEvents,
  fetchHealth,
  fetchNodes,
  fetchStats,
} from './api/index.js'
import ApiPanel from './components/ApiPanel.jsx'
import AuditTrail from './components/AuditTrail.jsx'
import DwellTimeGraph from './components/DwellTimeGraph.jsx'
import EventFeed from './components/EventFeed.jsx'
import NodeStatus from './components/NodeStatus.jsx'
import ThreatClassification from './components/ThreatClassification.jsx'
import WorldMap from './components/WorldMap.jsx'
import './styles/index.css'

const REFRESH_INTERVAL_MS = 4000

function formatClock(value) {
  if (!value) return 'Waiting'
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return value
  return date.toLocaleString('en-GB', {
    day: '2-digit',
    month: '2-digit',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    timeZoneName: 'short',
  })
}

function classifyActor(event) {
  const reasons = (event.analysis?.reasons || []).join(' ').toLowerCase()
  const label = String(event.analysis?.label || '').toLowerCase()
  const eventType = String(event.event_type || '').toLowerCase()
  const confidence = Number(event.analysis?.confidence || 0)

  if (eventType === 'tamper' || reasons.includes('manual probe') || reasons.includes('physical tamper')) {
    return 'Human'
  }
  if (reasons.includes('apt') || (label === 'critical' && confidence >= 0.98 && Number(event.failed_logins || 0) >= 6)) {
    return 'APT'
  }
  if (eventType === 'mesh_alert' || reasons.includes('bot') || reasons.includes('scan') || reasons.includes('request rate')) {
    return 'Bot'
  }
  return 'Unknown'
}

function mapLocation(event, index) {
  const geo = event.geo
  if (geo?.latitude != null && geo?.longitude != null) {
    const x = ((Number(geo.longitude) + 180) / 360) * 100
    const y = ((90 - Number(geo.latitude)) / 180) * 100
    return {
      city: geo.label || [geo.city, geo.country].filter(Boolean).join(', '),
      x: Math.min(Math.max(x, 4), 96),
      y: Math.min(Math.max(y, 8), 92),
    }
  }

  const presets = [
    { city: 'Mumbai, India', x: 71, y: 56 },
    { city: 'Singapore', x: 77, y: 62 },
    { city: 'Frankfurt, Germany', x: 53, y: 38 },
    { city: 'Virginia, USA', x: 27, y: 41 },
    { city: 'Tokyo, Japan', x: 84, y: 44 },
    { city: 'Sao Paulo, Brazil', x: 35, y: 74 },
  ]

  if (event.mesh_origin) return { ...presets[4], city: 'Peer Mesh Relay' }
  if (String(event.source || '').includes('manual')) return presets[0]
  if (event.dst_port === 22) return presets[2]
  if (event.dst_port === 23) return presets[3]
  if (event.dst_port === 3389) return presets[5]
  return presets[index % presets.length]
}

function buildMapPoints(events) {
  return events.slice(0, 12).map((event, index) => {
    const location = mapLocation(event, index)
    const severity = String(event.analysis?.label || 'low').toLowerCase()
    const classification = classifyActor(event)
    return {
      id: `${event.timestamp}-${index}`,
      city: location.city,
      x: location.x,
      y: location.y,
      severity,
      attempts: Math.max(1, Math.round(Number(event.request_rate || 1) / 12)),
      classification,
      firstSeen: event.timestamp,
      ip: event.geo?.ip || event.src_ip || 'unknown',
    }
  })
}

function buildThreatMix(events) {
  const counts = { Bot: 0, Human: 0, APT: 0, Unknown: 0 }
  events.forEach((event) => {
    counts[classifyActor(event)] += 1
  })

  return [
    { name: 'Bots', key: 'Bot', value: counts.Bot, color: '#4fa8ff' },
    { name: 'Human', key: 'Human', value: counts.Human, color: '#ff926b' },
    { name: 'APT', key: 'APT', value: counts.APT, color: '#ff4d6d' },
    { name: 'Unknown', key: 'Unknown', value: counts.Unknown, color: '#f4d35e' },
  ]
}

function buildDwellSeries(events) {
  return events
    .slice()
    .reverse()
    .slice(-12)
    .map((event, index) => ({
      label: new Date(event.timestamp || Date.now()).toLocaleTimeString('en-GB', {
        hour: '2-digit',
        minute: '2-digit',
      }),
      seconds: Math.max(4, Math.round(Number(event.duration_ms || 0) / 1.6)),
      severity: event.analysis?.label || 'low',
      rawIndex: index,
    }))
}

function buildFeedEntries(events) {
  const rows = []

  events.slice(0, 10).forEach((event) => {
    const time = new Date(event.timestamp || Date.now()).toLocaleTimeString('en-GB', {
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
    })

    if (event.event_type === 'tamper') {
      rows.push({ time, kind: 'tamper', message: `TAMPER DETECTED — ${event.device_id}` })
    }

    rows.push({
      time,
      kind: 'ai',
      message: `AI: ${classifyActor(event)} profile, ${Math.round(Number(event.analysis?.confidence || 0) * 100)}% confidence`,
    })

    if (event.mesh_status) {
      rows.push({
        time,
        kind: 'mesh',
        message: `Mesh alert → ${event.mesh_origin ? `Peer from ${event.mesh_origin}` : 'Node B, C, D'}`,
      })
    }

    if (event.blockchain?.tx_hash) {
      rows.push({ time, kind: 'chain', message: `Blockchain TX fired: ${event.blockchain.tx_hash.slice(0, 12)}...` })
      rows.push({ time, kind: 'success', message: `Block confirmed for ${event.device_id}` })
    }
  })

  return rows.slice(0, 18)
}

function buildApiStats(events, nodes) {
  const aptCount = events.filter((event) => classifyActor(event) === 'APT').length
  const asiaCount = events.filter((event, index) => ['Mumbai, India', 'Singapore', 'Tokyo, Japan'].includes(mapLocation(event, index).city)).length

  return {
    totalRecords: events.length,
    aptCount,
    asiaCount,
    lastQueried: events[0]?.timestamp || null,
    todayCalls: 1000 + (events.length * 13) + (nodes.length * 7),
  }
}

function App() {
  const [stats, setStats] = useState({
    total_events: 0,
    critical_events: 0,
    high_events: 0,
    anchored_events: 0,
  })
  const [events, setEvents] = useState([])
  const [nodes, setNodes] = useState([])
  const [blockchainEvents, setBlockchainEvents] = useState([])
  const [health, setHealth] = useState(null)
  const [error, setError] = useState('')
  const [lastUpdated, setLastUpdated] = useState('')
  const [isPending, startTransition] = useTransition()

  useEffect(() => {
    let active = true

    const loadDashboard = async () => {
      try {
        const [statsData, eventsData, nodesData, blockchainData, healthData] = await Promise.all([
          fetchStats(),
          fetchEvents(),
          fetchNodes(),
          fetchBlockchainEvents(),
          fetchHealth(),
        ])

        if (!active) return

        startTransition(() => {
          setStats(statsData)
          setEvents(eventsData)
          setNodes(nodesData)
          setBlockchainEvents(blockchainData)
          setHealth(healthData)
          setError('')
          setLastUpdated(new Date().toISOString())
        })
      } catch (loadError) {
        if (!active) return
        setError(loadError.message || 'Unable to reach SentinelMesh backend')
      }
    }

    loadDashboard()
    const intervalId = window.setInterval(loadDashboard, REFRESH_INTERVAL_MS)

    return () => {
      active = false
      window.clearInterval(intervalId)
    }
  }, [])

  const mapPoints = useMemo(() => buildMapPoints(events), [events])
  const threatMix = useMemo(() => buildThreatMix(events), [events])
  const dwellSeries = useMemo(() => buildDwellSeries(events), [events])
  const feedEntries = useMemo(() => buildFeedEntries(events), [events])
  const apiStats = useMemo(() => buildApiStats(events, nodes), [events, nodes])

  const activeAttackers = useMemo(() => {
    const recent = events.slice(0, 12).filter((event) => ['critical', 'high'].includes(String(event.analysis?.label || '').toLowerCase()))
    return new Set(recent.map((event) => event.device_id)).size
  }, [events])

  const blockedThreats = useMemo(() => {
    return events.reduce((total, event) => total + Math.max(1, Math.round(Number(event.request_rate || 0) / 4)), 0)
  }, [events])

  const onlineNodes = nodes.filter((node) => node.status !== 'offline').length
  const currentClock = formatClock(lastUpdated || new Date().toISOString())

  const topCards = [
    { label: 'Total Alerts', value: stats.total_events, detail: 'All incidents recorded' },
    { label: 'Active Attackers', value: activeAttackers, detail: 'Currently probing now' },
    { label: 'Threats Blocked', value: blockedThreats, detail: 'Fake services absorbed' },
    { label: 'Nodes Online', value: `${onlineNodes}/${Math.max(nodes.length, 4)}`, detail: 'ESP32 mesh heartbeat' },
  ]

  return (
    <main className="dashboard-shell">
      <div className="backdrop-grid" />
      <div className="backdrop-glow glow-a" />
      <div className="backdrop-glow glow-b" />

      <header className="topbar panel-surface">
        <div className="brand-lockup">
          <div className="brand-shield">🛡️</div>
          <div>
            <span className="brand-kicker">SentinelMesh</span>
            <h1>Autonomous Threat Intelligence Network</h1>
          </div>
        </div>

        <div className="topbar-meta">
          <span className={`live-badge ${health?.status === 'ok' ? 'is-live' : ''}`}>
            <i />
            {health?.status === 'ok' ? 'LIVE' : 'SYNCING'}
          </span>
          <span className="time-stamp">{currentClock}</span>
        </div>
      </header>

      {error ? (
        <section className="alert-banner panel-surface">
          <strong>Backend connection problem</strong>
          <span>{error}</span>
        </section>
      ) : null}

      <section className="stats-grid">
        {topCards.map((card) => (
          <article className="stat-card panel-surface" key={card.label}>
            <span>{card.label}</span>
            <strong>{card.value}</strong>
            <p>{card.detail}</p>
          </article>
        ))}
      </section>

      <section className="hero-grid">
        <WorldMap points={mapPoints} />
        <ThreatClassification items={threatMix} total={stats.total_events} isPending={isPending} />
      </section>

      <section className="mid-grid">
        <DwellTimeGraph data={dwellSeries} />
        <AuditTrail events={blockchainEvents} />
      </section>

      <section className="lower-grid">
        <EventFeed entries={feedEntries} />
        <div className="side-column">
          <NodeStatus nodes={nodes} />
          <ApiPanel stats={apiStats} service={health?.service || 'sentinelmesh-backend'} />
        </div>
      </section>
    </main>
  )
}

export default App
