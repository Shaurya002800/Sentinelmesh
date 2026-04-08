const ICONS = {
  tamper: '⚠️',
  ai: '🧠',
  mesh: '📡',
  chain: '⛓️',
  success: '✅',
  critical: '🔴',
}

export default function EventFeed({ entries }) {
  return (
    <section className="panel-surface feed-panel">
      <div className="panel-header-row">
        <div>
          <span className="section-kicker">Live Event Feed</span>
          <h2>System Sequence Log</h2>
        </div>
      </div>

      <div className="terminal-feed">
        {entries.length ? entries.map((entry, index) => (
          <div className={`terminal-line tone-${entry.kind}`} key={`${entry.time}-${entry.kind}-${index}`}>
            <span className="terminal-time">[{entry.time}]</span>
            <span className="terminal-icon">{ICONS[entry.kind] || '•'}</span>
            <span>{entry.message}</span>
          </div>
        )) : (
          <div className="terminal-line tone-ai">Waiting for hardware, AI, mesh, and blockchain events.</div>
        )}
      </div>
    </section>
  )
}
