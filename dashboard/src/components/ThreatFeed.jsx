function formatTimestamp(value) {
  if (!value) return 'No timestamp'
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return value
  return date.toLocaleString()
}

function severityTone(label) {
  if (label === 'critical') return 'severity-critical'
  if (label === 'high') return 'severity-high'
  if (label === 'medium') return 'severity-medium'
  return 'severity-low'
}

export default function ThreatFeed({ events }) {
  return (
    <section className="panel">
      <div className="panel-header">
        <span className="panel-kicker">Threat Feed</span>
        <h2>Live Event Stream</h2>
      </div>

      {events.length ? (
        <div className="feed-list">
          {events.slice(0, 10).map((event, index) => (
            <article className="feed-item" key={`${event.timestamp}-${index}`}>
              <div className="feed-row">
                <div>
                  <span className={`severity-pill ${severityTone(event.analysis?.label)}`}>
                    {event.analysis?.label || 'unknown'}
                  </span>
                  <h3>
                    {event.device_id} · {event.event_type}
                  </h3>
                </div>
                <span className="feed-time">{formatTimestamp(event.timestamp)}</span>
              </div>

              <p className="feed-summary">
                Confidence {event.analysis?.confidence ?? 0} · Anomaly {event.analysis?.anomaly_score ?? 0}
              </p>

              <div className="feed-meta">
                <span>Port {event.dst_port}</span>
                <span>Rate {event.request_rate}</span>
                <span>Banner {event.service_banner || 'Unknown'}</span>
              </div>

              <div className="feed-tags">
                {(event.analysis?.reasons || []).slice(0, 4).map((reason) => (
                  <span key={reason}>{reason}</span>
                ))}
              </div>
            </article>
          ))}
        </div>
      ) : (
        <div className="empty-state">
          <h3>No threat events yet</h3>
          <p>Once backend ingestion starts, the live feed will appear here.</p>
        </div>
      )}
    </section>
  )
}
