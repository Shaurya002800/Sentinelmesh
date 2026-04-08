function shortenHash(value) {
  if (!value) return 'Pending'
  if (value.length < 18) return value
  return `${value.slice(0, 10)}...${value.slice(-8)}`
}

export default function BlockchainLog({ events }) {
  return (
    <section className="panel">
      <div className="panel-header">
        <span className="panel-kicker">Evidence Chain</span>
        <h2>Blockchain Log</h2>
      </div>

      {events.length ? (
        <div className="chain-list">
          {events.slice(0, 8).map((event, index) => (
            <article className="chain-item" key={`${event.blockchain?.incident_hash}-${index}`}>
              <div className="chain-row">
                <strong>{event.device_id}</strong>
                <span className={event.blockchain?.anchored ? 'chain-ok' : 'chain-fail'}>
                  {event.blockchain?.anchored ? 'Anchored' : 'Failed'}
                </span>
              </div>
              <p>{event.event_type} · {event.analysis?.label || 'unknown'} severity</p>
              <div className="chain-meta">
                <span>Incident: {shortenHash(event.blockchain?.incident_hash)}</span>
                <span>TX: {shortenHash(event.blockchain?.tx_hash)}</span>
              </div>
              {event.blockchain?.error ? <p className="chain-error">{event.blockchain.error}</p> : null}
            </article>
          ))}
        </div>
      ) : (
        <div className="empty-state">
          <h3>No blockchain records yet</h3>
          <p>Anchored tamper events will appear here with incident and transaction hashes.</p>
        </div>
      )}
    </section>
  )
}
