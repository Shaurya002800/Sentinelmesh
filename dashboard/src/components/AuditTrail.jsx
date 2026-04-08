function shortHash(value) {
  if (!value) return 'Pending'
  if (value.length < 18) return value
  return `${value.slice(0, 8)}...${value.slice(-6)}`
}

function confidenceValue(event) {
  return `${Math.round(Number(event.analysis?.confidence || 0) * 100)}%`
}

export default function AuditTrail({ events }) {
  return (
    <section className="panel-surface audit-panel">
      <div className="panel-header-row">
        <div>
          <span className="section-kicker">Blockchain Audit Trail</span>
          <h2>Permanent Evidence Log</h2>
        </div>
      </div>

      <div className="audit-table-wrap">
        <table className="audit-table">
          <thead>
            <tr>
              <th>#</th>
              <th>Time (UTC)</th>
              <th>Classification</th>
              <th>Conf.</th>
              <th>TX Hash</th>
            </tr>
          </thead>
          <tbody>
            {events.slice(0, 8).map((event, index) => (
              <tr key={`${event.blockchain?.incident_hash}-${index}`}>
                <td>{events.length - index}</td>
                <td>{new Date(event.timestamp || Date.now()).toISOString().slice(11, 19)}</td>
                <td>{event.analysis?.label || 'unknown'}</td>
                <td>{confidenceValue(event)}</td>
                <td>
                  {event.blockchain?.tx_hash ? (
                    <span className="audit-link">{shortHash(event.blockchain.tx_hash)} ↗</span>
                  ) : (
                    <span className="audit-fail">Pending</span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  )
}
