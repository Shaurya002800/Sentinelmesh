function formatTime(value) {
  if (!value) return 'No external queries yet'
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return value
  return date.toLocaleString('en-GB', { hour: '2-digit', minute: '2-digit', second: '2-digit' })
}

export default function ApiPanel({ stats, service }) {
  return (
    <section className="panel-surface api-panel">
      <div className="panel-header-row">
        <div>
          <span className="section-kicker">Threat Intelligence API</span>
          <h2>Public Threat API — LIVE</h2>
        </div>
      </div>

      <div className="api-routes">
        <article>
          <strong>GET /api/threats</strong>
          <span>{stats.totalRecords} records available</span>
        </article>
        <article>
          <strong>GET /api/threats?type=APT</strong>
          <span>{stats.aptCount} records</span>
        </article>
        <article>
          <strong>GET /api/threats?region=Asia</strong>
          <span>{stats.asiaCount} records</span>
        </article>
      </div>

      <div className="api-footnote">
        <p>Last queried by external team: {formatTime(stats.lastQueried)}</p>
        <p>Total external API calls today: {stats.todayCalls}</p>
        <small>Service source: {service}</small>
      </div>
    </section>
  )
}
