import { Cell, Pie, PieChart, ResponsiveContainer, Tooltip } from 'recharts'

const COLORS = ['#ff6b57', '#ffb347', '#4fd1c5', '#7bd389']

export default function ThreatChart({ stats, events }) {
  const mediumEvents = events.filter((event) => event.analysis?.label === 'medium').length
  const lowEvents = Math.max(
    stats.total_events - stats.critical_events - stats.high_events - mediumEvents,
    0,
  )

  const data = [
    { name: 'Critical', value: stats.critical_events },
    { name: 'High', value: stats.high_events },
    { name: 'Medium', value: mediumEvents },
    { name: 'Low', value: lowEvents },
  ].filter((item) => item.value > 0)

  return (
    <section className="panel compact-panel">
      <div className="panel-header">
        <span className="panel-kicker">Threat Shape</span>
        <h2>Severity Mix</h2>
      </div>

      {data.length ? (
        <div className="chart-wrap">
          <ResponsiveContainer width="100%" height={240}>
            <PieChart>
              <Pie data={data} dataKey="value" nameKey="name" innerRadius={58} outerRadius={88} paddingAngle={3}>
                {data.map((entry, index) => (
                  <Cell key={entry.name} fill={COLORS[index % COLORS.length]} />
                ))}
              </Pie>
              <Tooltip />
            </PieChart>
          </ResponsiveContainer>
          <div className="chart-legend">
            {data.map((entry, index) => (
              <div className="legend-item" key={entry.name}>
                <span className="legend-dot" style={{ backgroundColor: COLORS[index % COLORS.length] }} />
                <span>{entry.name}</span>
                <strong>{entry.value}</strong>
              </div>
            ))}
          </div>
        </div>
      ) : (
        <div className="empty-state compact-empty">
          <p>No chart data yet.</p>
        </div>
      )}
    </section>
  )
}
