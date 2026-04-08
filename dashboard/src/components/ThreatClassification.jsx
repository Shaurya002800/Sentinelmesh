import { Cell, Pie, PieChart, ResponsiveContainer, Tooltip } from 'recharts'

export default function ThreatClassification({ items, total, isPending }) {
  const safeTotal = Math.max(total, 1)

  return (
    <section className="panel-surface classify-panel">
      <div className="panel-header-row">
        <div>
          <span className="section-kicker">Threat Classification</span>
          <h2>AI Attribution Donut</h2>
        </div>
        <span className="panel-chip">{isPending ? 'Refreshing' : 'Live model split'}</span>
      </div>

      <div className="classify-layout">
        <div className="donut-wrap">
          <ResponsiveContainer width="100%" height={260}>
            <PieChart>
              <Pie data={items} dataKey="value" nameKey="name" innerRadius={64} outerRadius={96} paddingAngle={4}>
                {items.map((item) => (
                  <Cell key={item.key} fill={item.color} />
                ))}
              </Pie>
              <Tooltip formatter={(value, name) => [`${value} incidents`, name]} />
            </PieChart>
          </ResponsiveContainer>
          <div className="donut-center">
            <strong>{total}</strong>
            <span>Incidents</span>
          </div>
        </div>

        <div className="classify-legend">
          {items.map((item) => (
            <article className="legend-row" key={item.key}>
              <div>
                <span className="legend-label"><i style={{ background: item.color }} /> {item.name}</span>
                <p>{Math.round((item.value / safeTotal) * 100)}%</p>
              </div>
              <strong>{item.value}</strong>
            </article>
          ))}
        </div>
      </div>
    </section>
  )
}
