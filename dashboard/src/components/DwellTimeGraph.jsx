import { Area, AreaChart, CartesianGrid, Cell, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'

function statusLabel(seconds) {
  if (seconds > 60) return 'Human attacker confirmed'
  if (seconds >= 15) return 'Suspicious dwell'
  return 'Bot-like touch'
}

export default function DwellTimeGraph({ data }) {
  return (
    <section className="panel-surface graph-panel">
      <div className="panel-header-row">
        <div>
          <span className="section-kicker">Attacker Dwell Time</span>
          <h2>Engagement Over Time</h2>
        </div>
      </div>

      <div className="graph-wrap">
        <ResponsiveContainer width="100%" height={280}>
          <AreaChart data={data}>
            <defs>
              <linearGradient id="dwellFill" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#6ea8fe" stopOpacity={0.5} />
                <stop offset="95%" stopColor="#6ea8fe" stopOpacity={0.05} />
              </linearGradient>
            </defs>
            <CartesianGrid stroke="rgba(255,255,255,0.08)" vertical={false} />
            <XAxis dataKey="label" stroke="#8fa7cb" tickLine={false} axisLine={false} />
            <YAxis stroke="#8fa7cb" tickLine={false} axisLine={false} width={36} />
            <Tooltip formatter={(value) => [`${value} sec`, statusLabel(value)]} />
            <Area type="monotone" dataKey="seconds" stroke="#8ec5ff" fill="url(#dwellFill)" strokeWidth={3} />
          </AreaChart>
        </ResponsiveContainer>

        <div className="graph-legend">
          <span><i className="legend-blue" /> Under 15 sec = Bot activity</span>
          <span><i className="legend-amber" /> 15-60 sec = Suspicious</span>
          <span><i className="legend-red" /> Over 60 sec = Human confirmed</span>
        </div>
      </div>
    </section>
  )
}
