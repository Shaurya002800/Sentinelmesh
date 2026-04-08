function toneClass(severity) {
  if (severity === 'critical') return 'dot-critical'
  if (severity === 'high') return 'dot-high'
  return 'dot-low'
}

function formatTime(value) {
  if (!value) return 'Unknown'
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return value
  return date.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit', timeZoneName: 'short' })
}

export default function WorldMap({ points }) {
  return (
    <section className="panel-surface map-panel">
      <div className="panel-header-row">
        <div>
          <span className="section-kicker">World Attack Heatmap</span>
          <h2>Global Threat Activity</h2>
        </div>
        <div className="mini-legend">
          <span><i className="dot-critical" /> High</span>
          <span><i className="dot-high" /> Medium</span>
          <span><i className="dot-low" /> Low</span>
        </div>
      </div>

      <div className="map-stage">
        <svg viewBox="0 0 1000 460" className="world-svg" aria-hidden="true">
          <path d="M95 146C146 110 188 97 236 108C271 116 285 138 313 145C347 155 382 128 411 140C437 151 451 179 434 199C415 223 370 220 341 239C316 255 290 289 245 280C197 271 161 247 128 217C103 195 83 172 95 146Z" />
          <path d="M420 110C454 95 502 95 544 112C585 129 617 167 635 195C658 229 662 267 640 282C612 301 586 273 553 271C519 268 501 293 470 287C435 279 423 247 400 228C374 206 328 196 332 168C336 141 389 126 420 110Z" />
          <path d="M681 114C710 103 762 105 806 121C855 139 904 180 912 220C919 257 888 282 849 283C809 284 771 259 739 255C709 251 675 270 656 252C638 236 648 206 654 179C661 151 654 127 681 114Z" />
          <path d="M743 321C766 310 795 313 813 329C833 346 834 375 814 390C791 407 753 411 726 394C704 379 703 344 743 321Z" />
        </svg>

        {points.map((point) => (
          <button
            type="button"
            className={`map-dot ${toneClass(point.severity)}`}
            key={point.id}
            style={{ left: `${point.x}%`, top: `${point.y}%` }}
          >
            <span className="map-pulse" />
            <span className="map-tooltip">
              <strong>{point.city}</strong>
              <small>IP: {point.ip}</small>
              <small>First seen: {formatTime(point.firstSeen)}</small>
              <small>Total attempts: {point.attempts}</small>
              <small>Classification: {point.classification}</small>
            </span>
          </button>
        ))}
      </div>
    </section>
  )
}
