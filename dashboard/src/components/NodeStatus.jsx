export default function NodeStatus({ nodes }) {
  const cards = nodes.length ? nodes : [
    { device_id: 'Node A', status: 'online', last_event_type: 'RTSP Camera', last_seen: '0 alerts' },
    { device_id: 'Node B', status: 'online', last_event_type: 'MQTT Sensor', last_seen: '2 alerts' },
    { device_id: 'Node C', status: 'online', last_event_type: 'HTTP Printer', last_seen: '0 alerts' },
    { device_id: 'Node D', status: 'online', last_event_type: 'SSH Server', last_seen: '1 alert' },
  ]

  return (
    <section className="panel-surface nodes-panel">
      <div className="panel-header-row">
        <div>
          <span className="section-kicker">Mesh Node Status</span>
          <h2>Canary Node Health</h2>
        </div>
      </div>

      <div className="node-grid">
        {cards.map((node, index) => (
          <article className="node-tile" key={`${node.device_id}-${index}`}>
            <div className="node-top">
              <strong>{node.device_id}</strong>
              <span className={`node-live ${node.status === 'alert' ? 'is-alert' : 'is-live'}`}>
                {node.status === 'alert' ? 'ALERT' : 'LIVE'}
              </span>
            </div>
            <p>{node.last_event_type || 'Service online'}</p>
            <small>{node.last_seen || 'Recently active'}</small>
          </article>
        ))}
      </div>
    </section>
  )
}
