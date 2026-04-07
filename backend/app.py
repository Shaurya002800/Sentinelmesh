from __future__ import annotations

import atexit
import json

from flask import Flask, jsonify, request
from flask_cors import CORS

from config import FLASK_DEBUG, FLASK_HOST, FLASK_PORT
from mqtt_listener import EventStore, MQTTThreatListener

app = Flask(__name__)
CORS(app)

store = EventStore()
listener = MQTTThreatListener(store)
listener.start()
atexit.register(listener.stop)


@app.get("/health")
def health():
    return jsonify({
        "status": "ok",
        "service": "sentinelmesh-backend",
        "mqtt_connected": listener.connected,
        "mqtt_error": listener.start_error,
        "model_loaded": listener.classifier.model is not None,
        "model_error": listener.classifier.model_error,
    })


@app.get("/api/events")
def get_events():
    limit = int(request.args.get("limit", 50))
    return jsonify(store.list_events(limit=limit))


@app.get("/api/stats")
def get_stats():
    return jsonify(store.stats())


@app.get("/api/blockchain")
def get_blockchain_logs():
    events = store.list_events(limit=100)
    anchored = [event for event in events if event.get("blockchain", {}).get("incident_hash")]
    return jsonify(anchored)


@app.get("/api/nodes")
def get_nodes():
    events = store.list_events(limit=200)
    nodes = {}

    for event in events:
        device_id = event.get("device_id", "unknown")
        nodes[device_id] = {
            "device_id": device_id,
            "last_seen": event.get("timestamp"),
            "status": "alert" if event.get("analysis", {}).get("label") in {"high", "critical"} else "normal",
            "last_event_type": event.get("event_type"),
        }

    return jsonify(list(nodes.values()))


@app.post("/api/simulate")
def simulate():
    payload = request.get_json(force=True, silent=True) or {}
    listener.on_message(
        None,
        None,
        type("MockMsg", (), {"payload": json.dumps(payload).encode("utf-8")})(),
    )
    return jsonify({"message": "Simulated event ingested"}), 201


if __name__ == "__main__":
    app.run(host=FLASK_HOST, port=FLASK_PORT, debug=FLASK_DEBUG)
