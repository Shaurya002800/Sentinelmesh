from __future__ import annotations

import json
import time
from datetime import datetime, timezone

import paho.mqtt.client as mqtt

from ai_model import EdgeThreatModel
from config import (
    AUTO_PEER_MESH_ALERT,
    DEVICE_ID,
    LOOP_DELAY_SECONDS,
    MQTT_BROKER,
    MQTT_PORT,
    MQTT_TOPIC,
    PEER_DEVICE_ID,
)
from fake_services import FakeServiceRegistry
from fingerprint import TrafficFingerprinter
from mesh import MeshBroadcaster
from tamper import TamperSensor


class SentinelHardwareNode:
    def __init__(self) -> None:
        self.device_id = DEVICE_ID
        self.peer_device_id = PEER_DEVICE_ID
        self.tamper_sensor = TamperSensor()
        self.fingerprinter = TrafficFingerprinter()
        self.edge_model = EdgeThreatModel()
        self.mesh = MeshBroadcaster()
        self.services = FakeServiceRegistry()
        self.client = mqtt.Client()
        self.connected = False
        self.client.on_connect = self._on_connect

    def _on_connect(self, client, userdata, flags, rc):
        self.connected = rc == 0

    def connect(self) -> None:
        self.client.connect(MQTT_BROKER, MQTT_PORT, 60)
        self.client.loop_start()

    def build_event(self) -> tuple[dict, object]:
        tamper_state = self.tamper_sensor.read()
        attack_hint = None
        event = self.fingerprinter.capture(tamper=tamper_state.triggered, attack_hint=attack_hint)
        event["touch_count"] = tamper_state.touch_count
        event["device_id"] = self.device_id
        event["timestamp"] = datetime.now(timezone.utc).isoformat()
        event["source"] = tamper_state.source
        event["service_banner"] = self.services.get_banner(int(event.get("dst_port", 0)))
        event.update(self.edge_model.infer(event))
        event.update(self.mesh.broadcast({"event_type": event["event_type"], "edge_label": event["edge_label"]}))
        return event, tamper_state

    def build_peer_mesh_event(self, origin_event: dict) -> dict:
        peer_event = self.fingerprinter.capture(tamper=False, attack_hint="scan")
        peer_event.update({
            "device_id": self.peer_device_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source": "mesh-peer-alert",
            "event_type": "mesh_alert",
            "touch_count": 0,
            "failed_logins": max(int(peer_event.get("failed_logins", 0)), 2),
            "request_rate": max(float(peer_event.get("request_rate", 0)), 90.0),
            "mesh_origin": origin_event["device_id"],
            "mesh_status": "received_alert",
            "service_banner": self.services.get_banner(int(peer_event.get("dst_port", 0))),
        })
        peer_event.update(self.edge_model.infer(peer_event))
        peer_event["edge_label"] = "high" if peer_event["edge_label"] == "low" else peer_event["edge_label"]
        peer_event["edge_confidence"] = max(float(peer_event.get("edge_confidence", 0)), 0.72)
        peer_event["edge_reasons"] = list(dict.fromkeys([
            "Mesh alert received from peer node",
            *peer_event.get("edge_reasons", []),
        ]))
        return peer_event

    def publish_once(self) -> list[dict]:
        event, tamper_state = self.build_event()
        published = [event]
        self.client.publish(MQTT_TOPIC, json.dumps(event))

        if tamper_state.triggered and AUTO_PEER_MESH_ALERT:
            peer_event = self.build_peer_mesh_event(event)
            self.client.publish(MQTT_TOPIC, json.dumps(peer_event))
            published.append(peer_event)

        return published

    def run(self) -> None:
        self.connect()
        print(f"SentinelMesh hardware node started: {self.device_id}")
        print(f"Publishing to mqtt://{MQTT_BROKER}:{MQTT_PORT} topic={MQTT_TOPIC}")
        print("Manual tamper trigger: touch hardware/manual_tamper.flag")
        while True:
            events = self.publish_once()
            for event in events:
                print(json.dumps(event, indent=2))
            time.sleep(LOOP_DELAY_SECONDS)


if __name__ == "__main__":
    SentinelHardwareNode().run()
