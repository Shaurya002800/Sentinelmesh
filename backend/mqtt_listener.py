from __future__ import annotations

import json
from collections import deque
from datetime import datetime, timezone
from threading import Lock
from typing import Any, Deque, Dict, List

import paho.mqtt.client as mqtt

from ai_classifier import ThreatClassifier
from blockchain import BlockchainAnchor
from config import (
    ANCHOR_ON_TAMPER,
    ANCHOR_RISK_THRESHOLD,
    MAX_EVENTS_IN_MEMORY,
    MQTT_BROKER,
    MQTT_PORT,
    MQTT_TOPIC,
)
from geolocation import GeoLocator
from influx_client import ThreatInfluxClient


class EventStore:
    def __init__(self, max_events: int = MAX_EVENTS_IN_MEMORY) -> None:
        self.events: Deque[Dict[str, Any]] = deque(maxlen=max_events)
        self.lock = Lock()

    def add(self, event: Dict[str, Any]) -> None:
        with self.lock:
            self.events.appendleft(event)

    def list_events(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self.lock:
            return list(self.events)[:limit]

    def stats(self) -> Dict[str, Any]:
        with self.lock:
            events = list(self.events)

        total = len(events)
        critical = sum(1 for e in events if e.get("analysis", {}).get("label") == "critical")
        high = sum(1 for e in events if e.get("analysis", {}).get("label") == "high")
        anchored = sum(1 for e in events if e.get("blockchain", {}).get("anchored"))

        return {
            "total_events": total,
            "critical_events": critical,
            "high_events": high,
            "anchored_events": anchored,
        }


class MQTTThreatListener:
    def __init__(self, store: EventStore) -> None:
        self.store = store
        self.classifier = ThreatClassifier()
        self.influx = ThreatInfluxClient()
        self.blockchain = BlockchainAnchor()
        self.geolocator = GeoLocator()
        self.connected = False
        self.start_error = None

        self.client = mqtt.Client()
        self.client.on_connect = self.on_connect
        self.client.on_message = self.on_message

    def on_connect(self, client, userdata, flags, rc):
        if rc == 0:
            self.connected = True
            client.subscribe(MQTT_TOPIC)

    def should_anchor(self, event: Dict[str, Any], analysis: Dict[str, Any]) -> bool:
        if ANCHOR_ON_TAMPER and str(event.get("event_type", "")).lower() == "tamper":
            return True
        return float(analysis.get("confidence", 0)) >= ANCHOR_RISK_THRESHOLD

    def on_message(self, client, userdata, msg):
        try:
            payload = json.loads(msg.payload.decode("utf-8"))
        except Exception:
            return

        payload.setdefault("timestamp", datetime.now(timezone.utc).isoformat())
        payload.setdefault("device_id", "esp32-node-1")
        payload.setdefault("event_type", "network")
        payload = self.geolocator.enrich(payload)

        analysis = self.classifier.analyze(payload)
        blockchain_result = {
            "anchored": False,
            "tx_hash": None,
            "incident_hash": None,
            "error": None,
        }

        if self.should_anchor(payload, analysis):
            blockchain_result = self.blockchain.anchor_event(payload)

        enriched_event = {
            **payload,
            "analysis": analysis,
            "blockchain": blockchain_result,
        }

        self.store.add(enriched_event)
        self.influx.write_event(payload, analysis)

    def start(self) -> None:
        try:
            self.client.connect(MQTT_BROKER, MQTT_PORT, 60)
            self.client.loop_start()
            self.start_error = None
        except Exception as exc:
            self.start_error = str(exc)
            self.connected = False

    def stop(self) -> None:
        if self.connected:
            self.client.loop_stop()
            self.client.disconnect()
        self.influx.close()
