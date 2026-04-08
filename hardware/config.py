from __future__ import annotations

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
MODEL_METADATA_PATH = BASE_DIR / "models" / "threat_classifier_metadata.json"
MANUAL_TAMPER_FILE = BASE_DIR / "manual_tamper.flag"

DEVICE_ID = os.getenv("DEVICE_ID", "esp32-node-1")
PEER_DEVICE_ID = os.getenv("PEER_DEVICE_ID", "esp32-node-2")
MQTT_BROKER = os.getenv("MQTT_BROKER", "localhost")
MQTT_PORT = int(os.getenv("MQTT_PORT", 1883))
MQTT_TOPIC = os.getenv("MQTT_TOPIC", "sentinelmesh/alerts")

SIMULATION_MODE = os.getenv("SIMULATION_MODE", "true").lower() == "true"
LOOP_DELAY_SECONDS = float(os.getenv("LOOP_DELAY_SECONDS", 2.0))
TAMPER_PROBABILITY = float(os.getenv("TAMPER_PROBABILITY", 0.15))
MESH_ENABLED = os.getenv("MESH_ENABLED", "true").lower() == "true"
AUTO_PEER_MESH_ALERT = os.getenv("AUTO_PEER_MESH_ALERT", "true").lower() == "true"

FAKE_SERVICES = [
    {"name": "mqtt-broker", "port": 1883, "banner": "Mosquitto 2.0"},
    {"name": "web-admin", "port": 8080, "banner": "SentinelMesh Gateway"},
    {"name": "ssh", "port": 22, "banner": "OpenSSH_9.0"},
]
