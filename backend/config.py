import os
from pathlib import Path

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")

# MQTT
MQTT_BROKER = os.getenv("MQTT_BROKER", "localhost")
MQTT_PORT = int(os.getenv("MQTT_PORT", 1883))
MQTT_TOPIC = os.getenv("MQTT_TOPIC", "sentinelmesh/alerts")

# InfluxDB
INFLUX_URL = os.getenv("INFLUX_URL", "http://localhost:8086")
INFLUX_TOKEN = os.getenv("INFLUX_TOKEN", "")
INFLUX_ORG = os.getenv("INFLUX_ORG", "sentinelmesh")
INFLUX_BUCKET = os.getenv("INFLUX_BUCKET", "threats")

# Blockchain
RPC_URL = os.getenv("RPC_URL", "")
PRIVATE_KEY = os.getenv("PRIVATE_KEY", "")
CONTRACT_ADDRESS = os.getenv("CONTRACT_ADDRESS", "")

# Flask
FLASK_HOST = os.getenv("FLASK_HOST", "0.0.0.0")
FLASK_PORT = int(os.getenv("FLASK_PORT", 5000))
FLASK_DEBUG = os.getenv("FLASK_DEBUG", "true").lower() == "true"

# Models
MODEL_PATH = BASE_DIR / "models" / "isolation_forest.pkl"

# App behavior
MAX_EVENTS_IN_MEMORY = int(os.getenv("MAX_EVENTS_IN_MEMORY", 200))
ANCHOR_ON_TAMPER = os.getenv("ANCHOR_ON_TAMPER", "true").lower() == "true"
ANCHOR_RISK_THRESHOLD = float(os.getenv("ANCHOR_RISK_THRESHOLD", 0.8))

# Geolocation
GEOLOCATION_ENABLED = os.getenv("GEOLOCATION_ENABLED", "true").lower() == "true"
GEOLOCATION_LOOKUP_TIMEOUT = float(os.getenv("GEOLOCATION_LOOKUP_TIMEOUT", 2.0))
