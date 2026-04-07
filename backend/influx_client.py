from __future__ import annotations

from typing import Any, Dict

from influxdb_client import InfluxDBClient, Point, WritePrecision
from influxdb_client.client.write_api import SYNCHRONOUS

from config import INFLUX_BUCKET, INFLUX_ORG, INFLUX_TOKEN, INFLUX_URL


class ThreatInfluxClient:
    def __init__(self) -> None:
        self.enabled = bool(INFLUX_URL and INFLUX_TOKEN)
        self.client = None
        self.write_api = None
        self.last_error = None

        if self.enabled:
            try:
                self.client = InfluxDBClient(url=INFLUX_URL, token=INFLUX_TOKEN, org=INFLUX_ORG)
                self.write_api = self.client.write_api(write_options=SYNCHRONOUS)
            except Exception as exc:
                self.enabled = False
                self.last_error = str(exc)

    def write_event(self, event: Dict[str, Any], analysis: Dict[str, Any]) -> None:
        if not self.enabled or self.write_api is None:
            return

        point = (
            Point("threat_events")
            .tag("device_id", str(event.get("device_id", "unknown")))
            .tag("event_type", str(event.get("event_type", "unknown")))
            .tag("label", str(analysis.get("label", "unknown")))
            .field("confidence", float(analysis.get("confidence", 0)))
            .field("anomaly_score", float(analysis.get("anomaly_score", 0)))
            .field("packet_size", float(event.get("packet_size", 0)))
            .field("duration_ms", float(event.get("duration_ms", 0)))
            .field("failed_logins", float(event.get("failed_logins", 0)))
            .field("request_rate", float(event.get("request_rate", 0)))
            .field("payload_size", float(event.get("payload_size", 0)))
            .field("touch_count", float(event.get("touch_count", 0)))
            .time(event.get("timestamp"), WritePrecision.NS)
        )

        try:
            self.write_api.write(bucket=INFLUX_BUCKET, org=INFLUX_ORG, record=point)
            self.last_error = None
        except Exception as exc:
            # Keep the backend alive even if Influx credentials are wrong during setup.
            self.last_error = str(exc)
            self.enabled = False

    def close(self) -> None:
        if self.client:
            self.client.close()
