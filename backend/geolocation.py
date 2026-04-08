from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass
from threading import Lock
from typing import Any, Dict, Optional
from urllib.error import URLError
from urllib.request import urlopen

from config import GEOLOCATION_ENABLED, GEOLOCATION_LOOKUP_TIMEOUT

DEMO_IP_LOCATIONS: dict[str, dict[str, Any]] = {
    "103.21.244.15": {
        "city": "Mumbai",
        "region": "Maharashtra",
        "country": "India",
        "latitude": 19.0760,
        "longitude": 72.8777,
    },
    "13.228.45.201": {
        "city": "Singapore",
        "region": "Singapore",
        "country": "Singapore",
        "latitude": 1.3521,
        "longitude": 103.8198,
    },
    "18.203.142.71": {
        "city": "Dublin",
        "region": "Leinster",
        "country": "Ireland",
        "latitude": 53.3498,
        "longitude": -6.2603,
    },
    "44.208.12.144": {
        "city": "Ashburn",
        "region": "Virginia",
        "country": "United States",
        "latitude": 39.0438,
        "longitude": -77.4874,
    },
    "35.73.210.55": {
        "city": "Tokyo",
        "region": "Tokyo",
        "country": "Japan",
        "latitude": 35.6762,
        "longitude": 139.6503,
    },
    "18.228.120.44": {
        "city": "Sao Paulo",
        "region": "Sao Paulo",
        "country": "Brazil",
        "latitude": -23.5505,
        "longitude": -46.6333,
    },
}


@dataclass
class GeoLookupResult:
    ip: str
    city: str
    region: str
    country: str
    latitude: float
    longitude: float
    source: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ip": self.ip,
            "city": self.city,
            "region": self.region,
            "country": self.country,
            "latitude": self.latitude,
            "longitude": self.longitude,
            "source": self.source,
            "label": ", ".join(part for part in [self.city, self.country] if part),
        }


class GeoLocator:
    def __init__(self) -> None:
        self.enabled = GEOLOCATION_ENABLED
        self.cache: dict[str, dict[str, Any]] = {}
        self.lock = Lock()

    def enrich(self, event: Dict[str, Any]) -> Dict[str, Any]:
        ip_value = str(event.get("src_ip") or event.get("source_ip") or "").strip()
        if not ip_value or not self.enabled:
            return event

        with self.lock:
            cached = self.cache.get(ip_value)
        if cached is not None:
            event["geo"] = cached
            return event

        geo = self._lookup(ip_value)
        if geo is not None:
            payload = geo.to_dict()
            with self.lock:
                self.cache[ip_value] = payload
            event["geo"] = payload
        return event

    def _lookup(self, ip_value: str) -> Optional[GeoLookupResult]:
        demo = DEMO_IP_LOCATIONS.get(ip_value)
        if demo:
            return GeoLookupResult(ip=ip_value, source="demo-map", **demo)

        try:
            ip_obj = ipaddress.ip_address(ip_value)
        except ValueError:
            return None

        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_unspecified:
            return None

        try:
            with urlopen(f"https://ipwho.is/{ip_value}", timeout=GEOLOCATION_LOOKUP_TIMEOUT) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except (OSError, URLError, TimeoutError, ValueError, json.JSONDecodeError):
            return None

        if not payload.get("success"):
            return None

        latitude = payload.get("latitude")
        longitude = payload.get("longitude")
        if latitude is None or longitude is None:
            return None

        return GeoLookupResult(
            ip=ip_value,
            city=str(payload.get("city") or "Unknown city"),
            region=str(payload.get("region") or "Unknown region"),
            country=str(payload.get("country") or "Unknown country"),
            latitude=float(latitude),
            longitude=float(longitude),
            source="ipwhois",
        )
