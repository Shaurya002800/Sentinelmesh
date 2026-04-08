from __future__ import annotations

import random
from dataclasses import dataclass
from typing import Any, Dict, Optional

DEMO_ATTACKER_IPS = [
    "103.21.244.15",
    "13.228.45.201",
    "18.203.142.71",
    "44.208.12.144",
    "35.73.210.55",
    "18.228.120.44",
]


@dataclass
class PacketFingerprint:
    packet_size: int
    duration_ms: int
    src_port: int
    dst_port: int
    failed_logins: int
    request_rate: float
    payload_size: int
    touch_count: int
    event_type: str
    src_ip: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "packet_size": self.packet_size,
            "duration_ms": self.duration_ms,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "failed_logins": self.failed_logins,
            "request_rate": self.request_rate,
            "payload_size": self.payload_size,
            "touch_count": self.touch_count,
            "event_type": self.event_type,
            "src_ip": self.src_ip,
        }


class TrafficFingerprinter:
    def __init__(self, seed: int = 42) -> None:
        self.rng = random.Random(seed)

    def _pick_ip(self) -> str:
        return self.rng.choice(DEMO_ATTACKER_IPS)

    def build_normal_fingerprint(self) -> PacketFingerprint:
        packet_size = int(min(max(self.rng.gauss(300, 55), 100), 520))
        duration_ms = int(min(max(self.rng.gauss(115, 22), 35), 180))
        return PacketFingerprint(
            packet_size=packet_size,
            duration_ms=duration_ms,
            src_port=self.rng.randint(30000, 65000),
            dst_port=self.rng.choice([1883, 443, 8080]),
            failed_logins=0,
            request_rate=round(min(max(self.rng.gauss(14, 4), 2), 28), 2),
            payload_size=int(packet_size * self.rng.uniform(0.35, 0.7)),
            touch_count=0,
            event_type=self.rng.choice(["heartbeat", "network", "status"]),
            src_ip=self._pick_ip(),
        )

    def build_tamper_fingerprint(self) -> PacketFingerprint:
        return PacketFingerprint(
            packet_size=self.rng.randint(420, 960),
            duration_ms=self.rng.randint(35, 150),
            src_port=self.rng.randint(30000, 65000),
            dst_port=self.rng.choice([22, 23, 3389, 1883]),
            failed_logins=self.rng.randint(5, 12),
            request_rate=round(self.rng.uniform(95, 180), 2),
            payload_size=self.rng.randint(240, 760),
            touch_count=self.rng.randint(1, 3),
            event_type="tamper",
            src_ip=self._pick_ip(),
        )

    def build_scan_fingerprint(self) -> PacketFingerprint:
        return PacketFingerprint(
            packet_size=self.rng.randint(64, 210),
            duration_ms=self.rng.randint(8, 50),
            src_port=self.rng.randint(30000, 65000),
            dst_port=self.rng.choice([21, 22, 23, 80, 443, 445, 1883, 3389]),
            failed_logins=self.rng.randint(0, 2),
            request_rate=round(self.rng.uniform(85, 220), 2),
            payload_size=self.rng.randint(16, 100),
            touch_count=0,
            event_type="network",
            src_ip=self._pick_ip(),
        )

    def capture(self, tamper: bool = False, attack_hint: Optional[str] = None) -> Dict[str, Any]:
        if tamper:
            fingerprint = self.build_tamper_fingerprint()
        elif attack_hint == "scan":
            fingerprint = self.build_scan_fingerprint()
        else:
            fingerprint = self.build_normal_fingerprint()
        return fingerprint.to_dict()
