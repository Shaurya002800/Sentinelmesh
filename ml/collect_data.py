from __future__ import annotations

import csv
import random
from pathlib import Path
from typing import Dict, Iterable, List

DATA_DIR = Path(__file__).resolve().parent / "data"
OUTPUT_PATH = DATA_DIR / "normal_traffic.csv"
FIELDNAMES = [
    "packet_size",
    "duration_ms",
    "src_port",
    "dst_port",
    "failed_logins",
    "request_rate",
    "payload_size",
    "touch_count",
    "bytes_per_ms",
    "payload_ratio",
    "auth_density",
    "privileged_dst",
    "is_tamper_event",
    "request_burst",
    "service_risk",
    "touch_intensity",
    "dwell_score",
    "mesh_signal",
    "event_type",
    "scenario",
    "label",
    "actor_type",
]

RNG = random.Random(42)
PRIVILEGED_PORTS = {21, 22, 23, 25, 445, 1883, 3389}
SERVICE_RISK_PORTS = {
    21: 0.75,
    22: 0.86,
    23: 0.92,
    80: 0.20,
    443: 0.18,
    445: 0.94,
    1883: 0.52,
    3389: 0.96,
    8080: 0.28,
}


def _clip(value: float, low: float, high: float) -> float:
    return max(low, min(high, value))



def _base_sample() -> Dict[str, float | int | str]:
    return {
        "packet_size": 0,
        "duration_ms": 0,
        "src_port": 0,
        "dst_port": 0,
        "failed_logins": 0,
        "request_rate": 0.0,
        "payload_size": 0,
        "touch_count": 0,
        "event_type": "network",
        "scenario": "unknown",
        "label": "normal",
        "actor_type": "benign",
    }



def _engineer_features(sample: Dict[str, float | int | str]) -> Dict[str, float | int | str]:
    packet_size = float(sample["packet_size"])
    duration_ms = max(float(sample["duration_ms"]), 1.0)
    payload_size = float(sample["payload_size"])
    failed_logins = float(sample["failed_logins"])
    request_rate = float(sample["request_rate"])
    dst_port = int(sample["dst_port"])
    touch_count = float(sample["touch_count"])
    event_type = str(sample["event_type"]).lower()

    sample["bytes_per_ms"] = round(packet_size / duration_ms, 4)
    sample["payload_ratio"] = round(min(payload_size / max(packet_size, 1.0), 1.5), 4)
    sample["auth_density"] = round(failed_logins / max(request_rate, 1.0), 4)
    sample["privileged_dst"] = 1 if dst_port in PRIVILEGED_PORTS else 0
    sample["is_tamper_event"] = 1 if event_type == "tamper" else 0
    sample["request_burst"] = 1 if request_rate >= 90 else 0
    sample["service_risk"] = round(SERVICE_RISK_PORTS.get(dst_port, 0.12), 3)
    sample["touch_intensity"] = round(touch_count / 3.0, 3)
    sample["dwell_score"] = round(duration_ms / max(request_rate, 1.0), 4)
    sample["mesh_signal"] = 1 if event_type == "mesh_alert" else 0
    return sample



def build_heartbeat_sample() -> Dict[str, float | int | str]:
    sample = _base_sample()
    packet_size = int(_clip(RNG.gauss(280, 35), 140, 360))
    sample.update({
        "packet_size": packet_size,
        "duration_ms": int(_clip(RNG.gauss(100, 16), 55, 150)),
        "src_port": RNG.randint(24000, 65000),
        "dst_port": RNG.choice([1883, 443]),
        "failed_logins": 0,
        "request_rate": round(_clip(RNG.gauss(7, 2), 1.5, 12), 2),
        "payload_size": int(_clip(packet_size * RNG.uniform(0.35, 0.55), 60, 190)),
        "touch_count": 0,
        "event_type": "heartbeat",
        "scenario": "heartbeat",
    })
    return _engineer_features(sample)



def build_telemetry_sample() -> Dict[str, float | int | str]:
    sample = _base_sample()
    packet_size = int(_clip(RNG.gauss(430, 70), 220, 650))
    sample.update({
        "packet_size": packet_size,
        "duration_ms": int(_clip(RNG.gauss(155, 30), 80, 280)),
        "src_port": RNG.randint(22000, 65000),
        "dst_port": RNG.choice([443, 1883, 8080]),
        "failed_logins": 0 if RNG.random() < 0.995 else 1,
        "request_rate": round(_clip(RNG.gauss(15, 4), 4, 24), 2),
        "payload_size": int(_clip(packet_size * RNG.uniform(0.45, 0.8), 120, 490)),
        "touch_count": 0,
        "event_type": "network",
        "scenario": "telemetry_upload",
    })
    return _engineer_features(sample)



def build_dashboard_poll_sample() -> Dict[str, float | int | str]:
    sample = _base_sample()
    packet_size = int(_clip(RNG.gauss(335, 55), 160, 520))
    sample.update({
        "packet_size": packet_size,
        "duration_ms": int(_clip(RNG.gauss(180, 30), 90, 280)),
        "src_port": RNG.randint(25000, 65000),
        "dst_port": RNG.choice([80, 443]),
        "failed_logins": 0,
        "request_rate": round(_clip(RNG.gauss(9, 2.5), 2, 15), 2),
        "payload_size": int(_clip(packet_size * RNG.uniform(0.30, 0.6), 80, 310)),
        "touch_count": 0,
        "event_type": "status",
        "scenario": "dashboard_poll",
    })
    return _engineer_features(sample)



def build_firmware_check_sample() -> Dict[str, float | int | str]:
    sample = _base_sample()
    packet_size = int(_clip(RNG.gauss(560, 100), 260, 900))
    sample.update({
        "packet_size": packet_size,
        "duration_ms": int(_clip(RNG.gauss(240, 50), 120, 420)),
        "src_port": RNG.randint(22000, 65000),
        "dst_port": 443,
        "failed_logins": 0,
        "request_rate": round(_clip(RNG.gauss(4.5, 1.5), 1, 9), 2),
        "payload_size": int(_clip(packet_size * RNG.uniform(0.58, 0.92), 180, 820)),
        "touch_count": 0,
        "event_type": "network",
        "scenario": "firmware_check",
    })
    return _engineer_features(sample)



def build_mesh_heartbeat_sample() -> Dict[str, float | int | str]:
    sample = _base_sample()
    packet_size = int(_clip(RNG.gauss(210, 35), 90, 320))
    sample.update({
        "packet_size": packet_size,
        "duration_ms": int(_clip(RNG.gauss(88, 15), 40, 140)),
        "src_port": RNG.randint(24000, 65000),
        "dst_port": 1883,
        "failed_logins": 0,
        "request_rate": round(_clip(RNG.gauss(6, 1.8), 1.5, 10), 2),
        "payload_size": int(_clip(packet_size * RNG.uniform(0.25, 0.45), 45, 130)),
        "touch_count": 0,
        "event_type": "mesh_alert",
        "scenario": "mesh_status",
    })
    return _engineer_features(sample)



def build_tamper_sample() -> Dict[str, float | int | str]:
    sample = _base_sample()
    sample.update({
        "packet_size": RNG.randint(520, 960),
        "duration_ms": RNG.randint(60, 180),
        "src_port": RNG.randint(32000, 65000),
        "dst_port": RNG.choice([22, 23, 3389, 1883]),
        "failed_logins": RNG.randint(5, 12),
        "request_rate": round(RNG.uniform(92, 150), 2),
        "payload_size": RNG.randint(260, 780),
        "touch_count": RNG.randint(1, 4),
        "event_type": "tamper",
        "scenario": "physical_tamper",
        "label": "attack",
        "actor_type": "human",
    })
    return _engineer_features(sample)



def build_credential_attack_sample() -> Dict[str, float | int | str]:
    sample = _base_sample()
    sample.update({
        "packet_size": RNG.randint(180, 520),
        "duration_ms": RNG.randint(55, 210),
        "src_port": RNG.randint(32000, 65000),
        "dst_port": RNG.choice([22, 443, 3389]),
        "failed_logins": RNG.randint(10, 28),
        "request_rate": round(RNG.uniform(38, 95), 2),
        "payload_size": RNG.randint(90, 360),
        "touch_count": 0,
        "event_type": "network",
        "scenario": "credential_stuffing",
        "label": "attack",
        "actor_type": "human",
    })
    return _engineer_features(sample)



def build_port_scan_sample() -> Dict[str, float | int | str]:
    sample = _base_sample()
    sample.update({
        "packet_size": RNG.randint(64, 180),
        "duration_ms": RNG.randint(8, 45),
        "src_port": RNG.randint(32000, 65000),
        "dst_port": RNG.choice([21, 22, 23, 25, 53, 80, 139, 443, 445, 1883, 3389, 8080]),
        "failed_logins": RNG.randint(0, 2),
        "request_rate": round(RNG.uniform(85, 190), 2),
        "payload_size": RNG.randint(16, 90),
        "touch_count": 0,
        "event_type": "network",
        "scenario": "port_scan",
        "label": "attack",
        "actor_type": "bot",
    })
    return _engineer_features(sample)



def build_flood_sample() -> Dict[str, float | int | str]:
    sample = _base_sample()
    sample.update({
        "packet_size": RNG.randint(700, 1500),
        "duration_ms": RNG.randint(5, 28),
        "src_port": RNG.randint(32000, 65000),
        "dst_port": RNG.choice([80, 443, 1883, 8080]),
        "failed_logins": RNG.randint(0, 2),
        "request_rate": round(RNG.uniform(180, 420), 2),
        "payload_size": RNG.randint(460, 1450),
        "touch_count": 0,
        "event_type": "network",
        "scenario": "request_flood",
        "label": "attack",
        "actor_type": "bot",
    })
    return _engineer_features(sample)



def build_low_and_slow_sample() -> Dict[str, float | int | str]:
    sample = _base_sample()
    sample.update({
        "packet_size": RNG.randint(140, 340),
        "duration_ms": RNG.randint(320, 1100),
        "src_port": RNG.randint(32000, 65000),
        "dst_port": RNG.choice([22, 80, 443, 1883]),
        "failed_logins": RNG.randint(1, 5),
        "request_rate": round(RNG.uniform(5, 18), 2),
        "payload_size": RNG.randint(70, 240),
        "touch_count": RNG.choice([0, 0, 1]),
        "event_type": "network",
        "scenario": "low_and_slow_probe",
        "label": "attack",
        "actor_type": "apt",
    })
    return _engineer_features(sample)



def build_mesh_pivot_sample() -> Dict[str, float | int | str]:
    sample = _base_sample()
    sample.update({
        "packet_size": RNG.randint(160, 360),
        "duration_ms": RNG.randint(90, 260),
        "src_port": RNG.randint(32000, 65000),
        "dst_port": RNG.choice([1883, 443, 8080]),
        "failed_logins": RNG.randint(2, 5),
        "request_rate": round(RNG.uniform(25, 70), 2),
        "payload_size": RNG.randint(80, 240),
        "touch_count": 0,
        "event_type": "mesh_alert",
        "scenario": "mesh_pivot_alert",
        "label": "attack",
        "actor_type": "apt",
    })
    return _engineer_features(sample)


NORMAL_BUILDERS = [
    build_heartbeat_sample,
    build_telemetry_sample,
    build_dashboard_poll_sample,
    build_firmware_check_sample,
    build_mesh_heartbeat_sample,
]
ATTACK_BUILDERS = [
    build_tamper_sample,
    build_credential_attack_sample,
    build_port_scan_sample,
    build_flood_sample,
    build_low_and_slow_sample,
    build_mesh_pivot_sample,
]



def build_dataset(normal_count: int = 6500, attack_count: int = 2600) -> List[Dict[str, float | int | str]]:
    rows = [RNG.choice(NORMAL_BUILDERS)() for _ in range(normal_count)]
    rows.extend(RNG.choice(ATTACK_BUILDERS)() for _ in range(attack_count))
    RNG.shuffle(rows)
    return rows



def write_dataset(rows: Iterable[Dict[str, float | int | str]], output_path: Path = OUTPUT_PATH) -> Path:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", newline="") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=FIELDNAMES)
        writer.writeheader()
        writer.writerows(rows)
    return output_path


if __name__ == "__main__":
    dataset = build_dataset()
    output = write_dataset(dataset)
    print(f"Wrote {len(dataset)} rows to {output}")
