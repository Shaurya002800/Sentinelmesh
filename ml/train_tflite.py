from __future__ import annotations

import json
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
OUTPUT_PATH = BASE_DIR.parent / "hardware" / "models" / "threat_classifier.tflite"
METADATA_PATH = BASE_DIR.parent / "hardware" / "models" / "threat_classifier_metadata.json"

# Lightweight placeholder export for the hackathon narrative.
# The actual ESP32 TFLite export can be added later when TensorFlow Lite tooling is available.
MODEL_METADATA = {
    "model_name": "sentinelmesh-edge-threshold-v1",
    "features": [
        "packet_size",
        "duration_ms",
        "src_port",
        "dst_port",
        "failed_logins",
        "request_rate",
        "payload_size",
        "touch_count",
    ],
    "thresholds": {
        "failed_logins": 5,
        "request_rate": 100,
        "touch_count": 1,
    },
    "notes": "Placeholder edge-model metadata. Replace with a real TFLite export when TensorFlow Lite conversion is available.",
}

if __name__ == "__main__":
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_PATH.write_bytes(b"SENTINELMESH_TFLITE_PLACEHOLDER")
    METADATA_PATH.write_text(json.dumps(MODEL_METADATA, indent=2) + "\n")
    print(f"Wrote placeholder TFLite artifact to {OUTPUT_PATH}")
    print(f"Wrote metadata to {METADATA_PATH}")
