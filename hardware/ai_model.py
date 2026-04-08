from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

from config import MODEL_METADATA_PATH


class EdgeThreatModel:
    def __init__(self, metadata_path: Path = MODEL_METADATA_PATH) -> None:
        self.metadata_path = metadata_path
        self.metadata = self._load_metadata()
        self.thresholds = self.metadata.get("thresholds", {})

    def _load_metadata(self) -> Dict[str, Any]:
        if self.metadata_path.exists() and self.metadata_path.stat().st_size > 0:
            return json.loads(self.metadata_path.read_text())
        return {
            "model_name": "fallback-edge-model",
            "thresholds": {"failed_logins": 5, "request_rate": 100, "touch_count": 1},
        }

    def infer(self, event: Dict[str, Any]) -> Dict[str, Any]:
        reasons: List[str] = []
        score = 0.08

        if float(event.get("touch_count", 0)) >= self.thresholds.get("touch_count", 1):
            score += 0.55
            reasons.append("Touch/tamper threshold exceeded")

        if float(event.get("failed_logins", 0)) >= self.thresholds.get("failed_logins", 5):
            score += 0.18
            reasons.append("Authentication failures exceeded threshold")

        if float(event.get("request_rate", 0)) >= self.thresholds.get("request_rate", 100):
            score += 0.16
            reasons.append("Request burst threshold exceeded")

        if int(event.get("dst_port", 0)) in {22, 23, 3389}:
            score += 0.08
            reasons.append("Sensitive port targeted")

        score = min(score, 0.99)
        label = "critical" if score >= 0.85 else "high" if score >= 0.65 else "medium" if score >= 0.4 else "low"
        return {
            "edge_label": label,
            "edge_confidence": round(score, 3),
            "edge_reasons": reasons or ["Traffic within normal edge thresholds"],
            "model_name": self.metadata.get("model_name", "fallback-edge-model"),
        }
