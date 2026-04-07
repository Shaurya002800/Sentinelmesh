from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List

import joblib

from config import MODEL_PATH


@dataclass
class ThreatAnalysis:
    label: str
    confidence: float
    anomaly_score: float
    reasons: List[str]


class ThreatClassifier:
    def __init__(self, model_path: Path = MODEL_PATH) -> None:
        self.model = None
        self.model_error = None

        if model_path.exists() and model_path.stat().st_size > 0:
            try:
                self.model = joblib.load(model_path)
            except Exception as exc:
                self.model_error = str(exc)

    def _extract_features(self, event: Dict[str, Any]) -> List[List[float]]:
        return [[
            float(event.get("packet_size", 0)),
            float(event.get("duration_ms", 0)),
            float(event.get("src_port", 0)),
            float(event.get("dst_port", 0)),
            float(event.get("failed_logins", 0)),
            float(event.get("request_rate", 0)),
            float(event.get("payload_size", 0)),
            float(event.get("touch_count", 0)),
        ]]

    def _heuristic_analysis(self, event: Dict[str, Any]) -> ThreatAnalysis:
        reasons = []
        score = 0.15

        event_type = str(event.get("event_type", "")).lower()
        if event_type == "tamper":
            score += 0.55
            reasons.append("Physical tamper signal detected")

        if float(event.get("failed_logins", 0)) >= 5:
            score += 0.2
            reasons.append("Repeated login failures")

        if float(event.get("request_rate", 0)) >= 100:
            score += 0.15
            reasons.append("Unusually high request rate")

        if int(event.get("dst_port", 0)) in {22, 23, 3389}:
            score += 0.1
            reasons.append("Sensitive target port touched")

        score = min(score, 0.99)
        label = "critical" if score >= 0.85 else "high" if score >= 0.65 else "medium" if score >= 0.4 else "low"
        return ThreatAnalysis(label=label, confidence=score, anomaly_score=score, reasons=reasons or ["Baseline heuristic evaluation"])

    def analyze(self, event: Dict[str, Any]) -> Dict[str, Any]:
        if self.model is None:
            result = self._heuristic_analysis(event)
            return result.__dict__

        try:
            features = self._extract_features(event)
            prediction = self.model.predict(features)[0]
            raw_score = float(self.model.decision_function(features)[0])

            anomaly_score = max(0.0, min(1.0, 0.5 + (-raw_score)))
            label = "high" if prediction == -1 else "low"
            confidence = anomaly_score if prediction == -1 else max(0.2, 1 - anomaly_score)

            reasons = ["Isolation Forest anomaly detection"]
            if prediction == -1:
                reasons.append("Traffic pattern deviates from normal baseline")

            return {
                "label": label,
                "confidence": round(confidence, 3),
                "anomaly_score": round(anomaly_score, 3),
                "reasons": reasons,
            }
        except Exception:
            result = self._heuristic_analysis(event)
            return result.__dict__
