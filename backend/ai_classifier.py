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
        self.pipeline = None
        self.attack_classifier = None
        self.actor_classifier = None
        self.hybrid_threshold = 0.56
        self.feature_names = [
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
        ]
        self.actor_labels = ["benign", "bot", "human", "apt"]
        self.model_error = None

        if model_path.exists() and model_path.stat().st_size > 0:
            try:
                loaded = joblib.load(model_path)
                if isinstance(loaded, dict):
                    self.model = loaded
                    self.pipeline = loaded.get("anomaly_pipeline") or loaded.get("pipeline")
                    self.attack_classifier = loaded.get("attack_classifier") or loaded.get("classifier")
                    self.actor_classifier = loaded.get("actor_classifier")
                    self.feature_names = loaded.get("feature_names", self.feature_names)
                    self.hybrid_threshold = loaded.get("hybrid_threshold", self.hybrid_threshold)
                    self.actor_labels = loaded.get("actor_labels", self.actor_labels)
                else:
                    self.pipeline = loaded
                    self.model = {"pipeline": loaded, "feature_names": self.feature_names}
            except Exception as exc:
                self.model_error = str(exc)

    def _enrich_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        enriched = dict(event)
        packet_size = float(enriched.get("packet_size", 0))
        duration_ms = max(float(enriched.get("duration_ms", 0)), 1.0)
        payload_size = float(enriched.get("payload_size", 0))
        failed_logins = float(enriched.get("failed_logins", 0))
        request_rate = float(enriched.get("request_rate", 0))
        dst_port = int(enriched.get("dst_port", 0))
        touch_count = float(enriched.get("touch_count", 0))
        event_type = str(enriched.get("event_type", "")).lower()

        service_risk_map = {
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

        enriched.setdefault("bytes_per_ms", round(packet_size / duration_ms, 4))
        enriched.setdefault("payload_ratio", round(min(payload_size / max(packet_size, 1.0), 1.5), 4))
        enriched.setdefault("auth_density", round(failed_logins / max(request_rate, 1.0), 4))
        enriched.setdefault("privileged_dst", 1 if dst_port in {21, 22, 23, 25, 445, 1883, 3389} else 0)
        enriched.setdefault("is_tamper_event", 1 if event_type == "tamper" else 0)
        enriched.setdefault("request_burst", 1 if request_rate >= 90 else 0)
        enriched.setdefault("service_risk", round(service_risk_map.get(dst_port, 0.12), 3))
        enriched.setdefault("touch_intensity", round(touch_count / 3.0, 3))
        enriched.setdefault("dwell_score", round(duration_ms / max(request_rate, 1.0), 4))
        enriched.setdefault("mesh_signal", 1 if event_type == "mesh_alert" else 0)
        return enriched

    def _extract_features(self, event: Dict[str, Any]) -> List[List[float]]:
        enriched = self._enrich_event(event)
        return [[float(enriched.get(name, 0)) for name in self.feature_names]]

    def _heuristic_analysis(self, event: Dict[str, Any]) -> ThreatAnalysis:
        reasons = []
        score = 0.08

        event_type = str(event.get("event_type", "")).lower()
        request_rate = float(event.get("request_rate", 0))
        failed_logins = float(event.get("failed_logins", 0))
        touch_count = float(event.get("touch_count", 0))
        dst_port = int(event.get("dst_port", 0))

        if event_type == "tamper":
            score += 0.56
            reasons.append("Physical tamper signal detected")

        if failed_logins >= 6:
            score += 0.18
            reasons.append("Repeated login failures")
        elif failed_logins >= 3:
            score += 0.08

        if request_rate >= 140:
            score += 0.16
            reasons.append("Unusually high request rate")
        elif request_rate >= 85:
            score += 0.07

        if dst_port in {22, 23, 3389, 445}:
            score += 0.08
            reasons.append("Sensitive target port touched")
        elif dst_port == 1883:
            score += 0.03

        if touch_count >= 1:
            score += 0.08

        if event_type in {"heartbeat", "status"} and request_rate <= 18 and failed_logins == 0 and touch_count == 0:
            score = min(score, 0.18)
            reasons = [reason for reason in reasons if reason != "Unusually high request rate"]

        score = min(score, 0.99)
        label = "critical" if score >= 0.82 else "high" if score >= 0.62 else "medium" if score >= 0.38 else "low"
        return ThreatAnalysis(label=label, confidence=score, anomaly_score=score, reasons=reasons or ["Baseline heuristic evaluation"])

    def analyze(self, event: Dict[str, Any]) -> Dict[str, Any]:
        heuristic = self._heuristic_analysis(event)
        if self.pipeline is None:
            return heuristic.__dict__

        try:
            features = self._extract_features(event)
            anomaly_raw = float(self.pipeline.decision_function(features)[0])
            anomaly_score = max(0.0, min(1.0, 0.5 + (-anomaly_raw)))

            attack_probability = 0.0
            if self.attack_classifier is not None:
                attack_probability = float(self.attack_classifier.predict_proba(features)[0][1])

            blended_signal = 0.62 * attack_probability + 0.38 * anomaly_score
            event_type = str(event.get("event_type", "")).lower()
            request_rate = float(event.get("request_rate", 0))
            failed_logins = float(event.get("failed_logins", 0))
            touch_count = float(event.get("touch_count", 0))
            dst_port = int(event.get("dst_port", 0))

            actor_type = "unknown"
            actor_probability = 0.0
            if self.actor_classifier is not None and blended_signal >= self.hybrid_threshold:
                actor_distribution = self.actor_classifier.predict_proba(features)[0]
                actor_index = int(actor_distribution.argmax())
                actor_probability = float(actor_distribution[actor_index])
                if actor_index < len(self.actor_labels):
                    actor_type = self.actor_labels[actor_index]

            reasons = []
            if self.attack_classifier is not None:
                reasons.append("Supervised attack detector")
            reasons.append("Isolation Forest anomaly detection")
            if blended_signal >= self.hybrid_threshold or anomaly_score >= 0.75:
                reasons.append("Traffic pattern deviates from normal baseline")
            if actor_type != "unknown":
                reasons.append(f"Actor profile: {actor_type}")
            reasons.extend(reason for reason in heuristic.reasons if reason not in reasons)

            # Conservative downgrade path for clearly normal device chatter.
            likely_benign = (
                event_type in {"heartbeat", "status"}
                and request_rate <= 20
                and failed_logins == 0
                and touch_count == 0
                and dst_port in {1883, 443, 8080}
            )
            if likely_benign and blended_signal < 0.45 and anomaly_score < 0.55:
                return {
                    "label": "low",
                    "confidence": round(max(0.18, blended_signal), 3),
                    "anomaly_score": round(anomaly_score, 3),
                    "reasons": ["Normal service heartbeat", *[r for r in reasons if r != "Traffic pattern deviates from normal baseline"]],
                    "actor_type": "benign",
                    "actor_confidence": 0.82,
                }

            if event_type == "tamper" and (touch_count >= 1 or failed_logins >= 5):
                label = "critical"
            elif blended_signal >= 0.82 or anomaly_score >= 0.90:
                label = "critical"
            elif blended_signal >= 0.64 or anomaly_score >= 0.78:
                label = "high"
            elif blended_signal >= self.hybrid_threshold or anomaly_score >= 0.66:
                label = "medium"
            else:
                label = "low"

            # Keep benign-looking network chatter from jumping straight to critical.
            if label in {"critical", "high"} and event_type == "network" and touch_count == 0 and failed_logins <= 1 and request_rate <= 35 and dst_port in {1883, 443, 8080}:
                label = "low" if blended_signal < 0.55 else "medium"

            return {
                "label": label,
                "confidence": round(max(blended_signal, heuristic.confidence * 0.75), 3),
                "anomaly_score": round(max(anomaly_score, attack_probability), 3),
                "reasons": reasons,
                "actor_type": actor_type,
                "actor_confidence": round(actor_probability, 3),
            }
        except Exception:
            return heuristic.__dict__
