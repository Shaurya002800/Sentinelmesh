from __future__ import annotations

import csv
from pathlib import Path
from statistics import mean
from typing import Dict, List, Tuple

import joblib
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

BASE_DIR = Path(__file__).resolve().parent
DATA_PATH = BASE_DIR / "data" / "normal_traffic.csv"
OUTPUT_PATH = BASE_DIR.parent / "backend" / "models" / "isolation_forest.pkl"
REPORT_PATH = BASE_DIR / "data" / "training_report.txt"
FEATURE_NAMES = [
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
ACTOR_LABELS = ["benign", "bot", "human", "apt"]
ACTOR_TO_ID = {label: index for index, label in enumerate(ACTOR_LABELS)}



def load_rows(data_path: Path) -> List[Dict[str, str]]:
    with data_path.open() as csvfile:
        return list(csv.DictReader(csvfile))



def split_features(rows: List[Dict[str, str]]) -> Tuple[List[List[float]], List[int], List[int], List[str]]:
    features: List[List[float]] = []
    attack_labels: List[int] = []
    actor_labels: List[int] = []
    scenarios: List[str] = []
    for row in rows:
        features.append([float(row[name]) for name in FEATURE_NAMES])
        attack_labels.append(1 if row["label"] == "attack" else 0)
        actor_labels.append(ACTOR_TO_ID[row["actor_type"]])
        scenarios.append(row["scenario"])
    return features, attack_labels, actor_labels, scenarios



def build_anomaly_pipeline(contamination: float) -> Pipeline:
    return Pipeline([
        ("scaler", StandardScaler()),
        ("model", IsolationForest(
            n_estimators=320,
            contamination=contamination,
            random_state=42,
            max_samples="auto",
        )),
    ])



def build_attack_classifier() -> RandomForestClassifier:
    return RandomForestClassifier(
        n_estimators=420,
        max_depth=18,
        min_samples_leaf=2,
        class_weight="balanced_subsample",
        random_state=42,
        n_jobs=-1,
    )



def build_actor_classifier() -> RandomForestClassifier:
    return RandomForestClassifier(
        n_estimators=360,
        max_depth=14,
        min_samples_leaf=2,
        class_weight="balanced_subsample",
        random_state=42,
        n_jobs=-1,
    )



def hybrid_predictions(
    attack_classifier: RandomForestClassifier,
    anomaly_pipeline: Pipeline,
    features: List[List[float]],
    hybrid_threshold: float,
) -> Tuple[List[int], List[float], List[float], List[float]]:
    class_probabilities = attack_classifier.predict_proba(features)
    attack_probabilities = [row[1] for row in class_probabilities]
    anomaly_scores = [max(0.0, min(1.0, 0.5 + (-score))) for score in anomaly_pipeline.decision_function(features)]

    blended_scores = []
    predictions = []
    for attack_prob, anomaly_score in zip(attack_probabilities, anomaly_scores):
        blended = 0.62 * attack_prob + 0.38 * anomaly_score
        blended_scores.append(blended)
        predictions.append(1 if blended >= hybrid_threshold else 0)

    return predictions, attack_probabilities, anomaly_scores, blended_scores



def write_report(report_text: str) -> None:
    REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    REPORT_PATH.write_text(report_text, encoding="utf-8")


if __name__ == "__main__":
    rows = load_rows(DATA_PATH)
    features, attack_labels, actor_labels, scenarios = split_features(rows)
    contamination = max(0.04, min(0.30, (sum(attack_labels) / len(attack_labels)) * 0.75))
    hybrid_threshold = 0.56

    (
        x_train,
        x_test,
        y_attack_train,
        y_attack_test,
        y_actor_train,
        y_actor_test,
    ) = train_test_split(
        features,
        attack_labels,
        actor_labels,
        test_size=0.25,
        random_state=42,
        stratify=attack_labels,
    )

    normal_train = [row for row, label in zip(x_train, y_attack_train) if label == 0]
    attack_train = [row for row, label in zip(x_train, y_attack_train) if label == 1]
    attack_actor_train = [label for label, attack_label in zip(y_actor_train, y_attack_train) if attack_label == 1]

    anomaly_pipeline = build_anomaly_pipeline(contamination=contamination)
    anomaly_pipeline.fit(normal_train)

    attack_classifier = build_attack_classifier()
    attack_classifier.fit(x_train, y_attack_train)

    actor_classifier = build_actor_classifier()
    actor_classifier.fit(attack_train, attack_actor_train)

    predictions, attack_probabilities, anomaly_scores, blended_scores = hybrid_predictions(
        attack_classifier,
        anomaly_pipeline,
        x_test,
        hybrid_threshold,
    )

    attack_report = classification_report(y_attack_test, predictions, target_names=["normal", "attack"], digits=3)
    attack_matrix = confusion_matrix(y_attack_test, predictions)

    attack_only_test = [row for row, label in zip(x_test, y_attack_test) if label == 1]
    attack_only_actor_test = [label for label, attack_label in zip(y_actor_test, y_attack_test) if attack_label == 1]
    actor_predictions = actor_classifier.predict(attack_only_test)
    actor_report = classification_report(
        attack_only_actor_test,
        actor_predictions,
        labels=[1, 2, 3],
        target_names=["bot", "human", "apt"],
        digits=3,
        zero_division=0,
    )

    report_lines = [
        "SentinelMesh Training Report",
        "==========================",
        f"Rows: {len(rows)}",
        f"Train rows: {len(x_train)}",
        f"Test rows: {len(x_test)}",
        f"Contamination: {contamination:.3f}",
        f"Hybrid threshold: {hybrid_threshold:.2f}",
        "",
        "Binary Attack Detection",
        "-----------------------",
        str(attack_matrix),
        attack_report,
        "",
        "Actor Classification (attack rows only)",
        "--------------------------------------",
        actor_report,
        "",
        f"Average normal blended score: {mean(score for score, label in zip(blended_scores, y_attack_test) if label == 0):.4f}",
        f"Average attack blended score: {mean(score for score, label in zip(blended_scores, y_attack_test) if label == 1):.4f}",
        f"Average normal anomaly score: {mean(score for score, label in zip(anomaly_scores, y_attack_test) if label == 0):.4f}",
        f"Average attack anomaly score: {mean(score for score, label in zip(anomaly_scores, y_attack_test) if label == 1):.4f}",
        f"Average normal attack probability: {mean(score for score, label in zip(attack_probabilities, y_attack_test) if label == 0):.4f}",
        f"Average attack probability: {mean(score for score, label in zip(attack_probabilities, y_attack_test) if label == 1):.4f}",
    ]
    report_text = "\n".join(report_lines)
    write_report(report_text)

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    artifact = {
        "attack_classifier": attack_classifier,
        "anomaly_pipeline": anomaly_pipeline,
        "actor_classifier": actor_classifier,
        "feature_names": FEATURE_NAMES,
        "contamination": contamination,
        "hybrid_threshold": hybrid_threshold,
        "actor_labels": ACTOR_LABELS,
        "version": "sentinelmesh-hybrid-v3",
    }
    joblib.dump(artifact, OUTPUT_PATH)

    print(f"Trained model saved to {OUTPUT_PATH}")
    print(f"Report saved to {REPORT_PATH}")
    print(report_text)
