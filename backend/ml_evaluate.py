"""Leakage-aware, reproducible binary evaluation for the optional Isolation Forest.

Input CSV must contain the five versioned flow features, a label column, and a
capture/session group column. Groups are split as indivisible units so related
flows cannot appear in both training and test sets.
"""
from __future__ import annotations

import argparse
import csv
import json
import math
import random
import sys
import time
from pathlib import Path
from statistics import mean

from ml_anomaly import FEATURES
from ml_isolation_forest import train_model, score_observation


def load_labeled_rows(path: str | Path, label_column: str, group_column: str,
                      benign_label: str) -> list[dict]:
    """Read and validate labeled flow rows without silently dropping bad data."""
    with open(path, newline="", encoding="utf-8-sig") as handle:
        reader = csv.DictReader(handle)
        headers = reader.fieldnames or []
        required = set(FEATURES) | {label_column, group_column}
        missing = sorted(required - set(headers))
        if missing:
            raise ValueError("CSV is missing required columns: " + ", ".join(missing))
        if len(headers) != len(set(headers)):
            raise ValueError("CSV contains duplicate column names")
        rows = []
        for line_number, row in enumerate(reader, start=2):
            if None in row:
                raise ValueError(f"CSV line {line_number} has more values than the header")
            label = row.get(label_column)
            group = row.get(group_column)
            if not isinstance(label, str) or not label.strip():
                raise ValueError(f"CSV line {line_number} has an empty label")
            if not isinstance(group, str) or not group.strip():
                raise ValueError(f"CSV line {line_number} has an empty group identifier")
            normalized_label = "benign" if label.strip().casefold() == benign_label.casefold() else "malicious"
            features = {}
            for name in FEATURES:
                value = row.get(name)
                try:
                    number = float(value)
                except (TypeError, ValueError) as error:
                    raise ValueError(f"CSV line {line_number}: {name} must be numeric") from error
                if not math.isfinite(number) or number < 0:
                    raise ValueError(f"CSV line {line_number}: {name} must be finite and non-negative")
                features[name] = number
            rows.append({"features": features, "label": normalized_label, "group": group.strip()})
    if not rows:
        raise ValueError("CSV contains no labeled observations")
    labels = {row["label"] for row in rows}
    if labels != {"benign", "malicious"}:
        raise ValueError("CSV must contain both benign and malicious observations")
    return rows


def split_by_group(rows: list[dict], test_fraction: float = 0.25,
                   seed: int = 42, attempts: int = 2000) -> tuple[list[dict], list[dict]]:
    """Find a deterministic group-disjoint split with both classes on each side."""
    if not 0.1 <= float(test_fraction) <= 0.5:
        raise ValueError("test_fraction must be between 0.10 and 0.50")
    groups: dict[str, list[dict]] = {}
    for row in rows:
        groups.setdefault(row["group"], []).append(row)
    group_names = list(groups)
    if len(group_names) < 4:
        raise ValueError("At least four distinct capture/session groups are required for a holdout split")
    target = max(1, min(len(group_names) - 1, round(len(group_names) * test_fraction)))
    rng = random.Random(seed)
    for _ in range(attempts):
        shuffled = group_names[:]
        rng.shuffle(shuffled)
        test_groups = set(shuffled[:target])
        train = [row for row in rows if row["group"] not in test_groups]
        test = [row for row in rows if row["group"] in test_groups]
        if len(train) < 50:
            continue
        if sum(row["label"] == "benign" for row in train) < 50:
            continue
        if {row["label"] for row in train} == {"benign", "malicious"} and {row["label"] for row in test} == {"benign", "malicious"}:
            if {row["group"] for row in train}.isdisjoint({row["group"] for row in test}):
                return train, test
    raise ValueError(
        "Unable to create a valid group-disjoint split with both classes in train/test "
        "and at least 50 benign training rows. Add more independent capture/session groups."
    )


def _metrics(actual: list[str], predicted: list[str]) -> dict:
    tp = sum(a == "malicious" and p == "malicious" for a, p in zip(actual, predicted))
    tn = sum(a == "benign" and p == "benign" for a, p in zip(actual, predicted))
    fp = sum(a == "benign" and p == "malicious" for a, p in zip(actual, predicted))
    fn = sum(a == "malicious" and p == "benign" for a, p in zip(actual, predicted))
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    specificity = tn / (tn + fp) if tn + fp else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    total = tp + tn + fp + fn
    return {
        "accuracy": (tp + tn) / total if total else 0.0,
        "precision_malicious": precision,
        "recall_malicious": recall,
        "f1_malicious": f1,
        "specificity_benign": specificity,
        "false_positive_rate": fp / (fp + tn) if fp + tn else 0.0,
        "false_negative_rate": fn / (fn + tp) if fn + tp else 0.0,
        "balanced_accuracy": (recall + specificity) / 2,
        "confusion_matrix": {
            "labels": ["benign", "malicious"],
            "rows_actual_columns_predicted": [[tn, fp], [fn, tp]],
        },
        "counts": {"true_positive": tp, "true_negative": tn, "false_positive": fp, "false_negative": fn},
    }


def evaluate_rows(rows: list[dict], *, test_fraction: float = 0.25, seed: int = 42,
                  contamination: float = 0.03, n_estimators: int = 200) -> dict:
    """Train only on benign training groups and evaluate once on held-out groups."""
    train, test = split_by_group(rows, test_fraction, seed)
    train_benign = [row["features"] for row in train if row["label"] == "benign"]
    if len(train_benign) < 50:
        raise ValueError("At least 50 benign training observations are required")
    model = train_model(train_benign, contamination=contamination, n_estimators=n_estimators)
    actual = [row["label"] for row in test]
    predicted = []
    latencies_ms = []
    for row in test:
        started = time.perf_counter_ns()
        result = score_observation(row["features"], model)
        latencies_ms.append((time.perf_counter_ns() - started) / 1_000_000)
        predicted.append("malicious" if result["anomalous"] else "benign")
    sorted_latency = sorted(latencies_ms)
    p95_index = max(0, math.ceil(0.95 * len(sorted_latency)) - 1)
    return {
        "schema_version": 1,
        "model": "IsolationForest",
        "split": {
            "method": "deterministic_group_holdout",
            "seed": seed,
            "test_fraction_target": test_fraction,
            "train_groups": len({row["group"] for row in train}),
            "test_groups": len({row["group"] for row in test}),
            "group_overlap": 0,
            "train_rows": len(train),
            "test_rows": len(test),
            "train_benign_rows": len(train_benign),
            "test_benign_rows": sum(label == "benign" for label in actual),
            "test_malicious_rows": sum(label == "malicious" for label in actual),
        },
        "training": {
            "trained_only_on": "benign",
            "contamination": float(contamination),
            "n_estimators": n_estimators,
            "random_state": 42,
            "features": list(FEATURES),
        },
        "metrics": _metrics(actual, predicted),
        "inference_latency_ms": {
            "mean_per_observation": mean(latencies_ms) if latencies_ms else 0.0,
            "p95_per_observation": sorted_latency[p95_index] if sorted_latency else 0.0,
            "observations_timed": len(latencies_ms),
            "measurement": "single-process wall-clock; includes Python scoring wrapper",
        },
        "limitations": [
            "Anomaly detection is not a calibrated probability or proof of compromise.",
            "Results depend on the dataset labels, feature definitions, capture grouping, and contamination setting.",
            "Use independent capture/session groups and review false positives before operational use.",
            "This report does not establish production readiness or cross-dataset generalization.",
        ],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Evaluate CyberGuard Isolation Forest using capture/session-disjoint CSV holdout"
    )
    parser.add_argument("csv_file", help="Labeled flow CSV; never commit private datasets")
    parser.add_argument("--label-column", default="label")
    parser.add_argument("--group-column", default="capture_id",
                        help="Capture/session identifier used to prevent train/test leakage")
    parser.add_argument("--benign-label", default="benign")
    parser.add_argument("--test-fraction", type=float, default=0.25)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--contamination", type=float, default=0.03)
    parser.add_argument("--estimators", type=int, default=200)
    parser.add_argument("--output", default="reports/isolation-forest-evaluation.json")
    args = parser.parse_args(argv)
    try:
        rows = load_labeled_rows(args.csv_file, args.label_column, args.group_column, args.benign_label)
        report = evaluate_rows(rows, test_fraction=args.test_fraction, seed=args.seed,
                               contamination=args.contamination, n_estimators=args.estimators)
        target = Path(args.output)
        target.parent.mkdir(parents=True, exist_ok=True)
        temporary = target.with_name(target.name + ".tmp")
        temporary.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        temporary.replace(target)
        print(json.dumps({"report": str(target), "metrics": report["metrics"],
                          "split": report["split"]}, indent=2))
        return 0
    except (OSError, ValueError, ImportError) as error:
        print(f"Evaluation failed: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
