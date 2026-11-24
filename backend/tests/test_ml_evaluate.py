import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ml_anomaly import FEATURES
from ml_evaluate import evaluate_rows, load_labeled_rows, split_by_group


def fixture_rows(group_count=12):
    rows = []
    for group_index in range(group_count):
        label = "benign" if group_index % 2 == 0 else "malicious"
        for sample in range(12):
            base = 10 + (sample % 4) * 0.1
            features = {name: base for name in FEATURES}
            if label == "malicious":
                features["packet_rate"] = 100 + sample
                features["distinct_ports"] = 80
            rows.append({"features": features, "label": label, "group": f"capture-{group_index}"})
    return rows


class EvaluationTests(unittest.TestCase):
    def test_group_split_has_no_overlap_and_both_classes(self):
        train, test = split_by_group(fixture_rows())
        self.assertTrue({r["group"] for r in train}.isdisjoint({r["group"] for r in test}))
        self.assertEqual({r["label"] for r in train}, {"benign", "malicious"})
        self.assertEqual({r["label"] for r in test}, {"benign", "malicious"})

    def test_evaluation_reports_security_metrics_and_latency(self):
        report = evaluate_rows(fixture_rows(), seed=13)
        self.assertEqual(report["split"]["group_overlap"], 0)
        self.assertIn("false_positive_rate", report["metrics"])
        self.assertIn("false_negative_rate", report["metrics"])
        self.assertIn("p95_per_observation", report["inference_latency_ms"])
        self.assertEqual(report["training"]["trained_only_on"], "benign")

    def test_rejects_too_few_groups(self):
        with self.assertRaises(ValueError):
            split_by_group(fixture_rows(group_count=3))

    def test_rejects_invalid_test_fraction(self):
        with self.assertRaises(ValueError):
            split_by_group(fixture_rows(), test_fraction=0.05)

    def test_csv_requires_capture_group_and_both_labels(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "flows.csv"
            columns = list(FEATURES) + ["label"]
            path.write_text(",".join(columns) + "\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "capture_id"):
                load_labeled_rows(path, "label", "capture_id", "benign")

    def test_csv_validates_rows_and_maps_non_benign_to_malicious(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "flows.csv"
            columns = list(FEATURES) + ["label", "capture_id"]
            rows = []
            for index, label in enumerate(["benign", "attack"]):
                values = ["10"] * len(FEATURES) + [label, f"capture-{index}"]
                rows.append(",".join(values))
            path.write_text(",".join(columns) + "\n" + "\n".join(rows) + "\n", encoding="utf-8")
            loaded = load_labeled_rows(path, "label", "capture_id", "benign")
            self.assertEqual([row["label"] for row in loaded], ["benign", "malicious"])


if __name__ == "__main__":
    unittest.main()
