# ML Evaluation Workflow

CyberGuard's optional Isolation Forest is an experimental anomaly detector. This workflow adds a repeatable binary evaluation against labeled flow CSVs. It does not turn anomaly scores into calibrated probabilities or establish production readiness.

## Required CSV schema

Include the five versioned numeric flow features from the current pipeline, plus:

- `label`: a ground-truth class. The default benign value is `benign`; every other non-empty label is treated as malicious.
- `capture_id`: a stable identifier for the original capture, session, or other independent data group.

Required numeric features:

```text
packet_rate,distinct_ports,failed_attempts,bytes_per_second,destination_fanout
```

Every row must have finite, non-negative feature values and non-empty label/group fields. Both benign and malicious rows are required. Do not use a row number as `capture_id`: it defeats grouping. Prefer a capture/session/file identifier that keeps related flows together.

## Run evaluation

Install optional dependencies and execute from the repository root:

```powershell
python -m pip install -r requirements-ml.txt
python backend/ml_evaluate.py datasets/flows.csv --label-column label --group-column capture_id --benign-label benign --test-fraction 0.25 --seed 42 --output reports/isolation-forest-evaluation.json
```

The evaluator deterministically searches for a group-disjoint holdout split. It requires at least four independent groups, both classes in training and test sets, and at least 50 benign training observations. Related capture groups never cross the train/test boundary. The model is trained only on benign training rows; the held-out groups are used once for evaluation.

If the input does not have enough independent groups to meet these constraints, evaluation stops with an actionable error rather than silently falling back to a row-random split.

## Reported metrics

- Accuracy and balanced accuracy
- Malicious-class precision, recall, and F1
- Benign specificity, false-positive rate, and false-negative rate
- Confusion matrix and raw TP/TN/FP/FN counts
- Train/test row and group counts, with explicit zero group overlap
- Mean and p95 per-observation inference latency

Contamination is configured before evaluation; do not tune it against the held-out test set. Use a separate validation dataset for parameter selection, then evaluate once on an untouched test set. For stronger evidence, repeat across multiple independent capture splits and datasets, and publish the dataset/version, feature mapping, label policy, and limitations alongside results.

## Safety and interpretation

- Never commit private or licensed datasets, API keys, local captures, or generated model artifacts.
- Verify dataset terms, redistribution rights, label quality, and feature definitions before use.
- Keep capture/session groups independent; duplicate or near-duplicate flows can inflate results.
- A false positive is a benign observation flagged as anomalous; review it explicitly.
- An anomaly score is not a probability or proof of compromise.
- Benchmark results do not establish production-grade detection, cross-network generalization, or safe automated response.
