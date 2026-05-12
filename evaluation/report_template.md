# ThreatScope Evaluation Report

Use this system only in controlled lab environments with synthetic traffic or traffic you are authorized to collect.

## Detection Metrics

| Scenario | TP | FP | TN | FN | Detection Rate / Recall | Precision | F1 | Accuracy |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| Brute force |  |  |  |  |  |  |  |  |
| Port scan |  |  |  |  |  |  |  |  |
| Credential stuffing |  |  |  |  |  |  |  |  |
| Injection |  |  |  |  |  |  |  |  |
| Mixed traffic |  |  |  |  |  |  |  |  |

## False Positive Rate

| Normal Traffic Count | False Positives | FPR Target | Actual FPR | Pass |
|---:|---:|---:|---:|---|
|  |  | < 5% |  |  |

## Risk Score Separation

| Traffic Class | Mean Risk | Median Risk | Min | Max |
|---|---:|---:|---:|---:|
| Normal |  |  |  |  |
| Suspicious |  |  |  |  |
| Attacker |  |  |  |  |

Risk separation target: Mean(attacker) - Mean(normal) > 50 points.

## Performance

| Concurrent Clients | Events/sec | Avg Latency | p95 Latency | p99 Latency | Error Rate |
|---:|---:|---:|---:|---:|---:|
| 50 |  |  |  |  |  |
| 100 |  |  |  |  |  |
| 500 |  |  |  |  |  |
