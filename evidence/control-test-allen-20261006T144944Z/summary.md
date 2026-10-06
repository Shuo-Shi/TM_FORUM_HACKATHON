# control-test_Allen summary

This report preserves evaluator outputs for threshold calibration. Do not automatically change register.yaml from these observations; review distributions, remove failed/runaway runs, and date the chosen baseline and threshold before scored runs.

| Scenario | Control | Evaluations | PASS | FAIL | Numeric measured values | Min | Median | P95 | Max |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| S1-fronthaul-degradation | 16 | 1 | 1 | 0 | 1 | 25306 | 25306 | 25306 | 25306 |
| S1-fronthaul-degradation | 7 | 1 | 0 | 0 | 0 |  |  |  |  |
| S1-fronthaul-degradation | 9 | 1 | 0 | 0 | 1 | 2194.89 | 2194.89 | 2194.89 | 2194.89 |
| S2-transport-congestion | 16 | 1 | 0 | 0 | 1 | 1.67916e+06 | 1.67916e+06 | 1.67916e+06 | 1.67916e+06 |
| S2-transport-congestion | 7 | 1 | 0 | 0 | 0 |  |  |  |  |
| S2-transport-congestion | 9 | 1 | 1 | 0 | 1 | 1221.39 | 1221.39 | 1221.39 | 1221.39 |

## Files

- `runs.csv`: one row per scenario run
- `measurements.csv`: normalized evaluator fields when detectable
- `measurements.jsonl`: full raw evaluator output plus normalized fields
- `register.snapshot.yaml`: exact register used for the campaign
- `campaign.json`: campaign settings and register SHA-256
- `runner/`, `gateway/`, `evidence/`, `evaluation/`: source artifacts
