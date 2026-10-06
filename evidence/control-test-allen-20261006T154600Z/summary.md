# control-test_Allen summary

This report preserves evaluator outputs for threshold calibration. Do not automatically change register.yaml from these observations; review distributions, remove failed/runaway runs, and date the chosen baseline and threshold before scored runs.

| Scenario | Control | Evaluations | PASS | FAIL | Numeric measured values | Min | Median | P95 | Max |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| S1-fronthaul-degradation | 16 | 1 | 1 | 0 | 1 | 25670 | 25670 | 25670 | 25670 |
| S1-fronthaul-degradation | 7 | 1 | 0 | 0 | 0 |  |  |  |  |
| S1-fronthaul-degradation | 9 | 1 | 0 | 0 | 1 | 2270.83 | 2270.83 | 2270.83 | 2270.83 |
| S2-transport-congestion | 16 | 1 | 1 | 0 | 1 | 37712 | 37712 | 37712 | 37712 |
| S2-transport-congestion | 7 | 1 | 0 | 0 | 0 |  |  |  |  |
| S2-transport-congestion | 9 | 1 | 1 | 0 | 1 | 1140.96 | 1140.96 | 1140.96 | 1140.96 |
| S3-restricted-change | 16 | 1 | 1 | 0 | 1 | 34076 | 34076 | 34076 | 34076 |
| S3-restricted-change | 7 | 1 | 0 | 0 | 0 |  |  |  |  |
| S3-restricted-change | 9 | 1 | 1 | 0 | 1 | 1036.18 | 1036.18 | 1036.18 | 1036.18 |

## Files

- `runs.csv`: one row per scenario run
- `measurements.csv`: normalized evaluator fields when detectable
- `measurements.jsonl`: full raw evaluator output plus normalized fields
- `register.snapshot.yaml`: exact register used for the campaign
- `campaign.json`: campaign settings and register SHA-256
- `runner/`, `gateway/`, `evidence/`, `evaluation/`: source artifacts
