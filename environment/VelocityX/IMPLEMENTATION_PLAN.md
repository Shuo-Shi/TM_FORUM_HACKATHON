# IMPLEMENTATION_PLAN_FOR_CODING_AGENT.md

# Trustworthy AI Hackathon - Step-by-Step Implementation Guide

Version: G-FM-v1
Approach: CLI First
Priority: Control 16 -> Control 7 -> Control 9

---

# Mission

Build a CLI-based governance platform capable of answering:

```bash
controltest check <CONTROL_ID> --run <RUN_ID>
```

and producing:

- PASS
- BREACH
- INCOMPLETE

with evidence.

---

# Phase 0 - Environment Validation

## Goal

Verify workshop environment is operational.

## Tasks

### Task 0.1

Verify agent configs.

```bash
kubectl get agentconfigs -n components
```

Expected:

- customer agent
- triage agent
- investigation agent

### Task 0.2

Verify model approved.

```bash
kubectl get modelconfig nemotron-nano-9b   -n components   -o jsonpath='{.status.phase}'
```

Expected:

```text
Approved
```

### Task 0.3

Verify gateway logs available.

```bash
kubectl logs deploy/modaas-agw   -n agentgateway-system   --since=5m
```

Deliverable:

```text
ENVIRONMENT_READY.md
```

---

# Phase 1 - Repository Setup

Create:

```text
hackathon/
│
├── register.yaml
├── controltest.py
├── evidence/
├── findings/
├── controls/
│   ├── control7.py
│   ├── control9.py
│   └── control16.py
│
└── docs/
```

---

# Phase 2 - Threshold Register

## Goal

Externalize ALL thresholds.

Never hardcode thresholds.

Create:

```yaml
controls:
  - control_id: "7"
    name: "Event Recording"
    observation_limit: 100
    exception_tolerance: 5
    version: "G-FM-v1"

  - control_id: "9"
    name: "Drift"
    baseline: 0.90
    observation_limit: 10
    exception_tolerance: 0
    version: "G-FM-v1"

  - control_id: "16"
    name: "Token Spend"
    observation_limit: 900
    exception_tolerance: 0
    version: "G-FM-v1"
```

Deliverable:

```text
register.yaml
```

---

# Phase 3 - Common Framework

## Goal

Build common evaluator.

File:

```text
controltest.py
```

CLI:

```bash
controltest check 16 --run fault-123
controltest check 7 --run fault-123
controltest check 9 --window window-1
```

Responsibilities:

1. Read register.yaml
2. Load evidence
3. Route to control evaluator
4. Return verdict

---

# Phase 4 - Control 16

## Priority 1

This is the easiest control.

## Data Source

Gateway logs.

Command:

```bash
kubectl -n agentgateway-system logs deploy/modaas-agw   --since=24h
```

## Evidence Puller

Create:

```text
controls/control16.py
```

Functions:

```python
collect_evidence(run_id)
calculate_tokens(records)
evaluate()
```

## Logic

For each call:

```text
input_tokens
output_tokens
```

Compute:

```text
total_tokens
```

Compare against:

```text
900
```

## PASS Example

```text
778 tokens
limit=900
PASS
```

## BREACH Example

```text
1030 tokens
limit=900
BREACH
```

## Deliverables

```text
evidence/control16/
pass_run.json
breach_run.json
```

---

# Phase 5 - Control 7

## Priority 2

Event recording.

## Goal

Verify all expected events exist.

## Event Catalog

Create:

```json
[
  "run_start",
  "chat_agent",
  "triage_agent",
  "investigation_agent",
  "run_complete"
]
```

## Evaluation

Expected Events:

```text
5
```

Observed:

```text
5
```

Coverage:

```text
100%
```

## PASS

```text
coverage=100%
PASS
```

## BREACH

Missing event.

```text
coverage=80%
BREACH
```

## Deliverables

```text
controls/control7.py
```

---

# Phase 6 - Control 9

## Priority 3

Drift control.

## Baseline

Freeze:

```text
0.90
```

## Formula

```text
(baseline-current)/baseline * 100
```

## PASS

```text
baseline=0.90
current=0.85
relative_drop=5.5%
PASS
```

## BREACH

```text
baseline=0.90
current=0.79
relative_drop=12%
BREACH
```

## Deliverables

```text
controls/control9.py
```

---

# Phase 7 - Evidence Layer

Create schema:

```json
{
  "control_id":"",
  "threshold_version":"",
  "run_id":"",
  "evidence_id":"",
  "measured_value":"",
  "verdict":""
}
```

Store:

```text
evidence/
```

---

# Phase 8 - Findings

Folder:

```text
findings/
```

Format:

```json
{
  "finding_id":"F-001",
  "control_id":"16",
  "run_id":"fault-123",
  "status":"OPEN"
}
```

---

# Phase 9 - Adversarial Testing

## Control 16

Force token overflow.

Expected:

```text
BREACH
```

## Control 7

Delete event.

Expected:

```text
BREACH
```

## Control 9

Inject drift.

Expected:

```text
BREACH
```

---

# Phase 10 - Judge Demo

Run:

```bash
controltest check 16 --run fault-123
```

Output:

```text
CONTROL: 16
RUN: fault-123
VERSION: G-FM-v1
LIMIT: 900
MEASURED: 1030
VERDICT: BREACH
```

Repeat for:

```bash
controltest check 7 --run fault-123
controltest check 9 --window W10
```

---

# Success Criteria

Mandatory:

- Control 16 Complete
- Control 7 Complete
- Control 9 Complete
- register.yaml exists
- PASS run exists
- BREACH run exists
- evidence export exists
- CLI works

Bonus:

- inline evaluation
- second enforcement point
- ServiceNow findings
- adversarial automation

# IMPORTANT

No UI work until all three controls are producing PASS and BREACH evidence via CLI.
