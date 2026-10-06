<!-- Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved. -->
<!-- SPDX-License-Identifier: MIT-0 -->
# Gap list

The challenge brief scores this file ("What to bring to judging", item 6):
*"what you could not close, and why. This is scored, and it scores well: one
honest failure beats a wall of green ticks."*

Delete this template text and write your own. One entry per gap — a control
you did not finish, an auditor question you can only partially answer, an
evidence surface you could not reach, a decision you made under time
pressure that a real deployment would need to revisit.

## Format

For each gap:

```
### <short title>

**What's missing:** one sentence.
**Why:** what actually stopped you — a platform limit, a time-box, a design
choice you'd reconsider. Be specific; "ran out of time" is fine if it's true,
but say what you would have done with more of it.
**Impact:** what an auditor cannot do because of this gap.
**If you had one more day:** the concrete next step.
```

## Example (delete before submitting)

### Control 9 (drift) has no frozen baseline yet

**What's missing:** `evaluate.py` has no metric function for control 9; the
register entry is still a placeholder.
**Why:** the diagnostic-quality measure we picked (disposition-match-rate
against `score-run.py`'s expected disposition) needs at least three
baseline runs to freeze a number against, and we spent our first two hours
on control 16 instead.
**Impact:** a judge asking "is control 9 satisfied for this run" gets no
verdict, only the raw disposition.
**If you had one more day:** run the three baseline scenarios, freeze the
match-rate as the threshold, and wire `_control_9_drift` into
`evaluate.py`'s `_METRICS` table the same way control 16 is wired.
- G-7-v1 / G-9-v1 metric text corrected 2026-10-05 to match evaluator logic, before any assessed run. Thresholds unchanged.
- Control 7 does not require a ledger record per gateway llm call: agents write 3 invocation records but make 5-11 model calls. Per-call ledger coverage is an open gap.
- F-01 correction (2026-10-05): negotiation NOT fixed. score-run.py fails "cross-domain negotiation recorded" on S1 fault-1791233498-502f40 and S3 fault-1791233553-bc1dec. Our control 7 keyword check was looser than the grader and passed it; evaluator to be aligned. OPEN
- Decisions correct on S1 (auto-resolve) and S3 (escalate, constraint named); failures are evidence-only.
- F-05 fix design: guardrail verdict in INVOCATION detail is inferred from call outcome (content_filter/blocked -> blocked, failure -> not-evaluated, else passed), not read from the Bedrock guardrail trace. Corroborate by joining action_id to gateway/PDP lines. OPEN until re-test.
- F-06 recovery: first rollback via kubectl apply was refused (last-applied annotation corrupted by an earlier get|sed|replace). Recovered by merge-patching only spec.awsAgentCore.containerUri. Lesson: change one field with patch, never replace a governed CR wholesale.
- F-06 contained 2026-10-05: reference image restored by image-only patch; S1 agents answer again. team-agent-v1 root cause: [TBD].
- F-07: IDE role is denied logs:FilterLogEvents on /aws/bedrock-agentcore/runtimes/*. Our team cannot read agent runtime crash logs, so runtime failures are diagnosable only by the platform owner. Evidence gap for auditor question "RECONSTRUCT".

- F-01 CLOSED 2026-10-05 (team-agent-v3): negotiation recorded; re-tests S1 fault-1791236662-9e45fb PASS 8/8, S3 fault-1791236756-121272 PASS 10/10.

- F-08 (2026-10-05): S2 regressed on v3. All agents auto-resolve (fault-1791236708-1401f9) vs gather-evidence on v2 (fault-1791236243-830d7a). Suspected cause: REVERSIBLE ACTION prompt line led the model to treat a reversible fix as resolution. OPEN.

