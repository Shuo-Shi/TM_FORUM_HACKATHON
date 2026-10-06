#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""answer.py — the six auditor questions, as six functions over ~/evidence.

The challenge brief (content/challenge-brief/index.en.md, "The six auditor
questions") judges score your submission by picking an incident and asking:

    1. WHO acted
    2. WHAT did it touch
    3. WAS IT AUTHORIZED
    4. WHO APPROVED
    5. INTEGRITY
    6. RECONSTRUCT

Every function below is a stub: it reads the files pull-evidence.sh writes
and returns "not implemented" until you fill it in. Wire your own evidence
model in, or read straight from the JSON here — either is fine, the judges
read your ANSWER, not this file.

Usage:
    bash pull-evidence.sh <run-id>          # writes ~/evidence/*.json
    python3 answer.py <run-id>              # asks all six, over ~/evidence
    python3 answer.py <run-id> --question 3 # just WAS_IT_AUTHORIZED

Each function takes `evidence` (a dict of the six loaded JSON files, keyed by
surface name) and the run id, and returns a plain string: the answer a
non-engineer could read, or a `NotImplementedError` if you have not written
it yet. That is score 0 on the brief's 0-3 rubric — filling these in is most
of the work the challenge asks for.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

SURFACES = ("tmf639", "cr-status", "approvals", "gateway-log", "registry", "otel-traces")


def load_evidence(evidence_dir: Path) -> dict:
    """The six files pull-evidence.sh writes, keyed by surface name.

    Missing files are None, not a crash: a team that has not run
    pull-evidence.sh for every surface yet should still be able to try the
    other answers.
    """
    out = {}
    for name in SURFACES:
        p = evidence_dir / f"{name}.json"
        try:
            out[name] = json.loads(p.read_text())
        except FileNotFoundError:
            out[name] = None
        except json.JSONDecodeError as e:
            out[name] = None
            print(f"warning: {p} is not valid JSON: {e}", file=sys.stderr)
    return out


def who(evidence: dict, run_id: str) -> str:
    """Q1 WHO acted — which identity, on whose behalf, with what scope?

    Read this from evidence["gateway-log"]: each governed call the gateway
    logged for this run carries the caller's identity (the credential the
    perimeter resolved) alongside modaas.action_id and modaas.trace_id.
    """
    raise NotImplementedError(
        "WHO: read evidence['gateway-log']['records'] for this run id; each "
        "record has the caller identity the perimeter resolved (see Baseline "
        "Walkthrough, 'gateway credential'). Return a plain sentence naming "
        "who acted, on whose behalf if delegated, and the scope.")


def what(evidence: dict, run_id: str) -> str:
    """Q2 WHAT did it touch — models, tools, resources?

    Cross-reference evidence["gateway-log"] (which model/tool alias was
    called) with evidence["cr-status"] (what that alias actually is: its
    kind, its Bedrock modelId or MCP tool, its namespace).
    """
    raise NotImplementedError(
        "WHAT: for each gateway-log record for this run id, resolve "
        "gen_ai.request.model (or the MCP tool alias) against "
        "evidence['cr-status'] to name the governed asset it points at.")


def was_it_authorized(evidence: dict, run_id: str) -> str:
    """Q3 WAS IT AUTHORIZED — which policy, which version, evaluated where?

    This platform's Cedar decisions are logged by modaas-pdp
    (`kubectl logs -n modaas-system deploy/modaas-pdp`), not shipped into
    pull-evidence.sh's six files by default — add a seventh surface if your
    utility needs it verbatim. Until then, the gateway's own 200/403 outcome
    in evidence["gateway-log"] is the enforcement result you have.
    """
    raise NotImplementedError(
        "WAS_IT_AUTHORIZED: for this run id's calls, read http.status in "
        "evidence['gateway-log'] (200 = allowed to reach the model/tool; a "
        "refusal at the perimeter never reaches Bedrock). Name the policy "
        "and version if your utility also pulls PDP decision logs.")


def who_approved(evidence: dict, run_id: str) -> str:
    """Q4 WHO APPROVED — attestation for every asset in the chain?

    evidence["approvals"] is exactly this: one row per governed CR with its
    approver and attestation text (Baseline Walkthrough step 2). Join it
    against the assets your WHAT answer named.
    """
    raise NotImplementedError(
        "WHO_APPROVED: for every asset named in your WHAT answer, look up "
        "its row in evidence['approvals'] and quote the approver and "
        "attestation. An asset with no approver recorded is a finding, not "
        "a blank.")


def integrity(evidence: dict, run_id: str) -> str:
    """Q5 INTEGRITY — prove the records were not altered.

    The audit ledger (evidence["otel-traces"], despite its filename — see the
    note inside that file) assigns each record a monotonic `seq` on write and
    accepts writes only with the shared token (see static/reference-impl/
    audit-store.py). Cross-check `seq` ordering and timestamps for gaps or
    reordering; a real integrity proof (e.g. a hash chain) is a stretch goal,
    not required.
    """
    raise NotImplementedError(
        "INTEGRITY: check evidence['otel-traces']['records'] for this run id "
        "— seq strictly increasing, ts monotonic, no records for a step that "
        "should exist but does not. State what you checked and what would "
        "have shown tampering.")


def reconstruct(evidence: dict, run_id: str) -> str:
    """Q6 RECONSTRUCT — replay it end to end with timestamps.

    Merge evidence["gateway-log"] and evidence["otel-traces"] on trace_id /
    action_id, sort by timestamp, and narrate the run: intent, invocation,
    guardrail outcome, result. This is the answer graders read most closely
    (score-run.py grades the same chain shape).
    """
    raise NotImplementedError(
        "RECONSTRUCT: merge evidence['gateway-log'] and "
        "evidence['otel-traces'] on trace_id/action_id, sort by time, and "
        "return a timestamped narrative of the run from intent to result.")


QUESTIONS = [
    ("1", "WHO", who),
    ("2", "WHAT", what),
    ("3", "WAS_IT_AUTHORIZED", was_it_authorized),
    ("4", "WHO_APPROVED", who_approved),
    ("5", "INTEGRITY", integrity),
    ("6", "RECONSTRUCT", reconstruct),
]


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("run_id", help="the correlation id / run id to answer for")
    p.add_argument("--evidence-dir", default=os.environ.get("EVIDENCE_DIR") or str(Path.home() / "evidence"))
    p.add_argument("--question", choices=[q[0] for q in QUESTIONS],
                   help="answer only this question (1-6); default: all six")
    args = p.parse_args(argv)

    evidence_dir = Path(args.evidence_dir)
    if not evidence_dir.is_dir():
        print(f"no evidence directory at {evidence_dir} — run pull-evidence.sh first", file=sys.stderr)
        return 2
    evidence = load_evidence(evidence_dir)
    missing = [k for k, v in evidence.items() if v is None]
    if missing:
        print(f"note: missing or unreadable surface(s): {', '.join(missing)}", file=sys.stderr)

    rc = 0
    for num, name, fn in QUESTIONS:
        if args.question and args.question != num:
            continue
        print(f"\n{num}. {name}")
        try:
            print("   " + fn(evidence, args.run_id))
        except NotImplementedError as e:
            print(f"   not implemented: {e}")
            rc = 1
    return rc


if __name__ == "__main__":
    sys.exit(main())
