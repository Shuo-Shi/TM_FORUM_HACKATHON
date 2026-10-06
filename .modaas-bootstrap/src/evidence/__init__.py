"""The MoDaaS evidence contract (a design note point 5).

Owned by core and versioned like a CRD contract, NOT by any one service: the
writer (`modaas-authz`), the reader (`evidence-service`) and every participant
agent must agree on the same record shape or the "one key from intent to
decision to result" claim is unjoinable prose.

Stdlib only, deliberately. Every consumer vendors this package into its image
(`evidence_build/` in each component's build script), and the three service
images do not share a requirements set -- a dependency here would have to be
added to all of them, and `evidence_record.py` needs nothing that is not in the
standard library. The JSON Schema beside it is the language-neutral half for a
non-Python participant; `tests/test_evidence_schema.py` pins the two together.
"""
