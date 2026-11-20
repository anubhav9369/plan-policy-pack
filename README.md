# plan-policy-pack

Versioned policy packs for InspectablePlans — the rules a plan must
satisfy before a human approves it, as content instead of code.

A team writes the rules it cares about in JSON, versions the pack, and
swaps it without touching any tool. This module loads and validates
packs, checks a plan against one, and runs a pack over a corpus of
known-good and known-bad plans to prove the pack itself is sound —
catching rules that never fire (dead rules) and rules that fire on
good plans (false positives).

It checks only. It never approves anything itself — the decision
still goes through `plan-approve`, and the blocking check at run
time still goes through `plan-policy-check`. This is the pack the
checker reads.

Part of [BRJP26100123](https://github.com/anubhav9369/trustworthy-agentic-ai)
— Building Trustworthy AI Systems through Explainability and
Human-in-the-Loop Control. Week 3: policy validation.

## Usage

```bash
python3 policy_pack.py examples/default-pack.json examples/plan.json
python3 policy_pack.py examples/default-pack.json examples/plan.json --json
python3 policy_pack.py --conformance examples/default-pack.json examples/conformance-corpus.json
```

Exit codes: `0` plan passes / conformance clean, `2` violations found /
conformance mismatch, `1` input error.

## Pack format

```json
{
  "name": "standard",
  "version": 1,
  "rules": [
    {"id": "SEC-01", "category": "security", "severity": "HIGH",
     "description": "Publishing, deleting or transferring is never a routine step.",
     "match": {"type": "forbid_action", "actions": ["publish", "delete", "transfer"]}}
  ]
}
```

Categories: `security`, `privacy`, `org`, `ethics`.
Severities: `HIGH`, `MEDIUM`, `LOW`. Rule ids must be unique; a pack
with a bad rule is rejected with a plain-English error, not silently
loaded.

Matcher types:

- **forbid_action** — fires when a step's action contains one of the
  listed words (case-insensitive)
- **forbid_target** — fires when a step's `target` contains one of the
  listed words; steps with no target are skipped
- **require_gate** — fires on irreversible steps with no human gate
- **require_reason** — fires on steps with no reason
- **require_estimate** — fires on steps with no cost or time estimate
- **require_field** — fires on steps missing the named field
- **max_total_cost** — fires once on the whole plan when the total
  known cost is over the limit; unpriced steps are unknown, not zero

## Examples

- `examples/default-pack.json` — the standard pack: 7 rules across
  all four categories (no ungated irreversible steps, no public or
  external targets, $5 total budget, every step reasoned, priced,
  and owned).
- `examples/strict-pack.json` — everything in standard, plus a $2
  budget, no production target, and no scraping.
- `examples/plan.json` — clean v2: passes the standard pack.
- `examples/risky-plan.json` — ungated publish to a public list, no
  reason, no owner, $6.50 total: breaks six rules.
- `examples/conformance-corpus.json` — four cases: a clean plan, the
  risky plan, an unpriced step, and a gated publish to an internal
  target.
- `examples/check-report.md`, `examples/conformance-report.md` — the
  generated reports. The strict pack passes all four corpus cases
  but flags `SEC-04` (no scraping) as a dead rule — see
  `examples/strict-conformance-report.md`.

## Tests

```bash
python3 -m unittest discover -s tests -v
```

11 tests, standard library only.
