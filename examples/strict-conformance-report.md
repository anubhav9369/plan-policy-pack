# Pack conformance
Pack `strict` v1 — 4/4 cases matched

**Verdict:** REVIEW — the pack has cases that mismatch, dead rules, or false positives; see below.

## Cases

- **PASS** clean plan passes — expected clean, got clean
- **PASS** risky plan breaks six rules — expected ['ETH-01', 'ORG-01', 'PRV-01', 'SEC-01', 'SEC-02', 'SEC-03'], got ['ETH-01', 'ORG-01', 'PRV-01', 'SEC-01', 'SEC-02', 'SEC-03']
- **PASS** unpriced step — expected ['ORG-02'], got ['ORG-02']
- **PASS** gated publish to an internal target — expected ['SEC-01'], got ['SEC-01']

## Dead rules (never fired on any bad plan)

- `SEC-04` — no corpus case exercises it; add a case or drop the rule.
