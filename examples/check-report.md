# Policy check
Plan `plan-risky-51` against pack `standard` v1

**Verdict:** FAIL — fix the HIGH violations before this plan goes to a human.

## Violations

- **HIGH** `SEC-01` (security, step s2) — Step s2 does 'Publish the digest to the public list', which the pack forbids (matches 'publish').
- **HIGH** `SEC-02` (security, step s2) — Step s2 cannot be undone and runs without permission — the pack requires a human gate on irreversible steps.
- **MEDIUM** `SEC-03` (security, step s2) — Step s2 has no reason written down — the pack requires one.
- **HIGH** `PRV-01` (privacy, step s2) — Step s2 targets 'public-list', which the pack forbids (matches 'public').
- **MEDIUM** `ORG-01` (org, whole plan) — Plan total $6.50 is over the pack limit of $5.00.
- **MEDIUM** `ETH-01` (ethics, step s1) — Step s1 is missing 'owner' — the pack requires it on every step.
- **MEDIUM** `ETH-01` (ethics, step s2) — Step s2 is missing 'owner' — the pack requires it on every step.
