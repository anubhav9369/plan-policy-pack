# Pack conformance
Pack `standard` v1 — 4/4 cases matched

**Verdict:** CLEAN — every case matched and every rule fired at least once.

## Cases

- **PASS** clean plan passes — expected clean, got clean
- **PASS** risky plan breaks six rules — expected ['ETH-01', 'ORG-01', 'PRV-01', 'SEC-01', 'SEC-02', 'SEC-03'], got ['ETH-01', 'ORG-01', 'PRV-01', 'SEC-01', 'SEC-02', 'SEC-03']
- **PASS** unpriced step — expected ['ORG-02'], got ['ORG-02']
- **PASS** gated publish to an internal target — expected ['SEC-01'], got ['SEC-01']
