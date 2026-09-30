# Verification report

## Executed evidence

**263 automated test cases passed, 2 failed** (node --test over tests/). TAP output in reports/tests.tap.

**22 simulation scenarios** run by scripts/simulate.mjs (reports/simulation-results.json).

## Requirement ledger (generated, not hand-maintained)

| Status | Count |
|---|---|
| VERIFIED_IN_ENGINEERING_PROFILE | 174 |
| BLOCKED_EXTERNAL | 27 |
| PARTIAL | 8 |
| NOT_IMPLEMENTED | 2 |

VERIFIED_IN_ENGINEERING_PROFILE means directly exercised in the declared engineering profile only — not closure of external/production acceptance. The production gate is expected BLOCKED: 1 is the observed exit code (1 = blocked by named items).

Independent verification: node:crypto export verifier, WebCrypto/bun export verifier, Python cryptography vector verifier — see reports/verification-*.json.
