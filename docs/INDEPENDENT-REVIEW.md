# Independent adversarial review record

Record of the hostile audit waves run against this codebase by isolated
review agents (separate machines, instructed to find defects, stubs,
overclaims and bypasses with file:line evidence). These are adversarial
**agent** reviews — they are not a third-party professional security
assessment, and `NFR-SEC-002` stays `PARTIAL` on exactly that basis: a
bill-of-trust document plus agent reviews do not equal independent
external review.

| Wave | Focus areas | Outcome |
|---|---|---|
| w1–w2 | Whole-codebase hostile review; ledger status re-verification | 10 ledger overclaims demoted; drift-quarantine, connector-drift, ceremony-delay, suite-rotation and test-strength fixes |
| w3 | Crypto, HTTP/authz, store/audit log, policy, runtime/datagate | Emergency-policy monotonicity, grant re-check at consume, health binding, audit-page tamper detection, real-deployment backup drill |
| w4 | Docs/console, PARTIAL statuses, release pipeline, concurrency | busy_timeout + savepoint nesting, atomic keystore writes, revocation recheck, fresh clock per composite child, outcome supersede |
| w5 | Schema/secrets/simulator, HTTP contract fuzz, test quality | Canonical query grammar, closed param set, path normalization refusal, 405 matrix, object guards, 13 vacuous tests repaired, 17+ mutation-kill tests |
| w6 | Perception/advisory, ceremony/threshold, tenancy/datagate, ledger re-verify, fix-verification | Dataset-row capsule leak closed, cross-tenant key/revoke oracles, export budget bypass, phantom budget spend, issuer claim signing scope |
| w7 | Backup/restore, clock/replay/idempotency, cross-component seams, console sessions, DEK | Sibling-session retirement, session/token revocation binding, backup trust anchors, log-path hardening |
| w8 | Ledger re-verify, fix-verification, tooling/CLI, composite/coverage, canonical/schema | Scoped trust anchors for restore, cli-sign key consistency, issuerd log protection, `--check-only` reports, prototype-member revoke oracles, evidence-binding own-property walks, parser depth split, 15-name key blocklist, reject-vector corpus |
| w9 | Network/quarantine, SRS completeness, deploy/bootstrap, fix-verification, schema/bootstrap | issuerd crash-on-metrics fix, uniform-404 issuer oracle, socket timeouts, Host pinning, early IP bucket, per-issuer buckets, digest-stored issuer credentials, `serve` custody coverage, nginx/systemd template alignment, ledger status corrections |

## Method

- Every auditor worked from a pinned commit, was instructed not to modify
  the repository, and returned severity-tagged findings with reproduction.
- Findings were re-verified against the live tree before any fix; stale or
  already-fixed findings were closed with the commit that pre-dated them.
- Every accepted finding landed with a dedicated regression test — see
  `tests/w5-*` … `tests/w9-deploy.test.mjs` — so a repeated auditor can
  check each repair independently.
- Fix-verification auditors specifically hunt for defects *inside* the
  fixes of the same wave, closing the self-review loop.

## Residual limits

The reviewers share this codebase's toolchain and threat-model
assumptions; they cannot substitute for a paid third-party audit, a
formal-methods review of the authorization core, or a production
penetration test. Those remain open production-acceptance gaps.
