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
| w10–w11 | Datagate (2nd pass), cert/execute lifecycle, approval/ceremony/quorum, ledger 3rd pass, timing/side-channel | request-intent row leakage closed, outcome-store export budget drain, phantom revoke of signer keys, approval consent dies with device quarantine, custodian share loss on revocation, dealer binding, quorum by real signing key, constitutional floors on key.rotate/key.ceremony, KEY-006/KEY-011 honest demotions, traceability gate hardened to asserting test bodies |
| w12–w13 | Provenance wave: store/auditIndex, timing, supply-chain, lifecycle | audit-chain provenance for all security state (mutable rows demoted to caches), tx-abort snapshot/restore, POLICY_STAGED anchor for promotion, folded cancel/reserve/outcome, composite parentage from chain, drift flag chain-anchored, self-contained verify-release, CI parity of verify.sh |
| w14–w16 | w13 residual batch, anchored state, fix-verification of provenance layer | dead-key signing window enforced in the fold, anchored repoint selection by KEY_ROTATED events, dead-key repoint refusal, grant legacy-fallback field equality, decisions-anchor DoS fix, seal repoint under live successor, auditExport per-row re-checks, _signingKeyId corroborated steering |
| w17 | Fix-verification, console/CSRF, red-team kill-chain, _auditIndex fold | chain-anchored ceremony plan/quorum, anchored-only policy restore (forged constitution un-signable), keyed rotation steering map, 60s denial/reject dedup, indexed runtime-use lookups, revoked-flag verify memo, CSRF byte-length + credential-bound logout, CORP/COOP headers |
| w18 | Fix-verification of w17, ledger/docs 4th pass, crypto/vault 2nd pass, HTTP/console 2nd pass | in progress — findings land with fixes + regression tests |

## Method

- Every auditor worked from a pinned commit, was instructed not to modify
  the repository, and returned severity-tagged findings with reproduction.
- Findings were re-verified against the live tree before any fix; stale or
  already-fixed findings were closed with the commit that pre-dated them.
- Every accepted finding landed with a dedicated regression test — see
  `tests/w5-*` … `tests/w17-*.test.mjs` — so a repeated auditor can
  check each repair independently.
- Fix-verification auditors specifically hunt for defects *inside* the
  fixes of the same wave, closing the self-review loop.

## Residual limits

The reviewers share this codebase's toolchain and threat-model
assumptions; they cannot substitute for a paid third-party audit, a
formal-methods review of the authorization core, or a production
penetration test. Those remain open production-acceptance gaps.
