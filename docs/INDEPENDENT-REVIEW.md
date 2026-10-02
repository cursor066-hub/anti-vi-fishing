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
| w18–w19 | Fix-verification of w17, ledger/docs 4th pass, crypto/vault 2nd pass, HTTP/console 2nd pass, issuerd 2nd pass, AAD-migration, anchored lifecycle | legacy-AAD closure via migrate-on-open + live-fallback removal (DEK/idempotency ciphertext transplants no longer decrypt), quorum-designated signing successors, single-use stored ceremonies, anchored ceremony lifecycle/consume/clock-veto |
| w20 | Datagate 3rd pass, fix-verification, ceremony/quorum, ledger 5th pass | anchored replay of COVERAGE_TECHNICAL_VALIDATION, sealAuditChain signed-certificate sweep, persistVault error honesty, issuerd full issuance-log verification, dedup-transplant donor accounting, driftCheck permissions/limitations constants |
| w21–w22 | Fix-verification, store/target, issuerd 3rd pass, crypto/vault, ledger 6th pass, HTTP/console, execute lifecycle, supply-chain | cited releases re-verified against the anchored chain, append-only ledger triggers + open-time probes, vault keys tenant-bound, issuerd issuance-log verification, deterministic TAP ordering |
| w24–w25 | Lifecycle expiry-at-dispatch, mutable-row vetoes, composite lineage, ledger 7th pass, benchmark honesty | expiry enforced at dispatch, mutable-row veto surfaces closed, composite lineage/journal binding, honest `_auditIndex` head-probe optimisation restoring the benchmark target, stale example fixture corrected |
| w26 | Secure-perception 2nd pass | session-bound releases (public-ECDH forgery refused), per-release anchored policy re-verify, private-half shredding on first touch, 64-session cap, /v1/me narrowing |
| w27 | Fix-verification, chain-head watermark, ledger 8th pass, datagate 5th pass, policy 3rd pass | signed head envelopes verified before monotone compare, durable two-file rollback detection, lock owner-token + honest INV-503-GATE + stale cleanup, 256/hour mint cap, composite sibling egress overlay, jit.grant row/dataset validation |
| w28–w30 | Fix-verification, store/crash-consistency, crypto/vault, HTTP/console, ledger 9th pass, datagate 6th pass, lifecycle/execute, policy 4th pass, issuerd/console, secure-perception | wipe-gate against silent re-genesis (vault injection exempt), chain-derived supersession (`_supersededMap`), fail-closed null-kid anchors, suite-floor on attestations, replay probes ahead of crypto, `_coversLiveSuites`, issuerd log-lock/empty-log guards |
| w31 | Fix-verification, ledger/docs 10th pass, runtime-gate 3rd pass, coverage/attestation 2nd pass | seal carryover: doomed-span spend/access/issuance re-attested inside signed AUDIT_SEALED; consume requires anchored issuance; constructor tolerates kline chains; single live identity per subject; anchored enumeration/binding/sweep over coverage |
| w32 | Fix-verification of w31, deep carryover audit, composite/outcome, store 5th pass | mirror-witness carryover bound, doomed AUTHORITY_REVOKED carried (seal can never un-revoke), wedge-integrity sweep gates wedge_cleared, sealed span graft/replay rejection, durable-watermark repair, target.db wipe residue, atomic dek+record deletes, wedged-child release denial, child-outcome folding |
| w33 | Seal/carryover 2nd pass, ledger/docs 11th pass, fix-verification, export/merkle | head-carried residue claims (checkpoint + revocation count convict unguarded-row deletion), incremental memoized merkle for proof/consistency endpoints, verify-proof de-circularised (proof's own claim + optional external pin), webcrypto signer-death window, three-verifier carryover 'key:' unfold parity |
| w34 | Composite/outcome (CRITICAL-1: seal cut laundered spent/cancelled/bound certs), ledger/docs 12th pass | lifecycle_carryover re-anchors every verifiable doomed event and replays it through the same fold; dropped_events names unverifiable destroyed rows and forces worst-case reconstruction coverage; unanchored outcome rows are strict INV-409-INTEGRITY (composite children anchor via parent's child_outcomes explode) |
| w35 | Fix-verification of w34, runtime-gate/consume 4th pass (tail-deletion laundering, stored-column surgery, planted floor rows) | doom boundary decided by signed payload sequence (stored-seq/hash surgery cannot strand or evict a doomed row); deleted-tail-under-head attested as head_regressed + abandoned_head_*, refused when floor/checkpoint residue regresses; planted revocation floors carried floor_derived (enforced, named, never gating the sealer) and convicted by anchored record_digest as planted_floor_refs; verify-proof binds tenant; proofs expose pin{root,size} |
| w36 | Seal/carryover 3rd pass, fix-verification of w35, ledger/docs 13th pass | carry pages bind the seal row that actually committed (repoint interposition cannot wedge a seal's own pages); carried key deaths (key: revocations + audit-class KEY_ROTATED inside lifecycle_carryover) unfold into every signer-death window — seals repoint to the ceremony-designated successor or refuse INV-503-CONFIG instead of dead-signing; carry-page amputation refuses on every path via table-derived recount (never 'already verifies'); the cut path consults the signed head's residue claims and attests abandoned_head_*; murdered revocation floors are named murdered_floor_refs, listed anchorless-carried, and re-anchorable; surviving-anchor floor rows are digest-checked (planted_floor_refs); planted audit-checkpoint rows cannot inflate the verified checkpoint floor; dead-key rejection unified at INV-409-INTEGRITY across page/export/standalone verifiers |
| w38 | Runtime-gate/consume 5th pass, store/crash-consistency 5th pass, fix-verification of w37, ledger/docs 14th pass, HTTP/console 6th pass | head-watermark entries are signed headmark envelopes (a forged unsigned floor above the head clamps to the verified tip and is surfaced as head_watermark_tampered on seal results instead of wedging every fold; a signed stranded floor still wedges and is re-anchored by seal); floor_derived exemptions narrowed to caller gates only — index/key-death enforcement restored; sparse audit view projections page forward to fill instead of under-filling; the connection cap gates inside the request handler so health probes can never be starved; resources route recursively redacts secret-named material_fields keys; key attestation binds a caller nonce (OpenAPI declares it); ceremony routes authorize before body-parse; session family cap + console deny/mint/logout ledger events; consume() budgets dropped carryover events at worst-case coverage |

## Method

- Every auditor worked from a pinned commit, was instructed not to modify
  the repository, and returned severity-tagged findings with reproduction.
- Findings were re-verified against the live tree before any fix; stale or
  already-fixed findings were closed with the commit that pre-dated them.
- Every accepted finding landed with a dedicated regression test —
  `tests/w<N>-*.test.mjs` files named per wave (w5 through the current
  wave; a wave's fixes land in the next wave's file when the report
  closes after the freeze) — so a repeated auditor can check each
  repair independently.
- Fix-verification auditors specifically hunt for defects *inside* the
  fixes of the same wave, closing the self-review loop.

## Residual limits

The reviewers share this codebase's toolchain and threat-model
assumptions; they cannot substitute for a paid third-party audit, a
formal-methods review of the authorization core, or a production
penetration test. Those remain open production-acceptance gaps.
