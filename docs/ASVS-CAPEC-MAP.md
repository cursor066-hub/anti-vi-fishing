# Security testing map — ASVS profile and CAPEC coverage

Engineering-profile mapping of the adversarial and negative test surface to
OWASP ASVS v5 sections and the CAPEC classes they counter. This documents
**self-assessed** coverage, not an ASVS certification or third-party
verification report (NFR-SEC-003 remains `PARTIAL` for exactly that reason).

## Declared profile

The codebase targets the verification properties a single-process,
zero-dependency Node application can honestly meet: input validation,
authentication, access control, cryptography, error handling and data
protection. Web-facility chapters that do not apply (e.g. front-end
architecture, WebSocket, GraphQL) are out of scope of this map.

## Suite → ASVS → CAPEC

| Suite | ASVS area | CAPEC classes countered |
|---|---|---|
| `tests/canonical.test.mjs`, `tests/w8-canonical.test.mjs`, `vectors/parse-vectors.json`, `tests/conformance.test.mjs` | Input Validation (parser strictness, depth limits, prototype-pollution key grammar, `-0`/astral/UTF-8 edge grammar) | CAPEC-153 input-data manipulation; CAPEC-267 protocol control data; CAPEC-88 OS command/serialization injection |
| `tests/adversarial.test.mjs` | Stored Cryptography / malicious input (signature malleability, padding-bit canonicality, share confusion, merkle forgery, unicode tricks, replay) | CAPEC-463 padding oracle class; CAPEC-94 replay/spoof signed objects; CAPEC-102 crypto algorithm confusion |
| `tests/issuerd.test.mjs`, `tests/w8-ledger.test.mjs`, `tests/w9-deploy.test.mjs` | Authentication & Access Control (scoped bearers, digest-stored credentials, per-issuer/per-IP rate limiting, uniform-404 enumeration resistance) | CAPEC-114 authentication abuse; CAPEC-97 resource/path enumeration; CAPEC-125 flooding |
| `tests/http-concurrency-ui.test.mjs`, `tests/w5-schema.test.mjs`, `tests/w5-negatives.test.mjs` | API/HTTP validation (method matrix, query grammar, Host/Origin pinning, CSRF, content-type strictness, request timeouts) | CAPEC-233 privilege escalation via parameters; CAPEC-273 HTTP verb tampering; CAPEC-219 DNS rebinding |
| `tests/w6-tenancy.test.mjs`, `tests/w6-fix.test.mjs` | Multitenancy isolation & data protection (cross-tenant key/revocation oracles, budget bypass, dataset-row redaction, error surface scoping) | CAPEC-127 directory/tenant boundary probing; CAPEC-59 session/credential prediction |
| `tests/w7-dek.test.mjs`, `tests/w7-seam.test.mjs`, `tests/w7-fix.test.mjs` | Data protection at rest (per-record DEK crypto-shredding, WAL truncation, tamper detection on audit pages/outcome store) | CAPEC-552 post-deletion data recovery; CAPEC-71 data interception |
| `tests/w8-composite.test.mjs`, `tests/w8-canonical.test.mjs` | Business-logic integrity (composite capability ceilings, per-child binding, schema/type confusion to INV-400) | CAPEC-122 privilege escalation via workflow; CAPEC-233 object-shape confusion |
| `tests/w8-tooling.test.mjs`, `tests/w8-fixverify.test.mjs` | Configuration & deployment (file custody checks, trust-anchor scoping, inconsistent keyfile refusal, symlink traps) | CAPEC-122 file/credential path abuse; CAPEC-35 binary/config integrity |
| `tests/w9-deploy.test.mjs` | Configuration/deployment resilience (serialize-before-write, socket timeouts, Host pinning, early rate bucketing, tokenless-opt-in, digest specs) | CAPEC-125 resource exhaustion; CAPEC-219 rebinding; CAPEC-114 bearer enumeration |
| `tests/regression.test.mjs`, `tests/lifecycle.test.mjs`, `tests/extended-security.test.mjs` | Cross-domain invariants (approval binding, revocation, replay, idempotency, evidence domain counting) | CAPEC-94 replay; CAPEC-115 authentication bypass |
| `scripts/verify-vectors.py`, `scripts/verify-vectors-webcrypto.mjs`, `scripts/verify-export-webcrypto.mjs` | Independent conformance: three separate implementations (node:crypto, WebCrypto/Bun, Python cryptography) verify the same canonical/envelope vectors | CAPEC-88 cross-implementation canonicalization divergence |
| `tests/w5-mutations.test.mjs` | Mutation-kill suite: adversarial gate-level attacks (planted rows, forged envelopes, injected identities) that must all be refused with the classified error | whole-map regression anchor |

## Not covered by this profile (honest gaps)

- Formal ASVS certification or independent verification report.
- SAST/DAST tooling runs, independent penetration test, provider advisories.
- Production KMS-backed release signing (`NFR-SEC-007` is `PARTIAL`: engineering-profile SLSA-lite detached-envelope provenance is implemented and pinned-anchor verified via `scripts/release-sign.mjs` + `scripts/verify-release.mjs`).
- Live-environment fuzzing against a production deployment.
