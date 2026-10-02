# Algorithm agility inventory (KEY-006)

Every cryptographic use in the engineering profile, the approved profile it maps to, and the transition posture when an algorithm must be retired. The single registry of approved signature suites is `SUITES` in `src/crypto.mjs`; policy narrows it per tenant via `policy.algorithms.allowed_suites` and plans rotation via `policy.algorithms.deprecation`.

## Signature suites

| Use | Primitive | Suite key | Approved profile | Transition posture |
|---|---|---|---|---|
| Capsule intent envelopes (`capsule-intent`) | EdDSA over IF-CJSON-1 | `Ed25519` | RFC 8032 | `ES256` already implemented; promote via `allowed_suites` per key |
| Evidence envelopes (`evidence`) | EdDSA over IF-CJSON-1 | `Ed25519` | RFC 8032 | Same-suite rollover first; cross-suite only after dual-verification window |
| Action approvals (`action-approval`) | EdDSA over IF-CJSON-1 | `Ed25519` | RFC 8032 | Challenge-bound; rotate custodian key + suite together |
| Ceremony acknowledgements (`ceremony-acknowledgement`) | EdDSA over IF-CJSON-1 | `Ed25519` | RFC 8032 | Tied to custodian key lifecycle |
| Key attestations (`key-attestation`) | EdDSA over IF-CJSON-1 | `Ed25519` | RFC 8032 | Re-attest under successor suite before deprecation deadline |
| Component attestations (`component-attestation`) | EdDSA over IF-CJSON-1 | `Ed25519` | RFC 8032 | Firmware allowlist + suite rotation are orthogonal gates |
| Certificates, capabilities, grants, audit envelopes | EdDSA over IF-CJSON-1 | `Ed25519` | RFC 8032 | `ES256` selectable through `allowed_suites` |
| Any of the above under ECDSA | ECDSA P-256/SHA-256, IEEE-P1363, low-s enforced | `ES256` | SEC 1 / FIPS 186-5 | Second approved suite; `allowed_suites` is a closed set — an unlisted suite fails signature verification, not policy |

## Non-signature primitives

| Use | Primitive | Approved profile | Transition posture |
|---|---|---|---|
| Vault record key-wrap (`IF-SOFTHSM-1`) | AES-256-GCM, AAD-bound tuple | NIST SP 800-38D | Re-wrap on rotation; DEK destruction = crypto-shredding |
| Audit chain linkage | SHA-256 hash chain + signed envelopes | RFC 6962-style Merkle/log pinning | Hash migration requires chain-reseal ceremony |
| Watermark / attribution MACs | HMAC-SHA-256 | RFC 2104 | Key-rotation bound; verify-only window for old watermarks |
| Secure Perception session seal | ECDH P-256 + AES-256-GCM | NIST SP 800-56A | Dev-attested profile only; hardware suite is an external upgrade |
| Shamir threshold shares | GF(256) polynomial interpolation | Shamir (1979) | Suite-independent; re-deal on custody changes |
| Content digests | SHA-256 | FIPS 180-4 | Envelope headers pin a fixed 4-key set `{profile,suite,key_id,purpose}` — verifiers reject any extra key, so digest agility rides on the suite/profile pair, not a per-envelope field |

## Suite-confusion posture

- Verification resolves the suite from the envelope's own `protected.suite` field and then checks that suite against `policy.algorithms.allowed_suites` — a valid Ed25519 signature presented as ES256 fails, and vice versa (tested).
- `allowed_suites` is a closed set validated at policy load; `deprecation` records retired suites that verify-only until their deadline, after which they verify nothing.
- No post-quantum suite is claimed; adding one means adding a `SUITES` entry, extending `allowed_suites` validation, and re-issuing attestations — a code change, not a config toggle.
