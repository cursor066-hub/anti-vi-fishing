# API and compatibility contract

The API is versioned under `/v1` and `/gate/v1`. `docs/openapi.json` enumerates 27 path templates, request schemas, roles and response/error shapes. `src/schema.mjs` and `src/policy.mjs` are the authoritative strict validators. Unknown fields fail rather than being silently ignored. The generated OpenAPI description is useful integration documentation, not an independent proof of every conditional predicate.

## Identity and tenant boundary

An Authorization header `Bearer <locally provisioned token>` identifies a tenant and subject. Callers cannot select a tenant with a request field or header. A browser may instead exchange the token at same-origin `POST /session`; subsequent POSTs require both the exact `Origin` and returned `X-CSRF-Token`. Session cookies are HttpOnly, SameSite=Strict, and Secure when the configured origin uses HTTPS. A session proves identity, not protected execution authority.

Permissions are explicit in `docs/openapi.json`. Auditor users see digest-only audit exports and conservative coverage, not full action payloads. Operators, eligible approvers, security and policy administrators have tenant-local access appropriate to the engineering workflow. Fine-grained finance/privacy assessor field projections and support-access workflows are incomplete and block enterprise acceptance.

## Capsule, evidence and authority

Proposal fields include actor/device, versioned schema ID/digest, typed action/resource/purpose, exact current state, requested state, destination, integer quantity, explicit exclusions, nonce, timestamps, policy version and compensation description. The server adds tenant and capsule ID. The explicitly versioned engineering currency profile supports EUR, USD, GBP, CHF, CAD, AUD, NZD and SGD, all with two decimal minor units. Other currencies are rejected, not silently interpreted with an incorrect scale. A required idempotency header provides stable proposal retry semantics; reusing a key with a changed request is rejected. Terminal denied/cancelled/dispatched instances cannot be reopened.

Evidence is an Ed25519 envelope with purpose `evidence`, signed by a configured issuer for its registered evidence kinds. The signed payload is action/tenant-bound and includes digest, acquisition/expiry, confidence, provenance, dependencies and retention. Unsigned documents and free-form prose cannot provide root authority. Adding evidence invalidates prior approvals. Evidence acquisition from real banks/ERP is not implemented.

The approval challenge includes capsule/evidence/policy digests, signer key ID and short expiry. The corresponding `action-approval` signature must match the authenticated approver and must not come from the initiating subject. A certificate is minted only after current deterministic ALLOW. It is registered, single-use and bound to exact scope, gate, policy, evidence, signer set, target state and nonce.

`POST /gate/v1/execute` accepts only an issued certificate plus an explicit boolean `dry_run`. There is no arbitrary mutation or fault-injection HTTP route. Test-only faults are available only through local module calls in `tests/` and `scripts/simulate.mjs`.

## Important response semantics

| Code | Handling |
|---|---|
| INV-400-SCHEMA | Correct the typed request; unchanged retries cannot fix it. |
| INV-401-AUTH / SIGNATURE / CERTIFICATE | Re-establish valid identity or separately re-authorise; never bypass. |
| INV-403-SCOPE / ROLE / HEALTH / QUARANTINE | Scope, identity, health or containment rejection. |
| INV-409-STATE | State/evidence/policy mismatch; re-canonicalise and re-review. |
| INV-409-REPLAY | Authority or request already consumed; inspect existing outcome. |
| INV-409-IDEMPOTENCY | Same idempotency key bound to different content. |
| INV-412-EVIDENCE | No current ALLOW; resolve deterministic gaps. |
| INV-429-BUDGET / RATE / FANOUT | Wait for bounded budget/rate recovery or separately review narrower authority. |
| INV-501-HARDWARE | Secure Perception unavailable; no decryption/secure-mode fallback. |
| INV-503-TIME / STORAGE / CONFIG / RELEASE | Local infrastructure/trust condition prevents safe operation. |

Policy DENY, DEFER and ESCROW are decision objects, not automatically HTTP 451/423/412 at the evaluate endpoint. UNCERTAIN is a signed **outcome status** returned with HTTP 200 after dispatch; clients must inspect the payload and must not treat all 2xx as execution success. This is an explicit difference from the SRS’s illustrative `INV-599-UNCERTAIN` transport code. The decision’s reasons and next action remain machine-readable.

The outcomes GET follows the SRS’s reconciliation endpoint and may append a new signed reconciliation result to the log. It does not re-dispatch the mutation. Clients must disable shared caching, as enforced by `Cache-Control: no-store`.

## Bounds and unsupported behavior

The HTTP body limit is 1 MiB; JSON nesting is bounded, object keys are ASCII and safe-integer quantities only are accepted. Evidence is bounded at 32 items per action. List pagination is limit/offset (max 100). Policy simulation scans at most 500 recent actions. Retention stops conservatively if it cannot establish all references within its batch bound. Engineering audit export is in-memory rather than a production streaming/pagination API.

There are no external URL fetch, plaintext-key extraction, raw SQL, universal administrator bypass, automatic compensating mutation, real bank connector, root-key enrollment, arbitrary capability widening, or production-enable API. Distributed revocation, true emergency policies, composition/batch atomicity, crypto migration and several long-term SRS features remain in the explicit gap register.
