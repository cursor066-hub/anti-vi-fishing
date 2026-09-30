# Architecture and trust bill

## Executed engineering profile

`server.mjs` validates HTTP framing, JSON, host/origin, authentication, roles and request budgets. `schema.mjs` binds typed semantic fields and schema digests. `fabric.mjs` implements the state machine and reservation journal. `policy.mjs` makes deterministic decisions without external calls or AI. `store.mjs` holds encrypted tenant records, replay guards, usage counters and a signed append-only hash chain. `target.mjs` simulates the external resource in a distinct SQLite database. `runtime.mjs` checks scoped local capabilities and consumes information budgets atomically.

The UI is dependency-free HTML/CSS/JavaScript served by the same origin. It does not hold approval keys. The approval challenge binds the exact capsule, current policy and evidence graph digests. Independent software signers sign outside the browser; the server verifies signatures against its public-only registry and requires distinct customer subjects/failure domains. The constitution requires a minimum three-custodian quorum for root policy and backup-deletion simulations. It cannot be weakened below that floor by a candidate policy.

## Durable mutation protocol

1. In a SQLite `BEGIN IMMEDIATE` transaction, verify certificate signature, scope, registered issuance, expiry, revocations, policy/evidence freshness, eligible approvals, configured device health, target-state version/digest, and single-use status.
2. Reserve the transaction by irreversibly consuming the certificate and append a signed reservation event. Commit this local journal before dispatch.
3. The isolated target performs its own compare-and-set inside a transaction, recording the result under the certificate identifier. Unique transaction identifiers make the simulated target idempotent.
4. The gate checks the observed state against independently reconstructed expected material fields; a self-consistent but unauthorised response does not pass. Append the signed outcome.
5. On timeout, malformed response or crash, persist or recover UNCERTAIN/EXECUTING and reconcile the target journal. Never re-dispatch an ambiguous mutation. “No journal confirmation” stays UNCERTAIN; only an authoritative future integration could prove non-execution.

There is no distributed two-phase commit, exactly-once guarantee for an arbitrary external target, or automatic compensation. A future real target adapter must define its idempotency and authoritative reconciliation contract and pass the same fault tests.

## State and key storage

Every tenant record is encrypted with AES-256-GCM under a per-tenant local key. Associated data binds tenant, kind and record ID, so moving ciphertext across tenants fails. Audit entries contain minimal integrity metadata, are hash-linked and individually signed with a separate audit key. Execution and audit private keys are logically separate. The local configuration file contains these software keys and is part of the trusted computing base; it is not a managed secret vault or HSM.

SQLite WAL, synchronous FULL, uniqueness constraints and immediate transactions serialize mutations across independent gate workers. This supports tested single-host concurrency, not multi-zone availability. SQLite administrative access can drop triggers or replace databases; trusted external checkpoints are required to detect history replacement or rollback. System time is checked for persisted regression, but is not attested or independently sourced. Forward jumps remain an operational risk.

## Canonical profile

IF-CJSON-1 uses lexicographically sorted ASCII object keys, Unicode NFC strings without lone surrogates, booleans, null, arrays and safe signed integers. Floating point, negative zero, duplicate keys and unsupported objects are rejected. The profile is deliberately narrower than general JSON and is not advertised as universal RFC 8785 compliance. Currency is expressed in integer minor units. JavaScript and Python digest vectors cover the supported profile; Node and independent Bun/WebCrypto verifiers validate the same signed sample log using separately pinned public keys.

Ed25519 and SHA-256 are the only signing/hash suite in this release. AES-GCM protects stored records. Algorithm identifiers are versioned, but algorithm migration, post-quantum support, certified key ceremonies and key-rotation workflows are not implemented.

## Runtime and data

A runtime capability includes a signed snapshot of its policy limits. Local evaluation does not call a vendor cloud. The current local active policy and revocation store must remain available; this is fail-closed, not disconnected multi-zone synchronisation. Every read is charged by requested rows × requested columns × server-configured classification weight. Charges aggregate across capabilities by tenant, subject and dataset over rolling windows; overlapping reads are charged again. SQL from callers is never accepted. Projection is over a synthetic dataset, not a SQL rewriting engine.

The API denies raw access to seeded datasets through the resource-state endpoint. Runtime selection is limited to the caller’s configured grants and the current policy. The network path enforces destination, HTTPS/443, rate and fan-out **as decisions only**. No kernel, proxy, switch, endpoint or packet action is performed.

## Coverage, perception and AI

Coverage declarations accept only MONITORED or UNKNOWN. Signed manifests always suppress a production guarantee because no total-mediation evidence exists. No API can turn a checkbox into ENFORCED. A full discovery/drift agent and actual bypass tests remain external integration work.

Secure Perception endpoints return a reason-coded failure. No attestation fallback releases protected plaintext while claiming Secure Mode. All ordinary UI is explicitly lower-assurance. AI is disabled and unnecessary for all executed flows; no provider receives content and no model has authority. There is no implemented AI extraction/evaluation service.

## Trusted computing base and limits

The trusted base includes Node, OpenSSL/SQLite bundled with it, the operating system, this server’s security modules, local key/configuration files and file permissions. `reports/code-inventory.json` records source line counts, not a reviewed assurance metric. The browser is trusted only for ordinary operator interaction, never as a secure display. The threat model and release blockers explicitly retain host compromise, software-key compromise, authority-registry compromise, external targets, operational key lifecycle and high availability as unclosed risks.
