# Operator runbooks

These are actionable local engineering procedures and proposed production response sequences. No organisational on-call assignment, SLA, external incident exercise or production DR has been validated. Security, platform, finance/data owners and customer custodians must be formally assigned before production acceptance.

## Certificate rejection

Use the machine-readable error and request ID; do not log the request body or token. For `INV-409-STATE`, compare the current target state, active policy version and evidence graph to the exact signed capsule. Cancel undispatched authority and create a separately reviewed new capsule if the business request remains valid. Do not edit a certified capsule or re-use its nonce. For expiry, re-propose and obtain fresh evidence/approval. For replay, inspect the existing certificate outcome; a replay error is not a request to mint a duplicate payment.

## Target uncertainty

An operator uses `GET /gate/v1/outcomes/{certificate_id}` or Reconcile target outcome. VERIFIED is valid only after observed target journal state matches the authorised fields. If no authoritative outcome exists, the result remains UNCERTAIN. Stop replacements for the same business transaction and have the real target owner establish execution/non-execution through an authoritative reconciliation channel. Never infer success or failure from a timeout. The simulation has no manual “mark successful” override and no blind retry button.

## Gate/process outage and restart

Preserve the deployment directory, private configuration and both SQLite databases. Stop the service gracefully (`SIGTERM`) rather than deleting state. Restart the same reviewed code with the same directory and configuration. A consumed reservation remains consumed after restart. Reconcile any EXECUTING/UNCERTAIN records. The included restart test demonstrates reservation persistence, not a production RTO or multi-zone failover.

For an actual database backup, use the shipped tooling: `node scripts/backup.mjs --dir <deployment> --out <backup-dir>` performs an engine-native online backup (WAL checkpoint + `node:sqlite` backup API, consistent snapshot — never a raw `.db` copy) and writes a signed-content manifest (`IF-BACKUP-1` with SHA-256 per file). `node scripts/restore-check.mjs --dir <backup-dir>` verifies the manifest offline: hashes match, schema versions are readable, and the audit chain is still ordered. The drill is exercised in CI via `scripts/simulate.mjs`. Key material outside the databases (vault file, master key, config) must be backed up separately under custodian control. Retain original checkpoints and encrypt backups under separately controlled keys. Production backup scheduling and remote key escrow are not implemented.

## Key or issuer compromise

The security role invokes `POST /v1/revocations` with the affected key/issuer/subject/certificate, an incident reason, and a separately authenticated token. This blocks future local use and preserves evidence. If the execution/audit-key host is compromised, isolate it first; application-level revocation cannot make a malicious host trustworthy. Preserve external checkpoints and forensic copies.

Rotation procedure: (1) `POST /v1/keys/rotate-prepare` with the affected `key_class` — the vault generates a **pending** key that cannot sign anything; (2) propose a `key.rotate` action binding `new_key_id`, the pending key's `new_public_key`, a `ceremony_id` and `revoke_old`; (3) collect `governance_review` evidence from two independent failure domains; (4) collect three custodian approvals and honour the cooldown; (5) certify and execute — the pending key activates and the old key is retired. `GET /v1/keys/{id}/attest` produces a signed software attestation for the new key. Unilateral rotation does not exist: the action is the authority.

Secret recovery procedure: `POST /v1/ceremonies` creates a k-of-n ceremony with named custodians and a validity window. Each custodian acknowledges with an offline envelope signed with purpose `ceremony-acknowledgement` (e.g. `node src/cli.mjs sign --purpose ceremony-acknowledgement ...`, then `POST .../acknowledge`). Only then may `POST .../split` divide a base64url secret into committed shares for distribution. `POST .../reconstruct` requires k distinct shares; a duplicate or below-quorum set is refused. The service never retains the secret.

## Suspected tenant isolation incident

Stop affected ingress, preserve encrypted state and minimal request-ID logs, record UTC times and affected component versions, and engage the assigned incident lead and privacy/legal owner. Keep tenant payloads compartmentalized. Revoke compromised principals and credentials under the approved customer process. Reproduce the suspected boundary failure only against isolated synthetic data. Document containment, scope, impact, recovery, root cause and corrective actions. Notification obligations require legal review, not a blanket product claim.

## Policy defect

Cancel unexecuted affected actions and revoke pending certificates. Use the exact policy simulator to review a correction. Root activation requires sequential policy version, reviewed exact diff, required evidence, delay and customer quorum. Never clear the revocation store or rewrite audit history to roll back a policy. Code rollback and authority rollback are distinct operations.

## Clock, evidence and hardware failures

A detected backward clock movement stops security mutations with `INV-503-TIME`. Restore an authoritative clock under operator control and preserve evidence; do not change stored last-seen time to bypass the check. Missing, expired or dependent evidence remains escrow. Synthetic health expires after 24 hours. Real attestation and protected recovery are unavailable; there is no universal refresh override. Secure Perception in this release is the dev-attested software profile — hardware attestation still fails closed.

## Evidence issuer operations

Start issuers with `node src/cli.mjs issuerd --dir <deploy>/issuers [--port 8090]` or `node src/issuerd.mjs --dir ... --port ...`. Each `*.issuer.json` spec carries its own key, channel, record store and optional `tenant` scope; two tenants may run same-named issuers — the registry keys are `<tenant>:<issuer>` and bare-name requests are refused when ambiguous (`?tenant=` on manifest/health, `tenant_id` in the issue body). The issuance log is appended per query at `<dir>/issuance-log.jsonl`. `POST /v1/connectors/{key_id}/drift-check` compares registered trust metadata with the live signed manifest and audits `CONNECTOR_DRIFT`; investigate version, kinds, channel or key changes as a potential connector compromise. Updating an issuer spec requires the same governance as any trust-registry change; do not edit spec files on a running daemon without a witnessed procedure.

## Staging release and rollback

Verify archive checksums, the complete test suite and machine-readable release gate. Install to a new versioned directory, preserve the existing application version and data, and test against a restored synthetic copy before traffic changes. Do not run different incompatible binaries against live state. Current schema version is 1; the program refuses a newer schema. No destructive migration exists. Do not claim safe rollback across future migrations without an independently tested plan.

Before production change, establish the exact target, recovery owner and rollback method, then build, migrate non-destructively, restart only the assigned service, verify health/logs and run an authorised critical flow. Those live steps could not be executed without an assigned customer environment.
