# Invariant Fabric

**Engineering release — not approved for production use.** This ZIP is an executable, tested software implementation of substantial parts of IF-02, together with synthetic target simulations, a control workspace, adversarial tests, offline verifiers, and a complete requirement-by-requirement gap register. It is **not the complete R0–R5 production platform**. Read [production acceptance](docs/PRODUCTION-ACCEPTANCE.md) before assigning any security guarantee.

The implementation has no third-party application dependencies. It uses Node.js 24 built-in HTTP, SQLite, cryptography, test runner, and worker threads. Node **24.19.0 on Linux x64** is the tested runtime. Other versions and operating systems are not verified. Python 3 is optional for independent canonical digest verification. Bun 1.3.14 is used by the independent WebCrypto audit verifier: without it that leg self-skips and `reports/verification-webcrypto.json` cannot be reproduced locally; Bun is not needed to run the server.

## Start locally

From this directory, with the tested Node runtime installed:

```sh
node src/cli.mjs init --dir ./var/local
node src/cli.mjs serve --dir ./var/local --port 8080
```

Open **http://127.0.0.1:8080**. The bootstrap command prints file paths, not secret values. Use the appropriate locally generated token in `var/local/access-tokens.json` in the console sign-in form. The `acme` tenant has separate operator, security, auditor, policy administrator, and five approval/custodian identities. No credentials are shipped in this ZIP. Tokens and synthetic device-health statements expire after 24 hours; this release intentionally has no unprotected renewal or recovery override. Create a **new** isolated deployment for another evaluation; never delete an existing deployment containing needed evidence.

Bootstrap creates software execution/audit keys and separate offline custodian/issuer key files with restrictive file permissions. They are initially on one machine for synthetic evaluation; this is **not independent physical custody, MPC, an HSM quorum, or WebAuthn**. Do not load custodian private keys into the web UI. The server only knows their public keys.

The development server binds only to loopback. It rejects non-engineering mode and non-loopback binding. It must not be exposed as a public production service. The HTTPS reverse-proxy template is for controlled staging review, not an assertion that production acceptance passed.

## What runs

Typed capsules cover four finance workflows plus the full v2 platform surface: composite actions, policy change (immediate, staged `not_before` and emergency), key rotation, JIT grants, secure-session reveals and data-export escrow. The complete local flow is proposal → signed evidence → deterministic decision → independent exact-action signatures → single-use certificate → state-bound simulated mutation → signed observed outcome. Finance changes run against a separate persistent synthetic SQLite target, never a real bank or ERP. Runtime capabilities enforce subject, device, resource, destination, selection, expiry, rate and shared rolling budgets for the synthetic data gate, with overlap-reconstruction detection and watermarking. The service-connect path evaluates a software envelope; it does **not** filter packets or connect a real service.

The operator console covers actions and proposals, coverage limitations, policy simulation/history, runtime reads, key vault with rotation and attestation, threshold recovery ceremonies, connector status and drift checks, audit Merkle proofs, dev-attested Secure Perception sessions, JIT grants, and audited evidence export. There are no fake approval buttons or generated claims that a normal browser is a secure display.

Evidence issuer daemons run over real HTTP: `node src/cli.mjs issuerd --dir <deploy>/issuers --port 8090` serves signed manifests, health and evidence issuance per issuer spec (tenant-scoped names supported). The fabric acquires evidence via `POST /v1/action-capsules/{id}/acquire-evidence` and audits connector drift.

The IF-SOFTHSM-1 software vault wraps keys at rest, binds purpose, rotates via verified `key.rotate` actions, and attests software residency. Threshold recovery uses committed k-of-n Shamir ceremonies — a real HSM/MPC is still external.

See [WORKFLOWS.md](docs/WORKFLOWS.md) for exact operation and signing instructions; [API.md](docs/API.md) and [openapi.json](docs/openapi.json) describe the API. The original SRS is preserved in `spec/`; its two referenced image assets were not included with the supplied document.

## Verify and reproduce

```sh
sh scripts/verify.sh        # complete pipeline: check + tests + simulate + verifiers
npm test                    # 877-test suite incl. adversarial, conformance, canonical fuzz + coverage bypass probe
npm run conformance         # regenerate vectors; verify under node, WebCrypto and Python
node scripts/verify-export.mjs reports/sample-audit.json reports/sample-pinned-trust.json
python scripts/canonical-vectors.py examples/canonical-vectors.json
bun scripts/verify-export-webcrypto.mjs reports/sample-audit.json reports/sample-pinned-trust.json
node scripts/benchmark.mjs
node scripts/release-check.mjs
```

Conformance vectors in `vectors/` are verified byte-for-byte by three independent implementations: node:crypto, the WebCrypto subtle API and Python `cryptography`. The adversarial suite covers signature malleability, Unicode confusion, Merkle forgery, share confusion, approval replay, certificate reuse, issuer ambiguity and purpose confusion.

`release-check` **must exit nonzero** for this delivery: production blockers are deliberately enforced. Do not change a status to pass without the required independently reviewed evidence. Verification reports bundled in `reports/` distinguish direct execution, simulation, analysis, and unavailable checks. Source checks are not a SAST certification. HTTP/static UI tests are not browser or accessibility certification.

All test databases and private fixture keys are generated in unique temporary directories. Tests remove only their own fixtures. The simulator writes public synthetic audit evidence and result files under `reports/`. Sample trust keys authenticate only the supplied synthetic audit, not the release publisher or a real customer.

## Boundaries that remain

Customer systems and credentials were unavailable. There is no real ERP/bank/cloud/identity/backup connector (the evidence issuer is a controlled local daemon, not a bank API), no real HSM/MPC (the software vault and Shamir ceremonies do not provide hardware custody), no packet enforcement, trusted display/input implementation (Secure Perception is a dev-attested software profile), remote attestation verifier, multi-zone consensus, enterprise authentication lifecycle, or independently witnessed production deployment. SQLite plus application-level AES-GCM is a single-host engineering profile, not a high-availability customer key-management architecture.

The target system and gate use the same customer-local process privilege boundary; a process/host compromise can bypass the simulator. The supplied signature quorum is a software multisignature workflow, not protection against compromise of the machine holding generated fixture keys. An independent verifier with a previously pinned checkpoint detects a conflicting prefix; external witness hosting and publication are not deployed.

External package/security documentation could not be fetched because network egress denied `nodejs.org:443`. No browser or Playwright was installed, and installing packages was prohibited in the available environment. Consequently visual, browser-interaction, WCAG, dependency-advisory, external penetration-test, and production deployment acceptance are not claimed.

Project-specific acceptance status, owners, baselines, verification methods, and outstanding evidence for **all 211 numbered requirements** are in [requirements.csv](docs/requirements.csv). Passing the included software tests does not close hardware, organisational, legal, real-system, or independent-assessment requirements.
