# Security model and review status

**Not independently assessed. Not approved for production.** Security-critical implementation was exercised by focused positive/negative tests, concurrency workers, fault injection, syntax checks, and a small source-pattern scan. These are evidence, not penetration testing, formal verification, ASVS certification, legal compliance or a complete vulnerability audit.

## Assets and adversaries

Assets are tenant action semantics, customer policy, signing authority, protected target state, evidence integrity, replay state and sensitive data. Caller sessions, inputs, network requests, proposed prose and evidence from communication channels are untrusted. The tested local profile assumes the customer host, runtime, local configuration, OS clock and registered public keys have not been compromised. Unlike the complete SRS threat model, it cannot withstand malicious OS memory access or compromise of the process holding execution/audit keys.

A valid session does not execute a protected mutation. Authority additionally requires typed action validation, independently signed scoped evidence, deterministic ALLOW, action-bound eligible signatures, and a short-lived registered single-use certificate. Tenant IDs are derived from authentication and checked again at cryptographic and storage boundaries. Encryption uses per-tenant keys with record-bound associated data. Revocation is monotonic and synchronous within the local state store; there is no remote propagation assurance.

## Implemented safeguards

HTTP uses exact host/origin matching, same-origin-only browser requests, HttpOnly SameSite=Strict sessions, CSRF tokens for cookie-based POSTs, request/header/body time and size limits, role checks, per-address/principal limits and safe generic unexpected-error responses. HTTPS terminates at an explicitly configured trusted staging reverse proxy; local HTTP is loopback-only. No CORS wildcards, browser persistent token storage, dynamic HTML injection, arbitrary SQL, external fetch endpoint, upload execution, hidden root bypass or public privileged default credentials are implemented.

The gate consumes authority before dispatch. Ambiguous target responses never become success and never trigger automatic mutating retries. Certificate registration equality prevents a caller from presenting a differently scoped envelope, even one signed by a local execution key outside the issuance path. It does not defend against full compromise of the trusted process or database/key host.

Software keys are generated using the platform CSPRNG and Ed25519 implementation. Approval and genesis verification require distinct customer failure domains. This is **software multisignature, not threshold cryptography**. Configuring `require_hardware` blocks all default software signers. No self-asserted API parameter can enroll a “hardware-backed” signer.

## Known material limitations

| Boundary | Current position | Required release evidence |
|---|---|---|
| Root keys | Custodian software files; no HSM/MPC adapter | Hardware lifecycle, independent custody, 3-of-5 ceremony, compromise/recovery drills |
| Host compromise | Host/runtime/local configuration is trusted | Reduced privileged gate, target credential ownership, hardened customer deployment and independent red team |
| Production authentication | 24-hour local tokens and static synthetic device-health statements | Real workforce/workload federation, phishing-resistant WebAuthn, attestation, protected enrollment/recovery and JIT lifecycle |
| Clock | Persisted regression check over OS milliseconds | Trusted-time profile, clock uncertainty and forward-jump drills |
| Real targets | Synthetic target only | Named APIs, real least-privilege credentials, timeout contracts, total mediation and bypass tests |
| Secure Perception | Unavailable; fail closed | Supported hardware, trusted display/input and hostile-OS tests |
| Runtime network | Decisions only | Customer network/endpoint integration and packet-level quarantine/DoS tests |
| Audit witness | Offline checkpoint comparison | Independent witness publication, monitoring and retention operations |
| Retention | Logical deletion plus digest tombstones | Per-record crypto-shredding, backup deletion and legal-hold governance |
| Availability | Local SQLite WAL | Multi-zone architecture, state-replication correctness, RTO/RPO and recovery exercises |
| Scale | Bounded engineering UI/query scans | Production-scale audit pagination, storage/rate/cache exhaustion and soak evidence |
| Secure SDLC | Test suite and focused checks | Human maintainers, code review, current advisories, SAST/DAST/fuzz coverage and independent assessment |

## Reporting and release ownership

No operational security-reporting inbox, legal entity, incident team, signer identity or external assessor was provisioned. This is a public-release blocker, not a fictitious security contact. Deployment owners must establish a monitored private reporting channel, acknowledgement/escalation policy and update process before any public beta. Do not send real vulnerabilities or customer data to an unverified address from a draft document.

Do not commit local `var/`, `.env`, database files, access tokens, software private keys or backup material. The distribution contains public synthetic audit examples only. `reports/sbom.cdx.json` inventories the application and tested runtime; it does not replace a transitive runtime/container SBOM or current advisory scan.
