# Invariant Fabric — Software Requirements Specification & System Architecture

![Invariant Fabric](assets/invariant-fabric-banner.png)

**Software Requirements Specification & System Architecture**

Normative product definition for the Invariant Fabric platform

| **DOCUMENT** | **VERSION** | **DATE** |
|---|---|---|
| IF-02 | Founder Working Package v0.9 | 15 August 2026 |

| **Legal founder identity**         | Habriel Dubov                                                                                                                                                                   |
|------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Professional / public identity** | Habriel Stark                                                                                                                                                                   |
| **Founder roles**                  | Founder; Executive Chair; Chief Executive Officer; Chief Product Officer; Chief Systems Architect; Interim Chief Technology Officer; Interim Chief Information Security Officer |
| **Proposed contracting entity**    | \[LEGAL ENTITY TO BE INCORPORATED\]                                                                                                                                             |
| **Classification**                 | CONFIDENTIAL — FOUNDER WORKING MATERIAL                                                                                                                                         |

*Requirements language: SHALL = mandatory; SHOULD = target unless waived; MAY = optional.*

*Aligned structurally to ISO/IEC/IEEE 29148:2018 and architecture viewpoints to ISO/IEC/IEEE 42010:2022.*

**Founder notice**

Habriel Dubov is the legal identity used in formal documents. “Habriel Stark” is the preferred professional and public identity. No document in this package creates a legal entity, guarantees regulatory approval, or replaces advice from licensed counsel, tax advisers, auditors or qualified security assessors.

# Document map

| **Section**                                 | **Purpose**                                                                  |
|---------------------------------------------|------------------------------------------------------------------------------|
| 1\. Document control and normative language | Authority, versioning and requirement interpretation.                        |
| 2\. Product purpose and scope               | System boundary, users, protected assets and exclusions.                     |
| 3\. Concepts and state model                | Action Capsule, certificate, capability, evidence and decisions.             |
| 4\. Architecture                            | Components, trust boundaries, deployment and data flows.                     |
| 5\. Use cases                               | Finance, data, identity, network, infrastructure, code, secrets and backups. |
| 6\. Functional requirements                 | Numbered SHALL requirements with acceptance criteria.                        |
| 7\. Non-functional requirements             | Security, performance, availability, privacy, operations and compliance.     |
| 8\. Data and interfaces                     | Canonical schemas, APIs, error semantics and compatibility.                  |
| 9\. Failure and recovery behaviour          | Explicit response to outages, uncertainty and compromise.                    |
| 10\. Verification and release gates         | Traceability, tests and phased acceptance.                                   |

# 1. Document control and normative language

| **Attribute**    | **Value**                                                                             |
|------------------|---------------------------------------------------------------------------------------|
| Product          | Invariant Fabric                                                                      |
| Document owner   | Habriel Stark — Founder, Chief Product Officer and Chief Systems Architect            |
| Legal identity   | Habriel Dubov                                                                         |
| Status           | Founder working specification; not yet an executed customer commitment                |
| Version          | Founder Working Package v0.9                                                          |
| Date             | 15 August 2026                                                                        |
| Entity           | \[LEGAL ENTITY TO BE INCORPORATED\]                                                   |
| Normative terms  | SHALL mandatory; SHOULD preferred target; MAY permitted option                        |
| Change authority | Founder proposal; production adoption through valid corporate and security governance |

> **Scope discipline.** This SRS defines the long-term platform and a separately gated finance MVP. Requirements for Secure Perception, full runtime fabric and post-quantum/threshold features do not become MVP promises unless assigned to a release baseline and demonstrated.

# 2. Product purpose and scope

**Purpose.** Invariant Fabric prevents a compromised or deceived person, device, workload, application or AI agent from exercising authority beyond an exact, independently evidenced and policy-compliant action. The system controls execution at resource boundaries rather than relying solely on detection, identity or user vigilance.

| **In scope**                                              | **Out of scope / non-guarantee**                                                                |
|-----------------------------------------------------------|-------------------------------------------------------------------------------------------------|
| Exact high-risk business and machine action authorisation | Detecting every phishing message, deepfake or malicious person.                                 |
| Resource-adjacent Root Gates and coverage proof           | Claiming protection where target systems retain uncontrolled bypass paths.                      |
| Runtime access budgets, segmentation and quarantine       | Preventing every action a legitimately authorised human can perform outside controlled systems. |
| Customer-controlled keys, policy and audit evidence       | Vendor possession of a universal customer master key.                                           |
| Secure Perception research and controlled deployment      | Claiming that an external camera or deliberate memorisation is impossible.                      |
| AI-assisted extraction, simulation and testing            | AI-only root decisions or “all future vulnerabilities found.”                                   |

## 2.1 Stakeholders and user classes

| **Actor**                     | **Responsibilities**                                                | **Trust assumption**                                                   |
|-------------------------------|---------------------------------------------------------------------|------------------------------------------------------------------------|
| Routine operator              | Initiates ordinary business actions and resolves evidence requests. | May be deceived; endpoint/session may be compromised.                  |
| High-risk approver            | Reviews exact material change and provides action-bound approval.   | May be pressured or deceived; independent evidence remains necessary.  |
| Customer policy administrator | Authors and tests tenant policy.                                    | Cannot unilaterally activate root-level changes unless policy permits. |
| Customer key custodian        | Participates in root ceremonies.                                    | Independent failure domain; no standing plaintext access.              |
| Security operations           | Monitors containment, drift, incidents and evidence.                | Privileged but constrained and audited.                                |
| Application/workload/agent    | Requests machine actions.                                           | Potentially compromised; receives narrow capability only.              |
| Invariant support             | Assists deployment and diagnosis.                                   | No standing customer authority or root key.                            |
| Independent assessor          | Tests claims, control design and implementation.                    | Independent from founder/product self-certification.                   |

## 2.2 Crown-jewel resources

| **Resource class**              | **Examples**                                                   | **Primary protected outcomes**                                       |
|---------------------------------|----------------------------------------------------------------|----------------------------------------------------------------------|
| Money and financial master data | Vendor records, beneficiaries, payments, treasury instructions | No unauthorised recipient/state/amount; exact outcome verification.  |
| Data                            | Databases, files, customer records, analytics, exports         | Minimum necessary access; slow-drip control; destination binding.    |
| Identity                        | MFA, sessions, roles, administrators, service identities       | No ambient admin; protected recovery and enrolment.                  |
| Network and services            | Endpoints, internal APIs, east-west traffic                    | Contain lateral movement and internal DoS/DDoS.                      |
| Cloud and infrastructure        | IAM, firewall, compute, DNS, storage                           | Prevent destructive or exposure-causing changes.                     |
| Code and build                  | Repositories, CI/CD, release keys, packages                    | Bind reviewed source/build/artifact/target and protect supply chain. |
| Secrets                         | API keys, tokens, signing material, database credentials       | Brokered or short-lived use; no broad extraction.                    |
| Backups and recovery            | Snapshots, archives, recovery roots                            | Isolated, immutable and threshold-protected destructive actions.     |

# 3. Core concepts and state model

```text
PROPOSED → CANONICALISED → EVIDENCED → EVALUATED
→ {ALLOW | SHIELD | ESCROW | DEFER | DENY}
→ CERTIFIED → EXECUTING → {VERIFIED | UNCERTAIN | FAILED | COMPENSATED}

No valid certificate + protected action = no execution.
```

| **Term**            | **Definition**                                                                                                   |
|---------------------|------------------------------------------------------------------------------------------------------------------|
| Action Capsule      | Versioned canonical representation of the exact requested action and relevant current state.                     |
| Evidence Graph      | Signed/provenanced evidence and dependency structure used to test independent trust domains.                     |
| Policy Constitution | Deterministic rules controlling actions and governing changes to the rules themselves.                           |
| Action Certificate  | Cryptographic statement that the exact capsule passed the named policy under the named evidence and constraints. |
| Capability          | Short-lived, least-authority permission usable by a subject at a specific gate.                                  |
| Commit Gate         | Enforces rare high-impact state changes and may mint/consume action certificates.                                |
| Runtime Gate        | Enforces high-frequency data, network, service and workload capability rules locally.                            |
| Root Gate           | Minimal resource-adjacent gate holding or mediating the credential needed to affect the crown jewel.             |
| Coverage Manifest   | Signed declaration and evidence of which paths are enforced, monitored, uncovered or unknown.                    |
| Secure Perception   | Trusted path that allows authorised human perception without exposing plaintext to the general-purpose OS.       |

# 4. System architecture

![Invariant Fabric reference architecture](assets/invariant-fabric-reference-architecture.png)

*Logical architecture and primary trust boundaries.*

## 4.1 Component responsibilities

| **Component**                    | **Mandatory responsibility**                                                       | **Must not do**                                                                             |
|----------------------------------|------------------------------------------------------------------------------------|---------------------------------------------------------------------------------------------|
| Control Plane                    | Tenant configuration, schema/policy lifecycle, evidence orchestration, dashboards. | Be required for every runtime dataplane decision or hold universal customer root authority. |
| Coverage Mapper                  | Path inventory, evidence freshness, drift and claim status.                        | Convert manual assertion into enforced status.                                              |
| Intent Compiler                  | Extract proposed action from user/UI/document/API input.                           | Authorise action or define final canonical state from untrusted prose alone.                |
| Policy Engine                    | Deterministically evaluate predicates and produce reasoned state.                  | Call an LLM for the root decision.                                                          |
| Evidence Service                 | Acquire, validate, minimise and graph evidence.                                    | Treat dependent evidence as independent.                                                    |
| Capability / Certificate Service | Mint scoped signed authority after successful evaluation.                          | Issue authority broader than the capsule or policy.                                         |
| Commit / Root Gate               | Verify, execute atomically, reconcile and report outcome.                          | Trust caller session as sufficient authority.                                               |
| Runtime Gate                     | Enforce cached local capabilities, rate and containment.                           | Depend on vendor cloud for each packet/query.                                               |
| Transparency Service             | Append, witness, export and verify action-chain evidence.                          | Store unnecessary plaintext as integrity metadata.                                          |
| Secure Perception Component      | Attest, decrypt, display and accept trusted input.                                 | Expose protected plaintext to ordinary OS memory/DOM/clipboard.                             |
| AI Advisory Plane                | Extract, explain, simulate and red-team.                                           | Mint root authority or bypass deterministic policy.                                         |

## 4.2 Deployment modes

| **Mode**                     | **Control plane**                           | **Dataplane / keys**                                                 | **Assurance position**                                      |
|------------------------------|---------------------------------------------|----------------------------------------------------------------------|-------------------------------------------------------------|
| Managed SaaS + customer gate | Vendor-hosted multitenant control services. | Customer network/VPC gate; customer root; target credential at gate. | Default mid-market path.                                    |
| Dedicated VPC                | Dedicated customer environment.             | Customer-controlled gates, HSM/KMS and private connectivity.         | Enterprise regulated path.                                  |
| Self-hosted / sovereign      | Customer operates control and dataplane.    | Customer owns all roots, operations and update acceptance.           | Highest isolation; greatest operational burden.             |
| Pilot shadow mode            | Vendor or customer control plane.           | Read-only/dry-run gate; no mutation authority.                       | Measures policy and friction without enforcement guarantee. |

## 4.3 Trust boundaries

- TB-1: user and communication inputs to Intent Compiler are attacker-controlled.

- TB-2: general-purpose endpoint OS is not trusted for protected plaintext or action semantics in Secure Perception mode.

- TB-3: customer control plane and vendor SaaS are separate from customer root signing authority.

- TB-4: calling applications and workloads are not trusted to enforce their own access limits.

- TB-5: Root Gate to crown-jewel resource is the final enforcement boundary and must be technically non-bypassable for a guarantee.

- TB-6: external evidence sources may be unavailable, compromised or correlated; independence and freshness are explicit.

- TB-7: software supply chain, updates, HSM/TEE firmware and deployment configuration are part of the trusted computing base and require lifecycle controls.

# 5. Principal use cases

| **ID / scenario**                | **Nominal protected flow**                                                                                                                                                                             |
|----------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| UC-01 Vendor bank-detail change  | Finance operator proposes old→new account; independent bank/counterparty evidence is collected; policy applies cooldown and separation; exact change executes; first payment remains separately gated. |
| UC-02 First payment after change | Payment capsule binds amount, currency, beneficiary, invoice/contract, budget and state; high-risk approval is action-bound; bank result is reconciled.                                                |
| UC-03 Sensitive data export      | Data gate applies row/column/purpose/destination limits and rolling budgets; exceptional bulk export enters escrow with exact destination and expiry.                                                  |
| UC-04 Slow-drip exfiltration     | Overlapping small queries accumulate information-value budget until throttled or blocked.                                                                                                              |
| UC-05 Helpdesk recovery          | Reset, new authenticator enrolment and privilege restoration are distinct actions requiring phishing-resistant and independent recovery evidence.                                                      |
| UC-06 Internal worm / DDoS       | Workstation peer scanning and excess service fan-out exceed capability envelope; local gate drops traffic and quarantines the device.                                                                  |
| UC-07 Ransomware containment     | Mass writes are throttled; device/workload is quarantined; backup deletion remains threshold-protected and isolated.                                                                                   |
| UC-08 Cloud exposure             | Firewall/IAM change is canonicalised, simulated and denied when it violates constitution; no admin session bypasses resource gate.                                                                     |
| UC-09 Production release         | Certificate binds source commit, build provenance, artifact digest, test result, signer and deployment target.                                                                                         |
| UC-10 AI agent action            | Agent proposes tool call; receives only action-specific capability; model output remains advisory and rate/volume constrained.                                                                         |
| UC-11 Secure Perception          | Attested protected component receives encrypted fields and renders them without ordinary OS plaintext access.                                                                                          |
| UC-12 Root policy change         | Exact policy diff is simulated, delayed and activated only by customer threshold governance.                                                                                                           |

# 6. Functional requirements

**This baseline contains 166 functional requirements.** Each requirement is normative only when included in the applicable release baseline or contract. Acceptance statements describe the minimum verification evidence.

## Coverage and guarantee control

| **ID**  | **Normative requirement**                                                                                                                                                                                                      | **Minimum acceptance evidence**                                                                              |
|---------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------|
| COV-001 | The system SHALL maintain a versioned inventory of every declared execution path for each protected action, including web UI, mobile, API, CLI, batch, import, service account, direct database, recovery and emergency paths. | A test tenant shows every configured path with owner, target, last evidence time and status.                 |
| COV-002 | Every path SHALL be labelled ENFORCED, MONITORED, UNCOVERED or UNKNOWN; no other state may be represented as protected.                                                                                                        | API and UI reject a “protected” badge when any required path is UNCOVERED or UNKNOWN.                        |
| COV-003 | The Coverage Mapper SHALL record the evidence supporting ENFORCED status, including connector configuration, credential ownership, target rejection behaviour and last negative test.                                          | An assessor can export the evidence bundle and reproduce the rejection test.                                 |
| COV-004 | The system SHALL detect drift in relevant target configuration, credentials, permissions, endpoints and integration versions.                                                                                                  | A controlled configuration change moves the affected path to UNKNOWN within the configured detection window. |
| COV-005 | The system SHALL block publication of an enforcement guarantee when evidence is stale beyond the customer-defined maximum age.                                                                                                 | Expired evidence automatically changes the claim state and generates an owner task.                          |
| COV-006 | Coverage status SHALL be scoped by tenant, action type, target instance, environment and connector version.                                                                                                                    | Two environments can hold different coverage states without cross-contamination.                             |
| COV-007 | The platform SHALL expose a machine-readable Coverage Manifest signed by the customer trust root or delegated policy key.                                                                                                      | Manifest signature verifies independently and includes all scoped paths.                                     |
| COV-008 | The Coverage Mapper SHALL support manual declarations only as MONITORED or UNKNOWN until technical enforcement evidence is attached.                                                                                           | A manual checkbox alone cannot produce ENFORCED.                                                             |
| COV-009 | The system SHALL retain historical coverage states and the exact time intervals in which guarantees were active.                                                                                                               | Audit query reconstructs coverage at an arbitrary historical timestamp.                                      |
| COV-010 | The system SHALL provide a pre-deployment bypass-test plan for every newly declared protected action.                                                                                                                          | Connector cannot enter production without test cases assigned and executed.                                  |

## Canonical Action Capsules

| **ID**  | **Normative requirement**                                                                                                                                                                                                                                                            | **Minimum acceptance evidence**                                                               |
|---------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------|
| ACT-001 | Every protected operation SHALL be represented as a Canonical Action Capsule before policy evaluation.                                                                                                                                                                               | Equivalent inputs canonicalise to the same stable representation and hash.                    |
| ACT-002 | The Action Capsule SHALL include tenant, actor, device/workload, action type, target resource, current state version, requested state, destination, quantity/volume, purpose, evidence references, policy version, nonce, issue time, expiry and rollback metadata where applicable. | Schema validator rejects a capsule missing a mandatory field for its action class.            |
| ACT-003 | Canonicalisation SHALL use deterministic field ordering, type rules, normalisation and versioned schemas.                                                                                                                                                                            | Cross-language reference implementations produce identical test-vector hashes.                |
| ACT-004 | The Action Capsule SHALL bind both the current state and proposed state for mutating actions.                                                                                                                                                                                        | A state change between approval and execution invalidates the certificate.                    |
| ACT-005 | The system SHALL distinguish request intent, authorised action and observed outcome as separate signed objects.                                                                                                                                                                      | Audit chain contains three linked records and detects a mismatched outcome.                   |
| ACT-006 | Free-form text SHALL never be the sole authoritative representation of a protected action.                                                                                                                                                                                           | Policy engine consumes typed fields rather than LLM prose.                                    |
| ACT-007 | Unknown or ambiguous values in a safety-relevant field SHALL produce ESCROW or DENY, never silent default ALLOW.                                                                                                                                                                     | Fuzz tests show all unknown enum values fail safely.                                          |
| ACT-008 | Every Action Capsule SHALL carry a schema identifier and schema digest.                                                                                                                                                                                                              | A verifier rejects unsupported or tampered schema versions.                                   |
| ACT-009 | Action schemas SHALL support nested resource scopes and explicit exclusions.                                                                                                                                                                                                         | A data export can permit named columns while explicitly denying payment tokens.               |
| ACT-010 | The platform SHALL provide human-readable rendering generated from the same canonical fields used for signing.                                                                                                                                                                       | Changing a rendered safety-relevant value changes the signed digest.                          |
| ACT-011 | Action Capsule identifiers SHALL be globally unique within a tenant and collision-resistant.                                                                                                                                                                                         | Duplicate capsule submission is detected and rejected.                                        |
| ACT-012 | The platform SHALL support action composition while preventing a composed action from silently acquiring authority not present in its children.                                                                                                                                      | A multi-step workflow is denied when any child capability is missing or broader than allowed. |

## Independent evidence graph

| **ID**  | **Normative requirement**                                                                                                                                | **Minimum acceptance evidence**                                                                                |
|---------|----------------------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------------------------------------------------------------------------|
| EVD-001 | Policy SHALL evaluate evidence by type, issuer, freshness, scope, confidence and trust domain.                                                           | Policy tests distinguish two pieces of evidence from the same compromised domain from two independent domains. |
| EVD-002 | The Evidence Graph SHALL model dependency relationships so derivative evidence does not count as independent.                                            | An invoice parsed from an email and the email itself count as one source domain.                               |
| EVD-003 | Every evidence item SHALL have an immutable reference, content digest, acquisition time, expiry and verification method.                                 | Tampered evidence fails digest verification and invalidates dependent decisions.                               |
| EVD-004 | The system SHALL support customer-defined authoritative sources such as ERP, bank, HRIS, device attestation, legal registry and counterparty credential. | Policy can require one item from each selected domain.                                                         |
| EVD-005 | Communication channels SHALL default to explanatory evidence with zero authorising weight unless explicitly and narrowly configured.                     | A valid CEO email alone cannot satisfy a high-risk action policy.                                              |
| EVD-006 | Evidence acquisition SHALL be purpose-limited and minimise stored content.                                                                               | The system stores extracted fields and digest when full content is not required.                               |
| EVD-007 | Evidence freshness requirements SHALL be action-specific.                                                                                                | A bank-ownership proof can expire sooner than a corporate registration proof.                                  |
| EVD-008 | Evidence revocation SHALL invalidate all unexecuted certificates that depended on it.                                                                    | Revoking a counterparty credential blocks pending actions immediately.                                         |
| EVD-009 | The platform SHALL distinguish missing evidence, conflicting evidence and unverifiable evidence in operator output.                                      | Each state results in a different machine-readable reason code.                                                |
| EVD-010 | Evidence connectors SHALL expose provenance and transformation steps.                                                                                    | An auditor can determine whether a field came directly from the source or an AI extraction.                    |
| EVD-011 | AI-derived evidence SHALL be marked advisory and SHALL require deterministic or authoritative corroboration for high-risk actions.                       | Removing corroboration changes decision from ALLOW to ESCROW or DENY.                                          |

## Deterministic policy constitution

| **ID**  | **Normative requirement**                                                                                                                                         | **Minimum acceptance evidence**                                                 |
|---------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------|---------------------------------------------------------------------------------|
| POL-001 | Policy evaluation SHALL be deterministic for the same capsule, evidence set, policy version and trusted time.                                                     | Repeated offline evaluation produces identical result and explanation.          |
| POL-002 | Policy decisions SHALL be one of ALLOW, SHIELD, ESCROW, DEFER or DENY.                                                                                            | No undefined decision reaches an execution gate.                                |
| POL-003 | ALLOW SHALL mean all mandatory conditions are met and the exact action may proceed.                                                                               | Certificate issuance is possible only for ALLOW.                                |
| POL-004 | SHIELD SHALL allow the action only after automatic risk-reducing transformation such as redaction, limit reduction, destination substitution or sandboxing.       | Transformed capsule differs explicitly and requires re-evaluation.              |
| POL-005 | ESCROW SHALL hold the action pending required evidence or independent approval.                                                                                   | Pending action cannot execute and has an owner, expiry and reason.              |
| POL-006 | DEFER SHALL impose a defined time or state condition before re-evaluation.                                                                                        | Action remains non-executable until the timer/state predicate is met.           |
| POL-007 | DENY SHALL permanently reject the evaluated action instance and record a reason.                                                                                  | The same capsule nonce cannot be resubmitted after DENY.                        |
| POL-008 | Policies SHALL be versioned, signed, testable and deployable through staged environments.                                                                         | Production policy version maps to a reviewed commit and signature.              |
| POL-009 | Safety-relevant policy changes SHALL themselves be protected actions.                                                                                             | Changing an export limit requires a PolicyChange capsule and governance route.  |
| POL-010 | The system SHALL render an exact policy diff and simulated impact before activation.                                                                              | Reviewer sees affected action classes, tenants and historical decisions.        |
| POL-011 | Policies SHALL support separation of duties, rolling budgets, cool-down periods, threshold approvals, destination allowlists, device health and state predicates. | Each control has executable test cases.                                         |
| POL-012 | No single vendor-controlled credential SHALL be able to activate a customer root policy.                                                                          | Vendor compromise simulation cannot satisfy activation threshold.               |
| POL-013 | Emergency policies SHALL be pre-defined, narrow, expiring and observable; no universal bypass SHALL exist.                                                        | Emergency test proves scope, expiry and alerts.                                 |
| POL-014 | Policy rollback SHALL require protection equivalent to activation and SHALL not revive revoked keys or invalid evidence.                                          | Rollback tests preserve revocations and audit continuity.                       |
| POL-015 | Every decision SHALL include machine-readable reasons and a concise human explanation derived from deterministic evaluation.                                      | Operator can see failed predicates without exposing unnecessary sensitive data. |

## Commit and Root Gate execution

| **ID**  | **Normative requirement**                                                                                                                               | **Minimum acceptance evidence**                                              |
|---------|---------------------------------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------|
| COM-001 | A Commit Gate SHALL reject every protected mutation that lacks a valid Action Certificate.                                                              | Direct API call without certificate fails even with a valid user session.    |
| COM-002 | An Action Certificate SHALL bind capsule hash, policy version, evidence graph digest, signer set, target gate, nonce, expiry and execution constraints. | Changing any bound field invalidates verification.                           |
| COM-003 | Certificates SHALL be single-use unless an action schema explicitly permits bounded repeated use.                                                       | Replay of a consumed certificate is rejected.                                |
| COM-004 | The gate SHALL verify trusted time, certificate revocation and target state immediately before execution.                                               | Expired, revoked and stale-state certificates fail.                          |
| COM-005 | Execution SHALL be atomic or use a documented compensating transaction when atomicity is unavailable.                                                   | Failure injection leaves either no change or a verified compensation record. |
| COM-006 | The gate SHALL enforce idempotency for retryable actions.                                                                                               | Network retry cannot create duplicate vendor, beneficiary or payment.        |
| COM-007 | The target-facing credential SHALL be held by the Root/Commit Gate where technically possible, not by the calling application.                          | Compromised application cannot directly authenticate to the resource.        |
| COM-008 | The gate SHALL minimise target credential scope to the protected action set.                                                                            | Credential cannot perform an unrelated administrator operation.              |
| COM-009 | The system SHALL verify the observed target outcome against the authorised action.                                                                      | A deliberately altered downstream response triggers incident status.         |
| COM-010 | Execution result SHALL be signed and linked to the certificate.                                                                                         | Independent verifier reconstructs the chain.                                 |
| COM-011 | The gate SHALL support a dry-run mode that never mutates the target.                                                                                    | Pilot can measure decisions safely.                                          |
| COM-012 | The gate SHALL expose explicit timeout and uncertain-outcome states; it SHALL not automatically assume success.                                         | Injected timeout produces reconciliation rather than duplicate retry.        |
| COM-013 | High-risk actions SHALL support deliberate delay and cancellation windows.                                                                              | A bank-detail change can be cancelled before first-payment eligibility.      |
| COM-014 | The platform SHALL support customer-controlled threshold authorisation for root and critical action classes.                                            | A 3-of-5 test succeeds with any valid three shares and fails with two.       |

## Runtime capability enforcement

| **ID**  | **Normative requirement**                                                                                                                                                                   | **Minimum acceptance evidence**                                                            |
|---------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------|
| RUN-001 | Runtime policy enforcement SHALL execute locally at the endpoint, gateway, service proxy or resource gate; ordinary dataplane decisions SHALL NOT require a round trip to the vendor cloud. | Disconnecting vendor cloud does not interrupt cached permitted runtime traffic.            |
| RUN-002 | Runtime capabilities SHALL bind subject, device/workload, action, resource, destination, volume, rate, time and state.                                                                      | Changing destination or exceeding rate causes enforcement.                                 |
| RUN-003 | Capabilities SHALL be short-lived and continuously renewable only while required health and policy conditions hold.                                                                         | Loss of device attestation prevents renewal.                                               |
| RUN-004 | The system SHALL support immediate revocation with bounded propagation time.                                                                                                                | Revoked subject loses access within configured SLO.                                        |
| RUN-005 | Local gates SHALL use fail behaviour defined per action class.                                                                                                                              | Test matrix demonstrates fail-closed, cached-allow or constrained fail-open as configured. |
| RUN-006 | Runtime enforcement SHALL expose reason-coded counters without logging sensitive payload by default.                                                                                        | Operations dashboard diagnoses blocks while respecting minimisation.                       |
| RUN-007 | The dataplane SHALL implement resource and tenant isolation.                                                                                                                                | Cross-tenant capability is rejected even with a syntactically valid token.                 |
| RUN-008 | Runtime gates SHALL rate-limit their own control interfaces and resist decision-cache exhaustion.                                                                                           | Adversarial load does not evict critical policy or crash the gate.                         |
| RUN-009 | The system SHALL distinguish policy denial, capacity throttling, quarantine and infrastructure failure.                                                                                     | Clients receive stable, documented error codes.                                            |
| RUN-010 | Every runtime gate SHALL support a signed configuration snapshot and local integrity check.                                                                                                 | Unauthorised local configuration change is detected and gate privileges are withdrawn.     |

## Data protection and information budgets

| **ID**  | **Normative requirement**                                                                                                   | **Minimum acceptance evidence**                                                         |
|---------|-----------------------------------------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------|
| DAT-001 | Data policy SHALL support row, column, field, classification, jurisdiction, purpose and destination constraints.            | A permitted query returns only authorised columns and rows.                             |
| DAT-002 | The system SHALL enforce rolling information budgets across configurable minute, hour, day and month windows.               | Low-and-slow extraction exceeds a cumulative budget and is blocked.                     |
| DAT-003 | Budgets SHALL account for sensitivity or information value, not bytes alone.                                                | A small export of passport records consumes more budget than ordinary marketing assets. |
| DAT-004 | Data capabilities SHALL bind an approved destination or protected output channel.                                           | Export to an unapproved domain or storage account fails.                                |
| DAT-005 | The platform SHALL support automatic SHIELD transformations including masking, aggregation, tokenisation and field removal. | Policy transforms an overbroad export into a compliant result.                          |
| DAT-006 | Query rewriting SHALL preserve database safety and SHALL be verifiable against the authorised schema.                       | Adversarial SQL cannot escape row/column constraints.                                   |
| DAT-007 | Database credentials SHALL be isolated at the data Root Gate where possible.                                                | Application compromise does not reveal reusable database credentials.                   |
| DAT-008 | The system SHALL support bulk-export escrow and exact approval for exceptional legitimate use.                              | Approved export has fixed dataset, fields, row ceiling, destination and expiry.         |
| DAT-009 | The platform SHALL detect repeated overlapping queries intended to reconstruct a restricted dataset.                        | Test sequence triggers cumulative reconstruction control.                               |
| DAT-010 | Data access logs SHALL record policy-relevant metadata and digests while minimising plaintext.                              | Auditor can verify access without receiving full record contents.                       |
| DAT-011 | Protected outputs SHALL support watermarking and user/session attribution where lawful and appropriate.                     | Rendered/exported output identifies authorised session without altering source data.    |
| DAT-012 | The system SHALL support deletion, retention and legal-hold controls for its own evidence store.                            | Retention policy is demonstrable and legal-hold prevents deletion.                      |

## Identity and recovery

| **ID**  | **Normative requirement**                                                                                           | **Minimum acceptance evidence**                                                 |
|---------|---------------------------------------------------------------------------------------------------------------------|---------------------------------------------------------------------------------|
| IDN-001 | Administrative and high-risk actions SHALL require phishing-resistant authentication and action-bound confirmation. | Password/OTP-only test cannot authorise configured high-risk action.            |
| IDN-002 | Authentication SHALL establish identity but SHALL NOT by itself grant protected action authority.                   | Valid login without capability fails at the gate.                               |
| IDN-003 | The platform SHALL support workforce, workload, device and counterparty identities.                                 | Policies can distinguish and combine all four identity classes.                 |
| IDN-004 | Standing administrator access SHALL be minimised in favour of just-in-time, scoped capabilities.                    | Admin privilege expires automatically and cannot be reused outside scope.       |
| IDN-005 | MFA reset, authenticator enrolment and account recovery SHALL be separate protected actions.                        | Helpdesk cannot collapse reset and enrolment into one unlogged operation.       |
| IDN-006 | Recovery SHALL not be weaker than normal authentication for the recovered privilege class.                          | Social-engineering-only recovery fails.                                         |
| IDN-007 | Device health and hardware-backed key status SHALL be bound to high-risk capabilities.                              | Moving the session to an unattested device invalidates capability.              |
| IDN-008 | The system SHALL support rapid identity and device quarantine without deleting evidence.                            | Quarantined identity loses access but audit remains available.                  |
| IDN-009 | Service and API credentials SHALL be short-lived or brokered wherever the target supports it.                       | No long-lived secret is exposed to the application in the reference deployment. |
| IDN-010 | The platform SHALL record identity proofing level and authenticator properties as evidence, not as universal trust. | Policy can require higher proofing for root recovery than routine access.       |

## Network containment

| **ID**  | **Normative requirement**                                                                                                                              | **Minimum acceptance evidence**                                           |
|---------|--------------------------------------------------------------------------------------------------------------------------------------------------------|---------------------------------------------------------------------------|
| NET-001 | Default workstation-to-workstation communication SHALL be denied unless explicitly required.                                                           | Peer scan from an ordinary workstation yields no reachable peers.         |
| NET-002 | The platform SHALL enforce microsegmentation by identity, workload, service and purpose rather than network location alone.                            | Moving a device to another subnet does not expand authority.              |
| NET-003 | Network capabilities SHALL define destination, protocol, service identity, rate envelope and expiry.                                                   | A permitted ERP connection cannot be reused to scan adjacent ports.       |
| NET-004 | Local enforcement SHALL throttle or drop traffic exceeding the configured rate or fan-out envelope.                                                    | Internal DoS simulation is contained at source.                           |
| NET-005 | A device that loses health attestation or disables the endpoint control SHALL lose ordinary network capability and enter constrained remediation mode. | Killing the agent triggers network quarantine rather than protection-off. |
| NET-006 | Quarantine SHALL permit only explicitly defined remediation, security and business-continuity services.                                                | Quarantined device cannot reach databases or peer systems.                |
| NET-007 | The system SHALL support distributed containment that does not depend on a central decision for every packet.                                          | Central controller outage does not remove local limits.                   |
| NET-008 | Network policy changes SHALL be protected actions and tested for unintended exposure.                                                                  | A rule opening a database to 0.0.0.0/0 is denied by constitution.         |
| NET-009 | The system SHALL identify and control east-west traffic generated by service accounts and workloads.                                                   | Compromised workload cannot laterally scan unrelated services.            |
| NET-010 | The runtime shall expose containment time, dropped traffic and affected capabilities for incident analysis.                                            | Incident report reconstructs the containment sequence.                    |

## Secure Perception

| **ID**  | **Normative requirement**                                                                                                                                   | **Minimum acceptance evidence**                                                        |
|---------|-------------------------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------------------------------------------------|
| PER-001 | Protected plaintext SHALL be decrypted only inside an attested trusted component when Secure Perception mode is required.                                   | General-purpose OS memory inspection does not reveal protected test plaintext.         |
| PER-002 | The protected display path SHALL prevent ordinary application screenshot, DOM extraction, clipboard access and accessibility scraping of protected content. | Automated hostile client tests return opaque surface or denied output.                 |
| PER-003 | The trusted component SHALL receive protected content directly from an authenticated service or gate, not from untrusted window content.                    | Malware cannot substitute displayed values without invalidating the trusted session.   |
| PER-004 | The user SHALL have a hardware- or trusted-path-backed indication that Secure Mode is active.                                                               | Untrusted OS overlay cannot reproduce the full trusted indication in the threat model. |
| PER-005 | Safety-relevant input SHALL use a trusted input path when the user is approving or entering protected values.                                               | Key/input interception test does not recover protected entry.                          |
| PER-006 | The platform SHALL minimise content displayed and apply purpose, field and time constraints.                                                                | User sees only data required by the active task.                                       |
| PER-007 | Secure Perception SHALL fail closed when attestation, protected path or version trust fails.                                                                | Modified trusted component receives no decryption material.                            |
| PER-008 | The architecture SHALL document residual risks including external camera, deliberate memorisation, compromised trusted hardware and side channels.          | Product documentation never claims prevention of all visual exfiltration.              |
| PER-009 | Secure Perception SHALL remain an optional gated module until supported hardware and usability meet acceptance criteria.                                    | Finance MVP can ship without falsely depending on unavailable hardware.                |
| PER-010 | The platform SHALL support a fallback controlled workspace or remote-rendering mode with clearly lower assurance classification.                            | Fallback is labelled and policy can forbid it for selected data.                       |

## Keys and cryptographic governance

| **ID**  | **Normative requirement**                                                                                                                                                              | **Minimum acceptance evidence**                                                              |
|---------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------------------------------------------------------|
| KEY-001 | No complete customer root private key SHALL be present in vendor-controlled systems.                                                                                                   | Vendor environment compromise cannot perform root signature.                                 |
| KEY-002 | Customer root operations SHALL support threshold cryptography or threshold-controlled HSM signing.                                                                                     | Configured quorum is required and individual shares never reconstruct in application memory. |
| KEY-003 | Key shares SHALL be separated across independent custodians, devices and failure domains.                                                                                              | Loss/compromise of one location does not meet threshold.                                     |
| KEY-004 | Key generation SHALL use approved cryptographic random generation; optional quantum entropy SHALL be treated as an input to randomness health, not as a substitute for key governance. | Randomness tests and provenance are recorded without overstating “quantum protection.”       |
| KEY-005 | The platform SHALL implement cryptographic agility with versioned algorithms and migration policy.                                                                                     | A test tenant can migrate signing algorithms without losing audit verification.              |
| KEY-006 | Post-quantum algorithms SHALL be introduced according to current standards, interoperability and risk, not marketing labels.                                                           | Algorithm inventory maps each use to approved profile and transition plan.                   |
| KEY-007 | Root, policy, execution, audit and support keys SHALL be logically and operationally separated.                                                                                        | Compromise of support key cannot sign policy or execution.                                   |
| KEY-008 | Keys SHALL have rotation, revocation, backup, destruction and compromise procedures.                                                                                                   | Ceremony evidence and drill records exist.                                                   |
| KEY-009 | Key recovery SHALL require a threshold, delay and out-of-band notification appropriate to the root risk.                                                                               | Two custodians cannot recover a 3-of-5 root.                                                 |
| KEY-010 | The system SHALL publish independent verification material without publishing secret key material.                                                                                     | Third party verifies certificates and transparency proofs offline.                           |
| KEY-011 | HSM and trusted-component firmware/version trust SHALL be policy inputs.                                                                                                               | Known-revoked firmware loses authorisation.                                                  |
| KEY-012 | Key ceremonies SHALL be documented, witnessed and reproducible.                                                                                                                        | Ceremony checklist records participants, devices, hashes and exceptions.                     |

## Audit and transparency

| **ID**  | **Normative requirement**                                                                                                            | **Minimum acceptance evidence**                                            |
|---------|--------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------------------------------------|
| AUD-001 | Security-relevant records SHALL be append-only and cryptographically linked.                                                         | Deletion or modification breaks independently verifiable continuity proof. |
| AUD-002 | The transparency log SHALL record capsule, evidence digest, policy decision, certificate, execution and observed outcome references. | Full action chain is reconstructable.                                      |
| AUD-003 | Sensitive payloads SHALL be minimised, encrypted and access-controlled separately from integrity metadata.                           | Verifier can validate integrity without broad plaintext access.            |
| AUD-004 | Logs SHALL include trusted timestamps and ordering sufficient to detect replay and policy races.                                     | Test replay is identifiable from log state.                                |
| AUD-005 | Customers SHALL be able to export their evidence and verify it without continued vendor availability.                                | Offline verifier validates exported bundle.                                |
| AUD-006 | Audit retention SHALL be configurable by action class, legal basis and customer instruction.                                         | Retention engine applies and records deletion/hold decisions.              |
| AUD-007 | Administrator access to logs SHALL itself be logged and protected.                                                                   | Support access produces immutable record and purpose.                      |
| AUD-008 | The system SHALL support external witness or checkpoint publication for high-assurance tenants.                                      | A forked log is detected by witness comparison.                            |
| AUD-009 | Operational telemetry SHALL separate security evidence from product analytics.                                                       | Disabling optional analytics does not disable required security evidence.  |
| AUD-010 | The platform SHALL provide audit views for finance, security, privacy and technical assessors with least-privilege fields.           | Each role sees only necessary information.                                 |

## AI governance

| **ID**  | **Normative requirement**                                                                                                | **Minimum acceptance evidence**                                        |
|---------|--------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------|
| AIG-001 | AI SHALL NOT independently issue root, policy or high-risk execution authority.                                          | Removing deterministic approval path prevents AI-only execution.       |
| AIG-002 | AI MAY classify intent, extract proposed fields, explain decisions, simulate policy and generate adversarial test cases. | All AI output is marked proposed/advisory until validated.             |
| AIG-003 | AI-derived structured fields SHALL preserve source provenance and uncertainty.                                           | Operator can trace a field to source span and confidence.              |
| AIG-004 | Prompt, model, provider, version and tool context SHALL be recorded for material AI-assisted decisions.                  | Audit can reproduce or compare the advisory step.                      |
| AIG-005 | Customer content SHALL not be used for general model training without explicit lawful agreement.                         | Provider settings and contract evidence support the configured mode.   |
| AIG-006 | Prompt injection and untrusted document content SHALL be treated as attacker-controlled input.                           | Adversarial document cannot change system policy or tool authority.    |
| AIG-007 | AI tools SHALL receive narrow capabilities and output limits.                                                            | Model cannot access unrelated tenant data or execute unapproved calls. |
| AIG-008 | High-impact AI recommendations SHALL be corroborated by deterministic checks or authoritative evidence.                  | AI risk score alone cannot satisfy a mandatory predicate.              |
| AIG-009 | The platform SHALL support disabling AI while preserving core enforcement.                                               | Tenant can run deterministic system with AI unavailable.               |
| AIG-010 | AI safety and performance SHALL be continuously evaluated with versioned test suites.                                    | Model update cannot be promoted without regression report.             |

## Connectors and target integration

| **ID**  | **Normative requirement**                                                                                                                   | **Minimum acceptance evidence**                                              |
|---------|---------------------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------|
| CON-001 | Every connector SHALL declare supported actions, required permissions, target limitations, idempotency behaviour and coverage implications. | Connector manifest is present and signed.                                    |
| CON-002 | Connectors SHALL use least-privilege target credentials and separate read, write and administrative scopes where possible.                  | Permission review shows no unnecessary scope.                                |
| CON-003 | Secrets SHALL be stored in approved secret infrastructure and never logged.                                                                 | Automated tests detect no secret in log or crash dump.                       |
| CON-004 | Connector inputs and target responses SHALL be schema-validated.                                                                            | Malformed target response produces uncertain outcome, not success.           |
| CON-005 | Connectors SHALL implement bounded retries and reconciliation.                                                                              | Failure injection does not duplicate a mutating action.                      |
| CON-006 | Connector upgrades SHALL trigger compatibility, security and coverage revalidation.                                                         | Major target API change moves path to UNKNOWN until tests pass.              |
| CON-007 | The platform SHALL support customer-hosted connectors and gates for high-assurance deployment.                                              | Customer VPC deployment operates without vendor access to target credential. |
| CON-008 | Connector support access SHALL be time-bound, customer-authorised and audited.                                                              | Vendor engineer has no standing access.                                      |
| CON-009 | Connectors SHALL expose health, latency, error and target-rate metrics without exposing unnecessary payload.                                | Operations can diagnose SLA impact safely.                                   |
| CON-010 | Unsupported target capabilities SHALL be surfaced as limitations, never silently emulated with weaker control.                              | UI shows exact limitation and prevents guarantee label.                      |

## User experience and workflow

| **ID** | **Normative requirement**                                                                                                                       | **Minimum acceptance evidence**                                                                |
|--------|-------------------------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------|
| UX-001 | Routine low-risk workflows SHALL require no additional human approval when policy and evidence permit straight-through processing.              | Design-partner workload achieves configured straight-through target.                           |
| UX-002 | Approval UI SHALL present the exact material change, old/new values, amount/volume, destination, evidence gaps, policy consequences and expiry. | User test identifies the changed field without opening source systems.                         |
| UX-003 | Generic “Approve” without transaction detail SHALL not be used for protected actions.                                                           | UI lint/test rejects detail-free critical approval.                                            |
| UX-004 | Approval screens SHALL visually distinguish trusted Secure Mode from ordinary application UI.                                                   | User research demonstrates reliable recognition.                                               |
| UX-005 | Operators SHALL receive concise next actions for ESCROW, DEFER and uncertain outcomes.                                                          | Every state has owner, reason and resolution path.                                             |
| UX-006 | The product SHALL minimise approval fatigue by batching only when individual semantic binding remains clear.                                    | Batch approval shows each action and aggregate constraints; hidden additions invalidate batch. |
| UX-007 | The system SHALL support accessible interfaces while protecting the secure-display threat model.                                                | Accessibility mode is documented with assurance level and tested.                              |
| UX-008 | Customer administrators SHALL be able to simulate policy before enforcement.                                                                    | Historical replay shows projected allow/deny/friction.                                         |
| UX-009 | The UI SHALL display coverage and guarantee scope next to protected workflows.                                                                  | User can see whether action is enforced or only monitored.                                     |
| UX-010 | Error messages SHALL not disclose sensitive policy or resource information to unauthorised users.                                               | Pen-test cases receive safe generic response while authorised operator receives reason.        |

# 7. Non-functional requirements

| **ID**       | **Requirement**                                                                                                                                                          | **Verification**                                   |
|--------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------------|
| NFR-SEC-001  | The default architecture SHALL assume the network, endpoint, user session, calling application and communication channel may be compromised.                             | Threat model review and red-team scenarios.        |
| NFR-SEC-002  | The trusted computing base SHALL be minimised and documented by component and line-of-code estimate.                                                                     | Architecture bill of trust and independent review. |
| NFR-SEC-003  | Security-sensitive code SHALL meet a defined OWASP ASVS profile and secure coding standard.                                                                              | Automated and manual verification report.          |
| NFR-SEC-004  | No production deployment SHALL contain default, shared or hardcoded privileged credentials.                                                                              | Secret scan and deployment test.                   |
| NFR-SEC-005  | All tenant boundaries SHALL be tested against confused-deputy and cross-tenant token attacks.                                                                            | Negative multi-tenant test suite.                  |
| NFR-SEC-006  | The product SHALL support encryption in transit and at rest using current approved profiles and crypto agility.                                                          | Configuration inventory and scanner results.       |
| NFR-SEC-007  | Critical build and release artifacts SHALL be signed and carry provenance.                                                                                               | SLSA-aligned provenance and verification.          |
| NFR-SEC-008  | The SDLC SHALL implement code review, dependency control, secret scanning, SAST, DAST, fuzzing and independent penetration testing.                                      | Release evidence bundle.                           |
| NFR-PERF-001 | Automated Commit Gate evaluation excluding external evidence calls SHOULD target p95 ≤250 ms and p99 ≤750 ms in the reference environment.                               | Benchmark with published hardware and policy set.  |
| NFR-PERF-002 | Cached local runtime decisions SHOULD target p99 ≤1 ms at supported software gates; packet enforcement targets SHALL be set per implementation.                          | Dataplane benchmark under load.                    |
| NFR-PERF-003 | The system SHALL publish external connector latency separately from core policy latency.                                                                                 | Telemetry and benchmark report.                    |
| NFR-PERF-004 | The reference finance gate SHALL sustain at least 100 protected action evaluations per second per gate instance without error.                                           | Load test.                                         |
| NFR-PERF-005 | Runtime enforcement SHALL remain stable under adversarial request and cache-churn load.                                                                                  | Soak and exhaustion test.                          |
| NFR-AVL-001  | Production control services SHOULD target 99.95% monthly availability before enterprise GA; specific SLA appears only after operational evidence.                        | Service metrics and SLA review.                    |
| NFR-AVL-002  | A single vendor-cloud failure SHALL NOT remove already cached local runtime controls.                                                                                    | Disconnection drill.                               |
| NFR-AVL-003  | Critical tenant gates SHALL support multi-zone deployment and state recovery.                                                                                            | Failover test.                                     |
| NFR-AVL-004  | Every action class SHALL have a documented failure policy and maximum stale-policy interval.                                                                             | Failure-mode matrix approved.                      |
| NFR-AVL-005  | Recovery objectives SHALL be tiered: proposed reference RTO 15 minutes for critical gates and RPO near-zero for signed audit metadata, subject to deployment validation. | DR exercise.                                       |
| NFR-PRV-001  | Personal data collection SHALL be purpose-limited and minimised by default.                                                                                              | Data inventory and DPIA.                           |
| NFR-PRV-002  | The system SHALL support regional processing, customer-hosted gates and configurable retention.                                                                          | Deployment and retention tests.                    |
| NFR-PRV-003  | Biometric templates used to unlock local keys SHALL remain in the platform authenticator where supported and SHALL not be ingested by Invariant.                         | Architecture and device API verification.          |
| NFR-PRV-004  | Employee monitoring features SHALL be disabled by default and require lawful basis, transparency and separate configuration.                                             | Product configuration and legal review.            |
| NFR-PRV-005  | Data subject and customer deletion workflows SHALL preserve legally required integrity metadata only where justified.                                                    | Deletion test and policy.                          |
| NFR-OPS-001  | All production changes SHALL use reviewed infrastructure-as-code or equivalent controlled configuration.                                                                 | Change evidence.                                   |
| NFR-OPS-002  | Operational runbooks SHALL cover certificate failure, target uncertainty, gate outage, key compromise, tenant isolation incident and recovery.                           | Runbook exercise.                                  |
| NFR-OPS-003  | High-severity alerts SHALL have defined ownership, acknowledgement and escalation SLOs.                                                                                  | On-call test.                                      |
| NFR-OPS-004  | Customer-visible incidents SHALL be tracked from detection through containment, recovery, root cause and corrective action.                                              | Incident record template.                          |
| NFR-OPS-005  | The platform SHALL support safe staged rollout, canary deployment and immediate rollback of software while preserving policy/key integrity.                              | Release drill.                                     |
| NFR-MNT-001  | Public and internal interfaces SHALL be versioned and backward compatibility documented.                                                                                 | API compatibility test.                            |
| NFR-MNT-002  | Core policy and certificate formats SHALL have independent test vectors and at least two verifier implementations before high-assurance GA.                              | Cross-implementation conformance.                  |
| NFR-MNT-003  | The codebase SHALL maintain a software bill of materials and dependency ownership.                                                                                       | SBOM and update workflow.                          |
| NFR-MNT-004  | Security-critical components SHALL have explicit maintainers and review requirements.                                                                                    | Repository policy.                                 |
| NFR-MNT-005  | Deprecated connector or schema versions SHALL have announced end-of-support and safe migration.                                                                          | Lifecycle record.                                  |
| NFR-USA-001  | Routine users SHOULD complete ordinary protected work without learning cryptographic concepts.                                                                           | Usability test.                                    |
| NFR-USA-002  | Critical approval comprehension SHALL be tested for amount, destination, changed state and consequences.                                                                 | User study threshold.                              |
| NFR-USA-003  | Accessibility SHALL target WCAG 2.2 AA for ordinary interfaces, with documented constraints for trusted hardware UI.                                                     | Accessibility audit.                               |
| NFR-USA-004  | Operators SHALL be able to explain every deterministic decision from stored inputs and policy.                                                                           | Decision replay.                                   |
| NFR-CMP-001  | The platform SHALL maintain a control map to NIST CSF, ISO 27001, GDPR security/privacy-by-design obligations and applicable customer-sector requirements.               | Current control matrix.                            |
| NFR-CMP-002  | Compliance mappings SHALL be labelled support evidence, not automatic certification.                                                                                     | Legal/marketing review.                            |
| NFR-CMP-003  | Vulnerability reporting, coordinated disclosure and product security update processes SHALL be operational before public beta.                                           | Published policy and internal workflow.            |
| NFR-CMP-004  | Security-relevant product changes SHALL be assessed for CRA, NIS2, DORA, AI Act and sector impact as applicable.                                                         | Release compliance checklist.                      |
| NFR-TST-001  | Every SHALL requirement SHALL map to at least one test, inspection, analysis or demonstration method.                                                                    | Traceability export.                               |
| NFR-TST-002  | Release acceptance SHALL include adversarial bypass testing, not only expected-path tests.                                                                               | Red-team report.                                   |
| NFR-TST-003  | Production-like test data SHALL be synthetic or lawfully controlled and isolated.                                                                                        | Test-data review.                                  |
| NFR-TST-004  | Known critical or high-severity exploitable findings SHALL block release unless formally accepted under documented exceptional governance.                               | Release gate evidence.                             |

# 8. Canonical data model

```text
ActionCapsule {
capsule_id, tenant_id, schema_id, schema_digest,
actor {subject_id, identity_class, assurance, device_or_workload},
action {type, target_resource, operation, purpose},
current_state {version, digest, material_fields},
requested_state {material_fields, destination, quantity, exclusions},
evidence_refs[], policy_hint, created_at, expires_at, nonce,
rollback_or_compensation, privacy_classification
}

ActionCertificate {
certificate_id, capsule_digest, evidence_graph_digest,
policy_id, policy_version, decision, constraints,
target_gate_id, signer_set, signature_suite,
issued_at, expires_at, single_use, revocation_ref
}

OutcomeRecord {
certificate_id, target_transaction_id, observed_state_digest,
status {VERIFIED|UNCERTAIN|FAILED|COMPENSATED},
execution_time, reconciliation_evidence, gate_signature
}
```

| **Object**       | **Retention / sensitivity**                              | **Integrity requirement**                                  |
|------------------|----------------------------------------------------------|------------------------------------------------------------|
| Action Capsule   | Action-dependent; may contain personal/business data.    | Canonical digest and versioned schema.                     |
| Evidence content | Store minimum necessary; full source only when required. | Digest, provenance, source signature/verification.         |
| Evidence Graph   | Long-lived decision evidence; usually metadata.          | Signed graph digest and dependency model.                  |
| Policy           | Long-lived and customer-controlled.                      | Signed version, review evidence and activation record.     |
| Certificate      | At least action/audit retention.                         | Independent signature verification and revocation.         |
| Outcome          | At least certificate retention.                          | Gate signature, target reconciliation and append-only log. |
| Telemetry        | Operational retention, minimised.                        | Tenant isolation and access logging.                       |

# 9. External and internal interfaces

| **Interface**            | **Illustrative endpoint / contract**   | **Key rules**                                                 |
|--------------------------|----------------------------------------|---------------------------------------------------------------|
| Propose action           | POST /v1/action-capsules               | Idempotency key, schema validation, no direct authority.      |
| Attach evidence          | POST /v1/action-capsules/{id}/evidence | Provenance, digest, issuer, freshness and minimisation.       |
| Evaluate                 | POST /v1/action-capsules/{id}/evaluate | Deterministic policy version and reason-coded result.         |
| Approve exact action     | POST /v1/approvals                     | Action-bound WebAuthn/hardware signature; signer eligibility. |
| Mint certificate         | POST /v1/certificates                  | Only after ALLOW and required threshold.                      |
| Execute                  | POST /gate/v1/execute                  | Gate verifies state, nonce, expiry, target and constraints.   |
| Reconcile outcome        | GET /gate/v1/outcomes/{id}             | Never infer success from timeout.                             |
| Issue runtime capability | POST /v1/capabilities                  | Short TTL, bound subject/device/resource/rate.                |
| Revoke                   | POST /v1/revocations                   | Immediate signed revocation and propagation status.           |
| Coverage manifest        | GET /v1/coverage/{scope}               | Signed path status and evidence age.                          |
| Audit export             | POST /v1/audit-exports                 | Purpose-limited, encrypted, independently verifiable bundle.  |
| Policy simulation        | POST /v1/policies/simulate             | Historical replay and predicted friction without activation.  |

## 9.1 Error and decision semantics

| **Code**          | **Meaning**                                        | **Caller behaviour**                                  |
|-------------------|----------------------------------------------------|-------------------------------------------------------|
| INV-400-SCHEMA    | Invalid or unsupported canonical schema.           | Correct request; do not retry unchanged.              |
| INV-409-STATE     | Current target state differs from signed state.    | Re-canonicalise and re-evaluate.                      |
| INV-409-REPLAY    | Nonce or certificate already consumed.             | Treat as security-relevant; do not retry.             |
| INV-412-EVIDENCE  | Required evidence missing, expired or conflicting. | Resolve evidence / remain in escrow.                  |
| INV-423-DEFER     | Policy time/state condition not yet met.           | Wait until supplied condition.                        |
| INV-429-BUDGET    | Rate or rolling information budget exceeded.       | Throttle, reduce scope or request exceptional action. |
| INV-451-POLICY    | Action denied by deterministic policy.             | No automatic override.                                |
| INV-503-GATE      | Gate unavailable; failure policy applies.          | Use local cache/alternate gate only as preconfigured. |
| INV-599-UNCERTAIN | Execution result cannot be confirmed.              | Reconcile; never blindly repeat mutating action.      |

# 10. Failure, compromise and recovery behaviour

| **Condition**                     | **Required system response**                                                                                                        | **Forbidden response**                                            |
|-----------------------------------|-------------------------------------------------------------------------------------------------------------------------------------|-------------------------------------------------------------------|
| Vendor cloud unavailable          | Local gates continue valid cached runtime decisions; new critical actions follow configured fail policy.                            | Disabling all enforcement or silently accepting new root actions. |
| Gate unavailable                  | Route to independent healthy gate where safe; otherwise fail closed for critical actions and surface business-continuity procedure. | Universal admin bypass.                                           |
| Evidence source unavailable       | Use fresh cached evidence only if policy permits; otherwise ESCROW/DEFER.                                                           | Assume evidence is valid.                                         |
| Target timeout                    | Mark outcome UNCERTAIN and reconcile target transaction state.                                                                      | Blind retry of payment or destructive action.                     |
| Endpoint agent disabled           | Withdraw renewal and quarantine via independent network/resource gate.                                                              | Protection-off while access remains.                              |
| Vendor control-plane compromise   | Revoke vendor credentials, preserve customer roots and continue customer-controlled gates.                                          | Vendor-issued root policy activation.                             |
| Customer root share compromised   | Revoke share, raise threshold/rotate under ceremony, investigate signed history.                                                    | Reconstruct full root in ordinary application memory.             |
| Policy bug discovered             | Freeze affected action class, simulate corrected policy, threshold-deploy and reconcile exposed interval.                           | Retroactively rewrite audit history.                              |
| Trusted display attestation fails | Withhold decryption and offer lower-assurance fallback only if policy allows.                                                       | Render plaintext through untrusted OS while claiming Secure Mode. |
| Suspected cross-tenant event      | Contain affected service, preserve evidence, rotate relevant material and notify per legal/contract process.                        | Continue normal operation without scoping.                        |

# 11. Verification strategy and traceability

| **Method**                  | **Used for**                                                                                          | **Required artefact**                         |
|-----------------------------|-------------------------------------------------------------------------------------------------------|-----------------------------------------------|
| Test                        | Deterministic functions, APIs, policy, canonicalisation, replay and failure behaviour.                | Automated result linked to requirement ID.    |
| Adversarial test / red team | Bypass, compromised account/application, prompt injection, lateral movement, low-and-slow extraction. | Attack narrative, evidence and residual risk. |
| Analysis                    | Cryptography, availability, privacy, threat model and capacity.                                       | Reviewed analysis with assumptions.           |
| Inspection                  | Configuration, key ceremony, code review, evidence bundle and legal controls.                         | Signed checklist / report.                    |
| Demonstration               | Human approval comprehension, recovery ceremony, customer workflow and controlled failure.            | Recorded result and acceptance sign-off.      |
| Independent assessment      | High-assurance claims and production readiness.                                                       | Third-party report; remediation evidence.     |

> **Traceability rule.** No SHALL requirement is complete until it maps to a test, inspection, analysis or demonstration, an owner, a release baseline and stored evidence. Requirement count is not progress; verified behaviour is progress.

# 12. Release baselines and acceptance gates

| **Baseline**                      | **Included scope**                                                                                | **Exit gate**                                                                   |
|-----------------------------------|---------------------------------------------------------------------------------------------------|---------------------------------------------------------------------------------|
| R0 — Falsification prototype      | Action Capsule, deterministic policy, certificate, one Root Gate, replay/state tests.             | Direct bypass rejected; exact action/state binding proven.                      |
| R1 — Finance design-partner pilot | Vendor/bank/beneficiary/first-payment schemas; shadow and limited enforcement; local gate; audit. | Paid pilot; routine friction measured; target uncertainty safe.                 |
| R2 — Finance production           | Tenant isolation, multi-zone, customer keys, incident/DR, external assessment, coverage proof.    | No unresolved exploitable critical/high findings; signed production acceptance. |
| R3 — Data / identity              | Database/file Root Gate, rolling budgets, recovery and JIT identity.                              | Low-and-slow and recovery red-team pass.                                        |
| R4 — Runtime Fabric               | Network/workload local gates, quarantine and rate envelopes.                                      | Internal worm/DoS contained under benchmark.                                    |
| R5 — Secure Perception            | Attested display/input path on supported hardware.                                                | OS extraction tests fail; usability and residual-risk disclosure accepted.      |

# 13. Finance MVP explicit boundary

| **In MVP**                                                   | **Not an MVP dependency**                            |
|--------------------------------------------------------------|------------------------------------------------------|
| One ERP/vendor master connector                              | Universal ERP support                                |
| One bank/payment connector or controlled execution simulator | All banks and payment rails                          |
| Four finance action schemas                                  | Full data/network/identity platform                  |
| Coverage Mapper for the selected workflow                    | Company-wide discovery                               |
| Customer-hosted Root Gate and exact certificate              | Custom hardware secure display                       |
| Policy simulation, shadow mode and controlled production     | Post-quantum migration completed for every component |
| WebAuthn/hardware-backed exact approval                      | AI autonomous decision authority                     |
| Append-only evidence export and outcome reconciliation       | Public blockchain dependency                         |

# 14. Open design decisions requiring prototype evidence

| **Decision**               | **Options**                                                                     | **Required evidence before commitment**                                 |
|----------------------------|---------------------------------------------------------------------------------|-------------------------------------------------------------------------|
| Certificate encoding       | CBOR/COSE, canonical JSON/JWS, protobuf + signed envelope                       | Cross-language canonicalisation, hardware support, audit usability.     |
| Policy engine              | Purpose-built DSL, Cedar/Rego-based restricted profile, formally specified core | Determinism, explainability, performance, safety of extensions.         |
| Root Gate deployment       | Sidecar, proxy, target plugin, transaction broker                               | Total mediation, latency, target credential ownership and failure mode. |
| Threshold implementation   | MPC threshold signature or HSM quorum wrapper                                   | Standards maturity, vendor interoperability and ceremony complexity.    |
| Transparency log           | Tenant Merkle log, external witness, public checkpoint                          | Privacy, independent verification and operational cost.                 |
| Secure Perception platform | Dedicated hardware, TEE trusted UI, remote-rendered controlled endpoint         | Actual protected path, OS extraction resistance and user acceptance.    |
| Runtime dataplane          | eBPF, service mesh, proxy, switch/NAC integration                               | Latency, tamper resistance and deployment coverage.                     |

# Specification boundaries and professional review

> **Not legal, tax, audit or investment advice.** This package is a founder-grade drafting and planning set. It is not a legal opinion, securities offering document, audit, certification, insurance policy or guarantee of security. Final documents must be tailored by qualified professionals to the selected entity, governing law, customer sector and deployment.

- The proposed entity has not been incorporated in these materials. Replace all bracketed placeholders only after incorporation and counsel review.

- Habriel Dubov is the legal identity. Habriel Stark is the public and professional identity and should not replace the legal name in signatures, statutory filings, banking, tax or employment documents.

- The founder is 16 on the document date. Legal capacity, parental or guardian consent, eligibility to hold corporate offices, beneficial ownership filings and enforceability vary by jurisdiction.

- Operational titles may be held by the founder. Independent roles such as statutory DPO, independent auditor, external counsel, penetration tester and selected key custodians must remain structurally independent where law, assurance or good governance requires it.

- No cybersecurity product is “unhackable.” Claims must be scoped to defined assets, deployment assumptions, verified enforcement coverage and measurable acceptance tests.

- Market, pricing, customer and financial figures are planning assumptions rather than verified bookings or audited forecasts.

# Founder approval of SRS baseline

| **Field**         | **Entry**                                                                        |
|-------------------|----------------------------------------------------------------------------------|
| Legal name        | Habriel Dubov                                                                    |
| Professional name | Habriel Stark                                                                    |
| Proposed entity   | \[LEGAL ENTITY TO BE INCORPORATED\]                                              |
| Capacity          | Founder and proposed executive officer                                           |
| Signature         | \_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_ |
| Date              | \_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_ |

Execution notice: this signature block is a founder acknowledgement only unless and until the relevant agreement is adopted by a valid legal entity and signed by a person with legal capacity and authority. Because the founder is a minor as of the document date, jurisdiction-specific capacity, guardian, corporate office and director requirements must be reviewed by licensed counsel before execution.

# Source register

Primary sources used to frame standards, legal timing and product architecture. Accessed 15 August 2026. Links should be revalidated before a financing, regulatory filing or customer signature.

| **S01** | **ISO/IEC/IEEE 29148:2018 — Requirements engineering — ISO.** <https://www.iso.org/standard/72089.html><br><br>*Current published requirements-engineering reference; revision work may be underway.* |
|---|---|

| **S02** | **ISO/IEC/IEEE 42010:2022 — Architecture description — ISO.** <https://www.iso.org/standard/74393.html> |
|---------|---------------------------------------------------------------------------------------------------------|

| **S03** | **Cybersecurity Framework 2.0 — NIST.** <https://www.nist.gov/cyberframework> |
|---------|-------------------------------------------------------------------------------|

| **S04** | **SP 800-207 — Zero Trust Architecture — NIST.** <https://csrc.nist.gov/pubs/sp/800/207/final> |
|---------|------------------------------------------------------------------------------------------------|

| **S05** | **SP 800-218 — Secure Software Development Framework — NIST.** <https://csrc.nist.gov/pubs/sp/800/218/final> |
|---------|--------------------------------------------------------------------------------------------------------------|

| **S06** | **SP 800-63-4 — Digital Identity Guidelines — NIST.** <https://csrc.nist.gov/pubs/sp/800/63/4/final> |
|---------|------------------------------------------------------------------------------------------------------|

| **S07** | **SP 800-63B-4 — Authentication and authenticator management — NIST.** <https://pages.nist.gov/800-63-4/sp800-63b/authenticators/> |
|---------|------------------------------------------------------------------------------------------------------------------------------------|

| **S08** | **Post-quantum cryptography FIPS standards — NIST.** <https://csrc.nist.gov/News/2024/postquantum-cryptography-fips-approved> |
|---------|-------------------------------------------------------------------------------------------------------------------------------|

| **S09** | **Threshold cryptography project — NIST.** <https://csrc.nist.gov/projects/threshold-cryptography> |
|---------|----------------------------------------------------------------------------------------------------|

| **S10** | **ISO/IEC 27001 — Information security management systems — ISO.** <https://www.iso.org/standard/27001> |
|---------|---------------------------------------------------------------------------------------------------------|

| **S11** | **ISO/IEC 27701 — Privacy information management systems — ISO.** <https://www.iso.org/standard/27701> |
|---------|--------------------------------------------------------------------------------------------------------|

| **S12** | **ISO 22301 — Business continuity management systems — ISO.** <https://www.iso.org/standard/75106.html> |
|---------|---------------------------------------------------------------------------------------------------------|

| **S13** | **Application Security Verification Standard — OWASP.** <https://owasp.org/www-project-application-security-verification-standard/> |
|---------|-------------------------------------------------------------------------------------------------------------------------------------|

| **S14** | **Supply-chain Levels for Software Artifacts v1.1 — OpenSSF / SLSA.** <https://slsa.dev/spec/v1.1/> |
|---------|-----------------------------------------------------------------------------------------------------|

| **S15** | **Zero Trust Microsegmentation Guidance — CISA.** <https://www.cisa.gov/news-events/alerts/2025/07/29/cisa-releases-part-one-zero-trust-microsegmentation-guidance> |
|---------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------|

| **S16** | **Product Security Bad Practices guidance — CISA / FBI.** <https://www.cisa.gov/news-events/alerts/2025/01/17/cisa-and-fbi-release-updated-guidance-product-security-bad-practices> |
|---------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|

| **S19** | **General Data Protection Regulation — European Union.** <https://eur-lex.europa.eu/eli/reg/2016/679/oj> |
|---------|----------------------------------------------------------------------------------------------------------|

| **S20** | **Data Protection Officer independence guidance — European Data Protection Board.** <https://www.edpb.europa.eu/sme/be-compliant/data-protection-officer_en> |
|---------|--------------------------------------------------------------------------------------------------------------------------------------------------------------|

| **S21** | **Directive (EU) 2022/2555 — NIS2 — European Union.** <https://eur-lex.europa.eu/eli/dir/2022/2555/oj> |
|---------|--------------------------------------------------------------------------------------------------------|

| **S22** | **Regulation (EU) 2022/2554 — DORA — European Union.** <https://eur-lex.europa.eu/eli/reg/2022/2554/oj> |
|---------|---------------------------------------------------------------------------------------------------------|

| **S23** | **EU AI Act regulatory framework and timeline — European Commission.** <https://digital-strategy.ec.europa.eu/en/policies/regulatory-framework-ai> |
|---------|----------------------------------------------------------------------------------------------------------------------------------------------------|

| **S24** | **Article 50 transparency guidance — European Commission.** <https://digital-strategy.ec.europa.eu/en/news/commission-publishes-guidelines-transparency-obligations-providers-and-deployers-certain-ai-systems> |
|---------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|

| **S25** | **Cyber Resilience Act overview — European Commission.** <https://digital-strategy.ec.europa.eu/en/policies/cyber-resilience-act> |
|---------|-----------------------------------------------------------------------------------------------------------------------------------|

| **S26** | **Cyber Resilience Act reporting obligations — European Commission.** <https://digital-strategy.ec.europa.eu/en/policies/cra-reporting> |
|---------|-----------------------------------------------------------------------------------------------------------------------------------------|

| **S27** | **Secure Payment Confirmation — W3C.** <https://www.w3.org/TR/2026/CRD-secure-payment-confirmation-20260604/> |
|---------|---------------------------------------------------------------------------------------------------------------|

| **S28** | **Web Authentication Level 3 — W3C.** <https://www.w3.org/news/2026/updated-candidate-recommendation-web-authentication-an-api-for-accessing-public-key-credentials-level-3/> |
|---------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|

| **S29** | **Trusted User Interface Protection Profile Module — GlobalPlatform.** <https://globalplatform.org/specs-library/trusted-user-interface-pp-module-v1-0-gpt_spe_142/> |
|---------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------|

| **S30** | **Intel Trust Domain Extensions overview — Intel.** <https://www.intel.com/content/www/us/en/support/articles/000097227/processors/intel-xeon-processors.html> |
|---------|----------------------------------------------------------------------------------------------------------------------------------------------------------------|
