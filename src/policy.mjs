import { digest, clone } from './canonical.mjs';
import { fields, integer, uniqueStrings, oneOf, text } from './schema.mjs';
import { requireThat } from './errors.mjs';

export function defaultPolicy(tenant) {
  const standard = { evidence_kinds: ['ownership'], independent_domains: 2, approval_threshold: 2, approval_role: 'approver', cooldown_ms: 0, max_quantity: 1_000_000_000, require_hardware: false, destinations: [], forbidden_fields: [], max_evidence_age_ms: 3600000 };
  const rules = {};
  for (const type of ['finance.vendor.create', 'finance.bank.change', 'finance.beneficiary.create', 'finance.payment.first', 'data.export', 'identity.mfa.reset', 'identity.authenticator.enroll', 'identity.account.recover', 'identity.jit.grant', 'cloud.firewall.change', 'code.release', 'secret.use', 'backup.delete', 'policy.change', 'key.rotate', 'key.ceremony', 'action.composite', 'ai.model.deploy', 'legal.contract.execute', 'security.case.investigate']) rules[type] = clone(standard);
  rules['finance.bank.change'].cooldown_ms = 60000;
  rules['finance.payment.first'].max_quantity = 10_000_000;
  // DAT-008: exports always pass an explicit approval — a zero-threshold
  // export path is constitutionally disallowed.
  rules['data.export'] = { ...clone(standard), evidence_kinds: ['dataset_authority'], independent_domains: 1, approval_threshold: 1, destinations: ['customer-vault'], forbidden_fields: ['passport', 'payment_token', 'password'], max_quantity: 1000 };
  // EVD binding: for action types where evidence must describe the action's
  // own content (SRS §1 exactness), declare claim-field → capsule-path maps.
  // The fabric overrides those claims at acquisition and requires the signed
  // envelope's claims to match at attach — true-but-irrelevant evidence for
  // a different account/dataset/subject is rejected (issuerd-audit HIGH-2).
  for (const t of ['finance.vendor.create', 'finance.bank.change', 'finance.beneficiary.create', 'finance.payment.first'])
    rules[t].evidence_bindings = { ownership: { account: 'requested_state.bank_account' } };
  rules['data.export'].evidence_bindings = { dataset_authority: { dataset: 'requested_state.dataset' } };
  for (const t of ['identity.mfa.reset', 'identity.authenticator.enroll', 'identity.account.recover', 'identity.jit.grant'])
    rules[t].evidence_bindings = { identity_proof: { subject_id: 'requested_state.subject_id' }, recovery_authority: { subject_id: 'requested_state.subject_id' } };
  rules['secret.use'].evidence_bindings = { workload_attestation: { workload_id: 'requested_state.workload_id' }, device_health: { device_id: 'actor.device_id' } };
  // Governance/payment/device evidence must describe THIS action, not merely
  // be a true statement of the right kind: the review/confirmation/health
  // claim carries the capsule reference (or actor device) it answers for
  // (w5 F-2).
  const governanceBinding = { governance_review: { action_ref: 'capsule_id' } };
  for (const t of ['key.rotate', 'key.ceremony', 'backup.delete', 'policy.change', 'security.case.investigate', 'ai.model.deploy'])
    rules[t].evidence_bindings = { ...(rules[t].evidence_bindings ?? {}), ...governanceBinding };
  rules['finance.payment.first'].evidence_bindings = { ...rules['finance.payment.first'].evidence_bindings, payment_confirmation: { transaction_id: 'capsule_id' } };
  for (const t of ['identity.mfa.reset', 'identity.authenticator.enroll', 'identity.account.recover', 'identity.jit.grant'])
    rules[t].evidence_bindings = { ...rules[t].evidence_bindings, device_health: { device_id: 'actor.device_id' } };
  rules['code.release'].evidence_bindings = { build_provenance: { artifact_digest: 'requested_state.artifact_digest' }, test_result: { test_digest: 'requested_state.test_digest' } };
  rules['ai.model.deploy'].evidence_bindings = { test_result: { test_digest: 'requested_state.test_digest' } };
  rules['legal.contract.execute'].evidence_bindings = { counterparty_credential: { counterparty_id: 'requested_state.counterparty_id' }, legal_registry: { entity: 'requested_state.entity' } };
  for (const t of ['identity.mfa.reset', 'identity.authenticator.enroll', 'identity.account.recover']) rules[t].evidence_kinds = ['identity_proof', 'recovery_authority'];
  rules['code.release'].evidence_kinds = ['build_provenance', 'test_result'];
  rules['secret.use'].evidence_kinds = ['workload_attestation'];
  rules['identity.jit.grant'].evidence_kinds = ['identity_proof'];
  rules['legal.contract.execute'].evidence_kinds = ['counterparty_credential', 'legal_registry'];
  rules['security.case.investigate'] = { ...clone(standard), evidence_kinds: ['governance_review'], approval_threshold: 1 };
  rules['ai.model.deploy'].evidence_kinds = ['test_result', 'governance_review'];
  rules['action.composite'] = { ...clone(standard), evidence_kinds: [], independent_domains: 0, approval_threshold: 2, max_quantity: 16 };
  rules['key.rotate'] = { ...clone(standard), evidence_kinds: ['governance_review'], approval_threshold: 3, approval_role: 'custodian', cooldown_ms: 60000 };
  rules['key.ceremony'] = { ...clone(standard), evidence_kinds: ['governance_review'], approval_threshold: 3, approval_role: 'custodian', cooldown_ms: 120000 };
  for (const t of ['backup.delete', 'policy.change']) { rules[t].approval_threshold = 3; rules[t].approval_role = 'custodian'; rules[t].evidence_kinds = ['governance_review']; rules[t].cooldown_ms = 120000; }
  return { policy_id: `constitution:${tenant}`, tenant_id: tenant, version: 1, not_before: 1, expires_at: 4102444800000, max_capsule_ttl_ms: 3600000, certificate_ttl_ms: 60000, capability_ttl_ms: 60000, mode: 'engineering', rules,
    // RUN-005/NFR-AVL-004: per-class failure mode when the active policy or
    // issuer path is unavailable. 'closed' denies; 'cached-allow' permits a
    // previously issued capability for at most max_stale_ms; 'constrained'
    // permits only reads at half budget.
    fail_modes: { default: 'closed', 'data.read': 'closed', 'service.connect': 'cached-allow' }, max_stale_ms: 300000,
    // Per-class staleness ceilings (NFR-AVL-004): a class may tighten the
    // global max_stale_ms but never loosen it beyond the default window.
    stale_ms: { default: 300000 },
    // POL-013/POL-014: staged rollout and emergency change contracts.
    staged_policy: { min_delay_ms: 60000, emergency_extra_custodians: 1, emergency_max_ttl_ms: 86400000 },
    secure_perception: { enabled: true, allowed_firmware: ['if-secureview-dev-1'], session_ttl_ms: 300000, release_fields: '*', fallback: 'controlled-workspace', required_assurance: 'dev-attested-software' },
    // AUD-006: retention ceilings per evidence class. An envelope may not
    // claim a retention window past its class ceiling.
    retention: { default_ms: 31536000000, per_kind: {} },
    algorithms: { allowed_suites: ['Ed25519'], deprecation: [] },
    runtime: { max_cost: 10000, rate_per_second: 20, max_fanout: 4, windows: [{ duration_ms: 60000, limit: 100 }, { duration_ms: 3600000, limit: 1000 }, { duration_ms: 86400000, limit: 5000 }, { duration_ms: 2592000000, limit: 10000 }], destinations: ['customer-vault', 'erp-service'], services: ['erp-service'], forbidden_columns: ['passport', 'payment_token', 'password'], jurisdictions: ['EU'], purposes: ['operations'], classifications: ['internal'], remediation_services: ['device-wipe', 'mdm-notify'], sensitivity_weights: { internal: 1, confidential: 5, restricted: 10 }, reconstruction: { window_ms: 86400000, max_distinct_rows: 5000, max_distinct_columns: 100, max_coverage_percent: 90 }, network: { deny_workstation_peers: true, allowed_protocols: ['https'], allowed_ports: [443] }, datasets: ['dataset-1'], allowed_columns: ['id', 'name', 'region', 'passport'], allowed_transforms: ['mask', 'tokenise', 'drop', 'constant', 'aggregate'] } };
}
export function validatePolicy(p) {
  fields(p, ['policy_id', 'tenant_id', 'version', 'not_before', 'expires_at', 'max_capsule_ttl_ms', 'certificate_ttl_ms', 'capability_ttl_ms', 'mode', 'rules', 'runtime', 'fail_modes', 'max_stale_ms', 'staged_policy', 'secure_perception', 'algorithms'], ['emergency_of', 'stale_ms', 'retention']);
  text(p.policy_id, 'policy id'); text(p.tenant_id, 'tenant'); integer(p.version, 'version', 1); integer(p.not_before, 'activation time', 1); integer(p.expires_at, 'expiry', p.not_before + 1);
  integer(p.max_capsule_ttl_ms, 'capsule TTL', 1000, 86400000); integer(p.certificate_ttl_ms, 'certificate TTL', 1000, 300000); integer(p.capability_ttl_ms, 'capability TTL', 1000, 300000);
  oneOf(p.mode, ['engineering', 'shadow', 'disabled'], 'deployment mode');
  fields(p.rules, Object.keys(defaultPolicy(p.tenant_id).rules));
  for (const [type, r] of Object.entries(p.rules)) {
    fields(r, ['evidence_kinds', 'independent_domains', 'approval_threshold', 'approval_role', 'cooldown_ms', 'max_quantity', 'require_hardware', 'destinations', 'forbidden_fields', 'max_evidence_age_ms'], ['evidence_bindings', 'identity_classes', 'min_proofing']);
    // evidence_bindings: kind → { claim_field → capsule path }. Each attached
    // envelope of that kind must carry claims equal to the resolved fields.
    if (r.evidence_bindings !== undefined) {
      requireThat(typeof r.evidence_bindings === 'object' && r.evidence_bindings !== null && !Array.isArray(r.evidence_bindings), 'INV-400-SCHEMA', 'evidence_bindings must be an object');
      for (const [kind, map] of Object.entries(r.evidence_bindings)) {
        text(kind, 'evidence binding kind', 128);
        requireThat(typeof map === 'object' && map !== null && !Array.isArray(map) && Object.keys(map).length >= 1 && Object.keys(map).length <= 16, 'INV-400-SCHEMA', 'evidence binding map must list 1-16 claim fields');
        for (const [cf, path] of Object.entries(map)) { text(cf, 'claim field', 128); requireThat(/^(actor\.(subject_id|device_id|identity_class)|action\.(type|target_resource|purpose|destination)|requested_state\.[A-Za-z0-9_-]{1,64}|subject_id|tenant_id|capsule_id)$/.test(path), 'INV-400-SCHEMA', `Invalid evidence binding path ${path}`); }
      }
    }
    // IDN-003/IDN-010 optional admission conditions: restrict which identity
    // classes may propose the action, and a minimum proofing level the
    // actor's identity must carry.
    if (r.identity_classes !== undefined) { uniqueStrings(r.identity_classes, 'identity classes', 8); for (const c of r.identity_classes) oneOf(c, ['workforce', 'workload', 'device', 'counterparty'], 'identity class'); }
    if (r.min_proofing !== undefined) oneOf(r.min_proofing, ['low', 'medium', 'high'], 'minimum proofing');
    uniqueStrings(r.evidence_kinds, 'evidence kinds', 10); integer(r.independent_domains, 'independent domains', type === 'action.composite' ? 0 : 1, 10); integer(r.approval_threshold, 'threshold', ['policy.change', 'backup.delete'].includes(type) ? 3 : 1, 5);
    oneOf(r.approval_role, ['approver', 'custodian'], 'approval role');
    if (['policy.change', 'backup.delete'].includes(type)) requireThat(r.approval_role === 'custodian', 'INV-451-POLICY', 'Root actions require customer custodians', 451);
    integer(r.cooldown_ms, 'cooldown', ['policy.change', 'backup.delete'].includes(type) ? 120000 : 0, 604800000);
    integer(r.max_quantity, 'maximum quantity', 1, 1_000_000_000_000); requireThat(typeof r.require_hardware === 'boolean', 'INV-400-SCHEMA', 'Hardware requirement must be boolean');
    uniqueStrings(r.destinations, 'destinations'); uniqueStrings(r.forbidden_fields, 'forbidden fields'); integer(r.max_evidence_age_ms, 'evidence age', 1000, 2592000000);
  }
  const r = p.runtime;
  fields(r, ['max_cost', 'rate_per_second', 'max_fanout', 'windows', 'destinations', 'services', 'forbidden_columns', 'jurisdictions', 'purposes', 'classifications', 'remediation_services', 'sensitivity_weights', 'reconstruction', 'network', 'datasets', 'allowed_columns', 'allowed_transforms']);
  integer(r.max_cost, 'runtime cost', 1, 1e9); integer(r.rate_per_second, 'runtime rate', 1, 10000); integer(r.max_fanout, 'fanout', 1, 100);
  requireThat(Array.isArray(r.windows) && r.windows.length >= 1 && r.windows.length <= 8, 'INV-400-SCHEMA', 'Invalid budget windows');
  for (const w of r.windows) { fields(w, ['duration_ms', 'limit']); integer(w.duration_ms, 'window duration', 1000, 2592000000); integer(w.limit, 'window limit', 1, 1e12); }
  for (const k of ['destinations', 'services', 'forbidden_columns', 'jurisdictions', 'purposes', 'classifications']) uniqueStrings(r[k], k);
  // NET-005/006: quarantine remediation may only target allowlisted services.
  uniqueStrings(r.remediation_services, 'remediation services', 8);
  fields(r.sensitivity_weights, ['internal', 'confidential', 'restricted']); for (const [k, v] of Object.entries(r.sensitivity_weights)) integer(v, k, 1, 1000);
  fields(r.reconstruction, ['window_ms', 'max_distinct_rows', 'max_distinct_columns', 'max_coverage_percent']);
  integer(r.reconstruction.window_ms, 'reconstruction window', 1000, 2592000000); integer(r.reconstruction.max_distinct_rows, 'rows', 1, 1000000); integer(r.reconstruction.max_distinct_columns, 'columns', 1, 1000); integer(r.reconstruction.max_coverage_percent, 'coverage percent', 1, 100);
  fields(r.network, ['deny_workstation_peers', 'allowed_protocols', 'allowed_ports']);
  requireThat(typeof r.network.deny_workstation_peers === 'boolean' && r.network.allowed_protocols.includes('https') && r.network.allowed_ports.every(x => Number.isSafeInteger(x) && x >= 1 && x <= 65535), 'INV-400-SCHEMA', 'Invalid network policy');
  // Data catalog ceilings: JIT grants and capabilities may only name
  // resources and columns the runtime policy declares (policy-audit F7).
  for (const k of ['datasets', 'allowed_columns']) uniqueStrings(r[k], k);
  uniqueStrings(r.allowed_transforms, 'transforms', 8);
  for (const op of r.allowed_transforms) oneOf(op, ['mask', 'tokenise', 'drop', 'constant', 'aggregate'], 'transform');
  // Fail modes (RUN-005): every class resolves to a documented mode.
  for (const [k, v] of Object.entries(p.fail_modes)) oneOf(v, ['closed', 'cached-allow', 'constrained'], `fail mode ${k}`);
  requireThat(p.fail_modes.default === 'closed', 'INV-451-POLICY', 'Default failure mode must be fail-closed', 451);
  integer(p.max_stale_ms, 'stale policy window', 0, 3600000);
  if (p.stale_ms !== undefined) {
    requireThat(typeof p.stale_ms === 'object' && p.stale_ms !== null && !Array.isArray(p.stale_ms), 'INV-400-SCHEMA', 'stale_ms must be a class→ms map');
    for (const [k, v] of Object.entries(p.stale_ms)) integer(v, `stale window ${k}`, 0, 3600000);
  }
  fields(p.staged_policy, ['min_delay_ms', 'emergency_extra_custodians', 'emergency_max_ttl_ms']);
  integer(p.staged_policy.min_delay_ms, 'staged delay', 0, 604800000); integer(p.staged_policy.emergency_extra_custodians, 'emergency custodians', 0, 5); integer(p.staged_policy.emergency_max_ttl_ms, 'emergency ttl', 1000, 2592000000);
  fields(p.secure_perception, ['enabled', 'allowed_firmware', 'session_ttl_ms', 'release_fields', 'fallback', 'required_assurance'], ['nonce']);
  if (p.secure_perception.nonce !== undefined) requireThat(/^[a-f0-9]{64}$/.test(p.secure_perception.nonce), 'INV-400-SCHEMA', 'secure_perception.nonce must be a 64-hex attestation pin');
  requireThat(typeof p.secure_perception.enabled === 'boolean' && Array.isArray(p.secure_perception.allowed_firmware), 'INV-400-SCHEMA', 'Invalid secure perception policy');
  oneOf(p.secure_perception.fallback, ['controlled-workspace', 'denied'], 'perception fallback');
  oneOf(p.secure_perception.required_assurance, ['dev-attested-software', 'workspace-unattested', 'hardware-enclave'], 'required assurance');
  if (p.secure_perception.required_assurance === 'hardware-enclave') requireThat(!p.secure_perception.enabled, 'INV-451-POLICY', 'Hardware-enclave assurance cannot be enabled in the software profile; disable or lower the requirement explicitly', 451);
  if (p.retention !== undefined) {
    fields(p.retention, ['default_ms', 'per_kind']);
    integer(p.retention.default_ms, 'default retention', 60000, 3153600000000);
    for (const [k, v] of Object.entries(p.retention.per_kind ?? {})) { text(k, 'retention kind', 128); integer(v, `retention ${k}`, 0, 3153600000000); }
  }
  integer(p.secure_perception.session_ttl_ms, 'perception ttl', 1000, 3600000);
  requireThat(p.secure_perception.release_fields === '*' || Array.isArray(p.secure_perception.release_fields), 'INV-400-SCHEMA', 'release_fields must be an explicit allowlist or "*"');
  if (Array.isArray(p.secure_perception.release_fields)) uniqueStrings(p.secure_perception.release_fields, 'release fields', 64);
  fields(p.algorithms, ['allowed_suites', 'deprecation']);
  requireThat(Array.isArray(p.algorithms.allowed_suites) && p.algorithms.allowed_suites.length > 0 && p.algorithms.allowed_suites.every(s => ['Ed25519', 'ES256'].includes(s)), 'INV-400-SCHEMA', 'Unsupported algorithm suite');
  if (p.emergency_of !== undefined) integer(p.emergency_of, 'emergency base version', 1);
  return p;
}
// POL-013 emergency contract: a successor marked emergency_of may tighten the
// base but must not weaken it along any dimension. Returns the first weakening
// found, or null. Subset = stricter for allowlists; superset = stricter for
// denylists and required evidence.
export function emergencyWeakening(base, next) {
  const extra = base.staged_policy.emergency_extra_custodians;
  const subset = (a, b) => a.every(x => b.includes(x));
  const superset = (a, b) => b.every(x => a.includes(x));
  if (next.mode !== base.mode) return 'mode';
  if (next.expires_at > base.expires_at) return 'expires_at';
  if (next.max_capsule_ttl_ms > base.max_capsule_ttl_ms) return 'max_capsule_ttl_ms';
  if (next.certificate_ttl_ms > base.certificate_ttl_ms) return 'certificate_ttl_ms';
  if (next.capability_ttl_ms > base.capability_ttl_ms) return 'capability_ttl_ms';
  if (next.max_stale_ms > base.max_stale_ms) return 'max_stale_ms';
  for (const [k, v] of Object.entries(next.stale_ms ?? {})) if (v > ((base.stale_ms ?? {})[k] ?? base.max_stale_ms)) return `stale_ms.${k}`;
  const permissiveness = { closed: 0, constrained: 1, 'cached-allow': 2 };
  for (const [k, v] of Object.entries(next.fail_modes)) if ((permissiveness[v] ?? -1) > (permissiveness[base.fail_modes[k]] ?? -1)) return `fail_modes.${k}`;
  for (const [t, r] of Object.entries(next.rules)) {
    const b = base.rules[t]; if (!b) continue;
    if (r.approval_threshold < b.approval_threshold + extra) return `${t}.approval_threshold`;
    if (r.independent_domains < b.independent_domains) return `${t}.independent_domains`;
    if (!superset(r.evidence_kinds, b.evidence_kinds)) return `${t}.evidence_kinds`;
    if (r.cooldown_ms < b.cooldown_ms) return `${t}.cooldown_ms`;
    if (r.max_quantity > b.max_quantity) return `${t}.max_quantity`;
    if (b.destinations.length && !subset(r.destinations, b.destinations)) return `${t}.destinations`;
    if (!superset(r.forbidden_fields, b.forbidden_fields)) return `${t}.forbidden_fields`;
    if (b.require_hardware && !r.require_hardware) return `${t}.require_hardware`;
    if (b.approval_role === 'custodian' && r.approval_role !== 'custodian') return `${t}.approval_role`;
    if (r.max_evidence_age_ms > b.max_evidence_age_ms) return `${t}.max_evidence_age_ms`;
  }
  const br = base.runtime, nr = next.runtime;
  if (!subset(nr.destinations, br.destinations)) return 'runtime.destinations';
  if (!subset(nr.services, br.services)) return 'runtime.services';
  if (!superset(nr.forbidden_columns, br.forbidden_columns)) return 'runtime.forbidden_columns';
  if (!subset(nr.jurisdictions, br.jurisdictions)) return 'runtime.jurisdictions';
  if (!subset(nr.purposes, br.purposes)) return 'runtime.purposes';
  if (!subset(nr.classifications, br.classifications)) return 'runtime.classifications';
  if (!subset(nr.datasets, br.datasets)) return 'runtime.datasets';
  if (!subset(nr.allowed_columns, br.allowed_columns)) return 'runtime.allowed_columns';
  if (!subset(nr.allowed_transforms, br.allowed_transforms)) return 'runtime.allowed_transforms';
  if (nr.max_cost > br.max_cost || nr.rate_per_second > br.rate_per_second || nr.max_fanout > br.max_fanout) return 'runtime.limits';
  for (const w of nr.windows) { const bw = br.windows.find(x => x.duration_ms === w.duration_ms); if (bw && w.limit > bw.limit) return 'runtime.windows'; }
  if (nr.reconstruction.max_distinct_rows > br.reconstruction.max_distinct_rows || nr.reconstruction.max_distinct_columns > br.reconstruction.max_distinct_columns || nr.reconstruction.max_coverage_percent > br.reconstruction.max_coverage_percent) return 'runtime.reconstruction';
  for (const k of Object.keys(br.sensitivity_weights)) if ((nr.sensitivity_weights[k] ?? 0) < br.sensitivity_weights[k]) return 'runtime.sensitivity_weights';
  const bs = base.secure_perception, ns = next.secure_perception;
  if (bs.enabled && !ns.enabled) return 'secure_perception.enabled';
  if (bs.fallback === 'denied' && ns.fallback !== 'denied') return 'secure_perception.fallback';
  const assuranceRank = { 'workspace-unattested': 0, 'dev-attested-software': 1, 'hardware-enclave': 2 };
  if (assuranceRank[ns.required_assurance] < assuranceRank[bs.required_assurance]) return 'secure_perception.required_assurance';
  if (ns.session_ttl_ms > bs.session_ttl_ms) return 'secure_perception.session_ttl_ms';
  if (bs.release_fields !== '*' && ns.release_fields !== '*' && !subset(ns.release_fields, bs.release_fields)) return 'secure_perception.release_fields';
  if (bs.release_fields !== '*' && ns.release_fields === '*') return 'secure_perception.release_fields';
  if (!subset(ns.allowed_firmware, bs.allowed_firmware)) return 'secure_perception.allowed_firmware';
  if (!subset(next.algorithms.allowed_suites, base.algorithms.allowed_suites)) return 'algorithms.allowed_suites';
  return null;
}
export function evaluatePolicy({ capsule, policy, evidence = [], approvals = [], identities, quarantined = false, now }) {
  const p = capsule, type = p.action.type, rule = policy.rules[type];
  const result = (decision, reasons, extra = {}) => ({ decision, reasons, explanation: reasons.map(r => r.message).join(' '), policy_id: policy.policy_id, policy_version: policy.version, policy_digest: digest(policy), capsule_digest: digest(p), evaluated_at: now, owner: p.actor.subject_id, expires_at: p.expires_at, ...extra });
  const reason = (code, message) => ({ code, message });
  if (!rule) return result('DENY', [reason('UNSUPPORTED_ACTION', 'Action type is not authorised.')]);
  if (quarantined) return result('DENY', [reason('QUARANTINED', 'The subject or device is quarantined.')]);
  // An expired constitution still permits its own succession — otherwise a
  // missed renewal bricks the tenant permanently (policy-audit F3).
  if (p.expires_at <= now || (policy.expires_at <= now && type !== 'policy.change')) return result('DENY', [reason('EXPIRED', 'Action or policy has expired.')]);
  if (p.policy_version !== policy.version) return result('DENY', [reason('POLICY_CHANGED', 'Re-propose under the active policy version.')]);
  if (p.quantity > rule.max_quantity) return result('DENY', [reason('QUANTITY_LIMIT', 'Requested quantity exceeds policy.')]);
  if (rule.destinations.length && !rule.destinations.includes(p.destination)) return result('DENY', [reason('DESTINATION_DENIED', 'Destination is not in the allowlist.')]);
  if (type === 'cloud.firewall.change' && ['0.0.0.0/0', '::/0', '0/0'].includes(p.requested_state.source_cidr)) return result('DENY', [reason('PUBLIC_EXPOSURE', 'Unrestricted public ingress is constitutionally prohibited.')]);
  if (type === 'secret.use' && !['sign', 'authenticate'].includes(p.requested_state.operation)) return result('DENY', [reason('SECRET_EXTRACTION', 'Raw secret extraction is not an authorised action.')]);
  if (type === 'policy.change') {
    const candidate = p.requested_state.policy;
    try { validatePolicy(candidate); } catch { return result('DENY', [reason('INVALID_CONSTITUTION', 'Proposed policy violates the schema or root governance floor.')]); }
    if (candidate.tenant_id !== p.tenant_id || candidate.version !== policy.version + 1) return result('DENY', [reason('POLICY_SEQUENCE', 'Policy activation must advance exactly one tenant-bound version.')]);
    // Admission-time checks (policy-audit F3/F5): an already-expired
    // successor and a staged activation inside the constitutional delay are
    // refused BEFORE dispatch — a certified-but-uninstallable policy must
    // never consume a certificate post-mutation.
    if (candidate.expires_at <= now) return result('DENY', [reason('SUCCESSOR_EXPIRED', 'Proposed policy is already expired at admission time.')]);
    if (candidate.not_before > now && candidate.not_before < now + policy.staged_policy.min_delay_ms) return result('DENY', [reason('STAGED_DELAY', `Staged activation must observe min_delay_ms (${policy.staged_policy.min_delay_ms}).`)]);
    // The governance brakes are constitutional floors: a successor may
    // tighten them but never weaken them (policy-audit F9).
    if (candidate.staged_policy.min_delay_ms < policy.staged_policy.min_delay_ms || candidate.staged_policy.emergency_extra_custodians < policy.staged_policy.emergency_extra_custodians || candidate.staged_policy.emergency_max_ttl_ms > policy.staged_policy.emergency_max_ttl_ms) return result('DENY', [reason('GOVERNANCE_FLOOR', 'staged_policy floors may not be lowered and emergency_max_ttl may not grow.')]);
  }
  if (type === 'data.export') {
    const state = p.current_state.material_fields;
    if (p.requested_state.dataset !== p.action.target_resource || state.classification !== p.requested_state.classification || state.jurisdiction !== p.requested_state.jurisdiction || !policy.runtime.classifications.includes(state.classification) || !policy.runtime.jurisdictions.includes(state.jurisdiction)) return result('DENY', [reason('DATA_CONTEXT', 'Dataset, classification or jurisdiction does not match authorised policy context.')]);
    const columns = p.requested_state.columns.filter(c => !rule.forbidden_fields.includes(c));
    if (columns.length !== p.requested_state.columns.length) return result(columns.length ? 'SHIELD' : 'DENY', [reason('RESTRICTED_FIELDS', 'Remove restricted columns and submit a new exact action.')], { transformation: { columns, exclusions: [...new Set([...p.exclusions, ...rule.forbidden_fields])].sort() } });
  }
  if (type === 'policy.change') {
    const next = p.requested_state.policy;
    // Emergency policies must be no weaker than the base in ANY dimension —
    // raising approval thresholds while loosening evidence, quantities,
    // destinations or failure modes is not an emergency amendment
    // (policy-audit F2, POL-013).
    if (next.emergency_of !== undefined) {
      if (next.emergency_of !== policy.version) return result('DENY', [reason('EMERGENCY_BASE', 'Emergency policy must amend the currently active version.')]);
      if (next.expires_at - now > policy.staged_policy.emergency_max_ttl_ms) return result('DENY', [reason('EMERGENCY_TTL', 'Emergency policies must carry a bounded lifetime.')]);
      const weak = emergencyWeakening(policy, next);
      if (weak) return result('DENY', [reason('EMERGENCY_WEAKER', `Emergency policy weakens the base: ${weak}`)]);
    }
  }
  if (type === 'key.rotate') {
    if (!/^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/.test(p.requested_state.new_key_id)) return result('DENY', [reason('KEY_ID', 'New key id is not a valid identifier.')]);
  }
  if (type === 'identity.jit.grant') {
    // IDN-*: a JIT grant may mint scope only inside the runtime catalog —
    // undeclared datasets, columns, destinations or transforms are denied at
    // admission, not at consume (policy-audit F7).
    const r = policy.runtime, req = p.requested_state;
    const resources = req.resources ?? [], columns = req.columns ?? [], destinations = req.destinations ?? [], rowIds = req.row_ids ?? [];
    if (!resources.every(x => r.datasets.includes(x) || r.services.includes(x)) || !columns.every(x => r.allowed_columns.includes(x) && !r.forbidden_columns.includes(x)) || !destinations.every(x => r.destinations.includes(x))) return result('DENY', [reason('SCOPE_CATALOG', 'JIT grant exceeds the declared data/service catalog.')]);
    // CON-008: grant-carried roles are support scope only — a JIT grant may
    // never mint custodian/security/policy_admin privilege.
    if (!(req.roles ?? []).every(x => ['operator', 'workload'].includes(x))) return result('DENY', [reason('ROLE_ESCALATION', 'JIT grant roles may only confer operator or workload scope.')]);
    if (!Array.isArray(rowIds)) return result('DENY', [reason('INVALID_GRANT', 'row_ids must be an explicit list.')]);
  }
  // POL-011: the cooldown anchors on the server-side receive timestamp, not
  // the caller's claim — created_at is inside a 300s backdate window and is
  // not trusted for delay controls (policy-audit F4).
  const notBefore = Math.max(policy.not_before, (p.received_at ?? p.created_at) + rule.cooldown_ms);
  if (notBefore > now) return result('DEFER', [reason('COOLDOWN', 'Wait for the mandatory delay, then re-evaluate.')], { not_before: notBefore });
  // IDN-003: identity-class admission condition on the rule.
  if (rule.identity_classes !== undefined && !rule.identity_classes.includes(p.actor.identity_class)) return result('DENY', [reason('IDENTITY_CLASS', `Action requires identity class ${rule.identity_classes.join('|')}; actor is ${p.actor.identity_class}.`)]);
  // IDN-010: minimum proofing level the actor identity must carry.
  if (rule.min_proofing !== undefined) {
    const LEVELS = { low: 0, medium: 1, high: 2 };
    const actorEntry = Object.values(identities ?? {}).find(i => i.subject_id === p.actor.subject_id);
    if ((LEVELS[actorEntry?.proofing_level] ?? -1) < LEVELS[rule.min_proofing]) return result('DENY', [reason('PROOFING', `Action requires proofing >= ${rule.min_proofing}; actor carries ${actorEntry?.proofing_level ?? 'none'}.`)]);
  }
  const issues = [], usable = [], unverifiable = new Set(), byId = new Map(evidence.map(e => [e.payload.evidence_id, e]));
  for (const e of evidence) {
    if (e.revoked) { issues.push(reason('EVIDENCE_REVOKED', 'An attached source was revoked.')); continue; }
    if (e.payload.expires_at <= now || now - e.payload.acquired_at > rule.max_evidence_age_ms) { issues.push(reason('EVIDENCE_EXPIRED', 'Refresh stale evidence.')); continue; }
    if (e.payload.claim === 'conflict') { issues.push(reason('EVIDENCE_CONFLICT', 'Resolve conflicting authoritative evidence.')); continue; }
    if (e.payload.confidence < 90 || e.payload.advisory || e.issuer.channel === 'communication') { unverifiable.add(e.payload.evidence_id); continue; }
    if (e.payload.dependencies.some(id => !byId.has(id) || byId.get(id).revoked || byId.get(id).payload.expires_at <= now)) { issues.push(reason('EVIDENCE_DEPENDENCY', 'A dependency is unavailable or invalid.')); continue; }
    usable.push(e);
  }
  function roots(e, seen = new Set()) {
    if (seen.has(e.payload.evidence_id)) return new Set(['cycle']);
    seen.add(e.payload.evidence_id);
    const out = new Set([e.issuer.failure_domain]);
    for (const id of e.payload.dependencies) { const dependency = byId.get(id); if (dependency) for (const domain of roots(dependency, new Set(seen))) out.add(domain); }
    return out;
  }
  // Greedy disjoint-domain count is conservative: it may escrow, never over-count.
  const usedDomains = new Set(); let independent = 0;
  for (const e of usable.filter(e => rule.evidence_kinds.includes(e.payload.kind)).sort((a, b) => a.payload.evidence_id < b.payload.evidence_id ? -1 : 1)) {
    const domains = roots(e);
    if (![...domains].some(d => usedDomains.has(d) || d === 'cycle')) { independent++; for (const d of domains) usedDomains.add(d); }
  }
  // EVD-009: missing vs present-but-unverifiable are distinct reason codes.
  for (const kind of rule.evidence_kinds) if (!usable.some(e => e.payload.kind === kind)) {
    const attached = evidence.filter(e => e.payload.kind === kind);
    if (attached.length && attached.every(e => unverifiable.has(e.payload.evidence_id))) issues.push(reason('EVIDENCE_UNVERIFIABLE', `Attached evidence for kind ${kind} is advisory-only, low-confidence or communication-channel.`));
    else issues.push(reason('EVIDENCE_MISSING', `Required evidence kind: ${kind}.`));
  }
  if (independent < rule.independent_domains) issues.push(reason('EVIDENCE_INDEPENDENCE', 'Independent source domains are insufficient.'));
  const requiredApprovals = rule.approval_threshold + (type === 'policy.change' && p.requested_state.policy?.emergency_of !== undefined ? policy.staged_policy.emergency_extra_custodians : 0);
  // Quorum = distinct subjects AND distinct failure domains — one person
  // holding two registered keys must not satisfy a two-of-two threshold
  // (policy-audit F8).
  const signers = [], domains = new Set(), subjects = new Set();
  for (const approval of approvals) {
    const identity = identities[approval.signer_id];
    if (!identity || identity.revoked || approval.expires_at <= now || identity.subject_id === p.actor.subject_id || !identity.roles.includes(rule.approval_role)) continue;
    if (rule.require_hardware && !identity.hardware_backed) continue;
    if (!domains.has(identity.failure_domain) && !subjects.has(identity.subject_id)) { signers.push(approval.signer_id); domains.add(identity.failure_domain); subjects.add(identity.subject_id); }
  }
  if (signers.length < requiredApprovals) issues.push(reason(rule.require_hardware ? 'HARDWARE_APPROVAL_REQUIRED' : 'APPROVAL_THRESHOLD', `Need ${requiredApprovals} eligible independent action-bound approvals.`));
  if (issues.length) return result('ESCROW', issues, { independent_domains: independent, eligible_signers: signers.sort() });
  return result('ALLOW', [reason('ALL_PREDICATES_MET', 'All deterministic conditions are met for this exact action.')], { independent_domains: independent, eligible_signers: signers.sort() });
}
export function policyDiff(before, after) {
  const changes = [];
  function walk(a, b, path) {
    if (digest(a ?? null) === digest(b ?? null)) return;
    if (a && b && typeof a === 'object' && typeof b === 'object' && !Array.isArray(a) && !Array.isArray(b)) for (const k of [...new Set([...Object.keys(a), ...Object.keys(b)])].sort()) walk(a[k], b[k], path ? `${path}.${k}` : k);
    else changes.push({ path, before: a ?? null, after: b ?? null });
  }
  walk(before, after, ''); return changes;
}
