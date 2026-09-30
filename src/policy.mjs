import { digest, clone } from './canonical.mjs';
import { fields, integer, uniqueStrings, oneOf, text } from './schema.mjs';
import { requireThat } from './errors.mjs';

export function defaultPolicy(tenant) {
  const standard = { evidence_kinds: ['ownership'], independent_domains: 2, approval_threshold: 2, approval_role: 'approver', cooldown_ms: 0, max_quantity: 1_000_000_000, require_hardware: false, destinations: [], forbidden_fields: [], max_evidence_age_ms: 3600000 };
  const rules = {};
  for (const type of ['finance.vendor.create', 'finance.bank.change', 'finance.beneficiary.create', 'finance.payment.first', 'data.export', 'identity.mfa.reset', 'identity.authenticator.enroll', 'identity.account.recover', 'cloud.firewall.change', 'code.release', 'secret.use', 'backup.delete', 'policy.change']) rules[type] = clone(standard);
  rules['finance.bank.change'].cooldown_ms = 60000;
  rules['finance.payment.first'].max_quantity = 10_000_000;
  rules['data.export'] = { ...clone(standard), evidence_kinds: ['dataset_authority'], independent_domains: 1, approval_threshold: 0, destinations: ['customer-vault'], forbidden_fields: ['passport', 'payment_token', 'password'], max_quantity: 1000 };
  for (const t of ['identity.mfa.reset', 'identity.authenticator.enroll', 'identity.account.recover']) rules[t].evidence_kinds = ['identity_proof', 'recovery_authority'];
  rules['code.release'].evidence_kinds = ['build_provenance', 'test_result'];
  rules['secret.use'].evidence_kinds = ['workload_attestation'];
  for (const t of ['backup.delete', 'policy.change']) { rules[t].approval_threshold = 3; rules[t].approval_role = 'custodian'; rules[t].evidence_kinds = ['governance_review']; rules[t].cooldown_ms = 120000; }
  return { policy_id: `constitution:${tenant}`, tenant_id: tenant, version: 1, not_before: 1, expires_at: 4102444800000, max_capsule_ttl_ms: 3600000, certificate_ttl_ms: 60000, capability_ttl_ms: 60000, mode: 'engineering', rules,
    runtime: { max_cost: 10000, rate_per_second: 20, max_fanout: 4, windows: [{ duration_ms: 60000, limit: 100 }, { duration_ms: 3600000, limit: 1000 }, { duration_ms: 86400000, limit: 5000 }, { duration_ms: 2592000000, limit: 10000 }], destinations: ['customer-vault', 'erp-service'], services: ['erp-service'], forbidden_columns: ['passport', 'payment_token', 'password'], jurisdictions: ['EU'], purposes: ['operations'], classifications: ['internal'], sensitivity_weights: { internal: 1, confidential: 5, restricted: 10 } } };
}
export function validatePolicy(p) {
  fields(p, ['policy_id', 'tenant_id', 'version', 'not_before', 'expires_at', 'max_capsule_ttl_ms', 'certificate_ttl_ms', 'capability_ttl_ms', 'mode', 'rules', 'runtime']);
  text(p.policy_id, 'policy id'); text(p.tenant_id, 'tenant'); integer(p.version, 'version', 1); integer(p.not_before, 'activation time', 1); integer(p.expires_at, 'expiry', p.not_before + 1);
  integer(p.max_capsule_ttl_ms, 'capsule TTL', 1000, 86400000); integer(p.certificate_ttl_ms, 'certificate TTL', 1000, 300000); integer(p.capability_ttl_ms, 'capability TTL', 1000, 300000);
  oneOf(p.mode, ['engineering', 'shadow'], 'deployment mode');
  fields(p.rules, Object.keys(defaultPolicy(p.tenant_id).rules));
  for (const [type, r] of Object.entries(p.rules)) {
    fields(r, ['evidence_kinds', 'independent_domains', 'approval_threshold', 'approval_role', 'cooldown_ms', 'max_quantity', 'require_hardware', 'destinations', 'forbidden_fields', 'max_evidence_age_ms']);
    uniqueStrings(r.evidence_kinds, 'evidence kinds', 10); integer(r.independent_domains, 'independent domains', 1, 10); integer(r.approval_threshold, 'threshold', type === 'data.export' ? 0 : ['policy.change', 'backup.delete'].includes(type) ? 3 : 1, 5);
    oneOf(r.approval_role, ['approver', 'custodian'], 'approval role');
    if (['policy.change', 'backup.delete'].includes(type)) requireThat(r.approval_role === 'custodian', 'INV-451-POLICY', 'Root actions require customer custodians', 451);
    integer(r.cooldown_ms, 'cooldown', ['policy.change', 'backup.delete'].includes(type) ? 120000 : 0, 604800000);
    integer(r.max_quantity, 'maximum quantity', 1, 1_000_000_000_000); requireThat(typeof r.require_hardware === 'boolean', 'INV-400-SCHEMA', 'Hardware requirement must be boolean');
    uniqueStrings(r.destinations, 'destinations'); uniqueStrings(r.forbidden_fields, 'forbidden fields'); integer(r.max_evidence_age_ms, 'evidence age', 1000, 2592000000);
  }
  const r = p.runtime;
  fields(r, ['max_cost', 'rate_per_second', 'max_fanout', 'windows', 'destinations', 'services', 'forbidden_columns', 'jurisdictions', 'purposes', 'classifications', 'sensitivity_weights']);
  integer(r.max_cost, 'runtime cost', 1, 1e9); integer(r.rate_per_second, 'runtime rate', 1, 10000); integer(r.max_fanout, 'fanout', 1, 100);
  requireThat(Array.isArray(r.windows) && r.windows.length >= 1 && r.windows.length <= 8, 'INV-400-SCHEMA', 'Invalid budget windows');
  for (const w of r.windows) { fields(w, ['duration_ms', 'limit']); integer(w.duration_ms, 'window duration', 1000, 2592000000); integer(w.limit, 'window limit', 1, 1e12); }
  for (const k of ['destinations', 'services', 'forbidden_columns', 'jurisdictions', 'purposes', 'classifications']) uniqueStrings(r[k], k);
  fields(r.sensitivity_weights, ['internal', 'confidential', 'restricted']); for (const [k, v] of Object.entries(r.sensitivity_weights)) integer(v, k, 1, 1000);
  return p;
}
export function evaluatePolicy({ capsule, policy, evidence = [], approvals = [], identities, quarantined = false, now }) {
  const p = capsule, type = p.action.type, rule = policy.rules[type];
  const result = (decision, reasons, extra = {}) => ({ decision, reasons, explanation: reasons.map(r => r.message).join(' '), policy_id: policy.policy_id, policy_version: policy.version, policy_digest: digest(policy), capsule_digest: digest(p), evaluated_at: now, owner: p.actor.subject_id, expires_at: p.expires_at, ...extra });
  const reason = (code, message) => ({ code, message });
  if (!rule) return result('DENY', [reason('UNSUPPORTED_ACTION', 'Action type is not authorised.')]);
  if (quarantined) return result('DENY', [reason('QUARANTINED', 'The subject or device is quarantined.')]);
  if (p.expires_at <= now || policy.expires_at <= now) return result('DENY', [reason('EXPIRED', 'Action or policy has expired.')]);
  if (p.policy_version !== policy.version) return result('DENY', [reason('POLICY_CHANGED', 'Re-propose under the active policy version.')]);
  if (p.quantity > rule.max_quantity) return result('DENY', [reason('QUANTITY_LIMIT', 'Requested quantity exceeds policy.')]);
  if (rule.destinations.length && !rule.destinations.includes(p.destination)) return result('DENY', [reason('DESTINATION_DENIED', 'Destination is not in the allowlist.')]);
  if (type === 'cloud.firewall.change' && ['0.0.0.0/0', '::/0', '0/0'].includes(p.requested_state.source_cidr)) return result('DENY', [reason('PUBLIC_EXPOSURE', 'Unrestricted public ingress is constitutionally prohibited.')]);
  if (type === 'secret.use' && !['sign', 'authenticate'].includes(p.requested_state.operation)) return result('DENY', [reason('SECRET_EXTRACTION', 'Raw secret extraction is not an authorised action.')]);
  if (type === 'policy.change') {
    try { validatePolicy(p.requested_state.policy); } catch { return result('DENY', [reason('INVALID_CONSTITUTION', 'Proposed policy violates the schema or root governance floor.')]); }
    if (p.requested_state.policy.tenant_id !== p.tenant_id || p.requested_state.policy.version !== policy.version + 1) return result('DENY', [reason('POLICY_SEQUENCE', 'Policy activation must advance exactly one tenant-bound version.')]);
  }
  if (type === 'data.export') {
    const state = p.current_state.material_fields;
    if (p.requested_state.dataset !== p.action.target_resource || state.classification !== p.requested_state.classification || state.jurisdiction !== p.requested_state.jurisdiction || !policy.runtime.classifications.includes(state.classification) || !policy.runtime.jurisdictions.includes(state.jurisdiction)) return result('DENY', [reason('DATA_CONTEXT', 'Dataset, classification or jurisdiction does not match authorised policy context.')]);
    const columns = p.requested_state.columns.filter(c => !rule.forbidden_fields.includes(c));
    if (columns.length !== p.requested_state.columns.length) return result(columns.length ? 'SHIELD' : 'DENY', [reason('RESTRICTED_FIELDS', 'Remove restricted columns and submit a new exact action.')], { transformation: { columns, exclusions: [...new Set([...p.exclusions, ...rule.forbidden_fields])].sort() } });
  }
  const notBefore = Math.max(policy.not_before, p.created_at + rule.cooldown_ms);
  if (notBefore > now) return result('DEFER', [reason('COOLDOWN', 'Wait for the mandatory delay, then re-evaluate.')], { not_before: notBefore });
  const issues = [], usable = [], byId = new Map(evidence.map(e => [e.payload.evidence_id, e]));
  for (const e of evidence) {
    if (e.revoked) { issues.push(reason('EVIDENCE_REVOKED', 'An attached source was revoked.')); continue; }
    if (e.payload.expires_at <= now || now - e.payload.acquired_at > rule.max_evidence_age_ms) { issues.push(reason('EVIDENCE_EXPIRED', 'Refresh stale evidence.')); continue; }
    if (e.payload.claim === 'conflict') { issues.push(reason('EVIDENCE_CONFLICT', 'Resolve conflicting authoritative evidence.')); continue; }
    if (e.payload.confidence < 90 || e.payload.advisory || e.issuer.channel === 'communication') continue;
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
  for (const kind of rule.evidence_kinds) if (!usable.some(e => e.payload.kind === kind)) issues.push(reason('EVIDENCE_MISSING', `Required evidence kind: ${kind}.`));
  if (independent < rule.independent_domains) issues.push(reason('EVIDENCE_INDEPENDENCE', 'Independent source domains are insufficient.'));
  const signers = [], domains = new Set();
  for (const approval of approvals) {
    const identity = identities[approval.signer_id];
    if (!identity || identity.revoked || approval.expires_at <= now || identity.subject_id === p.actor.subject_id || !identity.roles.includes(rule.approval_role)) continue;
    if (rule.require_hardware && !identity.hardware_backed) continue;
    if (!domains.has(identity.failure_domain)) { signers.push(approval.signer_id); domains.add(identity.failure_domain); }
  }
  if (signers.length < rule.approval_threshold) issues.push(reason(rule.require_hardware ? 'HARDWARE_APPROVAL_REQUIRED' : 'APPROVAL_THRESHOLD', `Need ${rule.approval_threshold} eligible independent action-bound approvals.`));
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
