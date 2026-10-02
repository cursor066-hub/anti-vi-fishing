import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';
import { createConfiguration, seedSyntheticResources } from '../src/bootstrap.mjs';
import { Fabric } from '../src/fabric.mjs';
import { proposal } from '../src/schema.mjs';
import { signed } from '../src/crypto.mjs';
import { signAcknowledgement } from '../src/ceremony.mjs';
import { digest, clone } from '../src/canonical.mjs';

export const BASE_TIME = 1788648000000;
// The chain-anchored identity tuple a technical_validation envelope binds
// (w31-coverage F3) — mirrors the identity_digest in COVERAGE_DECLARED.
export const coverageIdentity = path => digest({ path_id: path.path_id, action_type: path.action_type, target: path.target, environment: path.environment, connector_version: path.connector_version, owner: path.owner, path_class: path.path_class, ...(path.connector_key_id !== undefined ? { connector_key_id: path.connector_key_id } : {}), configuration_digest: path.configuration_digest, max_age_ms: path.max_age_ms });
export function fixture(t, tenants = ['acme', 'globex']) {
  let time = BASE_TIME;
  const directory = mkdtempSync(join(tmpdir(), 'if-test-')), setup = createConfiguration(tenants, time);
  let f = new Fabric(setup.config, directory, () => time); seedSyntheticResources(f, tenants);
  let closed = false;
  const close = () => { if (!closed) { f.close(); closed = true; } };
  // A sibling worker's mid-flight chain-head/watermark write can drop a
  // file into the tree between readdir and rmdir — retry, never swallow.
  t?.after(() => { close(); rmSync(directory, { recursive: true, force: true, maxRetries: 20, retryDelay: 50 }); });
  const p = (subject = 'operator', tenant = 'acme') => ({ subject_id: subject, tenant_id: tenant });
  const actor = (subject = 'operator') => ({ subject_id: subject, identity_class: 'workforce', device_id: `${subject}-device` });
  function proposed(type = 'finance.beneficiary.create', requested = { vendor_id: 'vendor-1', bank_account: 'TESTBANK000002', currency: 'EUR' }, overrides = {}, principal = p()) {
    const resource = overrides.action?.target_resource ?? `new-${randomUUID()}`;
    const action = { type, target_resource: resource, purpose: 'Synthetic verification' };
    const state = type === 'secret.use' ? f.target.secretState(principal.tenant_id, requested.secret_id) : f.target.state(principal.tenant_id, resource);
    const input = proposal(type, actor(principal.subject_id), state, requested, time, { action, policy_version: f.policy(principal.tenant_id).version, ...overrides });
    // ACT-005: request intent is signed by the actor's identity key.
    const intent = signed(input, setup.identityKeys[principal.tenant_id][principal.subject_id], 'capsule-intent');
    return f.propose(principal, input, randomUUID(), intent);
  }
  function evidence(record, { issuer, kind = 'ownership', advisory = false, claim = 'supports', dependencies = [], confidence = 100, tenant = record.capsule.tenant_id, expiry = time + 600000, claims } = {}) {
    // Issuer keys are scoped to their declared kinds — pick an issuer that
    // legitimately serves the requested kind when none is specified.
    issuer ??= kind === 'ownership' ? 'bank' : kind === 'governance_review' ? 'governance' : kind === 'dataset_authority' ? 'registry' : ['identity_proof', 'recovery_authority'].includes(kind) ? 'hris' : ['device_health', 'workload_attestation'].includes(kind) ? 'device-attestation' : kind === 'build_provenance' || kind === 'test_result' ? 'build-pipeline' : 'bank';
    // Envelopes carry the claim fields a policy evidence binding can check:
    // for bound kinds they mirror the capsule's own action content.
    const rs = record.capsule.requested_state ?? {};
    claims ??= claim !== 'supports' ? {} : kind === 'ownership' ? { account: rs.bank_account ?? 'TESTBANK000001', owner_id: record.capsule.action.target_resource }
      : kind === 'dataset_authority' ? { dataset: rs.dataset ?? record.capsule.action.target_resource }
      : kind === 'identity_proof' || kind === 'recovery_authority' ? { subject_id: rs.subject_id ?? record.capsule.actor.subject_id }
      : kind === 'workload_attestation' ? { workload_id: rs.workload_id ?? 'workload-1' }
      : kind === 'governance_review' ? { ref: 'REV-2026-001', action_ref: record.capsule.capsule_id }
      : kind === 'payment_confirmation' ? { transaction_id: record.capsule.capsule_id }
      : kind === 'device_health' ? { device_id: record.capsule.actor.device_id }
      : {};
    // Registered issuers declare a version — envelopes must pin it or the
    // attach gate rejects the drift (w18-issuerd F-8).
    const issEntry = Object.values(setup.config.tenants[tenant].issuers ?? {}).find(i => i.name === issuer || i.issuer_id === issuer);
    const payload = { evidence_id: randomUUID(), tenant_id: tenant, capsule_digest: record.capsule_digest, kind, content_digest: digest({ source: 'synthetic-only', claim }), acquired_at: time, expires_at: expiry, confidence, advisory, claim, dependencies, provenance: 'Synthetic test issuer; no external authority assertion', retention_until: expiry + 60000, claims, ...(issEntry?.version !== undefined ? { issuer_version: issEntry.version } : {}) };
    const key = setup.issuerKeys[tenant][issuer], envelope = signed(payload, key, 'evidence');
    f.attachEvidence(p('operator', tenant), record.capsule.capsule_id, envelope); return envelope;
  }
  function approve(record, countOrSigners = 2) {
    const subjects = Array.isArray(countOrSigners) ? countOrSigners : Array.from({ length: countOrSigners }, (_, i) => `custodian-${i + 1}`);
    for (const subject of subjects) {
      const principal = p(subject, record.capsule.tenant_id), challenge = f.approvalChallenge(principal, record.capsule.capsule_id);
      f.approve(principal, signed(challenge, setup.identityKeys[record.capsule.tenant_id][subject], 'action-approval'));
    }
  }
  // An approval envelope built as `subject` without the role-gated challenge
  // route — the object a compromised or ineligible credential would present.
  function approvalEnvelope(record, subject, mutate = {}) {
    const tenant = record.capsule.tenant_id, key = setup.identityKeys[tenant][subject];
    const [keyId] = Object.entries(f.identities(tenant)).find(([, v]) => v.subject_id === subject);
    const stored = f.store.must(tenant, 'capsule', record.capsule.capsule_id);
    const payload = { tenant_id: tenant, capsule_id: record.capsule.capsule_id, capsule_digest: stored.capsule_digest, evidence_graph_digest: f.graph(tenant, stored).digest, policy_digest: digest(f.policy(tenant)), signer_id: keyId, approved_at: time, expires_at: Math.min(time + 300000, stored.capsule.expires_at), ...mutate };
    return signed(payload, key, 'action-approval');
  }
  function ready(record = proposed(), options = {}) {
    const kind = options.kind ?? 'ownership'; evidence(record, { kind }); evidence(record, { issuer: 'registry', kind }); approve(record, options.approvals ?? 2);
    return { record, certificate: f.certificate(p('operator', record.capsule.tenant_id), record.capsule.capsule_id) };
  }
  const api = { f, setup, directory, p, actor, proposed, evidence, approve, approvalEnvelope, ready, close, now: () => time, advance: ms => { time += ms; }, set: t => { time = t; }, clone };
  // Attest that the gate honestly believed it lived forward to `at`: a
  // vault-signed audit row is the only carrier a file-writer cannot mint.
  // Inside the fold's 60s tolerance the row folds directly; beyond it the
  // seal cuts the row but carries its signed time as the attested lived
  // horizon — either way the clock-recovery veto grounds on chain
  // evidence, never on the forgeable clock row (w42-runtime F2).
  api.livedForward = (at, tenant = 'acme') => {
    f.store.tx(() => { f.store.clock(at); f.store.audit(tenant, 'HEALTH_ASSERTION', 'fixture', 'lived-span', {}, at); });
    f.invalidateAuditIndex(tenant);
    if (at > time + 60_000) f.sealAuditChain(p('security', tenant));
  };
  // Issuer endpoints are frozen trust anchors (w12-provenance F15): the
  // sanctioned update is a config reload — reopen the fabric on a cloned
  // configuration carrying the new endpoint. Helpers see the new instance
  // because they close over the `f` binding, not the object.
  api.repoint = (keyId, url, tenant = 'acme') => api.reconfigure(cfg => { cfg.tenants[tenant].issuers[keyId].endpoint = url; });
  // The honest equivalent of editing the config file and restarting: clone
  // the signed configuration, apply the mutation, reopen on the same
  // ledger, and let security re-attest the drifted snapshot (F13/F14 make
  // in-process tenant mutation itself unreachable).
  api.reconfigure = mutate => {
    const cfg = clone(setup.config);
    mutate(cfg);
    // Flush vault state first — keys generated at runtime must survive the
    // reopen or the new instance loses their bindings (w6-fix F5).
    f.persistVault();
    // Construct the successor BEFORE closing the incumbent — a refused
    // config must leave a live fabric behind, not a closed store the
    // teardown then double-closes (w31-runtime F-4 tests refuse configs).
    const next = new Fabric(cfg, directory, () => time);
    f.close();
    f = next;
    api.f = f;
    // Re-attest only the tenants whose snapshot actually drifted.
    for (const tn of Object.keys(cfg.tenants))
      if (f._configDrift.has(tn) || f.store.get(tn, 'config-flag', 'drift')) f.reassertConfig(api.p('security', tn));
  };
  return api;
}
export const hasCode = code => e => e?.code === code;
// A live constitution can only change through the governed policy.change
// pipeline — the active row is anchored to its ledger-signed activation
// (w12 red-team), so tests that need a different policy must certify one.
// The weakening flag is declared so any dimension may move; the declared
// surcharge raises the approval floor to threshold + emergency_extra (4).
export function installPolicy(h, mutate, { approvals = 4, tenant = 'acme' } = {}) {
  const next = clone(h.f.policy(tenant)); next.version += 1; next.allow_weakening = true; mutate?.(next);
  const r = h.proposed('policy.change', { policy: next }, { action: { type: 'policy.change', target_resource: 'policy-root', purpose: 'Amend constitution' } }, h.p('operator', tenant));
  h.f.simulate(h.p('policy-admin', tenant), next); h.advance(120001);
  h.evidence(r, { kind: 'governance_review' }); h.evidence(r, { kind: 'governance_review', issuer: 'audit-committee' }); h.approve(r, approvals);
  const outcome = h.f.execute(h.p('operator', tenant), h.f.certificate(h.p('operator', tenant), r.capsule.capsule_id));
  if (outcome.payload.status !== 'VERIFIED') throw new Error(`installPolicy dispatch failed: ${JSON.stringify(outcome.payload)}`);
  return next;
}
// Tenant configuration is deep-frozen at open — legitimate edits go through
// the same clone-and-swap path the fabric uses for key rotation.
// The live-tenant edit + security re-assertion flow, expressed through the
// only path that still exists: mutate a clone of the live tenant, then a
// config reload carries it (in-process _setTenant was F14's free swap).
export function setTenant(h, tenant, mutate) { const tn = clone(h.f.tenant(tenant)); mutate?.(tn); h.reconfigure(cfg => { cfg.tenants[tenant] = tn; }); }
// The fixture-level equivalent of a governed stage: the staged row AND its
// signed POLICY_STAGED anchor land in one tx, exactly as a VERIFIED
// policy.change produces them. A bare `store.put('policy','staged')` without
// the anchor is what a row-writing insider forges — promotion now refuses
// it (w12-lifecycle F2), so tests must stage through the chain.
export function stageConstitution(h, next, { tenant = 'acme', activate_at } = {}) {
  const at = activate_at ?? next.not_before ?? h.now();
  h.f.store.tx(() => {
    h.f.store.put(tenant, 'policy', 'staged', { policy: next, activate_at: at, staged_at: h.now() }, h.now());
    h.f.store.audit(tenant, 'POLICY_STAGED', 'policy-admin', next.policy_id, { activate_at: at, version: next.version, policy_digest: digest(next) }, h.now());
  });
}
export function runtimeInput(overrides = {}) { return { device_id: 'operator-device', resource: 'dataset-1', destination: 'customer-vault', action: 'data.read', purpose: 'operations', columns: ['id', 'name'], row_ids: ['row-1'], classification: 'internal', jurisdiction: 'EU', max_cost: 1000, ttl_ms: 60000, ...overrides }; }
export function runtimeRequest(capability, overrides = {}) { const c = capability.payload; return { capability, device_id: c.device_id, resource: c.resource, destination: c.destination, action: c.action, purpose: c.purpose, columns: c.columns, row_ids: c.row_ids, request_id: randomUUID(), protocol: 'https', port: 443, ...overrides }; }
// The quorum-designated successor the revoke/fallback gates now require:
// a pending key is only a legitimate successor when a custodian-acked
// key.rotate ceremony names it in its rotation spec — prepareRotation
// alone was a unilateral signer-substitution path (w18-crypto F3).
let designateSeq = 0;
export function designateSuccessor(h, key_class, tenant = 'acme') {
  const pending = h.f.prepareRotation(h.p('security', tenant), key_class);
  const custodians = ['custodian-1', 'custodian-2'];
  const ceremony = h.f.createCeremony(h.p('security', tenant), {
    ceremony_id: `cer-designate-${key_class}-${++designateSeq}`, purpose: 'key.rotate', threshold: 2,
    custodians, valid_until: h.now() + 3600000, min_delay_ms: 120000,
    rotation: { key_class, new_key_id: pending.key_id },
  });
  for (const subject of custodians) h.f.acknowledgeCeremony(h.p(subject, tenant), signAcknowledgement(ceremony, subject, h.setup.custodianKeys[tenant][subject], h.now()));
  return pending;
}
