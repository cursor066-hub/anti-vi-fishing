import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';
import { createConfiguration, seedSyntheticResources } from '../src/bootstrap.mjs';
import { Fabric } from '../src/fabric.mjs';
import { proposal } from '../src/schema.mjs';
import { signed } from '../src/crypto.mjs';
import { digest, clone } from '../src/canonical.mjs';

export const BASE_TIME = 1788648000000;
export function fixture(t, tenants = ['acme', 'globex']) {
  let time = BASE_TIME;
  const directory = mkdtempSync(join(tmpdir(), 'if-test-')), setup = createConfiguration(tenants, time);
  const f = new Fabric(setup.config, directory, () => time); seedSyntheticResources(f, tenants);
  let closed = false;
  const close = () => { if (!closed) { f.close(); closed = true; } };
  t?.after(() => { close(); rmSync(directory, { recursive: true }); });
  const p = (subject = 'operator', tenant = 'acme') => ({ subject_id: subject, tenant_id: tenant });
  const actor = (subject = 'operator') => ({ subject_id: subject, identity_class: 'workforce', device_id: `${subject}-device` });
  function proposed(type = 'finance.beneficiary.create', requested = { vendor_id: 'vendor-1', bank_account: 'TESTBANK000002', currency: 'EUR' }, overrides = {}, principal = p()) {
    const resource = overrides.action?.target_resource ?? `new-${randomUUID()}`;
    const action = { type, target_resource: resource, purpose: 'Synthetic verification' };
    const input = proposal(type, actor(principal.subject_id), f.target.state(principal.tenant_id, resource), requested, time, { action, ...overrides });
    return f.propose(principal, input, randomUUID());
  }
  function evidence(record, { issuer = 'bank', kind = 'ownership', advisory = false, claim = 'supports', dependencies = [], confidence = 100, tenant = record.capsule.tenant_id, expiry = time + 600000 } = {}) {
    const payload = { evidence_id: randomUUID(), tenant_id: tenant, capsule_digest: record.capsule_digest, kind, content_digest: digest({ source: 'synthetic-only', claim }), acquired_at: time, expires_at: expiry, confidence, advisory, claim, dependencies, provenance: 'Synthetic test issuer; no external authority assertion', retention_until: expiry + 60000 };
    const key = setup.issuerKeys[tenant][issuer], envelope = signed(payload, key, 'evidence');
    f.attachEvidence(p('operator', tenant), record.capsule.capsule_id, envelope); return envelope;
  }
  function approve(record, count = 2) {
    for (let i = 1; i <= count; i++) {
      const principal = p(`custodian-${i}`, record.capsule.tenant_id), challenge = f.approvalChallenge(principal, record.capsule.capsule_id);
      f.approve(principal, signed(challenge, setup.custodianKeys[record.capsule.tenant_id][principal.subject_id], 'action-approval'));
    }
  }
  function ready(record = proposed(), options = {}) {
    const kind = options.kind ?? 'ownership'; evidence(record, { kind }); evidence(record, { issuer: 'registry', kind }); approve(record, options.approvals ?? 2);
    return { record, certificate: f.certificate(p('operator', record.capsule.tenant_id), record.capsule.capsule_id) };
  }
  return { f, setup, directory, p, actor, proposed, evidence, approve, ready, close, now: () => time, advance: ms => { time += ms; }, clone };
}
export const hasCode = code => e => e?.code === code;
export function runtimeInput(overrides = {}) { return { device_id: 'operator-device', resource: 'dataset-1', destination: 'customer-vault', action: 'data.read', purpose: 'operations', columns: ['id', 'name'], row_ids: ['row-1'], classification: 'internal', jurisdiction: 'EU', max_cost: 1000, ttl_ms: 60000, ...overrides }; }
export function runtimeRequest(capability, overrides = {}) { const c = capability.payload; return { capability, device_id: c.device_id, resource: c.resource, destination: c.destination, action: c.action, purpose: c.purpose, columns: c.columns, row_ids: c.row_ids, request_id: randomUUID(), protocol: 'https', port: 443, ...overrides }; }
