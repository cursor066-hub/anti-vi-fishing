// w47 regression tests: the second w46 report batch — occurrence-precise
// containment binding (the wrong-victim murder), the seq-only heal window
// on idle tenants, meta_kv drop residue attestation, and the seal
// surface's records-drop taxonomy.
import test from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { join } from 'node:path';
import { fixture, runtimeInput, runtimeRequest, hasCode } from './helpers.mjs';
import { Fabric } from '../src/fabric.mjs';

// --- fixverify M-1: a murdered same-triple denial names its OWN occurrence ---
test('w47 fixverify M-1: same-request_id murder names the dead occurrence, not the live one', t => {
  const h = fixture(t);
  const cap = h.f.runtime.issue(h.p(), runtimeInput());
  const req = runtimeRequest(cap);
  try { h.f.runtime.consume(h.p(), { ...req, port: 99 }); } catch { /* denial 1: row + RUNTIME_DENIED anchor at t0 */ }
  h.advance(120_000); // past the 60s dedup — the second denial anchors its own event
  try { h.f.runtime.consume(h.p(), { ...req, port: 99 }); } catch { /* denial 2 at t1 */ }
  const denials = h.f._auditIndex('acme').denials.filter(d => d.request_id === req.request_id);
  assert.equal(denials.length, 2, 'two same-triple anchors landed');
  const [d1] = denials;
  const rowIds = h.f.store.ids('acme', 'containment', 10000);
  const older = rowIds.map(id => ({ id, v: h.f.store.get('acme', 'containment', id) })).find(x => x.v?.contained_at === d1.at);
  assert.ok(older, 'older occurrence row located');
  h.f.store.db.prepare("DELETE FROM records WHERE tenant='acme' AND kind='containment' AND id=?").run(older.id);
  const rep = h.f.containmentReport(h.p('security'));
  assert.equal(rep.anchored_denials_missing_total, 1);
  assert.equal(rep.anchored_denials_missing_rows.length, 1);
  assert.equal(rep.anchored_denials_missing_rows[0].at, d1.at, 'the MURDERED occurrence is named — the live row must not claim its seat');
  h.close();
});

// --- fixverify M-2: the heal window closes on wall time too ---
const jitCert = h => {
  const r = h.proposed('identity.jit.grant', { subject_id: 'operator', resources: ['dataset-1'], actions: ['data.read'], destinations: ['customer-vault'], columns: ['id'], row_ids: ['row-1'], ttl_ms: 300000, reason: 'Incident', roles: [] }, { action: { type: 'identity.jit.grant', target_resource: 'jit-grants', purpose: 'JIT' } });
  h.evidence(r, { kind: 'identity_proof' }); h.evidence(r, { kind: 'identity_proof', issuer: 'registry' }); h.approve(r, 2);
  return { record: r, certificate: h.f.certificate(h.p(), r.capsule.capsule_id) };
};

test('w47 fixverify M-2: an idle-tenant grant-row murder convicts once the wall bound closes', t => {
  const h = fixture(t);
  const cert = jitCert(h);
  h.f.execute(h.p(), cert.certificate); // JIT_GRANT_ISSUED anchored; apply lands the grants row
  const gid = `jit-${cert.certificate.payload.certificate_id}`;
  h.f.target.db.prepare("DELETE FROM grants WHERE tenant='acme' AND grant_id=?").run(gid);
  // Inside the apply window the missing dataplane row is still honest —
  // the in-flight heal may not have landed on this read.
  h.f.grantsFor('acme', 'operator', h.now());
  // No further appends (idle tenant): the seq bound alone would stay open
  // forever. Sixty seconds of wall time is the other bound — a mid-apply
  // cannot still be in flight, so the murder convicts.
  h.advance(61_000);
  assert.throws(() => h.f.grantsFor('acme', 'operator', h.now()), hasCode('INV-409-INTEGRITY'));
  h.close();
});

// --- seal F-1: a mid-flight records drop classifies INV-409, not raw sqlite ---
test('w47 seal F-1: dropping records inside the seal surface classifies INV-409-INTEGRITY', t => {
  const h = fixture(t);
  h.f.store.db.exec('DROP TABLE records');
  assert.throws(() => h.f.sealAuditChain(h.p('security')), hasCode('INV-409-INTEGRITY'));
  h.close();
});

// --- seal F-2: a dropped meta_kv leaves a named residue attestation ---
test('w47 seal F-2: empty meta_kv under non-empty audit attests the dropped table', t => {
  const h = fixture(t);
  h.f.execute; // ledger has rows for acme before close
  h.close();
  const raw = new DatabaseSync(join(h.directory, 'fabric.db'));
  raw.exec('DROP TABLE meta_kv');
  raw.close();
  const f2 = new Fabric(h.setup.config, h.directory, h.now);
  const hit = f2.store.db.prepare("SELECT envelope FROM audit WHERE tenant='acme'").all()
    .map(r => { try { return JSON.parse(r.envelope); } catch { return null; } })
    .find(e => e?.payload?.type === 'STORE_SCHEMA_RESIDUE');
  assert.ok(hit, 'STORE_SCHEMA_RESIDUE anchor names the dropped meta_kv');
  assert.equal(hit.payload.metadata.reason, 'meta_kv-empty-under-nonempty-audit');
  f2.close();
});
