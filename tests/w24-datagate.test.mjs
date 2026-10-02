// Wave-24 data-gate regressions — every test asserts the honest semantics
// the w24 datagate auditor falsified on 20f8fa7 (F1 transform-arg
// smuggling, F2 stale-window cross-dimension loosening, F3 tokenise-key
// overrequirement, F4 watermark row-identity collision).
import test from 'node:test';
import assert from 'node:assert/strict';
import { fixture, hasCode, installPolicy, setTenant, stageConstitution, runtimeInput, runtimeRequest } from './helpers.mjs';

// F1: an aggregate bucket below the policy floor is identity, not
// generalization — issue() refuses it before the capability can sign.
test('w24-dg F1: aggregate arg below the policy bucket floor is refused at issue', t => {
  const h = fixture(t);
  h.f.target.seed('acme', 'dataset-1', {
    columns: ['id', 'name', 'region', 'passport', 'salary'], classification: 'internal', jurisdiction: 'EU',
    rows: [
      { id: 'row-1', name: 'Ada', region: 'EU', passport: 'P1', salary: 42000 },
      { id: 'row-2', name: 'Lin', region: 'EU', passport: 'P2', salary: 68000 },
      { id: 'row-3', name: 'Sam', region: 'EU', passport: 'P3', salary: 51000 },
      { id: 'row-4', name: 'Kim', region: 'EU', passport: 'P4', salary: 39000 }],
  });
  setTenant(h, 'acme', tn => { for (const id of Object.keys(tn.identities)) tn.identities[id].grants.columns = [...tn.identities[id].grants.columns, 'salary']; });
  installPolicy(h, p => { p.runtime.allowed_columns.push('salary'); });
  assert.throws(() => h.f.runtime.issue(h.p(), runtimeInput({ columns: ['id', 'salary'], row_ids: ['row-1'], transforms: { salary: { op: 'aggregate', arg: 1 } } })), hasCode('INV-400-SCHEMA'));
  assert.throws(() => h.f.runtime.issue(h.p(), runtimeInput({ columns: ['id', 'salary'], row_ids: ['row-1'], transforms: { salary: { op: 'aggregate', arg: 4 } } })), hasCode('INV-400-SCHEMA'));
  // A conforming bucket is admitted and generalizes honestly.
  const cap = h.f.runtime.issue(h.p(), runtimeInput({ columns: ['id', 'salary'], row_ids: ['row-1'], transforms: { salary: { op: 'aggregate', arg: 10000 } } }));
  const out = h.f.runtime.consume(h.p(), runtimeRequest(cap));
  assert.equal(out.rows[0].salary, '40000-49999');
});

// F1b: a non-scalar constant arg is refused at issue, not reflected into egress.
test('w24-dg F1b: a non-scalar constant transform arg is refused at issue', t => {
  const h = fixture(t);
  assert.throws(() => h.f.runtime.issue(h.p(), runtimeInput({ transforms: { name: { op: 'constant', arg: { smuggle: 'obj' } } } })), hasCode('INV-400-SCHEMA'));
  const cap = h.f.runtime.issue(h.p(), runtimeInput({ transforms: { name: { op: 'constant', arg: 'REDACTED' } } }));
  assert.equal(h.f.runtime.consume(h.p(), runtimeRequest(cap)).rows[0].name, 'REDACTED');
});

// F2: stale_ms[k] can never exceed max_stale_ms inside one policy — the
// cross-dimension loosening is a schema error, not a silent grant.
test('w24-dg F2: a class stale window above max_stale_ms fails schema validation', t => {
  const h = fixture(t);
  assert.throws(() => installPolicy(h, p => {
    p.max_stale_ms = 0;
    p.stale_ms = { default: 0, 'data.read': 300000, 'service.connect': 0 };
    p.fail_modes['data.read'] = 'cached-allow';
  }), hasCode('INV-451-POLICY'));
  // A tightening class key still installs and still binds at consume.
  installPolicy(h, p => { p.stale_ms = { default: 300000, 'data.read': 1000, 'service.connect': 300000 }; p.fail_modes['data.read'] = 'cached-allow'; });
  const cap = h.f.runtime.issue(h.p(), runtimeInput());
  h.advance(5000);
  const next = h.clone(h.f.policy('acme')); next.version += 1; next.runtime.max_cost = 9999;
  stageConstitution(h, next, { activate_at: h.now() });
  assert.throws(() => h.f.runtime.consume(h.p(), runtimeRequest(cap)), hasCode('INV-503-GATE'));
});

// F3: the tokenise key is fetched only when a transform actually uses it —
// a mask-only capability consumes cleanly on a keyless tenant.
test('w24-dg F3: a mask-only capability consumes on a tenant without a tokenise key', t => {
  const h = fixture(t);
  setTenant(h, 'acme', tn => { delete tn.tokenise_key; delete tn.tokenise_key_wrapped; });
  const cap = h.f.runtime.issue(h.p(), runtimeInput({ transforms: { name: { op: 'mask' } } }));
  const out = h.f.runtime.consume(h.p(), runtimeRequest(cap));
  assert.match(out.rows[0].name, /^••••/);
  // A real tokenise transform still fails honestly on the same tenant.
  const bad = h.f.runtime.issue(h.p(), runtimeInput({ transforms: { name: { op: 'tokenise' } } }));
  assert.throws(() => h.f.runtime.consume(h.p(), runtimeRequest(bad)), hasCode('INV-503-CONFIG'));
});

// F4: watermark row identity is always the physical storage row — marks on
// an id-less export join back to dataset_rows and never collide.
test('w24-dg F4: id-less export watermarks carry the physical row_id', t => {
  const h = fixture(t);
  h.f.target.seed('acme', 'dataset-1', {
    columns: ['id', 'name', 'region', 'passport'], classification: 'internal', jurisdiction: 'EU',
    rows: [
      { id: 'row-1', name: 'Same Person', region: 'EU', passport: 'P1' },
      { id: 'row-2', name: 'Same Person', region: 'EU', passport: 'P2' },
      { id: 'row-3', name: 'Someone Else', region: 'EU', passport: 'P3' }],
  });
  const r = h.proposed('data.export',
    { dataset: 'dataset-1', columns: ['name', 'region'], row_ids: ['row-1', 'row-2'], max_rows: 2, classification: 'internal', jurisdiction: 'EU' },
    { action: { type: 'data.export', target_resource: 'dataset-1', purpose: 'Attribution audit' } });
  h.evidence(r, { kind: 'dataset_authority' });
  h.approve(r, 1);
  const outcome = h.f.execute(h.p(), h.f.certificate(h.p(), r.capsule.capsule_id));
  assert.equal(outcome.payload.status, 'VERIFIED');
  const marks = outcome.payload.watermarks;
  assert.deepEqual(marks.map(m => m.row_id).sort(), ['row-1', 'row-2']);
  // Identical projections keep distinct, source-joinable attribution.
  assert.notEqual(marks[0].tag, marks[1].tag);
});

// F4b: the consume path attributes the physical row too — id-less
// projections still join back to dataset_rows.
test('w24-dg F4b: consume watermarks bind the physical row_id without an id column', t => {
  const h = fixture(t);
  const cap = h.f.runtime.issue(h.p(), runtimeInput({ columns: ['name'], row_ids: ['row-1'] }));
  const out = h.f.runtime.consume(h.p(), runtimeRequest(cap));
  assert.equal(out.watermarks[0].row_id, 'row-1');
});
