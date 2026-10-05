// w57 self-audit regressions from the seal/residue-plane audit:
//  F1 — the residue pointer was single-slot: two marker heals before one
//       report overwrote each other, so only the last divergent content
//       reached the surface. Residue rows are now keyed per heal and the
//       conviction carries a heals list — every heal is named.
//  F2 — #wmTamper is not transactional: a heal latched on in-tx
//       uncommitted evidence survived an abort as a phantom conviction.
//       The flag map now rides the tx-depth snapshot like the other
//       in-memory anchors.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { clone } from '../src/canonical.mjs';
import { fixture } from './helpers.mjs';

const residueRows = h => h.f.store.db.prepare(
  "SELECT key,value FROM meta_kv WHERE tenant='acme' AND (key='fold_floor_healed' OR substr(key,1,18)='fold_floor_healed.')").all();

test('w57-seal F1: two heals before one report are both named', t => {
  const h = fixture(t);
  h.ready(); h.ready();
  h.f.store.db.prepare("UPDATE meta_kv SET value=? WHERE tenant='acme' AND key='fold_floor'").run('planted-A:garbage');
  h.f.store.audit('acme', 'PROBE', 'actor', null, {}, h.f.clock());
  h.f.store.db.prepare("UPDATE meta_kv SET value=? WHERE tenant='acme' AND key='fold_floor'").run('planted-B:garbage');
  h.f.store.audit('acme', 'PROBE', 'actor', null, {}, h.f.clock());
  assert.equal(residueRows(h).length, 2, 'each heal keeps its own residue pointer');
  const seal = h.f.sealAuditChain(h.p('security'));
  const healed = (seal.head_watermark_tampered ?? []).filter(e => e.kind === 'floor_marker_healed');
  const contents = healed.map(e => e.healed_marker).sort();
  assert.deepEqual(contents, ['planted-A:garbage', 'planted-B:garbage'],
    `every heal reaches the report: ${JSON.stringify(seal.head_watermark_tampered)}`);
  // The residue retires with the named convictions — a second seal must
  // not re-claim either heal.
  const seal2 = h.f.sealAuditChain(h.p('security'));
  assert.ok(!(seal2.head_watermark_tampered ?? []).some(e => e.kind === 'floor_marker_healed'),
    'all residue retires after one report');
  assert.equal(residueRows(h).length, 0, 'the keyed pointers are consumed exactly once');
  h.close();
});

test('w57-seal F2: a heal inside an aborted tx latches no phantom conviction', t => {
  const h = fixture(t);
  h.ready(); h.ready();
  h.f.store.db.prepare("UPDATE meta_kv SET value=? WHERE tenant='acme' AND key='fold_floor'").run('planted-abort:garbage');
  assert.throws(() => h.f.store.tx(() => {
    h.f.store.audit('acme', 'PROBE', 'actor', null, {}, h.f.clock());
    throw new Error('doomed');
  }), /doomed/);
  assert.equal(residueRows(h).length, 0, 'the residue pointer rolled back with the append');
  const seal = h.f.sealAuditChain(h.p('security'));
  const healed = (seal.head_watermark_tampered ?? []).filter(e => e.kind === 'floor_marker_healed');
  assert.equal(healed.length, 0, `no phantom heal conviction: ${JSON.stringify(seal.head_watermark_tampered)}`);
  // The still-divergent committed marker is the truthful evidence — the
  // report names what actually stands, not the rolled-back mint.
  assert.ok((seal.head_watermark_tampered ?? []).some(e => e.kind === 'floor_marker_malformed' || e.kind === 'floor_marker_forged' || e.kind === 'floor_marker_ahead' || e.kind === 'floor_marker_orphaned'),
    'the standing marker divergence is still named honestly');
  h.close();
});

test('w57-seal F1 parity: two planted unanchored pointers are both named', t => {
  const h = fixture(t);
  h.ready(); h.ready();
  h.f.store.db.exec('DROP TRIGGER fold_residue_keep_ins');
  h.f.store.db.prepare("INSERT INTO meta_kv VALUES('acme','fold_floor_healed.9998',?)").run('9998:forged');
  h.f.store.db.prepare("INSERT INTO meta_kv VALUES('acme','fold_floor_healed.9999',?)").run('9999:forged');
  h.f.store.db.exec("CREATE TRIGGER fold_residue_keep_ins BEFORE INSERT ON meta_kv WHEN NEW.key='fold_floor_healed' OR substr(NEW.key,1,18)='fold_floor_healed.' BEGIN SELECT RAISE(ABORT, 'fold-floor residue is evidence'); END");
  const seal = h.f.sealAuditChain(h.p('security'));
  const unanchored = (seal.head_watermark_tampered ?? []).filter(e => e.kind === 'floor_marker_healed_unanchored');
  assert.equal(unanchored.length, 2, `every planted pointer is named: ${JSON.stringify(seal.head_watermark_tampered)}`);
  assert.ok(!(seal.head_watermark_tampered ?? []).some(e => e.kind === 'floor_marker_healed'),
    'planted pointers mint no phantom heal conviction');
  h.close();
});
