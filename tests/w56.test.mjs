// w56 self-audit regressions: the append-side marker healer judged
// "well-formed" by `^\d+:` while the fold reader convicts strictly —
// '5:' (empty hash), '0:x' (seq < 1) and '5:a:b' (extra segment) counted
// honest on the write side and evaporated under a plain overwrite with
// no residue — a planted marker the reader would have named vanished
// silently (w56-1). The healer must now surface every reader-malformed
// shape as a named floor_marker_healed conviction.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fixture } from './helpers.mjs';

const markerValue = h => h.f.store.db.prepare("SELECT value FROM meta_kv WHERE tenant='acme' AND key='fold_floor'").get()?.value;

test('w56-1: reader-malformed marker shapes heal with the divergent content named', t => {
  const h = fixture(t);
  h.ready(); h.ready();
  for (const planted of ['5:', '0:x', '5:a:b', '9'.repeat(30) + ':h']) {
    h.f.store.db.prepare("UPDATE meta_kv SET value=? WHERE tenant='acme' AND key='fold_floor'").run(planted);
    h.f.store.audit('acme', 'PROBE', 'actor', null, {}, h.f.clock());
    const seal = h.f.sealAuditChain(h.p('security'));
    const healed = (seal.head_watermark_tampered ?? []).find(e => e.kind === 'floor_marker_healed');
    assert.ok(healed, `the heal of ${JSON.stringify(planted)} is named once: ${JSON.stringify(seal.head_watermark_tampered)}`);
    assert.equal(typeof healed.healed_marker === 'string' ? healed.healed_marker.split(':').slice(1).join(':') : healed.healed_marker, planted,
      'the conviction carries the planted content');
    // The huge-seq shape is intentionally left divergent (a plausible
    // floor is evidence, not garbage) — reset the marker plane for the
    // next iteration.
    if (markerValue(h) === planted)
      h.f.store.db.prepare("UPDATE meta_kv SET value=? WHERE tenant='acme' AND key='fold_floor'").run(`${(h.f.store.db.prepare("SELECT MAX(seq) s FROM audit WHERE tenant='acme'").get().s ?? 0)}:${'0'.repeat(64)}`);
  }
  h.close();
});
