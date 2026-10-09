import test from 'node:test';
import assert from 'node:assert/strict';
import { fixture, hasCode, runtimeInput, runtimeRequest } from './helpers.mjs';
import { writeFileSync, readFileSync, rmSync, mkdtempSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { InvariantError } from '../src/errors.mjs';

// Wave-55 regressions (runtime 14th-pass + seal 17th-pass + fix-verify of
// w54): a CAST-poisoned fold_floor marker wedged every append including
// the seal's own mints (C-1/F-1), a dedup-suppressed quarantine denial
// still wrote a containment row and could pin a murdered memo anchor
// (F-2/F-3), a seal refusal retired latched convictions (H-1), and the
// check/traceability gates had dead-code laundry shapes (H-2/H-3/H-4/M-1,
// F-2 freshness, F-4 marker reset, F-7 empty-chain consult).

// w76-fv F-1: the schema-version pin convicts a dropped guard set at the
// next guarded call — snapshot the canonical trigger text before the graft
// and restore it after (the pin re-verifies and re-pins silently).
let _auditSnap = [];
const dropAuditGuards = h => {
  _auditSnap = h.f.store.db.prepare("SELECT name,sql FROM sqlite_master WHERE type='trigger' AND tbl_name='audit'").all();
  for (const tr of _auditSnap)
    h.f.store.db.exec(`DROP TRIGGER "${tr.name}"`);
};
const restoreAuditGuards = h => {
  for (const tr of _auditSnap) { try { h.f.store.db.exec(tr.sql); } catch (e) { if (!/already exists/.test(String(e?.message ?? e))) throw e; } }
};
const maxSeq = h => h.f.store.db.prepare("SELECT COALESCE(MAX(seq),0) m FROM audit WHERE tenant='acme'").get().m;
const markerValue = h => h.f.store.db.prepare("SELECT value FROM meta_kv WHERE tenant='acme' AND key='fold_floor'").get()?.value;
const healedValue = h => h.f.store.db.prepare("SELECT value FROM meta_kv WHERE tenant='acme' AND key='fold_floor_healed'").get()?.value;
const wmTamper = (h, kind) => (seal => (seal.head_watermark_tampered ?? []).some(e => e.kind === kind));

// --- C-1/F-1 (CRITICAL, both reports): a malformed marker CAST-poisons
// the guarded UPSERT — the append heals it instead of wedging, and the
// divergent content is preserved on the same trust plane. The residue row
// is one-shot: the fold consult verifies the pointer against the signed
// chain and retires it only once the conviction reaches a report surface
// (w56: durable-until-report, chain-anchored).
test('w55 C-1a: a CAST-high marker self-heals and names its residue floor_marker_healed', t => {
  const h = fixture(t);
  h.ready(); h.ready();
  const tip = maxSeq(h);
  h.f.store.db.prepare("UPDATE meta_kv SET value=? WHERE tenant='acme' AND key='fold_floor'").run(' 999999999:x');
  h.f.store.audit('acme', 'PROBE', 'actor', null, {}, h.f.clock()); // the append must not wedge on the planted marker
  assert.ok(maxSeq(h) > tip, 'the append landed despite the poisoned marker');
  assert.match(markerValue(h) ?? '', /^\d+:/, 'the marker reads well-formed after the heal');
  const seal = h.f.sealAuditChain(h.p('security'));
  const healed = (seal.head_watermark_tampered ?? []).find(e => e.kind === 'floor_marker_healed');
  assert.ok(healed, `the residue is named once: ${JSON.stringify(seal.head_watermark_tampered)}`);
  assert.match(healed.healed_marker ?? '', /^ 999999999:x$/, 'the conviction carries the divergent content bound to the healing append');
  const seal2 = h.f.sealAuditChain(h.p('security'));
  assert.ok(!wmTamper(h, 'floor_marker_healed')(seal2), 'a reported residue does not re-report');
  h.close();
});

// The CAST-low shape ('abc' → CAST 0) took the silent-overwrite arm — the
// heal evidence must be written there too (M-3: no silent erasure).
test('w55 C-1b: a CAST-low malformed marker also lands fold_floor_healed evidence', t => {
  const h = fixture(t);
  h.ready(); h.ready();
  h.f.store.db.prepare("UPDATE meta_kv SET value=? WHERE tenant='acme' AND key='fold_floor'").run('abc');
  h.f.store.audit('acme', 'PROBE', 'actor', null, {}, h.f.clock());
  assert.match(markerValue(h) ?? '', /^\d+:/, 'the marker reads well-formed');
  const seal = h.f.sealAuditChain(h.p('security'));
  const healed = (seal.head_watermark_tampered ?? []).find(e => e.kind === 'floor_marker_healed');
  assert.ok(healed, `the overwritten garbage is named: ${JSON.stringify(seal.head_watermark_tampered)}`);
  assert.match(healed.healed_marker ?? '', /^abc$/, 'the conviction carries the divergent content');
  h.close();
});

// --- runtime F-2/F-3 (HIGH+MEDIUM): a dedup-suppressed rejection minted
// no anchor — under the old code it still wrote a containment row and, on
// put failure, could pin the memo's seq of a murdered anchor (absorbing
// its murder). Now suppression is total: no row, no attestation.
test('w55-runtime F-2/F-3: a dedup-suppressed gate denial writes no row and attests nothing', t => {
  const h = fixture(t);
  const cap = h.f.runtime.issue(h.p('operator'), runtimeInput());
  h.f.revoke(h.p('security'), { kind: 'device', id: 'operator-device', reason: 'w55 probe' });
  const count = () => h.f.store.db.prepare("SELECT COUNT(*) n FROM audit WHERE tenant='acme' AND (envelope LIKE '%SECURITY_OPERATION_REJECTED%' OR envelope LIKE '%AUTHORIZATION_DENIED%' OR envelope LIKE '%RUNTIME_DENIED%' OR envelope LIKE '%CONTAINMENT_ROW_UNCOMMITTED%')").get().n;
  const rows = () => h.f.store.db.prepare("SELECT COUNT(*) n FROM records WHERE tenant='acme' AND kind='containment' AND id LIKE 'deny:%'").get().n;
  assert.throws(() => h.f.runtime.consume(h.p('operator'), runtimeRequest(cap)), hasCode('INV-403-QUARANTINE'));
  const anchors = count(), rowsBefore = rows();
  assert.ok(anchors > 0, 'the first denial was evidenced');
  assert.throws(() => h.f.runtime.consume(h.p('operator'), runtimeRequest(cap)), hasCode('INV-403-QUARANTINE'));
  assert.equal(count(), anchors, 'a suppressed denial mints no second anchor and no attestation');
  assert.equal(rows(), rowsBefore, 'a suppressed denial writes no second row');
  h.close();
});

// --- runtime F-4: a failed dedup bump falls through to a fresh anchored
// mint — a transient put failure must not eat the denial's evidence.
test('w55-runtime F-4: a failed dedup bump falls through to the fresh anchored mint', t => {
  const h = fixture(t);
  const cap = h.f.runtime.issue(h.p('operator'), runtimeInput());
  h.f.revoke(h.p('security'), { kind: 'device', id: 'operator-device', reason: 'w55 probe' });
  assert.throws(() => h.f.runtime.consume(h.p('operator'), runtimeRequest(cap)), hasCode('INV-403-QUARANTINE'));
  const orig = h.f.store.put.bind(h.f.store);
  let blocked = true;
  h.f.store.put = (...a) => { if (blocked && a[1] === 'containment' && a[3]?.dropped_requests) { blocked = false; throw new InvariantError('INV-503-LEDGER', 'bump fail'); } return orig(...a); };
  assert.throws(() => h.f.runtime.consume(h.p('operator'), runtimeRequest(cap)), hasCode('INV-403-QUARANTINE'));
  h.f.store.put = orig;
  const denyRows = h.f.store.db.prepare("SELECT id FROM records WHERE tenant='acme' AND kind='containment' AND id LIKE 'deny:%'").all();
  assert.ok(denyRows.some(r => r.id.split(':').length >= 3), `the fall-through mints a fresh deny:id:code row, not a swallowed bump: ${JSON.stringify(denyRows.map(r => r.id))}`);
  h.close();
});

// --- fv H-1 (HIGH): a refusal is not an attestation surface — throwing
// mid-seal carries the latched convictions in details but must NOT retire
// them; only a delivered report may.
test('w55-fv H-1: an attacker-inducible refusal cannot retire a latched conviction', t => {
  const h = fixture(t);
  h.ready(); h.ready();
  h.f.store.db.prepare("UPDATE meta_kv SET value=? WHERE tenant='acme' AND key='fold_floor'").run('not-a-marker');
  h.f._foldFloorMarker('acme', 0); // latch the malformed conviction
  // Force a refusal mid-seal: an amputated tip drives mints, and the
  // first mint throws — an attacker holds this shape (a poisoned write
  // path) on demand.
  dropAuditGuards(h);
  h.f.store.db.prepare("DELETE FROM audit WHERE tenant='acme' AND seq=?").run(maxSeq(h));
  restoreAuditGuards(h);
  const orig = h.f.store.audit.bind(h.f.store);
  let block = true;
  h.f.store.audit = (...a) => { if (block) { block = false; throw new InvariantError('INV-503-LEDGER', 'planted refusal'); } return orig(...a); };
  try { h.f.sealAuditChain(h.p('security')); assert.fail('the planted refusal must propagate'); }
  catch (e) {
    assert.ok((e.details?.head_watermark_tampered ?? []).some(x => x.kind === 'floor_marker_malformed'), `the refusal still carries the conviction: ${JSON.stringify(e.details)}`);
  }
  h.f.store.audit = orig;
  // The conviction survived the refusal — the next delivered report names it.
  const seal = h.f.sealAuditChain(h.p('security'));
  assert.ok(wmTamper(h, 'floor_marker_malformed')(seal), `the conviction is delivered on the real surface: ${JSON.stringify(seal.head_watermark_tampered)}`);
  h.close();
});

// --- seal F-4: the cut path resets the marker with the doomed rows it
// named — the next seal must not convict a phantom ahead/forged.
test('w55-seal F-4: the cut path resets the floor marker — no phantom conviction on the next seal', t => {
  const h = fixture(t);
  h.ready(); h.ready(); h.ready();
  const tip = maxSeq(h);
  dropAuditGuards(h);
  // Envelope corruption (not a delete) drives the real cut path — the
  // marker naming the doomed tip must die with it, or every later seal
  // convicts a phantom floor_marker_ahead/forged.
  h.f.store.db.prepare("UPDATE audit SET envelope=? WHERE tenant='acme' AND seq=?").run('{"payload":{"time":1},"signatures":[{"signature":"AA"}]}', tip);
  const r = h.f.sealAuditChain(h.p('security'));
  assert.equal(r.sealed, true);
  assert.ok(markerValue(h) === undefined || /^\d+:/.test(markerValue(h)), `the marker names post-cut content or is gone: ${markerValue(h)}`);
  const r2 = h.f.sealAuditChain(h.p('security'));
  assert.ok(!(r2.head_watermark_tampered ?? []).some(e => e.kind?.startsWith('floor_marker_')), `no phantom floor conviction: ${JSON.stringify(r2.head_watermark_tampered)}`);
  h.close();
});

// --- seal F-7: the empty-chain re-anchor consults the marker before
// deleting it — a planted marker on a wiped chain must attest, not erase.
test('w55-seal F-7: the empty-chain re-anchor consults a planted marker before deleting it', t => {
  const h = fixture(t);
  h.ready(); h.ready();
  const tip = maxSeq(h);
  dropAuditGuards(h);
  h.f.store.db.prepare("DELETE FROM audit WHERE tenant='acme'").run();
  restoreAuditGuards(h);
  h.f.store.db.prepare("UPDATE meta_kv SET value=? WHERE tenant='acme' AND key='fold_floor'").run(`${tip + 50}:deadbeef`);
  // The signed watermark survives (wm > 0) but the head file is gone —
  // the empty-chain re-anchor arm owns this shape.
  rmSync(join(h.directory, 'chain-heads.json'), { force: true });
  const r = h.f.sealAuditChain(h.p('security'));
  const kinds = (r.head_watermark_tampered ?? []).map(e => e.kind);
  assert.ok(kinds.some(k => k.startsWith('floor_marker_')), `the planted marker is attested, not silently erased: ${JSON.stringify(kinds)}`);
  h.close();
});

// --- seal F-2: the production-gate freshness claim is mode-independent —
// a checkOnly-shaped value deterministically stale-failed CI.
test('w55-seal F-2: production-gate freshness_arm does not vary by mode', t => {
  const src = readFileSync('scripts/report.mjs', 'utf8');
  assert.ok(!/freshness_arm:\s*checkOnly/.test(src), 'the freshness claim is a constant, not a mode-shaped value');
});

// ============================================================================
// Gate regressions — run the shipped functions/scans, never a source grep.
// ============================================================================
const ledgerCopyTree = () => {
  const dir = mkdtempSync(join(tmpdir(), 'w55-ledger-'));
  execFileSync('sh', ['-c', 'git ls-files -z | xargs -0 cp --parents -t "$1"', 'sh', dir], { cwd: new URL('..', import.meta.url).pathname });
  return dir;
};
const specPatched = (dir, patch) => {
  const spec = join(dir, 'docs/openapi.json');
  const obj = JSON.parse(readFileSync(spec, 'utf8'));
  patch(obj);
  writeFileSync(spec, JSON.stringify(obj, null, 2));
};
const checkErr = dir => {
  try {
    execFileSync(process.execPath, ['scripts/check.mjs'], { cwd: dir, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
    return null;
  } catch (e) { return String(e.stderr ?? '') + String(e.stdout ?? ''); }
};
const pyEval = expr => execFileSync('python3', ['-c',
  `import json\nsrc=open('scripts/traceability.py').read()\ng={'__file__':'scripts/traceability.py'}\nexec(src[:src.index('def evidence_blocks')], g)\nprint(${expr})`], { encoding: 'utf8' }).trim();

// --- fv H-2: braces inside a route's string literal must not skew the
// parity window into the next arm's authorize (laundering) or truncate it.
test('w55-fv H-2: braces inside route strings do not corrupt the parity window', t => {
  const dir = ledgerCopyTree();
  try {
    specPatched(dir, o => {
      o.paths['/strbrace'] = { get: { description: 'Roles: unauthenticated. plant' } };
      o.paths['/afterbrace'] = { get: { description: 'Roles: auditor. plant' } };
    });
    const srv = join(dir, 'src/server.mjs');
    const src = readFileSync(srv, 'utf8');
    const arm = `if (path === '/strbrace' && req.method === 'GET') { const s = '{"a":'; return send(200, { ok: true }); }
      if (path === '/afterbrace' && req.method === 'GET') { fabric.authorize(p, ['auditor']); return send(200, { ok: true }); }
      `;
    writeFileSync(srv, src.replace("const p = auth(req", arm + "const p = auth(req"));
    const out = checkErr(dir);
    assert.ok(out == null || !out.includes('strbrace'), `a string brace must not extend the window into the next arm's gate: ${out?.slice(0, 400)}`);
    assert.ok(out == null || !out.includes('afterbrace'), `the gated sibling resolves on its own arm: ${out?.slice(0, 400)}`);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

// --- fv H-3: `false &&` at statement start, `false &&` inside a string
// (which must not eat the real gate after it), and a dead arm spilling
// across lines — none of them launder a claim.
test('w55-fv H-3: dead-operand, string-first and multiline false&& shapes do not launder gates', t => {
  const dir = ledgerCopyTree();
  try {
    specPatched(dir, o => {
      o.paths['/deadgate'] = { get: { description: 'Roles: unauthenticated. plant' } };
      o.paths['/strdead'] = { get: { description: 'Roles: auditor. plant' } };
      o.paths['/mldead'] = { get: { description: 'Roles: unauthenticated. plant' } };
    });
    const srv = join(dir, 'src/server.mjs');
    const src = readFileSync(srv, 'utf8');
    const arm = `if (path === '/deadgate' && req.method === 'GET') { false && fabric.authorize(p, ['security']); return send(200, { ok: true }); }
      if (path === '/strdead' && req.method === 'GET') { send(200, { ok: true }), 'x false && y', fabric.authorize(p, ['auditor']); return; }
      if (path === '/mldead' && req.method === 'GET') { cond, false &&
        fabric.authorize(p, ['security']); return send(200, { ok: true }); }
      `;
    writeFileSync(srv, src.replace("const p = auth(req", arm + "const p = auth(req"));
    const out = checkErr(dir);
    assert.ok(out == null || !out.includes('deadgate'), `a dead-operand gate must not resolve: ${out?.slice(0, 400)}`);
    assert.ok(out == null || !out.includes('strdead'), `a 'false &&' inside a string must not eat the real gate: ${out?.slice(0, 400)}`);
    assert.ok(out == null || !out.includes('mldead'), `a multiline dead arm must not resolve: ${out?.slice(0, 400)}`);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

// --- fv H-4: a dead emit cannot resurrect a listener's asserts; a dead
// listener cannot be resurrected by a live emit.
test('w55-fv H-4: dead emits and dead listeners mint no evidence', t => {
  const asserts = body => JSON.parse(pyEval(`json.dumps(bool(g['_asserts'](${JSON.stringify(body)})))`));
  assert.equal(asserts("t => { bus.on('go', () => assert.ok(1)); if (false) { bus.emit('go') } }"), false, 'a dead emit cannot resurrect the listener');
  assert.equal(asserts("t => { if (false) { bus.on('go', () => assert.ok(1)) }; bus.emit('go') }"), false, 'a dead listener is never registered');
  assert.equal(asserts("t => { bus.on('go', () => assert.ok(1)); bus.emit('go') }"), true, 'a live on/emit pair still counts');
});

// --- fv M-1: a hoisted/backward-referenced declaration is live; a bind
// inside dead code is not a bind.
test('w55-fv M-1: backward-referenced declarations count, dead binds do not', t => {
  const asserts = body => JSON.parse(pyEval(`json.dumps(bool(g['_asserts'](${JSON.stringify(body)})))`));
  assert.equal(asserts("t => { live(); function live() { assert.ok(1) } }"), true, 'a call above the declaration still invokes it');
  assert.equal(asserts("t => { run(() => cb()); function cb() { assert.ok(1) } }"), true, 'a callback-referenced declaration is live');
  assert.equal(asserts("t => { function dead() { assert.ok(1) } }"), false, 'an uninvoked declaration stays dead');
  const binds = text => JSON.parse(pyEval(`json.dumps(bool(g['_prod_binds'](${JSON.stringify(text)})))`));
  assert.equal(binds("const f = require('../src/fabric.mjs')\ntest('REQ-X', t => { assert.ok(1) })"), true, 'a live require binds');
  assert.equal(binds("if (false) { const f = require('../src/fabric.mjs') }\ntest('REQ-X', t => { assert.ok(1) })"), false, 'a require inside dead code binds nothing');
});
