import test from 'node:test';
import assert from 'node:assert/strict';
import { fixture, hasCode, runtimeInput, runtimeRequest } from './helpers.mjs';
import { writeFileSync, readFileSync, utimesSync, statSync, rmSync, copyFileSync, mkdirSync, mkdtempSync, existsSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

// Wave-54 regressions (runtime 13th-pass + seal 16th-pass reports on
// 2890b32): the fold_floor marker could be overwritten by honest appends
// and its flag retired by a consistent-looking rewrite (F-1 laundering),
// suppressed-denial uncommitted attestations fell back to the ±2s window
// (F-2), sealed_at_seq bound a stored-column value (M-1), in-tx wm flags
// were flushed before the report snapshot (M-2), and a stale probe could
// false-flag honest commits (M-3).

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
const wmTamper = (h, kind) => (seal => (seal.head_watermark_tampered ?? []).some(e => e.kind === kind));

// --- runtime F-1 (HIGH) + w66-seal F-2: an attacker-set divergent marker
// must be named, never silently overwritten — a `\d+`-shaped plant ahead
// of the committed tip wedges every later honest epoch attestation
// (guarded UPSERT refuses forever), so the append heals it to the true
// tip and attests the divergence on the signed chain: the append's own
// envelope carries fold_floor_divergent and a keyed fold_floor_healed.<seq>
// residue row names it on the next seal report.
test('w54-runtime F-1a + w66-seal F-2: an ahead-of-tip marker is healed on append and attested on-chain', t => {
  const h = fixture(t);
  h.ready(); h.ready();
  h.f._auditIndex('acme');
  const tip = maxSeq(h);
  const planted = `${tip + 1000}:${'a'.repeat(64)}`;
  h.f.store.db.prepare("UPDATE meta_kv SET value=? WHERE tenant='acme' AND key='fold_floor'").run(planted);
  h.ready(); h.ready(); // honest appends land below the planted span — guard refuses, heal writes the true tip
  const newTip = maxSeq(h);
  const tipHash = h.f.store.db.prepare("SELECT hash FROM audit WHERE tenant='acme' AND seq=?").get(newTip).hash;
  assert.equal(markerValue(h), `${newTip}:${tipHash}`, 'the divergent marker is healed to the committed tip');
  const divergent = h.f.store.db.prepare("SELECT json_extract(envelope,'$.payload.metadata.fold_floor_divergent') d FROM audit WHERE tenant='acme' AND envelope LIKE '%fold_floor_divergent%' ORDER BY seq DESC LIMIT 1").get()?.d;
  assert.equal(divergent, planted, 'the planted marker is named on the healing append\'s signed envelope');
  const healedRows = h.f.store.db.prepare("SELECT value FROM meta_kv WHERE tenant='acme' AND substr(key,1,18)='fold_floor_healed.'").all();
  assert.ok(healedRows.some(r => r.value.endsWith(`:${planted}`)), 'the heal residue row names the divergent marker');
  const seal = h.f.sealAuditChain(h.p('security'));
  assert.ok(wmTamper(h, 'floor_marker_healed')(seal), `the heal surfaces on the report: ${JSON.stringify(seal.head_watermark_tampered)}`);
  h.close();
});

// --- runtime F-1 (HIGH): marker flags are latched — a consistent rewrite
// after the observation cannot erase the conviction; it retires only once
// surfaced on a report.
test('w54-runtime F-1b: a marker rewritten consistent after the observation cannot erase the flag', t => {
  const h = fixture(t);
  h.ready(); h.ready();
  h.f._auditIndex('acme');
  const tip = maxSeq(h);
  // Plant a divergent marker and observe it once (the fold consult latches).
  h.f.store.db.prepare("UPDATE meta_kv SET value=? WHERE tenant='acme' AND key='fold_floor'").run(`${tip + 9}:${'a'.repeat(64)}`);
  h.f._foldFloorMarker('acme', tip);
  // Attacker cover: rewrite the marker to a consistent value and delete it.
  h.f.store.db.prepare("UPDATE meta_kv SET value=? WHERE tenant='acme' AND key='fold_floor'").run(`${tip}:ff`);
  const seal = h.f.sealAuditChain(h.p('security'));
  assert.ok(wmTamper(h, 'floor_marker_ahead')(seal), 'the latched conviction is reported once even though the marker now looks consistent');
  // Once surfaced, the flag retires — a clean marker state must not
  // re-report the same divergence forever.
  const seal2 = h.f.sealAuditChain(h.p('security'));
  assert.ok(!wmTamper(h, 'floor_marker_ahead')(seal2), 'an attested divergence does not re-report after the marker reads consistent');
  h.close();
});

// --- fv M-2 follow-on: the four marker kinds retire on the same rules —
// a malformed marker deleted after the observation reports once, then
// retires (a flag that never retired would convict a divergence the
// operator already removed forever).
test('w54 marker retirement: an attested malformed flag does not re-report after the marker is removed', t => {
  const h = fixture(t);
  h.ready(); h.ready();
  h.f._auditIndex('acme');
  const tip = maxSeq(h);
  h.f.store.db.prepare("UPDATE meta_kv SET value=? WHERE tenant='acme' AND key='fold_floor'").run('not-a-marker');
  h.f._foldFloorMarker('acme', tip);
  // Cover: the planted row is removed — only the latched conviction remains.
  h.f.store.db.prepare("DELETE FROM meta_kv WHERE tenant='acme' AND key='fold_floor'").run();
  const seal = h.f.sealAuditChain(h.p('security'));
  assert.ok(wmTamper(h, 'floor_marker_malformed')(seal), 'the planted-marker conviction reaches one report');
  const seal2 = h.f.sealAuditChain(h.p('security'));
  assert.ok(!wmTamper(h, 'floor_marker_malformed')(seal2), 'a removed marker cannot convict twice');
  h.close();
});

// --- runtime F-1 (HIGH): the sanctioned re-anchor resets the marker
// inside the same commit — the abandoned position is ledger-bound and the
// marker plane restarts at the repaired floor.
test('w54-runtime F-1c: a landed re-anchor resets the divergent marker and retires its flag', t => {
  const h = fixture(t);
  h.ready(); h.ready();
  h.f._auditIndex('acme');
  // A stale signed head (tip moved since) forces the re-anchor arm — and a
  // planted divergent marker rides the same repair.
  const snap = '/tmp/w54-head-snap'; mkdirSync(snap, { recursive: true });
  const headFile = join(h.directory, 'chain-heads.json');
  copyFileSync(headFile, join(snap, 'chain-heads.json'));
  h.ready();
  const tip = maxSeq(h);
  h.f.store.db.prepare("UPDATE meta_kv SET value=? WHERE tenant='acme' AND key='fold_floor'").run(`${tip + 500}:${'a'.repeat(64)}`);
  copyFileSync(join(snap, 'chain-heads.json'), headFile);
  const seal = h.f.sealAuditChain(h.p('security'));
  assert.equal(seal.head_reanchored, true, 'the stale head re-anchored');
  assert.ok(wmTamper(h, 'floor_marker_ahead')(seal), 'the divergent marker was attested by the repairing seal');
  const marker = markerValue(h);
  const newTip = maxSeq(h);
  assert.ok(!marker || Number(marker.split(':')[0]) <= newTip, 'the marker plane restarted at or below the post-repair tip');
  h.close();
});

// --- runtime F-2 (MEDIUM): a dedup-suppressed rejection mint leaves
// denialSeq null — the uncommitted attestation pins the SUPPRESSED
// anchor's seq, never the ±2s-any-anchor window.
test('w54-runtime F-2: a suppressed rejection pins the suppressed anchor seq on the uncommitted attestation', t => {
  const h = fixture(t);
  const cap = h.f.runtime.issue(h.p('operator'), runtimeInput());
  h.f.revoke(h.p('security'), { kind: 'device', id: 'operator-device', reason: 'w54 probe' });
  // A foreign trigger refuses the suppressed mint's containment put.
  // w76-fv F-1: a real planted trigger convicts 'live DDL' at the next
  // guarded call before any write reaches it — stage the same refusal at
  // the statement layer: the put's INSERT throws the RAISE(ROLLBACK)
  // errcode, exactly what deny_put produced.
  const origStmt = h.f.store._stmt.bind(h.f.store);
  h.f.store._stmt = (sql) => {
    const st = origStmt(sql);
    if (String(sql).startsWith('INSERT INTO records')) return {
      run: (...a) => { if (a[1] === 'containment' && /^deny:[^:]*$/.test(String(a[2]))) throw Object.assign(new Error('planted'), { errcode: 1811 }); return st.run(...a); },
      get: st.get.bind(st), all: st.all.bind(st) };
    return st;
  };
  try {
    // Two denials inside the 60s dedup window: the second mint is suppressed
    // but its refused put still attests — pinned to the first anchor's seq.
    assert.throws(() => h.f.runtime.consume(h.p('operator'), runtimeRequest(cap)), hasCode('INV-403-QUARANTINE'));
    assert.throws(() => h.f.runtime.consume(h.p('operator'), runtimeRequest(cap)), hasCode('INV-403-QUARANTINE'));
  } finally { h.f.store._stmt = origStmt; }
  const anchors = new Set(h.f.store.db.prepare("SELECT seq FROM audit WHERE tenant='acme'").all().map(r => r.seq));
  const uncommitted = h.f.store.db.prepare("SELECT seq, envelope FROM audit WHERE tenant='acme' AND envelope LIKE '%CONTAINMENT_ROW_UNCOMMITTED%' ORDER BY seq").all()
    .map(r => ({ seq: r.seq, meta: JSON.parse(r.envelope).payload.metadata ?? {} }));
  assert.ok(uncommitted.length >= 2, 'both refused puts attested');
  assert.ok(uncommitted.every(u => Number.isSafeInteger(u.meta.denial_seq) && anchors.has(u.meta.denial_seq)), `every attestation pins a real anchor seq — never the null ±2s window: ${JSON.stringify(uncommitted.map(u => u.meta.denial_seq))}`);
  h.close();
});

// --- seal M-1 (MEDIUM): sealed_at_seq binds the payload plane the signed
// mint attested — stored-seq surgery cannot inflate the cut boundary.
test('w54-seal M-1: sealed_at_seq binds the payload plane, not stored-seq surgery', t => {
  const h = fixture(t);
  h.ready(); h.ready(); h.ready();
  const tip = maxSeq(h);
  dropAuditGuards(h);
  // Corrupt the tip row AND inflate its stored seq — the reported cut
  // boundary must stay the payload-derived one (prevPlSeq + 1 = tip).
  const corrupt = "UPDATE audit SET envelope=?, seq=? WHERE tenant='acme' AND seq=?";
  h.f.store.db.prepare(corrupt).run('{"payload":{"time":1},"signatures":[{"signature":"AA"}]}', tip + 500, tip);
  const r = h.f.sealAuditChain(h.p('security'));
  assert.equal(r.sealed, true);
  assert.equal(r.sealed_at_seq, tip, `the payload-plane boundary stands (${tip}), not the stored ${tip + 500}`);
  h.close();
});

// --- seal M-2 (MEDIUM): file-side flags minted inside the reconcile tx
// (the forged watermark's own verify) are captured before the commit-edge
// flush clears them — they must reach the report.
test('w54-seal M-2: a forged watermark flag minted inside the reconcile tx reaches the report', t => {
  const h = fixture(t);
  h.ready(); h.ready();
  const tip = maxSeq(h);
  writeFileSync(join(h.directory, 'head-watermark.json'), JSON.stringify({ format: 'IF-HEADMARK-1', tenants: { acme: { seq: tip + 10, envelope: 'forged-bytes-not-a-signature' } } }) + '\n');
  const r = h.f.sealAuditChain(h.p('security'));
  assert.ok(wmTamper(h, 'unsigned_above_head')(r) || wmTamper(h, 'malformed')(r) || wmTamper(h, 'signature')(r),
    `the forged entry's own verify flag reaches the report: ${JSON.stringify(r.head_watermark_tampered)}`);
  h.close();
});

// --- seal M-3 (MEDIUM): committedMax is re-probed AFTER the marker read —
// a racing peer commit must not mint a false floor_marker_ahead.
test('w54-seal M-3: a marker at the committed tip against a stale attested floor does not false-flag', t => {
  const h = fixture(t);
  h.ready();
  h.f._auditIndex('acme'); // fold seals attestedFloor at this tip
  h.ready(); h.ready();    // honest commits advance marker+rows past the fold
  // Simulate the consult's stale floor: attestedFloor is the old fold tip.
  h.f._foldFloorMarker('acme', 1);
  const seal = h.f.sealAuditChain(h.p('security'));
  assert.ok(!wmTamper(h, 'floor_marker_ahead')(seal), `honest post-fold commits are not divergence: ${JSON.stringify(seal.head_watermark_tampered)}`);
  h.close();
});

// --- seal L-1 (LOW): a re-fire of the same kind moves the seq — the
// first divergence's position must not shadow a later one.
test('w54-seal L-1: a re-fired marker flag updates to the newest observed seq', t => {
  const h = fixture(t);
  h.ready(); h.ready();
  h.f._auditIndex('acme');
  const tip = maxSeq(h);
  h.f.store.db.prepare("UPDATE meta_kv SET value=? WHERE tenant='acme' AND key='fold_floor'").run(`${tip + 3}:${'a'.repeat(64)}`);
  h.f._foldFloorMarker('acme', tip);
  h.f.store.db.prepare("UPDATE meta_kv SET value=? WHERE tenant='acme' AND key='fold_floor'").run(`${tip + 8}:${'a'.repeat(64)}`);
  h.f._foldFloorMarker('acme', tip);
  const seal = h.f.sealAuditChain(h.p('security'));
  const entry = (seal.head_watermark_tampered ?? []).find(e => e.kind === 'floor_marker_ahead');
  assert.equal(entry?.seq, tip + 8, 'the reported seq is the newest divergence, not the first');
  h.close();
});

// --- seal L-2/L-7 (LOW): the commit-edge signed flush clears file-side
// evidence only — ledger-class convictions (floor_marker_forged) persist.
test('w54-seal L-2: a landed signed head cannot clear a ledger-class conviction', t => {
  const h = fixture(t);
  h.ready(); h.ready();
  h.f._auditIndex('acme');
  const tip = maxSeq(h);
  // A forged marker (real seq, foreign hash) flags floor_marker_forged.
  const rowHash = h.f.store.db.prepare("SELECT hash FROM audit WHERE tenant='acme' AND seq=?").get(tip).hash;
  h.f.store.db.prepare("UPDATE meta_kv SET value=? WHERE tenant='acme' AND key='fold_floor'").run(`${tip}:${'0'.repeat(64)}`);
  h.f._foldFloorMarker('acme', tip);
  // A subsequent honest append runs the commit-edge signed flush —
  // file-side flags would clear; the forged-marker conviction must not.
  h.ready();
  // Restore a consistent marker so the seal does not re-derive the flag —
  // the latched conviction alone must still surface.
  h.f.store.db.prepare("UPDATE meta_kv SET value=? WHERE tenant='acme' AND key='fold_floor'").run(`${maxSeq(h)}:${rowHash}`);
  const seal = h.f.sealAuditChain(h.p('security'));
  assert.ok(wmTamper(h, 'floor_marker_forged')(seal), 'the forged conviction survives the signed flush until attested');
  h.close();
});

// --- seal L-4 (LOW): a same-size wm rewrite with a restored mtime must
// still re-parse — ctime cannot be rewritten by utimesSync.
test('w54-seal L-4: a same-size watermark rewrite with restored mtime re-parses', t => {
  const h = fixture(t);
  h.ready();
  const p = join(h.directory, 'head-watermark.json');
  // Bare-int entries below the head resolve to themselves — an observable
  // value the stat-gate can serve stale only by skipping the re-parse.
  const body = seq => JSON.stringify({ format: 'IF-HEADMARK-1', tenants: { acme: seq } }) + '\n';
  const a = body(5), b = body(3);
  assert.equal(a.length, b.length, 'same-size bodies');
  writeFileSync(p, a);
  const first = h.f._headWatermark('acme');
  assert.equal(first, 5);
  writeFileSync(p, b);
  const st = statSync(p);
  utimesSync(p, st.atime, new Date(0)); // ctime still ticks — mtime lies
  const second = h.f._headWatermark('acme');
  assert.equal(second, 3, 'the ctime-changed file re-parses instead of serving the cached value');
  h.close();
});

// --- seal L-6 (LOW): the empty-chain re-anchor arm reports
// head_reanchored like the non-empty arm.
test('w54-seal L-6: the empty-chain re-anchor reports head_reanchored', t => {
  const h = fixture(t);
  h.ready();
  h.f._auditIndex('acme');
  // Preserve a signed high watermark while emptying the chain; the head
  // file must not survive or the residue refuse arm wins first.
  dropAuditGuards(h);
  h.f.store.db.prepare('DELETE FROM audit WHERE tenant=?').run('acme');
  restoreAuditGuards(h);
  rmSync(join(h.directory, 'chain-heads.json'), { force: true });
  const r = h.f.sealAuditChain(h.p('security'));
  assert.equal(r.head_reanchored, true, 'the empty-chain re-anchor is named the same as the non-empty arm');
  h.close();
});

// --- w54-ledger auditor regressions (26th-pass report on 2890b32):
// reachability-blind priorCalls, dead-branch authorize literals, nested-if
// window truncation, outside-scan blind spots, assert-minting dead shapes,
// an unused child_process import binding production, spaced marker
// spellings, and a release-check error taxonomy that called everything
// 'stale'.

const ledgerCopyTree = () => {
  const dir = mkdtempSync(join(tmpdir(), 'w54-ledger-'));
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

// H-1: an auth call nested inside an UNREACHABLE prior route arm must not
// satisfy the 'authenticated' contract on a deeper zero-auth route.
test('w54-ledger H-1: auth inside a dead prior arm does not launder authenticated', t => {
  const dir = ledgerCopyTree();
  try {
    specPatched(dir, o => { o.paths['/ledgerplantx'] = { get: { description: 'Roles: authenticated. plant' } }; });
    const srv = join(dir, 'src/server.mjs');
    const src = readFileSync(srv, 'utf8');
    const arm = `if (path === '/deadarm' && req.method === 'GET') { if (authenticateToken(req, 'ops')) return send(res, 200, { x: 1 }); }
    if (path === '/ledgerplantx' && req.method === 'GET') return send(res, 200, { ok: true });
    `;
    writeFileSync(srv, src.replace("const p = auth(req", arm + "const p = auth(req"));
    const out = checkErr(dir);
    assert.ok(out?.includes('ledgerplantx'), `the unreachable auth call must not satisfy the claim: ${out?.slice(0, 400)}`);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

// H-2: `false && authorize(p, ['security'])` never executes — the role
// claim must resolve as ungated, not as satisfied-by-literal.
test('w54-ledger H-2: a dead-branch authorize does not satisfy a role claim', t => {
  const dir = ledgerCopyTree();
  try {
    specPatched(dir, o => { o.paths['/deadauth'] = { get: { description: 'Roles: security. plant' } }; });
    const srv = join(dir, 'src/server.mjs');
    const src = readFileSync(srv, 'utf8');
    const arm = `if (path === '/deadauth' && req.method === 'GET') { const x = false && authorize(p, ['security']); return send(res, 200, { ok: true }); }
    `;
    writeFileSync(srv, src.replace("const p = auth(req", arm + "const p = auth(req"));
    const out = checkErr(dir);
    assert.ok(out?.includes('deadauth'), `a dead authorize must not satisfy the claim: ${out?.slice(0, 400)}`);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

// H-3 (positive): a real auth call one `if` deep INSIDE the arm block is
// reachable — the window must not truncate at the first nested `if`.
test('w54-ledger H-3: auth nested one if-deep inside the arm still satisfies authenticated', t => {
  const dir = ledgerCopyTree();
  try {
    specPatched(dir, o => { o.paths['/nestedauth'] = { get: { description: 'Roles: authenticated. plant' } }; });
    const srv = join(dir, 'src/server.mjs');
    const src = readFileSync(srv, 'utf8');
    const arm = `if (path === '/nestedauth' && req.method === 'GET') { if (!authenticateToken(req, 'ops')) return send(res, 401, { e: 1 }); return send(res, 200, { ok: true }); }
    `;
    writeFileSync(srv, src.replace("const p = auth(req", arm + "const p = auth(req"));
    const out = checkErr(dir);
    assert.ok(out == null || !out.includes('nestedauth'), `reachable nested auth must satisfy the claim: ${out?.slice(0, 400)}`);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

// H-4: dispatch surfaces in a .cjs file and in a non-scanned directory are
// live surface the three-root mjs-only walk never saw.
test('w54-ledger H-4: .cjs and out-of-tree dispatch surfaces flag', t => {
  const dir = ledgerCopyTree();
  try {
    writeFileSync(join(dir, 'scripts/__plant.cjs'), "require('http').createServer((req,res)=>{ if(req.url==='/x') res.end('x'); });\n");
    mkdirSync(join(dir, 'deploy'), { recursive: true });
    writeFileSync(join(dir, 'deploy/__plant.mjs'), "import http from 'node:http'; http.createServer((req,res)=>{ if(req.headers['x']) res.end('x'); });\n");
    // The gate rides `git ls-files` — a git-less copy only exercises the
    // fallback directory walk, not the tracked-set arm the fix claims
    // (w55-ledger H-5). Give the copy a real index, plants included.
    execFileSync('git', ['init', '-q'], { cwd: dir });
    execFileSync('git', ['add', '-A'], { cwd: dir });
    const out = checkErr(dir);
    assert.match(out ?? '', /__plant\.cjs/, 'the .cjs dispatch plant must flag');
    assert.match(out ?? '', /deploy\/__plant\.mjs/, 'the deploy-dir dispatch plant must flag');
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

// H-5: generator bodies, classic-fn param shadows and never-invoked class
// methods mint no asserts; an unused child_process import binds nothing.
test('w54-ledger H-5: dead assert shapes and the unused-import bind are dead evidence', t => {
  const py = `s = open('scripts/traceability.py').read()
g = {'__file__': 'scripts/traceability.py'}
exec(s[:s.index('for row in rows:')], g)
print(bool(g['_asserts']("test('X', () => { function* gen() { assert.ok(false); } gen(); })")))
print(bool(g['_asserts']("test('X', () => { for (const y of gen2()) assert.ok(y); })")))
print(bool(g['_asserts']("test('X', () => { function check(assert) { assert.ok(false); } check(()=>{}); })")))
print(bool(g['_asserts']("test('X', () => { class C { m() { assert.ok(false); } } new C(); })")))
print(bool(g['_asserts']("test('X', () => { class D { m() { assert.ok(false); } } const d = new D(); d.m(); })")))
print(g['_prod_binds']("import { execFileSync } from 'node:child_process'; test('X', () => assert.ok(true));"))
print(g['_prod_binds']("import { execFileSync } from 'node:child_process'; test('X', () => assert.ok(execFileSync('true')));"))
print(g['_prod_binds']("import { execFileSync } from 'node:child_process'; test('X', () => assert.ok(execFileSync('node', ['scripts/check.mjs'])));"))`;
  const out = execFileSync('python3', ['-c', py], { cwd: new URL('..', import.meta.url).pathname, encoding: 'utf8' }).trim().split('\n');
  assert.deepEqual(out, ['False', 'True', 'False', 'False', 'True', 'False', 'False', 'True'],
    'uniterated generator, shadowed param, never-invoked method, unused import and a repo-free spawn are all dead; live shapes still count');
});

// M-1: spaced spellings are the same unfinished marker.
test('w54-ledger M-1: the marker gate flags spaced spellings', t => {
  const dir = ledgerCopyTree();
  try {
    writeFileSync(join(dir, 'src/__markerplant.mjs'), `// TO ${'DO'}: wire this up\nexport const x = 1;\n`);
    const out = checkErr(dir);
    // The assertion must name the marker-gate arm — a bare filename match
    // is also satisfied by the manifest's 'unexpected file:' line even
    // when the marker rule never fires (w55-fv L-3).
    assert.match(out ?? '', /__markerplant\.mjs: unfinished code marker/, 'the two' + '-word marker must flag');
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

// M-3: a spawn failure is not a staleness verdict — the headline names
// the environment failure, not the regen recipe.
test('w54-ledger M-3: release-check names a spawn failure, not staleness', t => {
  const dir = ledgerCopyTree();
  try {
    try {
      execFileSync(process.execPath, ['scripts/release-check.mjs'], { cwd: dir, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], env: { PATH: join(dir, 'nope') } });
      assert.fail('release-check must fail when python3 is unspawnable');
    } catch (e) {
      const out = String(e.stderr ?? '') + String(e.stdout ?? '');
      assert.equal(e.status, 2, 'exit 2');
      assert.match(out, /could not run|not spawnable|python3 is required/i, 'the failure names the environment, not staleness');
      assert.doesNotMatch(out, /ledger is stale/i, 'a spawn failure must not misdirect to regeneration');
    }
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

// M-4: production-gate.json discloses the freshness arm honestly —
// the constant names what the committed-tree check actually proves
// (the generation-mode arm is tautological; --check-only proves
// freshness), so the pin is on the disclosure, not the vacuity
// spelling (w55-ledger C2).
test('w54-ledger M-4: production-gate records the freshness arm disclosure', t => {
  const gate = JSON.parse(readFileSync(new URL('../reports/production-gate.json', import.meta.url), 'utf8'));
  assert.match(gate.freshness_arm ?? '', /committed-tree freshness/, 'the committed artifact discloses the freshness arm honestly');
  assert.doesNotMatch(gate.freshness_arm ?? '', /checkOnly\s*\?/, 'the freshness arm is a constant disclosure, not mode-vacuous');
});

// ── w54-fixverify ───────────────────────────────────────────────────
// Regression tests for the w54 fix-verification auditor's findings:
// authorize() through a module-scope const alias is a real gate (H-3);
// a handler on a receiver the test never emits is dead evidence, and a
// destructured/class shadow is not node:assert (M-4); an XXX-colon literal is a planted
// marker label (M-5).

// H-3: a route gated via `fabric.authorize(p, CONST)` resolves the
// module-scope constant — the claimed roles must equal the SET contents.
test('w54-fv H-3: authorize(p, CONST_ARRAY) resolves module-scope role sets', t => {
  const dir = ledgerCopyTree();
  try {
    specPatched(dir, o => { o.paths['/aliasgate'] = { get: { description: 'Roles: auditor. plant' } }; });
    const srv = join(dir, 'src/server.mjs');
    const src = readFileSync(srv, 'utf8');
    const arm = `const W54_SET = ['auditor'];
      if (path === '/aliasgate' && req.method === 'GET') { fabric.authorize(p, W54_SET); return send(200, { ok: true }); }
      `;
    writeFileSync(srv, src.replace("const p = auth(req", arm + "const p = auth(req"));
    const out = checkErr(dir);
    assert.ok(out == null || !out.includes('aliasgate'), `the const-alias gate must resolve its roles: ${out?.slice(0, 400)}`);
    // Non-const carriers gate the same way — `let`, an alias chain, and a
    // post-decl mutation all carry the role set (w55-fv L-3/M-5: the old
    // const-only regex resolved none of these).
    const srv2 = readFileSync(srv, 'utf8');
    writeFileSync(srv, srv2.replace("const W54_SET = ['auditor'];", "let W54_LET = [];\n      const W54_SET = W54_LET; W54_SET.push('auditor');"));
    const outLet = checkErr(dir);
    assert.ok(outLet == null || !outLet.includes('aliasgate'), `the let/alias/mutated gate must resolve its roles: ${outLet?.slice(0, 400)}`);
    writeFileSync(srv, srv2);
    // Negative: the same arm claiming a different role must flag — the
    // resolution is to the real set contents, not a satisfied claim.
    specPatched(dir, o => { o.paths['/aliasgate'].get.description = 'Roles: security. plant'; });
    const out2 = checkErr(dir);
    assert.ok(out2?.includes('aliasgate'), `a mismatched claim against the alias must flag: ${out2?.slice(0, 400)}`);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

// M-4: an .on() handler on a receiver the test never emits is dead
// evidence; the honest on+emit idiom stays live; destructure and class
// shadows are not node:assert.
test('w54-fv M-4: emitter arms and destructure/class shadows disqualify', () => {
  const repoRoot = new URL('..', import.meta.url).pathname;
  const trPath = join(repoRoot, 'scripts/traceability.py');
  const probeErr = body => {
    const script = `import re, sys
__file__ = ${JSON.stringify(trPath)}
exec(open(__file__).read().split('for row in rows:')[0])
assert(_asserts(_live_code(TEST_BODY)))
`.replace('TEST_BODY', JSON.stringify(body));
    try {
      execFileSync('python3', ['-c', script], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
      return null;
    } catch (e) { return String(e.stderr ?? '') + String(e.stdout ?? ''); }
  };
  assert.match(probeErr("bus.on('go', () => assert(true));") ?? '', /AssertionError/, 'an .on() handler on a never-emitted receiver is dead');
  assert.ifError(probeErr("ee.on('go', () => assert(true)); ee.emit('go');"), 'on+emit is the honest idiom and stays live');
  assert.match(probeErr("process.on('x', () => assert(true));") ?? '', /AssertionError/, 'process.on callbacks are dead');
  assert.match(probeErr("const {assert} = fake; assert(true);") ?? '', /AssertionError/, 'const {assert} = x shadows the import');
  assert.match(probeErr("class assert { static m(){} } assert(true);") ?? '', /AssertionError/, 'class assert shadows the import');
});

// M-5: the triple-X colon label is a planted marker label; a tracked .js
// file under tests/ is still a dispatch surface. The copy gets a real
// git index so `git ls-files` — not the fallback walk — drives the file
// enumeration and the tests/*.mjs exemption actually applies.
test('w54-fv M-5: triple-X label flag + tests/*.js file scanned for surface', () => {
  const dir = ledgerCopyTree();
  try {
    execFileSync('sh', ['-c', 'git init -q && git add -A && git -c user.email=t@t -c user.name=t commit -qm init'], { cwd: dir });
    writeFileSync(join(dir, 'tests/__w54fv_aux.js'), "require('http').createServer((req,res)=>{res.end('x');}).listen(0);\n");
    execFileSync('git', ['add', '--', 'tests/__w54fv_aux.js'], { cwd: dir });
    const out = checkErr(dir);
    assert.match(out ?? '', /dispatch surface in tests\/__w54fv_aux\.js/, 'a tracked .js under tests/ still scans');
    assert.doesNotMatch(out ?? '', /dispatch surface in tests\/[\w.-]+\.mjs/, 'tracked tests/*.mjs stay exempt');
    writeFileSync(join(dir, 'src/__w54fv_xxx.mjs'), 'export const x = 1;\n// XXX' + ': placeholder\n');
    execFileSync('git', ['add', '--', 'src/__w54fv_xxx.mjs'], { cwd: dir });
    const out2 = checkErr(dir);
    assert.match(out2 ?? '', /__w54fv_xxx\.mjs: unfinished code marker \(xxx/, 'the triple-X label is flagged');
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
