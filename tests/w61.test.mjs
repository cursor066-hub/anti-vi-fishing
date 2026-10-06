// Wave-61 regression tests: seal F-1..F-4 (signed marker, shared trigger
// text, in-flight echo, paged mints), runtime F-1..F-5, fixverify F-1..F-9
// and ledger F-1..F-7 — every fix proven against the shipped machinery.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { fixture, hasCode } from './helpers.mjs';
import { verifySigned } from '../src/crypto.mjs';

const residueRows = h => h.f.store.db.prepare(
  "SELECT key,value FROM meta_kv WHERE tenant='acme' AND (key='fold_floor_healed' OR substr(key,1,18)='fold_floor_healed.')").all();
const dropResidueGuards = h => {
  h.f.store.db.exec('DROP TRIGGER IF EXISTS fold_residue_keep');
  h.f.store.db.exec('DROP TRIGGER IF EXISTS fold_residue_keep_upd');
  h.f.store.db.exec('DROP TRIGGER IF EXISTS fold_residue_keep_ins');
};
const healOnce = (h, garbage) => {
  h.f.store.db.prepare("UPDATE meta_kv SET value=? WHERE tenant='acme' AND key='fold_floor'").run(garbage);
  h.f.store.audit('acme', 'PROBE', 'actor', null, {}, h.f.clock());
};
const retireEnvs = h => h.f.store.db.prepare(
  "SELECT envelope FROM audit WHERE tenant='acme' AND envelope LIKE '%FOLD_RESIDUE_RETIRED%'").all();

// ============================================================================
// w61-seal F-1 / runtime F-3/F-4: the consumption marker is a signed
// envelope — planted bare arrays convict and cannot suppress convictions.
// ============================================================================
test('w61-seal F-1: a planted unsigned marker convicts, never suppresses', t => {
  const h = fixture(t);
  h.ready(); h.ready();
  healOnce(h, 'honest-heal');
  const seal = h.f.sealAuditChain(h.p('security'));
  assert.ok((seal.head_watermark_tampered ?? []).some(e => e.kind === 'floor_marker_healed'), 'precondition: the heal convicted');
  const marker = h.f.store.db.prepare("SELECT value FROM meta_kv WHERE tenant='acme' AND key='fold_floor_retired'").get()?.value;
  const parsed = JSON.parse(marker);
  assert.ok(Array.isArray(parsed.claims) && parsed.env && typeof parsed.env === 'object' && typeof parsed.env.signature === 'string',
    'the marker is a signed {claims,env} envelope');
  const pl = verifySigned(parsed.env, h.f.auditPublicKeys('acme'), 'audit');
  assert.ok(pl && Array.isArray(pl.fold_floor_retired), 'the envelope verifies under the audit key set');
  // Plant a bare-array marker naming a FUTURE claim — under the w60 shape
  // this suppressed the heal conviction at birth.
  dropResidueGuards(h);
  h.f.store.db.prepare("UPDATE meta_kv SET value=? WHERE tenant='acme' AND key='fold_floor_retired'").run(JSON.stringify(['99999:planted']));
  healOnce(h, 'suppressed-target');
  const seal2 = h.f.sealAuditChain(h.p('security'));
  const kinds = (seal2.head_watermark_tampered ?? []).map(e => e.kind);
  assert.ok(kinds.includes('floor_marker_retired_unauthenticated'), `an unsigned marker is named: ${kinds}`);
  assert.ok((seal2.head_watermark_tampered ?? []).some(e => e.kind === 'floor_marker_healed' && e.healed_marker === 'suppressed-target'),
    'a planted marker cannot suppress the heal conviction');
  h.close();
});

test('w61-seal F-1c: malformed marker content is named, not swallowed', t => {
  const h = fixture(t);
  h.ready(); h.ready();
  healOnce(h, 'first');
  h.f.sealAuditChain(h.p('security'));
  dropResidueGuards(h);
  h.f.store.db.prepare("UPDATE meta_kv SET value='not json' WHERE tenant='acme' AND key='fold_floor_retired'").run();
  const seal = h.f.sealAuditChain(h.p('security'));
  assert.ok((seal.head_watermark_tampered ?? []).some(e => e.kind === 'floor_marker_retired_malformed'),
    `malformed marker named: ${JSON.stringify(seal.head_watermark_tampered)}`);
  h.close();
});

// ============================================================================
// w61-seal F-2 / w61-runtime F-1: every emit path recreates the keep
// triggers from ONE canonical text — a heal cannot downgrade the guard.
// ============================================================================
test('w61-seal F-2: heals recreate the canonical trigger text', t => {
  const h = fixture(t);
  h.ready(); h.ready();
  healOnce(h, 'trigger-test');
  for (const tr of h.f.store.db.prepare("SELECT name, sql FROM sqlite_master WHERE type='trigger' AND name LIKE 'fold_residue_keep%'").all())
    assert.ok(/fold_floor_retired/.test(tr.sql), `${tr.name} kept its retired-marker arm post-heal`);
  // The guard is real in-band: a direct marker write aborts after a heal.
  assert.throws(() => h.f.store.db.prepare("INSERT INTO meta_kv(tenant,key,value) VALUES('acme','fold_floor_retired','[]')").run(),
    /fold-floor residue is evidence/, 'post-heal marker writes still abort');
  h.close();
});

// ============================================================================
// w61-seal F-3: an honest retire convicts no echo — the flag named defeated
// retirements, not successful ones; and it retires with its own report.
// ============================================================================
test('w61-seal F-3: a clean retire self-convicts no echo', t => {
  const h = fixture(t);
  h.ready(); h.ready();
  healOnce(h, 'clean');
  const s1 = h.f.sealAuditChain(h.p('security'));
  assert.ok(!(s1.head_watermark_tampered ?? []).some(e => e.kind === 'floor_marker_residue_retired_echo'),
    'a successful retire mints no echo flag');
  const s2 = h.f.sealAuditChain(h.p('security'));
  assert.ok(!(s2.head_watermark_tampered ?? []).some(e => e.kind === 'floor_marker_residue_retired_echo'),
    'the flag retires with the report that named it — no second sighting');
  h.close();
});

// ============================================================================
// w61-seal F-4 / fv F-2: retire mints page at 512 — claims past the cap bind
// the chain layer, not the marker alone.
// ============================================================================
test('w61-seal F-4: paged mints bind every claim past 512', t => {
  const h = fixture(t);
  h.ready(); h.ready();
  for (let i = 0; i < 520; i++) healOnce(h, `p-${i}`);
  h.f.sealAuditChain(h.p('security'));
  const retired = retireEnvs(h).map(r => JSON.parse(r.envelope).payload.metadata);
  assert.ok(retired.length >= 2, `expected paged mints, saw ${retired.length}`);
  assert.equal(retired[0].retired_pages, retired.length, 'pages attest the page count');
  const bound = new Set(retired.flatMap(r => r.retired_claims ?? []));
  assert.ok(bound.size >= 520, `every claim past 512 binds a mint: ${bound.size}`);
  h.close();
});

// ============================================================================
// w61-runtime F-2: a murdered grants row cannot make a live anchored grant
// unrevocable — resolve through the anchor like capability does.
// ============================================================================
test('w61-runtime F-2: murdered grants row cannot block revocation', t => {
  const h = fixture(t);
  const r = h.proposed('identity.jit.grant', { subject_id: 'operator', resources: ['dataset-1'], actions: ['data.read'], destinations: ['customer-vault'], columns: ['id'], row_ids: [], ttl_ms: 300000, reason: 'Incident', roles: [] }, { action: { type: 'identity.jit.grant', target_resource: 'jit-grants', purpose: 'JIT' } });
  h.evidence(r, { kind: 'identity_proof' }); h.evidence(r, { kind: 'identity_proof', issuer: 'registry' }); h.approve(r, 2);
  const cert = h.f.certificate(h.p(), r.capsule.capsule_id);
  h.f.execute(h.p(), cert);
  const grantId = `jit-${cert.payload.certificate_id}`;
  // Murder the mirror row — the anchor must still authorize the revocation.
  h.f.target.db.prepare("DELETE FROM grants WHERE tenant='acme' AND grant_id=?").run(grantId);
  const out = h.f.revoke(h.p('security'), { kind: 'grant', id: grantId, reason: 'murdered row' });
  assert.ok(out && !out.error, 'an anchored grant revokes through its anchor, not the murdered table');
  h.close();
});

// ============================================================================
// w61-runtime F-3: a dropped meta_kv rethrows INTEGRITY — the marker plane
// never mutes silently on read-only paths.
// ============================================================================
test('w61-runtime F-3: dropped meta_kv refuses, never mutes', t => {
  const h = fixture(t);
  h.ready(); h.ready();
  healOnce(h, 'drop-me');
  h.f.store.db.exec('DROP TABLE meta_kv');
  assert.throws(() => h.f.sealAuditChain(h.p('security')), hasCode('INV-409-INTEGRITY'),
    'a dropped meta_kv is tamper evidence, not a mute');
  h.close();
});

// ============================================================================
// Gate regressions — shipped collectAuthorize runs verbatim (w56 harness).
// ============================================================================
const ROOT = new URL('..', import.meta.url).pathname;
const collectRun = (lines, verb) => {
  const src = readFileSync(new URL('../scripts/check.mjs', import.meta.url).pathname, 'utf8');
  const helpers = src.slice(src.indexOf('// === shared source scanners'), src.indexOf('// === end shared source scanners'));
  const block = src.slice(src.indexOf('const NONROLE'), src.indexOf('const authorizeAt'));
  assert.ok(block.includes('collectAuthorize'), 'the slice carries the shipped scanner');
  return JSON.parse(execFileSync(process.execPath, ['-e', [
    helpers, block,
    `globalThis.process.stdout.write(JSON.stringify(collectAuthorize(${JSON.stringify(lines)}, 0, ${lines.length + 2}, true, ${JSON.stringify(verb)})));`
  ].join('\n')], { encoding: 'utf8', cwd: ROOT }).trim());
};
const HEAD = "if (req.method === 'GET' && (m = /^\\/x\\/(.*)/.exec(path))) {";

// w61-ledger F-3: a dead-operand tail must end at the call's own commas and
// parens — `helper(false && c, authorize)` counts the live second argument.
test('w61-ledger F-3: dead operand tails bound at commas and parens', t => {
  const r = collectRun([HEAD, "  if (m[1] === 'a') { helper(false && c, authorize(p, ['live'])); }", '}'], 'a');
  assert.deepEqual(r.roles, ['live'], 'an authorize in a sibling argument still mints');
  const r2 = collectRun([HEAD, "  if (m[1] === 'a') { authorize(p, ['live']); helper(false && dead()); }", '}'], 'a');
  assert.deepEqual(r2.roles, ['live'], 'a later dead operand cannot eat the earlier authorize');
});

// w61-fv F-1: non-empty literals inside a braceless dead statement keep the
// span — `if (0) x = {a:1}, authorize(...)` mints nothing.
test('w61-fv F-1: object literals cannot clear a dead braceless span', t => {
  const r = collectRun([HEAD, "  if (m[1] === 'a') { if (0) x = {a:1}, authorize(p, ['dead']); authorize(p, ['live']); }", '}'], 'a');
  assert.deepEqual(r.roles, ['live'], `the comma-joined authorize stays dead: ${JSON.stringify(r.roles)}`);
});

// w61-fv F-8: an ASI-complete dead statement owns nothing on the next line.
test('w61-fv F-8: ASI ends a dead braceless statement', t => {
  const r = collectRun([HEAD, "  if (m[1] === 'a') { if (0) x = f(p)", "      authorize(p, ['live']);", '  }', '}'], 'a');
  assert.deepEqual(r.roles, ['live'], 'the next-line statement is outside the dead span');
});

// w61-fv F-1 (merge arm): a nested dead `if` inside a dead span cannot
// re-arm a fresh span that ends the outer statement early.
test('w61-fv F-1b: nested dead control heads merge into the dead span', t => {
  const r = collectRun([HEAD, "  if (m[1] === 'a') { if (0) if (0) y; else authorize(p, ['dead']); authorize(p, ['live']); }", '}'], 'a');
  assert.deepEqual(r.roles, ['live'], `the else of a nested dead chain stays dead: ${JSON.stringify(r.roles)}`);
});

// w61-fv F-9: the else of a provably-dead `if` is the LIVE arm — its body
// runs unconditionally and mints roles, not just `.any`.
test('w61-fv F-9: the else of a dead if mints unconditionally', t => {
  const r = collectRun([HEAD, "  if (m[1] === 'a') { if (0) dead(); else authorize(p, ['live']); }", '}'], 'a');
  assert.deepEqual(r.roles, ['live'], `the live arm mints roles: ${JSON.stringify(r.roles)}`);
  const r2 = collectRun([HEAD, "  if (m[1] === 'a') { if (0) dead(); else { authorize(p, ['live']); } }", '}'], 'a');
  assert.deepEqual(r2.roles, ['live'], 'the braced live arm mints roles too');
});

// w61-fv F-9 (do-while): `while (0)` terminating a `do {}` owns nothing —
// the following statement runs unconditionally.
test('w61-fv F-9b: do-while tails arm no dead span', t => {
  const r = collectRun([HEAD, "  if (m[1] === 'a') { do { authorize(p, ['do']); } while (0) authorize(p, ['live']); }", '}'], 'a');
  assert.deepEqual((r.roles ?? []).sort(), ['do', 'live'], `do-body and post-while both mint: ${JSON.stringify(r.roles)}`);
});

// w61-ledger F-2: a function referenced but never invoked mints nothing —
// use position is not invocation; `g()`/`g.call`/`new g` keep it live.
test('w61-ledger F-2: dead declarations cannot mint a gate', t => {
  for (const tail of ['x = g', 'typeof g', 'return g', 'g === null', '!g'])
    assert.equal(collectRun([HEAD, `  if (m[1] === 'a') { const g = () => { authorize(p, ['dead']); }; ${tail}; }`, '}'], 'a').any, false,
      `${tail}: a bare reference minted liveness`);
  for (const tail of ['g()', 'g.call(null)', 'new g()', 'f(g())'])
    assert.equal(collectRun([HEAD, `  if (m[1] === 'a') { const g = () => { authorize(p, ['live']); }; ${tail}; }`, '}'], 'a').any, true,
      `${tail}: a real invocation keeps the body live`);
});

// w61-ledger F-5: whole-dispatcher aliases and switch/case arms bind their
// member — a y-arm's authorize mints nothing on the x row.
test('w61-ledger F-5: aliased and switched dispatch binds the member', t => {
  const aliased = [HEAD, "  const q = m; if (q[2] === 'y') { authorize(p, ['yrole']); }", '}'];
  assert.equal(collectRun(aliased, 'x').any, false, 'a y-arm through an alias mints nothing on x');
  assert.equal(collectRun(aliased, 'y').any, true, 'the y-arm counts on its own row');
  const switched = [HEAD, "  switch (m[2]) { case 'y': authorize(p, ['yrole']); }", '}'];
  assert.equal(collectRun(switched, 'x').any, false, 'a case arm mints nothing on a sibling row');
  assert.equal(collectRun(switched, 'y').any, true, 'the case arm counts on its own row');
});

// ============================================================================
// Python gate (traceability.py) — run the shipped folds verbatim.
// ============================================================================
const pyGate = (code) => execFileSync('python3', ['-c',
  `g = {'__file__': 'scripts/traceability.py'}\nsrc = open('scripts/traceability.py').read()\nexec(src[:src.index('def evidence_blocks')], g)\n${code}`],
  { encoding: 'utf8', cwd: ROOT }).trim().split('\n');

// w61-ledger F-1: loose equality folds by JS rules — `'1' == 1` and
// `0 == false` are TRUE, `null == undefined` only with each other.
test('w61-ledger F-1: ==/!= fold via JS loose equality', t => {
  const out = pyGate([
    `print(g['_const_val']("0 != '0'", {}))`,
    `print(g['_const_val']("0 == '0'", {}))`,
    `print(g['_const_val']("'a' == 1", {}))`,
    `print(g['_const_val']("null == undefined", {}))`,
    `print(g['_const_val']("null == 0", {}))`,
    `print(g['_const_val']("true == 1", {}))`,
    `print(g['_const_val']("'true' == true", {}))`,
  ].join('\n'));
  assert.deepEqual(out, ['False', 'True', 'False', 'True', 'False', 'True', 'False']);
});

// w61-fv F-6: unknown-valued consts are neither falsy nor truthy — a bound
// name classified falsy dead-spanned live code.
test('w61-fv F-6: unknown folds stay unknown in _truthy', t => {
  const out = pyGate([
    `print(g['_truthy'](g['_CONST_UNKNOWN']) is g['_CONST_UNKNOWN'])`,
    `print(g['_truthy'](g['_CONST_OBJ']))`,
    `print(g['_truthy'](g['_CONST_UNDEF']) is False)`,
  ].join('\n'));
  assert.deepEqual(out, ['True', 'True', 'True']);
});

// w61-ledger F-4: unknown-tolerant folds — a provable operand decides the
// whole `||`/`&&`/ternary chain.
test('w61-ledger F-4: provable operands decide through unknowns', t => {
  const out = pyGate([
    `print(g['_const_val']("x ? 0 : 0", {'x': g['_CONST_UNKNOWN']}))`,
    `print(g['_const_val']("x && 0", {'x': g['_CONST_UNKNOWN']}))`,
    `print(g['_const_val']("x || 's'", {'x': g['_CONST_UNKNOWN']}))`,
    `print(g['_const_val']("x && y", {'x': g['_CONST_UNKNOWN'], 'y': g['_CONST_UNKNOWN']}) is g['_CONST_UNKNOWN'])`,
  ].join('\n'));
  assert.deepEqual(out, ['0', '0', 's', 'True']);
});

// w61-ledger F-4 (iteration): never-iterating bodies are dead code.
test('w61-ledger F-4b: empty/non-iterable loops die in _live_code', t => {
  const out = pyGate([
    `live = g['_live_code']("for (x of new Set()) { assert.ok(1); } assert.ok(2);")`,
    `print('assert.ok(1)' in live, 'assert.ok(2)' in live)`,
    `live = g['_live_code']("for (k in {}) { assert.ok(1); } assert.ok(2);")`,
    `print('assert.ok(1)' in live, 'assert.ok(2)' in live)`,
    `live = g['_live_code']("for (x of 'ab') { assert.ok(1); } assert.ok(2);")`,
    `print('assert.ok(1)' in live, 'assert.ok(2)' in live)`,
  ].join('\n'));
  assert.deepEqual(out, ['False True', 'False True', 'True True']);
});

// w61-fv F-5: nested destructure defaults in param lists are still a
// method definition, not a call — `assert({x:{y}}){}` mints no hit.
test('w61-fv F-5: nested destructure params are defs, not calls', t => {
  const out = pyGate([
    `print(g['_asserts']("test('X', () => { assert({x:{y}}){}; })"))`,
    `print(g['_asserts']("test('X', () => { assert({x}=y){}; })"))`,
    `print(g['_asserts']("test('X', () => { assert.ok(1); })"))`,
  ].join('\n'));
  assert.deepEqual(out, ['0', '0', '1']);
});
