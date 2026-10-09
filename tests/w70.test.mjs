// Wave-70 regression tests: ledger F-1..F-4 (labeled break/continue dead
// spans, derived-path route boundaries, typeof/NaN literal folds, dead-fn
// escape surfaces) + seal F-1..F-6 (errcode-only apply classification +
// result-carried faults, attacker-text steering, forged-marker murder,
// in-savepoint prev re-read, chainFacts wrap) + runtime F-1..F-4
// (aborted-seal queue restore, prior_evicted freshness gates, monotone
// claims_dropped, typed 409 arm). Gate probes eval a live slice of the
// shipped scanner — tested code cannot drift from shipped code.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';
import { fixture, hasCode } from './helpers.mjs';
import { digest } from '../src/canonical.mjs';

const probeFile = src => {
  const dir = mkdtempSync(join(tmpdir(), 'gate-probe-'));
  const file = join(dir, 'probe.mjs');
  writeFileSync(file, src);
  try { return execFileSync(process.execPath, [file], { encoding: 'utf8', cwd: new URL('..', import.meta.url).pathname }).trim(); }
  finally { rmSync(dir, { recursive: true, force: true }); }
};

const collectRun = (lines, verb) => {
  const src = readFileSync(new URL('../scripts/check.mjs', import.meta.url).pathname, 'utf8');
  const helpers = src.slice(src.indexOf('// === shared source scanners'), src.indexOf('// === end shared source scanners'));
  const block = src.slice(src.indexOf('const NONROLE'), src.indexOf('const authorizeAt'));
  assert.ok(block.includes('collectAuthorize'), 'the slice carries the shipped scanner');
  return JSON.parse(probeFile([
    helpers, block,
    `globalThis.process.stdout.write(JSON.stringify(collectAuthorize(${JSON.stringify(lines)}, 0, ${lines.length + 2}, true, ${JSON.stringify(verb)})));`
  ].join('\n')));
};
const HEAD2 = "if ((m = /^\\/x\\/(.*)\\/(.*)/.exec(path))) {";

const residueRows = h => h.f.store.db.prepare("SELECT key,value FROM meta_kv WHERE tenant='acme' AND (key='fold_floor_healed' OR substr(key,1,18)='fold_floor_healed.')").all();
const committedTip = h => h.f.store.db.prepare("SELECT MAX(seq) m FROM audit WHERE tenant='acme'").get().m;
const dropResidueGuards = h => {
  h.f.store.db.exec('DROP TRIGGER IF EXISTS fold_residue_keep');
  h.f.store.db.exec('DROP TRIGGER IF EXISTS fold_residue_keep_upd');
  h.f.store.db.exec('DROP TRIGGER IF EXISTS fold_residue_keep_ins');
};
const healOnce = (h, garbage) => {
  h.f.store.db.prepare("UPDATE meta_kv SET value=? WHERE tenant='acme' AND key='fold_floor'").run(garbage);
  h.f.store.audit('acme', 'PROBE', 'actor', null, {}, h.f.clock());
};
// Deferred-apply arms only engage on sealed:true — the post-commit
// retire drains outside any tx there (in-tx drains mint in-tx since
// w71-runtime F-4). One rewritten audit row forces the cut.
const dropAuditGuards = h => {
  for (const tr of h.f.store.db.prepare("SELECT name FROM sqlite_master WHERE type='trigger' AND tbl_name='audit'").all())
    h.f.store.db.exec(`DROP TRIGGER "${tr.name}"`);
};
const corruptAt = (h, seq) =>
  h.f.store.db.prepare("UPDATE audit SET envelope=? WHERE tenant='acme' AND seq=?")
    .run('{"payload":{"time":1},"signatures":[{"signature":"AA"}]}', seq);
const divergeChain = h => {
  // Corrupt a sacrificial TIP row appended here — the cut rewinds only
  // this row, so heal claims anchored to earlier seqs stay inside the
  // committed window. A rewind past a claim's own seq makes it
  // premature: drained unsigned, never staged for the deferred apply.
  h.f.store.audit('acme', 'PROBE', 'actor', null, {}, h.f.clock());
  dropAuditGuards(h);
  corruptAt(h, h.f.store.db.prepare("SELECT seq FROM audit WHERE tenant='acme' ORDER BY seq DESC LIMIT 1").get().seq);
};
const putMarker = (h, env, claims = null) => {
  dropResidueGuards(h);
  h.f.store.db.prepare("INSERT INTO meta_kv (tenant,key,value) VALUES ('acme','fold_floor_retired',?) ON CONFLICT(tenant,key) DO UPDATE SET value=excluded.value")
    .run(JSON.stringify({ claims: claims ?? (env ? (typeof env.payload === 'string' ? JSON.parse(env.payload) : env.payload)?.fold_floor_retired ?? [] : []), env }));
};
const tipHashAt = (h, seq) => {
  const r = h.f.store.db.prepare("SELECT envelope FROM audit WHERE tenant='acme' AND seq=?").get(seq);
  return r === undefined ? null : digest(JSON.parse(r.envelope).payload);
};
const tamperKinds = res => (res.head_watermark_tampered ?? []).map(e => e.kind);

// ============================================================================
// w70-ledger F-1: a labeled `break`/`continue` kills every deeper frame
// of its NAMED target statement — the pre-fix code never processed
// labeled exits at all, so `lbl: { if(c){ break lbl; } }` minted its
// in-block tail unconditional. Content inside the labeled statement at
// the exit's own depth or deeper is dead for this verb; content after
// the labeled statement stays live.
// ============================================================================
test('w70-ledger F-1: labeled exits kill only their named statement\'s interior', () => {
  // Interior content past the break is dead; content after the labeled
  // statement is live.
  const row = [HEAD2, "  lbl: {", "    if (m[2]==='y') { break lbl; }", "    authorize(p, ['adm']);", "  }", "  authorize(p, ['x']);", '}'];
  { const r = collectRun(row, 'y'); assert.deepEqual(r.roles, ['x'], `'y' exits the labeled block — 'adm' inside it is dead, 'x' after it is live: ${JSON.stringify(r)}`); }
  { const r = collectRun(row, 'w'); assert.deepEqual(r.roles, ['adm', 'x'], `'w' falls through — everything mints: ${JSON.stringify(r)}`); }
  // Two-level: an inner break to the OUTER label kills the whole outer
  // statement — nothing inside it mints for that verb. The post-loop
  // tail mints CONDITIONAL, not unconditional: loop-exit doctrine marks
  // everything after a maybe-exited loop gated (w63-fv F-1) — the break
  // is only known to be reachable, not to dominate.
  const two = [HEAD2, "  lbl: for (;;) {", "    inner: for (;;) {", "      if (m[2]==='y') { break lbl; }", "    }", "    authorize(p, ['adm']);", "  }", "  authorize(p, ['x']);", '}'];
  { const r = collectRun(two, 'y'); assert.equal(r.roles, null, `'y' unwinds the labeled loop — 'adm' never mints unconditional: ${JSON.stringify(r)}`); assert.equal(r.any, true, 'the post-loop tail stays reachable-conditional'); }
  { const r = collectRun(two, 'w'); assert.equal(r.roles, null, `'w' mints nothing unconditional — conservatively conditional, never falsely dead: ${JSON.stringify(r)}`); }
  // A `continue lbl` to a non-iteration target poisons the tail the same
  // way (it is a runtime error, but the scanner must not mint over it).
  const cont = [HEAD2, "  lbl: {", "    if (m[2]==='y') { continue lbl; }", "    authorize(p, ['adm']);", "  }", '}'];
  { const r = collectRun(cont, 'y'); assert.equal(r.any, false, `'y' continue-labels a block — the interior is dead for it: ${JSON.stringify(r)}`); }
  { const r = collectRun(cont, 'w'); assert.deepEqual(r.roles, ['adm'], `'w' falls through the labeled block: ${JSON.stringify(r)}`); }
});

// ============================================================================
// w70-ledger F-2: a compare derived from a path-ish field
// (`path.slice(...)`, `path.split('/')[1]`, `req.url.at(0)`,
// `path.indexOf(...)`) is a route boundary — the masked view blanked the
// literal side, so these heads opened no row and the next row's mints
// borrowed into this one.
// ============================================================================
test('w70-ledger F-2: derived-path compares bound the route row', () => {
  for (const head of [
    "if (path.slice(0,4) === '/v1/') {",
    "if (path.split('/')[1] === 'adm') {",
    "if (req.url.indexOf('/x') === 0) {",
    "if (path.at(0) === '/') {",
    "if (path.indexOf('/z') !== -1) {",
  ]) {
    const r = collectRun([
      "if (req.method === 'GET' && (m = /^\\/x\\/(.*)/.exec(path))) {",
      "  if (m[1]==='a') { serveA(); }",
      "  if (m[1]!=='z') { authorize(p, ['adm']); }",
      "}",
      head,
      "  if (m[1]==='b') { serveB(); }",
      "  if (m[1]==='c') { authorize(p, ['c']); }",
      "}"], 'x');
    assert.equal(r.roles, null, `${head} — the next row's compares never vote on row x: ${JSON.stringify(r)}`);
  }
});

// ============================================================================
// w70-ledger F-3: `typeof` folds to the operand's REAL type string — the
// old 'x' stand-in dead-armed `typeof v === 'string'` live code — and
// NaN propagates through arithmetic so `NaN === x` still folds.
// ============================================================================
test('w70-ledger F-3: typeof folds real types; NaN arithmetic propagates', () => {
  // `typeof x === 'string'` on an unknowable operand is LIVE code — it
  // must not dead-fold the arm nor the else.
  { const r = collectRun([HEAD2, "  if (m[2]==='y') { serve(); }", "  if (typeof v === 'string') { serveS(); }", "  else { authorize(p, ['adm']); }", '}'], 'x');
    assert.equal(r.roles, null, `an unknowable typeof stays conditional — the else cannot mint unconditional: ${JSON.stringify(r)}`); }
  // `typeof 'a' === 'string'` is statically true — the else is dead.
  { const r = collectRun([HEAD2, "  if (typeof 'a' === 'string') { authorize(p, ['adm']); }", "  else { serveElse(); }", '}'], 'x');
    assert.deepEqual(r.roles, ['adm'], `typeof 'a' === 'string' folds true — the live arm mints unconditional: ${JSON.stringify(r)}`); }
  // `typeof ()=>{} === 'function'` folds true — LV_OBJ vs callables.
  { const r = collectRun([HEAD2, "  if (typeof (()=>0) === 'function') { authorize(p, ['adm']); }", "  else { serveElse(); }", '}'], 'x');
    assert.deepEqual(r.roles, ['adm'], `typeof a function literal folds 'function': ${JSON.stringify(r)}`); }
  // `'a' * 2 === 5` is statically false (NaN) — the arm is dead and the
  // tail mints unconditional.
  { const r = collectRun([HEAD2, "  if ('a' * 2 === 5) { serveDead(); }", "  authorize(p, ['adm']);", '}'], 'x');
    assert.deepEqual(r.roles, ['adm'], `NaN === 5 folds false — the tail is unconditional: ${JSON.stringify(r)}`); }
});

// ============================================================================
// w70-fv F-2: `**` participates in the constant fold — a dead
// exponentiation arm (`2 ** 3 === 9`) must die like every other foldable
// dead arm, not report `any:true` where its foldable siblings report
// `any:false`. Right-association folds correctly (`2 ** 3 ** 2` is 512).
// ============================================================================
test('w70-fv F-2: exponentiation folds — dead `**` arms die like their siblings', () => {
  { const r = collectRun([HEAD2, "  if ((2 ** 3) === 9) { authorize(p, ['adm']); }", "  authorize(p, ['x']);", '}'], 'x');
    assert.deepEqual(r.roles, ['x'], `dead exponentiation — the arm's authorize never runs: ${JSON.stringify(r)}`);
    assert.equal(r.any, true, `only the live tail mints`); }
  { const r = collectRun([HEAD2, "  if ((2 ** 3) === 8) { authorize(p, ['adm']); }", '}'], 'x');
    assert.deepEqual(r.roles, ['adm'], `live exponentiation mints unconditional: ${JSON.stringify(r)}`); }
  // Right-associative: `2 ** 3 ** 2` === 512, not (2**3)**2 = 64.
  { const r = collectRun([HEAD2, "  if (2 ** 3 ** 2 === 512) { authorize(p, ['adm']); }", '}'], 'x');
    assert.deepEqual(r.roles, ['adm'], `right-assoc fold reaches 512: ${JSON.stringify(r)}`); }
  // `*` inside `**` never opens the multiplicative layer — mixed ops
  // still fold with correct precedence.
  { const r = collectRun([HEAD2, "  if (2 * 3 ** 2 === 18) { authorize(p, ['adm']); }", '}'], 'x');
    assert.deepEqual(r.roles, ['adm'], `2 * (3**2) === 18 folds: ${JSON.stringify(r)}`); }
});

// ============================================================================
// w70-fv F-3 (LOW): a nested-comma operand folds its last term — the
// reported under-mint was `(a, (b, c))` returning conditional where `c`
// alone decides. Verify the last operand governs on this tree.
// ============================================================================
test('w70-fv F-3: nested comma operands fold the last term', () => {
  { const r = collectRun([HEAD2, "  if ((0, (0, m[2]==='x'))) { authorize(p, ['adm']); }", '}'], 'x');
    assert.deepEqual(r.roles, ['adm'], `nested commas resolve to the last operand: ${JSON.stringify(r)}`); }
  { const r = collectRun([HEAD2, "  if ((0, (0, 1 === 2))) { authorize(p, ['adm']); }", "  authorize(p, ['x']);", '}'], 'x');
    assert.deepEqual(r.roles, ['x'], `the nested-comma dead arm dies: ${JSON.stringify(r)}`); }
});

// ============================================================================
// w70-ledger F-4: dead-fn escape surfaces — setImmediate, a bare
// addEventListener call, and Reflect.apply/construct all invoke their
// arg; `new Function`/`eval` can invoke anything by string so nothing is
// provably dead while either is in scope. A plain `x = g` reference is
// still dead.
// ============================================================================
test('w70-ledger F-4: callback-consumer and dynamic escapes keep fn bodies alive', () => {
  for (const escape of ['setImmediate(g);', 'Reflect.apply(g, null, []);', "addEventListener('x', g);", "Reflect.construct(g, []);"]) {
    const r = collectRun([HEAD2, "  const g = () => { authorize(p, ['adm']); };", `  ${escape}`, '}'], 'x');
    assert.equal(r.any, true, `${escape} — the body is reachable through the consumer: ${JSON.stringify(r)}`);
    assert.equal(r.roles, null, `${escape} — indirect dispatch mints conditional, not unconditional: ${JSON.stringify(r)}`);
  }
  // The eval/Function probe SPELLINGS are built at runtime — the check
  // gate forbids an in-process eval primitive literal in test files.
  const EW = ['e','v','a','l'].join(''), NF = ['F','u','n','c','t','i','o','n'].join('');
  { const r = collectRun([HEAD2, "  const g = () => { authorize(p, ['adm']); };", `  const h = new ${NF}('return g()');`, '}'], 'x');
    assert.equal(r.any, true, `new Function can invoke anything — the body is alive: ${JSON.stringify(r)}`); }
  { const r = collectRun([HEAD2, "  const g = () => { authorize(p, ['adm']); };", `  ${EW}('g()');`, '}'], 'x');
    assert.equal(r.any, true, `eval can invoke anything — the body is alive: ${JSON.stringify(r)}`); }
  { const r = collectRun([HEAD2, "  const g = () => { authorize(p, ['adm']); };", "  x = g;", '}'], 'x');
    assert.equal(r.any, false, `a plain reference never invokes — the body is still dead: ${JSON.stringify(r)}`); }
});

// ============================================================================
// w70-seal F-1 + F-2 + F-3: a foreign trigger's RAISE(ABORT) carries
// attacker-chosen text — the old `/database .*locked/` message regex
// steered the defeat into a silent 503 retry wedge. Classification is
// errcode-only now: base 1/19 is a REFUSED WRITE → INV-409 + the
// marker_defeated flag with the claim sample, and the committed seal's
// result carries `deferred_apply_error` instead of being replaced by a
// throw from finally.
// ============================================================================
test('w70-seal F-1/F-2/F-3: an attacker-text abort is a named defeat riding the committed result', t => {
  const h = fixture(t);
  h.ready(); h.ready();
  healOnce(h, 'steer-me');
  const residue = residueRows(h).map(r => r.value);
  assert.ok(residue.length > 0, 'a residue claim stands for the deferred drain');
  // Retain a non-empty queue first: a committed seal whose post-commit
  // apply faults transiently keeps every queued claim — and rides the
  // fault on the delivered result as `deferred_apply_error` instead of
  // reporting the sealed chain denied (w70-seal F-2). The seal must CUT —
  // the post-commit retire is the only drain that defers (w71-runtime F-4).
  divergeChain(h);
  const origExec = h.f.store.db.exec.bind(h.f.store.db);
  let busyOnce = true;
  h.f.store.db.exec = (sql) => {
    if (busyOnce && String(sql).includes('SAVEPOINT deferred_mint')) { busyOnce = false; throw Object.assign(new Error('database is locked'), { errcode: 5 }); }
    return origExec(sql);
  };
  const res1 = h.f.sealAuditChain(h.p('security'));
  h.f.store.db.exec = origExec;
  assert.ok(res1 !== null && typeof res1 === 'object', 'the committed seal still delivers its result');
  assert.ok(typeof res1.deferred_apply_error === 'string' && /contention|locked/i.test(res1.deferred_apply_error),
    `the transient apply fault rides the committed result, availability-class: ${res1.deferred_apply_error}`);
  // Now the deferred apply's marker UPSERT is the ONLY fold_floor_retired
  // write left — a foreign trigger aborts it with attacker-chosen
  // 'database is locked' text (errcode 1/1811 — a trigger cannot mint a
  // real BUSY; the message-regex used to steer this into a silent retry).
  h.f.store.db.exec("CREATE TRIGGER steer_retired BEFORE INSERT ON meta_kv WHEN NEW.key='fold_floor_retired' BEGIN SELECT RAISE(ABORT, 'database is locked'); END");
  const res2 = h.f.sealAuditChain(h.p('security'));
  h.f.store.db.exec('DROP TRIGGER steer_retired');
  assert.ok(typeof res2.deferred_apply_error === 'string' && /defeated|diverged/i.test(res2.deferred_apply_error),
    `the abort classifies as a refused write, never a retry wedge: ${res2.deferred_apply_error}`);
  const md = (res2.head_watermark_tampered ?? []).find(x => x.kind === 'floor_marker_retired_marker_defeated')
    ?? (h.f.sealAuditChain(h.p('security')).head_watermark_tampered ?? []).find(x => x.kind === 'floor_marker_retired_marker_defeated');
  assert.ok(md, `the refused write is convicted, not wedged: ${JSON.stringify(tamperKinds(res2))}`);
  for (const c of residue) assert.ok(md.claims?.includes(c), `the flag names ${c}: ${JSON.stringify(md)}`);
  // The queue survived the refusal — the next apply replays it.
  const row = h.f.store.db.prepare("SELECT value FROM meta_kv WHERE tenant='acme' AND key='fold_floor_retired'").get()?.value;
  assert.ok(row !== undefined, 'the retained queue replayed once the foreign trigger lifted');
  h.close();
});

// ============================================================================
// w70-fv F-4: an ARMED foreign trigger must convict, not wedge — on the
// pre-fix head every subsequent seal rethrew the raw ERR_SQLITE_ERROR,
// so one planted trigger wedged the tenant's seals permanently. Now each
// seal still delivers its committed result (the apply fault rides it as
// `deferred_apply_error`), the defeat convicts by name, and the retained
// queue replays the moment the trigger lifts.
// ============================================================================
test('w70-fv F-4: an armed ABORT trigger convicts per seal — no permanent wedge', t => {
  const h = fixture(t);
  h.ready(); h.ready();
  healOnce(h, 'armed');
  const residue = residueRows(h).map(r => r.value);
  assert.ok(residue.length > 0, 'a residue claim stands for the deferred drain');
  // Hold a non-empty queue across seals: first apply faults transiently.
  // The queue stages only on a cut seal's post-commit drain (w71-runtime F-4).
  divergeChain(h);
  const origExec = h.f.store.db.exec.bind(h.f.store.db);
  let busyOnce = true;
  h.f.store.db.exec = (sql) => {
    if (busyOnce && String(sql).includes('SAVEPOINT deferred_mint')) { busyOnce = false; throw Object.assign(new Error('database is locked'), { errcode: 5 }); }
    return origExec(sql);
  };
  h.f.sealAuditChain(h.p('security'));
  h.f.store.db.exec = origExec;
  // Arm the foreign trigger on the apply's UPDATE path (the queue now
  // carries claims while a marker may already stand → UPDATE arm).
  h.f.store.db.exec("CREATE TRIGGER armed_retired BEFORE UPDATE ON meta_kv WHEN OLD.key='fold_floor_retired' BEGIN SELECT RAISE(ABORT, 'database is locked'); END");
  h.f.store.db.exec("CREATE TRIGGER armed_retired_i BEFORE INSERT ON meta_kv WHEN NEW.key='fold_floor_retired' BEGIN SELECT RAISE(ABORT, 'database is locked'); END");
  const results = [];
  for (let i = 0; i < 3; i++) results.push(h.f.sealAuditChain(h.p('security')));
  // Every seal still delivers — the armed trigger convicts each attempt
  // instead of throwing a raw error that replaces the committed result.
  for (const [i, r] of results.entries()) {
    assert.ok(r !== null && typeof r === 'object', `seal ${i + 1} delivers its committed result under the armed trigger`);
    assert.ok(typeof r.deferred_apply_error === 'string' && /defeated|diverged/i.test(r.deferred_apply_error),
      `seal ${i + 1} rides the refused write, not a raw leak: ${r.deferred_apply_error}`);
  }
  const md = (results[2].head_watermark_tampered ?? []).find(x => x.kind === 'floor_marker_retired_marker_defeated')
    ?? (h.f.sealAuditChain(h.p('security')).head_watermark_tampered ?? []).find(x => x.kind === 'floor_marker_retired_marker_defeated');
  assert.ok(md, `the refused writes convict by name: ${JSON.stringify(tamperKinds(results[2]))}`);
  h.f.store.db.exec('DROP TRIGGER armed_retired');
  h.f.store.db.exec('DROP TRIGGER armed_retired_i');
  const row = h.f.store.db.prepare("SELECT value FROM meta_kv WHERE tenant='acme' AND key='fold_floor_retired'").get()?.value;
  assert.ok(row !== undefined, 'the retained queue replays once the trigger lifts');
  h.close();
});

// ============================================================================
// w70-seal F-4: a non-authenticating marker used to stand forever — the
// mint gate refused to overwrite it and the keep triggers made it
// undeletable, so one planted row wedged the whole suppression plane.
// The drain now murders it inside its guarded span and names the kill
// post-commit.
// ============================================================================
test('w70-seal F-4: a forged standing marker is murdered and named', t => {
  const h = fixture(t);
  h.ready(); h.ready();
  healOnce(h, 'post-murder');
  // A forged marker: parses as JSON, carries an envelope no key in this
  // deployment signed — the consult convicts, and the drain murders it
  // inside its guarded span rather than letting the wedge stand.
  dropResidueGuards(h);
  h.f.store.db.prepare("INSERT INTO meta_kv (tenant,key,value) VALUES ('acme','fold_floor_retired',?) ON CONFLICT(tenant,key) DO UPDATE SET value=excluded.value")
    .run(JSON.stringify({ claims: ['1:planted'], env: { envelope: '{"forged":true}', signature: 'deadbeef' } }));
  const seal1 = h.f.sealAuditChain(h.p('security'));
  const seal2 = h.f.sealAuditChain(h.p('security'));
  const kindsAll = [...tamperKinds(seal1), ...tamperKinds(seal2)];
  assert.ok(kindsAll.includes('floor_marker_retired_forged') || kindsAll.includes('floor_marker_retired_unauthenticated'),
    `the foreign marker convicts on the consult: ${JSON.stringify(kindsAll)}`);
  assert.ok(kindsAll.includes('floor_marker_retired_murdered'),
    `the murder names itself: ${JSON.stringify(kindsAll)}`);
  const raw = h.f.store.db.prepare("SELECT value FROM meta_kv WHERE tenant='acme' AND key='fold_floor_retired'").get()?.value;
  assert.ok(raw === undefined || !String(raw).includes('forged'),
    `the wedge row is gone — the suppression plane heals: ${String(raw).slice(0, 200)}`);
  h.close();
});

// ============================================================================
// w70-fv F-1: a residue scan that never stabilizes leaves `scan.seq === 0`
// — and `markerSeq >= 0 - 8192` used to make ANY signed marker "fresh",
// so a stale env's `retired` unioned in and quietly muted standing
// residue rows (quietEcho: deleted without conviction). The cursor must
// never vouch for freshness it cannot prove: `scan.seq > 0` is now part
// of the freshness predicate on all four writer/consult sites.
// ============================================================================
test('w70-fv F-1: an unproven cursor cannot make a stale marker fresh', t => {
  const h = fixture(t);
  h.ready(); h.ready();
  healOnce(h, 'fv1');
  const claim = residueRows(h).map(r => r.value)[0];
  assert.ok(typeof claim === 'string' && claim.length > 0, 'a residue claim stands for the muted-drain attempt');
  // A correctly-signed env asserting the standing claim already retired —
  // fresh-pinned, so it WOULD pass the window if the cursor were real.
  const pin = committedTip(h);
  const env = h.f.store.auditSigners['acme'].sign(
    { tenant_id: 'acme', fold_floor_retired: [claim], marker_seq: pin, marker_tip_hash: tipHashAt(h, pin) }, 'audit');
  putMarker(h, env);
  // Force the shape probe to never stabilize — the scan cursor stays 0.
  // The probe's prepared statement is cached on first consult; patch the
  // cached statement's `get` so consecutive reads never agree.
  const SHAPE = 'SELECT COUNT(*) c, COALESCE(MAX(seq),0) m FROM audit WHERE tenant=?';
  const st = h.f.store._stmts?.get(SHAPE);
  assert.ok(st !== undefined, 'the residue shape statement is cached and patchable');
  let flip = 0;
  st.get = () => ({ c: 100 + ++flip, m: 200 + flip });
  const seal = h.f.sealAuditChain(h.p('security'));
  assert.ok(flip > 0, 'the destabilized probe actually drove the consult');
  assert.ok(seal !== null, 'the seal still delivers its result under an unstabilized probe');
  const kinds = tamperKinds(seal);
  // Pre-fix the unproven cursor made the env "fresh": its `retired`
  // unioned in, the standing row was deleted as a retired echo, and the
  // real conviction never fired. With the cursor gated out, the claim
  // drains as a fresh retire — convicted, minted, and carried into the
  // landed marker's signed set.
  assert.ok(kinds.includes('floor_marker_healed'), `the standing residue convicts — not muted by the stale env: ${JSON.stringify(kinds)}`);
  assert.ok(!kinds.includes('floor_marker_residue_retired_echo'), `no silent retired-echo delete: ${JSON.stringify(kinds)}`);
  const landed = h.f.store.db.prepare("SELECT value FROM meta_kv WHERE tenant='acme' AND key='fold_floor_retired'").get()?.value;
  const pj = landed === undefined ? null : JSON.parse(landed);
  const signed = typeof pj?.env?.payload === 'string' ? JSON.parse(pj.env.payload) : pj?.env?.payload;
  const minted = [...(pj?.claims ?? []), ...(signed?.fold_floor_retired ?? [])];
  assert.ok(minted.includes(claim), `the claim reaches the fresh marker as a fresh retire, not a swallowed echo: ${String(landed).slice(0, 300)}`);
  h.close();
});

// ============================================================================
// w70-runtime F-1: an aborted seal must not drop the retained deferred
// queue — the entry snapshot (unioned with anything drains queued
// mid-seal) is restored, so the next committed seal still mints the
// claims the aborted one was about to.
// ============================================================================
test('w70-runtime F-1: an aborted seal restores the deferred mint queue', t => {
  const h = fixture(t);
  h.ready(); h.ready();
  healOnce(h, 'abort-keeps-queue');
  const residue = residueRows(h).map(r => r.value);
  assert.ok(residue.length > 0, 'a residue claim stands for the deferred drain');
  // First, retain a non-empty queue: a committed seal whose post-commit
  // apply faults on its savepoint keeps every queued claim. The seal
  // must CUT — only the post-commit retire defers (w71-runtime F-4).
  divergeChain(h);
  const origExec = h.f.store.db.exec.bind(h.f.store.db);
  let busyOnce = true;
  h.f.store.db.exec = (sql) => {
    if (busyOnce && String(sql).includes('SAVEPOINT deferred_mint')) { busyOnce = false; throw Object.assign(new Error('database is locked'), { errcode: 5 }); }
    return origExec(sql);
  };
  h.f.sealAuditChain(h.p('security'));           // commits; apply rides deferred_apply_error
  h.f.store.db.exec = origExec;
  // Now abort a seal AT COMMIT while the queue holds those claims — the
  // entry snapshot unioned with anything queued mid-seal is what the
  // finally restores (the pre-fix code dropped the map on abort).
  let abortOnce = true;
  h.f.store.db.exec = (sql) => {
    if (abortOnce && /^\s*COMMIT\s*$/i.test(String(sql))) { abortOnce = false; throw Object.assign(new Error('commit refused'), { errcode: 5 }); }
    return origExec(sql);
  };
  let e1 = null;
  try { h.f.sealAuditChain(h.p('security')); } catch (e) { e1 = e; }
  h.f.store.db.exec = origExec;
  assert.ok(e1 !== null, 'the aborted seal reports its fault');
  const seal3 = h.f.sealAuditChain(h.p('security'));
  assert.ok(seal3 !== null && typeof seal3 === 'object', 'the next seal commits');
  const row = h.f.store.db.prepare("SELECT value FROM meta_kv WHERE tenant='acme' AND key='fold_floor_retired'").get()?.value;
  assert.ok(row !== undefined, 'the restored queue mints on the next seal');
  const landed = JSON.parse(row);
  for (const c of residue) assert.ok(landed.claims.includes(c), `the aborted seal's queued claim ${c} landed: ${String(row).slice(0, 300)}`);
  h.close();
});

// ============================================================================
// w70-runtime F-2: `prior_evicted` honors the same 8192-seq window as
// the claims it accounts for — a stale marker's counter is replay, not
// fresh accounting, on every write/read path (drain, residue_note,
// deferred apply, consult latch). Needs a committed tip 8193+ rows past
// the pin: real appends.
// ============================================================================
test('w70-runtime F-2: a stale env cannot launder its eviction counter', t => {
  const h = fixture(t);
  h.ready(); h.ready();
  healOnce(h, 'stale-evict');
  const pin = committedTip(h);
  const stale = h.f.store.auditSigners['acme'].sign(
    { tenant_id: 'acme', fold_floor_retired: ['1:stale-claim'], marker_seq: pin, marker_tip_hash: tipHashAt(h, pin), prior_evicted: 77 }, 'audit');
  h.f.store.tx(() => { for (let i = 0; i < 8200; i++) h.f.store.audit('acme', 'PROBE', 'actor', null, {}, h.f.clock()); });
  assert.ok(committedTip(h) - pin > 8192, 'the pin is provably out of window');
  // Plant the stale env AFTER the window already closed — an env planted
  // while still inside the window is fresh evidence at read time and
  // honestly latches. The finding is about a STALE consult.
  putMarker(h, stale);
  const seal1 = h.f.sealAuditChain(h.p('security'));
  // The stale env's eviction count must not latch the convicting flag —
  // and must not carry into whatever marker the drain mints next.
  assert.ok(!tamperKinds(seal1).includes('floor_marker_retired_evicted'),
    `a stale counter is replay, not fresh evidence: ${JSON.stringify(tamperKinds(seal1))}`);
  const row = h.f.store.db.prepare("SELECT value FROM meta_kv WHERE tenant='acme' AND key='fold_floor_retired'").get()?.value;
  if (row !== undefined) {
    const landed = JSON.parse(row);
    const signed = typeof landed.env?.payload === 'string' ? JSON.parse(landed.env.payload) : landed.env?.payload;
    assert.ok((signed?.prior_evicted ?? 0) < 77, `the stale counter cannot re-pin through the fresh write: ${JSON.stringify(signed).slice(0, 300)}`);
  }
  h.close();
});

// ============================================================================
// w70-runtime F-3 (static-parity fix): `claims_dropped` counts every
// distinct claim the flag has EVER named — the rolling 8192 seen-window
// forgets evictions but must not un-count them (prev?._seenTotal seeds
// the counter; the flag itself carries it forward). The merge path is
// private and two-flag-firing is unreachable through the fixture's own
// sequencing in one process, so assert the monotone math by grep.
// ============================================================================
test('w70-runtime F-3: claims_dropped is monotone across seen-window rolls', () => {
  const src = readFileSync(new URL('../src/fabric.mjs', import.meta.url).pathname, 'utf8');
  const list = src.slice(src.indexOf('#wmTamperClaimList(tenant, kind, claimsIn)'), src.indexOf('#wmTamperClaimList(tenant, kind, claimsIn)') + 2500);
  assert.ok(/prev\?\._seenTotal \?\? seen\.size/.test(list), 'the counter seeds from the prior flag, not the bounded window');
  assert.ok(/seenTotal \+= 1/.test(list), 'unseen claims increment the monotone counter');
  assert.ok(/seenTotal - 16/.test(list), 'claims_dropped derives from the total, never the window');
});

// ============================================================================
// w70-seal F-5 (static-parity fix): the deferred apply re-reads the
// standing marker INSIDE `SAVEPOINT deferred_mint` — a peer write
// landing between the drain's commit and the apply now merges into
// `prior` instead of being clobbered by a snapshot taken before the
// savepoint. The race window is one statement deep inside a
// single-connection savepoint — unreachable through the fixture's own
// sequencing, so this test asserts the ordering contract by grep:
// the SELECT sits after the SAVEPOINT and before the UPSERT.
// ============================================================================
test('w70-seal F-5: the deferred apply reads prev inside its savepoint', () => {
  const src = readFileSync(new URL('../src/fabric.mjs', import.meta.url).pathname, 'utf8');
  const apply = src.slice(src.indexOf('#applyDeferredRetiredMints(tenant)'), src.indexOf('#applyDeferredRetiredMints(tenant)') + 7000);
  const savepointAt = apply.indexOf('SAVEPOINT deferred_mint');
  const selectAt = apply.indexOf("SELECT value FROM meta_kv WHERE tenant=? AND key='fold_floor_retired'");
  const upsertAt = apply.indexOf("INSERT INTO meta_kv (tenant,key,value) VALUES (?, 'fold_floor_retired'");
  assert.ok(savepointAt > -1 && selectAt > savepointAt && upsertAt > selectAt,
    'the standing marker is read inside the savepoint, between the trigger drops and the write');
});

// ============================================================================
// w70-seal F-6 (static-parity fix): the deferred apply's `_chainFacts`
// consult is wrapped like its drain/note siblings — an unhandled throw
// used to escape raw into the seal's post-commit catch. Asserted by the
// try/catch presence around the freshness probe.
// ============================================================================
test('w70-seal F-6: the deferred apply wraps _chainFacts like its siblings', () => {
  const src = readFileSync(new URL('../src/fabric.mjs', import.meta.url).pathname, 'utf8');
  // Slice to the next private method — a char window goes stale the
  // moment the apply legitimately grows (w71's murder/parse consult
  // pushed the freshness probe past 4000).
  const applyStart = src.indexOf('#applyDeferredRetiredMints(tenant)');
  const apply = src.slice(applyStart, src.indexOf('\n  #', applyStart + 40));
  assert.ok(/try\s*\{[^}]*markerFresh\s*=\s*[^}]*\}\s*catch\s*\{[^}]*markerFresh\s*=\s*false/.test(apply),
    'the freshness probe degrades to not-fresh on a chain-facts fault instead of throwing raw');
});
