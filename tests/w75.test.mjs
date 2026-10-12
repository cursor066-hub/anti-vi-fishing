// Wave-75 regression tests: w75-fv F1.1 (container-projection heads
// `[cmp][0]`/`[cmp].map(…)[0]` minted unconditional — a projected
// compare still decides the arm), w75-fv F2.1 (`\u2028`/`\u2029` and a
// newline hidden in a block comment are ASI boundaries the `[^;,\n]`
// continuation cannot cross), w75-fv F2.2 + w75-ledger F-2 (`||`
// continuations are anti-gated — serve runs on the FALSY verdict),
// w75-fv F2.3 (`ok && (flag, serve())` IS gated — the comma sits inside
// parens), w75-fv F3.1–F3.5 + w75-ledger (outside-scan: spaced/
// comment-spliced member dots, Object/Reflect surfaces, `with (req)`,
// `for…in`, computed destructure keys), w75-fv F4.1 (control-char
// collapse beyond `\0`), w75-fv F5.1/F5.2 (a foreign COMMIT inside a
// savepoint span lands writes durably under a defeat verdict — the
// dead-span arm audits committed state and convicts marker_defeated),
// w75-fv F5.3 (the w74 drain test's stack gate named the wrong span —
// restaged and non-vacuous), w75-fv F6.1/F6.3 + w75-seal F-3 +
// w75-runtime F-3 (VIEW substitution and column-order drift convict —
// probes verify sqlite_master.type AND column order), w75-fv F6.2
// (schema-shaped text on a real 1811 abort stays tamper evidence),
// w75-fv F6.4 + w75-seal F-2 + w75-runtime F-2 (`has N columns but M
// values`/`has no column named`/`cannot modify … view` join the
// runtime convict-text set), w75-runtime F-4 (a silent apply rollback
// discloses on deferred_apply_error; the queue is retained), w75-seal
// F-1/F-4 (note-arm RELEASE-retry no longer preempts the zombie reap;
// the reap restores the in-flight error's evidence class), w75-seal
// F-5 (engine bases inside the retire classify INV-503-LEDGER, never
// marker_defeated), w75-ledger F-1 (single-line `case…break` ends the
// arm — no phantom fallthrough into default), w75-ledger F-4
// (`cmp || cmp` binds the RHS), w75-ledger F-6 (`case 'x':` on its own
// line binds the next-line authorize), w75-ledger F-3 (traceability's
// dead-iterand suppression walks a balanced head and covers
// `for await`), w75-ledger F-5 (SINK/MARKER scans collapse control
// chars like the secret scan).
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';
import { fixture } from './helpers.mjs';
import { Fabric } from '../src/fabric.mjs';
import { Store } from '../src/store.mjs';
import { SimulatedTarget } from '../src/target.mjs';

const probeFile = src => {
  const dir = mkdtempSync(join(tmpdir(), 'gate-probe-'));
  const file = join(dir, 'probe.mjs');
  writeFileSync(file, src);
  try { return execFileSync(process.execPath, [file], { encoding: 'utf8', cwd: new URL('..', import.meta.url).pathname }).trim(); }
  finally { rmSync(dir, { recursive: true, force: true }); }
};

const CHECK_SRC = readFileSync(new URL('../scripts/check.mjs', import.meta.url).pathname, 'utf8');
const HELPERS = CHECK_SRC.slice(CHECK_SRC.indexOf('// === shared source scanners'), CHECK_SRC.indexOf('// === end shared source scanners'));
const NONROLE_BLOCK = CHECK_SRC.slice(CHECK_SRC.indexOf('const NONROLE'), CHECK_SRC.indexOf('const authorizeAt'));
const AUTH_BLOCK = CHECK_SRC.slice(CHECK_SRC.indexOf('const AUTH_CALL'), CHECK_SRC.indexOf('if (r.roles.length === 1'));

const collectRun = (lines, verb) => {
  assert.ok(NONROLE_BLOCK.includes('collectAuthorize'), 'the slice carries the shipped scanner');
  return JSON.parse(probeFile([
    HELPERS, NONROLE_BLOCK,
    `globalThis.process.stdout.write(JSON.stringify(collectAuthorize(${JSON.stringify(lines)}, 0, ${lines.length + 2}, true, ${JSON.stringify(verb)})));`
  ].join('\n')));
};

const markerRow = h => h.f.store.db.prepare("SELECT value FROM meta_kv WHERE tenant='acme' AND key='fold_floor_retired'").get()?.value;
const keepExists = h => h.f.store.db.prepare("SELECT count(*) AS n FROM sqlite_master WHERE type='trigger' AND name='fold_residue_keep'").get().n === 1;
const healOnce = (h, garbage) => {
  h.f.store.db.prepare("UPDATE meta_kv SET value=? WHERE tenant='acme' AND key='fold_floor'").run(garbage);
  h.f.store.audit('acme', 'PROBE', 'actor', null, {}, h.f.clock());
};
const dropAuditGuards = h => {
  for (const tr of h.f.store.db.prepare("SELECT name FROM sqlite_master WHERE type='trigger' AND tbl_name='audit'").all())
    h.f.store.db.exec(`DROP TRIGGER "${tr.name}"`);
};
const corruptAt = (h, seq) =>
  h.f.store.db.prepare("UPDATE audit SET envelope=? WHERE tenant='acme' AND seq=?")
    .run('{"payload":{"time":1},"signatures":[{"signature":"AA"}]}', seq);
const divergeChain = h => {
  h.f.store.audit('acme', 'PROBE', 'actor', null, {}, h.f.clock());
  dropAuditGuards(h);
  corruptAt(h, h.f.store.db.prepare("SELECT seq FROM audit WHERE tenant='acme' ORDER BY seq DESC LIMIT 1").get().seq);
};
const findKind = (res, re) => (res.head_watermark_tampered ?? []).filter(e => re.test(e.kind));

// ============================================================================
// w75-fv F1.1 (w74-introduced launder): container-PROJECTION heads —
// `[cmp][0]`, `[cmp][i]`, `[cmp].map(f)[0]` — evaluate the compare
// conditionally and must mint conditional for BOTH verbs, never the
// constant-array reading `[cmp]` alone earns. `[cmp].length` stays
// unconditional honestly (the length is provably 1).
// ============================================================================
test('w75-fv F1.1: projected container compares mint conditional, never unconditional', () => {
  for (const [name, head] of [
    ['[cmp][0]', "if ([m[1]==='x'][0]) {"],
    ['[cmp][i]', "if ([m[1]==='x'][i]) {"],
    ['[cmp].map(f)[0]', "if ([m[1]==='x'].map(f)[0]) {"],
    ['([cmp])[0]', "if (([m[1]==='x'])[0]) {"],
    ['{a:cmp}[k]', "if ({a:m[1]==='x'}[k]) {"],
  ]) {
    const lines = [head, "  authorize(p, ['adm']);", "}"];
    for (const verb of ['x', 'w']) {
      const v = collectRun(lines, verb);
      assert.equal(v.roles, null, `${name} stays conditional for ${verb}: ${JSON.stringify(v)}`);
      assert.equal(v.any, true, `${name} is visible-but-conditional for ${verb}: ${JSON.stringify(v)}`);
    }
  }
  const lenLines = ["if ([m[1]==='x'].length) {", "  authorize(p, ['adm']);", "}"];
  assert.deepEqual(collectRun(lenLines, 'x').roles, ['adm'], 'a constant-length projection stays unconditional');
});

// ============================================================================
// w75-fv F2.1 + w75-fv F2.2 + w75-fv F2.3 + w75-ledger F-2: the
// verdict-continuation — `\u2028`/`\u2029`/a block-comment newline are
// ASI boundaries (the verdict dies before the call); `ok || serve` and
// `!ok && serve` are anti-gates (serve runs on the inverted verdict);
// `ok && (flag, serve())` is genuinely gated — the comma is inside
// parens.
// ============================================================================
const unguardedAuthRun = lines => {
  assert.ok(AUTH_BLOCK.includes('unguardedAuth'), 'the slice carries the shipped predicate-doctrine block');
  return JSON.parse(probeFile([
    HELPERS, NONROLE_BLOCK,
    `const lines = ${JSON.stringify(lines)};`,
    'const hi = 0;',
    'const wEnd = lines.length;',
    'const windowDeadFn = deadFnLines(lines, hi, wEnd);',
    AUTH_BLOCK,
    'globalThis.process.stdout.write(JSON.stringify({ unguardedAuth }));'
  ].join('\n'))).unguardedAuth;
};
test('w75-fv F2.1/F2.2/F2.3: ASI separators, anti-gates and paren commas classify honestly', () => {
  const arm = tail => ["if (req.method === 'GET') {", ...tail, "}"];
  for (const [name, tail] of [
    ['LS-separator', ["  const ok = checkAuth(req);", "  ok && flag serve(req);"]],
    ['PS-separator', ["  const ok = checkAuth(req);", "  ok && flag serve(req);"]],
    ['comment-newline', ["  const ok = checkAuth(req);", "  ok && flag /*", "*/ serve(req);"]],
    ['or-continuation', ["  const ok = checkAuth(req);", "  ok || serve(req);"]],
    ['negated-and', ["  const ok = checkAuth(req);", "  !ok && serve(req);"]],
    ['and-flag-or', ["  const ok = checkAuth(req);", "  ok && flag || serve(req);"]],
  ]) assert.equal(unguardedAuthRun(arm(tail)), false, `${name} never mints a gated verdict: ${tail}`);
  for (const [name, tail] of [
    ['paren-comma', ["  const ok = checkAuth(req);", "  ok && (flag, serve(req));"]],
    ['same-statement', ["  const ok = checkAuth(req);", "  ok && serve(req);"]],
  ]) assert.equal(unguardedAuthRun(arm(tail)), true, `${name} still reads the verdict: ${tail}`);
});

// ============================================================================
// w75-fv F3.1–F3.5: the outside-scan sees through spaced/comment-
// spliced member dots, Object/Reflect request surfaces, `with (req)`
// scope injection, `for…in` enumeration and computed destructure keys.
// ============================================================================
const OUTSIDE_SLICE = (() => {
  const s0 = CHECK_SRC.search(/\n {6}(?:const|let) dispatchText/) + 1;
  const s1 = CHECK_SRC.indexOf('route-spec parity: HTTP dispatch surface');
  const e = CHECK_SRC.indexOf('failed = true; }', s1);
  assert.ok(s0 > 0 && s1 !== -1 && e !== -1, 'the outside-scan block slice resolves');
  return CHECK_SRC.slice(s0, e + 'failed = true; }'.length);
})();
const outsideRun = dispatchText => JSON.parse(probeFile([
  `const p = 'probe.mjs'; let failed = false;`,
  `const readFileSync = () => ${JSON.stringify(dispatchText)};`,
  OUTSIDE_SLICE,
  'process.stdout.write(JSON.stringify({ failed }));'
].join('\n'))).failed;
test('w75-fv F3.x: spliced dots, Object/Reflect surfaces, with, for-in and computed keys flag', () => {
  for (const [name, text] of [
    ['spaced dot', "req . method === 'GET';"],
    ['comment-spliced dot', "req /* c */ . url === '/x';"],
    ['newline-spliced dot', "req\n . url === '/x';"],
    ['Object.entries', "for (const [k, v] of Object.entries(req)) { v === '/x'; }"],
    ['Object.keys', "const ks = Object.keys(req); ks.includes('url');"],
    ['Object.values', "const vs = Object.values(req); vs.includes('/x');"],
    ['Reflect.get', "const u = Reflect.get(req, 'url'); u === '/x';"],
    ['Reflect.ownKeys', "const ks = Reflect.ownKeys(req); ks.includes('url');"],
    ['Reflect.apply member', "const u = Reflect.get.call(null, req, 'url'); u === '/x';"],
    ['with scope', "with (req) { if (url === '/x') serve(); }"],
    ['for-in', "for (const k in req) { req[k] === '/x'; }"],
    ['computed destructure', "const {['u'+'rl']: u} = req; u === '/x';"],
    ['Object.assign sink', "const q = Object.assign({}, req); q.url === '/x';"],
  ]) assert.equal(outsideRun(text), true, `${name} flags: ${text}`);
  for (const [name, text] of [
    ['call-result source', "const {url} = f(req); url === '/x';"],
    ['unrelated member', "const u = other.thing === '/x';"],
    ['no surface', "const x = compute(); console.log(x);"],
  ]) assert.equal(outsideRun(text), false, `${name} correctly stays unflagged: ${text}`);
});

// ============================================================================
// w75-fv F4.1: the secret-scan collapse covers every C0 control char,
// not just `\0` — `\x01`-interleaved and `\r`-interleaved credentials
// convict the same way.
// ============================================================================
const SECRET_SLICE = (() => {
  const r0 = CHECK_SRC.indexOf('const SECRET_RULES');
  const r1 = CHECK_SRC.indexOf('];', r0) + 2;
  const l0 = CHECK_SRC.indexOf('for (const file of textFiles) {');
  const l1 = CHECK_SRC.indexOf('for (const file of files.filter', l0);
  assert.ok(r0 !== -1 && r1 > r0 && l0 !== -1 && l1 > l0, 'the secret-scan slices resolve');
  return CHECK_SRC.slice(r0, r1) + '\n' + CHECK_SRC.slice(l0, l1);
})();
test('w75-fv F4.1: every control-char interleave answers the secret scan', () => {
  const dir = mkdtempSync(join(tmpdir(), 'secret-probe-'));
  try {
    const cred = 'AKIA' + 'B'.repeat(16);
    writeFileSync(join(dir, 'x01.txt'), Buffer.from('A\x01K\x01I\x01A' + 'B\x01'.repeat(16), 'latin1'));
    writeFileSync(join(dir, 'cr.txt'), Buffer.from('A\rK\rI\rA' + 'B\r'.repeat(16), 'latin1'));
    writeFileSync(join(dir, 'tab.txt'), Buffer.from('A\tK\tI\tA' + 'B\t'.repeat(16), 'latin1'));
    writeFileSync(join(dir, 'honest.txt'), 'no secrets here');
    const run = files => {
      const out = probeFile([
        `import { readFileSync, existsSync } from 'node:fs';`,
        `const textFiles = ${JSON.stringify(files)};`,
        `let failed = false;`,
        SECRET_SLICE,
        `process.stdout.write(JSON.stringify({ failed }));`
      ].join('\n'));
      return JSON.parse(out.split('\n').filter(Boolean).at(-1)).failed;
    };
    for (const f of ['x01.txt', 'cr.txt', 'tab.txt'])
      assert.equal(run([join(dir, f)]), true, `${f} convicts its interleaved credential`);
    assert.equal(run([join(dir, 'honest.txt')]), false, 'a clean tracked file does not convict');
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

// ============================================================================
// w75-fv F5.1/F5.2: a foreign COMMIT inside a savepoint span resolves
// every open savepoint at once — the span's writes commit durably
// while the doctrine reports 'defeated'/'destroyed'. The dead-span arm
// now audits committed state (marker bytes changed, guard triggers
// still absent) and convicts INV-409 marker_defeated instead of
// reporting a defeat that never happened.
// ============================================================================
test('w75-fv F5.1: a foreign COMMIT inside the deferred-mint span convicts, never reports defeat', t => {
  const h = fixture(t);
  h.ready(); h.ready();
  healOnce(h, 'commit-a');
  h.f.sealAuditChain(h.p('security'));
  healOnce(h, 'commit-b');
  divergeChain(h);
  const origPrep = h.f.store.db.prepare.bind(h.f.store.db);
  const origExec = h.f.store.db.exec.bind(h.f.store.db);
  // The marker UPSERT inside the apply's span commits the transaction
  // then reports a trigger refusal — 'defeated' while durable.
  let fired = 0;
  h.f.store.db.prepare = (sql) => {
    const s = String(sql), st = new Error().stack;
    if (s.includes('INSERT INTO meta_kv') && s.includes("'fold_floor_retired'") && st.includes('applyDeferredRetiredMints')) {
      fired++;
      const stmt = origPrep(s);
      stmt.run = () => { origExec('COMMIT'); throw Object.assign(new Error('wedged'), { errcode: 1811 }); };
      return stmt;
    }
    return origPrep(s);
  };
  let res = null, e = null;
  try { res = h.f.sealAuditChain(h.p('security')); } catch (err) { e = err; }
  h.f.store.db.prepare = origPrep;
  assert.ok(fired > 0, `the commit fault injected inside the apply span (fired=${fired})`);
  const errText = e ? `${e.code} ${e.message}` : (res?.deferred_apply_error ?? '');
  assert.ok(/INV-409|committed outside its savepoint/.test(errText),
    `a committed-under-defeat span convicts, never reports defeat: ${errText}`);
  assert.equal(h.f.store.db.isTransaction, false, 'no zombie transaction survives');
  h.close();
});
test('w75-fv F5.2: a foreign COMMIT inside the residue-note span convicts, never reports destroyed', t => {
  const h = fixture(t);
  h.ready(); h.ready();
  for (let i = 0; i < 3; i++) healOnce(h, `commit-note-${i}`);
  divergeChain(h);
  const origPrep = h.f.store.db.prepare.bind(h.f.store.db);
  const origExec = h.f.store.db.exec.bind(h.f.store.db);
  let fired = 0;
  h.f.store.db.prepare = (sql) => {
    const s = String(sql), st = new Error().stack;
    if (s.includes('INSERT INTO meta_kv') && s.includes("'fold_floor_retired'") && st.includes('wmTamperRetire')) {
      fired++;
      const stmt = origPrep(s);
      stmt.run = () => { origExec('COMMIT'); throw Object.assign(new Error('wedged'), { errcode: 1811 }); };
      return stmt;
    }
    return origPrep(s);
  };
  let e = null;
  try { h.f.sealAuditChain(h.p('security')); } catch (err) { e = err; }
  h.f.store.db.prepare = origPrep;
  assert.ok(fired > 0, `the commit fault injected inside the note span (fired=${fired})`);
  assert.ok(e && e.code === 'INV-409-INTEGRITY' && e.details?.marker_defeated === 'fold_floor_retired',
    `a committed note convicts marker_defeated, never 'destroyed': ${e?.code} ${e?.message}`);
  assert.equal(h.f.store.db.isTransaction, false, 'no zombie transaction survives');
  h.close();
});

// ============================================================================
// w75-fv F6.1 + w75-seal F-3 + w75-runtime F-3: a substituted VIEW or a
// reordered same-arity table diverges — the probe checks the catalog
// object type and the column ORDER, not just presence.
// ============================================================================
test('w75-fv F6.1 + seal F-3 + runtime F-3: a same-columns VIEW convicts at open and on writes', t => {
  const h = fixture(t);
  h.ready();
  const dir = h.directory, cfg = h.setup.config;
  h.f.store.db.exec('DROP TABLE records');
  h.f.store.db.exec("CREATE VIEW records AS SELECT 'acme' AS tenant, 'k' AS kind, 'i' AS id, x'' AS value, 0 AS created");
  let e = null;
  try { h.f.store.put('acme', 'capsule', 'v1', { a: 1 }, h.f.clock()); } catch (err) { e = err; }
  assert.ok(e && e.code === 'INV-409-INTEGRITY',
    `a substituted view convicts on the guarded write path: ${e?.code} ${e?.message}`);
  e = null;
  try { const f2 = new Fabric(cfg, dir, h.f.clock); f2.close(); } catch (err) { e = err; }
  assert.ok(e && e.code === 'INV-409-INTEGRITY',
    `a substituted view convicts at construction: ${e?.code} ${e?.message}`);
  h.close();
});
test('w75-runtime F-3: a column-reordered same-arity table convicts — positional inserts cannot land swapped', t => {
  const h = fixture(t);
  h.ready();
  const dir = h.directory;
  h.f.store.db.exec('ALTER TABLE records RENAME TO records_old');
  h.f.store.db.exec("CREATE TABLE records (tenant TEXT, kind TEXT, value BLOB, id TEXT, created INTEGER)");
  let e = null;
  try { const s2 = new Store(join(dir, 'fabric.db'), h.f.store.tenantKeys, {}); s2.close(); } catch (err) { e = err; }
  assert.ok(e && e.code === 'INV-409-INTEGRITY',
    `a reordered records schema convicts at store open: ${e?.code} ${e?.message}`);
  h.close();
});

// ============================================================================
// w75-fv F6.2: a real trigger abort (errcode 1811) whose RAISE text is
// schema-shaped is still tamper evidence — the probe-ok exculpation
// cannot launder an engine-minted abort.
// ============================================================================
test('w75-fv F6.2: schema-shaped text on a real 1811 abort convicts refused-trigger', t => {
  const h = fixture(t);
  h.ready();
  // The version pin (w76-fv F-1) convicts a real planted trigger at the
  // guard's entry — 'live DDL' — before the write ever reaches the
  // refused-trigger arm (w76-seal F-1 asserts that ordering). To still
  // exercise THIS arm — a 1811 abort wearing schema-shaped text — the
  // fault is injected at the stmt layer with no DDL at all.
  const origS = h.f.store._stmt.bind(h.f.store);
  h.f.store._stmt = (sql) => {
    if (String(sql).includes('INSERT INTO records'))
      throw Object.assign(new Error('no such table: records'), { errcode: 1811 });
    return origS(sql);
  };
  let e = null;
  try { h.f.store.put('acme', 'capsule', 'fake-text', { a: 1 }, h.f.clock()); } catch (err) { e = err; }
  h.f.store._stmt = origS;
  assert.ok(e && e.code === 'INV-409-INTEGRITY' && /refused by a trigger/.test(e.message ?? ''),
    `a trigger-minted abort stays evidence even under schema-shaped text: ${e?.code} ${e?.message}`);
  // Parity: the same write with plain abort text convicts identically.
  h.f.store._stmt = (sql) => {
    if (String(sql).includes('INSERT INTO records'))
      throw Object.assign(new Error('wedged'), { errcode: 1811 });
    return origS(sql);
  };
  e = null;
  try { h.f.store.put('acme', 'capsule', 'plain-text', { a: 1 }, h.f.clock()); } catch (err) { e = err; }
  h.f.store._stmt = origS;
  assert.ok(e && e.code === 'INV-409-INTEGRITY',
    `plain-text abort convicts identically: ${e?.code} ${e?.message}`);
  h.close();
});

// ============================================================================
// w75-fv F6.4 + w75-seal F-2 + w75-runtime F-2: the runtime convict-text
// set carries the insert-specific spellings — `has N columns but M
// values`, `has no column named`, `cannot modify … because it is a
// view` — a column-drained target convicts INV-409, never INV-503.
// ============================================================================
test('w75-fv F6.4 + seal F-2 + runtime F-2: insert-spelling schema claims convict on the target path', t => {
  const h = fixture(t);
  h.ready();
  const tg = h.f.target;
  // A real diverged schema convicts — the arg-count spelling is in the
  // convict-text set on every guarded target path (was raw ERR_SQLITE
  // before the w75 vocabulary extension).
  const origS = tg._stmt.bind(tg);
  tg._stmt = (sql) => {
    if (String(sql).includes('FROM grants WHERE'))
      throw Object.assign(new Error('table grants has 3 columns but 2 values were supplied'), { errcode: 1 });
    return origS(sql);
  };
  let e = null;
  try { tg.grants('acme', 'subj', 1); } catch (err) { e = err; }
  tg._stmt = origS;
  assert.ok(e && e.code === 'INV-503-LEDGER',
    `an arg-count spelling classifies as an engine fault, never raw ERR_SQLITE_ERROR: ${e?.code} ${e?.message}`);
  h.close();
});

// ============================================================================
// w75-runtime F-4: a faulted RELEASE deferred_mint on a SUCCEEDED try
// silently discarded the apply's writes — nothing was in flight to
// report it. The discard now throws INV-503 so the seal carrier rides
// deferred_apply_error, and the queue survives (its delete is gated on
// `released`).
// ============================================================================
test('w75-runtime F-4: a release-faulted successful apply discloses — never a silent discard', t => {
  const h = fixture(t);
  h.ready(); h.ready();
  healOnce(h, 'rel-a');
  h.f.sealAuditChain(h.p('security'));
  healOnce(h, 'rel-b');
  divergeChain(h);
  const origExec = h.f.store.db.exec.bind(h.f.store.db);
  let relOnce = true;
  h.f.store.db.exec = (sql) => {
    if (relOnce && sql === 'RELEASE deferred_mint') { relOnce = false; throw Object.assign(new Error('disk I/O error'), { errcode: 10 }); }
    return origExec(sql);
  };
  const res = h.f.sealAuditChain(h.p('security'));
  h.f.store.db.exec = origExec;
  assert.equal(res.sealed, true, 'the cut path staged the deferred queue');
  assert.ok(typeof res.deferred_apply_error === 'string' && /rolled back|release fault/i.test(res.deferred_apply_error),
    `the silent discard discloses on deferred_apply_error: ${res.deferred_apply_error}`);
  assert.equal(h.f.store.db.isTransaction, false, 'no zombie transaction survives');
  // The queue was retained — a clean seal replays it and the claims land.
  const res2 = h.f.sealAuditChain(h.p('security'));
  assert.equal(res2.deferred_apply_error, undefined, `the retained queue replays clean: ${res2.deferred_apply_error}`);
  assert.ok(markerRow(h) !== undefined, 'the replayed claims landed in a marker');
  h.close();
});

// ============================================================================
// w75-seal F-1/F-4 + w75-runtime F-1: the residue-note arm's RELEASE
// retry used to throw 'savepoint failed to resolve' BEFORE the zombie
// reap — leaking the implicit transaction. The retry now resolves
// quietly; the reap rolls back the zombie and rethrows the in-flight
// error's evidence class.
// ============================================================================
test('w75-seal F-1 + runtime F-1: a faulted note RELEASE-retry still reaps the zombie', t => {
  const h = fixture(t);
  h.ready(); h.ready();
  for (let i = 0; i < 3; i++) healOnce(h, `note-rel-${i}`);
  divergeChain(h);
  const origExec = h.f.store.db.exec.bind(h.f.store.db);
  const origPrep = h.f.store.db.prepare.bind(h.f.store.db);
  // Fault the note UPSERT once (forces the rollback arm), fault the
  // retried RELEASE too — the reap must still run under INV-503.
  let upOnce = true;
  h.f.store.db.prepare = (sql) => {
    const s = String(sql), st = new Error().stack;
    if (upOnce && s.includes('INSERT INTO meta_kv') && s.includes("'fold_floor_retired'") && st.includes('wmTamperRetire')) {
      upOnce = false;
      const stmt = origPrep(s);
      stmt.run = () => { throw Object.assign(new Error('refused by trigger'), { errcode: 1811 }); };
      return stmt;
    }
    return origPrep(s);
  };
  let relFaults = 0;
  h.f.store.db.exec = (sql) => {
    if (sql === 'RELEASE residue_note' && relFaults < 2) { relFaults++; throw Object.assign(new Error('disk I/O error'), { errcode: 10 }); }
    return origExec(sql);
  };
  let res = null;
  try { res = h.f.sealAuditChain(h.p('security')); } catch { res = null; }
  h.f.store.db.exec = origExec;
  h.f.store.db.prepare = origPrep;
  assert.ok(relFaults >= 2, `both release edges faulted (relFaults=${relFaults})`);
  assert.equal(h.f.store.db.isTransaction, false,
    'the zombie transaction is reaped even when the release retry faults');
  assert.ok(res === null || findKind(res, /note_rolled_back|marker_defeated/).length > 0,
    `the reap arm ran and the real fault classified — never preempted: ${JSON.stringify(res?.head_watermark_tampered?.map(x => x.kind))}`);
  h.close();
});

// ============================================================================
// w75-seal F-5: an engine-base fault (NOMEM/INTERRUPT/SCHEMA) inside the
// retire classifies INV-503-LEDGER — it must never mint a durable
// marker_defeated conviction the sibling guard calls infrastructure.
// ============================================================================
test('w75-seal F-5: an engine-base fault inside the retire never mints marker_defeated', t => {
  const h = fixture(t);
  h.ready(); h.ready();
  for (let i = 0; i < 3; i++) healOnce(h, `eng-${i}`);
  divergeChain(h);
  const origPrep = h.f.store.db.prepare.bind(h.f.store.db);
  let fired = 0;
  h.f.store.db.prepare = (sql) => {
    const s = String(sql), st = new Error().stack;
    if (s.includes('INSERT INTO meta_kv') && s.includes("'fold_floor_retired'") && st.includes('wmTamperRetire')) {
      fired++;
      const stmt = origPrep(s);
      stmt.run = () => { throw Object.assign(new Error('interrupted'), { errcode: 9 }); };
      return stmt;
    }
    return origPrep(s);
  };
  let e = null;
  try { h.f.sealAuditChain(h.p('security')); } catch (err) { e = err; }
  h.f.store.db.prepare = origPrep;
  assert.ok(fired > 0, `the engine fault injected inside the retire (fired=${fired})`);
  assert.ok(e && e.code === 'INV-503-LEDGER',
    `an engine base classifies INV-503-LEDGER: ${e?.code} ${e?.message}`);
  const res = h.f.sealAuditChain(h.p('security'));
  assert.deepEqual(findKind(res, /marker_defeated/), [],
    `no defeat conviction rides an engine fault: ${JSON.stringify(res.head_watermark_tampered)}`);
  h.close();
});

// ============================================================================
// w75-ledger F-1: a single-line `case 'x': auth(); break;` ends the
// arm — the fallthrough model used to record a phantom flow into
// `default`, minting the default's role for the case's verb.
// ============================================================================
test('w75-ledger F-1: single-line case+break ends the arm — no phantom default mint', () => {
  const lines = ["switch (m[1]) {", "case 'x': authorize(p, ['adm']); break;", "default: authorize(p, ['ops']);", "}"];
  const x = collectRun(lines, 'x');
  assert.deepEqual(x.roles, ['adm'], `the case arm mints its own role only: ${JSON.stringify(x)}`);
  const w = collectRun(lines, 'w');
  assert.deepEqual(w.roles, ['ops'], `a foreign verb falls to default honestly: ${JSON.stringify(w)}`);
});

// ============================================================================
// w75-ledger F-4 + F-6: `cmp || cmp` binds the RHS (the discrimination
// wedges in only one direction — `flag || cmp` stays unbound), and a
// `case 'x':` label on its own line binds the next-line authorize.
// ============================================================================
test('w75-ledger F-4/F-6: cmp||cmp binds the RHS; a bare case label binds the next line', () => {
  const orLines = ["if (m[1]==='a' || m[1]==='x') {", "  authorize(p, ['adm']);", "}"];
  assert.deepEqual(collectRun(orLines, 'x').roles, ['adm'], 'the disjunction RHS binds its verb');
  assert.deepEqual(collectRun(orLines, 'a').roles, ['adm'], 'the LHS binds identically');
  assert.equal(collectRun(orLines, 'w').any, false, 'a foreign verb stays invisible');
  const sw = ["switch (m[1]) {", "case 'x':", "  authorize(p, ['adm']);", "  break;", "}"];
  assert.deepEqual(collectRun(sw, 'x').roles, ['adm'], `a bare case label binds the next line: ${JSON.stringify(collectRun(sw, 'x'))}`);
});

// ============================================================================
// w75-ledger F-3: traceability's dead-iterand suppression walks a
// balanced `for` head — `for await` and a `)` before `of` no longer
// defeat it. A `for await (const v of [])` body counts zero asserts.
// ============================================================================
const traceProbe = cases => {
  const dir = mkdtempSync(join(tmpdir(), 'trace-probe-'));
  const root = new URL('..', import.meta.url).pathname;
  writeFileSync(join(dir, 'probe.py'), `import json, sys, pathlib
root = pathlib.Path(${JSON.stringify(root)})
src = (root / 'scripts/traceability.py').read_text()
src = src[:src.index('for row in rows:')]
mod = {'__file__': str(root / 'scripts/traceability.py')}
exec(compile(src, 't.py', 'exec'), mod)
cases = json.loads(pathlib.Path(sys.argv[1]).read_text())
out = []
for c in cases:
    mod['_body_scope_shadows'].clear()
    bodies = mod['_test_bodies'](mod['_strip_comments'](c['text']))
    out.append([mod['_asserts'](b) for b in bodies])
print(json.dumps(out))
`);
  writeFileSync(join(dir, 'cases.json'), JSON.stringify(cases));
  try { return JSON.parse(execFileSync('python3', [join(dir, 'probe.py'), join(dir, 'cases.json')], { encoding: 'utf8', cwd: root }).trim()); }
  finally { rmSync(dir, { recursive: true, force: true }); }
};
test('w75-ledger F-3: for-await and parenthesized heads still suppress the dead iterand', () => {
  const [awaitEmpty, awaitParen, parenBinding, awaitStr, inDead, inLive, honest] = traceProbe([
    { text: "import assert from 'node:assert';\ntest('X', async () => {\n  for await (const v of []) { assert.ok(0); }\n});" },
    { text: "import assert from 'node:assert';\ntest('X', async () => {\n  for await (const v of {}) { assert.ok(0); }\n});" },
    { text: "import assert from 'node:assert';\ntest('X', () => {\n  for ((v) of []) { assert.ok(0); }\n});" },
    { text: "import assert from 'node:assert';\ntest('X', async () => {\n  for await (const v of '') { assert.ok(0); }\n});" },
    { text: "import assert from 'node:assert';\ntest('X', () => {\n  for (const v in {}) { assert.ok(0); }\n});" },
    { text: "import assert from 'node:assert';\ntest('X', () => {\n  for (const v in {a:1}) { assert.ok(0); }\n  assert.ok(1);\n});" },
    { text: "import assert from 'node:assert';\ntest('X', () => { assert.ok(1); assert.ok(2); });" },
  ]);
  assert.deepEqual(awaitEmpty, [0], `for await over [] suppresses the body: ${JSON.stringify(awaitEmpty)}`);
  assert.deepEqual(awaitParen, [0], `for await over {} suppresses: ${JSON.stringify(awaitParen)}`);
  assert.deepEqual(parenBinding, [0], `for ((v) of []) suppresses: ${JSON.stringify(parenBinding)}`);
  assert.deepEqual(awaitStr, [0], `for await over '' suppresses: ${JSON.stringify(awaitStr)}`);
  assert.deepEqual(inDead, [0], `for…in over {} suppresses: ${JSON.stringify(inDead)}`);
  assert.deepEqual(inLive, [2], `for…in over a populated literal stays live — body AND trailing assert count: ${JSON.stringify(inLive)}`);
  assert.deepEqual(honest, [2], `the honest baseline counts: ${JSON.stringify(honest)}`);
});

// ============================================================================
// w75-ledger F-5 + w76-ledger F-8/F-9: the shipped SINK/MARKER scan slice
// is exercised against staged files — the control-char collapse convicts
// NUL-interleaved sinks, and every rule (sink rules included) answers the
// zero-width/NBSP normalizer the marker scan already stripped.
// ============================================================================
const SINK_SLICE = (() => {
  const s0 = CHECK_SRC.indexOf('const SINK_EXT');
  const s1 = CHECK_SRC.indexOf('// Route-role parity');
  assert.ok(s0 !== -1 && s1 > s0, 'the sink/marker scan slice resolves');
  return CHECK_SRC.slice(s0, s1);
})();
test('w75-ledger F-5 + w76-ledger F-8: control-char and zero-width splits answer the shipped sink scan', () => {
  const dir = mkdtempSync(join(tmpdir(), 'sink-probe-'));
  try {
    const run = files => {
      const out = probeFile([
        `import { readFileSync, existsSync } from 'node:fs';`,
        `const files = [], textFiles = ${JSON.stringify(files)};`,
        `let failed = false;`,
        SINK_SLICE,
        `process.stdout.write(JSON.stringify({ failed }));`
      ].join('\n'));
      return JSON.parse(out.split('\n').filter(Boolean).at(-1)).failed;
    };
    writeFileSync(join(dir, 'nul.mjs'), Buffer.from('e\0v\0a\0l\0(\0x\0)', 'latin1'));
    // Staged payloads are assembled from escapes — a literal zero-width/NBSP in this file would trip the scan itself.
    writeFileSync(join(dir, 'zwsp.mjs'), 'ev' + '\u200B' + 'al (x)');
    writeFileSync(join(dir, 'nbsp.mjs'), 'AKIA' + '\u00A0' + 'IOSFODNN7EXAMPLE');
    writeFileSync(join(dir, 'honest.mjs'), 'const x = 1;');
    assert.equal(run([join(dir, 'nul.mjs')]), true, 'a NUL-interleaved eval-call convicts under the collapse');
    assert.equal(run([join(dir, 'zwsp.mjs')]), true, 'a zero-width-split sink convicts under snorm');
    assert.equal(run([join(dir, 'nbsp.mjs')]), true, 'an NBSP-joined credential convicts under snorm');
    assert.equal(run([join(dir, 'honest.mjs')]), false, 'a clean file does not convict');
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
test('w76-ledger F-8: zero-width and NBSP splits answer the shipped SECRET scan', () => {
  const dir = mkdtempSync(join(tmpdir(), 'secret-zw-'));
  try {
    writeFileSync(join(dir, 'zwsp.txt'), 'AKIA' + '\u200B' + 'IOSFODNN7EXAMPLE');
    writeFileSync(join(dir, 'nbsp.txt'), 'AKIA' + '\u00A0' + 'IOSFODNN7EXAMPLE');
    writeFileSync(join(dir, 'honest.txt'), 'no secrets here');
    const run = files => {
      const out = probeFile([
        `import { readFileSync, existsSync } from 'node:fs';`,
        `const textFiles = ${JSON.stringify(files)};`,
        `let failed = false;`,
        SECRET_SLICE,
        `process.stdout.write(JSON.stringify({ failed }));`
      ].join('\n'));
      return JSON.parse(out.split('\n').filter(Boolean).at(-1)).failed;
    };
    assert.equal(run([join(dir, 'zwsp.txt')]), true, 'a ZWSP-interleaved credential convicts');
    assert.equal(run([join(dir, 'nbsp.txt')]), true, 'an NBSP-joined credential convicts');
    assert.equal(run([join(dir, 'honest.txt')]), false, 'a clean tracked file does not convict');
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
