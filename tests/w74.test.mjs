// Wave-74 regression tests: w74-runtime F-1 + w74-fv F-6 (a catch-arm
// ROLLBACK TO that faults must never let the finally's RELEASE COMMIT
// the span it was meant to undo — `rollbackFailed` latches it on all
// three spans), w74-seal F-1 (a transaction-destroying fault — a foreign
// RAISE(ROLLBACK) — makes the dead-span arm restore the REAL error
// instead of minting a phantom 'unresolved savepoint'), w74-seal F-2 +
// w74-fv F-7 (the residue-note span reaps its leaked implicit
// transaction exactly like its siblings), w74-seal F-3 (the target's
// schema claims are probe-verified — a fabricated 'no such table'
// text over a standing schema rides the 1811 arm), w74-seal F-4 (the
// constructor probe is column-bearing — a column-drained meta_kv
// convicts), w74-seal F-5 (a probe-fault in the corruption family —
// errcode 11/26 — convicts INV-409), w74-fv F-1 + w74-ledger F-1
// (operand-head siblings: container literals, `=>`, `||`-LHS, `?:`,
// and compound-assign heads are operand contexts — never bindings),
// w74-fv F-2 (the bound-verdict continuation respects ASI — `[^;\n]`),
// w74-fv F-3/F-4 + w74-ledger F-2 (outside-scan: `?.` normalization,
// Reflect.get, req aliases, bare/for-of/param/nested/computed/await
// destructures), w74-fv F-5 (SECRET_RULES run over a NUL-collapsed
// decode — UTF-16/interleaved files cannot smuggle credentials),
// w74-fv LOW + w74-ledger F-3/F-4/F-5 (arrow-param and destructured
// for-head shadows scope clause-wide; `for await` covered deliberately).
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';
import { fixture } from './helpers.mjs';
import { Fabric } from '../src/fabric.mjs';

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
const HEAD2 = "if ((m = /^\\/x\\/(.*)\\/(.*)/.exec(path))) {";

const markerRow = h => h.f.store.db.prepare("SELECT value FROM meta_kv WHERE tenant='acme' AND key='fold_floor_retired'").get()?.value;
const keepExists = h => h.f.store.db.prepare("SELECT count(*) AS n FROM sqlite_master WHERE type='trigger' AND name='fold_residue_keep'").get().n === 1;
const dropResidueGuards = h => {
  h.f.store.db.exec('DROP TRIGGER IF EXISTS fold_residue_keep');
  h.f.store.db.exec('DROP TRIGGER IF EXISTS fold_residue_keep_upd');
  h.f.store.db.exec('DROP TRIGGER IF EXISTS fold_residue_keep_ins');
};
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
// w74-runtime F-1 + w74-fv F-6 (residue_drain): a faulted catch-arm
// ROLLBACK TO must never let the finally's plain RELEASE COMMIT the span
// it was meant to undo — under the old shape the committed span left the
// keep-trigger drops durable while reporting failure. The span rolls
// back for real, the guards stand, the claims land once on the clean
// follow-up drain.
// ============================================================================
test('w74-runtime F-1: a faulted catch-arm rollback never commits the drain span', t => {
  const h = fixture(t);
  h.ready(); h.ready();
  for (let i = 0; i < 3; i++) healOnce(h, `w74rb-${i}`);
  divergeChain(h);
  const origExec = h.f.store.db.exec.bind(h.f.store.db);
  const origPrep = h.f.store.db.prepare.bind(h.f.store.db);
  // Fault the marker UPSERT inside the drain's span PERMANENTLY — the
  // echo drain consumes it and swallows, the attested drain faults again
  // and propagates. The first catch-arm ROLLBACK TO faults once. Under
  // the buggy shape the first drain's RELEASE then committed its dropped
  // keep triggers; every later rollback only undoes its own span.
  let rbOnce = true; let fired = 0;
  h.f.store.db.prepare = (sql) => {
    const s = String(sql), st = new Error().stack;
    // The marker UPSERT actually executes inside #wmTamperRetire's
    // residue_note span (or a non-deferred drain's residueValueDelete)
    // — gating on residueValueDelete alone never fired (w75-fv F5.3:
    // the test was green-but-vacuous, fired=0).
    if (s.includes('INSERT INTO meta_kv') && s.includes("'fold_floor_retired'")
        && (st.includes('wmTamperRetire') || st.includes('residueValueDelete'))) {
      fired++;
      const stmt = origPrep(s);
      stmt.run = () => { throw Object.assign(new Error('refused by trigger: fold-floor'), { errcode: 1811 }); };
      return stmt;
    }
    return origPrep(s);
  };
  h.f.store.db.exec = (sql) => {
    if (rbOnce && /^ROLLBACK TO residue_(?:drain|note)$/.test(sql)) { rbOnce = false; throw Object.assign(new Error('disk I/O error'), { errcode: 10 }); }
    return origExec(sql);
  };
  let res = null;
  try { res = h.f.sealAuditChain(h.p('security')); } catch (err) { res = { threw: err }; }
  h.f.store.db.exec = origExec;
  h.f.store.db.prepare = origPrep;
  assert.ok(fired > 0, `the marker-write fault actually injected — the test is not vacuous (fired=${fired})`);
  assert.equal(h.f.store.db.isTransaction, false, 'no zombie transaction survives the refused unwind');
  assert.ok(keepExists(h), 'the keep-trigger drops rolled back with every span — never committed dirty');
  assert.ok(!res?.threw || res.threw.code !== 'INV-503-LEDGER',
    `no phantom storage fault rides the rolled-back span: ${res?.threw?.code}`);
  h.close();
});

// ============================================================================
// w74-runtime F-1 + w74-fv F-6 (deferred_mint): the deferred apply's own
// span — the auditor's d3 case committed the keep-trigger DROPs while
// `deferred_apply_error` reported a storage fault. Rolled-back spans
// leave the guard standing, keep the queue, and let the next apply land.
// ============================================================================
test('w74-fv F-6: a faulted rollback inside the deferred apply never commits the span', t => {
  const h = fixture(t);
  h.ready(); h.ready();
  healOnce(h, 'apply-rb-a');
  h.f.sealAuditChain(h.p('security'));
  healOnce(h, 'apply-rb-b');
  divergeChain(h);
  const origExec = h.f.store.db.exec.bind(h.f.store.db);
  // Fault the second keep-drop inside the APPLY only — stack-gated —
  // plus the apply's first catch-arm rollback.
  let dropOnce = true, rbOnce = true;
  h.f.store.db.exec = (sql) => {
    const s = String(sql), st = new Error().stack;
    if (dropOnce && s === 'DROP TRIGGER IF EXISTS fold_residue_keep_upd' && st.includes('applyDeferredRetiredMints')) {
      dropOnce = false; throw Object.assign(new Error('disk I/O error'), { errcode: 10 });
    }
    if (rbOnce && s === 'ROLLBACK TO deferred_mint') { rbOnce = false; throw Object.assign(new Error('disk I/O error'), { errcode: 10 }); }
    return origExec(s);
  };
  const res = h.f.sealAuditChain(h.p('security'));
  h.f.store.db.exec = origExec;
  assert.equal(res.sealed, true, 'the cut path defers the apply past commit');
  assert.equal(h.f.store.db.isTransaction, false, 'no zombie transaction survives the refused apply');
  assert.ok(keepExists(h), 'the committed-dirty span is gone — the keep drops rolled back');
  // The queue survived the rolled-back apply: the next clean seal
  // replays it and the claims land under a fresh envelope.
  const res2 = h.f.sealAuditChain(h.p('security'));
  assert.equal(res2.deferred_apply_error, undefined, `the clean apply lands: ${res2.deferred_apply_error}`);
  const mk = markerRow(h);
  assert.ok(mk !== undefined && JSON.parse(mk).env !== undefined, 'the retained queue lands under a signed envelope');
  h.close();
});

// ============================================================================
// w74-seal F-1: a transaction-destroying fault inside a savepoint — a
// foreign RAISE(ROLLBACK) — must surface the REAL error, not a phantom
// 'unresolved savepoint' INV-503 over destroyed evidence.
// ============================================================================
test('w74-seal F-1: a tx-destroying fault propagates the real error — never a phantom unresolved-savepoint', t => {
  const h = fixture(t);
  h.ready(); h.ready();
  for (let i = 0; i < 3; i++) healOnce(h, `w74kill-${i}`);
  divergeChain(h);
  // A RAISE(ROLLBACK)-class fault: the write destroys the savepoint's
  // implicit transaction BEFORE reporting — the span the catch tries
  // to ROLLBACK TO no longer exists. Under the old shape the finally
  // minted a phantom 'unresolved savepoint' INV-503 over the real
  // evidence; the dead-span arm now restores the original error.
  const origExec = h.f.store.db.exec.bind(h.f.store.db);
  const origPrep = h.f.store.db.prepare.bind(h.f.store.db);
  h.f.store.db.prepare = (sql) => {
    const s = String(sql), st = new Error().stack;
    if (s.includes('INSERT INTO meta_kv') && s.includes("'fold_floor_retired'") && st.includes('residueValueDelete')) {
      const stmt = origPrep(s);
      stmt.run = () => { origExec('ROLLBACK'); throw Object.assign(new Error('wedged'), { errcode: 1811 }); };
      return stmt;
    }
    return origPrep(s);
  };
  let e = null;
  try { h.f.sealAuditChain(h.p('security')); } catch (err) { e = err; }
  h.f.store.db.prepare = origPrep;
  assert.ok(!/unresolved savepoint/i.test(String(e?.message ?? '')),
    `the real fault propagates — never a phantom 'unresolved savepoint': ${e?.code} ${e?.message}`);
  assert.equal(h.f.store.db.isTransaction, false, 'the destroyed transaction is gone, not a zombie');
  assert.ok(keepExists(h), 'the dropped guards rolled back with the destroyed span — never committed');
  h.close();
});

// ============================================================================
// w74-seal F-2 + w74-fv F-7: the residue-note span reaps a leaked
// implicit transaction exactly like its siblings — an unresolvable
// savepoint under no caller tx throws 'leaked transaction rolled back',
// never leaves the zombie open to wedge every future seal.
// ============================================================================
test('w74-seal F-2: an unresolvable note savepoint reaps the leaked transaction', t => {
  const h = fixture(t);
  h.ready(); h.ready();
  for (let i = 0; i < 3; i++) healOnce(h, `w74note-${i}`);
  divergeChain(h);
  const origExec = h.f.store.db.exec.bind(h.f.store.db);
  h.f.store.db.exec = (sql) => {
    if (sql === 'RELEASE residue_note' || sql === 'ROLLBACK TO residue_note')
      throw Object.assign(new Error('disk I/O error'), { errcode: 10 });
    return origExec(sql);
  };
  let e = null;
  try { h.f.sealAuditChain(h.p('security')); } catch (err) { e = err; }
  h.f.store.db.exec = origExec;
  assert.ok(e && e.code === 'INV-503-LEDGER' && /leaked transaction rolled back/.test(e.message ?? ''),
    `the zombie reaps with the named refusal: ${e?.code} ${e?.message}`);
  assert.equal(h.f.store.db.isTransaction, false, 'the leaked implicit transaction is rolled back');
  // The wedge is gone: a clean seal never trips the 'cannot nest' guard.
  let e2 = null;
  try { h.f.sealAuditChain(h.p('security')); } catch (err) { e2 = err; }
  assert.ok(!/cannot nest/.test(String(e2?.message ?? '')), `no zombie wedges the next seal: ${e2?.message}`);
  h.close();
});

// ============================================================================
// w74-seal F-3: SimulatedTarget._schemaGuard probe-verifies a 'no such
// table' claim — a foreign trigger spelling it over a standing schema
// rides the 1811 'refused by a trigger' arm, never 'schema diverged'.
// ============================================================================
test('w74-seal F-3: the target probe-verifies schema claims — fabricated text is a refused write', t => {
  const h = fixture(t);
  h.ready();
  h.f.target.db.exec("CREATE TRIGGER fake_schema BEFORE INSERT ON grants BEGIN SELECT RAISE(ABORT, 'no such table: grants'); END");
  let e = null;
  try { h.f.target.grant('acme', 'g1', 'v'); } catch (err) { e = err; }
  assert.ok(e !== null, 'the armed trigger refuses the grant write');
  assert.equal(e.code, 'INV-409-INTEGRITY', `the refused write convicts INTEGRITY: ${e?.code}`);
  // The version pin (w76-fv F-1) convicts the planted trigger at the
  // guard's entry — 'live DDL' — before the write reaches the
  // refused-trigger arm. To exercise the arm itself, stage the same
  // 1811-with-schema-text at the statement layer where no DDL fires.
  assert.ok(/live DDL|refused by a trigger/.test(e.message ?? ''),
    `a planted trigger convicts at the pin or the arm: ${e?.message}`);
  h.f.target.db.exec('DROP TRIGGER fake_schema');
  const origS = h.f.target._stmt.bind(h.f.target);
  h.f.target._stmt = (sql) => {
    if (String(sql).includes('INSERT INTO grants'))
      throw Object.assign(new Error('no such table: grants'), { errcode: 1811 });
    return origS(sql);
  };
  e = null;
  try { h.f.target.grant('acme', 'g2', 'v'); } catch (err) { e = err; }
  h.f.target._stmt = origS;
  assert.ok(e !== null && e.code === 'INV-409-INTEGRITY' && /refused by a trigger/.test(e.message ?? ''),
    `the fabricated 'no such table' falls through to the 1811 arm: ${e?.message}`);
  assert.ok(!/diverged/.test(e.message ?? ''), 'a standing schema is never convicted as diverged');
  h.close();
});

// ============================================================================
// w74-seal F-4: the constructor's aad-migration probe is column-bearing —
// a column-drained meta_kv convicts INV-409 instead of passing the old
// existence check and dying raw on first use.
// ============================================================================
test('w74-seal F-4: a column-drained meta_kv convicts at construction', t => {
  const h = fixture(t);
  h.ready();
  const dir = h.directory, cfg = h.setup.config;
  h.f.store.db.exec('ALTER TABLE meta_kv DROP COLUMN value');
  let e = null;
  try { const f2 = new Fabric(cfg, dir, h.f.clock); f2.close(); } catch (err) { e = err; }
  assert.ok(e && e.code === 'INV-409-INTEGRITY' && /diverged/.test(e.message ?? ''),
    `a column-drained meta_kv convicts INV-409 at construction: ${e?.code} ${e?.message}`);
  h.close();
});

// ============================================================================
// w74-seal F-5: a probe-fault in the corruption family (errcode 11/26)
// convicts INV-409-INTEGRITY — the old [8,10,11,…] storage set wore
// INV-503-STORAGE over engine-reported corruption.
// ============================================================================
test('w74-seal F-5: a corruption-family probe fault convicts INV-409, never storage', t => {
  const h = fixture(t);
  h.ready(); h.ready();
  healOnce(h, 'pb-corrupt');
  h.f.sealAuditChain(h.p('security'));
  const orig = h.f.store._stmt.bind(h.f.store);
  const origP = h.f.store.db.prepare.bind(h.f.store.db);
  h.f.store._stmt = (sql) => {
    const s = String(sql), st = new Error().stack;
    if (s.includes("key='fold_floor_retired'") && st.includes('sealAuditChain'))
      throw Object.assign(new Error('no such table: meta_kv'), { errcode: 1 });
    return orig(sql);
  };
  // The schema probes prepare fresh statements (w75-runtime F-3) — the
  // faulted LIMIT-0 lands through db.prepare, never the _stmt cache.
  h.f.store.db.prepare = (sql) => {
    const s = String(sql), st = new Error().stack;
    if (s.includes('LIMIT 0') && st.includes('sealAuditChain'))
      throw Object.assign(new Error('database disk image is malformed at page 7'), { errcode: 11 });
    return origP(s);
  };
  healOnce(h, 'pb-corrupt-2');
  let e = null;
  try { h.f.sealAuditChain(h.p('security')); } catch (err) { e = err; }
  h.f.store._stmt = orig;
  h.f.store.db.prepare = origP;
  assert.ok(e && e.code === 'INV-409-INTEGRITY',
    `a corruption-family probe fault convicts INV-409: ${e?.code} ${e?.message}`);
  h.close();
});

// ============================================================================
// w74-fv F-1 + w74-ledger F-1: operand-head siblings — always-truthy
// container literals (`[cmp]`, `{k: cmp}`, `` `…${cmp}…` ``), subscript
// wrappers (`q[cmp]`), arrow operands (`z => cmp`), `||`-LHS and `?:`
// heads, and every compound-assign (`y op= cmp`) are operand contexts:
// the compare never decides the arm. Skipping the pair degrades the arm
// to conditional — `roles:null, any:true` for every verb — while honest
// `&&` keeps its pair.
// ============================================================================
test('w74-fv F-1 + ledger F-1: truthy-container/arrow/op-assign heads never bind a verb', () => {
  const arm = head => [HEAD2, `  if (${head}) { authorize(p, ['adm']); }`, '}'];
  // The honest degradation is `any:true` for EVERY verb — the arm is
  // live for anyone, it is just never bound to the compare's verb.
  // Pre-fix the pair binding reported `any:false` for foreign verbs —
  // a dead arm over code that runs unconditionally. Always-truthy
  // container heads additionally prove the authorize unconditional —
  // 'adm' mints for every verb; unprovable operand heads stay
  // conditional (roles null — the arm may run, never must).
  for (const [name, head, roles] of [
    ['array literal', "[m[1]==='x']", ['adm']],
    ['object literal', "{a: m[1]==='x'}", ['adm']],
    ['computed key', "{[m[1]==='x']:1}", ['adm']],
    ['template interpolation', "`x${m[1]==='x'}`", ['adm']],
    ['subscript wrapper', "q[m[1]==='x']", null],
    ['arrow operand', "z => m[1]==='x'", null],
    ['paren arrow', "(z) => m[1]==='x'", null],
    ['|| LHS', "flag || m[1]==='x'", null],
    ['ternary ? head', "flag ? m[1]==='x' : y", null],
    ['ternary : head', "flag ? y : m[1]==='x'", null],
    ['?? head', "flag ?? m[1]==='x'", null],
    ['+=', "y += m[1]==='x'", null],
    ['-=', "y -= m[1]==='x'", null],
    ['||=', "y ||= m[1]==='x'", null],
    ['&&=', "y &&= m[1]==='x'", null],
    ['**=', "y **= m[1]==='x'", null],
    ['>>>=', "y >>>= m[1]==='x'", null],
    ['while array', "while ([m[1]==='x'])", null],
  ]) {
    const cx = collectRun(arm(head), 'x'), cw = collectRun(arm(head), 'w');
    assert.equal(cx.any, true, `${name}: the arm is live for the compare's verb: ${JSON.stringify(cx)}`);
    assert.equal(cw.any, true, `${name}: the arm is live for foreign verbs — never falsely dead: ${JSON.stringify(cw)}`);
    assert.deepEqual(cw.roles, roles, `${name}: mint matches the arm's provability: ${JSON.stringify(cw)}`);
  }
  // Honest heads still bind — a real &&-gate keeps the arm dead for
  // foreign verbs and mints the pair for its own.
  const honest = collectRun(arm("flag && m[1]==='x'"), 'x'), honestW = collectRun(arm("flag && m[1]==='x'"), 'w');
  assert.equal(honest.any, true, 'a real &&-gate keeps the arm live for its verb');
  assert.equal(honestW.any, false, 'a real &&-gate stays dead for foreign verbs');
});

// ============================================================================
// w74-fv F-2: the bound-verdict continuation respects ASI — `ok && flag`
// then a newline-separated call is two statements (the verdict is
// discarded), while `ok &&\nserve(req)` stays one statement. Comma
// continuations are ungated too (`ok && flag, serve()` runs serve
// unconditionally).
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
test('w74-fv F-2: ASI and comma continuations never mint a gated verdict', () => {
  const arm = tail => ["if (req.method === 'GET') {", ...tail, "}"];
  assert.equal(unguardedAuthRun(arm(["  const ok = checkAuth(req);", "  ok && flag", "  serve(req);"])), false,
    'ASI: the verdict dies at the newline — serve is ungated');
  assert.equal(unguardedAuthRun(arm(["  const ok = checkAuth(req);", "  ok || flag", "  serve(req);"])), false,
    'same for the ||-continuation across ASI');
  assert.equal(unguardedAuthRun(arm(["  const ok = checkAuth(req);", "  ok && flag, serve(req);"])), false,
    'a comma continuation runs the call unconditionally');
  // Honest same-statement / operator-led wraps still mint.
  assert.equal(unguardedAuthRun(arm(["  const ok = checkAuth(req);", "  ok && serve(req);"])), true,
    'a same-statement continuation still reads the verdict');
  assert.equal(unguardedAuthRun(arm(["  const ok = checkAuth(req);", "  ok &&", "  serve(req);"])), true,
    'an operator-led newline is still one statement');
});

// ============================================================================
// w74-fv F-3/F-4 + w74-ledger F-2: the outside-scan — `?.` normalizes to
// `.`, `?.[` to `[`, Reflect.get/ownKeys count, a whole-request alias
// (`const r = req`) rebinds the surface, and destructures cover
// bare/nested/computed/for-of/param/await shapes.
// ============================================================================
const OUTSIDE_SLICE = (() => {
  // The slice starts at the `dispatchText` declaration so the shipped
  // `?.`/`?.[` normalization runs verbatim inside the probe (w74-fv
  // F-3: it is part of the audited surface, not test scaffolding).
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
test('w74-fv F-3/F-4 + ledger F-2: optional-chain, alias and destructure siblings all flag', () => {
  for (const [name, text] of [
    ['optional method', "req?.method === 'GET';"],
    ['optional headers', "const a = req?.headers['authorization'];"],
    ['optional url read', "const u = req?.url; u === '/x';"],
    ['spaced optional', "req ?. url === '/x';"],
    ['optional bracket', "const u = req?.['url'];"],
    ['Reflect.get', "const u = Reflect.get(req, 'url'); u === '/x';"],
    ['req alias member', "const r = req; const u = r.url; new URL(u);"],
    ['req alias startsWith', "const r = req; r.url.startsWith('/x');"],
    ['bare destructure', "let u; ({url: u} = req); u === '/x';"],
    ['for-of destructure', "for (const {url} of reqs) { url === '/x'; }"],
    ['for-await destructure', "for await (const {url} of reqs) { url === '/x'; }"],
    ['param destructure', "function h({url, method}) { url === '/x'; }"],
    ['await destructure', "async () => { const {url} = await req; url === '/x'; };"],
    ['computed key', "const {['url']: u} = req; u === '/x';"],
    ['nested destructure', "const {a: {url}} = req; url === '/x';"],
  ]) assert.equal(outsideRun(text), true, `${name} flags: ${text}`);
  for (const [name, text] of [
    ['call-result source', "const {url} = f(req); url === '/x';"],
    ['unrelated member', "const u = other.thing === '/x';"],
    ['no surface', "const x = compute(); console.log(x);"],
  ]) assert.equal(outsideRun(text), false, `${name} correctly stays unflagged: ${text}`);
});

// ============================================================================
// w74-fv F-5: SECRET_RULES also run over a NUL-collapsed decode — a
// UTF-16LE/BE or NUL-interleaved tracked file cannot smuggle a
// credential past the scan.
// ============================================================================
const SECRET_SLICE = (() => {
  // Two verbatim slices: the SECRET_RULES declaration and the tracked-
  // file scan loop — the probe supplies textFiles/readFileSync/
  // existsSync/failed so the shipped `collapsed` second pass runs as
  // written (w74-fv F-5).
  const r0 = CHECK_SRC.indexOf('const SECRET_RULES');
  const r1 = CHECK_SRC.indexOf('];', r0) + 2;
  const l0 = CHECK_SRC.indexOf('for (const file of textFiles) {');
  const l1 = CHECK_SRC.indexOf('for (const file of files.filter', l0);
  assert.ok(r0 !== -1 && r1 > r0 && l0 !== -1 && l1 > l0, 'the secret-scan slices resolve');
  return CHECK_SRC.slice(r0, r1) + '\n' + CHECK_SRC.slice(l0, l1);
})();
test('w74-fv F-5: UTF-16 / NUL-interleaved tracked files answer the secret scan', () => {
  const dir = mkdtempSync(join(tmpdir(), 'secret-probe-'));
  try {
    const cred = 'AKIA' + 'B'.repeat(16);
    writeFileSync(join(dir, 'u16.txt'), Buffer.from(`-----BEGIN ` + `PRIVATE KEY----- ${cred}`, 'utf16le'));
    writeFileSync(join(dir, 'inter.bin'), Buffer.from('A\0K\0I\0A' + 'B\0'.repeat(16), 'latin1'));
    writeFileSync(join(dir, 'honest.txt'), 'no secrets here');
    const out = probeFile([
      `import { readFileSync, existsSync } from 'node:fs';`,
      `const textFiles = ${JSON.stringify([join(dir, 'u16.txt'), join(dir, 'inter.bin'), join(dir, 'honest.txt')])};`,
      `let failed = false;`,
      SECRET_SLICE,
      `process.stdout.write(JSON.stringify({ failed }));`
    ].join('\n'));
    // The slice emits console.error lines per conviction — probeFile
    // returns stdout; parse the last JSON line.
    const last = out.split('\n').filter(Boolean).at(-1);
    assert.equal(JSON.parse(last).failed, true, 'UTF-16 and NUL-interleaved credentials convict');
    // Negative control: the honest file alone must not convict.
    const out2 = probeFile([
      `import { readFileSync, existsSync } from 'node:fs';`,
      `const textFiles = ${JSON.stringify([join(dir, 'honest.txt')])};`,
      `let failed = false;`,
      SECRET_SLICE,
      `process.stdout.write(JSON.stringify({ failed }));`
    ].join('\n'));
    const last2 = out2.split('\n').filter(Boolean).at(-1);
    assert.equal(JSON.parse(last2).failed, false, 'a clean tracked file does not convict');
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

// ============================================================================
// w74-fv LOW + w74-ledger F-3/F-4/F-5: arrow-param shadows and
// destructured for-head bindings scope clause-wide — a trailing honest
// assert survives — and `for await` is covered deliberately.
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
test('w74: arrow params and destructured loop heads scope to their clause, never the whole block', () => {
  const [parenArrow, bareArrow, nestedArg, destrArray, destrObj, forAwait, forAwaitBare, honest] = traceProbe([
    // `(assert) =>` binds the arrow body — the trailing assert is real.
    { text: "import assert from 'node:assert';\ntest('X', () => {\n  const f = (assert) => { assert.ok(0); };\n  assert.ok(1);\n});" },
    // `assert =>` binds identically.
    { text: "import assert from 'node:assert';\ntest('X', () => {\n  const f = assert => assert.ok(0);\n  assert.ok(1);\n});" },
    // An arrow inside call args scopes to its expression — the second
    // argument's honest assert counts.
    { text: "import assert from 'node:assert';\ntest('X', () => {\n  g((assert) => assert.ok(0), assert.ok(1));\n});" },
    // Destructured loop params bind the loop body only.
    { text: "import assert from 'node:assert';\ntest('X', () => {\n  for (const [assert] of []) { assert.ok(0); }\n  assert.ok(1);\n});" },
    { text: "import assert from 'node:assert';\ntest('X', () => {\n  for (const {assert} of []) { assert.ok(0); }\n  assert.ok(1);\n});" },
    // `for await` binds deliberately (braced and bodyless).
    { text: "import assert from 'node:assert';\ntest('X', () => {\n  for await (const assert of []) { assert.ok(0); }\n  assert.ok(1);\n});" },
    { text: "import assert from 'node:assert';\ntest('X', () => {\n  for await (const assert of []) assert.ok(0);\n  assert.ok(1);\n});" },
    { text: "import assert from 'node:assert';\ntest('X', () => { assert.ok(1); assert.ok(2); });" },
  ]);
  assert.deepEqual(parenArrow, [1], `(assert) => scopes to the arrow body: ${JSON.stringify(parenArrow)}`);
  assert.deepEqual(bareArrow, [1], `assert => scopes to the arrow body: ${JSON.stringify(bareArrow)}`);
  assert.deepEqual(nestedArg, [1], `an arg-position arrow frees the trailing assert: ${JSON.stringify(nestedArg)}`);
  assert.deepEqual(destrArray, [1], `for (const [assert] of …) binds the loop body: ${JSON.stringify(destrArray)}`);
  assert.deepEqual(destrObj, [1], `for (const {assert} of …) binds the loop body: ${JSON.stringify(destrObj)}`);
  assert.deepEqual(forAwait, [1], `for await binds the loop body: ${JSON.stringify(forAwait)}`);
  assert.deepEqual(forAwaitBare, [1], `bodyless for-await binds its expression: ${JSON.stringify(forAwaitBare)}`);
  assert.deepEqual(honest, [2], `the honest baseline counts: ${JSON.stringify(honest)}`);
});
