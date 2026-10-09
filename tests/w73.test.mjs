// Wave-73 regression tests: w73-runtime F-1 (a faulted ROLLBACK TO +
// retried RELEASE used to COMMIT the span it was meant to undo — now
// rollback retries boundedly and only a proven rollback may release),
// w73-fv F-3 (a rolled-back residue note names its transient
// `note_rolled_back` window), w73-seal F-1/F-2/F-3 + w73-fv F-1/F-2 +
// w73-runtime F-2 (schema-claim text is probe-VERIFIED by table
// membership everywhere — fabricated 'no such table' text is never a
// tamper conviction, a probe that cannot answer propagates its own
// classified fault, and a corruption-family errcode alone convicts),
// w73-ledger F-1/F-2/F-3 (a shared operand-head guard binds unary
// `+ - ~ ++ -- delete new typeof void` and masked-comment parens at all
// three extraction sites — direct member, alias compare, alias-equal),
// w73-ledger F-4 (`unguardedAuth`'s bound-verdict continuation no longer
// crosses `;` and logical assignment never gates), w73-ledger F-5
// (outside-scan capability shapes: renamed destructure, `new (URL)`,
// `URL['parse']`, `const u=URL` alias, `http['createServer']`,
// `addEventListener`, `switch (f().method)`, `{headers}` reads,
// `new URL(u)` of a rebound name), w73-ledger F-7 (traceability
// param/assign scoping).
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';
import { fixture } from './helpers.mjs';
import { RESIDUE_KEEP_TRIGGERS } from '../src/store.mjs';

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

const collectRun = (lines, verb) => {
  assert.ok(NONROLE_BLOCK.includes('collectAuthorize'), 'the slice carries the shipped scanner');
  return JSON.parse(probeFile([
    HELPERS, NONROLE_BLOCK,
    `globalThis.process.stdout.write(JSON.stringify(collectAuthorize(${JSON.stringify(lines)}, 0, ${lines.length + 2}, true, ${JSON.stringify(verb)})));`
  ].join('\n')));
};
const HEAD2 = "if ((m = /^\\/x\\/(.*)\\/(.*)/.exec(path))) {";

const markerRow = h => h.f.store.db.prepare("SELECT value FROM meta_kv WHERE tenant='acme' AND key='fold_floor_retired'").get()?.value;
const dropResidueGuards = h => {
  h.f.store.db.exec('DROP TRIGGER IF EXISTS fold_residue_keep');
  h.f.store.db.exec('DROP TRIGGER IF EXISTS fold_residue_keep_upd');
  h.f.store.db.exec('DROP TRIGGER IF EXISTS fold_residue_keep_ins');
};
// w76-fv F-1: the schema-version pin convicts a dropped guard set at the next
// guarded call — plants restore the canonical set before the seal runs.
const restoreResidueGuards = h => { for (const [name, sql] of RESIDUE_KEEP_TRIGGERS) { try { h.f.store.db.exec(sql); } catch (e) { if (!/already exists/.test(String(e?.message ?? e))) throw e; } } };
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
// w73-runtime F-1: the savepoint unwind doctrine — a faulted ROLLBACK TO
// retried once, RELEASE only after a proven rollback, and a savepoint
// that never resolves refuses INV-503 instead of silently committing the
// span (a RELEASE retried over a faulted ROLLBACK TO resolves the name by
// COMMITTING it — the old order did exactly that).
// ============================================================================
test('w73-runtime F-1: a permanently faulted ROLLBACK TO refuses — the span never silently commits', t => {
  const h = fixture(t);
  h.ready(); h.ready();
  for (let i = 0; i < 3; i++) healOnce(h, `rb-${i}`);
  divergeChain(h);
  const origExec = h.f.store.db.exec.bind(h.f.store.db);
  // The first drain in the seal is the echo path at :2368 — its own
  // `try {} catch {}` swallows a refused unwind (the flag stands
  // regardless). Fault the SECOND RELEASE — the attested drain whose
  // INV-503 propagates through the seal — and every ROLLBACK TO, so
  // the savepoint can never resolve and the span must refuse rather
  // than commit through a retried RELEASE.
  let relCalls = 0;
  h.f.store.db.exec = (sql) => {
    if (sql === 'RELEASE residue_drain' && ++relCalls === 2) throw Object.assign(new Error('disk I/O error'), { errcode: 10 });
    if (sql === 'ROLLBACK TO residue_drain') throw Object.assign(new Error('disk I/O error'), { errcode: 10 });
    return origExec(sql);
  };
  let e = null;
  try { h.f.sealAuditChain(h.p('security')); } catch (err) { e = err; }
  h.f.store.db.exec = origExec;
  assert.ok(e && e.code === 'INV-503-LEDGER',
    `a savepoint that never rolls back refuses INV-503 — never a silent commit: ${e?.code} ${e?.message}`);
  assert.equal(h.f.store.db.isTransaction, false, 'no zombie transaction survives the refused unwind');
  h.close();
});

test('w73-runtime F-1 (transient arm): a transient ROLLBACK TO fault retries and the claims land once', t => {
  const h = fixture(t);
  h.ready(); h.ready();
  for (let i = 0; i < 3; i++) healOnce(h, `rb2-${i}`);
  divergeChain(h);
  const origExec = h.f.store.db.exec.bind(h.f.store.db);
  // Fault the first RELEASE so the unwind runs, then the FIRST
  // ROLLBACK TO attempt only — the retry proves the span undone,
  // RELEASE runs, the rolled-back drain stands down, and the second
  // post-commit drain lands the claims exactly once.
  let relOnce = true, rbOnce = true;
  h.f.store.db.exec = (sql) => {
    if (relOnce && sql === 'RELEASE residue_drain') { relOnce = false; throw Object.assign(new Error('disk I/O error'), { errcode: 10 }); }
    if (rbOnce && sql === 'ROLLBACK TO residue_drain') { rbOnce = false; throw Object.assign(new Error('disk I/O error'), { errcode: 10 }); }
    return origExec(sql);
  };
  const res = h.f.sealAuditChain(h.p('security'));
  h.f.store.db.exec = origExec;
  assert.equal(res.sealed, true);
  assert.equal(h.f.store.db.isTransaction, false, 'no zombie transaction survives the retried unwind');
  const mk = markerRow(h);
  assert.ok(mk !== undefined, 'the surviving second drain latches the marker');
  assert.equal((JSON.parse(mk).claims ?? []).length, 3, 'each consumed claim lands exactly once');
  h.close();
});

// ============================================================================
// w73-fv F-3: a faulted RELEASE on the residue-note savepoint discards
// the note — the retiring window is named `floor_marker_retired_note_
// rolled_back` instead of sealing silently while the mints proceed.
// ============================================================================
test('w73-fv F-3: a rolled-back residue note is flagged, not silent', t => {
  const h = fixture(t);
  h.ready(); h.ready();
  for (let i = 0; i < 3; i++) healOnce(h, `note-${i}`);
  divergeChain(h);
  const origExec = h.f.store.db.exec.bind(h.f.store.db);
  let once = true;
  h.f.store.db.exec = (sql) => {
    if (once && sql === 'RELEASE residue_note') { once = false; throw Object.assign(new Error('disk I/O error'), { errcode: 10 }); }
    return origExec(sql);
  };
  let res = null, e = null;
  try { res = h.f.sealAuditChain(h.p('security')); } catch (err) { e = err; }
  h.f.store.db.exec = origExec;
  // The note rolled back; the flag names the transient window on this
  // seal's report (or the next, if the flag lands after the report row).
  const flagged = findKind(res ?? {}, /floor_marker_retired_note_rolled_back/).length >= 1
    || (e === null ? (() => { try { return findKind(h.f.sealAuditChain(h.p('security')), /floor_marker_retired_note_rolled_back/).length >= 1; } catch { return false; } })() : false);
  assert.ok(flagged, `the rolled-back note names its window: ${JSON.stringify(res?.head_watermark_tampered)}`);
  h.close();
});

// ============================================================================
// w73-seal F-2 tri-state: a schema claim whose PROBE cannot run is
// infrastructure — a busy probe (errcode 5) rides INV-503-LEDGER, never
// INV-409 'tamper evidence' over a merely contended ledger.
// ============================================================================
test('w73-seal F-2: a contended schema probe propagates its own classified fault', t => {
  const h = fixture(t);
  h.ready(); h.ready();
  healOnce(h, 'probe-busy');
  h.f.sealAuditChain(h.p('security'));
  const orig = h.f.store._stmt.bind(h.f.store);
  h.f.store._stmt = (sql) => {
    const s = String(sql), st = new Error().stack;
    if (s.includes("key='fold_floor_retired'") && st.includes('sealAuditChain'))
      throw Object.assign(new Error('no such table: meta_kv'), { errcode: 1 });
    if (s.includes('LIMIT 0') && st.includes('sealAuditChain'))
      throw Object.assign(new Error('database is locked'), { errcode: 5 });
    return orig(sql);
  };
  // The w75 membership probe prepares fresh per table — the contended
  // probe fault reaches it on db.prepare (w75-seal F-3's column-order
  // check is why fresh prepare is required).
  const origPrep = h.f.store.db.prepare.bind(h.f.store.db);
  h.f.store.db.prepare = (sql) => {
    if (String(sql).includes('LIMIT 0') && new Error().stack.includes('sealAuditChain'))
      throw Object.assign(new Error('database is locked'), { errcode: 5 });
    return origPrep(sql);
  };
  healOnce(h, 'probe-busy-2');
  let e = null;
  try { h.f.sealAuditChain(h.p('security')); } catch (err) { e = err; }
  h.f.store._stmt = orig;
  h.f.store.db.prepare = origPrep;
  assert.ok(e && e.code === 'INV-503-LEDGER' && /schema probe/i.test(e.message ?? ''),
    `a contended probe retries as INV-503-LEDGER, never tamper evidence: ${e?.code} ${e?.message}`);
  h.close();
});

// ============================================================================
// w73-seal F-3 + w73-fv F-1 + w73-runtime F-2: the store convict-on-text
// arm verifies SCHEMA MEMBERSHIP — a column-bearing probe of every
// expected ledger table — not a name parsed out of attacker text.
// Fabricated names (live, absent, case-folded) exculpate to the raw
// fault; a probe that diverges convicts INV-409; a corruption-family
// errcode convicts alone.
// ============================================================================
test('w73-seal F-3/fv F-1: _schemaGuard verifies membership — fabricated names ride raw', t => {
  const h = fixture(t);
  h.ready(); h.ready();
  const orig = h.f.store._stmt.bind(h.f.store);
  // A fabricated claim naming a LIVE table — the old name-probe
  // exculpated on the name standing; under membership doctrine the same
  // healthy schema answers 'ok' and the raw fault propagates.
  for (const msg of ['no such table: records', 'no such table: RECORDS', 'no such table: nonexistent_xyz']) {
    h.f.store._stmt = (sql) => {
      // Only the real read faults — the membership probe's own
      // `… FROM records LIMIT 0` must still answer, or the fabricated
      // name convicts through a probe the injection poisoned itself.
      if (String(sql).includes('FROM records WHERE')) throw Object.assign(new Error(msg), { errcode: 1 });
      return orig(sql);
    };
    let e = null;
    try { h.f.store.get('acme', 'capsule', 'nope'); } catch (err) { e = err; }
    assert.ok(e && e.code !== 'INV-409-INTEGRITY' && e.message === msg,
      `'${msg}' over a standing schema is the raw engine fault: ${e?.code ?? e.message}`);
  }
  // A probe that fails schema-shaped proves the divergence — convict.
  h.f.store._stmt = (sql) => {
    if (String(sql).includes('FROM records WHERE') || String(sql).includes('LIMIT 0'))
      throw Object.assign(new Error('no such table: records'), { errcode: 1 });
    return orig(sql);
  };
  // The w75 probe prepares fresh per table — same fault on db.prepare.
  const origPrep2 = h.f.store.db.prepare.bind(h.f.store.db);
  h.f.store.db.prepare = (sql) => {
    if (String(sql).includes('LIMIT 0'))
      throw Object.assign(new Error('no such table: records'), { errcode: 1 });
    return origPrep2(sql);
  };
  let e = null;
  try { h.f.store.get('acme', 'capsule', 'nope'); } catch (err) { e = err; }
  h.f.store.db.prepare = origPrep2;
  assert.ok(e && e.code === 'INV-409-INTEGRITY', `a probe-diverged schema convicts: ${e?.code}`);
  // A corruption-family errcode is engine-only proof — no probe needed.
  h.f.store._stmt = (sql) => {
    if (String(sql).includes('FROM records WHERE'))
      throw Object.assign(new Error('file is not a database'), { errcode: 26 });
    return orig(sql);
  };
  e = null;
  try { h.f.store.get('acme', 'capsule', 'nope'); } catch (err) { e = err; }
  h.f.store._stmt = orig;
  assert.ok(e && e.code === 'INV-409-INTEGRITY', `SQLITE_NOTADB convicts on the errcode alone: ${e?.code}`);
  h.close();
});

// ============================================================================
// w73-seal F-1 + fv F-2: the gate catch re-verifies too — a fabricated
// 'no such table' that survived _schemaGuard's exculpation must NOT be
// re-minted INV-409 one frame up; it classifies to INV-503-GATE.
// ============================================================================
test('w73-seal F-1/fv F-2: the gate wrapper never re-convicts a fabricated schema claim', t => {
  const h = fixture(t);
  h.ready(); h.ready();
  const pol = h.f.policy('acme');
  const cand = { ...pol, version: pol.version + 1 };
  const orig = h.f.store._stmt.bind(h.f.store);
  // Fault the kind-list read inside the transaction — `SELECT id,value`
  // names `store.list` alone (authorize's `ids()` sweep selects `id`
  // only and would ride out before the gate frame exists).
  const isList = sql => String(sql).includes('SELECT id,value FROM records');
  h.f.store._stmt = (sql) => {
    if (isList(sql))
      throw Object.assign(new Error('no such table: audit'), { errcode: 1 });
    return orig(sql);
  };
  let e = null;
  try { h.f.simulate(h.p('policy-admin', 'acme'), cand); } catch (err) { e = err; }
  assert.ok(e && e.code === 'INV-503-GATE',
    `fabricated text exculpated at the store rides out as gate-infra, not tamper: ${e?.code} ${e?.message}`);
  // The same text with a diverging probe convicts once, at the gate.
  h.f.store._stmt = (sql) => {
    if (isList(sql) || String(sql).includes('LIMIT 0'))
      throw Object.assign(new Error('no such table: audit'), { errcode: 1 });
    return orig(sql);
  };
  const origPrep = h.f.store.db.prepare.bind(h.f.store.db);
  h.f.store.db.prepare = (sql) => {
    if (String(sql).includes('LIMIT 0'))
      throw Object.assign(new Error('no such table: audit'), { errcode: 1 });
    return origPrep(sql);
  };
  e = null;
  try { h.f.simulate(h.p('policy-admin', 'acme'), cand); } catch (err) { e = err; }
  h.f.store._stmt = orig;
  h.f.store.db.prepare = origPrep;
  assert.ok(e && e.code === 'INV-409-INTEGRITY', `a probe-diverged schema convicts at the gate: ${e?.code}`);
  h.close();
});

// ============================================================================
// w73-ledger F-1/F-2/F-3: the shared operand-head guard binds every
// compare-spelling's left edge — unary +/- prefix, ++/--, delete, new,
// comment-masked typeof parens, and the alias sites (`q[N]`, `q===`).
// A member swallowed by a tighter operator is never a member-vs-verb
// compare: it neither serves nor votes — the arm mints conditional.
// ============================================================================
test('w73-ledger F-1/F-2/F-3: unary and masked-paren heads never mint a member pair', () => {
  const H = "if (m[1]==='x') {";
  // Unary heads on the direct-member site — the pair must not extract,
  // so the arm mints conditional rather than attesting 'adm' for x.
  for (const head of ['+', '-', '~', '++', '--', 'delete ', 'new ']) {
    const r = collectRun([H, `  if (${head}m[1]==='x') { authorize(p, ['adm']); }`, '}'], 'x');
    assert.deepEqual(r.roles, null, `${head}m[1] — the member is operand, not compare: ${JSON.stringify(r)}`);
    assert.equal(r.any, true, `${head}m[1] — the arm stays conditional-live: ${JSON.stringify(r)}`);
  }
  // Comment-masked parens between typeof and its operand (w73-ledger
  // F-2): the pair inside `typeof(…)` must NOT join the pair set — its
  // phantom vote used to prove member m[2] discriminates, folding a
  // later `m[2]!=='z'` unconditionally for every unbound verb. With the
  // pair gone, `m[2]` carries one real vote and the negated arm stays
  // conditional (the arm itself is still statically true — `typeof` of
  // a compare is 'boolean' — and mints honestly through the arm fold).
  { const r = collectRun([H,
      "  if (typeof(/*c*/(m[2]==='x'))) { a(); }",
      "  if (m[2]==='y') { authorize(p, ['ops']); }",
      "  if (m[2]!=='z') { authorize(p, ['adm']); }", '}'], 'w');
    assert.deepEqual(r.roles, null,
      `the masked-typeof pair may not prove m[2] discriminates — 'w' stays conditional: ${JSON.stringify(r)}`);
    const rx = collectRun([H,
      "  if (typeof(/*c*/(m[2]==='x'))) { a(); }",
      "  if (m[2]==='y') { authorize(p, ['ops']); }",
      "  if (m[2]!=='z') { authorize(p, ['adm']); }", '}'], 'x');
    assert.deepEqual(rx.roles, null,
      `without the phantom vote, 'x' on m[2] carries one vote — the negated arm stays conditional: ${JSON.stringify(rx)}`); }
  // The alias sites carry the same guard (w73-ledger F-3).
  { const r = collectRun([HEAD2, "  const q = m;", "  if (+q[2]==='x') { authorize(p, ['adm']); }", '}'], 'x');
    assert.deepEqual(r.roles, null, `+q[2] — the alias member is operand, not compare: ${JSON.stringify(r)}`); }
  { const r = collectRun([HEAD2, "  const q = m;", "  if (typeof q[2]==='x') { authorize(p, ['adm']); }", '}'], 'x');
    assert.deepEqual(r.roles, null, `typeof q[2] — the alias member is operand, not compare: ${JSON.stringify(r)}`); }
  { const r = collectRun([HEAD2, "  const q = m;", "  if (!!q[2]==='x') { authorize(p, ['adm']); }", '}'], 'x');
    assert.deepEqual(r.roles, null, `!!q[2] — the alias member is operand, not compare: ${JSON.stringify(r)}`); }
  { const r = collectRun([HEAD2, "  const q = m[1];", "  if (+q==='x') { authorize(p, ['adm']); }", '}'], 'x');
    assert.deepEqual(r.roles, null, `+q — the alias-equal member is operand, not compare: ${JSON.stringify(r)}`); }
  // Parity: honest heads still mint — a bare pair, an `&&` continuation,
  // an arrow expression and `await` all keep the real compare.
  { const r = collectRun([H, "  if (m[2]==='x') { authorize(p, ['adm']); }", '}'], 'x');
    assert.deepEqual(r.roles, ['adm'], `the bare compare still binds: ${JSON.stringify(r)}`); }
  // `!(m[1]==='x')` is a negated compare — it keeps its pair as a
  // negated seed (never a vote) so folds still resolve it, and the arm
  // itself rides the plural-gamble doctrine: conditional either way.
  for (const v of ['x', 'y']) {
    const r = collectRun(["if (!(m[1]==='x')) { authorize(p, ['adm']); }"], v);
    assert.deepEqual(r.roles, null, `!(m[1]==='x') for '${v}' — a negated arm never attests unconditional: ${JSON.stringify(r)}`);
    assert.equal(r.any, true, `!(m[1]==='x') for '${v}' — the arm is live-conditional: ${JSON.stringify(r)}`);
  }
});

// ============================================================================
// w73-ledger F-4: the bound-verdict continuation legs of unguardedAuth
// stay inside their statement — `ok && flag; serve(req)` minted 'token
// holder' off a call the verdict never gated — and logical assignment
// (`&&=`/`||=`) writes the verdict, never reads it.
// ============================================================================
const AUTH_BLOCK = CHECK_SRC.slice(CHECK_SRC.indexOf('const AUTH_CALL'), CHECK_SRC.indexOf('if (r.roles.length === 1'));
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
test('w73-ledger F-4: bound-verdict continuations never cross `;` and `&&=`/`||=` never gate', () => {
  const arm = tail => ["if (req.method === 'GET') {", ...tail, "}"];
  assert.equal(unguardedAuthRun(arm(["  const ok = checkAuth(req);", "  ok && flag;", "  serve(req);"])), false,
    'a discarded continuation then an independent call is ungated');
  assert.equal(unguardedAuthRun(arm(["  const ok = checkAuth(req);", "  ok || flag;", "  serve(req);"])), false,
    'the ||-continuation dies at the semicolon too');
  assert.equal(unguardedAuthRun(arm(["  const ok = checkAuth(req);", "  ok &&= serve(req);"])), false,
    'logical assignment writes the verdict, never gates');
  assert.equal(unguardedAuthRun(arm(["  const ok = checkAuth(req);", "  ok ||= serve(req);"])), false,
    'same for ||= — the verdict is stored, not consulted');
  // Same-statement continuations still count as gated.
  assert.equal(unguardedAuthRun(arm(["  const ok = checkAuth(req);", "  ok && serve(req);"])), true,
    'a same-statement continuation still reads the verdict');
});

// ============================================================================
// w73-ledger F-5: the outside-scan capability shapes — aliased/paren/
// bracket receivers and renamed destructure binds all count as HTTP
// dispatch surfaces outside the audited file.
// ============================================================================
const OUTSIDE_SLICE = (() => {
  // The slice runs the whole shipped block — normalization prelude
  // included — so the staged text must arrive through readFileSync.
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
test('w73-ledger F-5: aliased/bracket/paren dispatch surfaces flag outside the audited file', () => {
  for (const [name, text] of [
    ['parenthesized new URL', "const u = new (URL)(req.url);"],
    ['bracket URL.parse', "URL['parse'](req.url);"],
    ['URL alias', "const u = URL; u.parse(req.url);"],
    ['renamed destructure', "const {url: u} = req; u === '/x';"],
    ['destructure into new URL', "const {url} = req; new URL(url);"],
    ['headers member read', "const {headers} = req; headers.authorization;"],
    ['headers.get', "const {headers} = req; headers.get('x');"],
    ['switch of a call result', "switch (f().method) { case 'GET': break; }"],
    ['bracket createServer', "http['createServer'](handler);"],
    ['addEventListener request', "srv.addEventListener('request', handler);"],
  ]) assert.equal(outsideRun(text), true, `${name} flags: ${text}`);
  assert.equal(outsideRun("const x = compute(); console.log(x);"), false,
    'a plain statement is no dispatch surface');
});

// ============================================================================
// w73-ledger F-7: traceability param-vs-decl scoping — function/catch/
// for-of param bindings scope to their own clause body, never the
// enclosing block; a bare `for (assert of x)` poisons the block from the
// `for` onward (an assignment, not a binding).
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
test('w73-ledger F-7: param/catch/for-of bindings scope to their own body, not the enclosing block', () => {
  const [fnParam, catchParam, forConst, forAssign, honest] = traceProbe([
    // `function g(assert)` binds assert inside g's body only — the
    // asserts before and after it call the real node:assert.
    { text: "import assert from 'node:assert';\ntest('X', () => {\n  assert.ok(1);\n  function g(assert){ assert.ok(0); }\n  assert.ok(2);\n});" },
    // `catch (assert)` shadows inside the catch body only.
    { text: "import assert from 'node:assert';\ntest('X', () => {\n  try {} catch (assert) { assert.ok(0); }\n  assert.ok(1);\n});" },
    // `for (const assert of x)` binds for the loop body only.
    { text: "import assert from 'node:assert';\ntest('X', () => {\n  for (const assert of []) { assert.ok(0); }\n  assert.ok(1);\n});" },
    // `for (assert of x)` is an ASSIGNMENT — it poisons the block from
    // the `for` onward (the asserts after it are dead) but leaves the
    // earlier one real.
    { text: "import assert from 'node:assert';\ntest('X', () => {\n  assert.ok(1);\n  for (assert of []) { assert.ok(0); }\n  assert.ok(2);\n});" },
    { text: "import assert from 'node:assert';\ntest('X', () => { assert.ok(1); assert.ok(2); });" },
  ]);
  assert.deepEqual(fnParam, [2], `function-param scope keeps the sibling asserts honest: ${JSON.stringify(fnParam)}`);
  assert.deepEqual(catchParam, [1], `catch-param scope keeps the trailing assert honest: ${JSON.stringify(catchParam)}`);
  assert.deepEqual(forConst, [1], `for-of const binds the loop body only: ${JSON.stringify(forConst)}`);
  assert.deepEqual(forAssign, [1], `a bare for-of assignment poisons onward, not backward: ${JSON.stringify(forAssign)}`);
  assert.deepEqual(honest, [2], `the honest baseline counts: ${JSON.stringify(honest)}`);
});
