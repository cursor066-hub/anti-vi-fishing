// Wave-72 regression tests: seal F-1/F-2/F-6 (base===null raw
// propagation — an eval/infra fault with no sqlite errcode is never a
// refused write, and attacker-text schema claims are probe-verified
// before they may convict), seal F-4/fv F-2 (the INV-409 defeat
// re-latch is keyed on `marker_defeated` details — a bare consult
// verdict mints no flag), seal F-5/runtime F-2 (RELEASE savepoint
// doctrine: retry, then roll the leaked transaction and refuse — never
// leave a zombie tx), seal F-3/runtime F-4 (_seenTotal — a monotone
// distinct-claim ledger the eviction window cannot inflate), seal F-7
// (prior_evicted is asserted on the landed write), runtime F-3
// (committedTip/mint tip faults propagate raw — no seq-0 signed
// marker). Gate probes eval a live slice of the shipped scanner —
// tested code cannot drift from shipped code.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';
import { fixture } from './helpers.mjs';
import { digest } from '../src/canonical.mjs';

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
const putMarker = (h, env, claims = null) => {
  dropResidueGuards(h);
  h.f.store.db.prepare("INSERT INTO meta_kv (tenant,key,value) VALUES ('acme','fold_floor_retired',?) ON CONFLICT(tenant,key) DO UPDATE SET value=excluded.value")
    .run(JSON.stringify({ claims: claims ?? (env ? (typeof env.payload === 'string' ? JSON.parse(env.payload) : env.payload)?.fold_floor_retired ?? [] : []), env }));
};
const findKind = (res, re) => (res.head_watermark_tampered ?? []).filter(e => re.test(e.kind));

// ============================================================================
// w72-seal F-2 + F-6 + runtime F-5: attacker-flavored schema text inside
// the marker consult is probe-VERIFIED before it may convict — a foreign
// RAISE minting 'no such table' with a healthy schema is an engine fault
// (INV-503), and only a probe failing the same way proves divergence
// (INV-409). The consult catch classifies instead of swallowing (F-6).
// ============================================================================
test('w72-seal F-2/F-6: consult schema claims are probe-verified — attacker text never convicts', t => {
  const h = fixture(t);
  h.ready(); h.ready();
  healOnce(h, 'probe-verify');
  h.f.sealAuditChain(h.p('security'));
  // The marker consult reads meta_kv through store._stmt inside
  // _foldFloorMarker — patch that one path (the drain and apply use
  // db.prepare inside their savepoints and are unaffected).
  const orig = h.f.store._stmt.bind(h.f.store);
  h.f.store._stmt = (sql) => {
    if (String(sql).includes("key='fold_floor_retired'") && new Error().stack.includes('sealAuditChain'))
      throw Object.assign(new Error('no such table: meta_kv'), { errcode: 1 });
    return orig(sql);
  };
  healOnce(h, 'probe-verify-2');
  let e = null;
  try { h.f.sealAuditChain(h.p('security')); } catch (err) { e = err; }
  assert.ok(e && e.code !== 'INV-409-INTEGRITY' && (e.code?.startsWith('INV-503') || /no such table/.test(e.message ?? '')),
    `attacker-text 'no such table' over a healthy schema is an engine fault, not divergence: ${e?.code} ${e?.message}`);
  // Arm 2: the catalog probes fail identically — real divergence convicts.
  // The w73 probe is column-bearing `... LIMIT 0` membership over the
  // expected tables (no sqlite_master name-parse — w73-seal F-3), so the
  // patch shapes the probe statements themselves.
  h.f.store._stmt = (sql) => {
    if ((String(sql).includes("key='fold_floor_retired'") || String(sql).includes('LIMIT 0'))
        && new Error().stack.includes('sealAuditChain'))
      throw Object.assign(new Error('no such table: meta_kv'), { errcode: 1 });
    return orig(sql);
  };
  // The w75 probe prepares fresh per table (cached column metadata can
  // outlive the schema change it must see — F6.1) — the fault reaches
  // it on db.prepare, not store._stmt.
  const origPrep = h.f.store.db.prepare.bind(h.f.store.db);
  h.f.store.db.prepare = (sql) => {
    if (String(sql).includes('LIMIT 0') && new Error().stack.includes('sealAuditChain'))
      throw Object.assign(new Error('no such table: meta_kv'), { errcode: 1 });
    return origPrep(sql);
  };
  e = null;
  try { h.f.sealAuditChain(h.p('security')); } catch (err) { e = err; }
  h.f.store._stmt = orig;
  h.f.store.db.prepare = origPrep;
  assert.ok(e && e.code === 'INV-409-INTEGRITY', `a probe-failing schema fault convicts divergence: ${e?.code}`);
  // The consult INV-409 carries no `marker_defeated` details — the apply's
  // keyed re-latch must not mint a defeat flag off a bare verdict
  // (w72-seal F-4 / w72-fv F-2).
  const res = h.f.sealAuditChain(h.p('security'));
  assert.deepEqual(findKind(res, /marker_defeated/), [],
    `no phantom defeat flag rides a bare consult verdict: ${JSON.stringify(res.head_watermark_tampered)}`);
  h.close();
});

// ============================================================================
// w72-seal F-1 + fv F-1 + runtime F-1: an eval/infra fault with NO sqlite
// errcode inside the deferred apply (and its retire sibling) propagates
// raw — folding it into the defeat arm minted marker_defeated off pure
// infra noise. The raw message rides deferred_apply_error; no flag mints.
// ============================================================================
test('w72-seal F-1/fv F-1: an errcode-less apply fault propagates raw — no phantom defeat', t => {
  const h = fixture(t);
  h.ready(); h.ready();
  for (let i = 0; i < 3; i++) healOnce(h, `raw-${i}`);
  divergeChain(h);
  // _chainFacts faults raw INSIDE the apply's envelope mint — no errcode,
  // so the catch's base===null arm must rethrow it untouched.
  const origCf = h.f._chainFacts;
  h.f._chainFacts = (tenant) => {
    const s = new Error().stack;
    if (s.includes('mintRetiredEnvelope') && s.includes('applyDeferredRetiredMints')) throw new Error('catalog eval fault (no errcode)');
    return origCf.call(h.f, tenant);
  };
  const res = h.f.sealAuditChain(h.p('security'));
  delete h.f._chainFacts;
  assert.equal(res.sealed, true, 'the cut path staged the deferred queue');
  assert.ok(typeof res.deferred_apply_error === 'string' && /catalog eval fault/.test(res.deferred_apply_error),
    `the raw eval fault rides deferred_apply_error verbatim: ${res.deferred_apply_error}`);
  const res2 = h.f.sealAuditChain(h.p('security'));
  assert.deepEqual(findKind(res2, /marker_defeated/), [],
    `an infra fault never mints a defeat conviction: ${JSON.stringify(res2.head_watermark_tampered)}`);
  assert.ok(markerRow(h) !== undefined, 'the retained queue replays into a marker once the fault clears');
  h.close();
});

// ============================================================================
// w72-seal F-5 + runtime F-2: RELEASE savepoint doctrine — a transient
// RELEASE fault rolls back to the savepoint and retries; the commit-edge
// latches (deferred queue, murder naming) stay gated on `released`, so a
// faulted release never stages claims the rollback just un-deleted. An
// unresolvable release rolls the LEAKED transaction back and refuses
// INV-503 — never leaves a zombie tx.
// ============================================================================
test('w72-seal F-5/runtime F-2: RELEASE fault retries, then rolls the zombie tx and refuses', t => {
  const h = fixture(t);
  h.ready(); h.ready();
  for (let i = 0; i < 3; i++) healOnce(h, `rel-${i}`);
  divergeChain(h);
  const origExec = h.f.store.db.exec.bind(h.f.store.db);
  // One-shot RELEASE fault on the first post-commit drain: ROLLBACK TO
  // frees its (un-deleted) writes, the retry succeeds and `released`
  // stays false — that drain's deferred latch must skip, leaving the
  // residue standing for the SECOND post-commit drain to re-drain and
  // latch honestly. A phantom queue over rolled-back deletes would mint
  // suppression over rows that still stand.
  let once = true;
  h.f.store.db.exec = (sql) => {
    if (once && sql === 'RELEASE residue_drain') { once = false; throw Object.assign(new Error('disk I/O error'), { errcode: 10 }); }
    return origExec(sql);
  };
  const res1 = h.f.sealAuditChain(h.p('security'));
  h.f.store.db.exec = origExec;
  assert.equal(res1.sealed, true);
  assert.equal(res1.deferred_apply_error, undefined,
    `the surviving drain commits and the deferred apply lands clean: ${res1.deferred_apply_error}`);
  assert.equal(h.f.store.db.isTransaction, false, 'no zombie transaction survives the retried release');
  // The marker that lands must bind the SAME claims — the rolled-back
  // drain neither lost nor double-counted them.
  const mk = markerRow(h);
  assert.ok(mk !== undefined, 'the second drain re-drains and latches the marker');
  const mkClaims = JSON.parse(mk).claims ?? [];
  assert.equal(mkClaims.length, 3, `each consumed claim lands exactly once: ${JSON.stringify(mkClaims)}`);
  // Permanent RELEASE fault: ROLLBACK TO frees the savepoint's writes
  // but the retry faults too — the leaked tx is rolled back and the
  // fault refuses INV-503 instead of leaving a zombie transaction.
  healOnce(h, 'rel-zombie');
  divergeChain(h);
  h.f.store.db.exec = (sql) => {
    if (sql === 'RELEASE residue_drain') throw Object.assign(new Error('disk I/O error'), { errcode: 10 });
    return origExec(sql);
  };
  let e = null;
  try { h.f.sealAuditChain(h.p('security')); } catch (err) { e = err; }
  h.f.store.db.exec = origExec;
  const rode = e ?? {};
  assert.ok(rode.code === 'INV-503-LEDGER' || /INV-503|I\/O|deferred/.test(rode.deferred_apply_error ?? rode.message ?? ''),
    `the unresolvable release refuses: ${rode.code ?? rode.deferred_apply_error ?? rode.message}`);
  assert.equal(h.f.store.db.isTransaction, false, 'no zombie transaction survives the release fault');
  h.close();
});

// ============================================================================
// w72-seal F-3 + runtime F-4: `claims_dropped` counts DISTINCT claims —
// _seenTotal is monotone over _claimsSeen's 8192-entry window, so the
// same claim set re-latched twice cannot inflate the dropped counter.
// ============================================================================
test('w72-seal F-3/runtime F-4: claims_dropped counts distinct claims, not firings', t => {
  const h = fixture(t);
  h.ready(); h.ready();
  for (let i = 0; i < 20; i++) healOnce(h, `c${i}`);
  divergeChain(h);
  // Swallow every write/read-back of the marker row — staged at the
  // statement layer: real swallow triggers are convictable live-DDL
  // before the write ever runs (w76-fv F-1), so the landed probes
  // (note's or apply's, whichever reaches the write first) must read the
  // marker back absent and fault INV-409 with marker_defeated details
  // naming the whole claim set.
  const origPrep = h.f.store.db.prepare.bind(h.f.store.db);
  let armed = true;
  h.f.store.db.prepare = (sql) => {
    const s = String(sql);
    if (armed && s.includes("'fold_floor_retired'")) {
      if (/INSERT INTO meta_kv|UPDATE meta_kv/.test(s)) return { run: () => ({ changes: 1 }), get: () => undefined, all: () => [] };
      if (/SELECT value FROM meta_kv/.test(s)) return { run: () => ({ changes: 0 }), get: () => undefined, all: () => [] };
    }
    return origPrep(s);
  };
  let e1 = null, e2 = null;
  try { h.f.sealAuditChain(h.p('security')); } catch (err) { e1 = err; }
  assert.ok(e1?.code === 'INV-409-INTEGRITY' && e1.details?.marker_defeated !== undefined,
    `the defeated marker write refuses and names the claims: ${e1?.code}`);
  // The rolled-back seal leaves the residue standing — the next seal
  // drives the same claims through the same defeat: a re-latch of the
  // identical set must not double-count.
  try { h.f.sealAuditChain(h.p('security')); } catch (err) { e2 = err; }
  assert.ok(e2?.code === 'INV-409-INTEGRITY', `the second defeat refuses identically: ${e2?.code}`);
  armed = false;
  h.f.store.db.prepare = origPrep;
  const res = h.f.sealAuditChain(h.p('security'));
  const dropped = findKind(res, /floor_marker_retired_marker_defeated/)[0]?.claims_dropped;
  assert.equal(dropped, 4, `20 distinct claims latched twice keep dropped at 20-16=4 — firings never inflate: ${dropped}`);
  h.close();
});

// ============================================================================
// w72-seal F-7 (static-parity fix): the note-write landed probe asserts
// the SIGNED prior_evicted arithmetic, not just the row's presence — a
// trigger-spliced env field is caught by the post-write read.
// ============================================================================
test('w72-seal F-7: the note probe verifies the signed prior_evicted field', () => {
  const src = readFileSync(new URL('../src/fabric.mjs', import.meta.url).pathname, 'utf8');
  assert.ok(/backAuthed\.priorEvicted === prevEvicted \+ \(priorFull - prior\.length\)/.test(src),
    'the landed probe re-derives prior_evicted from the signed envelope');
});

// ============================================================================
// w72-fv F-4 + ledger F-1/F-2: the credential-call doctrine — a bound
// verdict mints only when read in a live gate/continuation; writes,
// optional-chaining, argument position and dead-scope reads never do.
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
test('w72-fv F-4 + ledger F-1/F-2: bound-read liveness and non-gating positions', () => {
  const arm = tail => ["if (req.method === 'GET') {", ...tail, "}"];
  // The awaited bound-read — `await` sits inside the binding, not the
  // gate: `const ok = await checkAuth(req); if (ok) …` resolves the
  // credential (w72-fv F-4).
  assert.equal(unguardedAuthRun(arm(["  const ok = await checkAuth(req);", "  if (!ok) return deny();", "  serve(req);"])), true,
    'an awaited bound verdict read by a gate resolves the credential');
  // Bound-name continuations: `ok && serve()` and `ok ? a() : b()`.
  assert.equal(unguardedAuthRun(arm(["  const ok = checkAuth(req);", "  ok && serve(req);"])), true,
    'a bound verdict short-circuiting a call is used');
  assert.equal(unguardedAuthRun(arm(["  const ok = checkAuth(req);", "  ok ? audit() : deny();"])), true,
    'a bound verdict picking a branch is used');
  // Dead-scope reads never mint: the read inside a never-invoked
  // closure is blank from the credential tail (w72-ledger F-1).
  assert.equal(unguardedAuthRun(arm(["  const ok = checkAuth(req);", "  const g = () => { if (ok) deny(); };", "  serve(req);"])), false,
    'a dead closure reading the binding mints nothing');
  // Writes to the binding are not reads (w72-ledger F-1).
  assert.equal(unguardedAuthRun(arm(["  const ok = checkAuth(req);", "  ok = 1;", "  serve(req);"])), false,
    'overwriting the binding mints nothing');
  assert.equal(unguardedAuthRun(arm(["  const ok = checkAuth(req);", "  ok++;", "  serve(req);"])), false,
    'incrementing the binding mints nothing');
  assert.equal(unguardedAuthRun(arm(["  const ok = checkAuth(req);", "  ok?.user;", "  serve(req);"])), false,
    'an optional-chain read is not a gate');
  // Non-gating call positions resolve nothing (w72-ledger F-2).
  assert.equal(unguardedAuthRun(arm(["  checkAuth(req) && flag;", "  serve(req);"])), false,
    'a short-circuit reaching only a value mints nothing');
  assert.equal(unguardedAuthRun(arm(["  (checkAuth(req));", "  serve(req);"])), false,
    'a parenthesized discard mints nothing');
  assert.equal(unguardedAuthRun(arm(["  checkAuth(req)?.user;", "  serve(req);"])), false,
    'an optional-chained verdict mints nothing');
  assert.equal(unguardedAuthRun(arm(["  checkAuth(req) === true;", "  serve(req);"])), false,
    'a compared-and-discarded verdict mints nothing');
  assert.equal(unguardedAuthRun(arm(["  f(x, checkAuth(req));", "  serve(req);"])), false,
    'an argument position is not a gate');
  // Gating continuations still serve.
  assert.equal(unguardedAuthRun(arm(["  checkAuth(req) && serve(req);"])), true,
    'a short-circuit into a call resolves');
  assert.equal(unguardedAuthRun(arm(["  checkAuth(req) ?? serve(req);"])), true,
    'a nullish-continuation into a call resolves');
  assert.equal(unguardedAuthRun(arm(["  checkAuth(req) ? audit() : deny();"])), true,
    'a ternary condition resolves');
});

// ============================================================================
// w72-ledger F-5: dispOperandCls strips WRAPPING parens to a fixpoint —
// `((typeof m[2]==='string'))` parses like the bare form — but only when
// the outer parens actually wrap the whole operand.
// ============================================================================
test('w72-ledger F-5: nested wrapping parens fold like the bare operand', () => {
  const H = "if (m[1]==='x') {";
  { const r = collectRun([H, "  if (((typeof m[2]==='string')) && m[2]==='x') { authorize(p, ['adm']); }", '}'], 'x');
    assert.deepEqual(r.roles, ['adm'], `x — double-paren typeof folds true: ${JSON.stringify(r)}`); }
  { const r = collectRun([H, "  if (((typeof m[2]==='string')) && m[2]==='x') { authorize(p, ['adm']); }", '}'], 'y');
    assert.deepEqual(r.roles, null, `y — the compare still decides: ${JSON.stringify(r)}`); }
  // A non-wrapping paren group is not a wrap — `(flag) && m[2]==='x'`
  // stays a real runtime gate → conditional mint, never unconditional.
  { const r = collectRun([H, "  if ((flag) && m[2]==='x') { authorize(p, ['adm']); }", '}'], 'x');
    assert.equal(r.any, true, `x — the gated arm is reachable: ${JSON.stringify(r)}`);
    assert.equal(r.roles, null, `x — a live flag conditions the mint: ${JSON.stringify(r)}`); }
});

// ============================================================================
// w72-ledger F-6: `!!m[2]==='x'` binds `!!` to the MEMBER — it folds
// `(!!m[2])==='x'`, an always-false compare, not a negated pair; only
// `!!(m[2]==='x')` unwraps the truthiness wrap.
// ============================================================================
test('w72-ledger F-6: `!!` without parens binds the member, never the compare', () => {
  const H = "if (m[1]==='x') {";
  { const r = collectRun([H, "  if (!!m[2]==='x') { authorize(p, ['adm']); }", '}'], 'x');
    assert.deepEqual(r.roles, null, `x — (!!m[2])==='x' is always false: ${JSON.stringify(r)}`); }
  { const r = collectRun([H, "  if (!!(m[2]==='x')) { authorize(p, ['adm']); }", '}'], 'x');
    assert.deepEqual(r.roles, ['adm'], `x — the parenthesized wrap still decides: ${JSON.stringify(r)}`); }
  // Bare `!!m[2]` truthiness is a live runtime gate — the arm is
  // reachable but conditioned on the member, never an unconditional mint.
  { const r = collectRun([H, "  if (!!m[2]) { authorize(p, ['adm']); }", '}'], 'x');
    assert.equal(r.any, true, `x — the gated arm is reachable: ${JSON.stringify(r)}`);
    assert.equal(r.roles, null, `x — member truthiness conditions the mint: ${JSON.stringify(r)}`); }
});

// ============================================================================
// w72-ledger F-7: a literal rebind of `m` voids the regex-capture typeof
// fold — `typeof m[N]` is 'string' only while `m` is still the exec
// result; `m = {2:7}` makes the fold defer to the literal's real type.
// ============================================================================
test('w72-ledger F-7: litPrim typeof honors a literal rebind of m', () => {
  const out = JSON.parse(probeFile([
    HELPERS,
    `const k = new Map(); k.set('m', {2: 7});`,
    `globalThis.process.stdout.write(JSON.stringify([`,
    `  litPrim("typeof m[2]", null),`,
    `  litPrim("typeof m[2]", k),`,
    `  litPrim("typeof m[2]", new Map())`,
    `].map(v => typeof v === 'symbol' ? String(v) : v)));`
  ].join('\n')));
  assert.equal(out[0], 'string', 'an unrebound m[N] is a regex capture — always string');
  assert.notEqual(out[1], 'string', `a rebound m = {2:7} no longer claims the capture type: ${out[1]}`);
  assert.equal(out[2], 'string', 'an empty known-map still folds the capture type');
});

// ============================================================================
// w72-fv F-6: dead-fn escape arms — a computed bracket call
// `g['call'+'']()` and an alias binding `const h = g; h()` invoke the
// function — neither may blank its body.
// ============================================================================
test('w72-fv F-6: computed-member and alias escapes keep bodies alive', () => {
  { const r = collectRun([HEAD2, "  const g = () => { authorize(p, ['adm']); };", "  g['call'+''](null);", '}'], 'x');
    assert.equal(r.any, true, `a concatenated bracket call invokes the body: ${JSON.stringify(r)}`);
    assert.equal(r.roles, null, `indirect dispatch mints conditional: ${JSON.stringify(r)}`); }
  { const r = collectRun([HEAD2, "  const g = () => { authorize(p, ['adm']); };", "  const h = g;", "  h();", '}'], 'x');
    assert.equal(r.any, true, `an alias call invokes the aliased body: ${JSON.stringify(r)}`); }
  { const r = collectRun([HEAD2, "  const g = () => { authorize(p, ['adm']); };", "  const h = g;", "  const k = h;", "  k();", '}'], 'x');
    assert.equal(r.any, true, `a transitive alias chain keeps the body live: ${JSON.stringify(r)}`); }
  { const r = collectRun([HEAD2, "  const g = () => { authorize(p, ['adm']); };", "  const h = g;", "  serve(h);", '}'], 'x');
    assert.equal(r.any, true, `an alias passed as an argument escapes the body: ${JSON.stringify(r)}`); }
  { const r = collectRun([HEAD2, "  const g = () => { authorize(p, ['adm']); };", "  const h = g;", "  return;", '}'], 'x');
    assert.equal(r.any, false, 'an alias never invoked keeps the body dead'); }
});

// ============================================================================
// w72-fv F-5 + ledger F-8 → w73-ledger F-6: the binary exemption is gone
// — every tracked file answers the secret/marker scans under a tolerant
// utf8 read. The straddle probe now puts a real multibyte char at the
// 8191-byte head edge, not mid-head at 4095.
// ============================================================================
test('w72-fv F-5/ledger F-8/w73-ledger F-6: binary content still answers the marker/secret scans', () => {
  assert.ok(!/isBinary|TEXT_EXT/.test(CHECK_SRC), 'binary-exemption machinery must not return');
  const i = CHECK_SRC.indexOf('const SECRET_RULES');
  const j = CHECK_SRC.indexOf('];', i);
  const mk = CHECK_SRC.indexOf('const MARKER_RULES');
  const mj = CHECK_SRC.indexOf('];', mk);
  assert.ok(i > 0 && j > i && mk > 0 && mj > mk, 'the shipped rule tables are extractable');
  const out = JSON.parse(probeFile(`${CHECK_SRC.slice(i, j + 2)}
${CHECK_SRC.slice(mk, mj + 2)}
// A multibyte char straddling the REAL 8192-byte head edge: 8191 'x'
// bytes then 'é' — its lead byte sits at 8191 and the continuation at
// 8192 (the w72 test placed it at 4095 and never reached the boundary —
// w73-ledger F-6). The content after the straddle still scans.
const edge = Buffer.concat([Buffer.alloc(8191, 120), Buffer.from('é', 'utf8'), Buffer.from(' AKIA' + 'IOSFODNN7EXAMPLE'), Buffer.from([0])]);
const word = Buffer.concat([Buffer.from([7, 8, 9]), Buffer.from(' FIX' + 'ME '), Buffer.from([0, 1])]);
process.stdout.write(JSON.stringify([
  [...SECRET_RULES].filter(([n, r]) => r.test(edge.toString('utf8'))).map(([n]) => n),
  [...MARKER_RULES].filter(([n, r]) => r.test(word.toString('utf8'))).map(([n]) => n),
]));`));
  assert.deepEqual(out, [['cloud credential pattern'], ['unfinished code marker']],
    `a secret behind a real UTF-8 straddle and a marker inside binary bytes both convict: ${JSON.stringify(out)}`);
});

// ============================================================================
// w72-ledger F-3/F-4: TDZ decl scope and arrow-param heads — a
// const/let/class declared LATER in the block still shadows the asserts
// above it (the scope starts at the enclosing brace, not the decl), a
// bodyless arrow `(assert) => assert.ok(1)` scopes to the expression,
// and a param list after `return` binds when `=>` follows.
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
test('w72-ledger F-3/F-4: TDZ scope starts at the brace; arrow param-heads after return still bind', () => {
  const [tdzConst, tdzInner, bodyless, retArrow, honest, honestIf] = traceProbe([
    // `const assert` declared BELOW the use still shadows it — the
    // binding is in TDZ over the whole enclosing block.
    { text: "import assert from 'node:assert';\ntest('X', () => {\n  assert.ok(1);\n  const assert = () => {};\n});" },
    // Same doctrine one block out: the inner-block use sits inside the
    // decl's TDZ span too.
    { text: "import assert from 'node:assert';\ntest('X', () => {\n  { assert.ok(1); }\n  const assert = () => {};\n});" },
    // A bodyless arrow's param binds through the expression body.
    { text: "import assert from 'node:assert';\ntest('X', () => {\n  ((assert) => assert.ok(1))(() => {});\n});" },
    // `(assert)` after `return` + `=>` follower — a real param head, not
    // a control keyword's operand.
    { text: "import assert from 'node:assert';\nfunction f() {\n  return (assert) => {\n    test('X', () => { assert.ok(1); });\n  };\n}" },
    { text: "import assert from 'node:assert';\ntest('X', () => { assert.ok(1); });" },
    // `if (assert) {` — a control head, not a param bind — the body
    // asserts stay honest.
    { text: "import assert from 'node:assert';\nfunction f(assert) {\n  if (assert) { test('X', () => { assert.ok(1); }); }\n}" },
  ]);
  assert.deepEqual(tdzConst, [0], `a later const shadows asserts above it (TDZ): ${JSON.stringify(tdzConst)}`);
  assert.deepEqual(tdzInner, [0], `an inner-block use inside the TDZ span shadows: ${JSON.stringify(tdzInner)}`);
  assert.deepEqual(bodyless, [0], `a bodyless arrow's param shadows its expression body: ${JSON.stringify(bodyless)}`);
  assert.deepEqual(retArrow, [0], `an arrow param-head after return binds: ${JSON.stringify(retArrow)}`);
  assert.ok(honest[0] >= 1, `the honest baseline still counts: ${JSON.stringify(honest)}`);
  // `function f(assert)` param shadows honestly — the assert.ok inside
  // is bound to the param either way; what matters is the control head
  // was not mistaken for a bind site (it would shadow nothing extra).
  assert.deepEqual(honestIf, [0], `the function param itself shadows — the control head adds nothing: ${JSON.stringify(honestIf)}`);
});
