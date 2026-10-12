// Wave-69 regression tests: ledger F-1..F-7 (alias `!==` opNeg, dead-fn
// votes, arithmetic dead conjuncts + literal folds, comma-discard
// operand, blank-line Allman peek, regex/predicate route boundaries,
// labeled break) + seal F-1/F-2/F-5 (delivery-bound retires, murdered-
// marker claims, re-latch) + runtime F-1/F-2 (compare-and-clear retire,
// deferred-apply fault split + queue retention). Gate probes eval a live
// slice of the shipped scanner — tested code cannot drift from shipped
// code.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';
import { fixture, hasCode } from './helpers.mjs';
import { digest } from '../src/canonical.mjs';
import { RESIDUE_KEEP_TRIGGERS } from '../src/store.mjs';

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
const HEAD = "if (req.method === 'GET' && (m = /^\\/x\\/(.*)/.exec(path))) {";
const HEAD2 = "if ((m = /^\\/x\\/(.*)\\/(.*)/.exec(path))) {";

const residueRows = h => h.f.store.db.prepare("SELECT key,value FROM meta_kv WHERE tenant='acme' AND (key='fold_floor_healed' OR substr(key,1,18)='fold_floor_healed.')").all();
const committedTip = h => h.f.store.db.prepare("SELECT MAX(seq) m FROM audit WHERE tenant='acme'").get().m;
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
const putMarker = (h, env, claims = null) => {
  dropResidueGuards(h);
  h.f.store.db.prepare("INSERT INTO meta_kv (tenant,key,value) VALUES ('acme','fold_floor_retired',?) ON CONFLICT(tenant,key) DO UPDATE SET value=excluded.value")
    .run(JSON.stringify({ claims: claims ?? (env ? (typeof env.payload === 'string' ? JSON.parse(env.payload) : env.payload)?.fold_floor_retired ?? [] : []), env }));
  restoreResidueGuards(h);
};
const tipHashAt = (h, seq) => {
  const r = h.f.store.db.prepare("SELECT envelope FROM audit WHERE tenant='acme' AND seq=?").get(seq);
  return r === undefined ? null : digest(JSON.parse(r.envelope).payload);
};
const tamperKinds = res => (res.head_watermark_tampered ?? []).map(e => e.kind);

// ============================================================================
// w69-ledger F-1: the alias `q[N]` site must carry opNeg like the direct
// `m[N]` site — a lone `!==` is an id-filter, not member proof, and the
// excluded literal can never serve its own negated arm.
// ============================================================================
test('w69-ledger F-1: an alias `!==` is member-dead like the direct site', () => {
  const row = [HEAD2, "  const q = m;", "  if (m[2]==='y') { serve(); }", "  if (q[2]!=='z') { authorize(p, ['adm']); }", '}'];
  { const r = collectRun(row, 'x'); assert.equal(r.any, true); assert.equal(r.roles, null, `lone vote is an id-filter — conditional for the unbound: ${JSON.stringify(r)}`); }
  { const r = collectRun(row, 'z'); assert.equal(r.any, false, `the excluded literal can never serve its own \`!==\`: ${JSON.stringify(r)}`); }
  { const r = collectRun(row, 'y'); assert.deepEqual(r.roles, ['adm'], `the bound verb's own binding proves the member: ${JSON.stringify(r)}`); }
  const row2 = [HEAD2, "  const q = m;", "  if (m[2]==='y') { serve(); }", "  if (m[2]==='w') { serveW(); }", "  if (q[2]!=='z') { authorize(p, ['adm']); }", '}'];
  { const r = collectRun(row2, 'x'); assert.deepEqual(r.roles, ['adm'], 'two positive votes prove the member — the alias fold returns'); }
});

// ============================================================================
// w69-ledger F-2: a member compare inside a never-invoked function body
// casts no discriminator vote — the seed loop must skip dead-fn lines.
// ============================================================================
test('w69-ledger F-2: a vote inside a dead function body does not count', () => {
  const dead = [HEAD2, "  if (m[2]==='y') { serve(); }", "  const h = () => { if (m[2]==='w') { serveW(); } };", "  if (m[2]!=='z') { authorize(p, ['adm']); }", '}'];
  { const r = collectRun(dead, 'x'); assert.equal(r.roles, null, `the dead arrow's 'w' is no vote: ${JSON.stringify(r)}`); }
  const live = [HEAD2, "  if (m[2]==='y') { serve(); }", "  const h = () => { if (m[2]==='w') { serveW(); } };", "  h();", "  if (m[2]!=='z') { authorize(p, ['adm']); }", '}'];
  { const r = collectRun(live, 'x'); assert.deepEqual(r.roles, ['adm'], `invoked — the vote counts: ${JSON.stringify(r)}`); }
  const deadFn = [HEAD2, "  if (m[2]==='y') { serve(); }", "  function g() { if (m[2]==='w') { serveW(); } }", "  if (m[2]!=='z') { authorize(p, ['adm']); }", '}'];
  { const r = collectRun(deadFn, 'x'); assert.equal(r.roles, null, `a never-invoked fn decl votes nothing: ${JSON.stringify(r)}`); }
});

// ============================================================================
// w69-ledger F-3: an arithmetic/string conjunct that folds provably-false
// kills the arm AND its member vote — and the literal folds themselves
// must evaluate (shifts, additive, multiplicative, bitwise, concat,
// unary, .length, exponents).
// ============================================================================
test('w69-ledger F-3: arithmetic dead conjuncts kill the arm and its vote', () => {
  for (const conj of ['1 - 2 === 2', '2 * 3 === 7', '4 % 3 === 0', '1 << 3 === 16', '5 >>> 1 === 3', '0 / 0 === 0', "'a' + 'b' === 'ac'", '~1 === 0', "'ab'.length === 3"]) {
    const r = collectRun([HEAD2, "  if (m[2]==='y') { serve(); }", `  if (m[2]==='w' && ${conj}) { serveW(); }`, "  if (m[2]!=='z') { authorize(p, ['adm']); }", '}'], 'x');
    assert.equal(r.roles, null, `dead conjunct '${conj}' — 'w' casts no vote: ${JSON.stringify(r)}`);
  }
  for (const conj of ['1 - 2 === -1', '2 * 3 === 6', '1 << 3 === 8', "'a' + 'b' === 'ab'", '1e-5 < 0.1', '5 >>> 1 === 2', '(2 | 4) === 6', '~1 === -2', "'ab'.length === 2"]) {
    const r = collectRun([HEAD2, "  if (m[2]==='y') { serve(); }", `  if (m[2]==='w' && ${conj}) { serveW(); }`, "  if (m[2]!=='z') { authorize(p, ['adm']); }", '}'], 'x');
    assert.deepEqual(r.roles, ['adm'], `live conjunct '${conj}' — 'w' votes, the fold returns: ${JSON.stringify(r)}`);
  }
});

// ============================================================================
// w69-ledger F-4: a comma operand discards every operand but the last —
// a leading compare never decides the arm and never votes; a trailing
// compare decides and serves.
// ============================================================================
test('w69-ledger F-4: comma operands discard all but the last', () => {
  { const r = collectRun([HEAD2, "  if ((a = 1, m[2]==='x')) { authorize(p, ['adm']); }", '}'], 'x');
    assert.deepEqual(r.roles, ['adm'], `the last comma operand decides the arm: ${JSON.stringify(r)}`); }
  const r = collectRun([HEAD2, "  if ((m[2]==='y', flag)) { serve(); }", "  if (m[2]==='w') { serveW(); }", "  if (m[2]!=='z') { authorize(p, ['adm']); }", '}'], 'x');
  assert.equal(r.roles, null, `a discarded pair casts no member vote: ${JSON.stringify(r)}`);
});

// ============================================================================
// w69-ledger F-5: the Allman peek must not stop at blank lines — a `{`
// after empty lines still gates the block's votes.
// ============================================================================
test('w69-ledger F-5: blank lines between `if` and `{` still gate the block', () => {
  const r = collectRun([HEAD2, "  if (flag)", "", "", "  {", "    if (m[2]==='y') { serve(); }", "    if (m[2]==='w') { serveW(); }", "  }", "  if (m[2]!=='z') { authorize(p, ['adm']); }", '}'], 'x');
  assert.equal(r.roles, null, `votes under a runtime flag gate stay conditional: ${JSON.stringify(r)}`);
});

// ============================================================================
// w69-ledger F-6: route-row boundaries — a path-ish `.exec`/`.test`/
// `.match`/`.startsWith` bind or a negated field literal opens the next
// route row just like a literal-compare or `^`-anchored head.
// ============================================================================
test('w69-ledger F-6: regex/predicate/negated heads still bound the row', () => {
  for (const head of [
    "if ((m = /y\\/(.*)/.exec(path))) {",
    "if (/y/.test(path)) {",
    "if (path !== '/y') {",
    "if (path.startsWith('/y')) {",
  ]) {
    const r = collectRun([
      "if (req.method === 'GET' && (m = /^\\/x\\/(.*)/.exec(path))) {",
      "  if (m[1]==='a') { serveA(); }",
      "  if (m[1]!=='z') { authorize(p, ['adm']); }",
      "}",
      head,
      "  if (m[1]==='b') { serveB(); }",
      "}"], 'x');
    assert.equal(r.roles, null, `${head} — the next row's 'b' never votes on row x: ${JSON.stringify(r)}`);
  }
});

// ============================================================================
// w69-ledger F-7: a labeled `break`/`continue` exits its named target —
// it marks every frame it unwinds like return/throw (the old bound=null
// path marked nothing and left the in-loop tail unconditional).
// w70-ledger F-1 refined the doctrine further: the exit kills only its
// named statement's interior — for the verb whose own arm proves the
// break fires, content past it inside the labeled loop is DEAD
// (any:false), not merely conditional. For verbs whose arm never fires,
// the interior mints conditional (the loop still carries a reachable
// exit for some verb — loop-exit doctrine, w63-fv F-1).
// ============================================================================
test('w69-ledger F-7: a labeled break gates the frames it exits', () => {
  const row = [HEAD2, "  lbl: for (;;) {", "    if (m[2]==='y') { break lbl; }", "    authorize(p, ['adm']);", "  }", '}'];
  { const r = collectRun(row, 'y'); assert.equal(r.any, false, `'y' provably exits the labeled loop — the in-loop tail is dead for it: ${JSON.stringify(r)}`); }
  { const r = collectRun(row, 'x'); assert.equal(r.any, true); assert.equal(r.roles, null, `'x' never enters the break arm — the tail is gated, not dead (conservative mark, like return/break doctrine): ${JSON.stringify(r)}`); }
});

// ============================================================================
// w69-seal F-1: a post-commit throw must not evaporate a marker
// conviction — the six floor_marker_* kinds retire at DELIVERY only.
// Before the fix the in-tx retire cleared the flag while the discarded
// report held the only naming copy: evidence row deleted, conviction
// gone. After it, the flag survives the fault and re-reports.
// ============================================================================
test('w69-seal F-1: a post-commit fault cannot evaporate a marker conviction', t => {
  const h = fixture(t);
  h.ready(); h.ready();
  // A divergent fold_floor — the in-tx consult latches floor_marker_ahead.
  h.f.store.db.prepare("INSERT INTO meta_kv (tenant,key,value) VALUES ('acme','fold_floor','99999:deadbeef') ON CONFLICT(tenant,key) DO UPDATE SET value=excluded.value").run();
  // Removing the heads file forces headMinted — the marker delete arm
  // (wmPlan || headMinted) runs.
  rmSync(join(h.f.directory, 'chain-heads.json'), { force: true });
  // Post-commit fault: the wedge-clear mint is a throwing step between
  // the commit and the report delivery.
  h.f._clockUnverifiable = () => true;
  h.f._wedgeIntegrity = () => ({ ok: true });
  const origAudit = h.f.store.audit.bind(h.f.store);
  let tripped = false;
  h.f.store.audit = (...a) => { if (!tripped && a[1] === 'AUDIT_WEDGE_CLEARED') { tripped = true; throw new Error('forced post-commit fault'); } return origAudit(...a); };
  assert.throws(() => h.f.sealAuditChain(h.p('security')), /forced post-commit fault/);
  delete h.f._clockUnverifiable;
  delete h.f._wedgeIntegrity;
  h.f.store.audit = origAudit;
  const seal2 = h.f.sealAuditChain(h.p('security'));
  const kinds = tamperKinds(seal2);
  assert.ok(kinds.includes('floor_marker_ahead'), `the conviction survived the fault and re-reports: ${JSON.stringify(kinds)}`);
  h.close();
});

// ============================================================================
// w69-seal F-2 + w69-runtime F-5: a foreign trigger eating the
// fold_floor_retired delete aborts the seal — the in-tx flag rolls back
// with it, so the catch re-latches the conviction AND names the murdered
// marker's own claims (no bare seq:0 slot).
// ============================================================================
test('w69-seal F-2/F-5: a defeated murder-delete names the murdered claims durably', t => {
  const h = fixture(t);
  h.ready(); h.ready();
  const tip = committedTip(h);
  const claims = ['77:claim-a', '88:claim-b'];
  // A verify-signed marker whose pin is dead (tip_hash mismatches the
  // live row) — murder-eligible.
  const env = h.f.store.auditSigners['acme'].sign(
    { tenant_id: 'acme', fold_floor_retired: claims, marker_seq: tip, marker_tip_hash: 'ff'.repeat(32) }, 'audit');
  putMarker(h, env);
  // A foreign trigger eats the delete. w76-fv F-1: a real planted trigger
  // convicts 'live DDL' at the next guarded call before any delete reaches
  // it, so the eat is staged at the statement layer — the murder's delete
  // reports 0 changes, exactly the RAISE(IGNORE) effect.
  const origStmt = h.f.store._stmt.bind(h.f.store);
  h.f.store._stmt = (sql) => {
    if (String(sql).includes("key='fold_floor_retired'") && String(sql).startsWith('DELETE'))
      return { run: () => ({ changes: 0 }), get: () => undefined, all: () => [] };
    return origStmt(sql);
  };
  let e1 = null;
  try { h.f.sealAuditChain(h.p('security')); } catch (e) { e1 = e; }
  assert.ok(e1 !== null && e1.code === 'INV-409-INTEGRITY', `the defeated murder refuses INV-409: ${e1?.code}`);
  assert.ok(e1.details?.marker_defeated === 'fold_floor_retired', `the refusal names the defeated marker: ${JSON.stringify(e1.details)}`);
  for (const c of claims) assert.ok(e1.details?.claims?.includes(c), `thrown detail names ${c}: ${JSON.stringify(e1.details?.claims)}`);
  // The flag survived the rollback — the next refusal attests it live.
  let e2 = null;
  try { h.f.sealAuditChain(h.p('security')); } catch (e) { e2 = e; }
  assert.ok(e2 !== null && e2.code === 'INV-409-INTEGRITY', `the second refusal is INV-409 too: ${e2?.code}`);
  const md = (e2.details?.head_watermark_tampered ?? []).find(x => x.kind === 'floor_marker_retired_marker_defeated');
  assert.ok(md, `the re-latched conviction attests on the next refusal: ${JSON.stringify(e2.details?.head_watermark_tampered)}`);
  for (const c of claims) assert.ok(md.claims?.includes(c), `the flag names ${c}: ${JSON.stringify(md)}`);
  // Lift the foreign eat — the murder lands and the flag delivers
  // once through the normal report surface.
  h.f.store._stmt = origStmt;
  const seal3 = h.f.sealAuditChain(h.p('security'));
  const md3 = (seal3.head_watermark_tampered ?? []).find(x => x.kind === 'floor_marker_retired_marker_defeated');
  assert.ok(md3, `the delivered report carries the conviction: ${JSON.stringify(tamperKinds(seal3))}`);
  for (const c of claims) assert.ok(md3.claims?.includes(c), `delivered report names ${c}: ${JSON.stringify(md3)}`);
  h.close();
});

// ============================================================================
// w69-runtime F-2 + w69-seal F-3: a non-integrity fault in the deferred
// apply is AVAILABILITY, not a conviction — the queue is retained and
// the next seal replays the same claims. No bare marker_defeated may
// latch for a transient fault.
// Doctrine updated w70-seal F-2: the apply runs in the seal's finally —
// a throw there REPLACED the committed seal's result and reported the
// sealed chain as denied. The fault now rides the delivered shape as
// `deferred_apply_error` (same convention as `vault_persist_error`).
// ============================================================================
test('w69-runtime F-2: a busy deferred apply retries with its claims intact', t => {
  const h = fixture(t);
  h.ready(); h.ready();
  healOnce(h, 'divergent-1');
  const residue = residueRows(h).map(r => r.value);
  assert.ok(residue.length > 0, 'a residue claim stands for the deferred drain');
  // Fault only the deferred apply: its SAVEPOINT is the first post-commit
  // statement (the in-tx drain consults fold_floor_retired via db.prepare
  // too, so patching prepare would abort the drain instead).
  const origExec = h.f.store.db.exec.bind(h.f.store.db);
  let armed = true;
  h.f.store.db.exec = (sql) => {
    if (armed && String(sql).includes('SAVEPOINT deferred_mint')) throw Object.assign(new Error('database is locked'), { errcode: 5 });
    return origExec(sql);
  };
  const res1 = h.f.sealAuditChain(h.p('security'));
  armed = false;
  h.f.store.db.exec = origExec;
  assert.ok(res1 !== null && typeof res1 === 'object', 'the committed seal still returns its result — the apply fault cannot claim the ledger denied it');
  assert.ok(typeof res1.deferred_apply_error === 'string' && res1.deferred_apply_error.length > 0,
    `the transient apply fault rides the committed result, availability-class: ${JSON.stringify(res1).slice(0, 400)}`);
  const seal2 = h.f.sealAuditChain(h.p('security'));
  const row = h.f.store.db.prepare("SELECT value FROM meta_kv WHERE tenant='acme' AND key='fold_floor_retired'").get()?.value;
  assert.ok(row !== undefined, 'the retained queue replays on the next seal');
  const landed = JSON.parse(row);
  for (const c of residue) assert.ok(landed.claims.includes(c), `the queued claim ${c} landed: ${String(row).slice(0, 300)}`);
  assert.ok(!tamperKinds(seal2).includes('floor_marker_retired_marker_defeated'), `no conviction minted for a transient fault: ${JSON.stringify(tamperKinds(seal2))}`);
  h.close();
});

// ============================================================================
// w69-runtime F-1: a same-kind re-latch between collect and delivery is
// a NEW conviction — compare-and-clear keeps the mutated flag live so
// the next report names it (the kind-level retire used to erase it).
// ============================================================================
test('w69-runtime F-1: a post-commit re-latch survives the retire pass', t => {
  const h = fixture(t);
  h.ready(); h.ready();
  const db = h.f.store.db;
  const dropMeta = () => { for (const tr of db.prepare("SELECT name FROM sqlite_master WHERE type='trigger' AND tbl_name='meta_kv'").all()) db.exec(`DROP TRIGGER "${String(tr.name).replace(/"/g, '""')}"`); };
  const dropAudit = () => { for (const tr of db.prepare("SELECT name FROM sqlite_master WHERE type='trigger' AND tbl_name='audit'").all()) db.exec(`DROP TRIGGER "${String(tr.name).replace(/"/g, '""')}"`); };
  const plant = (k, v) => { dropMeta(); db.prepare("INSERT INTO meta_kv (tenant,key,value) VALUES ('acme',?,?)").run(k, v); restoreMeta(); };
  const metaSnap = db.prepare("SELECT name,sql FROM sqlite_master WHERE type='trigger' AND tbl_name='meta_kv'").all();
  const restoreMeta = () => { for (const tr of metaSnap) { try { db.exec(tr.sql); } catch (e) { if (!/already exists/.test(String(e?.message ?? e))) throw e; } } };
  plant('fold_floor_healed.90001', '777001:deadbeef01');
  h.f._auditIndex('acme');                       // latches healed_unanchored {heals:[R1]}
  dropAudit();
  db.prepare("UPDATE audit SET envelope='{\"grafted\":true}' WHERE tenant='acme' AND seq=1").run(); // force the cut path
  // Plant R2 + re-latch inside the post-commit window — the sanctioned
  // _wedgeIntegrity seam the w69-runtime PoC used (isTransaction is
  // false on the post-commit sweep, true on the in-tx consult).
  const orig = h.f._wedgeIntegrity.bind(h.f);
  let planted = false;
  h.f._wedgeIntegrity = (t2, idx) => {
    if (!planted && t2 === 'acme' && !h.f.store.db.isTransaction) {
      planted = true;
      plant('fold_floor_healed.90002', '777002:deadbeef02');
      try { h.f._auditIndex('acme'); } catch { /* consult re-latch */ }
    }
    return orig(t2, idx);
  };
  const res1 = h.f.sealAuditChain(h.p('security'));
  h.f._wedgeIntegrity = orig;
  const named1 = (res1?.head_watermark_tampered ?? []).filter(e => e?.kind === 'floor_marker_healed_unanchored').map(e => e?.healed_marker);
  // The delivery-time collect names every live conviction — the
  // post-commit relatch lands in the SAME report, so the retire it
  // then runs has erased nothing unnamed (w69-runtime F-1).
  assert.ok(named1.includes('777001:deadbeef01'), `R1 named: ${JSON.stringify(named1)}`);
  assert.ok(planted, 'the post-commit seam fired on this path');
  assert.ok(named1.includes('777002:deadbeef02'), `the post-commit relatch is delivered in the same report, not erased: ${JSON.stringify(named1)}`);
  const res2 = h.f.sealAuditChain(h.p('security'));
  const named2 = (res2?.head_watermark_tampered ?? []).filter(e => e?.kind === 'floor_marker_healed_unanchored').map(e => e?.healed_marker);
  assert.deepEqual(named2, [], `the delivered convictions retire — nothing stale re-reports: ${JSON.stringify(named2)}`);
  h.close();
});

// ============================================================================
// w69-fv F-1 + w69-runtime F-3: the 8192-seq recency window is dead unless
// the WRITE side honors it — a stale env's retired claims must not be
// unioned into the fresh marker, or a planted claim re-pins forever and
// second-generation residue drains silently. Needs a committed tip at
// least 8193 rows past the marker's pin: real appends, no substitutes.
// ============================================================================
test('w69-fv F-1: a stale marker cannot launder its retired claims into a fresh mint', t => {
  const h = fixture(t);
  h.ready(); h.ready();
  healOnce(h, 'fresh-heal');
  const claim = residueRows(h)[0]?.value;
  assert.ok(claim, 'a residue claim stands');
  // A correctly-signed env pinned at the CURRENT tip — fresh right now.
  const pin = committedTip(h);
  const stale = h.f.store.auditSigners['acme'].sign(
    { tenant_id: 'acme', fold_floor_retired: ['1:stale-claim', claim], marker_seq: pin, marker_tip_hash: tipHashAt(h, pin) }, 'audit');
  putMarker(h, stale);
  // Advance the table 8200 rows — the env's pin falls out of the window.
  h.f.store.tx(() => { for (let i = 0; i < 8200; i++) h.f.store.audit('acme', 'PROBE', 'actor', null, {}, h.f.clock()); });
  assert.ok(committedTip(h) - pin > 8192, 'the pin is provably out of window');
  h.f.sealAuditChain(h.p('security'));
  const row = h.f.store.db.prepare("SELECT value FROM meta_kv WHERE tenant='acme' AND key='fold_floor_retired'").get()?.value;
  assert.ok(row !== undefined, 'the drain minted a marker');
  const landed = JSON.parse(row);
  const signed = typeof landed.env?.payload === 'string' ? JSON.parse(landed.env.payload) : landed.env?.payload;
  const minted = [...(landed.claims ?? []), ...(signed?.fold_floor_retired ?? [])];
  assert.ok(minted.includes(claim), `the real drained claim is minted: ${String(row).slice(0, 200)}`);
  assert.ok(!minted.includes('1:stale-claim'), `the stale env's foreign claim can never re-pin: ${String(row).slice(0, 300)}`);
  h.close();
});

// ============================================================================
// w69-fv F-4 (store twin): the fold_floor UPSERT consult read the `hash`
// column — attacker clay in principle. The consult now recomputes
// digest(payload) from the envelope bytes; a planted marker surviving the
// guard is healed to the recomputed pair, and the plant is named residue.
// ============================================================================
test('w69-fv F-4: the fold_floor survivor is healed to the recomputed truth', t => {
  const h = fixture(t);
  h.ready();
  const next = committedTip(h) + 1;
  const fakeHash = 'ab'.repeat(32);
  dropResidueGuards(h);
  // A planted marker claiming the seq the NEXT append lands — it survives
  // the guarded UPSERT (stored seq >= excluded), reaching the survivor
  // consult, which must bind the envelope recomputation, not the planted
  // pair. (The full clay-column launder is unreachable: `no_audit_update`
  // guards the column and the survivor geometry always names our own
  // just-written row — the fix is parity with floorPriorForeign.)
  h.f.store.db.prepare("INSERT INTO meta_kv (tenant,key,value) VALUES ('acme','fold_floor',?) ON CONFLICT(tenant,key) DO UPDATE SET value=excluded.value").run(`${next}:${fakeHash}`);
  restoreResidueGuards(h);
  h.f.store.audit('acme', 'PROBE', 'actor', null, {}, h.f.clock());
  const marker = h.f.store.db.prepare("SELECT value FROM meta_kv WHERE tenant='acme' AND key='fold_floor'").get()?.value;
  const landed = h.f.store.db.prepare("SELECT envelope FROM audit WHERE tenant='acme' AND seq=?").get(next);
  assert.equal(marker, `${next}:${digest(JSON.parse(landed.envelope).payload)}`,
    `the survivor is healed to the recomputed truth, never the planted pair: ${marker}`);
  const residue = residueRows(h).map(r => r.value);
  assert.ok(residue.some(v => String(v).includes(fakeHash)), `the planted content is named as residue: ${JSON.stringify(residue)}`);
  h.close();
});

// ============================================================================
// w69-runtime F-4: `floor_marker_retired_overcovered` carries the
// claim-list shape end-to-end — the over-cover fires inside
// #wmTamperRetire at delivery (cap-overflow union), and the flag must
// name the extras it consumed, not an anonymous slot. The ClaimList
// merge itself is a static parity fix: a second over-cover on the same
// standing flag cannot arise between consult and delivery (the extras
// are recomputed from the same rows microseconds apart), so merge-vs-
// replace has no observable distinction here — the merge mechanics are
// exercised on the sibling paths by the F-2/F-5/F-6 tests above.
// ============================================================================
test('w69-runtime F-4: the over-cover names every extra it consumed', t => {
  const h = fixture(t);
  h.ready(); h.ready();
  for (let i = 0; i < 260; i++) healOnce(h, `over-${i}`);
  // A standing residue row no flag ever names — guaranteed extra.
  dropResidueGuards(h);
  h.f.store.db.prepare("INSERT INTO meta_kv (tenant,key,value) VALUES ('acme','fold_floor_healed.999999','8:extra-a')").run();
  restoreResidueGuards(h);
  const res = h.f.sealAuditChain(h.p('security'));
  const e = (res.head_watermark_tampered ?? []).find(x => x?.kind === 'floor_marker_retired_overcovered');
  assert.ok(e, `the over-cover is flagged: ${JSON.stringify(tamperKinds(res))}`);
  assert.ok(Array.isArray(e.claims) && e.claims.includes('8:extra-a'),
    `the flag names the extra it consumed: ${JSON.stringify(e.claims?.slice(0, 5))}`);
  h.close();
});

// ============================================================================
// w69-runtime F-7: fresh-side pre-cap drops count in prior_evicted — the
// 2048-claim split budget silently swallowed every claim past slot 2048
// before this fix. 2051 standing residue claims must sign evicted=3.
// ============================================================================
test('w69-runtime F-7: pre-cap fresh drops are counted in prior_evicted', t => {
  const h = fixture(t);
  h.ready(); h.ready();
  // 257 real heals set heals_dropped>0, which unions EVERY standing
  // residue row into the consumed set — the remaining fresh claims are
  // planted rows the over-cover honestly consumes into the mint.
  for (let i = 0; i < 257; i++) healOnce(h, `cap-${i}`);
  dropResidueGuards(h);
  const ins = h.f.store.db.prepare("INSERT INTO meta_kv (tenant,key,value) VALUES ('acme',?,?)");
  for (let i = 0; i < 1794; i++) ins.run(`fold_floor_healed.${100000 + i}`, `9:cap-extra-${i}`);
  restoreResidueGuards(h);
  // fresh counts only claims the STANDING marker does not already carry
  // — the retiring note claims all of them, so pre-cap drops arise only
  // when the marker is rewritten between the drain's commit and the
  // deferred apply (the exact race the queue exists for). Interpose at
  // the commit edge: delete the marker so the apply sees all 2051.
  const origHook = h.f.store.onTxCommit;
  h.f.store.onTxCommit = () => {
    origHook?.();
    // w76-fv F-1: graft inside the hook — drop, delete, restore so the
    // next guarded call still meets the canonical trigger set.
    dropResidueGuards(h);
    h.f.store.db.prepare("DELETE FROM meta_kv WHERE tenant='acme' AND key='fold_floor_retired'").run();
    restoreResidueGuards(h);
  };
  try { h.f.sealAuditChain(h.p('security')); }
  finally { h.f.store.onTxCommit = origHook; }
  const row = h.f.store.db.prepare("SELECT value FROM meta_kv WHERE tenant='acme' AND key='fold_floor_retired'").get()?.value;
  assert.ok(row !== undefined, 'the drain minted a marker');
  const landed = JSON.parse(row);
  const signed = typeof landed.env?.payload === 'string' ? JSON.parse(landed.env.payload) : landed.env?.payload;
  assert.ok((signed?.prior_evicted ?? 0) >= 3, `the pre-cap drops are signed, not swallowed: prior_evicted=${signed?.prior_evicted}`);
  h.close();
});

// ============================================================================
// w69-runtime F-6: a same-kind re-fire must never regress the standing
// flag — seq and claims_dropped move forward only. Two unanchored heals at
// descending seqs: the delivered flag keeps the higher position.
// ============================================================================
test('w69-runtime F-6: a same-kind re-fire cannot regress seq', t => {
  const h = fixture(t);
  h.ready(); h.ready();
  const db = h.f.store.db;
  const plant = (k, v) => { dropResidueGuards(h); db.prepare("INSERT INTO meta_kv (tenant,key,value) VALUES ('acme',?,?)").run(k, v); restoreResidueGuards(h); };
  plant('fold_floor_healed.91001', '777001:healed-a');
  h.f._auditIndex('acme');            // flag latches at seq 777001
  plant('fold_floor_healed.91002', '666000:healed-b');  // LOWER seq — must not regress the flag
  h.f._auditIndex('acme');
  const res = h.f.sealAuditChain(h.p('security'));
  const e = (res.head_watermark_tampered ?? []).find(x => x?.kind === 'floor_marker_healed_unanchored');
  assert.ok(e, `the unanchored conviction delivers: ${JSON.stringify(tamperKinds(res))}`);
  assert.equal(e.seq, 777001, `the flag kept the higher position: ${JSON.stringify(e)}`);
  h.close();
});
