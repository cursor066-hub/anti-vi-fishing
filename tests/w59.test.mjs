// w59 self-audit regressions — hostile-audit wave findings:
//  runtime F-1 — the gate-deny tally bump scanned only the newest 25
//        containment rows: an honest deny burst (or a few planted rows)
//        crowded the survivor out of the window and the suppressed
//        denial's count was silently lost. The scan is now unbounded,
//        newest-first.
//  runtime F-2 — a murdered anchored evidence row was labeled 'deleted'
//        identically to a retention-shredded one. The tombstone row
//        distinguishes the two: no tombstone under a live anchor is
//        'missing_under_anchor', never 'deleted'.
//  runtime F-3 — the residue cursor's shape probe and LIKE scan shared
//        no snapshot on an outside-tx consult; a peer commit between the
//        two reads could pin a torn (count,seq) pair. The shape is
//        re-probed after the scan; a divergence restarts bounded.
//  seal F-1 — retire rebuilt delete keys from claim seqs, so a planted
//        residue row at a non-claim key outlived its claim; and the
//        residue consult ignored scan.retired. Deletes are now by claim
//        VALUE under the residue prefix, and a consumed claim's row
//        can never re-fire.
//  seal F-2 — a chain cut over a FOLD_RESIDUE_RETIRED mint carried it
//        only as an inert lifecycle entry: its consumed claims revived.
//        absorb() now re-applies retired_claims from signature-verified
//        lifecycle_carryover.
//  seal F-3 — the retire mint was gated on rows still standing
//        (if (claims.length)): a residue row wiped before its first
//        report left no consumption record and re-fired forever. The
//        mint now reconstructs claims from the flag's own heals.
//  seal F-4 — a claim latched in the cursor could outlive a same-
//        (count,max) slot rewrite: the seal attested a heal its anchor
//        no longer supported. Claims re-probe their anchor at fire time;
//        a dead or grafted anchor drops the claim and the latched flag.
//  seal F-5 — a verbatim replay of a divergent envelope at a foreign
//        seq minted a claim for a heal that never happened there. absorb
//        binds payload.sequence to the row position and tenant.
//  seal F-6 — residue enumeration was unbounded and malformed-value
//        rows never retired. Enumeration is capped (overflow attested)
//        and value-matched deletion retires rows regardless of key.
//  fixverify F-1 — check.mjs's dispatch verb extraction was polarity-
//        and conjunction-blind: `m[2]!=='x'`, `!(m[2]==='x')`, and
//        `m[2]==='x' && y` all minted 'x' as ours. Compares are now
//        parsed through the arm's whole condition.
//  fixverify F-2 — an own-verb arm nested inside a sibling arm on the
//        SAME member (`if(m[2]==='abort'){ if(m[2]==='acknowledge')`)
//        minted a gate for a statically dead arm. Same-member/
//        different-verb nesting is demoted to dead scope.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readFileSync , mkdtempSync, writeFileSync, rmSync} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fixture } from './helpers.mjs';
const probeFile = src => {
  const dir = mkdtempSync(join(tmpdir(), 'gate-probe-'));
  const file = join(dir, 'probe.mjs');
  writeFileSync(file, src);
  try { return execFileSync(process.execPath, [file], { encoding: 'utf8', cwd: new URL('..', import.meta.url).pathname }).trim(); }
  finally { rmSync(dir, { recursive: true, force: true }); }
};

const residueRows = h => h.f.store.db.prepare(
  "SELECT key,value FROM meta_kv WHERE tenant='acme' AND (key='fold_floor_healed' OR substr(key,1,18)='fold_floor_healed.')").all();
// w76-fv F-1: the schema-version pin convicts a dropped guard set at the
// next guarded call — snapshot the canonical trigger text before the graft
// and restore it after (the pin re-verifies and re-pins silently).
let _residueSnap = [];
const dropResidueGuards = h => {
  _residueSnap = h.f.store.db.prepare("SELECT name,sql FROM sqlite_master WHERE type='trigger' AND name LIKE 'fold_residue_keep%'").all();
  h.f.store.db.exec('DROP TRIGGER IF EXISTS fold_residue_keep');
  h.f.store.db.exec('DROP TRIGGER IF EXISTS fold_residue_keep_upd');
  h.f.store.db.exec('DROP TRIGGER IF EXISTS fold_residue_keep_ins');
};
const restoreResidueGuards = h => {
  for (const tr of _residueSnap) { try { h.f.store.db.exec(tr.sql); } catch (e) { if (!/already exists/.test(String(e?.message ?? e))) throw e; } }
};
let _auditSnap = [];
const dropAuditGuards = h => {
  _auditSnap = h.f.store.db.prepare("SELECT name,sql FROM sqlite_master WHERE type='trigger' AND tbl_name='audit'").all();
  for (const tr of _auditSnap)
    h.f.store.db.exec(`DROP TRIGGER "${tr.name}"`);
};
const restoreAuditGuards = h => {
  for (const tr of _auditSnap) { try { h.f.store.db.exec(tr.sql); } catch (e) { if (!/already exists/.test(String(e?.message ?? e))) throw e; } }
};
const healOnce = (h, garbage) => {
  h.f.store.db.prepare("UPDATE meta_kv SET value=? WHERE tenant='acme' AND key='fold_floor'").run(garbage);
  h.f.store.audit('acme', 'PROBE', 'actor', null, {}, h.f.clock());
};

// w59-runtime F-1: the tally bump must survive crowd-out — 40 newer
// containment rows cannot push the survivor beyond reach.
test('w59-runtime F-1: a crowded-out gate-deny row still gets its tally bump', t => {
  const h = fixture(t);
  h.ready(); h.ready();
  const now = h.now();
  h.f.store.put('acme', 'containment', 'deny:survivor', { contained_at: now, subject_id: 'subj-1', code: 'INV-403-X', request_id: 'gate-deny', dropped_requests: 1 }, now);
  for (let i = 0; i < 40; i++)
    h.f.store.put('acme', 'containment', `deny:crowd-${i}`, { contained_at: now + i + 1, subject_id: 'noise', code: 'INV-OTHER', request_id: 'gate-deny', dropped_requests: 1 }, now + i + 1);
  h.f._bumpGateDenyRow('acme', 'subj-1', 'INV-403-X', now);
  const row = h.f.store.get('acme', 'containment', 'deny:survivor');
  assert.equal(row.dropped_requests, 2, 'the buried survivor still counts the suppressed denial');
  h.close();
});

// w59-runtime F-2: the tombstone distinguishes a ledger shred from a
// murder — both revoke, but the label must not launder the murder into
// a routine deletion.
test('w59-runtime F-2: murdered vs tombstoned evidence carry different labels', t => {
  const h = fixture(t);
  const r = h.proposed();
  h.evidence(r); h.evidence(r, { issuer: 'registry' });
  const attached = h.f._auditIndex('acme').attached.get(r.capsule.capsule_id);
  assert.equal(attached.length, 2);
  // Legit shred: a tombstone row stands and keeps the original digest.
  h.f.store.remove('acme', 'evidence', attached[0]);
  h.f.store.put('acme', 'evidence-tombstone', attached[0], { evidence_id: attached[0], original_digest: 'dd'.repeat(32), deleted_at: h.now(), superseded: [], key_id: 'k1', kind: 'ownership' }, h.now());
  // Murdered: row gone, no tombstone, anchor still attests membership.
  h.f.store.remove('acme', 'evidence', attached[1]);
  const g = h.f.graph('acme', h.f.store.must('acme', 'capsule', r.capsule.capsule_id));
  const shredded = g.items.find(i => i.payload.evidence_id === attached[0]);
  const murdered = g.items.find(i => i.payload.evidence_id === attached[1]);
  assert.equal(shredded.revoked, true);
  assert.equal(shredded.issuer.failure_domain, 'deleted', 'a tombstoned shred stays labeled deleted');
  assert.equal(shredded.envelope.retained_digest, 'dd'.repeat(32));
  assert.equal(murdered.revoked, true);
  assert.equal(murdered.issuer.failure_domain, 'missing_under_anchor', 'a murdered row must not pass as a retention shred');
  assert.equal(murdered.missing_under_anchor, true);
  assert.equal(murdered.envelope.retained_digest, null);
  h.close();
});

// w59-seal F-1 + F-3: claims mint from the flag even when the rows are
// gone, and the delete runs by claim VALUE — a planted row at a
// non-claim key dies with the conviction it echoes; a re-planted copy of
// a consumed claim can never re-fire.
test('w59-seal F-1/F-3: value-matched retire; wiped rows still mint the consumption record', t => {
  const h = fixture(t);
  h.ready(); h.ready();
  healOnce(h, 'victim-claim');
  const claimVal = residueRows(h)[0].value;
  // A planted echo at a key the rebuilt keyset never names.
  dropResidueGuards(h);
  h.f.store.db.prepare("INSERT INTO meta_kv VALUES('acme','fold_floor_healed.77777',?)").run(claimVal);
  restoreResidueGuards(h);
  const seal = h.f.sealAuditChain(h.p('security'));
  assert.ok((seal.head_watermark_tampered ?? []).some(e => e.kind === 'floor_marker_healed' && e.healed_marker === 'victim-claim'));
  assert.equal(residueRows(h).length, 0, 'the planted echo dies with the claim it carries');
  // The consumption record is anchored: the planted claim can be
  // re-attached at a fresh key but never re-fire.
  const retired = h.f.store.db.prepare("SELECT envelope FROM audit WHERE tenant='acme' AND envelope LIKE '%FOLD_RESIDUE_RETIRED%'").all();
  assert.equal(retired.length, 1, 'the retire mint is the consumption record');
  assert.ok(JSON.parse(retired[0].envelope).payload.metadata.retired_claims.includes(claimVal));
  dropResidueGuards(h);
  h.f.store.db.prepare("INSERT INTO meta_kv VALUES('acme','fold_floor_healed.88888',?)").run(claimVal);
  restoreResidueGuards(h);
  const seal2 = h.f.sealAuditChain(h.p('security'));
  assert.ok(!(seal2.head_watermark_tampered ?? []).some(e => e.healed_marker === 'victim-claim'),
    `a re-planted copy of a consumed claim must not re-fire: ${JSON.stringify(seal2.head_watermark_tampered)}`);
  h.close();
});

// w59-seal F-3 hard case: rows wiped BEFORE the first report — no row
// stands to delete, but the consumption record still mints.
test('w59-seal F-3: residue wiped before its first report still retires the claim', t => {
  const h = fixture(t);
  h.ready(); h.ready();
  healOnce(h, 'wiped-claim');
  dropResidueGuards(h);
  h.f.store.db.prepare("DELETE FROM meta_kv WHERE tenant='acme' AND (key='fold_floor_healed' OR substr(key,1,18)='fold_floor_healed.')").run();
  restoreResidueGuards(h);
  const seal = h.f.sealAuditChain(h.p('security'));
  assert.ok((seal.head_watermark_tampered ?? []).some(e => e.kind === 'floor_marker_healed' && e.healed_marker === 'wiped-claim'),
    'the wiped heal is still named chain-side');
  const retired = h.f.store.db.prepare("SELECT envelope FROM audit WHERE tenant='acme' AND envelope LIKE '%FOLD_RESIDUE_RETIRED%'").all();
  assert.equal(retired.length, 1, 'the consumption record mints from the flag, not from surviving rows');
  assert.ok(JSON.parse(retired[0].envelope).payload.metadata.retired_claims.some(c => c.endsWith(':wiped-claim')));
  h.close();
});

// w59-seal F-2: the cut carries a doomed FOLD_RESIDUE_RETIRED as an
// inert lifecycle entry — absorb() must re-apply its consumed claims or
// every honest cut revives them.
test('w59-seal F-2: a cut over the retire mint keeps its claims consumed', t => {
  const h = fixture(t);
  h.ready(); h.ready();
  healOnce(h, 'cut-over');
  const claimVal = residueRows(h)[0].value;
  h.f.sealAuditChain(h.p('security'));
  assert.equal(residueRows(h).length, 0, 'the consulted heal retired with its report');
  // Doom the span containing the retire mint — a corrupted stored hash
  // makes it firstBad, and its still-signed envelope is carried as
  // lifecycle by the cut.
  dropAuditGuards(h);
  const rseq = h.f.store.db.prepare("SELECT seq FROM audit WHERE tenant='acme' AND envelope LIKE '%FOLD_RESIDUE_RETIRED%'").get().seq;
  h.f.store.db.prepare("UPDATE audit SET hash='00' WHERE tenant='acme' AND seq=?").run(rseq);
  restoreAuditGuards(h);
  h.f.invalidateAuditIndex('acme');
  h.f.sealAuditChain(h.p('security'));
  // The carried retire re-applies: a re-planted consumed claim is dead.
  dropResidueGuards(h);
  h.f.store.db.prepare("INSERT INTO meta_kv VALUES('acme','fold_floor_healed.99999',?)").run(claimVal);
  restoreResidueGuards(h);
  const seal3 = h.f.sealAuditChain(h.p('security'));
  assert.ok(!(seal3.head_watermark_tampered ?? []).some(e => e.healed_marker === 'cut-over'),
    `the carried retire keeps the claim consumed: ${JSON.stringify(seal3.head_watermark_tampered)}`);
  h.close();
});

// w59-seal F-4: a claim latched while its anchor was live dies when the
// slot is rewritten in place — the (count,max) invariant can hold across
// the graft, so the claim re-probes its anchor before it can ever
// re-fire. The first seal may still name the latch it found on entry
// (the flag was live when it started — the residue row stands and the
// heal genuinely happened); the second must not re-mint it.
test('w59-seal F-4: a stale latched claim dies with its rewritten anchor', t => {
  const h = fixture(t);
  h.ready(); h.ready();
  healOnce(h, 'latch-then-graft');
  // A plain index fold latches the claim in the cursor — no report
  // retires it yet.
  h.f._auditIndex('acme');
  const healSeq = Number(residueRows(h)[0].value.split(':')[0]);
  dropAuditGuards(h);
  h.f.store.db.prepare("UPDATE audit SET envelope='{}' WHERE tenant='acme' AND seq=?").run(healSeq);
  h.f.invalidateAuditIndex('acme');
  try { h.f.sealAuditChain(h.p('security')); } catch { /* a grafted anchor may refuse — the graft names itself */ }
  let seal2;
  try { seal2 = h.f.sealAuditChain(h.p('security')); } catch { seal2 = null; }
  const entries = seal2?.head_watermark_tampered ?? [];
  assert.ok(!entries.some(e => e.kind === 'floor_marker_healed' && e.healed_marker === 'latch-then-graft'),
    `the dead claim must not re-fire a phantom heal: ${JSON.stringify(entries)}`);
  h.close();
});

// w59-seal F-5: a verbatim replay of a real divergent envelope at a
// foreign seq verifies — but the claim it would mint names ITS OWN seq,
// not the planted position.
test('w59-seal F-5: a replayed divergent envelope cannot mint a claim at a foreign seq', t => {
  const h = fixture(t);
  h.ready(); h.ready();
  healOnce(h, 'phantom');
  const src = h.f.store.db.prepare("SELECT seq,hash,envelope FROM audit WHERE tenant='acme' AND envelope LIKE '%fold_floor_divergent%'").get();
  dropAuditGuards(h);
  const tip = h.f.store.db.prepare("SELECT seq,hash FROM audit WHERE tenant='acme' ORDER BY seq DESC LIMIT 1").get();
  h.f.store.db.prepare("INSERT INTO audit VALUES('acme',?,?,?,?)").run(tip.seq + 1, tip.hash, src.hash, src.envelope);
  let seal;
  try { seal = h.f.sealAuditChain(h.p('security')); } catch { seal = null; }
  const healed = (seal?.head_watermark_tampered ?? []).filter(e => e.kind === 'floor_marker_healed');
  assert.ok(!healed.some(e => e.seq === tip.seq + 1),
    `no claim mints for the planted position: ${JSON.stringify(healed)}`);
  h.close();
});

// w59-seal F-6: a residue row with a malformed value (no parseable seq)
// still retires — value-matched deletion kills it with the claim it
// carries, so it cannot re-report forever.
test('w59-seal F-6: malformed residue rows retire by claim value', t => {
  const h = fixture(t);
  h.ready(); h.ready();
  dropResidueGuards(h);
  h.f.store.db.prepare("INSERT INTO meta_kv VALUES('acme','fold_floor_healed.zzz','junk-value')").run();
  restoreResidueGuards(h);
  const seal = h.f.sealAuditChain(h.p('security'));
  assert.ok((seal.head_watermark_tampered ?? []).some(e => e.kind === 'floor_marker_healed_unanchored' && e.healed_marker === 'junk-value'));
  assert.equal(residueRows(h).length, 0, 'the malformed row retires with its report');
  const seal2 = h.f.sealAuditChain(h.p('security'));
  assert.ok(!(seal2.head_watermark_tampered ?? []).some(e => e.healed_marker === 'junk-value'), 'no re-fire after retire');
  h.close();
});

// ============================================================================
// Gate regressions — the shipped collectAuthorize, run verbatim against
// crafted multiplex chains (w56 harness pattern).
// ============================================================================
const collectRun = (lines, verb) => {
  const src = readFileSync('scripts/check.mjs', 'utf8');
  const helpers = src.slice(src.indexOf('// === shared source scanners'), src.indexOf('// === end shared source scanners'));
  const block = src.slice(src.indexOf('const NONROLE'), src.indexOf('const authorizeAt'));
  assert.ok(block.includes('collectAuthorize'), 'the slice carries the shipped scanner');
  return JSON.parse(probeFile([
    helpers, block,
    `globalThis.process.stdout.write(JSON.stringify(collectAuthorize(${JSON.stringify(lines)}, 0, ${lines.length + 2}, true, ${JSON.stringify(verb)}) ?? { roles: null, any: false }));`
  ].join('\n')));
};

// w59-fv F-1: negated, conjuncted, and operand-position compares mint
// no unconditional 'ours' for the named verb.
test('w59-fv F-1: verb extraction honors polarity and conjunction', t => {
  const head = "if (req.method === 'GET' && (m = /^\\/x\\/(.*)/.exec(path))) {";
  // !== — the arm can never serve the named verb.
  { const r = collectRun([head, "  if (m[1] !== 'a') {", "    authorize(p, ['sneak']);", "  }", "}"], 'a');
    assert.equal(r.any, false); assert.equal(r.roles, null); }
  // !(m===v) — negated group.
  { const r = collectRun([head, "  if (!(m[1] === 'a')) {", "    authorize(p, ['sneak']);", "  }", "}"], 'a');
    assert.equal(r.any, true); assert.equal(r.roles, null); }
  // && conjunct — the arm serves the verb only under the extra conjunct.
  { const r = collectRun([head, "  if (m[1] === 'a' && otherGate(p)) {", "    authorize(p, ['sneak']);", "  }", "}"], 'a');
    assert.equal(r.any, true); assert.equal(r.roles, null); }
  { const r = collectRun([head, "  if (otherGate(p) && m[1] === 'a') {", "    authorize(p, ['sneak']);", "  }", "}"], 'a');
    assert.equal(r.any, true); assert.equal(r.roles, null); }
  // Operand position — the compare feeds a ternary, not the condition.
  { const r = collectRun([head, "  if (x === (m[1] === 'a' ? 1 : 2)) {", "    authorize(p, ['sneak']);", "  }", "}"], 'a');
    assert.equal(r.any, true); assert.equal(r.roles, null); }
  // Preserved honest shapes: ||-alternation stays unconditional.
  assert.deepEqual(collectRun([head, "  if (m[1] === 'a' || m[1] === 'b') {", "    authorize(p, ['dual']);", "  }", "}"], 'a').roles, ['dual'],
    'an ||-joined same-member compare stays ours');
  assert.deepEqual(collectRun([head, "  if (m[1] === 'a' || otherGate(p)) {", "    authorize(p, ['dual']);", "  }", "}"], 'a').roles, ['dual'],
    'an ||-arm serves the named verb unconditionally');
  // The positive case still mints.
  assert.deepEqual(collectRun([head, "  if (m[1] === 'a') {", "    authorize(p, ['admin']);", "  }", "}"], 'a').roles, ['admin'],
    'a plain positive compare still mints');
});

// w59-fv F-2: a nested own-verb arm on the SAME member as the enclosing
// sibling arm is statically dead — it mints nothing; a nested arm on a
// DIFFERENT member stays reachable.
test('w59-fv F-2: same-member nested own-verb arm is dead scope', t => {
  const chain = [
    "if (req.method === 'GET' && (m = /^\\/x\\/(.*)/.exec(path))) {",
    "  if (m[1] === 'abort') {",
    "    if (m[1] === 'acknowledge') {",
    "      authorize(p, ['spy']);",
    "    }",
    "  }",
    "  authorize(p, ['shared']);",
    "}",
  ];
  { const r = collectRun(chain, 'acknowledge'); assert.deepEqual(r.roles, ['shared']); assert.equal(r.any, true); }
  const reachable = [
    "if (req.method === 'GET' && (m = /^\\/x\\/(.*)/.exec(path))) {",
    "  if (m[1] === 'abort') {",
    "    if (m[2] === 'acknowledge') {",
    "      authorize(p, ['nested']);",
    "    }",
    "  }",
    "  authorize(p, ['shared']);",
    "}",
  ];
  { const r = collectRun(reachable, 'acknowledge'); assert.deepEqual(r.roles, ['shared']); assert.equal(r.any, true); }
});

// ============================================================================
// w59-ledger regressions — the ledger-auditor's holes in the honesty
// machinery itself: check.mjs dead-scope judgment + traceability.py's
// syntactic evidence walk (F-1..F-16).
// ============================================================================

// F-6: an authorize inside a statically-dead branch mints nothing — not
// a role, and not even the '.any' reachability mark.
test('w59-ledger F-6: dead-constant branch mints no roles', t => {
  for (const deadCond of ['false', '0', 'null', 'undefined', "''", '!true', '!1']) {
    const lines = [
      "if (req.method === 'GET' && (m = /^\\/x\\/(.*)/.exec(path))) {",
      `  if (${deadCond}) {`,
      "    authorize(p, ['sneak']);",
      "  }",
      "  authorize(p, ['real']);",
      "}",
    ];
    assert.deepEqual(collectRun(lines, 'a').roles, ['real'], `if (${deadCond}) scope is dead`);
  }
  // `false &&` and `&& false` kill the whole condition.
  assert.deepEqual(collectRun([
    "if (req.method === 'GET' && (m = /^\\/x\\/(.*)/.exec(path))) {",
    "  if (false && gate(p)) { authorize(p, ['sneak']); }",
    "  if (gate(p) && false) { authorize(p, ['sneak2']); }",
    "  authorize(p, ['real']);",
    "}",
  ], 'a').roles, ['real'], 'a false-conjuncted condition is dead');
  // A truthy-constant `if` is statically proven to enter its arm —
  // the body mints unconditionally (w65 const-true doctrine).
  assert.deepEqual(collectRun([
    "if (req.method === 'GET' && (m = /^\\/x\\/(.*)/.exec(path))) {",
    "  if (true) { authorize(p, ['kept']); }",
    "  authorize(p, ['real']);",
    "}",
  ], 'a').roles, ['kept', 'real'], 'a statically-true arm mints unconditional');
});

// F-1: a declared-but-never-invoked local function carries dead asserts.
test('w59-ledger F-1: uninvoked local function is dead scope', t => {
  const lines = [
    "if (req.method === 'GET' && (m = /^\\/x\\/(.*)/.exec(path))) {",
    "  function hidden() { authorize(p, ['sneak']); }",
    "  authorize(p, ['real']);",
    "}",
  ];
  assert.deepEqual(collectRun(lines, 'a').roles, ['real'], 'an uninvoked function body mints nothing');
  const invoked = [
    "if (req.method === 'GET' && (m = /^\\/x\\/(.*)/.exec(path))) {",
    "  function helper() { authorize(p, ['tagged']); }",
    "  helper();",
    "  authorize(p, ['real']);",
    "}",
  ];
  assert.deepEqual(collectRun(invoked, 'a').roles, ['tagged', 'real'], 'an invoked function still mints');
});

// F-4: a comma inside a dead call's argument list is an argument
// separator, not a statement edge — the dead span must not revive.
test('w59-ledger F-4: dead continuation honors paren depth', t => {
  const lines = [
    "if (req.method === 'GET' && (m = /^\\/x\\/(.*)/.exec(path))) {",
    "  if (false) {",
    "    helper(a,",
    "      authorize(p, ['sneak']));",
    "  }",
    "  authorize(p, ['real']);",
    "}",
  ];
  assert.deepEqual(collectRun(lines, 'a').roles, ['real'], 'authorize nested in dead call args is dead');
});

// F-3: an else-if arm repeating the named verb after our chain closed
// is unreachable for that verb.
test('w59-ledger F-3: else-if after closed chain is dead scope', t => {
  const lines = [
    "if (req.method === 'GET' && (m = /^\\/x\\/(.*)/.exec(path))) {",
    "  if (m[1] === 'a') {",
    "    authorize(p, ['first']);",
    "  } else if (m[1] === 'a') {",
    "    authorize(p, ['sneak']);",
    "  }",
    "}",
  ];
  assert.deepEqual(collectRun(lines, 'a').roles, ['first'],
    'a repeat-verb else-if cannot run — it mints nothing');
});

// F-5: a dispatch alias rebound to a non-route value is unbound — the
// arm it gates is no dispatch arm.
test('w59-ledger F-5: rebound dispatch alias unbinds', t => {
  const lines = [
    "if (req.method === 'GET' && (m = /^\\/x\\/(.*)/.exec(path))) {",
    "  const d = m[1];",
    "  d = 'zz';",
    "  if (d === 'a') {",
    "    authorize(p, ['sneak']);",
    "  }",
    "  authorize(p, ['real']);",
    "}",
  ];
  const got = collectRun(lines, 'a');
  assert.ok(!(got.roles ?? []).includes('sneak'), `a rebound alias arm cannot serve the verb (got ${JSON.stringify(got)})`);
});

// F-7: a `${}` interpolation inside a template literal is code — an
// authorize there runs when the statement runs.
test('w59-ledger F-7: template interpolation is code', t => {
  const lines = [
    "if (req.method === 'GET' && (m = /^\\/x\\/(.*)/.exec(path))) {",
    "  if (m[1] === 'a') {",
    "    const s = `x${authorize(p, ['tagged'])}y`;",
    "  }",
    "}",
  ];
  assert.deepEqual(collectRun(lines, 'a').roles, ['tagged'], 'an authorize inside ${} still mints');
});

// ---------------------------------------------------------------------------
// traceability.py — run the real gate functions on crafted bodies.
// ---------------------------------------------------------------------------
const pyEval = (expr) => execFileSync('python3', ['-c',
  `import json\nsrc=open('scripts/traceability.py').read()\ng={'__file__':'scripts/traceability.py'}\nexec(src[:src.index('def evidence_blocks')], g)\nprint(${expr})`], { encoding: 'utf8' }).trim();
const pyLive = (code) => pyEval(`g['_live_code'](g['_blank_code'](${JSON.stringify(code)}), ${JSON.stringify(code)})`);
const pyAsserts = (code) => pyEval(`g['_asserts'](${JSON.stringify(code)}, {'assert','ok','strictEqual','throws'})`);

// F-10: `x ?? assert(...)` kills the RHS when the left is statically
// non-nullish — it never ran before (only &&/|| folded).
test('w59-ledger F-10: ?? short-circuit is dead-code judged', t => {
  assert.ok(!pyLive("const a = 5; a ?? assert.bad();").includes('assert.bad'),
    'a known-non-nullish left makes the ?? arm dead');
  assert.ok(pyLive("const a = null; a ?? assert.good();").includes('assert.good'),
    'a nullish left keeps the ?? arm live');
  assert.ok(pyLive("x ?? assert.stay();").includes('assert.stay'),
    'an unknown left keeps the ?? arm live');
});

// F-11/F-16: a comparison binding its operands is one expression — the
// && operand walk must see `false === true`, not just `true`.
test('w59-ledger F-11: comparison operands fold through &&', t => {
  assert.ok(!pyLive("assert.ok(x); false === true && assert.bad();").includes('assert.bad'),
    'false === true is dead — the && arm never ran');
  assert.ok(pyLive("assert.ok(x); 1 === 1 && assert.good();").includes('assert.good'),
    'a true comparison keeps the && arm live');
  assert.ok(!pyLive("assert.ok(x); 1 !== 1 && assert.bad();").includes('assert.bad'),
    'a false !== folds dead');
  assert.ok(!pyLive("assert.ok(x); 0 >= 1 && assert.bad();").includes('assert.bad'),
    'a false >= folds dead');
  assert.ok(pyLive("assert.ok(x); t instanceof K && assert.stay();").includes('assert.stay'),
    'instanceof is not constant-foldable — the arm stays live');
});

// F-12: only the trusted binding mints — `stub.assert(` is a member
// call on a host object, and `assert(args) {` is a method definition.
test('w59-ledger F-12: member-call and method-def asserts mint nothing', t => {
  assert.equal(pyAsserts("stub.assert(x)"), '0', 'a .assert member call is not the binding');
  assert.equal(pyAsserts("assert.ok(1)"), '1', 'the real call still counts');
  assert.equal(pyAsserts("const o = { assert(x) { return 1 } }; o.assert(1)"), '0',
    'an object method named assert is not the binding');
  assert.equal(pyAsserts("assert.throws(fn, re)"), '1', 'a real multi-arg call still counts');
  assert.equal(pyAsserts("x.assert.ok(1)"), '0', 'a nested member chain is not the binding');
});

// F-13: computed-member spellings die by the same reachability checks —
// `ee['on']` and `p['then']` are `.on`/`.then`.
test('w59-ledger F-13: computed-member emit/then judged', t => {
  assert.ok(!pyLive("ee['on']('x', () => assert.bad());").includes('assert.bad'),
    "an ee['on'] handler with no emit is dead");
  assert.ok(pyLive("ee['on']('x', () => assert.good()); ee['emit']('x');").includes('assert.good'),
    "the same-event ee['emit'] rescues the handler");
  assert.ok(!pyLive("p['then'](() => assert.bad());").includes('assert.bad'),
    "an unawaited p['then'] callback is dead");
  assert.ok(pyLive("await p['then'](() => assert.good());").includes('assert.good'),
    'an awaited computed-member then stays live');
});

// F-14: shadow escapes — a decl-less destructure, a computed member
// write, or eval all neuter the assert vocabulary.
test('w59-ledger F-14: destructure/computed-write/eval shadow neuter', t => {
  assert.equal(pyAsserts("({ assert } = fake); assert.ok(1)"), '0',
    'a decl-less destructure rebinds assert');
  assert.equal(pyAsserts("assert[k] = f; assert.ok(1)"), '0',
    'a variable-index member write neuters the method');
  assert.equal(pyAsserts("ev" + "al('x'); assert.ok(1)"), '0',
    'eval can rebind anything — the vocabulary is untrusted');
});

// F-15: a nested it()/describe()/context() is its own test boundary —
// its asserts attribute to its own title, never the parent's.
test('w59-ledger F-15: nested test calls are their own boundary', t => {
  const out = pyEval(`[(g['_test_title'](b), g['_asserts'](b, {'assert','ok'})) for b in g['_test_bodies'](${JSON.stringify("test('OUT-1', () => { it('inner', () => assert.ok(1)); });")})]`);
  assert.equal(out, "[('OUT-1', 0), ('inner', 1)]", 'the inner it attributes to its own title');
  // A skipped enclosing describe skips its children too.
  const skipped = pyEval(`len(g['_test_bodies'](${JSON.stringify("describe.skip('grp', () => { it('inner', () => assert.ok(1)); });")}))`);
  assert.equal(skipped, '0', 'children of a skipped block are skipped');
  // Node:test it() at top level is evidence in its own right.
  const top = pyEval(`[(g['_test_title'](b), g['_asserts'](b, {'assert','ok'})) for b in g['_test_bodies'](${JSON.stringify("it('REQ-9', () => assert.ok(1));")})]`);
  assert.equal(top, "[('REQ-9', 1)]", 'a top-level it() is a test boundary');
});

// F-9: the honest floor in the ledger matches the benchmark's actual
// Math.max(40,…) bound — no stale 60/s.
test('w59-ledger F-9: perf floor strings agree with the benchmark', t => {
  const bench = readFileSync('scripts/benchmark.mjs', 'utf8');
  assert.ok(!bench.includes('60/s'), 'benchmark comment names the real 40/s floor');
  const traceSrc = readFileSync('scripts/traceability.py', 'utf8');
  assert.ok(traceSrc.includes('>=40/s'), 'the limitation override names the real floor');
  assert.ok(!traceSrc.includes('>=60/s'), 'no stale 60/s survives in the ledger');
});
