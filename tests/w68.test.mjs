// Wave-68 regression tests: ledger F-1..F-5 (member-proof two-vote
// doctrine, dead-conjunct/binary-continuation vote rejection, Allman
// brace frames, seed-scan route boundary, break-scope bound) + fv F-2
// (seed votes cross route rows) + fv F-4 (floor_prior hash column is
// attacker clay — recompute from the signed envelope) and its fabric.mjs
// marker-consult twin. Gate probes eval a live slice of the shipped
// scanner — tested code cannot drift from shipped code.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';
import { fixture } from './helpers.mjs';
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

const residueRows = h => h.f.store.db.prepare("SELECT value FROM meta_kv WHERE tenant='acme' AND (key='fold_floor_healed' OR substr(key,1,18)='fold_floor_healed.')").all();
const committedTip = h => h.f.store.db.prepare("SELECT MAX(seq) m FROM audit WHERE tenant='acme'").get().m;
let _auditSnap = [];
const dropAuditGuards = h => {
  // w76-fv F-1: the schema-version pin convicts a dropped guard set at the
  // next guarded call — snapshot the canonical texts first so the graft
  // restores them (the pin then re-verifies and re-pins silently).
  _auditSnap = h.f.store.db.prepare("SELECT name,sql FROM sqlite_master WHERE type='trigger' AND tbl_name='audit'").all();
  for (const tr of _auditSnap)
    h.f.store.db.exec(`DROP TRIGGER "${String(tr.name).replace(/"/g, '""')}"`);
};
const restoreAuditGuards = h => {
  for (const tr of _auditSnap) { try { h.f.store.db.exec(tr.sql); } catch (e) { if (!/already exists/.test(String(e?.message ?? e))) throw e; } }
};
const payloadDigestAt = (h, seq) => digest(JSON.parse(h.f.store.db.prepare("SELECT envelope FROM audit WHERE tenant='acme' AND seq=?").get(seq).envelope).payload);

// ============================================================================
// w68-ledger F-1: a member is a dispatch discriminator only when at
// least two distinct verbs bind it positively in the same row — one
// positive compare is an id-filter, not proof. An unbound verb's `!==`
// on a lone-vote member mints CONDITIONAL (requests may carry the very
// excluded value); the deterministic folds survive: the excluded verb
// itself and any verb bound ON the member.
// ============================================================================
test('w68-ledger F-1: `!==` folds only for proven members — bound verbs and the excluded literal exempt', () => {
  const row = [HEAD2, "  if (m[2]==='y') { serve(); }", "  if (m[2]!=='z') { authorize(p, ['adm']); }", '}'];
  { const r = collectRun(row, 'x'); assert.equal(r.any, true); assert.equal(r.roles, null, 'lone vote is an id-filter — conditional for the unbound'); }
  { const r = collectRun(row, 'y'); assert.deepEqual(r.roles, ['adm'], 'bound verb: its own binding proves the member for it'); }
  { const r = collectRun(row, 'z'); assert.equal(r.any, false, 'the excluded literal can never satisfy its own `!==`'); }
  const row2 = [HEAD2, "  if (m[2]==='y') { serve(); }", "  if (m[2]==='w') { serveW(); }", "  if (m[2]!=='z') { authorize(p, ['adm']); }", '}'];
  { const r = collectRun(row2, 'x'); assert.deepEqual(r.roles, ['adm'], 'two positive votes prove the member — the fold returns'); }
});

// ============================================================================
// w68-ledger F-2: a member compare must END at the literal — a binary
// continuation (`instanceof`, `in`, relational/additive/bitwise ops, a
// call/index/member chain) re-reads a runtime value: the pair never
// served and never votes, so neither the arm nor a sibling `!==` mints.
// ============================================================================
test('w68-ledger F-2: binary continuations after the literal reject the pair entirely', () => {
  for (const cont of ['instanceof Object', 'in o', '< 1', '+ x', '| 0', '(x)', '[0]', '.f']) {
    const r = collectRun([HEAD2, `  if (m[2]==='y' ${cont}) { authorize(p, ['adm']); }`, '}'], 'y');
    assert.equal(r.roles, null, `'${cont}' reads a runtime value — never unconditional: ${JSON.stringify(r)}`);
  }
  // The pair is not a vote either — a sibling `!==` cannot fold off it.
  const r = collectRun([HEAD2, "  if (m[2]==='y' instanceof Object) { serve(); }", "  if (m[2]!=='z') { authorize(p, ['adm']); }", '}'], 'x');
  assert.equal(r.roles, null, 'a non-pair head casts no discriminator vote');
});

test('w68-ledger F-2b: a dead `&&` conjunct kills the arm AND its vote', () => {
  // `m[2]==='y' && false` is statically dead — it never served, and the
  // dead arm's pair must not cast the member vote either.
  for (const conj of ['false', 'null', '0']) {
    const r = collectRun([HEAD2, `  if (m[2]==='y' && ${conj}) { serve(); }`, "  if (m[2]!=='z') { authorize(p, ['adm']); }", '}'], 'x');
    assert.equal(r.roles, null, `dead conjunct '${conj}' cannot vote: ${JSON.stringify(r)}`);
  }
  // Same-member const-false (`m[1]==='a' && m[1]==='b'`) — the arm is
  // dead for every verb and votes nothing.
  const r = collectRun([HEAD, "  if (m[1]==='a' && m[1]==='b') { serve(); }", "  if (m[1]!=='z') { authorize(p, ['adm']); }", '}'], 'x');
  assert.equal(r.roles, null, `same-member contradiction is dead, not a vote: ${JSON.stringify(r)}`);
});

// ============================================================================
// w68-ledger F-3: an Allman brace — `if (flag)\n{` — gates the block the
// same as the same-line `{`: a peek at the next non-empty lines pushes
// the deferred frame before the block's votes are counted.
// ============================================================================
test('w68-ledger F-3: a `{` on the next line still gates the interior', () => {
  const r = collectRun([HEAD2, "  if (flag)", "  {", "    if (m[2]==='y') { serve(); }", "  }", "  if (m[2]!=='z') { authorize(p, ['adm']); }", '}'], 'x');
  assert.equal(r.roles, null, 'the braced gate votes under a runtime flag — conditional');
  // The same shape inline stays the baseline: ungated votes mint.
  const free = collectRun([HEAD2, "  if (m[2]==='y') { serve(); }", "  if (m[2]==='w') { serveW(); }", "  if (m[2]!=='z') { authorize(p, ['adm']); }", '}'], 'x');
  assert.deepEqual(free.roles, ['adm']);
});

// ============================================================================
// w68-ledger F-4 + w68-fv F-2: the seed loop walks past the row the
// `from` head opened — a compare in the NEXT route row used to vote for
// this row's members. The scan breaks at the same routeArmBoundary the
// mint loop uses.
// ============================================================================
test('w68-ledger F-4: a compare in the next route row cannot vote into this row', () => {
  const r = collectRun([
    "if (req.method === 'GET' && (m = /^\\/x\\/(.*)/.exec(path))) {",
    "  if (m[1]==='a') { serveA(); }",
    "}",
    "if (req.method === 'POST' && (m = /^\\/y\\/(.*)/.exec(path))) {",
    "  if (m[1]==='b') { serveB(); }",
    "  if (m[1]!=='z') { authorize(p, ['adm']); }",
    "}"
  ], 'x');
  assert.equal(r.roles, null, `the second row's 'b' vote never lands on row x: ${JSON.stringify(r)}`);
  // And the next row's `!==` stays conditional for row-x's verb too.
  const r2 = collectRun([
    "if (req.method === 'GET' && (m = /^\\/x\\/(.*)/.exec(path))) {",
    "  if (m[1]==='a') { serveA(); }",
    "  if (m[1]!=='z') { authorize(p, ['adm']); }",
    "}",
    "if (req.method === 'POST' && (m = /^\\/y\\/(.*)/.exec(path))) {",
    "  if (m[1]==='b') { serveB(); }",
    "}"
  ], 'x');
  assert.equal(r2.roles, null, `row y's pair must not prove row x's member: ${JSON.stringify(r2)}`);
});

// ============================================================================
// w68-ledger F-5: an unlabeled `break`/`continue` exits only the
// innermost for/while/switch — a foreign case's `break` must not poison
// the post-switch tail for verbs the case never serves. `return`,
// `throw` and labeled forms still mark every enclosing frame.
// ============================================================================
test('w68-ledger F-5: a foreign case `break` keeps the post-switch tail live', () => {
  // 'x' falls through `case 'x': work();` (no break) to the tail — the
  // `break` in case 'y' exits the switch, not the row.
  const r = collectRun([HEAD2,
    "  switch (m[2]) {",
    "    case 'y': serve(); break;",
    "    case 'x': work();",
    "  }",
    "  if (m[2]==='w' || m[2]==='x') { authorize(p, ['adm']); }",
    '}'], 'x');
  assert.deepEqual(r.roles, ['adm'], `x's fall-through tail stays unconditional: ${JSON.stringify(r)}`);
  // 'x'-returning case still gates the tail for 'x'.
  const r2 = collectRun([HEAD2,
    "  switch (m[2]) {",
    "    case 'x': return;",
    "    case 'y': work(); break;",
    "  }",
    "  authorize(p, ['adm']);",
    '}'], 'x');
  assert.equal(r2.any, false, 'x returns inside its case — the tail is dead for it');
  // A `while` loop's `break` bound to it — the enclosing `if` tail lives.
  const r3 = collectRun([HEAD2,
    "  while (q()) {",
    "    if (m[2]==='y') { break; }",
    "  }",
    "  if (m[2]==='x') { authorize(p, ['adm']); }",
    '}'], 'x');
  assert.deepEqual(r3.roles, ['adm'], `the loop break cannot gate the enclosing row's tail: ${JSON.stringify(r3)}`);
});

// ============================================================================
// w68-fv F-4 (store.mjs): `floorPriorForeign` must recompute the named
// row's digest from its signed envelope bytes — the `hash` column is
// attacker clay. A column rewrite matching a planted marker's hash half
// can no longer launder the marker into 'not divergent'; and a column
// rewrite on the named row cannot frame an HONEST marker as foreign.
// ============================================================================
test('w68-fv F-4: a hash-column rewrite cannot launder a planted floor marker', t => {
  const h = fixture(t);
  h.ready(); h.ready();
  const tip = committedTip(h);
  const seq = 1;
  const fake = 'aa'.repeat(32);
  // Plant `seq:fake` on an in-span row and rewrite the named row's hash
  // column to match — the old SELECT-hash consult read them as
  // consistent. The insider drops the append-only guards to reach the
  // column — exactly the attacker the column-trust laundered for. (The
  // tip row's own divergence is already fail-closed by the audit-index
  // check; the in-span consult is where the column was believed.)
  h.f.store.db.prepare("UPDATE meta_kv SET value=? WHERE tenant='acme' AND key='fold_floor'").run(`${seq}:${fake}`);
  dropAuditGuards(h);
  h.f.store.db.prepare("UPDATE audit SET hash=? WHERE tenant='acme' AND seq=?").run(fake, seq);
  restoreAuditGuards(h);
  h.f.store.audit('acme', 'PROBE', 'actor', null, {}, h.f.clock());
  const res = residueRows(h).map(r => r.value);
  assert.ok(res.some(v => v.includes(fake)), `the plant is named divergent — column clay cannot launder it: ${JSON.stringify(res)}`);
  const now = h.f.store.db.prepare("SELECT value FROM meta_kv WHERE tenant='acme' AND key='fold_floor'").get().value;
  assert.ok(now.startsWith(`${tip + 1}:`), `the marker advanced honestly past the plant: ${now}`);
  h.close();
});

test('w68-fv F-4b: a hash-column rewrite cannot frame an honest marker as foreign', t => {
  const h = fixture(t);
  h.ready(); h.ready();
  const seq = 1;
  // The marker's hash half is honest (digest of the named row's
  // envelope payload); an attacker then rewrites ONLY the `hash`
  // column. The old consult flagged the marker divergent on the column
  // alone — a false-positive conviction.
  h.f.store.db.prepare("UPDATE meta_kv SET value=? WHERE tenant='acme' AND key='fold_floor'").run(`${seq}:${payloadDigestAt(h, seq)}`);
  dropAuditGuards(h);
  h.f.store.db.prepare("UPDATE audit SET hash=? WHERE tenant='acme' AND seq=?").run('bb'.repeat(32), seq);
  restoreAuditGuards(h);
  h.f.store.audit('acme', 'PROBE', 'actor', null, {}, h.f.clock());
  const res = residueRows(h).map(r => r.value);
  assert.ok(!res.some(v => v.includes('bb'.repeat(32))), 'no false divergent claim from column clay');
  h.close();
});
