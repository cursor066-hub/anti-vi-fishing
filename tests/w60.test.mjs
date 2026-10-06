// Wave-60 regression tests: the w60-http findings — drift-check must refuse
// revoked issuers before credentialed egress (F-1), and the connector lookup
// must name 'Issuer not found' distinctly from an endpoint defect (F-2).
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fixture, hasCode } from './helpers.mjs';
import { createIssuerServer, loadIssuers, writeIssuer } from '../src/issuerd.mjs';
import { ISSUER_RULES, issuerRecords } from '../src/bootstrap.mjs';

async function serve(t, dir, opts = {}) {
  const srv = createIssuerServer(loadIssuers(dir), { port: 0, host: '127.0.0.1', ...opts });
  await srv.listen(); t.after(() => srv.close().catch(() => {}));
  return srv;
}

const bankOf = h => Object.entries(h.f.tenant('acme').issuers).find(([, v]) => v.name === 'bank');

const liveBank = async (t, h) => {
  const [bankKeyId, bank] = bankOf(h);
  const dir = mkdtempSync(join(tmpdir(), 'w60-rev-')); t.after(() => rmSync(dir, { recursive: true, force: true }));
  writeIssuer(dir, { issuer: 'bank', tenant: 'acme', channel: 'authoritative', version: '1.0.0', key: h.setup.issuerKeys.acme.bank, kinds: ISSUER_RULES.bank, records: issuerRecords().bank, read_token: bank.read_token });
  const srv = await serve(t, dir, { clock: () => h.now() });
  h.repoint(bankKeyId, `http://127.0.0.1:${srv.server.address().port}`);
  assert.equal((await h.f.checkIssuerDrift(h.p('security'), bankKeyId)).drifted, false, 'precondition: live connector revalidates clean');
  return { bankKeyId, srv };
};

// F-1: revocation is a terminal conviction — the drift-check must refuse a
// revoked issuer BEFORE the socket opens, not remediate it.
test('w60 F-1: drift-check refuses an issuer-revoked connector before egress', async t => {
  const h = fixture(t, ['acme']);
  const { bankKeyId } = await liveBank(t, h);
  h.f.revoke(h.p('security'), { kind: 'issuer', id: bankKeyId, reason: 'compromised' });
  await assert.rejects(() => h.f.checkIssuerDrift(h.p('security'), bankKeyId), hasCode('INV-401-EVIDENCE'),
    'a revoked issuer earns no credentialed drift-check — the endpoint stays live so a missing gate would resolve instead of rejecting');
  assert.ok(!h.f.store.db.prepare("SELECT 1 FROM audit WHERE tenant='acme' AND json_extract(envelope,'$.payload.type')='CONNECTOR_REVALIDATED' AND json_extract(envelope,'$.payload.object')=?").get(bankKeyId),
    'no revalidation evidence mints under dead authority');
  h.close();
});

test('w60 F-1: drift-check refuses a key-revoked connector before egress', async t => {
  const h = fixture(t, ['acme']);
  const { bankKeyId } = await liveBank(t, h);
  h.f.revoke(h.p('security'), { kind: 'key', id: bankKeyId, reason: 'key compromise' });
  await assert.rejects(() => h.f.checkIssuerDrift(h.p('security'), bankKeyId), hasCode('INV-401-EVIDENCE'),
    'a revoked key earns no credentialed drift-check either');
  h.close();
});

// F-2: 'no such connector' names itself — it must not misdescribe a defect on
// an endpoint that was never registered.
test('w60 F-2: missing connector names itself on both remediate routes', async t => {
  const h = fixture(t, ['acme']);
  await assert.rejects(() => h.f.checkIssuerDrift(h.p('security'), 'deadbeef'), /Issuer not found/,
    'drift-check names the missing connector, not an endpoint defect');
  await assert.rejects(() => h.f.repinIssuerSpec(h.p('security'), 'deadbeef'), /Issuer not found/,
    'repin names the missing connector, not an endpoint defect');
  h.close();
});

// ============================================================================
// w60-seal: residue-retire survives its own mint's murder (F-1), echo rows
// flag+drain (F-2), and capped heals still join the consumed set (F-3).
// ============================================================================
const residueRows = h => h.f.store.db.prepare(
  "SELECT key,value FROM meta_kv WHERE tenant='acme' AND (key='fold_floor_healed' OR substr(key,1,18)='fold_floor_healed.')").all();
const dropResidueGuards = h => {
  h.f.store.db.exec('DROP TRIGGER IF EXISTS fold_residue_keep');
  h.f.store.db.exec('DROP TRIGGER IF EXISTS fold_residue_keep_upd');
  h.f.store.db.exec('DROP TRIGGER IF EXISTS fold_residue_keep_ins');
};
const dropAuditGuards = h => {
  for (const tr of h.f.store.db.prepare("SELECT name FROM sqlite_master WHERE type='trigger' AND tbl_name='audit'").all())
    h.f.store.db.exec(`DROP TRIGGER "${tr.name}"`);
};
const healOnce = (h, garbage) => {
  h.f.store.db.prepare("UPDATE meta_kv SET value=? WHERE tenant='acme' AND key='fold_floor'").run(garbage);
  h.f.store.audit('acme', 'PROBE', 'actor', null, {}, h.f.clock());
};

// w60-seal F-1: the AUDIT_SEALED envelope itself carries the consumed-claim
// set, so murdering the FOLD_RESIDUE_RETIRED row cannot un-consume them.
test('w60-seal F-1: the retire binds the consumed claim set redundantly', t => {
  const h = fixture(t);
  h.ready(); h.ready();
  healOnce(h, 'fold-bound');
  const claimVal = residueRows(h)[0].value;
  const seal = h.f.sealAuditChain(h.p('security'));
  assert.ok((seal.head_watermark_tampered ?? []).some(e => e.kind === 'floor_marker_healed' && e.healed_marker === 'fold-bound'));
  assert.equal(residueRows(h).length, 0, 'the consulted heal retired with its report');
  // The durable consumption marker lives on the residue plane — a
  // murdered retire mint cannot un-consume the claim while it stands.
  const marker = h.f.store.db.prepare("SELECT value FROM meta_kv WHERE tenant='acme' AND key='fold_floor_retired'").get()?.value;
  assert.ok(JSON.parse(marker ?? '[]').includes(claimVal), 'the durable marker binds the consumed claim');
  h.close();
});

// w60-seal F-1+F-2: murder the retire mint AND re-plant the claim — the
// seal's own retired_claims_fold still binds it: the echo row is named and
// drained instead of re-firing as a fresh conviction.
test('w60-seal F-1/F-2: retire-mint murder cannot un-consume a claim', t => {
  const h = fixture(t);
  h.ready(); h.ready();
  healOnce(h, 'unconsummable');
  const claimVal = residueRows(h)[0].value;
  h.f.sealAuditChain(h.p('security'));
  assert.equal(residueRows(h).length, 0, 'precondition: the heal retired');
  // Murder the consumption record; keep the seal that carries the fold.
  dropAuditGuards(h);
  h.f.store.db.prepare("DELETE FROM audit WHERE tenant='acme' AND envelope LIKE '%FOLD_RESIDUE_RETIRED%'").run();
  // Re-plant the consumed claim at a fresh key.
  dropResidueGuards(h);
  h.f.store.db.prepare("INSERT INTO meta_kv VALUES('acme','fold_floor_healed.echo',?)").run(claimVal);
  const seal2 = h.f.sealAuditChain(h.p('security'));
  assert.ok(!(seal2.head_watermark_tampered ?? []).some(e => e.healed_marker === 'unconsummable'),
    `a re-planted retired claim must not re-fire: ${JSON.stringify(seal2.head_watermark_tampered)}`);
  assert.ok((seal2.head_watermark_tampered ?? []).some(e => e.kind === 'floor_marker_residue_retired_echo'),
    'the defeated retirement is named, not skipped');
  assert.equal(residueRows(h).length, 0, 'the echo row is drained by value');
  // The seal-fold is a third consumption record when a cut mints one —
  // a tail-murdered retire leaves a verifying chain, so nothing mints.
  const seals = h.f.store.db.prepare("SELECT envelope FROM audit WHERE tenant='acme' AND envelope LIKE '%AUDIT_SEALED%'").all();
  if (seals.length) {
    const fold = JSON.parse(seals.at(-1).envelope).payload.metadata.retired_claims_fold;
    assert.ok((fold ?? []).includes(claimVal), 'the seal mint itself names the consumed claims');
  }
  h.close();
});

// w60-seal F-3: a consult that dropped heals by cap still retires every row
// the flag's span touched — the live residue values join the consumed set.
test('w60-seal F-3: cap-evicted heals still retire with their report', t => {
  const h = fixture(t);
  h.ready(); h.ready();
  // HEALS_CAP is 256 — mint 258 heals so two are dropped.
  for (let i = 0; i < 258; i++) healOnce(h, `cap-${i}`);
  const seal = h.f.sealAuditChain(h.p('security'));
  const retired = h.f.store.db.prepare("SELECT envelope FROM audit WHERE tenant='acme' AND envelope LIKE '%FOLD_RESIDUE_RETIRED%'").all();
  assert.ok(retired.length >= 1, 'the consumption record minted');
  const total = retired.reduce((n, r) => n + (JSON.parse(r.envelope).payload.metadata.retired_total ?? 0), 0);
  assert.ok(total >= 258, `all ${total} cap-dropped claims joined the mint`);
  assert.equal(residueRows(h).length, 0, 'every residue row drained, dropped heals included');
  h.close();
});

// w60-fv F-10: the retire DELETE is probed — a resurrecting trigger leaves a
// standing echo that names itself rather than reporting a clean retire.
test('w60-fv F-10: a defeated residue delete is named', t => {
  const h = fixture(t);
  h.ready(); h.ready();
  healOnce(h, 'resurrect-me');
  // A hostile AFTER-DELETE trigger resurrects every drained residue row —
  // the sanctioned delete runs under it and the post-delete probe must
  // see the echo still standing.
  dropResidueGuards(h);
  h.f.store.db.exec(`CREATE TRIGGER residue_zombie AFTER DELETE ON meta_kv
    WHEN OLD.key='fold_floor_healed' OR substr(OLD.key,1,18)='fold_floor_healed.'
    BEGIN INSERT INTO meta_kv VALUES(OLD.tenant, OLD.key, OLD.value); END`);
  const seal = h.f.sealAuditChain(h.p('security'));
  assert.ok((seal.head_watermark_tampered ?? []).some(e => e.kind === 'floor_marker_residue_retired_echo'),
    `the resurrected rows are named: ${JSON.stringify(seal.head_watermark_tampered)}`);
  h.f.store.db.exec('DROP TRIGGER IF EXISTS residue_zombie');
  h.close();
});

// ============================================================================
// Gate regressions — the shipped collectAuthorize runs verbatim against the
// w60 hostile shapes (w56 harness pattern).
// ============================================================================
import { readFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
const collectRun = (lines, verb) => {
  const src = readFileSync('scripts/check.mjs', 'utf8');
  const helpers = src.slice(src.indexOf('// === shared source scanners'), src.indexOf('// === end shared source scanners'));
  const block = src.slice(src.indexOf('const NONROLE'), src.indexOf('const authorizeAt'));
  assert.ok(block.includes('collectAuthorize'), 'the slice carries the shipped scanner');
  return JSON.parse(execFileSync(process.execPath, ['-e', [
    helpers, block,
    `globalThis.process.stdout.write(JSON.stringify(collectAuthorize(${JSON.stringify(lines)}, 0, ${lines.length + 2}, true, ${JSON.stringify(verb)})));`
  ].join('\n')], { encoding: 'utf8' }).trim());
};
const HEAD = "if (req.method === 'GET' && (m = /^\\/x\\/(.*)/.exec(path))) {";

// w60-fv F-1 / w60-ledger F-3/F-8: dead-condition bodies — every falsy-
// literal orthography — mint nothing; the live arm still mints.
test('w60 gate: dead-condition literals mint nothing', t => {
  const dead = ['0', '0.0', '0x0', '0b0', '0e0', "''", '""', 'NaN', 'false', 'null', 'undefined', 'void 0', '!true',
    'false || false', '1 < 0', '{} instanceof Array', "new Set() instanceof Map", '0 ? 1 : 2'];
  for (const cond of dead) {
    const r = collectRun([HEAD, `  if (m[1] === 'a') { if (${cond}) { authorize(p, ['dead']); } authorize(p, ['live']); }`, '}'], 'a');
    assert.deepEqual(r.roles, ['live'], `${cond}: dead arm minted`);
    assert.equal(r.any, true, `${cond}: the live authorize still counts as any`);
  }
  // The pure-dead route — nothing live at all — mints no any either.
  const r = collectRun([HEAD, "  if (m[1] === 'a') { if (0) authorize(p, ['dead']); }", '}'], 'a');
  assert.equal(r.any, false, 'a fully dead body mints no evidence at all');
});
test('w60 gate: dead for/while bodies mint nothing', t => {
  for (const cond of [
    'for (let i=0;i<0;i++) { authorize(p, [\'dead\']); }',
    'for (const x of []) { authorize(p, [\'dead\']); }',
    'for (const k in {}) { authorize(p, [\'dead\']); }',
    'while (false || false) { authorize(p, [\'dead\']); }',
    'while (new Set() instanceof Map) authorize(p, [\'dead\']);',
  ]) {
    const r = collectRun([HEAD, `  if (m[1] === 'a') { ${cond} authorize(p, ['live']); }`, '}'], 'a');
    assert.deepEqual(r.roles, ['live'], `${cond}: dead loop body minted`);
  }
  // Honest preserved: a live iterable still mints.
  const r = collectRun([HEAD, "  if (m[1] === 'a') { for (const x of items) { authorize(p, ['live']); } }", '}'], 'a');
  assert.ok(r.roles === null || r.roles.includes('live'), 'a live for-of body is conditional, not erased');
});
// w60-ledger F-7: a braceless own-verb arm mints exactly like the braced one.
test('w60-ledger F-7: braceless own-verb dispatch mints', t => {
  const r = collectRun([HEAD, "  if (m[1] === 'a') authorize(p, ['braceless']);", '}'], 'a');
  assert.deepEqual(r.roles, ['braceless']);
});
// w60-ledger F-2/F-5: the dead-operand span owns the next line only while
// the operand is genuinely open — an operator tail, open depth, or a
// continuation-start token; a `;` or ASI-complete operand ends it.
test('w60-ledger F-2/F-5: multiline dead operand swallows the operand, not the statement', t => {
  // Operand-start identifier — swallowed.
  assert.deepEqual(collectRun([HEAD, "  if (m[1] === 'a') { const x = false &&", "    authorize(p, ['dead']);", "    authorize(p, ['live']); }", '}'], 'a').roles,
    ['live'], 'the wrapped operand call is dead, the next statement is live');
  // ASI-complete operand — the next line is a fresh statement.
  assert.deepEqual(collectRun([HEAD, "  if (m[1] === 'a') { const x = false && f()", "    authorize(p, ['live']); }", '}'], 'a').roles,
    ['live'], 'false && f() ended by ASI — the authorize below is live');
  // A statement keyword ends the operand even mid-swallow.
  assert.deepEqual(collectRun([HEAD, "  if (m[1] === 'a') { const x = false &&", "    if (m[1] === 'a') authorize(p, ['live']); }", '}'], 'a').roles,
    ['live'], 'an if opens a new statement — not the operand');
  // An open-paren operand keeps owning lines until it closes.
  assert.deepEqual(collectRun([HEAD, "  if (m[1] === 'a') { const x = false && f(", "    authorize(p, ['dead'])", "  );", "    authorize(p, ['live']); }", '}'], 'a').roles,
    ['live'], 'the unclosed call arg stays dead across lines');
  // Comment-only line inside the operand does not disarm it.
  assert.deepEqual(collectRun([HEAD, "  if (m[1] === 'a') { const x = false &&", "    // a note", "    authorize(p, ['dead']);", "    authorize(p, ['live']); }", '}'], 'a').roles,
    ['live'], 'a comment line inside the operand does not rescue it');
});
// w60-fv F-3: a self-contained one-line block does not pop its enclosing
// sibling frame — the nested contradict stays dead.
test('w60-fv F-3: same-line nested contradict arm stays dead', t => {
  assert.deepEqual(collectRun([HEAD, "  if (m[1] === 'b') { if (m[1] === 'a') authorize(p, ['nested']); }", '}'], 'a').roles,
    null, 'a nested arm under a same-member sibling can never run');
});
// w60-fv F-4: surface-spelling aliases bind the resolved member — a
// same-member contradict through an alias is still a contradict.
test('w60-fv F-4: dispatch aliases resolve to the member they carry', t => {
  assert.deepEqual(collectRun([HEAD, "  const sub = m[1];", "  if (sub === 'a') { authorize(p, ['alias']); }", '}'], 'a').roles,
    ['alias'], 'the aliased compare mints for its verb');
  assert.deepEqual(collectRun([HEAD, "  const sub = m[1];", "  if (m[1] === 'b') { if (sub === 'a') authorize(p, ['nested']); }", '}'], 'a').roles,
    null, 'sub===a under m[1]===b is a same-member contradict');
  // A rebound name no longer resolves.
  assert.deepEqual(collectRun([HEAD, "  const sub = m[1]; sub = 'z';", "  if (sub === 'a') { authorize(p, ['rb']); }", '}'], 'a').roles,
    null, 'a rebound alias is dead weight');
  // Chained aliases resolve transitively.
  assert.deepEqual(collectRun([HEAD, "  const sub = m[1]; const s2 = sub;", "  if (s2 === 'a') { authorize(p, ['ch']); }", '}'], 'a').roles,
    ['ch'], 'sub2 = sub carries the member');
});
// w60-fv F-2 / w60-ledger F-6: dead function declarations — decl shapes a
// regex list used to miss — mint nothing; any real use position revives.
test('w60-fv F-2/F-6: dead fn decls die, used decls live', t => {
  // Dead — no invocation spelling escapes the body.
  for (const decl of [
    "function g() { authorize(p, ['dead']); }",
    "function* g() { authorize(p, ['dead']); }",
    "const o = { g: function() { authorize(p, ['dead']); } };",
    "const o = { g: () => authorize(p, ['dead']) };",
    "const o = { g() { authorize(p, ['dead']); } };",
    "class K { static g() { authorize(p, ['dead']); } };",
  ]) {
    const r = collectRun([HEAD, `  if (m[1] === 'a') { ${decl}`, "    authorize(p, ['live']); }", '}'], 'a');
    assert.deepEqual(r.roles, ['live'], `${decl}: an uncalled declaration minted`);
  }
  // Live — every real use spelling revives the decl.
  for (const use of ['g()', 'g.call(null)', 'g?.()', 'foo(g)', 'setTimeout(g, 0)', 'g`x`', 'x = g']) {
    const r = collectRun([HEAD, `  if (m[1] === 'a') { function g() { authorize(p, ['revived']); } ${use};`, "    authorize(p, ['live']); }", '}'], 'a');
    assert.ok((r.roles ?? []).includes('revived'), `${use}: a live invocation left its body dead`);
  }
});

// ---------------------------------------------------------------------------
// traceability.py — run the real gate functions on crafted bodies.
// ---------------------------------------------------------------------------
const pyEval = (expr) => execFileSync('python3', ['-c',
  `import json\nsrc=open('scripts/traceability.py').read()\ng={'__file__':'scripts/traceability.py'}\nexec(src[:src.index('def evidence_blocks')], g)\nprint(${expr})`], { encoding: 'utf8' }).trim();
const pyLive = (code) => pyEval(`g['_live_code'](g['_blank_code'](${JSON.stringify(code)}), ${JSON.stringify(code)})`);
const pyAsserts = (code) => pyEval(`g['_asserts'](${JSON.stringify(code)}, {'assert','ok','strictEqual','throws'})`);

// w60-fv F-6: the second `?` of `??` must not match the ternary arm — a
// nullish left keeps the RHS live.
test('w60-fv F-6: ?? RHS survives a nullish left', t => {
  assert.ok(pyLive("const a = null; a ?? assert.stay();").includes('assert.stay'),
    'null ?? assert runs the assert');
  assert.ok(pyLive("const a = undefined; a ?? assert.stay();").includes('assert.stay'),
    'undefined ?? assert runs the assert');
  assert.ok(pyLive("const a = f(); a ?? assert.stay();").includes('assert.stay'),
    'a call-result binding keeps the ?? arm live');
  assert.ok(!pyLive("const a = 5; a ?? assert.dead();").includes('assert.dead'),
    'a non-nullish left still kills the ?? arm');
});
// w60-fv F-7: comparison chains fold left-associatively and instanceof with
// a provable left folds too.
test('w60-fv F-7: chained comparisons and instanceof fold', t => {
  assert.ok(!pyLive("(1 === 1 === 1) && assert.dead();").includes('assert.dead'),
    '(1===1)===1 is false — dead');
  assert.ok(!pyLive("({}) instanceof K && assert.dead();").includes('assert.dead'),
    'a literal object is no K instance — dead');
  assert.ok(!pyLive("new Set() instanceof Map && assert.dead();").includes('assert.dead'),
    'new Set() is no Map — dead');
  assert.ok(pyLive("new Set() instanceof Set && assert.live();").includes('assert.live'),
    'new Set() IS a Set — live');
  assert.ok(pyLive("x instanceof K && assert.live();").includes('assert.live'),
    'an unknown left keeps instanceof live');
});
// w60-fv F-8 / w60-ledger F-12: optional and computed assert spellings.
test('w60-fv F-8/F-12: spaced/optional/computed assert spellings count', t => {
  assert.equal(pyAsserts("assert ?. ok(1)"), '1', 'assert ?. ok counts');
  assert.equal(pyAsserts("assert?.(1)"), '1', 'assert?.( counts');
  assert.equal(pyAsserts("assert['ok'](1)"), '1', 'computed-member assert counts');
  assert.equal(pyAsserts("assert.ok?.(1)"), '1', 'optional method call counts');
  assert.equal(pyAsserts("x.assert.ok(1)"), '0', 'a nested member chain is still not the binding');
});
// w60-fv F-5: method definitions with defaults/rest do not mint.
test('w60-fv F-5: multi-param method defs are not assert calls', t => {
  assert.equal(pyAsserts("const o = { assert(a = 1, ...rest) {} }; o.assert(x, y)"), '0',
    'a defaulted/rest method def is not the binding');
  assert.equal(pyAsserts("const o = { assert({ x } = {}, [y] = []) {} }; o.assert(1)"), '0',
    'a destructured-param method def is not the binding');
});
// w60-ledger F-10: `.only` is a live boundary; nested option objects do not
// truncate early.
test('w60-ledger F-10: .only mints a body; nested options parse balanced', t => {
  const only = pyEval(`len(g['_test_bodies'](${JSON.stringify("test.only('REQ-1', () => { assert.ok(1); })")}))`);
  assert.equal(only, '1', '.only is a live test boundary');
  const skip = pyEval(`len(g['_test_bodies'](${JSON.stringify("describe.skip('g', () => { it('x', () => assert.ok(1)); })")}))`);
  assert.equal(skip, '0', 'skipped suites still mint nothing');
  const nested = pyEval(`len(g['_test_bodies'](${JSON.stringify("test('R', { nested: { skip: {} } }, () => assert.ok(1))")}))`);
  assert.equal(nested, '1', 'a nested option object does not truncate the options arg');
});
// w60-fv F-9: a spaced member call is not a test boundary.
test('w60-fv F-9: x . it( is a member call, not a boundary', t => {
  const out = pyEval(`len(g['_test_bodies'](${JSON.stringify("x . it('R', () => assert.ok(1))")}))`);
  assert.equal(out, '0', 'a spaced member call mints no test body');
});
// w60-ledger F-11: only value-side destructures that bind `assert` neuter
// the vocabulary.
test('w60-ledger F-11: renamed destructures bind only the names they take', t => {
  assert.equal(pyAsserts("const { y } = fake; assert.ok(1)"), '1',
    'a destructure that does not bind assert keeps it');
  assert.equal(pyAsserts("const { assert } = fake; assert.ok(1)"), '0',
    'a destructure binding assert neuters it');
  assert.equal(pyAsserts("const { z: assert } = fake; assert.ok(1)"), '0',
    'a renamed destructure to assert neuters it');
});
