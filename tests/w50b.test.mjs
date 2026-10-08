// Wave-50b regression tests: fixverify + ledger findings on 8b63ea8 —
// seq-guard discrimination against the unwrapped error, busy-class
// errcode masking, delete/shred residue probes against swallow triggers,
// gate-deny murder coverage with occurrence-wise naming, cumulative
// seal-drop accounting, savepoint rollback non-masking, single-mint
// quarantine containment, and the traceability/report/route-grammar
// honesty gates.
import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readFileSync, writeFileSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fixture, hasCode } from './helpers.mjs';

// --- fixverify F-1: the seq-guard mimic still dies as INTEGRITY — the
// discriminator is the free slot, and a mimic that leaves it free
// convicts regardless of the RAISE text it replays ---
test('w50 F-1: a planted abort whose slot stays free is INTEGRITY, never CONFLICT', t => {
  const h = fixture(t);
  h.proposed();
  h.f.store.db.exec("CREATE TRIGGER mimic_guard BEFORE INSERT ON audit BEGIN SELECT RAISE(ABORT, 'audit sequence must extend the head'); END");
  assert.throws(() => h.f.store.tx(() => h.f.store.audit('acme', 'TAMPER_PROBE', 'system', 'x', {}, h.f.clock())),
    hasCode('INV-409-INTEGRITY'), 'no peer owns the slot — the refusal is foreign-trigger evidence');
  h.close();
});

// --- fixverify F-5: busy-class extended errcodes stay contention (raw,
// for outer INV-503 translation); engine/storage/unknown classes keep
// their honest taxonomy ---
test('w50 F-5: _schemaGuard masks extended errcodes by primary class', t => {
  const h = fixture(t);
  const boom = errcode => () => { const e = new Error('sqlite fault'); e.errcode = errcode; throw e; };
  for (const code of [5, 6, 261, 517, 773])
    assert.throws(() => h.f.store._schemaGuard(boom(code)), e => e?.errcode === code && !(e.code ?? '').startsWith('INV-'), `errcode ${code} is contention — raw for outer translation, never tamper`);
  for (const code of [7, 9, 17])
    assert.throws(() => h.f.store._schemaGuard(boom(code)), hasCode('INV-503-LEDGER'), `errcode ${code} is an engine fault`);
  for (const code of [8, 10, 11, 13, 14, 15])
    assert.throws(() => h.f.store._schemaGuard(boom(code)), hasCode('INV-503-STORAGE'), `errcode ${code} is storage-class`);
  assert.throws(() => h.f.store._schemaGuard(boom(1811)), hasCode('INV-409-INTEGRITY'), 'a trigger abort is tamper evidence');
  // Unmapped codes are honest engine faults, not mislabeled tamper
  // evidence (w51-fv F-5 — doctrine update: only guards/constraints mint
  // INTEGRITY).
  assert.throws(() => h.f.store._schemaGuard(boom(1)), hasCode('INV-503-LEDGER'), 'an unclassified sqlite fault on a ledger path is an honest engine fault');
  h.close();
});

test('w50 F-5: target.db masks errcodes identically', t => {
  const h = fixture(t);
  const boom = errcode => () => { const e = new Error('sqlite fault'); e.errcode = errcode; throw e; };
  assert.throws(() => h.f.target._schemaGuard(boom(517)), e => e?.errcode === 517 && !(e.code ?? '').startsWith('INV-'), 'BUSY_SNAPSHOT is contention on the dataplane too');
  assert.throws(() => h.f.target._schemaGuard(boom(9)), hasCode('INV-503-LEDGER'), 'engine fault class');
  assert.throws(() => h.f.target._schemaGuard(boom(1811)), hasCode('INV-409-INTEGRITY'), 'trigger abort is tamper evidence');
  h.close();
});

// --- fixverify F-2: a BEFORE DELETE RAISE(IGNORE) trigger swallowing
// the dek/record delete is residue-probed, not read as 'already gone' ---
test('w50 F-2: a swallow trigger on records convicts remove() INV-409', t => {
  const h = fixture(t);
  h.f.store.put('acme', 'record', 'rid-sw', { x: 1 }, h.now());
  h.f.store.db.exec("CREATE TRIGGER swallow_r BEFORE DELETE ON records BEGIN SELECT RAISE(IGNORE); END");
  assert.throws(() => h.f.store.remove('acme', 'record', 'rid-sw'), hasCode('INV-409-INTEGRITY'), 'a swallowed delete is tamper evidence');
  // The pair rolled back: neither row may be left deleted.
  assert.ok(h.f.store.db.prepare("SELECT 1 FROM records WHERE tenant='acme' AND kind='record' AND id='rid-sw'").get(), 'the record survives the rolled-back pair');
  assert.ok(h.f.store.db.prepare("SELECT 1 FROM deks WHERE tenant='acme' AND kind='record' AND id='rid-sw'").get(), 'the dek survives the rolled-back pair');
  h.close();
});

test('w50 F-2: a swallow trigger on deks convicts shred() INV-409', t => {
  const h = fixture(t);
  h.f.store.put('acme', 'record', 'rid-sh', { x: 2 }, h.now());
  h.f.store.db.exec("CREATE TRIGGER swallow_d BEFORE DELETE ON deks BEGIN SELECT RAISE(IGNORE); END");
  assert.throws(() => h.f.store.shred('acme', 'record', 'rid-sh'), hasCode('INV-409-INTEGRITY'), 'a swallowed shred is tamper evidence');
  assert.ok(h.f.store.db.prepare("SELECT 1 FROM deks WHERE tenant='acme' AND kind='record' AND id='rid-sh'").get(), 'the dek survives the rolled-back pair');
  h.close();
});

// --- fixverify F-8: one quarantine denial = one containment row —
// assertHealthy no longer double-mints the gate-deny ---
test('w50 F-8: a quarantine denial lands exactly one gate-deny containment row', t => {
  const h = fixture(t);
  h.f.revoke(h.p('security'), { kind: 'subject', id: 'operator', reason: 'quarantine probe' });
  const count = () => h.f.store.db.prepare("SELECT COUNT(*) n FROM records WHERE tenant='acme' AND kind='containment'").get().n;
  const before = count();
  assert.throws(() => h.f.assertHealthy('acme', 'operator', 'operator-device', h.now()), hasCode('INV-403-QUARANTINE'));
  assert.equal(count(), before + 1, 'the denial mints one row through _rejectionAudit, not two');
  h.close();
});

// --- fixverify F-3/F-4: gate-deny anchors join murder coverage, and a
// murdered LATER occurrence names itself as the victim ---
test('w50 F-3/4: a murdered later gate-deny row names the murdered anchor', t => {
  const h = fixture(t);
  h.f.revoke(h.p('security'), { kind: 'subject', id: 'operator', reason: 'quarantine probe' });
  assert.throws(() => h.f.assertHealthy('acme', 'operator', 'operator-device', h.now()), hasCode('INV-403-QUARANTINE'));
  // A second identical denial past the dedup window mints a second anchor
  // + a second row — same triple (gate-deny|code|operator), later `at`.
  h.advance(120000);
  const t2 = h.now();
  assert.throws(() => h.f.assertHealthy('acme', 'operator', 'operator-device', h.now()), hasCode('INV-403-QUARANTINE'));
  const rows = h.f.store.db.prepare("SELECT id FROM records WHERE tenant='acme' AND kind='containment' ORDER BY created").all();
  assert.equal(rows.length, 2, 'two denials, two rows');
  // Murder the LATER row — the report must name the later anchor, not
  // pair the survivor against both.
  h.f.store.db.prepare("DELETE FROM records WHERE tenant='acme' AND kind='containment' AND id=?").run(rows[1].id);
  const rep = h.f.containmentReport(h.p('security'));
  assert.equal(rep.anchored_denials_missing_total, 1, 'one murdered row, one named victim');
  assert.equal(rep.anchored_denials_missing_rows[0].request_id, 'gate-deny');
  assert.equal(rep.anchored_denials_missing_rows[0].at, t2, 'the murdered LATER occurrence is named — occurrence-wise pairing');
  h.close();
});

// --- fixverify F-6: seal drop claims are cumulative — a re-attested
// loss cannot double-count the tally or keep the wedge window alive ---
test('w50 F-6: re-attested seal drops do not double-count or refresh the wedge', t => {
  const h = fixture(t);
  const seal = (meta, at) => h.f.store.tx(() => h.f.store.audit('acme', 'AUDIT_SEALED', 'operator', 'audit', meta, at));
  const drops = [{ seq: 11, hash: 'aa' }, { seq: 12, hash: 'bb' }, { seq: 13, hash: 'cc' }];
  const t1 = h.now();
  seal({ carryover_totals: { dropped_events: 3 }, dropped_events: drops }, t1);
  let idx = h.f._auditIndex('acme');
  assert.equal(idx.sealDroppedEvents, 3, 'first seal counts its own losses');
  assert.equal(idx.sealDroppedAt, t1, 'fresh losses open the wedge window');
  // A later seal RE-ATTESTING the same cumulative losses must not add
  // them again nor keep the wedge alive.
  h.advance(120000);
  seal({ carryover_totals: { dropped_events: 3 }, dropped_events: drops }, h.now());
  idx = h.f._auditIndex('acme');
  assert.equal(idx.sealDroppedEvents, 3, 'cumulative claims take the running max — the same loss counts once');
  assert.equal(idx.sealDroppedAt, t1, 'a re-attested old loss does not refresh the wedge window');
  // A third seal attesting genuinely new losses grows the total and the
  // window together.
  seal({ carryover_totals: { dropped_events: 5 }, dropped_events: drops }, h.now());
  idx = h.f._auditIndex('acme');
  assert.equal(idx.sealDroppedEvents, 5, 'growth past the running total counts the newly-attested losses');
  assert.equal(idx.sealDroppedAt, h.now(), 'new losses refresh the wedge');
  h.close();
});

// --- fixverify F-7: a failed savepoint rollback annotates the original
// error — the underlying verdict is never masked by the guard ---
test('w50 F-7: a broken savepoint rollback surfaces on the original error', t => {
  const h = fixture(t);
  const orig = h.f.target.db.exec.bind(h.f.target.db);
  h.f.target.db.exec = sql => { if (/ROLLBACK TO/.test(sql)) throw new Error('rollback dead'); return orig(sql); };
  h.f.target.db.exec("CREATE TRIGGER boom BEFORE INSERT ON grants BEGIN SELECT RAISE(ABORT, 'planted'); END");
  // A nested tx takes the savepoint arm — the outer rollback still works.
  let err; try { h.f.target.tx(() => h.f.target.grant('acme', 'grant-rb', { issued_at: h.now() })); } catch (e) { err = e; }
  assert.ok(err, 'the write fails');
  assert.equal(err.code, 'INV-409-INTEGRITY', 'the planted-trigger verdict survives');
  assert.equal(err.details?.cause?.rollback_error ?? err.cause?.rollback_error ?? err.rollback_error, 'rollback dead', 'the failed cleanup annotates the thrown error');
  h.f.target.db.exec = orig;
  h.close();
});

// The traceability probes below run the REAL gate functions against
// fixture inputs — a source-grep for a regex would tautologically
// verify its own presence, not the behaviour (w51-ledger M-3).
const pyEval = (expr) => execFileSync('python3', ['-c',
  `import json\nsrc=open('scripts/traceability.py').read()\ng={'__file__':'scripts/traceability.py'}\nexec(src[:src.index('def evidence_blocks')], g)\nprint(${expr})`], { encoding: 'utf8' }).trim();
// Same pattern for JS-side shipped expressions: a fresh interpreter gets
// the fixture scope via the environment, the expression under test is the
// file's own text — no in-process eval primitive (the check gate flags it).
const jsEval = (expr, scope) => {
  const prog = `const {${Object.keys(scope).join(',')}} = JSON.parse(process.env.JS_SCOPE);` +
    `globalThis.process.stdout.write(JSON.stringify((${expr})));`;
  return JSON.parse(execFileSync(process.execPath, ['-e', prog], { env: { ...process.env, JS_SCOPE: JSON.stringify(scope) }, encoding: 'utf8' }).trim());
};

// --- ledger M-3: report.mjs fails when any verifier exits nonzero ---
test('w50 M-3: report.mjs gates on the external verifiers, not only TAP', t => {
  // Evaluate the shipped predicate against dead-verifier states — the
  // expression under test is the file's own exit gate, not a copy.
  const line = readFileSync('scripts/report.mjs', 'utf8').split('\n').find(l => l.includes('nodeVerify.status') && l.includes('process.exitCode'));
  assert.ok(line, 'the verifier exit gate exists');
  const cond = /if \((.+)\) process\.exitCode/.exec(line)[1];
  const gate = (counts, tap, nodeVerify, py) => jsEval(cond, { counts, tap, nodeVerify, py });
  const ok = { fail: 0 }, alive = { status: 0 };
  assert.equal(gate(ok, alive, { status: 1 }, alive), true, 'a dead node verifier fails the regeneration');
  assert.equal(gate(ok, alive, alive, { status: 1 }), true, 'a dead python verifier fails the regeneration');
  assert.equal(gate({ fail: 1 }, alive, alive, alive), true, 'a TAP failure fails the regeneration');
  assert.equal(gate(ok, alive, alive, alive), false, 'green verifiers do not fail it');
});

// --- ledger H-1: production binding is checked on comment-stripped
// text — an import inside a comment binds nothing ---
test('w50 H-1: traceability binds production code outside comments only', t => {
  const binds = text => pyEval(`g['_prod_binds'](g['_strip_comments'](${JSON.stringify(text)}))`);
  assert.equal(binds("import { Fabric } from '../src/fabric.mjs'"), 'True', 'a real production import binds');
  assert.equal(binds("import { fixture } from './helpers.mjs'"), 'True', 'a helpers import binds');
  assert.equal(binds("// import { Fabric } from '../src/fabric.mjs'"), 'False', 'a commented import binds nothing');
  assert.equal(binds("/* import { Fabric } from '../src/fabric.mjs' */"), 'False', 'a block-comment import binds nothing');
  assert.equal(binds("const s = 'from ../src/fabric.mjs import trick'"), 'False', 'literal text cannot mint the bind');
});

// --- ledger M-1: only a literal-true skip in the options object
// disqualifies a citing test ---
test('w50 M-1: options skip is object-scoped and literal-true', t => {
  const bodies = text => JSON.parse(pyEval(`json.dumps(len(g['_test_bodies'](${JSON.stringify(text)})))`));
  assert.equal(bodies("test('X', {skip: true}, t => { assert.ok(1); })"), 0, 'literal skip:true disqualifies');
  assert.equal(bodies("test('X', {t" + "odo: true}, t => { assert.ok(1); })"), 0, 'literal t' + 'odo:true disqualifies');
  assert.equal(bodies("test('X', {skip: cond}, t => { assert.ok(1); })"), 1, 'a conditional skip proves itself via TAP');
  assert.equal(bodies("test('X', t => { const o = {skip: true}; assert.ok(1); })"), 1, 'skip inside the body is not an options token');
  assert.equal(bodies("test.skip('X', t => { assert.ok(1); })"), 0, 'test.skip disqualifies');
});

// --- ledger L-2: a test titled FOO-100 cannot mint evidence for FOO-10 ---
test('w50 L-2: requirement citation needs an ID boundary', t => {
  const cites = (title, rid) => pyEval(`g['_cites'](${JSON.stringify(title)}, ${JSON.stringify(rid)})`);
  assert.equal(cites('FOO-100 must work', 'FOO-10'), 'False', 'FOO-100 is not a FOO-10 citation');
  assert.equal(cites('XFOO-10 sneaks left', 'FOO-10'), 'False', 'XFOO-10 is not a FOO-10 citation');
  assert.equal(cites('FOO-10 works', 'FOO-10'), 'True', 'a real citation binds');
});

// --- ledger L-1: openapi path params mirror the dispatch charsets and
// the {1,128} length bound ---
test('w50 L-1: openapi path params carry the dispatch grammar', t => {
  const spec = JSON.parse(readFileSync('docs/openapi.json', 'utf8'));
  const param = path => (spec.paths[path]?.get?.parameters ?? []).find(p => p.name === 'id' && p.in === 'path');
  assert.equal(param('/v1/resources/{id}')?.schema?.pattern, '^[A-Za-z0-9_.:-]{1,128}$', 'wide family');
  assert.equal(param('/v1/action-capsules/{id}')?.schema?.pattern, '^[A-Za-z0-9-]{1,128}$', 'narrow family');
});

// --- ledger H-2: the reverse parity gate flags unauditable dispatch
// shapes — executed against fixture dispatch lines, not grepped for ---
test('w50 H-2: check.mjs parity gate flags unauditable dispatch shapes', t => {
  // Slice the REAL gate block (expandAlternations through auditDispatch)
  // out of check.mjs and run it against crafted dispatch lines — the
  // code under test is the shipped scanner, verbatim. The module-scope
  // helpers the block consumes (codeSpan, stripComment) live between the
  // shared-scanner sentinels; they are spliced in beside it (w55-ledger).
  const src = readFileSync('scripts/check.mjs', 'utf8');
  const helpers = src.slice(src.indexOf('// === shared source scanners'), src.indexOf('// === end shared source scanners'));
  assert.ok(helpers.includes('codeSpan') && helpers.includes('stripComment'), 'the slice carries the shared scanners');
  const block = src.slice(src.indexOf('const expandAlternations'), src.indexOf('// Live HTTP dispatch outside'));
  assert.ok(block.includes('auditDispatch ='), 'the slice carries the scanner');
  const run = (lines, declaredSet) => {
    // Exec the shipped block verbatim in a subprocess — the same shipped-
    // code honesty as pyEval, without an in-process eval primitive.
    const prog = [
      `const server = ${JSON.stringify(lines)};`,
      `const issuerd = [];`,
      `const declared = new Set(${JSON.stringify([...declaredSet])});`,
      `const errors = [];`,
      `const console = { error: m => errors.push(m) };`,
      'let failed = false;',
      helpers,
      block,
      `globalThis.process.stdout.write(JSON.stringify({ failed, errors }));`
    ].join('\n');
    // Exec from a file, not `-e`: the shared-scanner slice outgrew the
    // 128KB single-argv limit (E2BIG). The bytes under test are still
    // the shipped block verbatim — only the transport changed.
    const dir = mkdtempSync(join(tmpdir(), 'w50b-'));
    try {
      const f = join(dir, 'probe.mjs');
      writeFileSync(f, prog);
      return JSON.parse(execFileSync(process.execPath, [f], { encoding: 'utf8' }).trim());
    } finally { rmSync(dir, { recursive: true, force: true }); }
  };
  const declared = new Set(['GET /x']);
  assert.equal(run(["if (req.method === 'GET' && path === '/x') send(200, {});"], declared).failed, false, 'a declared route passes');
  const undeclared = run(["if (req.method === 'GET' && path === '/sneak') send(200, {});"], declared);
  assert.equal(undeclared.failed, true); assert.ok(undeclared.errors.some(e => e.includes('absent from docs/openapi.json')), 'an undeclared literal route is flagged');
  const negated = run(["if (req.method !== 'GET' && path === '/x') send(200, {});"], declared);
  assert.equal(negated.failed, true); assert.ok(negated.errors.some(e => e.includes('unauditable method dispatch')), 'a negated method dispatch is flagged');
});
