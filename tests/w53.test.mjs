import test from 'node:test';
import assert from 'node:assert/strict';
import { fixture, hasCode, runtimeInput, runtimeRequest } from './helpers.mjs';
import { execFileSync } from 'node:child_process';
import { readFileSync, writeFileSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

// Wave-53 runtime auditor regressions (report on 66bfe80): the
// uncommitted-attestation binding laundered murdered rows, the
// subject-revoked probe was silent, and a refused containment put rolled
// the denial anchor back with the row.

// F-1 (HIGH): a CONTAINMENT_ROW_UNCOMMITTED attestation must bind the
// anchor that minted it — not any time-adjacent denial. One denied
// consume under a gate-deny-only put trigger mints two uncommitted
// attestations while the RUNTIME_DENIED row commits; deleting that row
// must name murder, never zero.
test('w53-runtime F-1: uncommitted attestations pin their owning anchor — a murdered committed row cannot launder into them', t => {
  const h = fixture(t);
  const cap = h.f.runtime.issue(h.p('operator'), runtimeInput());
  h.f.revoke(h.p('security'), { kind: 'device', id: 'operator-device', reason: 'w53 probe' });
  const containmentRows = () => h.f.store.db.prepare("SELECT id FROM records WHERE tenant='acme' AND kind='containment'").all();
  // The gate-deny puts (id 'deny:<uuid>') are refused; the runtime deny
  // row (id 'deny:<uuid>:<code>') carries a second colon and commits.
  h.f.store.db.exec("CREATE TRIGGER deny_put BEFORE INSERT ON records WHEN NEW.kind='containment' AND NEW.id LIKE 'deny:%' AND NEW.id NOT LIKE 'deny:%:%' BEGIN SELECT RAISE(ROLLBACK,'planted'); END");
  assert.throws(() => h.f.runtime.consume(h.p('operator'), runtimeRequest(cap)), hasCode('INV-403-QUARANTINE'));
  const rows = containmentRows();
  assert.equal(rows.length, 1, 'the runtime-deny row committed while both gate-deny puts were refused');
  h.f.store.db.prepare("DELETE FROM records WHERE tenant='acme' AND kind='containment' AND id=?").run(rows[0].id);
  const rep = h.f.containmentReport(h.p('security'));
  assert.equal(rep.anchored_denials_missing_total, 1, 'the murdered committed row is named — it cannot absorb a neighbouring uncommitted attestation');
  assert.equal(rep.anchored_denials_rows_uncommitted.length, 2, 'both refused gate-deny puts still read as named uncommitted, not murder');
  h.close();
});

// F-2 (MEDIUM): a revoked-subject probe used to mint nothing at all —
// authorize() threw without quarantine details. The denial must land the
// same anchor + containment row a device quarantine produces.
test('w53-runtime F-2: a revoked-subject probe anchors its denial and lands the containment row', t => {
  const h = fixture(t);
  h.f.revoke(h.p('security'), { kind: 'subject', id: 'operator', reason: 'w53 probe' });
  const rows = () => h.f.store.db.prepare("SELECT COUNT(*) n FROM records WHERE tenant='acme' AND kind='containment'").get().n;
  const before = rows();
  assert.throws(() => h.f.runtime.consume(h.p('operator'), {}), hasCode('INV-403-QUARANTINE'));
  assert.equal(rows(), before + 1, 'the subject-revoke denial lands a containment row like a device quarantine');
  const denied = h.f.store.db.prepare("SELECT COUNT(*) n FROM audit WHERE tenant='acme' AND envelope LIKE '%AUTHORIZATION_DENIED%'").get().n;
  assert.ok(denied >= 1, 'the denial is anchored on the signed chain');
  h.close();
});

// F-3 (LOW): a refused containment put used to roll the RUNTIME_DENIED
// anchor back with the row — zero evidence for a denied consume. The
// anchor now commits first and the non-commit attests itself.
test('w53-runtime F-3: a refused containment put attests the non-commit — the denial anchor survives', t => {
  const h = fixture(t);
  const cap = h.f.runtime.issue(h.p('operator'), runtimeInput());
  h.f.revoke(h.p('security'), { kind: 'device', id: 'operator-device', reason: 'w53 probe' });
  h.f.store.db.exec("CREATE TRIGGER deny_put BEFORE INSERT ON records WHEN NEW.kind='containment' BEGIN SELECT RAISE(ROLLBACK,'planted'); END");
  assert.throws(() => h.f.runtime.consume(h.p('operator'), runtimeRequest(cap)), hasCode('INV-403-QUARANTINE'));
  const types = h.f.store.db.prepare("SELECT envelope FROM audit WHERE tenant='acme' ORDER BY seq").all().map(r => JSON.parse(r.envelope).payload.type);
  assert.ok(types.includes('RUNTIME_DENIED'), 'the denial anchored even though its row put was refused');
  assert.ok(types.includes('CONTAINMENT_ROW_UNCOMMITTED'), 'the refused put is named on the chain');
  h.close();
});

// --- w53 fixverify + seal wave (audits on 66bfe80): the traceability
// assert-gate evasions, the dead marker-hash half, the ledger chmod
// taxonomy, the wm 'signed' presence check, the floor-marker false
// positives, and the survivingTip off-by-one.

const dropAuditGuards = h => {
  for (const tr of h.f.store.db.prepare("SELECT name FROM sqlite_master WHERE type='trigger' AND tbl_name='audit'").all())
    h.f.store.db.exec(`DROP TRIGGER "${tr.name}"`);
};
const maxSeq = h => h.f.store.db.prepare("SELECT COALESCE(MAX(seq),0) m FROM audit WHERE tenant='acme'").get().m;
const auditRows = (h, like) => h.f.store.db.prepare("SELECT seq, envelope FROM audit WHERE tenant='acme' AND envelope LIKE ? ORDER BY seq").all(like).map(r => ({ seq: r.seq, meta: JSON.parse(r.envelope).payload.metadata ?? {} }));

// fv H-1: shadowed asserts (catch-param, bare for-head) and emitter-dead
// asserts must all fail the shipped traceability gate.
test('w53-fv H-1: catch-param, for-head and emitter shadows cannot mint evidence', t => {
  const py = `g={'__file__':'scripts/traceability.py'}
s=open('scripts/traceability.py').read()
exec(s[:s.index('def evidence_blocks')], g)
print(bool(g['_asserts']("test('X', () => { try { y(); } catch (assert) { assert.ok(false); } })")))
print(bool(g['_asserts']("test('X', () => { for (assert of z) assert.ok(false); })")))
print(bool(g['_asserts']("test('X', () => { for (const assert of z) assert.ok(false); })")))
print(bool(g['_asserts']("test('X', () => { process.on('uncaughtException', () => assert.ok(false)); })")))
print(bool(g['_asserts']("test('X', () => { emitter.on('x', () => assert.equal(1, 2)); })")))
print(bool(g['_asserts']("test('X', () => { assert.ok(1); })")))`;
  const out = execFileSync('python3', ['-c', py], { cwd: new URL('..', import.meta.url).pathname, encoding: 'utf8' }).trim().split('\n');
  assert.deepEqual(out, ['False', 'False', 'False', 'False', 'False', 'True'], 'every neutralized assert must fail; a live assert still passes');
});

// fv M-2: the marker's {tip_hash} half binds — a marker naming a real seq
// with a foreign hash is floor_marker_forged, not silent.
test('w53-fv M-2: a fold_floor marker with a foreign tip hash convicts floor_marker_forged', t => {
  const h = fixture(t);
  h.ready(); h.ready();
  h.f._auditIndex('acme');
  const tip = maxSeq(h);
  h.f.store.db.prepare("UPDATE meta_kv SET value=? WHERE tenant='acme' AND key='fold_floor'").run(`${tip}:${'0'.repeat(64)}`);
  const r = h.f.sealAuditChain(h.p('security'));
  assert.ok((r.head_watermark_tampered ?? []).some(e => e.kind === 'floor_marker_forged'), 'the hand-written marker is named as forged');
  h.close();
});

// fv M-4: the outside-scan regex itself must flag a req.url-only
// dispatch surface.
test('w53-fv M-4: the dispatch-parity scan flags req.url/req.headers-only surfaces', t => {
  const src = readFileSync(new URL('../scripts/check.mjs', import.meta.url), 'utf8');
  const m = /if \((\/[^/]+\/)\.test\(readFileSync\(p, 'utf8'\)\)\)/.exec(src);
  assert.ok(m, 'the parity predicate is present');
  const re = new RegExp(m[1].slice(1, -1));
  assert.ok(re.test("require('http').createServer((req,res)=>{ if(req.url==='/v1/x') res.end('x'); })"), 'req.url dispatch flags');
  assert.ok(re.test("const h=(req,res)=>{ if(req.headers['x-key']) res.end('k'); }"), 'req.headers dispatch flags');
  assert.ok(re.test("createServer((q,r)=>{})"), 'server factory flags');
});

// seal M-1: a forged wm entry never mints abandoned_watermark_signed —
// 'signed' means the envelope verifies, not that a field exists.
test('w53-seal M-1: a non-verifying watermark entry is not signed evidence', t => {
  const h = fixture(t);
  h.ready(); h.ready(); h.ready();
  const tip = maxSeq(h);
  // A file-writer's forged-high entry: a seq above the tip with
  // non-verifying envelope bytes.
  writeFileSync(join(h.directory, 'head-watermark.json'), JSON.stringify({ format: 'IF-HEADMARK-1', tenants: { acme: { seq: tip + 10, envelope: 'forged-bytes-not-a-signature' } } }) + '\n');
  dropAuditGuards(h);
  const cutAt = tip - 4;
  h.f.store.db.prepare("UPDATE audit SET envelope=? WHERE tenant='acme' AND seq=?").run('{"payload":{"time":1},"signatures":[{"signature":"AA"}]}', cutAt);
  const r = h.f.sealAuditChain(h.p('security'));
  const reanchored = auditRows(h, '%AUDIT_WM_REANCHORED%');
  assert.ok(reanchored.length >= 1, 'a floor retreat is still attested');
  assert.equal(reanchored.at(-1).meta.abandoned_watermark_signed, false, 'a forged entry never reads as signed');
  h.close();
});

// seal M-2a: an honest cut seal never self-reports floor_marker_ahead —
// the signed head still attests the deleted span mid-cut.
test('w53-seal M-2a: the sanctioned delete window does not self-convict', t => {
  const h = fixture(t);
  h.ready(); h.ready(); h.ready();
  dropAuditGuards(h);
  const tip = maxSeq(h);
  h.f.store.db.prepare("UPDATE audit SET envelope=? WHERE tenant='acme' AND seq=?").run('{"payload":{"time":1},"signatures":[{"signature":"AA"}]}', tip - 2);
  const r = h.f.sealAuditChain(h.p('security'));
  assert.equal(r.sealed, true);
  assert.ok(!(r.head_watermark_tampered ?? []).some(e => e.kind === 'floor_marker_ahead'), 'the cut window is not tamper evidence');
  h.close();
});

// seal M-2b: a stale signed head under live committed rows is the
// stale-head channel's evidence, not destroyed fold progress.
test('w53-seal M-2b: a crash-gap stale head does not flag floor_marker_ahead', t => {
  const h = fixture(t);
  h.ready();
  h.f._auditIndex('acme');
  const staleHead = readFileSync(join(h.directory, 'chain-heads.json'), 'utf8');
  h.ready(); h.ready(); // commits land marker+rows ahead of the snapshotted head
  writeFileSync(join(h.directory, 'chain-heads.json'), staleHead);
  const r = h.f.sealAuditChain(h.p('security'));
  assert.ok(!(r.head_watermark_tampered ?? []).some(e => e.kind === 'floor_marker_ahead'), 'the crash gap is not named as destroyed progress');
  h.close();
});

// seal M-3: stored-seq surgery cannot misname the surviving tip — the
// re-anchor names the largest stored seq the cut actually left standing.
test('w53-seal M-3: the re-anchor names the real surviving tip under stored-seq surgery', t => {
  const h = fixture(t);
  h.ready(); h.ready(); h.ready();
  const tip = maxSeq(h);
  dropAuditGuards(h);
  const cutAt = tip - 4;
  // Corrupt the boundary row, then inflate its stored seq so seq-1 names
  // a slot that never survived.
  h.f.store.db.prepare("UPDATE audit SET envelope=? WHERE tenant='acme' AND seq=?").run('{"payload":{"time":1},"signatures":[{"signature":"AA"}]}', cutAt);
  h.f.store.db.prepare('UPDATE audit SET seq=? WHERE tenant=? AND seq=?').run(cutAt + 50, 'acme', cutAt);
  const r = h.f.sealAuditChain(h.p('security'));
  const reanchored = auditRows(h, '%AUDIT_WM_REANCHORED%');
  assert.ok(reanchored.length >= 1, 'the retreat is attested');
  assert.equal(reanchored.at(-1).meta.reanchored_tip_seq, cutAt - 1, 'the re-anchor names the real surviving tip, not a doomed slot');
  h.close();
});

// --- w53-ledger auditor regressions (report on 66bfe80): the release
// gate that silently repaired its own input, the verified-by-nothing
// 'authenticated' claim, and the .mjs-only outside-scan. Each gate runs
// against a throwaway copy of the working tree — the mutation under test
// can never land on the real tree mid-suite.

const copyTree = () => {
  const dir = mkdtempSync(join(tmpdir(), 'w53-ledger-'));
  const root = new URL('..', import.meta.url).pathname;
  execFileSync('sh', ['-c', 'git ls-files -z | xargs -0 cp --parents -t "$1"', 'sh', dir], { cwd: root });
  // The copied tree has no .git, so its traceability falls back to the
  // reports/tests.tap FILE — cp just cloned the working one, which may
  // hold an uncommitted mid-regeneration run. The gate semantics bind
  // the committed artifact (`git show HEAD:` first, file only as
  // fallback) — give the copy exactly that so a dirty working TAP does
  // not poison every citation check on the copy (w55 regen: a red
  // working TAP made every gate test trip the disqualification arm
  // before the arm under test could fire).
  try {
    const tap = execFileSync('git', ['show', 'HEAD:reports/tests.tap'], { cwd: root, encoding: 'utf8' });
    writeFileSync(join(dir, 'reports/tests.tap'), tap);
  } catch { /* no HEAD TAP — the copied file stands on its own */ }
  return dir;
};

// HIGH-1: release-check must FAIL loudly on a stale ledger — the
// verify-only contract forbids regenerating the file it checks.
test('w53-ledger H-1: release-check refuses a stale ledger instead of repairing it', t => {
  const dir = copyTree();
  try {
    const csv = join(dir, 'docs/requirements.csv');
    writeFileSync(csv, readFileSync(csv, 'utf8').replace('COV-003', 'COV-00X'));
    try {
      execFileSync(process.execPath, ['scripts/release-check.mjs'], { cwd: dir, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
      assert.fail('release-check must refuse a stale ledger');
    } catch (e) {
      assert.equal(e.status, 2, `release-check must exit 2 on a stale ledger, exited ${e.status}`);
      const out = String(e.stderr ?? '') + String(e.stdout ?? '');
      assert.match(out, /committed requirement ledger is stale/i, 'the STALE arm, not a crash, produced the refusal (w54-ledger L-2)');
      assert.match(out, /STALE:.*requirements\.csv/s, 'the staleness names the mutated file');
      assert.ok(readFileSync(csv, 'utf8').includes('COV-00X'), 'the verifier must NOT have repaired the file');
    }
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

// HIGH-2/HIGH-3: an 'authenticated' claim on a zero-auth route is a
// contract lie, and a .js-suffixed dispatch surface is no safer than
// .mjs — one gate run flags both.
test('w53-ledger H-2/H-3: a false authenticated claim and a .js dispatch surface both flag', t => {
  const dir = copyTree();
  try {
    const spec = join(dir, 'docs/openapi.json');
    const specObj = JSON.parse(readFileSync(spec, 'utf8'));
    specObj.paths['/healthz'].get.description = 'Roles: authenticated. Engineering profile; all target mutations are simulated.';
    writeFileSync(spec, JSON.stringify(specObj, null, 2));
    writeFileSync(join(dir, 'src/__check_plant.js'), "require('http').createServer((req,res)=>{ if(req.url==='/x') res.end('x'); });" + String.fromCharCode(10));
    try {
      execFileSync(process.execPath, ['scripts/check.mjs'], { cwd: dir, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
      assert.fail('check.mjs must fail on the planted lies');
    } catch (e) {
      const out = String(e.stderr ?? '') + String(e.stdout ?? '');
      assert.match(out, /route-role parity.*authenticated/i, 'the refusal names the false claim');
      // The manifest arm fires 'unexpected file' on ANY unlisted path —
      // the assertion must name the DISPATCH-SURFACE arm's own line so a
      // plant with no dispatch content cannot satisfy it (w54-ledger M-2).
      assert.match(out, /dispatch surface in src\/__check_plant\.js/i, 'the refusal names the dispatch-surface arm, not just the manifest arm');
    }
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

// MEDIUM: the marker gate covers the real unfinished-marker vocabulary,
// not just the two classic words. Marker spellings are assembled at
// runtime so this file does not flag itself (and its TAP name stays
// marker-free).
test('w53-ledger M: the marker gate flags the widened vocabulary too', t => {
  const src = readFileSync(new URL('../scripts/check.mjs', import.meta.url), 'utf8');
  // The widened pattern spells each letter through an interpolation so
  // this table never spells the marker words itself (w58-fv F-7): the
  // separator is any non-alphanumeric run up to three chars — slashes,
  // pluses, dashes, spaces, dots, NBSP and none at all — and the word
  // vocabulary covers the separated and fullwidth forms (w55-ledger:
  // literal pins track the shipped interpolation shape).
  const sep = "[^A-Za-z0-9]{0,3}";
  for (const [w, lit] of [
    ['T' + 'BD', "${'T'}" + sep + "${'B'}" + sep + "${'D'}"],
    ['W' + 'IP', "${'I'}" + sep + "${'P'}"],
    ['HA' + 'CK', "${'H'}" + sep + "${'A'}" + sep + "${'C'}" + sep + "${'K'}"],
    ['FI' + 'XME', "${'F'}" + sep + "${'I'}" + sep + "${'X'}" + sep + "${'M'}"],
    ['separated class', sep],
    ['fullwidth spellings', "${'Ｔ'}"],
  ])
    assert.ok(src.includes(lit), `marker ${w} must be in the gate (split literal ${lit})`);
});
