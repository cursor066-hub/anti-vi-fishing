// w58 self-audit regressions from the residue-plane + gate-doctrine audit:
//  F-1 — the residue plane was erasable at file level: drop the keep
//        triggers, delete the rows, restart, and every heal conviction
//        evaporated unnamed. Heals are now enumerated chain-side too —
//        the signed envelope's own fold_floor_divergent metadata is the
//        durable evidence (same pendingScan doctrine as the aad marker).
//  F-2 — rename-in minted evidence: UPDATE key='fold_floor_healed.9'
//        on an innocent row landed outside every guard. The upd arms
//        now cover NEW.key/substr(NEW.key) on residue + aad planes.
//  F-3 — a call inside a conditional body (if/catch/arrow/case body)
//        resolves only some requests — it cannot satisfy 'authenticated'
//        or a role claim; for/while bodies are the handler's own scope.
//  F-4 — pre-w58 trigger text wedged honest upgrades: legacy-verbatim
//        bodies are now upgraded at open; any other shape still fails.
//  seal — heals list capped at 256 with a heals_dropped counter, and a
//        malformed residue claim no longer gates the anchor probe.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readFileSync, writeFileSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';
import { Store } from '../src/store.mjs';
import { fixture } from './helpers.mjs';

const residueRows = h => h.f.store.db.prepare(
  "SELECT key,value FROM meta_kv WHERE tenant='acme' AND (key='fold_floor_healed' OR substr(key,1,18)='fold_floor_healed.')").all();
const healOnce = (h, garbage) => {
  h.f.store.db.prepare("UPDATE meta_kv SET value=? WHERE tenant='acme' AND key='fold_floor'").run(garbage);
  h.f.store.audit('acme', 'PROBE', 'actor', null, {}, h.f.clock());
};

// w58-fv F-2: the residue upd arm covers NEW.key — rename-in mints
// evidence by moving an innocent row onto a guarded key.
test('w58-store F-2: residue + aad rename-in aborts on store.db', t => {
  const h = fixture(t);
  h.ready(); h.ready();
  const db = h.f.store.db;
  db.prepare("INSERT INTO meta_kv VALUES('acme','innocent','x')").run();
  assert.throws(() => db.prepare("UPDATE meta_kv SET key='fold_floor_healed.9' WHERE tenant='acme' AND key='innocent'").run(),
    /fold-floor residue is evidence/, 'rename-in onto a keyed residue key must abort');
  assert.throws(() => db.prepare("UPDATE meta_kv SET key='fold_floor_healed' WHERE tenant='acme' AND key='innocent'").run(),
    /fold-floor residue is evidence/, 'rename-in onto the bare residue key must abort');
  assert.throws(() => db.prepare("UPDATE meta_kv SET key='aad_migration' WHERE tenant='acme' AND key='innocent'").run(),
    /aad migration marker is evidence/, 'rename-in onto the aad marker must abort');
  // The arm is narrow — ordinary key renames stay writable.
  db.prepare("UPDATE meta_kv SET key='renamed' WHERE tenant='acme' AND key='innocent'").run();
  assert.equal(db.prepare("SELECT value FROM meta_kv WHERE tenant='acme' AND key='renamed'").get()?.value, 'x');
  // Rename-OUT of a guarded row is still armed (OLD.key arm).
  db.exec("DROP TRIGGER fold_residue_keep_ins");
  db.prepare("INSERT INTO meta_kv VALUES('acme','fold_floor_healed.77','77:x')").run();
  db.exec("CREATE TRIGGER fold_residue_keep_ins BEFORE INSERT ON meta_kv WHEN NEW.key='fold_floor_healed' OR substr(NEW.key,1,18)='fold_floor_healed.' BEGIN SELECT RAISE(ABORT, 'fold-floor residue is evidence'); END");
  assert.throws(() => db.prepare("UPDATE meta_kv SET key='exfil' WHERE tenant='acme' AND key='fold_floor_healed.77'").run(),
    /fold-floor residue is evidence/, 'rename-out of a residue key still aborts');
  h.close();
});

test('w58-store F-2 parity: aad rename-in aborts on target.db', t => {
  const h = fixture(t);
  h.ready(); h.ready();
  const db = h.f.target.db;
  db.prepare("INSERT INTO meta_kv VALUES('acme','innocent','x')").run();
  assert.throws(() => db.prepare("UPDATE meta_kv SET key='aad_migration' WHERE tenant='acme' AND key='innocent'").run(),
    /aad migration marker is evidence/, 'rename-in onto the target aad marker must abort');
  db.prepare("UPDATE meta_kv SET key='renamed' WHERE tenant='acme' AND key='innocent'").run();
  assert.equal(db.prepare("SELECT value FROM meta_kv WHERE tenant='acme' AND key='renamed'").get()?.value, 'x');
  h.close();
});

// w58-fv F-1 / w58-store F-1: a file-level wipe of the residue plane —
// drop the keep triggers, delete the rows — cannot hide a heal: the
// signed envelope's own fold_floor_divergent metadata enumerates every
// heal the residue rows pointed at (chain-anchored pendingScan doctrine).
test('w58-fv F-1: erased residue rows are re-named from the chain itself', t => {
  const h = fixture(t);
  h.ready(); h.ready();
  healOnce(h, 'wiped-A:garbage');
  assert.equal(residueRows(h).length, 1, 'the heal minted its residue pointer');
  // File-level wipe: triggers + rows both gone, as a writer would leave
  // the image before the process restarts.
  h.f.store.db.exec('DROP TRIGGER fold_residue_keep');
  h.f.store.db.exec('DROP TRIGGER fold_residue_keep_upd');
  h.f.store.db.exec('DROP TRIGGER fold_residue_keep_ins');
  h.f.store.db.prepare("DELETE FROM meta_kv WHERE tenant='acme' AND (key='fold_floor_healed' OR substr(key,1,18)='fold_floor_healed.')").run();
  // The chain row itself is the durable evidence — the seal names the
  // heal even though no residue row survived.
  const seal = h.f.sealAuditChain(h.p('security'));
  const healed = (seal.head_watermark_tampered ?? []).filter(e => e.kind === 'floor_marker_healed');
  assert.deepEqual(healed.map(e => e.healed_marker), ['wiped-A:garbage'],
    `the wiped heal is re-named chain-side: ${JSON.stringify(seal.head_watermark_tampered)}`);
  h.close();
});

// w58-store F-1: retirement is conviction-scoped — a heal minted after a
// report mints fresh residue and is named on the next report; the seal
// retires only the convictions it actually consulted.
test('w58-store F-1: retired residue does not eat heals minted after the report', t => {
  const h = fixture(t);
  h.ready(); h.ready();
  healOnce(h, 'first:garbage');
  const seal = h.f.sealAuditChain(h.p('security'));
  assert.ok((seal.head_watermark_tampered ?? []).some(e => e.kind === 'floor_marker_healed' && e.healed_marker === 'first:garbage'));
  assert.equal(residueRows(h).length, 0, 'the consulted heal retires with its report');
  healOnce(h, 'second:garbage');
  assert.equal(residueRows(h).length, 1, 'a post-report heal mints fresh residue');
  const seal2 = h.f.sealAuditChain(h.p('security'));
  const healed2 = (seal2.head_watermark_tampered ?? []).filter(e => e.kind === 'floor_marker_healed');
  assert.deepEqual(healed2.map(e => e.healed_marker), ['second:garbage'],
    `the post-report heal is named fresh, not eaten: ${JSON.stringify(seal2.head_watermark_tampered)}`);
  h.close();
});

// w58-seal F-2: the heals list is capped — past 256 entries the
// heals_dropped counter still attests every observed heal rather than
// letting planted residue rows run the scan/report unbounded. Plant the
// rows directly: the dedupe scan pushes each as a heal, exercising the
// same cap path as real heals without 258 signed envelopes.
test('w58-seal F-2: heals beyond the cap surface as heals_dropped', t => {
  const h = fixture(t);
  h.ready(); h.ready();
  h.f.store.db.exec('DROP TRIGGER fold_residue_keep_ins');
  const plant = h.f.store.db.prepare("INSERT INTO meta_kv VALUES('acme',?,?)");
  for (let i = 0; i < 260; i++) plant.run(`fold_floor_healed.${9000 + i}`, `${9000 + i}:planted-${i}`);
  const seal = h.f.sealAuditChain(h.p('security'));
  const rows = (seal.head_watermark_tampered ?? []).filter(e => e.kind === 'floor_marker_healed_unanchored');
  const named = rows.filter(e => e.healed_marker !== undefined);
  const dropped = rows.find(e => e.heals_dropped !== undefined);
  assert.ok(named.length <= 256, `the named list is bounded: ${named.length}`);
  assert.ok(dropped && dropped.heals_dropped >= 4,
    `heals past the cap still attest: ${JSON.stringify(dropped)}`);
  h.close();
});

// w58-seal F-3: a malformed residue value must not launder an anchor
// murder — the anchor-presence probe runs independent of the claim's
// shape, so a value with no seq still convicts as unanchored.
test('w58-seal F-3: a malformed residue claim still convicts', t => {
  const h = fixture(t);
  h.ready(); h.ready();
  h.f.store.db.exec('DROP TRIGGER fold_residue_keep_ins');
  h.f.store.db.prepare("INSERT INTO meta_kv VALUES('acme','fold_floor_healed.1','garbage')").run();
  const seal = h.f.sealAuditChain(h.p('security'));
  const unanchored = (seal.head_watermark_tampered ?? []).filter(e => e.kind === 'floor_marker_healed_unanchored');
  assert.equal(unanchored.length, 1, `the malformed pointer is named: ${JSON.stringify(seal.head_watermark_tampered)}`);
  h.close();
});

// w58-fv F-4 / w58-store F-3: a database written by the pre-w58 build
// stores the OLD trigger text — open upgrades it verbatim instead of
// wedging; any OTHER shape is still tamper evidence and fails.
test('w58-fv F-4: legacy trigger text upgrades at open; foreign text still wedges', t => {
  const dir = mkdtempSync(join(tmpdir(), 'w58-legacy-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const tenantKeys = { acme: randomBytes(32).toString('base64url') };
  const signer = { sign: p => ({ protected: { profile: 'IF-CJSON-1', suite: 'Ed25519', key_id: 'a', purpose: 'audit' }, payload: p, signature: 'x'.repeat(86) }) };
  const path = join(dir, 's.db');
  const s1 = new Store(path, tenantKeys, { acme: signer });
  // Rewrite the armed upd guard to its pre-w58 verbatim text (OLD.key
  // only) — the stored shape of a database the previous build wrote.
  s1.db.exec('DROP TRIGGER fold_residue_keep_upd');
  s1.db.exec("CREATE TRIGGER fold_residue_keep_upd BEFORE UPDATE ON meta_kv WHEN OLD.key='fold_floor_healed' OR substr(OLD.key,1,18)='fold_floor_healed.' BEGIN SELECT RAISE(ABORT, 'fold-floor residue is evidence'); END");
  s1.db.exec('DROP TRIGGER aad_marker_keep_upd');
  s1.db.exec("CREATE TRIGGER aad_marker_keep_upd BEFORE UPDATE ON meta_kv WHEN OLD.key='aad_migration' BEGIN SELECT RAISE(ABORT, 'aad migration marker is evidence'); END");
  s1.close();
  const s2 = new Store(path, tenantKeys, { acme: signer });
  const upd = s2.db.prepare("SELECT sql FROM sqlite_master WHERE name='fold_residue_keep_upd'").get()?.sql ?? '';
  assert.ok(upd.includes('NEW.key'), `the legacy body is upgraded at open: ${upd}`);
  s2.close();
  // A foreign body under our name is still tamper evidence — wedge.
  const s3 = new Store(path, tenantKeys, { acme: signer });
  s3.db.exec('DROP TRIGGER fold_residue_keep_upd');
  s3.db.exec("CREATE TRIGGER fold_residue_keep_upd BEFORE UPDATE ON meta_kv WHEN NEW.key='innocent' BEGIN SELECT RAISE(ABORT, 'impostor'); END");
  s3.close();
  assert.throws(() => new Store(path, tenantKeys, { acme: signer }), /INV-503-STORAGE|integrity trigger/);
});

// ============================================================================
// Gate regressions — run the shipped check.mjs against copied trees,
// never a source grep (w58 doctrine is exercised end-to-end).
// ============================================================================
const ledgerCopyTree = () => {
  const dir = mkdtempSync(join(tmpdir(), 'w58-ledger-'));
  execFileSync('sh', ['-c', 'git ls-files -z | xargs -0 cp --parents -t "$1"', 'sh', dir], { cwd: new URL('..', import.meta.url).pathname });
  return dir;
};
const checkErr = dir => {
  try {
    execFileSync(process.execPath, ['scripts/check.mjs'], { cwd: dir, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
    return null;
  } catch (e) { return String(e.stderr ?? '') + String(e.stdout ?? ''); }
};

// w58-fv F-3 + F-7 (one copied-tree gate run — each run also pays the
// full traceability phase): a bearer call inside an if-body resolves
// only some requests so the route claim must fail; the separated-marker
// and widened eval sinks flag authored files on the same pass. The
// for-body case stays unconditional — the live tree's clean gate proves
// the control (the issuerd for-loop bearer resolves there).
test('w58-ledger: conditional bearer + separated marker + eval sink all flag', t => {
  const dir = ledgerCopyTree();
  try {
    const file = join(dir, 'src', 'issuerd.mjs');
    const text = readFileSync(file, 'utf8');
    const patched = text.replace(
      'const issueAuthed = anyBearer(\'issue\');',
      'let issueAuthed = false; if (request !== null) { issueAuthed = anyBearer(\'issue\'); }');
    assert.notEqual(patched, text, 'the patch must land on the shipped line');
    // The injected spellings are assembled at runtime — this file must
    // not self-match the marker/sink scans it is testing (the loose
    // scan reads comments and strings).
    const markerText = '\x54\x4f\x44\x4f'.split('').join('.');
    const sinkText = 'eva' + 'l.call';
    writeFileSync(file, `${patched}\n// deferred work: ${markerText} tag line\nconst sink = ${sinkText}(this, 'x');\n`);
    const err = checkErr(dir);
    assert.ok(err?.includes('/v1/issuers/{id}/issue'),
      `an if-bodied bearer must not resolve the claim: ${String(err).slice(0, 400)}`);
    assert.ok(err?.includes('unfinished code marker'), `separated marker spelling must flag: ${String(err).slice(0, 300)}`);
    assert.ok(err?.includes('dynamic eval'), `eval.call must flag as a sink: ${String(err).slice(0, 300)}`);
  } finally { rmSync(dir, { recursive: true, force: true, maxRetries: 20, retryDelay: 50 }); }
});
