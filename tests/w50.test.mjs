// w50-seal CRITICAL-1/MEDIUM-1/LOW-1: a doomed-but-verified carry page bound
// to a SURVIVING seal is restored verbatim under its original seal_seq, so
// the fold must bind restores by live-seal membership (not lastSealSeq
// adjacency) — else the seal's own remedy bricked the tenant permanently.
// Restored pages must also NOT double-unfold into the new seal's carry
// (each entry would attest twice into runtimeUse/dataAccess), and
// stored-`previous` divergence must count in divergent_stored.
import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { fixture, hasCode } from './helpers.mjs';
import { signed } from '../src/crypto.mjs';
import { ISSUER_RULES } from '../src/bootstrap.mjs';
import { ISSUER_MANIFEST_PERMISSIONS, ISSUER_MANIFEST_LIMITATIONS, ISSUER_MANIFEST_IDEMPOTENCY, ISSUER_MANIFEST_COVERAGE } from '../src/connectors.mjs';
import { createServer } from '../src/server.mjs';

const dropAuditGuards = h => {
  for (const tr of h.f.store.db.prepare("SELECT name FROM sqlite_master WHERE type='trigger' AND tbl_name='audit'").all())
    h.f.store.db.exec(`DROP TRIGGER "${tr.name}"`);
};
const corruptAt = (h, seq) =>
  h.f.store.db.prepare("UPDATE audit SET envelope=? WHERE tenant='acme' AND seq=?")
    .run('{"payload":{"time":1},"signatures":[{"signature":"AA"}]}', seq);
const chainRows = h => h.f.store.db.prepare("SELECT seq,envelope FROM audit WHERE tenant='acme' ORDER BY seq").all()
  .map(r => ({ seq: r.seq, env: JSON.parse(r.envelope) }));

// N pads -> corrupt one -> seal mints carry pages for the doomed span
// (512 entries land on the seal row itself, the rest spill 512/page).
const buildWithCarryPage = (t, pads = 600) => {
  const h = fixture(t);
  for (let i = 0; i < pads; i++) h.f.store.audit('acme', 'W50_PAD', 'operator', `pad-${i}`, { i }, h.now());
  dropAuditGuards(h);
  corruptAt(h, h.f.store.db.prepare("SELECT seq FROM audit WHERE tenant='acme' AND envelope LIKE '%pad-0%'").get().seq);
  const r0 = h.f.sealAuditChain(h.p('security'));
  assert.equal(r0.sealed, true);
  const pages = chainRows(h).filter(x => x.env.payload.type === 'AUDIT_SEAL_CARRY');
  assert.ok(pages.length >= 1, 'carryover must spill onto pages');
  return { h, pages, seal0: r0 };
};

// Rewrite ONLY the stored `previous` column: the row keeps a valid
// signature (envelope untouched) but the prescan's link check dooms it —
// the exact surgery class doomed-restore exists to remediate.
const rewritePrevious = (h, seq) =>
  h.f.store.db.prepare("UPDATE audit SET previous='deadbeef' WHERE tenant='acme' AND seq=?").run(seq);

test('w50-seal CRITICAL-1: one rewritten carry page -> restore, no permanent wedge', t => {
  const { h, pages } = buildWithCarryPage(t);
  dropAuditGuards(h);
  rewritePrevious(h, pages[0].seq);
  const r = h.f.sealAuditChain(h.p('security'));
  assert.equal(r.sealed, true, 'the remediation seal must commit, not abort');
  // A verbatim restored page must exist, marked and bound to the ORIGINAL
  // surviving seal — landing after the newer seal row.
  const restored = chainRows(h).filter(x => x.env.payload.metadata?.restored_from_doomed_span === true);
  assert.ok(restored.length >= 1, 'a restored_from_doomed_span page must be minted');
  for (const p of restored) {
    assert.equal(p.env.payload.type, 'AUDIT_SEAL_CARRY');
    assert.ok(p.env.payload.metadata.seal_seq < p.seq, 'restore binds its original (surviving) seal_seq');
  }
  // The fold must accept the seal's own restore — membership, not adjacency.
  assert.doesNotThrow(() => h.f._auditIndex('acme'), 'fold must not convict the honest restore');
  // Every later write signs through the fold — the tenant is not bricked.
  assert.doesNotThrow(() => h.f.store.audit('acme', 'W50_AFTER', 'operator', 'after-1', {}, h.now()));
  // And a THIRD seal still works — remediation is repeatable, not one-shot.
  const r2 = h.f.sealAuditChain(h.p('security'));
  assert.ok(r2.sealed === true || r2.sealed === false, 'a routine seal on a restored chain must not wedge');
});

test('w50-seal CRITICAL-1 variant B: multiple rewritten pages -> seal commits atomically', t => {
  const { h, pages } = buildWithCarryPage(t, 1200);
  assert.ok(pages.length >= 2, 'need >=2 carry pages for variant B');
  dropAuditGuards(h);
  for (const p of pages) rewritePrevious(h, p.seq);
  const r = h.f.sealAuditChain(h.p('security'));
  assert.equal(r.sealed, true, 'the seal must not abort on its own second restored page');
  assert.doesNotThrow(() => h.f._auditIndex('acme'), 'fold clean after multi-page restore');
  assert.doesNotThrow(() => h.f.store.audit('acme', 'W50_AFTER', 'operator', 'after-2', {}, h.now()));
});

test('w50-seal MEDIUM-1: restored page content does not double-attest into the new seal', t => {
  const { h, pages } = buildWithCarryPage(t);
  const doomedEntries = (pages[0].env.payload.metadata.lifecycle_carryover ?? []).length;
  assert.ok(doomedEntries > 0, 'the doomed page must carry lifecycle entries');
  dropAuditGuards(h);
  rewritePrevious(h, pages[0].seq);
  const r = h.f.sealAuditChain(h.p('security'));
  assert.equal(r.sealed, true);
  // The restored page keeps feeding the fold under its surviving seal — if
  // the new seal's OWN carry also unfolded the page's arrays, every entry
  // attested twice and the totals would inflate by the page's whole carry.
  assert.ok(r.carryover_totals.lifecycle < doomedEntries,
    `double-attestation inflated the seal carry: lifecycle=${r.carryover_totals.lifecycle} >= restored page's ${doomedEntries}`);
});

test('w50-seal LOW-1: a stored-previous rewrite counts in divergent_stored', t => {
  const { h, pages } = buildWithCarryPage(t);
  dropAuditGuards(h);
  rewritePrevious(h, pages[0].seq);
  const r = h.f.sealAuditChain(h.p('security'));
  assert.ok(r.carryover_totals.divergent_stored >= 1, `previous-column divergence must be attested — got ${r.carryover_totals.divergent_stored}`);
});

test('w50-seal: a transplanted restored page is doomed evidence, never replayed', t => {
  const { h, pages } = buildWithCarryPage(t);
  dropAuditGuards(h);
  rewritePrevious(h, pages[0].seq);
  const r = h.f.sealAuditChain(h.p('security'));
  assert.equal(r.sealed, true);
  const restored = chainRows(h).filter(x => x.env.payload.metadata?.restored_from_doomed_span === true);
  assert.ok(restored.length >= 1);
  // Attacker replays the restored page's signed envelope at a new position —
  // its payload.sequence binds the original slot, so the row is doomed
  // evidence (fold wedge -> seal names it), never a second attestation.
  dropAuditGuards(h);
  const tip = chainRows(h).at(-1);
  const headHash = h.f.store.db.prepare("SELECT hash FROM audit WHERE tenant='acme' AND seq=?").get(tip.seq).hash;
  h.f.store.db.prepare("INSERT INTO audit VALUES(?,?,?,?,?)")
    .run('acme', tip.seq + 1, headHash, 'deadbeef', JSON.stringify(restored[0].env));
  let err;
  try { h.f._auditIndex('acme'); } catch (e) { err = e; }
  assert.ok(err, 'an unverifiable planted row must be convicted');
  const r2 = h.f.sealAuditChain(h.p('security'));
  assert.equal(r2.sealed, true, 'the seal must remediate the planted row');
  assert.doesNotThrow(() => h.f._auditIndex('acme'), 'fold clean after the seal drops the duplicate');
});

// --- w50-http HIGH: the Bearer credential must never reach an endpoint the
// config-drift gate already convicted — egress gates run before the socket ---
const bankEntry = h => Object.entries(h.f.tenant('acme').issuers).find(([, v]) => v.name === 'bank');
const listener = async t => {
  const hits = { count: 0 };
  const srv = http.createServer((req, res) => { hits.count++; res.setHeader('content-type', 'application/json'); res.end('{}'); });
  await new Promise(r => srv.listen(0, '127.0.0.1', r));
  t.after(() => srv.close());
  return { hits, url: `http://127.0.0.1:${srv.address().port}` };
};

test('w50-http HIGH: issuer egress refuses before the socket while config drift stands', async t => {
  const h = fixture(t, ['acme']);
  const [bankKeyId] = bankEntry(h);
  const evil = await listener(t);
  h.repoint(bankKeyId, evil.url);
  h.f._configDrift.add('acme'); // simulates the file-tamper verdict
  await assert.rejects(() => h.f.checkIssuerDrift(h.p('security'), bankKeyId), hasCode('INV-403-QUARANTINE'));
  await assert.rejects(() => h.f.repinIssuerSpec(h.p('security'), bankKeyId), hasCode('INV-403-QUARANTINE'));
  assert.equal(evil.hits.count, 0, 'the token must never leave — no socket opened');
});

// A fake manifest server signing with the issuer's real key — fields the
// stock daemon cannot vary (horizon, permissions) are dialed here.
const manifestServer = async (t, key, now, over = {}) => {
  const srv = http.createServer((req, res) => {
    const payload = { connector_id: 'issuer:bank', version: '1.0.0', domain: 'authoritative',
      actions: Object.keys(ISSUER_RULES.bank), permissions: ISSUER_MANIFEST_PERMISSIONS,
      limitations: ISSUER_MANIFEST_LIMITATIONS, idempotency: ISSUER_MANIFEST_IDEMPOTENCY,
      coverage_implications: ISSUER_MANIFEST_COVERAGE, spec_digest: 'e'.repeat(64),
      issued_at: now(), expires_at: now() + 600000, ...over };
    res.setHeader('content-type', 'application/json');
    res.end(JSON.stringify(signed(payload, key, 'connector-manifest')));
  });
  await new Promise(r => srv.listen(0, '127.0.0.1', r));
  t.after(() => srv.close());
  return `http://127.0.0.1:${srv.address().port}`;
};

test('w50-http MEDIUM: repin enforces the same signed-horizon cap drift-check does', async t => {
  const h = fixture(t, ['acme']);
  const [bankKeyId, bank] = bankEntry(h);
  h.repoint(bankKeyId, await manifestServer(t, h.setup.issuerKeys.acme.bank, h.now, { expires_at: h.now() + 365 * 86400000 }));
  await assert.rejects(() => h.f.repinIssuerSpec(h.p('security'), bankKeyId), hasCode('INV-401-CONNECTOR'), 'a 1-year manifest must not pin');
});

test('w50-http MEDIUM: repin evaluates the full contract — residual drift stays named', async t => {
  const h = fixture(t, ['acme']);
  const [bankKeyId] = bankEntry(h);
  // New spec_digest (so repin has something to pin) AND an escalated
  // permissions set (drift repin must not silently settle).
  h.repoint(bankKeyId, await manifestServer(t, h.setup.issuerKeys.acme.bank, h.now, { spec_digest: 'f'.repeat(64), permissions: ['mint-anything'] }));
  const repin = await h.f.repinIssuerSpec(h.p('security'), bankKeyId);
  assert.equal(repin.repinned, true, 'the digest pin still lands');
  assert.ok(Array.isArray(repin.residual_drift) && repin.residual_drift.length > 0, 'the permissions escalation is named, not settled');
  const row = h.f.store.db.prepare("SELECT value FROM records WHERE tenant='acme' AND kind='issuer-drift' AND id=?").get(bankKeyId);
  assert.ok(row, 'the forensic drift row survives while quarantine persists');
  // The residual drift must reach the enforcement plane the name-and-gate
  // contract promises — idx.issuerDrift, not only the row (w51-http F1).
  assert.ok(h.f._auditIndex('acme').issuerDrift.has(bankKeyId), 'the residual drift arms the chain-anchored quarantine');
  assert.equal(repin.quarantined, true, 'the response says the suspension stands');
});

test('w50-http LOW: repin refuses a revoked issuer', async t => {
  const h = fixture(t, ['acme']);
  const [bankKeyId] = bankEntry(h);
  h.repoint(bankKeyId, 'http://127.0.0.1:1');
  h.f.revoke(h.p('security'), { kind: 'issuer', id: bankKeyId, reason: 'decommissioned' });
  await assert.rejects(() => h.f.repinIssuerSpec(h.p('security'), bankKeyId), hasCode('INV-401-EVIDENCE'), 'pinning a dead connector must refuse');
});

test('w50-http LOW: the 405 template binding cannot exceed the 404 dispatch charset', async t => {
  const h = fixture(t), app = createServer(h.f, { port: 0, origin: 'http://127.0.0.1:17777' }); await app.listen(); t.after(() => app.close());
  const port = app.server.address().port;
  const req = (path, method = 'GET') => new Promise((resolve, reject) => {
    const r = http.request({ host: '127.0.0.1', port, path, method, headers: { Host: '127.0.0.1:17777', Authorization: `Bearer ${h.setup.credentials.acme.security}` } }, res => { res.resume(); res.on('end', () => resolve(res.statusCode)); });
    r.on('error', reject); r.end();
  });
  assert.equal(await req('/v1/connectors/!/repin'), 404, 'undispatchable id must 404, not 405-oracle the template');
  assert.equal(await req('/v1/connectors/ab-c/repin'), 405, 'a dispatchable id with the wrong method stays 405');
});
