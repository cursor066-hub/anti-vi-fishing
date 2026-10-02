// w45 regression tests: the 18th ledger/docs hostile pass attacked the
// w44 marker/durability wave itself — unsigned dedupe suppression, the
// unconditional marker delete, and the RO-mount chmod wedge. Every test
// asserts the FIXED behavior; attack shapes come from the auditor PoCs.
import test from 'node:test';
import assert from 'node:assert/strict';
import { chmodSync, statSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import http from 'node:http';
import { randomUUID } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import { fixture, runtimeInput, runtimeRequest, coverageIdentity } from './helpers.mjs';
import { Fabric } from '../src/fabric.mjs';
import { KeyVault } from '../src/keystore.mjs';
import { hashBytes, digest } from '../src/canonical.mjs';
import { signed } from '../src/crypto.mjs';
import { createServer } from '../src/server.mjs';

const markerRows = db => db.prepare("SELECT envelope FROM audit WHERE json_valid(envelope) AND json_extract(envelope,'$.payload.type') IN ('AAD_MIGRATION','AAD_MIGRATION_MARKER')").all();

async function httpFixture(t, serverOpts = {}) {
  const h = fixture(t), app = createServer(h.f, { port: 0, origin: 'http://127.0.0.1:17777', ...serverOpts });
  await app.listen(); t.after(() => app.close());
  const port = app.server.address().port;
  const request = (path, { method = 'GET', body, token = h.setup.credentials.acme.security, headers = {}, rawBody } = {}) => new Promise((resolve, reject) => {
    const payload = rawBody ?? (body === undefined ? undefined : JSON.stringify(body));
    const req = http.request({ host: '127.0.0.1', port, path, method, headers: { Host: '127.0.0.1:17777', ...(token ? { Authorization: `Bearer ${token}` } : {}), ...(payload === undefined ? {} : { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) }), ...headers } }, response => {
      const chunks = []; response.on('data', c => chunks.push(c)); response.on('end', () => { const s = Buffer.concat(chunks).toString('utf8'); let data; try { data = JSON.parse(s); } catch { data = s; } resolve({ status: response.statusCode, data, headers: response.headers }); });
    }); req.on('error', reject); req.end(payload);
  });
  const login = async (cred = h.setup.credentials.acme.operator) => {
    const res = await request('/session', { method: 'POST', body: { token: cred }, token: null, headers: { Origin: 'http://127.0.0.1:17777' } });
    assert.equal(res.status, 200);
    return { cookie: /if_session=([^;]+)/.exec(res.headers['set-cookie']?.[0] ?? '')?.[0], csrf: res.data.csrf_token };
  };
  return { ...h, request, app, port, login };
}
const markersLeft = db => db.prepare("SELECT COUNT(*) n FROM meta_kv WHERE key='aad_migration'").get().n;
// An unsigned append at MAX(seq)+1 shaped exactly like a marker row — the
// exact surgery the w45 PoC used: audit_seq_guard permits it, and before
// the fix it matched the dedupe scan and suppressed the attestation.
const plantUnsignedMarkerRow = (h, tenant, digests) => {
  const head = h.f.store.db.prepare('SELECT seq,hash FROM audit WHERE tenant=? ORDER BY seq DESC LIMIT 1').get(tenant);
  h.f.store.db.prepare('INSERT INTO audit VALUES(?,?,?,?,?)').run(tenant, head.seq + 1, head.hash, 'f'.repeat(64), JSON.stringify({ payload: { type: 'AAD_MIGRATION_MARKER', metadata: { marker_digests: digests } } }));
};

test('w45-ledger HIGH-1a: an unsigned planted marker row cannot suppress ghost-marker attestation', t => {
  const h = fixture(t);
  const markerValue = JSON.stringify({ migrated: 7 });
  h.f.store.db.prepare("INSERT INTO meta_kv VALUES('ghost','aad_migration',?)").run(markerValue);
  plantUnsignedMarkerRow(h, 'acme', [hashBytes(markerValue)]);
  h.close();
  // The plant convicts the tail, so the marker attestation cannot write
  // at this open — but the constructor must still finish: dying here would
  // make sealAuditChain (the remediation) unreachable forever (w45-seal
  // F-1). The marker survives, the wedge surfaces through the index, seal
  // cuts the planted tail, and the NEXT open attests + clears.
  const f2 = new Fabric(h.setup.config, h.directory, h.now);
  try {
    assert.equal(markersLeft(f2.store.db), 1, 'marker evidence survives the refused attestation');
    f2.sealAuditChain(h.p('security'));
  } finally { f2.close(); }
  const f3 = new Fabric(h.setup.config, h.directory, h.now);
  try {
    assert.equal(markerRows(f3.store.db).filter(r => JSON.parse(r.envelope).payload.metadata?.claimed_tenant === 'ghost').length, 1, 'post-seal open attests the residue');
    assert.equal(markersLeft(f3.store.db), 0, 'residue clears only after the verified anchor lands');
  } finally { f3.close(); }
});

test('w45-ledger HIGH-1b: an unsigned planted marker row cannot suppress the configured-tenant AAD_MIGRATION', t => {
  const h = fixture(t);
  const markerValue = JSON.stringify({ migrated: 3 });
  h.f.store.db.prepare("INSERT INTO meta_kv VALUES('acme','aad_migration',?)").run(markerValue);
  plantUnsignedMarkerRow(h, 'acme', [hashBytes(markerValue)]);
  h.close();
  // Same doctrine on the configured path: the unsigned marker-shaped row
  // is evidence, not cover — the open survives with the wedge on the
  // index (seal reachable), the marker row survives unattested for now,
  // and the post-seal open lands the real attestation (w45-seal F-1).
  const f2 = new Fabric(h.setup.config, h.directory, h.now);
  try {
    assert.equal(markersLeft(f2.store.db), 1);
    f2.sealAuditChain(h.p('security'));
  } finally { f2.close(); }
  const f3 = new Fabric(h.setup.config, h.directory, h.now);
  try {
    assert.equal(markerRows(f3.store.db).filter(r => JSON.parse(r.envelope).payload.type === 'AAD_MIGRATION').length, 1, 'post-seal open attests the configured migration');
    assert.equal(markersLeft(f3.store.db), 0);
  } finally { f3.close(); }
});

test('w45-ledger HIGH-1d: marker attestation is asserted, not just the delete — replay dedupes against the verified anchor', t => {
  const h = fixture(t);
  h.f.store.db.prepare("INSERT INTO meta_kv VALUES('ghost','aad_migration',?)").run(JSON.stringify({ migrated: 1 }));
  h.close();
  const f2 = new Fabric(h.setup.config, h.directory, h.now);
  try {
    // The delete alone cannot be the pass condition — an unattested delete
    // is the laundering hole (w45 MEDIUM-2). Assert the anchor landed.
    assert.equal(markerRows(f2.store.db).filter(r => JSON.parse(r.envelope).payload.metadata?.claimed_tenant === 'ghost').length, 1);
    assert.equal(markersLeft(f2.store.db), 0);
  } finally { f2.close(); }
});

test('w45-ledger HIGH-1c: marker shaped plant after the honest tail still attests — dedupe consults verified rows only', t => {
  const h = fixture(t);
  const markerValue = JSON.stringify({ migrated: 5 });
  h.f.store.db.prepare("INSERT INTO meta_kv VALUES('ghost','aad_migration',?)").run(markerValue);
  h.close();
  // A VERIFIED ghost attestation lands even when unrelated residue sits on
  // the chain — replay dedupe consults the verified anchor, so the second
  // open mints nothing and clears cleanly (HIGH-1 honest side).
  const f2 = new Fabric(h.setup.config, h.directory, h.now);
  try {
    assert.equal(markerRows(f2.store.db).filter(r => JSON.parse(r.envelope).payload.metadata?.claimed_tenant === 'ghost').length, 1);
    assert.equal(markersLeft(f2.store.db), 0);
  } finally { f2.close(); }
});

test('w45-ledger M-2 fold path: a dropped audit table also classifies INV-409 through _auditIndex', t => {
  const h = fixture(t);
  for (const tr of h.f.store.db.prepare("SELECT name FROM sqlite_master WHERE type='trigger' AND tbl_name='audit'").all())
    h.f.store.db.exec(`DROP TRIGGER "${tr.name}"`);
  h.f.store.db.exec('DROP TABLE audit');
  h.f.invalidateAuditIndex('acme');
  assert.throws(() => h.f._auditIndex('acme'), e => e?.code === 'INV-409-INTEGRITY', 'schema divergence must classify as integrity evidence on the fold too');
});

test('w45-fv HIGH: a dup-key decoy payload cannot hide a verified death from the fold-free scans', t => {
  const h = fixture(t);
  const tenant = 'acme';
  h.f.store.audit(tenant, 'AUTHORITY_REVOKED', 'security', 'key:audit-dead-1', {}, h.now());
  const row = h.f.store.db.prepare("SELECT seq,envelope FROM audit WHERE tenant=? ORDER BY seq DESC LIMIT 1").get(tenant);
  // Splice a decoy first 'payload' member before the real one: sqlite's
  // json_extract reads the FIRST dup member where JSON.parse reads the
  // LAST — the row keeps its signature yet vanished from every
  // parsed-type scan, diverging the offline and live death surfaces
  // (w45-fv HIGH PoC).
  const dupd = row.envelope.replace('"payload":', '"payload":{"type":"DECOY"},"payload":');
  for (const tr of h.f.store.db.prepare("SELECT name FROM sqlite_master WHERE type='trigger' AND tbl_name='audit'").all())
    h.f.store.db.exec(`DROP TRIGGER "${tr.name}"`);
  h.f.store.db.prepare('UPDATE audit SET envelope=? WHERE tenant=? AND seq=?').run(dupd, tenant, row.seq);
  assert.equal(JSON.parse(dupd).payload.type, 'AUTHORITY_REVOKED', 'JS parse sees the real last-member type');
  const deadOffline = h.f.store._auditKeyDeaths(tenant);
  h.f.invalidateAuditIndex(tenant);
  const facts = h.f._chainFacts(tenant);
  assert.equal(deadOffline.has('audit-dead-1'), true, 'the offline verifier surfaces the death');
  assert.equal(facts.dead.has('audit-dead-1'), true, 'the live fold sees the same death — surfaces cannot diverge');
  h.close();
});

test('w45-fv MEDIUM: a dropped grants table classifies INV-409, not raw sqlite noise', t => {
  const h = fixture(t);
  h.f.target.db.exec('DROP TABLE grants');
  assert.throws(() => h.f.target.grants('acme', 'investor@acme', h.now()), e => e?.code === 'INV-409-INTEGRITY', 'target.db schema divergence is integrity evidence');
  h.close();
});

test('w45-ledger HIGH-2: a compliant owner-only file never pays the chmod — read-only mounts stay open', t => {
  const h = fixture(t);
  const kf = join(h.directory, 'keystore-ro.json');
  h.f.vault.save(kf);
  chmodSync(kf, 0o400);
  const re = KeyVault.load(kf, h.f.vault.masterKey.toString('base64url'));
  assert.ok(re.list().length > 0, 'read still succeeds');
  assert.equal(statSync(kf).mode & 0o777, 0o400, 'already-compliant mode is left alone — no EROFS window');
  chmodSync(kf, 0o644);
  KeyVault.load(kf, h.f.vault.masterKey.toString('base64url'));
  assert.equal(statSync(kf).mode & 0o777, 0o600, 'genuinely loose mode still tightens before the read');
});

// --- w45-runtime F1: the wedge-clear must name resurrected authority ---
const jitCert = (h, ttl = 120_000) => {
  const r = h.proposed('identity.jit.grant', { subject_id: 'operator', resources: ['dataset-1'], actions: ['data.read'], destinations: ['customer-vault'], columns: ['id'], row_ids: ['row-1'], ttl_ms: ttl, reason: 'Incident', roles: [] }, { action: { type: 'identity.jit.grant', target_resource: 'jit-grants', purpose: 'JIT' } });
  h.evidence(r, { kind: 'identity_proof' }); h.evidence(r, { kind: 'identity_proof', issuer: 'registry' });
  h.approve(r, 2);
  return { record: r, certificate: h.f.certificate(h.p(), r.capsule.capsule_id) };
};

test('w45-runtime F1: a wedge-clear names the resurrected anchored authority', t => {
  const h = fixture(t);
  const cert = jitCert(h);
  h.f.execute(h.p(), cert.certificate); // JIT_GRANT_ISSUED anchored; grant expires now+120s
  const t0 = h.now();
  h.livedForward(t0 + 150_000, 'acme');
  h.livedForward(t0 + 150_000, 'globex');
  // Sabotage acme's fold: an unsigned tail row wedges its index so the
  // veto scan cannot see acme's horizon — the flag must still land.
  const head = h.f.store.db.prepare('SELECT seq,hash FROM audit WHERE tenant=? ORDER BY seq DESC LIMIT 1').get('acme');
  h.f.store.db.prepare('INSERT INTO audit VALUES(?,?,?,?,?)').run('acme', head.seq + 1, head.hash, 'f'.repeat(64), '{}');
  h.f.invalidateAuditIndex('acme');
  h.set(t0 + 100_000); // rewind inside the grant's validity window
  // Recover under the SISTER tenant (acme's own anchor write would refuse
  // on the planted head): acme is flagged unverifiable even though the
  // veto could never inspect its horizon (w45-runtime F1).
  const out = h.f.recoverClock(h.p('security', 'globex'));
  assert.deepEqual(out.unverifiable_tenants, ['acme']);
  // Repair the sabotage, then seal — the grant would resurrect against
  // the rewound clock (expires t0+120s > rewound now) and the clear must
  // name it instead of sweeping it under the flag.
  h.f.store.db.exec('DROP TRIGGER no_audit_delete');
  h.f.store.db.prepare('DELETE FROM audit WHERE tenant=? AND seq=?').run('acme', head.seq + 1);
  h.f.store.db.exec("CREATE TRIGGER no_audit_delete BEFORE DELETE ON audit BEGIN SELECT RAISE(ABORT, 'append-only audit'); END");
  h.f.invalidateAuditIndex('acme');
  const seal = h.f.sealAuditChain(h.p('security'));
  assert.equal(seal.unverifiable_cleared, true);
  assert.equal(seal.resurrected_total, 1, 'the grant that would have resurrected is counted');
  const anchor = h.f.store.db.prepare("SELECT envelope FROM audit WHERE tenant='acme' AND json_extract(envelope,'$.payload.type')='AUDIT_WEDGE_CLEARED' ORDER BY seq DESC LIMIT 1").get();
  const named = JSON.parse(anchor.envelope).payload.metadata.resurrected;
  assert.equal(named[0].kind, 'grant');
  assert.equal(named[0].id, `jit-${cert.certificate.payload.certificate_id}`, 'anchor names the resurrected grant');
  h.close();
});

// --- w45-runtime F4/F5: missing anchored denials are counted honestly ---
test('w45-runtime F4/F5: a murdered containment row is named, with an honest total', t => {
  const h = fixture(t);
  const cap = h.f.runtime.issue(h.p(), runtimeInput());
  try { h.f.runtime.consume(h.p(), { ...runtimeRequest(cap), port: 99 }); } catch { /* denial anchored + row minted */ }
  let rep = h.f.containmentReport(h.p('security'));
  assert.equal(rep.anchored_denials_missing_total, 0, 'row present — nothing missing');
  assert.equal(rep.anchored_denial_events, 1);
  h.f.store.db.prepare("DELETE FROM records WHERE tenant='acme' AND kind='containment'").run();
  rep = h.f.containmentReport(h.p('security'));
  assert.equal(rep.anchored_denials_missing_total, 1, 'the murdered row is counted outside the cap');
  assert.equal(rep.anchored_denials_missing_rows.length, 1);
  h.close();
});

// --- w45-http HIGH: colon-named coverage paths must be reachable ---
test('w45-http HIGH: technical-validation reaches :/_/. path ids', async t => {
  const h = await httpFixture(t);
  const decl = await h.request('/v1/coverage', { method: 'POST', body: { path_id: 'dataset:pii.eu', action_type: 'data.export', target: 'dataset-1', environment: 'prod', connector_version: '1.0', owner: 'op', status: 'UNKNOWN', path_class: 'api', max_age_ms: 60000, configuration_digest: digest({ x: 1 }) } });
  assert.equal(decl.status, 201);
  const path = h.f.store.must('acme', 'coverage', 'dataset:pii.eu');
  const claims = { capsule_digest: coverageIdentity(path) };
  const payload = { evidence_id: randomUUID(), tenant_id: 'acme', capsule_digest: coverageIdentity(path), kind: 'technical_validation', content_digest: digest({ probe: 'ok' }), acquired_at: h.now(), expires_at: h.now() + 60000, confidence: 100, advisory: false, claim: 'supports', dependencies: [], provenance: 'manual probe', retention_until: h.now() + 120000, issuer_version: '1.0.0', claims };
  const envelope = signed(payload, h.setup.issuerKeys.acme['security-ops'], 'evidence');
  const res = await h.request('/v1/coverage/dataset:pii.eu/technical-validation', { method: 'POST', body: envelope });
  assert.equal(res.status, 200, 'colon-named path is reachable — the declared obligation can close');
  assert.equal(res.data.status, 'ENFORCED');
});

// --- w45-http M-1a: cookie-ambient GET /v1/coverage takes the CSRF gate ---
test('w45-http M-1a: an ambient cookie GET cannot ride the coverage write', async t => {
  const h = await httpFixture(t);
  const { cookie, csrf } = await h.login(h.setup.credentials.acme.security);
  const forged = await h.request('/v1/coverage', { token: null, headers: { Cookie: cookie } });
  assert.equal(forged.status, 403, 'cookie GET on a writing path demands CSRF+Origin');
  assert.equal(forged.data.error?.code, 'INV-403-CSRF');
  const consented = await h.request('/v1/coverage', { token: null, headers: { Cookie: cookie, 'X-CSRF-Token': csrf, Origin: 'http://127.0.0.1:17777' } });
  assert.equal(consented.status, 200);
  const bearer = await h.request('/v1/coverage');
  assert.equal(bearer.status, 200, 'bearer callers stay exempt — never sent ambiently');
});

// --- w45-http M-1b: ambient cookie GETs never mint denial evidence ---
test('w45-http M-1b: a forged cookie GET mints no AUTHORIZATION_DENIED row', async t => {
  const h = await httpFixture(t);
  const deniedRows = () => h.f.store.db.prepare("SELECT COUNT(*) n FROM audit WHERE tenant='acme' AND json_valid(envelope) AND json_extract(envelope,'$.payload.type')='AUTHORIZATION_DENIED'").get().n;
  const before = deniedRows();
  const { cookie } = await h.login(h.setup.credentials.acme.operator);
  // operator lacks 'security' — the forged role-probe GET still refuses,
  // but the denial must not land as signed evidence (w45-http M-1b).
  const res = await h.request('/v1/metrics', { token: null, headers: { Cookie: cookie } });
  assert.equal(res.status, 403);
  assert.equal(deniedRows(), before, 'ambient GET left no forged denial row');
  // A consented request still audits: bearer denial mints the row.
  const probe = await h.request('/v1/metrics', { token: h.setup.credentials.acme.operator });
  assert.equal(probe.status, 403);
  assert.equal(deniedRows(), before + 1, 'consented credential denial is audited');
});

// --- w45-http M-2: colon-named resources are served and the console keeps them ---
test('w45-http M-2: colon resource ids serve literally; console path ids keep the alphabet', async t => {
  const h = await httpFixture(t);
  h.f.target.seed('acme', 'vendor:eu-9', { name: 'Colon Vendor', bank_account: 'TESTBANK000009', currency: 'EUR' });
  const res = await h.request('/v1/resources/vendor:eu-9', { token: h.setup.credentials.acme.operator });
  assert.equal(res.status, 200, 'server serves colon-named resources literally');
  const appJs = readFileSync(new URL('../web/app.js', import.meta.url), 'utf8');
  assert.ok(appJs.includes("replaceAll('%3A', ':')"), 'console path-id encoding decodes the colon the identifier alphabet allows');
});
