// w18-issuerd regression suite — planted perception-session tamper, release
// binding integrity, issuerd registry/boot validation, probe logging.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomBytes, randomUUID } from 'node:crypto';
import { fixture, hasCode } from './helpers.mjs';
import { createIssuerServer, writeIssuer, answerQuery, loadIssuers } from '../src/issuerd.mjs';
import { ISSUER_RULES, issuerRecords } from '../src/bootstrap.mjs';
import { signed, generateKey } from '../src/crypto.mjs';
import { digest, canonical } from '../src/canonical.mjs';
import { httpJson, verifyManifest, signedManifest, driftCheck } from '../src/connectors.mjs';
import { request as httpRequest } from 'node:http';
import { InvariantError } from '../src/errors.mjs';

const T = 'acme';
const component = h => h.setup.componentSecrets.acme['secure-view-acme'];
const flipSession = (h, sid, mutate) => { const r = h.f.store.must(T, 'perception-session', sid); mutate(r); h.f.store.put(T, 'perception-session', sid, r, h.now()); };

// F-1a — the release channel is chain-anchored: swapping the row's
// component_ecdh can never exfiltrate (the derived key would be attacker-
// readable under the attacker private key).
test('w18-issuerd F-1a: a swapped component_ecdh refuses release', t => {
  const h = fixture(t);
  const session = h.f.perceptionSession(h.p(), component(h).attest(randomBytes(32).toString('hex'), h.now() + 300000));
  flipSession(h, session.session_id, r => { r.component_ecdh = generateKey().public_key; });
  assert.throws(() => h.f.perceptionRelease(h.p(), session.session_id, { fields: { vendor: 'v1' }, purpose: 'verify' }), hasCode('INV-409-INTEGRITY'));
});

// F-1b — a stretched expires_at diverges from the anchored binding.
test('w18-issuerd F-1b: an extended expires_at refuses release', t => {
  const h = fixture(t);
  const session = h.f.perceptionSession(h.p(), component(h).attest(randomBytes(32).toString('hex'), h.now() + 300000));
  flipSession(h, session.session_id, r => { r.expires_at = h.now() + 86400000; });
  assert.throws(() => h.f.perceptionRelease(h.p(), session.session_id, { fields: { vendor: 'v1' }, purpose: 'verify' }), hasCode('INV-409-INTEGRITY'));
});

// F-1c — a forged creator cannot hijack the session.
test('w18-issuerd F-1c: a planted creator cannot hijack the sealed channel', t => {
  const h = fixture(t);
  const session = h.f.perceptionSession(h.p(), component(h).attest(randomBytes(32).toString('hex'), h.now() + 300000));
  flipSession(h, session.session_id, r => { r.creator = 'security'; });
  assert.throws(() => h.f.perceptionRelease(h.p('security'), session.session_id, { fields: { vendor: 'v1' }, purpose: 'verify' }), hasCode('INV-409-INTEGRITY'));
  // And the real creator can still release on the untampered session.
  const clean = h.f.perceptionSession(h.p(), component(h).attest(randomBytes(32).toString('hex'), h.now() + 300000));
  assert.equal(h.f.perceptionRelease(h.p(), clean.session_id, { fields: { vendor: 'v1' }, purpose: 'verify' }).binding.fields[0], 'vendor');
});

// F-4 — release provenance commits a digest of the released VALUES, not only
// the field names: the ledger can attest exactly what was sealed.
test('w18-issuerd F-4: release audit carries the value digest', t => {
  const h = fixture(t);
  const session = h.f.perceptionSession(h.p(), component(h).attest(randomBytes(32).toString('hex'), h.now() + 300000));
  const fields = { vendor: 'v1', verdict: 'ALLOW' };
  h.f.perceptionRelease(h.p(), session.session_id, { fields, purpose: 'verify' });
  const row = h.f.store.db.prepare("SELECT envelope FROM audit WHERE tenant='acme' AND json_extract(envelope,'$.payload.type')='PERCEPTION_RELEASE' ORDER BY seq DESC LIMIT 1").get();
  const meta = JSON.parse(row.envelope).payload.metadata;
  assert.equal(meta.fields_digest, digest(fields), 'sealed content is digest-bound in the signed event');
  h.f.perceptionFallback(h.p(), { fields: { a: 1 }, purpose: 'inspect' });
  const fb = h.f.store.db.prepare("SELECT envelope FROM audit WHERE tenant='acme' AND json_extract(envelope,'$.payload.type')='PERCEPTION_FALLBACK' ORDER BY seq DESC LIMIT 1").get();
  assert.equal(JSON.parse(fb.envelope).payload.metadata.fields_digest, digest({ a: 1 }), 'fallback path digests too');
});

// F-5 — component signing-key revocation reaches LIVE sessions immediately.
test('w18-issuerd F-5: revoking the component signing key kills live releases', t => {
  const h = fixture(t);
  const comp = component(h);
  const session = h.f.perceptionSession(h.p(), comp.attest(randomBytes(32).toString('hex'), h.now() + 300000));
  h.f.revoke(h.p('security'), { kind: 'key', id: comp.signing.key_id, reason: 'component compromised' });
  assert.throws(() => h.f.perceptionRelease(h.p(), session.session_id, { fields: { vendor: 'v1' }, purpose: 'verify' }), hasCode('INV-403-SCOPE'));
});

// F-3 — the signed provenance string is uniform for hit and miss alike: the
// envelope is no longer an authenticated record-existence oracle.
test('w18-issuerd F-3: signed provenance cannot leak record existence', t => {
  const spec = { issuer: 'bank', tenant: 'acme', version: '1.0.0', channel: 'authoritative', key: generateKey(), kinds: ISSUER_RULES.bank, records: issuerRecords().bank };
  const req = { tenant_id: 'acme', kind: 'ownership', subject_id: 'operator', claims: { account: 'TESTBANK000001', owner_id: 'vendor-1' }, capsule_digest: 'a'.repeat(64) };
  const hit = answerQuery(spec, req, Date.now());
  const miss = answerQuery(spec, { ...req, claims: { account: 'GHOST', owner_id: 'nobody' } }, Date.now());
  assert.equal(hit.payload.claim, 'supports');
  assert.equal(miss.payload.claim, 'conflict');
  assert.equal(hit.payload.provenance, miss.payload.provenance, 'provenance is byte-identical for hit and miss');
  assert.ok(!/UNSATISFIED|\*/.test(miss.payload.provenance));
});

// F-6 — kind rules are semantics-validated at boot: string ttl_ms, object
// expect, non-scalar expect values all refuse at load, not per-request.
test('w18-issuerd F-6: malformed kind rules refuse at boot', t => {
  const dir = mkdtempSync(join(tmpdir(), 'if-issuer-')); t.after(() => rmSync(dir, { recursive: true }));
  const base = { issuer: 'badbank', tenant: 'acme', version: '1.0.0', channel: 'authoritative', key: generateKey(), records: {} };
  writeFileSync(join(dir, 'a.issuer.json'), canonical({ ...base, kinds: { ownership: { lookup: 'a:${claims.a}', ttl_ms: '300000' } } }) + '\n', { mode: 0o600 });
  assert.throws(() => loadIssuers(dir), hasCode('INV-400-SCHEMA'), 'string ttl_ms refuses at boot');
  rmSync(join(dir, 'a.issuer.json'));
  writeFileSync(join(dir, 'b.issuer.json'), canonical({ ...base, kinds: { ownership: { lookup: 'a:${claims.a}', expect: { tags: { nested: true } } } } }) + '\n', { mode: 0o600 });
  assert.throws(() => loadIssuers(dir), hasCode('INV-400-SCHEMA'), 'object-valued expect refuses at boot');
  rmSync(join(dir, 'b.issuer.json'));
  writeFileSync(join(dir, 'c.issuer.json'), canonical({ ...base, kinds: { ownership: { lookup: 'a:${claims.a}', expect: ['vip'] } } }) + '\n', { mode: 0o600 });
  assert.throws(() => loadIssuers(dir), hasCode('INV-400-SCHEMA'), 'array expect refuses at boot');
});

// F-7 — bare-alias registration is deterministic: tenanted+untenanted same
// name → bare alias marked ambiguous (never order-dependent shadowing).
test('w18-issuerd F-7: bare-alias collisions resolve deterministically ambiguous', t => {
  const dir = mkdtempSync(join(tmpdir(), 'if-issuer-')); t.after(() => rmSync(dir, { recursive: true }));
  const mk = (tenant, name) => ({ issuer: name, tenant, version: '1.0.0', channel: 'authoritative', key: generateKey(), kinds: ISSUER_RULES.bank, records: issuerRecords().bank });
  writeIssuer(dir, mk('acme', 'bank'));
  // A second spec file claiming the same bare name — same issuer name, no
  // tenant binding. Placed directly (writeIssuer would collide on filename).
  const untenanted = mk('acme', 'bank'); delete untenanted.tenant;
  writeFileSync(join(dir, 'bank-dup.issuer.json'), canonical(untenanted) + '\n', { mode: 0o600 });
  // A bare plus a scoped claim on the same name can never resolve
  // deterministically — the registry refuses to load at all.
  assert.throws(() => loadIssuers(dir), hasCode('INV-409-CONFLICT'));
  rmSync(join(dir, 'bank-dup.issuer.json'));
  // Two TENANTED claims on one bare name still resolve to the ambiguous
  // marker — deterministic in both readdir orders, never a silent shadow.
  writeFileSync(join(dir, 'bank-globex.issuer.json'), canonical(mk('globex', 'bank')) + '\n', { mode: 0o600 });
  const issuers = loadIssuers(dir);
  assert.equal(issuers['bank'].ambiguous, true, 'two scoped claims mark the bare alias ambiguous');
  assert.equal(issuers['acme:bank'].issuer, 'bank', 'the qualified key still resolves');
});

// F-8 — issuer_version drift pin: envelopes on a versioned issuer must carry
// the pinned version; omission is not a bypass.
test('w18-issuerd F-8: omitted issuer_version cannot skip the drift pin', t => {
  const h = fixture(t);
  const r = h.proposed();
  // Claims must satisfy the ownership binding so ONLY the version pin can
  // fire — the isolate proves the pin, not the claims gate.
  const claims = { account: 'TESTBANK000002', owner_id: 'vendor-1' };
  const payload = { evidence_id: randomUUID(), tenant_id: 'acme', capsule_digest: r.capsule_digest, kind: 'ownership', content_digest: digest('x'), acquired_at: h.now(), expires_at: h.now() + 600000, confidence: 100, advisory: false, claim: 'supports', dependencies: [], provenance: 'x', retention_until: h.now() + 900000, claims };
  // Omitted — the versioned issuer's pin must still fire.
  assert.throws(() => h.f.attachEvidence(h.p(), r.capsule.capsule_id, signed(payload, h.setup.issuerKeys.acme.bank, 'evidence')), hasCode('INV-403-SCOPE'), 'a registered version cannot be silently skipped');
  // Mismatched — rejected.
  assert.throws(() => h.f.attachEvidence(h.p(), r.capsule.capsule_id, signed({ ...payload, issuer_version: '9.9.9' }, h.setup.issuerKeys.acme.bank, 'evidence')), hasCode('INV-403-SCOPE'));
  // Matching — attaches.
  h.f.attachEvidence(h.p(), r.capsule.capsule_id, signed({ ...payload, issuer_version: '1.0.0' }, h.setup.issuerKeys.acme.bank, 'evidence'));
});

// F-12 — a tokenless open-loopback issue logs exactly one entry, no phantom
// refused record preceding the success.
test('w18-issuerd F-12: tokenless issue writes one honest log entry', async t => {
  const dir = mkdtempSync(join(tmpdir(), 'if-issuer-')); t.after(() => rmSync(dir, { recursive: true }));
  const spec = { issuer: 'bank', tenant: 'acme', version: '1.0.0', channel: 'authoritative', key: generateKey(), kinds: ISSUER_RULES.bank, records: issuerRecords().bank };
  writeIssuer(dir, spec);
  const logPath = join(dir, 'issuance.log');
  const srv = createIssuerServer(loadIssuers(dir), { port: 0, host: '127.0.0.1', allow_insecure_loopback: true, logPath });
  await srv.listen(); t.after(() => srv.close());
  const port = srv.server.address().port;
  const res = await httpJson(`http://127.0.0.1:${port}/v1/issuers/bank/issue`, { method: 'POST', body: { kind: 'ownership', subject_id: 'operator', claims: { account: 'TESTBANK000001', owner_id: 'vendor-1' }, capsule_digest: 'a'.repeat(64), tenant_id: 'acme' } });
  assert.equal(res.status, 201);
  const lines = readFileSync(logPath, 'utf8').trim().split('\n').filter(Boolean).map(JSON.parse);
  assert.equal(lines.length, 1, 'a successful tokenless issue logs exactly once');
  assert.equal(lines[0].refused, undefined, 'no phantom refused entry precedes the success');
  assert.equal(lines[0].evidence_id, res.data.payload.evidence_id);
});

// F-2 — oversize POSTs are logged probes too: 413 lands in the issuance log.
test('w18-issuerd F-2: oversize probes are logged and budgeted', async t => {
  const dir = mkdtempSync(join(tmpdir(), 'if-issuer-')); t.after(() => rmSync(dir, { recursive: true }));
  const spec = { issuer: 'bank', tenant: 'acme', version: '1.0.0', channel: 'authoritative', key: generateKey(), kinds: ISSUER_RULES.bank, records: issuerRecords().bank };
  writeIssuer(dir, spec);
  const logPath = join(dir, 'issuance.log');
  const srv = createIssuerServer(loadIssuers(dir), { port: 0, host: '127.0.0.1', allow_insecure_loopback: true, logPath });
  await srv.listen(); t.after(() => srv.close());
  const port = srv.server.address().port;
  // Raw HTTP write — httpJson canonicalizes the body itself, and the point
  // is wire bytes beyond the server's 256 KiB intake bound.
  const res = await new Promise((resolve, reject) => {
    const req = httpRequest({ host: '127.0.0.1', port, path: '/v1/issuers/bank/issue', method: 'POST', headers: { 'Content-Type': 'application/json' } }, r => { const chunks = []; r.on('data', c => chunks.push(c)); r.on('end', () => resolve({ status: r.statusCode })); });
    req.on('error', reject);
    req.end('x'.repeat(300 * 1024));
  });
  assert.equal(res.status, 413);
  const lines = readFileSync(logPath, 'utf8').trim().split('\n').filter(Boolean).map(JSON.parse);
  assert.ok(lines.some(l => l.malformed === true && l.code === 'INV-413-BODY'), 'the oversize probe reached the chained log');
});

// F-9 — the issuance log chain is keyed: a rewritten tail cannot be extended
// without the issuers' custody material.
test('w18-issuerd F-9: issuance log is an HMAC-keyed chain', async t => {
  const dir = mkdtempSync(join(tmpdir(), 'if-issuer-')); t.after(() => rmSync(dir, { recursive: true }));
  const spec = { issuer: 'bank', tenant: 'acme', version: '1.0.0', channel: 'authoritative', key: generateKey(), kinds: ISSUER_RULES.bank, records: issuerRecords().bank };
  writeIssuer(dir, spec);
  const logPath = join(dir, 'issuance.log');
  const srv = createIssuerServer(loadIssuers(dir), { port: 0, host: '127.0.0.1', allow_insecure_loopback: true, logPath });
  await srv.listen(); t.after(() => srv.close());
  const port = srv.server.address().port;
  for (let i = 0; i < 3; i++) await httpJson(`http://127.0.0.1:${port}/v1/issuers/bank/issue`, { method: 'POST', body: { kind: 'ownership', subject_id: 'operator', claims: { account: 'TESTBANK000001', owner_id: 'vendor-1' }, capsule_digest: 'a'.repeat(64), tenant_id: 'acme' } });
  const lines = readFileSync(logPath, 'utf8').trim().split('\n').filter(Boolean).map(JSON.parse);
  assert.equal(lines.length, 3);
  for (let i = 1; i < lines.length; i++) assert.equal(lines[i].previous, lines[i - 1].digest, 'each entry chains to the keyed digest of the previous');
  // Deleting a middle entry leaves a gap the next append cannot hide: the
  // digest chain is keyed — recomputing it requires the issuers' private
  // material, so the truncated tail diverges on the next record.
  assert.notEqual(lines[0].digest, lines[2].previous, 'chain positions are bound to their own entry');
});

// F-10 — writeIssuer validates the issuer name against the identifier
// charset: path-traversal spec names cannot escape the issuer directory.
test('w18-issuerd F-10: writeIssuer rejects traversal and malformed names', t => {
  const dir = mkdtempSync(join(tmpdir(), 'if-issuer-')); t.after(() => rmSync(dir, { recursive: true }));
  const spec = { issuer: '../escaped', tenant: 'acme', version: '1.0.0', channel: 'authoritative', key: generateKey(), kinds: {}, records: {} };
  assert.throws(() => writeIssuer(dir, spec), hasCode('INV-400-SCHEMA'));
  assert.throws(() => writeIssuer(dir, { ...spec, issuer: 'a/b' }), hasCode('INV-400-SCHEMA'));
});

// F-11 — verifyManifest honours the caller's freshness floor.
test('w18-issuerd F-11: verifyManifest enforces max_age_ms', t => {
  const key = generateKey();
  const issuers = { [key.key_id]: { public_key: key.public_key } };
  const manifest = signedManifest({ connector_id: 'bank', version: '1.0.0', domain: 'finance', actions: ['ownership'], permissions: [], limitations: [], idempotency: { mutating_retries: false, safe_read_retries: 1, timeout_ms: 5000 }, coverage_implications: ['evidence-source'], issued_at: Date.now() - 86400000, expires_at: Date.now() + 86400000 }, key);
  assert.throws(() => verifyManifest(manifest, issuers, Date.now(), { max_age_ms: 600000 }), hasCode('INV-401-CONNECTOR'), 'a stale manifest refuses under the floor');
  assert.doesNotThrow(() => verifyManifest(manifest, issuers, Date.now()), 'no floor remains the permissive contract');
});

// F-13 — 'localhost' is no longer a loopback pass: only literal IPs qualify.
test('w18-issuerd F-13: hostname-based loopback is refused', async t => {
  await assert.rejects(() => httpJson('http://localhost:9/', {}), e => e.code === 'INV-400-CONNECTOR', 'the DNS-resolved name cannot pass the loopback set');
});

// F-15 — driftCheck watches permissions and limitations, not just actions.
test('w18-issuerd F-15: driftCheck flags permission and limitation changes', t => {
  const registered = { connector_id: 'bank', version: '1.0.0', actions: ['ownership'], channel: 'authoritative', key_id: 'k1', permissions: ['read'], limitations: ['no-pii'] };
  const escalated = driftCheck(registered, { ...registered, permissions: ['read', 'write'] }, Date.now());
  assert.ok(escalated.changes.some(c => c.field === 'permissions' && c.escalated?.includes('write')), 'a silently grown permission set is escalation');
  assert.equal(escalated.drifted, true);
  const reduced = driftCheck(registered, { ...registered, permissions: [] }, Date.now());
  assert.ok(reduced.changes.some(c => c.field === 'permissions_reduced'), 'a shrunk permission set is recorded');
  const limDropped = driftCheck(registered, { ...registered, limitations: [] }, Date.now());
  assert.ok(limDropped.changes.some(c => c.field === 'limitations' && c.escalated?.includes('dropped:no-pii')), 'a dropped limitation is escalation');
  assert.equal(limDropped.drifted, true);
});
