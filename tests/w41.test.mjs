// w41: hostile-audit wave — verified-only chain facts (a planted
// AUTHORITY_REVOKED/KEY_ROTATED mints no death, quorum or successor),
// rollback eviction of phantom-consumed index heads, honest destroyed-row
// magnitudes (a planted far-future seq attests a span, not a count), the
// rotating consumed-row re-verification sweep, break-glass HTTP seal auth
// (a wedged chain must not deadlock its own remediation), cookie CSRF on
// audit-writing GETs, bodiless-POST drains, acknowledge path binding, and
// post-auth query validation.
import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { fixture, designateSuccessor } from './helpers.mjs';
import { digest } from '../src/canonical.mjs';
import { createServer } from '../src/server.mjs';
import { signAcknowledgement } from '../src/ceremony.mjs';

const dropAuditGuards = h => {
  for (const tr of h.f.store.db.prepare("SELECT name FROM sqlite_master WHERE type='trigger' AND tbl_name='audit'").all())
    h.f.store.db.exec(`DROP TRIGGER "${tr.name}"`);
};
const lastSeq = h => h.f.store.db.prepare("SELECT seq FROM audit WHERE tenant='acme' ORDER BY seq DESC LIMIT 1").get().seq;
const wmPath = h => join(h.directory, 'head-watermark.json');
const headsPath = h => join(h.directory, 'chain-heads.json');
const forgedRow = (h, seq, type, extra = {}) => ({
  protected: { profile: 'IF-CJSON-1', suite: 'Ed25519', key_id: h.f.keys('acme').audit.key_id, purpose: 'audit' },
  payload: { type, tenant_id: 'acme', sequence: seq, time: h.now(), actor: 'planted', reference: 'x', metadata: {}, ...extra },
  signature: 'A'.repeat(86),
});
const plantRow = (h, seq, row) => {
  const prev = h.f.store.db.prepare("SELECT hash FROM audit WHERE tenant='acme' AND seq=?").get(seq - 1);
  h.f.store.db.prepare('INSERT INTO audit VALUES(?,?,?,?,?)').run('acme', seq, prev?.hash ?? '', digest(row.payload), JSON.stringify(row));
};

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
  return { ...h, request, app, port };
}

test('w41-fv F-1/F-2: planted unsigned lifecycle rows mint no deaths, quorums, or successors', t => {
  const h = fixture(t, ['acme']);
  h.proposed(); h.f._auditIndex('acme');
  const bound = h.f.keys('acme').audit.key_id;
  dropAuditGuards(h);
  // Plant an unverified key death AND an unverified rotation that would
  // have steered every consumer — verified-only facts ignore both.
  plantRow(h, lastSeq(h) + 1, forgedRow(h, lastSeq(h) + 1, 'AUTHORITY_REVOKED', { reference: `key:${bound}`, metadata: { reason_digest: 'x', record_digest: 'y' } }));
  const keyId2 = 'planted-successor';
  plantRow(h, lastSeq(h) + 1, forgedRow(h, lastSeq(h) + 1, 'KEY_ROTATED', { reference: keyId2, metadata: { previous_key_id: bound, key_class: 'audit' } }));
  const facts = h.f._chainFacts('acme');
  assert.ok(!facts.dead.has(bound), 'a forged AUTHORITY_REVOKED must not kill the signer');
  assert.ok(!facts.succ.has(bound), 'a forged KEY_ROTATED must not mint a successor');
  assert.ok(facts.refsDead.size === 0, 'a forged revocation must not reference-kill anything');
});

test('w41-seal F2: a phantom index head from a rolled-back fold never wedges the next fold', t => {
  const h = fixture(t, ['acme']);
  h.proposed(); h.f._auditIndex('acme');
  const committed = lastSeq(h);
  try {
    h.f.store.tx(() => {
      h.f.store.audit('acme', 'POLICY_STAGED', 'operator', 'doomed', {}, h.now());
      h.f._auditIndex('acme');
      throw new Error('abort the batch');
    });
    assert.fail('the abort must surface');
  } catch { /* expected rollback */ }
  // The doomed row is gone — an index that kept it would wedge every later
  // fold on "truncated below the consumed index" (INV-409-AUDIT-TAMPER).
  const idx = h.f._auditIndex('acme');
  assert.equal(idx.maxSeq, committed, 'the consumed head tracks only committed truth');
});

test('w41-seal F5: a planted far-future seq attests its span, never a fabricated destroyed-row magnitude', t => {
  const h = fixture(t, ['acme']);
  h.proposed(); h.f._auditIndex('acme');
  dropAuditGuards(h);
  const far = 1_000_000;
  plantRow(h, far, forgedRow(h, far, 'AUDIT_NOTE'));
  const r = h.f.sealAuditChain(h.p('security'));
  assert.equal(r.sealed, true);
  assert.equal(r.carryover_totals?.deleted_rows_total ?? r.deleted_rows_total, 0, 'stored seq-space cannot mint destroyed rows — only verified payloads bound a magnitude');
  assert.ok((r.carryover_totals?.deleted_gaps_total ?? r.deleted_gaps_total) >= 1, 'the inflated span is still attested as a gap');
  assert.deepEqual(r.deleted_gaps?.[0]?.[1], far, 'the gap names the planted seq boundary');
});

test('w41-fv F-3: tail deletes that renumber under the cursor re-derive chain facts and wedge honestly', t => {
  const h = fixture(t, ['acme']);
  h.proposed();
  h.f.revoke(h.p('security'), { kind: 'subject', id: 'operator', reason: 'w41 probe' });
  h.f._auditIndex('acme');
  assert.ok(h.f.revoked('acme', 'subject', 'operator'), 'precondition: revocation folded');
  dropAuditGuards(h);
  // Delete the two tail rows (the revocation event is one of them) and
  // re-land a benign row at MAX+1 — the count/maxSeq fingerprint catches
  // the regression and the surviving floor row indicts the gap.
  const revSeq = h.f.store.db.prepare("SELECT seq FROM audit WHERE tenant='acme' AND envelope LIKE '%AUTHORITY_REVOKED%' ORDER BY seq DESC LIMIT 1").get().seq;
  const tip = lastSeq(h);
  for (const s of [tip, tip - 1]) h.f.store.db.prepare("DELETE FROM audit WHERE tenant='acme' AND seq=?").run(s);
  plantRow(h, tip - 1, forgedRow(h, tip - 1, 'AUDIT_NOTE'));
  assert.ok(revSeq >= tip - 1, 'test premise: the revocation sat in the deleted tail');
  assert.throws(() => h.f._auditIndex('acme'), e => e?.code?.startsWith('INV-409'), 'a renumbered tail that buried a revocation event must wedge the fold');
});

test('w41-http F7: rewriting a consumed mid-chain row is convicted on the rotating re-verify sweep', t => {
  const h = fixture(t, ['acme']);
  h.proposed(); h.f._auditIndex('acme');
  const victim = Math.max(1, lastSeq(h) - 1);
  dropAuditGuards(h);
  const row = h.f.store.db.prepare("SELECT envelope FROM audit WHERE tenant='acme' AND seq=?").get(victim);
  const env = JSON.parse(row.envelope);
  env.signature = 'A'.repeat(86);
  h.f.store.db.prepare("UPDATE audit SET envelope=? WHERE tenant='acme' AND seq=?").run(JSON.stringify(env), victim);
  // The sweep rotates a bounded window per fold — the victim is convicted
  // within a bounded number of folds.
  assert.throws(() => { for (let i = 0; i <= lastSeq(h) + 2; i++) h.f._auditIndex('acme'); }, e => e?.code?.startsWith('INV-409'), 'mid-chain surgery must convict the table');
});

test('w41-http F1: /v1/audit/seal authenticates against the frozen auth table on a wedged chain', async t => {
  const h = await httpFixture(t);
  h.proposed();
  dropAuditGuards(h);
  plantRow(h, lastSeq(h) + 1, forgedRow(h, lastSeq(h) + 1, 'AUDIT_NOTE'));
  // A wedged ledger must still answer its own break-glass remediation —
  // chain-derived auth (revoked + authorize) is exactly what is down.
  const r = await h.request('/v1/audit/seal', { method: 'POST', body: {} });
  assert.equal(r.status, 200, `wedged seal must still run, got ${r.status}: ${JSON.stringify(r.data).slice(0, 200)}`);
  assert.equal(r.data.sealed, true);
  const bad = await h.request('/v1/audit/seal', { method: 'POST', body: {}, token: 'Z'.repeat(43) });
  assert.equal(bad.status, 401);
});

test('w41-http F4: audit-writing GETs require the CSRF+Origin proof under cookie auth', async t => {
  const h = await httpFixture(t);
  const login = await h.request('/session', { method: 'POST', token: null, body: { token: h.setup.credentials.acme.security }, headers: { Origin: 'http://127.0.0.1:17777' } });
  assert.equal(login.status, 200);
  const cookie = login.headers['set-cookie'][0].split(';')[0];
  const csrf = login.data.csrf_token;
  // No CSRF header under the ambient cookie → the ledger-writing GET
  // refuses like a POST would.
  const noCsrf = await h.request('/v1/audit/entries', { token: null, headers: { Cookie: cookie, Origin: 'http://127.0.0.1:17777' } });
  assert.equal(noCsrf.status, 403, `cookie GET without CSRF must refuse, got ${noCsrf.status}`);
  const withCsrf = await h.request('/v1/audit/entries', { token: null, headers: { Cookie: cookie, Origin: 'http://127.0.0.1:17777', 'X-CSRF-Token': csrf } });
  assert.equal(withCsrf.status, 200, `bound cookie GET must pass, got ${withCsrf.status}`);
  const bearer = await h.request('/v1/audit/entries');
  assert.equal(bearer.status, 200, 'Bearer stays CSRF-exempt');
});

test('w41-http F5: bodiless POST routes drain and validate the body', async t => {
  const h = await httpFixture(t);
  const junk = await h.request('/gate/v1/outcomes/cert-1', { method: 'POST', body: { anything: true } });
  assert.equal(junk.status, 400, `non-empty body on a bodiless route must 400, got ${junk.status}`);
  const badType = await h.request('/gate/v1/outcomes/cert-1', { method: 'POST', rawBody: 'not json', headers: { 'Content-Type': 'text/plain' } });
  assert.equal(badType.status, 415, `wrong content-type must 415, got ${badType.status}`);
});

test('w41-http F3: acknowledge binds the path ceremony to the signed body', async t => {
  const h = await httpFixture(t);
  h.proposed();
  const custodians = ['custodian-1', 'custodian-2'];
  const cer = h.f.createCeremony(h.p('security'), { ceremony_id: 'cer-w41', purpose: 'documented drill', threshold: 2, custodians, valid_until: h.now() + 3600000, min_delay_ms: 120000 });
  const ack = signAcknowledgement(cer, 'custodian-1', h.setup.custodianKeys.acme['custodian-1'], h.now());
  // A valid ack envelope for ceremony A posted to path B must refuse —
  // the signer consented to exactly one ceremony id.
  const wrong = await h.request('/v1/ceremonies/other-ceremony/acknowledge', { method: 'POST', token: h.setup.credentials.acme['custodian-1'] ?? h.setup.credentials.acme.security, body: ack });
  assert.equal(wrong.status, 400, `path/body mismatch must 400, got ${wrong.status}`);
});

test('w41-http F8: query validation happens post-auth — anonymous probes see only 401', async t => {
  const h = await httpFixture(t);
  const anon = await h.request('/v1/audit/entries?bogus=1', { token: null });
  assert.equal(anon.status, 401, `pre-auth bad query must not leak the allowlist, got ${anon.status}`);
  const authed = await h.request('/v1/audit/entries?bogus=1');
  assert.equal(authed.status, 400, `post-auth bad query still 400s, got ${authed.status}`);
});

test('w41-http F2: /v1/me serves effective grant-derived roles', async t => {
  const h = await httpFixture(t);
  const r = await h.request('/v1/me', { token: h.setup.credentials.acme.security });
  assert.equal(r.status, 200);
  const folded = h.f.grantsFor('acme', r.data.subject_id, h.f.clock()).roles ?? [];
  assert.deepEqual([...r.data.roles].sort(), [...folded].sort(), '/v1/me must reflect authorize-semantic roles');
});
