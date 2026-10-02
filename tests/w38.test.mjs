// w38: seal-attestation honesty wave — the signed head claims only
// VERIFIED residue (a planted records row can no longer wedge every
// fold forever), a wiped chain-heads file is attested prior_head_
// unverifiable instead of passing the residue consult silently,
// floor_derived carried through a surviving seal never gates the
// remediation caller or fakes a key death, the recount re-verifies
// counted rows, unreadable floor rows are named, carried key deaths
// pin at orig_seq on every verifier, consume() budgets seal-dropped
// events, and corrupt grant rows surface as evidence.
import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import net from 'node:net';
import { rmSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fixture, designateSuccessor, runtimeInput, runtimeRequest } from './helpers.mjs';
import { digest, canonical } from '../src/canonical.mjs';
import { createServer } from '../src/server.mjs';

async function httpFixture(t, serverOpts = {}) {
  const h = fixture(t), app = createServer(h.f, { port: 0, origin: 'http://127.0.0.1:17777', ...serverOpts });
  await app.listen(); t.after(() => app.close());
  const port = app.server.address().port;
  const request = (path, { method = 'GET', body, token = h.setup.credentials.acme.security, headers = {} } = {}) => new Promise((resolve, reject) => {
    const payload = body === undefined ? undefined : JSON.stringify(body);
    const req = http.request({ host: '127.0.0.1', port, path, method, headers: { Host: '127.0.0.1:17777', ...(token ? { Authorization: `Bearer ${token}` } : {}), ...(payload === undefined ? {} : { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) }), ...headers } }, response => {
      const chunks = []; response.on('data', c => chunks.push(c)); response.on('end', () => { const s = Buffer.concat(chunks).toString('utf8'); let data; try { data = JSON.parse(s); } catch { data = s; } resolve({ status: response.statusCode, data }); });
    }); req.on('error', reject); req.end(payload);
  });
  return { ...h, request, app, port };
}

const dropAuditGuards = h => {
  for (const tr of h.f.store.db.prepare("SELECT name FROM sqlite_master WHERE type='trigger' AND tbl_name='audit'").all())
    h.f.store.db.exec(`DROP TRIGGER "${tr.name}"`);
};
const corruptAt = (h, seq) =>
  h.f.store.db.prepare("UPDATE audit SET envelope=? WHERE tenant='acme' AND seq=?")
    .run('{"payload":{"time":1},"signatures":[{"signature":"AA"}]}', seq);
const delRow = (h, seq) => h.f.store.db.prepare("DELETE FROM audit WHERE tenant='acme' AND seq=?").run(seq);
const delRecord = (h, kind, id) => {
  h.f.store.db.prepare('DELETE FROM deks WHERE tenant=? AND kind=? AND id=?').run('acme', kind, id);
  h.f.store.db.prepare('DELETE FROM records WHERE tenant=? AND kind=? AND id=?').run('acme', kind, id);
};
const chainRows = h => h.f.store.db.prepare("SELECT seq,envelope FROM audit WHERE tenant='acme' ORDER BY seq").all()
  .map(r => ({ seq: r.seq, env: JSON.parse(r.envelope) }));
const lastSeq = h => h.f.store.db.prepare("SELECT seq FROM audit WHERE tenant='acme' ORDER BY seq DESC LIMIT 1").get().seq;

// A seal carrying >512 entries spills onto AUDIT_SEAL_CARRY pages.
const buildSealedWithPages = t => {
  const h = fixture(t);
  designateSuccessor(h, 'audit');
  for (let i = 0; i < 600; i++) h.f.store.audit('acme', 'W38_PAD', 'operator', `pad-${i}`, { i }, h.now());
  dropAuditGuards(h);
  corruptAt(h, h.f.store.db.prepare("SELECT seq FROM audit WHERE tenant='acme' AND envelope LIKE '%pad-0%'").get().seq);
  const r = h.f.sealAuditChain(h.p('security'));
  assert.equal(r.sealed, true);
  return { h, r };
};

test('w38 store-F1: a planted audit-checkpoint row cannot poison the next signed head', t => {
  const h = fixture(t);
  h.f.exportAudit(h.p('auditor'), 'checkpoint baseline');
  const head0 = h.f._chainHead('acme');
  assert.equal(head0.checkpoints, 1, 'the honest export must be the only claimed checkpoint');
  // One unsigned records INSERT — the w38-store PoC primitive.
  h.f.store.db.prepare("INSERT INTO records(tenant,kind,id,value,created) VALUES('acme','audit-checkpoint','cp-999999','{}',0)").run();
  h.f.store.audit('acme', 'W38_PAD', 'operator', 'pad', {}, h.now()); // mints a fresh head
  const head = h.f._chainHead('acme');
  assert.ok(head.seq > head0.seq, 'a new head must land');
  assert.equal(head.checkpoints, 1, 'the signed claim binds only VERIFIED checkpoints');
  assert.ok(head.checkpoint < 999999, 'the claimed newest checkpoint is the real export');
  assert.doesNotThrow(() => h.f._auditIndex('acme'), 'the fold must not wedge on a claim it never made');
});

test('w38 fixverify-F1: wiping chain-heads.json is attested prior_head_unverifiable, never silent', t => {
  // Cut path: deleted head + doomed tail → the seal record names the
  // destroyed attestation.
  {
    const h = fixture(t); h.ready();
    rmSync(join(h.directory, 'chain-heads.json'), { force: true });
    rmSync(join(h.directory, 'head-watermark.json'), { force: true });
    dropAuditGuards(h);
    corruptAt(h, lastSeq(h));
    const r = h.f.sealAuditChain(h.p('security'));
    assert.equal(r.sealed, true);
    assert.equal(r.prior_head_unverifiable, true, 'the result must name the destroyed attestation');
    const seal = chainRows(h).find(x => x.env.payload.type === 'AUDIT_SEALED');
    assert.equal(seal.env.payload.metadata.prior_head_unverifiable, true, 'the signed record must name it too');
  }
  // Re-anchor path: clean chain, head file gone — the recovery event
  // names what it replaces.
  {
    const h = fixture(t); h.ready();
    rmSync(join(h.directory, 'chain-heads.json'), { force: true });
    const r = h.f.sealAuditChain(h.p('security'));
    assert.equal(r.sealed, false);
    const ev = chainRows(h).find(x => x.env.payload.type === 'AUDIT_HEAD_REANCHORED');
    assert.equal(ev.env.payload.metadata.prior_head_unverifiable, true, 're-anchor after head loss is evidence, not a clean mint');
  }
});

test('w38 store-F2: floor_derived promoted through a surviving seal never gates the caller', t => {
  const h = fixture(t); h.ready();
  // Plant an unanchored revocation floor for the sealer's own ref.
  h.f.store.db.prepare("INSERT INTO records(tenant,kind,id,value,created) VALUES('acme','revocation','subject:security','{}',0)").run();
  dropAuditGuards(h);
  corruptAt(h, lastSeq(h));
  const r1 = h.f.sealAuditChain(h.p('security'));
  assert.equal(r1.sealed, true, 'H-2: the first seal must exempt floor_derived from the caller gate');
  assert.ok(r1.floor_derived.includes('subject:security'));
  // The ref now sits inside a SURVIVING signed carry — the caller gates
  // must keep honoring floor_derived or the next seal bricks forever.
  dropAuditGuards(h);
  corruptAt(h, lastSeq(h));
  const r2 = h.f.sealAuditChain(h.p('security'));
  assert.equal(r2.sealed, true, 'a planted floor must never disable remediation');
  // The ref still enforces chain-side (fail-closed), it just cannot aim
  // the refusal at the operator running the repair.
  assert.equal(h.f.revoked('acme', 'subject', 'security'), true);
});

test('w38 store-F2: a floor_derived key: ref enforces — repoint under a designated successor', t => {
  const h = fixture(t); h.ready();
  const auditKid = h.f.tenant('acme').keys.audit.key_id;
  designateSuccessor(h, 'audit');
  // Pad past the designation rows so the doomed span starts ABOVE them —
  // the repoint needs a surviving ceremony anchor.
  for (let i = 0; i < 2; i++) h.f.store.audit('acme', 'W38_PAD', 'operator', `pad-${i}`, {}, h.now());
  h.f.store.db.prepare("INSERT INTO records(tenant,kind,id,value,created) VALUES('acme','revocation',?, '{}',0)").run(`key:${auditKid}`);
  dropAuditGuards(h);
  corruptAt(h, lastSeq(h));
  const r = h.f.sealAuditChain(h.p('security'));
  assert.equal(r.sealed, true);
  assert.ok(r.floor_derived.includes(`key:${auditKid}`));
  // Floor-derived revocation claims enforce fail-closed by design: the
  // claimed-dead key repoints under the designated successor (w35-H1).
  assert.notEqual(h.f.tenant('acme').keys.audit.key_id, auditKid);
});

test('w38 store-F3: a seal attesting a totals shape without lifecycle never wedges the recount', t => {
  const h = fixture(t); h.ready();
  // An honestly-signed AUDIT_SEALED in the pre-w34 shape — totals lack
  // the lifecycle class entirely.
  h.f.store.audit('acme', 'AUDIT_SEALED', 'security', 'audit', { sealed_at_seq: 1, removed_count: 0, spend_carryover: [], access_carryover: [], capabilities_cut: [], revocations_carryover: [], lifecycle_carryover: [], carryover_pages: 0, carryover_totals: { spend: 0, access: 0, revocations: 0, capabilities: 0, mirrors_dropped: 0, dropped_events: 0 } }, h.now());
  assert.doesNotThrow(() => h.f._auditIndex('acme'), 'a class the seal never attested must not wedge the fold');
  assert.doesNotThrow(() => h.f.sealAuditChain(h.p('security')), 'nor the remediation path');
});

test('w38 fixverify-F2: a forged AUDIT_SEAL_CARRY page counts as destroyed residue, not a surviving one', t => {
  const { h } = buildSealedWithPages(t);
  const pages = chainRows(h).filter(x => x.env.payload.type === 'AUDIT_SEAL_CARRY');
  assert.ok(pages.length >= 1);
  const mid = pages[0];
  // Replace the page with unsigned attacker JSON still carrying the real
  // seal_seq — present but unverifiable, it must NOT satisfy the claim.
  dropAuditGuards(h);
  h.f.store.db.prepare("UPDATE audit SET envelope=? WHERE tenant='acme' AND seq=?")
    .run(JSON.stringify({ payload: { type: 'AUDIT_SEAL_CARRY', tenant_id: 'acme', sequence: mid.seq, time: 1, metadata: { seal_seq: mid.env.payload.metadata.seal_seq, spend_carryover: [], access_carryover: [], revocations_carryover: [], capabilities_cut: [], lifecycle_carryover: [] } }, signatures: [{ signature: 'AA' }] }), mid.seq);
  assert.throws(() => h.f._auditIndex('acme'), e => /^INV-409/.test(e?.code ?? ''));
});

test('w38 fixverify-F3: an unreadable floor row under a legacy anchor is named murdered', t => {
  const h = fixture(t); h.ready();
  // A revocation anchor WITHOUT record_digest (legacy shape — content
  // check skipped): the floor row corrupted to ciphertext is neither
  // plantable-convicted nor silently enforced — it is named murdered.
  h.f.store.audit('acme', 'AUTHORITY_REVOKED', 'security', 'subject:auditor', { kind: 'subject', id: 'auditor' }, h.now());
  h.f.store.put('acme', 'revocation', 'subject:auditor', { kind: 'subject', id: 'auditor' }, h.now());
  for (let i = 0; i < 2; i++) h.f.store.audit('acme', 'W38_PAD', 'operator', `pad-${i}`, {}, h.now());
  rmSync(join(h.directory, 'chain-heads.json'), { force: true });
  rmSync(join(h.directory, 'head-watermark.json'), { force: true });
  h.f.store.db.prepare("UPDATE records SET value=? WHERE tenant='acme' AND kind='revocation' AND id='subject:auditor'").run('garbage-ciphertext');
  dropAuditGuards(h);
  corruptAt(h, lastSeq(h));
  const r = h.f.sealAuditChain(h.p('security'));
  assert.equal(r.sealed, true);
  assert.ok(r.murdered_floor_refs.includes('subject:auditor'), `unreadable floor must be named murdered: ${JSON.stringify(r.murdered_floor_refs)}`);
});

test('w38 fixverify-F4: the standalone verifier pins carried key deaths at orig_seq', t => {
  const h = fixture(t);
  const pending = h.f.prepareRotation(h.p('security'), 'audit');
  // A doomed AUTHORITY_REVOKED carried into a seal — its orig_seq is the
  // real death position; the verifier must pin there, not at the page.
  // revoke() writes both the anchor and the floor row.
  h.f.revoke(h.p('security'), { kind: 'key', id: pending.key_id, reason: 'drill' });
  const deathSeq = h.f.store.db.prepare("SELECT seq FROM audit WHERE tenant='acme' AND envelope LIKE '%AUTHORITY_REVOKED%' ORDER BY seq DESC LIMIT 1").get().seq;
  dropAuditGuards(h);
  // Doom the span by corrupting a row BEFORE the revocation — the
  // revocation row itself still verifies, so it carries with orig_seq.
  corruptAt(h, deathSeq - 1);
  const r = h.f.sealAuditChain(h.p('security'));
  assert.equal(r.sealed, true);
  const deaths = h.f.store._auditKeyDeaths('acme');
  assert.equal(deaths.get(pending.key_id), deathSeq, 'carried death must pin at the event seq, not the carry seq');
});

test('w38 runtime-F1: consume() budgets seal-dropped events at worst-case coverage', t => {
  const h = fixture(t); h.ready();
  const cap = h.f.runtime.issue(h.p(), runtimeInput({ row_ids: ['row-1'] }));
  assert.equal(h.f.runtime.consume(h.p(), runtimeRequest(cap)).decision, 'ALLOW');
  // Doom an audit row so the seal drops it unverified.
  dropAuditGuards(h);
  corruptAt(h, lastSeq(h));
  const r = h.f.sealAuditChain(h.p('security'));
  assert.equal(r.sealed, true);
  assert.ok(r.carryover_totals.dropped_events >= 1, 'the dropped row must be counted');
  const cap2 = h.f.runtime.issue(h.p(), runtimeInput({ row_ids: ['row-1'] }));
  assert.throws(() => h.f.runtime.consume(h.p(), runtimeRequest(cap2)),
    e => e?.code === 'INV-429-BUDGET' && e.details?.coverage_percent === 100);
});

test('w38 runtime-L1: corrupt grant rows surface on the grant listing', t => {
  const h = fixture(t); h.ready();
  h.f.target.grant('acme', 'g-ok', { grant_id: 'g-ok', subject_id: 'operator', roles: ['security'], resources: [], actions: [], destinations: [], columns: [], row_ids: [], expires_at: h.now() + 60000, revoked: false });
  h.f.target.grant('acme', 'g-bad', { grant_id: 'g-bad', subject_id: 'operator', roles: ['security'], resources: [], actions: [], destinations: [], columns: [], row_ids: [], expires_at: h.now() + 60000, revoked: false });
  h.f.target.db.prepare("UPDATE grants SET value=? WHERE tenant='acme' AND grant_id='g-bad'").run('garbage');
  const res = h.f.listGrants(h.p());
  assert.equal(res.corrupt_grant_rows, 1, 'the hidden-grant evidence must be named');
  assert.ok(res.items.some(g => g.grant_id === 'g-ok'));
});

test('w38 http: key attestation binds the caller nonce and the spec declares it', async t => {
  const h = await httpFixture(t); h.ready();
  const keyId = h.f.vault.list().filter(k => h.f.ownsVaultKey('acme', k.key_id))[0].key_id;
  const r = await h.request(`/v1/keys/${keyId}/attest?nonce=challenge-7`);
  assert.equal(r.status, 200, JSON.stringify(r.data));
  assert.equal(r.data.payload.nonce, 'challenge-7');
  const r2 = await h.request(`/v1/keys/${keyId}/attest?nonce=other`);
  assert.equal(r2.data.payload.nonce, 'other', 'the served attestation must bind the caller-supplied challenge');
  const spec = JSON.parse(readFileSync(new URL('../docs/openapi.json', import.meta.url), 'utf8'));
  const params = spec.paths['/v1/keys/{id}/attest'].get.parameters ?? [];
  assert.ok(params.some(x => x.name === 'nonce' && x.in === 'query'), 'openapi must document the nonce query parameter');
});

test('w38 http: the resources route scrubs secret-named material fields', async t => {
  const h = await httpFixture(t); h.ready();
  h.f.target.seed('acme', 'registry-1', { display: 'vendor', api_key: 'live-secret-bytes', nested: { password: 'pw', note: 'ok' } });
  const r = await h.request('/v1/resources/registry-1', { token: h.setup.credentials.acme.operator });
  assert.equal(r.status, 200, JSON.stringify(r.data));
  assert.equal(r.data.material_fields.api_key, '«redacted»');
  assert.equal(r.data.material_fields.nested.password, '«redacted»');
  assert.equal(r.data.material_fields.nested.note, 'ok');
  assert.equal(r.data.material_fields.display, 'vendor');
});

test('w38 http: a sparse view projection pages forward instead of under-filling', t => {
  const h = fixture(t); h.ready();
  // Seed a chain where 'privacy' matches are sparse — one in every few rows.
  for (let i = 0; i < 4; i++) {
    h.f.store.audit('acme', 'RETENTION_DELETED', 'system', `res-${i}`, { resource: `res-${i}` }, h.now());
    h.f.store.audit('acme', 'CONFIG_SNAPSHOT', 'system', 'config', { config_digest: `d${i}` }, h.now());
    h.f.store.audit('acme', 'KEY_ROTATED', 'system', 'vault', { key_id: `k${i}` }, h.now());
  }
  const PRIVACY = new Set(['RETENTION_DELETED', 'RETENTION_HOLD_CHANGED', 'CAPABILITY_ISSUED', 'RUNTIME_ALLOWED', 'PERCEPTION_SESSION', 'PERCEPTION_RELEASE', 'PERCEPTION_FALLBACK', 'AUDIT_ACCESSED']);
  const page = h.f.auditPageScoped(h.p('auditor'), { limit: 4, view: 'privacy' });
  assert.equal(page.entries.length, 4, 'the projection must page forward until the limit fills');
  for (const e of page.entries) assert.ok(PRIVACY.has(e.envelope.payload.type), `non-privacy type ${e.envelope.payload.type} leaked into the projection`);
  // Cursor continuation must collect every remaining match — no skipped
  // rows between the served tail and the raw scan position.
  const seen = new Set(page.entries.map(e => e.sequence));
  for (let cursor = page.next_cursor; cursor !== null;) {
    const next = h.f.auditPageScoped(h.p('auditor'), { limit: 4, view: 'privacy', after: cursor });
    for (const e of next.entries) { assert.ok(!seen.has(e.sequence), `seq ${e.sequence} served twice`); seen.add(e.sequence); assert.ok(PRIVACY.has(e.envelope.payload.type)); }
    cursor = next.next_cursor;
  }
  assert.ok(seen.size >= 4);
});

test('w38 http: the connection cap cannot starve the health probes', async t => {
  const h = await httpFixture(t, { connectionCap: 3 });
  // Hold the cap full plus over-cap sockets open without a request line.
  const held = [];
  for (let i = 0; i < 5; i++) held.push(await new Promise((resolve, reject) => { const s = net.connect(h.port, '127.0.0.1', () => resolve(s)); s.on('error', reject); }));
  t.after(() => { for (const s of held) s.destroy(); });
  const health = await h.request('/healthz', { token: null });
  assert.equal(health.status, 200, 'an over-cap socket must still serve a health probe');
  const gated = await new Promise(resolve => {
    const req = http.request({ host: '127.0.0.1', port: h.port, path: '/v1/me', method: 'GET' }, res => resolve(res.statusCode));
    req.on('error', () => resolve('destroyed')); req.end();
  });
  assert.ok(gated === 'destroyed' || gated === 503, `over-cap non-probe request must be killed, got ${gated}`);
});
