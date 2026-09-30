import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fixture } from './helpers.mjs';
import { createIssuerServer, loadIssuers, writeIssuer } from '../src/issuerd.mjs';
import { ISSUER_RULES } from '../src/bootstrap.mjs';

// w8-ledger COV-004: the full drift chain is exercised end-to-end — a live
// issuerd manifest change moves a declared path to UNKNOWN and opens an owner
// task through checkIssuerDrift → driftCheck → applyDriftToPaths →
// coverageTransition. Previously only the last-hop helper was unit-tested.
const declareBankPath = (h, id = 'path-bank-1') => h.f.declareCoverage(h.p('security'), {
  path_id: id, action_type: 'payment.submit', target: 'bank', environment: 'production',
  connector_version: '1.0.0', owner: 'bank-owner', status: 'MONITORED',
  max_age_ms: 600000, configuration_digest: 'a'.repeat(64)
});

const bankEntry = h => Object.entries(h.f.tenant('acme').issuers).find(([, v]) => v.name === 'bank');

const serve = async (t, spec, clock) => {
  const dir = mkdtempSync(join(tmpdir(), 'if-issuerdrift-')); t.after(() => rmSync(dir, { recursive: true }));
  writeIssuer(dir, spec);
  const srv = createIssuerServer(loadIssuers(dir), { port: 0, host: '127.0.0.1', clock });
  await srv.listen(); t.after(() => srv.close());
  return srv;
};

test('COV-004: a live manifest drift drops the dependent path to UNKNOWN and opens an owner task', async t => {
  const h = fixture(t, ['acme']);
  const [bankKeyId, bank] = bankEntry(h);
  const baseSpec = { issuer: 'bank', tenant: 'acme', channel: 'authoritative', key: h.setup.issuerKeys.acme['bank'], kinds: ISSUER_RULES.bank, records: {}, issue_token: bank.issue_token, read_token: bank.read_token };
  bank.endpoint = `http://127.0.0.1:${(await serve(t, { ...baseSpec, version: '1.0.0' }, () => h.now())).server.address().port}`;
  declareBankPath(h);
  const clean = await h.f.checkIssuerDrift(h.p('security'), bankKeyId);
  assert.equal(clean.drifted, false);
  assert.equal(h.f.store.must('acme', 'coverage', 'path-bank-1').status, 'MONITORED');
  // The issuer upgrades without a matching config registration → drifted.
  const srv2 = await serve(t, { ...baseSpec, version: '9.9.9' }, () => h.now());
  bank.endpoint = `http://127.0.0.1:${srv2.server.address().port}`;
  const drifted = await h.f.checkIssuerDrift(h.p('security'), bankKeyId);
  assert.equal(drifted.drifted, true);
  assert.equal(drifted.coverage_paths_staled, 1);
  const path = h.f.store.must('acme', 'coverage', 'path-bank-1');
  assert.equal(path.status, 'UNKNOWN');
  assert.equal(path.evidence_at, null);
  const task = h.f.store.must('acme', 'coverage-task', `connector-drift:${bankKeyId}:path-bank-1`);
  assert.equal(task.status, 'open');
  assert.equal(task.owner, 'bank-owner');
});

// w8-ledger COV-005: evidence aging past max_age_ms is a recorded transition,
// not a computed convenience — the stored path, coverage-event log and owner
// task all move together.
test('COV-005: stale evidence transitions to UNKNOWN at read time with event and owner task', t => {
  const h = fixture(t, ['acme']);
  declareBankPath(h, 'path-stale-1');
  h.advance(600001);
  const manifest = h.f.coverage(h.p('auditor'));
  const stale = h.f.store.must('acme', 'coverage', 'path-stale-1');
  assert.equal(stale.status, 'UNKNOWN');
  const reported = manifest.payload.paths.find(p => p.path_id === 'path-stale-1');
  assert.equal(reported.effective_status, 'UNKNOWN');
  const task = h.f.store.must('acme', 'coverage-task', 'evidence-expired:path-stale-1');
  assert.equal(task.status, 'open');
  assert.equal(task.cause, 'evidence-expired');
  const events = h.f.store.list('acme', 'coverage-event', 100).filter(e => e.path_id === 'path-stale-1');
  assert.ok(events.some(e => e.cause === 'evidence-expired' && e.to === 'UNKNOWN'), JSON.stringify(events));
  // Idempotent: a second read must not re-fire the transition or the task.
  h.advance(1000);
  h.f.coverage(h.p('auditor'));
  assert.equal(h.f.store.list('acme', 'coverage-event', 100).filter(e => e.path_id === 'path-stale-1' && e.cause === 'evidence-expired').length, 1);
});

// COV-005 negative control: an unexpired path read produces no task.
test('COV-005: a fresh MONITORED path produces no expiry task or event', t => {
  const h = fixture(t, ['acme']);
  declareBankPath(h, 'path-fresh-1');
  h.f.coverage(h.p('auditor'));
  assert.equal(h.f.store.must('acme', 'coverage', 'path-fresh-1').status, 'MONITORED');
  assert.throws(() => h.f.store.must('acme', 'coverage-task', 'evidence-expired:path-fresh-1'), e => e?.code === 'INV-404-NOT-FOUND');
});
