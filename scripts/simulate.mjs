#!/usr/bin/env node
import { fixture, runtimeInput, runtimeRequest } from '../tests/helpers.mjs';
import { writeFileSync, readFileSync, copyFileSync, existsSync, mkdirSync, rmSync, mkdtempSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { bootstrap } from '../src/bootstrap.mjs';
import { digest, clone } from '../src/canonical.mjs';
import { verifyAudit } from '../src/store.mjs';
import { verifySigned } from '../src/crypto.mjs';
import { DatabaseSync } from 'node:sqlite';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
const h = fixture(null, ['acme']), scenarios = [];
function scenario(name, expected, fn) {
  try { const actual = fn(); scenarios.push({ name, expected, actual, pass: actual === expected }); }
  catch (e) { scenarios.push({ name, expected, actual: e.code ?? 'unexpected-error', pass: e.code === expected }); }
}
try {
  const ready = h.ready();
  scenario('Exact approved finance mutation', 'VERIFIED', () => h.f.execute(h.p(), ready.certificate).payload.status);
  scenario('Replay of consumed authority', 'INV-409-REPLAY', () => h.f.execute(h.p(), ready.certificate));
  const uncertain = h.ready(); scenario('Response lost after durable target commit', 'UNCERTAIN', () => h.f.execute(h.p(), uncertain.certificate, { fault: 'after-commit' }).payload.status);
  scenario('Reconcile post-commit timeout without repeat payment', 'VERIFIED', () => h.f.reconcile(h.p(), uncertain.certificate.payload.certificate_id).payload.status);
  scenario('Direct mutation without certificate', 'INV-401-SIGNATURE', () => h.f.execute(h.p(), {}));
  const drift = h.ready(); h.f.target.seed('acme', drift.record.capsule.action.target_resource, { drift: true });
  scenario('Target state changes after approval', 'INV-409-STATE', () => h.f.execute(h.p(), drift.certificate));
  const confused = h.proposed(); h.evidence(confused, { issuer: 'email' }); h.evidence(confused, { advisory: true }); h.approve(confused);
  scenario('CEO email and AI advice cannot authorise', 'ESCROW', () => h.f.evaluate(h.p(), confused.capsule.capsule_id).decision);
  const firewall = h.proposed('cloud.firewall.change', { protocol: 'tcp', port: 5432, source_cidr: '0.0.0.0/0', service_id: 'database' });
  scenario('Public database exposure request', 'DENY', () => h.f.evaluate(h.p(), firewall.capsule.capsule_id).decision);
  const cap = h.f.runtime.issue(h.p(), runtimeInput());
  scenario('Synthetic minimum-column data read', 'ALLOW', () => h.f.runtime.consume(h.p(), runtimeRequest(cap)).decision);
  scenario('Destination substitution', 'INV-403-SCOPE', () => h.f.runtime.consume(h.p(), runtimeRequest(cap, { destination: 'attacker-storage' })));
  scenario('Restricted column injection', 'INV-403-SCOPE', () => h.f.runtime.consume(h.p(), runtimeRequest(cap, { columns: ['passport'] })));
  let allowed = 1, blocked = null;
  for (let i = 0; i < 60; i++) { h.advance(1001); try { const c = h.f.runtime.issue(h.p(), runtimeInput()); h.f.runtime.consume(h.p(), runtimeRequest(c)); allowed++; } catch (e) { blocked = e.code; break; } }
  scenario('Low-and-slow extraction across new capabilities', 'INV-429-BUDGET', () => blocked);
  // A gate dead after the very first consume would still satisfy the
  // throttle oracle — bound the useful work it must do first (release-audit M5).
  scenario('Budget throttling engages only after real capacity', true, () => allowed > 1);
  // NFR-OPS-005: staged canary rollout — a verified successor stages behind
  // its not_before slot, the old constitution keeps serving through the
  // window, then exactly one version promotes at activate_at.
  const active = h.f.policy('acme'), canary = clone(active);
  canary.version = 2; canary.policy_id = 'constitution:acme:v2'; canary.not_before = h.now() + 240000;
  canary.rules['finance.payment.first'].max_quantity = 5;
  const pc = h.proposed('policy.change', { policy: canary }, { action: { type: 'policy.change', target_resource: 'policy-root', purpose: 'Canary rollout' } });
  h.f.simulate(h.p('policy-admin'), canary); h.advance(120001);
  h.evidence(pc, { kind: 'governance_review' }); h.evidence(pc, { kind: 'governance_review', issuer: 'audit-committee' }); h.approve(pc, 3);
  const pcCert = h.f.certificate(h.p(), pc.capsule.capsule_id);
  scenario('Staged canary policy verifies and parks behind not_before', 'VERIFIED', () => h.f.execute(h.p(), pcCert).payload.status);
  scenario('Old constitution keeps serving inside the stage window', 1, () => h.f.policy('acme').version);
  h.advance(150000); h.proposed();
  scenario('Exactly one version promotes at activate_at', 2, () => h.f.policy('acme').version);
  scenario('Tightened rule applies after cutover', 5, () => h.f.policy('acme').rules['finance.payment.first'].max_quantity);
  h.f.revoke(h.p('security'), { kind: 'device', id: 'operator-device', reason: 'Synthetic endpoint agent loss' });
  scenario('Device quarantine prevents renewal', 'INV-403-QUARANTINE', () => h.f.runtime.issue(h.p(), runtimeInput()));
  const bundle = h.f.exportAudit(h.p('auditor'), 'Synthetic simulation evidence');
  scenario('Offline signed audit integrity', true, () => verifyAudit(bundle, bundle.public_keys).valid);
  const tampered = clone(bundle); tampered.entries.splice(3, 1);
  scenario('Audit deletion detection', 'INV-409-AUDIT', () => verifyAudit(tampered, bundle.public_keys));
  mkdirSync('reports', { recursive: true });
  writeFileSync('reports/sample-audit.json', JSON.stringify(bundle, null, 2) + '\n');
  writeFileSync('reports/sample-pinned-trust.json', JSON.stringify(bundle.public_keys, null, 2) + '\n');
  writeFileSync('reports/sample-checkpoint.json', JSON.stringify(bundle.checkpoint.payload, null, 2) + '\n');
  const values = [null, true, false, 0, 9007199254740991, -9007199254740991, { b: 2, a: 1 }, { greeting: 'Žižek 🛡 café', nested: [1, { zero: 0 }] }, { '123hash': { x: '\n\t' } }, { alpha: ['é', '🎛'], omega: {} }];
  writeFileSync('examples/canonical-vectors.json', JSON.stringify(values.map((value, i) => ({ name: `vector-${i + 1}`, value, sha256: digest(value) })), null, 2) + '\n');
  // Backup/restore drill: a REAL deployment directory (bootstrap writes
  // master.key + keystore.json + config.json + dbs) is backed up with the
  // CLI, then verified offline with the restore-check tool.
  const drillDir = mkdtempSync(join(tmpdir(), 'if-drill-'));
  try {
    bootstrap(join(drillDir, 'deploy'), ['acme'], Date.now());
    const drill = spawnSync(process.execPath, ['scripts/backup.mjs', '--dir', join(drillDir, 'deploy'), '--out', join(drillDir, 'backup')], { encoding: 'utf8' });
    scenario('Engine-native online backup completes', 0, () => drill.status);
    const check = spawnSync(process.execPath, ['scripts/restore-check.mjs', '--dir', join(drillDir, 'backup'), '--trusted-keys', join(drillDir, 'deploy', 'config.json')], { encoding: 'utf8' });
    scenario('Offline restore verification of drill backup', 0, () => check.status);
    // NFR-OPS-005 rollback drill: a bad release clobbers the live store (a
    // corrupt write over real bytes is what a broken deploy actually does);
    // the rollback path restores the VERIFIED backup files, then proves the
    // restored deployment is both byte-identical to the backup and
    // functionally healthy — the db opens and every tenant's audit chain
    // re-verifies against the deployment's configured audit keys (w22-ledger).
    const drillDeploy = join(drillDir, 'deploy'), drillBackup = join(drillDir, 'backup');
    const drillConfig = JSON.parse(readFileSync(join(drillDeploy, 'config.json'), 'utf8'));
    const trustedAudit = {};
    for (const t of Object.values(drillConfig.tenants ?? {})) trustedAudit[t.keys.audit.key_id] = { public_key: t.keys.audit.public_key };
    const sha = f => createHash('sha256').update(readFileSync(f)).digest('hex');
    for (const name of ['fabric.db', 'target.db']) {
      const backupFile = join(drillBackup, name), liveFile = join(drillDeploy, name);
      if (!existsSync(backupFile) || !existsSync(liveFile)) continue;
      writeFileSync(liveFile, Buffer.concat([Buffer.from('BAD-RELEASE\0'), readFileSync(backupFile).subarray(64)]));
      for (const suffix of ['-wal', '-shm']) rmSync(liveFile + suffix, { force: true });
      copyFileSync(backupFile, liveFile);
      scenario(`Rollback of ${name} restores byte-identical deployment`, true, () => sha(liveFile) === sha(backupFile));
    }
    scenario('Rolled-back store opens and audit chain re-verifies', true, () => {
      const db = new DatabaseSync(join(drillDeploy, 'fabric.db'), { readOnly: true });
      try {
        const rows = db.prepare('SELECT tenant,seq,previous,hash,envelope FROM audit ORDER BY tenant,seq').all();
        const seen = {};
        for (const row of rows) {
          const prior = seen[row.tenant] ?? { seq: 0, hash: '0'.repeat(64) };
          if (row.seq !== prior.seq + 1 || row.previous !== prior.hash) return false;
          const entry = verifySigned(JSON.parse(row.envelope), trustedAudit, 'audit');
          if (digest(entry) !== row.hash) return false;
          seen[row.tenant] = { seq: row.seq, hash: row.hash };
        }
        return rows.length > 0;
      } finally { db.close(); }
    });
  } finally { rmSync(drillDir, { recursive: true, force: true }); }
  // Results are written AFTER every scenario — the report must cover the
  // drill scenarios too, not a prefix of the run.
  writeFileSync('reports/simulation-results.json', JSON.stringify({ simulated: true, real_systems_tested: false, scenarios, allowed_low_and_slow_queries: allowed, all_pass: scenarios.every(s => s.pass) }, null, 2) + '\n');
  console.log(JSON.stringify({ simulations: scenarios.length, passed: scenarios.filter(s => s.pass).length, audit_entries: bundle.entries.length, real_systems_tested: false }));
  if (scenarios.some(s => !s.pass)) process.exitCode = 1;
} finally { h.close(); rmSync(h.directory, { recursive: true }); }
