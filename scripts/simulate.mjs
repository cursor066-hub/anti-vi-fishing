#!/usr/bin/env node
import { fixture, runtimeInput, runtimeRequest } from '../tests/helpers.mjs';
import { writeFileSync, mkdirSync, rmSync } from 'node:fs';
import { digest, clone } from '../src/canonical.mjs';
import { verifyAudit } from '../src/store.mjs';
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
  h.f.revoke(h.p('security'), { kind: 'device', id: 'operator-device', reason: 'Synthetic endpoint agent loss' });
  scenario('Device quarantine prevents renewal', 'INV-403-QUARANTINE', () => h.f.runtime.issue(h.p(), runtimeInput()));
  const bundle = h.f.exportAudit(h.p('auditor'), 'Synthetic simulation evidence');
  scenario('Offline signed audit integrity', true, () => verifyAudit(bundle, bundle.public_keys).valid);
  const tampered = clone(bundle); tampered.entries.splice(3, 1);
  scenario('Audit deletion detection', 'INV-409-AUDIT', () => verifyAudit(tampered, bundle.public_keys));
  mkdirSync('reports', { recursive: true });
  writeFileSync('reports/simulation-results.json', JSON.stringify({ simulated: true, real_systems_tested: false, scenarios, allowed_low_and_slow_queries: allowed, all_pass: scenarios.every(s => s.pass) }, null, 2) + '\n');
  writeFileSync('reports/sample-audit.json', JSON.stringify(bundle, null, 2) + '\n');
  writeFileSync('reports/sample-pinned-trust.json', JSON.stringify(bundle.public_keys, null, 2) + '\n');
  writeFileSync('reports/sample-checkpoint.json', JSON.stringify(bundle.checkpoint.payload, null, 2) + '\n');
  const values = [null, true, false, 0, 9007199254740991, -9007199254740991, { b: 2, a: 1 }, { greeting: 'Žižek 🛡 café', nested: [1, { zero: 0 }] }, { '123hash': { x: '\n\t' } }, { alpha: ['é', '🎛'], omega: {} }];
  writeFileSync('examples/canonical-vectors.json', JSON.stringify(values.map((value, i) => ({ name: `vector-${i + 1}`, value, sha256: digest(value) })), null, 2) + '\n');
  console.log(JSON.stringify({ simulations: scenarios.length, passed: scenarios.filter(s => s.pass).length, audit_entries: bundle.entries.length, real_systems_tested: false }));
  if (scenarios.some(s => !s.pass)) process.exitCode = 1;
} finally { h.close(); rmSync(h.directory, { recursive: true }); }
