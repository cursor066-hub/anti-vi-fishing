import { performance } from 'node:perf_hooks';
import { cpus, totalmem, platform, arch } from 'node:os';
import { mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { fixture, runtimeInput, runtimeRequest } from '../tests/helpers.mjs';
import { evaluatePolicy } from '../src/policy.mjs';
const h = fixture(null, ['acme']);
const percentile = (values, q) => [...values].sort((a, b) => a - b)[Math.min(values.length - 1, Math.floor(values.length * q))];
function summary(values, elapsed) { return { samples: values.length, p50_ms: percentile(values, .5), p95_ms: percentile(values, .95), p99_ms: percentile(values, .99), operations_per_second: values.length * 1000 / elapsed }; }
try {
  const r = h.proposed(); h.evidence(r); h.evidence(r, { issuer: 'registry' }); h.approve(r);
  const stored = h.f.getCapsule(h.p(), r.capsule.capsule_id), graph = h.f.graph('acme', stored), policy = h.f.policy('acme'), identities = h.f.identities('acme');
  const input = { capsule: stored.capsule, policy, evidence: graph.items, approvals: stored.approvals.map(a => a.payload), identities, now: h.now() };
  const raw = [], integrated = [], runtime = []; let start = performance.now();
  for (let i = 0; i < 2000; i++) { const at = performance.now(); const out = evaluatePolicy(input); if (out.decision !== 'ALLOW') throw new Error('Policy unexpectedly denied'); raw.push(performance.now() - at); }
  const core = summary(raw, performance.now() - start); start = performance.now();
  for (let i = 0; i < 500; i++) { const at = performance.now(); const out = h.f.evaluate(h.p(), r.capsule.capsule_id); if (out.decision !== 'ALLOW') throw new Error('Integrated policy failed'); integrated.push(performance.now() - at); }
  const control = summary(integrated, performance.now() - start);
  let cap;
  start = performance.now();
  for (let i = 0; i < 500; i++) { if (i % 50 === 0) { h.advance(60001); cap = h.f.runtime.issue(h.p(), runtimeInput({ action: 'service.connect', resource: 'erp-service', destination: 'erp-service', columns: [], row_ids: [], max_cost: 10000 })); } h.advance(101); const at = performance.now(); h.f.runtime.consume(h.p(), runtimeRequest(cap)); runtime.push(performance.now() - at); }
  const local = summary(runtime, performance.now() - start);
  const result = { reference_environment: { node: process.version, os: platform(), architecture: arch(), cpu: cpus()[0]?.model ?? 'unknown', logical_cpus: cpus().length, memory_bytes: totalmem(), isolated_environment: true }, core_deterministic_evaluation: core, integrated_evaluation_with_sqlite_audit: control, local_software_runtime_with_signed_audit: local, target_network_latency: 'not measured: no external target connector', targets: { core_p95_at_most_250_ms: core.p95_ms <= 250, core_p99_at_most_750_ms: core.p99_ms <= 750, integrated_100_evaluations_per_second: control.operations_per_second >= 100, runtime_p99_at_most_1_ms: local.p99_ms <= 1 }, production_capacity_claim: false, caveat: 'Single-node microbenchmark, warm process, synthetic data and virtual policy clock advanced to respect budget/rate limits; not a production load, soak, packet or multi-zone benchmark.' };
  mkdirSync('reports', { recursive: true }); writeFileSync('reports/benchmark.json', JSON.stringify(result, null, 2) + '\n'); console.log(JSON.stringify(result, null, 2));
} finally { h.close(); rmSync(h.directory, { recursive: true }); }
