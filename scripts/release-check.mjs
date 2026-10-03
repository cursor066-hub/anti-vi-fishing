import { readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';

// requirements-summary.json must be FRESH before it is trusted — a gate
// on a stale committed input is a gate on nothing (w8-tooling F4), and a
// verifier that silently regenerates it masks the staleness it exists to
// catch: a corrupted requirements.csv would never appear stale to the
// caller (w53-ledger HIGH-1). Verify-only — regeneration is a deliberate
// operator step (report.mjs), never a side effect of checking.
const regen = spawnSync('python3', ['scripts/traceability.py', '--check'], { cwd: new URL('..', import.meta.url).pathname, encoding: 'utf8', timeout: 300000 });
if (regen.status !== 0) { console.error(`committed requirement ledger is stale — run node scripts/report.mjs to regenerate\n${regen.stderr || regen.stdout || 'traceability check failed'}`); process.exit(2); }
const acceptance = JSON.parse(readFileSync(new URL('../docs/production-acceptance.json', import.meta.url), 'utf8'));
const requirements = JSON.parse(readFileSync(new URL('../reports/requirements-summary.json', import.meta.url), 'utf8'));
const blocked = acceptance.items.filter(item => item.status !== 'VERIFIED');
if (!requirements.production_ready && !blocked.some(b => b.id === 'full-srs-implementation')) blocked.push({ id: 'requirement-acceptance', status: 'BLOCKED', reason: 'Requirement-level production acceptance is incomplete.' });
const pass = acceptance.production_ready === true && requirements.production_ready === true && blocked.length === 0;
console.log(JSON.stringify({ release: acceptance.release, production_release: pass ? 'PASS' : 'BLOCKED', blocked_items: blocked, engineering_tests_do_not_override_external_acceptance: true }, null, 2));
if (!pass) process.exitCode = 1;
