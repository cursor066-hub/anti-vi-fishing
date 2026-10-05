import { readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';

// requirements-summary.json must be FRESH before it is trusted — a gate
// on a stale committed input is a gate on nothing (w8-tooling F4), and a
// verifier that silently regenerates it masks the staleness it exists to
// catch: a corrupted requirements.csv would never appear stale to the
// caller (w53-ledger HIGH-1). Verify-only — regeneration is a deliberate
// operator step (report.mjs), never a side effect of checking.
// Fifteen-minute ceiling, not five: under test-file concurrency several
// copy-tree release-checks share the box and a healthy python3 can
// legitimately outlive 300s — the ceiling only has to outlive honest
// load; a real wedge never finishes either way (w55 regen: ETIMEDOUT).
const regen = spawnSync('python3', ['scripts/traceability.py', '--check'], { cwd: new URL('..', import.meta.url).pathname, encoding: 'utf8', timeout: 900000 });
// Three distinct failure shapes, three honest headlines: a spawn that
// never ran (python3 missing — the prescribed regen cannot run either), a
// crash (any non-stale failure — regenerating hides it), and staleness
// (STALE: rows — regen is the remedy). Collapsing them into 'stale'
// misdirects the operator every way (w54-ledger M-3).
if (regen.error || regen.status === null || regen.status === undefined) {
  // 'no status' is TWO different failures: the spawn never ran (python3
  // absent → regen recipe applies) versus the process exited by signal or
  // the 900s timeout (a hung/killed check — regeneration cannot fix it,
  // and 'install python3' misdirects the operator) (w55-ledger H-4).
  if (regen.error) {
    console.error(`traceability check could not run — python3 is required and was not spawnable: ${regen.error.message}\nInstall python3, then run node scripts/report.mjs to regenerate`);
  } else {
    console.error(`traceability check exited abnormally${regen.signal ? ` (signal ${regen.signal})` : ' — killed by signal or the 900s timeout, no exit status'}\nInspect the failure, then run node scripts/report.mjs to regenerate`);
  }
  process.exit(2);
}
if (regen.status !== 0) {
  const out = `${regen.stdout ?? ''}\n${regen.stderr ?? ''}`.trim();
  if (/(?:^|\n)STALE:/.test(out)) {
    console.error(`committed requirement ledger is stale — run node scripts/report.mjs to regenerate\n${out}`);
  } else {
    console.error(`traceability check failed without a staleness verdict — fix the reported error before regenerating\n${out}`);
  }
  process.exit(2);
}
const acceptance = JSON.parse(readFileSync(new URL('../docs/production-acceptance.json', import.meta.url), 'utf8'));
const requirements = JSON.parse(readFileSync(new URL('../reports/requirements-summary.json', import.meta.url), 'utf8'));
const blocked = acceptance.items.filter(item => item.status !== 'VERIFIED');
if (!requirements.production_ready && !blocked.some(b => b.id === 'full-srs-implementation')) blocked.push({ id: 'requirement-acceptance', status: 'BLOCKED', reason: 'Requirement-level production acceptance is incomplete.' });
const pass = acceptance.production_ready === true && requirements.production_ready === true && blocked.length === 0;
console.log(JSON.stringify({ release: acceptance.release, production_release: pass ? 'PASS' : 'BLOCKED', blocked_items: blocked, engineering_tests_do_not_override_external_acceptance: true }, null, 2));
if (!pass) process.exitCode = 1;
