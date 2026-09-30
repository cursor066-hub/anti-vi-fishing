// AIG-010: golden eval suite for the deterministic advisory plane.
// Each case in ai-eval/cases.json pins the exact expected output; the suite
// also re-runs every case to prove byte-identical determinism. Any model or
// pattern change must regenerate the corpus deliberately — this suite is the
// tripwire that makes silent advisory drift impossible.
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { extract, explain, classifyIntent } from '../src/advisory.mjs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const corpus = JSON.parse(readFileSync(join(root, 'ai-eval', 'cases.json'), 'utf8'));
if (corpus.format !== 'IF-AI-EVAL-1' || !Array.isArray(corpus.cases) || !corpus.cases.length) { console.error('ai-eval: malformed corpus'); process.exit(2); }
const OPS = { extract, explain, intent: classifyIntent };

let pass = 0, fail = 0;
const failures = [];
for (const c of corpus.cases) {
  const fn = OPS[c.operation];
  if (!fn) { fail++; failures.push(`${c.id}: unknown operation ${c.operation}`); continue; }
  const arg = c.input.document ?? c.input.decision ?? c.input.text;
  const first = JSON.stringify(fn(arg));
  // Determinism is the load-bearing property: a second call must be
  // byte-identical (AIG-002/AIG-005), not merely equivalent.
  const second = JSON.stringify(fn(arg));
  const expected = JSON.stringify(c.expected);
  if (first !== expected) { fail++; failures.push(`${c.id}: output drifted from golden\n  expected ${expected.slice(0, 200)}\n  got      ${first.slice(0, 200)}`); }
  else if (first !== second) { fail++; failures.push(`${c.id}: non-deterministic output across calls`); }
  else pass++;
}
// The corpus digest goes into the report so the eval evidence names the
// exact golden set it ran against — a same-commit corpus edit is visible in
// the artifact (supply-chain L5).
const report = { suite: 'IF-AI-EVAL-1', cases: corpus.cases.length, corpus_sha256: createHash('sha256').update(readFileSync(join(root, 'ai-eval', 'cases.json'))).digest('hex'), pass, fail, failures: failures.slice(0, 20) };
console.log(JSON.stringify(report, null, 2));
process.exit(fail ? 1 : 0);
