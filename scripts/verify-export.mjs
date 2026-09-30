#!/usr/bin/env node
import { readFileSync } from 'node:fs';
import { parseStrict } from '../src/canonical.mjs';
import { verifyAudit } from '../src/store.mjs';
const [bundlePath, trustPath, witnessPath] = process.argv.slice(2);
if (!bundlePath || !trustPath) { console.error('Usage: node scripts/verify-export.mjs BUNDLE.json PINNED-TRUST.json [PRIOR-CHECKPOINT.json]'); process.exitCode = 2; }
else {
  try { console.log(JSON.stringify(verifyAudit(parseStrict(readFileSync(bundlePath, 'utf8')), parseStrict(readFileSync(trustPath, 'utf8')), witnessPath ? parseStrict(readFileSync(witnessPath, 'utf8')) : null), null, 2)); }
  catch (e) { console.error(JSON.stringify({ valid: false, code: e.code ?? 'INVALID_EXPORT', message: e.code ? e.message : 'Unable to read or verify export' })); process.exitCode = 1; }
}
