#!/usr/bin/env bun
// Independent canonicalizer and audit verifier. No imports from src/.
// Run under Bun to exercise a different runtime and WebCrypto signature path.
import { readFileSync } from 'node:fs';
function check(condition, message) { if (!condition) throw new Error(message); }
function encode(v, depth = 0) {
  check(depth <= 32, 'Excess depth');
  if (v === null || typeof v === 'boolean') return JSON.stringify(v);
  if (typeof v === 'number') { check(Number.isSafeInteger(v) && !Object.is(v, -0), 'Invalid number'); return String(v); }
  if (typeof v === 'string') { check(v.normalize('NFC') === v && v.isWellFormed() && v.length <= 65536, 'Invalid string'); return JSON.stringify(v); }
  if (Array.isArray(v)) { check(v.length <= 10000, 'Excess array length'); return '[' + v.map(x => encode(x, depth + 1)).join(',') + ']'; }
  check(v && typeof v === 'object' && Object.keys(v).length <= 256, 'Invalid object');
  return '{' + Object.keys(v).sort().map(k => { check(/^[A-Za-z0-9_][A-Za-z0-9_.:-]{0,127}$/.test(k) && !['constructor', '__proto__', 'prototype'].includes(k), 'Invalid key'); return JSON.stringify(k) + ':' + encode(v[k], depth + 1); }).join(',') + '}';
}
const bytes = v => new TextEncoder().encode(encode(v));
async function hash(v) { return Buffer.from(await crypto.subtle.digest('SHA-256', bytes(v))).toString('hex'); }
async function verify(envelope, keys, purpose) {
  check(Object.keys(envelope).sort().join() === 'payload,protected,signature', 'Invalid envelope');
  const h = envelope.protected; check(Object.keys(h).sort().join() === 'key_id,profile,purpose,suite' && h.profile === 'IF-CJSON-1' && h.suite === 'Ed25519' && h.purpose === purpose, 'Bad context');
  const source = keys[h.key_id]; check(source && !source.revoked, 'Untrusted key');
  check(/^[A-Za-z0-9_-]{86}$/.test(envelope.signature), 'Bad signature encoding');
  const raw = Buffer.from(source.public_key.replace(/-----[^-]+-----|\s/g, ''), 'base64');
  const key = await crypto.subtle.importKey('spki', raw, { name: 'Ed25519' }, false, ['verify']);
  check(await crypto.subtle.verify('Ed25519', key, Buffer.from(envelope.signature, 'base64url'), bytes({ protected: h, payload: envelope.payload })), 'Bad signature'); return envelope.payload;
}
function noDuplicates(raw) {
  const stack = [];
  for (const token of raw.matchAll(/"(?:\\.|[^"\\])*"|[{}\[\]:,]/g)) {
    const value = token[0], frame = stack.at(-1);
    if (value === '{') stack.push({ object: true, key: true, seen: new Set() });
    else if (value === '[') stack.push({ object: false });
    else if (value === '}' || value === ']') stack.pop();
    else if (value === ',' && frame?.object) frame.key = true;
    else if (value.startsWith('"') && frame?.object && frame.key) {
      const key = JSON.parse(value); check(!frame.seen.has(key), 'Duplicate JSON key'); frame.seen.add(key); frame.key = false;
    }
  }
}
async function main() {
  const [file, trust, witness] = process.argv.slice(2); check(file && trust, 'Usage: bun scripts/verify-export-webcrypto.mjs BUNDLE PINNED-TRUST [PRIOR-CHECKPOINT]');
  const read = p => { const raw = readFileSync(p, 'utf8'); check(Buffer.byteLength(raw) <= 20 * 1024 * 1024, 'File too large'); noDuplicates(raw); const value = JSON.parse(raw); encode(value); return value; };
  const bundle = read(file), keys = read(trust), prior = witness ? read(witness) : null;
  check(bundle.format === 'IF-AUDIT-1' && Array.isArray(bundle.entries), 'Bad bundle'); const checkpoint = await verify(bundle.checkpoint, keys, 'checkpoint');
  let head = '0'.repeat(64), n = 0, time = 0;
  for (const row of bundle.entries) {
    const e = await verify(row.envelope, keys, 'audit');
    check(e.tenant_id === checkpoint.tenant_id && e.sequence === ++n && e.previous === head && e.time >= time && row.hash === await hash(e), 'Broken continuity'); head = row.hash; time = e.time;
    if (prior && n === prior.size) check(head === prior.head, 'Witness fork');
  }
  check(checkpoint.size === n && checkpoint.head === head && (!prior || (prior.tenant_id === checkpoint.tenant_id && n >= prior.size)), 'Checkpoint mismatch');
  console.log(JSON.stringify({ valid: true, entries: n, head, tenant_id: checkpoint.tenant_id, verifier: 'independent-webcrypto' }));
}
main().catch(e => { console.error(JSON.stringify({ valid: false, message: e.message })); process.exitCode = 1; });
