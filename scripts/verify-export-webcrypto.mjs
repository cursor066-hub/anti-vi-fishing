#!/usr/bin/env bun
// Independent canonicalizer and audit verifier. No imports from src/.
// Run under Bun to exercise a different runtime and WebCrypto signature path.
// A second-implementation verifier must reject everything the primary does —
// mirroring src/store.mjs verifyAudit: full forbidden-key set, embedded
// prior_checkpoint fork check, tree_head recompute, suite pinning and the
// 1 MiB input cap (w23-supply F2).
import { readFileSync } from 'node:fs';
function check(condition, message) { if (!condition) throw new Error(message); }
const FORBIDDEN = new Set(['__defineGetter__', '__defineSetter__', '__lookupGetter__', '__lookupSetter__', '__proto__', 'constructor', 'hasOwnProperty', 'isPrototypeOf', 'propertyIsEnumerable', 'toLocaleString', 'toString', 'valueOf', 'prototype', 'watch', 'unwatch']);
function encode(v, depth = 0) {
  check(depth <= 32, 'Excess depth');
  if (v === null || typeof v === 'boolean') return JSON.stringify(v);
  if (typeof v === 'number') { check(Number.isSafeInteger(v) && !Object.is(v, -0), 'Invalid number'); return String(v); }
  if (typeof v === 'string') { check(v.normalize('NFC') === v && v.isWellFormed() && v.length <= 65536, 'Invalid string'); return JSON.stringify(v); }
  if (Array.isArray(v)) { check(v.length <= 10000, 'Excess array length'); return '[' + v.map(x => encode(x, depth + 1)).join(',') + ']'; }
  check(v && typeof v === 'object' && Object.keys(v).length <= 256, 'Invalid object');
  return '{' + Object.keys(v).sort().map(k => { check(/^[A-Za-z0-9_][A-Za-z0-9_.:-]{0,127}$/.test(k) && !FORBIDDEN.has(k), 'Invalid key'); return JSON.stringify(k) + ':' + encode(v[k], depth + 1); }).join(',') + '}';
}
const bytes = v => new TextEncoder().encode(encode(v));
async function hash(v) { return Buffer.from(await crypto.subtle.digest('SHA-256', bytes(v))).toString('hex'); }
const P256_HALF_ORDER = BigInt('0x7FFFFFFF80000000FFFFFFFFFFFFFFFFDE737D56D38BCF4279DCE5617E3192A8');
const SUITE = {
  Ed25519: { alg: 'Ed25519', import: { name: 'Ed25519' } },
  ES256: { alg: { name: 'ECDSA', hash: 'SHA-256' }, import: { name: 'ECDSA', namedCurve: 'P-256' } },
};
async function verify(envelope, keys, purpose) {
  check(Object.keys(envelope).sort().join() === 'payload,protected,signature', 'Invalid envelope');
  const h = envelope.protected; check(Object.keys(h).sort().join() === 'key_id,profile,purpose,suite' && h.profile === 'IF-CJSON-1' && SUITE[h.suite] && h.purpose === purpose, 'Bad context');
  // Member access through an own-property check — prototype-resolved keys
  // are never anchors. The anchor's declared suite is PINNED to the
  // envelope's suite: a trust file mislabeling a P-256 key as Ed25519 must
  // fail, not silently verify cross-suite (w23-supply F2).
  check(typeof h.key_id === 'string' && !FORBIDDEN.has(h.key_id) && Object.hasOwn(keys, h.key_id), 'Untrusted key');
  const source = keys[h.key_id]; check(source && !source.revoked, 'Untrusted key');
  check(source.suite === undefined || source.suite === h.suite, 'Envelope suite differs from the anchor-declared suite');
  check(/^[A-Za-z0-9_-]{86}$/.test(envelope.signature), 'Bad signature encoding');
  const sig = Buffer.from(envelope.signature, 'base64url');
  if (h.suite === 'ES256') check(sig.length === 64 && BigInt('0x' + sig.subarray(32).toString('hex')) <= P256_HALF_ORDER, 'Non-canonical (high-s) ECDSA signature');
  const raw = Buffer.from(source.public_key.replace(/-----[^-]+-----|\s/g, ''), 'base64');
  const key = await crypto.subtle.importKey('spki', raw, SUITE[h.suite].import, false, ['verify']);
  check(await crypto.subtle.verify(SUITE[h.suite].alg, key, sig, bytes({ protected: h, payload: envelope.payload })), 'Bad signature'); return envelope.payload;
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
// IF-MERKLE-1 independent recompute — the checkpoint's signed tree_head is
// proven, never trusted (mirrors merkle.mjs: leaf = sha256(0x00||hash);
// node = sha256(0x01||left||right); maximal aligned power-of-two split).
async function merkleRoot(hashes) {
  for (const h of hashes) check(/^[a-f0-9]{64}$/.test(h), 'Merkle leaves must be SHA-256 digests');
  if (!hashes.length) return '0'.repeat(64);
  const leafHash = h => crypto.subtle.digest('SHA-256', Buffer.concat([Buffer.from([0x00]), Buffer.from(h, 'hex')])).then(b => Buffer.from(b).toString('hex'));
  const nodeHash = (a, b) => crypto.subtle.digest('SHA-256', Buffer.concat([Buffer.from([0x01]), Buffer.from(a, 'hex'), Buffer.from(b, 'hex')])).then(b => Buffer.from(b).toString('hex'));
  const split = n => { let k = 1; while (k * 2 < n) k *= 2; return k; };
  async function subtree(lo, hi) {
    const n = hi - lo;
    if (n === 1) return leafHash(hashes[lo]);
    const k = split(n);
    return nodeHash(await subtree(lo, lo + k), await subtree(lo + k, hi));
  }
  return subtree(0, hashes.length);
}
async function main() {
  const [file, trust, witness] = process.argv.slice(2); check(file && trust, 'Usage: bun scripts/verify-export-webcrypto.mjs BUNDLE PINNED-TRUST [PRIOR-CHECKPOINT]');
  const read = p => { const raw = readFileSync(p, 'utf8'); check(Buffer.byteLength(raw) <= 1024 * 1024, 'File too large'); noDuplicates(raw); const value = JSON.parse(raw); encode(value); return value; };
  const bundle = read(file), keys = read(trust), prior0 = witness ? read(witness) : null;
  check(bundle.format === 'IF-AUDIT-1' && Array.isArray(bundle.entries), 'Bad bundle'); const checkpoint = await verify(bundle.checkpoint, keys, 'checkpoint');
  // The bundle's embedded prior_checkpoint is a signed witness that must
  // itself verify and agree with the entries — ignoring it lets a fork
  // slide by that the node verifier rejects (w23-supply F2).
  const prior = prior0 ?? (bundle.prior_checkpoint ? await verify(bundle.prior_checkpoint, keys, 'checkpoint') : null);
  let head = '0'.repeat(64), n = 0, time = 0;
  // Signer-death window, mirroring store.mjs _auditKeyDeaths: a key revoked
  // or rotated out ON THE CHAIN cannot attest rows sequenced after its death
  // (w33-export F2 — the independent verifier must reject what node rejects).
  const deadAt = new Map();
  const kill = (kid, seq) => { if (typeof kid === 'string') deadAt.set(kid, Math.min(deadAt.get(kid) ?? Infinity, seq)); };
  for (const row of bundle.entries) {
    const e = await verify(row.envelope, keys, 'audit');
    check(e.tenant_id === checkpoint.tenant_id && e.sequence === ++n && e.previous === head && e.time >= time && row.hash === await hash(e), 'Broken continuity');
    // Inclusive boundary, same as the fold: the death row itself may be
    // self-signed, so the row's own death events apply only to later seqs.
    const kid = row.envelope?.protected?.key_id;
    check(!(kid !== undefined && deadAt.has(kid) && n > deadAt.get(kid)), 'Audit row signed by a key past its ledger death');
    const meta = e.metadata;
    if (e.type === 'AUTHORITY_REVOKED' && typeof e.reference === 'string' && e.reference.startsWith('key:')) kill(e.reference.slice(4), n);
    if (e.type === 'KEY_ROTATED' && meta?.key_class === 'audit') kill(meta.previous_key_id, n);
    if (e.type === 'AUDIT_SEALED' || e.type === 'AUDIT_SEAL_CARRY') {
      for (const rv of Array.isArray(meta?.revocations_carryover) ? meta.revocations_carryover : []) if (typeof rv?.reference === 'string' && rv.reference.startsWith('key:')) kill(rv.reference.slice(4), n);
      // Carried audit-class rotations pin the predecessor's death at the
      // carrying row — lifecycle_carryover parity with the fold's replay
      // (w34).
      for (const lc of Array.isArray(meta?.lifecycle_carryover) ? meta.lifecycle_carryover : []) if (lc?.type === 'KEY_ROTATED' && lc?.metadata?.key_class === 'audit') kill(lc.metadata.previous_key_id, n);
    }
    head = row.hash; time = e.time;
    if (prior && n === prior.size) check(head === prior.head, 'Witness fork');
  }
  check(checkpoint.size === n && checkpoint.head === head && (!prior || (prior.tenant_id === checkpoint.tenant_id && n >= prior.size)), 'Checkpoint mismatch');
  check(checkpoint.tree_head === await merkleRoot(bundle.entries.map(i => i.hash)), 'Checkpoint tree head does not match the audit entries');
  console.log(JSON.stringify({ valid: true, entries: n, head, tenant_id: checkpoint.tenant_id, verifier: 'independent-webcrypto' }));
}
main().catch(e => { console.error(JSON.stringify({ valid: false, message: e.message })); process.exitCode = 1; });
