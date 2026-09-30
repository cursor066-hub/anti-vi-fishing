import http from 'node:http';
import https from 'node:https';
import { digest, canonical, parseStrict } from './canonical.mjs';
import { fields, text, identifier, integer, uniqueStrings, oneOf } from './schema.mjs';
import { signed, verifySigned } from './crypto.mjs';
import { requireThat, InvariantError } from './errors.mjs';

// IF-CON-1: connector framework. Every connector publishes a signed manifest
// declaring supported actions, required permissions, target limitations,
// idempotency behaviour and coverage implications (CON-001). Responses are
// schema-validated before use (CON-004); bounded retries apply only to safe
// reads (CON-005).

export function createManifest(input) {
  fields(input, ['connector_id', 'version', 'domain', 'actions', 'permissions', 'limitations', 'idempotency', 'coverage_implications', 'issued_at', 'expires_at'], ['lifecycle']);
  if (input.lifecycle !== undefined) {
    fields(input.lifecycle, ['deprecated_at', 'end_of_support_at', 'superseded_by']);
    integer(input.lifecycle.deprecated_at, 'deprecation', 1); integer(input.lifecycle.end_of_support_at, 'end of support', input.lifecycle.deprecated_at + 1); identifier(input.lifecycle.superseded_by, 'superseded by');
  }
  identifier(input.connector_id, 'connector'); text(input.version, 'version', 32); text(input.domain, 'domain', 128);
  uniqueStrings(input.actions, 'actions', 32); uniqueStrings(input.permissions, 'permissions', 32); uniqueStrings(input.limitations, 'limitations', 32);
  uniqueStrings(input.coverage_implications, 'coverage implications', 16);
  fields(input.idempotency, ['mutating_retries', 'safe_read_retries', 'timeout_ms']);
  requireThat(input.idempotency.mutating_retries === false, 'INV-400-CONNECTOR', 'Mutating operations must never be retried silently');
  integer(input.idempotency.safe_read_retries, 'safe read retries', 0, 5); integer(input.idempotency.timeout_ms, 'timeout', 1000, 120000);
  integer(input.issued_at, 'issued', 1); integer(input.expires_at, 'expiry', input.issued_at + 1);
  return input;
}

export function signedManifest(input, key) {
  return signed(createManifest(input), key, 'connector-manifest');
}

export function verifyManifest(envelope, issuers, now) {
  const m = verifySigned(envelope, issuers, 'connector-manifest');
  fields(m, ['connector_id', 'version', 'domain', 'actions', 'permissions', 'limitations', 'idempotency', 'coverage_implications', 'issued_at', 'expires_at'], ['lifecycle']);
  requireThat(m.expires_at > now, 'INV-401-CONNECTOR', 'Connector manifest expired', 401);
  if (m.lifecycle) requireThat(m.lifecycle.end_of_support_at > now, 'INV-410-CONNECTOR', `Connector end of support reached; migrate to ${m.lifecycle.superseded_by}`, 410);
  integer(m.issued_at, 'issued', 1, now + 300000);
  return m;
}

// Bounded-retry HTTP client. Only idempotent GET-style reads are retried;
// every request is deadline-bounded and body/schema-checked by the caller.
export async function httpJson(url, { method = 'GET', body, timeout_ms = 10000, headers = {}, token } = {}) {
  const payload = body === undefined ? undefined : canonical(body);
  const target = new URL(url);
  // Cleartext transport is only acceptable toward loopback (the synthetic
  // issuer mesh); any remote endpoint must be TLS (w5 F-8).
  const LOOPBACK = new Set(['localhost', '127.0.0.1', '::1', '[::1]', '0.0.0.0']);
  requireThat(target.protocol === 'https:' || (target.protocol === 'http:' && LOOPBACK.has(target.hostname)), 'INV-400-CONNECTOR', `Refusing cleartext http to non-loopback host ${target.hostname}`, 400);
  const transport = target.protocol === 'https:' ? https : http;
  return await new Promise((resolve, reject) => {
    const req = transport.request({
      hostname: target.hostname, port: target.port, path: target.pathname + target.search, method,
      headers: { 'Content-Type': 'application/json', Accept: 'application/json', ...(payload ? { 'Content-Length': Buffer.byteLength(payload) } : {}), ...(token ? { Authorization: `Bearer ${token}` } : {}), ...headers },
      timeout: timeout_ms
    }, res => {
      const chunks = []; let size = 0;
      res.on('data', c => { size += c.length; if (size <= 1048576) chunks.push(c); });
      res.on('end', () => {
        try {
          // Fatal decode — replacement characters must never reach the
          // canonicalizer as if they were the sender's bytes (w8-canonical F9).
          const textBody = new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks));
          requireThat(size <= 1048576, 'INV-413-CONNECTOR', 'Connector response too large', 413);
          requireThat((res.headers['content-type'] ?? '').split(';')[0] === 'application/json', 'INV-502-CONNECTOR', 'Connector returned non-JSON', 502);
          const data = parseStrict(textBody);
          resolve({ status: res.statusCode, data });
        } catch (e) { reject(e); }
      });
    });
    req.on('timeout', () => req.destroy(new InvariantError('INV-504-CONNECTOR', 'Connector timeout', 504)));
    req.on('error', e => reject(e instanceof InvariantError ? e : new InvariantError('INV-502-CONNECTOR', 'Connector unreachable', 502)));
    req.end(payload);
  });
}

export async function readWithRetry(url, options = {}) {
  const retries = options.retries ?? 2;
  let last;
  for (let i = 0; i <= retries; i++) {
    try {
      const r = await httpJson(url, { ...options, method: 'GET' });
      if (r.status >= 200 && r.status < 300) return r;
      if (r.status < 500) throw new InvariantError('INV-412-EVIDENCE', `Connector rejected read (${r.status})`, 412);
      last = new InvariantError('INV-502-CONNECTOR', `Connector read failed (${r.status})`, 502);
    } catch (e) {
      last = e;
      // 4xx rejections are authoritative — never retry them. Transport-level
      // failures (no HTTP status at all) and 5xx responses may retry.
      if (e.status && e.status < 500) throw e;
    }
  }
  throw last;
}

export async function postOnce(url, body, options = {}) {
  const r = await httpJson(url, { ...options, method: 'POST', body });
  requireThat(r.status >= 200 && r.status < 300, 'INV-502-CONNECTOR', `Connector rejected request (${r.status})`, 502);
  return r;
}

// Drift / upgrade detector: compares observed connector identity to the
// registered configuration digest. Any change returns a drift record; the
// caller maps the affected coverage paths to UNKNOWN (COV-004, CON-006).
export function driftCheck(registered, observed, now) {
  const changes = [];
  const cmp = (field, was, is) => { const a = JSON.stringify(was ?? null), b = JSON.stringify(is ?? null); if (a !== b) changes.push({ field, was: was ?? null, now: is ?? null }); };
  const sorted = a => [...(a ?? [])].sort();
  cmp('connector_id', registered.connector_id, observed.connector_id);
  cmp('version', registered.version, observed.version);
  // Registered actions are the TRUST CEILING: an observed manifest claiming a
  // kind outside registration is drift (authority escalation). An observed
  // manifest offering fewer than registered is reduced capability, recorded
  // as an informational change — not a security drift (a deliberately narrow
  // issuer must not self-report drift by construction).
  const added = (observed.actions ?? []).filter(a => !(registered.actions ?? []).includes(a));
  const removed = (registered.actions ?? []).filter(a => !(observed.actions ?? []).includes(a));
  if (added.length) changes.push({ field: 'actions', was: sorted(registered.actions), now: sorted(observed.actions), escalated: added });
  else if (removed.length) changes.push({ field: 'actions_reduced', was: sorted(registered.actions), now: sorted(observed.actions), informational: true });
  cmp('channel', registered.channel, observed.channel);
  cmp('key_id', registered.key_id, observed.key_id);
  const configDigest = digest({ connector_id: observed.connector_id ?? null, version: observed.version ?? null, actions: observed.actions ?? [], permissions: observed.permissions ?? [] });
  const drifted = changes.some(c => !c.informational);
  return { drifted, changes, configuration_digest: configDigest, checked_at: now, action: drifted ? 'coverage->UNKNOWN pending compatibility, security and bypass revalidation' : 'none' };
}
