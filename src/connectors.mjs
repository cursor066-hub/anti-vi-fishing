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

// Canonical issuer-manifest claims: the issuerd wire contract and the
// tenant registration must carry the same strings or every first drift
// check reads as escalation (w20-fixverify F-14 pairing).
export const ISSUER_MANIFEST_PERMISSIONS = ['issue signed evidence within declared kinds'];
export const ISSUER_MANIFEST_LIMITATIONS = ['Records are authoritative only for this issuer domain', 'No claim about target-side enforcement'];
// Retry semantics and declared coverage impact live in the signed manifest
// AND the registered baseline — driftCheck compares both, so a connector
// that silently changes either is drift, not a signed silent change
// (w21-fixverify M-2).
export const ISSUER_MANIFEST_IDEMPOTENCY = { mutating_retries: false, safe_read_retries: 2, timeout_ms: 10000 };
export const ISSUER_MANIFEST_COVERAGE = ['evidence-source'];

export function verifyManifest(envelope, issuers, now, { max_age_ms } = {}) {
  const m = verifySigned(envelope, issuers, 'connector-manifest');
  fields(m, ['connector_id', 'version', 'domain', 'actions', 'permissions', 'limitations', 'idempotency', 'coverage_implications', 'issued_at', 'expires_at'], ['lifecycle']);
  requireThat(m.expires_at > now, 'INV-401-CONNECTOR', 'Connector manifest expired', 401);
  if (m.lifecycle) requireThat(m.lifecycle.end_of_support_at > now, 'INV-410-CONNECTOR', `Connector end of support reached; migrate to ${m.lifecycle.superseded_by}`, 410);
  integer(m.issued_at, 'issued', 1, now + 300000);
  // The upper bound alone cannot bound staleness — callers that need a
  // freshness floor must declare it (w18-issuerd F-11).
  if (max_age_ms !== undefined) requireThat(m.issued_at >= now - max_age_ms, 'INV-401-CONNECTOR', 'Connector manifest older than the declared freshness floor', 401);
  return m;
}

// Bounded-retry HTTP client. Only idempotent GET-style reads are retried;
// every request is deadline-bounded and body/schema-checked by the caller.
export async function httpJson(url, { method = 'GET', body, timeout_ms = 10000, headers = {}, token } = {}) {
  const payload = body === undefined ? undefined : canonical(body);
  const target = new URL(url);
  // Cleartext transport is only acceptable toward loopback (the synthetic
  // issuer mesh); any remote endpoint must be TLS (w5 F-8).
  // '0.0.0.0' is NOT a loopback address — it is the wildcard bind; some
  // systems route it to an arbitrary interface (w9-deploy F10).
  // Literal addresses only — a DNS-resolved name can be pointed off-box by
  // a resolver quirk; the cleartext exception binds to addresses
  // (w18-issuerd F-13).
  const LOOPBACK = new Set(['127.0.0.1', '::1', '[::1]']);
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
          // The decoder's TypeError is normalised into the connector error
          // taxonomy so callers see INV-502, not a bare runtime throw
          // (w9-fixverify NB-3).
          let textBody;
          try { textBody = new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks)); }
          catch { throw new InvariantError('INV-502-CONNECTOR', 'Connector returned invalid UTF-8', 502); }
          requireThat(size <= 1048576, 'INV-413-CONNECTOR', 'Connector response too large', 413);
          requireThat((res.headers['content-type'] ?? '').split(';')[0] === 'application/json', 'INV-502-CONNECTOR', 'Connector returned non-JSON', 502);
          // Malformed JSON is an upstream failure too — INV-502, never the
          // caller-fault INV-400 a parseStrict throw would surface
          // (w10-fixverify F-10).
          let data;
          try { data = parseStrict(textBody); } catch { throw new InvariantError('INV-502-CONNECTOR', 'Connector returned malformed JSON', 502); }
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
  // Permissions and limitations are trust fields too — a manifest that
  // quietly grows its permission set is escalation, and shrinking the
  // declared set is a recorded informational change (w18-issuerd F-15).
  // A registered baseline that never declared the field cannot assert
  // equality: an upgrade must not false-drift every pre-field tenant —
  // the observed set is recorded informationally until re-registered
  // (w21-fixverify M-3).
  if (registered.permissions !== undefined) {
    const permAdded = (observed.permissions ?? []).filter(x => !registered.permissions.includes(x));
    const permRemoved = registered.permissions.filter(x => !(observed.permissions ?? []).includes(x));
    if (permAdded.length) changes.push({ field: 'permissions', was: sorted(registered.permissions), now: sorted(observed.permissions), escalated: permAdded });
    else if (permRemoved.length) changes.push({ field: 'permissions_reduced', was: sorted(registered.permissions), now: sorted(observed.permissions), informational: true });
  } else if ((observed.permissions ?? []).length) changes.push({ field: 'permissions_undeclared_baseline', now: sorted(observed.permissions), informational: true });
  if (registered.limitations !== undefined) {
    const limAdded = (observed.limitations ?? []).filter(x => !registered.limitations.includes(x));
    const limRemoved = registered.limitations.filter(x => !(observed.limitations ?? []).includes(x));
    if (limRemoved.length) changes.push({ field: 'limitations', was: sorted(registered.limitations), now: sorted(observed.limitations), escalated: limRemoved.map(l => `dropped:${l}`) });
    else if (limAdded.length) changes.push({ field: 'limitations_added', was: sorted(registered.limitations), now: sorted(observed.limitations), informational: true });
  } else if ((observed.limitations ?? []).length) changes.push({ field: 'limitations_undeclared_baseline', now: sorted(observed.limitations), informational: true });
  // Signed contract fields beyond identity: idempotency semantics and the
  // declared coverage impact are part of what was registered — a connector
  // that silently changes retry or coverage claims drifts even under a
  // valid signature (w21-fixverify M-2). Same undeclared-baseline rule.
  for (const f of ['idempotency', 'coverage_implications']) {
    if (registered[f] !== undefined) cmp(f, registered[f], observed[f]);
    else if (observed[f] !== undefined) changes.push({ field: `${f}_undeclared_baseline`, now: observed[f], informational: true });
  }
  const configDigest = digest({ connector_id: observed.connector_id ?? null, version: observed.version ?? null, actions: observed.actions ?? [], permissions: observed.permissions ?? [] });
  const drifted = changes.some(c => !c.informational);
  return { drifted, changes, configuration_digest: configDigest, checked_at: now, action: drifted ? 'coverage->UNKNOWN pending compatibility, security and bypass revalidation' : 'none' };
}
