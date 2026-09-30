#!/usr/bin/env node
import http from 'node:http';
import { readFileSync, writeFileSync, appendFileSync, mkdirSync, readdirSync, existsSync, statSync, lstatSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { randomUUID, randomBytes, timingSafeEqual } from 'node:crypto';
import { canonical, digest, hashBytes, parseStrict } from './canonical.mjs';
import { signed, verifySigned } from './crypto.mjs';
import { fields, text, identifier, integer, uniqueStrings } from './schema.mjs';
import { requireThat, InvariantError } from './errors.mjs';

// IF-ISSUER-1: an independent evidence issuer service. Each issuer is a
// separate trust-domain process holding its own signing key and record store.
// It answers structured evidence queries with signed evidence envelopes —
// never raw authority. Records live in <name>.issuer.json; every issuance is
// appended to a hash-chained JSONL log for provenance audit (EVD-010).

export function loadIssuers(directory) {
  // Null-prototype registry: issuer names like 'constructor' must not resolve
  // via Object.prototype (issuerd-audit LOW-4).
  const issuers = Object.create(null);
  for (const file of readdirSync(directory)) {
    if (!file.endsWith('.issuer.json')) continue;
    // These files carry private signing keys — group/world-readable specs
    // refuse to serve, matching the `sign` and `serve` custody bars
    // (w8-tooling F8).
    requireThat((statSync(join(directory, file)).mode & 0o077) === 0, 'INV-503-CONFIG', `Issuer file ${file} must not be readable by group or other users`, 503);
    const spec = JSON.parse(readFileSync(join(directory, file), 'utf8'));
    fields(spec, ['issuer', 'key', 'channel', 'kinds', 'records', 'version'], ['tenant', 'issue_token', 'read_token', 'token_expires_at']);
    identifier(spec.issuer); text(spec.version, 'issuer version', 32);
    // Tenant names use the strict tenant charset — ':' inside a tenant or
    // issuer name would collide with the '<tenant>:<issuer>' key form.
    if (spec.tenant !== undefined) requireThat(/^[a-z][a-z0-9-]{1,31}$/.test(spec.tenant), 'INV-400-SCHEMA', 'Issuer tenant must use the tenant charset');
    requireThat(!spec.issuer.includes(':'), 'INV-400-SCHEMA', 'Issuer name must not contain ":"');
    requireThat(['authoritative', 'communication', 'device', 'counterparty'].includes(spec.channel), 'INV-400-SCHEMA', 'Unsupported issuer channel');
    // Registry key: '<tenant>:<issuer>' when the spec carries a tenant, so
    // two tenants can run same-named issuers with independent keys/records.
    // A bare '<issuer>' alias is registered only when unambiguous.
    const key = spec.tenant ? `${spec.tenant}:${spec.issuer}` : spec.issuer;
    requireThat(!issuers[key], 'INV-409-CONFLICT', `Duplicate issuer ${key}`, 409);
    issuers[key] = spec;
    if (!issuers[spec.issuer]) issuers[spec.issuer] = spec; else if (issuers[spec.issuer] !== spec) issuers[spec.issuer] = { ambiguous: true };
  }
  requireThat(Object.keys(issuers).length > 0, 'INV-503-CONFIG', 'No issuers configured', 503);
  return issuers;
}

// Constant-time bearer comparison — a plain `===` leaks match length via
// early-exit timing (issuerd-audit LOW-2).
function bearerMatches(auth, token) {
  // Compare fixed-size digests so the token length is not a timing oracle.
  if (typeof auth !== 'string') return false;
  return timingSafeEqual(Buffer.from(digest(auth)), Buffer.from(digest(`Bearer ${token}`)));
}

function interpolate(template, claims) {
  return template.replace(/\$\{([a-z0-9_.]+)\}/g, (_, path) => {
    const v = path.split('.').reduce((o, k) => o?.[k], { claims });
    requireThat(typeof v === 'string' || Number.isSafeInteger(v), 'INV-412-EVIDENCE', `Query lacks required field ${path}`, 412);
    return String(v);
  });
}

export function answerQuery(issuer, request, now) {
  // request: {tenant_id, capsule_digest, kind, subject_id, claims}
  // MED-3: a spec bound to a tenant must not mint envelopes asserting other
  // tenants — the signed payload copies request.tenant_id verbatim.
  requireThat(!issuer.tenant || issuer.tenant === request.tenant_id, 'INV-403-SCOPE', 'Issuer does not serve this tenant', 403);
  const rule = issuer.kinds[request.kind];
  requireThat(rule, 'INV-412-EVIDENCE', `Issuer does not supply evidence kind ${request.kind}`, 412);
  requireThat(Number.isSafeInteger(rule.confidence) && rule.confidence >= 0 && rule.confidence <= 100, 'INV-503-CONFIG', `Evidence rule for ${request.kind} must declare an explicit confidence`);
  requireThat(request.dependencies === undefined || (Array.isArray(request.dependencies) && request.dependencies.every(d => typeof d === 'string')), 'INV-400-SCHEMA', 'dependencies must be an array of strings');
  const key = interpolate(rule.lookup, request.claims ?? {});
  const record = issuer.records[key];
  const evidence_id = randomUUID();
  const base = {
    evidence_id, tenant_id: request.tenant_id, capsule_digest: request.capsule_digest, kind: request.kind,
    acquired_at: now, expires_at: now + (rule.ttl_ms ?? 300000), confidence: rule.confidence,
    advisory: issuer.channel === 'communication' ? true : Boolean(rule.advisory), dependencies: request.dependencies ?? [],
    retention_until: now + (rule.ttl_ms ?? 300000) + 86400000
  };
  const prov = suffix => `issuer:${issuer.issuer}@${issuer.version} record:${key.split(':')[0]}:${suffix} transformation:direct`;
  if (!record) {
    // A missing record is a signed `conflict`, not an exception — the response
    // shape is identical to a claim mismatch, so /issue cannot be used to
    // enumerate the record store by guessing lookup keys (issuerd-audit MED-5).
    return signed({ ...base, claim: 'conflict', content_digest: digest({ issuer: issuer.issuer, key, record: null }), claims: {}, provenance: prov('UNSATISFIED'), issuer_version: issuer.version }, issuer.key, 'evidence');
  }
  let claim = 'supports';
  const extracted = {}, matched = new Set();
  for (const [field, expected] of Object.entries(rule.expect ?? {})) {
    const want = typeof expected === 'string' && expected.includes('${') ? interpolate(expected, request.claims ?? {}) : expected;
    extracted[field] = record[field] ?? null;
    const got = record[field];
    if (String(got) === String(want)) matched.add(field); else claim = 'conflict';
  }
  for (const f of rule.extract ?? []) {
    extracted[f] = record[f] ?? null;
    if (String(record[f]) === String(request.claims?.[f])) matched.add(f);
  }
  // A conflict answer reveals nothing: echoing even the correctly-guessed
  // fields is a per-field value-confirmation oracle (w5 F-7).
  // A `supports` answer echoes the caller's own query claims plus the
  // subject_id the record itself carries — NOT the independently supplied
  // request.subject_id, which would let the caller stamp any subject onto a
  // record that matched someone else (w5 F-1). The fabric binds
  // claims.subject_id to the capsule's actor, so the lie must be impossible
  // below the signature.
  const resolvedSubject = record.subject_id ?? request.claims?.subject_id ?? request.subject_id;
  // Only fields the issuer verified may appear under the signature: expect/
  // extract fields, the resolved subject, and claims bound into the lookup
  // template — a 'supports' answer proves that exact identifier resolved to
  // a real record. Arbitrary caller claims are never echoed (w6-tenancy F7).
  const lookupBound = {};
  // The extraction charset must equal interpolate()'s exactly: a broader
  // match echoes claims the lookup never bound, a narrower one silently
  // drops nested paths (w6-fix F7).
  if (claim === 'supports') for (const m of rule.lookup.matchAll(/\$\{claims\.([a-z0-9_.]+)\}/g)) { const v = m[1].split('.').reduce((o, k) => o?.[k], request.claims ?? {}); if (v !== undefined) lookupBound[m[1]] = v; }
  const revealed = claim === 'conflict' ? {} : { ...lookupBound, ...extracted, subject_id: resolvedSubject };
  return signed({ ...base, claim, content_digest: digest({ issuer: issuer.issuer, key, record }), claims: revealed, provenance: prov('*'), issuer_version: issuer.version }, issuer.key, 'evidence');
}

export function createIssuerServer(issuers, { port = 8090, host = '127.0.0.1', clock = Date.now, logPath } = {}) {
  const sequence = { n: 0, previous: '0'.repeat(64) };
  // Continue the hash chain across restarts: seed sequence/previous from the
  // last logged record so truncation of earlier entries stays detectable
  // (issuerd-audit LOW-3).
  if (logPath && existsSync(logPath)) {
    try {
      const lines = readFileSync(logPath, 'utf8').trim().split('\n').filter(Boolean);
      const last = lines.length ? JSON.parse(lines[lines.length - 1]) : null;
      // A present-but-unparseable tail means the chain was tampered with or
      // truncated mid-write — refuse to start rather than orphaning the whole
      // prior segment under a fresh genesis.
      if (lines.length && !(last && Number.isSafeInteger(last.sequence) && /^[a-f0-9]{64}$/.test(last.digest ?? '')))
        throw new InvariantError('INV-503-CONFIG', 'Issuance log tail is corrupt; refuse to re-genesis silently', 503);
      if (last) { sequence.n = last.sequence; sequence.previous = last.digest; }
    } catch (e) { if (e instanceof InvariantError) throw e; /* unreadable tail — start a fresh chain segment */ }
  }
  function issuanceLog(entry) {
    if (!logPath) return;
    sequence.n += 1;
    const record = { sequence: sequence.n, previous: sequence.previous, ...entry, time: clock() };
    sequence.previous = digest(record);
    mkdirSync(resolve(logPath, '..'), { recursive: true });
    // Refuse symlinked log paths — appending through a planted link would
    // write signed issuance records into an attacker-chosen file
    // (w8-tooling F8).
    if (existsSync(logPath)) requireThat(!lstatSync(logPath).isSymbolicLink(), 'INV-503-CONFIG', 'Issuance log path must not be a symlink', 503);
    appendFileSync(logPath, canonical({ ...record, digest: sequence.previous }) + '\n', { mode: 0o600 });
  }
  for (const i of Object.values(issuers)) i.metrics ??= { requests: 0, errors: 0, issued: 0, refused: 0, latencies: [] };
  const server = http.createServer(async (req, res) => {
    res.setHeader('X-Content-Type-Options', 'nosniff'); res.setHeader('Cache-Control', 'no-store');
    const send = (status, data) => { res.writeHead(status, { 'Content-Type': 'application/json' }); res.end(canonical(data)); };
    try {
      const url = new URL(req.url, `http://${host}:${port}`);
      const loopback = ['127.0.0.1', '::1', 'localhost'].includes(host);
      // Scoped bearer credentials: `issue_token` authorises only the mutating
      // /issue surface; `read_token` (or issue_token when no read token is
      // configured) authorises the read surfaces. Both expire at
      // `token_expires_at` — expired credentials are refused, forcing rotation
      // through a configuration update rather than riding forever (IDN-009).
      const checkAuth = (issuer, scope = 'read') => {
        const token = scope === 'issue' ? issuer?.issue_token : (issuer?.read_token ?? issuer?.issue_token);
        if (token) {
          requireThat(!issuer.token_expires_at || issuer.token_expires_at > clock(), 'INV-401-AUTH', 'Issuer token expired; rotate it via configuration update', 401);
          requireThat(bearerMatches(req.headers.authorization ?? '', token), 'INV-401-AUTH', `Issuer endpoint requires the ${scope} bearer token`, 401);
        } else {
          requireThat(loopback, 'INV-503-CONNECTOR', 'Issuer endpoint requires a configured bearer token off loopback', 503);
        }
      };
      // Authenticate before existence/scope resolution (w5 F-3): an
      // unauthenticated caller must get a uniform 401 — never a 404/403 that
      // enumerates issuer names or tenant bindings. `anyBearer` accepts any
      // configured, unexpired issuer token of the required scope; per-issuer
      // binding is still enforced by checkAuth afterwards.
      const anyBearer = (scope) => {
        const auth = req.headers.authorization ?? '';
        return Object.values(issuers).some(i => {
          const t = scope === 'issue' ? i.issue_token : (i.read_token ?? i.issue_token);
          return t && (!i.token_expires_at || i.token_expires_at > clock()) && bearerMatches(auth, t);
        });
      };
      const noTokens = !Object.values(issuers).some(i => i.issue_token || i.read_token);
      const gate = (scope) => { requireThat(loopback || !noTokens, 'INV-503-CONNECTOR', 'Issuer endpoint requires a configured bearer token off loopback', 503); requireThat(anyBearer(scope) || (loopback && noTokens), 'INV-401-AUTH', `Issuer endpoint requires the ${scope} bearer token`, 401); };
      // Per-IP token bucket (w5 F-4): reads and issues are separately
      // budgeted; unauthenticated traffic shares a small bucket so probing
      // cannot burn signing CPU or grow the issuance log unboundedly.
      const buckets = createIssuerServer._buckets ??= new Map();
      const ip = req.socket.remoteAddress ?? 'unknown';
      const bucketFor = (scope) => {
        const key = `${ip}:${scope}`, now = clock();
        const limits = { read: [240, 60000], issue: [120, 60000], probe: [30, 60000] };
        const [cap, window] = limits[scope] ?? limits.probe;
        let b = buckets.get(key); if (!b || now >= b.reset) { b = { left: cap, reset: now + window }; buckets.set(key, b); }
        if (buckets.size > 10000) for (const [k, v] of buckets) if (now >= v.reset) buckets.delete(k);
        return b;
      };
      const take = (scope) => { const b = bucketFor(scope); requireThat(b.left > 0, 'INV-429-RATE', 'Rate limit exceeded', 429); b.left--; };
      const resolveIssuer = (name, tenant) => (tenant && issuers[`${tenant}:${name}`]) || (issuers[name] && !issuers[name].ambiguous ? issuers[name] : (issuers[`${tenant}:${name}`] ?? null));
      if (req.method === 'GET' && url.pathname === '/v1/issuers') {
        const auth = req.headers.authorization ?? '';
        const holder = Object.values(issuers).find(i => {
          const t = i.read_token ?? i.issue_token;
          return t && bearerMatches(auth, t) && (!i.token_expires_at || i.token_expires_at > clock());
        });
        if (!holder) { take('probe'); requireThat(loopback || !noTokens, 'INV-503-CONNECTOR', 'Issuer endpoint requires a configured bearer token off loopback', 503); requireThat(loopback && noTokens, 'INV-401-AUTH', 'Issuer listing requires a valid read bearer token', 401); } else take('read');
        // The directory is scoped to the holder's tenant: one issuer's token
        // must not enumerate every tenant's issuers (issuerd-audit MED-4),
        // and a tenantless holder must not enumerate tenant-scoped issuers
        // (w5 F-14).
        const out = {};
        for (const [k, i] of Object.entries(issuers)) {
          if (i.ambiguous || !i.issuer) continue;
          if (holder && (i.tenant ?? null) !== (holder.tenant ?? null) && i.tenant) continue;
          out[k] = { issuer: i.issuer, tenant: i.tenant ?? null, channel: i.channel, version: i.version, kinds: Object.keys(i.kinds), key_id: i.key.key_id, public_key: i.key.public_key };
        }
        return send(200, out);
      }
      // Tenant-aware resolution: '<tenant>:<issuer>' wins; a bare name
      // resolves only when it is not ambiguous across tenants.
      let m;
      if (req.method === 'GET' && (m = /^\/v1\/issuers\/([A-Za-z0-9_-]+)\/manifest$/.exec(url.pathname))) {
        if (!anyBearer('read')) { take('probe'); } gate('read'); take('read');
        const issuer = resolveIssuer(m[1], url.searchParams.get('tenant'));
        requireThat(issuer, 'INV-404-NOT-FOUND', 'Issuer not found', 404);
        const requestedTenant = url.searchParams.get('tenant');
        if (requestedTenant) requireThat(!issuer.tenant || issuer.tenant === requestedTenant, 'INV-403-SCOPE', 'Issuer does not serve this tenant', 403);
        checkAuth(issuer);
        return send(200, signed({
          connector_id: `issuer:${issuer.issuer}`, version: issuer.version, domain: issuer.channel,
          actions: Object.keys(issuer.kinds), permissions: ['issue signed evidence within declared kinds'],
          limitations: ['Records are authoritative only for this issuer domain', 'No claim about target-side enforcement'],
          idempotency: { mutating_retries: false, safe_read_retries: 2, timeout_ms: 10000 },
          coverage_implications: ['evidence-source'], issued_at: clock(), expires_at: clock() + 86400000 * 30
        }, issuer.key, 'connector-manifest'));
      }
      if (req.method === 'POST' && (m = /^\/v1\/issuers\/([A-Za-z0-9_-]+)\/issue$/.exec(url.pathname))) {
        const chunks = []; let size = 0;
        for await (const c of req) { size += c.length; requireThat(size <= 262144, 'INV-413-BODY', 'Request too large', 413); chunks.push(c); }
        const request = parseStrict(Buffer.concat(chunks).toString('utf8'));
        fields(request, ['tenant_id', 'capsule_digest', 'kind', 'subject_id', 'claims'], ['dependencies']);
        identifier(request.tenant_id, 'tenant'); identifier(request.subject_id, 'subject'); text(request.kind, 'kind', 64);
        requireThat(/^[a-f0-9]{64}$/.test(request.capsule_digest), 'INV-400-SCHEMA', 'capsule_digest must be a digest');
        if (!anyBearer('issue')) { take('probe'); issuanceLog({ issuer: 'unknown', request_digest: digest(request), refused: true, unauthenticated: true, code: 'INV-401-AUTH' }); } gate('issue'); take('issue');
        const issuer = resolveIssuer(m[1], request.tenant_id);
        requireThat(issuer, 'INV-404-NOT-FOUND', 'Issuer not found', 404);
        // Authentication failures are logged to the issuance chain too —
        // probing must not be invisible to provenance audit (MED-5).
        try { checkAuth(issuer, 'issue'); } catch (e) { issuanceLog({ issuer: issuer.issuer, request_digest: digest(request), refused: true, unauthenticated: true, code: e.code ?? 'ERR' }); throw e; }
        issuer.metrics.requests++; const t0 = performance.now();
        try {
          const envelope = answerQuery(issuer, request, clock());
          issuer.metrics.issued++; issuer.metrics.latencies.push(performance.now() - t0); if (issuer.metrics.latencies.length > 512) issuer.metrics.latencies.shift();
          issuanceLog({ issuer: issuer.issuer, request_digest: digest(request), evidence_id: envelope.payload.evidence_id, claim: envelope.payload.claim });
          return send(201, envelope);
        } catch (e) {
          issuer.metrics.errors++; issuer.metrics.refused++;
          issuanceLog({ issuer: issuer.issuer, request_digest: digest(request), refused: true, code: e.code ?? 'ERR' });
          throw e;
        }
      }
      if (req.method === 'GET' && (m = /^\/v1\/issuers\/([A-Za-z0-9_-]+)\/health$/.exec(url.pathname))) {
        if (!anyBearer('read')) { take('probe'); } gate('read'); take('read');
        const issuer = resolveIssuer(m[1], url.searchParams.get('tenant'));
        requireThat(issuer, 'INV-404-NOT-FOUND', 'Issuer not found', 404);
        checkAuth(issuer);
        const lat = issuer.metrics.latencies, sorted = [...lat].sort((a, b) => a - b);
        return send(200, { status: 'ok', issuer: issuer.issuer, version: issuer.version, records: Object.keys(issuer.records).length, uptime_ms: process.uptime() * 1000 | 0, metrics: { requests: issuer.metrics.requests, errors: issuer.metrics.errors, issued: issuer.metrics.issued, refused: issuer.metrics.refused, p50_ms: sorted.length ? sorted[Math.floor(sorted.length / 2)] : 0 }, token_expires_at: issuer.token_expires_at ?? null });
      }
      throw new InvariantError('INV-404-NOT-FOUND', 'Resource not found', 404);
    } catch (e) {
      const known = e instanceof InvariantError;
      send(known ? e.status : 500, { error: { code: known ? e.code : 'INV-500-INTERNAL', message: known ? e.message : 'Internal failure', ...(e.details ? { details: e.details } : {}) } });
    }
  });
  server.requestTimeout = 10000;
  return { server, issuers, listen: () => new Promise(r => server.listen(port, host, r)), close: () => new Promise((r, j) => { server.closeAllConnections(); server.close(e => e ? j(e) : r()); }) };
}

export function writeIssuer(directory, spec) {
  mkdirSync(directory, { recursive: true, mode: 0o700 });
  writeFileSync(join(directory, `${spec.issuer}.issuer.json`), canonical(spec) + '\n', { mode: 0o600, flag: 'wx' });
}

if (process.argv[1] && import.meta.url === `file://${process.argv[1]}`) {
  const args = process.argv.slice(2);
  const opt = (name, fallback) => { const i = args.indexOf(`--${name}`); return i < 0 ? fallback : args[i + 1]; };
  try {
    const directory = resolve(opt('dir', './var/issuers'));
    const port = Number(opt('port', '8090'));
    const issuers = loadIssuers(directory);
    const app = createIssuerServer(issuers, { port, logPath: join(directory, 'issuance-log.jsonl') });
    await app.listen();
    console.log(`Invariant evidence issuers on http://127.0.0.1:${port} serving: ${Object.keys(issuers).join(', ')}`);
    const close = async () => { await app.close(); process.exit(0); };
    process.on('SIGINT', close); process.on('SIGTERM', close);
  } catch (e) {
    console.error(JSON.stringify({ error: e.code ?? 'INV-500-CLI', message: e.code ? e.message : 'Issuer startup failed' }));
    process.exit(1);
  }
}
