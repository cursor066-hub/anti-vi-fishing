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
    // Specs parse through the strict grammar too — duplicate keys, floats
    // and oversize strings must fail at load, not inside canonical() at
    // serve time (w9-deploy F10).
    const spec = parseStrict(readFileSync(join(directory, file), 'utf8'));
    fields(spec, ['issuer', 'key', 'channel', 'kinds', 'records', 'version'], ['tenant', 'issue_token', 'read_token', 'token_expires_at', 'issue_token_digest', 'read_token_digest']);
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
    requireThat(!Object.hasOwn(issuers, key), 'INV-409-CONFLICT', `Duplicate issuer ${key}`, 409);
    issuers[key] = spec;
    if (!Object.hasOwn(issuers, spec.issuer)) issuers[spec.issuer] = spec; else if (issuers[spec.issuer] !== spec) issuers[spec.issuer] = { ambiguous: true };
  }
  requireThat(Object.keys(issuers).length > 0, 'INV-503-CONFIG', 'No issuers configured', 503);
  return issuers;
}

// Constant-time bearer comparison — a plain `===` leaks match length via
// early-exit timing (issuerd-audit LOW-2). The stored side is the bearer
// DIGEST so a circulated spec file never carries a live credential
// (w9-deploy F7).
function bearerMatches(auth, storedDigest) {
  if (typeof auth !== 'string' || !storedDigest) return false;
  return timingSafeEqual(Buffer.from(digest(auth)), Buffer.from(storedDigest));
}
// The stored credential for a scope: the spec's `*_token_digest`, else the
// digest of its plaintext token (legacy specs/tests), else null — tokenless
// issuers serve only under the explicit insecure-loopback opt-in.
function bearerDigest(i, scope) {
  const stored = scope === 'issue' ? i.issue_token_digest : (i.read_token_digest ?? i.issue_token_digest);
  if (stored) return stored;
  const plain = scope === 'issue' ? i.issue_token : (i.read_token ?? i.issue_token);
  return plain ? digest(`Bearer ${plain}`) : null;
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
  // Own-property lookups — 'constructor'/'toString' kind names must miss,
  // not resolve Object.prototype members (w9-deploy F10).
  const rule = Object.hasOwn(issuer.kinds, request.kind) ? issuer.kinds[request.kind] : undefined;
  requireThat(rule, 'INV-412-EVIDENCE', `Issuer does not supply evidence kind ${request.kind}`, 412);
  requireThat(Number.isSafeInteger(rule.confidence) && rule.confidence >= 0 && rule.confidence <= 100, 'INV-503-CONFIG', `Evidence rule for ${request.kind} must declare an explicit confidence`);
  requireThat(request.dependencies === undefined || (Array.isArray(request.dependencies) && request.dependencies.every(d => typeof d === 'string')), 'INV-400-SCHEMA', 'dependencies must be an array of strings');
  const key = interpolate(rule.lookup, request.claims ?? {});
  const record = Object.hasOwn(issuer.records, key) ? issuer.records[key] : null;
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

export function createIssuerServer(issuers, { port = 8090, host = '127.0.0.1', clock = Date.now, logPath, allow_insecure_loopback = false } = {}) {
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
  // Per-IP token buckets are per-server-instance — a static map shared
  // across createIssuerServer calls leaks budgets between daemons and
  // couples unrelated tests (w9-deploy F10).
  const buckets = new Map();
  const server = http.createServer(async (req, res) => {
    res.setHeader('X-Content-Type-Options', 'nosniff'); res.setHeader('Cache-Control', 'no-store');
    // Serialize before any byte is flushed: a canonical() failure must land
    // in the catch cleanly, never mid-response after writeHead (w9-deploy F1).
    const send = (status, data) => { const bodyOut = canonical(data); res.writeHead(status, { 'Content-Type': 'application/json' }); res.end(bodyOut); };
    const ip = req.socket.remoteAddress ?? 'unknown';
    const bucketFor = (scope, issuer = '*') => {
      const key = `${ip}:${scope}:${issuer}`, now = clock();
      const limits = { ip: [600, 60000], read: [240, 60000], issue: [120, 60000], probe: [30, 60000] };
      const [cap, window] = limits[scope] ?? limits.probe;
      let b = buckets.get(key); if (!b || now >= b.reset) { b = { left: cap, reset: now + window }; buckets.set(key, b); }
      if (buckets.size > 10000) for (const [k, v] of buckets) if (now >= v.reset) buckets.delete(k);
      return b;
    };
    const take = (scope, issuer) => { const b = bucketFor(scope, issuer); requireThat(b.left > 0, 'INV-429-RATE', 'Rate limit exceeded', 429); b.left--; };
    try {
      // The coarse per-IP bucket is taken before any request validation —
      // malformed traffic must consume budget too (w9-deploy F9).
      take('ip');
      const url = new URL(req.url, `http://${host}:${port}`);
      // Same Host pinning as the main server: requests naming another
      // authority are answered by nothing here (w9-deploy F5). Compare
      // against the socket's own local address/port so a wildcard-bound
      // daemon still pins the authority it actually received (w9-deploy F5).
      requireThat(req.headers.host === `${req.socket.localAddress}:${req.socket.localPort}` || req.headers.host === req.socket.localAddress, 'INV-400-HOST', 'Unrecognised host', 400);
      const loopback = ['127.0.0.1', '::1', 'localhost'].includes(host);
      // Whether the presented bearer authorises THIS issuer — boolean, so
      // callers can fold it into the same 404 as a missing name and a
      // wrong-issuer bearer learns nothing (w9-deploy F4). `issue` scope
      // requires the issue credential; `read` scope accepts a read
      // credential or the issue credential when no read credential is
      // configured. Both expire at `token_expires_at` (IDN-009).
      const issuerAuthOk = (issuer, scope) => {
        const d = bearerDigest(issuer, scope);
        if (!d) return loopback && allow_insecure_loopback;
        if (issuer.token_expires_at && issuer.token_expires_at <= clock()) return false;
        return bearerMatches(req.headers.authorization ?? '', d);
      };
      // Authenticate before existence/scope resolution (w5 F-3): an
      // unauthenticated caller must get a uniform 401 — never a 404/403 that
      // enumerates issuer names or tenant bindings. `anyBearer` accepts any
      // configured, unexpired issuer token of the required scope; per-issuer
      // binding is still enforced by issuerAuthOk afterwards.
      const anyBearer = (scope) => {
        const auth = req.headers.authorization ?? '';
        return Object.values(issuers).some(i => {
          const d = bearerDigest(i, scope);
          return d && (!i.token_expires_at || i.token_expires_at > clock()) && bearerMatches(auth, d);
        });
      };
      const noTokens = !Object.values(issuers).some(i => i.issue_token || i.read_token || i.issue_token_digest || i.read_token_digest);
      // A tokenless spec set is only servable behind an explicit opt-in —
      // loopback alone must never open the issuer surface silently
      // (w9-deploy F10).
      const openLoopback = loopback && noTokens && allow_insecure_loopback;
      const gate = (scope) => { requireThat(loopback || !noTokens, 'INV-503-CONNECTOR', 'Issuer endpoint requires a configured bearer token off loopback', 503); requireThat(!noTokens || allow_insecure_loopback, 'INV-503-CONNECTOR', 'Tokenless issuers require the insecure-loopback opt-in', 503); requireThat(anyBearer(scope) || openLoopback, 'INV-401-AUTH', `Issuer endpoint requires the ${scope} bearer token`, 401); };
      // Own-property lookups only — a caller-controlled name like 'toString'
      // must never resolve an inherited member into a truthy issuer
      // (w9-fixverify: same oracle class as revoke()).
      const own = k => (Object.hasOwn(issuers, k) ? issuers[k] : undefined);
      const resolveIssuer = (name, tenant) => (tenant && own(`${tenant}:${name}`)) || (own(name) && !own(name).ambiguous ? own(name) : (own(`${tenant}:${name}`) ?? null));
      if (req.method === 'GET' && url.pathname === '/v1/issuers') {
        const auth = req.headers.authorization ?? '';
        const holder = Object.values(issuers).find(i => {
          const d = bearerDigest(i, 'read');
          return d && bearerMatches(auth, d) && (!i.token_expires_at || i.token_expires_at > clock());
        });
        if (!holder) { take('probe'); requireThat(loopback || !noTokens, 'INV-503-CONNECTOR', 'Issuer endpoint requires a configured bearer token off loopback', 503); requireThat(!noTokens || allow_insecure_loopback, 'INV-503-CONNECTOR', 'Tokenless issuers require the insecure-loopback opt-in', 503); requireThat(openLoopback, 'INV-401-AUTH', 'Issuer listing requires a valid read bearer token', 401); } else take('read');
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
        const requestedTenant = url.searchParams.get('tenant');
        // Existence, tenant binding and per-issuer authorisation share one
        // answer — a bearer for a different issuer learns nothing about
        // whether the name resolved (w9-deploy F4).
        requireThat(issuer && (!requestedTenant || !issuer.tenant || issuer.tenant === requestedTenant) && issuerAuthOk(issuer, 'read'), 'INV-404-NOT-FOUND', 'Issuer not found', 404);
        take('read', issuer.issuer);
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
        // Malformed wire bytes surface as INV-400-SCHEMA, never as a 500:
        // the fatal decoder throws TypeError, which the generic handler
        // would otherwise map to INV-500 (w9-fixverify NB-1).
        let request;
        try { request = parseStrict(new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks))); }
        catch (e) { if (e instanceof InvariantError) throw e; throw new InvariantError('INV-400-SCHEMA', 'Malformed request body encoding', 400); }
        fields(request, ['tenant_id', 'capsule_digest', 'kind', 'subject_id', 'claims'], ['dependencies']);
        identifier(request.tenant_id, 'tenant'); identifier(request.subject_id, 'subject'); text(request.kind, 'kind', 64);
        requireThat(/^[a-f0-9]{64}$/.test(request.capsule_digest), 'INV-400-SCHEMA', 'capsule_digest must be a digest');
        if (!anyBearer('issue')) { take('probe'); issuanceLog({ issuer: 'unknown', request_digest: digest(request), refused: true, unauthenticated: true, code: 'INV-401-AUTH' }); } gate('issue'); take('issue');
        const issuer = resolveIssuer(m[1], request.tenant_id);
        // Authentication failures are logged to the issuance chain too —
        // probing must not be invisible to provenance audit (MED-5) — but
        // the response is a uniform 404 so wrong-issuer bearers cannot
        // enumerate names (w9-deploy F4).
        try { requireThat(issuer && issuerAuthOk(issuer, 'issue'), 'INV-404-NOT-FOUND', 'Issuer not found', 404); } catch (e) { issuanceLog({ issuer: issuer?.issuer ?? 'unknown', request_digest: digest(request), refused: true, unauthenticated: true, code: 'INV-404-NOT-FOUND' }); throw e; }
        take('issue', issuer.issuer);
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
        requireThat(issuer && issuerAuthOk(issuer, 'read'), 'INV-404-NOT-FOUND', 'Issuer not found', 404);
        take('read', issuer.issuer);
        const lat = issuer.metrics.latencies, sorted = [...lat].sort((a, b) => a - b);
        // Latencies are floats — emit an integer so the response can never
        // fail canonicalisation (w9-deploy F1).
        return send(200, { status: 'ok', issuer: issuer.issuer, version: issuer.version, records: Object.keys(issuer.records).length, uptime_ms: process.uptime() * 1000 | 0, metrics: { requests: issuer.metrics.requests, errors: issuer.metrics.errors, issued: issuer.metrics.issued, refused: issuer.metrics.refused, p50_ms: sorted.length ? Math.round(sorted[Math.floor(sorted.length / 2)]) : 0 }, token_expires_at: issuer.token_expires_at ?? null });
      }
      throw new InvariantError('INV-404-NOT-FOUND', 'Resource not found', 404);
    } catch (e) {
      // Serialize-first send plus this guard: a mid-response failure
      // destroys the socket instead of re-writing headers — and a throw
      // inside the catch can never exit the process (w9-deploy F1/F2).
      try {
        const known = e instanceof InvariantError;
        if (!res.headersSent) send(known ? e.status : 500, { error: { code: known ? e.code : 'INV-500-INTERNAL', message: known ? e.message : 'Internal failure' } });
        else res.destroy();
      } catch { res.destroy(); }
    }
  });
  // Socket hardening mirrors the main server: header trickle, idle
  // keep-alives and unbounded request streams are all bounded (w9-deploy F5).
  server.requestTimeout = 15000; server.headersTimeout = 8000; server.keepAliveTimeout = 5000; server.maxRequestsPerSocket = 100;
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
    const app = createIssuerServer(issuers, { port, logPath: join(directory, 'issuance-log.jsonl'), allow_insecure_loopback: args.includes('--allow-insecure-loopback') });
    await app.listen();
    console.log(`Invariant evidence issuers on http://127.0.0.1:${port} serving: ${Object.keys(issuers).join(', ')}`);
    const close = async () => { await app.close(); process.exit(0); };
    process.on('SIGINT', close); process.on('SIGTERM', close);
  } catch (e) {
    console.error(JSON.stringify({ error: e.code ?? 'INV-500-CLI', message: e.code ? e.message : 'Issuer startup failed' }));
    process.exit(1);
  }
}
