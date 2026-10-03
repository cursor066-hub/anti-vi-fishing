import http from 'node:http';
import { randomBytes, timingSafeEqual } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';
import { parseStrict, canonical, hashBytes, digest } from './canonical.mjs';
import { fields, text, identifier, integer } from './schema.mjs';
import { SCHEMAS } from './schema.mjs';
import { requireThat, InvariantError } from './errors.mjs';

// Known route paths and their legal methods, for 405 classification of a
// wrong-method request on a real path. {param} templates match one segment.
// Freshness is enforced end-to-end against docs/openapi.json by the
// wrong-method test in http-concurrency-ui.test.mjs.
export const ROUTE_METHODS = new Map(Object.entries({
  '/healthz': 'GET', '/readyz': 'GET', '/': 'GET', '/app.js': 'GET', '/style.css': 'GET',
  '/session': 'POST', '/session/logout': 'POST',
  '/v1/me': 'GET', '/v1/schemas': 'GET', '/v1/policy': 'GET', '/v1/policy/history': 'GET',
  '/v1/action-capsules': 'GET,POST', '/v1/action-capsules/{id}': 'GET',
  '/v1/action-capsules/{id}/approval-challenge': 'GET',
  '/v1/action-capsules/{id}/evidence': 'POST', '/v1/action-capsules/{id}/evaluate': 'POST',
  '/v1/action-capsules/{id}/cancel': 'POST', '/v1/action-capsules/{id}/acquire-evidence': 'POST',
  '/v1/approvals': 'POST', '/v1/approvals/batch': 'POST', '/v1/containment': 'GET',
  '/v1/certificates': 'GET,POST', '/v1/certificates/{id}': 'GET',
  '/gate/v1/execute': 'POST', '/gate/v1/outcomes/{id}': 'GET,POST',
  '/v1/resources/{id}': 'GET', '/v1/capabilities': 'POST', '/gate/v1/runtime': 'POST',
  '/v1/revocations': 'GET,POST', '/v1/coverage': 'GET,POST', '/v1/coverage/history': 'GET',
  '/v1/coverage/{id}/technical-validation': 'POST',
  '/v1/connectors': 'GET', '/v1/connectors/status': 'GET', '/v1/connectors/{id}/drift-check': 'POST', '/v1/connectors/{id}/repin': 'POST',
  '/v1/policies/simulate': 'POST',
  '/v1/audit-exports': 'POST', '/v1/audit/entries': 'GET', '/v1/audit/proofs/{sequence}': 'GET',
  '/v1/audit/consistency': 'GET', '/v1/audit/verify-proof': 'POST',
  '/v1/subjects': 'GET', '/v1/grants': 'GET',
  '/v1/retention/hold': 'POST', '/v1/retention/sweep': 'POST', '/v1/metrics': 'GET',
  '/v1/ceremonies': 'GET,POST', '/v1/ceremonies/{id}/acknowledge': 'POST',
  '/v1/ceremonies/{id}/split': 'POST', '/v1/ceremonies/{id}/reconstruct': 'POST',
  '/v1/ceremonies/{id}/abort': 'POST',
  '/v1/keys': 'GET', '/v1/keys/rotate-prepare': 'POST', '/v1/keys/{id}/attest': 'GET',
  '/v1/config-drift': 'GET', '/v1/config-drift/reassert': 'POST', '/v1/policy/reanchor': 'POST', '/v1/clock/recover': 'POST', '/v1/audit/seal': 'POST',
  '/v1/secure-perception/sessions': 'POST', '/v1/secure-perception/release': 'POST',
  '/v1/secure-perception/fallback': 'POST', '/v1/advisory': 'POST',
}).map(([k, v]) => [k, v.split(',')]));

// Compiled once: each template's {param} expands to the charset its dispatch
// regex enforces, so the 405 binding can never exceed the 404 one
// (w50-http LOW — template/dispatch charset oracle).
const ROUTE_TEMPLATES = [...ROUTE_METHODS.keys()].filter(t => t.includes('{')).map(t => {
  const wide = t.startsWith('/v1/resources/') || t.startsWith('/v1/coverage/') || t.startsWith('/v1/ceremonies/') || t.startsWith('/v1/keys/');
  return [t, new RegExp('^' + t.split('/').map(seg => seg.startsWith('{') ? (seg === '{sequence}' ? '\\d+' : (wide ? '[A-Za-z0-9_.:-]{1,128}' : '[A-Za-z0-9-]{1,128}')) : seg.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('/') + '$')];
});

export function createServer(fabric, { port = 8080, host = '127.0.0.1', origin = `http://127.0.0.1:${port}`, tenantSessionCap = 250, trustProxy = false, proxySecret = null, connectionCap = 2048 } = {}) {
  // A non-numeric or negative cap disables the comparison silently:
  // `openConnections > NaN` is always false and the accept path is then
  // unbounded. Zero is a legal posture — probes only (w40-fv F-10).
  requireThat(Number.isSafeInteger(connectionCap) && connectionCap >= 0, 'INV-400-CONFIG', 'connectionCap must be a non-negative integer', 400);
  requireThat(Number.isSafeInteger(tenantSessionCap) && tenantSessionCap >= 0, 'INV-400-CONFIG', 'tenantSessionCap must be a non-negative integer', 400);
  // The session cookie gets Secure on every origin EXCEPT plaintext
  // loopback — a TLS-terminating upstream proxy serving http internally
  // still hands the cookie to browsers over https (w22-http F4). The
  // __Host- prefix is deliberately not used: it requires Secure, which a
  // loopback-http dev profile cannot set without the cookie being refused.
  const cookieSecure = !(origin.startsWith('http:') && ['localhost', '127.0.0.1', '::1', '[::1]'].some(h => new URL(origin).hostname === h || new URL(origin).hostname.endsWith('.localhost')));
  requireThat(['127.0.0.1', '::1'].includes(host), 'INV-503-RELEASE', 'Engineering HTTP service must bind to loopback', 503);
  // --trust-proxy without a shared proxy secret is vacuous: the daemon only
  // binds loopback, so EVERY peer is "a trusted loopback peer" and any local
  // process could rotate X-Forwarded-For to sidestep every rate bucket
  // (w10-fixverify F-2). The proxy must authenticate its XFF claims with the
  // X-Fabric-Proxy header matching proxySecret.
  requireThat(!trustProxy || typeof proxySecret === 'string' && proxySecret.length >= 16, 'INV-503-CONFIG', '--trust-proxy requires PROXY_SECRET in the environment (never argv — /proc/<pid>/cmdline is world-readable) of at least 16 characters', 503);
  const web = fileURLToPath(new URL('../web/', import.meta.url));
  const sessions = new Map(), rate = new Map();
  const metrics = { requests: 0, errors: 0, unauthorised: 0, rejections: {}, tenants: {} };
  // A backward clock recovery must not resurrect a console session that had
  // legitimately lapsed — mint-time expiry is stored, so the reaper kills
  // every session whose expiry falls inside the rewound span (w22-http F6).
  fabric.onClockRecovery = (now, prior) => { if (now < prior) for (const [key, session] of sessions) if (session.expires > now && session.expires <= prior) sessions.delete(key); };
  function rateLimit(key, max, window = 60000) {
    const now = Date.now();
    if (rate.size > 10000) for (const [k, v] of rate) if (v.reset <= now) rate.delete(k);
    let entry = rate.get(key); if (!entry || entry.reset <= now) { entry = { count: 0, reset: now + window }; rate.set(key, entry); }
    requireThat(++entry.count <= max, 'INV-429-RATE', 'Request rate limit reached', 429);
  }
  function authenticateToken(token) {
    requireThat(typeof token === 'string' && /^[A-Za-z0-9_-]{43}$/.test(token), 'INV-401-AUTH', 'Authentication required', 401);
    const hash = hashBytes(token);
    for (const [tenant, t] of Object.entries(fabric.tenantMap())) {
      const entry = t.auth[hash];
      if (entry && entry.expires_at > fabric.clock() && !fabric.revoked(tenant, 'token', hash)) {
        const principal = { tenant_id: tenant, subject_id: entry.subject_id };
        fabric.authorize(principal, ['operator', 'approver', 'custodian', 'security', 'auditor', 'policy_admin', 'workload']);
        return { principal, expires: entry.expires_at };
      }
    }
    throw new InvariantError('INV-401-AUTH', 'Authentication required', 401);
  }
  // GET routes that mint signed audit rows are not HTTP-safe — a browser
  // <img>/<link> GET under an ambient console cookie would forge ledger
  // evidence with no CSRF binding, so those paths take the POST check too
  // (w41-http F4). Bearer callers stay exempt: the header is never sent
  // ambiently.
  // GET /v1/coverage demotes expired evidence through coverageTransition —
  // a real chain write — so it belongs here too (w45-http M-1a).
  const GET_AUDIT_WRITING = new Set(['/v1/audit/entries', '/v1/audit/consistency', '/v1/containment', '/v1/coverage']);
  function auth(req, getWrites = false) {
    const authorization = req.headers.authorization;
    if (authorization) { requireThat(/^Bearer [A-Za-z0-9_-]{43}$/.test(authorization), 'INV-401-AUTH', 'Authentication required', 401); return authenticateToken(authorization.slice(7)).principal; }
    const sid = /(?:^|;\s*)if_session=([A-Za-z0-9_-]{43})(?:;|$)/.exec(req.headers.cookie ?? '')?.[1], session = sid ? sessions.get(hashBytes(sid)) : null;
    requireThat(session && session.expires > fabric.clock(), 'INV-401-AUTH', 'Authentication required', 401);
    // A session minted from a token dies with it — token revocation checked
    // at mint time alone would leave a residual window (w7-clock F3).
    requireThat(!fabric.revoked(session.principal.tenant_id, 'token', session.token_hash), 'INV-401-AUTH', 'Authentication required', 401);
    // Byte length, not char length: Node decodes headers latin1 but
    // Buffer.from re-encodes UTF-8, so a non-ASCII header passes a
    // char-length gate and throws inside timingSafeEqual — surfacing an
    // INV-500 where the contract promises INV-403 (w17-console F1).
    if (req.method !== 'GET' || getWrites) requireThat(typeof req.headers['x-csrf-token'] === 'string' && Buffer.byteLength(req.headers['x-csrf-token']) === session.csrf.length && timingSafeEqual(Buffer.from(req.headers['x-csrf-token']), Buffer.from(session.csrf)) && req.headers.origin === origin, 'INV-403-CSRF', 'Request origin or CSRF token rejected', 403);
    // An ambient cookie GET is not consented evidence — a forged
    // <img>-class request must never mint AUTHORIZATION_DENIED rows
    // against the victim, so denial auditing is suppressed on the
    // principal this request resolves to (w45-http M-1b). Marker is
    // non-enumerable: it never leaks into response bodies or spreads.
    // The marker must ride INTO the union-role authorize itself — a role
    // or identity failure there mints denial evidence too, so marking
    // after the gate would leave that mint reachable (w46-fixverify L).
    const ambientPrincipal = { ...session.principal };
    if (req.method === 'GET' && !getWrites) Object.defineProperty(ambientPrincipal, '_ambient_get', { value: true });
    fabric.authorize(ambientPrincipal, ['operator', 'approver', 'custodian', 'security', 'auditor', 'policy_admin', 'workload']);
    return ambientPrincipal;
  }
  // Break-glass authentication for /v1/audit/seal: resolve the credential
  // against the frozen auth tables only. The chain-derived revocation and
  // authorize checks inside auth() are exactly what a wedged ledger
  // cannot serve — gating the seal route on them makes remediation dead
  // code in every state it exists for (w41-http F1). sealAuditChain
  // applies its own static identity gate over this principal.
  function authBreakglass(req) {
    // Chain-derived checks are enforced whenever the fold can serve them:
    // on a healthy chain a revoked credential or missing role still
    // refuses — only a ledger wedge (the state break-glass exists to
    // repair) exempts the credential (w43-fv M2). Non-wedge failures
    // always stand: revocation and scope verdicts are never swallowed as
    // 'wedged'.
    const chainChecked = (fn) => { try { fn(); } catch (e) { if (!['INV-409-INTEGRITY', 'INV-409-AUDIT-TAMPER', 'INV-503-GATE'].includes(e?.code)) throw e; } };
    const authorization = req.headers.authorization;
    if (authorization) {
      requireThat(/^Bearer [A-Za-z0-9_-]{43}$/.test(authorization), 'INV-401-AUTH', 'Authentication required', 401);
      const hash = hashBytes(authorization.slice(7));
      for (const [tenant, t] of Object.entries(fabric.tenantMap())) {
        const entry = t.auth[hash];
        if (entry && entry.expires_at > fabric.clock()) {
          const principal = { tenant_id: tenant, subject_id: entry.subject_id };
          chainChecked(() => { requireThat(!fabric.revoked(tenant, 'token', hash), 'INV-401-AUTH', 'Authentication required', 401); fabric.authorize(principal, ['operator', 'approver', 'custodian', 'security', 'auditor', 'policy_admin', 'workload']); });
          return principal;
        }
      }
      throw new InvariantError('INV-401-AUTH', 'Authentication required', 401);
    }
    const sid = /(?:^|;\s*)if_session=([A-Za-z0-9_-]{43})(?:;|$)/.exec(req.headers.cookie ?? '')?.[1], session = sid ? sessions.get(hashBytes(sid)) : null;
    requireThat(session && session.expires > fabric.clock(), 'INV-401-AUTH', 'Authentication required', 401);
    // POST under an ambient cookie keeps the CSRF+Origin binding —
    // break-glass skips chain-derived checks, never ambient-cookie proof.
    requireThat(typeof req.headers['x-csrf-token'] === 'string' && Buffer.byteLength(req.headers['x-csrf-token']) === session.csrf.length && timingSafeEqual(Buffer.from(req.headers['x-csrf-token']), Buffer.from(session.csrf)) && req.headers.origin === origin, 'INV-403-CSRF', 'Request origin or CSRF token rejected', 403);
    chainChecked(() => { requireThat(!fabric.revoked(session.principal.tenant_id, 'token', session.token_hash), 'INV-401-AUTH', 'Authentication required', 401); fabric.authorize(session.principal, ['operator', 'approver', 'custodian', 'security', 'auditor', 'policy_admin', 'workload']); });
    return session.principal;
  }
  // Canonical integer grammar for query params — the same strictness the
  // JSON body parser applies: no hex/exponent/whitespace/signed spellings
  // (w5-http M-3).
  const qint = (raw, name, def, min, max) => {
    // '-0' matches the integer grammar but is not a canonical integer —
    // the body grammar rejects it and the query grammar must agree
    // (w8-canonical F8).
    requireThat(raw === null || (/^-?(0|[1-9]\d*)$/.test(raw) && raw !== '-0'), 'INV-400-SCHEMA', `Invalid ${name}`, 400);
    return integer(raw === null ? def : Number(raw), name, min, max);
  };
  // Only the declared params for a path may appear — unknowns and duplicates
  // are contract violations, not ignored input (w5-http L-1/L-7).
  const QUERY_ALLOW = new Map([
    ['/v1/action-capsules', ['limit', 'offset']], ['/v1/certificates', ['limit', 'offset']],
    ['/v1/grants', ['subject']], ['/v1/coverage/history', ['at']],
    ['/v1/audit/consistency', ['first']], ['/v1/audit/entries', ['cursor', 'limit', 'view']],
    ['/v1/keys/{id}/attest', ['nonce']],
    ['/v1/action-capsules/{id}/approval-challenge', ['signer_id']],
  ]);
  const QUERY_TEMPLATES = [...QUERY_ALLOW.entries()].filter(([t]) => t.includes('{'));
    const object = v => { requireThat(v && typeof v === 'object' && !Array.isArray(v), 'INV-400-SCHEMA', 'Request body must be an object', 400); return v; };
  const queryCheck = (url, path) => {
    // {param} templates match one concrete segment — the same binding the
    // ROUTE_METHODS map applies to methods (w28-crypto F7).
    const allowed = QUERY_ALLOW.get(path) ?? QUERY_TEMPLATES.find(([t]) => {
      const tp = t.split('/'), pp = path.split('/');
      return tp.length === pp.length && tp.every((seg, i) => seg.startsWith('{') || seg === pp[i]);
    })?.[1] ?? [];
    const seen = new Set();
    for (const k of url.searchParams.keys()) {
      requireThat(allowed.includes(k), 'INV-400-SCHEMA', `Unknown query parameter ${k}`, 400);
      requireThat(!seen.has(k), 'INV-400-SCHEMA', `Duplicate query parameter ${k}`, 400);
      seen.add(k);
    }
  };
  async function body(req) {
    // The bare media type is required, but standard clients legitimately
    // append parameters — 'application/json; charset=utf-8' is the same
    // contract (w22-http F7).
    requireThat(typeof req.headers['content-type'] === 'string' && /^application\/json\s*(\s*;\s*[^;=\s]+=[^;\s]+)*$/.test(req.headers['content-type']), 'INV-415-CONTENT', 'Use application/json', 415);
    requireThat(!req.headers['content-encoding'], 'INV-415-CONTENT', 'Compressed request bodies are not accepted', 415);
    if (req.headers['content-length']) requireThat(Number(req.headers['content-length']) <= 1048576, 'INV-413-BODY', 'Request body too large', 413);
    let size = 0; const chunks = [];
    for await (const chunk of req) { size += chunk.length; requireThat(size <= 1048576, 'INV-413-BODY', 'Request body too large', 413); chunks.push(chunk); }
    try { return parseStrict(new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks))); } catch (e) { if (e instanceof InvariantError) throw e; throw new InvariantError('INV-400-SCHEMA', 'Invalid UTF-8 or JSON'); }
  }
  // Bodiless operations still honour the contract: a caller that sends
  // bytes must send them as application/json, and the object must be
  // empty — a text/plain garbage payload can never smuggle a state
  // change past validation, and the body is drained before the response
  // commits (w18-http F-2).
  async function noBody(req) {
    let size = 0; const chunks = [];
    for await (const chunk of req) { size += chunk.length; requireThat(size <= 1048576, 'INV-413-BODY', 'Request body too large', 413); chunks.push(chunk); }
    if (!size) return;
    // The bare media type is required, but standard clients legitimately
    // append parameters — 'application/json; charset=utf-8' is the same
    // contract (w22-http F7).
    requireThat(typeof req.headers['content-type'] === 'string' && /^application\/json\s*(\s*;\s*[^;=\s]+=[^;\s]+)*$/.test(req.headers['content-type']), 'INV-415-CONTENT', 'Use application/json', 415);
    requireThat(!req.headers['content-encoding'], 'INV-415-CONTENT', 'Compressed request bodies are not accepted', 415);
    const parsed = (() => { try { return parseStrict(new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks))); } catch (e) { if (e instanceof InvariantError) throw e; throw new InvariantError('INV-400-SCHEMA', 'Invalid UTF-8 or JSON'); } })();
    requireThat(parsed && typeof parsed === 'object' && !Array.isArray(parsed) && Object.keys(parsed).length === 0, 'INV-400-SCHEMA', 'Operation takes no request body', 400);
  }
  const server = http.createServer({ maxHeaderSize: 16384 }, async (req, res) => {
    // Over-cap sockets serve only health probes — any other request line
    // kills the socket before a byte of response is produced
    // (w38-http LOW; comment corrected w40-fv F-11).
    if (req.socket.overCap && req.url !== '/healthz' && req.url !== '/readyz') {
      try { req.socket.destroy(); } catch { /* already gone */ }
      return;
    }
    metrics.requests++; const requestId = randomBytes(12).toString('hex');
    let requestPrincipal = null;
    // Per-tenant mirrors are counted once the principal resolves — the
    // process-global roll-up is never served to tenants (w6-tenancy F6).
    const bumpTenant = () => { if (requestPrincipal) { const tm = metrics.tenants[requestPrincipal.tenant_id] ??= { requests: 0, errors: 0, unauthorised: 0, rejections: {} }; tm.requests++; } };
    res.setHeader('X-Request-Id', requestId); res.setHeader('X-Content-Type-Options', 'nosniff'); res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('X-Frame-Options', 'DENY'); res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
    res.setHeader('Content-Security-Policy', "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; font-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'");
    res.setHeader('Cross-Origin-Resource-Policy', 'same-origin'); res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
    res.setHeader('Cache-Control', 'no-store');
    // Serialize before any byte is flushed: a canonical() failure must surface
    // as a clean error response, never a destroyed socket after a 200 header.
    const send = (status, data, type = 'application/json; charset=utf-8') => { const bodyOut = type.startsWith('application/json') ? canonical(data) : data; res.writeHead(status, { 'Content-Type': type }); res.end(bodyOut); };
    try {
      // Bucket identity: the socket peer, or the first X-Forwarded-For hop
      // when --trust-proxy is set AND the peer is loopback AND the request
      // carries the proxy secret — loopback contains every local process,
      // not just the reverse proxy, so the peer address alone proves
      // nothing (w10-fixverify F-2). Digests keep the comparison
      // fixed-length for timingSafeEqual.
      const peer = req.socket.remoteAddress;
      const presented = req.headers['x-fabric-proxy'];
      const proxyOk = trustProxy && ['127.0.0.1', '::1', '::ffff:127.0.0.1'].includes(peer)
        && typeof presented === 'string' && timingSafeEqual(Buffer.from(digest(presented)), Buffer.from(digest(proxySecret)));
      // The RIGHTMOST hop is the address the authenticated proxy actually
      // vouched for: append-semantics proxies (nginx $proxy_add_x_forwarded_for,
      // ALB, Cloudflare) put raw client input leftmost, so taking [0] lets any
      // client forge its rate-limit identity (w22-http F1). Under replace-style
      // configs the single entry is also the rightmost, so both shapes are safe.
      const clientIp = proxyOk ? (req.headers['x-forwarded-for']?.split(',').at(-1)?.trim() || peer) : peer;
      // Rate-limit before any request validation — malformed traffic must
      // consume the budget too (w9-deploy F9).
      rateLimit(`ip:${clientIp}`, 600);
      requireThat(['GET', 'POST'].includes(req.method), 'INV-405-METHOD', 'Method not allowed', 405);
      requireThat(req.headers.host === new URL(origin).host, 'INV-400-HOST', 'Unrecognised host', 400);
      requireThat(!req.headers.origin || req.headers.origin === origin, 'INV-403-ORIGIN', 'Cross-origin requests are not allowed', 403);
      const url = new URL(req.url, origin), path = url.pathname;
      // Route on the canonical path only: absolute-form targets, backslashes,
      // and encoded or literal dot-segments must be rejected, never silently
      // normalized — an upstream ACL sees the raw bytes (w5-http M-6).
      const rawTarget = req.url, rawPath = rawTarget.split('?')[0];
      requireThat(rawTarget.startsWith('/') && rawPath === path, 'INV-400-SCHEMA', 'Request target must be an origin-form canonical path', 400);
      if (path === '/healthz' && req.method === 'GET') return send(200, { status: 'ok', profile: 'engineering', production_ready: false });
      if (path === '/readyz' && req.method === 'GET') { fabric.store._stmt('SELECT 1').get(); return send(200, { status: 'ready', profile: 'engineering', real_targets: false }); }
      const assets = { '/': ['index.html', 'text/html; charset=utf-8'], '/app.js': ['app.js', 'text/javascript; charset=utf-8'], '/style.css': ['style.css', 'text/css; charset=utf-8'] };
      // Query-parameter validation runs AFTER authentication: the
      // allow-list is a per-route contract map, and a pre-auth 400-vs-401
      // oracle would expose the whole authenticated surface's parameter
      // grammar to anonymous probers (w41-http F8). The login route keeps
      // its own check inside the handler; public assets have no
      // parameters to leak.
      const queryCheckAfterAuth = path !== '/session';
      // Static assets dispatch as literal route arms — the route-parity
      // gate audits this shape; a map lookup is live code it cannot see.
      if (req.method === 'GET' && (path === '/' || path === '/app.js' || path === '/style.css')) { const [file, type] = assets[path]; return send(200, readFileSync(join(web, file)), type); }
      if (path === '/session' && req.method === 'POST') {
        // Two buckets: a coarse per-IP ceiling AND a per-token FAILURE
        // counter. Keying login only on the address starves every console
        // user behind one proxy IP when a single client floods (w28-http
        // F-05); keying failures per token caps brute-force on any single
        // credential at 5/min without denying legitimate repeat logins —
        // successful authentication costs nothing on that bucket.
        rateLimit(`login:${clientIp}`, 200);
        requireThat(req.headers.origin === origin, 'INV-403-ORIGIN', 'Session creation requires same origin', 403);
        queryCheck(url, path);
        const input = await body(req); fields(input, ['token']); requireThat(typeof input.token === 'string', 'INV-400-SCHEMA', 'token must be a string', 400);
        let result;
        try { result = authenticateToken(input.token); }
        catch (err) { rateLimit(`login-token:${digest(input.token)}`, 5); throw err; }
        // A login is a tenant-scoped request too — attribute it once the
        // token resolves so the slice isn't skewed toward post-auth traffic
        // only. Failures stay unattributed: a bad token resolves no tenant
        // (w6-fix F9).
        requestPrincipal = result.principal; bumpTenant();
        for (const [key, session] of sessions) if (session.expires <= fabric.clock()) sessions.delete(key);
        if (!(sessions.size < 1000)) {
          // The tenant-cap sibling names its refusal — the global cap must
          // too, or a login flood leaves no signed evidence (w45-http L-2).
          try { fabric.store.audit(requestPrincipal.tenant_id, 'CONSOLE_SESSION_DENIED', requestPrincipal.subject_id, 'console', { reason: 'global_session_cap' }, fabric.clock()); } catch { /* best-effort */ }
          requireThat(false, 'INV-503-CAPACITY', 'Session capacity reached', 503);
        }
        // Per-tenant ceiling too: the global cap alone lets one spoofed
        // flood lock every other tenant out (w7-console F1).
        if (!([...sessions.values()].filter(s => s.principal.tenant_id === requestPrincipal.tenant_id).length < tenantSessionCap)) {
          try { fabric.store.audit(requestPrincipal.tenant_id, 'CONSOLE_SESSION_DENIED', requestPrincipal.subject_id, 'console', { reason: 'tenant_session_cap' }, fabric.clock()); } catch { /* best-effort */ }
          requireThat(false, 'INV-503-CAPACITY', 'Tenant session capacity reached', 503);
        }
        // A credential family may not fill the tenant's slice: sessions
        // minted from the same token are capped far below the tenant cap
        // and the family's oldest is evicted, so one credential churning
        // logins locks only itself out (w38-http M-2).
        const loginTokenHash = hashBytes(input.token), family = [...sessions.entries()].filter(([, s]) => s.token_hash === loginTokenHash);
        if (family.length >= 32) {
          let oldest = null;
          for (const [key, s] of family) if (oldest === null || s.expires < oldest.s.expires) oldest = { key, s };
          if (oldest) sessions.delete(oldest.key);
        }
        const sid = randomBytes(32).toString('base64url'), csrf = randomBytes(32).toString('base64url');
        const expires = Math.min(fabric.clock() + 900000, result.expires);
        sessions.set(hashBytes(sid), { principal: requestPrincipal, csrf, expires, token_hash: loginTokenHash });
        // Console session lifecycle lands on the signed chain — mint/deny/
        // logout are security events an incident review must reconstruct.
        // Best-effort: a wedged ledger must not brick operator login
        // (w38-http LOW).
        try { fabric.store.audit(requestPrincipal.tenant_id, 'CONSOLE_SESSION_MINTED', requestPrincipal.subject_id, 'console', { expires }, fabric.clock()); } catch { /* ledger evidence is best-effort for console sessions */ }
        res.setHeader('Set-Cookie', `if_session=${sid}; HttpOnly; SameSite=Strict; Path=/; Max-Age=900${cookieSecure ? '; Secure' : ''}`);
        // expires_in is the REAL clipped lifetime, not the 900s ceiling — a
        // client scheduling a refresh off the literal must not hold a dead
        // session (w22-http F3).
        return send(200, { ...result.principal, csrf_token: csrf, expires_in: Math.max(0, Math.round((expires - fabric.clock()) / 1000)) });
      }
      // Break-glass seal path: authenticate against the frozen auth table
      // alone — the chain-derived revocation/authorize checks inside
      // auth() are exactly what a wedged chain cannot serve, which would
      // make /v1/audit/seal dead code in every state it exists for
      // (w41-http F1). sealAuditChain's own static identity gate still
      // decides; a revoked-token chain check is unknowable here and is
      // attested inside the seal evidence instead.
      if (path === '/v1/audit/seal' && req.method === 'POST') {
        const p = authBreakglass(req); requestPrincipal = p; bumpTenant();
        rateLimit(`subject:${p.tenant_id}:${p.subject_id}`, 300);
        await noBody(req);
        // Parameter validation must run BEFORE the seal executes — a
        // malformed request must never rewrite the ledger on its way to a
        // 400 (w43-fv M1, same ordering doctrine as logout).
        if (queryCheckAfterAuth) queryCheck(url, path);
        const out = fabric.sealAuditChain(p);
        return send(200, out);
      }
      const p = auth(req, GET_AUDIT_WRITING.has(path) || /^\/v1\/audit\/proofs\/\d+$/.test(path)); requestPrincipal = p; bumpTenant(); rateLimit(`subject:${p.tenant_id}:${p.subject_id}`, 300);
      if (queryCheckAfterAuth) queryCheck(url, path);
      if (path === '/session/logout' && req.method === 'POST') {
        // Logout retires every sibling session minted from the same
        // credential — one stolen token's sessions must not linger under a
        // device the user never sees (w7-console F4). The kill is bound to
        // the credential the CALLER authenticated with: a Bearer token for
        // principal A presenting a sid minted under B's token may not force
        // B's family out — only sessions whose token_hash equals the
        // caller's own credential hash are terminated (w17-console F3).
        // With no matching session the response reports it rather than
        // claiming a logout that terminated nothing (w17-console F4).
        const sid = /(?:^|;\s*)if_session=([A-Za-z0-9_-]{43})(?:;|$)/.exec(req.headers.cookie ?? '')?.[1];
        const callerTokenHash = req.headers.authorization ? hashBytes(req.headers.authorization.slice(7)) : (sid ? sessions.get(hashBytes(sid))?.token_hash : null);
        // A Bearer-only logout presents no sid: retiring the caller's own
        // credential family is still the honest answer — the token itself
        // identifies which sessions must die (w25-issuerd logout residual).
        const doomed = sid ? sessions.get(hashBytes(sid))?.token_hash : callerTokenHash;
        // Validate the body BEFORE any state change — a malformed request
        // must not terminate sessions on its way to a 400 (w38-http LOW).
        await noBody(req);
        let terminated = 0;
        if (doomed && doomed === callerTokenHash) for (const [key, session] of sessions) if (session.token_hash === doomed) { sessions.delete(key); terminated++; }
        res.setHeader('Set-Cookie', 'if_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0');
        try { fabric.store.audit(p.tenant_id, 'CONSOLE_SESSION_LOGGED_OUT', p.subject_id, 'console', { sessions_terminated: terminated }, fabric.clock()); } catch { /* best-effort */ }
        return send(200, { logged_out: terminated > 0, sessions_terminated: terminated });
      }
      // /v1/me serves the EFFECTIVE role set — what authorize() actually
      // grants, grant-derived roles included. The static identity row
      // alone would lie to a caller holding a capability-minted role
      // (w41-http F2).
      if (path === '/v1/me' && req.method === 'GET') { const effRoles = fabric.grantsFor(p.tenant_id, p.subject_id, fabric.clock()).roles; const meRoles = Array.isArray(effRoles) && effRoles.length ? effRoles : fabric.identity(p)?.roles; return send(200, { ...p, roles: Array.isArray(meRoles) ? meRoles : [], device_id: fabric.identity(p).device_id, profile: 'engineering', secure_perception: 'dev-attested-software', perception_components: (Array.isArray(meRoles) && meRoles.some(r => ['operator', 'approver', 'custodian', 'security'].includes(r))) ? Object.keys(fabric.perceptionComponents[p.tenant_id] ?? {}) : [] }); }
      if (path === '/v1/schemas' && req.method === 'GET') return send(200, Object.values(SCHEMAS).map(s => ({ ...s, digest: digest(s) })));
      if (path === '/v1/policy' && req.method === 'GET') { fabric.authorize(p, ['operator', 'approver', 'custodian', 'policy_admin', 'security', 'auditor']); return send(200, fabric.policy(p.tenant_id)); }
      if (path === '/v1/action-capsules' && req.method === 'GET') {
        fabric.authorize(p, ['operator', 'approver', 'custodian', 'security', 'policy_admin', 'auditor']);
        const limit = qint(url.searchParams.get('limit'), 'limit', 50, 1, 100), offset = qint(url.searchParams.get('offset'), 'offset', 0, 0, 1000000);
        return send(200, { items: fabric.store.list(p.tenant_id, 'capsule', limit, offset).map(c => fabric.capsuleView(c, p.tenant_id)), limit, offset });
      }
      if (path === '/v1/action-capsules' && req.method === 'POST') { fabric.authorize(p, ['operator', 'workload', 'policy_admin']); const input = await body(req); fields(input, ['input', 'signature']); return send(201, fabric.capsuleView(fabric.propose(p, input.input, req.headers['idempotency-key'], input.signature))); }
      let m;
      if ((m = /^\/v1\/action-capsules\/([A-Za-z0-9-]{1,128})$/.exec(path)) && req.method === 'GET') return send(200, fabric.getCapsule(p, m[1]));
      if ((m = /^\/v1\/action-capsules\/([A-Za-z0-9-]{1,128})\/approval-challenge$/.exec(path)) && req.method === 'GET') return send(200, fabric.approvalChallenge(p, m[1], url.searchParams.get('signer_id')));
      // Authorize BEFORE field-shape validation: a 400-vs-403 delta leaks
      // the route's field whitelist to unauthorized callers (w22-http F2).
      if ((m = /^\/v1\/action-capsules\/([A-Za-z0-9-]{1,128})\/evaluate$/.exec(path)) && req.method === 'POST') { fabric.authorize(p, ['operator', 'policy_admin', 'approver', 'custodian']); const input = await body(req); fields(input, []); return send(200, fabric.evaluate(p, m[1])); }
      if ((m = /^\/v1\/action-capsules\/([A-Za-z0-9-]{1,128})\/(evidence|cancel)$/.exec(path)) && req.method === 'POST') {
        fabric.authorize(p, ['operator', 'security', 'policy_admin']);
        const input = await body(req); if (m[2] === 'evidence') return send(201, fabric.attachEvidence(p, m[1], input)); fields(input, []);
        return send(200, fabric.cancel(p, m[1]));
      }
      // Authorize before parsing the body — a body-shape 400 must not leak
      // parse semantics to a caller who would 403 anyway (w39-ledger F2).
      if (path === '/v1/approvals' && req.method === 'POST') { fabric.authorize(p, ['approver', 'custodian']); return send(201, fabric.approve(p, await body(req))); }
      if (path === '/v1/approvals/batch' && req.method === 'POST') { fabric.authorize(p, ['approver', 'custodian']); return send(201, fabric.batchApprove(p, await body(req))); }
      if (path === '/v1/containment' && req.method === 'GET') return send(200, fabric.containmentReport(p));
      if (path === '/v1/certificates' && req.method === 'POST') { fabric.authorize(p, ['operator', 'policy_admin']); const input = await body(req); fields(input, ['capsule_id']); identifier(input.capsule_id); return send(201, fabric.certificate(p, input.capsule_id)); }
      if ((m = /^\/v1\/certificates\/([A-Za-z0-9-]{1,128})$/.exec(path)) && req.method === 'GET') { fabric.authorize(p, ['operator', 'policy_admin', 'security']); return send(200, fabric.store.must(p.tenant_id, 'certificate', m[1]).envelope); }
      if (path === '/gate/v1/execute' && req.method === 'POST') { fabric.authorize(p, ['operator', 'policy_admin']); const input = await body(req); fields(input, ['certificate', 'dry_run']); requireThat(typeof input.dry_run === 'boolean', 'INV-400-SCHEMA', 'dry_run must be boolean'); return send(200, fabric.execute(p, input.certificate, { dryRun: input.dry_run })); }
      if ((m = /^\/gate\/v1\/outcomes\/([A-Za-z0-9-]{1,128})$/.exec(path)) && req.method === 'GET') {
        // Read-only view: reconciliation itself is a POST — a GET never writes.
        fabric.authorize(p, ['operator', 'security', 'policy_admin']); const out = fabric.store.get(p.tenant_id, 'outcome', m[1]);
        requireThat(out, 'INV-404-NOT-FOUND', 'No recorded outcome for this certificate', 404);
        return send(200, fabric.outcomeView(p.tenant_id, out, m[1]));
      }
      if ((m = /^\/gate\/v1\/outcomes\/([A-Za-z0-9-]{1,128})$/.exec(path)) && req.method === 'POST') { fabric.authorize(p, ['operator', 'security', 'policy_admin']); await noBody(req); return send(200, fabric.outcomeView(p.tenant_id, fabric.reconcile(p, m[1]), m[1])); }
      if ((m = /^\/v1\/resources\/([A-Za-z0-9_.:-]{1,128})$/.exec(path)) && req.method === 'GET') { fabric.authorize(p, ['operator', 'policy_admin']); requireThat(fabric.target.exists(p.tenant_id, m[1]), 'INV-404-NOT-FOUND', 'Resource not found', 404); const state = fabric.target.state(p.tenant_id, m[1]); if (Array.isArray(state.material_fields.rows)) throw new InvariantError('INV-403-SCOPE', 'Use a data capability for dataset access', 403); return send(200, fabric.resourceStateView(state)); }
      if (path === '/v1/capabilities' && req.method === 'POST') { fabric.authorize(p, ['operator', 'workload']); return send(201, fabric.runtime.issue(p, object(await body(req)))); }
      if (path === '/gate/v1/runtime' && req.method === 'POST') { fabric.authorize(p, ['operator', 'workload']); return send(200, fabric.runtime.consume(p, object(await body(req)))); }
      if (path === '/v1/revocations' && req.method === 'POST') { fabric.authorize(p, ['security']); return send(201, fabric.revoke(p, object(await body(req)))); }
      if (path === '/v1/coverage' && req.method === 'GET') return send(200, fabric.coverage(p));
      if (path === '/v1/coverage' && req.method === 'POST') { fabric.authorize(p, ['security']); return send(201, fabric.declareCoverage(p, await body(req))); }
      if (path === '/v1/coverage/history' && req.method === 'GET') return send(200, fabric.coverageAt(p, qint(url.searchParams.get('at'), 'at', fabric.clock(), 0, 1e14)));
      // The path-id alphabet is the identifier alphabet declarePath admits —
      // ':'/'.'/'_' ids are legal coverage paths, so the route must reach
      // them or a declared obligation can never close (w45-http HIGH).
      if ((m = /^\/v1\/coverage\/([A-Za-z0-9_.:-]{1,128})\/technical-validation$/.exec(path)) && req.method === 'POST') { fabric.authorize(p, ['security']); return send(200, fabric.technicalValidation(p, m[1], await body(req))); }
      if (path === '/v1/connectors' && req.method === 'GET') { fabric.authorize(p, ['operator', 'security', 'policy_admin', 'auditor']); return send(200, fabric.target.manifest()); }
      if (path === '/v1/policies/simulate' && req.method === 'POST') { fabric.authorize(p, ['policy_admin', 'security']); return send(200, fabric.simulate(p, object(await body(req)))); }
      if (path === '/v1/audit-exports' && req.method === 'POST') { fabric.authorize(p, ['auditor', 'security']); const input = await body(req); fields(input, ['purpose']); return send(200, fabric.exportAudit(p, input.purpose)); }
      if (path === '/v1/retention/hold' && req.method === 'POST') { fabric.authorize(p, ['security']); return send(200, fabric.retention(p, object(await body(req)))); }
      if (path === '/v1/retention/sweep' && req.method === 'POST') { fabric.authorize(p, ['security']); fields(await body(req), []); return send(200, fabric.retentionSweep(p)); }
      // RUN-006: rejections are reason-coded — every denial carries the INV
      // code so dashboards can facet by cause without parsing message text.
      if (path === '/v1/metrics' && req.method === 'GET') { fabric.authorize(p, ['security']); const tm = metrics.tenants[p.tenant_id] ?? { requests: 0, errors: 0, unauthorised: 0, rejections: {} }; return send(200, { ...tm, scope: 'tenant', analytics_enabled: false }); }
      if (path === '/v1/revocations' && req.method === 'GET') return send(200, fabric.revocations(p));
      if (path === '/v1/grants' && req.method === 'GET') { fabric.authorize(p, ['operator', 'security', 'auditor']); const subject = url.searchParams.get('subject'); requireThat(subject === null || subject === p.subject_id || ['security', 'auditor'].some(r => fabric.identity(p).roles?.includes(r)), 'INV-403-SCOPE', 'Grant enumeration for another subject requires security or auditor', 403); return send(200, fabric.listGrants(p, subject)); }
      if (path === '/v1/subjects' && req.method === 'GET') { fabric.authorize(p, ['operator', 'security', 'auditor', 'policy_admin']); return send(200, { items: Object.values(fabric.identities(p.tenant_id)).map(i => ({ subject_id: i.subject_id, roles: i.roles, device_id: i.device_id, identity_class: i.identity_class, health_expires_at: i.health_expires_at })) }); }
      if (path === '/v1/certificates' && req.method === 'GET') { fabric.authorize(p, ['operator', 'security', 'auditor', 'policy_admin']); const limit = qint(url.searchParams.get('limit'), 'limit', 50, 1, 200), offset = qint(url.searchParams.get('offset'), 'offset', 0, 0, 1000000); return send(200, { items: fabric.store.list(p.tenant_id, 'certificate', limit, offset).map(c => ({ certificate_id: c.envelope?.payload?.certificate_id ?? null, status: c.status, issued_at: c.issued_at ?? null, consumed: c.consumed === true })), limit, offset }); }
      if (path === '/v1/policy/history' && req.method === 'GET') { fabric.authorize(p, ['operator', 'security', 'auditor', 'policy_admin']); return send(200, { items: fabric.store.list(p.tenant_id, 'policy-history', 100, 0), staged: fabric.store.get(p.tenant_id, 'policy', 'staged') ?? null }); }
      if ((m = /^\/v1\/action-capsules\/([A-Za-z0-9-]{1,128})\/acquire-evidence$/.exec(path)) && req.method === 'POST') { fabric.authorize(p, ['operator', 'security', 'policy_admin']); const input = await body(req); fields(input, ['issuer', 'kind', 'claims']); return send(201, await fabric.acquireEvidence(p, m[1], input)); }
      if (path === '/v1/connectors/status' && req.method === 'GET') return send(200, fabric.connectorStatus(p));
      if ((m = /^\/v1\/connectors\/([A-Za-z0-9-]{1,128})\/drift-check$/.exec(path)) && req.method === 'POST') { fabric.authorize(p, ['security', 'policy_admin']); await noBody(req); return send(200, await fabric.checkIssuerDrift(p, m[1])); }
      // The governed re-provisioning path: an honest issuer record-set
      // change re-pins the served spec digest on-chain instead of file
      // surgery (w49-ledger F4).
      if ((m = /^\/v1\/connectors\/([A-Za-z0-9-]{1,128})\/repin$/.exec(path)) && req.method === 'POST') { fabric.authorize(p, ['security']); await noBody(req); return send(200, await fabric.repinIssuerSpec(p, m[1])); }
      if ((m = /^\/v1\/audit\/proofs\/(\d+)$/.exec(path)) && req.method === 'GET') { fabric.authorize(p, ['operator', 'security', 'auditor']); return send(200, fabric.auditProof(p, Number(m[1]))); }
      if (path === '/v1/audit/consistency' && req.method === 'GET') { fabric.authorize(p, ['operator', 'security', 'auditor']); const first = qint(url.searchParams.get('first'), 'first', 1, 1, 1e12); return send(200, fabric.auditConsistency(p, first)); }
      if (path === '/v1/audit/entries' && req.method === 'GET') { const cursor = qint(url.searchParams.get('cursor'), 'cursor', 0, 0, 1e12), limit = qint(url.searchParams.get('limit'), 'limit', 1000, 1, 5000); return send(200, fabric.auditPageScoped(p, { after: cursor, limit, view: url.searchParams.get('view') ?? undefined })); }
      // The proof verifies against its OWN claimed (root,size) — pinning the
      // live DB would be circular under file-write (the answer would only mean
      // "consistent with current clay") and was also deterministically stale:
      // auditProof appends its own access row before returning, so a re-pinned
      // check always forked (w33-export F3). An optional caller-supplied `pin`
      // binds the proof to an externally witnessed checkpoint instead.
      if (path === '/v1/audit/verify-proof' && req.method === 'POST') { fabric.authorize(p, ['operator', 'security', 'auditor']); const i = await body(req); fields(i, ['proof'], ['pin']); let pinned = null; if (i.pin !== undefined) { fields(i.pin, ['root', 'size']); text(i.pin.root, 'pin.root', 128); integer(i.pin.size, 'pin.size', 1); pinned = { root: i.pin.root, size: i.pin.size }; } return send(200, { valid: fabric.verifyAuditProof(p.tenant_id, i.proof, pinned) }); }
      if (path === '/v1/ceremonies' && req.method === 'GET') { fabric.authorize(p, ['security', 'custodian', 'policy_admin']); return send(200, { items: fabric.store.list(p.tenant_id, 'ceremony', 100, 0).map(c => ({ ceremony_id: c.ceremony_id, status: fabric.ceremonyStatus(p.tenant_id, c), row_status: c.status, purpose: c.purpose })) }); }
      if (path === '/v1/ceremonies' && req.method === 'POST') { fabric.authorize(p, ['security', 'custodian']); return send(201, fabric.createCeremony(p, object(await body(req)))); }
      if ((m = /^\/v1\/ceremonies\/([A-Za-z0-9_.:-]{1,128})\/(acknowledge|split|reconstruct|abort)$/.exec(path)) && req.method === 'POST') {
        // Authorize before parsing the body — a body-shape 400 must not
        // leak parse semantics to a caller who would 403 anyway
        // (w38-http LOW ordering parity with the noBody routes).
        if (m[2] === 'acknowledge') { fabric.authorize(p, ['custodian']); const input = object(await body(req)); requireThat(input?.payload?.ceremony_id === m[1], 'INV-400-SCHEMA', 'ceremony_id in the body must match the path', 400); return send(200, fabric.acknowledgeCeremony(p, input)); }
        if (m[2] === 'abort') { fabric.authorize(p, ['security', 'custodian']); const input = await body(req); fields(input, []); return send(200, fabric.abortCeremony(p, m[1])); }
        if (m[2] === 'split') { fabric.authorize(p, ['security', 'custodian']); const input = await body(req); fields(input, ['secret']); return send(200, fabric.splitCeremonySecret(p, m[1], input.secret)); }
        fabric.authorize(p, ['security', 'custodian']); const input = await body(req); fields(input, ['shares']); return send(200, fabric.reconstructCeremony(p, m[1], input.shares));
      }
      if (path === '/v1/keys' && req.method === 'GET') { fabric.authorize(p, ['security', 'policy_admin']); return send(200, { keys: fabric.vault.list().filter(k => fabric.ownsVaultKey(p.tenant_id, k.key_id)).map(({ wrapped, ...k }) => k), firmware: fabric.vault.firmware }); }
      if (path === '/v1/keys/rotate-prepare' && req.method === 'POST') { fabric.authorize(p, ['security', 'custodian']); const input = await body(req); fields(input, ['key_class'], ['suite']); return send(201, fabric.prepareRotation(p, input.key_class, input.suite)); }
      // Authorize before body validation on the seal-family routes too —
      // an unauthorized caller must see 403, not a body-shape 400
      // (w38-http LOW ordering parity).
      if (path === '/v1/config-drift/reassert' && req.method === 'POST') { fabric.authorize(p, ['security']); await noBody(req); return send(200, fabric.reassertConfig(p)); }
      if (path === '/v1/policy/reanchor' && req.method === 'POST') { fabric.authorize(p, ['security']); await noBody(req); return send(200, fabric.reanchorPolicy(p)); }
      if (path === '/v1/clock/recover' && req.method === 'POST') { fabric.authorize(p, ['security', 'policy_admin']); await noBody(req); return send(200, fabric.recoverClock(p)); }
      if (path === '/v1/config-drift' && req.method === 'GET') return send(200, fabric.configDriftStatus(p));
      // A caller-supplied nonce binds the artifact to the verifier's
      // challenge — without it the endpoint mints freely-replayable
      // attestations (w28-crypto F7).
      if ((m = /^\/v1\/keys\/([A-Za-z0-9_.:-]{1,128})\/attest$/.exec(path)) && req.method === 'GET') { fabric.authorize(p, ['security', 'auditor']); const e = fabric.vault.keys.get(m[1]); requireThat(e && fabric.ownsVaultKey(p.tenant_id, m[1]), 'INV-404-NOT-FOUND', 'Key not found', 404); const nonce = url.searchParams.get('nonce'); if (nonce !== null) text(nonce, 'nonce', 128); return send(200, fabric.vault.attest(m[1], { now: fabric.clock(), nonce })); }
      if (path === '/v1/secure-perception/sessions' && req.method === 'POST') { fabric.authorize(p, ['operator', 'approver', 'custodian', 'security']); const input = await body(req); fields(input, ['attestation']); return send(201, fabric.perceptionSession(p, input.attestation)); }
      if (path === '/v1/secure-perception/release' && req.method === 'POST') { fabric.authorize(p, ['operator', 'approver', 'custodian', 'security']); const input = await body(req); fields(input, ['session_id', 'fields', 'purpose'], ['capsule_id', 'evidence_ref']); const { session_id, ...release } = input; return send(200, fabric.perceptionRelease(p, session_id, release)); }
      if (path === '/v1/secure-perception/fallback' && req.method === 'POST') { fabric.authorize(p, ['operator', 'approver', 'custodian', 'security']); const input = await body(req); fields(input, ['fields', 'purpose'], ['reason', 'capsule_id', 'evidence_ref']); return send(200, fabric.perceptionFallback(p, input)); }
      if (path === '/v1/advisory' && req.method === 'POST') { fabric.authorize(p, ['operator', 'security', 'policy_admin', 'approver', 'custodian', 'auditor']); return send(200, fabric.advise(p, object(await body(req)))); }
      // A real path with the wrong method is a 405, not an ambiguous 404 —
      // keeps the contract honest for method-probing clients (w5-http L-6).
      // The {param} expansion must carry the SAME charset dispatch enforces:
      // a wider match would oracle template existence (GET on an
      // undispatchable id answering 405 where its POST sibling 404s) —
      // w50-http LOW. Charsets mirror the dispatch regexes: {sequence} is
      // numeric; the resources/coverage/ceremonies/keys families accept the
      // wider id grammar; every other {id} is [A-Za-z0-9-]. All captures
      // are length-bounded {1,128} — the openapi contract's maxLength and
      // dispatch now agree (w50-ledger L-1).
      const routeMethods = ROUTE_METHODS.get(path) ?? ROUTE_METHODS.get(ROUTE_TEMPLATES.find(([, re]) => re.test(path))?.[0]);
      requireThat(!routeMethods || routeMethods.includes(req.method), 'INV-405-METHOD', 'Method not allowed', 405);
      throw new InvariantError('INV-404-NOT-FOUND', 'Resource not found', 404);
    } catch (e) {
      // A client that aborts mid-request is client behaviour, not a server
      // fault — nothing is counted or sent on a dead socket (w5-http M-1).
      if (req.aborted || req.errored) { try { res.destroy(); } catch { /* already gone */ } return; }
      metrics.errors++; if (e.status === 401) metrics.unauthorised++;
      const known = e instanceof InvariantError;
      if (known) metrics.rejections[e.code] = (metrics.rejections[e.code] ?? 0) + 1;
      if (requestPrincipal) { const tm = metrics.tenants[requestPrincipal.tenant_id] ??= { requests: 0, errors: 0, unauthorised: 0, rejections: {} }; tm.errors++; if (e.status === 401) tm.unauthorised++; if (known) tm.rejections[e.code] = (tm.rejections[e.code] ?? 0) + 1; }
      // UX-010: the reason code is stable contract; the message may carry
      // field-level internals, so it is redacted for principals without a
      // security/auditor role — they get code + request_id to take up out
      // of band.
      let roles = [];
      try { roles = requestPrincipal ? (fabric.grantsFor(requestPrincipal.tenant_id, requestPrincipal.subject_id, fabric.clock()).roles ?? []) : []; } catch { /* error path must never throw */ }
      const privileged = roles.some(r => ['security', 'auditor', 'policy_admin'].includes(r));
      const message = !known ? 'Internal failure; contact the operator with the request id' : privileged ? e.message : 'Rejected; security or auditor roles can read the detail';
      // Structured details ride the same visibility gate as the message —
      // field-level internals go only to privileged callers (w41-http
      // F10). Unknown faults still carry none. A detail object that
      // cannot canonicalize degrades to absent, never to a broken send.
      let details;
      if (known && privileged && e.details !== undefined) { try { canonical({ d: e.details }); details = e.details; } catch { /* unserializable detail */ } }
      if (!res.headersSent) send(known ? e.status : 500, { error: { code: known ? e.code : 'INV-500-INTERNAL', message, request_id: requestId, ...(details !== undefined ? { details } : {}) } });
      else res.destroy();
      // Never log request bodies, tokens, target fields, or raw exception text.
      if (!known) process.stderr.write(JSON.stringify({ level: 'error', request_id: requestId, code: 'INV-500-INTERNAL' }) + '\n');
    }
  });
  server.requestTimeout = 15000; server.headersTimeout = 10000; server.keepAliveTimeout = 5000; server.maxRequestsPerSocket = 100;
  // Connection-count bound independent of request rate: sockets held open
  // without a completed request line never reach the rate limiter, so an
  // unbounded accept path is a raw fd-exhaustion vector (w22-http F5).
  let openConnections = 0;
  server.on('connection', socket => {
    // The connection cap must not blind the health probes: an over-cap
    // socket keeps answering probes; the request handler kills it on any
    // other request line (w38-http LOW; comment corrected w40-fv F-11).
    if (++openConnections > connectionCap) {
      socket.overCap = true;
      socket.setTimeout(5000, () => socket.destroy());
    }
    socket.on('close', () => openConnections--);
  });

  return { server, sessions, metrics, listen: () => new Promise(resolve => server.listen(port, host, resolve)), close: () => new Promise((resolve, reject) => { server.closeAllConnections(); server.close(e => e ? reject(e) : resolve()); }) };
}
