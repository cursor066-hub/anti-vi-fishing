import http from 'node:http';
import { randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';
import { parseStrict, canonical, hashBytes, digest } from './canonical.mjs';
import { fields, text, identifier, integer } from './schema.mjs';
import { SCHEMAS } from './schema.mjs';
import { requireThat, InvariantError } from './errors.mjs';

export function createServer(fabric, { port = 8080, host = '127.0.0.1', origin = `http://127.0.0.1:${port}` } = {}) {
  requireThat(['127.0.0.1', '::1'].includes(host), 'INV-503-RELEASE', 'Engineering HTTP service must bind to loopback', 503);
  const web = fileURLToPath(new URL('../web/', import.meta.url));
  const sessions = new Map(), rate = new Map();
  const metrics = { requests: 0, errors: 0, unauthorised: 0 };
  function rateLimit(key, max, window = 60000) {
    const now = Date.now();
    if (rate.size > 10000) for (const [k, v] of rate) if (v.reset <= now) rate.delete(k);
    let entry = rate.get(key); if (!entry || entry.reset <= now) { entry = { count: 0, reset: now + window }; rate.set(key, entry); }
    requireThat(++entry.count <= max, 'INV-429-RATE', 'Request rate limit reached', 429);
  }
  function authenticateToken(token) {
    requireThat(typeof token === 'string' && /^[A-Za-z0-9_-]{43}$/.test(token), 'INV-401-AUTH', 'Authentication required', 401);
    const hash = hashBytes(token);
    for (const [tenant, t] of Object.entries(fabric.config.tenants)) {
      const entry = t.auth[hash];
      if (entry && entry.expires_at > fabric.clock()) {
        const principal = { tenant_id: tenant, subject_id: entry.subject_id };
        fabric.authorize(principal, ['operator', 'approver', 'custodian', 'security', 'auditor', 'policy_admin', 'workload']);
        return { principal, expires: entry.expires_at };
      }
    }
    throw new InvariantError('INV-401-AUTH', 'Authentication required', 401);
  }
  function auth(req) {
    const authorization = req.headers.authorization;
    if (authorization) { requireThat(/^Bearer [A-Za-z0-9_-]{43}$/.test(authorization), 'INV-401-AUTH', 'Authentication required', 401); return authenticateToken(authorization.slice(7)).principal; }
    const sid = /(?:^|;\s*)if_session=([A-Za-z0-9_-]{43})(?:;|$)/.exec(req.headers.cookie ?? '')?.[1], session = sid ? sessions.get(hashBytes(sid)) : null;
    requireThat(session && session.expires > fabric.clock(), 'INV-401-AUTH', 'Authentication required', 401);
    if (req.method !== 'GET') requireThat(req.headers['x-csrf-token'] === session.csrf && req.headers.origin === origin, 'INV-403-CSRF', 'Request origin or CSRF token rejected', 403);
    fabric.authorize(session.principal, ['operator', 'approver', 'custodian', 'security', 'auditor', 'policy_admin', 'workload']); return session.principal;
  }
  async function body(req) {
    requireThat(req.headers['content-type']?.split(';')[0] === 'application/json', 'INV-415-CONTENT', 'Use application/json', 415);
    requireThat(!req.headers['content-encoding'], 'INV-415-CONTENT', 'Compressed request bodies are not accepted', 415);
    if (req.headers['content-length']) requireThat(Number(req.headers['content-length']) <= 1048576, 'INV-413-BODY', 'Request body too large', 413);
    let size = 0; const chunks = [];
    for await (const chunk of req) { size += chunk.length; requireThat(size <= 1048576, 'INV-413-BODY', 'Request body too large', 413); chunks.push(chunk); }
    try { return parseStrict(new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks))); } catch (e) { if (e instanceof InvariantError) throw e; throw new InvariantError('INV-400-SCHEMA', 'Invalid UTF-8 or JSON'); }
  }
  const server = http.createServer({ maxHeaderSize: 16384 }, async (req, res) => {
    metrics.requests++; const requestId = randomBytes(12).toString('hex');
    res.setHeader('X-Request-Id', requestId); res.setHeader('X-Content-Type-Options', 'nosniff'); res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('X-Frame-Options', 'DENY'); res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
    res.setHeader('Content-Security-Policy', "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; font-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'");
    res.setHeader('Cache-Control', 'no-store');
    const send = (status, data, type = 'application/json; charset=utf-8') => { res.writeHead(status, { 'Content-Type': type }); res.end(type.startsWith('application/json') ? canonical(data) : data); };
    try {
      requireThat(['GET', 'POST'].includes(req.method), 'INV-405-METHOD', 'Method not allowed', 405);
      requireThat(req.headers.host === new URL(origin).host, 'INV-400-HOST', 'Unrecognised host', 400);
      requireThat(!req.headers.origin || req.headers.origin === origin, 'INV-403-ORIGIN', 'Cross-origin requests are not allowed', 403);
      const url = new URL(req.url, origin), path = url.pathname;
      rateLimit(`ip:${req.socket.remoteAddress}`, 600);
      if (path === '/healthz' && req.method === 'GET') return send(200, { status: 'ok', profile: 'engineering', production_ready: false });
      if (path === '/readyz' && req.method === 'GET') { fabric.store.db.prepare('SELECT 1').get(); return send(200, { status: 'ready', profile: 'engineering', real_targets: false }); }
      const assets = { '/': ['index.html', 'text/html; charset=utf-8'], '/app.js': ['app.js', 'text/javascript; charset=utf-8'], '/style.css': ['style.css', 'text/css; charset=utf-8'] };
      if (req.method === 'GET' && assets[path]) { const [file, type] = assets[path]; return send(200, readFileSync(join(web, file)), type); }
      if (path === '/session' && req.method === 'POST') {
        rateLimit(`login:${req.socket.remoteAddress}`, 20);
        requireThat(req.headers.origin === origin, 'INV-403-ORIGIN', 'Session creation requires same origin', 403);
        const input = await body(req); fields(input, ['token']); const result = authenticateToken(input.token);
        for (const [key, session] of sessions) if (session.expires <= fabric.clock()) sessions.delete(key);
        requireThat(sessions.size < 1000, 'INV-503-CAPACITY', 'Session capacity reached', 503);
        const sid = randomBytes(32).toString('base64url'), csrf = randomBytes(32).toString('base64url');
        sessions.set(hashBytes(sid), { principal: result.principal, csrf, expires: Math.min(fabric.clock() + 900000, result.expires) });
        res.setHeader('Set-Cookie', `if_session=${sid}; HttpOnly; SameSite=Strict; Path=/; Max-Age=900${origin.startsWith('https:') ? '; Secure' : ''}`);
        return send(200, { ...result.principal, csrf_token: csrf, expires_in: 900 });
      }
      const p = auth(req); rateLimit(`subject:${p.tenant_id}:${p.subject_id}`, 300);
      if (path === '/session/logout' && req.method === 'POST') {
        const sid = /(?:^|;\s*)if_session=([A-Za-z0-9_-]{43})(?:;|$)/.exec(req.headers.cookie ?? '')?.[1]; if (sid) sessions.delete(hashBytes(sid));
        res.setHeader('Set-Cookie', 'if_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0'); return send(200, { logged_out: true });
      }
      if (path === '/v1/me' && req.method === 'GET') return send(200, { ...p, roles: fabric.identity(p).roles, device_id: fabric.identity(p).device_id, profile: 'engineering', secure_perception: 'dev-attested-software', perception_components: Object.keys(fabric.perceptionComponents[p.tenant_id] ?? {}) });
      if (path === '/v1/schemas' && req.method === 'GET') return send(200, Object.values(SCHEMAS).map(s => ({ ...s, digest: digest(s) })));
      if (path === '/v1/policy' && req.method === 'GET') { fabric.authorize(p, ['operator', 'approver', 'custodian', 'policy_admin', 'security']); return send(200, fabric.policy(p.tenant_id)); }
      if (path === '/v1/action-capsules' && req.method === 'GET') {
        fabric.authorize(p, ['operator', 'approver', 'custodian', 'security', 'policy_admin']);
        const limit = integer(Number(url.searchParams.get('limit') ?? 50), 'limit', 1, 100), offset = integer(Number(url.searchParams.get('offset') ?? 0), 'offset', 0, 1000000);
        return send(200, { items: fabric.store.list(p.tenant_id, 'capsule', limit, offset), limit, offset });
      }
      if (path === '/v1/action-capsules' && req.method === 'POST') return send(201, fabric.propose(p, await body(req), req.headers['idempotency-key']));
      let m;
      if ((m = /^\/v1\/action-capsules\/([A-Za-z0-9-]+)$/.exec(path)) && req.method === 'GET') return send(200, fabric.getCapsule(p, m[1]));
      if ((m = /^\/v1\/action-capsules\/([A-Za-z0-9-]+)\/approval-challenge$/.exec(path)) && req.method === 'GET') return send(200, fabric.approvalChallenge(p, m[1]));
      if ((m = /^\/v1\/action-capsules\/([A-Za-z0-9-]+)\/(evidence|evaluate|cancel)$/.exec(path)) && req.method === 'POST') {
        const input = await body(req); if (m[2] === 'evidence') return send(201, fabric.attachEvidence(p, m[1], input)); fields(input, []);
        return send(200, m[2] === 'evaluate' ? fabric.evaluate(p, m[1]) : fabric.cancel(p, m[1]));
      }
      if (path === '/v1/approvals' && req.method === 'POST') return send(201, fabric.approve(p, await body(req)));
      if (path === '/v1/certificates' && req.method === 'POST') { const input = await body(req); fields(input, ['capsule_id']); identifier(input.capsule_id); return send(201, fabric.certificate(p, input.capsule_id)); }
      if ((m = /^\/v1\/certificates\/([A-Za-z0-9-]+)$/.exec(path)) && req.method === 'GET') { fabric.authorize(p, ['operator', 'policy_admin', 'security']); return send(200, fabric.store.must(p.tenant_id, 'certificate', m[1]).envelope); }
      if (path === '/gate/v1/execute' && req.method === 'POST') { const input = await body(req); fields(input, ['certificate', 'dry_run']); requireThat(typeof input.dry_run === 'boolean', 'INV-400-SCHEMA', 'dry_run must be boolean'); return send(200, fabric.execute(p, input.certificate, { dryRun: input.dry_run })); }
      if ((m = /^\/gate\/v1\/outcomes\/([A-Za-z0-9-]+)$/.exec(path)) && req.method === 'GET') return send(200, fabric.reconcile(p, m[1]));
      if ((m = /^\/v1\/resources\/([A-Za-z0-9_.:-]+)$/.exec(path)) && req.method === 'GET') { fabric.authorize(p, ['operator', 'policy_admin']); const state = fabric.target.state(p.tenant_id, m[1]); if (Array.isArray(state.material_fields.rows)) throw new InvariantError('INV-403-SCOPE', 'Use a data capability for dataset access', 403); return send(200, state); }
      if (path === '/v1/capabilities' && req.method === 'POST') { fabric.authorize(p, ['operator', 'workload']); return send(201, fabric.runtime.issue(p, await body(req))); }
      if (path === '/gate/v1/runtime' && req.method === 'POST') return send(200, fabric.runtime.consume(p, await body(req)));
      if (path === '/v1/revocations' && req.method === 'POST') return send(201, fabric.revoke(p, await body(req)));
      if (path === '/v1/coverage' && req.method === 'GET') return send(200, fabric.coverage(p));
      if (path === '/v1/coverage' && req.method === 'POST') return send(201, fabric.declareCoverage(p, await body(req)));
      if (path === '/v1/connectors' && req.method === 'GET') return send(200, fabric.target.manifest());
      if (path === '/v1/policies/simulate' && req.method === 'POST') return send(200, fabric.simulate(p, await body(req)));
      if (path === '/v1/audit-exports' && req.method === 'POST') { const input = await body(req); fields(input, ['purpose']); return send(200, fabric.exportAudit(p, input.purpose)); }
      if (path === '/v1/retention/hold' && req.method === 'POST') return send(200, fabric.retention(p, await body(req)));
      if (path === '/v1/retention/sweep' && req.method === 'POST') { fields(await body(req), []); return send(200, fabric.retentionSweep(p)); }
      if (path === '/v1/metrics' && req.method === 'GET') { fabric.authorize(p, ['security']); return send(200, { ...metrics, scope: 'process', analytics_enabled: false }); }
      if (path === '/v1/revocations' && req.method === 'GET') return send(200, fabric.revocations(p));
      if (path === '/v1/grants' && req.method === 'GET') return send(200, fabric.listGrants(p, url.searchParams.get('subject')));
      if (path === '/v1/subjects' && req.method === 'GET') { fabric.authorize(p, ['operator', 'security', 'auditor', 'policy_admin']); return send(200, { items: Object.values(fabric.identities(p.tenant_id)).map(i => ({ subject_id: i.subject_id, roles: i.roles, device_id: i.device_id, identity_class: i.identity_class, health_expires_at: i.health_expires_at })) }); }
      if (path === '/v1/certificates' && req.method === 'GET') { fabric.authorize(p, ['operator', 'security', 'auditor', 'policy_admin']); const limit = integer(Number(url.searchParams.get('limit') ?? 50), 'limit', 1, 200), offset = integer(Number(url.searchParams.get('offset') ?? 0), 'offset', 0, 1000000); return send(200, { items: fabric.store.list(p.tenant_id, 'certificate', limit, offset).map(c => ({ certificate_id: c.certificate_id, status: c.status, stored_at: c.stored_at })), limit, offset }); }
      if (path === '/v1/policy/history' && req.method === 'GET') { fabric.authorize(p, ['operator', 'security', 'auditor', 'policy_admin']); return send(200, { items: fabric.store.list(p.tenant_id, 'policy-history', 100, 0), staged: fabric.store.get(p.tenant_id, 'policy', 'staged') ?? null }); }
      if ((m = /^\/v1\/action-capsules\/([A-Za-z0-9-]+)\/acquire-evidence$/.exec(path)) && req.method === 'POST') { const input = await body(req); fields(input, ['issuer', 'kind', 'claims']); return send(201, await fabric.acquireEvidence(p, m[1], input)); }
      if (path === '/v1/connectors/status' && req.method === 'GET') return send(200, fabric.connectorStatus(p));
      if ((m = /^\/v1\/connectors\/([A-Za-z0-9-]+)\/drift-check$/.exec(path)) && req.method === 'POST') return send(200, await fabric.checkIssuerDrift(p, m[1]));
      if ((m = /^\/v1\/audit\/proofs\/(\d+)$/.exec(path)) && req.method === 'GET') { fabric.authorize(p, ['operator', 'security', 'auditor']); return send(200, fabric.auditProof(p, Number(m[1]))); }
      if (path === '/v1/audit/consistency' && req.method === 'GET') { fabric.authorize(p, ['operator', 'security', 'auditor']); const first = integer(Number(url.searchParams.get('first') ?? 0), 'first', 1, 1e12); return send(200, fabric.auditConsistency(p, first)); }
      if (path === '/v1/audit/verify-proof' && req.method === 'POST') { const i = await body(req); fields(i, ['proof']); return send(200, { valid: fabric.verifyAuditProof(p.tenant_id, i.proof) }); }
      if (path === '/v1/ceremonies' && req.method === 'GET') { fabric.authorize(p, ['security', 'custodian', 'policy_admin']); return send(200, { items: fabric.store.list(p.tenant_id, 'ceremony', 100, 0).map(c => ({ ceremony_id: c.ceremony_id, status: c.status, purpose: c.purpose })) }); }
      if (path === '/v1/ceremonies' && req.method === 'POST') return send(201, fabric.createCeremony(p, await body(req)));
      if ((m = /^\/v1\/ceremonies\/([A-Za-z0-9_.:-]+)\/(acknowledge|split|reconstruct)$/.exec(path)) && req.method === 'POST') {
        const input = await body(req);
        if (m[2] === 'acknowledge') return send(200, fabric.acknowledgeCeremony(p, input));
        if (m[2] === 'split') { fields(input, ['secret']); return send(200, fabric.splitCeremonySecret(p, m[1], input.secret)); }
        fields(input, ['shares']); return send(200, fabric.reconstructCeremony(p, m[1], input.shares));
      }
      if (path === '/v1/keys' && req.method === 'GET') { fabric.authorize(p, ['security', 'policy_admin']); return send(200, { keys: fabric.vault.list().map(({ wrapped, ...k }) => k), firmware: fabric.vault.firmware }); }
      if (path === '/v1/keys/rotate-prepare' && req.method === 'POST') { const input = await body(req); fields(input, ['key_class']); return send(201, fabric.prepareRotation(p, input.key_class)); }
      if ((m = /^\/v1\/keys\/([A-Za-z0-9_.:-]+)\/attest$/.exec(path)) && req.method === 'GET') { fabric.authorize(p, ['security', 'auditor']); return send(200, fabric.vault.attest(m[1])); }
      if (path === '/v1/secure-perception/sessions' && req.method === 'POST') { const input = await body(req); fields(input, ['attestation']); return send(201, fabric.perceptionSession(p, input.attestation)); }
      if (path === '/v1/secure-perception/release' && req.method === 'POST') { const input = await body(req); fields(input, ['session_id', 'fields', 'purpose'], ['capsule_id', 'evidence_ref']); const { session_id, ...release } = input; return send(200, fabric.perceptionRelease(p, session_id, release)); }
      if (path === '/v1/secure-perception/fallback' && req.method === 'POST') return send(200, fabric.perceptionFallback(p, await body(req)));
      if (path === '/v1/advisory' && req.method === 'POST') return send(200, fabric.advise(p, await body(req)));
      throw new InvariantError('INV-404-NOT-FOUND', 'Resource not found', 404);
    } catch (e) {
      metrics.errors++; if (e.status === 401) metrics.unauthorised++;
      const known = e instanceof InvariantError;
      if (!res.headersSent) send(known ? e.status : 500, { error: { code: known ? e.code : 'INV-500-INTERNAL', message: known ? e.message : 'Internal failure; contact the operator with the request id', request_id: requestId } });
      else res.destroy();
      // Never log request bodies, tokens, target fields, or raw exception text.
      if (!known) process.stderr.write(JSON.stringify({ level: 'error', request_id: requestId, code: 'INV-500-INTERNAL' }) + '\n');
    }
  });
  server.requestTimeout = 15000; server.headersTimeout = 10000; server.keepAliveTimeout = 5000; server.maxRequestsPerSocket = 100;
  return { server, sessions, metrics, listen: () => new Promise(resolve => server.listen(port, host, resolve)), close: () => new Promise((resolve, reject) => { server.closeAllConnections(); server.close(e => e ? reject(e) : resolve()); }) };
}
