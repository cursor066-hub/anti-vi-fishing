#!/usr/bin/env node
import http from 'node:http';
import { readFileSync, writeFileSync, mkdirSync, readdirSync, statSync, lstatSync, openSync, closeSync, writeSync, fstatSync, rmSync, constants as fsConstants } from 'node:fs';
import { join, resolve } from 'node:path';
import { randomUUID, randomBytes, timingSafeEqual, createHmac, createPrivateKey, createPublicKey } from 'node:crypto';
import { canonical, digest, hashBytes, parseStrict } from './canonical.mjs';
import { signed, verifySigned, ctEqual } from './crypto.mjs';
import { fields, text, identifier, integer, uniqueStrings } from './schema.mjs';
import { requireThat, InvariantError } from './errors.mjs';
import { ISSUER_MANIFEST_PERMISSIONS, ISSUER_MANIFEST_LIMITATIONS, ISSUER_MANIFEST_IDEMPOTENCY, ISSUER_MANIFEST_COVERAGE } from './connectors.mjs';

// IF-ISSUER-1: an independent evidence issuer service. Each issuer is a
// separate trust-domain process holding its own signing key and record store.
// It answers structured evidence queries with signed evidence envelopes —
// never raw authority. Records live in <name>.issuer.json; every issuance is
// appended to a hash-chained JSONL log for provenance audit (EVD-010).

export function loadIssuers(directory) {
  // Null-prototype registry: issuer names like 'constructor' must not resolve
  // via Object.prototype (issuerd-audit LOW-4).
  const issuers = Object.create(null);
  const parsed = [];
  // Directory custody: a group/world-WRITABLE issuer dir lets any local
  // principal plant a spec (or a FIFO that hangs the boot — w21-issuerd
  // F3/F4), so the directory itself is checked before its contents.
  const dstat = statSync(directory);
  requireThat((dstat.mode & 0o022) === 0, 'INV-503-CONFIG', 'Issuer directory must not be writable by group or other users', 503);
  for (const file of readdirSync(directory)) {
    if (!file.endsWith('.issuer.json')) continue;
    const specPath = join(directory, file);
    // lstat — never stat-through: a symlinked spec (or FIFO/device) must
    // not be served just because its target carries good mode bits
    // (w21-issuerd F3/F4).
    const st = lstatSync(specPath);
    requireThat(!st.isSymbolicLink() && st.isFile(), 'INV-503-CONFIG', `Issuer file ${file} must be a regular file, not a link or special file`, 503);
    // These files carry private signing keys — group/world-readable specs
    // refuse to serve, matching the `sign` and `serve` custody bars
    // (w8-tooling F8).
    requireThat((st.mode & 0o077) === 0, 'INV-503-CONFIG', `Issuer file ${file} must not be readable by group or other users`, 503);
    // Ownership: a spec another non-root uid can rewrite is not custody —
    // root-provisioned files pass because only root can touch them
    // (w21-issuerd F4).
    if (process.getuid) requireThat(st.uid === process.getuid() || st.uid === 0, 'INV-503-CONFIG', `Issuer file ${file} must be owned by the daemon user or root`, 503);
    // Specs parse through the strict grammar too — duplicate keys, floats
    // and oversize strings must fail at load, not inside canonical() at
    // serve time (w9-deploy F10).
    const spec = parseStrict(readFileSync(join(directory, file), 'utf8'));
    fields(spec, ['issuer', 'key', 'channel', 'kinds', 'records', 'version'], ['tenant', 'issue_token', 'read_token', 'token_expires_at', 'issue_token_digest', 'read_token_digest']);
    identifier(spec.issuer); text(spec.version, 'issuer version', 32);
    // Presence is not shape: null kinds/records, a keyless signing spec or a
    // string token_expires_at would otherwise load and then crash (or never
    // expire) per-request instead of failing the boot (w9-schema F-5).
    requireThat(spec.kinds && typeof spec.kinds === 'object' && !Array.isArray(spec.kinds), 'INV-400-SCHEMA', 'Issuer kinds must be an object');
    requireThat(spec.records && typeof spec.records === 'object' && !Array.isArray(spec.records), 'INV-400-SCHEMA', 'Issuer records must be an object');
    requireThat(spec.key && typeof spec.key.key_id === 'string' && typeof spec.key.public_key === 'string' && typeof spec.key.private_key === 'string', 'INV-400-SCHEMA', 'Issuer key must carry key_id, public_key and private_key');
    // The declared keypair must actually be a keypair: the private half
    // parses and derives the advertised public half, same consistency bar
    // the vault applies per entry (w11-fixverify R3).
    const derivedPublic = (() => { try { return createPublicKey(createPrivateKey(spec.key.private_key)).export({ type: 'spki', format: 'pem' }).trim(); } catch { return null; } })();
    requireThat(derivedPublic !== null && derivedPublic === spec.key.public_key.trim(), 'INV-400-SCHEMA', 'Issuer key public/private material is inconsistent');
    for (const [kind, rule] of Object.entries(spec.kinds)) {
      identifier(kind, 'kind'); requireThat(rule && typeof rule === 'object' && !Array.isArray(rule), 'INV-400-SCHEMA', `Kind rule ${kind} must be an object`);
      // Semantics, not only shape (w18-issuerd F-6): a string ttl_ms would
      // mint dead string-dated envelopes, an object-valued expect would
      // crash every request, and a non-string extract would sign nonsense.
      // lookup and confidence are read unconditionally when serving the
      // kind — a rule missing either crashes every request with TypeError
      // instead of failing the boot (w20-fixverify F-13), so they are
      // required here, not optional.
      requireThat(typeof rule.lookup === 'string' && rule.lookup.length > 0, 'INV-400-SCHEMA', `Kind rule ${kind} lookup must be a non-empty string`);
      // ttl_ms joins `now` arithmetic at sign time — a safe-integer near
      // MAX would overflow expires_at/retention_until and 400 every
      // request forever; 30 days is the declared ceiling (w21-issuerd F9).
      requireThat(rule.ttl_ms === undefined || (Number.isSafeInteger(rule.ttl_ms) && rule.ttl_ms > 0 && rule.ttl_ms <= 2592000000), 'INV-400-SCHEMA', `Kind rule ${kind} ttl_ms must be an integer 1..2592000000`);
      // extract names land as object keys of the signed `claims` map — a
      // name the canonical encoder cannot express (proto keys, exotic
      // charset) must fail at boot, not inside signed() per request
      // (w21-issuerd F9).
      const nameOk = f => { try { canonical({ [f]: 0 }); return true; } catch { return false; } };
      requireThat(rule.extract === undefined || (Array.isArray(rule.extract) && rule.extract.every(f => typeof f === 'string' && nameOk(f))), 'INV-400-SCHEMA', `Kind rule ${kind} extract must be an array of canonical field names`);
      requireThat(rule.expect === undefined || (rule.expect && typeof rule.expect === 'object' && !Array.isArray(rule.expect) && Object.keys(rule.expect).every(nameOk) && Object.values(rule.expect).every(v => v === null || typeof v !== 'object')), 'INV-400-SCHEMA', `Kind rule ${kind} expect keys must be canonical names with scalar values`);
      requireThat(Number.isSafeInteger(rule.confidence) && rule.confidence >= 0 && rule.confidence <= 100, 'INV-400-SCHEMA', `Kind rule ${kind} confidence must be an integer 0..100`);
      // advisory is signed verbatim — a string 'false' would sign
      // Boolean('false') === true into the envelope (w21-issuerd F9).
      requireThat(rule.advisory === undefined || typeof rule.advisory === 'boolean', 'INV-400-SCHEMA', `Kind rule ${kind} advisory must be a boolean`);
    }
    if (spec.token_expires_at !== undefined) requireThat(Number.isSafeInteger(spec.token_expires_at), 'INV-400-SCHEMA', 'token_expires_at must be an integer epoch-ms');
    // A malformed *_token_digest must fail at boot: bearerMatches compares
    // fixed-length digests and timingSafeEqual throws RangeError on any
    // length mismatch — one bad spec would otherwise 500 every authed
    // request, daemon-wide, via the anyBearer sweep (w10-fixverify F-3).
    for (const f of ['issue_token_digest', 'read_token_digest'])
      if (spec[f] !== undefined) requireThat(typeof spec[f] === 'string' && /^[a-f0-9]{64}$/.test(spec[f]), 'INV-400-SCHEMA', `${f} must be a sha256 hex digest`);
    // A plaintext token and a digest credential for the same scope cannot
    // coexist: the digest silently wins (bearerDigest prefers stored
    // digests), so the operator who sets both believes in a credential
    // that never authenticates — refuse the dead config at boot
    // (w21-issuerd F12).
    requireThat(!(spec.issue_token !== undefined && spec.issue_token_digest !== undefined), 'INV-400-SCHEMA', 'issue_token is dead when issue_token_digest is set — pick one custody form');
    requireThat(!(spec.read_token !== undefined && (spec.read_token_digest !== undefined || spec.issue_token_digest !== undefined)), 'INV-400-SCHEMA', 'read_token is dead when a digest credential shadows it — pick one custody form');
    // Tenant names use the strict tenant charset — ':' inside a tenant or
    // issuer name would collide with the '<tenant>:<issuer>' key form.
    if (spec.tenant !== undefined) requireThat(/^[a-z][a-z0-9-]{1,31}$/.test(spec.tenant), 'INV-400-SCHEMA', 'Issuer tenant must use the tenant charset');
    // The issuer name becomes a route path segment — a name the route
    // regex cannot express ('.', ':', '/') loads but is unreachable:
    // refuse it at boot instead of shipping a dead issuer (w21-issuerd F8).
    requireThat(/^[A-Za-z0-9_-]+$/.test(spec.issuer), 'INV-400-SCHEMA', 'Issuer name must use the route charset [A-Za-z0-9_-]');
    requireThat(['authoritative', 'communication', 'device', 'counterparty'].includes(spec.channel), 'INV-400-SCHEMA', 'Unsupported issuer channel');
    parsed.push(spec);
  }
  // Registry key: '<tenant>:<issuer>' when the spec carries a tenant, so
  // two tenants can run same-named issuers with independent keys/records.
  // Registration is two-pass — every spec keys first, then bare aliases are
  // decided by the WHOLE set — so readdir order can never pick between a
  // silent shadow and a boot refusal (w18-issuerd F-7).
  for (const spec of parsed) {
    const key = spec.tenant ? `${spec.tenant}:${spec.issuer}` : spec.issuer;
    requireThat(!Object.hasOwn(issuers, key), 'INV-409-CONFLICT', `Duplicate issuer ${key}`, 409);
    issuers[key] = spec;
  }
  const bareClaims = new Map();
  for (const spec of parsed) { const s = bareClaims.get(spec.issuer) ?? new Set(); s.add(spec); bareClaims.set(spec.issuer, s); }
  for (const [name, claimants] of bareClaims) {
    if (claimants.size > 1) {
      // A bare name plus a scoped claim can never resolve deterministically
      // — refuse the ambiguous registry outright instead of shadowing the
      // untenanted issuer by file order.
      requireThat(![...claimants].some(c => !c.tenant), 'INV-409-CONFLICT', `Issuer name ${name} is claimed by both a bare and a tenant-scoped spec`, 409);
      issuers[name] = { ambiguous: true };
    } else if (!Object.hasOwn(issuers, name)) issuers[name] = [...claimants][0];
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
  // The fabric's evidence verifier caps dependencies at 32 — a signed
  // envelope beyond that ceiling could never attach anywhere, so refuse
  // to mint it rather than sign an unusable artifact (w25-issuerd LOW).
  // Same shape contract the fabric's evidence verifier enforces
  // (uniqueStrings: ≤32 unique strings of ≤128 chars each) — a signed
  // envelope outside that grammar could never attach anywhere, so it must
  // never be minted (w30-issuerd F7).
  requireThat(request.dependencies === undefined || (Array.isArray(request.dependencies) && request.dependencies.length <= 32 && request.dependencies.every(d => typeof d === 'string' && d.length <= 128) && new Set(request.dependencies).size === request.dependencies.length), 'INV-400-SCHEMA', 'dependencies must be an array of at most 32 unique strings of at most 128 characters');
  const key = interpolate(rule.lookup, request.claims ?? {});
  const record = Object.hasOwn(issuer.records, key) ? issuer.records[key] : null;
  const evidence_id = randomUUID();
  const base = {
    evidence_id, tenant_id: request.tenant_id, capsule_digest: request.capsule_digest, kind: request.kind,
    acquired_at: now, expires_at: now + (rule.ttl_ms ?? 300000), confidence: rule.confidence,
    advisory: issuer.channel === 'communication' ? true : Boolean(rule.advisory), dependencies: request.dependencies ?? [],
    retention_until: now + (rule.ttl_ms ?? 300000) + 86400000
  };
  // The provenance string is uniform for hit and miss alike — a signed
  // 'UNSATISFIED' vs '*' distinction would make the envelope itself an
  // authenticated record-existence oracle (w18-issuerd F-3).
  // The provenance segment is issuer-keyed material too — echoing the
  // caller's lookup text into a signed field would reflect whatever
  // string the requester chose to embed (w21-issuerd F15).
  const prov = `issuer:${issuer.issuer}@${issuer.version} record:${contentMac(issuer, { lookup_segment: key.split(':')[0] }).slice(0, 24)}:lookup transformation:direct`;
  if (!record) {
    // A missing record is a signed `conflict`, not an exception — the response
    // shape is identical to a claim mismatch, so /issue cannot be used to
    // enumerate the record store by guessing lookup keys (issuerd-audit MED-5).
    return signed({ ...base, claim: 'conflict', content_digest: contentMac(issuer, { issuer: issuer.issuer, key, record: null }), claims: {}, provenance: prov, issuer_version: issuer.version }, issuer.key, 'evidence');
  }
  let claim = 'supports';
  const extracted = {};
  // Objects compare by canonical form — String() on a null-prototype record
  // value would throw TypeError per-request instead of answering 'conflict'
  // (w18-issuerd F-6).
  const scalar = v => v === null || typeof v !== 'object' ? String(v) : canonical(v);
  for (const [field, expected] of Object.entries(rule.expect ?? {})) {
    const want = typeof expected === 'string' && expected.includes('${') ? interpolate(expected, request.claims ?? {}) : expected;
    extracted[field] = record[field] ?? null;
    const got = record[field];
    // Digest-vs-digest equality — early-exit string compare would leak
    // match depth on credential-shaped fields (w15-timing F5).
    if (!ctEqual(digest(scalar(got)), digest(scalar(want)))) claim = 'conflict';
  }
  for (const f of rule.extract ?? []) {
    extracted[f] = record[f] ?? null;
    void ctEqual(digest(scalar(record[f])), digest(scalar(request.claims?.[f])));
  }
  // A conflict answer reveals nothing: echoing even the correctly-guessed
  // fields is a per-field value-confirmation oracle (w5 F-7).
  // A `supports` answer echoes the caller's own query claims plus the
  // subject_id the record itself carries — NOT the independently supplied
  // request.subject_id, which would let the caller stamp any subject onto a
  // record that matched someone else (w5 F-1). The fabric binds
  // claims.subject_id to the capsule's actor, so the lie must be impossible
  // below the signature.
  // The contract above is literal: request.subject_id (the route-required
  // query parameter) is caller input and must never be echoed under the
  // signature — only the record's own subject or a claim the caller
  // supplied inside the claim block counts (w9-schema F-3).
  // Only fields the issuer verified may appear under the signature: expect/
  // extract fields, the resolved subject, and claims bound into the lookup
  // template — a 'supports' answer proves that exact identifier resolved to
  // a real record. Arbitrary caller claims are never echoed (w6-tenancy F7).
  const lookupBound = {};
  // The extraction charset must equal interpolate()'s exactly: a broader
  // match echoes claims the lookup never bound, a narrower one silently
  // drops nested paths (w6-fix F7).
  if (claim === 'supports') for (const m of rule.lookup.matchAll(/\$\{claims\.([a-z0-9_.]+)\}/g)) { const v = m[1].split('.').reduce((o, k) => o?.[k], request.claims ?? {}); if (v !== undefined) lookupBound[m[1]] = v; }
  // subject_id may only be echoed when the issuer actually verified it —
  // the record's own field, a caller claim the lookup template bound, or a
  // caller claim an expect rule checked against the record (a mismatch there
  // already produced 'conflict'). An unbound claims.subject_id is caller
  // input, not a verified identity (w11-fixverify R1).
  const expectBoundSubject = Object.values(rule.expect ?? {}).some(v => typeof v === 'string' && v.includes('${claims.subject_id}'));
  const resolvedSubject = record.subject_id ?? (Object.hasOwn(lookupBound, 'subject_id') || expectBoundSubject ? request.claims?.subject_id : undefined);
  const revealed = claim === 'conflict' ? {} : { ...lookupBound, ...extracted, ...(resolvedSubject === undefined ? {} : { subject_id: resolvedSubject }) };
  return signed({ ...base, claim, content_digest: contentMac(issuer, { issuer: issuer.issuer, key, record }), claims: revealed, provenance: prov, issuer_version: issuer.version }, issuer.key, 'evidence');
}

// Evidence content bindings are keyed under the issuer's own private key —
// a bare sha256 over the record is an offline dictionary oracle for
// low-entropy rows held by every envelope reader (w15-timing F11). The
// 64-hex shape is preserved for schema compatibility; recomputation now
// needs the issuer's private material — the same custody the signature
// already asserts.
const contentMac = (issuer, obj) => createHmac('sha256', issuer.key.private_key).update(canonical(obj)).digest('hex');

export function createIssuerServer(issuers, { port = 8090, host = '127.0.0.1', clock = Date.now, logPath, allow_insecure_loopback = false, log_max_bytes = 67108864 } = {}) {
  // Bind-time honesty: configuration states that make parts of the
  // registry unreachable are warned once on stderr instead of leaking
  // through per-request refusal codes (w21-issuerd F10/F11).
  {
    const credentialled = i => i.issuer && !i.ambiguous && (i.issue_token || i.read_token || i.issue_token_digest || i.read_token_digest);
    const real = Object.values(issuers).filter(i => i.issuer && !i.ambiguous);
    const tokenless = real.filter(i => !credentialled(i));
    if (!real.some(credentialled) && !allow_insecure_loopback)
      process.stderr.write('issuerd: no bearer credentials configured — all endpoints refuse with uniform 401 until a token is provisioned or allow_insecure_loopback is set\n');
    else if (tokenless.length)
      process.stderr.write(`issuerd: tokenless issuers unreachable in a tokened registry: ${[...new Set(tokenless.map(i => i.issuer))].join(', ')}\n`);
  }
  // Two daemons must never share one issuance log — a failover pair on one
  // directory forks the chain (duplicate sequence numbers under divergent
  // digests) and permanently wedges the next boot. Hold an exclusive
  // create-or-fail lock beside the log for the server's whole lifetime,
  // acquired BEFORE the chain key is read or minted (w30-issuerd F1).
  // A stale lock left by a crashed daemon is reclaimed only when its
  // recorded pid is provably dead; an unreadable or live pid refuses
  // honestly. Residual: pid reuse can stale-lock the log — the operator
  // clears the file after confirming no live daemon (documented in the
  // runbook), never silently.
  let lockFd = null;
  const logLockPath = logPath ? `${logPath}.lock` : null;
  if (logLockPath) {
    mkdirSync(resolve(logPath, '..'), { recursive: true });
    for (let attempt = 0; attempt < 2 && lockFd === null; attempt++) {
      try { lockFd = openSync(logLockPath, fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_WRONLY, 0o600); writeSync(lockFd, `${process.pid} ${clock()}
`); }
      catch (e) {
        if (e.code !== 'EEXIST') throw e;
        let holder = null; try { holder = readFileSync(logLockPath, 'utf8').trim().split(' ')[0]; } catch { holder = null; }
        const pid = Number(holder);
        let alive = false;
        if (Number.isSafeInteger(pid) && pid > 0) { try { process.kill(pid, 0); alive = true; } catch (err) { alive = err.code === 'EPERM'; } }
        requireThat(!alive, 'INV-503-CONFIG', 'Issuance log lock is held by a live daemon — a second issuerd on one directory would fork the chain', 503);
        rmSync(logLockPath);
      }
    }
    requireThat(lockFd !== null, 'INV-503-CONFIG', 'Issuance log lock could not be acquired', 503);
  }
  const sequence = { n: 0, previous: '0'.repeat(64) };
  // request_digest in the chained log gets the same keyed treatment —
  // request bodies can carry claim/credential material an offline log
  // holder could dictionary (w15-timing F11). The chain key is a
  // DEDICATED secret beside the log (`<log>.key`, 0600, minted on first
  // boot): deriving it from the live issuer set would make every routine
  // issuer add/remove/rotation invalidate the chain and permanently
  // refuse boot (w21-issuerd F1). Losing the key file is honest data
  // loss — the old log refuses rather than re-genesising silently.
  // Any boot failure AFTER the lock is taken must release it — a refused
  // boot that leaked the lockfile would falsely report a live daemon on
  // the operator's retry (w30-issuerd F1).
  const releaseLock = () => { if (lockFd !== null) { try { closeSync(lockFd); } catch { /* already closed */ } lockFd = null; try { rmSync(logLockPath); } catch { /* already gone */ } } };
  let logKey = '0'.repeat(64), logMac = null;
  try {
  logKey = (() => {
    if (!logPath) return '0'.repeat(64);
    mkdirSync(resolve(logPath, '..'), { recursive: true });
    const keyPath = `${logPath}.key`;
    let ks = null;
    try { ks = lstatSync(keyPath); } catch (e) { if (e.code !== 'ENOENT') throw e; }
    if (ks) {
      requireThat(!ks.isSymbolicLink() && ks.isFile(), 'INV-503-CONFIG', 'Issuance log key must be a regular file', 503);
      requireThat((ks.mode & 0o077) === 0, 'INV-503-CONFIG', 'Issuance log key must not be readable by group or other users', 503);
      const k = readFileSync(keyPath, 'utf8').trim();
      requireThat(/^[a-f0-9]{64}$/.test(k), 'INV-503-CONFIG', 'Issuance log key is not a 64-hex secret', 503);
      return k;
    }
    const k = randomBytes(32).toString('hex');
    writeFileSync(keyPath, k + '\n', { mode: 0o600 });
    return k;
  })();
  logMac = v => createHmac('sha256', logKey).update(canonical(v)).digest('hex');
  // Continue the hash chain across restarts: seed sequence/previous from the
  // last logged record so truncation of earlier entries stays detectable
  // (issuerd-audit LOW-3). The read goes through O_NOFOLLOW + fstat, so a
  // dangling symlink cannot redirect the open and a FIFO/device cannot
  // hang the boot on an empty read (w21-issuerd F3).
  if (logPath) {
    let fd = null;
    // O_NONBLOCK keeps a FIFO/socket node at logPath from hanging the
    // open itself; fstat below then refuses it as non-regular.
    try { fd = openSync(logPath, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW | fsConstants.O_NONBLOCK); }
    catch (e) {
      if (e.code !== 'ENOENT') { if (e instanceof InvariantError) throw e; throw new InvariantError('INV-503-CONFIG', 'Issuance log path is not openable as a regular file', 503); }
    }
    if (fd !== null) {
      let lines;
      try {
        const fst = fstatSync(fd);
        requireThat(fst.isFile(), 'INV-503-CONFIG', 'Issuance log path must be a regular file', 503);
        // Same custody bar as the key and specs — a group-readable log
        // leaks issuance metadata (w22-fixverify F10).
        requireThat((fst.mode & 0o077) === 0, 'INV-503-CONFIG', 'Issuance log must not be readable by group or other users', 503);
        // Strict line discipline: an interior blank line is tamper
        // evidence, not formatting (w22-fixverify F13).
        const raw = readFileSync(fd, 'utf8');
        lines = raw.trim() === '' ? [] : raw.trim().split('\n');
      }
      finally { closeSync(fd); }
      // Boot verifies the WHOLE chain, not just the tail: every line must
      // parse, sequence must be contiguous, the hash link must hold, and
      // the keyed HMAC must verify. An unparseable or edited line —
      // including a mid-write-truncated tail — refuses boot rather than
      // silently orphaning the prior segment under a fresh genesis
      // (w20-fixverify F-7/F-8). Residuals: a file truncated to a VALID
      // prefix cannot be detected, and neither can a wholesale replace —
      // the chain key lives beside the log, so a directory-owning writer
      // who swaps both files forges the whole history under a
      // self-consistent key (w22-fixverify F3). Deriving the key from
      // issuer spec material was rejected: routine issuer add/remove or
      // rotation would invalidate the chain permanently (w21-issuerd F1).
      // The honest bound is operational: the log has no external anchor —
      // ship it off-box (SIEM/filebeat) so an external copy attests the
      // head, and treat the dir's custody bits as the control.
      let previous = '0'.repeat(64), last = null;
      for (const [i, line] of lines.entries()) {
        let rec = null;
        try { rec = JSON.parse(line); } catch { throw new InvariantError('INV-503-CONFIG', `Issuance log line ${i + 1} is unparseable; refuse to re-genesis silently`, 503); }
        requireThat(rec && Number.isSafeInteger(rec.sequence) && rec.sequence === i + 1 && rec.previous === previous && /^[a-f0-9]{64}$/.test(rec.digest ?? ''), 'INV-503-CONFIG', `Issuance log line ${i + 1} breaks the hash chain; refuse to re-genesis silently`, 503);
        const { digest: d, ...rest } = rec;
        requireThat(ctEqual(logMac(rest), d), 'INV-503-CONFIG', `Issuance log line ${i + 1} fails its keyed HMAC; refuse to re-genesis silently`, 503);
        previous = d; last = rec;
      }
      if (!last) {
        // An empty log under a live head watermark is truncation-to-zero —
        // the watermarked history vanished, which is tamper evidence rather
        // than a fresh segment; re-genesis would silently orphan it
        // (w30-issuerd F3). A first-boot log carries no watermark at all.
        let headRec = null;
        try { headRec = JSON.parse(readFileSync(`${logPath}.head`, 'utf8')); } catch { headRec = null; }
        requireThat(!headRec || headRec.format !== 'ISSUER-LOG-HEAD-1' || !(headRec.sequence > 0), 'INV-503-CONFIG', 'Issuance log vanished under a live head watermark — refuse to re-genesis silently', 503);
      }
      if (last) {
        // Head watermark parity with the fabric's chain-heads.json: the
        // companion file pins the last committed sequence+MAC outside the
        // log, so truncating the log to a VALID prefix still diverges at
        // boot (w25-issuerd residual). The head MAC is keyed over the
        // CLAIMED tail — copying a stored digest into .head cannot
        // re-anchor a truncated prefix (w25-issuerd F-3). A missing head
        // on a non-empty verified chain is indistinguishable from a
        // deleted-watermark truncation, so it refuses too; legacy
        // pre-watermark logs re-anchor via the runbook (delete the file
        // after archiving), never silently (w25-issuerd F-2).
        const headPath = logPath + '.head';
        let headRec = null;
        try { headRec = JSON.parse(readFileSync(headPath, 'utf8')); } catch { headRec = null; }
        const headMac = (sequence, digest) => logMac({ format: 'ISSUER-LOG-HEAD-1', sequence, digest });
        requireThat(headRec !== null, 'INV-503-CONFIG', 'Issuance log head watermark is absent over a non-empty log — the file was deleted or the log predates the watermark; archive and re-anchor per runbook', 503);
        requireThat(headRec.format === 'ISSUER-LOG-HEAD-1' && Number.isSafeInteger(headRec.sequence) && headRec.sequence === last.sequence && ctEqual(headRec.mac ?? '', headMac(last.sequence, last.digest)), 'INV-503-CONFIG', 'Issuance log head watermark diverges from the log tail — the log was truncated or replaced', 503);
        sequence.n = last.sequence; sequence.previous = last.digest;
      }
    }
  }
  } catch (e) { releaseLock(); throw e; }
  // The log never rotates on its own: a size ceiling refuses the NEXT
  // logged event instead of letting boot-verification cost and residency
  // grow without bound — the operator archives + moves the file and the
  // next boot genesises a fresh segment (w21-issuerd F5).
  const LOG_MAX_BYTES = log_max_bytes;
  function issuanceLog(entry) {
    if (!logPath) return;
    // Server fields own the record — a caller-supplied 'digest' must not
    // ride into the MAC input or the written line refuses boot forever
    // (w22-fixverify F11).
    const { digest: _ignored, ...rest } = entry;
    const record = { ...rest, sequence: sequence.n + 1, previous: sequence.previous, time: clock() };
    // The chain itself is keyed — an unkeyed sha256 tail can be recomputed
    // after selective deletion; HMAC under the dedicated key makes a
    // rewritten history diverge at the next append (w18-issuerd F-9).
    const next = logMac(record);
    mkdirSync(resolve(logPath, '..'), { recursive: true });
    // The head watermark is written BEFORE the line lands: a crashed append
    // leaves head-ahead-of-tail (boot refuses honestly) rather than
    // tail-ahead-of-head (a silent truncation window) (w25-issuerd). The
    // MAC is keyed over the claimed tail, so a file-editor cannot
    // re-anchor a truncated prefix by copying a stored digest (w25-issuerd
    // F-3).
    // O_NOFOLLOW + fstat binds the append to the inode: a dangling
    // symlink planted between checks gets ELOOP, and a FIFO/socket at
    // logPath fails isFile instead of blocking or absorbing writes
    // (w21-issuerd F3).
    const afd = openSync(logPath, fsConstants.O_APPEND | fsConstants.O_CREAT | fsConstants.O_WRONLY | fsConstants.O_NOFOLLOW | fsConstants.O_NONBLOCK, 0o600);
    try {
      const st = fstatSync(afd);
      requireThat(st.isFile(), 'INV-503-CONFIG', 'Issuance log path must be a regular file', 503);
      requireThat((st.mode & 0o077) === 0, 'INV-503-CONFIG', 'Issuance log must not be readable by group or other users', 503);
      // The capacity check precedes the watermark write: a routine cap
      // refusal must never mint head-ahead-of-tail state — the next boot
      // would read that as truncation tamper and refuse to start
      // (w30-issuerd F2).
      requireThat(st.size < LOG_MAX_BYTES, 'INV-503-CONFIG', 'Issuance log exceeds the 64 MiB custody cap — archive and rotate it', 503);
      // The head watermark is written BEFORE the line lands: a crashed
      // append leaves head-ahead-of-tail (boot refuses honestly) rather
      // than tail-ahead-of-head (a silent truncation window) (w25-issuerd).
      // The MAC is keyed over the claimed tail, so a file-editor cannot
      // re-anchor a truncated prefix by copying a stored digest
      // (w25-issuerd F-3).
      writeFileSync(logPath + '.head', canonical({ format: 'ISSUER-LOG-HEAD-1', sequence: record.sequence, mac: logMac({ format: 'ISSUER-LOG-HEAD-1', sequence: record.sequence, digest: next }) }) + '\n', { mode: 0o600 });
      writeSync(afd, canonical({ ...record, digest: next }) + '\n');
    } finally { closeSync(afd); }
    // Chain state commits only once the bytes are durable: a failed
    // append must never burn a phantom sequence the next boot cannot
    // find on disk (w21-issuerd F2).
    sequence.n = record.sequence; sequence.previous = next;
  }
  for (const i of Object.values(issuers)) i.metrics ??= { requests: 0, errors: 0, issued: 0, refused: 0, latencies: [] };
  // Per-IP token buckets are per-server-instance — a static map shared
  // across createIssuerServer calls leaks budgets between daemons and
  // couples unrelated tests (w9-deploy F10).
  const buckets = new Map();
  const server = http.createServer(async (req, res) => {
    res.setHeader('X-Content-Type-Options', 'nosniff'); res.setHeader('Cache-Control', 'no-store');
    // Same response-header bar as the main server — issuer responses are
    // JSON only and must never be embedded cross-origin (w18-http F-4).
    res.setHeader('Referrer-Policy', 'no-referrer'); res.setHeader('Content-Security-Policy', "default-src 'none'");
    res.setHeader('Cross-Origin-Resource-Policy', 'same-origin'); res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
    // Serialize before any byte is flushed: a canonical() failure must land
    // in the catch cleanly, never mid-response after writeHead (w9-deploy F1).
    const send = (status, data) => { const bodyOut = canonical(data); res.writeHead(status, { 'Content-Type': 'application/json' }); res.end(bodyOut); };
    // IPv4-mapped IPv6 forms share one bucket with their dotted twin — a
    // dual-stack bind must not give a client two budgets (w21-issuerd F13).
    // The bucket key must be as stable as the authority it limits: on a
    // loopback bind every 127/8 source is one client process choosing its
    // source address, and on remote binds an IPv6 peer rotates freely
    // inside its /64 — both collapse to one bucket identity
    // (w30-issuerd F6).
    const bindLoopback = ['127.0.0.1', '::1'].includes(host);
    const rawIp = (req.socket.remoteAddress ?? 'unknown').replace(/^::ffff:/, '');
    const ip = bindLoopback ? '127.0.0.1' : (rawIp.includes(':') ? `${rawIp.split(':').slice(0, 4).join(':')}::/64` : rawIp);
    // The coarse gate is keyed on the PRESENTED credential when it matches
    // a configured bearer: a loopback flood holding one token spends its own
    // budget and can never starve the fabric's drift checks riding a
    // different credential from the same address (w25-issuerd F3).
    // Unauthenticated traffic keeps the shared per-IP line.
    const presented = req.headers.authorization ?? '';
    // Only a LIVE bearer earns its own budget: an expired credential is
    // caller input, not a principal — otherwise every stale token an
    // attacker holds buys a fresh cred-keyed bucket on top of the IP line
    // (w30-issuerd F5).
    const recognized = presented.startsWith('Bearer ') && Object.values(issuers).some(i => {
      if (i.token_expires_at && i.token_expires_at <= clock()) return false;
      const di = bearerDigest(i, 'issue'), dr = bearerDigest(i, 'read');
      return (di && bearerMatches(presented, di)) || (dr && bearerMatches(presented, dr));
    });
    const principalKey = recognized ? `cred:${hashBytes(presented.slice(7)).slice(0, 24)}` : ip;
    const bucketFor = (scope) => {
      const key = `${principalKey}:${scope}`, now = clock();
      const limits = { ip: [600, 60000], read: [240, 60000], issue: [120, 60000], probe: [30, 60000] };
      const [cap, window] = limits[scope] ?? limits.probe;
      let b = buckets.get(key); if (!b || now >= b.reset) { b = { left: cap, reset: now + window }; buckets.set(key, b); }
      // The expiry sweep is amortized, not whole-map: a >10k-key map
      // scanned per request is a quadratic CPU flood on non-loopback
      // binds (w47-http MED-LOW). Map iteration is insertion-ordered —
      // sweeping a bounded slice per call expires what it can, and the
      // hard ceiling below bounds the map absolutely (a map that large is
      // itself the flood; evicted entries just reset their allowance).
      if (buckets.size > 10000) {
        let swept = 0;
        for (const [k, v] of buckets) { if (now >= v.reset) buckets.delete(k); if (++swept >= 256) break; }
        while (buckets.size > 50000) buckets.delete(buckets.keys().next().value);
      }
      return b;
    };
    const take = (scope) => { const b = bucketFor(scope); requireThat(b.left > 0, 'INV-429-RATE', 'Rate limit exceeded', 429); b.left--; };
    try {
      // The coarse per-IP bucket is taken before any request validation —
      // malformed traffic must consume budget too (w9-deploy F9).
      take('ip');
      // IPv6 literals need brackets in a URL authority — an unbracketed
      // '::1' base is a parse error that 500s every request (w10-fixverify
      // F-1). Absolute-form targets are refused outright, same as the main
      // server (w10-fixverify F-13).
      const base = `http://${host.includes(':') ? `[${host}]` : host}:${port}`;
      requireThat(req.url.startsWith('/'), 'INV-400-SCHEMA', 'Request target must be origin-form', 400);
      const url = new URL(req.url, base);
      requireThat(req.url.split('?')[0] === url.pathname, 'INV-400-SCHEMA', 'Request target must be an origin-form canonical path', 400);
      // The wire contract is closed: 'tenant' on the manifest route is
      // the only declared parameter — anything else fails rather than
      // being silently ignored (w18-http F-4).
      // Same closed-params grammar as the gate: only the declared 'tenant'
      // parameter, and a parameter may never repeat (w28-http F-02).
      const seen = new Set();
      for (const k of url.searchParams.keys()) {
        requireThat(k === 'tenant' && req.method === 'GET' && /^\/v1\/issuers\/[A-Za-z0-9_-]+\/(manifest|health)$/.test(url.pathname), 'INV-400-SCHEMA', 'Unknown query parameter', 400);
        requireThat(!seen.has(k), 'INV-400-SCHEMA', `Duplicate query parameter ${k}`, 400);
        seen.add(k);
      }
      // Same Host pinning as the main server: requests naming another
      // authority are answered by nothing here (w9-deploy F5). Compare
      // against the socket's own local address/port so a wildcard-bound
      // daemon still pins the authority it actually received (w9-deploy F5).
      // A bare-address Host is refused: the pin is authority:port, never
      // authority alone (w10-fixverify F-8).
      const expected = `${req.socket.localAddress}:${req.socket.localPort}`, expected6 = `[${req.socket.localAddress}]:${req.socket.localPort}`;
      requireThat(req.headers.host === expected || req.headers.host === expected6, 'INV-400-HOST', 'Unrecognised host', 400);
      // Literal loopback addresses only — 'localhost' resolves through
      // DNS and a resolver quirk could route the check off-box
      // (w18-issuerd F-13).
      const loopback = ['127.0.0.1', '::1'].includes(host);
      // Whether the presented bearer authorises THIS issuer — boolean, so
      // callers can fold it into the same 404 as a missing name and a
      // wrong-issuer bearer learns nothing (w9-deploy F4). `issue` scope
      // requires the issue credential; `read` scope accepts a read
      // credential or the issue credential when no read credential is
      // configured. Both expire at `token_expires_at` (IDN-009).
      const issuerAuthOk = (issuer, scope) => {
        const d = bearerDigest(issuer, scope);
        if (!d) {
          if (!(loopback && allow_insecure_loopback)) return false;
          // An open issuer under the loopback opt-in must still never mint
          // under a bearer that belongs to a DIFFERENT issuer — a registry
          // credential is scoped to its own name (w10-fixverify F-5).
          const auth = req.headers.authorization ?? '';
          if (auth && Object.values(issuers).some(i => i !== issuer && (bearerDigest(i, 'issue') || bearerDigest(i, 'read')) && (bearerMatches(auth, bearerDigest(i, 'issue') ?? '') || bearerMatches(auth, bearerDigest(i, 'read') ?? '')))) return false;
          return true;
        }
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
      // Uniform 401: whether the registry is tokenless, off-loopback or
      // missing the opt-in is deployment state an unauthenticated caller
      // must not fingerprint — the honest diagnosis is the one-time
      // stderr warning printed at bind (w21-issuerd F11).
      const configOk = (loopback || !noTokens) && (!noTokens || allow_insecure_loopback);
      const gate = (scope) => requireThat(configOk && (anyBearer(scope) || openLoopback), 'INV-401-AUTH', `Issuer endpoint requires the ${scope} bearer token`, 401);
      // Own-property lookups only — a caller-controlled name like 'toString'
      // must never resolve an inherited member into a truthy issuer
      // (w9-fixverify: same oracle class as revoke()).
      const own = k => (Object.hasOwn(issuers, k) ? issuers[k] : undefined);
      // No 'null' coercion: a missing tenant parameter resolves the bare
      // name only — never a phantom 'null:<name>' entry that a real tenant
      // literally named 'null' would collide with (w10-fixverify F-6).
      const resolveIssuer = (name, tenant) => {
        const scoped = tenant ? own(`${tenant}:${name}`) : undefined;
        if (scoped) return scoped;
        const bare = own(name);
        return bare && !bare.ambiguous ? bare : null;
      };
      if (req.method === 'GET' && url.pathname === '/v1/issuers') {
        const auth = req.headers.authorization ?? '';
        const holder = Object.values(issuers).find(i => {
          const d = bearerDigest(i, 'read');
          return d && bearerMatches(auth, d) && (!i.token_expires_at || i.token_expires_at > clock());
        });
        if (!holder) {
          take('probe');
          // Refused listing probes land on the issuance chain too — the
          // same provenance bar as manifest/health reads (w21-fixverify L-4).
          if (!(configOk && openLoopback)) {
            issuanceLog({ issuer: null, tenant: null, refused: true, unauthenticated: true, route: 'issuers-list', code: 'INV-401-AUTH' });
            throw new InvariantError('INV-401-AUTH', 'Issuer listing requires a valid read bearer token', 401);
          }
        } else take('read');
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
        // Successful directory reads are support access too — the chain
        // records them, not only refusals and issuance (w22-ledger AUD-007).
        issuanceLog({ issuer: holder?.issuer ?? null, tenant: holder?.tenant ?? null, route: 'issuers-list', accessed: true });
        return send(200, out);
      }
      // Tenant-aware resolution: '<tenant>:<issuer>' wins; a bare name
      // resolves only when it is not ambiguous across tenants.
      let m;
      if (req.method === 'GET' && (m = /^\/v1\/issuers\/([A-Za-z0-9_-]+)\/manifest$/.exec(url.pathname))) {
        const authed = anyBearer('read');
        if (!authed) take('probe'); gate('read'); take('read');
        const issuer = resolveIssuer(m[1], url.searchParams.get('tenant'));
        const requestedTenant = url.searchParams.get('tenant');
        // Existence, tenant binding and per-issuer authorisation share one
        // answer — a bearer for a different issuer learns nothing about
        // whether the name resolved (w9-deploy F4). Foreign-bearer probing
        // is charged AND logged like unauthenticated probing: the read
        // bucket must not buy an 8x enumeration rate, and refused reads
        // must not leave zero provenance (w21-issuerd F6).
        const ok = issuer && (!requestedTenant || !issuer.tenant || issuer.tenant === requestedTenant) && issuerAuthOk(issuer, 'read');
        if (!ok) {
          if (authed || openLoopback) take('probe');
          issuanceLog({ issuer: m[1], tenant: requestedTenant ?? null, refused: true, unauthenticated: !authed, route: 'manifest', code: 'INV-404-NOT-FOUND' });
          throw new InvariantError('INV-404-NOT-FOUND', 'Issuer not found', 404);
        }
        issuanceLog({ issuer: issuer.issuer, tenant: issuer.tenant ?? null, route: 'manifest', accessed: true });
        return send(200, signed({
          connector_id: `issuer:${issuer.issuer}`, version: issuer.version, domain: issuer.channel,
          actions: Object.keys(issuer.kinds), permissions: ISSUER_MANIFEST_PERMISSIONS,
          limitations: ISSUER_MANIFEST_LIMITATIONS,
          idempotency: ISSUER_MANIFEST_IDEMPOTENCY,
          // Manifests are short-lived so a captured replay cannot suppress
          // drift detection for weeks (w9-network F8): the consumer bounds
          // both the accepted issue age and the signed horizon.
          coverage_implications: ISSUER_MANIFEST_COVERAGE, issued_at: clock(), expires_at: clock() + 600000
        }, issuer.key, 'connector-manifest'));
      }
      if (req.method === 'POST' && (m = /^\/v1\/issuers\/([A-Za-z0-9_-]+)\/issue$/.exec(url.pathname))) {
        const chunks = []; let size = 0;
        try {
          for await (const c of req) { size += c.length; requireThat(size <= 262144, 'INV-413-BODY', 'Request too large', 413); chunks.push(c); }
        } catch (e) {
          // Oversize floods must be visible and costly regardless of bearer
          // configuration — authenticated probes consume the same bucket
          // and land in the same log, never 413'd silently
          // (w18-issuerd F-2, w20-fixverify F-6).
          take('probe');
          issuanceLog({ issuer: 'unknown', request_digest: logMac({ wire_bytes: size }), refused: true, unauthenticated: !anyBearer('issue'), malformed: true, code: e.code ?? 'INV-413-BODY' });
          throw e;
        }
        let request;
        try {
          // Same strict content contract as the main API — any other
          // Content-Type cannot mint evidence (w18-http F-4).
          requireThat(req.headers['content-type'] === 'application/json', 'INV-415-CONTENT', 'Use application/json', 415);
          // Malformed wire bytes surface as INV-400-SCHEMA, never as a 500:
          // the fatal decoder throws TypeError, which the generic handler
          // would otherwise map to INV-500 (w9-fixverify NB-1).
          try { request = parseStrict(new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks))); }
          catch (e) { if (e instanceof InvariantError) throw e; throw new InvariantError('INV-400-SCHEMA', 'Malformed request body encoding', 400); }
          fields(request, ['tenant_id', 'capsule_digest', 'kind', 'subject_id', 'claims'], ['dependencies']);
          identifier(request.tenant_id, 'tenant'); identifier(request.subject_id, 'subject'); text(request.kind, 'kind', 64);
          requireThat(/^[a-f0-9]{64}$/.test(request.capsule_digest), 'INV-400-SCHEMA', 'capsule_digest must be a digest');
        } catch (e) {
          // Malformed floods are logged+charged regardless of bearer
          // configuration — a schema-failing flood under a valid token
          // must not be any more invisible to provenance than an
          // unauthenticated one (w18-http F-5, w20-fixverify F-6); the
          // probe bucket bounds the entries.
          take('probe');
          issuanceLog({ issuer: 'unknown', request_digest: logMac(request ?? { wire_bytes: size }), refused: true, unauthenticated: !anyBearer('issue'), malformed: true, code: e.code ?? 'INV-400-SCHEMA' });
          throw e;
        }
        // 'refused' is logged only when the request is actually refused —
        // a tokenless open-loopback issue must not precede every success
        // with a phantom denial entry (w18-issuerd F-12).
        try { gate('issue'); } catch (e) { if (!anyBearer('issue')) { take('probe'); issuanceLog({ issuer: 'unknown', request_digest: logMac(request), refused: true, unauthenticated: true, code: e.code ?? 'INV-401-AUTH' }); } throw e; }
        take('issue');
        const issuer = resolveIssuer(m[1], request.tenant_id);
        // Authentication failures are logged to the issuance chain too —
        // probing must not be invisible to provenance audit (MED-5) — but
        // the response is a uniform 404 so wrong-issuer bearers cannot
        // enumerate names (w9-deploy F4).
        try { requireThat(issuer && issuerAuthOk(issuer, 'issue'), 'INV-404-NOT-FOUND', 'Issuer not found', 404); } catch (e) { if (anyBearer('issue') || openLoopback) take('probe'); issuanceLog({ issuer: issuer?.issuer ?? 'unknown', request_digest: logMac(request), refused: true, unauthenticated: !anyBearer('issue'), code: 'INV-404-NOT-FOUND' }); throw e; }
        issuer.metrics.requests++; const t0 = performance.now();
        try {
          const envelope = answerQuery(issuer, request, clock());
          issuer.metrics.issued++; issuer.metrics.latencies.push(performance.now() - t0); if (issuer.metrics.latencies.length > 512) issuer.metrics.latencies.shift();
          issuanceLog({ issuer: issuer.issuer, tenant: issuer.tenant ?? request.tenant_id ?? null, request_digest: logMac(request), evidence_id: envelope.payload.evidence_id, claim: envelope.payload.claim });
          return send(201, envelope);
        } catch (e) {
          issuer.metrics.errors++; issuer.metrics.refused++;
          issuanceLog({ issuer: issuer.issuer, tenant: issuer.tenant ?? request.tenant_id ?? null, request_digest: logMac(request), refused: true, code: e.code ?? 'ERR' });
          throw e;
        }
      }
      if (req.method === 'GET' && (m = /^\/v1\/issuers\/([A-Za-z0-9_-]+)\/health$/.exec(url.pathname))) {
        const authed = anyBearer('read');
        if (!authed) take('probe'); gate('read'); take('read');
        const issuer = resolveIssuer(m[1], url.searchParams.get('tenant'));
        // Same probing bar as manifest: a foreign read token burning the
        // read bucket for 404-answer probing must ride the probe budget
        // and leave a chain entry (w21-issuerd F6).
        if (!(issuer && issuerAuthOk(issuer, 'read'))) {
          if (authed || openLoopback) take('probe');
          issuanceLog({ issuer: m[1], refused: true, unauthenticated: !authed, route: 'health', code: 'INV-404-NOT-FOUND' });
          throw new InvariantError('INV-404-NOT-FOUND', 'Issuer not found', 404);
        }
        issuanceLog({ issuer: issuer.issuer, tenant: issuer.tenant ?? null, route: 'health', accessed: true });
        const lat = issuer.metrics.latencies, sorted = [...lat].sort((a, b) => a - b);
        // Latencies are floats — emit an integer so the response can never
        // fail canonicalisation (w9-deploy F1).
        // uptime_ms must stay an integer without the int32 `|0` overflow
        // — Math.floor keeps canonical form past ~24.8 days (w47-http LOW).
        return send(200, { status: 'ok', issuer: issuer.issuer, version: issuer.version, records: Object.keys(issuer.records).length, uptime_ms: Math.floor(process.uptime() * 1000), metrics: { requests: issuer.metrics.requests, errors: issuer.metrics.errors, issued: issuer.metrics.issued, refused: issuer.metrics.refused, p50_ms: sorted.length ? Math.round(sorted[Math.floor(sorted.length / 2)]) : 0 }, token_expires_at: issuer.token_expires_at ?? null });
      }
      // Unauthenticated unknown-path probes must consume probe budget and
      // land in the issuance log — a silent 404 fallthrough is a free recon
      // surface below the daemon's own provenance bar (w47-http LOW).
      if (!anyBearer('read') && !anyBearer('issue')) { take('probe'); issuanceLog({ issuer: 'unknown', refused: true, unauthenticated: true, route: 'unknown', code: 'INV-404-NOT-FOUND' }); }
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
  // Same connection ceiling as the gate — a flood of half-open sockets
  // must not exhaust the issuer daemon's file descriptors (w28-http F-03).
  let openConnections = 0;
  server.on('connection', socket => {
    // The close handler must attach BEFORE the cap decision: a destroyed
    // over-cap socket still closes, and skipping the decrement wedged the
    // counter above 2048 permanently — total liveness death until restart
    // (w47-http HIGH).
    socket.on('close', () => openConnections--);
    if (++openConnections > 2048) { socket.destroy(); return; }
  });
  return { server, issuers, listen: () => new Promise(r => server.listen(port, host, r)), close: () => new Promise((r, j) => { server.closeAllConnections(); server.close(e => { releaseLock(); return e ? j(e) : r(); }); }) };
}

export function writeIssuer(directory, spec) {
  // The issuer name becomes a filename — bind it to the same identifier
  // charset the loader enforces so a crafted spec can never write outside
  // the issuer directory or produce a spec that cannot load back
  // (w18-issuerd F-10).
  identifier(spec?.issuer, 'issuer');
  requireThat(/^[A-Za-z0-9_-]+$/.test(spec.issuer), 'INV-400-SCHEMA', 'Issuer name must use the route charset [A-Za-z0-9_-]');
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
