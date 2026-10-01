import { DatabaseSync } from 'node:sqlite';
import { dirname } from 'node:path';
import { mkdirSync, chmodSync } from 'node:fs';
import { digest, clone, canonical } from './canonical.mjs';
import { encrypt, decrypt } from './crypto.mjs';
import { buildPlan, verifyPlan, executePlan } from './datagate.mjs';
import { requireThat, InvariantError } from './errors.mjs';

// Controlled target simulator. It NEVER talks to a real bank, ERP, OS, or
// cloud. Resources and dataset rows live in real tables with per-tenant AES-256-GCM
// at rest; dataset reads go through the verified query plan (IF-DATA-1) — no
// caller text ever reaches SQL.
// Tuple AADs joined by canonical(): a slash-joined AAD collides if any
// identifier ever admits '/' — 'a/b'+'c' vs 'a'+'b/c' encrypt the same
// context. Writes use the tuple form; the legacy slash space was migrated
// away at open and is dead thereafter — a live fallback IS the transplant
// surface (w18-crypto F1/F2, uniform closure).
const AAD = (...parts) => canonical(parts);
export class SimulatedTarget {
  _dec(value, tenant, tuple) { return decrypt(value, this.key(tenant), tuple); }
  constructor(path, tenantKeys, { aadDedup } = {}) {
    mkdirSync(dirname(path), { recursive: true, mode: 0o700 }); this.db = new DatabaseSync(path); chmodSync(path, 0o600); this.keys = tenantKeys;
    // Shared with the ledger store — the same ciphertext must never mint
    // canonical bindings on both sides of a cross-DB graft (w19-aad W19-1).
    this._aadDedup = aadDedup ?? new Map();
    // Same contention contract as the ledger store: constructor writes lose
    // a busy-timeout race as INV-503-LEDGER, never a raw sqlite error
    // (w20-fixverify F-12).
    try {
      this.db.exec(`PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA busy_timeout=30000; PRAGMA secure_delete=ON;
        CREATE TABLE IF NOT EXISTS resources(tenant TEXT, id TEXT, version INTEGER, value TEXT, PRIMARY KEY(tenant,id));
        CREATE TABLE IF NOT EXISTS transactions(tenant TEXT,id TEXT,value TEXT,PRIMARY KEY(tenant,id));
        CREATE TABLE IF NOT EXISTS dataset_rows(tenant TEXT, dataset TEXT, row_id TEXT, data TEXT, PRIMARY KEY(tenant,dataset,row_id));
        CREATE TABLE IF NOT EXISTS data_access(tenant TEXT, subject TEXT, dataset TEXT, row_id TEXT, column_name TEXT, at INTEGER);
        CREATE INDEX IF NOT EXISTS data_access_ix ON data_access(tenant,subject,dataset,at);
        CREATE TABLE IF NOT EXISTS secrets_registry(tenant TEXT, secret_id TEXT, version INTEGER, value TEXT, PRIMARY KEY(tenant,secret_id));
        CREATE TABLE IF NOT EXISTS grants(tenant TEXT, grant_id TEXT, value TEXT, PRIMARY KEY(tenant,grant_id));
        CREATE INDEX IF NOT EXISTS grants_subject ON grants(tenant);`);
      // Crash residue: a post-delete checkpoint that never ran leaves superseded
      // ciphertext in the WAL — truncate at open like the ledger store does
      // (w8-fixverify F3).
      this.db.exec('PRAGMA wal_checkpoint(TRUNCATE)');
    } catch (e) {
      if (e?.errcode === 5 || /database is locked/i.test(e?.message ?? '')) throw new InvariantError('INV-503-LEDGER', 'Ledger writer contention exceeded the wait bound; retry', 503);
      throw e;
    }
    this._migrateAad();
  }
  // One-shot migration out of the legacy slash-form AAD space — same shape
  // as the ledger store's migration: each row that only authenticates
  // under the legacy form is re-sealed under its tuple form in one tx, a
  // row authenticating under neither stays sealed and keeps failing on
  // read (w18-crypto F1/F2).
  _migrateAad() {
    const spec = [
      ['resources', 'value', r => [AAD('target', 'resource', r.tenant, r.id), `${r.tenant}/resource/${r.id}`], r => [r.tenant, r.id]],
      ['transactions', 'value', r => [AAD('target', 'transaction', r.tenant, r.id), `${r.tenant}/transaction/${r.id}`], r => [r.tenant, r.id]],
      ['dataset_rows', 'data', r => [AAD('target', 'dataset', r.tenant, r.dataset, r.row_id), `${r.tenant}/dataset/${r.dataset}/${r.row_id}`], r => [r.tenant, r.dataset, r.row_id]],
      ['secrets_registry', 'value', r => [AAD('target', 'secret', r.tenant, r.secret_id), `${r.tenant}/secret/${r.secret_id}`], r => [r.tenant, r.secret_id]],
      ['grants', 'value', r => [AAD('target', 'grant', r.tenant, r.grant_id), `${r.tenant}/grant/${r.grant_id}`], r => [r.tenant, r.grant_id]],
    ];
    // Same accounting + transplant defenses as the ledger store's
    // migration: identical bytes under two identities quarantines BOTH
    // rows, slash-bearing identities stay sealed, and nothing is skipped
    // silently (w19-aad W19-1/W19-2).
    const stats = this.aadMigration = new Map();
    const mark = (tenant, k) => { const s = stats.get(tenant) ?? { migrated: 0, transplants: 0, ambiguous: 0, skipped: 0 }; s[k]++; stats.set(tenant, s); };
    // Same honest accounting as the store migrator: a grafted donor is
    // reverted, and its 'migrated' mark must unwind with it — the sibling
    // migrator's dedup hit invokes this closure (w20-fixverify F-9).
    const unmark = tenant => { const s = stats.get(tenant); if (s && s.migrated > 0) { s.migrated--; s.reverted = (s.reverted ?? 0) + 1; } };
    const seen = this._aadDedup;
    const slashy = (...parts) => parts.some(p => typeof p === 'string' && p.includes('/'));
    this.db.exec('BEGIN IMMEDIATE');
    try {
      for (const [table, col, aads, pks] of spec) {
        const where = table === 'dataset_rows' ? 'tenant=? AND dataset=? AND row_id=?'
          : table === 'secrets_registry' ? 'tenant=? AND secret_id=?'
          : table === 'grants' ? 'tenant=? AND grant_id=?'
          : 'tenant=? AND id=?';
        for (const r of this.db.prepare(`SELECT * FROM ${table}`).all()) {
          const [tuple, legacy] = aads(r);
          try { decrypt(r[col], this.key(r.tenant), tuple); continue; } catch { /* legacy-sealed or corrupt */ }
          const prior = seen.get(r[col]);
          if (prior) { prior.revert?.(); prior.unmark?.(); mark(r.tenant, 'transplants'); continue; }
          if (slashy(r.tenant, r.id, r.dataset, r.row_id, r.secret_id, r.grant_id)) { seen.set(r[col], {}); mark(r.tenant, 'ambiguous'); continue; }
          try {
            const plain = decrypt(r[col], this.key(r.tenant), legacy);
            const upd = this.db.prepare(`UPDATE ${table} SET ${col}=? WHERE ${where}`), orig = r[col];
            seen.set(orig, { revert: () => upd.run(orig, ...pks(r)), unmark: () => unmark(r.tenant) });
            upd.run(encrypt(plain, this.key(r.tenant), tuple), ...pks(r));
            mark(r.tenant, 'migrated');
          } catch { mark(r.tenant, 'skipped'); }
        }
      }
      this.db.exec('COMMIT');
      // Truncate post-migration so dead legacy ciphertext does not linger
      // in the WAL (w19-aad W19-3).
      let migrated = 0; for (const s of stats.values()) migrated += s.migrated;
      if (migrated > 0) { try { this.db.exec('PRAGMA wal_checkpoint(TRUNCATE)'); } catch { /* contention: residue clears at next open */ } }
    } catch (e) {
      if (this.db.isTransaction) this.db.exec('ROLLBACK');
      // BEGIN IMMEDIATE contention surfaces in the ledger taxonomy, not
      // as a raw sqlite error (w19-aad W19-4).
      if (e?.errcode === 5 || /database is locked/i.test(e?.message ?? '')) throw new InvariantError('INV-503-LEDGER', 'Ledger writer contention exceeded the wait bound; retry', 503);
      throw e;
    }
  }
  close() { this.db.close(); }
  tx(fn) {
    if (this.db.isTransaction) return fn();
    this.db.exec('BEGIN IMMEDIATE');
    try {
      const r = fn(); this.db.exec('COMMIT');
      // Deleted ciphertext must not linger in the WAL — any armed delete
      // truncates the log right at the commit boundary (DEK-audit F4). A
      // contended checkpoint throws SQLITE_LOCKED after the COMMIT: the write
      // is durable, so the flag stays armed for the next tx instead of
      // failing committed work (w8-fixverify F2).
      if (this._deleted) try { this.db.exec('PRAGMA wal_checkpoint(TRUNCATE)'); this._deleted = false; } catch { /* retry next tx */ }
      return r;
    }
    catch (e) { this.db.exec('ROLLBACK'); throw e; }
  }
  key(tenant) { requireThat(this.keys[tenant], 'INV-404-NOT-FOUND', 'Resource not found', 404); return Buffer.from(this.keys[tenant], 'base64url'); }
  exists(tenant, id) {
    return this.db.prepare('SELECT 1 FROM resources WHERE tenant=? AND id=?').get(tenant, id) !== undefined;
  }
  _readResource(tenant, id) {
    const row = this.db.prepare('SELECT version,value FROM resources WHERE tenant=? AND id=?').get(tenant, id);
    return row ? { version: row.version, value: this._dec(row.value, tenant, AAD('target', 'resource', tenant, id)) } : { version: 0, value: null };
  }
  state(tenant, id) {
    const res = this._readResource(tenant, id);
    const material_fields = res.value ?? {};
    // 'rows' is a read-model projection for real datasets only. A write whose
    // payload merely contains a 'columns' key (e.g. a JIT grant) must not
    // start projecting rows — the stored record and its digest would drift
    // apart (w5 F-6 post-read).
    if (material_fields.columns && material_fields.rows === undefined && this.db.prepare('SELECT 1 FROM dataset_rows WHERE tenant=? AND dataset=? LIMIT 1').get(tenant, id)) {
      material_fields.rows = this.datasetRows(tenant, id);
    }
    return { version: res.version, digest: digest(material_fields), material_fields };
  }
  datasetRows(tenant, dataset) {
    return this.db.prepare('SELECT row_id, data FROM dataset_rows WHERE tenant=? AND dataset=? ORDER BY row_id').all(tenant, dataset)
      // Registry columns win the spread — a stored 'id'/'version' member
      // must not shadow the row's identity or counter (w9-schema F-7).
      .map(r => ({ ...this._dec(r.data, tenant, AAD('target', 'dataset', tenant, dataset, r.row_id)), id: r.row_id }));
  }
  // Provisioning/fault harness only: not reachable through the HTTP API.
  // The versioned read-modify-write runs in a transaction like every other
  // mutation — a parallel seed can never produce a lost update (concurrency
  // audit L3).
  seed(tenant, id, fields) {
    const { rows, ...meta } = fields;
    return this.tx(() => {
      const state = this._readResource(tenant, id);
      this._deleted = true; // upsert supersedes ciphertext — truncate at commit (w8-fixverify F3)
      this.db.prepare('INSERT INTO resources VALUES(?,?,?,?) ON CONFLICT(tenant,id) DO UPDATE SET version=excluded.version,value=excluded.value').run(tenant, id, state.version + 1, encrypt(meta, this.key(tenant), AAD('target', 'resource', tenant, id)));
      if (Array.isArray(rows)) {
        this.db.prepare('DELETE FROM dataset_rows WHERE tenant=? AND dataset=?').run(tenant, id);
        for (const row of rows) {
          const { id: row_id, ...data } = row;
          this.db.prepare('INSERT INTO dataset_rows VALUES(?,?,?,?)').run(tenant, id, row_id, encrypt(data, this.key(tenant), AAD('target', 'dataset', tenant, id, row_id)));
        }
      }
    });
  }
  seedSecret(tenant, secret_id, fields) {
    return this.tx(() => {
      const state = this.db.prepare('SELECT version FROM secrets_registry WHERE tenant=? AND secret_id=?').get(tenant, secret_id);
      this._writeSecret(tenant, secret_id, (state?.version ?? 0) + 1, fields);
    });
  }
  secret(tenant, secret_id) {
    const row = this.db.prepare('SELECT version,value FROM secrets_registry WHERE tenant=? AND secret_id=?').get(tenant, secret_id);
    return row ? { ...this._dec(row.value, tenant, AAD('target', 'secret', tenant, secret_id)), version: row.version } : null;
  }
  // For secret.use the DECISIVE record is the registry row — that is the state
  // a capsule must bind, not an arbitrary resources row (w5 F-7).
  secretState(tenant, secret_id) {
    const row = this.secret(tenant, secret_id);
    const material_fields = row ? Object.fromEntries(Object.entries(row).filter(([k]) => k !== 'version')) : {};
    return { version: row?.version ?? 0, digest: digest(material_fields), material_fields };
  }
  _writeSecret(tenant, secret_id, version, fields) {
    this._deleted = true; // secret upsert supersedes ciphertext (w8-fixverify F3)
    this.db.prepare('INSERT INTO secrets_registry VALUES(?,?,?,?) ON CONFLICT(tenant,secret_id) DO UPDATE SET version=excluded.version,value=excluded.value').run(tenant, secret_id, version, encrypt(fields, this.key(tenant), AAD('target', 'secret', tenant, secret_id)));
  }
  grant(tenant, grant_id, value) {
    this._deleted = true; // grant upsert supersedes ciphertext (w8-fixverify F3)
    this.db.prepare('INSERT INTO grants VALUES(?,?,?) ON CONFLICT(tenant,grant_id) DO UPDATE SET value=excluded.value').run(tenant, grant_id, encrypt(value, this.key(tenant), AAD('target', 'grant', tenant, grant_id)));
  }
  // One undecryptable grant row must not wedge every authorize() call — a
  // corrupt row can only ever HIDE a grant (anchoring is the authority), so
  // it is skipped and counted, never fatal (w17-fixverify).
  grants(tenant, subject_id, now) {
    const out = [];
    for (const r of this.db.prepare('SELECT grant_id, value FROM grants WHERE tenant=?').all(tenant)) {
      let g; try { g = this._dec(r.value, tenant, AAD('target', 'grant', tenant, r.grant_id)); } catch { this._corruptGrantRows = (this._corruptGrantRows ?? 0) + 1; continue; }
      if (g.subject_id === subject_id && g.expires_at > now && !g.revoked) out.push(g);
    }
    return out;
  }
  allGrants(tenant) {
    const out = [];
    for (const r of this.db.prepare('SELECT grant_id, value FROM grants WHERE tenant=?').all(tenant)) {
      try { out.push(this._dec(r.value, tenant, AAD('target', 'grant', tenant, r.grant_id))); } catch { this._corruptGrantRows = (this._corruptGrantRows ?? 0) + 1; }
    }
    return out;
  }
  revokeGrant(tenant, grant_id) {
    const row = this.db.prepare('SELECT value FROM grants WHERE tenant=? AND grant_id=?').get(tenant, grant_id);
    requireThat(row, 'INV-404-NOT-FOUND', 'Grant not found', 404);
    const value = this._dec(row.value, tenant, AAD('target', 'grant', tenant, grant_id));
    value.revoked = true;
    this._deleted = true; // revoke supersedes ciphertext (w8-fixverify F3)
    this.db.prepare('UPDATE grants SET value=? WHERE tenant=? AND grant_id=?').run(encrypt(value, this.key(tenant), AAD('target', 'grant', tenant, grant_id)), tenant, grant_id);
    return value;
  }
  outcome(tenant, id) {
    const row = this.db.prepare('SELECT value FROM transactions WHERE tenant=? AND id=?').get(tenant, id);
    return row ? this._dec(row.value, tenant, AAD('target', 'transaction', tenant, id)) : null;
  }
  // Verified dataset read: caller scope is compiled into a QueryPlan, rebound
  // against the authorising grant, then executed with bound parameters only.
  readDataset(tenant, id, columns, rowIds, ceiling, grant = null) {
    const dataset = this.state(tenant, id).material_fields;
    requireThat(Array.isArray(dataset.columns), 'INV-404-NOT-FOUND', 'Dataset not found', 404);
    const plan = buildPlan({ dataset: id, columns, row_ids: rowIds, max_rows: ceiling }, dataset.columns);
    // The plan rebinds to the authorising scope when a distinct authority
    // exists (the capability payload on the consume path); on the certified
    // export path the capsule's requested_state IS the authority — the
    // reflexive check stays as a shape guard, and the finish-time
    // exactOutput recompute is the real binding (w20-datagate F8).
    verifyPlan(plan, grant ?? { dataset: id, columns, row_ids: rowIds, max_rows: ceiling });
    const rows = executePlan(this.db, plan, tenant, (row, r) => this._dec(r.data, tenant, AAD('target', 'dataset', tenant, id, row)));
    return rows;
  }
  execute(capsule, transactionId, now, fault = null) {
    const tenant = capsule.tenant_id, id = capsule.action.target_resource;
    const prior = this.outcome(tenant, transactionId); if (prior) return prior;
    if (fault === 'before-dispatch') throw new Error('Simulated transport timeout before dispatch');
    // 'state-conflict' simulates a DETERMINISTIC refusal raised inside the
    // target transaction (e.g. a predicate the reservation check could not
    // see) — the outcome must record FAILED, never UNCERTAIN.
    if (fault === 'state-conflict') throw new InvariantError('INV-409-STATE', 'Simulated deterministic target refusal', 409);
    this.db.exec('BEGIN IMMEDIATE');
    let outcome;
    try {
      const requested = capsule.requested_state, type = capsule.action.type;
      const state = type === 'secret.use' ? this.secretState(tenant, requested.secret_id) : this.state(tenant, id);
      requireThat(state.version === capsule.current_state.version && state.digest === capsule.current_state.digest, 'INV-409-STATE', 'Target state changed', 409);
      let next = { ...state.material_fields, ...clone(requested) }, output = null;
      if (['finance.vendor.create', 'finance.beneficiary.create'].includes(type)) requireThat(state.version === 0, 'INV-409-STATE', 'Resource already exists', 409);
      if (type === 'finance.bank.change') { requireThat(state.version > 0, 'INV-409-STATE', 'Bank change requires existing resource', 409); next.first_payment_done = false; next.payment_eligible_at = now + 60000; }
      if (type === 'finance.payment.first') {
        requireThat(state.version > 0 && id === requested.beneficiary_id && state.material_fields.bank_account === requested.bank_account && state.material_fields.currency === requested.currency && state.material_fields.first_payment_done !== true && (state.material_fields.payment_eligible_at ?? 0) <= now, 'INV-409-STATE', 'Beneficiary, first-payment or cooldown predicate failed', 409);
        next = { ...state.material_fields, first_payment_done: true, payment: clone(requested), payment_transaction: transactionId };
      }
      if (type === 'data.export') {
        requireThat(requested.dataset === id, 'INV-451-POLICY', 'Dataset binding mismatch', 451);
        output = this.readDataset(tenant, id, requested.columns, requested.row_ids, requested.max_rows);
        next = state.material_fields;
      }
      if (type === 'identity.mfa.reset' || type === 'identity.authenticator.enroll' || type === 'identity.account.recover') {
        next = { ...state.material_fields, ...clone(requested), last_identity_operation: { type, at: now, transaction: transactionId } };
      }
      if (type === 'key.rotate') {
        next = { ...state.material_fields, ...clone(requested), rotated_at: now, rotation_transaction: transactionId };
      }
      if (type === 'secret.use') {
        const secret = this.secret(tenant, requested.secret_id);
        requireThat(secret && (secret.allowed_operations ?? []).includes(requested.operation), 'INV-451-POLICY', 'Secret or operation unavailable', 451);
        requireThat(secret.workload_id === requested.workload_id, 'INV-403-SCOPE', 'Workload binding mismatch', 403);
        next = { ...state.material_fields, last_use: { secret_id: requested.secret_id, operation: requested.operation, workload_id: requested.workload_id, at: now, transaction: transactionId } };
      }
      if (type === 'backup.delete') {
        requireThat(state.material_fields.recovery_set === requested.recovery_set, 'INV-409-STATE', 'Recovery set mismatch', 409);
        next = { ...state.material_fields, deleted_backups: [...(state.material_fields.deleted_backups ?? []), { backup_id: requested.backup_id, at: now, transaction: transactionId }] };
      }
      if (fault === 'before-commit') throw new Error('Simulated target transaction failure');
      if (type === 'secret.use') this._writeSecret(tenant, requested.secret_id, state.version + 1, next);
      else if (type !== 'data.export') { this._deleted = true; this.db.prepare('INSERT INTO resources VALUES(?,?,?,?) ON CONFLICT(tenant,id) DO UPDATE SET version=excluded.version,value=excluded.value').run(tenant, id, state.version + 1, encrypt(next, this.key(tenant), AAD('target', 'resource', tenant, id))); }
      // An export's observed_state would persist the WHOLE dataset —
      // including columns the requester may not see — into the durable
      // journal for no validation benefit: the digest alone proves the
      // snapshot. Export entries keep the digest and the authorised output
      // only (w10-datagate F5). A secret.use row gets the same treatment
      // a fortiori — the registry material may carry secret bytes, so the
      // journal holds only the digest-bearing projection (w15-timing F9).
      const journalState = type === 'data.export' ? null
        : type === 'secret.use' ? { withheld: true, material_digest: digest(next) }
        : next;
      outcome = { target_transaction_id: transactionId, capsule_digest: digest(capsule), authorised_requested_digest: digest(requested), observed_state_digest: digest(next), observed_state: journalState, output, status: 'VERIFIED', execution_time: now, simulation: true };
      this.db.prepare('INSERT INTO transactions VALUES(?,?,?)').run(tenant, transactionId, encrypt(outcome, this.key(tenant), AAD('target', 'transaction', tenant, transactionId)));
      this.db.exec('COMMIT');
      // Same commit-boundary truncation as tx() — durable on success, armed
      // for a later retry when the log is contended (w8-fixverify F2/F3).
      if (this._deleted) try { this.db.exec('PRAGMA wal_checkpoint(TRUNCATE)'); this._deleted = false; } catch { /* retry later */ }
    } catch (e) {
      this.db.exec('ROLLBACK');
      // Two processes racing the same transactionId hit the PK constraint
      // inside the write — the loser must get the stored outcome, not an
      // error (store-audit LOW: idempotent replay under contention).
      if (/PRIMARYKEY|UNIQUE/.test(String(e.code ?? e.message))) {
        const prior = this.outcome(tenant, transactionId);
        if (prior) return prior;
      }
      throw e;
    }
    if (fault === 'after-commit') throw new Error('Simulated response lost after durable commit');
    if (fault === 'malformed-response') return { status: 'VERIFIED' };
    if (fault === 'altered-response') return { ...outcome, authorised_requested_digest: '0'.repeat(64) };
    return outcome;
  }
  // Compensation for a previously executed child of a composite action. Only
  // registered, verifiable compensations exist: registry-state restoration for
  // non-monetary mutations. Monetary effects cannot be un-sent — the record
  // says so instead of pretending.
  compensate(capsule, priorState, now) {
    const tenant = capsule.tenant_id, id = capsule.action.target_resource, type = capsule.action.type;
    const compensatable = ['finance.vendor.create', 'finance.beneficiary.create', 'finance.bank.change', 'identity.mfa.reset', 'identity.authenticator.enroll', 'identity.account.recover', 'cloud.firewall.change', 'code.release', 'key.rotate', 'backup.delete'];
    if (!compensatable.includes(type)) {
      return { compensated: false, reason: 'NON_COMPENSATABLE_EFFECT', note: 'Effect cannot be reversed; a separately authorised remedy action is required.' };
    }
    // Read-modify-write inside one tx — a second concurrent compensation
    // cannot lose-update the version counter (concurrency-audit L3).
    return this.tx(() => {
      const state = this.state(tenant, id);
      // The restore may only overwrite the child's own write: if a later
      // authorised action already moved the resource past the compensated
      // version, reverting would silently erase it (w10-cert F6).
      const expected = capsule.current_state.version + 1;
      if (state.version !== expected) return { compensated: false, reason: 'STALE_COMPENSATION', note: `Registry moved past the compensated write (version ${state.version}, expected ${expected}); a separately authorised remedy action is required.` };
      this._deleted = true; // restoration supersedes ciphertext (w8-fixverify F3)
      this.db.prepare('UPDATE resources SET version=?, value=? WHERE tenant=? AND id=?').run(state.version + 1, encrypt({ ...priorState, compensated_at: now, compensation_of: digest(capsule) }, this.key(tenant), AAD('target', 'resource', tenant, id)), tenant, id);
      return { compensated: true, restored_version: state.version + 1 };
    });
  }
  manifest() {
    return { connector_id: 'controlled-sqlite-target', version: '1.1.0', environment: 'simulation', production_supported: false, credentials: 'customer-local software encryption key; no external target credentials', idempotency: 'durable unique transaction id; mutating timeout never retried automatically', permissions: ['local simulated resource read', 'local simulated resource mutation', 'verified dataset query plans', 'registered compensation for non-monetary mutations'], limitations: ['No bank/ERP API integration', 'No target-wide bypass guarantee', 'No hardware-backed credential isolation', 'No actual network/cloud/identity/secret/backup mutation', 'Composite atomicity is compensation-based, not transactional'], upgrade_rule: 'coverage becomes UNKNOWN until compatibility and bypass tests pass' };
  }
}
