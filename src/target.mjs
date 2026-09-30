import { DatabaseSync } from 'node:sqlite';
import { dirname } from 'node:path';
import { mkdirSync, chmodSync } from 'node:fs';
import { digest, clone } from './canonical.mjs';
import { encrypt, decrypt } from './crypto.mjs';
import { buildPlan, verifyPlan, executePlan } from './datagate.mjs';
import { requireThat, InvariantError } from './errors.mjs';

// Controlled target simulator. It NEVER talks to a real bank, ERP, OS, or
// cloud. Resources and dataset rows live in real tables with per-tenant AES-256-GCM
// at rest; dataset reads go through the verified query plan (IF-DATA-1) — no
// caller text ever reaches SQL.
export class SimulatedTarget {
  constructor(path, tenantKeys) {
    mkdirSync(dirname(path), { recursive: true, mode: 0o700 }); this.db = new DatabaseSync(path); chmodSync(path, 0o600); this.keys = tenantKeys;
    this.db.exec(`PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA busy_timeout=5000; PRAGMA secure_delete=ON;
      CREATE TABLE IF NOT EXISTS resources(tenant TEXT, id TEXT, version INTEGER, value TEXT, PRIMARY KEY(tenant,id));
      CREATE TABLE IF NOT EXISTS transactions(tenant TEXT,id TEXT,value TEXT,PRIMARY KEY(tenant,id));
      CREATE TABLE IF NOT EXISTS dataset_rows(tenant TEXT, dataset TEXT, row_id TEXT, data TEXT, PRIMARY KEY(tenant,dataset,row_id));
      CREATE TABLE IF NOT EXISTS data_access(tenant TEXT, subject TEXT, dataset TEXT, row_id TEXT, column_name TEXT, at INTEGER);
      CREATE INDEX IF NOT EXISTS data_access_ix ON data_access(tenant,subject,dataset,at);
      CREATE TABLE IF NOT EXISTS secrets_registry(tenant TEXT, secret_id TEXT, version INTEGER, value TEXT, PRIMARY KEY(tenant,secret_id));
      CREATE TABLE IF NOT EXISTS grants(tenant TEXT, grant_id TEXT, value TEXT, PRIMARY KEY(tenant,grant_id));
      CREATE INDEX IF NOT EXISTS grants_subject ON grants(tenant);`);
  }
  close() { this.db.close(); }
  key(tenant) { requireThat(this.keys[tenant], 'INV-404-NOT-FOUND', 'Resource not found', 404); return Buffer.from(this.keys[tenant], 'base64url'); }
  _readResource(tenant, id) {
    const row = this.db.prepare('SELECT version,value FROM resources WHERE tenant=? AND id=?').get(tenant, id);
    return row ? { version: row.version, value: decrypt(row.value, this.key(tenant), `${tenant}/resource/${id}`) } : { version: 0, value: null };
  }
  state(tenant, id) {
    const res = this._readResource(tenant, id);
    const material_fields = res.value ?? {};
    if (material_fields.columns && material_fields.rows === undefined) {
      material_fields.rows = this.datasetRows(tenant, id);
    }
    return { version: res.version, digest: digest(material_fields), material_fields };
  }
  datasetRows(tenant, dataset) {
    return this.db.prepare('SELECT row_id, data FROM dataset_rows WHERE tenant=? AND dataset=? ORDER BY row_id').all(tenant, dataset)
      .map(r => ({ id: r.row_id, ...decrypt(r.data, this.key(tenant), `${tenant}/dataset/${dataset}/${r.row_id}`) }));
  }
  // Provisioning/fault harness only: not reachable through the HTTP API.
  seed(tenant, id, fields) {
    const { rows, ...meta } = fields;
    const state = this._readResource(tenant, id);
    this.db.prepare('INSERT INTO resources VALUES(?,?,?,?) ON CONFLICT(tenant,id) DO UPDATE SET version=excluded.version,value=excluded.value').run(tenant, id, state.version + 1, encrypt(meta, this.key(tenant), `${tenant}/resource/${id}`));
    if (Array.isArray(rows)) {
      this.db.prepare('DELETE FROM dataset_rows WHERE tenant=? AND dataset=?').run(tenant, id);
      for (const row of rows) {
        const { id: row_id, ...data } = row;
        this.db.prepare('INSERT INTO dataset_rows VALUES(?,?,?,?)').run(tenant, id, row_id, encrypt(data, this.key(tenant), `${tenant}/dataset/${id}/${row_id}`));
      }
    }
  }
  seedSecret(tenant, secret_id, fields) {
    const state = this.db.prepare('SELECT version FROM secrets_registry WHERE tenant=? AND secret_id=?').get(tenant, secret_id);
    this.db.prepare('INSERT INTO secrets_registry VALUES(?,?,?,?) ON CONFLICT(tenant,secret_id) DO UPDATE SET version=excluded.version,value=excluded.value').run(tenant, secret_id, (state?.version ?? 0) + 1, encrypt(fields, this.key(tenant), `${tenant}/secret/${secret_id}`));
  }
  secret(tenant, secret_id) {
    const row = this.db.prepare('SELECT version,value FROM secrets_registry WHERE tenant=? AND secret_id=?').get(tenant, secret_id);
    return row ? { version: row.version, ...decrypt(row.value, this.key(tenant), `${tenant}/secret/${secret_id}`) } : null;
  }
  grant(tenant, grant_id, value) {
    this.db.prepare('INSERT INTO grants VALUES(?,?,?) ON CONFLICT(tenant,grant_id) DO UPDATE SET value=excluded.value').run(tenant, grant_id, encrypt(value, this.key(tenant), `${tenant}/grant/${grant_id}`));
  }
  grants(tenant, subject_id, now) {
    return this.db.prepare('SELECT grant_id, value FROM grants WHERE tenant=?').all(tenant)
      .map(r => decrypt(r.value, this.key(tenant), `${tenant}/grant/${r.grant_id}`))
      .filter(g => g.subject_id === subject_id && g.expires_at > now && !g.revoked);
  }
  allGrants(tenant) {
    return this.db.prepare('SELECT grant_id, value FROM grants WHERE tenant=?').all(tenant)
      .map(r => decrypt(r.value, this.key(tenant), `${tenant}/grant/${r.grant_id}`));
  }
  revokeGrant(tenant, grant_id) {
    const row = this.db.prepare('SELECT value FROM grants WHERE tenant=? AND grant_id=?').get(tenant, grant_id);
    requireThat(row, 'INV-404-NOT-FOUND', 'Grant not found', 404);
    const value = decrypt(row.value, this.key(tenant), `${tenant}/grant/${grant_id}`);
    value.revoked = true;
    this.db.prepare('UPDATE grants SET value=? WHERE tenant=? AND grant_id=?').run(encrypt(value, this.key(tenant), `${tenant}/grant/${grant_id}`), tenant, grant_id);
    return value;
  }
  outcome(tenant, id) {
    const row = this.db.prepare('SELECT value FROM transactions WHERE tenant=? AND id=?').get(tenant, id);
    return row ? decrypt(row.value, this.key(tenant), `${tenant}/transaction/${id}`) : null;
  }
  // Verified dataset read: caller scope is compiled into a QueryPlan, rebound
  // against the authorising grant, then executed with bound parameters only.
  readDataset(tenant, id, columns, rowIds, ceiling) {
    const dataset = this.state(tenant, id).material_fields;
    requireThat(Array.isArray(dataset.columns), 'INV-404-NOT-FOUND', 'Dataset not found', 404);
    const plan = buildPlan({ dataset: id, columns, row_ids: rowIds, max_rows: ceiling }, dataset.columns);
    verifyPlan(plan, { dataset: id, columns, row_ids: rowIds, max_rows: ceiling });
    const rows = executePlan(this.db, plan, tenant, (row, r) => decrypt(r.data, this.key(tenant), `${tenant}/dataset/${id}/${row}`));
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
      const state = this.state(tenant, id);
      requireThat(state.version === capsule.current_state.version && state.digest === capsule.current_state.digest, 'INV-409-STATE', 'Target state changed', 409);
      const requested = capsule.requested_state, type = capsule.action.type;
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
      if (type !== 'data.export') this.db.prepare('INSERT INTO resources VALUES(?,?,?,?) ON CONFLICT(tenant,id) DO UPDATE SET version=excluded.version,value=excluded.value').run(tenant, id, state.version + 1, encrypt(next, this.key(tenant), `${tenant}/resource/${id}`));
      outcome = { target_transaction_id: transactionId, capsule_digest: digest(capsule), authorised_requested_digest: digest(requested), observed_state_digest: digest(next), observed_state: next, output, status: 'VERIFIED', execution_time: now, simulation: true };
      this.db.prepare('INSERT INTO transactions VALUES(?,?,?)').run(tenant, transactionId, encrypt(outcome, this.key(tenant), `${tenant}/transaction/${transactionId}`));
      this.db.exec('COMMIT');
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
    const state = this.state(tenant, id);
    this.db.prepare('UPDATE resources SET version=?, value=? WHERE tenant=? AND id=?').run(state.version + 1, encrypt({ ...priorState, compensated_at: now, compensation_of: digest(capsule) }, this.key(tenant), `${tenant}/resource/${id}`), tenant, id);
    return { compensated: true, restored_version: state.version + 1 };
  }
  manifest() {
    return { connector_id: 'controlled-sqlite-target', version: '1.1.0', environment: 'simulation', production_supported: false, credentials: 'customer-local software encryption key; no external target credentials', idempotency: 'durable unique transaction id; mutating timeout never retried automatically', permissions: ['local simulated resource read', 'local simulated resource mutation', 'verified dataset query plans', 'registered compensation for non-monetary mutations'], limitations: ['No bank/ERP API integration', 'No target-wide bypass guarantee', 'No hardware-backed credential isolation', 'No actual network/cloud/identity/secret/backup mutation', 'Composite atomicity is compensation-based, not transactional'], upgrade_rule: 'coverage becomes UNKNOWN until compatibility and bypass tests pass' };
  }
}
