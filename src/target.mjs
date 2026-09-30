import { DatabaseSync } from 'node:sqlite';
import { dirname } from 'node:path';
import { mkdirSync, chmodSync } from 'node:fs';
import { digest, clone } from './canonical.mjs';
import { encrypt, decrypt } from './crypto.mjs';
import { requireThat } from './errors.mjs';

// Controlled target simulator. It NEVER talks to a real bank, ERP, OS, or cloud.
export class SimulatedTarget {
  constructor(path, tenantKeys) {
    mkdirSync(dirname(path), { recursive: true, mode: 0o700 }); this.db = new DatabaseSync(path); chmodSync(path, 0o600); this.keys = tenantKeys;
    this.db.exec('PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA busy_timeout=5000; CREATE TABLE IF NOT EXISTS resources(tenant TEXT, id TEXT, version INTEGER, value TEXT, PRIMARY KEY(tenant,id)); CREATE TABLE IF NOT EXISTS transactions(tenant TEXT,id TEXT,value TEXT,PRIMARY KEY(tenant,id));');
  }
  close() { this.db.close(); }
  key(tenant) { requireThat(this.keys[tenant], 'INV-404-NOT-FOUND', 'Resource not found', 404); return Buffer.from(this.keys[tenant], 'base64url'); }
  state(tenant, id) {
    const row = this.db.prepare('SELECT version,value FROM resources WHERE tenant=? AND id=?').get(tenant, id);
    const material_fields = row ? decrypt(row.value, this.key(tenant), `${tenant}/resource/${id}`) : {};
    return { version: row?.version ?? 0, digest: digest(material_fields), material_fields };
  }
  // Provisioning/fault harness only: not reachable through the HTTP API.
  seed(tenant, id, fields) {
    const state = this.state(tenant, id);
    this.db.prepare('INSERT INTO resources VALUES(?,?,?,?) ON CONFLICT(tenant,id) DO UPDATE SET version=excluded.version,value=excluded.value').run(tenant, id, state.version + 1, encrypt(fields, this.key(tenant), `${tenant}/resource/${id}`));
  }
  outcome(tenant, id) {
    const row = this.db.prepare('SELECT value FROM transactions WHERE tenant=? AND id=?').get(tenant, id);
    return row ? decrypt(row.value, this.key(tenant), `${tenant}/transaction/${id}`) : null;
  }
  execute(capsule, transactionId, now, fault = null) {
    const tenant = capsule.tenant_id, id = capsule.action.target_resource;
    const prior = this.outcome(tenant, transactionId); if (prior) return prior;
    if (fault === 'before-dispatch') throw new Error('Simulated transport timeout before dispatch');
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
      if (fault === 'before-commit') throw new Error('Simulated target transaction failure');
      if (type !== 'data.export') this.db.prepare('INSERT INTO resources VALUES(?,?,?,?) ON CONFLICT(tenant,id) DO UPDATE SET version=excluded.version,value=excluded.value').run(tenant, id, state.version + 1, encrypt(next, this.key(tenant), `${tenant}/resource/${id}`));
      outcome = { target_transaction_id: transactionId, capsule_digest: digest(capsule), authorised_requested_digest: digest(requested), observed_state_digest: digest(next), observed_state: next, output, status: 'VERIFIED', execution_time: now, simulation: true };
      this.db.prepare('INSERT INTO transactions VALUES(?,?,?)').run(tenant, transactionId, encrypt(outcome, this.key(tenant), `${tenant}/transaction/${transactionId}`));
      this.db.exec('COMMIT');
    } catch (e) { this.db.exec('ROLLBACK'); throw e; }
    if (fault === 'after-commit') throw new Error('Simulated response lost after durable commit');
    if (fault === 'malformed-response') return { status: 'VERIFIED' };
    if (fault === 'altered-response') return { ...outcome, authorised_requested_digest: '0'.repeat(64) };
    return outcome;
  }
  readDataset(tenant, id, columns, rowIds, ceiling) {
    const dataset = this.state(tenant, id).material_fields;
    requireThat(Array.isArray(dataset.rows) && Array.isArray(dataset.columns), 'INV-404-NOT-FOUND', 'Dataset not found', 404);
    requireThat(columns.length > 0 && columns.every(c => dataset.columns.includes(c)) && rowIds.length <= ceiling, 'INV-451-POLICY', 'Dataset scope denied', 451);
    const rows = dataset.rows.filter(row => rowIds.includes(row.id));
    requireThat(rows.length === rowIds.length, 'INV-409-STATE', 'Requested row set changed', 409);
    return rows.map(row => Object.fromEntries(columns.map(c => [c, row[c] ?? null])));
  }
  manifest() {
    return { connector_id: 'controlled-sqlite-target', version: '1.0.0', environment: 'simulation', production_supported: false, credentials: 'customer-local software encryption key; no external target credentials', idempotency: 'durable unique transaction id; mutating timeout never retried automatically', permissions: ['local simulated resource read', 'local simulated resource mutation'], limitations: ['No bank/ERP API integration', 'No target-wide bypass guarantee', 'No hardware-backed credential isolation', 'No actual network/cloud/identity/secret/backup mutation'], upgrade_rule: 'coverage becomes UNKNOWN until compatibility and bypass tests pass' };
  }
}
