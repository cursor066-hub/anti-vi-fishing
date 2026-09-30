import { createHmac } from 'node:crypto';
import { digest, clone, canonical } from './canonical.mjs';
import { fields, identifier, text, integer, uniqueStrings, oneOf } from './schema.mjs';
import { requireThat } from './errors.mjs';

// IF-DATA-1: verified query path for governed datasets.
// Callers never supply SQL. A capability/capsule is compiled into an explicit
// QueryPlan {table, select, row_ids, limit}; executePlan turns the plan into
// parameter-bound SQL, and verifyPlan re-checks every plan field against the
// authorising object immediately before execution (DAT-006).

export function buildPlan(scope, datasetColumns) {
  // scope fields come from a verified capability or certificate constraint.
  fields(scope, ['dataset', 'columns', 'row_ids', 'max_rows']);
  identifier(scope.dataset, 'dataset');
  uniqueStrings(scope.columns, 'columns', 256); uniqueStrings(scope.row_ids, 'row ids', 4096);
  integer(scope.max_rows, 'row ceiling', 1, 100000);
  requireThat(scope.row_ids.length > 0 && scope.row_ids.length <= scope.max_rows, 'INV-400-SCHEMA', 'Row selection exceeds ceiling');
  requireThat(scope.columns.length > 0 && scope.columns.every(c => /^[a-z][a-z0-9_]{0,63}$/.test(c) && datasetColumns.includes(c)), 'INV-403-SCOPE', 'Column not present in authorised dataset schema', 403);
  return { table: 'dataset_rows', dataset: scope.dataset, select: [...scope.columns].sort(), where: { row_id: [...scope.row_ids].sort() }, limit: scope.max_rows };
}

export function verifyPlan(plan, grant) {
  // Re-bind the plan to the authorising grant: every selected column and row
  // must be a subset of what was authorised; the bound limit must not grow.
  requireThat(plan && grant && plan.dataset === grant.dataset, 'INV-403-SCOPE', 'Query plan escapes authorised dataset', 403);
  requireThat(plan.select.every(c => grant.columns.includes(c)), 'INV-403-SCOPE', 'Plan column outside capability', 403);
  requireThat(plan.where.row_id.every(r => grant.row_ids.includes(r)) && plan.where.row_id.length <= grant.row_ids.length, 'INV-403-SCOPE', 'Plan row outside capability', 403);
  requireThat(plan.limit <= grant.max_rows, 'INV-403-SCOPE', 'Plan limit exceeds authorisation', 403);
  return true;
}

export function executePlan(db, plan, tenant, decode = null) {
  // Parameter-bound execution: identifiers are verified plan fields, values are
  // bound parameters. No caller text reaches SQL.
  const marks = plan.where.row_id.map(() => '?').join(',');
  const rows = db.prepare(`SELECT row_id, data FROM dataset_rows WHERE tenant=? AND dataset=? AND row_id IN (${marks}) ORDER BY row_id LIMIT ?`)
    .all(tenant, plan.dataset, ...plan.where.row_id, plan.limit)
    .map(r => ({ row_id: r.row_id, data: decode ? decode(r.row_id, r) : JSON.parse(r.data) }));
  requireThat(rows.length === plan.where.row_id.length, 'INV-409-STATE', 'Dataset row set changed since authorisation', 409);
  return rows.map(r => Object.fromEntries(plan.select.map(c => [c, c === 'id' ? r.row_id : (r.data[c] ?? null)])));
}

// SHIELD transformations applied to a result set (DAT-005). Each transform is
// deterministic so an assessor can recompute the transformed output.
export const TRANSFORMS = {
  mask: (value, field) => value === null || value === undefined ? null : '\u2022\u2022\u2022\u2022' + String(value).slice(-2),
  tokenise: (value, field, ctx) => 'tok:' + createHmac('sha256', ctx.tenantKey).update(`${ctx.tenant}/${ctx.dataset}/${field}/${canonical(value)}`).digest('hex').slice(0, 24),
  drop: () => null,
  constant: (value, field, ctx, arg) => arg ?? null,
  // Generalization: replace a numeric value with a fixed-size bucket range.
  // Deterministic so the transformed output is recomputable by an assessor.
  aggregate: (value, field, ctx, arg) => {
    if (value === null || value === undefined) return null;
    const size = Number.isSafeInteger(arg) && arg > 0 ? arg : 100;
    const n = Number(value); if (!Number.isFinite(n)) return null;
    const lo = Math.floor(n / size) * size; return `${lo}-${lo + size - 1}`;
  }
};
export function applyTransforms(rows, transforms, ctx) {
  // transforms: {column: {op, arg?}} — returns new rows; never mutates source.
  return rows.map(row => Object.fromEntries(Object.entries(row).map(([k, v]) => {
    const t = transforms[k];
    return [k, t ? TRANSFORMS[t.op](v, k, ctx, t.arg) : v];
  })));
}

// DAT-011: per-row attribution watermark. The mark is an HMAC over the row's
// authorised identity, request and content so a leaked row is attributable
// without altering source data.
export function watermark(rows, ctx) {
  const key = Buffer.from(ctx.tenantWatermarkKey, 'base64url');
  // Row identity falls back to a full-row digest so exports lacking an 'id'
  // column are still attributable per record (runtime-audit F-3).
  const marks = rows.map(row => ({ row_id: row.id ?? `digest:${digest(row).slice(0, 24)}`, tag: createHmac('sha256', key).update(canonical({ dataset: ctx.dataset, subject: ctx.subject, request_id: ctx.requestId, row })).digest('hex').slice(0, 24) }));
  return { rows, watermarks: marks };
}

// DAT-009: cumulative reconstruction control. Counts distinct rows and
// columns a subject has touched per dataset inside the window; crossing the
// configured coverage threshold produces a budget denial plus an audit signal.
export function reconstructionCheck(touchDb, catalogDb, { tenant, subject, dataset, rows, columns, now, policy }) {
  // Touch records live on the fabric store's transaction so a rolled-back
  // consume cannot leave phantom access rows (cross-DB atomicity, M2).
  // Counts are computed PROSPECTIVELY before writing: a denied attempt
  // records nothing — the ledger measures disclosure, not probing, and a
  // rejection must not ratchet coverage toward self-DoS (w6-fix F6).
  const window = policy.window_ms ?? 86400000;
  const touched = touchDb.prepare('SELECT row_id, column_name FROM data_access WHERE tenant=? AND subject=? AND dataset=? AND at>?').all(tenant, subject, dataset, now - window);
  const rowSet = new Set(touched.map(x => x.row_id));
  const colSet = new Set(touched.map(x => x.column_name));
  for (const r of rows) rowSet.add(r);
  for (const c of columns) colSet.add(c);
  const rowCount = rowSet.size, colCount = colSet.size;
  const totalRows = catalogDb.prepare('SELECT count(*) AS n FROM dataset_rows WHERE tenant=? AND dataset=?').get(tenant, dataset).n;
  const coveragePercent = totalRows ? Math.floor((rowCount * 100) / totalRows) : 0;
  const limits = policy ?? { max_distinct_rows: 100000, max_distinct_columns: 100000, max_coverage_percent: 100 };
  if (rowCount > limits.max_distinct_rows || colCount > limits.max_distinct_columns || coveragePercent > limits.max_coverage_percent) {
    return { allowed: false, code: 'INV-429-BUDGET', row_count: rowCount, column_count: colCount, coverage_percent: coveragePercent };
  }
  const ins = touchDb.prepare('INSERT INTO data_access VALUES(?,?,?,?,?,?)');
  for (const row of rows) for (const c of columns) ins.run(tenant, subject, dataset, row, c, now);
  return { allowed: true, row_count: rowCount, column_count: colCount, coverage_percent: coveragePercent };
}
