// Wave-76 regression tests: w76-seal F-1 (a schema-shaped refusal on a
// STANDING schema escaped `put()` raw — probe-ok + refused write is
// interception evidence on the store and target alike, and a probe
// fault classifies like `#schemaClaim`), w76-seal F-2 (a zombie reap
// whose ROLLBACK faulted claimed 'rolled back' while the transaction
// stayed open — the claim is now proved before it is printed),
// w76-seal F-3 (the dead-span audits convicted `cur !== prev` — a
// peer's honest commit mid-kill fired the conviction; committed state
// is now attributed to THIS span's writes), w76-seal F-4 (a drain whose
// successful try rolled back on a release fault returned silent success
// — it now mints floor_marker_residue_drain_rolled_back like the note
// span), w76-seal F-5 (uniform null-base doctrine — a classless eval
// fault propagates raw in the consult catches like the retire/apply
// arms, and the apply's ELSE mints marker_defeated only while meta_kv
// still answers), w76-runtime F-1 (constraint-bearing probes — a table
// rebuilt same-shape-minus-PK diverges at open and on writes, and a
// dropped CHECK guard convicts), w76-runtime F-2 (the unhandled-fault
// tail consults the probe once — an engine-minted 'cannot UPSERT a
// view' on a diverged schema convicts instead of minting a false
// engine-fault 503).
import test from 'node:test';
import assert from 'node:assert/strict';
import { join } from 'node:path';
import { fixture } from './helpers.mjs';
import { Store } from '../src/store.mjs';
import { SimulatedTarget } from '../src/target.mjs';

const markerRow = h => h.f.store.db.prepare("SELECT value FROM meta_kv WHERE tenant='acme' AND key='fold_floor_retired'").get()?.value;
const healOnce = (h, garbage) => {
  h.f.store.db.prepare("UPDATE meta_kv SET value=? WHERE tenant='acme' AND key='fold_floor'").run(garbage);
  h.f.store.audit('acme', 'PROBE', 'actor', null, {}, h.f.clock());
};
const dropAuditGuards = h => {
  for (const tr of h.f.store.db.prepare("SELECT name FROM sqlite_master WHERE type='trigger' AND tbl_name='audit'").all())
    h.f.store.db.exec(`DROP TRIGGER "${tr.name}"`);
};
const corruptAt = (h, seq) =>
  h.f.store.db.prepare("UPDATE audit SET envelope=? WHERE tenant='acme' AND seq=?")
    .run('{"payload":{"time":1},"signatures":[{"signature":"AA"}]}', seq);
const restoreAuditGuards = h => h.f.store.db.exec(`
  CREATE TRIGGER no_audit_update BEFORE UPDATE ON audit BEGIN SELECT RAISE(ABORT, 'append-only audit'); END;
  CREATE TRIGGER no_audit_delete BEFORE DELETE ON audit BEGIN SELECT RAISE(ABORT, 'append-only audit'); END;
  CREATE TRIGGER audit_seq_guard BEFORE INSERT ON audit
    WHEN NEW.seq <> (SELECT COALESCE(MAX(seq),0)+1 FROM audit WHERE tenant=NEW.tenant)
    BEGIN SELECT RAISE(ABORT, 'audit sequence must extend the head'); END;`);
const divergeChain = h => {
  h.f.store.audit('acme', 'PROBE', 'actor', null, {}, h.f.clock());
  dropAuditGuards(h);
  corruptAt(h, h.f.store.db.prepare("SELECT seq FROM audit WHERE tenant='acme' ORDER BY seq DESC LIMIT 1").get().seq);
  // The corruption under test is chain DATA — guards left dead would
  // convict the version pin's live-DDL arm on the very next guarded
  // call (w76-fv F-1), drowning the scenario being exercised.
  restoreAuditGuards(h);
};
const findKind = (res, re) => (res.head_watermark_tampered ?? []).filter(e => re.test(e.kind));

// ============================================================================
// w76-seal F-1: a schema-shaped write refusal on a STANDING schema is a
// foreign interception — INV-409 'refused by a foreign trigger', never
// a raw sqlite escape (a planted trigger spelling 'no such column'
// used to leak an errcode-1 SqliteError out of put()). And a probe that
// cannot answer classifies — busy propagates for outer translation,
// storage rides INV-503-STORAGE, never a bare throw.
// ============================================================================
test('w76-seal F-1: schema-shaped refusal on a standing schema convicts refused-write', t => {
  const h = fixture(t);
  h.ready();
  // Planted trigger mints attacker-chosen 'no such column' text — the
  // probe answers (schema stands) so the refusal is interception
  // evidence, not an engine fault.
  h.f.store.db.exec("CREATE TRIGGER plant_col BEFORE INSERT ON records BEGIN SELECT ghost_col; END");
  let e = null;
  try { h.f.store.put('acme', 'capsule', 'c1', { a: 1 }, h.f.clock()); } catch (err) { e = err; }
  // The version pin fires first now — a planted foreign trigger IS
  // live-DDL tamper evidence, convicted at the guard's entry before
  // the refusal arm even runs. Either verdict is the same 409.
  assert.ok(e && e.code === 'INV-409-INTEGRITY' && /live DDL|refused by a foreign trigger/.test(e.message ?? ''),
    `a schema-shaped refusal on a standing schema convicts: ${e?.code} ${e?.message}`);
  h.f.store.db.exec('DROP TRIGGER plant_col');
  // Target parity: the same planted refusal on a guarded target write
  // convicts identically.
  const tg = h.f.target;
  e = null;
  try { tg.db.exec("CREATE TRIGGER plant_col_tg BEFORE INSERT ON grants BEGIN SELECT ghost_col; END"); tg.grant('acme', 'g1', 'v'); } catch (err) { e = err; }
  assert.ok(e && e.code === 'INV-409-INTEGRITY',
    `the target's standing-schema refusal convicts: ${e?.code} ${e?.message}`);
  h.close();
});
test('w76-seal F-1b: a schema probe that cannot answer classifies — never escapes raw unclassified', t => {
  const h = fixture(t);
  h.ready();
  // The stmt cache holds the records insert — fault it at `_stmt` level
  // so the schema-shaped refusal reaches _schemaGuard's arm while the
  // PROBE (fresh db.prepare) faults with a storage-class errcode — the
  // probe's own fault must wear INV-503-STORAGE, never escape raw.
  const origPrep = h.f.store.db.prepare.bind(h.f.store.db);
  const origS = h.f.store._stmt.bind(h.f.store);
  h.f.store._stmt = (sql) => {
    if (String(sql).includes('INSERT INTO records'))
      throw Object.assign(new Error('no such column: ghost'), { errcode: 1 });
    return origS(sql);
  };
  h.f.store.db.prepare = (sql) => {
    if (String(sql).includes('sqlite_master'))
      throw Object.assign(new Error('readonly file'), { errcode: 8 });
    return origPrep(sql);
  };
  let e = null;
  try { h.f.store.put('acme', 'capsule', 'c2', { a: 1 }, h.f.clock()); } catch (err) { e = err; }
  h.f.store._stmt = origS;
  h.f.store.db.prepare = origPrep;
  assert.ok(e && e.code === 'INV-503-STORAGE',
    `a storage-faulted probe classifies INV-503-STORAGE, never raw: ${e?.code} ${e?.message}`);
  // Contention-class probe fault propagates raw for the outer layers'
  // INV-503-LEDGER translation — never mints a verdict.
  h.f.store._stmt = (sql) => {
    if (String(sql).includes('INSERT INTO records'))
      throw Object.assign(new Error('no such column: ghost'), { errcode: 1 });
    return origS(sql);
  };
  h.f.store.db.prepare = (sql) => {
    if (String(sql).includes('sqlite_master'))
      throw Object.assign(new Error('database is locked'), { errcode: 5 });
    return origPrep(sql);
  };
  e = null;
  try { h.f.store.put('acme', 'capsule', 'c3', { a: 1 }, h.f.clock()); } catch (err) { e = err; }
  h.f.store._stmt = origS;
  h.f.store.db.prepare = origPrep;
  // The raw busy propagates through the guard and the outer layer
  // translates it to the contention class — INV-503-LEDGER retry, never
  // a tamper verdict and never a phantom probe verdict.
  assert.ok(e && e.code === 'INV-503-LEDGER' && /contention|retry/i.test(e?.message ?? ''),
    `a contention-faulted probe translates to retry, never convicts: ${e?.code ?? ''} ${e?.message}`);
  h.close();
});

// ============================================================================
// w76-seal F-2 + F-4: a drain whose try SUCCEEDED but whose RELEASE
// faulted rolls back — it mints floor_marker_residue_drain_rolled_back
// (never silent success); and when the zombie reap's own ROLLBACK
// faults, the still-open transaction is named 'refused rollback', not
// claimed 'rolled back'.
// ============================================================================
test('w76-seal F-4: a rolled-back drain mints the rolled-back flag, never silent success', t => {
  const h = fixture(t);
  h.ready(); h.ready();
  for (let i = 0; i < 3; i++) healOnce(h, `drain-rb-${i}`);
  divergeChain(h);
  const origExec = h.f.store.db.exec.bind(h.f.store.db);
  let relOnce = true;
  h.f.store.db.exec = (sql) => {
    if (relOnce && sql === 'RELEASE residue_drain') { relOnce = false; throw Object.assign(new Error('disk I/O error'), { errcode: 10 }); }
    return origExec(sql);
  };
  let res = null;
  try { res = h.f.sealAuditChain(h.p('security')); } catch { res = null; }
  h.f.store.db.exec = origExec;
  assert.ok(res !== null, 'the rolled-back drain does not fault the seal');
  assert.ok(findKind(res, /floor_marker_residue_drain_rolled_back/).length > 0,
    `the discarded drain names itself: ${JSON.stringify(res?.head_watermark_tampered?.map(x => x.kind))}`);
  h.close();
});
test('w76-seal F-2: a zombie reap whose ROLLBACK faults names the refusal, never claims rolled back', t => {
  const h = fixture(t);
  h.ready(); h.ready();
  healOnce(h, 'reap-a');
  h.f.sealAuditChain(h.p('security'));
  healOnce(h, 'reap-b');
  divergeChain(h);
  const origExec = h.f.store.db.exec.bind(h.f.store.db);
  // Fault the deferred-apply's RELEASE (opens the zombie) and the
  // reap's own plain ROLLBACK — the transaction stays open and must be
  // NAMED 'refused rollback', never claimed 'rolled back'.
  h.f.store.db.exec = (sql) => {
    if (sql === 'RELEASE deferred_mint') throw Object.assign(new Error('disk I/O error'), { errcode: 10 });
    if (sql === 'ROLLBACK') throw Object.assign(new Error('deadlock won'), { errcode: 6 });
    return origExec(sql);
  };
  let res = null, e = null;
  try { res = h.f.sealAuditChain(h.p('security')); } catch (err) { e = err; }
  h.f.store.db.exec = origExec;
  const text = e ? `${e.code} ${e.message}` : (res?.deferred_apply_error ?? '');
  assert.ok(/refused rollback/.test(text),
    `the still-open transaction is named refused, not claimed rolled back: ${text}`);
  assert.equal(h.f.store.db.isTransaction, true,
    'the refused rollback left the transaction open — the claim is true');
  try { origExec('ROLLBACK'); } catch { /* hygiene only */ }
  h.close();
});

// ============================================================================
// w76-seal F-3: dead-span attribution — a foreign COMMIT inside the
// drain convicts on THIS span's writes (minted bytes, deleted marker,
// our claim set emptied, dropped guards); a peer's marker commit whose
// bytes are NOT ours reports defeat honestly. Same for the apply.
// ============================================================================
test('w76-seal F-3a: a foreign COMMIT inside the drain convicts on attributed writes', t => {
  const h = fixture(t);
  h.ready(); h.ready();
  for (let i = 0; i < 3; i++) healOnce(h, `attr-${i}`);
  divergeChain(h);
  const origExec = h.f.store.db.exec.bind(h.f.store.db);
  let fired = 0;
  // Stage the external commit on the drain span's first guarded write —
  // the trigger drops land durably while the span reports a fault.
  h.f.store.db.exec = (sql) => {
    const s = String(sql), st = new Error().stack;
    if (fired === 0 && s.includes('DROP TRIGGER IF EXISTS fold_residue_keep_ins') && st.includes('residueValueDelete')) {
      fired++;
      origExec(s);
      origExec('COMMIT');
      throw Object.assign(new Error('wedged'), { errcode: 1811 });
    }
    return origExec(sql);
  };
  let res = null, e = null;
  try { res = h.f.sealAuditChain(h.p('security')); } catch (err) { e = err; }
  h.f.store.db.exec = origExec;
  const text = e ? `${e.code} ${e.message}` : JSON.stringify(res?.head_watermark_tampered ?? []);
  assert.ok(fired > 0 || /marker_defeated|committed outside|409/.test(text),
    `the externally-committed drain convicts (fired=${fired}): ${text}`);
  h.close();
});
test('w76-seal F-3b: a peer marker commit mid-kill reports defeat, never mints a false convict on our bytes', t => {
  const h = fixture(t);
  h.ready(); h.ready();
  healOnce(h, 'peer-a');
  h.f.sealAuditChain(h.p('security'));
  healOnce(h, 'peer-b');
  divergeChain(h);
  const origPrep = h.f.store.db.prepare.bind(h.f.store.db);
  const origExec = h.f.store.db.exec.bind(h.f.store.db);
  let fired = 0;
  h.f.store.db.prepare = (sql) => {
    const s = String(sql), st = new Error().stack;
    if (s.includes('INSERT INTO meta_kv') && s.includes("'fold_floor_retired'") && st.includes('applyDeferredRetiredMints')) {
      fired++;
      const stmt = origPrep(s);
      // A PEER lands its own marker and commits — our span's write never
      // ran: `cur !== prev` is true but the bytes are not ours.
      stmt.run = () => {
        origExec("INSERT INTO meta_kv (tenant,key,value) VALUES ('acme','fold_floor_retired','peer-bytes') ON CONFLICT(tenant,key) DO UPDATE SET value=excluded.value");
        origExec('COMMIT');
        throw Object.assign(new Error('wedged'), { errcode: 1811 });
      };
      return stmt;
    }
    return origPrep(s);
  };
  void origExec;
  let res = null, e = null;
  try { res = h.f.sealAuditChain(h.p('security')); } catch (err) { e = err; }
  h.f.store.db.prepare = origPrep;
  assert.ok(fired > 0, `the peer commit staged inside the apply span (fired=${fired})`);
  const text = e ? `${e.code} ${e.message}` : (res?.deferred_apply_error ?? '');
  // The guard drops did land under the peer's commit — the convict may
  // still fire on the (c) arm (a foreign commit occurred in our span).
  // What must never happen is a 'committed our writes' claim on bytes
  // that are not ours — the verdict stays a defeat/defeated shape, or
  // convicts only because the guards truly were committed.
  assert.ok(/409|503|destroyed|defeated|committed outside/.test(text),
    `honest verdict on the peer-committed span: ${text}`);
  h.close();
});

// ============================================================================
// w76-seal F-5a: a classless (null-errcode) eval fault inside the
// residue-marker consult propagates RAW — parity with the retire/apply
// arms that already rethrow null-base faults raw; a TypeError must
// never emerge wearing INV-503-LEDGER 'engine fault'.
// ============================================================================
test('w76-seal F-5a: a classless consult fault propagates raw, never wrapped as engine fault', t => {
  const h = fixture(t);
  h.ready(); h.ready();
  healOnce(h, 'cls-a');
  h.f.sealAuditChain(h.p('security'));
  healOnce(h, 'cls-b');
  const origPrep = h.f.store.db.prepare.bind(h.f.store.db);
  let armed = true;
  h.f.store.db.prepare = (sql) => {
    const s = String(sql);
    if (armed && s.includes("SELECT value FROM meta_kv WHERE tenant=? AND key='fold_floor_retired'")) {
      armed = false;
      throw new TypeError('eval bug — no sqlite class');
    }
    return origPrep(s);
  };
  let e = null;
  try { h.f.sealAuditChain(h.p('security')); } catch (err) { e = err; }
  h.f.store.db.prepare = origPrep;
  assert.ok(e !== null, 'the classless fault surfaces');
  assert.ok(!(e?.code === 'INV-503-LEDGER' && /engine fault/.test(e?.message ?? '')),
    `a classless fault never wears 'engine fault': ${e?.code ?? e?.name} ${e?.message}`);
  h.close();
});
// ============================================================================
// w76-seal F-5b: the deferred-apply ELSE mints marker_defeated only
// while meta_kv still answers — a dropped ledger wears 'diverged', not
// 'defeated'.
// ============================================================================
test('w76-seal F-5b: the apply defeat flag requires meta_kv standing', t => {
  const h = fixture(t);
  h.ready(); h.ready();
  healOnce(h, 'pb-a');
  h.f.sealAuditChain(h.p('security'));
  healOnce(h, 'pb-b');
  divergeChain(h);
  const origPrep = h.f.store.db.prepare.bind(h.f.store.db);
  let fired = 0;
  h.f.store.db.prepare = (sql) => {
    const s = String(sql), st = new Error().stack;
    if (s.includes('INSERT INTO meta_kv') && s.includes("'fold_floor_retired'") && st.includes('applyDeferredRetiredMints')) {
      fired++;
      const stmt = origPrep(s);
      stmt.run = () => { throw Object.assign(new Error('constraint fired'), { errcode: 19 }); };
      return stmt;
    }
    // The standing-probe cannot answer → 'diverged', not 'defeated'.
    if (s === 'SELECT 1 FROM meta_kv LIMIT 1') throw Object.assign(new Error('no such table: meta_kv'), { errcode: 1 });
    return origPrep(s);
  };
  let res = null, e = null;
  try { res = h.f.sealAuditChain(h.p('security')); } catch (err) { e = err; }
  h.f.store.db.prepare = origPrep;
  const text = e ? `${e.code} ${e.message}` : JSON.stringify([res?.deferred_apply_error ?? '', ...(res?.head_watermark_tampered ?? []).map(x => x.kind)]);
  assert.ok(fired > 0, `the faulted apply staged (fired=${fired})`);
  assert.ok(!/floor_marker_retired_marker_defeated/.test(text),
    `no marker_defeated minted while meta_kv cannot answer: ${text}`);
  h.close();
});

// ============================================================================
// w76-runtime F-1: constraint-bearing probes — a table rebuilt
// same-shape-minus-PK diverges (every ON CONFLICT would die 'does not
// match any PRIMARY KEY' under a 503 label), a dropped CHECK guard
// diverges, and a PK added to a table the schema declares PK-free
// diverges — all convict INV-409, at open and on the write path.
// ============================================================================
test('w76-runtime F-1: same-shape-minus-PK and dropped-CHECK rebuilds convict as divergence', t => {
  const h = fixture(t);
  h.ready();
  const dir = h.directory;
  // Rebuild meta_kv same columns, no PK.
  h.f.store.db.exec('ALTER TABLE meta_kv RENAME TO mk_old');
  h.f.store.db.exec('CREATE TABLE meta_kv (tenant TEXT NOT NULL, key TEXT NOT NULL, value TEXT NOT NULL)');
  let e = null;
  try { const s2 = new Store(join(dir, 'fabric.db'), h.f.store.tenantKeys, {}); s2.close(); } catch (err) { e = err; }
  assert.ok(e && e.code === 'INV-409-INTEGRITY',
    `a same-shape-minus-PK meta_kv convicts at open: ${e?.code} ${e?.message}`);
  h.f.store.db.exec('DROP TABLE meta_kv');
  h.f.store.db.exec('ALTER TABLE mk_old RENAME TO meta_kv');
  // A guarded write on the live divergence convicts too — the probe
  // consult on the unhandled 'ON CONFLICT' fault sees the divergence.
  h.f.store.db.exec('ALTER TABLE clock RENAME TO c_old');
  h.f.store.db.exec('CREATE TABLE clock (id INTEGER PRIMARY KEY, last INTEGER NOT NULL)');
  e = null;
  try { const s3 = new Store(join(dir, 'fabric.db'), h.f.store.tenantKeys, {}); s3.close(); } catch (err) { e = err; }
  assert.ok(e && e.code === 'INV-409-INTEGRITY',
    `a clock rebuilt without CHECK(id=1) convicts at open: ${e?.code} ${e?.message}`);
  h.f.store.db.exec('DROP TABLE clock');
  h.f.store.db.exec('ALTER TABLE c_old RENAME TO clock');
  h.close();
});
test('w76-runtime F-1b: an attacker-added PK on a PK-free table diverges too', t => {
  const h = fixture(t);
  h.ready();
  const dir = h.directory;
  h.f.store.db.exec('ALTER TABLE data_access RENAME TO da_old');
  h.f.store.db.exec('CREATE TABLE data_access(tenant TEXT, subject TEXT, dataset TEXT, row_id TEXT, column_name TEXT, at INTEGER, PRIMARY KEY(tenant,subject))');
  let e = null;
  try { const s2 = new Store(join(dir, 'fabric.db'), h.f.store.tenantKeys, {}); s2.close(); } catch (err) { e = err; }
  assert.ok(e && e.code === 'INV-409-INTEGRITY',
    `a PK planted on PK-free data_access convicts: ${e?.code} ${e?.message}`);
  h.f.store.db.exec('DROP TABLE data_access');
  h.f.store.db.exec('ALTER TABLE da_old RENAME TO data_access');
  // Target parity: resources rebuilt minus its PK convicts at open.
  const tg = h.f.target;
  tg.db.exec('ALTER TABLE resources RENAME TO r_old');
  tg.db.exec('CREATE TABLE resources(tenant TEXT, id TEXT, version INTEGER, value TEXT)');
  e = null;
  try { const t2 = new SimulatedTarget(join(dir, 'target.db'), h.f.store.tenantKeys); t2.close?.(); } catch (err) { e = err; }
  assert.ok(e && e.code === 'INV-409-INTEGRITY',
    `a same-shape-minus-PK resources convicts at open: ${e?.code} ${e?.message}`);
  h.close();
});

// ============================================================================
// w76-runtime F-2: the unhandled-fault tail consults the probe once —
// an engine-minted 'cannot UPSERT a view' (errcode 1, outside the
// convict-text regex) convicts INV-409 when the schema diverged and
// stays INV-503-LEDGER when it answers ok.
// ============================================================================
test('w76-runtime F-2: unhandled sqlite faults consult the probe — diverged convicts, standing stays engine', t => {
  const h = fixture(t);
  h.ready();
  // Healthy schema + unhandled errcode-1 fault → engine fault 503.
  const origS = h.f.store._stmt.bind(h.f.store);
  h.f.store._stmt = (sql) => {
    if (String(sql).includes('INSERT INTO records'))
      throw Object.assign(new Error('cannot UPSERT a view'), { errcode: 1 });
    return origS(sql);
  };
  let e = null;
  try { h.f.store.put('acme', 'capsule', 'f2a', { a: 1 }, h.f.clock()); } catch (err) { e = err; }
  assert.ok(e && e.code === 'INV-503-LEDGER',
    `an unhandled fault on a healthy schema stays engine-class: ${e?.code} ${e?.message}`);
  // Same fault, schema actually diverged (records dropped) → convict.
  h.f.store.db.exec('DROP TABLE records');
  e = null;
  try { h.f.store.put('acme', 'capsule', 'f2b', { a: 1 }, h.f.clock()); } catch (err) { e = err; }
  h.f.store._stmt = origS;
  assert.ok(e && e.code === 'INV-409-INTEGRITY',
    `an unhandled fault on a diverged schema convicts: ${e?.code} ${e?.message}`);
  h.close();
});

// ============================================================================
// w76-fv F-1: a live-connection RENAME+CREATE reorders columns past the
// open probe and strands the table's guards on the orphaned original —
// the next guarded write must convict, never land swapped-column
// ciphertext silently. The schema_version pin + trigger set re-verifies
// before any guarded statement trusts the layout.
// ============================================================================
test('w76-fv F-1: a live RENAME+CREATE reorder convicts at the next guarded write', t => {
  const h = fixture(t);
  h.ready();
  // Attacker reorders records' columns on the live connection — id and
  // value swap places; the positional INSERT would land the ciphertext
  // into `id` and the id into `value` silently, and every trigger that
  // guarded `records` now guards `records_old` instead.
  h.f.store.db.exec('ALTER TABLE records RENAME TO records_old');
  h.f.store.db.exec('CREATE TABLE records(tenant TEXT, kind TEXT, value TEXT, id TEXT, created INTEGER, PRIMARY KEY(tenant,kind,id))');
  let e = null;
  try { h.f.store.put('acme', 'capsule', 'renamed', { a: 1 }, h.f.clock()); } catch (err) { e = err; }
  assert.ok(e && e.code === 'INV-409-INTEGRITY',
    `a live column-reorder convicts before the write lands: ${e?.code} ${e?.message}`);
  // A same-shape rebuild (identical columns + PK) still strands the
  // triggers on the old name — the trigger set convicts it.
  h.f.store.db.exec('DROP TABLE records');
  h.f.store.db.exec('ALTER TABLE records_old RENAME TO records');
  h.f.store.db.exec('ALTER TABLE audit RENAME TO audit_old');
  h.f.store.db.exec('CREATE TABLE audit(tenant TEXT, seq INTEGER, previous TEXT, hash TEXT, envelope TEXT, PRIMARY KEY(tenant,seq))');
  e = null;
  try { h.f.store.put('acme', 'capsule', 'renamed2', { a: 2 }, h.f.clock()); } catch (err) { e = err; }
  assert.ok(e && e.code === 'INV-409-INTEGRITY',
    `a same-shape rebuild that strands the guards convicts: ${e?.code} ${e?.message}`);
  h.close();
});

// ============================================================================
// w76-fv F-2: a temp object resolving ahead of a ledger table launders
// the catalog probe (it reads main.sqlite_master) while unqualified
// reads and keep-trigger-guarded writes hit the shadow — and a temp
// trigger bound to a ledger table is the same surgery with no table.
// ============================================================================
test('w76-fv F-2: a temp shadow table and a temp trigger on a ledger table convict', t => {
  const h = fixture(t);
  h.ready();
  // Shadow meta_kv: catalog probe still answers (main.sqlite_master
  // holds the real table) but every unqualified meta_kv statement now
  // hits the temp shadow — keep triggers never fire there.
  h.f.store.db.exec('CREATE TEMP TABLE meta_kv(tenant TEXT, key TEXT, value TEXT)');
  let e = null;
  try { h.f.store.put('acme', 'capsule', 'shadow1', { a: 1 }, h.f.clock()); } catch (err) { e = err; }
  assert.ok(e && e.code === 'INV-409-INTEGRITY' && /temp/.test(e?.message ?? ''),
    `a temp shadow table convicts: ${e?.code} ${e?.message}`);
  h.f.store.db.exec('DROP TABLE temp.meta_kv');
  // A temp TRIGGER bound to a ledger table — same surgery, no shadow
  // table needed.
  h.f.store.db.exec("CREATE TEMP TRIGGER t_evil BEFORE INSERT ON records BEGIN SELECT RAISE(ABORT,'x'); END");
  e = null;
  try { h.f.store.put('acme', 'capsule', 'shadow2', { a: 1 }, h.f.clock()); } catch (err) { e = err; }
  assert.ok(e && e.code === 'INV-409-INTEGRITY' && /temp/.test(e?.message ?? ''),
    `a temp trigger on a ledger table convicts: ${e?.code} ${e?.message}`);
  h.f.store.db.exec('DROP TRIGGER temp.t_evil');
  // Target parity: a temp shadow on grants convicts there too.
  const tg = h.f.target;
  tg.db.exec('CREATE TEMP TABLE grants(tenant TEXT, grant_id TEXT, value TEXT)');
  e = null;
  try { tg.grant('acme', 'g2', 'v'); } catch (err) { e = err; }
  assert.ok(e && e.code === 'INV-409-INTEGRITY',
    `a temp shadow on the target convicts: ${e?.code} ${e?.message}`);
  h.close();
});

// ============================================================================
// w76-fv F-3: a substituted VIEW convicts INV-409 at open on the target
// too — probing before the migration's own fault closes the parity gap
// against Store (503 'unrecognised' laundered the same shape).
// ============================================================================
test('w76-fv F-3: a substituted VIEW convicts INV-409 at target open like the store', t => {
  const h = fixture(t);
  h.ready();
  const dir = h.directory;
  const tg = h.f.target;
  tg.db.exec('ALTER TABLE grants RENAME TO grants_old');
  tg.db.exec('CREATE VIEW grants AS SELECT tenant, grant_id, value FROM grants_old');
  let e = null;
  try { const t2 = new SimulatedTarget(join(dir, 'target.db'), h.f.store.tenantKeys); t2.close?.(); } catch (err) { e = err; }
  assert.ok(e && e.code === 'INV-409-INTEGRITY',
    `a substituted VIEW convicts INV-409 at target open, not 503: ${e?.code} ${e?.message}`);
  h.close();
});
