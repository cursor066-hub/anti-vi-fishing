export function nextAction(status) {
  return ({ CANONICALISED: 'Attach independently signed evidence, then evaluate.', EVIDENCED: 'Evaluate the exact evidence set and collect eligible approvals.', ALLOW: 'Mint the single-use certificate before its evidence or approval expires.', ESCROW: 'Resolve the listed evidence or approval gaps, then re-evaluate.', SHIELD: 'Create a new proposal with the specified field removal; this action cannot execute.', DEFER: 'Wait until the mandatory condition is met, then re-evaluate.', DENY: 'This action is permanently denied. Investigate the reason; any revised request needs a new capsule.', CERTIFIED: 'Dry-run the gate or execute the exact reviewed change before expiry.', EXECUTING: 'Reconcile the durable transaction. Never blindly repeat the mutation.', UNCERTAIN: 'Reconcile the target journal. Do not submit a replacement until the operator resolves uncertainty.', VERIFIED: 'The observed synthetic outcome matches the authorised action. No repeat execution is allowed.', FAILED: 'The target rejected execution. Inspect state before creating any separately authorised replacement.', CANCELLED: 'The action is closed. Its prior authority cannot execute.' })[status] ?? 'Inspect the current state before continuing.';
}
export function actionAvailability(status, roles) {
  const mutable = !['DENY', 'CANCELLED', 'CERTIFIED', 'EXECUTING', 'VERIFIED', 'UNCERTAIN', 'FAILED'].includes(status);
  const can = (...r) => r.some(x => roles.includes(x));
  return { evaluate: mutable && can('operator', 'policy_admin', 'approver', 'custodian'), mint: mutable && status === 'ALLOW' && can('operator', 'policy_admin'), evidence: mutable && can('operator', 'security', 'policy_admin'), approval: mutable && can('approver', 'custodian'), execute: status === 'CERTIFIED' && can('operator', 'policy_admin'), reconcile: ['EXECUTING', 'UNCERTAIN', 'VERIFIED', 'FAILED'].includes(status) && can('operator', 'security', 'policy_admin'), cancel: !['EXECUTING', 'UNCERTAIN', 'VERIFIED', 'FAILED', 'CANCELLED'].includes(status) && can('operator', 'security', 'policy_admin') };
}
export function typedValue(value, rule) {
  if (rule === 'positive') { if (!/^[1-9][0-9]*$/.test(value) || !Number.isSafeInteger(Number(value))) throw new Error('Enter a positive integer without decimals or exponent notation.'); return Number(value); }
  if (!value.trim()) throw new Error('Complete all required action fields.'); return value;
}
export function csvSelection(value) { const items = value.split(',').map(x => x.trim()).filter(Boolean); if (!items.length || new Set(items).size !== items.length) throw new Error('Provide a nonempty list without duplicates.'); return items; }
export function fieldsMap(value) { const out = {}; for (const pair of csvSelection(value)) { const i = pair.indexOf('='); if (i <= 0) throw new Error('Enter fields as name=value pairs, comma-separated.'); out[pair.slice(0, i).trim()] = pair.slice(i + 1).trim(); } return out; }
export function formatQuantity(c) { if (c.action.type === 'finance.payment.first') return `${c.requested_state.currency} ${(c.quantity / 100).toFixed(2)} (${c.quantity} minor units)`; return `${c.quantity} unit${c.quantity === 1 ? '' : 's'}`; }
// Exact in-browser replica of src/canonical.mjs (IF-CJSON-1): NFC strings,
// ASCII object keys, safe integers only, sorted keys, strict key charset.
export function canonicalJson(value, depth = 0) {
  if (depth > 32) throw new Error('Maximum nesting depth exceeded');
  if (value === null || typeof value === 'boolean') return JSON.stringify(value);
  if (typeof value === 'number') { if (!Number.isSafeInteger(value) || Object.is(value, -0)) throw new Error('Only safe non-negative-zero integers are supported'); return String(value); }
  if (typeof value === 'string') { if (value !== value.normalize('NFC') || /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/u.test(value)) throw new Error('Strings must be valid NFC Unicode'); if (value.length > 65536) throw new Error('String too long'); return JSON.stringify(value); }
  if (Array.isArray(value)) { if (value.length > 10000) throw new Error('Array too long'); return '[' + value.map(v => canonicalJson(v, depth + 1)).join(',') + ']'; }
  if (value && typeof value === 'object') {
    const keys = Object.keys(value).sort(); if (keys.length > 256) throw new Error('Object too large');
    return '{' + keys.map(k => { if (!/^[A-Za-z0-9_][A-Za-z0-9_.:-]{0,127}$/.test(k) || ['__proto__', 'prototype', 'constructor'].includes(k)) throw new Error('Unsupported object key'); return JSON.stringify(k) + ':' + canonicalJson(value[k], depth + 1); }).join(',') + '}';
  }
  throw new Error('Unsupported canonical value');
}
// Signs an IF-CJSON-1 'capsule-intent' envelope in the browser via WebCrypto
// Ed25519 — identical message bytes to src/crypto.mjs signed(). The private
// key never leaves this page context.
export async function signIntent(payload, keyFile) {
  const protectedHeader = { profile: 'IF-CJSON-1', suite: keyFile.suite ?? 'Ed25519', key_id: keyFile.key_id, purpose: 'capsule-intent' };
  if (protectedHeader.suite !== 'Ed25519') throw new Error('Browser signing supports Ed25519 identity keys; use the CLI signer for ES256.');
  const message = new TextEncoder().encode(canonicalJson({ protected: protectedHeader, payload }));
  const der = Uint8Array.from(atob(keyFile.private_key.replace(/-----[^-]+-----|\s/g, '')), c => c.charCodeAt(0));
  let key;
  try { key = await crypto.subtle.importKey('pkcs8', der, { name: 'Ed25519' }, false, ['sign']); }
  catch { throw new Error('This browser lacks WebCrypto Ed25519 support — sign with the CLI instead.'); }
  const sig = await crypto.subtle.sign({ name: 'Ed25519' }, key, message);
  const b64 = btoa(String.fromCharCode(...new Uint8Array(sig))).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');
  return { protected: protectedHeader, payload, signature: b64 };
}

if (typeof document !== 'undefined') {
  const $ = id => document.getElementById(id);
  const state = { me: null, csrf: null, schemas: [], policy: null, selected: null, currentState: null, currentResource: null, offset: 0, pageCount: 0, runtime: null, identityKey: null };
  function notify(message, error = false) { const el = $('notice'); el.hidden = false; el.textContent = message; el.dataset.error = String(error); if (error) el.setAttribute('role', 'alert'); else el.setAttribute('role', 'status'); }
  async function api(path, { method = 'GET', body, headers = {} } = {}) {
    const response = await fetch(path, { method, credentials: 'same-origin', headers: { ...headers, ...(body === undefined ? {} : { 'Content-Type': 'application/json' }), ...(state.csrf ? { 'X-CSRF-Token': state.csrf } : {}) }, ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
    const value = await response.json();
    if (!response.ok) { if (response.status === 401 && value.error?.code === 'INV-401-AUTH') { state.me = null; state.csrf = null; $('login-panel').hidden = false; $('workspace').hidden = true; $('logout').hidden = true; $('identity').textContent = 'Session expired'; } throw new Error(`${value.error?.code ?? response.status}: ${value.error?.message ?? 'Request failed'}`); }
    return value;
  }
  // Path-segment ids use the identifier alphabet ([A-Za-z0-9_.:-]) —
  // encodeURIComponent percent-escapes ':' which route regexes accept
  // literally, so decode it back or colon-named ids 404 forever
  // (w45-http M-2).
  const pathId = v => encodeURIComponent(v).replaceAll('%3A', ':');
  function handle(id, event, fn) {
    $(id).addEventListener(event, async e => {
      e.preventDefault(); $('notice').hidden = true; const buttons = event === 'submit' ? [...e.currentTarget.querySelectorAll('button')] : [e.currentTarget]; const wasDisabled = buttons.map(b => b.disabled); buttons.forEach(b => { b.disabled = true; b.setAttribute('aria-busy', 'true'); });
      try { await fn(e); } catch (error) { notify(error.message || 'Network unavailable. Retry after checking connection.', true); }
      finally { buttons.forEach((b, i) => { if (b.disabled) b.disabled = wasDisabled[i]; b.removeAttribute('aria-busy'); }); if (state.selected) applyAvailability(); $('previous').disabled = state.offset === 0; $('next').disabled = state.pageCount < 25; }
    });
  }
  function node(tag, value, className) { const n = document.createElement(tag); if (value !== undefined) n.textContent = value; if (className) n.className = className; return n; }
  function show(view) { document.querySelectorAll('.view').forEach(el => { el.hidden = el.id !== `view-${view}`; }); document.querySelectorAll('nav button').forEach(b => { if (b.dataset.view === view) b.setAttribute('aria-current', 'page'); else b.removeAttribute('aria-current'); }); }
  function download(value, filename) { const blob = new Blob([JSON.stringify(value, null, 2)], { type: 'application/json' }), url = URL.createObjectURL(blob), a = document.createElement('a'); a.href = url; a.download = filename; a.click(); setTimeout(() => URL.revokeObjectURL(url), 1000); }
  async function loadList() {
    const page = await api(`/v1/action-capsules?limit=25&offset=${state.offset}`); $('action-rows').replaceChildren();
    for (const r of page.items) {
      const tr = node('tr'), title = node('td', r.capsule.action.type); title.append(node('span', r.capsule.action.target_resource, 'resource')); tr.append(title, node('td', formatQuantity(r.capsule)));
      const status = node('td'), badge = node('span', r.status, 'badge'); badge.dataset.state = r.status; status.append(badge); tr.append(status, node('td', new Date(r.capsule.expires_at).toLocaleString()));
      const cell = node('td'), button = node('button', 'Review exact action', 'secondary'); button.addEventListener('click', () => detail(r.capsule.capsule_id).catch(e => notify(e.message, true))); cell.append(button); tr.append(cell); $('action-rows').append(tr);
    }
    state.pageCount = page.items.length; $('count-total').textContent = page.items.length; $('count-pending').textContent = page.items.filter(x => !['VERIFIED', 'DENY', 'FAILED', 'CANCELLED'].includes(x.status)).length; $('count-verified').textContent = page.items.filter(x => x.status === 'VERIFIED').length;
    $('empty').hidden = page.items.length !== 0; $('previous').disabled = state.offset === 0; $('next').disabled = page.items.length < 25; $('page-label').textContent = `Page ${Math.floor(state.offset / 25) + 1}`;
  }
  function applyAvailability() {
    if (!state.selected || !state.me) return; const available = actionAvailability(state.selected.status, state.me.roles);
    for (const [id, key] of [['evaluate', 'evaluate'], ['mint', 'mint'], ['dry-run', 'execute'], ['execute', 'execute'], ['reconcile', 'reconcile'], ['cancel', 'cancel'], ['challenge', 'approval']]) $(id).disabled = !available[key];
    for (const [id, key] of [['evidence-form', 'evidence'], ['approval-form', 'approval']]) for (const control of $(id).elements) control.disabled = !available[key];
  }
  async function detail(id) {
    const r = await api(`/v1/action-capsules/${id}`); state.selected = r; const c = r.capsule;
    $('detail-title').textContent = c.action.type; $('detail-id').textContent = c.capsule_id; $('detail-status').textContent = r.status; $('detail-status').dataset.state = r.status;
    $('material-details').replaceChildren();
    // UX-009: the coverage row shows this action's own declared path state
    // (enforced/monitored/uncovered), not a static disclaimer — the manifest
    // is vault-signed, so what the console shows is what the gate attested.
    let coverageText;
    try {
      const manifest = (await api('/v1/coverage')).payload;
      const path = (manifest.paths ?? []).find(x => x.action_type === c.action.type && x.target === c.action.target_resource);
      coverageText = path ? `${path.effective_status ?? path.status}${(path.effective_status ?? path.status) !== path.status ? ` (declared ${path.status})` : ''} — ${path.next_action ?? ''}` : 'No declared coverage path for this action';
      if (manifest.guarantee === false) coverageText += ` · manifest: ${manifest.assurance ?? 'no guarantee'}`;
    } catch { coverageText = 'Coverage manifest unavailable'; }
    for (const [key, value] of Object.entries({ Resource: c.action.target_resource, Destination: c.destination, Quantity: formatQuantity(c), Purpose: c.action.purpose, Owner: c.actor.subject_id, Expires: new Date(c.expires_at).toLocaleString(), Exclusions: c.exclusions.join(', ') || 'None', Coverage: coverageText })) $('material-details').append(node('dt', key), node('dd', value));
    $('old-values').textContent = JSON.stringify(c.current_state.material_fields, null, 2); $('new-values').textContent = JSON.stringify(c.requested_state, null, 2); $('next-action').textContent = nextAction(r.status);
    $('decision-reasons').replaceChildren(); for (const reason of r.decision?.reasons ?? []) $('decision-reasons').append(node('p', `${reason.code}: ${reason.message}`, 'help'));
    $('binding-digests').textContent = `Capsule SHA-256: ${r.capsule_digest}\nEvidence: ${r.evidence.length} · Signed approvals: ${r.approvals.length}`;
    $('outcome').hidden = true; applyAvailability(); show('detail');
  }
  function renderRequested() {
    $('requested-fields').replaceChildren(); const schema = state.schemas.find(s => s.type === $('action-type').value); if (!schema) return;
    for (const [key, rule] of Object.entries(schema.requested)) {
      const id = `requested-${key}`, label = node('label', key === 'amount_minor' ? 'Amount in minor currency units (for example cents)' : key.replaceAll('_', ' ')); label.htmlFor = id;
      const input = node('input'); input.id = id; input.name = key; input.required = true; input.dataset.rule = rule;
      if (rule === 'positive') { input.type = 'number'; input.min = '1'; input.step = '1'; input.max = '1000000000000'; } else { input.type = 'text'; input.maxLength = '512'; }
      $('requested-fields').append(label, input);
    }
    state.currentState = null; $('state-preview').textContent = 'Read current target state before creating the proposal.';
  }
  handle('login-form', 'submit', async () => {
    const login = await api('/session', { method: 'POST', body: { token: $('token').value } }); $('token').value = ''; state.csrf = login.csrf_token; state.me = await api('/v1/me');
    $('identity').textContent = `${state.me.tenant_id} / ${state.me.subject_id}`; $('logout').hidden = false; $('login-panel').hidden = true; $('workspace').hidden = false;
    state.schemas = await api('/v1/schemas'); $('action-type').replaceChildren(new Option('Choose action type', '')); for (const s of state.schemas.filter(s => s.type.startsWith('finance.'))) $('action-type').append(new Option(s.type, s.type));
    const has = (...r) => state.me.roles.some(x => r.includes(x));
    // GET /v1/action-capsules permits the auditor read path too — the nav
    // must show the list to exactly the roles the server serves it to.
    const canActions = has('operator', 'approver', 'custodian', 'security', 'policy_admin', 'auditor');
    const admin = has('security', 'policy_admin', 'custodian');
    // Affordances mirror the server's own authorization sets — a nav entry is
    // hidden exactly when every API call under it would 403 (UX-004,
    // w17-console F5: propose includes workload+policy_admin, coverage
    // excludes workload, grants excludes policy_admin).
    const access = { actions: canActions, propose: has('operator', 'workload', 'policy_admin'), coverage: has('operator', 'approver', 'custodian', 'security', 'auditor', 'policy_admin'), policy: has('policy_admin', 'security'), runtime: has('operator', 'workload'), audit: has('auditor', 'security'), keys: has('security', 'policy_admin'), ceremonies: admin, connectors: has('operator', 'security', 'policy_admin', 'auditor'), proofs: has('operator', 'security', 'auditor'), perception: has('operator', 'approver', 'custodian', 'security'), grants: has('operator', 'security', 'auditor') };
    document.querySelectorAll('nav button').forEach(b => { b.hidden = !access[b.dataset.view]; });
    // Per-ACTION affordances inside a visible view must also mirror the
    // server's role set: a button that always 403s is a dishonest
    // affordance (w7-console F3).
    $('rotate-form').hidden = !has('security', 'custodian');
    $('ceremony-form').hidden = !has('security', 'custodian');
    $('ack-form').hidden = !has('custodian');
    $('split-form').hidden = !has('security', 'custodian');
    $('reconstruct-form').hidden = !has('security', 'custodian');
    if (canActions) { show('actions'); await loadList(); }
    // A principal with no list access (e.g. workload) lands on the first
    // view it can actually use — never on 'audit' it cannot read
    // (w17-console F5).
    else { const first = Object.entries(access).find(([, v]) => v)?.[0]; if (first) show(first); }
    notify('Connected to the isolated engineering workspace. Targets and evidence issuers are synthetic.');
  });
  handle('logout', 'click', async () => { await api('/session/logout', { method: 'POST', body: {} }); state.csrf = null; state.me = null; state.selected = null; state.runtime = null; state.currentState = null; location.reload(); });
  document.querySelectorAll('nav button').forEach(button => button.addEventListener('click', async () => { show(button.dataset.view); try { if (button.dataset.view === 'coverage') await loadCoverage(); if (button.dataset.view === 'actions') await loadList(); } catch (e) { notify(e.message, true); } }));
  handle('refresh', 'click', loadList); handle('previous', 'click', async () => { state.offset = Math.max(0, state.offset - 25); await loadList(); }); handle('next', 'click', async () => { state.offset += 25; await loadList(); }); handle('back-actions', 'click', async () => { show('actions'); await loadList(); });
  $('action-type').addEventListener('change', renderRequested); $('resource').addEventListener('input', () => { state.currentState = null; state.currentResource = null; });
  handle('load-state', 'click', async () => { if (!$('resource').checkValidity() || !$('resource').value) throw new Error('Enter a valid target resource identifier.'); const resource = $('resource').value; state.currentState = await api(`/v1/resources/${pathId(resource)}`); state.currentResource = resource; $('state-preview').textContent = JSON.stringify(state.currentState, null, 2); });
  handle('identity-key-file', 'change', async e => {
    const file = e.target.files[0]; if (!file) { state.identityKey = null; return; }
    const key = JSON.parse(await file.text());
    if (typeof key?.private_key !== 'string' || typeof key?.key_id !== 'string' || !key.private_key.includes('PRIVATE KEY')) throw new Error('Select an identity key file generated by bootstrap (identity-<tenant>-<subject>.json).');
    state.identityKey = key; notify(`Identity key ${key.key_id} loaded — the private key stays in this page.`);
  });
  handle('propose-form', 'submit', async () => {
    if (!state.currentState || state.currentResource !== $('resource').value) throw new Error('Read current target state for this exact resource first.');
    const schema = state.schemas.find(s => s.type === $('action-type').value), requested = {}; for (const input of $('requested-fields').querySelectorAll('input')) requested[input.name] = typedValue(input.value, input.dataset.rule);
    const policy = await api('/v1/policy'), now = Date.now(), ttl = typedValue($('ttl').value, 'positive');
    const input = { schema_id: schema.id, schema_digest: schema.digest, actor: { subject_id: state.me.subject_id, identity_class: 'workforce', device_id: state.me.device_id }, action: { type: schema.type, target_resource: $('resource').value, purpose: $('purpose').value }, current_state: state.currentState, requested_state: requested, destination: requested.bank_account, quantity: requested.amount_minor ?? 1, exclusions: [], evidence_refs: [], policy_version: policy.version, nonce: crypto.randomUUID(), created_at: now, expires_at: now + ttl * 60000, rollback_or_compensation: $('rollback').value, privacy_classification: 'confidential' };
    // The API requires a signed capsule-intent envelope: the proposal is
    // signed in-browser via WebCrypto Ed25519 against the loaded identity
    // key file (w17-console F2 — the previous form POSTed the bare capsule
    // and could never succeed).
    if (!state.identityKey) throw new Error('Select your operator identity key file (identity-<tenant>-<subject>.json) — the proposal must be signed in this browser.');
    const envelope = await signIntent(input, state.identityKey);
    const r = await api('/v1/action-capsules', { method: 'POST', body: { input, signature: envelope }, headers: { 'Idempotency-Key': crypto.randomUUID() } }); notify('Immutable proposal created. No target execution has occurred.'); await detail(r.capsule.capsule_id);
  });
  handle('evaluate', 'click', async () => { await api(`/v1/action-capsules/${state.selected.capsule.capsule_id}/evaluate`, { method: 'POST', body: {} }); await detail(state.selected.capsule.capsule_id); });
  handle('mint', 'click', async () => { await api('/v1/certificates', { method: 'POST', body: { capsule_id: state.selected.capsule.capsule_id } }); await detail(state.selected.capsule.capsule_id); notify('Single-use certificate issued. It expires shortly and cannot authorise a different action.'); });
  async function execute(dry) {
    const r = state.selected;
    if (!dry && !window.confirm(`Execute this exact synthetic change?\n${r.capsule.action.type}\nTarget: ${r.capsule.action.target_resource}\nDestination: ${r.capsule.destination}\nQuantity: ${formatQuantity(r.capsule)}\nNo real bank or ERP will be changed.`)) return;
    const certificate = await api(`/v1/certificates/${r.certificate_id}`), result = await api('/gate/v1/execute', { method: 'POST', body: { certificate, dry_run: dry } }); await detail(r.capsule.capsule_id); $('outcome').hidden = false; $('outcome').textContent = JSON.stringify(result, null, 2); notify(dry ? 'Dry-run passed without target mutation.' : `Synthetic outcome: ${result.payload.status}.`);
  }
  handle('dry-run', 'click', () => execute(true)); handle('execute', 'click', () => execute(false));
  handle('reconcile', 'click', async () => { const result = await api(`/gate/v1/outcomes/${state.selected.certificate_id}`, { method: 'POST', body: {} }); await detail(state.selected.capsule.capsule_id); $('outcome').hidden = false; $('outcome').textContent = JSON.stringify(result, null, 2); });
  handle('cancel', 'click', async () => { await api(`/v1/action-capsules/${state.selected.capsule.capsule_id}/cancel`, { method: 'POST', body: {} }); await detail(state.selected.capsule.capsule_id); });
  handle('evidence-form', 'submit', async () => { await api(`/v1/action-capsules/${state.selected.capsule.capsule_id}/evidence`, { method: 'POST', body: JSON.parse($('evidence-json').value) }); $('evidence-json').value = ''; await detail(state.selected.capsule.capsule_id); notify('Signed evidence attached. Earlier approvals were invalidated.'); });
  handle('challenge', 'click', async () => { const challenge = await api(`/v1/action-capsules/${state.selected.capsule.capsule_id}/approval-challenge`); download(challenge, `approval-challenge-${challenge.capsule_id}.json`); notify('Challenge downloaded. Sign it outside the browser with your independently controlled software key.'); });
  handle('approval-form', 'submit', async () => { const envelope = JSON.parse($('approval-json').value); if (envelope.payload?.capsule_id !== state.selected.capsule.capsule_id) throw new Error('Approval does not match the currently reviewed action.'); await api('/v1/approvals', { method: 'POST', body: envelope }); $('approval-json').value = ''; await detail(state.selected.capsule.capsule_id); notify('Exact-action signature accepted. Policy must still be evaluated.'); });
  async function loadCoverage() {
    const manifest = (await api('/v1/coverage')).payload;
    // UX-009: per-path enforced-vs-monitored state rendered as rows next to
    // the manifest, not only a raw JSON dump.
    $('coverage-rows').replaceChildren();
    for (const p of manifest.paths ?? []) {
      const tr = node('tr'), status = node('td'), badge = node('span', p.effective_status ?? p.status, 'badge'); badge.dataset.state = p.effective_status ?? p.status; status.append(badge);
      tr.append(node('td', p.path_id), node('td', p.action_type), node('td', p.target), status, node('td', p.anchored ? 'anchored' : 'unanchored'), node('td', p.next_action ?? ''));
      $('coverage-rows').append(tr);
    }
    $('coverage-json').textContent = JSON.stringify(manifest, null, 2); $('connector-json').textContent = JSON.stringify(await api('/v1/connectors'), null, 2);
  }
  handle('refresh-coverage', 'click', loadCoverage); handle('load-policy', 'click', async () => { $('policy-json').value = JSON.stringify(await api('/v1/policy'), null, 2); });
  handle('policy-form', 'submit', async () => { $('policy-result').textContent = JSON.stringify(await api('/v1/policies/simulate', { method: 'POST', body: JSON.parse($('policy-json').value) }), null, 2); notify('Simulation complete. No policy was activated.'); });
  handle('runtime-form', 'submit', async () => {
    state.runtime = await api('/v1/capabilities', { method: 'POST', body: { device_id: state.me.device_id, resource: 'dataset-1', destination: 'customer-vault', action: 'data.read', purpose: 'operations', columns: csvSelection($('runtime-columns').value), row_ids: csvSelection($('runtime-rows').value), classification: 'internal', jurisdiction: 'EU', max_cost: typedValue($('runtime-cost').value, 'positive'), ttl_ms: 60000 } }); $('runtime-read').disabled = false; $('runtime-result').textContent = JSON.stringify(state.runtime.payload, null, 2); notify('Narrow capability issued. Each read will consume the shared rolling budget.');
  });
  handle('runtime-read', 'click', async () => { const c = state.runtime.payload; $('runtime-result').textContent = JSON.stringify(await api('/gate/v1/runtime', { method: 'POST', body: { capability: state.runtime, device_id: c.device_id, resource: c.resource, destination: c.destination, action: c.action, purpose: c.purpose, columns: c.columns, row_ids: c.row_ids, request_id: crypto.randomUUID(), protocol: 'https', port: 443 } }), null, 2); });
  handle('audit-form', 'submit', async () => { const bundle = await api('/v1/audit-exports', { method: 'POST', body: { purpose: $('audit-purpose').value } }); download(bundle, `invariant-audit-${state.me.tenant_id}.json`); notify(`Exported ${bundle.entries.length} linked records. Verify with an independently pinned trust key.`); });
  async function loadKeys() {
    const data = await api('/v1/keys'); $('key-rows').replaceChildren();
    for (const k of data.keys) {
      const tr = node('tr'), title = node('td', `${k.key_id.slice(0, 12)}… ${k.purpose}`); title.append(node('span', `${k.suite} · ${k.exportable ? 'exportable' : 'non-exportable'}`, 'resource'));
      const status = node('td', k.revoked ? 'revoked' : k.pending ? 'pending' : 'active');
      const cell = node('td'), button = node('button', 'Attest', 'secondary');
      button.addEventListener('click', async () => { $('attest-result').textContent = JSON.stringify(await api(`/v1/keys/${pathId(k.key_id)}/attest?nonce=${encodeURIComponent(crypto.randomUUID())}`), null, 2); });
      cell.append(button); tr.append(title, status, cell); $('key-rows').append(tr);
    }
  }
  handle('refresh-keys', 'click', loadKeys);
  handle('rotate-form', 'submit', async () => { const out = await api('/v1/keys/rotate-prepare', { method: 'POST', body: { key_class: $('rotate-class').value } }); $('rotate-result').textContent = JSON.stringify(out, null, 2); await loadKeys(); notify('Pending key created inside the vault. Activate it via a verified key.rotate action.'); });
  let selectedCeremony = null;
  async function loadCeremonies() {
    const data = await api('/v1/ceremonies'); $('ceremony-rows').replaceChildren();
    for (const c of data.items) {
      const tr = node('tr'), title = node('td', c.ceremony_id); title.append(node('span', c.purpose, 'resource'));
      const cell = node('td'), button = node('button', 'Open', 'secondary'); button.addEventListener('click', () => selectCeremony(c)); cell.append(button);
      tr.append(title, node('td', c.status), cell); $('ceremony-rows').append(tr);
    }
  }
  function selectCeremony(c) { selectedCeremony = c; $('ceremony-title').textContent = c.ceremony_id; $('ceremony-detail').textContent = JSON.stringify(c, null, 2); }
  handle('refresh-ceremonies', 'click', loadCeremonies);
  handle('ceremony-form', 'submit', async () => {
    const body = { ceremony_id: $('cer-id').value, purpose: $('cer-purpose').value, threshold: typedValue($('cer-threshold').value, 'positive'), custodians: csvSelection($('cer-custodians').value), valid_until: Date.now() + typedValue($('cer-ttl').value, 'positive') * 60000 };
    const c = await api('/v1/ceremonies', { method: 'POST', body }); await loadCeremonies(); selectCeremony(c); notify('Ceremony created. Custodians acknowledge offline.');
  });
  handle('ack-form', 'submit', async () => { if (!selectedCeremony) throw new Error('Select a ceremony first.'); await api(`/v1/ceremonies/${selectedCeremony.ceremony_id}/acknowledge`, { method: 'POST', body: JSON.parse($('ack-json').value) }); $('ack-json').value = ''; await loadCeremonies(); notify('Custodian acknowledgement recorded.'); });
  handle('split-form', 'submit', async () => { if (!selectedCeremony) throw new Error('Select a ceremony first.'); const out = await api(`/v1/ceremonies/${selectedCeremony.ceremony_id}/split`, { method: 'POST', body: { secret: $('split-secret').value.trim() } }); $('ceremony-result').textContent = JSON.stringify(out, null, 2); download(out, `shares-${selectedCeremony.ceremony_id}.json`); notify('Shares split. Distribute each share to its named custodian.'); });
  handle('reconstruct-form', 'submit', async () => { if (!selectedCeremony) throw new Error('Select a ceremony first.'); const shares = $('reconstruct-shares').value.split('\n').map(s => s.trim()).filter(Boolean); const out = await api(`/v1/ceremonies/${selectedCeremony.ceremony_id}/reconstruct`, { method: 'POST', body: { shares } }); $('ceremony-result').textContent = JSON.stringify(out, null, 2); });
  async function loadConnectors() {
    const data = await api('/v1/connectors/status'); $('connector-rows').replaceChildren();
    for (const i of data.issuers) {
      const tr = node('tr'), title = node('td', i.name ?? i.key_id.slice(0, 12)); title.append(node('span', i.key_id.slice(0, 12), 'resource'));
      const cell = node('td'), button = node('button', 'Drift check', 'secondary');
      if (!i.endpoint) { button.disabled = true; button.title = 'No live endpoint registered'; }
      button.hidden = !(state.me?.roles ?? []).some(r => ['security', 'policy_admin'].includes(r));
      button.addEventListener('click', async () => { try { $('drift-result').textContent = JSON.stringify(await api(`/v1/connectors/${i.key_id}/drift-check`, { method: 'POST', body: {} }), null, 2); } catch (error) { notify(error.message || 'Drift check failed.', true); } });
      cell.append(button); tr.append(title, node('td', `${i.channel} / ${i.failure_domain}`), node('td', i.endpoint ?? 'offline envelope only'), node('td', i.revoked ? 'revoked' : 'trusted'), cell); $('connector-rows').append(tr);
    }
  }
  handle('refresh-connectors', 'click', loadConnectors);
  let lastProof = null;
  handle('proof-form', 'submit', async () => { lastProof = await api(`/v1/audit/proofs/${$('proof-seq').value}`); $('proof-result').textContent = JSON.stringify(lastProof, null, 2); $('verify-proof').disabled = false; });
  handle('verify-proof', 'click', async () => { if (!lastProof) return; const out = await api('/v1/audit/verify-proof', { method: 'POST', body: { proof: lastProof } }); notify(out.valid ? 'Inclusion proof verifies against the exported tree head.' : 'Proof failed to verify.', !out.valid); });
  handle('consistency-form', 'submit', async () => { $('proof-result').textContent = JSON.stringify(await api(`/v1/audit/consistency?first=${$('consistency-first').value}`), null, 2); });
  handle('perception-form', 'submit', async () => { const session = await api('/v1/secure-perception/sessions', { method: 'POST', body: { attestation: JSON.parse($('attestation-json').value) } }); $('release-session').value = session.session_id; $('perception-result').textContent = JSON.stringify(session, null, 2); notify('Dev-attested session opened. This is software attestation, not a trusted display.'); });
  handle('release-form', 'submit', async () => { const body = { session_id: $('release-session').value.trim(), fields: fieldsMap($('release-fields').value), purpose: $('release-purpose').value }; $('perception-result').textContent = JSON.stringify(await api('/v1/secure-perception/release', { method: 'POST', body }), null, 2); });
  handle('fallback-form', 'submit', async () => { const body = { fields: fieldsMap($('fallback-fields').value), purpose: $('fallback-purpose').value, reason: $('fallback-reason').value }; $('perception-result').textContent = JSON.stringify(await api('/v1/secure-perception/fallback', { method: 'POST', body }), null, 2); });
  handle('grants-form', 'submit', async () => { const subject = $('grants-subject').value.trim(); $('grants-result').textContent = JSON.stringify(await api(`/v1/grants${subject ? `?subject=${encodeURIComponent(subject)}` : ''}`), null, 2); });
  handle('refresh-grants', 'click', async () => { $('grants-result').textContent = JSON.stringify(await api('/v1/grants'), null, 2); });
  const loaders = { keys: loadKeys, ceremonies: loadCeremonies, connectors: loadConnectors, grants: async () => {} };
  document.querySelectorAll('nav button').forEach(b => { const fn = loaders[b.dataset.view]; if (fn) b.addEventListener('click', async () => { try { await fn(); } catch (e) { notify(e.message, true); } }); });
}
