'use strict';
// Additional tools: DNS, Domain & policy, Reports (+CSV import/export), Recycle Bin, Audit log.
// Shares helpers (h, api, GET, POST, dialog, form, menu, icon, pickObjects, pickContainer, ...) with app.js.

const TOOLS = { dns: renderDNS, domain: renderDomain, reports: renderReports, recycle: renderRecycle, audit: renderAudit, settings: renderSettings };

// ---------- small helpers ----------
function simpleTable(cols, rows) {
  return h('table', { class: 'simple' }, h('thead', {}, h('tr', {}, cols.map(c => h('th', { style: 'cursor:default' }, c)))),
    h('tbody', {}, rows.map(r => h('tr', {}, r.map(c => h('td', {}, c))))));
}
function card(title, ...kids) { return h('div', { class: 'card' }, h('h3', {}, title), ...kids); }
function csvCell(v) {
  v = String(v ?? '');
  if (/^[=+\-@\t\r]/.test(v)) v = "'" + v;           // neutralise spreadsheet formulas
  return /[",\n\r]/.test(v) ? '"' + v.replace(/"/g, '""') + '"' : v;
}
function downloadCSV(name, header, rows) {
  const text = [header, ...rows].map(r => r.map(csvCell).join(',')).join('\r\n');
  const a = h('a', { href: URL.createObjectURL(new Blob(['﻿' + text], { type: 'text/csv' })), download: name });
  document.body.append(a); a.click(); a.remove(); setTimeout(() => URL.revokeObjectURL(a.href), 2000);
}
function parseCSV(t) {
  const rows = []; let row = [], f = '', q = false; t = t.replace(/^﻿/, '');
  for (let i = 0; i < t.length; i++) {
    const c = t[i];
    if (q) { if (c === '"') { if (t[i + 1] === '"') { f += '"'; i++; } else q = false; } else f += c; }
    else if (c === '"') q = true;
    else if (c === ',') { row.push(f); f = ''; }
    else if (c === '\n' || c === '\r') { if (c === '\r' && t[i + 1] === '\n') i++; row.push(f); f = ''; if (row.some(x => x !== '')) rows.push(row); row = []; }
    else f += c;
  }
  row.push(f); if (row.some(x => x !== '')) rows.push(row);
  return rows;
}
function randomPassword(n = 16) {
  const sets = ['ABCDEFGHJKLMNPQRSTUVWXYZ', 'abcdefghijkmnopqrstuvwxyz', '23456789', '!#%*+?_'];
  const rnd = m => { const b = new Uint32Array(1); let x; do { crypto.getRandomValues(b); x = b[0]; } while (x >= 4294967296 - (4294967296 % m)); return x % m; };
  const all = sets.join('');
  const out = [sets[1][rnd(sets[1].length)]]; // start with a letter
  for (const s of [sets[0], sets[2], sets[3]]) out.push(s[rnd(s.length)]);
  while (out.length < n) out.push(all[rnd(all.length)]);
  for (let i = out.length - 1; i > 1; i--) { const j = 1 + rnd(i); [out[i], out[j]] = [out[j], out[i]]; }
  return out.join('');
}
const fmtErr = e => e.message || String(e);
function pageStatus(el, msg, bad) { el.textContent = msg || ''; el.className = 'pmsg' + (bad ? ' err' : ''); }

// ---------- DNS Manager ----------
const DNS_TYPES = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'PTR', 'SRV', 'TXT', 'SOA'];
const DNS_FIELDS = {
  A: [['address', 'IPv4 address']], AAAA: [['address', 'IPv6 address']],
  CNAME: [['target', 'Alias to (FQDN)']], NS: [['target', 'Name server (FQDN)']], PTR: [['target', 'Host name (FQDN)']],
  MX: [['preference', 'Preference'], ['target', 'Mail server (FQDN)']],
  SRV: [['priority', 'Priority'], ['weight', 'Weight'], ['port', 'Port'], ['target', 'Host offering the service (FQDN)']],
  TXT: [['text', 'Text', 'area']],
  SOA: [['serial', 'Serial number'], ['refresh', 'Refresh (s)'], ['retry', 'Retry (s)'], ['expire', 'Expire (s)'], ['minimum', 'Minimum TTL (s)'], ['primary', 'Primary server (FQDN)'], ['admin', 'Responsible person (FQDN)']],
};

async function renderDNS(page) {
  const zl = h('div', { class: 'zones' }), right = h('div', { class: 'recs' });
  page.classList.add('split'); page.append(zl, right);
  let zones = [], zone = null, rows = [], sel = null, filter = '';
  const msg = h('span', { class: 'pmsg' });
  const body = h('div', { class: 'tablewrap' });
  const filt = h('input', { type: 'text', placeholder: 'Filter records…', style: 'width:220px' });
  filt.addEventListener('input', () => { filter = filt.value.toLowerCase(); draw(); });
  const btn = (label, fn, cls) => h('button', { class: cls || '', onclick: fn }, label);

  async function loadZones() {
    try { zones = (await GET('/api/dns/zones')).zones; } catch (e) { return pageStatus(msg, fmtErr(e), true); }
    zl.replaceChildren(h('div', { class: 'zh' }, 'DNS zones'), ...zones.map(z => {
      const d = h('div', { class: 'zone' + (zone && zone.dn === z.dn ? ' sel' : '') }, icon(z.reverse ? 'subnet' : 'domain'), z.name, h('span', { class: 'badge' }, z.scope));
      d.addEventListener('click', () => { zone = z; sel = null; loadZones(); loadRecords(); });
      d.addEventListener('contextmenu', e => {
        e.preventDefault();
        const same = zone && zone.dn === z.dn; zone = z; sel = null; loadZones(); if (!same) loadRecords();
        menu(e.clientX, e.clientY, [{ label: 'New record…', fn: () => editRec(null) }, '-', { label: 'Refresh', fn: refresh }]);
      });
      return d;
    }), ...(zones.length ? [] : [h('div', { class: 'muted', style: 'padding:8px' }, 'No DNS zones found (is this a Samba AD DNS server?)')]),
      h('div', { class: 'muted', style: 'padding:10px;font-size:12px' }, 'Create or delete zones with samba-tool dns zonecreate / zonedelete.'));
  }
  async function loadRecords() {
    if (!zone) return;
    pageStatus(msg, 'Loading…');
    try {
      const r = await GET('/api/dns/records', { zone: zone.dn });
      rows = r.nodes.flatMap(n => n.records.map(rec => ({ name: n.name, ...rec })));
      pageStatus(msg, r.truncated ? 'List truncated at 5000 nodes.' : '');
    } catch (e) { rows = []; pageStatus(msg, fmtErr(e), true); }
    draw();
  }
  function draw() {
    if (!zone) { body.replaceChildren(h('div', { class: 'muted', style: 'padding:14px' }, 'Select a zone.')); return; }
    const vis = rows.filter(r => !filter || (r.name + ' ' + r.type + ' ' + r.text).toLowerCase().includes(filter));
    const key = r => r.name + '|' + r.raw;
    body.replaceChildren(h('table', {}, h('thead', {}, h('tr', {}, ['Name', 'Type', 'Data', 'TTL', 'Timestamp'].map(c => h('th', { style: 'cursor:default' }, c)))),
      h('tbody', {}, vis.map(r => {
        const tr = h('tr', { class: 'row' + (sel && key(sel) === key(r) ? ' sel' : '') }, h('td', {}, r.name === '@' ? '(same as parent)' : r.name), h('td', {}, r.type), h('td', { title: r.text }, r.text), h('td', {}, String(r.ttl)), h('td', {}, r.dynamic ? r.timestamp : 'static'));
        tr.addEventListener('click', () => { sel = r; draw(); });
        tr.addEventListener('dblclick', () => editRec(r));
        tr.addEventListener('contextmenu', e => {
          e.preventDefault(); sel = r; draw();
          menu(e.clientX, e.clientY, [{ label: 'Edit…', disabled: !r.editable, fn: () => editRec(r) }, { label: 'Delete', danger: true, fn: delRec }, '-',
            { label: 'New record…', fn: () => editRec(null) }, { label: 'Refresh', fn: refresh }]);
        });
        return tr;
      }))));
    document.getElementById('st-count') && (document.getElementById('st-count').textContent = vis.length + ' record(s)');
  }
  const refresh = () => { loadZones(); loadRecords(); };
  body.addEventListener('contextmenu', e => {
    if (e.target.closest('tr') || !zone) return;
    e.preventDefault();
    menu(e.clientX, e.clientY, [{ label: 'New record…', fn: () => editRec(null) }, '-', { label: 'Refresh', fn: refresh }]);
  });
  async function editRec(r) {
    if (r && !r.editable) return pageStatus(msg, 'This record type cannot be edited here.', true);
    if (await dnsRecordDialog(zone, r)) { loadRecords(); }
  }
  async function delRec() {
    if (!sel) return;
    const r = sel;
    if (!(await confirmBox('Delete record', `Delete ${r.type} record “${r.name === '@' ? zone.name : r.name}” (${r.text})?`, 'Delete', true))) return;
    try { await POST('/api/dns/delete', { zone: zone.dn, name: r.name, old: r.raw, type: r.type }); sel = null; loadRecords(); } catch (e) { pageStatus(msg, fmtErr(e), true); }
  }
  right.append(h('div', { class: 'toolbar' }, btn('Refresh', refresh), btn('New record…', () => zone && editRec(null)),
    btn('Edit…', () => sel && editRec(sel)), btn('Delete', delRec, 'danger'), h('span', { class: 'sp' }), filt), msg, body);
  draw(); loadZones();
}

async function dnsRecordDialog(zone, rec) {
  const editing = !!rec;
  const nameIn = h('input', { type: 'text', value: rec ? rec.name : '', readOnly: editing, placeholder: '@ for the zone itself' });
  const typeIn = h('select', { disabled: editing }, DNS_TYPES.map(t => h('option', { value: t }, t)));
  typeIn.value = rec ? rec.type : 'A';
  const ttlIn = h('input', { type: 'text', value: rec ? rec.ttl : '3600' });
  const fieldBox = h('div', { class: 'frm', style: 'margin-top:8px' });
  let inputs = {};
  const build = () => {
    inputs = {}; fieldBox.replaceChildren();
    for (const [k, label, kind] of DNS_FIELDS[typeIn.value]) {
      const i = kind === 'area' ? h('textarea', { rows: 3 }) : h('input', { type: 'text' });
      const v = rec && rec.type === typeIn.value ? rec.fields[k] : (typeIn.value === 'MX' && k === 'preference' ? 10 : typeIn.value === 'SRV' && k === 'priority' ? 0 : typeIn.value === 'SRV' && k === 'weight' ? 100 : '');
      i.value = v ?? ''; inputs[k] = i; fieldBox.append(h('label', {}, label), i);
    }
  };
  typeIn.addEventListener('change', build); build();
  const head = h('div', { class: 'frm' }, h('label', {}, 'Name (relative to ' + zone.name + ')'), nameIn, h('label', {}, 'Type'), typeIn, h('label', {}, 'TTL (seconds)'), ttlIn);
  const note = h('p', { class: 'muted', style: 'font-size:12px;margin-top:10px' }, 'Host names are fully-qualified (a trailing dot is optional).' + (rec && rec.dynamic ? ' This is a dynamically registered record; the client may overwrite your change.' : ''));
  return dialog((editing ? 'Edit ' : 'New ') + 'DNS record — ' + zone.name, h('div', {}, head, fieldBox, note),
    [{ label: 'Cancel' }, { label: 'Save', primary: true, action: async () => {
      const fields = Object.fromEntries(Object.entries(inputs).map(([k, i]) => [k, i.value]));
      await POST('/api/dns/save', { zone: zone.dn, name: nameIn.value, old: rec ? rec.raw : '', type: typeIn.value, ttl: parseInt(ttlIn.value, 10) || 0, fields });
    } }], { wide: false });
}

// ---------- Domain: info, FSMO, DCs, password policy, PSOs ----------
const FUNC_LEVELS = { 0: '2000', 1: '2003 interim', 2: '2003', 3: '2008', 4: '2008 R2', 5: '2012', 6: '2012 R2', 7: '2016' };

async function renderDomain(page) {
  const msg = h('div', { class: 'pmsg' }); page.append(msg);
  let di, pol, psos;
  try { [di, pol, psos] = await Promise.all([GET('/api/domaininfo'), GET('/api/policy'), GET('/api/pso')]); } catch (e) { return pageStatus(msg, fmtErr(e), true); }
  const rd = di.rootDSE || {}, one = k => (rd[k] || [])[0] || '';
  const lvl = k => { const v = one(k); return v === '' ? '—' : (FUNC_LEVELS[v] ? 'Windows Server ' + FUNC_LEVELS[v] : v); };
  const kv = rows => h('table', { class: 'simple kv' }, h('tbody', {}, rows.map(([k, v]) => h('tr', {}, h('th', {}, k), h('td', {}, v)))));

  const infoCard = card('Domain', kv([['Domain', info.realm], ['Domain DN', info.base], ['Domain functional level', lvl('domainFunctionality')],
    ['Forest functional level', lvl('forestFunctionality')], ['Connected to', one('dnsHostName')],
    ['Recycle Bin', di.recycleBin === undefined ? 'unknown' : di.recycleBin ? 'enabled' : 'not enabled']]));
  const fsmo = card('Operations masters (FSMO roles)', simpleTable(['Role', 'Server', 'Site'], (di.fsmo || []).map(r => [r.role, r.server || '—', r.site || '—'])),
    h('p', { class: 'muted' }, 'Read-only. Transfer roles with samba-tool fsmo transfer.'));
  const dcs = card('Domain controllers', simpleTable(['Name', 'DNS name', 'Site', 'Global Catalog'], (di.dcs || []).map(d => [d.name, d.dns, d.site, d.gc ? 'yes' : 'no'])));

  // alternative UPN suffixes (right-click: Add… / Delete…)
  const upnBox = h('div', { style: 'min-height:90px' }), upnMsg = h('span', { class: 'pmsg' });
  let sufs = [];
  const saveSufs = async next => { sufs = (await api('PUT', '/api/upnsuffixes', { suffixes: next })).suffixes; drawSufs(); };
  const addSuf = async () => {
    const f = form([{ k: 'suffix', label: 'UPN suffix', placeholder: 'example.org' }]);
    f.inputs.suffix.placeholder = 'example.org';
    await dialog('Add UPN suffix', f.el, [{ label: 'Cancel' }, { label: 'Add', primary: true, action: async () => {
      const v = f.get().suffix.trim(); if (!v) throw new Error('Enter a suffix');
      await saveSufs([...sufs, v]);
    } }]);
    pageStatus(upnMsg, '');
  };
  const delSuf = async x => {
    if (!await confirmBox('Delete UPN suffix', `Delete “${x}”? Users who already have it keep it.`, 'Delete', true)) return;
    try { await saveSufs(sufs.filter(y => y !== x)); pageStatus(upnMsg, ''); } catch (e) { pageStatus(upnMsg, fmtErr(e), true); }
  };
  const drawSufs = () => {
    const t = simpleTable(['Suffix'], sufs.map(x => [x]));
    t.querySelectorAll('tbody tr').forEach((tr, i) => tr.addEventListener('contextmenu', e => {
      e.preventDefault(); e.stopPropagation(); menu(e.clientX, e.clientY, [{ label: 'Add…', fn: addSuf }, { label: 'Delete…', danger: true, fn: () => delSuf(sufs[i]) }]);
    }));
    upnBox.replaceChildren(t);
  };
  upnBox.addEventListener('contextmenu', e => { e.preventDefault(); menu(e.clientX, e.clientY, [{ label: 'Add…', fn: addSuf }]); });
  const upnCard = card('Alternative UPN suffixes', upnBox, upnMsg);
  GET('/api/upnsuffixes').then(r => { sufs = r.suffixes || []; drawSufs(); }).catch(e => pageStatus(upnMsg, fmtErr(e), true));

  // default policy
  const pf = form([
    { k: 'minLength', label: 'Minimum password length', value: pol.minLength }, { k: 'history', label: 'Password history (0–24)', value: pol.history },
    { k: 'maxAgeDays', label: 'Maximum password age (days, 0 = never)', value: pol.maxAgeDays }, { k: 'minAgeDays', label: 'Minimum password age (days)', value: pol.minAgeDays },
    { k: 'threshold', label: 'Account lockout threshold (0 = off)', value: pol.threshold }, { k: 'durationMin', label: 'Lockout duration (minutes, 0 = until unlocked)', value: pol.durationMin },
    { k: 'windowMin', label: 'Reset lockout counter after (minutes)', value: pol.windowMin },
    { k: 'complexity', type: 'check', label: 'Password must meet complexity requirements', value: pol.complexity },
    { k: 'reversible', type: 'check', label: 'Store passwords using reversible encryption', value: pol.reversible }]);
  const polMsg = h('span', { class: 'pmsg' });
  const polCard = card('Default domain password and lockout policy', pf.el, h('div', { class: 'row2' }, h('button', { class: 'primary', onclick: async () => {
    const v = pf.get(); const n = k => { const x = parseInt(v[k], 10); return Number.isNaN(x) ? -1 : x; };
    try {
      await api('PUT', '/api/policy', { minLength: n('minLength'), history: n('history'), maxAgeDays: n('maxAgeDays'), minAgeDays: n('minAgeDays'), threshold: n('threshold'), durationMin: n('durationMin'), windowMin: n('windowMin'), complexity: v.complexity, reversible: v.reversible });
      pageStatus(polMsg, 'Saved.');
    } catch (e) { pageStatus(polMsg, fmtErr(e), true); }
  } }, 'Save policy'), polMsg));

  // PSOs
  const psoBox = h('div');
  const drawPSOs = list => psoBox.replaceChildren(list.length ? simpleTable(['Precedence', 'Name', 'Min length', 'Max age', 'Lockout', 'Applies to', ''], list.map(p => [String(p.precedence), p.name, String(p.minLength),
    p.maxAgeDays ? p.maxAgeDays + ' d' : 'never', p.threshold ? p.threshold + ' tries' : 'off', (p.appliesTo || []).map(rdnName).join(', ') || '—',
    h('span', {}, h('button', { onclick: () => psoDialog(p) }, 'Edit'), ' ', h('button', { class: 'danger', onclick: async () => {
      if (await confirmBox('Delete password settings', `Delete “${p.name}”?`, 'Delete', true)) { try { await POST('/api/delete', { dn: p.dn }); reloadPSOs(); } catch (e) { pageStatus(polMsg, fmtErr(e), true); } }
    } }, 'Delete'))])) : h('p', { class: 'muted' }, 'No fine-grained password policies defined.'));
  const reloadPSOs = async () => { try { drawPSOs((await GET('/api/pso')).psos); } catch (e) { pageStatus(polMsg, fmtErr(e), true); } };
  drawPSOs(psos.psos);
  const psoCard = card('Fine-grained password policies', psoBox, h('div', { class: 'row2' }, h('button', { onclick: () => psoDialog(null) }, 'New policy…')),
    h('p', { class: 'muted' }, 'The policy with the lowest precedence number that applies to a user (directly or via a group) wins over the default policy.'));

  async function psoDialog(p) {
    const e = p || { name: '', precedence: 10, minLength: 12, history: 24, maxAgeDays: 42, minAgeDays: 1, threshold: 5, durationMin: 30, windowMin: 30, complexity: true, reversible: false, appliesTo: [] };
    const f = form([{ k: 'name', label: 'Name', value: e.name, readonly: !!p }, { k: 'precedence', label: 'Precedence', value: e.precedence },
      { k: 'minLength', label: 'Minimum length', value: e.minLength }, { k: 'history', label: 'History', value: e.history },
      { k: 'maxAgeDays', label: 'Max age (days, 0 = never)', value: e.maxAgeDays }, { k: 'minAgeDays', label: 'Min age (days)', value: e.minAgeDays },
      { k: 'threshold', label: 'Lockout threshold', value: e.threshold }, { k: 'durationMin', label: 'Lockout duration (min)', value: e.durationMin }, { k: 'windowMin', label: 'Observation window (min)', value: e.windowMin },
      { k: 'complexity', type: 'check', label: 'Complexity required', value: e.complexity }, { k: 'reversible', type: 'check', label: 'Reversible encryption', value: e.reversible }]);
    let applies = [...(e.appliesTo || [])];
    const list = h('div', { class: 'pl', style: 'height:110px' });
    const drawList = () => list.replaceChildren(...applies.map(d => { const x = h('div', { class: 'it', title: d }, icon('group'), rdnName(d), h('span', { class: 'muted', style: 'margin-left:auto;cursor:pointer' }, '✕')); x.addEventListener('click', () => { applies = applies.filter(a => a !== d); drawList(); }); return x; }));
    drawList();
    const add = h('button', { onclick: async () => { const r = await pickObjects('Apply to users or groups', 'all', true); for (const o of r) if (!applies.includes(o.dn)) applies.push(o.dn); drawList(); } }, 'Add users/groups…');
    const ok = await dialog((p ? 'Edit ' : 'New ') + 'password settings', h('div', {}, f.el, h('div', { class: 'sec' }, 'Applies to (click to remove)'), list, h('div', { class: 'row2' }, add)),
      [{ label: 'Cancel' }, { label: 'Save', primary: true, action: async () => {
        const v = f.get(), n = k => { const x = parseInt(v[k], 10); return Number.isNaN(x) ? -1 : x; };
        await POST('/api/pso/save', { dn: p ? p.dn : '', name: v.name, precedence: n('precedence'), minLength: n('minLength'), history: n('history'), maxAgeDays: n('maxAgeDays'), minAgeDays: n('minAgeDays'), threshold: n('threshold'), durationMin: n('durationMin'), windowMin: n('windowMin'), complexity: v.complexity, reversible: v.reversible, appliesTo: applies });
      } }], { wide: true });
    if (ok) reloadPSOs();
  }
  page.append(h('div', { class: 'cards' }, infoCard, fsmo, dcs, upnCard, polCard, psoCard));
}

// ---------- Reports, CSV import/export ----------
const REPORTS = [
  ['stale-users', 'Inactive users', true], ['stale-computers', 'Inactive computers', true], ['expiring', 'Passwords expired or expiring', true, 14],
  ['locked', 'Locked-out accounts'], ['disabled', 'Disabled users'], ['never-expire', 'Passwords that never expire'], ['no-preauth', 'Kerberos pre-auth disabled'],
  ['unconstrained', 'Unconstrained delegation'], ['privileged', 'Privileged group members'], ['empty-groups', 'Empty groups'],
];

async function renderReports(page) {
  page.classList.add('split');
  const left = h('div', { class: 'zones' }), right = h('div', { class: 'recs' });
  page.append(left, right);
  const out = h('div', { class: 'tablewrap' });
  const note = h('div', { class: 'pmsg' });
  const days = h('input', { type: 'text', value: '90', style: 'width:60px' });
  const daysLbl = h('span', { class: 'muted' }, 'days:');
  let cur = null, last = null;
  const tools = h('div', { class: 'toolbar' }, daysLbl, days, h('button', { onclick: () => run() }, 'Run'),
    h('button', { onclick: () => last && downloadCSV(cur[0] + '.csv', ['Name', 'Logon name', 'Type', 'Detail', 'DN'], last.map(r => [r.name, r.sam, r.type, r.detail, r.dn])) }, 'Export CSV'));
  async function run() {
    if (!cur) return;
    pageStatus(note, 'Running…'); out.replaceChildren();
    try {
      const r = await GET('/api/report', { name: cur[0], days: days.value });
      last = r.rows;
      pageStatus(note, (r.note || '') + (r.truncated ? ' (truncated at 5000)' : ''));
      out.replaceChildren(simpleTable(['Name', 'Logon name', 'Type', 'Detail', 'Location'], r.rows.map(x => [h('a', { href: '#', onclick: e => { e.preventDefault(); properties(x.dn); } }, x.name), x.sam, x.type, x.detail, parentOf(x.dn).replace(/,DC=.*$/i, '')])));
      document.getElementById('st-count').textContent = r.rows.length + ' result(s)';
    } catch (e) { last = null; pageStatus(note, fmtErr(e), true); }
  }
  const drawLeft = () => left.replaceChildren(h('div', { class: 'zh' }, 'Reports'), ...REPORTS.map(rp => {
    const d = h('div', { class: 'zone' + (cur === rp ? ' sel' : '') }, rp[1]);
    d.addEventListener('click', () => { cur = rp; tools.style.display = ''; days.value = rp[3] || 90; days.style.display = daysLbl.style.display = rp[2] ? '' : 'none'; drawLeft(); run(); });
    return d;
  }), h('div', { class: 'zh', style: 'margin-top:14px' }, 'Bulk'),
    h('div', { class: 'zone', onclick: () => importUsers() }, 'Import users from CSV…'),
    h('div', { class: 'zone', onclick: () => downloadCSV('users-template.csv', IMPORT_COLS, [['jsmith', 'John', 'Smith', 'jsmith@' + info.realm, '', 'Sales rep', 'yes', 'no', 'no', 'john.smith@example.com', 'Sales', 'Sales Rep']])}, 'Download CSV template'));
  drawLeft();
  tools.style.display = 'none';
  right.append(tools, note, out);
  out.append(h('div', { class: 'muted', style: 'padding:14px' }, 'Choose a report.'));
}

const IMPORT_COLS = ['sam', 'first', 'last', 'upn', 'password', 'description', 'mustchange', 'neverexpires', 'disabled', 'mail', 'department', 'title'];

async function importUsers() {
  let recs = [], target = null;
  const file = h('input', { type: 'file', accept: '.csv,text/csv' });
  const info1 = h('div', { class: 'muted', style: 'margin:8px 0' }, 'Columns: sam (required), first, last, name, upn, password, description, mustchange, neverexpires, disabled, mail, department, title, ou (DN, overrides the target). Missing passwords are generated.');
  const tgt = h('span', { class: 'muted' }, '(choose a container)');
  const pickBtn = h('button', { onclick: async () => { const d = await pickContainer('Create users in…'); if (d) { target = d; tgt.textContent = d; } } }, 'Target container…');
  const prev = h('div', { class: 'pl', style: 'height:150px;padding:6px' });
  file.addEventListener('change', async () => {
    recs = []; prev.replaceChildren();
    const f = file.files[0]; if (!f) return;
    const rows = parseCSV(await f.text());
    if (rows.length < 2) { prev.textContent = 'No data rows found.'; return; }
    const hdr = rows[0].map(x => x.trim().toLowerCase().replace(/[^a-z]/g, ''));
    const alias = { samaccountname: 'sam', username: 'sam', logon: 'sam', firstname: 'first', givenname: 'first', lastname: 'last', surname: 'last', fullname: 'name', cn: 'name', userprincipalname: 'upn', email: 'mail', must: 'mustchange', mustchangepassword: 'mustchange', passwordneverexpires: 'neverexpires', organizationalunit: 'ou' };
    const cols = hdr.map(x => alias[x] || x);
    if (!cols.includes('sam')) { prev.textContent = 'The CSV needs a "sam" column.'; return; }
    recs = rows.slice(1).map(r => Object.fromEntries(cols.map((c, i) => [c, (r[i] || '').trim()]))).filter(r => r.sam);
    prev.replaceChildren(...recs.slice(0, 200).map(r => h('div', { class: 'it' }, icon('user'), r.sam + ' — ' + [r.first, r.last].filter(Boolean).join(' '))), ...(recs.length > 200 ? [h('div', { class: 'muted' }, '…')] : []));
    prev.prepend(h('div', { class: 'muted' }, recs.length + ' user(s) to create'));
  });
  const yes = v => /^(1|y|yes|true|x)$/i.test(v || '');
  const ok = await dialog('Import users from CSV', h('div', {}, file, info1, h('div', { class: 'row2' }, pickBtn, tgt), prev),
    [{ label: 'Close' }, { label: 'Import', primary: true, action: async () => {
      if (!recs.length) throw new Error('Choose a CSV file first');
      if (!target && recs.some(r => !r.ou)) throw new Error('Choose a target container');
      if (!(await confirmBox('Create users', `Create ${recs.length} user account(s)?`, 'Create'))) throw new Error('Cancelled');
      return recs;
    } }], { wide: true });
  if (!ok || ok === true) return;
  // run, with a results dialog
  const results = [], logEl = h('div', { class: 'pl', style: 'height:300px;padding:6px;font-family:monospace;font-size:12px' }), prog = h('div', { class: 'muted' });
  let cancelled = false;
  const resDlg = dialog('Importing users…', h('div', {}, prog, logEl), [{ label: 'Stop', danger: true, action: async () => { cancelled = true; throw new Error('Stopping after the current user…'); } }, { label: 'Close', value: 'close' }], { modal: true });
  resDlg.then(() => { cancelled = true; });
  let created = 0, failed = 0;
  for (let i = 0; i < recs.length && !cancelled; i++) {
    const r = recs[i], gen = !r.password, pw = r.password || randomPassword();
    prog.textContent = `${i + 1} / ${recs.length}`;
    const first = r.first || '', last = r.last || '';
    const cn = r.name || (first + ' ' + last).trim() || r.sam;
    try {
      const res = await POST('/api/create', { kind: 'user', parent: r.ou || target, name: cn, first, last, sam: r.sam, upn: r.upn || '', description: r.description || '', password: pw, mustChange: r.mustchange === '' ? true : yes(r.mustchange), neverExpires: yes(r.neverexpires), disabled: yes(r.disabled) });
      const set = {};
      if (r.mail) set.mail = [r.mail]; if (r.department) set.department = [r.department]; if (r.title) set.title = [r.title];
      if (Object.keys(set).length) await api('PUT', '/api/object', { dn: res.dn, set });
      created++; results.push([r.sam, 'created', gen ? pw : '(supplied)', res.dn]);
      logEl.append(h('div', {}, '✓ ' + r.sam));
    } catch (e) { failed++; results.push([r.sam, 'FAILED: ' + e.message, '', '']); logEl.append(h('div', { style: 'color:var(--danger)' }, '✗ ' + r.sam + ': ' + e.message)); }
    logEl.scrollTop = logEl.scrollHeight;
  }
  prog.textContent = `Done: ${created} created, ${failed} failed.`;
  logEl.append(h('div', { style: 'margin-top:8px' }, h('button', { class: 'primary', onclick: () => downloadCSV('import-results.csv', ['sam', 'result', 'generated password', 'dn'], results) }, 'Download results (includes generated passwords)')));
  await resDlg;
}

// ---------- Recycle Bin ----------
async function renderRecycle(page) {
  const err = h('span', { class: 'terr' }), body = h('div', { class: 'tablewrap' });
  const filt = h('input', { type: 'text', placeholder: 'Filter…', style: 'width:220px' });
  const enableBtn = h('button', {
    class: 'danger', hidden: true, onclick: enable,
    title: 'Not enabled: deleted objects lose most attributes and group memberships. Enabling is forest-wide and cannot be undone.'
  }, 'Enable Recycle Bin…');
  let rows = [], truncated = false;
  page.append(h('div', { class: 'toolbar' }, h('button', { onclick: load }, 'Refresh'), enableBtn, err, h('span', { class: 'sp' }), filt), body);
  filt.addEventListener('input', draw);
  async function load() {
    err.textContent = '';
    try {
      const [r, di] = await Promise.all([GET('/api/deleted'), GET('/api/domaininfo').catch(() => ({}))]);
      // records deleted on the DNS page live in goaduc's own list (AD keeps no record of an attribute value going away)
      const dnsRows = (r.dns || []).map(d => ({ dns: true, id: d.id, name: d.name + ' ' + d.type + ' ' + d.text, type: 'dnsrecord', sam: '', lastParent: d.zoneName, when: d.when, recycled: !d.restorable }));
      rows = [...r.objects, ...dnsRows].sort((a, b) => (b.when || '').localeCompare(a.when || ''));
      truncated = !!r.truncated;
      enableBtn.hidden = di.recycleBin !== false;
    } catch (e) { rows = []; truncated = false; err.textContent = fmtErr(e); }
    draw();
  }
  async function enable() {
    const ok = await dialog('Enable Recycle Bin', h('p', {}, 'Enable the AD Recycle Bin for the whole forest? This cannot be undone.'),
      [{ label: 'Cancel' }, { label: 'Enable', primary: true, danger: true, action: async () => { await POST('/api/recyclebin/enable', {}); } }]);
    if (ok) load();
  }
  function draw() {
    const q = filt.value.toLowerCase();
    const vis = rows.filter(r => !q || (r.name + ' ' + r.sam + ' ' + r.lastParent).toLowerCase().includes(q));
    const tbl = simpleTable(['Name', 'Type', 'Logon name', 'Deleted from', 'Changed'], vis.map(r => [h('span', {}, icon(r.type), r.name), TYPE_LABEL[r.type] || r.type, r.sam, r.lastParent.replace(/,DC=.*$/i, ''), r.when]));
    tbl.querySelectorAll('tbody tr').forEach((tr, i) => tr.addEventListener('contextmenu', e => {
      e.preventDefault();
      const r = vis[i];
      tbl.querySelectorAll('tr.sel').forEach(x => x.classList.remove('sel')); tr.classList.add('sel');
      menu(e.clientX, e.clientY, [{ label: 'Restore…', disabled: r.recycled, fn: () => restore(r) }, { label: 'Delete…', danger: true, fn: () => purge(r) }, '-', { label: 'Empty Recycle Bin…', danger: true, fn: emptyBin }]);
    }));
    body.replaceChildren(tbl);
    const cnt = document.getElementById('st-count');
    cnt.textContent = vis.length + ' deleted object(s)' + (truncated ? ' (truncated)' : '');
    cnt.title = truncated ? 'List truncated at 2000.' : '';
  }
  body.addEventListener('contextmenu', e => {
    if (e.target.closest('tr')) return;
    e.preventDefault();
    menu(e.clientX, e.clientY, [{ label: 'Empty Recycle Bin…', danger: true, disabled: !rows.length, fn: emptyBin }]);
  });
  async function purge(r) {
    if (!(await confirmBox('Delete', `Permanently delete “${r.name}”? This cannot be undone.`, 'Delete', true))) return;
    let msg = '';
    try { await POST('/api/deleted/purge', r.dns ? { dns: r.id } : { dn: r.dn }); } catch (e) { msg = fmtErr(e); }
    await load(); err.textContent = msg;   // load() clears the text, so a failure is put back after it
  }
  async function emptyBin() {
    if (!rows.length || !(await confirmBox('Empty Recycle Bin', `Permanently delete all ${rows.length} object(s)? This cannot be undone.`, 'Empty', true))) return;
    let msg = '';
    try { await POST('/api/deleted/purge', { all: true }); } catch (e) { msg = fmtErr(e); }
    await load(); err.textContent = msg;
  }
  async function restore(r) {
    if (r.dns) {
      let msg = '';
      try { await POST('/api/deleted/dns/restore', { id: r.id }); } catch (e) { msg = fmtErr(e); }
      await load(); err.textContent = msg;
      return;
    }
    let parent = r.lastParent.includes('\\0ADEL:') || !r.lastParent ? 'CN=Users,' + info.base : r.lastParent;
    const f = form([{ k: 'name', label: 'Restore as', value: r.name }]);
    const tgt = h('input', { type: 'text', value: parent, readOnly: true });
    const pick = h('button', { onclick: async () => { const d = await pickContainer('Restore into…'); if (d) { parent = d; tgt.value = d; } } }, 'Browse…');
    f.el.append(h('label', {}, 'Into container'), h('div', { class: 'row2', style: 'margin:0' }, tgt, pick));
    const ok = await dialog('Restore ' + r.name, f.el, [{ label: 'Cancel' }, { label: 'Restore', primary: true, action: async () => { await POST('/api/deleted/restore', { dn: r.dn, parent, name: f.get().name, type: r.type }); } }]);
    if (ok) load();
  }
  load();
}

// ---------- Audit log ----------
async function renderAudit(page) {
  const body = h('div', { class: 'tablewrap' }), msg = h('div', { class: 'pmsg' });
  page.append(h('div', { class: 'toolbar' }, h('button', { onclick: load }, 'Refresh')), msg, body);
  async function load() {
    try {
      const r = await GET('/api/audit');
      pageStatus(msg, 'Changes made through this web tool since it started (newest first). Passwords are never recorded.' + (r.file ? '' : ' Start with -audit-log FILE to keep a permanent copy.'));
      body.replaceChildren(simpleTable(['Time (UTC)', 'User', 'Action', 'Detail', 'Result'], r.entries.map(e => [e.time.replace('T', ' ').replace('Z', ''), e.user, e.action, h('span', { class: 'mono', title: e.detail }, e.detail), e.ok ? 'ok' : h('span', { class: 'err' }, e.error)])));
      document.getElementById('st-count').textContent = r.entries.length + ' entries';
    } catch (e) { pageStatus(msg, fmtErr(e), true); }
  }
  load();
}

// ---------- Update ----------
// ---------- Settings: Certificate and Update ----------
let settingsTab = 'Certificate';
function renderSettings(page) {
  const body = h('div', { class: 'setbody' });
  const tabs = h('div', { class: 'tabs' });
  const subs = { Certificate: renderCertificate, Update: renderUpdate };
  const show = k => {
    settingsTab = k;
    [...tabs.children].forEach(t => t.classList.toggle('on', t.textContent === k));
    const c = h('div', { class: 'setpane' }); body.replaceChildren(c);   // a fresh pane, so the Update poller of the old one stops
    subs[k](c);
  };
  for (const k of Object.keys(subs)) tabs.append(h('div', { onclick: () => show(k) }, k));
  page.append(tabs, body);
  show(settingsTab);
}

async function renderCertificate(page) {
  const err = h('span', { class: 'terr' });
  const body = h('div', { class: 'tablewrap' });
  const upBtn = h('button', { onclick: upload }, 'Upload certificate…');
  const resetBtn = h('button', { onclick: reset }, 'Use self-signed');
  page.append(h('div', { class: 'toolbar' }, upBtn, resetBtn, err), body);
  let st;
  const day = v => new Date(v).toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
  function draw() {
    const off = !st.managed || st.plain;
    for (const b of [upBtn, resetBtn]) { b.disabled = off; b.title = off ? st.why : ''; }
    resetBtn.disabled = off || !st.custom;
    if (st.plain) { body.replaceChildren(h('table', { class: 'simple kv' }, h('tbody', {}, h('tr', {}, h('th', {}, 'Web UI'), h('td', {}, 'plain HTTP (no certificate)'))))); return; }
    const left = Math.floor((new Date(st.notAfter) - Date.now()) / 864e5);
    const kv = [['Source', st.custom ? 'Uploaded' : st.managed ? 'Self-signed by goaduc' : 'Files (-tls-cert / -tls-key)'], ['Subject', st.subject], ['Issuer', st.selfSigned ? 'Self-signed' : st.issuer],
      ['Names', (st.names || []).join(', ') || '—'], ['Valid from', day(st.notBefore)],
      ['Expires', h('span', { class: left < 30 ? 'terr' : '' }, day(st.notAfter) + (left < 0 ? ' (expired)' : ` (${left} days)`))], ['SHA-256', h('code', {}, st.fingerprint)]];
    if (st.chain > 1) kv.push(['Chain', st.chain + ' certificates']);
    body.replaceChildren(h('table', { class: 'simple kv' }, h('tbody', {}, kv.map(([k, v]) => h('tr', {}, h('th', {}, k), h('td', {}, v))))));
  }
  async function refresh() { try { st = await GET('/api/settings/cert'); draw(); } catch (e) { err.textContent = fmtErr(e); } }
  const readText = f => new Promise((res, rej) => { const r = new FileReader(); r.onload = () => res(String(r.result)); r.onerror = () => rej(new Error('cannot read ' + f.name)); r.readAsText(f); });
  async function upload() {
    err.textContent = '';
    const cf = h('input', { type: 'file', accept: '.crt,.pem,.cer,.cert,.chain' }), kf = h('input', { type: 'file', accept: '.key,.pem' });
    const ok = await dialog('Upload certificate', h('div', { class: 'frm' }, h('label', {}, 'Certificate (PEM, with chain)'), cf, h('label', {}, 'Private key (PEM, no passphrase)'), kf),
      [{ label: 'Cancel' }, { label: 'Upload', primary: true, action: async () => {
        if (!cf.files[0]) throw new Error('Choose the certificate file');
        const cert = await readText(cf.files[0]);
        const key = kf.files[0] ? await readText(kf.files[0]) : cert;   // one combined PEM file is fine
        st = await POST('/api/settings/cert/save', { cert, key });
      } }]);
    if (ok) draw();
  }
  async function reset() {
    if (!(await confirmBox('Use self-signed', 'Replace the uploaded certificate with a self-signed one? Browsers will warn again.', 'Replace'))) return;
    err.textContent = '';
    try { st = await POST('/api/settings/cert/reset', {}); draw(); } catch (e) { err.textContent = fmtErr(e); }
  }
  await refresh();
}

async function renderUpdate(page) {
  const err = h('span', { class: 'terr' });
  const body = h('div', { class: 'tablewrap' });
  let st = null, latest = null, timer = null, restarting = false;
  const checkBtn = h('button', { onclick: check }, 'Check online');
  const goBtn = h('button', { class: 'primary', hidden: true, onclick: () => online(latest) }, '');
  const up = h('input', { type: 'file', hidden: true, accept: '.tgz,.tar.gz,application/gzip' });
  const upBtn = h('button', { onclick: () => up.click() }, 'Upload release…');
  page.append(h('div', { class: 'toolbar' }, checkBtn, goBtn, upBtn, up, err), body);
  const WORD = { downloading: 'Downloading…', building: 'Building…', applying: 'Restarting…' };

  function draw() {
    const job = st.job || {}, busy = !!WORD[job.state], last = st.last;
    const off = busy || !st.canApply;
    for (const b of [checkBtn, upBtn]) { b.disabled = off; b.title = st.canApply ? '' : st.why; }
    goBtn.hidden = !busy && !(latest && latest.newer);
    goBtn.disabled = off; goBtn.title = st.canApply ? '' : st.why;
    goBtn.textContent = busy ? WORD[job.state] : latest && latest.newer ? 'Update to v' + latest.version : '';
    if (job.state === 'failed') err.textContent = job.msg;
    const kv = [['Installed', 'v' + st.version], ['Source', st.repo]];
    if (latest) kv.push(['Latest', latest.newer ? 'v' + latest.version : 'v' + st.version + ' (up to date)']);
    if (last) {
      const when = last.at ? new Date(last.at).toLocaleString() : '';
      const txt = `v${last.from} → v${last.to}, ${last.state}${last.by ? ', ' + last.by : ''}${when ? ', ' + when : ''}`;
      kv.push(['Last update', last.state === 'failed' || last.state === 'rolled-back' ? h('span', { class: 'terr', title: last.err || '' }, txt) : txt]);
    }
    body.replaceChildren(h('table', { class: 'simple kv' }, h('tbody', {}, kv.map(([k, v]) => h('tr', {}, h('th', {}, k), h('td', {}, v))))));
  }
  async function refresh() {
    try { st = await GET('/api/update'); } catch (e) {
      if (restarting) { clearInterval(timer); setTimeout(() => location.reload(), 3000); }   // the service is restarting: sign in again
      else err.textContent = fmtErr(e);
      return;
    }
    if (st.job && st.job.state === 'applying') restarting = true;
    draw();
    if (!(st.job && WORD[st.job.state]) && !restarting) { clearInterval(timer); timer = null; }
  }
  function poll() { if (!timer) timer = setInterval(() => { if (!page.isConnected) { clearInterval(timer); timer = null; } else refresh(); }, 1500); refresh(); }
  async function check() {
    err.textContent = ''; checkBtn.disabled = true;
    try { latest = await POST('/api/update/check', {}); } catch (e) { err.textContent = fmtErr(e); }
    await refresh();
  }
  async function online(l) {
    if (!(await confirmBox('Update', `Update to v${l.version}? goaduc restarts and everyone signs in again.`, 'Update'))) return;
    err.textContent = '';
    try { await POST('/api/update/online', { tag: l.tag }); } catch (e) { err.textContent = fmtErr(e); return; }
    poll();
  }
  up.addEventListener('change', async () => {
    const f = up.files[0]; up.value = '';
    if (!f || !(await confirmBox('Update', `Install “${f.name}”? goaduc restarts and everyone signs in again.`, 'Install'))) return;
    err.textContent = '';
    try {
      const r = await fetch('/api/update/upload', { method: 'POST', credentials: 'same-origin', headers: { 'X-Requested-With': 'aduc', 'Content-Type': 'application/octet-stream' }, body: f });
      const j = await r.json().catch(() => ({}));
      if (!r.ok) throw new Error(j.error || 'HTTP ' + r.status);
    } catch (e) { err.textContent = e.message; return; }
    poll();
  });
  await refresh();
  if (st && st.job && WORD[st.job.state]) poll();
}
