'use strict';
// ADUC web client. All DOM built with textContent / createElement (no innerHTML on data).

const $app = document.getElementById('app');
let info = null;            // {user, base, realm}
let cur = null;             // currently selected container DN
let items = [];             // items in list
let selected = new Set();   // selected DNs in list
let sortKey = 'name', sortDir = 1;
let mode = 'browse';        // browse | search
let tree = null;
let section = 'users';     // users | sites
let lastSearch = { q: '', type: 'all', base: null };
const rerunSearch = () => runSearch(lastSearch.q, lastSearch.type, lastSearch.base);

// ---------- helpers ----------
function h(tag, props, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(props || {})) {
    if (k === 'class') e.className = v;
    else if (k.startsWith('on')) e.addEventListener(k.slice(2), v);
    else if (k === 'value') e.value = v;
    else if (k === 'checked') e.checked = v;
    else if (v !== false && v != null) e.setAttribute(k, v === true ? '' : v);
  }
  for (const k of kids.flat()) if (k != null && k !== false) e.append(k.nodeType ? k : document.createTextNode(String(k)));
  return e;
}

async function api(method, path, body) {
  const opt = { method, headers: { 'X-Requested-With': 'aduc' }, credentials: 'same-origin' };
  if (body !== undefined) { opt.headers['Content-Type'] = 'application/json'; opt.body = JSON.stringify(body); }
  const r = await fetch(path, opt);
  let j = {};
  try { j = await r.json(); } catch (_) {}
  if (r.status === 401 && info) { info = null; showLogin('Session expired. Please sign in again.'); throw new Error('session expired'); }
  if (!r.ok) throw new Error(j.error || r.statusText);
  return j;
}
const GET = (p, q) => api('GET', p + (q ? '?' + new URLSearchParams(q) : ''));
const POST = (p, b) => api('POST', p, b);

const SVG = {
  folder: '<path d="M1 3h5l1.5 1.5H15v8.5H1z" fill="#e0a82e"/>',
  ou: '<path d="M1 3h5l1.5 1.5H15v8.5H1z" fill="#e0a82e"/><circle cx="8" cy="9" r="2" fill="#fff" stroke="#8a6500"/>',
  container: '<path d="M1 3h5l1.5 1.5H15v8.5H1z" fill="#9aa5b1"/>',
  domain: '<circle cx="8" cy="8" r="6.5" fill="#3b82f6"/><path d="M1.5 8h13M8 1.5c-3 3-3 10 0 13M8 1.5c3 3 3 10 0 13" stroke="#fff" fill="none"/>',
  user: '<circle cx="8" cy="5" r="3" fill="#4a90d9"/><path d="M2 14c0-4 3-5 6-5s6 1 6 5z" fill="#4a90d9"/>',
  group: '<circle cx="5.5" cy="5" r="2.5" fill="#4a90d9"/><circle cx="11" cy="6" r="2.2" fill="#6aa9e6"/><path d="M1 13c0-3 2-4.5 4.5-4.5S10 10 10 13zM9.5 13c.2-2 1.2-3.6 3.5-3.6 1.6 0 2.6 1 2.6 3.6z" fill="#4a90d9"/>',
  computer: '<rect x="1.5" y="2.5" width="13" height="8.5" rx="1" fill="#5b6672"/><rect x="3" y="4" width="10" height="5.5" fill="#9fd0ff"/><path d="M5 14h6M8 11v3" stroke="#5b6672"/>',
  other: '<rect x="3" y="2" width="10" height="12" rx="1" fill="#9aa5b1"/>',
};
SVG.site = '<circle cx="8" cy="8" r="6.5" fill="#43a047"/><path d="M1.5 8h13M8 1.5c-3 3-3 10 0 13M8 1.5c3 3 3 10 0 13" stroke="#fff" fill="none"/>';
SVG.subnet = '<circle cx="8" cy="3.5" r="2" fill="#7b61c9"/><circle cx="3" cy="12" r="2" fill="#7b61c9"/><circle cx="13" cy="12" r="2" fill="#7b61c9"/><path d="M8 5.5v3M8 8.5L3 10M8 8.5L13 10" stroke="#7b61c9" fill="none"/>';
SVG.sitelink = '<circle cx="3" cy="8" r="2.5" fill="#43a047"/><circle cx="13" cy="8" r="2.5" fill="#43a047"/><path d="M5.5 8h5" stroke="#e08a00" stroke-width="2"/>';
SVG.servers = SVG.folder; SVG.transport = SVG.container;
SVG.server = '<rect x="2" y="1.5" width="12" height="5" rx="1" fill="#5b6672"/><rect x="2" y="9" width="12" height="5" rx="1" fill="#5b6672"/><circle cx="4.5" cy="4" r=".8" fill="#9fd0ff"/><circle cx="4.5" cy="11.5" r=".8" fill="#9fd0ff"/>';
SVG.ntds = '<circle cx="8" cy="8" r="3" fill="none" stroke="#5b6672" stroke-width="2"/><path d="M8 1v3M8 12v3M1 8h3M12 8h3M3 3l2 2M11 11l2 2M13 3l-2 2M5 11l-2 2" stroke="#5b6672" stroke-width="1.6"/>';
SVG.connection = '<path d="M2 5h10M9 2l3 3-3 3M14 11H4M7 8l-3 3 3 3" stroke="#1f6feb" stroke-width="1.6" fill="none"/>';
SVG.sitesettings = SVG.other;
SVG.builtin = SVG.container; SVG.contact = SVG.user; SVG.fsp = SVG.other;
function icon(t) {
  const s = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  s.setAttribute('viewBox', '0 0 16 16'); s.setAttribute('class', 'ico');
  s.innerHTML = SVG[t] || SVG.other; // static strings only
  return s;
}
const TYPE_LABEL = { dnsrecord: 'DNS record', site: 'Site', subnet: 'Subnet', sitelink: 'Site Link', servers: 'Servers Container', server: 'Server', ntds: 'NTDS Settings', connection: 'Connection', sitesettings: 'NTDS Site Settings', transport: 'Inter-Site Transport', user: 'User', group: 'Group', computer: 'Computer', ou: 'Organizational Unit', container: 'Container', domain: 'Domain', builtin: 'builtinDomain', contact: 'Contact', fsp: 'Foreign Security Principal', other: 'Object' };
const USER_CONT = ['ou', 'container', 'domain', 'builtin'];
const SITE_CONT = ['container', 'site', 'servers', 'server', 'ntds', 'transport'];
// Tree nodes and "open on double-click": in the LDAP Browser only objects that can hold others; elsewhere by kind.
const isCont = it => section === 'browser' ? !!it.cont : (section === 'sites' ? SITE_CONT : USER_CONT).includes(it.type);
const sitesRoot = () => 'CN=Sites,' + info.config;
const lc = x => String(x).toLowerCase();
const isProtectedSite = dn => { const sr = sitesRoot(); return [info.config, sr, 'CN=Subnets,' + sr, 'CN=Inter-Site Transports,' + sr, 'CN=IP,CN=Inter-Site Transports,' + sr, 'CN=SMTP,CN=Inter-Site Transports,' + sr].some(p => lc(p) === lc(dn)); };
const rdnName = dn => { const r = dn.split(/(?<!\\),/)[0]; return r.slice(r.indexOf('=') + 1).replace(/\\(.)/g, '$1'); };
const parentOf = dn => dn.split(/(?<!\\),/).slice(1).join(',');

// Failures only: plain red text at the end of the toolbar. No progress or success messages.
function status(msg, bad) {
  const s = document.getElementById('st-err');
  if (s) s.textContent = bad ? (msg || '') : '';
}
function fail(e) { status(e.message || String(e), true); }

// ---------- dialogs ----------
function dialog(title, body, buttons, opts = {}) {
  return new Promise(resolve => {
    const msg = h('span', { class: 'msg' });
    const back = h('div', { class: 'back' });
    const close = v => { back.remove(); resolve(v); };
    const foot = h('div', { class: 'foot' }, msg);
    for (const b of buttons) {
      const btn = h('button', { class: (b.primary ? 'primary ' : '') + (b.danger ? 'danger' : '') }, b.label);
      btn.addEventListener('click', async () => {
        if (!b.action) return close(b.value ?? null);
        btn.disabled = true; msg.textContent = '';
        try { const r = await b.action(); close(r === undefined ? true : r); }
        catch (e) { msg.textContent = e.message; btn.disabled = false; }
      });
      foot.append(btn);
    }
    const dlg = h('div', { class: 'dlg' + (opts.wide ? ' wide' : '') }, h('h2', {}, title), h('div', { class: 'body' }, body), foot);
    back.append(dlg);
    back.addEventListener('mousedown', e => { if (e.target === back && !opts.modal) close(null); });
    back.addEventListener('keydown', e => { if (e.key === 'Escape') close(null); });
    document.body.append(back);
    const f = dlg.querySelector('input,select,textarea'); if (f) f.focus();
  });
}
const confirmBox = (title, text, label = 'OK', danger = false) =>
  dialog(title, h('div', {}, text), [{ label: 'Cancel', value: false }, { label, primary: !danger, danger, value: true }]).then(v => v === true);

// Domain suffix first, then the alternative UPN suffixes (empty list if the DC refuses the read).
async function upnSuffixes() {
  try { return [info.realm, ...((await GET('/api/upnsuffixes')).suffixes || [])]; } catch (_) { return [info.realm]; }
}
const upnWith = (upn, suf, sam) => { const l = (sam != null ? sam : String(upn || '').split('@')[0]); return l ? l + '@' + suf : ''; };

function form(fields) { // fields: [{k,label,type,value,opts,full}] → {el, get()}
  const el = h('div', { class: 'frm' }), inputs = {};
  for (const f of fields) {
    let inp;
    if (f.type === 'check') {
      inp = h('input', { type: 'checkbox', checked: !!f.value });
      el.append(h('label', { class: 'chk' }, inp, f.label));
    } else {
      if (f.type === 'select') inp = h('select', {}, f.opts.map(([v, l]) => h('option', { value: v }, l)));
      else if (f.type === 'area') inp = h('textarea', { rows: 3 });
      else inp = h('input', { type: f.type || 'text', autocomplete: 'off' });
      if (f.value != null) inp.value = f.value;
      if (f.readonly) inp.readOnly = true;
      if (f.oninput) inp.addEventListener('input', () => f.oninput(inp, inputs));
      el.append(h('label', {}, f.label), inp);
    }
    inputs[f.k] = inp;
  }
  return { el, inputs, get: () => Object.fromEntries(Object.entries(inputs).map(([k, i]) => [k, i.type === 'checkbox' ? i.checked : i.value])) };
}

// ---------- context menu ----------
function menu(x, y, entries) {
  document.querySelectorAll('.menu').forEach(m => m.remove());
  const m = h('div', { class: 'menu' });
  for (const e of entries) {
    if (e === '-') { m.append(h('hr')); continue; }
    const d = h('div', { class: e.disabled ? 'd' : e.danger ? 'x' : '' }, e.label);
    if (!e.disabled) d.addEventListener('click', () => { m.remove(); e.fn(); });
    m.append(d);
  }
  document.body.append(m);
  const r = m.getBoundingClientRect();
  m.style.left = Math.min(x, innerWidth - r.width - 4) + 'px';
  m.style.top = Math.min(y, innerHeight - r.height - 4) + 'px';
}
document.addEventListener('click', () => document.querySelectorAll('.menu').forEach(m => m.remove()));
document.addEventListener('keydown', e => { if (e.key === 'Escape') document.querySelectorAll('.menu').forEach(m => m.remove()); });

// ---------- login ----------
function themeBtn() {
  const b = h('button', { class: 'themebtn', title: 'Theme: Auto follows your system', onclick: () => { adTheme.next(); b.textContent = adTheme.label(); } }, adTheme.label());
  return b;
}

function showLogin(msg) {
  $app.replaceChildren();
  const u = h('input', { type: 'text', autocomplete: 'username', placeholder: 'administrator@example.com' });
  const p = h('input', { type: 'password', autocomplete: 'current-password' });
  const err = h('div', { class: 'err' }, msg || '');
  const go = async () => {
    err.textContent = '';
    try {
      info = await POST('/api/login', { username: u.value.trim(), password: p.value });
      p.value = '';
      showMain();
    } catch (e) { err.textContent = e.message; }
  };
  p.addEventListener('keydown', e => { if (e.key === 'Enter') go(); });
  u.addEventListener('keydown', e => { if (e.key === 'Enter') p.focus(); });
  $app.append(h('div', { class: 'login' },
    h('h1', {}, 'Directory Manager'),
    h('label', {}, 'User name'), u, h('label', {}, 'Password'), p,
    h('button', { class: 'primary', onclick: go }, 'Sign in'), err, themeBtn()));
  u.focus();
}

// ---------- main layout ----------
const SECTIONS = [['users', 'Users and Computers'], ['sites', 'Sites and Services'], ['dns', 'DNS'], ['gpo', 'Group Policy'], ['domain', 'Domain'], ['reports', 'Reports'], ['browser', 'LDAP Browser'], ['audit', 'Audit Log'], ['recycle', 'Recycle Bin'], ['settings', 'Settings']];
let browserNC = null;

function navBar() {
  return h('div', { class: 'topbar' },
    h('div', { class: 'nav' }, SECTIONS.map(([k, l]) => h('button', { class: section === k ? 'on' : '', onclick: () => { if (section !== k) { section = k; showMain(); } } }, l))),
    h('span', { class: 'sp', style: 'flex:1' }), h('span', { class: 'muted' }, info.user), themeBtn(),
    h('button', { onclick: async () => { try { await POST('/api/logout', {}); } catch (_) {} info = null; section = 'users'; showLogin(); } }, 'Sign out'));
}
const statusBar = () => h('div', { class: 'status' }, h('span', { id: 'st-count' }), h('span', { style: 'flex:1' }), h('span', {}, info.realm));

function showMain() {
  $app.replaceChildren(); cur = null; items = []; selected.clear(); mode = 'browse';
  $app.append(navBar());
  if (TOOLS[section]) { const page = h('div', { class: 'page' }); $app.append(page, statusBar()); TOOLS[section](page); return; }

  let tools;
  if (section === 'users') {
    const q = h('input', { type: 'text', placeholder: 'Find users, groups, computers (or an LDAP filter)…' });
    const qt = h('select', {}, [['all', 'All'], ['user', 'Users'], ['group', 'Groups'], ['computer', 'Computers'], ['ou', 'OUs'], ['disabled', 'Disabled accounts']].map(([v, l]) => h('option', { value: v }, l)));
    const doFind = () => runSearch(q.value.trim(), qt.value);
    q.addEventListener('keydown', e => { if (e.key === 'Enter') doFind(); });
    tools = [h('button', { onclick: () => refresh() }, 'Refresh'),
      h('button', { onclick: () => newObject('user') }, 'New user'), h('button', { onclick: () => newObject('group') }, 'New group'),
      h('button', { onclick: () => newObject('ou') }, 'New OU'), h('button', { onclick: () => newObject('computer') }, 'New computer'),
      h('button', { onclick: e => { e.stopPropagation(); queriesMenu(e.currentTarget); } }, 'Queries ▾'), h('button', { onclick: exportList }, 'Export CSV'),
      h('span', { class: 'sp' }), q, qt, h('button', { onclick: doFind }, 'Find')];
  } else if (section === 'sites') {
    tools = [h('button', { onclick: () => refresh() }, 'Refresh'), h('button', { onclick: () => newSite() }, 'New site'),
      h('button', { onclick: () => newSubnet() }, 'New subnet'), h('button', { onclick: () => newSiteLink() }, 'New site link'), h('span', { class: 'sp' })];
  } else { // browser
    browserNC = browserNC || info.base;
    const ncSel = h('select', { style: 'max-width:320px' }, (info.ncs && info.ncs.length ? info.ncs : [info.base]).map(n => h('option', { value: n }, n)));
    ncSel.value = browserNC;
    ncSel.addEventListener('change', () => { browserNC = ncSel.value; showMain(); });
    const q = h('input', { type: 'text', placeholder: 'Text or LDAP filter, e.g. (objectClass=dnsNode)' });
    const base = () => cur || browserNC;
    const go = () => runSearch(q.value.trim(), 'any', base());
    q.addEventListener('keydown', e => { if (e.key === 'Enter') go(); });
    tools = [ncSel, h('button', { onclick: () => refresh() }, 'Refresh'), h('span', { class: 'sp' }), q, h('button', { onclick: go }, 'Search below selection'),
      h('button', { title: 'Search classes and attributes in the schema by name', onclick: () => { const t = q.value.trim(); runSearch('(&(|(objectClass=classSchema)(objectClass=attributeSchema))' + (t ? '(|(lDAPDisplayName=*' + escF(t) + '*)(name=*' + escF(t) + '*))' : '') + ')', 'any', info.schema); } }, 'Schema search')];
  }
  const treeEl = h('div', { class: 'tree' });
  const listEl = h('div', { class: 'list', id: 'list' });
  $app.append(h('div', { class: 'toolbar' }, ...tools, h('span', { id: 'st-err', class: 'terr' })), h('div', { class: 'main' }, treeEl, listEl), statusBar());
  const onSelect = dn => { mode = 'browse'; cur = dn; load(); };
  const onMenu = (e, n) => section === 'sites' ? sitesMenu(e.clientX, e.clientY, [n]) : section === 'browser' ? browserMenu(e.clientX, e.clientY, [n]) : containerMenu(e.clientX, e.clientY, n);
  tree = section === 'sites' ? makeTree(treeEl, { rootDn: sitesRoot(), rootName: 'Sites', rootType: 'container', onSelect, onMenu })
    : section === 'browser' ? makeTree(treeEl, { rootDn: browserNC, rootName: browserNC, rootType: 'container', onSelect, onMenu })
      : makeTree(treeEl, { onSelect, onMenu });
  tree.init();
}

function browserMenu(x, y, sel) {
  if (!sel.length) return;
  const one = sel.length === 1 ? sel[0] : null, e = [];
  if (one) {
    e.push({ label: 'Properties', fn: () => properties(one.dn) });
    e.push({ label: 'Open in tree', fn: async () => { try { await tree.reveal(one.dn); tree.select(one.dn); } catch (er) { fail(er); } } });
    e.push({ label: 'Refresh', fn: () => { tree.refresh(one.dn); if (lc(cur) === lc(one.dn)) load(); } });
    e.push('-', { label: 'Rename…', fn: () => renameObj(one.dn) });
  }
  e.push({ label: 'Delete…', danger: true, fn: () => deleteObjs(sel) });
  menu(x, y, e);
}

function exportList() {
  if (!items.length) return status('Nothing to export.', true);
  downloadCSV('objects.csv', ['Name', 'Type', 'Logon name', 'UPN', 'E-mail', 'Disabled', 'Description', 'DN'], items.map(i => [i.name, TYPE_LABEL[i.type] || i.type, i.sam || '', i.upn || '', i.mail || '', i.disabled ? 'yes' : '', i.description || '', i.dn]));
}

// ---------- saved queries and query builder ----------
const escF = s => Array.from(new TextEncoder().encode(s)).map(b => (b < 0x20 || b > 0x7e || '*()\\'.includes(String.fromCharCode(b))) ? '\\' + b.toString(16).padStart(2, '0') : String.fromCharCode(b)).join('');
const QKEY = 'aduc.queries';
const loadQueries = () => { try { return JSON.parse(localStorage.getItem(QKEY) || '[]'); } catch (_) { return []; } };
const storeQueries = q => { try { localStorage.setItem(QKEY, JSON.stringify(q)); } catch (_) { status('Could not save (browser storage unavailable).', true); } };

function queriesMenu(btn) {
  const r = btn.getBoundingClientRect(), qs = loadQueries();
  const e = qs.map(q => ({ label: q.name, fn: () => runSearch(q.filter, 'all', q.base || info.base) }));
  if (qs.length) e.push('-');
  e.push({ label: 'Query builder…', fn: () => queryBuilder() });
  if (qs.length) { e.push('-'); for (const q of qs) e.push({ label: 'Delete “' + q.name + '”', danger: true, fn: () => storeQueries(loadQueries().filter(x => x.name !== q.name)) }); }
  menu(r.left, r.bottom + 2, e);
}

const QB = [['name', 'Name', 'text'], ['sAMAccountName', 'Logon name', 'text'], ['displayName', 'Display name', 'text'], ['givenName', 'First name', 'text'], ['sn', 'Last name', 'text'],
  ['mail', 'E-mail', 'text'], ['description', 'Description', 'text'], ['department', 'Department', 'text'], ['title', 'Job title', 'text'], ['company', 'Company', 'text'],
  ['userPrincipalName', 'User principal name', 'text'], ['servicePrincipalName', 'Service principal name', 'text'], ['memberOf', 'Member of (full DN)', 'text'], ['manager', 'Manager (full DN)', 'text'],
  ['lastLogonTimestamp', 'Last logon', 'ft'], ['pwdLastSet', 'Password last set', 'ft'], ['whenCreated', 'Created', 'gt'], ['whenChanged', 'Modified', 'gt'], ['userAccountControl', 'Account control flags', 'bits']];
const QB_OPS = {
  text: [['contains', 'contains'], ['eq', 'is'], ['ne', 'is not'], ['starts', 'starts with'], ['ends', 'ends with'], ['set', 'has a value'], ['unset', 'has no value']],
  ft: [['older', 'is older than (days)'], ['newer', 'is within the last (days)'], ['unset', 'was never set']],
  gt: [['older', 'is older than (days)'], ['newer', 'is within the last (days)']],
  bits: [['on', 'has bit set (number)'], ['off', 'has bit clear (number)']],
};
function qbClause(attr, kind, op, v) {
  const days = Math.max(0, parseFloat(v) || 0), t = Date.now() - days * 86400000;
  if (kind === 'text') {
    const e = escF(v);
    return { contains: `(${attr}=*${e}*)`, eq: `(${attr}=${e})`, ne: `(!(${attr}=${e}))`, starts: `(${attr}=${e}*)`, ends: `(${attr}=*${e})`, set: `(${attr}=*)`, unset: `(!(${attr}=*))` }[op];
  }
  if (kind === 'ft') {
    if (op === 'unset') return `(|(!(${attr}=*))(${attr}=0))`;
    return `(${attr}${op === 'older' ? '<=' : '>='}${(BigInt(Math.floor(t)) + 11644473600000n) * 10000n})`;
  }
  if (kind === 'gt') { const d = new Date(t).toISOString().replace(/[-:T]/g, '').slice(0, 14) + '.0Z'; return `(${attr}${op === 'older' ? '<=' : '>='}${d})`; }
  const n = parseInt(v, 10) || 0, c = `(${attr}:1.2.840.113556.1.4.803:=${n})`;
  return op === 'on' ? c : `(!${c})`;
}
const QB_TYPES = { all: '(|(objectClass=user)(objectClass=group)(objectClass=organizationalUnit)(objectClass=contact))', user: '(&(objectClass=user)(!(objectClass=computer)))', computer: '(objectClass=computer)', group: '(objectClass=group)', ou: '(objectClass=organizationalUnit)' };

async function queryBuilder() {
  const type = h('select', {}, [['all', 'Any object'], ['user', 'Users'], ['computer', 'Computers'], ['group', 'Groups'], ['ou', 'Organizational units']].map(([v, l]) => h('option', { value: v }, l)));
  const comb = h('select', {}, [['&', 'all of'], ['|', 'any of']].map(([v, l]) => h('option', { value: v }, l)));
  const scope = h('select', {}, [[info.base, 'Entire domain'], ...(cur && mode === 'browse' && section === 'users' && lc(cur) !== lc(info.base) ? [[cur, 'Current container: ' + rdnName(cur)]] : [])].map(([v, l]) => h('option', { value: v }, l)));
  const rowsEl = h('div'), out = h('textarea', { rows: 3, style: 'font-family:monospace;font-size:12px' });
  let manual = false;
  const rows = [];
  const regen = () => {
    if (manual) return;
    const cl = rows.map(r => { const [a, , k] = QB.find(x => x[0] === r.attr.value); return r.op.value && (r.val.disabled || r.val.value !== '' || ['set', 'unset'].includes(r.op.value)) ? qbClause(a, k, r.op.value, r.val.value) : null; }).filter(Boolean);
    out.value = '(&' + QB_TYPES[type.value] + (cl.length ? (cl.length > 1 ? '(' + comb.value + cl.join('') + ')' : cl[0]) : '') + ')';
  };
  out.addEventListener('input', () => { manual = true; });
  [type, comb].forEach(x => x.addEventListener('change', regen));
  const addRow = () => {
    const attr = h('select', {}, QB.map(([v, l]) => h('option', { value: v }, l))), op = h('select'), val = h('input', { type: 'text' });
    const fill = () => { const k = QB.find(x => x[0] === attr.value)[2]; op.replaceChildren(...QB_OPS[k].map(([v, l]) => h('option', { value: v }, l))); sync(); };
    const sync = () => { val.disabled = ['set', 'unset'].includes(op.value); regen(); };
    attr.addEventListener('change', fill); op.addEventListener('change', sync); val.addEventListener('input', regen);
    const r = { attr, op, val }; rows.push(r);
    const del = h('button', { onclick: () => { rows.splice(rows.indexOf(r), 1); line.remove(); regen(); } }, '✕');
    const line = h('div', { class: 'qbrow' }, attr, op, val, del);
    rowsEl.append(line); fill();
  };
  addRow();
  regen();
  const body = h('div', {}, h('div', { class: 'row2', style: 'margin:0 0 8px' }, 'Find', type, 'where', comb, 'these match:'), rowsEl,
    h('div', { class: 'row2' }, h('button', { onclick: addRow }, '+ Add condition'), h('span', { class: 'sp', style: 'flex:1' }), 'Search in', scope),
    h('div', { class: 'sec' }, 'LDAP filter (editable)'), out);
  const r = await dialog('Query builder', body, [{ label: 'Cancel' },
    { label: 'Save as…', action: async () => {
      const f = form([{ k: 'name', label: 'Query name' }]);
      const nm = await dialog('Save query', f.el, [{ label: 'Cancel' }, { label: 'Save', primary: true, action: async () => { const n = f.get().name.trim(); if (!n) throw new Error('Enter a name'); return n; } }]);
      if (typeof nm === 'string') { storeQueries([...loadQueries().filter(q => q.name !== nm), { name: nm, filter: out.value.trim(), base: scope.value }]) }
      throw new Error('');   // keep the builder open
    } },
    { label: 'Run', primary: true, action: async () => { if (!out.value.trim().startsWith('(')) throw new Error('Not a valid LDAP filter'); return { filter: out.value.trim(), base: scope.value }; } }], { wide: true });
  if (r && r.filter) runSearch(r.filter, 'all', r.base);
}

// ---------- tree ----------
function makeTree(root, opts) {
  const nodes = new Map(); // dn -> {dn,name,type,li,kids:ul,loaded,open}
  const api_ = {};
  const rootDn = () => opts.rootDn || info.base;
  async function loadKids(n) {
    const r = await GET('/api/children', { dn: n.dn });
    n.kids.replaceChildren();
    n.loaded = true;
    const cs = r.items.filter(i => isCont(i));
    n.twisty.textContent = cs.length ? (n.open ? '▼' : '▶') : '';
    for (const c of cs) addNode(c, n.kids);
  }
  function addNode(it, ul) {
    const n = { dn: it.dn, name: it.name, type: it.type, open: false, loaded: false };
    const tw = h('span', { class: 'twisty' }, '▶');
    const label = h('div', { class: 'tnode' }, tw, icon(it.type), it.name);
    n.kids = h('ul'); n.kids.hidden = true; n.twisty = tw; n.label = label;
    n.li = h('li', {}, label, n.kids);
    nodes.set(it.dn.toLowerCase(), n);
    const toggle = async () => {
      if (!n.loaded) { try { await loadKids(n); } catch (e) { return fail(e); } }
      n.open = !n.open; n.kids.hidden = !n.open;
      if (n.kids.children.length) tw.textContent = n.open ? '▼' : '▶';
    };
    tw.addEventListener('click', e => { e.stopPropagation(); toggle(); });
    label.addEventListener('click', () => api_.select(n.dn));
    label.addEventListener('dblclick', toggle);
    label.addEventListener('contextmenu', e => { e.preventDefault(); api_.select(n.dn, true); opts.onMenu && opts.onMenu(e, n); });
    ul.append(n.li);
    return n;
  }
  api_.select = (dn, silent) => {
    const n = nodes.get(dn.toLowerCase());
    if (!n) return;
    root.querySelectorAll('.tnode.sel').forEach(x => x.classList.remove('sel'));
    n.label.classList.add('sel');
    api_.current = dn;
    if (!silent || opts.onSelect) opts.onSelect(dn);
  };
  api_.init = async () => {
    root.replaceChildren();
    const ul = h('ul'); root.append(ul);
    const n = addNode({ dn: rootDn(), name: opts.rootName || info.realm, type: opts.rootType || 'domain' }, ul);
    try { await loadKids(n); n.open = true; n.kids.hidden = false; n.twisty.textContent = n.kids.children.length ? '▼' : ''; } catch (e) { fail(e); }
    api_.select(rootDn());
  };
  api_.refresh = async dn => {
    const n = nodes.get((dn || '').toLowerCase());
    if (!n) return;
    const wasOpen = n.open;
    try { await loadKids(n); n.open = wasOpen || n.open; n.kids.hidden = !n.open; if (n.kids.children.length) n.twisty.textContent = n.open ? '▼' : '▶'; } catch (e) { fail(e); }
  };
  api_.reveal = async dn => { // expand path to dn
    const chain = []; let d = dn;
    while (d && d.toLowerCase() !== rootDn().toLowerCase()) { chain.unshift(d); d = parentOf(d); }
    let p = nodes.get(rootDn().toLowerCase());
    for (const c of chain) {
      if (!p) return;
      if (!p.loaded) await loadKids(p);
      p.open = true; p.kids.hidden = false;
      p = nodes.get(c.toLowerCase());
    }
    return nodes.get(dn.toLowerCase());
  };
  return api_;
}

// ---------- list ----------
async function load() {
  status('');
  try {
    const r = await GET('/api/children', { dn: cur });
    items = r.items.map(withDetails); selected.clear();
    renderList(r.truncated ? 'Result list truncated at 5000 entries.' : '');
  } catch (e) { items = []; renderList(); fail(e); }
}

async function runSearch(q, type, base) {
  lastSearch = { q, type, base };
  status('');
  try {
    const r = await GET('/api/search', { q, type, base: base || info.base });
    mode = 'search'; items = r.items.map(withDetails); selected.clear();
    renderList(r.truncated ? 'Showing the first 500 matches.' : '');
  } catch (e) { fail(e); }
}

function refresh() {
  if (mode === 'search' || !cur) return;
  tree.refresh(cur); load();
}

function withDetails(it) {
  const x = it.extra || {};
  switch (it.type) {
    case 'subnet': it.details = [x.site ? 'Site: ' + x.site : '(no site)', x.location].filter(Boolean).join(' · '); break;
    case 'sitelink': it.details = `Cost ${x.cost || '?'}, every ${x.interval || '?'} min — ${x.sites || ''}`; break;
    case 'connection': it.details = 'From: ' + (x.from || '?') + (x.enabled === 'FALSE' ? ' (disabled)' : ''); break;
    case 'server': it.details = x.dns || ''; break;
    case 'site': it.details = x.location || ''; break;
    default: it.details = '';
  }
  return it;
}

function renderList(note) {
  const el = document.getElementById('list');
  const cols = section === 'sites' ? [['name', 'Name'], ['type', 'Type'], ['details', 'Details'], ['description', 'Description']]
    : [['name', 'Name'], ['type', 'Type'], ['sam', 'Logon name'], ['description', 'Description']];
  if (mode === 'search') cols.push(['dn', 'Location']);
  const sorted = [...items].sort((a, b) => {
    const ca = isCont(a) ? 0 : 1, cb = isCont(b) ? 0 : 1;
    if (mode === 'browse' && ca !== cb) return ca - cb;
    return String(a[sortKey] || '').toLowerCase().localeCompare(String(b[sortKey] || '').toLowerCase()) * sortDir;
  });
  const thead = h('tr', {}, cols.map(([k, l]) => h('th', { onclick: () => { sortDir = sortKey === k ? -sortDir : 1; sortKey = k; renderList(note); } }, l + (sortKey === k ? (sortDir > 0 ? ' ▲' : ' ▼') : ''))));
  const byRow = new Map();   // row -> item, so the list can handle double-click itself
  const paint = () => byRow.forEach((it, tr) => tr.classList.toggle('sel', selected.has(it.dn)));
  const rows = sorted.map(it => {
    const tr = h('tr', { class: 'row' + (selected.has(it.dn) ? ' sel' : '') },
      h('td', { class: it.disabled ? 'dis' : '' }, icon(it.type), it.name),
      h('td', {}, section === 'browser' ? (it.class || it.type) : (TYPE_LABEL[it.type] || it.type)),
      h('td', { title: section === 'sites' ? it.details : '' }, section === 'sites' ? it.details : (it.sam || '')),
      h('td', { title: it.description }, it.description),
      mode === 'search' ? h('td', { title: it.dn }, parentOf(it.dn)) : null);
    tr.addEventListener('click', e => {
      if (e.ctrlKey || e.metaKey) selected.has(it.dn) ? selected.delete(it.dn) : selected.add(it.dn);
      else { selected.clear(); selected.add(it.dn); }
      paint();   // update in place: rebuilding the rows here made the second click of a double-click miss
    });
    byRow.set(tr, it);
    tr.addEventListener('contextmenu', e => {
      e.preventDefault();
      if (!selected.has(it.dn)) { selected.clear(); selected.add(it.dn); paint(); }
      section === 'sites' ? sitesMenu(e.clientX, e.clientY, selItems()) : section === 'browser' ? browserMenu(e.clientX, e.clientY, selItems()) : itemMenu(e.clientX, e.clientY);
    });
    return tr;
  });
  el.replaceChildren(h('table', {}, h('thead', {}, thead), h('tbody', {}, rows)));
  el.ondblclick = e => {
    const tr = e.target.closest && e.target.closest('tr.row'), it = tr && byRow.get(tr);
    if (it) { selected.clear(); selected.add(it.dn); paint(); openItem(it); }
  };
  const cnt = document.getElementById('st-count');
  cnt.textContent = (mode === 'search' ? 'Search results: ' : '') + items.length + ' object' + (items.length === 1 ? '' : 's') + (note ? ' (truncated)' : '');
  cnt.title = note || '';
  el.oncontextmenu = e => { if (e.target === el && mode === 'browse') { e.preventDefault(); if (section === 'sites') sitesMenu(e.clientX, e.clientY, [{ dn: cur, name: rdnName(cur), type: 'container' }]); else containerMenu(e.clientX, e.clientY, { dn: cur }); } };
}

async function openItem(it) {
  if (section === 'browser') return properties(it.dn);
  if (isCont(it) && mode === 'browse') {
    try { await tree.reveal(it.dn); tree.select(it.dn); } catch (e) { fail(e); }
  } else properties(it.dn);
}

const selItems = () => items.filter(i => selected.has(i.dn));

// ---------- menus ----------
function newMenuEntries(parent) {
  return ['user', 'group', 'ou', 'computer'].map(k => ({ label: 'New ' + { user: 'User', group: 'Group', ou: 'Organizational Unit', computer: 'Computer' }[k] + '…', fn: () => newObject(k, parent) }));
}
function containerMenu(x, y, n) {
  const isRoot = n.dn.toLowerCase() === info.base.toLowerCase();
  menu(x, y, [...newMenuEntries(n.dn), '-',
    { label: 'Refresh', fn: () => { tree.refresh(n.dn); if (cur === n.dn) load(); } },
    { label: 'Properties', fn: () => properties(n.dn) },
    '-',
    { label: 'Rename…', disabled: isRoot, fn: () => renameObj(n.dn) },
    { label: 'Move…', disabled: isRoot, fn: () => moveObjs([n.dn]) },
    { label: 'Delete…', danger: true, disabled: isRoot, fn: () => deleteObjs([{ dn: n.dn, name: n.name, type: n.type }]) }]);
}
function itemMenu(x, y) {
  const sel = selItems(); if (!sel.length) return;
  const one = sel.length === 1 ? sel[0] : null;
  const users = sel.filter(i => i.type === 'user' || i.type === 'computer');
  const e = [];
  if (one) e.push({ label: isCont(one) && mode === 'browse' ? 'Open' : 'Properties', fn: () => openItem(one) });
  if (one && isCont(one)) e.push({ label: 'Properties', fn: () => properties(one.dn) });
  if (one && (one.type === 'user')) e.push({ label: 'Reset password…', fn: () => resetPassword(one) });
  if (users.length) {
    e.push('-');
    const anyEn = users.some(u => !u.disabled), anyDis = users.some(u => u.disabled);
    if (anyDis) e.push({ label: 'Enable account', fn: () => setEnabled(users, true) });
    if (anyEn) e.push({ label: 'Disable account', fn: () => setEnabled(users, false) });
    if (one && one.type === 'user') e.push({ label: 'Unlock account', fn: () => POST('/api/unlock', { dn: one.dn }).then(() => status('')).catch(fail) });
  }
  if (sel.length) e.push({ label: 'Add to a group…', fn: () => addToGroup(sel) });
  e.push('-');
  if (one) e.push({ label: 'Rename…', fn: () => renameObj(one.dn) });
  e.push({ label: 'Move…', fn: () => moveObjs(sel.map(s => s.dn)) });
  e.push({ label: 'Delete…', danger: true, fn: () => deleteObjs(sel) });
  menu(x, y, e);
}

// ---------- actions ----------
async function afterChange(refreshDn) {
  await tree.refresh(refreshDn || cur);
  if (mode === 'browse') await load();
}

// If the current container was renamed/moved/deleted, fall back to its parent.
async function fixCurrent(oldDns) {
  if (mode !== 'browse') return;
  for (const d of oldDns) {
    if (cur.toLowerCase() === d.toLowerCase() || cur.toLowerCase().endsWith(',' + d.toLowerCase())) {
      cur = parentOf(d);
      await tree.refresh(cur);
      tree.select(cur);
      return;
    }
  }
}

async function setEnabled(list, on) {
  try {
    for (const u of list) await POST('/api/uac', on ? { dn: u.dn, clear: 2 } : { dn: u.dn, set: 2 });
    status('');
    if (mode === 'browse') load(); else rerunSearch();
  } catch (e) { fail(e); }
}

async function renameObj(dn) {
  const f = form([{ k: 'name', label: 'New name', value: rdnName(dn) }]);
  const ok = await dialog('Rename', f.el, [{ label: 'Cancel' }, { label: 'Rename', primary: true, action: async () => {
    const r = await POST('/api/rename', { dn, name: f.get().name }); return r; } }]);
  if (ok) { await fixCurrent([dn]); await afterChange(parentOf(dn)); }
}

async function deleteObjs(list) {
  const names = list.map(i => i.name).join(', ');
  const hasCont = list.some(i => isCont(i));
  const f = form(hasCont ? [{ k: 'rec', type: 'check', label: 'Also delete everything inside (subtree delete)' }] : []);
  let rb = { enabled: false, known: false };
  try { rb = await GET('/api/recyclebin'); } catch (_) { /* treated as unknown: the dialog says permanent */ }
  const what = list.length > 1 ? list.length + ' objects' : '“' + names + '”';
  const ok = await dialog('Delete', h('div', {}, h('p', {}, rb.enabled ? `Delete ${what}? It goes to the Recycle Bin.` : `Permanently delete ${what}? The Recycle Bin is ${rb.known ? 'off' : 'not confirmed on'}; this cannot be undone.`),
      list.some(i => ['server', 'servers', 'ntds', 'site'].includes(i.type)) ? h('p', { class: 'err' }, 'Warning: deleting sites, servers or NTDS Settings of a live domain controller breaks replication. To retire a DC properly use “samba-tool domain demote”.') : null, f.el),
    [{ label: 'Cancel' }, { label: 'Delete', danger: true, action: async () => {
      for (const i of list) await POST('/api/delete', { dn: i.dn, recursive: !!f.get().rec });
    } }]);
  if (ok) { selected.clear(); await fixCurrent(list.map(i => i.dn)); await afterChange(parentOf(list[0].dn)); if (mode === 'search') rerunSearch(); }
}

async function pickContainer(title) {
  const box = h('div', { class: 'pl', style: 'height:320px;padding:4px' });
  let target = null;
  const t = makeTree(box, { onSelect: dn => { target = dn; }, onMenu: null });
  const p = dialog(title, h('div', {}, h('p', { class: 'muted' }, 'Choose a container:'), box), [{ label: 'Cancel' }, { label: 'Select', primary: true, action: async () => {
    if (!target) throw new Error('Choose a container');
    return target;
  } }]);
  t.init();
  const r = await p;
  return typeof r === 'string' ? r : null;
}

async function moveObjs(dns) {
  const target = await pickContainer('Move to');
  if (!target) return;
  try {
    for (const dn of dns) await POST('/api/move', { dn, newParent: target });
  } catch (e) { return fail(e); }
  selected.clear(); await fixCurrent(dns); await tree.refresh(target); await tree.refresh(parentOf(dns[0])); if (mode === 'browse') load();
}

async function pickObjects(title, type, multi = true, base) {
  const q = h('input', { type: 'text', placeholder: 'Search by name…' });
  const out = h('div', { class: 'pl' });
  const chosen = new Map();
  let res = [];
  const draw = () => out.replaceChildren(...res.map(it => {
    const d = h('div', { class: 'it' + (chosen.has(it.dn) ? ' sel' : '') }, icon(it.type), it.name, h('span', { class: 'muted' }, ' — ' + parentOf(it.dn)));
    d.addEventListener('click', () => { if (!multi) chosen.clear(); chosen.has(it.dn) ? chosen.delete(it.dn) : chosen.set(it.dn, it); draw(); });
    return d;
  }));
  const go = async () => { try { res = (await GET('/api/search', { q: q.value.trim(), type, base: base || info.base })).items; draw(); } catch (e) { out.textContent = e.message; } };
  q.addEventListener('keydown', e => { if (e.key === 'Enter') go(); });
  const p = dialog(title, h('div', {}, h('div', { class: 'row2', style: 'margin:0 0 8px' }, q, h('button', { onclick: go }, 'Search')), out),
    [{ label: 'Cancel' }, { label: 'OK', primary: true, value: 'ok' }]);
  go();
  return (await p) === 'ok' ? [...chosen.values()] : [];
}

async function addToGroup(objs) {
  const gs = await pickObjects('Select group', 'group', false);
  if (!gs.length) return;
  try {
    await POST('/api/members', { group: gs[0].dn, add: objs.map(o => o.dn) });
    status('');
  } catch (e) { fail(e); }
}

async function resetPassword(it) {
  const f = form([
    { k: 'pw', label: 'New password', type: 'password' },
    { k: 'pw2', label: 'Confirm password', type: 'password' },
    { k: 'must', type: 'check', label: 'User must change password at next logon', value: true },
    { k: 'unlock', type: 'check', label: 'Unlock the account' }]);
  const ok = await dialog('Reset password — ' + it.name, f.el, [{ label: 'Cancel' }, { label: 'OK', primary: true, action: async () => {
    const v = f.get();
    if (!v.pw) throw new Error('Enter a password');
    if (v.pw !== v.pw2) throw new Error('Passwords do not match');
    await POST('/api/password', { dn: it.dn, password: v.pw, mustChange: v.must, unlock: v.unlock });
  } }]);
  if (ok) status('');
}

async function newObject(kind, parent) {
  parent = parent || (mode === 'browse' ? cur : info.base);
  const sub = rdnName(parent);
  let fields = [];
  const title = { user: 'New User', group: 'New Group', ou: 'New Organizational Unit', computer: 'New Computer' }[kind];
  if (kind === 'user') {
    const sufs = await upnSuffixes();
    const upd = (i, all) => { if (!all.name.dataset.touched) all.name.value = (all.first.value + ' ' + all.last.value).trim(); };
    const sufF = sufs.length > 1 ? [{ k: 'upnSuffix', label: 'UPN suffix', type: 'select', opts: sufs.map(x => [x, '@' + x]), oninput: (i, all) => { all.upn.value = upnWith(all.upn.value, i.value); all.upn.dataset.touched = ''; } }] : [];
    fields = [
      { k: 'first', label: 'First name', oninput: upd }, { k: 'last', label: 'Last name', oninput: upd },
      { k: 'name', label: 'Full name (CN)' },
      { k: 'sam', label: 'Logon name', oninput: (i, all) => { if (!all.upn.dataset.touched) all.upn.value = upnWith('', all.upnSuffix ? all.upnSuffix.value : info.realm, i.value); } },
      ...sufF,
      { k: 'upn', label: 'User principal name' },
      { k: 'description', label: 'Description' },
      { k: 'password', label: 'Password', type: 'password' }, { k: 'password2', label: 'Confirm password', type: 'password' },
      { k: 'mustChange', type: 'check', label: 'User must change password at next logon', value: true },
      { k: 'neverExpires', type: 'check', label: 'Password never expires' },
      { k: 'disabled', type: 'check', label: 'Account is disabled' }];
  } else if (kind === 'group') {
    fields = [{ k: 'name', label: 'Group name' }, { k: 'description', label: 'Description' },
      { k: 'scope', label: 'Group scope', type: 'select', opts: [['global', 'Global'], ['domainlocal', 'Domain local'], ['universal', 'Universal']] },
      { k: 'groupType', label: 'Group type', type: 'select', opts: [['security', 'Security'], ['distribution', 'Distribution']] }];
  } else if (kind === 'computer') {
    fields = [{ k: 'name', label: 'Computer name' }, { k: 'description', label: 'Description' }];
  } else fields = [{ k: 'name', label: 'Name' }, { k: 'description', label: 'Description' }];
  const f = form(fields);
  if (kind === 'user') { f.inputs.name.addEventListener('input', () => f.inputs.name.dataset.touched = '1'); f.inputs.upn.addEventListener('input', () => f.inputs.upn.dataset.touched = '1'); }
  let created;
  const ok = await dialog(title, h('div', {}, h('p', { class: 'muted' }, 'Create in: ' + sub), f.el), [{ label: 'Cancel' }, { label: 'Create', primary: true, action: async () => {
    const v = f.get();
    if (kind === 'user' && v.password !== v.password2) throw new Error('Passwords do not match');
    delete v.password2;
    created = await POST('/api/create', { kind, parent, ...v });
  } }]);
  if (ok) { await afterChange(parent); status(''); }
}

// ---------- properties ----------
const UAC = { DISABLE: 0x2, LOCKOUT: 0x10, NEVER: 0x10000, SMARTCARD: 0x40000, NOT_DELEG: 0x100000, NOPREAUTH: 0x400000, TRUST_DELEG: 0x80000, TRUST_AUTH: 0x1000000 };
const GENERAL = {
  user: [['givenName', 'First name'], ['initials', 'Initials'], ['sn', 'Last name'], ['displayName', 'Display name'], ['description', 'Description'], ['physicalDeliveryOfficeName', 'Office'], ['telephoneNumber', 'Telephone'], ['mail', 'E-mail'], ['wWWHomePage', 'Web page']],
  group: [['description', 'Description'], ['mail', 'E-mail'], ['info', 'Notes', { area: true }]],
  computer: [['description', 'Description'], ['location', 'Location'], ['dNSHostName', 'DNS name', { ro: true }], ['operatingSystem', 'Operating system', { ro: true }], ['operatingSystemVersion', 'OS version', { ro: true }]],
  ou: [['description', 'Description'], ['street', 'Street'], ['l', 'City'], ['st', 'State/Province'], ['postalCode', 'Postal code'], ['co', 'Country']],
  contact: [['givenName', 'First name'], ['sn', 'Last name'], ['displayName', 'Display name'], ['description', 'Description'], ['mail', 'E-mail'], ['telephoneNumber', 'Telephone']],
  site: [['description', 'Description'], ['location', 'Location']],
  subnet: [['description', 'Description'], ['location', 'Location']],
  sitelink: [['description', 'Description']],
  server: [['description', 'Description'], ['dNSHostName', 'DNS name', { ro: true }], ['serverReference', 'Computer account', { ro: true }]],
  connection: [['description', 'Description'], ['fromServer', 'Replicate from', { ro: true }]],
};
for (const t of ['container', 'domain', 'builtin', 'other', 'servers', 'sitesettings', 'transport', 'ntds']) GENERAL[t] = [['description', 'Description']];

async function properties(dn) {
  let obj;
  try { obj = await GET('/api/object', { dn }); } catch (e) { return fail(e); }
  const sufs = obj.type === 'user' ? await upnSuffixes() : [info.realm];
  const A = k => { const e = Object.entries(obj.attrs).find(([n]) => n.toLowerCase() === k.toLowerCase()); return e ? e[1] : []; };
  const type = obj.type;
  const name = A('name')[0] || rdnName(dn);
  let siteChoices = [];
  if (type === 'subnet' || type === 'sitelink') {
    try { siteChoices = (await GET('/api/children', { dn: sitesRoot() })).items.filter(i => i.type === 'site'); } catch (e) { return fail(e); }
  }
  let pending = null;                 // set by a tab function to register its "apply" step
  const cache = new Map();            // tab index -> {el, p}; tabs keep their unsaved edits when you switch
  let curTab = 0;
  const reload = async () => { obj = await GET('/api/object', { dn }); };

  // form of plain attributes, applied as a diff
  function attrForm(fields, o = {}) {
    const f = form([...(o.pre || []), ...fields.map(([k, l, op]) => ({ k, label: l, readonly: !!(op && op.ro), type: op && (op.area || op.multi) ? 'area' : 'text', value: A(k).join('\n') }))]);
    if (o.tail) f.el.append(...o.tail);
    pending = async () => {
      const v = f.get(), set = {};
      for (const [k, , op] of fields) {
        if (op && op.ro) continue;
        const nv = v[k].trim(), ov = A(k).join('\n');
        if (nv !== ov) set[k] = nv ? (op && op.multi ? nv.split('\n').map(x => x.trim()).filter(Boolean) : [nv]) : [];
      }
      if (Object.keys(set).length) await api('PUT', '/api/object', { dn, set });
    };
    return f;
  }
  const chain = (...fns) => async () => { for (const f of fns) if (f) await f(); };

  function tabGeneral() {
    const f = attrForm(GENERAL[type] || GENERAL.other, { pre: [{ k: '_n', label: 'Name', value: name, readonly: true }] });
    f.el.append(h('label', {}, 'Distinguished name'), h('input', { type: 'text', value: dn, readOnly: true }), h('label', {}, 'Object type'), h('input', { type: 'text', value: TYPE_LABEL[type] || type, readOnly: true }));
    return f.el;
  }

  function dnChooser(attr, label, pickType) {   // single-DN attribute with Change/Clear
    let val = A(attr)[0] || '', changed = false;
    const shown = h('input', { type: 'text', readOnly: true, value: val ? rdnName(val) : '' }); shown.title = val;
    const change = h('button', { onclick: async () => { const r = await pickObjects('Select ' + label.toLowerCase(), pickType, false); if (r.length) { val = r[0].dn; changed = true; shown.value = r[0].name; shown.title = val; } } }, 'Change…');
    const clear = h('button', { onclick: () => { val = ''; changed = true; shown.value = ''; } }, 'Clear');
    return { el: [h('label', {}, label), h('div', { class: 'row2', style: 'margin:0' }, shown, change, clear)], apply: async () => { if (changed) await api('PUT', '/api/object', { dn, set: { [attr]: val ? [val] : [] } }); } };
  }

  function tabOrg() {
    const mgr = dnChooser('manager', 'Manager', 'user');
    const f = attrForm([['title', 'Job title'], ['department', 'Department'], ['company', 'Company']], { tail: mgr.el });
    const base = pending; pending = chain(base, mgr.apply);
    const reports = A('directReports').sort((a, b) => rdnName(a).localeCompare(rdnName(b)));
    return h('div', {}, f.el, h('div', { class: 'sec' }, 'Direct reports'), h('div', { class: 'pl', style: 'height:110px' }, reports.length ? reports.map(d => h('div', { class: 'it', title: d, ondblclick: () => properties(d) }, icon('user'), rdnName(d))) : h('div', { class: 'muted', style: 'padding:6px' }, 'None')));
  }
  const tabAddress = () => attrForm([['streetAddress', 'Street', { area: true }], ['postOfficeBox', 'P.O. Box'], ['l', 'City'], ['st', 'State/Province'], ['postalCode', 'Postal code'], ['c', 'Country code (2 letters)'], ['co', 'Country']]).el;
  const tabPhones = () => attrForm([['homePhone', 'Home'], ['mobile', 'Mobile'], ['pager', 'Pager'], ['facsimileTelephoneNumber', 'Fax'], ['ipPhone', 'IP phone'], ['info', 'Notes', { area: true }]]).el;
  const tabProfile = () => attrForm([['profilePath', 'Profile path'], ['scriptPath', 'Logon script'], ['homeDrive', 'Home drive (e.g. H:)'], ['homeDirectory', 'Home folder (UNC path)']]).el;

  function tabManagedBy() {
    const m = dnChooser('managedBy', 'Managed by', 'user');
    pending = m.apply;
    return h('div', {}, h('div', { class: 'frm' }, m.el), h('p', { class: 'muted' }, 'The user or group responsible for this object.'));
  }

  function tabAccount() {
    const uac = parseInt(A('userAccountControl')[0] || '0', 10);
    const computed = parseInt(A('msDS-User-Account-Control-Computed')[0] || '0', 10);
    const lockT = A('lockoutTime')[0];
    const locked = (computed & UAC.LOCKOUT) !== 0 || (lockT && lockT !== '0' && obj.times.lockoutTime);
    const pwdSet = A('pwdLastSet')[0];
    // account expiry
    const expRaw = A('accountExpires')[0] || '0';
    const never = expRaw === '0' || expRaw === '9223372036854775807';
    let expDate = '';
    if (!never) { try { const ms = Number(BigInt(expRaw) / 10000n - 11644473600000n) - 1000; const d = new Date(ms); expDate = d.getFullYear() + '-' + String(d.getMonth() + 1).padStart(2, '0') + '-' + String(d.getDate()).padStart(2, '0'); } catch (_) {} }
    const curUpn = A('userPrincipalName')[0] || '';
    const curSuf = sufs.find(x => x.toLowerCase() === curUpn.split('@')[1]?.toLowerCase()) || sufs[0];
    const f = form([
      { k: 'sam', label: 'Logon name (pre-Win2000)', value: A('sAMAccountName')[0] || '' },
      ...(sufs.length > 1 ? [{ k: 'upnSuffix', label: 'UPN suffix', type: 'select', opts: sufs.map(x => [x, '@' + x]), value: curSuf, oninput: (i, all) => { all.upn.value = upnWith(all.upn.value || all.sam.value, i.value); } }] : []),
      { k: 'upn', label: 'User principal name', value: A('userPrincipalName')[0] || '' },
      { k: 'wks', label: 'Log on to (comma-separated; empty = all)', value: A('userWorkstations')[0] || '' },
      { k: 'expMode', label: 'Account expires', type: 'select', opts: [['never', 'Never'], ['date', 'End of']], value: never ? 'never' : 'date' },
      { k: 'expDate', label: 'Expiry date', type: 'date', value: expDate },
      { k: 'disabled', type: 'check', label: 'Account is disabled', value: !!(uac & UAC.DISABLE) },
      { k: 'must', type: 'check', label: 'User must change password at next logon', value: pwdSet === '0' },
      { k: 'never', type: 'check', label: 'Password never expires', value: !!(uac & UAC.NEVER) },
      { k: 'smart', type: 'check', label: 'Smart card is required for interactive logon', value: !!(uac & UAC.SMARTCARD) },
      { k: 'nopre', type: 'check', label: 'Do not require Kerberos pre-authentication', value: !!(uac & UAC.NOPREAUTH) },
      { k: 'notdel', type: 'check', label: 'Account is sensitive and cannot be delegated', value: !!(uac & UAC.NOT_DELEG) }]);
    f.inputs.expMode.value = never ? 'never' : 'date';
    const syncExp = () => { f.inputs.expDate.disabled = f.inputs.expMode.value === 'never'; };
    f.inputs.expMode.addEventListener('change', syncExp); syncExp();
    let lh = null;   // new logon hours (hex) if edited
    const lhBtn = h('button', { onclick: async () => { const r = await logonHoursDialog(lh ?? (A('logonHours')[0] || '')); if (r) lh = r; } }, 'Logon hours…');
    const info2 = h('div', { class: 'muted', style: 'margin-top:10px' },
      'Password last set: ' + (obj.times.pwdLastSet || (pwdSet === '0' ? 'must change at next logon' : 'never')),
      h('br'), 'Last logon: ' + (obj.times.lastLogonTimestamp || obj.times.lastLogon || 'never / unknown'),
      h('br'), 'Status: ', locked ? h('span', { class: 'badge bad' }, 'locked out') : h('span', { class: 'badge' }, 'not locked'));
    const btns = h('div', { class: 'row2' }, lhBtn, h('button', { onclick: () => resetPassword({ dn, name }) }, 'Reset password…'),
      h('button', { disabled: !locked, onclick: async () => { try { await POST('/api/unlock', { dn }); status(''); await reload(); cache.delete(tabs.findIndex(t => t[0] === 'Account')); show(curTab); } catch (e) { fail(e); } } }, 'Unlock account'));
    pending = async () => {
      const v = f.get(), set = {};
      if (v.sam !== (A('sAMAccountName')[0] || '')) set.sAMAccountName = [v.sam];
      if (v.upn !== (A('userPrincipalName')[0] || '')) set.userPrincipalName = v.upn ? [v.upn] : [];
      if (v.wks.trim() !== (A('userWorkstations')[0] || '')) set.userWorkstations = v.wks.trim() ? [v.wks.trim()] : [];
      if (v.must !== (pwdSet === '0')) set.pwdLastSet = [v.must ? '0' : '-1'];
      if (v.expMode === 'never') { if (!never) set.accountExpires = ['0']; }
      else {
        if (!v.expDate) throw new Error('Choose an expiry date');
        const [y, m, d] = v.expDate.split('-').map(Number);
        if (v.expDate !== expDate) set.accountExpires = [String((BigInt(new Date(y, m - 1, d + 1).getTime()) + 11644473600000n) * 10000n)]; // midnight at the end of that day
      }
      const body = { dn, set };
      if (lh !== null) { const bytes = lh.match(/../g).map(x => parseInt(x, 16)); body.bin = { logonHours: [btoa(String.fromCharCode(...bytes))] }; }
      if (Object.keys(set).length || body.bin) await api('PUT', '/api/object', body);
      let s = 0, c = 0; const flag = (on, bit) => on ? (s |= bit) : (c |= bit);
      flag(v.disabled, UAC.DISABLE); flag(v.never, UAC.NEVER); flag(v.smart, UAC.SMARTCARD); flag(v.nopre, UAC.NOPREAUTH); flag(v.notdel, UAC.NOT_DELEG);
      await POST('/api/uac', { dn, set: s, clear: c });
      lh = null;
    };
    return h('div', {}, f.el, info2, btns);
  }

  function tabDelegation() {
    const uac = parseInt(A('userAccountControl')[0] || '0', 10);
    const dele = A('msDS-AllowedToDelegateTo');
    const mode0 = (uac & UAC.TRUST_DELEG) ? 'any' : (dele.length || (uac & UAC.TRUST_AUTH)) ? 'spec' : 'none';
    const f = form([
      { k: 'spn', label: 'Service principal names (one per line)', type: 'area', value: A('servicePrincipalName').join('\n') },
      { k: 'mode', label: 'Delegation', type: 'select', opts: [['none', 'Do not trust this account for delegation'], ['any', 'Trust for delegation to any service (Kerberos only)'], ['spec', 'Trust for delegation to specified services only']], value: mode0 },
      { k: 'svc', label: 'Services to delegate to (one per line)', type: 'area', value: dele.join('\n') },
      { k: 'trans', type: 'check', label: 'Use any authentication protocol (protocol transition)', value: !!(uac & UAC.TRUST_AUTH) }]);
    f.inputs.mode.value = mode0;
    const sync = () => { const sp = f.inputs.mode.value === 'spec'; f.inputs.svc.disabled = !sp; f.inputs.trans.disabled = !sp; };
    f.inputs.mode.addEventListener('change', sync); sync();
    pending = async () => {
      const v = f.get(), set = {}, lines = t => t.split('\n').map(x => x.trim()).filter(Boolean);
      if (lines(v.spn).join('\n') !== A('servicePrincipalName').join('\n')) set.servicePrincipalName = lines(v.spn);
      const want = v.mode === 'spec' ? lines(v.svc) : [];
      if (want.join('\n') !== dele.join('\n')) set['msDS-AllowedToDelegateTo'] = want;
      if (Object.keys(set).length) await api('PUT', '/api/object', { dn, set });
      let s = 0, c = 0; const flag = (on, bit) => on ? (s |= bit) : (c |= bit);
      flag(v.mode === 'any', UAC.TRUST_DELEG); flag(v.mode === 'spec' && v.trans, UAC.TRUST_AUTH);
      await POST('/api/uac', { dn, set: s, clear: c });
    };
    return h('div', {}, f.el, h('p', { class: 'muted' }, 'Delegation lets a service act on behalf of users. Unconstrained delegation is a security risk; prefer specific services.'));
  }

  function tabMembers(attr, label) {
    const isMembers = attr === 'member';
    const list = h('div', { class: 'pl' });
    const chosen = new Set();
    const draw = () => {
      const dns = A(attr).slice().sort((a, b) => rdnName(a).toLowerCase().localeCompare(rdnName(b).toLowerCase()));
      list.replaceChildren(...dns.map(d => {
        const el = h('div', { class: 'it' + (chosen.has(d) ? ' sel' : ''), title: d }, icon(isMembers ? 'user' : 'group'), rdnName(d), h('span', { class: 'muted' }, ' — ' + parentOf(d).replace(/,DC=.*$/i, '')));
        el.addEventListener('click', e => { if (!(e.ctrlKey || e.metaKey)) chosen.clear(); chosen.has(d) ? chosen.delete(d) : chosen.add(d); draw(); });
        el.addEventListener('dblclick', () => properties(d));
        return el;
      }));
      if (!dns.length) list.append(h('div', { class: 'muted', style: 'padding:8px' }, 'None'));
    };
    draw();
    const msg = h('div', { class: 'err' });
    const apply = async (add, remove) => {
      msg.textContent = '';
      try {
        if (isMembers) await POST('/api/members', { group: dn, add, remove });
        else for (const g of [...add, ...remove]) await POST('/api/members', { group: g, add: add.includes(g) ? [dn] : [], remove: remove.includes(g) ? [dn] : [] });
        chosen.clear(); await reload(); draw();
      } catch (e) { msg.textContent = e.message; await reload().catch(() => {}); draw(); }
    };
    const bar = h('div', { class: 'row2' },
      h('button', { onclick: async () => { const ps = await pickObjects(isMembers ? 'Select members' : 'Select groups', isMembers ? 'all' : 'group', true); if (ps.length) apply(ps.map(p => p.dn), []); } }, 'Add…'),
      h('button', { class: 'danger', onclick: () => { if (chosen.size) apply([], [...chosen]); } }, 'Remove'));
    return h('div', {}, h('div', { class: 'sec', style: 'margin-top:0' }, label + ':'), list, bar, msg);
  }

  function tabSubnet() {
    const sel = h('select', {}, h('option', { value: '' }, '(none)'), siteChoices.map(si => h('option', { value: si.dn }, si.name)));
    sel.value = A('siteObject')[0] || '';
    const f = form([{ k: 'prefix', label: 'Prefix', value: name, readonly: true }]);
    f.el.append(h('label', {}, 'Site'), sel);
    pending = async () => { const nv = sel.value, ov = A('siteObject')[0] || ''; if (nv !== ov) await api('PUT', '/api/object', { dn, set: { siteObject: nv ? [nv] : [] } }); };
    return h('div', {}, f.el, h('p', { class: 'muted' }, 'Clients whose IP address falls in this prefix are placed in the selected site.'));
  }

  function tabSiteLink() {
    const opts = parseInt(A('options')[0] || '0', 10);
    const f = form([
      { k: 'cost', label: 'Cost', value: A('cost')[0] || '100' },
      { k: 'interval', label: 'Replicate every (minutes)', value: A('replInterval')[0] || '180' },
      { k: 'notify', type: 'check', label: 'Change notification enabled', value: !!(opts & 1) }]);
    const inc = new Map(A('siteList').map(d => [lc(d), d]));
    const selIn = new Set(), selOut = new Set();
    const inL = h('div', { class: 'pl', style: 'height:140px;flex:1' }), outL = h('div', { class: 'pl', style: 'height:140px;flex:1' });
    const row = (it, set) => { const d = h('div', { class: 'it' + (set.has(lc(it.dn)) ? ' sel' : '') }, icon('site'), it.name);
      d.addEventListener('click', () => { set.has(lc(it.dn)) ? set.delete(lc(it.dn)) : set.add(lc(it.dn)); draw(); }); return d; };
    const nameOf = d => { const c = siteChoices.find(x => lc(x.dn) === lc(d)); return c || { dn: d, name: rdnName(d) }; };
    const draw = () => {
      inL.replaceChildren(...[...inc.values()].map(nameOf).sort((a, b) => a.name.localeCompare(b.name)).map(i => row(i, selIn)));
      outL.replaceChildren(...siteChoices.filter(c => !inc.has(lc(c.dn))).map(i => row(i, selOut)));
    };
    draw();
    const mv = h('div', { style: 'display:flex;flex-direction:column;gap:6px;justify-content:center' },
      h('button', { onclick: () => { for (const k of selOut) inc.set(k, siteChoices.find(c => lc(c.dn) === k).dn); selOut.clear(); draw(); } }, '« Add'),
      h('button', { onclick: () => { for (const k of selIn) inc.delete(k); selIn.clear(); draw(); } }, 'Remove »'));
    pending = async () => {
      const v = f.get(), set = {};
      if (inc.size < 2) throw new Error('A site link needs at least two sites');
      if (!/^\d+$/.test(v.cost) || +v.cost < 1 || +v.cost > 99999) throw new Error('Cost must be 1–99999');
      if (!/^\d+$/.test(v.interval) || +v.interval < 15 || +v.interval > 10080) throw new Error('Interval must be 15–10080 minutes');
      if (v.cost !== A('cost')[0]) set.cost = [v.cost];
      if (v.interval !== A('replInterval')[0]) set.replInterval = [v.interval];
      if (v.notify !== !!(opts & 1)) set.options = [String(v.notify ? opts | 1 : opts & ~1)];
      const before = A('siteList').map(lc).sort().join('|'), after = [...inc.keys()].sort().join('|');
      if (before !== after) set.siteList = [...inc.values()];
      if (Object.keys(set).length) await api('PUT', '/api/object', { dn, set });
    };
    return h('div', {}, f.el, h('div', { class: 'sec' }, 'Sites in this link / not in this link'), h('div', { style: 'display:flex;gap:8px' }, inL, mv, outL));
  }

  function tabNtds() {
    const opts = parseInt(A('options')[0] || '0', 10);
    const f = form([{ k: 'gc', type: 'check', label: 'Global Catalog', value: !!(opts & 1) }]);
    pending = async () => { const gc = f.get().gc; if (gc !== !!(opts & 1)) await api('PUT', '/api/object', { dn, set: { options: [String(gc ? opts | 1 : opts & ~1)] } }); };
    return h('div', {}, h('p', { class: 'muted' }, 'Server: ' + rdnName(parentOf(dn))), f.el,
      h('div', { class: 'sec' }, 'Directory partitions held'), h('div', { class: 'muted', style: 'word-break:break-all' }, ...A('hasMasterNCs').concat(A('msDS-hasMasterNCs')).filter((v, i, a) => a.indexOf(v) === i).flatMap(v => [v, h('br')])));
  }

  function tabConnection() {
    const opts = parseInt(A('options')[0] || '0', 10);
    const f = form([{ k: 'en', type: 'check', label: 'Connection is enabled', value: A('enabledConnection')[0] !== 'FALSE' }]);
    const from = A('fromServer')[0] || '';
    pending = async () => { const en = f.get().en; if (en !== (A('enabledConnection')[0] !== 'FALSE')) await api('PUT', '/api/object', { dn, set: { enabledConnection: [en ? 'TRUE' : 'FALSE'] } }); };
    return h('div', {}, h('p', {}, 'Replicate from: ', h('b', {}, from ? dnLabel(from, 1) : '?'), from ? h('span', { class: 'muted' }, ' (site ' + dnLabel(from, 3) + ')') : null),
      h('p', {}, 'Created by: ', opts & 1 ? 'KCC (automatically generated)' : 'administrator (manual)'), f.el);
  }

  function tabAttrs() {
    const wrap = h('div');
    const draw = () => {
      const keys = Object.keys(obj.attrs).sort((a, b) => a.toLowerCase().localeCompare(b.toLowerCase()));
      const msg = h('div', { class: 'err' });
      const rows = keys.map(k => {
        const vals = obj.attrs[k], ro = obj.binary.includes(k) && !/^logonhours$/i.test(k) || ['objectClass', 'distinguishedName', 'name', 'memberOf', 'msDS-User-Account-Control-Computed', 'logonHours'].includes(k);
        const td = h('td', {}, vals.join('\n'), obj.times[k] ? h('span', { class: 'muted' }, '\n(' + obj.times[k] + ')') : null);
        const act = h('td', { style: 'white-space:nowrap;width:1%' });
        if (!ro) {
          act.append(h('button', { onclick: () => {
            const ta = h('textarea', { rows: Math.min(8, vals.length + 1) }); ta.value = vals.join('\n');
            const save = h('button', { class: 'primary', onclick: async () => {
              try { await api('PUT', '/api/object', { dn, set: { [k]: ta.value.split('\n').map(x => x.replace(/\r$/, '')).filter(Boolean) } }); await reload(); draw(); } catch (e) { msg.textContent = e.message; }
            } }, 'Save');
            td.replaceChildren(ta, h('div', { class: 'row2' }, save, h('button', { onclick: draw }, 'Cancel')));
          } }, 'Edit'), ' ', h('button', { class: 'danger', onclick: async () => {
            if (!(await confirmBox('Delete attribute', `Remove all values of ${k}?`, 'Remove', true))) return;
            try { await api('PUT', '/api/object', { dn, set: { [k]: [] } }); await reload(); draw(); } catch (e) { msg.textContent = e.message; }
          } }, 'Clear'));
        }
        return h('tr', {}, h('td', {}, k), td, act);
      });
      const nk = h('input', { type: 'text', placeholder: 'attribute name' }), nv = h('input', { type: 'text', placeholder: 'value' });
      const add = h('button', { onclick: async () => {
        if (!nk.value.trim()) return;
        const existing = Object.keys(obj.attrs).find(x => x.toLowerCase() === nk.value.trim().toLowerCase());
        const vals = existing ? [...obj.attrs[existing], nv.value] : [nv.value];
        try { await api('PUT', '/api/object', { dn, set: { [nk.value.trim()]: vals } }); await reload(); draw(); } catch (e) { msg.textContent = e.message; }
      } }, 'Add value');
      wrap.replaceChildren(h('table', { class: 'attrs' }, h('tbody', {}, rows)), h('div', { class: 'row2' }, nk, nv, add), msg);
    };
    draw();
    return wrap;
  }

  const tabs = [['General', tabGeneral]];
  if (type === 'user') tabs.push(['Account', tabAccount], ['Profile', tabProfile], ['Telephones', tabPhones], ['Address', tabAddress], ['Organization', tabOrg], ['Delegation', tabDelegation]);
  if (type === 'contact') tabs.push(['Organization', tabOrg]);
  if (type === 'computer') tabs.push(['Delegation', tabDelegation]);
  if (['group', 'ou', 'computer', 'contact'].includes(type)) tabs.push(['Managed By', tabManagedBy]);
  if (type === 'subnet') tabs.push(['Subnet', tabSubnet]);
  if (type === 'sitelink') tabs.push(['Site Link', tabSiteLink]);
  if (type === 'ntds') tabs.push(['NTDS Settings', tabNtds]);
  if (type === 'connection') tabs.push(['Connection', tabConnection]);
  if (type === 'group') tabs.push(['Members', () => tabMembers('member', 'Members')]);
  if (['user', 'group', 'computer', 'contact'].includes(type)) tabs.push(['Member Of', () => tabMembers('memberOf', 'Member of')]);
  tabs.push(['Attributes', tabAttrs]);

  const content = h('div', { class: 'body', style: 'min-height:380px' });
  const tabBar = h('div', { class: 'tabs' });
  const show = i => {
    curTab = i;
    tabBar.replaceChildren(...tabs.map(([n], j) => h('div', { class: j === i ? 'on' : '', onclick: () => show(j) }, n)));
    let ent = cache.get(i);
    if (!ent) { pending = null; const el = tabs[i][1](); ent = { el, p: pending }; pending = null; cache.set(i, ent); }
    content.replaceChildren(ent.el);
  };
  const msg = h('span', { class: 'msg' });
  const back = h('div', { class: 'back' });
  const close = () => back.remove();
  const run = async () => {
    msg.textContent = '';
    try {
      for (const ent of cache.values()) if (ent.p) await ent.p();
      close(); afterChange(parentOf(dn)).catch(() => {});
    } catch (e) { msg.textContent = e.message; await reload().catch(() => {}); }
  };
  const dlg = h('div', { class: 'dlg props' },
    h('h2', {}, icon(type), name, h('span', { class: 'badge' }, TYPE_LABEL[type] || type)), tabBar, content,
    h('div', { class: 'foot' }, msg, h('button', { onclick: close }, 'Cancel'), h('button', { class: 'primary', onclick: run }, 'OK')));
  back.append(dlg);
  back.addEventListener('mousedown', e => { if (e.target === back) close(); });
  back.addEventListener('keydown', e => { if (e.key === 'Escape') close(); });
  document.body.append(back);
  show(0);
}

// 7 days x 24 hours grid; hex is the 21-byte logonHours value (bit 0 = Sunday 00:00 UTC). Empty = all hours permitted.
function logonHoursDialog(hex) {
  const bits = new Array(168).fill(true);
  if (hex && hex.length === 42) { const by = hex.match(/../g).map(x => parseInt(x, 16)); for (let i = 0; i < 168; i++) bits[i] = !!(by[i >> 3] & (1 << (i & 7))); }
  const offset = Math.round(-new Date().getTimezoneOffset() / 60);   // whole hours east of UTC
  let local = true;
  const idx = (d, hr) => { const k = local ? (d * 24 + hr - offset) : d * 24 + hr; return ((k % 168) + 168) % 168; };
  const days = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
  const grid = h('div', { class: 'lh' });
  const draw = () => {
    grid.replaceChildren(h('div'), ...Array.from({ length: 24 }, (_, hr) => h('div', { class: 'lhh', onclick: () => { const on = !Array.from({ length: 7 }, (_, d) => bits[idx(d, hr)]).every(Boolean); for (let d = 0; d < 7; d++) bits[idx(d, hr)] = on; draw(); } }, String(hr))));
    for (let d = 0; d < 7; d++) {
      grid.append(h('div', { class: 'lhd', onclick: () => { const on = !Array.from({ length: 24 }, (_, hr) => bits[idx(d, hr)]).every(Boolean); for (let hr = 0; hr < 24; hr++) bits[idx(d, hr)] = on; draw(); } }, days[d]));
      for (let hr = 0; hr < 24; hr++) grid.append(h('div', { class: 'lhc' + (bits[idx(d, hr)] ? ' on' : ''), onclick: () => { bits[idx(d, hr)] = !bits[idx(d, hr)]; draw(); } }));
    }
  };
  draw();
  const tz = h('input', { type: 'checkbox', checked: true });
  tz.addEventListener('change', () => { local = tz.checked; draw(); });
  const all = (v) => h('button', { onclick: () => { bits.fill(v); draw(); } }, v ? 'Permit all' : 'Deny all');
  return dialog('Logon hours', h('div', {}, grid, h('div', { class: 'row2' }, all(true), all(false), h('label', { style: 'margin-left:12px;display:flex;gap:6px;align-items:center' }, tz, 'Show in local time (UTC' + (offset >= 0 ? '+' : '') + offset + ')')),
    h('p', { class: 'muted' }, 'Blue = logon permitted. Click cells, or a day / hour label to toggle the whole row or column.')),
    [{ label: 'Cancel' }, { label: 'OK', primary: true, action: async () => { const by = new Array(21).fill(0); for (let i = 0; i < 168; i++) if (bits[i]) by[i >> 3] |= 1 << (i & 7); return by.map(b => b.toString(16).padStart(2, '0')).join(''); } }], { wide: true })
    .then(r => (typeof r === 'string' ? r : null));
}

// ---------- Sites and Services ----------
const dnLabel = (dn, i) => { const p = dn.split(/(?<!\\),/)[i]; return p ? p.slice(p.indexOf('=') + 1).replace(/\\(.)/g, '$1') : dn; };
const ipTransport = () => 'CN=IP,CN=Inter-Site Transports,' + sitesRoot();
const listSites = async () => (await GET('/api/children', { dn: sitesRoot() })).items.filter(i => i.type === 'site');
const listSiteLinks = async () => (await GET('/api/children', { dn: ipTransport() })).items.filter(i => i.type === 'sitelink');

async function createSites(title, body, f, payload, refreshDn) {
  let created;
  const ok = await dialog(title, body, [{ label: 'Cancel' }, { label: 'Create', primary: true, action: async () => { created = await POST('/api/sites/create', payload()); } }]);
  if (ok) { await tree.refresh(refreshDn); if (mode === 'browse') load(); status(''); }
}

async function newSite() {
  let links; try { links = await listSiteLinks(); } catch (e) { return fail(e); }
  const f = form([{ k: 'name', label: 'Site name' }, { k: 'description', label: 'Description' }, { k: 'location', label: 'Location' },
    { k: 'siteLink', label: 'Add to site link', type: 'select', opts: [['', '(none)'], ...links.map(l => [l.dn, l.name])] }]);
  const def = links.find(l => l.name === 'DEFAULTIPSITELINK'); if (def) f.inputs.siteLink.value = def.dn;
  await createSites('New Site', f.el, f, () => ({ kind: 'site', ...f.get() }), sitesRoot());
}

async function newSubnet(siteDn) {
  let sites; try { sites = await listSites(); } catch (e) { return fail(e); }
  const f = form([{ k: 'name', label: 'Prefix (CIDR)', value: '' }, { k: 'site', label: 'Site', type: 'select', opts: [['', '(none)'], ...sites.map(x => [x.dn, x.name])] },
    { k: 'location', label: 'Location' }, { k: 'description', label: 'Description' }]);
  if (siteDn) f.inputs.site.value = siteDn;
  f.inputs.name.placeholder = '10.1.0.0/24 or fd00:1::/64';
  await createSites('New Subnet', f.el, f, () => ({ kind: 'subnet', ...f.get() }), 'CN=Subnets,' + sitesRoot());
}

async function newSiteLink() {
  let sites; try { sites = await listSites(); } catch (e) { return fail(e); }
  const f = form([{ k: 'name', label: 'Name' }, { k: 'cost', label: 'Cost', value: '100' }, { k: 'interval', label: 'Replicate every (minutes)', value: '180' },
    { k: 'changeNotify', type: 'check', label: 'Enable change notification' }, { k: 'description', label: 'Description' }]);
  const boxes = sites.map(x => ({ x, cb: h('input', { type: 'checkbox' }) }));
  const list = h('div', { class: 'pl', style: 'height:150px;padding:4px' }, boxes.map(({ x, cb }) => h('label', { class: 'chk', style: 'display:flex;padding:2px 4px' }, cb, icon('site'), x.name)));
  await createSites('New Site Link', h('div', {}, f.el, h('div', { class: 'sec' }, 'Sites in this link (at least two)'), list), f, () => {
    const v = f.get();
    return { kind: 'sitelink', name: v.name, description: v.description, changeNotify: v.changeNotify, cost: +v.cost || 0, interval: +v.interval || 0, sites: boxes.filter(b => b.cb.checked).map(b => b.x.dn) };
  }, ipTransport());
}

async function newConnection(ntds) {
  let from = null;
  const lbl = h('span', { class: 'muted' }, '(none selected)');
  const f = form([{ k: 'name', label: 'Connection name' }]);
  const pick = h('button', { onclick: async () => {
    const r = await pickObjects('Select source server', 'ntds', false, info.config);
    if (r.length) { from = r[0].dn; lbl.textContent = rdnName(parentOf(from)) + ' (site ' + dnLabel(from, 3) + ')'; if (!f.inputs.name.value) f.inputs.name.value = 'From-' + rdnName(parentOf(from)); }
  } }, 'Choose…');
  f.el.append(h('label', {}, 'Replicate from'), h('div', { class: 'row2', style: 'margin:0' }, pick, lbl));
  await createSites('New Connection to ' + rdnName(parentOf(ntds.dn)), h('div', {}, h('p', { class: 'muted' }, 'Creates a manual replication connection. The KCC keeps managing its own automatically generated connections.'), f.el), f,
    () => { if (!from) throw new Error('Choose the source server'); return { kind: 'connection', parent: ntds.dn, name: f.get().name, from }; }, ntds.dn);
}

async function moveServer(it) {
  let sites; try { sites = await listSites(); } catch (e) { return fail(e); }
  const curSite = parentOf(parentOf(it.dn));
  const f = form([{ k: 'site', label: 'Move to site', type: 'select', opts: sites.filter(x => lc(x.dn) !== lc(curSite)).map(x => [x.dn, x.name]) }]);
  const ok = await dialog('Move server ' + it.name, h('div', {}, h('p', { class: 'muted' }, 'Currently in site: ' + rdnName(curSite)), f.el,
    h('p', { class: 'err' }, 'Only move a domain controller to match its real network location; the KCC will rebuild its replication connections.')),
    [{ label: 'Cancel' }, { label: 'Move', primary: true, action: async () => {
      const t = f.get().site; if (!t) throw new Error('No other site available');
      await POST('/api/move', { dn: it.dn, newParent: 'CN=Servers,' + t });
    } }]);
  if (ok) { selected.clear(); await fixCurrent([it.dn]); await tree.refresh('CN=Servers,' + curSite); await tree.refresh(sitesRoot()); if (mode === 'browse') load(); }
}

function sitesMenu(x, y, sel) {
  if (!sel.length) return;
  const one = sel.length === 1 ? sel[0] : null, sr = sitesRoot(), e = [];
  if (one) {
    if (lc(one.dn) === lc(sr)) e.push({ label: 'New Site…', fn: () => newSite() });
    if (lc(one.dn) === lc('CN=Subnets,' + sr)) e.push({ label: 'New Subnet…', fn: () => newSubnet() });
    if (lc(one.dn) === lc(ipTransport())) e.push({ label: 'New Site Link…', fn: () => newSiteLink() });
    if (one.type === 'site') e.push({ label: 'New Subnet for this site…', fn: () => newSubnet(one.dn) });
    if (one.type === 'ntds') e.push({ label: 'New Connection…', fn: () => newConnection(one) });
    if (one.type === 'server') e.push({ label: 'Move to another site…', fn: () => moveServer(one) });
    if (e.length) e.push('-');
    if (isCont(one) && mode === 'browse' && !sel[0].__tree && lc(one.dn) !== lc(cur)) e.push({ label: 'Open', fn: () => openItem(one) });
    e.push({ label: 'Refresh', fn: () => { tree.refresh(one.dn); if (lc(cur) === lc(one.dn)) load(); } });
    e.push({ label: 'Properties', fn: () => properties(one.dn) });
    if (['site', 'subnet', 'sitelink'].includes(one.type)) e.push({ label: 'Rename…', fn: () => renameObj(one.dn) });
  }
  const del = sel.filter(i => !isProtectedSite(i.dn) && !['sitesettings'].includes(i.type));
  if (del.length) { e.push('-'); e.push({ label: 'Delete…', danger: true, fn: () => deleteObjs(del) }); }
  menu(x, y, e);
}

// ---------- boot ----------
window.addEventListener('load', async () => {   // after tools.js has loaded
  try { info = await GET('/api/info'); showMain(); } catch (_) { showLogin(); }
});
