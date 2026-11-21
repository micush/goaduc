'use strict';
// Group Policy: GPO list, links, and the settings editors (Registry.pol, security settings, SYSVOL files).
// Shares helpers (h, GET, POST, dialog, confirmBox, form, pickContainer, simpleTable, fmtErr) with app.js / tools.js.

const REG_TYPES = [[1, 'REG_SZ'], [2, 'REG_EXPAND_SZ'], [4, 'REG_DWORD'], [11, 'REG_QWORD'], [7, 'REG_MULTI_SZ'], [3, 'REG_BINARY']];
const regTypeName = t => (REG_TYPES.find(x => x[0] === t) || [t, 'type ' + t])[1];
const GPO_STATUS = [[0, 'Enabled'], [1, 'User configuration disabled'], [2, 'Computer configuration disabled'], [3, 'All settings disabled']];
const SEC_KEYS = {
  'System Access': ['MinimumPasswordAge', 'MaximumPasswordAge', 'MinimumPasswordLength', 'PasswordComplexity', 'PasswordHistorySize', 'LockoutBadCount', 'ResetLockoutCount', 'LockoutDuration', 'RequireLogonToChangePassword', 'ForceLogoffWhenHourExpire', 'ClearTextPassword', 'EnableAdminAccount', 'EnableGuestAccount', 'LSAAnonymousNameLookup', 'NewAdministratorName', 'NewGuestName'],
  'Kerberos Policy': ['MaxTicketAge', 'MaxRenewAge', 'MaxServiceAge', 'MaxClockSkew', 'TicketValidateClient'],
  'Event Audit': ['AuditSystemEvents', 'AuditLogonEvents', 'AuditObjectAccess', 'AuditPrivilegeUse', 'AuditPolicyChange', 'AuditAccountManage', 'AuditProcessTracking', 'AuditDSAccess', 'AuditAccountLogon'],
  'Privilege Rights': ['SeNetworkLogonRight', 'SeInteractiveLogonRight', 'SeRemoteInteractiveLogonRight', 'SeDenyNetworkLogonRight', 'SeDenyInteractiveLogonRight', 'SeDenyRemoteInteractiveLogonRight', 'SeServiceLogonRight', 'SeBatchLogonRight', 'SeBackupPrivilege', 'SeRestorePrivilege', 'SeShutdownPrivilege', 'SeDebugPrivilege', 'SeTakeOwnershipPrivilege', 'SeSystemtimePrivilege', 'SeChangeNotifyPrivilege', 'SeLoadDriverPrivilege', 'SeMachineAccountPrivilege'],
  'Group Membership': ['*S-1-5-32-544__Members', '*S-1-5-32-544__Memberof'],
  'Registry Values': [],
};

function bufToB64(buf) {
  const a = new Uint8Array(buf); let s = '';
  for (let i = 0; i < a.length; i += 0x8000) s += String.fromCharCode.apply(null, a.subarray(i, i + 0x8000));
  return btoa(s);
}
function b64ToBytes(b) { const s = atob(b), a = new Uint8Array(s.length); for (let i = 0; i < s.length; i++) a[i] = s.charCodeAt(i); return a; }
function saveBlob(name, blob) {
  const a = h('a', { href: URL.createObjectURL(blob), download: name });
  document.body.append(a); a.click(); a.remove(); setTimeout(() => URL.revokeObjectURL(a.href), 2000);
}
const fmtSize = n => n < 1024 ? n + ' B' : n < 1048576 ? (n / 1024).toFixed(1) + ' KiB' : (n / 1048576).toFixed(1) + ' MiB';

async function renderGPO(page) {
  page.classList.add('split');
  const listEl = h('div', { class: 'zones' }), right = h('div', { class: 'recs' });
  page.append(listEl, right);
  const err = h('span', { class: 'terr' });
  const tabBar = h('div', { class: 'tabs' }), body = h('div', { class: 'gbody' });
  let gpos = [], sysvol = { available: false, writable: false }, cur = null, tab = 'links', dirty = null;
  const say = e => { err.textContent = e ? fmtErr(e) : ''; };
  const guard = async () => !(dirty && dirty()) || await confirmBox('Unsaved changes', 'Discard the unsaved changes?', 'Discard', true);
  const btn = (label, fn, cls, title) => h('button', { class: cls || '', title: title || null, onclick: fn }, label);
  // right-click on the empty part of a tab (not on a row or the toolbar) shows these entries
  const blankMenu = entries => { body.oncontextmenu = e => { if (e.target.closest('tr, .toolbar')) return; e.preventDefault(); menu(e.clientX, e.clientY, entries); }; };
  const none = text => body.replaceChildren(h('div', { class: 'muted gpad' }, text));
  const noSysvol = () => none(sysvol.available ? 'SYSVOL is read-only for goaduc.' : 'SYSVOL is not available on this host.');

  const TABS = [['links', 'Links'], ['computer', 'Computer'], ['user', 'User'], ['security', 'Security'], ['files', 'Files'], ['details', 'Details']];

  // redraw=false refreshes the data and the list only (the Files tab keeps its folder)
  async function load(redraw = true) {
    say(null);
    try { const r = await GET('/api/gpo/list'); gpos = r.gpos; sysvol = r.sysvol; } catch (e) { gpos = []; say(e); }
    if (cur) cur = gpos.find(g => g.guid === cur.guid) || null;
    drawList(); if (redraw || !cur) drawRight();
    const c = document.getElementById('st-count');
    if (c) c.textContent = gpos.length + ' GPO(s)';
  }

  function drawList() {
    listEl.replaceChildren(h('div', { class: 'zh' }, 'Group Policy Objects'), ...gpos.map(g => {
      const d = h('div', { class: 'zone' + (cur && cur.guid === g.guid ? ' sel' : '') + (g.flags === 3 ? ' off' : '') }, g.name,
        g.links.length ? h('span', { class: 'badge', title: 'Linked to ' + g.links.length + ' container(s)' }, String(g.links.length)) : null);
      d.addEventListener('click', async () => {
        if (cur && cur.guid === g.guid) return;
        if (!(await guard())) return;
        dirty = null; cur = g; drawList(); drawRight();
      });
      d.addEventListener('contextmenu', async e => {
        e.preventDefault();
        const x = e.clientX, y = e.clientY;
        if (!cur || cur.guid !== g.guid) {
          if (!(await guard())) return;
          dirty = null; cur = g; drawList(); drawRight();
        }
        menu(x, y, [{ label: 'New GPO…', fn: newGPO }, '-', { label: 'Rename…', fn: renameGPO }, { label: 'Delete', danger: true, fn: deleteGPO }, '-',
          { label: 'Refresh', fn: async () => { if (await guard()) { dirty = null; load(); } } }]);
      });
      return d;
    }));
  }

  function drawRight() {
    body.oncontextmenu = null;
    tabBar.replaceChildren(...TABS.map(([k, l]) => h('div', { class: tab === k ? 'on' : '', onclick: async () => { if (tab === k || !(await guard())) return; dirty = null; tab = k; drawRight(); } }, l)));
    tabBar.hidden = !cur;
    if (!cur) { none(gpos.length ? 'Select a GPO.' : 'No GPOs.'); return; }
    ({ links: linksTab, computer: g => polTab(g, 'machine'), user: g => polTab(g, 'user'), security: securityTab, files: filesTab, details: detailsTab })[tab](cur);
  }

  // ----- GPO commands -----
  async function newGPO() {
    if (!(await guard())) return;
    const f = form([{ k: 'name', label: 'Name' }]);
    let guid = null;
    const ok = await dialog('New GPO', f.el, [{ label: 'Cancel' }, { label: 'Create', primary: true, action: async () => { const r = await POST('/api/gpo/create', { name: f.get().name }); guid = r.guid; } }]);
    if (ok && guid) { dirty = null; cur = { guid }; await load(); }
  }
  async function renameGPO() {
    if (!cur) return;
    const f = form([{ k: 'name', label: 'Name', value: cur.name }]);
    if (await dialog('Rename GPO', f.el, [{ label: 'Cancel' }, { label: 'Rename', primary: true, action: async () => { await POST('/api/gpo/rename', { guid: cur.guid, name: f.get().name }); } }])) load();
  }
  async function deleteGPO() {
    if (!cur) return;
    const n = cur.links.length;
    if (!(await confirmBox('Delete GPO', `Delete “${cur.name}”` + (n ? `? It is linked to ${n} container(s); those links are removed too.` : '?'), 'Delete', true))) return;
    try { const r = await POST('/api/gpo/delete', { guid: cur.guid }); dirty = null; cur = null; await load(); if (r.warning) say(r.warning); } catch (e) { say(e); }
  }

  // ----- Links -----
  async function addLink(g) {
    let target = info.base;
    const kind = h('select', {}, [['ou', 'Domain or OU'], ['site', 'Site']].map(([v, l]) => h('option', { value: v }, l)));
    const tgt = h('input', { type: 'text', value: target, readOnly: true });
    const row = h('div', { class: 'row2', style: 'margin:0' }, tgt, h('button', { onclick: async () => { const d = await pickContainer('Link to…'); if (d) { target = d; tgt.value = d; } } }, 'Browse…'));
    let sites = [];
    try { sites = (await GET('/api/children', { dn: 'CN=Sites,' + info.config })).items.filter(i => i.type === 'site'); } catch (_) { /* no site list: only domain/OU */ }
    const siteSel = h('select', {}, sites.map(s => h('option', { value: s.dn }, s.name)));
    siteSel.hidden = true; kind.disabled = !sites.length;
    kind.addEventListener('change', () => { row.hidden = kind.value === 'site'; siteSel.hidden = kind.value !== 'site'; });
    const enf = h('input', { type: 'checkbox' });
    const body = h('div', { class: 'frm' }, h('label', {}, 'Link to'), kind, row, siteSel, h('label', { class: 'chk' }, enf, 'Enforced'));
    if (await dialog('Link “' + g.name + '”', body, [{ label: 'Cancel' }, { label: 'Link', primary: true, action: async () => {
      const t = kind.value === 'site' ? siteSel.value : target;
      if (!t) throw new Error('Choose a target');
      await POST('/api/gpo/link', { guid: g.guid, target: t, enforced: enf.checked, disabled: false });
    } }])) load();
  }
  function linksTab(g) {
    const act = async (path, b) => { try { await POST(path, { guid: g.guid, ...b }); await load(); } catch (e) { await load(); say(e); } };
    const chk = (v, fn, title) => h('input', { type: 'checkbox', checked: v, title, onchange: e => fn(e.target.checked) });
    const rows = g.links.map(l => [
      h('span', { title: l.target }, l.targetName, h('span', { class: 'badge' }, l.kind === 'ou' ? 'OU' : l.kind === 'site' ? 'Site' : 'Domain')),
      l.order + ' of ' + l.of,
      chk(l.enforced, v => act('/api/gpo/link', { target: l.target, enforced: v, disabled: l.disabled }), 'Enforced'),
      chk(!l.disabled, v => act('/api/gpo/link', { target: l.target, enforced: l.enforced, disabled: !v }), 'Link enabled'),
      chk(l.block, v => act('/api/gpo/inherit', { target: l.target, block: v }), 'This container blocks inheritance from above'),
      h('span', {}, btn('▲', () => act('/api/gpo/move', { target: l.target, delta: -1 }), '', 'Higher precedence'),
        btn('▼', () => act('/api/gpo/move', { target: l.target, delta: 1 }), '', 'Lower precedence'),
        btn('Unlink', () => act('/api/gpo/unlink', { target: l.target }), 'danger')),
    ]);
    const tbl = rows.length ? simpleTable(['Linked to', 'Link order', 'Enforced', 'Enabled', 'Blocks inheritance', ''], rows) : h('div', { class: 'muted gpad' }, 'Not linked.');
    if (rows.length) tbl.querySelectorAll('tbody tr').forEach((tr, i) => tr.addEventListener('contextmenu', e => {
      e.preventDefault();
      const l = g.links[i];
      menu(e.clientX, e.clientY, [{ label: 'Move up', disabled: l.order <= 1, fn: () => act('/api/gpo/move', { target: l.target, delta: -1 }) },
        { label: 'Move down', disabled: l.order >= l.of, fn: () => act('/api/gpo/move', { target: l.target, delta: 1 }) },
        { label: 'Unlink', danger: true, fn: () => act('/api/gpo/unlink', { target: l.target }) }, '-', { label: 'Add link…', fn: () => addLink(g) }]);
    }));
    blankMenu([{ label: 'Add link…', fn: () => addLink(g) }]);
    body.replaceChildren(h('div', { class: 'toolbar' }, btn('Add link…', () => addLink(g))), tbl);
  }

  // ----- Registry.pol -----
  async function polEntryDialog(e) {
    const f = form([{ k: 'key', label: 'Key', value: e ? e.key : '' }, { k: 'value', label: 'Value name', value: e ? e.value : '' },
      { k: 'type', label: 'Type', type: 'select', opts: REG_TYPES.map(([v, l]) => [String(v), l]), value: String(e ? e.type : 1) },
      { k: 'data', label: 'Data', type: 'area', value: e ? e.data : '' }]);
    if (e && !REG_TYPES.some(t => t[0] === e.type)) f.inputs.type.append(h('option', { value: String(e.type) }, regTypeName(e.type)));
    f.inputs.type.value = String(e ? e.type : 1);
    return dialog(e ? 'Edit entry' : 'New entry', f.el, [{ label: 'Cancel' }, { label: 'OK', primary: true, action: async () => {
      const v = f.get();
      if (!v.key.trim()) throw new Error('A key is required');
      return { key: v.key.trim(), value: v.value, type: +v.type, data: v.data };
    } }]).then(r => (r && r.key ? r : null));
  }
  async function polTab(g, scope) {
    if (!sysvol.available) return noSysvol();
    let r;
    try { r = await GET('/api/gpo/registry', { guid: g.guid, scope }); } catch (e) { say(e); return none(''); }
    let entries = r.entries, etag = r.etag, sel = -1, isDirty = false;
    dirty = () => isDirty;
    const saveBtn = btn('Save', save, 'primary'); saveBtn.disabled = true;
    const mark = () => { isDirty = true; saveBtn.disabled = false; draw(); };
    async function save() {
      try { const res = await POST('/api/gpo/registry/save', { guid: g.guid, scope, entries, etag }); etag = res.etag; isDirty = false; dirty = null; await load(); } catch (e) { say(e); }
    }
    const add = async () => { const n = await polEntryDialog(null); if (n) { entries.push(n); sel = entries.length - 1; mark(); } };
    const remove = () => { if (sel >= 0) { entries.splice(sel, 1); sel = -1; mark(); } };
    function draw() {
      blankMenu([{ label: 'Add…', fn: add }]);
      body.replaceChildren(h('div', { class: 'toolbar' },
        btn('Add…', add),
        btn('Edit…', () => edit(sel)), btn('Remove', remove, 'danger', 'Remove this entry from the policy'),
        btn('Delete value…', async () => {
          const f = form([{ k: 'key', label: 'Key' }, { k: 'name', label: 'Value name' }]);
          const o = await dialog('Delete a registry value on clients', f.el, [{ label: 'Cancel' }, { label: 'OK', primary: true, action: async () => { const v = f.get(); if (!v.key.trim() || !v.name.trim()) throw new Error('Key and value name are required'); return v; } }]);
          if (o && o.key) { entries.push({ key: o.key.trim(), value: '**del.' + o.name.trim(), type: 1, data: ' ' }); mark(); }
        }, '', 'Make clients delete a value'),
        h('span', { class: 'sp' }), saveBtn),
        entries.length ? h('table', {}, h('thead', {}, h('tr', {}, ['Key', 'Value', 'Type', 'Data'].map(c => h('th', { style: 'cursor:default' }, c)))),
          h('tbody', {}, entries.map((e, i) => {
            const tr = h('tr', { class: 'row' + (i === sel ? ' sel' : '') }, h('td', { title: e.key }, e.key), h('td', {}, e.value), h('td', {}, regTypeName(e.type)), h('td', { title: e.data }, e.data));
            tr.addEventListener('click', () => { sel = i; draw(); });
            tr.addEventListener('dblclick', () => edit(i));
            tr.addEventListener('contextmenu', e => {
              e.preventDefault(); sel = i; draw();
              menu(e.clientX, e.clientY, [{ label: 'Edit…', fn: () => edit(i) }, { label: 'Remove', danger: true, fn: remove }, '-', { label: 'Add…', fn: add }]);
            });
            return tr;
          }))) : h('div', { class: 'muted gpad' }, 'No registry settings.'));
    }
    async function edit(i) { if (i < 0) return; const n = await polEntryDialog(entries[i]); if (n) { entries[i] = n; mark(); } }
    draw();
  }

  // ----- Security settings (GptTmpl.inf) -----
  async function secEntryDialog(secs, e) {
    const dl = h('datalist', { id: 'sec-sections' }, Object.keys(SEC_KEYS).map(k => h('option', { value: k })));
    const kl = h('datalist', { id: 'sec-keys' });
    const f = form([{ k: 'section', label: 'Section', value: e ? e.section : 'System Access' }, { k: 'key', label: 'Setting', value: e ? e.item.key : '' }, { k: 'value', label: 'Value', value: e ? e.item.value : '' }]);
    f.inputs.section.setAttribute('list', 'sec-sections'); f.inputs.key.setAttribute('list', 'sec-keys');
    const fill = () => kl.replaceChildren(...(SEC_KEYS[f.inputs.section.value] || []).map(k => h('option', { value: k })));
    f.inputs.section.addEventListener('input', fill); fill();
    f.el.append(dl, kl);
    return dialog(e ? 'Edit setting' : 'New setting', f.el, [{ label: 'Cancel' }, { label: 'OK', primary: true, action: async () => {
      const v = f.get();
      if (!v.section.trim() || !v.key.trim()) throw new Error('Section and setting are required');
      return { section: v.section.trim(), key: v.key.trim(), value: v.value.trim() };
    } }]).then(r => (r && r.section ? r : null));
  }
  async function securityTab(g) {
    if (!sysvol.available) return noSysvol();
    let r;
    try { r = await GET('/api/gpo/security', { guid: g.guid }); } catch (e) { say(e); return none(''); }
    let secs = r.sections, etag = r.etag, sel = null, isDirty = false;
    dirty = () => isDirty;
    const saveBtn = btn('Save', save, 'primary'); saveBtn.disabled = true;
    const mark = () => { isDirty = true; saveBtn.disabled = false; draw(); };
    async function save() {
      try { const res = await POST('/api/gpo/security/save', { guid: g.guid, sections: secs, etag }); etag = res.etag; isDirty = false; dirty = null; await load(); } catch (e) { say(e); }
    }
    async function put(old, n) {
      const it = { key: n.key, value: n.value };
      if (old && old.item.noEq && !n.value) it.noEq = true;
      if (old && old.section.toLowerCase() === n.section.toLowerCase()) { secs[old.si].items[old.ii] = it; sel = null; return mark(); }
      if (old) secs[old.si].items.splice(old.ii, 1);
      let s = secs.find(x => x.name.toLowerCase() === n.section.toLowerCase());
      if (!s) { s = { name: n.section, items: [] }; secs.push(s); }
      s.items.push(it);
      secs = secs.filter(x => x.items.length || x === s);
      sel = null; mark();
    }
    const add = async () => { const n = await secEntryDialog(secs, null); if (n) put(null, n); };
    const remove = () => { if (!sel) return; secs[sel.si].items.splice(sel.ii, 1); secs = secs.filter(x => x.items.length); sel = null; mark(); };
    function draw() {
      blankMenu([{ label: 'Add…', fn: add }]);
      const trs = [];
      secs.forEach((s, si) => {
        trs.push(h('tr', {}, h('td', { colspan: 2, class: 'muted', style: 'font-weight:600' }, '[' + s.name + ']')));
        s.items.forEach((it, ii) => {
          const tr = h('tr', { class: 'row' + (sel && sel.si === si && sel.ii === ii ? ' sel' : '') }, h('td', {}, it.key), h('td', { title: it.value }, it.value));
          tr.addEventListener('click', () => { sel = { si, ii, item: it, section: s.name }; draw(); });
          tr.addEventListener('dblclick', () => edit({ si, ii, item: it, section: s.name }));
          tr.addEventListener('contextmenu', e => {
            e.preventDefault(); sel = { si, ii, item: it, section: s.name }; draw();
            menu(e.clientX, e.clientY, [{ label: 'Edit…', fn: () => edit(sel) }, { label: 'Remove', danger: true, fn: remove }, '-', { label: 'Add…', fn: add }]);
          });
          trs.push(tr);
        });
      });
      body.replaceChildren(h('div', { class: 'toolbar' },
        btn('Add…', add),
        btn('Edit…', () => edit(sel)),
        btn('Remove', remove, 'danger'),
        h('span', { class: 'sp' }), saveBtn),
        trs.length ? h('table', {}, h('thead', {}, h('tr', {}, ['Setting', 'Value'].map(c => h('th', { style: 'cursor:default' }, c)))), h('tbody', {}, trs)) : h('div', { class: 'muted gpad' }, 'No security settings.'));
    }
    async function edit(e) { if (!e) return; const n = await secEntryDialog(secs, e); if (n) put(e, n); }
    draw();
  }

  // ----- Files -----
  function filesTab(g) {
    if (!sysvol.available) return noSysvol();
    let path = '', files = [], sel = null;
    const crumbs = h('span', { class: 'crumbs' });
    const canWrite = () => /^(machine|user)(\/|$)/i.test(path);
    const join = n => (path ? path + '/' : '') + n;
    async function go(p) {
      try { const r = await GET('/api/gpo/files', { guid: g.guid, path: p }); path = p; files = r.files; sel = null; say(null); } catch (e) { say(e); }
      draw();
    }
    async function openFile(f) {
      if (f.dir) return go(join(f.name));
      let r;
      try { r = await GET('/api/gpo/file', { guid: g.guid, path: join(f.name) }); } catch (e) { return say(e); }
      if (r.kind !== 'text') return saveBlob(f.name, new Blob([b64ToBytes(r.b64)]));
      const ta = h('textarea', { class: 'ed mono', spellcheck: 'false' }); ta.value = r.text;
      if (await dialog(join(f.name), ta, canWrite() ? [{ label: 'Cancel' }, { label: 'Save', primary: true, action: async () => {
        await POST('/api/gpo/file/save', { guid: g.guid, path: join(f.name), encoding: r.encoding, text: ta.value, etag: r.etag }); await load(false);
      } }] : [{ label: 'Close' }], { wide: true })) go(path);
    }
    async function download(f) {
      try {
        const r = await GET('/api/gpo/file', { guid: g.guid, path: join(f.name) });
        saveBlob(f.name, new Blob([r.kind === 'text' ? r.text : b64ToBytes(r.b64)]));
      } catch (e) { say(e); }
    }
    async function newFile() {
      const f = form([{ k: 'name', label: 'File name' }]);
      if (await dialog('New file', f.el, [{ label: 'Cancel' }, { label: 'Create', primary: true, action: async () => {
        const n = f.get().name.trim(); if (!n) throw new Error('A name is required');
        await POST('/api/gpo/file/save', { guid: g.guid, path: join(n), create: true, encoding: 'utf-8', text: '' }); await load(false);
      } }])) go(path);
    }
    async function newFolder() {
      const f = form([{ k: 'name', label: 'Folder name' }]);
      if (await dialog('New folder', f.el, [{ label: 'Cancel' }, { label: 'Create', primary: true, action: async () => {
        const n = f.get().name.trim(); if (!n) throw new Error('A name is required');
        await POST('/api/gpo/file/mkdir', { guid: g.guid, path: join(n) }); await load(false);
      } }])) go(path);
    }
    const up = h('input', { type: 'file', hidden: true });
    up.addEventListener('change', async () => {
      const f = up.files[0]; up.value = '';
      if (!f) return;
      if (f.size > 700 * 1024) return say('Files up to 700 KiB can be uploaded.');
      try { await POST('/api/gpo/file/save', { guid: g.guid, path: join(f.name), create: true, b64: bufToB64(await f.arrayBuffer()) }); await load(false); go(path); } catch (e) { say(e); }
    });
    async function del(f) {
      if (!(await confirmBox('Delete', `Delete “${f.name}”` + (f.dir ? ' and everything in it?' : '?'), 'Delete', true))) return;
      try { await POST('/api/gpo/file/delete', { guid: g.guid, path: join(f.name) }); await load(false); go(path); } catch (e) { say(e); }
    }
    function draw() {
      const parts = path ? path.split('/') : [];
      crumbs.replaceChildren(h('a', { onclick: () => go('') }, 'GPT'), ...parts.flatMap((p, i) => [' / ', h('a', { onclick: () => go(parts.slice(0, i + 1).join('/')) }, p)]));
      const w = canWrite();
      blankMenu([{ label: 'New file…', disabled: !w, fn: newFile }, { label: 'New folder…', disabled: !w, fn: newFolder }, { label: 'Upload…', disabled: !w, fn: () => up.click() }]);
      const d = (label, fn, cls, on) => { const b = btn(label, fn, cls); b.disabled = !on; return b; };
      body.replaceChildren(h('div', { class: 'toolbar' }, crumbs, h('span', { class: 'sp' }),
        d('New file…', newFile, '', w), d('New folder…', newFolder, '', w), d('Upload…', () => up.click(), '', w),
        d('Open', () => openFile(sel), '', !!sel), d('Download', () => download(sel), '', !!sel && !sel.dir), d('Delete', () => del(sel), 'danger', !!sel && w), up),
        h('table', {}, h('thead', {}, h('tr', {}, ['Name', 'Size', 'Modified'].map(c => h('th', { style: 'cursor:default' }, c)))),
          h('tbody', {}, files.map(f => {
            const tr = h('tr', { class: 'row' + (sel && sel.name === f.name ? ' sel' : '') }, h('td', {}, icon(f.dir ? 'folder' : 'other'), f.name), h('td', {}, f.dir ? '' : fmtSize(f.size)), h('td', {}, f.modified));
            tr.addEventListener('click', () => { sel = f; draw(); });
            tr.addEventListener('dblclick', () => openFile(f));
            tr.addEventListener('contextmenu', e => {
              e.preventDefault(); sel = f; draw();
              menu(e.clientX, e.clientY, [{ label: 'Open', fn: () => openFile(f) }, { label: 'Download', disabled: f.dir, fn: () => download(f) },
                { label: 'Delete', danger: true, disabled: !w, fn: () => del(f) }, '-',
                { label: 'New file…', disabled: !w, fn: newFile }, { label: 'New folder…', disabled: !w, fn: newFolder }, { label: 'Upload…', disabled: !w, fn: () => up.click() }]);
            });
            return tr;
          }))));
    }
    go('');
  }

  // ----- Details -----
  function detailsTab(g) {
    const st = h('select', {}, GPO_STATUS.map(([v, l]) => h('option', { value: v }, l)));
    st.value = String(g.flags);
    st.addEventListener('change', async () => { try { await POST('/api/gpo/status', { guid: g.guid, flags: +st.value }); await load(); } catch (e) { say(e); st.value = String(g.flags); } });
    const me = h('input', { type: 'text', class: 'mono', value: g.machineExt }), ue = h('input', { type: 'text', class: 'mono', value: g.userExt });
    const ver = (ad, gpt) => !g.gptKnown ? String(ad) : ad === gpt ? String(ad) : h('span', { class: 'terr', title: 'AD and SYSVOL disagree' }, ad + ' in AD, ' + gpt + ' in SYSVOL');
    const kv = [['Name', g.name], ['GUID', g.guid], ['Created', g.created], ['Changed', g.changed], ['SYSVOL path', h('span', { class: 'mono' }, g.path)],
      ['Computer version', ver(g.machineVersion, g.gptVersion & 0xffff)], ['User version', ver(g.userVersion, g.gptVersion >>> 16)],
      ['Status', st], ['Computer extensions', me], ['User extensions', ue]];
    body.replaceChildren(h('table', { class: 'simple kv' }, h('tbody', {}, kv.map(([k, v]) => h('tr', {}, h('th', {}, k), h('td', {}, v))))),
      h('div', { class: 'toolbar' }, btn('Save extensions', async () => { try { await POST('/api/gpo/ext', { guid: g.guid, machine: me.value, user: ue.value }); await load(); } catch (e) { say(e); } }, '', 'Which kinds of settings clients should process')));
  }

  right.append(h('div', { class: 'toolbar' }, btn('Refresh', async () => { if (await guard()) { dirty = null; load(); } }), btn('New GPO…', newGPO), btn('Rename…', renameGPO), btn('Delete', deleteGPO, 'danger'), err), tabBar, body);
  load();
}

TOOLS.gpo = renderGPO;
