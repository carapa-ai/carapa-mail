var API = window.location.origin;
var accounts = [];
var apiToken = sessionStorage.getItem('carapamail_token') || '';
var authMode = sessionStorage.getItem('carapamail_auth_mode') || ''; // 'admin', 'user', or ''
var ALLOW_SIGNUP = '{{ALLOW_SIGNUP}}' === 'true';
var HAS_TOKEN = '{{HAS_TOKEN}}' === 'true';
var PUBLIC_HOSTNAME = '{{PUBLIC_HOSTNAME}}' || window.location.hostname;
var SMTP_PORT = Number('{{SMTP_PORT}}') || 2525;
var IMAP_PORT = Number('{{IMAP_PORT}}') || 1993;
var MCP_PORT = Number('{{MCP_PORT}}') || 3466;
var MCP_ENABLED = '{{MCP_ENABLED}}' === 'true';
var MCP_PUBLIC_URL = '{{MCP_PUBLIC_URL}}';
var isGuest = ALLOW_SIGNUP && HAS_TOKEN && (!apiToken);
var isUser = authMode === 'user';

// Auto-fill IMAP/SMTP from email domain
document.getElementById('f-email').addEventListener('change', function () {
  const email = this.value;
  if (!email.includes('@')) return;
  const domain = email.split('@')[1];
  const imapHost = document.getElementById('f-imapHost');
  const smtpHost = document.getElementById('f-smtpHost');
  const imapUser = document.getElementById('f-imapUser');
  const smtpUser = document.getElementById('f-smtpUser');
  if (!imapHost.value) imapHost.value = 'imap.' + domain;
  if (!smtpHost.value) smtpHost.value = 'smtp.' + domain;
  if (!imapUser.value) imapUser.value = email;
  if (!smtpUser.value) smtpUser.value = email;
});

async function api(path, opts = {}) {
  const headers = { 'Content-Type': 'application/json' };
  if (apiToken) {
    headers['Authorization'] = authMode === 'user' ? 'Basic ' + apiToken : 'Bearer ' + apiToken;
  }
  const res = await fetch(API + path, { headers, ...opts });
  if (res.status === 401) {
    if (apiToken) {
      apiToken = '';
      authMode = '';
      isUser = false;
      sessionStorage.removeItem('carapamail_token');
      sessionStorage.removeItem('carapamail_auth_mode');
      isGuest = ALLOW_SIGNUP && HAS_TOKEN;
    }
    if (!isGuest) showAuthPrompt();
    throw new Error('Unauthorized');
  }
  return res;
}

async function apiJson(path, opts = {}) {
  const res = await api(path, opts);
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || 'Request failed');
  return data;
}

function showAuthPrompt() {
  document.getElementById('auth-prompt').style.display = 'block';
  document.getElementById('main-ui').style.display = 'none';
  document.getElementById('user-email').focus();
}

function cancelAuthPrompt() {
  isGuest = true;
  document.getElementById('auth-prompt').style.display = 'none';
  document.getElementById('main-ui').style.display = 'block';
  document.getElementById('main-tabs').style.display = 'none';
  document.getElementById('accounts-list').innerHTML = '<div class="empty">Add your email account to get started with CarapaMail.<br><br><button class="primary" onclick="isGuest=false;showAuthPrompt();return false;">Login</button></div>';
}

async function submitToken() {
  const token = document.getElementById('auth-token').value.trim();
  if (!token) return;
  const errEl = document.getElementById('admin-login-error');
  if (errEl) errEl.textContent = '';

  // Validate the token with the server before updating UI
  try {
    const res = await fetch(API + '/api/accounts', {
      headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + token }
    });
    if (!res.ok) {
      if (errEl) errEl.textContent = 'Invalid admin key';
      return;
    }
  } catch (err) {
    if (errEl) errEl.textContent = 'Connection failed: ' + err.message;
    return;
  }

  apiToken = token;
  authMode = 'admin';
  isUser = false;
  isGuest = false;
  sessionStorage.setItem('carapamail_token', token);
  sessionStorage.setItem('carapamail_auth_mode', 'admin');
  document.getElementById('auth-prompt').style.display = 'none';
  document.getElementById('main-ui').style.display = 'block';
  document.getElementById('logout-btn').style.display = 'inline-block';
  loadAccounts();
}

function showUserLogin() {
  document.getElementById('admin-login').style.display = 'none';
  document.getElementById('user-login').style.display = 'block';
  document.getElementById('user-email').focus();
}

function showAdminLogin() {
  document.getElementById('user-login').style.display = 'none';
  document.getElementById('admin-login').style.display = 'block';
  document.getElementById('auth-token').focus();
}

async function submitUserLogin() {
  const email = document.getElementById('user-email').value.trim();
  const password = document.getElementById('user-password').value;
  const errEl = document.getElementById('user-login-error');
  errEl.textContent = '';
  if (!email || !password) { errEl.textContent = 'Email and password required'; return; }

  // Validate credentials via /api/auth
  try {
    const res = await fetch(API + '/api/auth', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password }),
    });
    const data = await res.json();
    if (!res.ok) { errEl.textContent = data.error || 'Login failed'; return; }

    // Store Basic auth token (base64 of email:password)
    apiToken = btoa(email + ':' + password);
    authMode = 'user';
    isUser = true;
    isGuest = false;
    sessionStorage.setItem('carapamail_token', apiToken);
    sessionStorage.setItem('carapamail_auth_mode', 'user');
    document.getElementById('auth-prompt').style.display = 'none';
    document.getElementById('main-ui').style.display = 'block';
    document.getElementById('logout-btn').style.display = 'inline-block';
    loadAccounts();
  } catch (err) {
    errEl.textContent = 'Login failed: ' + err.message;
  }
}

function logout() {
  apiToken = '';
  authMode = '';
  isUser = false;
  sessionStorage.removeItem('carapamail_token');
  sessionStorage.removeItem('carapamail_auth_mode');
  if (ALLOW_SIGNUP && HAS_TOKEN) {
    isGuest = true;
  }
  window.location.reload();
}



function showMsg(text, type) {
  const el = document.getElementById('status-msg');
  el.textContent = text;
  el.style.display = '';
  el.className = type;
  setTimeout(() => { el.className = ''; }, 5000);
}

async function loadAccounts() {
  if (isGuest) {
    document.getElementById('main-ui').style.display = 'block';
    document.getElementById('main-tabs').style.display = 'none';
    document.getElementById('auth-prompt').style.display = 'block';
    document.getElementById('accounts-list').innerHTML = '';
    return;
  }

  if (!isUser) {
    document.getElementById('main-tabs').style.display = 'flex';
    const rulesNavTab = document.getElementById('tab-nav-rules');
    if (rulesNavTab) rulesNavTab.style.display = 'inline-block';
    const whitelistNavTab = document.getElementById('tab-nav-whitelist');
    if (whitelistNavTab) whitelistNavTab.style.display = 'inline-block';
    const statsNavTab = document.getElementById('tab-nav-stats');
    if (statsNavTab) statsNavTab.style.display = 'inline-block';
  } else {
    document.getElementById('main-tabs').style.display = 'flex';
    document.getElementById('add-btn').style.display = 'none';
  }

  try {
    accounts = await apiJson('/api/accounts');
    render();
    if (activeMainTab === 'quarantine') loadQuarantine();
    else if (activeMainTab === 'audit') loadAuditLogs();
    else if (activeMainTab === 'rules') loadRules();
    else if (activeMainTab === 'whitelist') loadWhitelist();
    else if (activeMainTab === 'stats') loadStats();
  } catch (e) {
    document.getElementById('accounts-list').innerHTML = '<div class="empty">Failed to load accounts</div>';
  }
}

var quarantinePage = 0;
var quarantinePageSize = 20;
var auditPage = 0;
var auditPageSize = 50;

var activeMainTab = 'accounts';
function switchMainTab(tab) {
  activeMainTab = tab;
  document.querySelectorAll('#main-tabs .tab').forEach(t => {
    t.classList.toggle('active', t.getAttribute('data-tab') === tab);
  });
  document.querySelectorAll('#main-ui > .tab-content').forEach(c => {
    c.classList.toggle('active', c.id === 'tab-' + tab);
  });
  if (tab === 'quarantine') { quarantinePage = 0; loadQuarantine(); }
  else if (tab === 'audit') { auditPage = 0; loadAuditLogs(); }
  else if (tab === 'rules') loadRules();
  else if (tab === 'whitelist') loadWhitelist();
  else if (tab === 'stats') loadStats();
}

async function loadQuarantine() {
  const el = document.getElementById('quarantine-list');
  if (!el) return;
  try {
    const offset = quarantinePage * quarantinePageSize;
    const list = await apiJson('/quarantine?status=pending&limit=' + quarantinePageSize + '&offset=' + offset);
    if (list.length === 0 && quarantinePage === 0) {
      el.innerHTML = '<div class="empty">No messages in quarantine</div>';
      return;
    }
    let html = '<div class="table-wrap"><table style="table-layout:fixed; width:100%;"><thead><tr><th style="width:110px;">Date</th><th style="width:15%;">Sender</th><th style="width:25%;">Subject</th><th style="width:120px;">Decision</th><th style="width:145px;">Action</th></tr></thead><tbody>';
    html += list.map(e => {
      const preview = e.body_preview ? e.body_preview.substring(0, 100).replace(/\s+/g, ' ') : '';
      return `
      <tr>
        <td style="white-space:nowrap; vertical-align:top; color:#888; font-size:12px;">${new Date(e.created_at).toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })}</td>
        <td style="overflow:hidden; text-overflow:ellipsis; white-space:nowrap; vertical-align:top;" title="${esc(e.from_addr || '')} &rarr; ${esc(e.to_addr || '')}">
          <div style="font-weight:500;">${esc(e.from_addr || '')}</div>
          <div style="font-size:11px; color:#888;">to: ${esc(e.to_addr || '')}</div>
        </td>
        <td style="overflow:hidden; vertical-align:top;">
          <div style="font-weight:500; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;" title="${esc(e.subject)}">${esc(e.subject || '(no subject)')}</div>
          <div style="font-size:11px;color:#666;margin-top:2px; display:-webkit-box; -webkit-line-clamp:3; -webkit-box-orient:vertical; overflow:hidden;" title="${esc(preview)}">${esc(preview)}${e.body_preview && e.body_preview.length > 100 ? '...' : ''}</div>
        </td>
        <td style="overflow:hidden; vertical-align:top;">
          <span class="status-pending">Blocked</span><br>
          <span class="reason-text" style="display:-webkit-box; -webkit-line-clamp:4; -webkit-box-orient:vertical; overflow:hidden;" title="${esc(e.reason)}">${esc(e.reason)}</span>
        </td>
        <td style="vertical-align:top;">
          <div style="display:flex;gap:4px;flex-wrap:wrap;">
            <button class="primary" style="padding:4px 8px;" onclick="releaseEntry('${e.id}', this)">Release</button>
            <button class="danger" style="padding:4px 8px;" onclick="deleteEntry('${e.id}', this)">Delete</button>
          </div>
        </td>
      </tr>
    `}).join('');
    html += '</tbody></table></div>';
    html += renderPagination(quarantinePage, list.length, quarantinePageSize, 'quarantine');
    el.innerHTML = html;
  } catch (e) {
    el.innerHTML = '<div class="empty">Failed to load quarantine</div>';
  }
}

async function releaseEntry(id, btn) {
  if (!confirm('Release and whitelist this sender?')) return;
  const originalText = btn.textContent;
  btn.textContent = 'Relasing...';
  btn.disabled = true;
  try {
    await apiJson('/quarantine/' + id + '/release', { method: 'POST' });
    showMsg('Message released and sender whitelisted', 'success');
    loadQuarantine();
  } catch (e) {
    showMsg('Release failed: ' + e.message, 'error');
    btn.textContent = originalText;
    btn.disabled = false;
  }
}

async function deleteEntry(id, btn) {
  if (!confirm('Permanently delete this message?')) return;
  btn.disabled = true;
  try {
    await apiJson('/quarantine/' + id, { method: 'DELETE' });
    showMsg('Message deleted', 'success');
    loadQuarantine();
  } catch (e) {
    showMsg('Delete failed: ' + e.message, 'error');
    btn.disabled = false;
  }
}

async function loadAuditLogs() {
  const el = document.getElementById('audit-list');
  if (!el) return;
  try {
    const offset = auditPage * auditPageSize;
    const list = await apiJson('/audit?limit=' + auditPageSize + '&offset=' + offset);
    if (list.length === 0 && auditPage === 0) {
      el.innerHTML = '<div class="empty">No audit logs available</div>';
      return;
    }
    let html = '<div class="table-wrap"><table style="table-layout:fixed; width:100%;"><thead><tr><th style="width:140px;">Date & Time</th><th style="width:85px;">Direction</th><th style="width:15%;">Sender / Recipient</th><th style="width:25%;">Subject</th><th style="width:85px;">Decision</th><th style="width:auto;">Reason</th></tr></thead><tbody>';
    html += list.map(e => {
      const badgeClass = e.action === 'pass' ? 'ok' : (e.action === 'quarantine' ? 'pending' : (e.action === 'block' ? 'err' : ''));
      return `
      <tr>
        <td style="white-space:nowrap; vertical-align:top; color:#888; font-size:12px;">${new Date(e.created_at).toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', second: '2-digit' })}</td>
        <td style="white-space:nowrap; vertical-align:top;">${esc(e.direction)}</td>
        <td style="overflow:hidden; text-overflow:ellipsis; white-space:nowrap; vertical-align:top;" title="${esc(e.from_addr || '')} &rarr; ${esc(e.to_addr || '')}">
          <div style="font-weight:500;">${esc(e.from_addr || '')}</div>
          <div style="font-size:11px; color:#888;">to: ${esc(e.to_addr || '')}</div>
        </td>
        <td style="overflow:hidden; text-overflow:ellipsis; white-space:nowrap; vertical-align:top;" title="${esc(e.subject || '')}">${esc(e.subject || '-')}</td>
        <td style="overflow:hidden; text-overflow:ellipsis; white-space:nowrap; vertical-align:top;"><span class="badge ${badgeClass ? 'badge-' + badgeClass : ''}">${esc(e.action)}</span></td>
        <td style="overflow:hidden; vertical-align:top;">
          <div style="font-size:12px;color:#ccc; display:-webkit-box; -webkit-line-clamp:3; -webkit-box-orient:vertical; overflow:hidden;" title="${esc(e.reason || '-')}">${esc(e.reason || '-')}</div>
        </td>
      </tr>
    `}).join('');
    html += '</tbody></table></div>';
    html += renderPagination(auditPage, list.length, auditPageSize, 'audit');
    el.innerHTML = html;
  } catch (e) {
    el.innerHTML = '<div class="empty">Failed to load audit logs: ' + esc(e.message) + '</div>';
  }
}

function renderPagination(page, count, pageSize, type) {
  const hasPrev = page > 0;
  const hasNext = count === pageSize;
  if (!hasPrev && !hasNext) return '';
  return '<div style="display:flex;align-items:center;justify-content:space-between;padding:12px 0;">'
    + '<button ' + (hasPrev ? 'onclick="paginateTo(\'' + type + '\',' + (page - 1) + ')"' : 'disabled') + ' style="padding:6px 14px;">&larr; Newer</button>'
    + '<span style="color:#888;font-size:13px;">Page ' + (page + 1) + '</span>'
    + '<button ' + (hasNext ? 'onclick="paginateTo(\'' + type + '\',' + (page + 1) + ')"' : 'disabled') + ' style="padding:6px 14px;">Older &rarr;</button>'
    + '</div>';
}

function paginateTo(type, page) {
  if (type === 'quarantine') { quarantinePage = page; loadQuarantine(); }
  else if (type === 'audit') { auditPage = page; loadAuditLogs(); }
}

async function loadRules() {
  const el = document.getElementById('rules-list');
  if (!el) return;
  try {
    const list = await apiJson('/rules');
    if (list.length === 0) {
      el.innerHTML = '<div class="empty">No custom rules configured</div>';
      return;
    }
    let html = '<div class="table-wrap"><table style="table-layout:fixed; width:100%;"><thead><tr><th style="width:10%;">Action</th><th style="width:10%;">Direction</th><th style="width:8%;">Field</th><th style="width:auto;">Pattern</th><th style="width:5%;">Prio</th><th style="width:12%;">Date</th><th style="width:110px;"></th></tr></thead><tbody>';
    html += list.map(e => `
      <tr>
        <td style="white-space:nowrap; vertical-align:top;">
          <span class="badge badge-${e.type === 'allow' ? 'ok' : (e.type === 'block' ? 'err' : 'pending')}">${e.type}</span>
        </td>
        <td style="white-space:nowrap; vertical-align:top; color:#888;">${esc(e.direction || 'both')}</td>
        <td style="white-space:nowrap; vertical-align:top; font-weight:500;">${esc(e.match_field)}</td>
        <td style="vertical-align:top; font-family:monospace; line-break:anywhere;">${esc(e.match_pattern)}</td>
        <td style="white-space:nowrap; vertical-align:top; text-align:center;">${e.priority || 0}</td>
        <td style="white-space:nowrap; vertical-align:top; color:#888;">${new Date(e.created_at).toLocaleDateString()}</td>
        <td style="vertical-align:top; text-align:right; white-space:nowrap;">
          <button style="padding:4px 8px;" onclick='editRule(${JSON.stringify(e).replace(/'/g, "&#39;")})'>Edit</button>
          <button class="danger" style="padding:4px 8px;" onclick="deleteRule('${e.id}')">Delete</button>
        </td>
      </tr>
    `).join('');
    html += '</tbody></table></div>';
    el.innerHTML = html;
  } catch (e) {
    el.innerHTML = '<div class="empty">Failed to load rules: ' + esc(e.message) + '</div>';
  }
}

let editingRuleId = null;

function showAddRuleForm() {
  editingRuleId = null;
  document.getElementById('rule-form').reset();
  document.getElementById('rule-form-error').textContent = '';
  document.getElementById('rule-form-title').textContent = 'Add Rule';
  document.getElementById('rule-submit').textContent = 'Save Rule';
  document.getElementById('rule-overlay').classList.add('active');
}

function editRule(rule) {
  editingRuleId = rule.id;
  document.getElementById('rule-form-error').textContent = '';
  document.getElementById('rule-form-title').textContent = 'Edit Rule';
  document.getElementById('rule-submit').textContent = 'Update Rule';
  document.getElementById('r-type').value = rule.type;
  document.getElementById('r-field').value = rule.match_field;
  document.getElementById('r-pattern').value = rule.match_pattern;
  document.getElementById('r-direction').value = rule.direction || 'both';
  document.getElementById('r-priority').value = rule.priority || 0;
  document.getElementById('rule-overlay').classList.add('active');
}

function hideRuleForm() {
  editingRuleId = null;
  document.getElementById('rule-overlay').classList.remove('active');
}

async function handleRuleSubmit(e) {
  e.preventDefault();
  const errEl = document.getElementById('rule-form-error');
  errEl.textContent = '';

  const data = {
    type: document.getElementById('r-type').value,
    match_field: document.getElementById('r-field').value,
    match_pattern: document.getElementById('r-pattern').value,
    direction: document.getElementById('r-direction').value,
    priority: parseInt(document.getElementById('r-priority').value, 10) || 0
  };

  const submitBtn = document.getElementById('rule-submit');
  submitBtn.disabled = true;
  submitBtn.textContent = 'Saving...';

  try {
    if (editingRuleId) {
      await apiJson('/rules/' + editingRuleId, { method: 'PUT', body: JSON.stringify(data) });
      showMsg('Rule updated', 'success');
    } else {
      await apiJson('/rules', { method: 'POST', body: JSON.stringify(data) });
      showMsg('Rule added successfully', 'success');
    }
    hideRuleForm();
    loadRules();
  } catch (err) {
    errEl.textContent = err.message;
  } finally {
    submitBtn.disabled = false;
    submitBtn.textContent = editingRuleId ? 'Update Rule' : 'Save Rule';
  }
}

async function deleteRule(id) {
  if (!confirm('Are you sure you want to delete this rule?')) return;
  try {
    await apiJson('/rules/' + id, { method: 'DELETE' });
    showMsg('Rule deleted', 'success');
    loadRules();
  } catch (err) {
    showMsg('Failed to delete rule: ' + err.message, 'error');
  }
}

async function loadWhitelist() {
  const el = document.getElementById('whitelist-list');
  if (!el) return;
  try {
    const list = await apiJson('/whitelist');
    if (list.length === 0) {
      el.innerHTML = '<div class="empty">No whitelist entries configured</div>';
      return;
    }
    let html = '<div class="table-wrap"><table style="table-layout:fixed; width:100%;"><thead><tr><th style="width:15%;">Type</th><th style="width:auto%;">Pattern / Email</th><th style="width:15%;">Source</th><th style="width:15%;">Date added</th><th style="width:100px;"></th></tr></thead><tbody>';
    html += list.map(e => `
      <tr>
        <td style="white-space:nowrap; vertical-align:top; font-weight:500;">
          <span class="badge badge-ok">${esc(e.type)}</span>
        </td>
        <td style="vertical-align:top; font-family:monospace; line-break:anywhere;">${esc(e.pattern)}</td>
        <td style="white-space:nowrap; vertical-align:top;">${esc(e.source)}</td>
        <td style="white-space:nowrap; vertical-align:top; color:#888;">${new Date(e.created_at).toLocaleDateString()}</td>
        <td style="vertical-align:top; text-align:right;">
          <button class="danger" style="padding:4px 8px;" onclick="deleteWhitelist('${esc(e.type)}', '${esc(e.pattern)}', '${esc(e.account_id)}')">Delete</button>
        </td>
      </tr>
    `).join('');
    html += '</tbody></table></div>';
    el.innerHTML = html;
  } catch (e) {
    el.innerHTML = '<div class="empty">Failed to load whitelist: ' + esc(e.message) + '</div>';
  }
}

function showAddWhitelistForm() {
  document.getElementById('whitelist-form').reset();
  document.getElementById('whitelist-form-error').textContent = '';
  document.getElementById('whitelist-overlay').classList.add('active');
}

function hideWhitelistForm() {
  document.getElementById('whitelist-overlay').classList.remove('active');
}

async function handleWhitelistSubmit(e) {
  e.preventDefault();
  const errEl = document.getElementById('whitelist-form-error');
  errEl.textContent = '';

  const data = {
    type: document.getElementById('w-type').value,
    pattern: document.getElementById('w-pattern').value
  };

  const submitBtn = document.getElementById('whitelist-submit');
  submitBtn.disabled = true;
  submitBtn.textContent = 'Saving...';

  try {
    await apiJson('/whitelist', { method: 'POST', body: JSON.stringify(data) });
    showMsg('Whitelist entry added', 'success');
    hideWhitelistForm();
    loadWhitelist();
  } catch (err) {
    errEl.textContent = err.message;
  } finally {
    submitBtn.disabled = false;
    submitBtn.textContent = 'Add Entry';
  }
}

async function deleteWhitelist(type, pattern, accountId) {
  if (!confirm('Are you sure you want to delete this whitelist entry?')) return;
  try {
    await apiJson('/whitelist', {
      method: 'DELETE',
      body: JSON.stringify({ type, pattern, account_id: accountId })
    });
    showMsg('Whitelist entry deleted', 'success');
    loadWhitelist();
  } catch (err) {
    showMsg('Failed to delete entry: ' + err.message, 'error');
  }
}

async function loadStats() {
  const el = document.getElementById('stats-list');
  if (!el) return;
  try {
    const stats = await apiJson('/stats');
    if (!stats) {
      el.innerHTML = '<div class="empty">No stats available</div>';
      return;
    }
    el.innerHTML = `
      <div style="display:grid; grid-template-columns:repeat(auto-fit, minmax(200px, 1fr)); gap:16px;">
        <div class="card" style="background:rgba(34,211,238,0.05);border:1px solid rgba(34,211,238,0.2);text-align:center;">
          <div style="font-size:32px;font-weight:700;color:#22d3ee;margin-bottom:8px;">${stats.total || 0}</div>
          <div style="font-size:14px;color:#888;">Total Emails Scanned</div>
        </div>
        <div class="card" style="background:rgba(34,197,94,0.05);border:1px solid rgba(34,197,94,0.2);text-align:center;">
          <div style="font-size:32px;font-weight:700;color:#22c55e;margin-bottom:8px;">${stats.passed || 0}</div>
          <div style="font-size:14px;color:#888;">Passed</div>
        </div>
        <div class="card" style="background:rgba(239,68,68,0.05);border:1px solid rgba(239,68,68,0.2);text-align:center;">
          <div style="font-size:32px;font-weight:700;color:#ef4444;margin-bottom:8px;">${stats.rejected || 0}</div>
          <div style="font-size:14px;color:#888;">Rejected</div>
        </div>
        <div class="card" style="background:rgba(234,179,8,0.05);border:1px solid rgba(234,179,8,0.2);text-align:center;">
          <div style="font-size:32px;font-weight:700;color:#eab308;margin-bottom:8px;">${stats.quarantined || 0}</div>
          <div style="font-size:14px;color:#888;">Total Quarantined</div>
        </div>
        <div class="card" style="background:rgba(168,85,247,0.05);border:1px solid rgba(168,85,247,0.2);text-align:center;">
          <div style="font-size:32px;font-weight:700;color:#a855f7;margin-bottom:8px;">${stats.pending_quarantine || 0}</div>
          <div style="font-size:14px;color:#888;">Pending Review</div>
        </div>
      </div>
    `;
  } catch (e) {
    el.innerHTML = '<div class="empty">Failed to load stats: ' + esc(e.message) + '</div>';
  }
}

function render() {
  const el = document.getElementById('accounts-list');
  if (accounts.length === 0) {
    el.innerHTML = '<div class="empty">No accounts configured. Click "Add Account" to get started.</div>';
    return;
  }
  let html = '';
  if (isUser && accounts.length > 0) {
    const a = accounts[0];
    html += `<div class="card" style="background:rgba(34,211,238,0.05);border:1px solid rgba(34,211,238,0.2);">
      <p style="font-weight:500;margin-bottom:8px;color:#fff;">Mail client settings</p>
      <div style="font-size:13px;line-height:1.8;color:#ccc;">
        <strong style="color:#fff;">IMAP:</strong> ${esc(PUBLIC_HOSTNAME)}:${IMAP_PORT}<br>
        <strong style="color:#fff;">SMTP:</strong> ${esc(PUBLIC_HOSTNAME)}:${SMTP_PORT}<br>
        <strong style="color:#fff;">Username:</strong> ${esc(a.email)}<br>
        <strong style="color:#fff;">Password:</strong> your CarapaMail password<br>
        <strong style="color:#fff;">Security:</strong> None (local proxy)
      </div>
    </div>`;
    if (MCP_ENABLED && a.mcpTokenSet) {
      const mcpUrl = MCP_PUBLIC_URL || ('https://' + PUBLIC_HOSTNAME + ':' + MCP_PORT + '/mcp');
      html += `<div class="card" style="background:rgba(168,85,247,0.05);border:1px solid rgba(168,85,247,0.2);">
        <p style="font-weight:500;margin-bottom:8px;color:#fff;">MCP connection</p>
        <div style="font-size:13px;line-height:1.8;color:#ccc;">
          <p style="margin-bottom:8px;">Connect Claude or other MCP clients to your mailbox:</p>
          <div style="background:rgba(0,0,0,0.4);border-radius:8px;padding:12px;font-family:monospace;font-size:12px;word-break:break-all;color:#e2e8f0;position:relative;">            
          <span style="color:#9ca3af;">$</span> claude mcp add --transport http carapamail ${esc(mcpUrl)} <br> --header <span style="color:#fbbf24;">"Authorization: Bearer &lt;your-mcp-token&gt;"</span>
          <br>
          <button onclick="navigator.clipboard.writeText('claude mcp add --transport http carapamail ${esc(mcpUrl)} --header \\&quot;Authorization: Bearer <TOKEN>\\&quot;')" style="position:absolute;top:8px;right:8px;background:rgba(255,255,255,0.1);border:1px solid rgba(255,255,255,0.2);border-radius:4px;padding:2px 8px;font-size:11px;color:#ccc;cursor:pointer;">Copy</button>
          <br>
          <p style="margin-bottom:8px;">Verify claude registered the mcp server</p>
          <span style="color:#9ca3af;">$</span> claude mcp list</span><br><br>           
          </div>
          <p style="margin-top:8px;font-size:12px;color:#9ca3af;">Use the MCP token you set in your account settings above.</p>         
        </div>
      </div>`;
    }
  }
  html += accounts.map(a => `
    <div class="card">
      <h3>${esc(a.id)}</h3>
      <div class="meta">${esc(a.email)}</div>
      <div class="servers">
        <span>IMAP: ${esc(a.imap.host)}:${a.imap.port}</span>
        <span>SMTP: ${esc(a.smtp.host || '(not set)')}:${a.smtp.port}</span>
      </div>
      <div style="margin-top:8px;display:flex;gap:6px;flex-wrap:wrap;">
        ${a.inboundEnabled ? '<span class="badge badge-ok">Inbound</span>' : '<span class="badge badge-err">Inbound off</span>'}
        ${a.outboundEnabled ? '<span class="badge badge-ok">Outbound</span>' : '<span class="badge badge-err">Outbound off</span>'}
        ${a.mcpReceiveEnabled ? '<span class="badge badge-ok">MCP read</span>' : '<span class="badge badge-err">MCP read off</span>'}
        ${a.mcpSendEnabled ? '<span class="badge badge-ok">MCP send</span>' : '<span class="badge badge-pending">MCP send off</span>'}
        ${a.mcpDeleteEnabled ? '<span class="badge badge-ok">MCP delete</span>' : '<span class="badge badge-pending">MCP delete off</span>'}
        ${a.mcpTokenSet ? '<span class="badge badge-ok">Token set</span>' : '<span class="badge badge-err">No token</span>'}
      </div>
      <div class="actions">
        <button onclick="testConn('${esc(a.id)}', this)">Test Connection</button>
        <button onclick="sendTestMail('${esc(a.id)}', this)">Send Test Mail</button>
        <button onclick="showEditForm('${esc(a.id)}')">Edit</button>
        <button onclick="showPromptsForm('${esc(a.id)}')">Prompts</button>
        <button class="danger" onclick="deleteAcc('${esc(a.id)}')">Delete</button>
      </div>
    </div>
  `).join('');
  el.innerHTML = html;
}

function esc(s) {
  const d = document.createElement('div');
  d.textContent = s;
  return d.innerHTML;
}

function generateToken() {
  const arr = new Uint8Array(24);
  crypto.getRandomValues(arr);
  const token = Array.from(arr, b => b.toString(16).padStart(2, '0')).join('');
  const input = document.getElementById('f-mcpToken');
  input.value = token;
  input.type = 'text';
  document.getElementById('f-mcpTokenStatus').textContent = 'Generated. Copy this token before saving — it won\'t be shown again.';
}

function showAddForm() {
  document.getElementById('form-title').textContent = 'Add Account';
  document.getElementById('form-submit').textContent = 'Add Account';
  document.getElementById('f-mode').value = 'add';
  document.getElementById('f-id').disabled = false;
  document.getElementById('account-form').reset();
  document.getElementById('f-imapPort').value = '993';
  document.getElementById('f-smtpPort').value = '587';
  document.getElementById('f-mcpToken').value = '';
  document.getElementById('f-mcpToken').type = 'password';
  document.getElementById('f-mcpTokenStatus').textContent = '';
  document.getElementById('form-error').textContent = '';
  document.getElementById('form-overlay').classList.add('active');
}

function showEditForm(id) {
  const acc = accounts.find(a => a.id === id);
  if (!acc) return;
  document.getElementById('form-title').textContent = isUser ? 'My Account' : 'Edit Account';
  document.getElementById('form-submit').textContent = 'Save Changes';
  document.getElementById('f-mode').value = id;
  document.getElementById('f-id').value = id;
  document.getElementById('f-id').disabled = true;
  document.getElementById('f-email').value = acc.email;
  document.getElementById('f-localPassword').value = '';
  document.getElementById('f-imapHost').value = acc.imap.host;
  document.getElementById('f-imapPort').value = acc.imap.port;
  document.getElementById('f-imapUser').value = acc.imap.user;
  document.getElementById('f-imapPass').value = '';
  document.getElementById('f-smtpHost').value = acc.smtp.host;
  document.getElementById('f-smtpPort').value = acc.smtp.port;
  document.getElementById('f-smtpUser').value = acc.smtp.user;
  document.getElementById('f-smtpPass').value = '';
  document.getElementById('f-smtpSecure').value = acc.smtp.secure || 'starttls';
  document.getElementById('f-inboundEnabled').checked = acc.inboundEnabled !== false;
  document.getElementById('f-outboundEnabled').checked = acc.outboundEnabled !== false;
  document.getElementById('f-mcpReceiveEnabled').checked = acc.mcpReceiveEnabled !== false;
  document.getElementById('f-mcpSendEnabled').checked = acc.mcpSendEnabled === true;
  document.getElementById('f-mcpDeleteEnabled').checked = acc.mcpDeleteEnabled === true;
  document.getElementById('f-mcpToken').value = '';
  document.getElementById('f-mcpTokenStatus').textContent = acc.mcpTokenSet ? 'Token is set. Leave blank to keep, or enter a new one.' : 'No token set.';
  document.getElementById('form-error').textContent = '';
  document.getElementById('form-overlay').classList.add('active');
}

function hideForm() {
  document.getElementById('form-overlay').classList.remove('active');
}

async function handleSubmit(e) {
  e.preventDefault();
  const mode = document.getElementById('f-mode').value;
  const errEl = document.getElementById('form-error');
  errEl.textContent = '';

  const data = {};
  const fields = ['id', 'email', 'localPassword', 'imapHost', 'imapPort', 'imapUser', 'imapPass', 'smtpHost', 'smtpPort', 'smtpUser', 'smtpPass', 'smtpSecure'];
  for (const f of fields) {
    const val = document.getElementById('f-' + f).value;
    if (val) {
      data[f] = (f === 'imapPort' || f === 'smtpPort') ? parseInt(val) : val;
    }
  }
  data.inboundEnabled = document.getElementById('f-inboundEnabled').checked;
  data.outboundEnabled = document.getElementById('f-outboundEnabled').checked;
  data.mcpReceiveEnabled = document.getElementById('f-mcpReceiveEnabled').checked;
  data.mcpSendEnabled = document.getElementById('f-mcpSendEnabled').checked;
  data.mcpDeleteEnabled = document.getElementById('f-mcpDeleteEnabled').checked;
  const mcpToken = document.getElementById('f-mcpToken').value;
  if (mcpToken) data.mcpToken = mcpToken;
  const submitBtn = document.getElementById('form-submit');
  try {
    if (mode === 'add') {
      if (!data.localPassword) { errEl.textContent = 'Local password is required'; return false; }
      if (!data.imapPass) { errEl.textContent = 'IMAP password is required'; return false; }
      submitBtn.textContent = 'Validating...';
      submitBtn.disabled = true;
      const result = await apiJson('/api/accounts', { method: 'POST', body: JSON.stringify(data) });
      // Auto-login as the newly created account
      if (isGuest) {
        apiToken = btoa(data.email + ':' + data.localPassword);
        authMode = 'user';
        isUser = true;
        isGuest = false;
        sessionStorage.setItem('carapamail_token', apiToken);
        sessionStorage.setItem('carapamail_auth_mode', 'user');
        document.getElementById('logout-btn').style.display = 'inline-block';
      }
      showMsg('Account added' + (result.smtp === false ? ' (SMTP not verified)' : ''), 'success');
    } else {
      // Edit mode: only send changed fields (skip empty passwords)
      if (!data.localPassword) delete data.localPassword;
      if (!data.imapPass) delete data.imapPass;
      if (!data.smtpPass) delete data.smtpPass;
      delete data.id;
      await apiJson('/api/accounts/' + mode, { method: 'PUT', body: JSON.stringify(data) });
      showMsg('Account updated', 'success');
    }
    hideForm();
    loadAccounts();
  } catch (err) {
    errEl.textContent = err.message;
  } finally {
    submitBtn.textContent = mode === 'add' ? 'Add Account' : 'Save Changes';
    submitBtn.disabled = false;
  }
  return false;
}

async function testConn(id, btn) {
  btn.textContent = 'Testing...';
  btn.disabled = true;
  try {
    const acc = accounts.find(a => a.id === id);
    const r = await apiJson('/api/accounts/' + id + '/test', { method: 'POST' });
    const parts = [];
    if (acc && acc.inboundEnabled) parts.push('IMAP: ' + (r.imap ? 'OK' : 'FAILED'));
    if (acc && acc.outboundEnabled) parts.push('SMTP: ' + (r.smtp ? 'OK' : 'FAILED'));
    if (parts.length === 0) parts.push('No services enabled');
    if (r.error) parts.push(r.error);
    const allOk = (!acc?.inboundEnabled || r.imap) && (!acc?.outboundEnabled || r.smtp);
    showMsg(parts.join(' | '), allOk ? 'success' : 'error');
  } catch (err) {
    showMsg('Test failed: ' + err.message, 'error');
  }
  btn.textContent = 'Test Connection';
  btn.disabled = false;
}

async function sendTestMail(id, btn) {
  const destination = prompt('Enter destination email for test mail:');
  if (!destination) return;
  const originalText = btn.textContent;
  btn.textContent = 'Sending...';
  btn.disabled = true;
  try {
    const r = await apiJson('/api/accounts/' + id + '/test-mail', {
      method: 'POST',
      body: JSON.stringify({ to: destination }),
    });
    showMsg('Test mail sent to ' + destination + ' (decision: ' + r.decision + ')', r.decision === 'pass' ? 'success' : 'error');
  } catch (err) {
    showMsg('Test mail failed: ' + err.message, 'error');
  }
  btn.textContent = originalText;
  btn.disabled = false;
}

async function deleteAcc(id) {
  if (!confirm('Delete account "' + id + '"? This cannot be undone.')) return;
  try {
    const opts = { method: 'DELETE' };
    if (isUser) {
      const password = prompt('Enter your CarapaMail password to confirm deletion:');
      if (!password) return;
      opts.body = JSON.stringify({ password });
    }
    await apiJson('/api/accounts/' + id, opts);
    showMsg('Account deleted', 'success');
    if (isUser) {
      logout();
      return;
    }
    loadAccounts();
  } catch (err) {
    showMsg('Delete failed: ' + err.message, 'error');
  }
}

function setPromptMode(name, mode) {
  const radios = document.querySelectorAll('input[name="p-mode-' + name + '"]');
  radios.forEach(r => { r.checked = r.value === mode; });
  togglePromptTextarea(name);
}

function getPromptMode(name) {
  const checked = document.querySelector('input[name="p-mode-' + name + '"]:checked');
  return checked ? checked.value : 'default';
}

function togglePromptTextarea(name) {
  const mode = getPromptMode(name);
  const ids = { inbound: 'p-inbound', outbound: 'p-outbound', agent: 'p-agent' };
  const ta = document.getElementById(ids[name]);
  ta.disabled = mode === 'default';
  ta.style.opacity = mode === 'default' ? '0.5' : '1';
}

function showPromptsForm(id) {
  const acc = accounts.find(a => a.id === id);
  if (!acc) return;
  document.getElementById('p-accountId').value = id;
  document.getElementById('p-inbound').value = acc.customInboundPrompt || '';
  document.getElementById('p-outbound').value = acc.customOutboundPrompt || '';
  document.getElementById('p-agent').value = acc.customAgentPrompt || '';

  // Apply admin restrictions to UI
  ['inbound', 'outbound', 'agent'].forEach(name => {
    const overrideRadio = document.querySelector('input[name="p-mode-' + name + '"][value="replace"]');
    const appendRadio = document.querySelector('input[name="p-mode-' + name + '"][value="append"]');

    if (overrideRadio) overrideRadio.disabled = !window.ALLOW_PROMPT_OVERRIDE;
    if (appendRadio) appendRadio.disabled = !window.ALLOW_PROMPT_APPEND;

    if (overrideRadio && !window.ALLOW_PROMPT_OVERRIDE) {
      overrideRadio.parentElement.style.opacity = '0.5';
      overrideRadio.parentElement.title = 'Admin has disabled custom prompt overrides';
    }
    if (appendRadio && !window.ALLOW_PROMPT_APPEND) {
      appendRadio.parentElement.style.opacity = '0.5';
      appendRadio.parentElement.title = 'Admin has disabled custom prompt appending';
    }
  });

  const inboundMode = (!window.ALLOW_PROMPT_OVERRIDE && acc.customInboundPromptMode === 'replace') || (!window.ALLOW_PROMPT_APPEND && acc.customInboundPromptMode === 'append') ? 'default' : (acc.customInboundPromptMode || 'default');
  const outboundMode = (!window.ALLOW_PROMPT_OVERRIDE && acc.customOutboundPromptMode === 'replace') || (!window.ALLOW_PROMPT_APPEND && acc.customOutboundPromptMode === 'append') ? 'default' : (acc.customOutboundPromptMode || 'default');
  const agentMode = (!window.ALLOW_PROMPT_OVERRIDE && acc.customAgentPromptMode === 'replace') || (!window.ALLOW_PROMPT_APPEND && acc.customAgentPromptMode === 'append') ? 'default' : (acc.customAgentPromptMode || 'default');

  setPromptMode('inbound', inboundMode);
  setPromptMode('outbound', outboundMode);
  setPromptMode('agent', agentMode);
  document.getElementById('prompts-error').textContent = '';
  switchPromptTab('inbound');
  document.getElementById('prompts-overlay').classList.add('active');
}

function hidePrompts() {
  document.getElementById('prompts-overlay').classList.remove('active');
}

function switchPromptTab(name) {
  document.querySelectorAll('#prompts-overlay .tab').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('#prompts-overlay .tab-content').forEach(t => t.classList.remove('active'));
  document.querySelector('#prompts-overlay .tab[onclick*="' + name + '"]').classList.add('active');
  document.getElementById('ptab-' + name).classList.add('active');
}

async function handlePromptsSave() {
  const id = document.getElementById('p-accountId').value;
  const errEl = document.getElementById('prompts-error');
  errEl.textContent = '';
  const data = {
    customInboundPrompt: document.getElementById('p-inbound').value,
    customOutboundPrompt: document.getElementById('p-outbound').value,
    customAgentPrompt: document.getElementById('p-agent').value,
    customInboundPromptMode: getPromptMode('inbound'),
    customOutboundPromptMode: getPromptMode('outbound'),
    customAgentPromptMode: getPromptMode('agent'),
  };
  const btn = document.getElementById('prompts-submit');
  btn.textContent = 'Saving...';
  btn.disabled = true;
  try {
    await apiJson('/api/accounts/' + id, { method: 'PUT', body: JSON.stringify(data) });
    hidePrompts();
    showMsg('Prompts updated', 'success');
    loadAccounts();
  } catch (err) {
    errEl.textContent = err.message;
  } finally {
    btn.textContent = 'Save Prompts';
    btn.disabled = false;
  }
}

// Click outside form to close
document.getElementById('form-overlay').addEventListener('click', function (e) {
  if (e.target === this) hideForm();
});
document.getElementById('prompts-overlay').addEventListener('click', function (e) {
  if (e.target === this) hidePrompts();
});
document.getElementById('rule-overlay').addEventListener('click', function (e) {
  if (e.target === this) hideRuleForm();
});
document.getElementById('whitelist-overlay').addEventListener('click', function (e) {
  if (e.target === this) hideWhitelistForm();
});

// Show logout button if user has a saved token
if (apiToken) {
  document.getElementById('logout-btn').style.display = 'inline-block';
} else if (!isGuest && HAS_TOKEN) {
  showAuthPrompt();
}

if (ALLOW_SIGNUP) {
  const cancelBtn = document.getElementById('auth-cancel-btn');
  if (cancelBtn) cancelBtn.style.display = 'inline';
}

loadAccounts();