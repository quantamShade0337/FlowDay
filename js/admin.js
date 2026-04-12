'use strict';

(function () {
  const FOUNDER_EMAIL = 'ethan.sohyt@gmail.com';
  const ADMIN_ALLOWLIST = [FOUNDER_EMAIL, 'me@adamzafir.com'];
  const PLAN_ORDER = ['free', 'lite', 'pro', 'advanced', 'elite'];
  const PLAN_CREDITS = { free: 5000, lite: 20000, pro: 50000, advanced: 100000, elite: 200000 };

  const S = {
    user: null,
    profile: null,
    authorized: false,
    users: [],
    audits: [],
    liveStats: null,
    snapshot: null,
    snapshotLoaded: false,
    snapshotWriting: false,
    filters: { q: '', role: 'all', plan: 'all', sort: 'last_seen' },
    pendingAction: null,
    openDrawerUid: '',
    unsubs: { users: null, audits: null },
  };

  function esc(v) {
    if (v === null || v === undefined) return '';
    return String(v)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#x27;')
      .replace(/`/g, '&#x60;');
  }

  function setTheme(theme) {
    document.documentElement.setAttribute('data-theme', theme);
    localStorage.setItem('theme', theme);
  }

  function getPreferredTheme() {
    const saved = localStorage.getItem('theme');
    if (saved === 'dark' || saved === 'light') return saved;
    return window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
  }

  function toggleTheme() {
    const cur = document.documentElement.getAttribute('data-theme') || getPreferredTheme();
    setTheme(cur === 'dark' ? 'light' : 'dark');
  }

  function toMs(value) {
    if (!value) return 0;
    const parsed = Date.parse(value);
    return Number.isNaN(parsed) ? 0 : parsed;
  }

  function fmtDateTime(value) {
    const ms = toMs(value);
    if (!ms) return '-';
    return new Date(ms).toLocaleString();
  }

  function safeId(uid) {
    return String(uid || '').replace(/[^a-zA-Z0-9_-]/g, '_');
  }

  function showToast(message, type = '') {
    let wrap = document.querySelector('.toast-wrap');
    if (!wrap) {
      wrap = document.createElement('div');
      wrap.className = 'toast-wrap';
      document.body.appendChild(wrap);
    }
    const node = document.createElement('div');
    node.className = `toast ${type}`.trim();
    node.textContent = message;
    wrap.appendChild(node);
    setTimeout(() => node.remove(), 3800);
  }

  function getDisplayName() {
    return S.profile?.name || S.user?.displayName || S.user?.email || 'Admin';
  }

  function todayKey() {
    return new Date().toISOString().split('T')[0];
  }

  function redirectToAppLogin() {
    const qs = new URLSearchParams({ returnTo: '/admin' });
    window.location.replace(`/app?${qs.toString()}`);
  }

  function renderScreen(html, centered = false) {
    const root = document.getElementById('admin-root');
    if (!root) return;
    root.innerHTML = `<div class="admin-screen${centered ? ' centered' : ''}">${html}</div>`;
  }

  function renderLoading() {
    renderScreen(`
      <div class="admin-card">
        <h1>Loading Admin Console</h1>
        <p>Checking your session and permissions.</p>
      </div>
    `, true);
  }

  function renderForbidden() {
    renderScreen(`
      <div class="admin-card">
        <h1>403 Access Denied</h1>
        <p>Your account is signed in but does not have admin access.</p>
        <div style="display:flex;gap:8px;flex-wrap:wrap">
          <a class="btn btn-action" href="/app/home">Go to App</a>
          <button class="btn btn-secondary" id="btn-signout-forbidden">Sign Out</button>
        </div>
      </div>
    `, true);

    const btn = document.getElementById('btn-signout-forbidden');
    if (btn) {
      btn.onclick = async () => {
        try { await window.fb.signOut(window.fb.auth); } catch (_) {}
        redirectToAppLogin();
      };
    }
  }

  function checkAdminAccess(user, profile) {
    const email = String(user?.email || '').toLowerCase();
    return ADMIN_ALLOWLIST.includes(email) || !!profile?.isAdmin;
  }

  async function loadCurrentUserProfile(uid) {
    try {
      const snap = await window.fb.get(window.fb.ref(window.fb.database, `users/${uid}/profile`));
      return snap.exists() ? (snap.val() || {}) : {};
    } catch {
      return {};
    }
  }

  function normalizeUserRow(uid, data) {
    const row = data || {};
    const tierRaw = String(row.tier || 'free').toLowerCase();
    const tier = PLAN_ORDER.includes(tierRaw) ? tierRaw : 'free';
    const creditTotalRaw = Number(row.creditTotal ?? row.total);
    const creditUsedRaw = Number(row.creditUsed ?? row.used);
    return {
      uid: row.uid || uid,
      email: String(row.email || ''),
      name: String(row.name || row.displayName || row.email || 'Unknown User'),
      isAdmin: !!row.isAdmin,
      tier,
      customTag: String(row.customTag || ''),
      adminTag: String(row.adminTag || ''),
      creditTotal: Number.isFinite(creditTotalRaw) ? creditTotalRaw : Number(PLAN_CREDITS[tier] || 5000),
      creditUsed: Number.isFinite(creditUsedRaw) ? creditUsedRaw : 0,
      createdAt: row.createdAt || '',
      lastSeenAt: row.lastSeenAt || '',
    };
  }

  function computeStats(users) {
    const now = Date.now();
    const last24h = now - (24 * 60 * 60 * 1000);
    const last7d = now - (7 * 24 * 60 * 60 * 1000);
    const plans = { free: 0, lite: 0, pro: 0, advanced: 0, elite: 0 };

    let adminUsers = 0;
    let active24h = 0;
    let active7d = 0;
    let newUsers7d = 0;

    users.forEach(u => {
      const tier = PLAN_ORDER.includes(u.tier) ? u.tier : 'free';
      plans[tier] += 1;
      if (u.isAdmin) adminUsers += 1;

      const seenMs = toMs(u.lastSeenAt);
      if (seenMs >= last24h) active24h += 1;
      if (seenMs >= last7d) active7d += 1;

      const createdMs = toMs(u.createdAt);
      if (createdMs >= last7d) newUsers7d += 1;
    });

    return {
      totalUsers: users.length,
      adminUsers,
      active24h,
      active7d,
      newUsers7d,
      plans,
      computedAt: new Date().toISOString(),
      computedBy: S.user?.uid || '',
    };
  }

  async function loadOrComputeDailySnapshot() {
    const key = todayKey();
    try {
      const ref = window.fb.ref(window.fb.database, `adminStats/daily/${key}`);
      const snap = await window.fb.get(ref);
      if (snap.exists()) {
        S.snapshot = snap.val() || null;
      } else {
        S.snapshot = null;
      }
    } catch {
      S.snapshot = null;
    } finally {
      S.snapshotLoaded = true;
      await maybeWriteSnapshot();
      renderDashboard();
    }
  }

  async function maybeWriteSnapshot() {
    if (!S.snapshotLoaded || S.snapshot || S.snapshotWriting || !S.liveStats || !S.user) return;
    S.snapshotWriting = true;
    const key = todayKey();
    const payload = {
      ...S.liveStats,
      computedAt: new Date().toISOString(),
      computedBy: S.user.uid,
    };
    try {
      await window.fb.set(window.fb.ref(window.fb.database, `adminStats/daily/${key}`), payload);
      S.snapshot = payload;
    } catch {
      // no-op
    } finally {
      S.snapshotWriting = false;
    }
  }

  function subscribeUserIndex() {
    if (S.unsubs.users) {
      S.unsubs.users();
      S.unsubs.users = null;
    }
    const ref = window.fb.ref(window.fb.database, 'userIndex');
    S.unsubs.users = window.fb.onValue(ref, async snap => {
      const raw = snap.exists() ? (snap.val() || {}) : {};
      S.users = Object.entries(raw).map(([uid, value]) => normalizeUserRow(uid, value));
      S.liveStats = computeStats(S.users);
      await maybeWriteSnapshot();
      renderDashboard();
    });
  }

  function subscribeAudit() {
    if (S.unsubs.audits) {
      S.unsubs.audits();
      S.unsubs.audits = null;
    }

    const ref = window.fb.database.ref('adminAudit').limitToLast(80);
    const listener = snap => {
      const raw = snap.exists() ? (snap.val() || {}) : {};
      S.audits = Object.entries(raw)
        .map(([id, value]) => ({ id, ...(value || {}) }))
        .sort((a, b) => toMs(b.createdAt) - toMs(a.createdAt));
      renderDashboard();
    };

    ref.on('value', listener);
    S.unsubs.audits = () => ref.off('value', listener);
  }

  function getFilteredUsers() {
    let list = [...S.users];
    const q = S.filters.q.trim().toLowerCase();
    if (q) {
      list = list.filter(u =>
        String(u.name || '').toLowerCase().includes(q)
        || String(u.email || '').toLowerCase().includes(q)
      );
    }

    if (S.filters.role === 'admin') list = list.filter(u => u.isAdmin);
    if (S.filters.role === 'user') list = list.filter(u => !u.isAdmin);

    if (S.filters.plan !== 'all') list = list.filter(u => u.tier === S.filters.plan);

    if (S.filters.sort === 'name') {
      list.sort((a, b) => String(a.name).localeCompare(String(b.name)));
    } else if (S.filters.sort === 'newest') {
      list.sort((a, b) => toMs(b.createdAt) - toMs(a.createdAt));
    } else {
      list.sort((a, b) => toMs(b.lastSeenAt) - toMs(a.lastSeenAt));
    }

    return list;
  }

  function renderKpiCards(stats) {
    const cards = [
      { label: 'Total Users', value: stats.totalUsers || 0 },
      { label: 'Admin Users', value: stats.adminUsers || 0 },
      { label: 'Active 24h', value: stats.active24h || 0 },
      { label: 'Active 7d', value: stats.active7d || 0 },
      { label: 'New Users 7d', value: stats.newUsers7d || 0 },
    ];

    return cards.map(c => `
      <div class="kpi">
        <div class="kpi-label">${esc(c.label)}</div>
        <div class="kpi-value">${Number(c.value || 0).toLocaleString()}</div>
      </div>
    `).join('');
  }

  function renderPlanRows(stats) {
    return PLAN_ORDER.map(plan => `
      <div class="plan-row">
        <span class="plan-name">${esc(plan)}</span>
        <span class="plan-count">${Number(stats.plans?.[plan] || 0).toLocaleString()} users</span>
      </div>
    `).join('');
  }

  function renderAuditRows() {
    if (!S.audits.length) {
      return '<div class="empty-state">No admin activity yet.</div>';
    }

    return S.audits.slice(0, 24).map(a => {
      const actor = a.actorEmail || a.actorUid || 'unknown';
      const target = a.targetEmail || a.targetUid || 'unknown';
      return `
        <div class="audit-row">
          <div class="audit-row-title">${esc(a.action || 'action')} | ${esc(target)}</div>
          <div class="audit-row-meta">by ${esc(actor)} | ${esc(fmtDateTime(a.createdAt))}</div>
          <div class="audit-row-reason">Reason: ${esc(a.reason || '-')}</div>
        </div>
      `;
    }).join('');
  }

  function renderUserRows() {
    const rows = getFilteredUsers();
    if (!rows.length) {
      return '<tr><td colspan="8" class="empty-state">No users matched the current filters.</td></tr>';
    }

    return rows.map(user => {
      const rid = safeId(user.uid);
      const isOpen = S.openDrawerUid === user.uid;
      const tagValue = user.isAdmin ? (user.adminTag || 'Admin') : (user.customTag || '');
      const totalValue = Number(user.creditTotal || PLAN_CREDITS[user.tier] || 5000);
      return `
        <tr>
          <td>
            <div class="table-user-name">${esc(user.name)}</div>
            <div class="table-user-email">${esc(user.email || 'No email')}</div>
          </td>
          <td><code>${esc(user.uid)}</code></td>
          <td>
            <span class="pill ${user.isAdmin ? 'admin' : 'user'}">${user.isAdmin ? 'Admin' : 'User'}</span>
          </td>
          <td>
            <span class="pill">${esc(user.tier)}</span>
          </td>
          <td>${esc(fmtDateTime(user.lastSeenAt))}</td>
          <td>${esc(fmtDateTime(user.createdAt))}</td>
          <td>
            ${tagValue ? `<span class="pill tag">${esc(tagValue)}</span>` : '<span class="table-user-email">-</span>'}
          </td>
          <td class="actions-cell">
            <div class="row-actions" data-rid="${esc(rid)}" data-uid="${esc(user.uid)}" data-email="${esc(user.email || '')}" data-admin="${user.isAdmin ? '1' : '0'}">
              <div class="actions-row single">
                <button class="btn btn-secondary btn-sm" data-action="toggle">${isOpen ? 'Close Actions' : 'Manage User'}</button>
              </div>
              <div class="row-action-panel${isOpen ? ' open' : ''}">
                <div class="actions-row">
                  <button class="btn btn-secondary btn-sm" data-action="promote">Promote</button>
                  <button class="btn btn-secondary btn-sm" data-action="demote">Demote</button>
                </div>
                <div class="actions-row">
                  <input class="form-input" data-input="tag" maxlength="60" value="${esc(tagValue)}" placeholder="Tag value">
                  <button class="btn btn-secondary btn-sm" data-action="set_tag">Save Tag</button>
                </div>
                <div class="actions-row">
                  <select class="form-input" data-input="plan">
                    ${PLAN_ORDER.map(p => `<option value="${esc(p)}"${user.tier === p ? ' selected' : ''}>${esc(p)}</option>`).join('')}
                  </select>
                  <input class="form-input" data-input="total" type="number" min="1" step="1" value="${totalValue}" placeholder="Credit total">
                </div>
                <div class="actions-row">
                  <button class="btn btn-secondary btn-sm" data-action="set_plan">Set Plan</button>
                  <button class="btn btn-danger btn-sm" data-action="reset_used">Reset Used</button>
                </div>
              </div>
            </div>
          </td>
        </tr>
      `;
    }).join('');
  }

  function bindDashboardEvents() {
    const q = document.getElementById('flt-q');
    const role = document.getElementById('flt-role');
    const plan = document.getElementById('flt-plan');
    const sort = document.getElementById('flt-sort');
    const toggleThemeBtn = document.getElementById('btn-theme');
    const signOutBtn = document.getElementById('btn-signout');

    if (q) q.oninput = e => { S.filters.q = e.target.value || ''; renderDashboard(); };
    if (role) role.onchange = e => { S.filters.role = e.target.value || 'all'; renderDashboard(); };
    if (plan) plan.onchange = e => { S.filters.plan = e.target.value || 'all'; renderDashboard(); };
    if (sort) sort.onchange = e => { S.filters.sort = e.target.value || 'last_seen'; renderDashboard(); };

    if (toggleThemeBtn) toggleThemeBtn.onclick = () => {
      toggleTheme();
      renderDashboard();
    };

    if (signOutBtn) {
      signOutBtn.onclick = async () => {
        try { await window.fb.signOut(window.fb.auth); } catch (_) {}
        redirectToAppLogin();
      };
    }

    const wrap = document.getElementById('user-table-wrap');
    if (wrap) {
      wrap.onclick = e => {
        const btn = e.target.closest('button[data-action]');
        if (!btn) return;
        const drawer = btn.closest('.row-actions');
        if (!drawer) return;
        const action = btn.dataset.action;
        const uid = drawer.getAttribute('data-uid') || '';
        if (!uid) return;
        if (action === 'toggle') {
          S.openDrawerUid = S.openDrawerUid === uid ? '' : uid;
          renderDashboard();
          return;
        }

        const email = drawer.getAttribute('data-email') || '';
        const isAdmin = drawer.getAttribute('data-admin') === '1';
        const tagInput = drawer.querySelector('[data-input="tag"]');
        const planInput = drawer.querySelector('[data-input="plan"]');
        const totalInput = drawer.querySelector('[data-input="total"]');
        if (action === 'promote') return requestPromote(uid, email);
        if (action === 'demote') return requestDemote(uid, email);
        if (action === 'set_tag') return requestSetTag(uid, email, isAdmin, tagInput?.value || '');
        if (action === 'set_plan') return requestSetPlan(uid, email, planInput?.value || 'free', totalInput?.value || '');
        if (action === 'reset_used') return requestResetUsed(uid, email);
      };

      wrap.onchange = e => {
        const planSelect = e.target.closest('select[data-input="plan"]');
        if (!planSelect) return;
        const drawer = planSelect.closest('.row-actions');
        const totalInput = drawer?.querySelector('input[data-input="total"]');
        if (!totalInput) return;
        const tier = String(planSelect.value || 'free').toLowerCase();
        if (PLAN_CREDITS[tier]) totalInput.value = String(PLAN_CREDITS[tier]);
      };
    }

    if (S.pendingAction) bindModalEvents();
  }

  function renderModal() {
    const existing = document.getElementById('admin-modal');
    if (existing) existing.remove();
    if (!S.pendingAction) return;

    const modal = document.createElement('div');
    modal.id = 'admin-modal';
    modal.className = 'admin-modal';
    modal.innerHTML = `
      <div class="admin-modal-card">
        <h3>${esc(S.pendingAction.title)}</h3>
        <p>${esc(S.pendingAction.description)}</p>
        <div class="admin-modal-details">Target: <strong>${esc(S.pendingAction.targetEmail || S.pendingAction.targetUid)}</strong></div>
        <div class="form-group" style="margin-top:12px">
          <label class="form-label">Reason (required)</label>
          <textarea id="admin-reason" class="form-input" maxlength="280" rows="3" placeholder="Why are you making this change?"></textarea>
        </div>
        <div class="admin-modal-actions">
          <button class="btn btn-ghost" id="admin-cancel">Cancel</button>
          <button class="btn btn-action" id="admin-confirm">Confirm</button>
        </div>
      </div>
    `;
    modal.addEventListener('click', e => {
      if (e.target === modal) closePendingAction();
    });
    document.body.appendChild(modal);
    bindModalEvents();
  }

  function bindModalEvents() {
    const cancel = document.getElementById('admin-cancel');
    const confirm = document.getElementById('admin-confirm');
    if (cancel) cancel.onclick = () => closePendingAction();
    if (confirm) {
      confirm.onclick = async () => {
        const reasonEl = document.getElementById('admin-reason');
        const reason = String(reasonEl?.value || '').trim();
        if (!reason) {
          showToast('A reason is required before confirming.', 'error');
          return;
        }
        confirm.disabled = true;
        confirm.textContent = 'Saving...';
        try {
          await S.pendingAction.run(reason);
          closePendingAction();
          renderDashboard();
        } catch (e) {
          showToast(e.message || 'Action failed', 'error');
          confirm.disabled = false;
          confirm.textContent = 'Confirm';
        }
      };
    }
  }

  function closePendingAction() {
    S.pendingAction = null;
    const modal = document.getElementById('admin-modal');
    if (modal) modal.remove();
  }

  function renderDashboard() {
    if (!S.authorized) return;

    const stats = S.liveStats || S.snapshot || {
      totalUsers: 0,
      adminUsers: 0,
      active24h: 0,
      active7d: 0,
      newUsers7d: 0,
      plans: { free: 0, lite: 0, pro: 0, advanced: 0, elite: 0 },
      computedAt: '',
      computedBy: '',
    };

    const root = document.getElementById('admin-root');
    if (!root) return;

    root.innerHTML = `
      <div class="admin-shell">
        <header class="admin-topbar">
          <div class="admin-brand">
            <span>Axinote</span>
            <span class="admin-brand-badge">Admin</span>
          </div>
          <div class="admin-topbar-right">
            <span style="font-size:12px;color:var(--text-muted)">${esc(getDisplayName())}</span>
            <a class="btn btn-secondary btn-sm" href="/app/home">Open App</a>
            <button class="btn btn-secondary btn-sm" id="btn-theme">Theme</button>
            <button class="btn btn-danger btn-sm" id="btn-signout">Sign Out</button>
          </div>
        </header>

        <main class="admin-main">
          <div class="admin-grid">
            <section class="admin-panel">
              <h2>Operational Metrics</h2>
              <div class="kpi-row">${renderKpiCards(stats)}</div>
              <div style="margin-top:8px;font-size:12px;color:var(--text-muted)">
                ${S.snapshot
                  ? `Daily snapshot: ${esc(fmtDateTime(S.snapshot.computedAt))}`
                  : 'Daily snapshot missing. It will be created automatically.'}
              </div>
            </section>

            <div class="split-panels">
              <section class="admin-panel">
                <h2>Plan Distribution</h2>
                <div class="plan-list">${renderPlanRows(stats)}</div>
              </section>

              <section class="admin-panel">
                <h2>Recent Admin Activity</h2>
                <div class="audit-list">${renderAuditRows()}</div>
              </section>
            </div>

            <section class="admin-panel">
              <h2>User Management</h2>
              <div class="table-toolbar">
                <input id="flt-q" class="form-input" placeholder="Search name or email" value="${esc(S.filters.q)}">
                <select id="flt-role" class="form-input">
                  <option value="all"${S.filters.role === 'all' ? ' selected' : ''}>All roles</option>
                  <option value="admin"${S.filters.role === 'admin' ? ' selected' : ''}>Admins</option>
                  <option value="user"${S.filters.role === 'user' ? ' selected' : ''}>Users</option>
                </select>
                <select id="flt-plan" class="form-input">
                  <option value="all"${S.filters.plan === 'all' ? ' selected' : ''}>All plans</option>
                  ${PLAN_ORDER.map(p => `<option value="${p}"${S.filters.plan === p ? ' selected' : ''}>${p}</option>`).join('')}
                </select>
                <select id="flt-sort" class="form-input">
                  <option value="last_seen"${S.filters.sort === 'last_seen' ? ' selected' : ''}>Sort: last seen</option>
                  <option value="newest"${S.filters.sort === 'newest' ? ' selected' : ''}>Sort: newest</option>
                  <option value="name"${S.filters.sort === 'name' ? ' selected' : ''}>Sort: name</option>
                </select>
              </div>

              <div class="table-wrap" id="user-table-wrap">
                <table class="admin-table">
                  <thead>
                    <tr>
                      <th>User</th>
                      <th>UID</th>
                      <th>Role</th>
                      <th>Plan</th>
                      <th>Last Seen</th>
                      <th>Created</th>
                      <th>Tag</th>
                      <th>Actions</th>
                    </tr>
                  </thead>
                  <tbody>${renderUserRows()}</tbody>
                </table>
              </div>
            </section>
          </div>
        </main>
      </div>
    `;

    bindDashboardEvents();
    renderModal();
  }

  async function readTargetState(uid) {
    const [profileSnap, creditsSnap, indexSnap] = await Promise.all([
      window.fb.get(window.fb.ref(window.fb.database, `users/${uid}/profile`)),
      window.fb.get(window.fb.ref(window.fb.database, `users/${uid}/credits`)),
      window.fb.get(window.fb.ref(window.fb.database, `userIndex/${uid}`)),
    ]);

    return {
      profile: profileSnap.exists() ? (profileSnap.val() || {}) : {},
      credits: creditsSnap.exists() ? (creditsSnap.val() || {}) : {},
      userIndex: indexSnap.exists() ? (indexSnap.val() || {}) : {},
    };
  }

  async function writeAuditRecord(action, targetUid, targetEmail, before, after, reason) {
    const now = new Date().toISOString();
    const payload = {
      actorUid: S.user.uid,
      actorEmail: S.user.email || '',
      targetUid,
      targetEmail: targetEmail || '',
      action,
      before,
      after,
      reason,
      createdAt: now,
    };

    const ref = window.fb.ref(window.fb.database, 'adminAudit');
    const auditRef = window.fb.push(ref);
    await window.fb.set(auditRef, payload);
  }

  async function applyUserMutation(opts) {
    if (!S.authorized) throw new Error('Unauthorized');
    const { uid, email, action, reason, profilePatch, creditsPatch, indexPatch } = opts;
    const before = await readTargetState(uid);

    const writes = [];
    if (profilePatch && Object.keys(profilePatch).length) {
      writes.push(window.fb.update(window.fb.ref(window.fb.database, `users/${uid}/profile`), profilePatch));
    }
    if (creditsPatch && Object.keys(creditsPatch).length) {
      writes.push(window.fb.update(window.fb.ref(window.fb.database, `users/${uid}/credits`), creditsPatch));
    }
    if (indexPatch && Object.keys(indexPatch).length) {
      writes.push(window.fb.update(window.fb.ref(window.fb.database, `userIndex/${uid}`), indexPatch));
    }

    await Promise.all(writes);
    const after = await readTargetState(uid);
    await writeAuditRecord(action, uid, email, before, after, reason);
    applyOptimisticRowPatch(uid, { profilePatch, creditsPatch, indexPatch });
  }

  function applyOptimisticRowPatch(uid, patches) {
    const idx = S.users.findIndex(u => u.uid === uid);
    if (idx < 0) return;

    const next = { ...S.users[idx] };
    const { profilePatch, creditsPatch, indexPatch } = patches || {};

    if (profilePatch && typeof profilePatch === 'object') {
      if (Object.prototype.hasOwnProperty.call(profilePatch, 'isAdmin')) next.isAdmin = !!profilePatch.isAdmin;
      if (Object.prototype.hasOwnProperty.call(profilePatch, 'adminTag')) next.adminTag = String(profilePatch.adminTag || '');
      if (Object.prototype.hasOwnProperty.call(profilePatch, 'customTag')) next.customTag = String(profilePatch.customTag || '');
      if (Object.prototype.hasOwnProperty.call(profilePatch, 'name')) next.name = String(profilePatch.name || next.name || '');
      if (Object.prototype.hasOwnProperty.call(profilePatch, 'email')) next.email = String(profilePatch.email || next.email || '');
    }

    if (creditsPatch && typeof creditsPatch === 'object') {
      if (Object.prototype.hasOwnProperty.call(creditsPatch, 'tier')) {
        const tierRaw = String(creditsPatch.tier || '').toLowerCase();
        if (PLAN_ORDER.includes(tierRaw)) next.tier = tierRaw;
      }
      if (Object.prototype.hasOwnProperty.call(creditsPatch, 'total')) {
        const total = Number(creditsPatch.total);
        if (Number.isFinite(total) && total > 0) next.creditTotal = total;
      }
      if (Object.prototype.hasOwnProperty.call(creditsPatch, 'used')) {
        const used = Number(creditsPatch.used);
        next.creditUsed = Number.isFinite(used) && used >= 0 ? used : 0;
      }
    }

    if (indexPatch && typeof indexPatch === 'object') {
      if (Object.prototype.hasOwnProperty.call(indexPatch, 'isAdmin')) next.isAdmin = !!indexPatch.isAdmin;
      if (Object.prototype.hasOwnProperty.call(indexPatch, 'tier')) {
        const tierRaw = String(indexPatch.tier || '').toLowerCase();
        if (PLAN_ORDER.includes(tierRaw)) next.tier = tierRaw;
      }
      if (Object.prototype.hasOwnProperty.call(indexPatch, 'name')) next.name = String(indexPatch.name || next.name || '');
      if (Object.prototype.hasOwnProperty.call(indexPatch, 'email')) next.email = String(indexPatch.email || next.email || '');
      if (Object.prototype.hasOwnProperty.call(indexPatch, 'adminTag')) next.adminTag = String(indexPatch.adminTag || '');
      if (Object.prototype.hasOwnProperty.call(indexPatch, 'customTag')) next.customTag = String(indexPatch.customTag || '');
      if (Object.prototype.hasOwnProperty.call(indexPatch, 'creditTotal')) {
        const total = Number(indexPatch.creditTotal);
        if (Number.isFinite(total) && total > 0) next.creditTotal = total;
      }
      if (Object.prototype.hasOwnProperty.call(indexPatch, 'creditUsed')) {
        const used = Number(indexPatch.creditUsed);
        next.creditUsed = Number.isFinite(used) && used >= 0 ? used : 0;
      }
    }

    S.users[idx] = next;
    S.liveStats = computeStats(S.users);
    maybeWriteSnapshot().catch(() => {});
  }

  function queueAction(config) {
    S.pendingAction = config;
    renderModal();
  }

  function requestPromote(uid, email) {
    queueAction({
      title: 'Promote to Admin',
      description: 'This grants admin access and sets the Elite plan override.',
      targetUid: uid,
      targetEmail: email,
      run: async reason => {
        await applyUserMutation({
          uid,
          email,
          action: 'promote_admin',
          reason,
          profilePatch: { isAdmin: true, adminTag: 'Admin' },
          creditsPatch: { tier: 'elite', total: PLAN_CREDITS.elite, used: 0, adminOverride: true },
          indexPatch: { isAdmin: true, tier: 'elite', adminTag: 'Admin', creditTotal: PLAN_CREDITS.elite, creditUsed: 0 },
        });
        showToast(`Promoted ${email || uid} to admin.`);
      }
    });
  }

  function requestDemote(uid, email) {
    queueAction({
      title: 'Demote Admin',
      description: 'This removes admin access and clears admin tag/override.',
      targetUid: uid,
      targetEmail: email,
      run: async reason => {
        await applyUserMutation({
          uid,
          email,
          action: 'demote_admin',
          reason,
          profilePatch: { isAdmin: false, adminTag: '' },
          creditsPatch: { tier: 'free', total: PLAN_CREDITS.free, used: 0, adminOverride: false },
          indexPatch: { isAdmin: false, tier: 'free', adminTag: '', creditTotal: PLAN_CREDITS.free, creditUsed: 0 },
        });
        showToast(`Demoted ${email || uid}.`);
      }
    });
  }

  function requestSetTag(uid, email, isAdmin, tagRaw) {
    const tag = String(tagRaw || '').trim();
    const patch = isAdmin ? { adminTag: tag } : { customTag: tag };

    queueAction({
      title: isAdmin ? 'Update Admin Tag' : 'Update User Tag',
      description: tag
        ? 'This changes the visible tag on the target profile.'
        : 'This clears the current tag from the target profile.',
      targetUid: uid,
      targetEmail: email,
      run: async reason => {
        await applyUserMutation({
          uid,
          email,
          action: 'set_tag',
          reason,
          profilePatch: patch,
          creditsPatch: null,
          indexPatch: patch,
        });
        showToast(`Tag updated for ${email || uid}.`);
      }
    });
  }

  function requestSetPlan(uid, email, tierRaw, totalRaw) {
    const tier = String(tierRaw || '').toLowerCase();
    if (!PLAN_ORDER.includes(tier)) {
      showToast('Invalid plan tier.', 'error');
      return;
    }

    const total = Number(totalRaw);
    if (!Number.isFinite(total) || total <= 0) {
      showToast('Credit total must be a positive number.', 'error');
      return;
    }

    queueAction({
      title: 'Set Plan and Credit Total',
      description: `This sets plan to ${tier} and total credits to ${total.toLocaleString()}.`,
      targetUid: uid,
      targetEmail: email,
      run: async reason => {
        const before = await readTargetState(uid);
        const used = Number(before.credits?.used || 0);
        const nextUsed = Math.min(used, total);
        await applyUserMutation({
          uid,
          email,
          action: 'set_plan',
          reason,
          profilePatch: null,
          creditsPatch: { tier, total, used: nextUsed, adminOverride: tier === 'elite' },
          indexPatch: { tier, creditTotal: total, creditUsed: nextUsed },
        });
        showToast(`Plan updated for ${email || uid}.`);
      }
    });
  }

  function requestResetUsed(uid, email) {
    queueAction({
      title: 'Reset Used Credits',
      description: 'This sets used credits to 0 for the target account.',
      targetUid: uid,
      targetEmail: email,
      run: async reason => {
        await applyUserMutation({
          uid,
          email,
          action: 'reset_credits',
          reason,
          profilePatch: null,
          creditsPatch: { used: 0 },
          indexPatch: { creditUsed: 0 },
        });
        showToast(`Used credits reset for ${email || uid}.`);
      }
    });
  }

  function cleanupSubscriptions() {
    if (S.unsubs.users) {
      S.unsubs.users();
      S.unsubs.users = null;
    }
    if (S.unsubs.audits) {
      S.unsubs.audits();
      S.unsubs.audits = null;
    }
  }

  async function handleAuthChange(user) {
    cleanupSubscriptions();
    closePendingAction();

    if (!user) {
      redirectToAppLogin();
      return;
    }

    S.user = user;
    S.profile = await loadCurrentUserProfile(user.uid);
    S.authorized = checkAdminAccess(user, S.profile);

    if (!S.authorized) {
      renderForbidden();
      return;
    }

    renderDashboard();
    subscribeUserIndex();
    subscribeAudit();
    await loadOrComputeDailySnapshot();
  }

  function init() {
    document.documentElement.setAttribute('data-theme', getPreferredTheme());
    renderLoading();

    const poll = setInterval(() => {
      if (!window.fb) return;
      clearInterval(poll);
      window.fb.onAuthStateChanged(window.fb.auth, handleAuthChange);
    }, 60);
  }

  window.addEventListener('DOMContentLoaded', init);
})();
