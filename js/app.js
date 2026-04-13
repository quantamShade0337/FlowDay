'use strict';

// ═══════════════════════════════════════════════════════════════
// FLOWDAY SECURITY LAYER
// ═══════════════════════════════════════════════════════════════
(function () {
  const w = '%c\u26a0 Axinote Security Notice %c\n\nThis is a private workspace. If someone told you to paste code here, this is a social engineering attack. Close this tab immediately.';
  console.log(w, 'background:#c00;color:#fff;font-size:16px;padding:4px 8px;border-radius:4px;font-weight:bold;', 'color:inherit;font-size:13px');
})();

function esc(s) {
  if (s === null || s === undefined) return '';
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#x27;').replace(/`/g, '&#x60;');
}

function sanitizeUrl(url) {
  if (!url) return '';
  const s = String(url).trim();
  if (/^https?:\/\//i.test(s)) return s;
  if (/^data:(image\/(png|jpeg|jpg|gif|webp|svg\+xml)|application\/pdf);base64,/i.test(s)) return s;
  console.warn('[Security] Blocked unsafe URL');
  return '';
}

const ALLOWED_RICH_TAGS = new Set(['B', 'STRONG', 'I', 'EM', 'U', 'S', 'STRIKE', 'BR', 'MARK', 'A', 'CODE']);
const ALLOWED_RICH_ATTRS = new Set(['href', 'target', 'rel']);

function sanitizeEditableHtml(html) {
  const tpl = document.createElement('template');
  tpl.innerHTML = String(html || '');
  const walk = node => {
    if (node.nodeType === Node.TEXT_NODE) return;
    if (node.nodeType !== Node.ELEMENT_NODE) {
      node.parentNode?.removeChild(node);
      return;
    }
    const tag = node.tagName.toUpperCase();
    if (!ALLOWED_RICH_TAGS.has(tag)) {
      const parent = node.parentNode;
      if (!parent) return;
      while (node.firstChild) parent.insertBefore(node.firstChild, node);
      parent.removeChild(node);
      return;
    }
    Array.from(node.attributes).forEach(attr => {
      const name = attr.name.toLowerCase();
      if (!ALLOWED_RICH_ATTRS.has(name)) node.removeAttribute(attr.name);
    });
    if (tag === 'A') {
      const safeHref = sanitizeUrl(node.getAttribute('href') || '');
      if (!safeHref || !/^https?:\/\//i.test(safeHref)) {
        const parent = node.parentNode;
        if (parent) {
          while (node.firstChild) parent.insertBefore(node.firstChild, node);
          parent.removeChild(node);
        }
        return;
      }
      node.setAttribute('href', safeHref);
      node.setAttribute('target', '_blank');
      node.setAttribute('rel', 'noopener noreferrer');
    }
    Array.from(node.childNodes).forEach(walk);
  };
  Array.from(tpl.content.childNodes).forEach(walk);
  return tpl.innerHTML;
}

function renderSafeEditableHtml(html) {
  return sanitizeEditableHtml(html || '');
}

const LIMITS = { title: 200, name: 100, bio: 500, description: 1000, content: 50000, email: 254, tag: 40, colName: 80, cellValue: 2000, noteContent: 100000 };

function validateStr(s, maxLen, fallback = '') {
  if (s === null || s === undefined) return fallback;
  const str = String(s).trim();
  return str.length > maxLen ? str.slice(0, maxLen) : str;
}

const RateLimit = {
  _key: 'fd_rl_v1',
  _get() { try { return JSON.parse(localStorage.getItem(this._key) || '{}'); } catch { return {}; } },
  _set(d) { try { localStorage.setItem(this._key, JSON.stringify(d)); } catch { } },
  _norm(e) { return (e || '').toLowerCase().trim(); },
  check(email) {
    const k = this._norm(email), d = this._get(), rec = d[k] || { count: 0, lockUntil: 0 };
    if (Date.now() < rec.lockUntil) {
      const s = Math.ceil((rec.lockUntil - Date.now()) / 1000), m = Math.ceil(s / 60);
      return { allowed: false, message: `Too many failed attempts. Try again in ${m > 1 ? m + ' minutes' : s + ' seconds'}.` };
    }
    return { allowed: true };
  },
  recordFailure(email) {
    const k = this._norm(email), d = this._get(), rec = d[k] || { count: 0, lockUntil: 0 };
    rec.count++;
    if (rec.count >= 20) rec.lockUntil = Date.now() + 24 * 3600000;
    else if (rec.count >= 15) rec.lockUntil = Date.now() + 3600000;
    else if (rec.count >= 10) rec.lockUntil = Date.now() + 900000;
    else if (rec.count >= 5) rec.lockUntil = Date.now() + 60000;
    d[k] = rec; this._set(d);
  },
  recordSuccess(email) { const k = this._norm(email), d = this._get(); delete d[k]; this._set(d); },
  remaining(email) { return Math.max(0, 5 - (this._get()[this._norm(email)] || { count: 0 }).count); }
};

function checkPasswordStrength(pass) {
  const checks = [
    { test: p => p.length >= 8, label: '8+ characters' },
    { test: p => /[A-Z]/.test(p), label: 'uppercase letter' },
    { test: p => /[a-z]/.test(p), label: 'lowercase letter' },
    { test: p => /[0-9]/.test(p), label: 'number' },
    { test: p => /[^A-Za-z0-9]/.test(p), label: 'special character' },
  ];
  const passed = checks.filter(c => c.test(pass));
  const score = passed.length;
  const strength = score < 2 ? 'Weak' : score < 4 ? 'Fair' : score < 5 ? 'Strong' : 'Very Strong';
  const color = score < 2 ? 'var(--red)' : score < 4 ? 'var(--orange)' : score < 5 ? 'var(--green)' : 'var(--accent)';
  return { score, strength, color, missing: checks.filter(c => !c.test(pass)).map(c => c.label) };
}

function renderStrengthMeter(pass) {
  if (!pass) return '';
  const { score, strength, color, missing } = checkPasswordStrength(pass);
  const bars = Array.from({ length: 5 }, (_, i) =>
    `<div style="flex:1;height:4px;border-radius:2px;background:${i < score ? color : 'var(--border-mid)'};transition:background .2s"></div>`
  ).join('');
  const tip = missing.length ? 'Missing: ' + missing.join(', ') : 'Strong password!';
  return `<div style="margin-top:6px"><div style="display:flex;gap:3px;margin-bottom:4px">${bars}</div><div style="font-size:11.5px;color:${color};font-weight:600">${strength}</div><div style="font-size:11px;color:var(--text-faint);margin-top:1px">${tip}</div></div>`;
}

function updateStrengthMeter(pass) { const e = document.getElementById('strength-meter'); if (e) e.innerHTML = renderStrengthMeter(pass); }

const Session = {
  TIMEOUT_MS: 2 * 60 * 60 * 1000, WARN_MS: (2 * 60 - 5) * 60 * 1000,
  _last: Date.now(), _warned: false, _iv: null,
  touch() { this._last = Date.now(); this._warned = false; document.getElementById('session-warn')?.remove(); },
  start() {
    this._last = Date.now();
    ['mousemove', 'keydown', 'click', 'touchstart'].forEach(ev => document.addEventListener(ev, () => this.touch(), { passive: true }));
    this._iv = setInterval(() => this._check(), 60000);
  },
  stop() { clearInterval(this._iv); document.getElementById('session-warn')?.remove(); },
  _check() {
    if (!S.user) return;
    const idle = Date.now() - this._last;
    if (idle >= this.TIMEOUT_MS) { this.stop(); toast('Signed out due to inactivity.'); doLogout(); }
    else if (idle >= this.WARN_MS && !this._warned) {
      this._warned = true;
      document.getElementById('session-warn')?.remove();
      const w = document.createElement('div'); w.className = 'session-warn'; w.id = 'session-warn';
      w.innerHTML = '<div class="session-warn-inner"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg><span>You\'ll be signed out in 5 minutes due to inactivity.</span><button class="btn btn-ghost btn-sm" onclick="Session.touch()" style="padding:3px 10px;flex-shrink:0">Stay signed in</button></div>';
      document.body.appendChild(w);
    }
  }
};


const FOUNDER_EMAIL = 'ethan.sohyt@gmail.com';
const BOOTSTRAP_ADMIN_EMAILS = ['me@adamzafir.com'];
const ADMIN_ALLOWLIST = Array.from(new Set([FOUNDER_EMAIL, ...BOOTSTRAP_ADMIN_EMAILS].map(e => String(e).toLowerCase())));
function canAccessAdminPath(profile = S.userProfile) {
  const email = String(S.user?.email || '').toLowerCase();
  return ADMIN_ALLOWLIST.includes(email) || !!profile?.isAdmin;
}
// isAdmin checks local state (loaded from Firebase) AND founder
function isAdvancedUser() {
  if (isAdmin()) return true;
  const tier = (S.aiCredits?.tier || 'free');
  return tier === 'advanced' || tier === 'elite' || tier === 'pro';
}

const isBootstrapAdmin = () => {
  const email = String(S.user?.email || '').toLowerCase();
  return BOOTSTRAP_ADMIN_EMAILS.includes(email);
};

const isAdmin = () => {
  if (!S.user) return false;
  if (String(S.user.email || '').toLowerCase() === FOUNDER_EMAIL) return true;
  if (isBootstrapAdmin()) return true;
  return !!(S.userProfile?.isAdmin);
};
const isFounder = () => String(S.user?.email || '').toLowerCase() === FOUNDER_EMAIL;

async function ensureFounderAdmin() {
  return;
}
function getAdminTag() {
  if (isFounder()) {
    return S.userProfile?.adminTag || 'Creator & Founder of Axinote';
  }
  return S.userProfile?.adminTag || 'Admin';
}

async function ensureBootstrapAdmin() {
  return;
}
// Only users whose admin tag is exactly "AAdmin" (or the founder) can promote others to admin
const canPromoteAdmins = () => {
  if (!isAdmin()) return false;
  if (isFounder()) return true;
  return getAdminTag() === 'AAdmin';
};
function getGroupMembers(group) {
  const raw = group?.members || {};
  if (Array.isArray(raw)) return raw.filter(Boolean);
  return Object.entries(raw)
    .filter(([uid]) => !String(uid).startsWith('_'))
    .map(([uid, member]) => ({ ...(member || {}), uid: member?.uid || uid }));
}
function groupMemberCount(group) { return getGroupMembers(group).length; }
function isGroupMember(group, uid) { return !!getGroupMembers(group).find(m => m.uid === uid); }


// ─── STATE ───────────────────────────────────────────────────
const S = {
  user: null, userProfile: null,
  view: 'home', page: null,
  pages: [], databases: [], tasks: [], calendar: [], flashcards: [],
  sidebarOpen: true,
  sidebarMode: 'expanded', // expanded | rail
  sidebarDrawerOpen: false, // mobile drawer
  _navStack: [],
  calView: 'month', calDate: new Date(),
  _sbCol: { pages: true, databases: true }, notifications: [],
  taskView: 'list',
  deck: null, cardIdx: 0, flipped: false, studyScore: { ok: 0, miss: 0 },
  pom: { on: false, mode: 'work', secs: 25 * 60, total: 25 * 60, sess: 0, iv: null, vis: false },
  evColor: 'red', editEvId: null,
  slashActive: false, slashBlockId: null, _saveTimer: null,
  activeCollabNote: null, collabListener: null, presenceListener: null,
  studySessions: 0, studyMinutes: 0, pomStartTime: null,
  // New
  showForm: null,
  studyGroups: [],
  pendingDeleteId: null,
  calSelectedDay: null,
  dbSort: null,
  dbFilter: '',
  dbView: 'table',
  // Phase 1 additions
  projects: [],
  saveStatus: '', // 'saving' | 'saved' | ''
  _saveIndicatorTimer: null,
  onboardingStep: 0, // 0 = not started, 1-3 = steps, 4 = done
  _offlineQueue: [],
  // AI Credits
  aiCredits: null, // loaded from Firebase
  aiCreditListener: null,
  userIndexHeartbeatIv: null,
  groupMembershipListener: null,
  groupRealtimeListeners: {},
  eliteBenchListener: null,
  eliteGroupBenchmark: null,
  _aiRequestQueue: [], // queued AI requests
  _aiProcessing: false,
  // Mock Exams (Advanced only)
  mockExams: [],
  currentMockExam: null,
  // Spotify
  spotifyToken: null,
  spotifyPlayer: null,
  spotifyCurrentTrack: null,
  spotifyPlaying: false,
  homeInsightsOpen: false,
  _shellEventsBound: false,
};

const SHELL_PREF_MODE_KEY = 'fd_sidebar_mode';
const SHELL_PREF_SECTIONS_KEY = 'fd_sidebar_sections';

function isMobileShell() {
  return window.innerWidth <= 980;
}

function loadShellPrefs() {
  try {
    const mode = localStorage.getItem(SHELL_PREF_MODE_KEY);
    if (mode === 'expanded' || mode === 'rail') S.sidebarMode = mode;
  } catch (_) { }
  try {
    const raw = localStorage.getItem(SHELL_PREF_SECTIONS_KEY);
    const parsed = raw ? JSON.parse(raw) : null;
    if (parsed && typeof parsed === 'object') {
      S._sbCol = {
        ...S._sbCol,
        pages: !!parsed.pages,
        databases: !!parsed.databases,
      };
    }
  } catch (_) { }
}

function persistSidebarMode() {
  try { localStorage.setItem(SHELL_PREF_MODE_KEY, S.sidebarMode); } catch (_) { }
}

function persistSidebarSections() {
  try {
    localStorage.setItem(SHELL_PREF_SECTIONS_KEY, JSON.stringify({
      pages: !!S._sbCol.pages,
      databases: !!S._sbCol.databases,
    }));
  } catch (_) { }
}

function closeSidebarDrawer() {
  if (!S.sidebarDrawerOpen) return;
  S.sidebarDrawerOpen = false;
}

function closeSidebarAfterNavigate() {
  if (isMobileShell()) S.sidebarDrawerOpen = false;
}

loadShellPrefs();

const APP_ROUTE_BASE = '/app';

function _normPath(path) {
  const p = String(path || '/').replace(/\/{2,}/g, '/');
  if (p.length > 1 && p.endsWith('/')) return p.slice(0, -1);
  return p || '/';
}

function _encSeg(v) { return encodeURIComponent(String(v || '').trim()); }
function _decSeg(v) { try { return decodeURIComponent(v); } catch (_) { return v; } }

function getRoutePathFromState() {
  const view = S.view || 'home';
  if (view === 'page') {
    if (S.page?.id) return `${APP_ROUTE_BASE}/notes/${_encSeg(S.page.id)}`;
    if (S.deck?.id) return `${APP_ROUTE_BASE}/flashcards/deck/${_encSeg(S.deck.id)}`;
    return `${APP_ROUTE_BASE}/home`;
  }
  if (view === 'database') return S.page?.id ? `${APP_ROUTE_BASE}/databases/${_encSeg(S.page.id)}` : `${APP_ROUTE_BASE}/home`;
  if (view === 'study') return S.deck?.id ? `${APP_ROUTE_BASE}/flashcards/study/${_encSeg(S.deck.id)}` : `${APP_ROUTE_BASE}/flashcards`;
  if (view === 'collabNote') return S.activeCollabNote ? `${APP_ROUTE_BASE}/collab/${_encSeg(S.activeCollabNote)}` : `${APP_ROUTE_BASE}/collab`;
  if (view === 'studyGroup') return S._currentGroupId ? `${APP_ROUTE_BASE}/groups/${_encSeg(S._currentGroupId)}` : `${APP_ROUTE_BASE}/groups`;
  if (view === 'projectDetail') return S.currentProject?.id ? `${APP_ROUTE_BASE}/projects/${_encSeg(S.currentProject.id)}` : `${APP_ROUTE_BASE}/projects`;

  const staticPaths = {
    home: `${APP_ROUTE_BASE}/home`,
    calendar: `${APP_ROUTE_BASE}/calendar`,
    tasks: `${APP_ROUTE_BASE}/tasks`,
    dailyTasks: `${APP_ROUTE_BASE}/tasks/today`,
    flashcards: `${APP_ROUTE_BASE}/flashcards`,
    projects: `${APP_ROUTE_BASE}/projects`,
    examSuite: `${APP_ROUTE_BASE}/exam-advantage`,
    mockExam: `${APP_ROUTE_BASE}/mock-exams`,
    collab: `${APP_ROUTE_BASE}/collab`,
    groups: `${APP_ROUTE_BASE}/groups`,
    profile: `${APP_ROUTE_BASE}/settings`,
    settings: `${APP_ROUTE_BASE}/settings`,
    aiDashboard: `${APP_ROUTE_BASE}/ai-dashboard`,
    aiChat: `${APP_ROUTE_BASE}/ai-chat`,
    privacy: `${APP_ROUTE_BASE}/privacy`,
    changelog: `${APP_ROUTE_BASE}/changelog`,
  };
  return staticPaths[view] || `${APP_ROUTE_BASE}/home`;
}

function syncRouteWithState(opts = {}) {
  const { push = false, replace = false } = opts;
  const nextPath = _normPath(getRoutePathFromState());
  const curPath = _normPath(window.location.pathname);
  if (nextPath === curPath) return;
  const method = (replace || !push) ? 'replaceState' : 'pushState';
  if (method === 'pushState' && curPath.startsWith(APP_ROUTE_BASE)) {
    if (S._navStack[S._navStack.length - 1] !== curPath) {
      S._navStack.push(curPath);
      if (S._navStack.length > 140) S._navStack.shift();
    }
  }
  history[method]({ flowday: true, path: nextPath }, '', nextPath + window.location.search);
}

function parseRouteFromPath(pathname = window.location.pathname) {
  const path = _normPath(pathname);
  if (path === '/app' || path === '/app.html' || path === '/app/index.html') return { kind: 'view', view: 'home' };
  if (!path.startsWith('/app/')) return null;

  const seg = path.slice(5).split('/').filter(Boolean).map(_decSeg);
  if (!seg.length) return { kind: 'view', view: 'home' };

  if (seg[0] === 'home') return { kind: 'view', view: 'home' };
  if (seg[0] === 'calendar') return { kind: 'view', view: 'calendar' };
  if (seg[0] === 'tasks' && seg[1] === 'today') return { kind: 'view', view: 'dailyTasks' };
  if (seg[0] === 'tasks') return { kind: 'view', view: 'tasks' };
  if (seg[0] === 'flashcards' && seg[1] === 'study' && seg[2]) return { kind: 'studyDeck', id: seg[2] };
  if (seg[0] === 'flashcards' && seg[1] === 'deck' && seg[2]) return { kind: 'flashDeck', id: seg[2] };
  if (seg[0] === 'flashcards') return { kind: 'view', view: 'flashcards' };
  if (seg[0] === 'notes' && seg[1]) return { kind: 'page', id: seg[1] };
  if (seg[0] === 'databases' && seg[1]) return { kind: 'database', id: seg[1] };
  if (seg[0] === 'projects' && seg[1]) return { kind: 'project', id: seg[1] };
  if (seg[0] === 'projects') return { kind: 'view', view: 'projects' };
  if (seg[0] === 'exam-advantage') return { kind: 'view', view: 'examSuite' };
  if (seg[0] === 'mock-exams') return { kind: 'view', view: 'mockExam' };
  if (seg[0] === 'collab' && seg[1]) return { kind: 'collabNote', id: seg[1] };
  if (seg[0] === 'collab') return { kind: 'view', view: 'collab' };
  if (seg[0] === 'groups' && seg[1]) return { kind: 'studyGroup', id: seg[1] };
  if (seg[0] === 'groups') return { kind: 'view', view: 'groups' };
  if (seg[0] === 'settings') return { kind: 'view', view: 'profile' };
  if (seg[0] === 'ai-dashboard') return { kind: 'view', view: 'aiDashboard' };
  if (seg[0] === 'ai-chat') return { kind: 'view', view: 'aiChat' };
  if (seg[0] === 'privacy') return { kind: 'view', view: 'privacy' };
  if (seg[0] === 'changelog') return { kind: 'view', view: 'changelog' };
  return { kind: 'view', view: 'home' };
}

function applyParsedRoute(route, opts = {}) {
  const { replaceHistory = false, pushHistory = false } = opts;
  if (route.kind === 'view') {
    navigate(route.view, { pushHistory, replaceHistory });
    return true;
  }
  if (route.kind === 'page') {
    if (S.pages.some(p => p.id === route.id)) { openPage(route.id, { pushHistory, replaceHistory }); return true; }
    navigate('home', { pushHistory: false, replaceHistory: true });
    return false;
  }
  if (route.kind === 'database') {
    if (S.databases.some(d => d.id === route.id)) { openDatabase(route.id, { pushHistory, replaceHistory }); return true; }
    navigate('home', { pushHistory: false, replaceHistory: true });
    return false;
  }
  if (route.kind === 'project') {
    if (S.projects.some(p => p.id === route.id)) { openProject(route.id, { pushHistory, replaceHistory }); return true; }
    navigate('projects', { pushHistory: false, replaceHistory: true });
    return false;
  }
  if (route.kind === 'studyGroup') {
    openStudyGroup(route.id, { pushHistory, replaceHistory });
    return true;
  }
  if (route.kind === 'collabNote') {
    openCollabNote(route.id, { pushHistory, replaceHistory });
    return true;
  }
  if (route.kind === 'flashDeck') {
    if (S.flashcards.some(d => d.id === route.id)) { openDeckEditor(route.id, { pushHistory, replaceHistory }); return true; }
    navigate('flashcards', { pushHistory: false, replaceHistory: true });
    return false;
  }
  if (route.kind === 'studyDeck') {
    if (S.flashcards.some(d => d.id === route.id)) { startStudy(route.id, { pushHistory, replaceHistory }); return true; }
    navigate('flashcards', { pushHistory: false, replaceHistory: true });
    return false;
  }

  navigate('home', { pushHistory: false, replaceHistory: true });
  return false;
}

function applyRouteFromLocation(opts = {}) {
  const route = parseRouteFromPath();
  if (!route) return false;
  return applyParsedRoute(route, opts);
}

function applyRouteFromPath(pathname, opts = {}) {
  const route = parseRouteFromPath(pathname);
  if (!route) return false;
  return applyParsedRoute(route, opts);
}

function getPostLoginReturnTo() {
  const p = new URLSearchParams(window.location.search || '');
  const raw = p.get('returnTo');
  if (!raw) return '';
  if (!raw.startsWith('/admin')) return '';
  if (raw.startsWith('//')) return '';
  return raw;
}

function clearPostLoginReturnTo() {
  const p = new URLSearchParams(window.location.search || '');
  if (!p.has('returnTo')) return;
  p.delete('returnTo');
  const qs = p.toString();
  history.replaceState(null, '', window.location.pathname + (qs ? `?${qs}` : ''));
}

async function maybeRedirectToPostLoginPath() {
  const target = getPostLoginReturnTo();
  if (!target || !S.user) return false;
  const allowed = canAccessAdminPath();
  if (!allowed) {
    clearPostLoginReturnTo();
    return false;
  }
  window.location.assign(target);
  return true;
}

async function syncUserIndexHeartbeat() {
  if (!S.user) return;
  const email = String(S.user.email || '').toLowerCase();
  const createdAt = S.user?.metadata?.creationTime ? new Date(S.user.metadata.creationTime).toISOString() : null;
  const payload = {
    uid: S.user.uid,
    email,
    name: getDisplayName(),
    displayName: getDisplayName(),
    tier: getCurrentTier(),
    lastSeenAt: new Date().toISOString(),
  };
  if (createdAt) payload.createdAt = createdAt;
  try {
    await window.fb.update(window.fb.ref(window.fb.database, `userIndex/${S.user.uid}`), payload);
  } catch (e) {
    // userIndex writes should never block app usage
  }
}

function startUserIndexHeartbeat() {
  if (S.userIndexHeartbeatIv) clearInterval(S.userIndexHeartbeatIv);
  if (!S.user) return;
  syncUserIndexHeartbeat();
  S.userIndexHeartbeatIv = setInterval(() => {
    if (!S.user) {
      if (S.userIndexHeartbeatIv) clearInterval(S.userIndexHeartbeatIv);
      S.userIndexHeartbeatIv = null;
      return;
    }
    syncUserIndexHeartbeat();
  }, 5 * 60 * 1000);
}

// ═══════════════════════════════════════════════════════════════
// OFFLINE-FIRST LOCAL CACHE
// ═══════════════════════════════════════════════════════════════
const LocalCache = {
  _key: 'fd_cache_v1',
  save(uid) {
    if (!uid) return;
    try {
      const data = { pages: S.pages, tasks: S.tasks, calendar: S.calendar, flashcards: S.flashcards, projects: S.projects, ts: Date.now() };
      localStorage.setItem(this._key + '_' + uid, JSON.stringify(data));
    } catch (e) { console.warn('[Cache] save failed:', e); }
  },
  load(uid) {
    if (!uid) return false;
    try {
      const raw = localStorage.getItem(this._key + '_' + uid);
      if (!raw) return false;
      const data = JSON.parse(raw);
      if (data.pages) S.pages = data.pages;
      if (data.tasks) S.tasks = data.tasks;
      if (data.calendar) S.calendar = data.calendar;
      if (data.flashcards) S.flashcards = data.flashcards;
      if (data.projects) S.projects = data.projects;
      if (data.mockExams) S.mockExams = data.mockExams;
      return true;
    } catch (e) { return false; }
  },
  clear(uid) { try { localStorage.removeItem(this._key + '_' + uid); } catch (e) { } }
};

// ═══════════════════════════════════════════════════════════════
// UNDO / REDO MANAGER (per-page block history)
// ═══════════════════════════════════════════════════════════════
const UndoMgr = {
  _history: {},  // pageId -> [{blocks snapshot}]
  _pos: {},      // pageId -> current position
  _MAX: 100,
  snapshot(pageId, blocks) {
    if (!pageId || !blocks) return;
    if (!this._history[pageId]) { this._history[pageId] = []; this._pos[pageId] = -1; }
    const snap = JSON.stringify(blocks);
    const hist = this._history[pageId];
    // Don't push if identical to current
    if (hist.length && hist[this._pos[pageId]] === snap) return;
    // Truncate any redo history
    this._pos[pageId]++;
    hist.splice(this._pos[pageId], Infinity, snap);
    if (hist.length > this._MAX) { hist.shift(); this._pos[pageId]--; }
  },
  undo(pageId) {
    if (!this._history[pageId] || this._pos[pageId] <= 0) return null;
    this._pos[pageId]--;
    return JSON.parse(this._history[pageId][this._pos[pageId]]);
  },
  redo(pageId) {
    const hist = this._history[pageId];
    if (!hist || this._pos[pageId] >= hist.length - 1) return null;
    this._pos[pageId]++;
    return JSON.parse(hist[this._pos[pageId]]);
  },
  canUndo(pageId) { return this._pos[pageId] > 0; },
  canRedo(pageId) { const h = this._history[pageId]; return h && this._pos[pageId] < h.length - 1; }
};

// ─── UTILS ───────────────────────────────────────────────────
const $ = id => document.getElementById(id);
const uid = () => Date.now().toString(36) + Math.random().toString(36).slice(2, 6);
const el = (tag, cls, html) => { const e = document.createElement(tag); if (cls) e.className = cls; if (html !== undefined) e.innerHTML = html; return e; };

function toast(msg) {
  let wrap = document.querySelector('.toast-wrap');
  if (!wrap) { wrap = el('div', 'toast-wrap'); document.body.appendChild(wrap); }
  const t = el('div', 'toast', msg);
  wrap.appendChild(t);
  setTimeout(() => t.remove(), 3100);
}

const fmt = d => d ? new Date(d).toLocaleDateString('en-US', { month: 'short', day: 'numeric' }) : '';
const overdue = ds => ds && ds < new Date().toISOString().split('T')[0];
const greet = () => {
  const name = (getDisplayName() || 'there').trim().split(/\s+/)[0] || 'there';
  const h = new Date().getHours();
  const s = 'width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"';
  const coffee = `<svg ${s}><path d="M18 8h1a4 4 0 0 1 0 8h-1"/><path d="M2 8h16v9a4 4 0 0 1-4 4H6a4 4 0 0 1-4-4V8z"/><path d="M6 2c0 1.2-.8 2-1 3"/><path d="M10 2c0 1.2-.8 2-1 3"/><path d="M14 2c0 1.2-.8 2-1 3"/></svg>`;
  const sun = `<svg ${s}><circle cx="12" cy="12" r="4"/><path d="M12 1v3M12 20v3M4.22 4.22l2.12 2.12M17.66 17.66l2.12 2.12M1 12h3M20 12h3M4.22 19.78l2.12-2.12M17.66 6.34l2.12-2.12"/></svg>`;
  const house = `<svg ${s}><path d="M3 9.5L12 3l9 6.5V20a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1z"/><path d="M9 21V12h6v9"/><rect x="14" y="9" width="3" height="3" rx="0.5"/></svg>`;
  const moon = `<svg ${s}><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/><circle cx="19.5" cy="5.5" r="1" fill="currentColor" stroke="none"/><circle cx="17" cy="9" r="0.75" fill="currentColor" stroke="none"/><circle cx="22" cy="8.5" r="0.75" fill="currentColor" stroke="none"/></svg>`;
  if (h >= 5 && h < 12) return { phrase: `Good morning ${name}`, svg: coffee, sub: 'Based on your local time' };
  if (h >= 12 && h < 17) return { phrase: `Good afternoon ${name}`, svg: sun, sub: 'Based on your local time' };
  if (h >= 17 && h < 22) return { phrase: `Good evening ${name}`, svg: house, sub: 'Based on your local time' };
  return { phrase: `Good night ${name}`, svg: moon, sub: 'Based on your local time' };
};

// ─── FIREBASE HELPERS ────────────────────────────────────────
async function saveData(path, data) {
  if (!S.user) { console.warn('[Security] saveData without auth'); return; }
  if (!path || typeof path !== 'string') return;
  const safePath = path.replace(/\.\./g, '').replace(/^\//, '');
  try { await window.fb.update(window.fb.ref(window.fb.database, `users/${S.user.uid}/${safePath}`), data); }
  catch (e) { console.error('save:', e); }
}

async function delData(path) {
  if (!S.user) { console.warn('[Security] delData without auth'); return; }
  if (!path || typeof path !== 'string') return;
  const safePath = path.replace(/\.\./g, '').replace(/^\//, '');
  try { await window.fb.remove(window.fb.ref(window.fb.database, `users/${S.user.uid}/${safePath}`)); }
  catch (e) { console.error('del:', e); }
}

async function loadUserData(uid) {
  // Init undo for this user
  UndoMgr.init(uid);
  try {
    const snap = await window.fb.get(window.fb.ref(window.fb.database, 'users/' + uid));
    if (snap.exists()) {
      const d = snap.val();
      S.pages = Object.values(d.pages || {});
      S.databases = Object.values(d.databases || {});
      S.tasks = Object.values(d.tasks || {});
      S.calendar = Object.values(d.calendar || {});
      S.flashcards = Object.values(d.flashcards || {});
      S.projects = Object.values(d.projects || {});
      const _prof = d.profile || {};
      if (!_prof.name) _prof.name = S.user?.displayName || S.user?.email?.split('@')[0] || 'User';
      if (!_prof.description) _prof.description = 'Student';
      S.userProfile = _prof;
      S.studySessions = d.stats?.sessions || 0;
      S.studyMinutes = d.stats?.minutes || 0;
      await loadStudyGroups(d.groups ? Object.keys(d.groups) : []);
      // Save fetch to local cache
      LocalCache.save(uid);
    } else {
      // Fallback if snap doesn't exist but has cache
      LocalCache.load(uid);
    }
  } catch (e) {
    console.error('load:', e);
    // If offline or failed, fallback to cache
    LocalCache.load(uid);
  }
}

async function loadStudyGroups(groupIds) {
  S.studyGroups = [];
  const knownIds = new Set(groupIds || []);
  for (const gid of knownIds) {
    try {
      const snap = await window.fb.get(window.fb.ref(window.fb.database, `studyGroups/${gid}`));
      if (snap.exists()) S.studyGroups.push({ ...snap.val(), id: gid });
    } catch (e) { }
  }
}

function scheduleSave() {
  clearTimeout(S._saveTimer);
  // Show saving indicator
  S.saveStatus = 'saving';
  updateSaveIndicator();
  S._saveTimer = setTimeout(async () => {
    if (!S.page || !S.user) { S.saveStatus = ''; updateSaveIndicator(); return; }
    const total = (S.page.blocks || []).map(b => b.content || '').join('');
    if (total.length > LIMITS.content) { toast('Page too large (max 50k chars)'); S.saveStatus = ''; updateSaveIndicator(); return; }
    S.page.updatedAt = new Date().toISOString();

    // Convert in-line to-dos to global tasks
    (S.page.blocks || []).forEach(b => {
      if (b.type === 'todo') {
        const text = (b.content || '').replace(/<[^>]+>/g, '').trim();
        if (text) {
          // Check if task exists globally (by finding matching block ID as task id, or matching name)
          let t = S.tasks.find(x => x.id === b.id);
          if (t) {
            t.title = text;
            t.completed = !!b.completed;
            t.status = b.completed ? 'done' : 'todo';
          } else {
            // Create a new synced task
            S.tasks.push({
              id: b.id, title: text, completed: !!b.completed, status: b.completed ? 'done' : 'todo',
              due: new Date().toISOString().split('T')[0], priority: 'med', createdAt: new Date().toISOString()
            });
          }
        }
      }
    });

    // Take undo snapshot
    UndoMgr.snapshot(S.page.id, S.page.blocks);
    // Save to cache immediately
    LocalCache.save(S.user.uid);
    // Save to Firebase
    try {
      await saveData('pages', { [S.page.id]: S.page });
      // Bulk save updated tasks
      const updates = {};
      S.tasks.forEach(t => updates[t.id] = t);
      await saveData('tasks', updates);
      S.saveStatus = 'saved';
    } catch (e) {
      // Queue for retry if offline
      if (!navigator.onLine) {
        S._offlineQueue.push({ path: 'pages', data: { [S.page.id]: S.page } });
        S.saveStatus = 'offline';
      } else { S.saveStatus = ''; }
    }
    updateSaveIndicator();
    clearTimeout(S._saveIndicatorTimer);
    S._saveIndicatorTimer = setTimeout(() => { S.saveStatus = ''; updateSaveIndicator(); }, 2500);
  }, 2500);
}

function updateSaveIndicator() {
  const el = document.getElementById('save-indicator');
  if (!el) return;
  if (S.saveStatus === 'saving') {
    el.className = 'save-indicator saving';
    el.innerHTML = '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg> Saving…';
  } else if (S.saveStatus === 'saved') {
    el.className = 'save-indicator saved';
    el.innerHTML = '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg> Saved';
  } else if (S.saveStatus === 'offline') {
    el.className = 'save-indicator offline';
    el.innerHTML = '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="1" y1="1" x2="23" y2="23"/><path d="M16.72 11.06A10.94 10.94 0 0 1 19 12.55"/><path d="M5 12.55a10.94 10.94 0 0 1 5.17-2.39"/></svg> Saved offline';
  } else {
    el.className = 'save-indicator';
    el.innerHTML = '';
  }
}

// Retry offline queue when connection restores
window.addEventListener('online', async () => {
  if (!S._offlineQueue.length) return;
  const queue = [...S._offlineQueue];
  S._offlineQueue = [];
  for (const item of queue) {
    try { await saveData(item.path, item.data); } catch (e) { S._offlineQueue.push(item); }
  }
  if (!S._offlineQueue.length) toast('Changes synced!');
});

// ─── AUTH ────────────────────────────────────────────────────
function showAuth(mode = 'login') {
  const theme = document.documentElement.getAttribute('data-theme') || getPreferredTheme();
  $('auth-screen').innerHTML = `
    <div class="auth-card">
      <div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:4px">
        <div class="auth-logo"><div class="auth-logo-icon">A</div>Axinote</div>
        <button class="icon-btn" onclick="toggleTheme()">${themeIcon(theme)}</button>
      </div>
      <div class="auth-sub">Your connected study workspace</div>
      <div id="a-err" class="err-msg hidden"></div>
      <div id="a-ok"  class="ok-msg  hidden"></div>
      ${mode === 'login' ? `
        <div class="form-group"><label class="form-label">Email</label>
          <input id="le" type="email" class="form-input" placeholder="name@email.com" maxlength="254" autocomplete="email"></div>
        <div class="form-group"><label class="form-label">Password</label>
          <input id="lp" type="password" class="form-input" placeholder="••••••••" maxlength="128" autocomplete="current-password"></div>
        <div id="login-attempts-warn" style="font-size:12px;color:var(--orange);margin-bottom:8px;display:none"></div>
        <button class="btn btn-primary" onclick="doLogin()">Sign In</button>
        <div class="auth-switch">No account? <button onclick="showAuth('signup')">Sign up</button></div>
      `: `
        <div class="form-group"><label class="form-label">Display Name</label>
          <input id="sn" type="text" class="form-input" placeholder="Your name" maxlength="100" autocomplete="name"></div>
        <div class="form-group"><label class="form-label">Email</label>
          <input id="se" type="email" class="form-input" placeholder="name@email.com" maxlength="254" autocomplete="email"></div>
        <div class="form-group"><label class="form-label">Password</label>
          <input id="sp" type="password" class="form-input" placeholder="Min 8 chars, mixed, number, symbol" maxlength="128" autocomplete="new-password" oninput="updateStrengthMeter(this.value)">
          <div id="strength-meter"></div>
        </div>
        <div class="form-group"><label class="form-label">Confirm Password</label>
          <input id="sc" type="password" class="form-input" placeholder="••••••••" maxlength="128" autocomplete="new-password"></div>
        <button class="btn btn-primary" onclick="doSignup()">Create Account</button>
        <div class="auth-switch">Have an account? <button onclick="showAuth('login')">Sign in</button></div>
      `}
    </div>`;
  document.querySelectorAll('.form-input').forEach(i =>
    i.addEventListener('keydown', e => { if (e.key === 'Enter') mode === 'login' ? doLogin() : doSignup(); }));
  if (mode === 'login') {
    const emailEl = $('le');
    if (emailEl) emailEl.addEventListener('blur', () => {
      const w = $('login-attempts-warn'); if (!w) return;
      const res = RateLimit.check(emailEl.value);
      if (!res.allowed) { w.textContent = res.message; w.style.display = 'block'; }
      else { const r = RateLimit.remaining(emailEl.value); if (r < 5) { w.textContent = `${r} attempt${r !== 1 ? 's' : ''} remaining before lockout`; w.style.display = 'block'; } else w.style.display = 'none'; }
    });
  }
}

function authErr(msg) { const e = $('a-err'); if (e) { e.textContent = msg; e.classList.remove('hidden'); setTimeout(() => e.classList.add('hidden'), 5000); } }
function authOk(msg) { const e = $('a-ok'); if (e) { e.textContent = msg; e.classList.remove('hidden'); setTimeout(() => e.classList.add('hidden'), 3000); } }

async function doLogin() {
  const email = ($('le')?.value || '').trim(), pass = $('lp')?.value || '';
  if (!email || !pass) return authErr('Please enter email and password');
  const rl = RateLimit.check(email);
  if (!rl.allowed) return authErr(rl.message);
  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) return authErr('Enter a valid email address');
  const btn = document.querySelector('.auth-card .btn-primary');
  if (btn) { btn.disabled = true; btn.textContent = 'Signing in…'; }
  try {
    const cred = await window.fb.signInWithEmailAndPassword(window.fb.auth, email, pass);
    await cred.user.reload();
    
    RateLimit.recordSuccess(email);
  } catch (e) {
    RateLimit.recordFailure(email);
    const rem = RateLimit.remaining(email);
    const safe = ['auth/user-not-found', 'auth/wrong-password', 'auth/invalid-credential'];
    const msg = safe.includes(e.code) ? 'Incorrect email or password.' + (rem < 5 ? ` (${rem} attempt${rem !== 1 ? 's' : ''} left)` : '') : (e.message || 'Sign in failed');
    authErr(msg);
    if (btn) { btn.disabled = false; btn.textContent = 'Sign In'; }
  }
}

async function doSignup() {
  const name = validateStr($('sn')?.value || '', LIMITS.name);
  const email = ($('se')?.value || '').trim().toLowerCase().slice(0, LIMITS.email);
  const pass = $('sp')?.value || '', conf = $('sc')?.value || '';
  if (!name) return authErr('Please enter your display name');
  if (!email || !pass || !conf) return authErr('Fill all fields');
  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) return authErr('Enter a valid email address');
  if (pass !== conf) return authErr('Passwords do not match');
  const strength = checkPasswordStrength(pass);
  if (strength.score < 3) return authErr('Password too weak. Add: ' + strength.missing.join(', '));
  const btn = document.querySelector('.auth-card .btn-primary');
  if (btn) { btn.disabled = true; btn.textContent = 'Creating account…'; }
  try {
    const cred = await window.fb.createUserWithEmailAndPassword(window.fb.auth, email, pass);
    await window.fb.updateProfile(cred.user, { displayName: name }).catch(() => { });
    await window.fb.set(window.fb.ref(window.fb.database, 'users/' + cred.user.uid), {
      email, createdAt: new Date().toISOString(),
      profile: { name, bio: '', description: '' },
      stats: { sessions: 0, minutes: 0 },
      pages: {}, databases: {}, tasks: {}, calendar: {}, flashcards: {}, groups: {}
    });
    await window.fb.set(window.fb.ref(window.fb.database, `userIndex/${cred.user.uid}`), { name, email, uid: cred.user.uid });
    await window.fb.signOut(window.fb.auth).catch(() => { });
    if (btn) { btn.disabled = false; btn.textContent = 'Create Account'; }
    authOk('Account created! You can now sign in.');
    showAuth('login');
  } catch (e) { if (btn) { btn.disabled = false; btn.textContent = 'Create Account'; } authErr(e.message || 'Signup failed'); }
}

async function doLogout() {
  if (S.collabListener) { S.collabListener(); S.collabListener = null; }
  if (S.presenceListener) { S.presenceListener(); S.presenceListener = null; }
  if (S.activeCollabNote && S.user) {
    try { await window.fb.remove(window.fb.ref(window.fb.database, `collab/${S.activeCollabNote}/presence/${S.user.uid}`)); } catch (e) { }
  }
  if (S.groupMembershipListener) { try { S.groupMembershipListener(); } catch (e) { } S.groupMembershipListener = null; }
  Object.values(S.groupRealtimeListeners || {}).forEach(unsub => { try { unsub(); } catch (e) { } });
  S.groupRealtimeListeners = {};
  if (S.userIndexHeartbeatIv) { clearInterval(S.userIndexHeartbeatIv); S.userIndexHeartbeatIv = null; }
  if (S.eliteBenchListener) { try { S.eliteBenchListener(); } catch (e) { } S.eliteBenchListener = null; }
  S.eliteGroupBenchmark = null;
  try { await window.fb.signOut(window.fb.auth); } catch (e) { console.error(e); }
}

// ─── ICONS ───────────────────────────────────────────────────
const icons = {
  home: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/><polyline points="9 22 9 12 15 12 15 22"/></svg>`,
  calendar: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="4" width="18" height="18" rx="2"/><line x1="16" y1="2" x2="16" y2="6"/><line x1="8" y1="2" x2="8" y2="6"/><line x1="3" y1="10" x2="21" y2="10"/></svg>`,
  check: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="9 11 12 14 22 4"/><path d="M21 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11"/></svg>`,
  flash: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>`,
  timer: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="13" r="8"/><path d="M12 9v4l2 2"/><path d="M5 3L2 6"/><path d="M22 6l-3-3"/></svg>`,
  file: `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>`,
  db: `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"/><path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/></svg>`,
  plus: `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>`,
  trash: `<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2"/></svg>`,
  search: `<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>`,
  sidebar: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="18" height="18" rx="2"/><path d="M9 3v18"/></svg>`,
  logout: `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg>`,
  prev: `<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="15 18 9 12 15 6"/></svg>`,
  next: `<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="9 18 15 12 9 6"/></svg>`,
  list: `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="8" y1="6" x2="21" y2="6"/><line x1="8" y1="12" x2="21" y2="12"/><line x1="8" y1="18" x2="21" y2="18"/><line x1="3" y1="6" x2="3.01" y2="6"/><line x1="3" y1="12" x2="3.01" y2="12"/><line x1="3" y1="18" x2="3.01" y2="18"/></svg>`,
  kanban: `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="5" height="18"/><rect x="10" y="3" width="5" height="11"/><rect x="17" y="3" width="5" height="14"/></svg>`,
  close: `<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>`,
  play: `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="5 3 19 12 5 21 5 3"/></svg>`,
  pause: `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="6" y="4" width="4" height="16"/><rect x="14" y="4" width="4" height="16"/></svg>`,
  reset: `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="1 4 1 10 7 10"/><path d="M3.51 15a9 9 0 1 0 .49-3.5"/></svg>`,
  skip: `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="5 4 15 12 5 20 5 4"/><line x1="19" y1="5" x2="19" y2="19"/></svg>`,
  ok: `<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>`,
  x: `<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>`,
  back: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="19" y1="12" x2="5" y2="12"/><polyline points="12 19 5 12 12 5"/></svg>`,
  shuffle: `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="16 3 21 3 21 8"/><line x1="4" y1="20" x2="21" y2="3"/><polyline points="21 16 21 21 16 21"/><line x1="15" y1="15" x2="21" y2="21"/><line x1="4" y1="4" x2="9" y2="9"/></svg>`,
  dot6: `<svg width="10" height="16" viewBox="0 0 10 16" fill="currentColor"><circle cx="3" cy="4" r="1.3"/><circle cx="7" cy="4" r="1.3"/><circle cx="3" cy="8" r="1.3"/><circle cx="7" cy="8" r="1.3"/><circle cx="3" cy="12" r="1.3"/><circle cx="7" cy="12" r="1.3"/></svg>`,
  edit: `<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>`,
  collab: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg>`,
  profile: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>`,
  crown: `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"/></svg>`,
  clock: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>`,
  cardIcon: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="4" width="20" height="16" rx="2"/><path d="M12 4v16"/><path d="M2 12h4"/><path d="M18 12h4"/></svg>`,
  bookIcon: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 19.5A2.5 2.5 0 0 1 6.5 17H20"/><path d="M6.5 2H20v20H6.5A2.5 2.5 0 0 1 4 19.5v-15A2.5 2.5 0 0 1 6.5 2z"/></svg>`,
  brainIcon: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M9.5 2A2.5 2.5 0 0 1 12 4.5v15a2.5 2.5 0 0 1-4.96-.46 2.5 2.5 0 0 1-1.98-3 2.5 2.5 0 0 1-1.32-4.24 3 3 0 0 1 .34-5.58 2.5 2.5 0 0 1 1.32-4.24 2.5 2.5 0 0 1 4.1-1.98z"/></svg>`,
  zapIcon: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>`,
  flaskIcon: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M9 3h6"/><path d="M8 10l-3 9a1 1 0 0 0 .95 1.32h12.1A1 1 0 0 0 19 19l-3-9H8z"/><line x1="9" y1="3" x2="8" y2="10"/><line x1="15" y1="3" x2="16" y2="10"/></svg>`,
  rulerIcon: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21.3 8.7 8.7 21.3c-1 1-2.5 1-3.4 0l-2.6-2.6c-1-1-1-2.5 0-3.4L15.3 2.7c1-1 2.5-1 3.4 0l2.6 2.6c1 1 1 2.5 0 3.4z"/><path d="m7.5 10.5 2 2"/><path d="m10.5 7.5 2 2"/><path d="m13.5 4.5 2 2"/></svg>`,
  globeIcon: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>`,
  bulbIcon: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="9" y1="18" x2="15" y2="18"/><line x1="10" y1="22" x2="14" y2="22"/><path d="M15.09 14c.18-.98.65-1.74 1.41-2.5A4.65 4.65 0 0 0 18 8 6 6 0 0 0 6 8c0 1 .23 2.23 1.5 3.5A4.61 4.61 0 0 1 8.91 14"/></svg>`,
  targetIcon: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><circle cx="12" cy="12" r="6"/><circle cx="12" cy="12" r="2"/></svg>`,
  penIcon: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 20h9"/><path d="M16.5 3.5a2.121 2.121 0 0 1 3 3L7 19l-4 1 1-4L16.5 3.5z"/></svg>`,
  // New icons
  table: `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="18" height="18" rx="2"/><path d="M3 9h18"/><path d="M3 15h18"/><path d="M9 3v18"/><path d="M15 3v18"/></svg>`,
  image: `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="18" height="18" rx="2"/><circle cx="8.5" cy="8.5" r="1.5"/><polyline points="21 15 16 10 5 21"/></svg>`,
  pdfIcon: `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/><polyline points="10 9 9 9 8 9"/></svg>`,
  users: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg>`,
  projects: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/></svg>`,
  group: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="5" r="3"/><path d="M6 22v-2a6 6 0 0 1 12 0v2"/><circle cx="20" cy="8" r="2"/><path d="M22 22v-1a4 4 0 0 0-4-4h-1"/><circle cx="4" cy="8" r="2"/><path d="M2 22v-1a4 4 0 0 1 4-4h1"/></svg>`,
  uploadIcon: `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="16 16 12 12 8 16"/><line x1="12" y1="12" x2="12" y2="21"/><path d="M20.39 18.39A5 5 0 0 0 18 9h-1.26A8 8 0 1 0 3 16.3"/></svg>`,
  linkIcon: `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/></svg>`,
  descIcon: `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="17" y1="10" x2="3" y2="10"/><line x1="21" y1="6" x2="3" y2="6"/><line x1="21" y1="14" x2="3" y2="14"/><line x1="17" y1="18" x2="3" y2="18"/></svg>`,
  addRow: `<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M9 3H5a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-4"/><polyline points="16 3 20 7 16 11"/><line x1="20" y1="7" x2="9" y2="7"/></svg>`,
  addCol: `<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M11 3H5a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-6"/><polyline points="13 8 17 12 13 16"/><line x1="17" y1="12" x2="6" y2="12"/></svg>`,
  moon: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></svg>`,
  sunrise: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17 18a5 5 0 0 0-10 0"/><line x1="12" y1="2" x2="12" y2="9"/><line x1="4.22" y1="10.22" x2="5.64" y2="11.64"/><line x1="2" y1="18" x2="4" y2="18"/><line x1="20" y1="18" x2="22" y2="18"/><line x1="19.78" y1="11.64" x2="18.36" y2="10.22"/><line x1="3" y1="18" x2="21" y2="18"/></svg>`,
  sunset: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17 18a5 5 0 0 0-10 0"/><line x1="3" y1="18" x2="21" y2="18"/><polyline points="8 9 12 5 16 9"/><line x1="12" y1="5" x2="12" y2="12"/></svg>`,
  candle: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M9 21h6"/><path d="M9 9h6v12H9z"/><path d="M12 9c0-1.5 1.5-3 1.5-4.5a1.5 1.5 0 0 0-3 0C10.5 6 12 7.5 12 9z"/></svg>`,
  sun: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="5"/><line x1="12" y1="1" x2="12" y2="3"/><line x1="12" y1="21" x2="12" y2="23"/><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/><line x1="1" y1="12" x2="3" y2="12"/><line x1="21" y1="12" x2="23" y2="12"/><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/></svg>`,
  exam: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M2 17h20v2a1 1 0 0 1-1 1H3a1 1 0 0 1-1-1v-2z"/><path d="M2 17L5 8l5 4 4-8 4 8 5-4-3 9"/></svg>`,
  dna: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M2 15c6.667-6 13.333 0 20-6"/><path d="M9 22c1.798-1.998 2.518-3.995 2.807-5.993"/><path d="M15 2c-1.798 1.998-2.518 3.995-2.807 5.993"/><path d="m2 9 3 .36"/><path d="m19.7 14.36 3 .36"/><path d="M5 6.09l.6 2.58"/><path d="m18.4 15.33.6 2.58"/><path d="m6.52 17 1.98 1.5"/><path d="m17.48 7-1.98-1.5"/></svg>`,
  sparkle: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m12 3-1.912 5.813a2 2 0 0 1-1.275 1.275L3 12l5.813 1.912a2 2 0 0 1 1.275 1.275L12 21l1.912-5.813a2 2 0 0 1 1.275-1.275L21 12l-5.813-1.912a2 2 0 0 1-1.275-1.275L12 3Z"/></svg>`,
};
const I = (name, extra = '') => `<span style="${extra}">${icons[name] || ''}</span>`;

function themeIcon(theme) {
  return theme === 'dark'
    ? `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></svg>`
    : `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="5"/><line x1="12" y1="1" x2="12" y2="3"/><line x1="12" y1="21" x2="12" y2="23"/><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/><line x1="1" y1="12" x2="3" y2="12"/><line x1="21" y1="12" x2="23" y2="12"/><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/></svg>`;
}

// ─── APP RENDER ───────────────────────────────────────────────
function getDisplayName() { return S.userProfile?.name || S.user?.displayName || S.user?.email?.split('@')[0] || 'User'; }

const APP_NAV_SCHEMA = {
  core: [
    { view: 'home', icon: 'home', label: 'Home' },
    { view: 'tasks', icon: 'check', label: 'Tasks' },
    { view: 'calendar', icon: 'calendar', label: 'Calendar' },
    { view: 'flashcards', icon: 'flash', label: 'Flashcards' },
    { view: 'projects', icon: 'projects', label: 'Projects', badge: () => (S.projects.length || '') },
    { view: 'examSuite', icon: 'exam', label: 'Exam Advantage' },
    { view: 'mockExam', icon: 'check', label: 'Mock Exams', advancedOnly: true, badge: () => ((S.mockExams || []).length || '') },
  ],
  collaboration: [
    { view: 'groups', icon: 'group', label: 'Study Groups' },
    { view: 'collab', icon: 'collab', label: 'Collab Notes' },
  ],
};

function bindShellEvents() {
  if (S._shellEventsBound) return;
  window.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && S.sidebarDrawerOpen) {
      closeSidebarDrawer();
      renderApp();
    }
  });
  window.addEventListener('resize', () => {
    if (!isMobileShell() && S.sidebarDrawerOpen) {
      closeSidebarDrawer();
      renderApp();
    }
  });
  S._shellEventsBound = true;
}

function renderSidebar(displayName) {
  const admin = isAdmin();
  const mobile = isMobileShell();
  const mode = mobile ? 'drawer' : (S.sidebarMode || 'expanded');
  const isRail = mode === 'rail';
  const isOpen = mobile ? !!S.sidebarDrawerOpen : true;
  const notesExpanded = !S._sbCol.pages && !isRail;
  const dbExpanded = !S._sbCol.databases && !isRail;
  const sortedPages = [...S.pages].sort((a, b) => (b.pinned ? 1 : 0) - (a.pinned ? 1 : 0));
  const coreItems = APP_NAV_SCHEMA.core
    .filter(it => !it.advancedOnly || isAdvancedUser())
    .map(it => navItem(it.view, it.icon, it.label, it.badge ? it.badge() : ''))
    .join('');
  const collabItems = APP_NAV_SCHEMA.collaboration.map(it => navItem(it.view, it.icon, it.label, it.badge ? it.badge() : '')).join('');

  return `
    <div class="sidebar mode-${mode}${isOpen ? ' is-open' : ' is-closed'}" id="sidebar">
      <div class="sidebar-header">
        <div class="workspace-name"><div class="workspace-icon">A</div><span>Axinote</span></div>
        <button class="icon-btn sidebar-mobile-close" onclick="closeSidebarDrawer();renderApp()" title="Close navigation">${icons.close}</button>
      </div>
      <div class="sidebar-scroll">
        <div class="sidebar-section">
          <div class="sec-title">Core</div>
          ${coreItems}
          <div class="nav-item nav-panel-toggle${S.view === 'page' ? ' active' : ''}" onclick="toggleSbSection('pages')" title="Notes">
            ${icons.file}<span>Notes</span>
            <span class="nav-badge">${S.pages.length}</span>
            <span class="panel-caret${notesExpanded ? ' open' : ''}">${icons.next}</span>
          </div>
          ${notesExpanded ? `
            <div class="nav-panel-list">
              <div class="nav-item nav-add" onclick="showTemplatePicker()">${icons.plus}<span>New Page</span></div>
              ${sortedPages.map(p => `
                <div class="nav-item nav-item-sub${S.view === 'page' && S.page?.id === p.id ? ' active' : ''}" onclick="openPage('${p.id}')" title="${esc(p.title || 'Untitled')}">
                  ${p.pinned ? '<svg width="12" height="12" viewBox="0 0 24 24" fill="currentColor" stroke="none"><path d="M16 2l-4.6 4.6L8 7l-1 5 5-1 .4-3.4L17 3V2h-1zM2 22l5.5-5.5L9 18l3-3-3-3-3 3 1.5 1.5L2 22z"/></svg>' : icons.file}
                  <span>${esc(p.title) || 'Untitled'}</span>
                  <button class="icon-btn page-del-btn" onclick="event.stopPropagation();deletePage('${p.id}')" style="width:22px;height:22px;margin-left:auto;opacity:0">${icons.trash}</button>
                </div>
              `).join('')}
            </div>
          ` : ''}
        </div>

        <div class="sidebar-section">
          <div class="sec-title">Workspace Data</div>
          <div class="nav-item nav-panel-toggle${S.view === 'database' ? ' active' : ''}" onclick="toggleSbSection('databases')" title="Databases">
            ${icons.db}<span>Databases</span>
            <span class="nav-badge">${S.databases.length}</span>
            <span class="panel-caret${dbExpanded ? ' open' : ''}">${icons.next}</span>
          </div>
          ${dbExpanded ? `
            <div class="nav-panel-list">
              <div class="nav-item nav-add" onclick="createDatabase()">${icons.plus}<span>New Database</span></div>
              ${S.databases.map(d => `
                <div class="nav-item nav-item-sub${S.view === 'database' && S.page?.id === d.id ? ' active' : ''}" onclick="openDatabase('${d.id}')" title="${esc(d.title || 'Untitled DB')}">
                  ${icons.db}<span>${esc(d.title) || 'Untitled DB'}</span>
                  <button class="icon-btn db-del-btn" onclick="event.stopPropagation();deleteDatabase('${d.id}')" style="width:20px;height:20px;margin-left:4px;opacity:0;color:var(--red);flex-shrink:0">${icons.trash}</button>
                </div>
              `).join('')}
            </div>
          ` : ''}
        </div>

        <div class="sidebar-section">
          <div class="sec-title">Collaboration</div>
          ${collabItems}
        </div>
      </div>
      <div class="sidebar-footer">
        <button class="notif-row" id="notif-row-btn" onclick="openNotifications()" title="Notifications">
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.73 21a2 2 0 0 1-3.46 0"/></svg>
          <span>Notifications</span>
          <span class="notif-count" id="notif-count" style="display:none">0</span>
        </button>

        <div class="user-row${admin ? ' admin-user' : ''}" onclick="navigate('profile')" title="Open settings">
          <div class="user-av${admin ? ' admin-av admin-glow' : ''}">
            ${admin ? icons.crown : (S.userProfile?.avatar ? (() => { const _ic = AVATAR_ICONS.find(i => i.id === S.userProfile.avatar); return _ic ? `<span class="nav-av-svg">${_ic.svg}</span>` : `<span style="font-weight:700">${displayName[0]?.toUpperCase() || '?'}</span>`; })() : `<span style="font-weight:700">${displayName[0]?.toUpperCase() || '?'}</span>`)}
          </div>
          <div class="user-info-col">
            <div class="user-name">${esc(displayName)}<span class="admin-badge${admin ? '' : ' user-badge'}">${admin ? esc(getAdminTag().split(' ').slice(0, 2).join(' ')) : (S.userProfile?.customTag || 'User')}</span></div>
            <div class="user-email">${esc(S.user.email)}</div>
          </div>
          <button class="icon-btn" onclick="event.stopPropagation();doLogout()" title="Sign out" style="flex-shrink:0">${icons.logout}</button>
        </div>
      </div>
    </div>`;
}

function renderTopbar(theme) {
  const showBack = S.view !== 'home' || canGoBack();
  return `
    <div class="topbar">
      <div class="topbar-left">
        <button class="icon-btn topbar-menu-btn" onclick="toggleSidebar()" title="Toggle navigation">${icons.sidebar}</button>
        ${showBack ? `<button class="icon-btn topbar-back-btn" onclick="goBack()" title="Back">${icons.back}</button>` : ''}
        <div class="breadcrumb">${breadcrumb()}</div>
        <div class="save-indicator" id="save-indicator"></div>
      </div>
      <div class="topbar-right">
        <button class="icon-btn" onclick="togglePom()" title="Focus timer">${icons.timer}</button>
        <button class="icon-btn" onclick="openSearch()" title="Search ⌘K">${icons.search}</button>
        <button class="icon-btn" onclick="toggleTheme()" title="Toggle theme">${themeIcon(theme)}</button>
      </div>
    </div>`;
}

function renderMainContentShell() {
  return `<div class="content" id="main-content"></div>`;
}

function renderApp() {
  const theme = document.documentElement.getAttribute('data-theme') || getPreferredTheme();
  const displayName = getDisplayName();
  const mobile = isMobileShell();
  const mode = mobile ? 'drawer' : (S.sidebarMode || 'expanded');

  if (!mobile) S.sidebarDrawerOpen = false;
  S.sidebarOpen = mode === 'expanded';

  $('app').innerHTML = `
    ${renderSidebar(displayName)}
    <div class="main">
      ${renderTopbar(theme)}
      ${renderMainContentShell()}
    </div>
    <button class="app-scrim${mobile && S.sidebarDrawerOpen ? ' show' : ''}" onclick="closeSidebarDrawer();renderApp()" aria-label="Close navigation"></button>`;

  // Ensure AI floating bubble exists
  if (!document.getElementById('ai-float-bubble')) {
    const bubble = document.createElement('button');
    bubble.id = 'ai-float-bubble';
    bubble.className = 'ai-float-bubble';
    bubble.title = 'FlowAI';
    bubble.innerHTML = `<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M9.5 2A2.5 2.5 0 0 1 12 4.5v15a2.5 2.5 0 0 1-4.96-.46 2.5 2.5 0 0 1-2.96-3.08 3 3 0 0 1-.34-5.58 2.5 2.5 0 0 1 1.32-4.24 2.5 2.5 0 0 1 1.98-3A2.5 2.5 0 0 1 9.5 2z"/><path d="M14.5 2A2.5 2.5 0 0 0 12 4.5v15a2.5 2.5 0 0 0 4.96-.46 2.5 2.5 0 0 0 2.96-3.08 3 3 0 0 0 .34-5.58 2.5 2.5 0 0 0-1.32-4.24 2.5 2.5 0 0 0-1.98-3A2.5 2.5 0 0 0 14.5 2z"/></svg><div class="ai-float-pulse"></div>`;
    bubble.onclick = () => { AI.open ? closeAIPanel() : openAIPanelTab('flowai'); };
    document.body.appendChild(bubble);
  }

  // Hover show delete buttons
  document.querySelectorAll('.nav-item').forEach(item => {
    const btns = [...item.querySelectorAll('.page-del-btn, .db-del-btn')];
    if (btns.length) {
      item.addEventListener('mouseenter', () => btns.forEach(b => b.style.opacity = '1'));
      item.addEventListener('mouseleave', () => btns.forEach(b => b.style.opacity = '0'));
    }
  });
  loadNotifications();
  syncRouteWithState({ replace: true });
  bindShellEvents();

  renderContent();
}

function navItem(view, icon, label, badge) {
  const active = S.view === view
    || (view === 'groups' && S.view === 'studyGroup')
    || (view === 'projects' && (S.view === 'projects' || S.view === 'projectDetail'))
    || (view === 'collab' && S.view === 'collabNote')
    || (view === 'flashcards' && S.view === 'study');
  return `<div class="nav-item${active ? ' active' : ''}" onclick="navigate('${view}')" title="${esc(label)}">
    ${icons[icon]}<span>${label}</span>
    ${badge ? `<span class="nav-badge">${badge}</span>` : ''}
  </div>`;
}

function breadcrumb() {
  const bc = (label, onclick) => onclick
    ? `<span class="bc-link" onclick="${onclick}">${label}</span><span class="bc-sep">/</span>`
    : `<span class="bc-curr">${label}</span>`;
  let crumbs = bc('Axinote', "navigate('home')");
  const map = { home: 'Home', examSuite: 'Exam Advantage System', mockExam: 'Mock Exams', calendar: 'Calendar', tasks: 'Tasks', flashcards: 'Flashcards', collab: 'Collab Notes', profile: 'Settings', groups: 'Study Groups', aiChat: 'FlowAI Chat', projects: 'Projects', settings: 'Settings', dailyTasks: 'Tasks', aiDashboard: 'AI Dashboard', privacy: 'Privacy Policy', changelog: "What's New" };
  if (map[S.view]) { crumbs += bc(map[S.view]); return crumbs; }
  if (S.view === 'page' && S.page) {
    // Check if note belongs to a project
    const proj = S.projects.find(p => (p.noteIds || []).includes(S.page.id));
    if (proj) crumbs += bc(esc(proj.title), `openProject('${proj.id}')`) + ' ';
    crumbs += bc(esc(S.page.title || 'Untitled'));
    return crumbs;
  }
  if (S.view === 'database' && S.page) return crumbs + bc(esc(S.page.title || 'Untitled DB'));
  if (S.view === 'study' && S.deck) return crumbs + bc('Flashcards', "navigate('flashcards')") + ' ' + bc(`Studying: ${esc(S.deck.title)}`);
  if (S.view === 'collabNote') return crumbs + bc('Collab Notes', "navigate('collab')") + ' ' + bc('Note');
  if (S.view === 'studyGroup') return crumbs + bc('Study Groups', "navigate('groups')") + ' ' + bc('Group');
  if (S.view === 'projectDetail' && S.currentProject) return crumbs + bc('Projects', "navigate('projects')") + ' ' + bc(esc(S.currentProject.title));
  return crumbs + bc('Axinote');
}

function fallbackViewForCurrent() {
  if (S.view === 'study') return 'flashcards';
  if (S.view === 'collabNote') return 'collab';
  if (S.view === 'studyGroup') return 'groups';
  if (S.view === 'projectDetail') return 'projects';
  if (S.view === 'database') return 'home';
  if (S.view === 'page' && S.deck?.id) return 'flashcards';
  if (S.view === 'aiChat') return 'home';
  return 'home';
}

function canUseBrowserBackSafely() {
  if (window.history.length <= 1) return false;
  try {
    if (!document.referrer) return false;
    const ref = new URL(document.referrer);
    return ref.origin === window.location.origin && _normPath(ref.pathname).startsWith(APP_ROUTE_BASE);
  } catch (_) {
    return false;
  }
}

function canGoBack() {
  return (S._navStack || []).length > 0 || canUseBrowserBackSafely();
}

function goBack() {
  if (S._navStack && S._navStack.length) {
    const targetPath = S._navStack.pop();
    const ok = applyRouteFromPath(targetPath, { replaceHistory: true, pushHistory: false });
    if (ok) return;
  }
  if (canUseBrowserBackSafely()) {
    window.history.back();
    return;
  }
  navigate(fallbackViewForCurrent(), { pushHistory: false, replaceHistory: true });
}

function renderContent() {
  const c = $('main-content'); if (!c) return;
  try {
    const fns = {
      home: renderHomeCompact, examSuite: renderExamSuitePage, calendar: renderCalendar, tasks: renderTasks, dailyTasks: renderDailyTasks,
      flashcards: renderFlashdecks, page: renderEditor, database: renderDatabase,
      study: renderStudy, collab: renderCollabList, collabNote: renderCollabNote,
      profile: renderProfile, groups: renderStudyGroups, studyGroup: renderStudyGroupDetail,
      aiChat: renderAIChatView,
      projects: renderProjectsList, projectDetail: renderProjectDetail,
      mockExam: renderMockExamHub,
      settings: renderProfile,
      aiDashboard: renderAIDashboard,
      privacy: renderPrivacyPage,
      changelog: renderChangelog,
    };
    (fns[S.view] || renderHome)(c);
  } catch (e) {
    console.error('[Axinote] renderContent error:', e, 'view:', S.view);
    c.innerHTML = `<div style="padding:60px 0;text-align:center;color:var(--text-muted)"><svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" style="margin-bottom:12px;color:var(--accent)"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg><div style="font-size:15px;font-weight:600;margin-bottom:6px">Something went wrong</div><div style="font-size:13px;margin-bottom:16px">${e.message || 'unknown error'}</div><button class="btn btn-action btn-sm" onclick="navigate('home')">Go Home</button></div>`;
  }
  // Check onboarding — only after profile has loaded from Firebase
  if (S.user && S.userProfile && !S.userProfile?.onboardingComplete && S.pages.length === 0 && S.view === 'home') {
    showOnboarding();
  }
}

function navigate(view, options = {}) {
  const { pushHistory = true, replaceHistory = false } = options;
  if (S.collabListener && view !== 'collabNote') { S.collabListener(); S.collabListener = null; }
  if (view !== 'collab' && _collabListListener) { _collabListListener(); _collabListListener = null; }
  if (view !== 'studyGroup' && _groupNotesListener) { _groupNotesListener(); _groupNotesListener = null; }
  if (view !== 'studyGroup' && _groupChatListener) { _groupChatListener(); _groupChatListener = null; }
  if (S.presenceListener && view !== 'collabNote') {
    S.presenceListener(); S.presenceListener = null;
    if (S.activeCollabNote && S.user) window.fb.remove(window.fb.ref(window.fb.database, `collab/${S.activeCollabNote}/presence/${S.user.uid}`)).catch(() => { });
    S.activeCollabNote = null;
  }
  if (view !== 'examSuite' && S.eliteBenchListener) {
    try { S.eliteBenchListener(); } catch (e) { }
    S.eliteBenchListener = null;
  }
  S.view = view; S.page = null; S.showForm = null;
  closeSidebarAfterNavigate();
  syncRouteWithState({ push: pushHistory, replace: replaceHistory });
  renderApp();
}

function toggleSidebar() {
  if (isMobileShell()) {
    S.sidebarDrawerOpen = !S.sidebarDrawerOpen;
    renderApp();
    return;
  }
  S.sidebarMode = S.sidebarMode === 'rail' ? 'expanded' : 'rail';
  S.sidebarOpen = S.sidebarMode === 'expanded';
  persistSidebarMode();
  renderApp();
}

function toggleSbSection(key) {
  if (!S._sbCol) S._sbCol = { pages: true, databases: true };
  S._sbCol[key] = !S._sbCol[key];
  persistSidebarSections();
  renderApp();
}

function getPreferredTheme() {
  const saved = localStorage.getItem('theme');
  if (saved === 'dark' || saved === 'light') return saved;
  return window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
}

function toggleTheme() {
  const cur = document.documentElement.getAttribute('data-theme') || getPreferredTheme();
  const nxt = cur === 'dark' ? 'light' : 'dark';
  document.documentElement.setAttribute('data-theme', nxt); localStorage.setItem('theme', nxt);
  if ($('app') && !$('app').classList.contains('hidden')) renderApp(); else showAuth();
}

// ─── HOME ─────────────────────────────────────────────────────
function renderHome(c) {
  const active = S.tasks.filter(t => !t.completed).length, done = S.tasks.filter(t => t.completed).length;
  const today = new Date().toISOString().split('T')[0], todayEvs = S.calendar.filter(e => e.date === today);
  const recent = [...S.pages].sort((a, b) => (b.updatedAt || b.createdAt || '') > (a.updatedAt || a.createdAt || '') ? 1 : -1).slice(0, 6);
  const g = greet();
  const greetIcon = `<span style="display:inline-flex;align-items:center;color:var(--accent)">${g.svg}</span>`;
  c.innerHTML = `
    <div style="margin-bottom:28px">
      <div style="display:flex;align-items:center;gap:10px;margin-bottom:4px">
        <h1 style="font-size:36px;font-weight:700;line-height:1.15">${esc(g.phrase)}</h1>
        ${greetIcon}
      </div>
      <p style="color:var(--text-faint);font-size:14px">${esc(g.sub)}</p>
    </div>
    <div class="stat-row">
      <div class="stat-box stat-box-link" onclick="navigate('home')" title="Pages"><div class="stat-num" style="color:var(--accent)">${S.pages.length}</div><div class="stat-lbl">Pages</div></div>
      <div class="stat-box stat-box-link" onclick="navigate('tasks')" title="Tasks"><div class="stat-num" style="color:var(--blue)">${active}</div><div class="stat-lbl">Tasks</div></div>
      <div class="stat-box stat-box-link" onclick="navigate('tasks')" title="Done"><div class="stat-num" style="color:var(--green)">${done}</div><div class="stat-lbl">Done</div></div>
      <div class="stat-box stat-box-link" onclick="navigate('flashcards')" title="Decks"><div class="stat-num" style="color:var(--purple)">${S.flashcards.length}</div><div class="stat-lbl">Decks</div></div>
    </div>
    <div class="quick-actions">
      <button class="btn btn-action btn-sm" onclick="showTemplatePicker()">${icons.plus} New Page</button>
      <button class="btn btn-secondary btn-sm" onclick="navigate('tasks')">${icons.check} Tasks</button>
      <button class="btn btn-secondary btn-sm" onclick="navigate('calendar')">${icons.calendar} Calendar</button>
      <button class="btn btn-secondary btn-sm" onclick="navigate('flashcards')">${icons.flash} Flashcards</button>
      <button class="btn btn-secondary btn-sm" onclick="togglePom()">${icons.timer} Pomodoro</button>
      <button class="btn btn-secondary btn-sm" onclick="navigate('collab')">${icons.collab} Collab Notes</button>
    </div>
    ${todayEvs.length ? `<div class="section-lbl">Today's Events</div>${todayEvs.map(e => `<div class="recent-row" onclick="openCalEventModal(null,'',null,'${e.id}')"><span style="width:8px;height:8px;border-radius:50%;background:var(--${e.color});flex-shrink:0;display:inline-block"></span><span>${esc(e.title)}</span>${e.time ? `<span class="recent-date">${e.time}</span>` : ''}</div>`).join('')}` : ''}
    
    ${S.pages.filter(p => p.pinned).length ? `<div class="section-lbl">Pinned Notes</div>${S.pages.filter(p => p.pinned).map(p => `
      <div class="recent-row" onclick="openPage('${p.id}')">
        <span style="color:var(--accent);margin-right:8px">${icons.star}</span><span>${esc(p.title) || 'Untitled'}</span>
        ${p.tags && p.tags.length ? `<span style="font-size:10px;padding:2px 6px;border-radius:10px;background:var(--bg-sec);margin-left:8px">${esc(p.tags[0].label)}</span>` : ''}
        <button class="icon-btn" style="margin-left:auto;width:24px;height:24px" onclick="event.stopPropagation();togglePinPage('${p.id}')">${icons.star}</button>
      </div>`).join('')}` : ''}

    <div class="section-lbl">Recent Pages</div>
    ${recent.length ? recent.map(p => `
      <div class="recent-row" onclick="openPage('${p.id}')">
        ${icons.file}<span>${esc(p.title) || 'Untitled'}</span>
        ${p.tags && p.tags.length ? `<span style="font-size:10px;padding:2px 6px;border-radius:10px;background:var(--bg-sec);margin-left:8px">${esc(p.tags[0].label)}</span>` : ''}
        <span class="recent-date" style="margin-left:auto;margin-right:8px">${fmt(p.updatedAt || p.createdAt)}</span>
        <button class="icon-btn" style="width:24px;height:24px" title="${p.pinned ? 'Unpin' : 'Pin'}" onclick="event.stopPropagation();togglePinPage('${p.id}')">${p.pinned ? icons.star : icons.moon}</button>
      </div>`).join('') :
      '<div class="empty"><div class="empty-icon"><svg width="34" height="34" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg></div><div class="empty-title">No pages yet</div><p class="empty-sub">Create your first page to get started.</p></div>'}
    ${active ? `<div class="section-lbl">Active Tasks</div>${S.tasks.filter(t => !t.completed).slice(0, 5).map(t => `<div class="task-row"><div class="task-chk" onclick="toggleTask('${t.id}')"></div><span class="task-lbl">${esc(t.title)}</span>${t.priority ? `<div class="dot d-${t.priority === 'high' ? 'high' : t.priority === 'low' ? 'low' : 'med'}"></div>` : ''}${t.due ? `<span class="task-due${overdue(t.due) ? ' late' : ''}"> ${fmt(t.due)}</span>` : ''}</div>`).join('')}` : ''}
    ${renderStudyTipsPanel()}`;
}

function renderHomeCompact(c) {
  const todayISO = new Date().toISOString().split('T')[0];
  const g = greet();
  const tasksActive = S.tasks.filter(t => !t.completed);
  const tasksDone = S.tasks.filter(t => t.completed).length;
  const tasksDueToday = tasksActive.filter(t => t.due === todayISO).slice(0, 4);
  const tasksDueSoon = tasksActive
    .filter(t => t.due && t.due >= todayISO)
    .sort((a, b) => String(a.due || '').localeCompare(String(b.due || '')))
    .slice(0, 5);
  const overdueCount = tasksActive.filter(t => t.due && t.due < todayISO).length;
  const todayEvents = S.calendar.filter(e => e.date === todayISO).slice(0, 4);
  const recentNotes = [...S.pages].sort((a, b) => String(b.updatedAt || b.createdAt || '').localeCompare(String(a.updatedAt || a.createdAt || ''))).slice(0, 4);
  const recentProjects = [...S.projects].sort((a, b) => String(b.updatedAt || b.createdAt || '').localeCompare(String(a.updatedAt || a.createdAt || ''))).slice(0, 3);
  const taskCompletion = S.tasks.length ? Math.round((tasksDone / S.tasks.length) * 100) : 0;
  const admin = isAdmin();
  const credits = getCredits();
  const creditsLeft = getCreditLeft();
  const creditsUsedPct = Math.max(0, Math.min(100, Math.round(((credits.used || 0) / Math.max(1, credits.total || 1)) * 100)));
  const resumeNote = recentNotes[0] || null;
  const resumeAction = resumeNote ? `openPage('${resumeNote.id}')` : 'showTemplatePicker()';
  const resumeLabel = resumeNote ? `Resume ${esc((resumeNote.title || 'Untitled').slice(0, 24))}` : 'Create your first note';
  const firstTime = !S.pages.length && !S.tasks.length && !S.calendar.length && !S.projects.length && !S.flashcards.length;

  c.innerHTML = `
    <div class="home-shell">
      <div class="home-hero">
        <div>
          <h1>${esc(g.phrase)}</h1>
          <p>${esc(g.sub)}</p>
        </div>
        <div class="home-hero-mark">${g.svg}</div>
      </div>

      ${firstTime ? `
        <div class="card home-starter">
          <div class="home-starter-head">Start in 3 steps</div>
          <div class="home-starter-row">
            <div class="home-starter-step">
              <span class="home-step-num">1</span>
              <div><strong>Create your first note</strong><p>Capture what you are studying today.</p></div>
              <button class="btn btn-action btn-sm" onclick="showTemplatePicker()">New Note</button>
            </div>
            <div class="home-starter-step">
              <span class="home-step-num">2</span>
              <div><strong>Add a priority task</strong><p>Give yourself one clear action to complete.</p></div>
              <button class="btn btn-secondary btn-sm" onclick="navigate('tasks')">Open Tasks</button>
            </div>
            <div class="home-starter-step">
              <span class="home-step-num">3</span>
              <div><strong>Set your first deadline or group</strong><p>Anchor your week with a date or collaborator.</p></div>
              <div style="display:flex;gap:8px">
                <button class="btn btn-secondary btn-sm" onclick="navigate('calendar')">Calendar</button>
                <button class="btn btn-secondary btn-sm" onclick="navigate('groups')">Groups</button>
              </div>
            </div>
          </div>
        </div>
      ` : `
        <div class="home-zone-grid">
          <div class="card home-zone-card">
            <div class="home-zone-title">Today Snapshot</div>
            <div class="home-kpis">
              <div><span>Due Today</span><strong>${tasksDueToday.length}</strong></div>
              <div><span>Events</span><strong>${todayEvents.length}</strong></div>
              <div><span>Overdue</span><strong>${overdueCount}</strong></div>
            </div>
            <div class="home-list">
              ${tasksDueToday.length ? tasksDueToday.map(t => `<div class="home-list-row" onclick="navigate('tasks')">${icons.check}<span>${esc(t.title)}</span><span>${t.due ? fmt(t.due) : ''}</span></div>`).join('') : '<div class="home-empty-row">No tasks due today.</div>'}
            </div>
            <div class="home-primary-actions">
              <button class="btn btn-action btn-sm" onclick="${resumeAction}">${resumeLabel}</button>
              <button class="btn btn-secondary btn-sm" onclick="navigate('tasks')">Plan Tasks</button>
            </div>
          </div>

          <div class="card home-zone-card">
            <div class="home-zone-title">Schedule</div>
            <div class="home-list">
              ${todayEvents.length ? todayEvents.map(e => `<div class="home-list-row" onclick="openCalEventModal(null,'',null,'${e.id}')"><span class="home-dot" style="background:var(--${e.color || 'accent'})"></span><span>${esc(e.title)}</span><span>${e.time ? esc(e.time) : 'All day'}</span></div>`).join('') : '<div class="home-empty-row">No events today.</div>'}
              ${tasksDueSoon.slice(0, 2).map(t => `<div class="home-list-row" onclick="navigate('tasks')">${icons.timer}<span>${esc(t.title)}</span><span>${fmt(t.due)}</span></div>`).join('')}
            </div>
            <div class="home-primary-actions">
              <button class="btn btn-secondary btn-sm" onclick="navigate('calendar')">Open Calendar</button>
              <button class="btn btn-secondary btn-sm" onclick="showTemplatePicker()">New Note</button>
            </div>
          </div>
        </div>

        <div class="home-zone-grid home-zone-grid-mid">
          <div class="card home-zone-card">
            <div class="home-zone-title">Recent Work</div>
            <div class="home-subtitle">Notes</div>
            <div class="home-list">
              ${recentNotes.length ? recentNotes.map(p => `<div class="home-list-row" onclick="openPage('${p.id}')">${icons.file}<span>${esc(p.title) || 'Untitled'}</span><span>${fmt(p.updatedAt || p.createdAt)}</span></div>`).join('') : '<div class="home-empty-row">No notes yet.</div>'}
            </div>
            <div class="home-subtitle">Projects</div>
            <div class="home-list">
              ${recentProjects.length ? recentProjects.map(p => `<div class="home-list-row" onclick="openProject('${p.id}')">${icons.projects}<span>${esc(p.title) || 'Untitled Project'}</span><span>${(p.noteIds || []).length} notes</span></div>`).join('') : '<div class="home-empty-row">No projects yet.</div>'}
            </div>
          </div>

          <div class="card home-zone-card">
            <div class="home-zone-title">Progress Snapshot</div>
            <div class="home-kpis home-kpis-vertical">
              <div><span>Task completion</span><strong>${taskCompletion}%</strong></div>
              <div><span>Open tasks</span><strong>${tasksActive.length}</strong></div>
              <div><span>Flashcard decks</span><strong>${S.flashcards.length}</strong></div>
            </div>
            <div class="home-credit">
              <div class="home-credit-row">
                <span>AI credits</span>
                <strong>${admin ? 'Unlimited' : `${creditsLeft.toLocaleString()} left`}</strong>
              </div>
              ${admin ? '' : `<div class="home-credit-bar"><div style="width:${creditsUsedPct}%"></div></div>`}
            </div>
            <div class="home-primary-actions">
              <button class="btn btn-secondary btn-sm" onclick="navigate('groups')">Open Groups</button>
              ${hasPlan('advanced') ? `<button class="btn btn-secondary btn-sm" onclick="navigate('examSuite')">Exam Insights</button>` : '<button class="btn btn-secondary btn-sm" onclick="navigate(\'flashcards\')">Flashcards</button>'}
            </div>
          </div>
        </div>
      `}

      <div class="home-insights-toggle">
        <button class="btn btn-ghost btn-sm" onclick="S.homeInsightsOpen=!S.homeInsightsOpen;renderContent()">${S.homeInsightsOpen ? 'Hide' : 'Show'} deeper insights</button>
      </div>
      ${S.homeInsightsOpen ? `<div class="home-insights-wrap">${renderStudyTipsPanel()}</div>` : ''}
    </div>`;
}

function renderExamSuitePage(c) {
  if (!hasPlan('advanced')) {
    c.innerHTML = `
      <div class="card" style="padding:22px;border-color:rgba(184,82,30,.25);background:linear-gradient(180deg,rgba(184,82,30,.06),transparent)">
        <div style="font-size:12px;color:var(--text-muted);font-weight:700;text-transform:uppercase;letter-spacing:.06em">Exam Advantage System</div>
        <h2 style="margin:8px 0 4px;font-size:26px">Advanced feature</h2>
        <p style="color:var(--text-muted);font-size:14px;max-width:580px;line-height:1.55">Upgrade to Advanced or Elite to access Exam Insights. Elite unlocks the full Exam Advantage System — Exam Readiness Score, SG-focused predictions, benchmarking, panic mode, and adaptive exam planning.</p>
        <div style="display:flex;gap:10px;margin-top:14px">
          <button class="btn btn-action" onclick="window.open('/pricing.html','_blank')">View Plans</button>
          <button class="btn btn-secondary" onclick="navigate('home')">Back Home</button>
        </div>
      </div>
    `;
    return;
  }

  if (!hasPlan('elite')) {
    // Advanced plan — Exam Insights (Preview) only
    c.innerHTML = `
      <div style="margin-bottom:12px">
        <h1 style="font-size:30px;font-weight:700;margin:0 0 4px">Exam Insights <span style="font-size:16px;font-weight:600;color:var(--accent);background:rgba(184,82,30,.1);padding:3px 10px;border-radius:999px;vertical-align:middle">Preview</span></h1>
        <div style="font-size:13px;color:var(--text-faint)">Basic analysis — upgrade to Elite to unlock the full Exam Advantage System.</div>
      </div>
      ${renderAdvancedInsightsPreview()}
    `;
    return;
  }

  c.innerHTML = `
    <div style="margin-bottom:12px">
      <h1 style="font-size:30px;font-weight:700;margin:0 0 4px">Exam Advantage System</h1>
      <div style="font-size:13px;color:var(--text-faint)">Elite-only prediction, benchmarking, and exam optimization tools.</div>
    </div>
    ${renderEliteSuite()}
  `;
  elitePublishBenchmarkSnapshots();
  eliteBindGroupBenchmarkRealtime();
}

// ─── CALENDAR ─────────────────────────────────────────────────
const CAL_CATS = [
  { id: 'class', label: 'Class', color: 'blue' },
  { id: 'study', label: 'Study', color: 'purple' },
  { id: 'exam', label: 'Exam', color: 'red' },
  { id: 'work', label: 'Work', color: 'orange' },
  { id: 'personal', label: 'Personal', color: 'green' },
  { id: 'deadline', label: 'Deadline', color: 'red' },
  { id: 'social', label: 'Social', color: 'blue' },
];

function renderCalendar(c) {
  c.innerHTML = `
    <div class="cal-page-hd">
      <h1 style="font-size:32px;font-weight:700;font-family:var(--font-head)">Calendar</h1>
      <div class="cal-page-actions">
        <button class="btn btn-ghost btn-sm" onclick="calToday()">Today</button>
        <div class="cal-tabs">
          <button class="cal-tab${S.calView === 'month' ? ' active' : ''}" onclick="setCalView('month')">Month</button>
          <button class="cal-tab${S.calView === 'week' ? ' active' : ''}" onclick="setCalView('week')">Week</button>
          <button class="cal-tab${S.calView === 'day' ? ' active' : ''}" onclick="setCalView('day')">Day</button>
        </div>
        <button class="btn btn-action btn-sm cal-add-event-btn" onclick="openCalEventModal()">${icons.plus} Event</button>
      </div>
    </div>
    <div class="cal-layout">
      <div>
        <div class="cal-toolbar">
          <button class="icon-btn" onclick="calNav(-1)">${icons.prev}</button>
          <h2 id="cal-title" class="cal-nav-title"></h2>
          <button class="icon-btn" onclick="calNav(1)">${icons.next}</button>
        </div>
        <div id="cal-body"></div>
      </div>
      <div class="cal-sidebar-col">
        <div class="agenda-panel">
          <div class="agenda-hd">Upcoming</div>
          <div id="agenda-body"></div>
        </div>
        <div class="agenda-panel" style="margin-top:14px">
          <div class="agenda-hd">Categories</div>
          <div class="cal-legend" id="cal-legend"></div>
        </div>
      </div>
    </div>`;
  drawCal(); drawAgenda(); drawCalLegend();
}

function drawCalLegend() {
  const el = document.getElementById('cal-legend'); if (!el) return;
  const now = new Date(); const yr = now.getFullYear(), mo = now.getMonth();
  const monthEvs = S.calendar.filter(e => { const d = new Date(e.date + 'T12:00:00'); return d.getFullYear() === yr && d.getMonth() === mo; });
  el.innerHTML = CAL_CATS.map(cat => {
    const cnt = monthEvs.filter(e => (e.category || 'class') === cat.id).length;
    return `<div class="cal-legend-item"><span class="cal-legend-dot" style="background:var(--${cat.color})"></span><span>${cat.label}</span><span class="cal-legend-cnt">${cnt}</span></div>`;
  }).join('');
}

function calToday() {
  S.calDate = new Date(); S.calSelectedDay = new Date().toISOString().split('T')[0];
  drawCal(); drawAgenda(); drawCalLegend();
}

function setCalView(v) {
  S.calView = v;
  if (v === 'day' && !S.calSelectedDay) S.calSelectedDay = S.calDate.toISOString().split('T')[0];
  renderContent();
}

function calNav(d) {
  if (S.calView === 'month') S.calDate = new Date(S.calDate.getFullYear(), S.calDate.getMonth() + d, 1);
  else if (S.calView === 'week') S.calDate = new Date(S.calDate.getTime() + d * 7 * 86400000);
  else {
    const cur = new Date((S.calSelectedDay || S.calDate.toISOString().split('T')[0]) + 'T12:00:00');
    cur.setDate(cur.getDate() + d); S.calSelectedDay = cur.toISOString().split('T')[0]; S.calDate = cur;
  }
  drawCal(); drawAgenda();
}

function drawCal() {
  const title = $('cal-title'); const body = $('cal-body'); if (!title || !body) return;
  const d = S.calDate, todayStr = new Date().toISOString().split('T')[0];

  if (S.calView === 'month') {
    const yr = d.getFullYear(), mo = d.getMonth();
    const firstDay = new Date(yr, mo, 1).getDay(), daysInMonth = new Date(yr, mo + 1, 0).getDate(), daysInPrev = new Date(yr, mo, 0).getDate();
    title.textContent = d.toLocaleDateString('en-US', { month: 'long', year: 'numeric' });
    let html = '<div class="cal-grid"><div class="cal-day-names">';
    ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'].forEach(n => html += `<div>${n}</div>`);
    html += '</div><div class="cal-cells">';
    for (let i = 0; i < firstDay; i++) html += `<div class="cal-cell other">${daysInPrev - firstDay + 1 + i}</div>`;
    for (let day = 1; day <= daysInMonth; day++) {
      const ds = `${yr}-${String(mo + 1).padStart(2, '0')}-${String(day).padStart(2, '0')}`;
      const isToday = ds === todayStr, isPast = ds < todayStr;
      const evs = S.calendar.filter(e => e.date === ds).sort((a, b) => (a.time || '') > (b.time || '') ? 1 : -1);
      const dueTasks = S.tasks.filter(t => t.due === ds && !t.completed);
      const total = evs.length + dueTasks.length;
      html += `<div class="cal-cell${isToday ? ' today' : ''}${isPast ? ' past' : ''}" onclick="calDayClick('${ds}')">
        <div class="cal-day-num${isToday ? ' today' : ''}">${day}</div>
        ${evs.slice(0, 2).map(e => `<div class="cal-ev ev-${e.color || (CAL_CATS.find(c => c.id === (e.category || 'class')) || CAL_CATS[0]).color}" onclick="event.stopPropagation();openCalEventModal('${ds}','','','${e.id}')" title="${esc(e.title)}">${e.time ? '<span class=\'cal-ev-time\'>' + e.time + '</span> ' : ''}<span class=\'cal-ev-text\'>${esc(e.title)}</span></div>`).join('')}
        ${evs.length < 2 ? dueTasks.slice(0, 2 - evs.length).map(t => `<div class="cal-ev cal-ev-task" title="${t.title}">• ${esc(t.title)}</div>`).join('') : ''}
        ${total > 2 ? `<div class="cal-ev-more">+${total - 2} more</div>` : ''}
      </div>`;
    }
    const rem = 42 - firstDay - daysInMonth;
    for (let i = 1; i <= rem; i++) html += `<div class="cal-cell other">${i}</div>`;
    html += '</div></div>'; body.innerHTML = html;

  } else if (S.calView === 'week') {
    const sow = new Date(d); sow.setDate(d.getDate() - d.getDay());
    const days = Array.from({ length: 7 }, (_, i) => { const day = new Date(sow); day.setDate(sow.getDate() + i); return day; });
    title.textContent = `${days[0].toLocaleDateString('en-US', { month: 'short', day: 'numeric' })} – ${days[6].toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' })}`;
    let html = '<div class="week-grid">';
    days.forEach(day => {
      const ds = day.toISOString().split('T')[0];
      const isToday = ds === todayStr;
      const evs = S.calendar.filter(e => e.date === ds).sort((a, b) => (a.time || '') > (b.time || '') ? 1 : -1);
      const dueTasks = S.tasks.filter(t => t.due === ds && !t.completed);
      html += `<div class="week-col${isToday ? ' today' : ''}">
        <div class="week-head" onclick="calDayClick('${ds}')" style="cursor:pointer">
          <div class="week-day-name">${day.toLocaleDateString('en-US', { weekday: 'short' })}</div>
          <div class="week-day-num${isToday ? ' today' : ''}">${day.getDate()}</div>
        </div>
        <div class="week-evs">
          ${evs.map(e => `<div class="week-ev ev-${e.color || 'blue'}" onclick="openCalEventModal('${ds}','','','${e.id}')">${e.time ? `<span class="wev-time">${e.time}</span> ` : ''}${esc(e.title)}</div>`).join('')}
          ${dueTasks.map(t => `<div class="week-ev week-ev-task">• ${esc(t.title)}</div>`).join('')}
          <div class="week-add-btn" onclick="openCalEventModal('${ds}')">${icons.plus}</div>
        </div>
      </div>`;
    });
    html += '</div>'; body.innerHTML = html;

  } else { // day view
    if (!S.calSelectedDay) S.calSelectedDay = todayStr;
    const ds = S.calSelectedDay;
    const dayDate = new Date(ds + 'T12:00:00');
    title.textContent = dayDate.toLocaleDateString('en-US', { weekday: 'long', month: 'long', day: 'numeric', year: 'numeric' });
    const evs = S.calendar.filter(e => e.date === ds).sort((a, b) => (a.time || '00:00') > (b.time || '00:00') ? 1 : -1);
    const dueTasks = S.tasks.filter(t => t.due === ds);
    const allDay = evs.filter(e => !e.time), timed = evs.filter(e => e.time);
    let html = '<div class="day-view">';
    if (allDay.length || dueTasks.length) {
      html += `<div class="day-allday-row"><div class="day-slot-lbl">All day</div><div class="day-slot-body">
        ${allDay.map(e => `<div class="day-ev ev-${e.color || 'blue'}" onclick="openCalEventModal('${e.date}','','','${e.id}')">${esc(e.title)}${e.description ? ' · ' + esc(e.description) : ''}</div>`).join('')}
        ${dueTasks.map(t => `<div class="day-ev day-ev-task"><span class="day-task-chk" onclick="event.stopPropagation();toggleTask('${t.id}')">${t.completed ? icons.ok : ''}</span>${t.title}${t.completed ? ' (done)' : ''}</div>`).join('')}
      </div></div>`;
    }
    for (let h = 6; h <= 22; h++) {
      const hLabel = h === 12 ? '12 PM' : h < 12 ? h + ' AM' : (h - 12) + ' PM';
      const hourEvs = timed.filter(e => parseInt(e.time.split(':')[0]) === h);
      html += `<div class="day-slot${hourEvs.length ? ' day-slot-busy' : ''}" onclick="openCalEventModal('${ds}','${String(h).padStart(2, '0')}:00')">
        <div class="day-slot-lbl">${hLabel}</div>
        <div class="day-slot-body">
          ${hourEvs.map(e => `<div class="day-ev ev-${e.color || 'blue'}" onclick="event.stopPropagation();openCalEventModal('${e.date}','','','${e.id}')">${esc(e.time)} · ${esc(e.title)}${e.description ? ' — ' + esc(e.description) : ''}</div>`).join('')}
        </div>
      </div>`;
    }
    html += '</div>'; body.innerHTML = html;
  }
}

function calDayClick(ds) {
  S.calSelectedDay = ds; S.calDate = new Date(ds + 'T12:00:00');
  if (S.calView !== 'day') { S.calView = 'day'; renderContent(); } else drawCal();
}

function drawAgenda() {
  const body = $('agenda-body'); if (!body) return;
  const today = new Date().toISOString().split('T')[0];
  const tomorrow = new Date(Date.now() + 86400000).toISOString().split('T')[0];
  const groups = {};
  const all = [...S.calendar.filter(e => e.date >= today), ...S.tasks.filter(t => !t.completed && t.due && t.due >= today).map(t => ({ ...t, _isTask: true, date: t.due }))]
    .sort((a, b) => { if (a.date !== b.date) return a.date > b.date ? 1 : -1; return (a.time || '') > (b.time || '') ? 1 : -1; });
  all.forEach(e => { if (!groups[e.date]) groups[e.date] = []; groups[e.date].push(e); });
  let html = '';
  Object.entries(groups).slice(0, 10).forEach(([date, items]) => {
    const dt = new Date(date + 'T12:00:00');
    const isToday = date === today, isTomorrow = date === tomorrow;
    const dayLbl = isToday ? 'Today' : isTomorrow ? 'Tomorrow' : dt.toLocaleDateString('en-US', { weekday: 'short', month: 'short', day: 'numeric' });
    html += `<div class="agenda-date${isToday ? ' agenda-date-today' : ''}">${dayLbl}</div>`;
    items.forEach(item => {
      const cat = !item._isTask && CAL_CATS.find(c => c.id === (item.category || 'class'));
      const dotColor = item._isTask ? 'blue' : item.color || (cat?.color || 'blue');
      const agClick = item._isTask ? '' : ("openCalEventModal('" + item.date + "','" + (item.time || '') + "','" + (item.color || '') + "','" + item.id + "')");
      html += '<div class="agenda-ev" onclick="' + agClick + '">';
      html += `<div class="agenda-ev-dot" style="background:var(--${dotColor})"></div>`;
      html += `<div class="agenda-ev-body"><div class="agenda-ev-title">${esc(item.title)}${item._isTask ? '<span class="agenda-task-pill">task</span>' : ''}</div>`;
      const meta = [item.time, cat && !item._isTask ? cat.label : ''].filter(Boolean).join(' · ');
      if (meta) html += `<div class="agenda-ev-sub">${meta}</div>`;
      html += '</div></div>';
    });
  });
  body.innerHTML = html || '<div class="agenda-empty">Nothing upcoming</div>';
}

function openCalEventModal(date = '', time = '', color = '', editId = '') {
  closeCalEventModal(); S.editEvId = editId || null; S.evColor = color || 'red';
  let ev = null;
  if (editId) { ev = S.calendar.find(e => e.id === editId); if (ev) { date = ev.date; time = ev.time || ''; S.evColor = ev.color || 'red'; } }
  const curCat = ev?.category || 'class', curRepeat = ev?.repeat || 'none';
  const bg = el('div', 'modal-bg'); bg.id = 'ev-modal-bg';
  bg.innerHTML = `
    <div class="modal cal-event-modal" style="width:520px;max-width:96vw">
      <div class="modal-title">${editId ? 'Edit Event' : 'New Event'}</div>
      <div class="form-group"><label class="form-label">Title</label>
        <input id="ev-title" class="form-input" placeholder="Event title" value="${esc(ev?.title || '')}"></div>
      <div class="cal-event-modal-grid">
        <div class="form-group"><label class="form-label">Date</label>
          <input id="ev-date" type="date" class="form-input cal-modal-picker" value="${date || new Date().toISOString().split('T')[0]}"></div>
        <div class="form-group"><label class="form-label">Time <span style="color:var(--text-faint);font-weight:400">(optional)</span></label>
          <input id="ev-time" type="time" class="form-input cal-modal-picker" value="${time || ''}"></div>
      </div>
      <div class="form-group"><label class="form-label">Description</label>
        <input id="ev-desc" class="form-input" placeholder="Optional…" value="${esc(ev?.description || '')}"></div>
      <div class="form-group"><label class="form-label">Tags <span style="color:var(--text-faint);font-weight:400">(comma-separated, use "exam" for exam events)</span></label>
        <input id="ev-tags" class="form-input" placeholder="e.g. exam, chemistry, prelim" value="${esc(Array.isArray(ev?.tags) ? ev.tags.join(', ') : (ev?.tags || ''))}"></div>
      <div class="cal-event-modal-grid">
        <div class="form-group"><label class="form-label">Category</label>
          <select id="ev-cat" class="form-input">
            ${CAL_CATS.map(cat => `<option value="${cat.id}"${curCat === cat.id ? ' selected' : ''}>${cat.label}</option>`).join('')}
          </select>
        </div>
        <div class="form-group"><label class="form-label">Repeat</label>
          <select id="ev-repeat" class="form-input">
            <option value="none"${curRepeat === 'none' ? ' selected' : ''}>No repeat</option>
            <option value="daily"${curRepeat === 'daily' ? ' selected' : ''}>Daily</option>
            <option value="weekly"${curRepeat === 'weekly' ? ' selected' : ''}>Weekly</option>
            <option value="monthly"${curRepeat === 'monthly' ? ' selected' : ''}>Monthly</option>
            <option value="yearly"${curRepeat === 'yearly' ? ' selected' : ''}>Yearly</option>
          </select>
        </div>
      </div>
      <div class="form-group"><label class="form-label">Color</label>
        <div class="color-swatches" id="ev-swatches">
          ${['red', 'orange', 'green', 'blue', 'purple'].map(c => `<div class="swatch sw-${c}${S.evColor === c ? ' sel' : ''}" data-color="${c}" onclick="pickEvColor('${c}')"></div>`).join('')}
        </div>
      </div>
      <div class="modal-foot">
        <button class="btn btn-ghost btn-sm" onclick="closeCalEventModal()">Cancel</button>
        ${editId ? `<button class="btn btn-danger btn-sm" onclick="deleteCalEvent('${editId}')">Delete</button>` : ''}
        <button class="btn btn-action btn-sm" onclick="saveCalEvent()">Save</button>
      </div>
    </div>`;
  bg.addEventListener('click', e => { if (e.target === bg) closeCalEventModal(); });
  document.body.appendChild(bg);
  requestAnimationFrame(() => bg.classList.add('show'));
  setTimeout(() => $('ev-title')?.focus(), 100);
}

function closeCalEventModal() { $('ev-modal-bg')?.remove(); }
function pickEvColor(c) { S.evColor = c; document.querySelectorAll('#ev-swatches .swatch').forEach(s => s.classList.toggle('sel', s.dataset.color === c)); }

function showDeleteConfirmModal(opts = {}) {
  const { title = 'Delete item?', message = 'This cannot be undone.', confirmLabel = 'Delete', onConfirm = '' } = opts;
  document.getElementById('delete-confirm-modal')?.remove();
  const bg = el('div', 'modal-bg show');
  bg.id = 'delete-confirm-modal';
  bg.innerHTML = `
    <div class="modal" style="max-width:430px">
      <div class="modal-title" style="display:flex;align-items:center;gap:8px;color:var(--red)">
        ${icons.trash} ${esc(title)}
      </div>
      <div style="font-size:13.5px;color:var(--text-muted);line-height:1.6">${esc(message)}</div>
      <div class="modal-foot">
        <button class="btn btn-ghost btn-sm" onclick="document.getElementById('delete-confirm-modal')?.remove()">Cancel</button>
        <button class="btn btn-danger btn-sm" onclick="${onConfirm};document.getElementById('delete-confirm-modal')?.remove()">${esc(confirmLabel)}</button>
      </div>
    </div>`;
  bg.addEventListener('click', e => { if (e.target === bg) bg.remove(); });
  document.body.appendChild(bg);
}

async function saveCalEvent() {
  const title = $('ev-title')?.value.trim(), date = $('ev-date')?.value;
  if (!title || !date) return toast('Fill in title and date');
  const rawTags = $('ev-tags')?.value || '';
  const tags = Array.from(new Set(rawTags.split(',').map(t => t.trim().toLowerCase()).filter(Boolean))).slice(0, 12);
  const evData = {
    title, date, time: $('ev-time')?.value || '', description: $('ev-desc')?.value || '', color: S.evColor,
    category: $('ev-cat')?.value || 'class', repeat: $('ev-repeat')?.value || 'none', tags
  };
  if (S.editEvId) {
    const ev = S.calendar.find(e => e.id === S.editEvId); if (ev) { Object.assign(ev, evData); await saveData('calendar', { [ev.id]: ev }); }
  } else {
    const id = uid(), ev = { id, ...evData }; S.calendar.push(ev); await saveData('calendar', { [id]: ev });
  }
  closeCalEventModal(); toast(S.editEvId ? 'Event updated' : 'Event created'); renderContent();
}

async function deleteCalEvent(id) {
  S.calendar = S.calendar.filter(e => e.id !== id); await delData('calendar/' + id);
  closeCalEventModal(); toast('Event deleted'); renderContent();
}

// ─── TASKS ────────────────────────────────────────────────────
function renderTasks(c) {
  S.taskView = S.taskView || 'kanban';
  const today = new Date().toISOString().split('T')[0];
  const pc = { high: S.tasks.filter(t => !t.completed && t.priority === 'high').length, med: S.tasks.filter(t => !t.completed && t.priority === 'med').length, low: S.tasks.filter(t => !t.completed && t.priority === 'low').length };
  const overdueCnt = S.tasks.filter(t => !t.completed && t.due && t.due < today).length;
  const tp = S._taskPriFilter || '';
  const td = S._taskDueFilter || '';

  const priPill = (val, label, color, bgVar) =>
    `<button class="task-filter-pill${tp===val?' active':''}" style="${tp===val?`background:color-mix(in srgb,${color} 18%,transparent);color:${color};border-color:${color};`:`color:var(--text-muted);`}" onclick="S._taskPriFilter=S._taskPriFilter==='${val}'?'':'${val}';renderContent()">
      <span class="task-filter-dot" style="background:${color}"></span>${label}
      <span class="task-filter-cnt">${pc[val]}</span>
    </button>`;

  const datePill = (val, label) =>
    `<button class="task-filter-pill${td===val?' active':''}" onclick="S._taskDueFilter=S._taskDueFilter==='${val}'?'':'${val}';renderContent()">${label}</button>`;

  c.innerHTML = `
    <div class="tasks-topbar">
      <div class="tasks-title-row">
        <h1 class="page-title-el">Tasks</h1>
        ${overdueCnt ? `<span class="task-overdue-badge">${overdueCnt} overdue</span>` : ''}
      </div>
      <div class="tasks-actions">
        <div class="view-switcher">
          <button class="view-sw-btn${S.taskView==='kanban'?' on':''}" onclick="setTaskView('kanban')">
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><rect x="3" y="3" width="6" height="14" rx="1.5"/><rect x="11" y="3" width="6" height="9" rx="1.5"/><rect x="19" y="3" width="0" height="0"/><rect x="11" y="14" width="6" height="7" rx="1.5"/><rect x="19" y="7" width="0" height="0"/></svg>
            Board
          </button>
          <button class="view-sw-btn${S.taskView==='list'?' on':''}" onclick="setTaskView('list')">
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><line x1="8" y1="6" x2="21" y2="6"/><line x1="8" y1="12" x2="21" y2="12"/><line x1="8" y1="18" x2="21" y2="18"/><circle cx="3" cy="6" r="1.5" fill="currentColor" stroke="none"/><circle cx="3" cy="12" r="1.5" fill="currentColor" stroke="none"/><circle cx="3" cy="18" r="1.5" fill="currentColor" stroke="none"/></svg>
            List
          </button>
          <button class="view-sw-btn${S.taskView==='table'?' on':''}" onclick="setTaskView('table')">
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><rect x="3" y="3" width="18" height="18" rx="2"/><line x1="3" y1="9" x2="21" y2="9"/><line x1="3" y1="15" x2="21" y2="15"/><line x1="9" y1="3" x2="9" y2="21"/></svg>
            Table
          </button>
        </div>
        <button class="btn btn-action btn-sm" onclick="addTask()">${icons.plus} New Task</button>
        ${(S.tasks.filter(t => t.completed || !t.title?.trim()).length > 0) ? `<button class="btn btn-ghost btn-sm" style="color:var(--red);border-color:var(--red);opacity:.8" onclick="confirmClearDoneTasks()" title="Remove completed & empty ghost tasks">${icons.trash} Clear Done</button>` : ''}
      </div>
    </div>

    <div class="tasks-filter-bar">
      <div class="task-search-wrap">
        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
        <input id="task-search-inp" class="task-search-inp" placeholder="Search tasks…" value="${esc(S._taskSearch||'')}" oninput="filterTasksSearch(this.value)">
        ${S._taskSearch ? `<button class="task-search-clear" onclick="S._taskSearch='';renderContent()">✕</button>` : ''}
      </div>
      <div class="task-filter-group">
        <span class="task-filter-label">Priority</span>
        ${priPill('high','High','var(--red)','var(--red)')}
        ${priPill('med','Med','var(--orange)','var(--orange)')}
        ${priPill('low','Low','var(--green)','var(--green)')}
      </div>
      <div class="task-filter-group">
        <span class="task-filter-label">Date</span>
        ${datePill('overdue','Overdue')}
        ${datePill('today','Today')}
        ${datePill('week','This week')}
        ${datePill('nodue','No date')}
      </div>
      ${(S._taskSearch||tp||td) ? `<button class="task-clear-all" onclick="clearTaskFilters()">Clear all</button>` : ''}
    </div>

    <div id="tasks-body"></div>`;
  renderTasksBody();
}

function filterTasksSearch(v) { S._taskSearch = v; renderTasksBody(); }
function filterTasksByPriority(p) { S._taskPriFilter = p; S._taskDueFilter = ''; renderContent(); }
function filterOverdueTasks() { S._taskDueFilter = 'overdue'; S._taskPriFilter = ''; renderContent(); }
function clearTaskFilters() { S._taskSearch = ''; S._taskPriFilter = ''; S._taskDueFilter = ''; renderContent(); }

function getFilteredTasks(includeCompleted = false) {
  const today = new Date().toISOString().split('T')[0];
  const weekEnd = new Date(); weekEnd.setDate(weekEnd.getDate() + 7);
  const weekStr = weekEnd.toISOString().split('T')[0];
  let tasks = S.tasks.filter(t => includeCompleted ? true : true);
  const q = (S._taskSearch || '').toLowerCase();
  if (q) tasks = tasks.filter(t => (t.title || '').toLowerCase().includes(q));
  if (S._taskPriFilter) tasks = tasks.filter(t => (t.priority || 'med') === S._taskPriFilter);
  if (S._taskDueFilter === 'overdue') tasks = tasks.filter(t => !t.completed && t.due && t.due < today);
  else if (S._taskDueFilter === 'today') tasks = tasks.filter(t => t.due === today);
  else if (S._taskDueFilter === 'week') tasks = tasks.filter(t => t.due && t.due >= today && t.due <= weekStr);
  else if (S._taskDueFilter === 'nodue') tasks = tasks.filter(t => !t.due);
  return tasks;
}

function setTaskView(v) { S.taskView = v; renderContent(); }

function renderTasksBody() {
  const body = $('tasks-body'); if (!body) return;
  if (S.taskView === 'list') renderListView(body);
  else if (S.taskView === 'table') renderTableView(body);
  else renderKanbanView(body);
}

function renderListView(body) {
  const filtered = getFilteredTasks();
  const act = filtered.filter(t => !t.completed), done = filtered.filter(t => t.completed);
  body.innerHTML = `
    ${act.length ? `<div class="sec-header">Active (${act.length})</div>${act.map(t => taskRow(t)).join('')}` :
      `<div class="empty"><div class="empty-icon">${icons.check}</div><div class="empty-title">No tasks found</div></div>`}
    ${done.length ? `<div class="sec-header" style="margin-top:24px">Completed (${done.length})</div>${done.map(t => taskRow(t)).join('')}` : ''}`;
}

function renderTableView(body) {
  const today = new Date().toISOString().split('T')[0];
  const filtered = getFilteredTasks();
  const sorted = [...filtered].sort((a, b) => {
    const pa = a.priority === 'high' ? 0 : a.priority === 'med' ? 1 : 2;
    const pb = b.priority === 'high' ? 0 : b.priority === 'med' ? 1 : 2;
    if (pa !== pb) return pa - pb;
    return (a.due || 'z') < (b.due || 'z') ? -1 : 1;
  });
  if (!sorted.length) { body.innerHTML = `<div class="empty"><div class="empty-icon">${icons.check}</div><div class="empty-title">No tasks found</div></div>`; return; }
  const notePage = (t) => S.pages.find(pg => pg.id === t.noteId || pg.blocks?.some(b => b.id === t.id));
  body.innerHTML = `<div style="overflow-x:auto"><table class="task-table">
    <thead><tr><th style="width:32px"></th><th>Title</th><th>Priority</th><th>Status</th><th>Due</th><th>Note</th><th style="width:36px"></th></tr></thead>
    <tbody>${sorted.map(t => {
      const pg = notePage(t);
      const od = !t.completed && t.due && t.due < today;
      return `<tr class="${t.completed ? 'task-table-done' : ''}">
        <td><div class="task-chk${t.completed ? ' on' : ''}" onclick="toggleTask('${t.id}')"></div></td>
        <td><div class="task-lbl" contenteditable="${!t.completed}" spellcheck="false" onblur="updateTaskTitle('${t.id}',this.textContent)">${esc(t.title)}</div></td>
        <td><select class="task-table-sel" onchange="updateTaskPriority('${t.id}',this.value)">
          <option value="low"${t.priority==='low'?' selected':''}>Low</option>
          <option value="med"${!t.priority||t.priority==='med'?' selected':''}>Med</option>
          <option value="high"${t.priority==='high'?' selected':''}>High</option>
        </select></td>
        <td><select class="task-table-sel" onchange="moveTask('${t.id}',this.value)">
          <option value="todo"${!t.status||t.status==='todo'?' selected':''}>To Do</option>
          <option value="prog"${t.status==='prog'?' selected':''}>In Progress</option>
          <option value="done"${t.status==='done'||t.completed?' selected':''}>Done</option>
        </select></td>
        <td><input type="date" class="task-table-date${od?' late':''}" value="${t.due||''}" onchange="updateTaskDate('${t.id}',this.value)"></td>
        <td>${pg ? `<button class="btn btn-ghost btn-sm" onclick="openPage('${pg.id}')" style="font-size:11px;padding:1px 5px"> ${esc(pg.title||'Note')}</button>` : '<span style="color:var(--text-faint);font-size:12px">—</span>'}</td>
        <td><button class="icon-btn" onclick="deleteTask('${t.id}')" style="width:22px;height:22px;color:var(--red)">${icons.trash}</button></td>
      </tr>`;
    }).join('')}</tbody></table></div>`;
}
function taskRow(t) {
  const pri = t.priority || 'med';
  const priLabel = pri === 'high' ? 'High' : pri === 'low' ? 'Low' : 'Med';
  return `<div class="task-row${t.completed ? ' done' : ''}">
    <div class="task-chk${t.completed ? ' on' : ''}" onclick="toggleTask('${t.id}')"></div>
    <div class="task-lbl" contenteditable="${!t.completed}" spellcheck="false" onblur="updateTaskTitle('${t.id}',this.textContent)">${esc(t.title)}</div>
    ${t.priority ? `<span class="task-pri-badge ${pri}">${priLabel}</span>` : ''}
    ${t.due ? `<span class="task-due${overdue(t.due) && !t.completed ? ' late' : ''}"> ${fmt(t.due)}</span>` : ''}
    <button class="icon-btn task-del-btn" onclick="deleteTask('${t.id}')" title="Delete task">${icons.trash}</button>
  </div>`;
}

function renderKanbanView(body) {
  const _ft = getFilteredTasks();
  const cols = [
    { id: 'todo', cls: 'k-todo', label: 'To Do', tasks: _ft.filter(t => (t.status === 'todo' || !t.status) && !t.completed) },
    { id: 'prog', cls: 'k-prog', label: 'In Progress', tasks: _ft.filter(t => t.status === 'prog') },
    { id: 'done', cls: 'k-done', label: 'Done', tasks: _ft.filter(t => t.status === 'done' || t.completed) }
  ];
  body.innerHTML = `<div class="kanban">${cols.map(col => `
    <div class="k-col ${col.cls}">
      <div class="k-head"><div class="dot"></div><div class="k-label">${col.label}</div><div class="k-cnt">${col.tasks.length}</div></div>
      <div class="k-cards">
        ${col.tasks.map(t => `
          <div class="k-card">
            <div class="k-card-title" contenteditable="true" spellcheck="false" onblur="updateTaskTitle('${t.id}',this.textContent)">${esc(t.title)}</div>
            <div class="k-card-foot">
              <select class="task-kanban-sel" onchange="updateTaskPriority('${t.id}',this.value)">
                <option value="low" ${t.priority === 'low' ? 'selected' : ''}>Low</option>
                <option value="med" ${t.priority === 'med' || !t.priority ? 'selected' : ''}>Med</option>
                <option value="high" ${t.priority === 'high' ? 'selected' : ''}>High</option>
              </select>
              <input type="date" class="task-kanban-date" value="${t.due || ''}" onchange="updateTaskDate('${t.id}',this.value)">
              <div style="display:flex;gap:3px;margin-left:auto">
                ${col.id !== 'todo' ? `<button class="icon-btn" onclick="moveTask('${t.id}','${col.id === 'prog' ? 'todo' : 'prog'}')" style="width:22px;height:22px" title="Move Back">${icons.prev}</button>` : ''}
                ${col.id !== 'done' ? `<button class="icon-btn" onclick="moveTask('${t.id}','${col.id === 'todo' ? 'prog' : 'done'}')" style="width:22px;height:22px" title="Move Forward">${icons.next}</button>` : ''}
                <button class="icon-btn" onclick="deleteTask('${t.id}')" style="width:22px;height:22px" title="Delete Task">${icons.trash}</button>
              </div>
            </div>
            ${S.pages.find(p => p.blocks?.some(b => b.id === t.id)) ? `<div style="font-size:10px;margin-top:6px;color:var(--accent);cursor:pointer" onclick="openPage('${S.pages.find(p => p.blocks?.some(b => b.id === t.id)).id}')">↗ From Note: ${esc(S.pages.find(p => p.blocks?.some(b => b.id === t.id)).title || 'Untitled')}</div>` : ''}
          </div>`).join('')}
      </div>
      <button class="k-add" onclick="addTask('${col.id}')">${icons.plus} ${col.id === 'done' ? 'Log task' : 'Add task'}</button>
    </div>`).join('')}</div>`;
}

// Global functions for task metadata
async function updateTaskPriority(id, p) { const t = S.tasks.find(t => t.id === id); if (!t) return; t.priority = p; await saveData('tasks', { [id]: t }); }
async function updateTaskDate(id, d) { const t = S.tasks.find(t => t.id === id); if (!t) return; t.due = d; await saveData('tasks', { [id]: t }); }

function closeTaskCreateModal() {
  document.getElementById('task-create-modal')?.remove();
}

function addTask(status = 'todo') {
  closeTaskCreateModal();
  const bg = el('div', 'modal-bg show');
  bg.id = 'task-create-modal';
  bg.innerHTML = `
    <div class="modal cal-event-modal" style="width:500px;max-width:96vw">
      <div class="modal-title">New Task</div>
      <div class="form-group">
        <label class="form-label">Task name</label>
        <input id="task-new-title" class="form-input" placeholder="e.g. Revise chapter 4">
      </div>
      <div class="cal-event-modal-grid">
        <div class="form-group">
          <label class="form-label">Due date <span style="color:var(--text-faint);font-weight:400">(optional)</span></label>
          <input id="task-new-due" type="date" class="form-input cal-modal-picker">
        </div>
        <div class="form-group">
          <label class="form-label">Priority</label>
          <select id="task-new-priority" class="form-input">
            <option value="low">Low</option>
            <option value="med" selected>Med</option>
            <option value="high">High</option>
          </select>
        </div>
      </div>
      <div class="form-group">
        <label class="form-label">Status</label>
        <select id="task-new-status" class="form-input">
          <option value="todo"${status === 'todo' ? ' selected' : ''}>To Do</option>
          <option value="prog"${status === 'prog' ? ' selected' : ''}>In Progress</option>
          <option value="done"${status === 'done' ? ' selected' : ''}>Done</option>
        </select>
      </div>
      <div class="modal-foot">
        <button class="btn btn-ghost btn-sm" onclick="closeTaskCreateModal()">Cancel</button>
        <button class="btn btn-action btn-sm" onclick="saveNewTaskFromModal()">Create Task</button>
      </div>
    </div>`;
  bg.addEventListener('click', e => { if (e.target === bg) closeTaskCreateModal(); });
  document.body.appendChild(bg);
  setTimeout(() => document.getElementById('task-new-title')?.focus(), 20);
}

async function saveNewTaskFromModal() {
  const title = (document.getElementById('task-new-title')?.value || '').trim();
  if (!title) return toast('Task name is required');
  const status = document.getElementById('task-new-status')?.value || 'todo';
  const id = uid();
  const t = {
    id,
    title,
    completed: status === 'done',
    status,
    priority: document.getElementById('task-new-priority')?.value || 'med',
    due: document.getElementById('task-new-due')?.value || '',
    createdAt: new Date().toISOString()
  };
  S.tasks.push(t);
  await saveData('tasks', { [id]: t });
  closeTaskCreateModal();
  renderContent();
}

async function toggleTask(id) { const t = S.tasks.find(t => t.id === id); if (!t) return; t.completed = !t.completed; t.status = t.completed ? 'done' : 'todo'; await saveData('tasks', { [id]: t }); renderContent(); }
async function updateTaskTitle(id, title) { const t = S.tasks.find(t => t.id === id); if (!t) return; t.title = title.trim() || 'Untitled'; await saveData('tasks', { [id]: t }); }
async function moveTask(id, newStatus) { const t = S.tasks.find(t => t.id === id); if (!t) return; t.status = newStatus; t.completed = newStatus === 'done'; await saveData('tasks', { [id]: t }); renderContent(); }
async function deleteTask(id) { S.tasks = S.tasks.filter(t => t.id !== id); await delData('tasks/' + id); renderContent(); }

function confirmClearDoneTasks() {
  const doneTasks = S.tasks.filter(t => t.completed);
  const ghostTasks = S.tasks.filter(t => !t.completed && !t.title?.trim());
  const total = doneTasks.length + ghostTasks.length;
  if (total === 0) { toast('No tasks to clear!'); return; }
  const msg = [
    doneTasks.length ? `${doneTasks.length} completed task${doneTasks.length>1?'s':''}` : '',
    ghostTasks.length ? `${ghostTasks.length} empty/ghost task${ghostTasks.length>1?'s':''}` : ''
  ].filter(Boolean).join(' and ');
  if (confirm(`Delete ${msg}? This cannot be undone.`)) clearDoneAndGhostTasks();
}

async function clearDoneAndGhostTasks() {
  const toDelete = S.tasks.filter(t => t.completed || !t.title?.trim());
  if (!toDelete.length) { toast('Nothing to clear.'); return; }
  S.tasks = S.tasks.filter(t => !t.completed && t.title?.trim());
  // Delete from Firebase in parallel
  await Promise.all(toDelete.map(t => delData('tasks/' + t.id).catch(() => {})));
  toast(`Cleared ${toDelete.length} task${toDelete.length>1?'s':''}. Won't auto-clear again.`);
  renderContent();
}

// ─── TASK BLOCKS IN NOTES ─────────────────────────────────────
async function toggleTaskBlock(blockId) {
  if (!S.page) return;
  const b = S.page.blocks?.find(b => b.id === blockId);
  if (!b) return;
  if (b.taskId) {
    // Toggle the linked task
    const t = S.tasks.find(t => t.id === b.taskId);
    if (t) {
      t.completed = !t.completed;
      t.status = t.completed ? 'done' : 'todo';
      await saveData('tasks', { [b.taskId]: t });
    }
  }
  scheduleSave();
  renderBlocks();
}

function openTaskBlockOptions(blockId, e) {
  e.stopPropagation();
  const existing = document.getElementById('task-block-popup');
  if (existing) { existing.remove(); return; }
  const b = S.page?.blocks?.find(b => b.id === blockId);
  if (!b) return;
  const popup = document.createElement('div');
  popup.id = 'task-block-popup';
  popup.className = 'slash-menu';
  popup.style.cssText = 'position:fixed;z-index:9999;min-width:180px;padding:6px 0';
  const rect = e.target.getBoundingClientRect();
  popup.style.left = rect.left + 'px';
  popup.style.top = (rect.bottom + 4) + 'px';
  popup.innerHTML = `
    <div class="slash-item" onclick="convertTaskBlockToGlobal('${blockId}')"> Add to Global Tasks</div>
    <div class="slash-item" onclick="setTaskBlockPriority('${blockId}','high')"> High Priority</div>
    <div class="slash-item" onclick="setTaskBlockPriority('${blockId}','med')">🟡 Medium Priority</div>
    <div class="slash-item" onclick="setTaskBlockPriority('${blockId}','low')">🟢 Low Priority</div>
    <div class="slash-item" onclick="setTaskBlockDue('${blockId}')"> Set Due Date</div>
    <div class="slash-item" style="color:var(--red)" onclick="deleteBlock('${blockId}');document.getElementById('task-block-popup')?.remove()"> Delete</div>`;
  document.body.appendChild(popup);
  setTimeout(() => document.addEventListener('click', () => popup.remove(), { once: true }), 10);
}

async function convertTaskBlockToGlobal(blockId) {
  document.getElementById('task-block-popup')?.remove();
  if (!S.page) return;
  const b = S.page.blocks?.find(b => b.id === blockId);
  if (!b) return;
  // Create or update the real task
  const taskId = b.taskId || uid();
  b.taskId = taskId;
  const existing = S.tasks.find(t => t.id === taskId);
  if (!existing) {
    const task = { id: taskId, title: b.content || 'Task', completed: false, status: 'todo', priority: b.priority || 'med', due: b.due || '', noteId: S.page.id, createdAt: new Date().toISOString() };
    S.tasks.push(task);
    await saveData('tasks', { [taskId]: task });
  }
  scheduleSave(); renderBlocks();
  toast('Task added to Global Tasks ✓');
}

async function setTaskBlockPriority(blockId, pri) {
  document.getElementById('task-block-popup')?.remove();
  if (!S.page) return;
  const b = S.page.blocks?.find(b => b.id === blockId);
  if (!b) return;
  b.priority = pri;
  if (b.taskId) { const t = S.tasks.find(t => t.id === b.taskId); if (t) { t.priority = pri; await saveData('tasks', { [b.taskId]: t }); } }
  scheduleSave(); renderBlocks();
}

function setTaskBlockDue(blockId) {
  document.getElementById('task-block-popup')?.remove();
  if (!S.page) return;
  const b = S.page.blocks?.find(b => b.id === blockId);
  if (!b) return;
  document.getElementById('task-due-modal')?.remove();
  const modal = document.createElement('div');
  modal.className = 'modal-bg';
  modal.id = 'task-due-modal';
  modal.innerHTML = `
    <div class="modal" style="max-width:420px">
      <div class="modal-title">Set Task Due Date</div>
      <div class="form-group">
        <label class="form-label">Due date</label>
        <input id="task-due-input" type="date" class="form-input" value="${esc(b.due || new Date().toISOString().split('T')[0])}">
      </div>
      <div class="modal-foot">
        <button class="btn btn-ghost btn-sm" onclick="closeTaskDueModal()">Cancel</button>
        <button class="btn btn-danger btn-sm" onclick="clearTaskBlockDue('${b.id}')">Clear</button>
        <button class="btn btn-action btn-sm" onclick="saveTaskBlockDue('${b.id}')">Save</button>
      </div>
    </div>`;
  document.body.appendChild(modal);
  setTimeout(() => document.getElementById('task-due-input')?.focus(), 0);
}

function closeTaskDueModal() {
  document.getElementById('task-due-modal')?.remove();
}

async function clearTaskBlockDue(blockId) {
  if (!S.page) return;
  const b = S.page.blocks?.find(x => x.id === blockId);
  if (!b) return;
  b.due = '';
  if (b.taskId) {
    const t = S.tasks.find(x => x.id === b.taskId);
    if (t) {
      t.due = '';
      await saveData('tasks', { [b.taskId]: t });
    }
  }
  closeTaskDueModal();
  scheduleSave();
  renderBlocks();
}

async function saveTaskBlockDue(blockId) {
  if (!S.page) return;
  const b = S.page.blocks?.find(x => x.id === blockId);
  if (!b) return;
  const dateStr = (document.getElementById('task-due-input')?.value || '').trim();
  if (!dateStr) return toast('Pick a due date');
  if (!/^\d{4}-\d{2}-\d{2}$/.test(dateStr)) return toast('Invalid date format');
  b.due = dateStr;
  if (b.taskId) {
    const t = S.tasks.find(x => x.id === b.taskId);
    if (t) {
      t.due = dateStr;
      await saveData('tasks', { [b.taskId]: t });
    }
  }
  closeTaskDueModal();
  scheduleSave();
  renderBlocks();
}

// When task_block is inserted via slash menu, create it properly
async function initTaskBlock(blockId) {
  if (!S.page) return;
  const b = S.page.blocks?.find(b => b.id === blockId);
  if (!b) return;
  b.taskId = uid();
  const task = { id: b.taskId, title: b.content || 'Task', completed: false, status: 'todo', priority: 'med', due: '', noteId: S.page.id, createdAt: new Date().toISOString() };
  S.tasks.push(task);
  await saveData('tasks', { [task.id]: task });
  scheduleSave();
}


function renderFlashdecks(c) {
  c.innerHTML = `
    <h1 class="page-title-el" style="font-size:36px;margin-bottom:20px">Flashcards</h1>
    <div style="display:flex;justify-content:flex-end;margin-bottom:20px">
      <button class="btn btn-action btn-sm" onclick="toggleDeckForm()">${icons.plus} New Deck</button>
    </div>
    <div id="deck-form-wrap" class="inline-form-wrap" style="display:none">
      <div class="inline-form">
        <div class="inline-form-title">New Deck</div>
        <div class="form-group"><label class="form-label">Deck Name</label>
          <input id="deck-name-inp" class="form-input" placeholder="e.g. Biology Chapter 4"></div>
        <div class="modal-foot">
          <button class="btn btn-ghost btn-sm" onclick="toggleDeckForm()">Cancel</button>
          <button class="btn btn-action btn-sm" onclick="submitCreateDeck()">${icons.plus} Create</button>
        </div>
      </div>
    </div>
    ${S.flashcards.length ? `<div class="deck-grid">${S.flashcards.map(d => `
      <div class="deck-card">
        <span class="deck-emoji">${icons[d.icon] || icons.cardIcon}</span>
        <div class="deck-name">${esc(d.title)}</div>
        <div class="deck-count">${(d.cards || []).length} cards</div>
        <div class="deck-actions">
          <button class="btn btn-action btn-sm" onclick="startStudy('${d.id}')">Study</button>
          <button class="btn btn-secondary btn-sm" onclick="openDeckEditor('${d.id}')">${icons.edit}</button>
          <button class="btn btn-ghost btn-sm" onclick="deleteDeck('${d.id}')">${icons.trash}</button>
        </div>
      </div>`).join('')}</div>` :
      `<div class="empty"><div class="empty-icon">${icons.cardIcon}</div><div class="empty-title">No decks yet</div><p class="empty-sub">Create a deck to start studying</p><button class="btn btn-action" onclick="toggleDeckForm()" style="margin-top:14px;width:auto">${icons.plus} Create Deck</button></div>`}`;
  const inp = $('deck-name-inp'); if (inp) inp.addEventListener('keydown', e => { if (e.key === 'Enter') submitCreateDeck(); });
}

function toggleDeckForm() {
  const w = $('deck-form-wrap'); if (!w) return;
  const vis = w.style.display === 'block'; w.style.display = vis ? 'none' : 'block';
  if (!vis) setTimeout(() => $('deck-name-inp')?.focus(), 50);
}

async function submitCreateDeck() {
  const title = $('deck-name-inp')?.value.trim(); if (!title) return toast('Enter a deck name');
  const deckIcons = ['cardIcon', 'bookIcon', 'brainIcon', 'zapIcon', 'flaskIcon', 'rulerIcon', 'globeIcon', 'bulbIcon', 'targetIcon', 'penIcon'];
  const id = uid();
  const d = { id, title, icon: deckIcons[Math.floor(Math.random() * deckIcons.length)], cards: [], createdAt: new Date().toISOString() };
  S.flashcards.push(d); await saveData('flashcards', { [id]: d }); openDeckEditor(id);
}

function openDeckEditor(deckId, options = {}) {
  const { pushHistory = true, replaceHistory = false } = options;
  const deck = S.flashcards.find(d => d.id === deckId); if (!deck) return;
  S.deck = deck; S.page = null; S.view = 'page';
  closeSidebarAfterNavigate();
  syncRouteWithState({ push: pushHistory, replace: replaceHistory });
  const c = $('main-content'); if (!c) { renderApp(); return; }
  c.innerHTML = `
    <div style="display:flex;align-items:center;gap:10px;margin-bottom:6px">
      <button class="icon-btn" onclick="navigate('flashcards')">${icons.back}</button>
      <h1 style="font-size:32px;font-weight:700;display:flex;align-items:center;gap:10px"><span style="color:var(--accent)">${icons[deck.icon] || icons.flash}</span>${esc(deck.title)}</h1>
    </div>
    <p style="color:var(--text-muted);font-size:13.5px;margin-bottom:20px">${(deck.cards || []).length} cards · Click cells to edit</p>
    <div style="display:flex;gap:8px;margin-bottom:22px">
      <button class="btn btn-action btn-sm" onclick="startStudy('${deck.id}')">${icons.play} Study</button>
      <button class="btn btn-secondary btn-sm" onclick="addCard('${deck.id}')">${icons.plus} Add Card</button>
    </div>
    <div style="font-size:12px;color:var(--text-muted);display:grid;grid-template-columns:1fr 1fr auto;gap:10px;padding:0 14px 6px;text-transform:uppercase;letter-spacing:.04em"><span>Front</span><span>Back</span><span></span></div>
    <div id="cards-list">
      ${(deck.cards || []).map((card, i) => `
        <div class="card-row">
          <div class="card-side" contenteditable="true" onblur="updateCard('${deck.id}',${i},'front',this.textContent)" spellcheck="false">${esc(card.front)}</div>
          <div class="card-side" contenteditable="true" onblur="updateCard('${deck.id}',${i},'back',this.textContent)" spellcheck="false" style="color:var(--text-muted)">${esc(card.back)}</div>
          <button class="icon-btn" onclick="deleteCard('${deck.id}',${i})">${icons.trash}</button>
        </div>`).join('')}
    </div>
    ${!deck.cards?.length ? '<div class="empty"><div class="empty-icon">' + icons.cardIcon + '</div><div class="empty-title">No cards</div><p class="empty-sub">Add your first front/back card</p></div>' : ''}`;
}

async function addCard(deckId) { const d = S.flashcards.find(d => d.id === deckId); if (!d) return; if (!d.cards) d.cards = []; d.cards.push({ front: 'Question', back: 'Answer' }); await saveData('flashcards', { [deckId]: d }); openDeckEditor(deckId); }
async function updateCard(deckId, idx, side, text) { const d = S.flashcards.find(d => d.id === deckId); if (!d?.cards?.[idx]) return; d.cards[idx][side] = text.trim() || (side === 'front' ? 'Question' : 'Answer'); await saveData('flashcards', { [deckId]: d }); }
async function deleteCard(deckId, idx) { const d = S.flashcards.find(d => d.id === deckId); if (!d) return; d.cards.splice(idx, 1); await saveData('flashcards', { [deckId]: d }); openDeckEditor(deckId); }

async function deleteDeck(id) {
  const d = S.flashcards.find(d => d.id === id); if (!d) return;
  // Inline confirm via toast-style
  const banner = el('div', 'delete-confirm-banner');
  banner.innerHTML = `<span>Delete "${esc(d.title)}"?</span><button class="btn btn-danger btn-sm" onclick="confirmDeleteDeck('${id}')">Delete</button><button class="btn btn-ghost btn-sm" onclick="this.closest('.delete-confirm-banner').remove()">Cancel</button>`;
  const c = $('main-content'); if (c) c.prepend(banner);
}

async function confirmDeleteDeck(id) {
  S.flashcards = S.flashcards.filter(d => d.id !== id); await delData('flashcards/' + id); toast('Deck deleted'); renderContent();
}

function startStudy(id, options = {}) {
  const { pushHistory = true, replaceHistory = false } = options;
  const d = S.flashcards.find(d => d.id === id);
  if (!d?.cards?.length) return toast('Add some cards first');
  S.deck = { ...d, cards: [...d.cards].sort(() => Math.random() - .5) };
  S.cardIdx = 0; S.flipped = false; S.studyScore = { ok: 0, miss: 0 }; S.view = 'study';
  closeSidebarAfterNavigate();
  syncRouteWithState({ push: pushHistory, replace: replaceHistory });
  renderApp();
}

function renderStudy(c) {
  const deck = S.deck; if (!deck) return navigate('flashcards');
  const cards = deck.cards, i = S.cardIdx;
  if (i >= cards.length) {
    recordStudySession(cards.length);
    c.innerHTML = `<div class="study-wrap" style="text-align:center">
      <button class="icon-btn" onclick="navigate('flashcards')" style="margin-bottom:32px">${icons.back}</button>
      <div style="margin-bottom:16px;color:var(--accent)"><svg width="56" height="56" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg></div>
      <h2 style="font-size:28px;font-weight:700;margin-bottom:8px">Done!</h2>
      <p style="color:var(--text-muted);margin-bottom:28px">${cards.length} cards reviewed</p>
      <div class="stat-row" style="max-width:280px;margin:0 auto 28px"><div class="stat-box"><div class="stat-num" style="color:var(--green)">${S.studyScore.ok}</div><div class="stat-lbl">Correct</div></div><div class="stat-box"><div class="stat-num" style="color:var(--red)">${S.studyScore.miss}</div><div class="stat-lbl">Missed</div></div></div>
      <div style="display:flex;gap:10px;justify-content:center">
        <button class="btn btn-action" onclick="startStudy('${deck.id}')" style="width:auto">${icons.shuffle} Again</button>
        <button class="btn btn-secondary" onclick="navigate('flashcards')" style="width:auto">Finish</button>
      </div></div>`; return;
  }
  const card = cards[i];
  c.innerHTML = `<div class="study-wrap">
    <div style="display:flex;align-items:center;gap:10px;margin-bottom:20px">
      <button class="icon-btn" onclick="navigate('flashcards')">${icons.back}</button>
      <span style="font-size:13px;color:var(--text-muted)">${icons[deck.icon] || icons.flash} ${esc(deck.title)}</span>
      <span style="margin-left:auto;font-size:13px;color:var(--text-muted)">${i + 1}/${cards.length}</span>
    </div>
    <div class="study-prog"><div class="study-bar" style="width:${Math.round(i / cards.length * 100)}%"></div></div>
    <div class="card-3d" onclick="flipCard()">
      <div class="card-inner${S.flipped ? ' flipped' : ''}">
        <div class="card-face"><div class="card-text">${esc(card.front)}</div></div>
        <div class="card-face card-back"><div class="card-text">${esc(card.back)}</div></div>
      </div>
    </div>
    ${S.flipped ? `<div class="study-btns">
      <button class="btn btn-miss" onclick="markCard(false)" style="width:auto;padding:9px 22px">${icons.x} Missed</button>
      <button class="btn btn-got"  onclick="markCard(true)"  style="width:auto;padding:9px 22px">${icons.ok} Got it</button>
    </div>`: `<p style="text-align:center;color:var(--text-faint);font-size:13px">Click the card to flip it</p>`}
  </div>`;
}

function flipCard() { S.flipped = !S.flipped; renderContent(); }
function markCard(ok) { if (ok) S.studyScore.ok++; else S.studyScore.miss++; S.cardIdx++; S.flipped = false; renderContent(); }
async function recordStudySession(cardCount) { if (!S.user) return; S.studySessions++; S.studyMinutes += Math.ceil(cardCount * .5); try { await window.fb.update(window.fb.ref(window.fb.database, `users/${S.user.uid}/stats`), { sessions: S.studySessions, minutes: S.studyMinutes }); } catch (e) { } }

// ─── PAGE EDITOR ──────────────────────────────────────────────
const SLASH_CMDS = [
  { g: 'Basic', t: 'text', icon: '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M13 4v16"/><path d="M17 4v16"/><path d="M19 4H9.5a4.5 4.5 0 0 0 0 9H13"/></svg>', name: 'Text', desc: 'Plain paragraph' },
  { g: 'Basic', t: 'h1', icon: 'H1', name: 'Heading 1', desc: 'Large section header' },
  { g: 'Basic', t: 'h2', icon: 'H2', name: 'Heading 2', desc: 'Medium section header' },
  { g: 'Basic', t: 'h3', icon: 'H3', name: 'Heading 3', desc: 'Small section header' },
  { g: 'Basic', t: 'h4', icon: 'H4', name: 'Heading 4', desc: 'Subtle label header' },
  { g: 'Lists', t: 'todo', icon: 'todo', name: 'To-do', desc: 'Checkbox item' },
  { g: 'Lists', t: 'bullet', icon: '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="9" y1="6" x2="20" y2="6"/><line x1="9" y1="12" x2="20" y2="12"/><line x1="9" y1="18" x2="20" y2="18"/><circle cx="4" cy="6" r="1.5" fill="currentColor" stroke="none"/><circle cx="4" cy="12" r="1.5" fill="currentColor" stroke="none"/><circle cx="4" cy="18" r="1.5" fill="currentColor" stroke="none"/></svg>', name: 'Bullet', desc: 'Bulleted list' },
  { g: 'Lists', t: 'numbered', icon: '1.', name: 'Numbered', desc: 'Numbered list' },
  { g: 'Lists', t: 'toggle', icon: '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="9 18 15 12 9 6"/></svg>', name: 'Toggle', desc: 'Collapsible section' },
  // ── Inline formatting (applies to selected text or typed after) ──
  { g: 'Format', t: 'fmt-bold', icon: '<b>B</b>', name: 'Bold', desc: 'Make selected text bold' },
  { g: 'Format', t: 'fmt-italic', icon: '<i>I</i>', name: 'Italic', desc: 'Make selected text italic' },
  { g: 'Format', t: 'fmt-underline', icon: '<u>U</u>', name: 'Underline', desc: 'Underline selected text' },
  { g: 'Format', t: 'fmt-strike', icon: '<s>S</s>', name: 'Strikethrough', desc: 'Strike through selected text' },
  { g: 'Format', t: 'fmt-code', icon: '<span style="font-family:var(--mono);font-size:10px">&lt;/&gt;</span>', name: 'Inline Code', desc: 'Wrap text in inline code' },
  { g: 'Format', t: 'fmt-size-small', icon: '<span style="font-size:10px">S</span>', name: 'Small Text', desc: 'Make selected text smaller' },
  { g: 'Format', t: 'fmt-size-large', icon: '<span style="font-size:15px">L</span>', name: 'Large Text', desc: 'Make selected text larger' },
  { g: 'Format', t: 'fmt-clear', icon: 'clearFmt', name: 'Clear Formatting', desc: 'Remove all inline styles' },
  { g: 'Highlight', t: 'hl-yellow', icon: '<span style="background:#fff9c4;padding:0 4px;border-radius:3px">A</span>', name: 'Yellow Highlight', desc: 'Yellow background text' },
  { g: 'Highlight', t: 'hl-green', icon: '<span style="background:#c8e6c9;padding:0 4px;border-radius:3px">A</span>', name: 'Green Highlight', desc: 'Green background text' },
  { g: 'Highlight', t: 'hl-blue', icon: '<span style="background:#bbdefb;padding:0 4px;border-radius:3px">A</span>', name: 'Blue Highlight', desc: 'Blue background text' },
  { g: 'Highlight', t: 'hl-pink', icon: '<span style="background:#f8bbd0;padding:0 4px;border-radius:3px">A</span>', name: 'Pink Highlight', desc: 'Pink background text' },
  { g: 'Highlight', t: 'hl-purple', icon: '<span style="background:#e1bee7;padding:0 4px;border-radius:3px">A</span>', name: 'Purple Highlight', desc: 'Purple background text' },
  { g: 'Highlight', t: 'hl-clear', icon: 'clearFmt', name: 'Clear Highlight', desc: 'Remove background color' },
  { g: 'Fonts', t: 'font-serif', icon: 'Tf', name: 'Serif', desc: 'Elegant serif font' },
  { g: 'Fonts', t: 'font-mono', icon: 'T_', name: 'Monospace', desc: 'Code-style monospace' },
  { g: 'Fonts', t: 'font-hand', icon: 'Th', name: 'Handwriting', desc: 'Casual handwriting style' },
  { g: 'Media', t: 'quote', icon: '"', name: 'Quote', desc: 'Blockquote' },
  { g: 'Media', t: 'callout', icon: 'calloutIcon', name: 'Callout', desc: 'Highlighted note box' },
  { g: 'Media', t: 'code', icon: '</>', name: 'Code', desc: 'Code block' },
  { g: 'Media', t: 'math', icon: '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M18 4H6l6 8-6 8h12"/></svg>', name: 'Math', desc: 'LaTeX-style equation' },
  { g: 'Media', t: 'table', icon: '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="18" height="18" rx="2"/><line x1="3" y1="9" x2="21" y2="9"/><line x1="3" y1="15" x2="21" y2="15"/><line x1="9" y1="9" x2="9" y2="21"/></svg>', name: 'Table', desc: 'Data table with rows/cols' },
  { g: 'Media', t: 'image', icon: 'img', name: 'Image', desc: 'Upload or link an image' },
  { g: 'Media', t: 'pdf', icon: 'PDF', name: 'PDF', desc: 'Embed a PDF document' },
  { g: 'Media', t: 'divider', icon: '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="3" y1="12" x2="21" y2="12"/></svg>', name: 'Divider', desc: 'Horizontal rule' },
  { g: "Tasks", t: "task_block", icon: "✓", name: "Task", desc: "Linked task synced to Tasks board" },
];

const NOTE_INK_COLORS = ['#111827', '#2563eb', '#dc2626', '#059669', '#7c3aed', '#ea580c'];
const NOTE_INK_HIGHLIGHTERS = ['#fde047', '#86efac', '#93c5fd', '#f9a8d4', '#c4b5fd'];
const NOTE_INK_PALM_WIDTH = 28;
const NOTE_INK_PALM_HEIGHT = 28;
const NOTE_INK_PALM_AREA = 900;

const NoteInk = {
  enabled: false,
  tool: 'pen',
  color: NOTE_INK_COLORS[0],
  highlighterColor: NOTE_INK_HIGHLIGHTERS[0],
  penWidth: 2.6,
  highlighterWidth: 18,
  activeStroke: null,
  pointerId: null,
  drawing: false,
};
const NOTE_INK_SIZES = {
  pen: [
    { id: 'fine', label: 'Fine', width: 1.8 },
    { id: 'medium', label: 'Medium', width: 2.6 },
    { id: 'bold', label: 'Bold', width: 4.2 },
  ],
  highlighter: [
    { id: 'small', label: 'Small', width: 14 },
    { id: 'medium', label: 'Medium', width: 18 },
    { id: 'broad', label: 'Broad', width: 24 },
  ],
  eraser: [
    { id: 'small', label: 'Small', width: 16 },
    { id: 'medium', label: 'Medium', width: 24 },
    { id: 'broad', label: 'Broad', width: 34 },
  ],
};
const NOTE_INK_GROWTH_CHUNK = 720;
const NOTE_INK_GROWTH_THRESHOLD = 180;
window.addEventListener('resize', () => {
  if (NoteInk.enabled) redrawNoteInk();
});

function noteInkToolbarHTML(page) {
  const strokeCount = (page?.inkStrokes || []).length;
  const sizes = NOTE_INK_SIZES[NoteInk.tool] || NOTE_INK_SIZES.pen;
  const activeWidth = NoteInk.tool === 'highlighter' ? NoteInk.highlighterWidth : NoteInk.penWidth;
  return `<div class="note-ink-toolbar">
    <button class="note-ink-toggle${NoteInk.enabled ? ' active' : ''}" onclick="toggleNoteInkMode()" title="Stylus writing mode">${icons.penIcon} ${NoteInk.enabled ? 'Ink On' : 'Ink Off'}</button>
    <div class="note-ink-tools">
      <button class="note-ink-tool${NoteInk.tool === 'pen' ? ' active' : ''}" onclick="setNoteInkTool('pen')">Pen</button>
      <button class="note-ink-tool${NoteInk.tool === 'highlighter' ? ' active' : ''}" onclick="setNoteInkTool('highlighter')">Highlighter</button>
      <button class="note-ink-tool${NoteInk.tool === 'eraser' ? ' active' : ''}" onclick="setNoteInkTool('eraser')">Stroke Eraser</button>
    </div>
    <div class="note-ink-tools">
      ${sizes.map(size => `<button class="note-ink-tool${Math.abs(activeWidth - size.width) < 0.05 ? ' active' : ''}" onclick="setNoteInkSize(${size.width})">${size.label}</button>`).join('')}
    </div>
    <div class="note-ink-swatches">
      ${NOTE_INK_COLORS.map(color => `<button class="note-ink-swatch${NoteInk.tool === 'pen' && NoteInk.color === color ? ' active' : ''}" onclick="setNoteInkColor('${color}')" style="background:${color}" title="${color}"></button>`).join('')}
    </div>
    <div class="note-ink-swatches">
      ${NOTE_INK_HIGHLIGHTERS.map(color => `<button class="note-ink-swatch note-ink-swatch-hi${NoteInk.tool === 'highlighter' && NoteInk.highlighterColor === color ? ' active' : ''}" onclick="setNoteInkColor('${color}', true)" style="background:${color}" title="${color}"></button>`).join('')}
    </div>
    <div class="note-ink-meta">${strokeCount} stroke${strokeCount === 1 ? '' : 's'}</div>
    <div class="note-ink-actions">
      <button class="note-ink-tool" onclick="undoNoteInkStroke()" ${strokeCount ? '' : 'disabled'}>Undo</button>
      <button class="note-ink-tool" onclick="clearNoteInk()" ${strokeCount ? '' : 'disabled'}>Clear</button>
    </div>
  </div>`;
}

function ensurePageInkState(page = S.page) {
  if (!page) return;
  if (!Array.isArray(page.inkStrokes)) page.inkStrokes = [];
}

function toggleNoteInkMode(force) {
  NoteInk.enabled = typeof force === 'boolean' ? force : !NoteInk.enabled;
  renderContent();
}

function setNoteInkTool(tool) {
  if (tool === 'highlighter' || tool === 'eraser') NoteInk.tool = tool;
  else NoteInk.tool = 'pen';
  renderNoteInkToolbar();
}

function setNoteInkColor(color, highlighter = false) {
  if (highlighter) NoteInk.highlighterColor = color;
  else NoteInk.color = color;
  renderNoteInkToolbar();
}

function setNoteInkSize(width) {
  const nextWidth = Math.max(1, Number(width) || 0);
  if (NoteInk.tool === 'highlighter') NoteInk.highlighterWidth = nextWidth;
  else NoteInk.penWidth = nextWidth;
  renderNoteInkToolbar();
}

function renderNoteInkToolbar() {
  const toolbar = document.getElementById('note-ink-toolbar-wrap');
  if (toolbar && S.page) toolbar.innerHTML = noteInkToolbarHTML(S.page);
}

function getNoteInkColorForTool(tool) {
  return tool === 'highlighter' ? NoteInk.highlighterColor : NoteInk.color;
}

function getNoteInkStrokeStyle(tool) {
  if (tool === 'highlighter') return { width: NoteInk.highlighterWidth, alpha: 0.24 };
  if (tool === 'eraser') return { width: 24, alpha: 1 };
  return { width: NoteInk.penWidth, alpha: 1 };
}

function noteInkStrokeHit(stroke, point, radius, surfaceWidth, surfaceHeight) {
  if (!stroke?.points?.length || !point) return false;
  const hitRadius = Math.max(8, Number(radius) || 0);
  for (const p of stroke.points) {
    const x = typeof p.x === 'number' ? p.x : ((p.xr ?? 0) * surfaceWidth);
    const y = typeof p.y === 'number' ? p.y : ((p.yr ?? 0) * surfaceHeight);
    if (Math.hypot(point.x - x, point.y - y) <= hitRadius) return true;
  }
  return false;
}

function eraseNoteInkAtPoint(point) {
  if (!S.page) return false;
  ensurePageInkState(S.page);
  const surface = getNoteInkSurface();
  if (!surface) return false;
  const rect = surface.getBoundingClientRect();
  const width = Math.max(1, Math.round(rect.width || 1));
  const height = Math.max(1, Math.round(surface.scrollHeight || rect.height || 1));
  const radius = Math.max(10, NoteInk.penWidth * 4);
  const before = S.page.inkStrokes.length;
  S.page.inkStrokes = S.page.inkStrokes.filter(stroke => !noteInkStrokeHit(stroke, point, radius, width, height));
  const changed = S.page.inkStrokes.length !== before;
  if (changed) scheduleSave();
  return changed;
}

function cloneInkStrokes(strokes) {
  return Array.isArray(strokes) ? JSON.parse(JSON.stringify(strokes)) : [];
}

function isPalmTouch(evt) {
  const width = Number(evt.width || evt.radiusX || 0);
  const height = Number(evt.height || evt.radiusY || 0);
  return width >= NOTE_INK_PALM_WIDTH || height >= NOTE_INK_PALM_HEIGHT || (width * height) >= NOTE_INK_PALM_AREA;
}

function getNoteInkSurface() {
  return document.getElementById('note-ink-surface');
}

function getNoteInkCanvas() {
  return document.getElementById('note-ink-canvas');
}

function getNoteInkContext() {
  return getNoteInkCanvas()?.getContext('2d') || null;
}

function getNoteInkPoint(evt) {
  const surface = getNoteInkSurface();
  if (!surface) return null;
  const rect = surface.getBoundingClientRect();
  const x = Math.max(0, Math.min(rect.width, evt.clientX - rect.left));
  const y = Math.max(0, evt.clientY - rect.top);
  return {
    x,
    y,
    xr: rect.width ? x / rect.width : 0,
    yr: rect.height ? y / rect.height : 0,
    pressure: evt.pressure && evt.pressure > 0 ? evt.pressure : 0.5,
  };
}

function drawInkStroke(ctx, stroke, surfaceWidth, surfaceHeight) {
  if (!ctx || !stroke?.points?.length) return;
  const style = getNoteInkStrokeStyle(stroke.tool);
  ctx.save();
  ctx.lineCap = 'round';
  ctx.lineJoin = 'round';
  ctx.strokeStyle = stroke.color;
  ctx.globalAlpha = stroke.alpha ?? style.alpha;
  if (stroke.tool === 'highlighter') ctx.globalCompositeOperation = 'multiply';
  if (stroke.points.length === 1) {
    const point = stroke.points[0];
    const x = typeof point.x === 'number' ? point.x : ((point.xr ?? 0) * surfaceWidth);
    const y = typeof point.y === 'number' ? point.y : ((point.yr ?? 0) * surfaceHeight);
    const radius = Math.max(1, ((stroke.width || style.width) * ((point.pressure || 0.5) * 0.65 + 0.35)) / 2);
    ctx.beginPath();
    ctx.arc(x, y, radius, 0, Math.PI * 2);
    ctx.fillStyle = stroke.color;
    ctx.fill();
    ctx.restore();
    return;
  }
  ctx.beginPath();
  stroke.points.forEach((point, index) => {
    const x = typeof point.x === 'number' ? point.x : ((point.xr ?? 0) * surfaceWidth);
    const y = typeof point.y === 'number' ? point.y : ((point.yr ?? 0) * surfaceHeight);
    const width = Math.max(1, (stroke.width || style.width) * ((point.pressure || 0.5) * 0.65 + 0.35));
    ctx.lineWidth = width;
    if (index === 0) ctx.moveTo(x, y);
    else ctx.lineTo(x, y);
  });
  ctx.stroke();
  ctx.restore();
}

function redrawNoteInk() {
  const canvas = getNoteInkCanvas();
  const surface = getNoteInkSurface();
  const editorSurface = document.getElementById('editor-surface');
  const ctx = getNoteInkContext();
  if (!canvas || !surface || !ctx || !S.page) return;
  const rect = surface.getBoundingClientRect();
  const ratio = window.devicePixelRatio || 1;
  const width = Math.max(1, Math.round(rect.width));
  const contentHeight = Math.round(surface.scrollHeight || rect.height || 240);
  const height = Math.max(420, Math.round(S.page.inkCanvasHeight || contentHeight));
  if (editorSurface) editorSurface.style.minHeight = `${height}px`;
  surface.style.minHeight = `${height}px`;
  canvas.width = Math.round(width * ratio);
  canvas.height = Math.round(height * ratio);
  canvas.style.width = `${width}px`;
  canvas.style.height = `${height}px`;
  ctx.setTransform(ratio, 0, 0, ratio, 0, 0);
  ctx.clearRect(0, 0, width, height);
  ensurePageInkState(S.page);
  S.page.inkStrokes.forEach(stroke => drawInkStroke(ctx, stroke, width, height));
  if (NoteInk.activeStroke) drawInkStroke(ctx, NoteInk.activeStroke, width, height);
}

function ensureNoteInkCanvasSpace(requiredY = 0) {
  if (!S.page) return false;
  const currentHeight = Math.max(420, Number(S.page.inkCanvasHeight) || 0);
  const neededHeight = Math.max(currentHeight, Math.ceil(requiredY + NOTE_INK_GROWTH_THRESHOLD));
  if (neededHeight <= currentHeight) return false;
  S.page.inkCanvasHeight = Math.ceil(neededHeight / NOTE_INK_GROWTH_CHUNK) * NOTE_INK_GROWTH_CHUNK;
  redrawNoteInk();
  scheduleSave();
  return true;
}

function finishNoteInkStroke(saveStroke = true) {
  if (saveStroke && NoteInk.activeStroke && S.page) {
    ensurePageInkState(S.page);
    if (NoteInk.activeStroke.points.length > 0) S.page.inkStrokes.push(NoteInk.activeStroke);
    scheduleSave();
  }
  NoteInk.activeStroke = null;
  NoteInk.pointerId = null;
  NoteInk.drawing = false;
  redrawNoteInk();
  renderNoteInkToolbar();
}

function handleNoteInkPointerDown(evt) {
  if (!NoteInk.enabled || !S.page) return;
  if (evt.pointerType === 'touch') {
    if (isPalmTouch(evt)) evt.preventDefault();
    return;
  }
  if (evt.pointerType !== 'pen' && evt.pointerType !== 'mouse') return;
  evt.preventDefault();
  const point = getNoteInkPoint(evt);
  if (!point) return;
  const surface = getNoteInkSurface();
  if (!surface) return;
  const style = getNoteInkStrokeStyle(NoteInk.tool);
  if (NoteInk.tool === 'eraser') {
    NoteInk.pointerId = evt.pointerId;
    NoteInk.drawing = true;
    surface.setPointerCapture?.(evt.pointerId);
    if (eraseNoteInkAtPoint(point)) {
      redrawNoteInk();
      renderNoteInkToolbar();
    }
    return;
  }
  ensureNoteInkCanvasSpace(point.y);
  NoteInk.activeStroke = {
    id: uid(),
    tool: NoteInk.tool,
    color: getNoteInkColorForTool(NoteInk.tool),
    width: style.width,
    alpha: style.alpha,
    createdAt: new Date().toISOString(),
    points: [point],
  };
  NoteInk.pointerId = evt.pointerId;
  NoteInk.drawing = true;
  surface.setPointerCapture?.(evt.pointerId);
  redrawNoteInk();
}

function handleNoteInkPointerMove(evt) {
  if (!NoteInk.enabled) return;
  if (evt.pointerType === 'touch') return;
  if (!NoteInk.drawing || evt.pointerId !== NoteInk.pointerId) return;
  if (NoteInk.tool === 'eraser') {
    const point = getNoteInkPoint(evt);
    if (!point) return;
    if (eraseNoteInkAtPoint(point)) {
      redrawNoteInk();
      renderNoteInkToolbar();
    }
    return;
  }
  if (!NoteInk.activeStroke) return;
  evt.preventDefault();
  const point = getNoteInkPoint(evt);
  if (!point) return;
  ensureNoteInkCanvasSpace(point.y);
  NoteInk.activeStroke.points.push(point);
  redrawNoteInk();
}

function handleNoteInkPointerUp(evt) {
  if (!NoteInk.enabled) return;
  if (evt.pointerType === 'touch') return;
  if (!NoteInk.drawing || evt.pointerId !== NoteInk.pointerId) return;
  evt.preventDefault();
  if (NoteInk.tool === 'eraser') {
    NoteInk.pointerId = null;
    NoteInk.drawing = false;
    redrawNoteInk();
    renderNoteInkToolbar();
    return;
  }
  finishNoteInkStroke(true);
}

function handleNoteInkPointerCancel(evt) {
  if (!NoteInk.enabled) return;
  if (evt.pointerType === 'touch') return;
  if (evt.pointerId !== NoteInk.pointerId) return;
  if (NoteInk.tool === 'eraser') {
    NoteInk.pointerId = null;
    NoteInk.drawing = false;
    redrawNoteInk();
    renderNoteInkToolbar();
    return;
  }
  finishNoteInkStroke(false);
}

function preventNoteInkTouchScroll(evt) {
  if (NoteInk.enabled && isPalmTouch(evt)) evt.preventDefault();
}

function initNoteInkLayer() {
  if (!S.page) return;
  ensurePageInkState(S.page);
  const surface = getNoteInkSurface();
  const canvas = getNoteInkCanvas();
  if (!surface || !canvas) return;
  const blocksWrap = document.getElementById('blocks-wrap');
  const contentHeight = Math.max(
    420,
    Math.round(blocksWrap?.scrollHeight || 0) + 180,
    Math.round(document.getElementById('editor-surface')?.scrollHeight || 0)
  );
  S.page.inkCanvasHeight = Math.max(Number(S.page.inkCanvasHeight) || 0, contentHeight);
  surface.onpointerdown = handleNoteInkPointerDown;
  surface.onpointermove = handleNoteInkPointerMove;
  surface.onpointerup = handleNoteInkPointerUp;
  surface.onpointercancel = handleNoteInkPointerCancel;
  surface.addEventListener('touchstart', preventNoteInkTouchScroll, { passive: false });
  surface.addEventListener('touchmove', preventNoteInkTouchScroll, { passive: false });
  redrawNoteInk();
  window.requestAnimationFrame(() => redrawNoteInk());
}

function undoNoteInkStroke() {
  if (!S.page?.inkStrokes?.length) return;
  S.page.inkStrokes.pop();
  scheduleSave();
  redrawNoteInk();
  renderNoteInkToolbar();
}

function clearNoteInk() {
  if (!S.page) return;
  ensurePageInkState(S.page);
  S.page.inkStrokes = [];
  scheduleSave();
  redrawNoteInk();
  renderNoteInkToolbar();
}

function renderEditor(c) {
  const page = S.page; if (!page) return;
  const tags = page.tags || [];
  const pinLabel = page.pinned ? 'Unpin' : 'Pin';
  const pinIcon = page.pinned
    ? '<svg width="13" height="13" viewBox="0 0 24 24" fill="currentColor" stroke="none" style="vertical-align:-2px;margin-right:3px"><path d="M16 2l-4.6 4.6L8 7l-1 5 5-1 .4-3.4L17 3V2h-1zM2 22l5.5-5.5L9 18l3-3-3-3-3 3 1.5 1.5L2 22z"/></svg>'
    : '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:-2px;margin-right:3px"><path d="M16 2l-4.6 4.6L8 7l-1 5 5-1 .4-3.4L17 3V2h-1zM2 22l5.5-5.5L9 18l3-3-3-3-3 3 1.5 1.5L2 22z"/></svg>';
  c.innerHTML = `
    <div style="display:flex;align-items:center;gap:10px;margin-bottom:16px;flex-wrap:wrap">
      <div class="page-tags" id="page-tags">
        ${tags.map(t => `<span class="ptag t-${t.color || 'default'}">${esc(t.label)}<span class="ptag-x" onclick="removeTag('${t.label}')">×</span></span>`).join('')}
        <button class="btn btn-ghost btn-sm" onclick="addTagInline()" id="add-tag-btn" style="padding:1px 8px;font-size:11.5px">+ Tag</button>
      </div>
      <div style="margin-left:auto;display:flex;gap:6px;flex-wrap:wrap">
        <button class="btn btn-ghost btn-sm" onclick="togglePinPage('${page.id}')" style="font-size:12px">${pinIcon}${pinLabel}</button>
        <button class="btn btn-ghost btn-sm" onclick="exportPageToMarkdown()" style="font-size:12px">
          <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:-2px;margin-right:3px"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>Markdown
        </button>
        <button class="btn btn-ghost btn-sm" onclick="exportPageToPdf()" style="font-size:12px">
          <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:-2px;margin-right:3px"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/><polyline points="10 9 9 9 8 9"/></svg>PDF
        </button>
        <button class="btn btn-ghost btn-sm" onclick="askAIAboutNote()" style="font-size:12px;color:var(--accent)"> Ask AI</button>
        <button class="btn btn-ghost btn-sm" onclick="deletePage('${page.id}')" style="color:var(--red)">${icons.trash}</button>
      </div>
    </div>
    <div id="tag-form-wrap" class="inline-form-wrap" style="display:none;margin-bottom:12px">
      <div class="inline-form" style="padding:14px;flex-direction:row;align-items:flex-end;gap:10px">
        <div class="form-group" style="margin:0;flex:1"><label class="form-label">Tag Name</label>
          <input id="tag-inp" class="form-input" placeholder="e.g. important" style="margin-top:4px"></div>
        <button class="btn btn-action btn-sm" onclick="submitAddTag()">Add</button>
        <button class="btn btn-ghost btn-sm" onclick="toggleTagForm()">Cancel</button>
      </div>
    </div>
    <div class="page-title-el" id="page-title" contenteditable="true" data-ph="Untitled" spellcheck="false">${esc(page.title) || ''}</div>
    <div class="page-meta">
      <span id="word-count">0 words</span>
      <span>·</span>
      <span>Created ${fmt(page.createdAt)}</span>
    </div>
    <div class="page-desc-el" id="page-desc" contenteditable="true" data-ph="Add a description…" spellcheck="false">${esc(page.description) || ''}</div>
    <div id="note-ink-toolbar-wrap">${noteInkToolbarHTML(page)}</div>
    <div class="editor-surface${NoteInk.enabled ? ' ink-active' : ''}" id="editor-surface">
      <div class="blocks-wrap" id="blocks-wrap"></div>
      <div class="note-ink-surface${NoteInk.enabled ? ' active' : ''}" id="note-ink-surface" aria-hidden="${NoteInk.enabled ? 'false' : 'true'}">
        <canvas id="note-ink-canvas"></canvas>
      </div>
    </div>`;

  const titleEl = $('page-title');
  titleEl.addEventListener('keydown', e => { if (e.key === 'Enter') { e.preventDefault(); ensureFirstBlock(); renderBlocks(); setTimeout(() => focusBlock(page.blocks[0]?.id), 40); } });
  titleEl.addEventListener('blur', () => { page.title = titleEl.textContent.trim() || 'Untitled'; scheduleSave(); });

  const descEl = $('page-desc');
  descEl.addEventListener('blur', () => { page.description = descEl.textContent.trim(); scheduleSave(); });

  const tagInp = $('tag-inp'); if (tagInp) tagInp.addEventListener('keydown', e => { if (e.key === 'Enter') submitAddTag(); if (e.key === 'Escape') toggleTagForm(); });

  // Take initial undo snapshot
  UndoMgr.snapshot(page.id, page.blocks || []);
  renderBlocks(); updateWordCount();
  initNoteInkLayer();
}

function toggleTagForm() {
  const w = $('tag-form-wrap'); if (!w) return;
  const vis = w.style.display === 'block'; w.style.display = vis ? 'none' : 'block';
  if (!vis) setTimeout(() => $('tag-inp')?.focus(), 50);
}

function addTagInline() { toggleTagForm(); }

async function submitAddTag() {
  const label = $('tag-inp')?.value.trim(); if (!label) return toast('Enter a tag name');
  const colors = ['red', 'orange', 'green', 'blue', 'purple'];
  const color = colors[Math.floor(Math.random() * colors.length)];
  if (!S.page.tags) S.page.tags = [];
  if (S.page.tags.find(t => t.label === label)) { toast('Tag already exists'); return; }
  S.page.tags.push({ label, color }); scheduleSave(); toggleTagForm(); renderContent();
}

async function removeTag(label) { if (!S.page) return; S.page.tags = (S.page.tags || []).filter(t => t.label !== label); scheduleSave(); renderContent(); }

async function deletePage(id) {
  const page = S.pages.find(p => p.id === id);
  showDeleteConfirmModal({
    title: `Delete "${page?.title || 'Untitled'}"?`,
    message: 'This page will be permanently deleted.',
    onConfirm: `confirmDeletePage('${id}')`
  });
}

async function confirmDeletePage(id) {
  S.pages = S.pages.filter(p => p.id !== id); await delData('pages/' + id);
  S.page = null; S.view = 'home'; toast('Page deleted');
  syncRouteWithState({ replace: true });
  renderApp();
}

function ensureFirstBlock() { if (!S.page) return; if (!S.page.blocks) S.page.blocks = []; if (!S.page.blocks.length) S.page.blocks.push({ id: uid(), type: 'text', content: '' }); }

const LAZY_LOAD_THRESHOLD = 60; // blocks before activating lazy load
const LAZY_BATCH = 30; // blocks per batch

function renderBlocks() {
  const wrap = $('blocks-wrap'); if (!wrap || !S.page) return;
  const blocks = S.page.blocks || [];
  if (blocks.length > LAZY_LOAD_THRESHOLD) {
    // Lazy load: render first batch immediately, rest on scroll
    const firstBatch = blocks.slice(0, LAZY_BATCH);
    wrap.innerHTML = firstBatch.map((b, idx) => blockHTML(b, idx)).join('') +
      `<div id="lazy-sentinel" style="height:1px"></div>`;
    _lazyLoadRemaining(blocks, LAZY_BATCH, wrap);
  } else {
    wrap.innerHTML = blocks.map((b, idx) => blockHTML(b, idx)).join('');
  }
  setupBlockEvents();
  _initPdfBlocks();
  redrawNoteInk();
}

function _lazyLoadRemaining(blocks, offset, wrap) {
  if (offset >= blocks.length) return;
  const sentinel = document.getElementById('lazy-sentinel');
  if (!sentinel) return;
  const observer = new IntersectionObserver((entries) => {
    if (!entries[0].isIntersecting) return;
    observer.disconnect();
    // Render next batch
    const nextBatch = blocks.slice(offset, offset + LAZY_BATCH);
    const fragment = nextBatch.map((b, i) => blockHTML(b, offset + i)).join('');
    sentinel.insertAdjacentHTML('beforebegin', fragment);
    setupBlockEvents();
    if (offset + LAZY_BATCH < blocks.length) {
      _lazyLoadRemaining(blocks, offset + LAZY_BATCH, wrap);
    } else {
      sentinel.remove();
    }
  }, { rootMargin: '300px' });
  observer.observe(sentinel);
}

function setupBlockEvents() {
  const wrap = $('blocks-wrap'); if (!wrap) return;
  wrap.contentEditable = !NoteInk.enabled;
  wrap.onkeydown = e => { const row = e.target.closest('[data-bid]'); if (!row) return; handleBlockKey(e, row.dataset.bid); };
  wrap.oninput = e => { const row = e.target.closest('[data-bid]'); if (!row) return; handleBlockInput(e.target, row.dataset.bid); updateWordCount(); };
  wrap.addEventListener('blur', e => {
    const row = e.target.closest('[data-bid]');
    if (!row) return;
    const b = S.page?.blocks?.find(block => block.id === row.dataset.bid);
    if (b && e.target.classList.contains('b-el')) {
      const clean = sanitizeEditableHtml(e.target.innerHTML);
      e.target.innerHTML = clean;
      if (e.target.classList.contains('b-toggle-content')) b.toggleContent = clean;
      else b.content = clean;
      scheduleSave();
    }
  }, true);

  // Table cell blur
  wrap.addEventListener('blur', e => {
    const td = e.target.closest('td[data-trow]');
    if (!td) return;
    const row = td.closest('[data-bid]'); if (!row) return;
    const b = S.page?.blocks?.find(b => b.id === row.dataset.bid); if (!b || b.type !== 'table') return;
    const ri = parseInt(td.dataset.trow), ci = parseInt(td.dataset.tcol);
    if (td.dataset.header === '1') { b.headers[ci] = td.textContent; } else { b.rows[ri][ci] = td.textContent; }
    scheduleSave();
  }, true);

  // ── Drag & drop to reorder blocks ──────────────────────────────────────────
  let _dragId = null, _dragOverId = null;
  wrap.addEventListener('dragstart', e => {
    const row = e.target.closest('[data-bid]'); if (!row) return;
    _dragId = row.dataset.bid; row.classList.add('b-dragging');
    e.dataTransfer.effectAllowed = 'move';
    e.dataTransfer.setData('text/plain', _dragId);
  });
  wrap.addEventListener('dragend', () => {
    wrap.querySelectorAll('.b-dragging,.b-drag-over').forEach(el => { el.classList.remove('b-dragging', 'b-drag-over'); });
    _dragId = null; _dragOverId = null;
  });
  wrap.addEventListener('dragover', e => {
    e.preventDefault(); e.dataTransfer.dropEffect = 'move';
    const row = e.target.closest('[data-bid]');
    if (!row || row.dataset.bid === _dragId) return;
    if (row.dataset.bid !== _dragOverId) {
      wrap.querySelectorAll('.b-drag-over').forEach(el => el.classList.remove('b-drag-over'));
      row.classList.add('b-drag-over'); _dragOverId = row.dataset.bid;
    }
  });
  wrap.addEventListener('drop', e => {
    e.preventDefault();
    if (!_dragId || !_dragOverId || _dragId === _dragOverId) return;
    const blocks = S.page?.blocks; if (!blocks) return;
    const fi = blocks.findIndex(b => b.id === _dragId), ti = blocks.findIndex(b => b.id === _dragOverId);
    if (fi < 0 || ti < 0) return;
    const [moved] = blocks.splice(fi, 1); blocks.splice(ti, 0, moved);
    scheduleSave(); renderBlocks();
  });
  // Click on empty space below blocks → create first/new block
  wrap.addEventListener('click', e => {
    if (NoteInk.enabled) return;
    if (!e.target.closest('[data-bid]')) {
      ensureFirstBlock();
      renderBlocks();
      setTimeout(() => { const blocks = S.page?.blocks || []; if (blocks.length) focusBlock(blocks[blocks.length - 1].id, true); }, 40);
    }
  });
  // Make handles draggable
  wrap.querySelectorAll('.b-handle').forEach(h => {
    const row = h.closest('[data-bid]'); if (row) row.draggable = true;
    h.style.cursor = 'grab';
  });
}

function blockHTML(b, idx) {
  if (b.type === 'divider') return `<div class="b-row b-divider" data-bid="${b.id}"><div class="b-handle">${icons.dot6}</div><div class="b-inner"><hr></div></div>`;

  if (b.type === 'callout') {
    const iconMap = { info: `<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>`, warning: `<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>`, tip: `<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="9" y1="18" x2="15" y2="18"/><line x1="10" y1="22" x2="14" y2="22"/><path d="M15.09 14c.18-.98.65-1.74 1.41-2.5A4.65 4.65 0 0 0 18 8 6 6 0 0 0 6 8c0 1 .23 2.23 1.5 3.5A4.61 4.61 0 0 1 8.91 14"/></svg>` };
    return `<div class="b-row b-callout" data-bid="${b.id}"><div class="b-handle">${icons.dot6}</div><div class="b-inner"><div class="b-callout-inner c-${b.variant || 'info'}"><span class="b-callout-icon">${iconMap[b.variant || 'info']}</span><div class="b-el" contenteditable="true" data-ph="Write a note…" spellcheck="false">${renderSafeEditableHtml(b.content)}</div></div></div></div>`;
  }

  if (b.type === 'task_block') {
    const linkedTask = S.tasks.find(t => t.id === b.taskId);
    const title = renderSafeEditableHtml(b.content || linkedTask?.title || 'New task…');
    const done = linkedTask ? linkedTask.completed : false;
    const pri = linkedTask?.priority || 'med';
    const due = linkedTask?.due || '';
    return `<div class="b-row b-task-block${done ? ' b-todo-done' : ''}" data-bid="${b.id}"><div class="b-handle">${icons.dot6}</div><div class="b-inner"><div class="b-todo-row"><div class="b-chk${done ? ' chk-on' : ''}" onclick="toggleTaskBlock('${b.id}')"></div><div class="b-el" contenteditable="true" data-ph="Task title…" spellcheck="false">${title}</div><span class="task-block-badges">${pri !== 'med' ? `<span class="dot d-${pri === 'high' ? 'high' : 'low'}"></span>` : ''}${due ? `<span class="task-due${due < new Date().toISOString().split('T')[0] && !done ? ' late' : ''}">${fmt(due)}</span>` : ''}<button class="btn btn-ghost btn-sm" style="font-size:10px;padding:1px 5px" onclick="openTaskBlockOptions('${b.id}',event)">⋯</button></span></div></div></div></div>`;
  }
  if (b.type === 'todo') return `<div class="b-row${b.completed ? ' b-todo-done' : ''}" data-bid="${b.id}"><div class="b-handle">${icons.dot6}</div><div class="b-inner"><div class="b-todo-row"><div class="b-chk${b.completed ? ' chk-on' : ''}" onclick="toggleBlockTodo('${b.id}')"></div><div class="b-el" contenteditable="true" data-ph="To-do…" spellcheck="false">${renderSafeEditableHtml(b.content)}</div></div></div></div>`;
  if (b.type === 'bullet') return `<div class="b-row" data-bid="${b.id}"><div class="b-handle">${icons.dot6}</div><div class="b-inner"><div class="b-list-row"><span class="b-list-mrk">•</span><div class="b-el" contenteditable="true" data-ph="List item…" spellcheck="false">${renderSafeEditableHtml(b.content)}</div></div></div></div>`;
  if (b.type === 'numbered') return `<div class="b-row" data-bid="${b.id}"><div class="b-handle">${icons.dot6}</div><div class="b-inner"><div class="b-list-row"><span class="b-list-mrk">${idx + 1}.</span><div class="b-el" contenteditable="true" data-ph="List item…" spellcheck="false">${renderSafeEditableHtml(b.content)}</div></div></div></div>`;

  // Table block
  if (b.type === 'table') {
    const headers = b.headers || ['Column 1', 'Column 2', 'Column 3'];
    const rows = b.rows || [['', '', ''], ['', '', '']];
    const thead = headers.map((h, ci) => `<th><div class="b-tbl-cell" contenteditable="true" data-trow="0" data-tcol="${ci}" data-header="1" spellcheck="false">${esc(h)}</div></th>`).join('');
    const tbody = rows.map((row, ri) => `<tr>${row.map((cell, ci) => `<td><div class="b-tbl-cell" contenteditable="true" data-trow="${ri}" data-tcol="${ci}" spellcheck="false">${esc(cell)}</div></td>`).join('')}<td class="b-tbl-del-td"><button class="icon-btn" onclick="tableDelRow('${b.id}',${ri})" style="width:20px;height:20px">${icons.trash}</button></td></tr>`).join('');
    return `<div class="b-row b-table-wrap" data-bid="${b.id}">
      <div class="b-handle">${icons.dot6}</div>
      <div class="b-inner">
        <div class="b-table-container">
          <table class="b-table"><thead><tr>${thead}<th class="b-tbl-del-td"></th></tr></thead><tbody>${tbody}</tbody></table>
          <div class="b-table-actions">
            <button class="btn btn-ghost btn-sm" onclick="tableAddRow('${b.id}')">${icons.plus} Row</button>
            <button class="btn btn-ghost btn-sm" onclick="tableAddCol('${b.id}')">${icons.plus} Col</button>
            <button class="btn btn-ghost btn-sm" style="color:var(--red)" onclick="deleteBlock('${b.id}')">${icons.trash}</button>
          </div>
        </div>
      </div>
    </div>`;
  }

  // Image block
  if (b.type === 'image') {
    if (b.src) {
      return `<div class="b-row b-image-wrap" data-bid="${b.id}">
        <div class="b-handle">${icons.dot6}</div>
        <div class="b-inner">
          <div class="b-image-container">
            <img src="${b.src}" alt="${esc(b.alt || '')}" class="b-image" onclick="selectBlockImage('${b.id}')">
            <div class="b-image-caption" contenteditable="true" data-ph="Add caption…" spellcheck="false">${esc(b.caption || '')}</div>
            <button class="btn btn-ghost btn-sm b-image-delete" onclick="deleteBlock('${b.id}')" style="color:var(--red)">${icons.trash} Remove</button>
          </div>
        </div>
      </div>`;
    } else {
      return `<div class="b-row" data-bid="${b.id}">
        <div class="b-handle">${icons.dot6}</div>
        <div class="b-inner">
          <div class="b-media-upload">
            ${icons.image}
            <span>Upload an image or paste URL</span>
            <div style="display:flex;gap:8px;margin-top:8px">
              <label class="btn btn-secondary btn-sm" style="cursor:pointer">${icons.uploadIcon} Upload<input type="file" accept="image/*" style="display:none" onchange="handleImageUpload(this,'${b.id}')"></label>
              <input class="form-input" placeholder="or paste image URL…" style="max-width:260px;height:34px;font-size:13px" onkeydown="if(event.key==='Enter')handleImageUrl(this.value,'${b.id}')">
            </div>
            <button class="btn btn-ghost btn-sm" onclick="deleteBlock('${b.id}')" style="margin-top:6px;color:var(--text-muted)">${icons.close} Cancel</button>
          </div>
        </div>
      </div>`;
    }
  }

  // PDF block
  if (b.type === 'pdf') {
    if (b.src || b.url) {
      const src = b.src || b.url;
      const isDataUrl = src.startsWith('data:');
      return `<div class="b-row b-pdf-wrap" data-bid="${b.id}">
        <div class="b-handle">${icons.dot6}</div>
        <div class="b-inner">
          <div class="b-pdf-container">
            <div class="b-pdf-header">
              ${icons.pdfIcon}
              <span class="b-pdf-title">${esc(b.title) || 'PDF Document'}</span>
              <div class="b-pdf-controls">
                <button class="btn btn-ghost btn-sm b-pdf-nav" onclick="pdfPrevPage('${b.id}')">‹ Prev</button>
                <span class="b-pdf-pginfo" id="pginfo-${b.id}">—</span>
                <button class="btn btn-ghost btn-sm b-pdf-nav" onclick="pdfNextPage('${b.id}')">Next ›</button>
                <button class="btn btn-ghost btn-sm b-pdf-nav" onclick="pdfZoom('${b.id}',-0.25)">−</button>
                <button class="btn btn-ghost btn-sm b-pdf-nav" onclick="pdfZoom('${b.id}',+0.25)">+</button>
                ${!isDataUrl ? `<a href="${sanitizeUrl(src)}" target="_blank" rel="noopener noreferrer" class="btn btn-ghost btn-sm b-pdf-nav">Open ↗</a>` : ''}
                <button class="btn btn-ghost btn-sm b-pdf-nav" onclick="extractPdfToText('${b.id}')" title="Extract text to editable blocks" style="color:var(--accent);font-weight:600">
                  <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/></svg>
                  Extract Text
                </button>
                <button class="btn btn-ghost btn-sm b-pdf-nav" onclick="deleteBlock('${b.id}')" style="color:var(--red)">${icons.trash}</button>
              </div>
            </div>
            <div class="b-pdf-viewer" id="pdfviewer-${b.id}">
              <div class="b-pdf-loading" id="pdfloading-${b.id}">
                <div class="b-pdf-spinner"></div>
                <span>Loading PDF…</span>
              </div>
              <canvas id="pdfcanvas-${b.id}" class="b-pdf-canvas" style="display:none"></canvas>
              <div class="b-pdf-error" id="pdferror-${b.id}" style="display:none">
                ${icons.pdfIcon}
                <p>Could not render this PDF.</p>
                ${!isDataUrl ? `<a href="${sanitizeUrl(src)}" target="_blank" rel="noopener noreferrer" class="btn btn-action btn-sm">Open in new tab ↗</a>`
          : `<p style="font-size:12px;color:var(--text-faint)">Try a smaller file (&lt;15 MB)</p>`}
              </div>
            </div>
          </div>
        </div>
      </div>`;
    } else {
      return `<div class="b-row" data-bid="${b.id}">
        <div class="b-handle">${icons.dot6}</div>
        <div class="b-inner">
          <div class="b-media-upload">
            ${icons.pdfIcon}
            <span>Upload a PDF or enter a URL</span>
            <div style="display:flex;gap:8px;margin-top:8px;flex-wrap:wrap;justify-content:center">
              <label class="btn btn-secondary btn-sm" style="cursor:pointer">${icons.uploadIcon} Upload PDF
                <input type="file" accept=".pdf,application/pdf" style="display:none" onchange="handlePdfUpload(this,'${b.id}')">
              </label>
              <input class="form-input" placeholder="or paste PDF URL…" style="max-width:260px;height:34px;font-size:13px"
                onkeydown="if(event.key==='Enter')handlePdfUrl(this.value,'${b.id}')">
            </div>
            <button class="btn btn-ghost btn-sm" onclick="deleteBlock('${b.id}')" style="margin-top:6px;color:var(--text-muted)">${icons.close} Cancel</button>
          </div>
        </div>
      </div>`;
    }
  }

  // Toggle block
  if (b.type === 'toggle') {
    const open = b.open !== false;
    return `<div class="b-row b-toggle${open ? ' open' : ''}" data-bid="${b.id}">
      <div class="b-handle">${icons.dot6}</div>
      <div class="b-inner">
        <div class="b-toggle-hd">
          <button class="b-toggle-arrow" onclick="toggleBlock('${b.id}')" aria-label="toggle"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="9 18 15 12 9 6"/></svg></button>
          <div class="b-el" contenteditable="true" data-ph="Toggle heading…" spellcheck="false">${esc(b.content) || ''}</div>
        </div>
        ${open ? `<div class="b-toggle-body"><div class="b-el b-toggle-content" contenteditable="true" data-ph="Toggle content…" spellcheck="false">${esc(b.toggleContent || '')}</div></div>` : ''}
      </div>
    </div>`;
  }

  // Math block
  if (b.type === 'math') {
    return `<div class="b-row b-math-wrap" data-bid="${b.id}">
      <div class="b-handle">${icons.dot6}</div>
      <div class="b-inner">
        <div class="b-math-container">
          <div class="b-math-input-row">
            <input class="b-math-input" value="${esc(b.content || '')}" placeholder="e.g. E = mc^2  or  \\sum_{i=1}^{n} i" oninput="updateMathBlock('${b.id}',this.value)">
          </div>
          <div class="b-math-preview" id="math-prev-${b.id}">${renderMathPreview(b.content || '')}</div>
          <button class="btn btn-ghost btn-sm b-math-del" onclick="deleteBlock('${b.id}')" style="color:var(--red)">${icons.trash} Remove</button>
        </div>
      </div>
    </div>`;
  }

  const clsMap = { h1: 'b-h1', h2: 'b-h2', h3: 'b-h3', h4: 'b-h4', quote: 'b-quote', code: 'b-code' };
  // Font/highlight blocks store their variant in b.variant
  let fontCls = '', fontStyle = '';
  if (b.type === 'font-serif') fontStyle = 'font-family:Georgia,"Times New Roman",serif;';
  else if (b.type === 'font-mono') fontStyle = 'font-family:var(--mono);font-size:14.5px;';
  else if (b.type === 'font-hand') fontStyle = 'font-family:"Segoe Print","Comic Sans MS",cursive;font-size:16.5px;';
  const hlColors = { 'hl-yellow': '#fffde7', 'hl-green': '#e8f5e9', 'hl-blue': '#e3f2fd', 'hl-pink': '#fce4ec', 'hl-purple': '#f3e5f5' };
  let hlStyle = '';
  if (hlColors[b.type]) hlStyle = `background:${hlColors[b.type]};border-radius:4px;padding:8px 14px;`;

  const phMap = { text: 'Press / to insert a block · Enter for new line', h1: 'Heading 1', h2: 'Heading 2', h3: 'Heading 3', h4: 'Heading 4', quote: 'Blockquote…', code: 'Code…' };
  const cls = clsMap[b.type] || '';
  const style = fontStyle || hlStyle;
  // Allow stored HTML markup (bold/italic/highlight spans) — content is sanitized on save
  const safeContent = renderSafeEditableHtml(b.content);
  return `<div class="b-row${cls ? ' ' + cls : ''}" data-bid="${b.id}"><div class="b-handle">${icons.dot6}</div><div class="b-inner"><div class="b-el" contenteditable="true" data-ph="${phMap[b.type] || 'Type something…'}" spellcheck="false"${style ? ' style="' + style + '"' : ''}>${safeContent}</div></div></div>`;
}

// Image/PDF upload handlers
function handleImageUpload(input, bid) {
  const file = input.files[0]; if (!file) return;
  if (file.size > 5 * 1024 * 1024) return toast('Image too large (max 5MB)');
  const reader = new FileReader();
  reader.onload = e => {
    const b = S.page?.blocks?.find(b => b.id === bid); if (!b) return;
    b.src = sanitizeUrl(e.target.result); b.alt = validateStr(file.name, 100);
    scheduleSave(); renderBlocks();
  };
  reader.readAsDataURL(file);
}

function handleImageUrl(url, bid) {
  if (!url.trim()) return;
  const b = S.page?.blocks?.find(b => b.id === bid); if (!b) return;
  b.src = sanitizeUrl(url.trim()); if (!b.src) return toast('Invalid URL. Use https:// only.'); b.alt = 'Image';
  scheduleSave(); renderBlocks();
}

function selectBlockImage(bid) {
  // Allow changing image
  const input = document.createElement('input'); input.type = 'file'; input.accept = 'image/*';
  input.onchange = () => handleImageUpload(input, bid);
  input.click();
}

function handlePdfUpload(input, bid) {
  const file = input.files[0]; if (!file) return;
  if (file.type && file.type !== 'application/pdf' && !file.name.toLowerCase().endsWith('.pdf'))
    return toast('Please select a PDF file');
  if (file.size > 25 * 1024 * 1024) return toast('PDF too large — max 25 MB');

  // Show inline spinner in the upload area
  const row = document.querySelector(`[data-bid="${bid}"]`);
  const area = row?.querySelector('.b-media-upload');
  if (area) area.innerHTML = `<div style="padding:24px;text-align:center;color:var(--text-muted)">
    <div class="b-pdf-spinner" style="margin:0 auto 8px"></div>Reading PDF…</div>`;

  const reader = new FileReader();
  reader.onload = e => {
    const b = S.page?.blocks?.find(b => b.id === bid); if (!b) return;
    let dataUrl = e.target.result;
    // Normalise MIME — some browsers emit application/octet-stream
    if (dataUrl.startsWith('data:') && !dataUrl.startsWith('data:application/pdf'))
      dataUrl = dataUrl.replace(/^data:[^;]+;/, 'data:application/pdf;');
    const safe = sanitizeUrl(dataUrl);
    if (!safe) { toast('Could not read PDF — file may be corrupted'); renderBlocks(); return; }
    b.src = safe; b.title = validateStr(file.name, 100);
    scheduleSave(); renderBlocks();
    // Kick off PDF.js render once DOM updates
    setTimeout(() => _pdfLoad(bid, safe), 60);
  };
  reader.onerror = () => { toast('Failed to read PDF'); renderBlocks(); };
  reader.readAsDataURL(file);
}

function handlePdfUrl(url, bid) {
  if (!url.trim()) return;
  const b = S.page?.blocks?.find(b => b.id === bid); if (!b) return;
  const safe = sanitizeUrl(url.trim());
  if (!safe) return toast('Invalid URL — use https:// only');
  b.url = safe; b.title = validateStr(url.split('/').pop() || 'PDF Document', LIMITS.title);
  scheduleSave(); renderBlocks();
  setTimeout(() => _pdfLoad(bid, safe), 60);
}

function setPdfHeight(bid, height) {
  const b = S.page?.blocks?.find(b => b.id === bid); if (!b) return;
  b.pdfHeight = parseInt(height) || 600; scheduleSave(); renderBlocks();
  setTimeout(() => _pdfLoad(bid, b.src || b.url), 60);
}

// ── PDF.js rendering engine ────────────────────────────────────────
// State: { doc, page (1-based), scale, total }
const _PDF = {};

async function _pdfLoad(bid, src) {
  if (typeof pdfjsLib === 'undefined') {
    _pdfShowError(bid); return;
  }
  _pdfShowLoading(bid);
  try {
    let loadArg;
    if (src.startsWith('data:')) {
      // Convert base64 data URL → Uint8Array (PDF.js prefers typed arrays)
      const b64 = src.split(',')[1];
      const bin = atob(b64);
      const arr = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
      loadArg = { data: arr };
    } else {
      loadArg = { url: src };
    }
    const pdfDoc = await pdfjsLib.getDocument(loadArg).promise;
    if (!_PDF[bid]) _PDF[bid] = { page: 1, scale: 1.3 };
    _PDF[bid].doc = pdfDoc;
    _PDF[bid].total = pdfDoc.numPages;
    await _pdfRender(bid);
  } catch (err) {
    console.error('[PDF.js]', err);
    _pdfShowError(bid);
  }
}

async function _pdfRender(bid) {
  const s = _PDF[bid]; if (!s?.doc) return;
  _pdfShowLoading(bid);
  try {
    const page = await s.doc.getPage(s.page);
    const viewport = page.getViewport({ scale: s.scale });
    const canvas = document.getElementById(`pdfcanvas-${bid}`);
    if (!canvas) return;
    canvas.width = viewport.width;
    canvas.height = viewport.height;
    await page.render({ canvasContext: canvas.getContext('2d'), viewport }).promise;
    // Show canvas, hide loading
    canvas.style.display = 'block';
    const loading = document.getElementById(`pdfloading-${bid}`);
    if (loading) loading.style.display = 'none';
    const info = document.getElementById(`pginfo-${bid}`);
    if (info) info.textContent = `${s.page} / ${s.total}`;
  } catch (err) {
    console.error('[PDF.js render]', err);
    _pdfShowError(bid);
  }
}

function _pdfShowLoading(bid) {
  const loading = document.getElementById(`pdfloading-${bid}`);
  const canvas = document.getElementById(`pdfcanvas-${bid}`);
  const error = document.getElementById(`pdferror-${bid}`);
  if (loading) loading.style.display = 'flex';
  if (canvas) canvas.style.display = 'none';
  if (error) error.style.display = 'none';
}

function _pdfShowError(bid) {
  const loading = document.getElementById(`pdfloading-${bid}`);
  const canvas = document.getElementById(`pdfcanvas-${bid}`);
  const error = document.getElementById(`pdferror-${bid}`);
  if (loading) loading.style.display = 'none';
  if (canvas) canvas.style.display = 'none';
  if (error) error.style.display = 'flex';
}

function pdfPrevPage(bid) {
  const s = _PDF[bid]; if (!s?.doc || s.page <= 1) return;
  s.page--; _pdfRender(bid);
}

function pdfNextPage(bid) {
  const s = _PDF[bid]; if (!s?.doc || s.page >= s.total) return;
  s.page++; _pdfRender(bid);
}

function pdfZoom(bid, delta) {
  const s = _PDF[bid]; if (!s?.doc) return;
  s.scale = Math.max(0.5, Math.min(3.0, s.scale + delta));
  _pdfRender(bid);
}

// Called by renderBlocks() to auto-start rendering existing PDF blocks
function _initPdfBlocks() {
  (S.page?.blocks || []).forEach(b => {
    if (b.type === 'pdf' && (b.src || b.url))
      setTimeout(() => _pdfLoad(b.id, b.src || b.url), 60);
  });
}

// ── Export page to PDF ─────────────────────────────────────────────
function exportPageToPdf() {
  const page = S.page; if (!page) return toast('Open a page first');
  const blocks = page.blocks || [];

  // Convert each block to clean HTML for printing
  const bodyHtml = blocks.map((b, i) => {
    if (b.type === 'divider') return `<hr>`;
    if (b.type === 'image') return b.src ? `<div class="ep-img"><img src="${b.src}" alt="${b.alt || ''}"></div>` : '';
    if (b.type === 'pdf') return b.title ? `<div class="ep-pdf-ref"> Embedded PDF: ${esc(b.title)}</div>` : '';
    if (b.type === 'table') {
      const ths = (b.headers || []).map(h => `<th>${esc(h)}</th>`).join('');
      const trs = (b.rows || []).map(r => `<tr>${r.map(c => `<td>${esc(c)}</td>`).join('')}</tr>`).join('');
      return `<table><thead><tr>${ths}</tr></thead><tbody>${trs}</tbody></table>`;
    }
    if (b.type === 'callout') {
      const color = { info: '#dbeafe', warn: '#fef9c3', error: '#fee2e2', success: '#dcfce7' }[b.variant || 'info'] || '#dbeafe';
      return `<div class="ep-callout" style="background:${color}">${b.content || ''}</div>`;
    }
    if (b.type === 'code') {
      const text = (b.content || '').replace(/<[^>]+>/g, '');
      return `<pre><code>${esc(text)}</code></pre>`;
    }
    if (b.type === 'math') {
      return `<div class="ep-math">${esc(b.content || '')}</div>`;
    }
    // Text-based blocks — strip HTML tags but keep meaningful structure
    const raw = (b.content || '').replace(/<br\s*\/?>/gi, '\n');
    const text = raw.replace(/<[^>]+>/g, '').trim();
    if (!text) return '';
    if (b.type === 'h1') return `<h1>${text}</h1>`;
    if (b.type === 'h2') return `<h2>${text}</h2>`;
    if (b.type === 'h3') return `<h3>${text}</h3>`;
    if (b.type === 'quote') return `<blockquote>${text}</blockquote>`;
    if (b.type === 'bullet') return `<ul><li>${text}</li></ul>`;
    if (b.type === 'numbered') return `<ol start="${i + 1}"><li>${text}</li></ol>`;
    if (b.type === 'todo') return `<div class="ep-todo">${b.completed ? '☑' : '☐'} <span style="${b.completed ? 'text-decoration:line-through;opacity:.5' : ''}">${text}</span></div>`;
    if (b.type === 'toggle') return `<div class="ep-toggle"><strong>${text}</strong>${b.toggleContent ? `<div>${b.toggleContent.replace(/<[^>]+>/g, '')}</div>` : ''}</div>`;
    // Default paragraph — allow basic bold/italic HTML through
    const safe = (b.content || '').replace(/<(?!\/?(strong|em|b|i|br)\b)[^>]+>/gi, '');
    return `<p>${safe || text}</p>`;
  }).filter(Boolean).join('\n');

  const titleText = esc(page.title || 'Untitled');
  const desc = (page.description || '').replace(/<[^>]+>/g, '');
  const tags = (page.tags || []).map(t => `<span class="ep-tag">${esc(t.label)}</span>`).join('');
  const dateStr = new Date().toLocaleDateString('en-GB', { day: 'numeric', month: 'long', year: 'numeric' });

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>${titleText}</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif;
      font-size: 14.5px; line-height: 1.7; color: #1a1a1a; background: #fff;
      -webkit-print-color-adjust: exact; print-color-adjust: exact;
    }
    .wrap { max-width: 740px; margin: 0 auto; padding: 52px 48px; }
    /* Header */
    .ep-header { margin-bottom: 28px; border-bottom: 2px solid #e8e8e8; padding-bottom: 22px; }
    h1.ep-title { font-size: 34px; font-weight: 800; color: #111; line-height: 1.15; margin-bottom: 8px; }
    .ep-meta { font-size: 12px; color: #888; margin-bottom: 8px; }
    .ep-desc { font-size: 15px; color: #555; font-style: italic; margin-bottom: 10px; }
    .ep-tags { display: flex; gap: 6px; flex-wrap: wrap; }
    .ep-tag { background: #f0f0f0; border-radius: 20px; padding: 2px 10px; font-size: 11.5px; color: #555; }
    /* Body blocks */
    h1 { font-size: 26px; font-weight: 700; margin: 22px 0 6px; }
    h2 { font-size: 20px; font-weight: 700; margin: 18px 0 5px; }
    h3 { font-size: 16px; font-weight: 600; margin: 14px 0 4px; }
    p  { margin: 5px 0; }
    ul, ol { padding-left: 22px; margin: 4px 0; }
    li { margin: 2px 0; }
    blockquote { border-left: 3px solid #ccc; padding: 6px 14px; color: #555; font-style: italic; margin: 10px 0; }
    pre { background: #f6f6f6; border: 1px solid #e0e0e0; border-radius: 6px; padding: 14px; font-size: 12.5px; overflow-x: auto; white-space: pre-wrap; font-family: 'Courier New', monospace; margin: 10px 0; }
    code { font-family: 'Courier New', monospace; }
    hr { border: none; border-top: 1px solid #e0e0e0; margin: 18px 0; }
    table { border-collapse: collapse; width: 100%; margin: 12px 0; }
    th, td { border: 1px solid #d0d0d0; padding: 7px 12px; text-align: left; font-size: 13.5px; }
    th { background: #f5f5f5; font-weight: 600; }
    .ep-img { margin: 12px 0; text-align: center; }
    .ep-img img { max-width: 100%; border-radius: 6px; }
    .ep-callout { border-radius: 6px; padding: 12px 16px; margin: 10px 0; font-size: 14px; }
    .ep-math { text-align: center; font-style: italic; color: #333; margin: 10px 0; padding: 8px; background:#fafafa; border-radius:4px; }
    .ep-todo { margin: 3px 0; display: flex; gap: 8px; align-items: flex-start; }
    .ep-toggle { margin: 6px 0; }
    .ep-toggle strong { display: block; }
    .ep-toggle div { margin-left: 18px; color: #444; }
    .ep-pdf-ref { background: #f5f5f5; border: 1px solid #ddd; border-radius: 6px; padding: 10px 14px; margin: 10px 0; font-size: 13px; color: #555; }
    /* Consecutive lists merge visually */
    ul + ul, ol + ol { margin-top: -4px; }
    @media print {
      body { font-size: 13px; }
      .wrap { padding: 0; max-width: 100%; }
      h1.ep-title { font-size: 28px; }
      pre { font-size: 11px; }
    }
  </style>
</head>
<body>
<div class="wrap">
  <div class="ep-header">
    <h1 class="ep-title">${titleText}</h1>
    <div class="ep-meta">Axinote · Exported ${dateStr}</div>
    ${desc ? `<div class="ep-desc">${esc(desc)}</div>` : ''}
    ${tags ? `<div class="ep-tags">${tags}</div>` : ''}
  </div>
  <div class="ep-body">
${bodyHtml}
  </div>
</div>
<script>
  // Auto-open print dialog, then close tab when done
  window.addEventListener('load', () => {
    setTimeout(() => {
      window.print();
      window.addEventListener('afterprint', () => window.close());
    }, 300);
  });
<\/script>
</body>
</html>`;

  const blob = new Blob([html], { type: 'text/html;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const win = window.open(url, '_blank');
  if (win) {
    setTimeout(() => URL.revokeObjectURL(url), 60000);
  } else {
    // Pop-up blocked — fall back to download
    const a = document.createElement('a');
    a.href = url; a.download = (page.title || 'Axinote Note').replace(/[^\w\s-]/g, '').trim() + '.html';
    document.body.appendChild(a); a.click(); document.body.removeChild(a);
    setTimeout(() => URL.revokeObjectURL(url), 5000);
    toast('Downloaded as HTML — open it and print to PDF');
  }
}


// Table helpers
function tableAddRow(bid) {
  const b = S.page?.blocks?.find(b => b.id === bid); if (!b || b.type !== 'table') return;
  const cols = (b.headers || []).length || 3; b.rows.push(Array(cols).fill(''));
  scheduleSave(); renderBlocks();
}

function tableDelRow(bid, ri) {
  const b = S.page?.blocks?.find(b => b.id === bid); if (!b || b.type !== 'table') return;
  b.rows.splice(ri, 1); scheduleSave(); renderBlocks();
}

function tableAddCol(bid) {
  const b = S.page?.blocks?.find(b => b.id === bid); if (!b || b.type !== 'table') return;
  b.headers.push(`Column ${b.headers.length + 1}`);
  b.rows.forEach(r => r.push(''));
  scheduleSave(); renderBlocks();
}

function deleteBlock(bid) {
  if (!S.page?.blocks) return;
  S.page.blocks = S.page.blocks.filter(b => b.id !== bid);
  scheduleSave(); renderBlocks();
}

function handleBlockKey(e, bid) {
  const el = e.target; if (!el.classList.contains('b-el')) return;
  const blocks = S.page?.blocks; if (!blocks) return;
  const idx = blocks.findIndex(b => b.id === bid);
  if (e.key === 'Escape') { hideSlash(); removeFormatBar(); return; }
  // Slash key fallback – oninput can lag on some mobile keyboards
  if (e.key === '/' && !S.slashActive) {
    setTimeout(() => {
      const cur = document.querySelector(`[data-bid="${bid}"] .b-el`);
      if (cur && !S.slashActive) openSlash(cur, bid);
    }, 0);
  }
  if (S.slashActive) {
    const items = document.querySelectorAll('.slash-cmd'), hi = document.querySelector('.slash-cmd.hi');
    const hiIdx = hi ? Array.from(items).indexOf(hi) : -1;
    if (e.key === 'ArrowDown') { e.preventDefault(); const n = items[Math.min(hiIdx + 1, items.length - 1)]; if (hi) hi.classList.remove('hi'); if (n) { n.classList.add('hi'); n.scrollIntoView({ block: 'nearest' }); } return; }
    if (e.key === 'ArrowUp') { e.preventDefault(); const n = items[Math.max(hiIdx - 1, 0)]; if (hi) hi.classList.remove('hi'); if (n) { n.classList.add('hi'); n.scrollIntoView({ block: 'nearest' }); } return; }
    if (e.key === 'Enter') { e.preventDefault(); if (hi) hi.click(); return; }
    // Hide slash if backspace removes the /
    if (e.key === 'Backspace') {
      const text = el.textContent;
      const slashIdx = text.lastIndexOf('/');
      if (slashIdx < 0 || (slashIdx === text.length - 1 && text.length === 1)) { setTimeout(() => { if (el.textContent.indexOf('/') < 0) hideSlash(); }, 0); }
    }
  }
  if (e.key === 'Enter' && !e.shiftKey) {
    e.preventDefault();
    if (blocks[idx]) blocks[idx].content = el.textContent;
    const nb = { id: uid(), type: 'text', content: '' }; blocks.splice(idx + 1, 0, nb); scheduleSave(); renderBlocks();
    setTimeout(() => focusBlock(nb.id), 30); return;
  }
  if (e.key === 'Backspace' && el.textContent === '' && blocks.length > 1) {
    e.preventDefault();
    const prevId = blocks[Math.max(0, idx - 1)]?.id;
    blocks.splice(idx, 1); scheduleSave(); renderBlocks();
    setTimeout(() => { if (prevId) focusBlock(prevId, true); }, 30);
  }
}

function handleBlockInput(el, bid) {
  const text = el.textContent;
  const b = S.page?.blocks?.find(b => b.id === bid);
  if (b) b.content = el.innerHTML;

  if (S.slashActive) {
    // filter existing palette
    const slashIdx = text.lastIndexOf('/');
    if (slashIdx < 0) { hideSlash(); return; }
    const query = text.slice(slashIdx + 1);
    filterSlash(query);
  } else {
    // detect fresh / typed
    if (text.endsWith('/')) {
      openSlash(el, bid);
    }
  }
}

function openSlash(el, bid) {
  hideSlash();
  S.slashActive = true; S.slashBlockId = bid;

  // Use the block row element for reliable positioning
  const row = document.querySelector(`[data-bid="${bid}"]`) || el;
  const rect = row.getBoundingClientRect();
  const top = rect.bottom + 4;
  const left = rect.left + 16;

  const pal = document.createElement('div');
  pal.className = 'slash-pal'; pal.id = 'slash-pal';
  pal.style.cssText = `position:fixed!important;z-index:999999!important;top:${Math.min(top, window.innerHeight - 330)}px;left:${Math.min(Math.max(4, left), window.innerWidth - 280)}px;`;
  pal.innerHTML = buildSlashHTML('');
  document.body.appendChild(pal);
  wireSlashClicks(pal, bid);
  // Auto-highlight first item so Enter immediately works
  const firstItem = pal.querySelector('.slash-cmd');
  if (firstItem) firstItem.classList.add('hi');
  setTimeout(() => document.addEventListener('mousedown', slashOutsideClick), 50);
}

function wireSlashClicks(pal, bid) {
  pal.querySelectorAll('.slash-cmd').forEach(item => {
    item.addEventListener('mousedown', e => { e.preventDefault(); insertSlashBlock(item.dataset.type, bid); });
  });
}

function filterSlash(query) {
  const pal = document.getElementById('slash-pal'); if (!pal) return;
  const html = buildSlashHTML(query);
  if (!html) { hideSlash(); return; }
  pal.innerHTML = html;
  wireSlashClicks(pal, S.slashBlockId);
  // Keep first item highlighted after filter
  const firstItem = pal.querySelector('.slash-cmd');
  if (firstItem) firstItem.classList.add('hi');
}

function buildSlashHTML(query) {
  const filtered = SLASH_CMDS.filter(c => !query || c.name.toLowerCase().includes(query.toLowerCase()) || c.t.includes(query.toLowerCase()));
  if (!filtered.length) return '';
  let html = ''; const groups = {};
  filtered.forEach(c => { if (!groups[c.g]) groups[c.g] = []; groups[c.g].push(c); });
  Object.entries(groups).forEach(([grp, cmds]) => {
    html += `<div class="slash-grp">${grp}</div>`;
    cmds.forEach(c => {
      let iconStyle = '';
      const hlMap = { 'hl-yellow': '#fff9c4', 'hl-green': '#c8e6c9', 'hl-blue': '#bbdefb', 'hl-pink': '#f8bbd0', 'hl-purple': '#e1bee7' };
      const fontFamilyMap = { 'font-serif': 'Georgia,serif', 'font-mono': 'monospace', 'font-hand': 'cursive' };
      const isHtmlIcon = c.icon.includes('<');
      if (!isHtmlIcon) {
        if (hlMap[c.t]) iconStyle = `background:${hlMap[c.t]};border:none;`;
        if (fontFamilyMap[c.t]) iconStyle = `font-family:${fontFamilyMap[c.t]};font-size:13px;`;
      }
      html += `<div class="slash-cmd" data-type="${c.t}"><div class="slash-icon" style="${iconStyle}">${c.icon}</div><div><div class="slash-name">${c.name}</div><div class="slash-desc">${c.desc}</div></div></div>`;
    });
  });
  return html;
}

function showSlash(el, bid, query = '') { openSlash(el, bid); }

function slashOutsideClick(e) { if (!e.target.closest('#slash-pal')) hideSlash(); }
function hideSlash() { $('slash-pal')?.remove(); S.slashActive = false; S.slashBlockId = null; document.removeEventListener('mousedown', slashOutsideClick); }

async function insertSlashBlock(type, bid) {
  hideSlash();
  const blocks = S.page?.blocks; if (!blocks) return;
  const idx = blocks.findIndex(b => b.id === bid); if (idx < 0) return;

  // Remove the "/query" text the user typed to trigger the slash menu
  const curEl = document.querySelector(`[data-bid="${bid}"] .b-el`);
  if (curEl) {
    const text = curEl.textContent;
    const slashIdx = text.lastIndexOf('/');
    if (slashIdx >= 0) {
      curEl.textContent = text.slice(0, slashIdx);
      blocks[idx].content = curEl.innerHTML;
    }
  }

  // ── Inline formatting commands (apply to current selection if any) ──
  if (type.startsWith('fmt-') || type.startsWith('hl-')) {
    // Restore focus to the block first so selection stays
    const bel = document.querySelector(`[data-bid="${bid}"] .b-el`);
    bel?.focus();
    const sel = window.getSelection();
    const hasSelection = sel && !sel.isCollapsed;

    if (type === 'fmt-bold') { document.execCommand('bold'); }
    else if (type === 'fmt-italic') { document.execCommand('italic'); }
    else if (type === 'fmt-underline') { document.execCommand('underline'); }
    else if (type === 'fmt-strike') { document.execCommand('strikeThrough'); }
    else if (type === 'fmt-code') {
      if (hasSelection) {
        const range = sel.getRangeAt(0), text = range.toString();
        const code = document.createElement('code'); code.className = 'b-inline-code'; code.textContent = text;
        range.deleteContents(); range.insertNode(code); sel.removeAllRanges();
      }
    }
    else if (type === 'fmt-size-small') {
      if (hasSelection) { const r = sel.getRangeAt(0), t = r.toString(), sp = document.createElement('span'); sp.style.fontSize = '0.85em'; r.deleteContents(); r.insertNode(sp); sp.textContent = t; }
    }
    else if (type === 'fmt-size-large') {
      if (hasSelection) { const r = sel.getRangeAt(0), t = r.toString(), sp = document.createElement('span'); sp.style.fontSize = '1.25em'; r.deleteContents(); r.insertNode(sp); sp.textContent = t; }
    }
    else if (type === 'fmt-clear') { document.execCommand('removeFormat'); }
    else if (type === 'hl-yellow') { document.execCommand('hiliteColor', false, '#fff9c4'); }
    else if (type === 'hl-green') { document.execCommand('hiliteColor', false, '#c8e6c9'); }
    else if (type === 'hl-blue') { document.execCommand('hiliteColor', false, '#bbdefb'); }
    else if (type === 'hl-pink') { document.execCommand('hiliteColor', false, '#f8bbd0'); }
    else if (type === 'hl-purple') { document.execCommand('hiliteColor', false, '#e1bee7'); }
    else if (type === 'hl-clear') { document.execCommand('hiliteColor', false, 'transparent'); document.execCommand('removeFormat'); }

    saveCurrentBlock();
    return;
  }
  // For block-type changes, clear the block content (slash text already removed above)
  if (curEl) { curEl.textContent = ''; blocks[idx].content = ''; }
  if (type === 'divider') { blocks.splice(idx + 1, 0, { id: uid(), type: 'divider', content: '' }); }
  else if (type === 'table') {
    blocks[idx] = { id: blocks[idx].id, type: 'table', headers: ['Column 1', 'Column 2', 'Column 3'], rows: [['', '', ''], ['', '', '']] };
  } else if (type === 'image') {
    blocks[idx] = { id: blocks[idx].id, type: 'image', src: '', alt: '', caption: '' };
  } else if (type === 'pdf') {
    blocks[idx] = { id: blocks[idx].id, type: 'pdf', src: '', url: '', title: '' };
  } else if (type === 'toggle') {
    blocks[idx] = { id: blocks[idx].id, type: 'toggle', content: '', toggleContent: '', open: true };
  } else if (type === 'math') {
    blocks[idx] = { id: blocks[idx].id, type: 'math', content: '' };
  } else if (type.startsWith('font-') || type.startsWith('hl-')) {
    blocks[idx].type = type; blocks[idx].content = blocks[idx].content || '';
  } else {
    blocks[idx].type = type;
    if (type === 'callout') blocks[idx].variant = 'info';
    if (type === 'todo') blocks[idx].completed = false;
    if (type === 'task_block') { blocks[idx].taskId = uid(); blocks[idx].priority = 'med'; blocks[idx].due = ''; }
  }
  scheduleSave(); renderBlocks();
  if (type === 'task_block') {
    // Create corresponding global task after render
    setTimeout(() => initTaskBlock(blocks[idx]?.id), 60);
  }
  setTimeout(() => focusBlock(blocks[idx]?.id), 40);
}

// ── Toggle block ──
function toggleBlock(bid) {
  const b = S.page?.blocks?.find(b => b.id === bid); if (!b) return;
  b.open = !b.open; scheduleSave(); renderBlocks();
}

// ── Math block ──
function renderMathPreview(expr) {
  if (!expr) return '<span style="color:var(--text-faint);font-size:13px">Enter an expression above</span>';
  // Simple inline rendering — superscripts, fractions, greek letters
  let html = expr
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/\^\{([^}]+)\}/g, '<sup>$1</sup>').replace(/\^([^{\s])/g, '<sup>$1</sup>')
    .replace(/\_\{([^}]+)\}/g, '<sub>$1</sub>').replace(/\_([^{\s])/g, '<sub>$1</sub>')
    .replace(/\\frac\{([^}]+)\}\{([^}]+)\}/g, '<span class="math-frac"><span class="math-num">$1</span><span class="math-den">$2</span></span>')
    .replace(/\\sqrt\{([^}]+)\}/g, '√<span style="text-decoration:overline;padding:0 2px">$1</span>')
    .replace(/\\sum/g, '∑').replace(/\\int/g, '∫').replace(/\\prod/g, '∏')
    .replace(/\\infty/g, '∞').replace(/\\pi/g, 'π').replace(/\\alpha/g, 'α')
    .replace(/\\beta/g, 'β').replace(/\\gamma/g, 'γ').replace(/\\delta/g, 'δ')
    .replace(/\\theta/g, 'θ').replace(/\\lambda/g, 'λ').replace(/\\mu/g, 'μ')
    .replace(/\\sigma/g, 'σ').replace(/\\omega/g, 'ω').replace(/\\phi/g, 'φ')
    .replace(/\\leq/g, '≤').replace(/\\geq/g, '≥').replace(/\\neq/g, '≠')
    .replace(/\\approx/g, '≈').replace(/\\times/g, '×').replace(/\\div/g, '÷')
    .replace(/\\pm/g, '±').replace(/\\cdot/g, '·');
  return html;
}

function updateMathBlock(bid, val) {
  const b = S.page?.blocks?.find(b => b.id === bid); if (!b) return;
  b.content = val; scheduleSave();
  const prev = document.getElementById('math-prev-' + bid);
  if (prev) prev.innerHTML = renderMathPreview(val);
}

// ── Floating format bar ──
let _fmtBarActive = false;
function showFormatBar(sel) {
  removeFormatBar();
  if (sel.isCollapsed || !sel.toString().trim()) return;
  const range = sel.getRangeAt(0);
  const rect = range.getBoundingClientRect();
  if (!rect.width) return;
  const bar = document.createElement('div');
  bar.id = 'fmt-bar'; bar.className = 'fmt-bar';
  bar.innerHTML = `
    <button class="fmt-btn" title="Bold" onclick="fmtDo('bold')"><b>B</b></button>
    <button class="fmt-btn" title="Italic" onclick="fmtDo('italic')"><i>I</i></button>
    <button class="fmt-btn" title="Underline" onclick="fmtDo('underline')"><u>U</u></button>
    <button class="fmt-btn" title="Strikethrough" onclick="fmtDo('strikeThrough')"><s>S</s></button>
    <div class="fmt-sep"></div>
    <button class="fmt-btn" title="Inline Code" onclick="fmtCode()"><span style="font-family:var(--mono);font-size:11px">&lt;/&gt;</span></button>
    <div class="fmt-sep"></div>
    <span class="fmt-lbl">Highlight</span>
    <button class="fmt-hl fmt-hl-yellow" title="Yellow" onclick="fmtHighlight('yellow')"></button>
    <button class="fmt-hl fmt-hl-green"  title="Green"  onclick="fmtHighlight('green')"></button>
    <button class="fmt-hl fmt-hl-blue"   title="Blue"   onclick="fmtHighlight('blue')"></button>
    <button class="fmt-hl fmt-hl-pink"   title="Pink"   onclick="fmtHighlight('pink')"></button>
    <button class="fmt-hl fmt-hl-purple" title="Purple" onclick="fmtHighlight('purple')"></button>
    <button class="fmt-hl fmt-hl-clear"  title="Clear"  onclick="fmtHighlight('')"><svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg></button>
    <div class="fmt-sep"></div>
    <span class="fmt-lbl">Size</span>
    <button class="fmt-btn" title="Small" onclick="fmtSize('0.85em')">S</button>
    <button class="fmt-btn" title="Large" onclick="fmtSize('1.25em')">L</button>
    <button class="fmt-btn" title="Normal" onclick="fmtSize('')">N</button>
    <div class="fmt-sep"></div>
    <button class="fmt-btn" title="Clear formatting" onclick="fmtClear()" style="font-size:11px;color:var(--text-muted);display:flex;align-items:center;gap:3px"><svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg> Clear</button>
  `;
  const top = rect.top + window.scrollY - 44;
  const left = Math.max(8, Math.min(rect.left + window.scrollX + (rect.width / 2) - bar.offsetWidth / 2, window.innerWidth - 440));
  bar.style.top = top + 'px';
  bar.style.left = left + 'px';
  document.body.appendChild(bar);
  // Position after render
  requestAnimationFrame(() => {
    const bw = bar.offsetWidth;
    bar.style.left = Math.max(8, Math.min(rect.left + window.scrollX + (rect.width / 2) - bw / 2, window.innerWidth - bw - 8)) + 'px';
  });
  _fmtBarActive = true;
}

function removeFormatBar() {
  document.getElementById('fmt-bar')?.remove();
  _fmtBarActive = false;
}

function fmtDo(cmd) {
  document.execCommand(cmd);
  saveCurrentBlock();
  removeFormatBar();
}

function fmtCode() {
  const sel = window.getSelection(); if (!sel || sel.isCollapsed) return;
  const range = sel.getRangeAt(0);
  const text = range.toString();
  const code = document.createElement('code');
  code.className = 'b-inline-code';
  code.textContent = text;
  range.deleteContents();
  range.insertNode(code);
  sel.removeAllRanges();
  saveCurrentBlock();
  removeFormatBar();
}

function fmtHighlight(color) {
  const sel = window.getSelection(); if (!sel || sel.isCollapsed) return;
  const range = sel.getRangeAt(0);
  const hlColors = { yellow: '#fff9c4', green: '#c8e6c9', blue: '#bbdefb', pink: '#f8bbd0', purple: '#e1bee7' };
  if (color && hlColors[color]) {
    document.execCommand('hiliteColor', false, hlColors[color]);
  } else {
    document.execCommand('hiliteColor', false, 'transparent');
    document.execCommand('removeFormat');
  }
  saveCurrentBlock();
  removeFormatBar();
}

function fmtSize(size) {
  const sel = window.getSelection(); if (!sel || sel.isCollapsed) return;
  const range = sel.getRangeAt(0);
  const text = range.toString();
  if (!size) { document.execCommand('removeFormat'); saveCurrentBlock(); removeFormatBar(); return; }
  const span = document.createElement('span');
  span.style.fontSize = size;
  range.deleteContents();
  range.insertNode(span);
  span.textContent = text;
  saveCurrentBlock();
  removeFormatBar();
}

function fmtClear() {
  document.execCommand('removeFormat');
  saveCurrentBlock();
  removeFormatBar();
}

function saveCurrentBlock() {
  const sel = window.getSelection();
  if (!sel || !sel.anchorNode) return;
  const row = sel.anchorNode.parentElement?.closest('[data-bid]');
  if (!row) return;
  const bid = row.dataset.bid;
  const b = S.page?.blocks?.find(b => b.id === bid); if (!b) return;
  const bel = row.querySelector('.b-el');
  if (bel) b.content = bel.innerHTML;
  scheduleSave();
}

// Listen for selection to show format bar
document.addEventListener('selectionchange', () => {
  const sel = window.getSelection();
  if (!sel || sel.isCollapsed || !sel.toString().trim()) {
    if (_fmtBarActive && !document.getElementById('fmt-bar')?.matches(':hover')) {
      setTimeout(() => {
        const sel2 = window.getSelection();
        if (!sel2 || sel2.isCollapsed) removeFormatBar();
      }, 150);
    }
    return;
  }
  // Only show in blocks-wrap
  const anchor = sel.anchorNode?.parentElement?.closest('.blocks-wrap');
  if (!anchor) return;
  clearTimeout(window._fmtBarTimeout);
  window._fmtBarTimeout = setTimeout(() => showFormatBar(sel), 120);
});

function focusBlock(id, atEnd = false) {
  if (!id) return;
  const el = document.querySelector(`[data-bid="${id}"] .b-el`); if (!el) return;
  el.focus();
  if (atEnd) { const r = document.createRange(); r.selectNodeContents(el); r.collapse(false); const s = window.getSelection(); s.removeAllRanges(); s.addRange(r); }
}

async function toggleBlockTodo(bid) { const b = S.page?.blocks?.find(b => b.id === bid); if (!b) return; b.completed = !b.completed; scheduleSave(); renderBlocks(); }

function updateWordCount() {
  const el = $('word-count'); if (!el || !S.page) return;
  const text = (S.page.blocks || []).map(b => { const d = document.createElement('div'); d.innerHTML = b.content || ''; return d.textContent; }).join(' ').trim();
  const n = text ? text.split(/\s+/).length : 0;
  el.textContent = `${n} word${n !== 1 ? 's' : ''}`;
}

async function createPage(tmpl = null) {
  closeTemplatePicker();
  const id = uid(); const now = new Date().toISOString();
  const page = { id, title: tmpl?.title || 'Untitled', description: '', blocks: (tmpl?.blocks || []).map(b => ({ ...b, id: uid() })), tags: [], createdAt: now, updatedAt: now };
  S.pages.unshift(page); S.page = page; S.deck = null; S.view = 'page';
  await saveData('pages', { [id]: page });
  closeSidebarAfterNavigate();
  syncRouteWithState({ push: true });
  renderApp();
  setTimeout(() => { const t = $('page-title'); if (t) { t.focus(); const r = document.createRange(); r.selectNodeContents(t); r.collapse(false); const s = window.getSelection(); s.removeAllRanges(); s.addRange(r); } }, 80);
}

async function openPage(id, options = {}) {
  const { pushHistory = true, replaceHistory = false } = options;
  const page = S.pages.find(p => p.id === id); if (!page) return;
  S.page = page; S.deck = null; S.view = 'page';
  closeSidebarAfterNavigate();
  syncRouteWithState({ push: pushHistory, replace: replaceHistory });
  renderApp();
}

// ─── TEMPLATE PICKER ──────────────────────────────────────────
const TMPL_ICONS = {
  blank: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>`,
  lecture: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M22 10v6M2 10l10-5 10 5-10 5z"/><path d="M6 12v5c3 3 9 3 12 0v-5"/></svg>`,
  session: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>`,
  exam: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M9 11l3 3L22 4"/><path d="M21 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11"/></svg>`,
  essay: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 20h9"/><path d="M16.5 3.5a2.121 2.121 0 0 1 3 3L7 19l-4 1 1-4L16.5 3.5z"/></svg>`,
  studyplan: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="4" width="18" height="18" rx="2"/><line x1="16" y1="2" x2="16" y2="6"/><line x1="8" y1="2" x2="8" y2="6"/><line x1="3" y1="10" x2="21" y2="10"/></svg>`,
  review: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><polyline points="23 4 23 10 17 10"/><polyline points="1 20 1 14 7 14"/><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/></svg>`,
  project: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><line x1="8" y1="6" x2="21" y2="6"/><line x1="8" y1="12" x2="21" y2="12"/><line x1="8" y1="18" x2="21" y2="18"/><line x1="3" y1="6" x2="3.01" y2="6"/><line x1="3" y1="12" x2="3.01" y2="12"/><line x1="3" y1="18" x2="3.01" y2="18"/></svg>`,
  book: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M4 19.5A2.5 2.5 0 0 1 6.5 17H20"/><path d="M6.5 2H20v20H6.5A2.5 2.5 0 0 1 4 19.5v-15A2.5 2.5 0 0 1 6.5 2z"/></svg>`,
  meeting: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg>`,
  calloutIcon: `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>`,
  todo: `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="18" height="18" rx="3"/></svg>`,
  clearFmt: `<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>`,

};

const TEMPLATES = [
  // ─── STUDY ────────────────────────────────────────────────────────────────
  {
    label: 'Lecture Notes', desc: 'Objectives, key terms, summary & follow-ups', icon: 'lecture', cat: 'Study',
    title: 'Lecture Notes',
    blocks: [
      { type: 'h1', content: '' },
      { type: 'text', content: 'Date: &nbsp;&nbsp;&nbsp;&nbsp;&nbsp; Course: &nbsp;&nbsp;&nbsp; Lecturer:' },
      { type: 'divider', content: '' },
      { type: 'callout', content: 'Learning objectives — what should I understand by the end of this lecture?', variant: 'tip' },
      { type: 'h2', content: 'Main Notes' },
      { type: 'text', content: '' },
      { type: 'h2', content: 'Key Terms & Definitions' },
      { type: 'bullet', content: 'Term — definition' },
      { type: 'bullet', content: 'Term — definition' },
      { type: 'h2', content: 'Examples & Illustrations' },
      { type: 'text', content: '' },
      { type: 'h2', content: 'Questions That Came Up' },
      { type: 'numbered', content: '' },
      { type: 'divider', content: '' },
      { type: 'h2', content: 'Summary' },
      { type: 'text', content: 'In one paragraph, what was this lecture about?' },
      { type: 'h2', content: 'Follow-up Actions' },
      { type: 'todo', content: 'Review slides' },
      { type: 'todo', content: 'Read textbook pages: ' },
      { type: 'todo', content: 'Attempt practice problems' },
    ]
  },
  {
    label: 'Study Session', desc: 'Log topics covered, struggles & next steps', icon: 'session', cat: 'Study',
    title: 'Study Session',
    blocks: [
      { type: 'h1', content: 'Study Session' },
      { type: 'text', content: 'Date: &nbsp;&nbsp;&nbsp;&nbsp;&nbsp; Duration: &nbsp;&nbsp; Subject:' },
      { type: 'divider', content: '' },
      { type: 'h2', content: 'Topics Covered' },
      { type: 'numbered', content: '' },
      { type: 'numbered', content: '' },
      { type: 'h2', content: 'What I Understood Well' },
      { type: 'bullet', content: '' },
      { type: 'h2', content: 'What I Struggled With' },
      { type: 'bullet', content: '' },
      { type: 'callout', content: 'Flag these for extra review in your next session.', variant: 'warning' },
      { type: 'h2', content: 'Questions to Resolve' },
      { type: 'numbered', content: '' },
      { type: 'h2', content: 'Notes' },
      { type: 'text', content: '' },
      { type: 'h2', content: 'Next Steps' },
      { type: 'todo', content: '' },
      { type: 'todo', content: '' },
    ]
  },
  {
    label: 'Exam Revision', desc: 'Topic checklist, formulas, weak areas & practice Qs', icon: 'exam', cat: 'Study',
    title: 'Exam Revision',
    blocks: [
      { type: 'h1', content: 'Exam Revision' },
      { type: 'text', content: 'Exam Date: &nbsp;&nbsp; Subject: &nbsp;&nbsp;&nbsp; Format:' },
      { type: 'callout', content: 'Goal: what grade am I aiming for, and what do I need to get there?', variant: 'tip' },
      { type: 'divider', content: '' },
      { type: 'h2', content: 'Topics Checklist' },
      { type: 'todo', content: 'Topic 1' },
      { type: 'todo', content: 'Topic 2' },
      { type: 'todo', content: 'Topic 3' },
      { type: 'h2', content: 'Key Formulas & Definitions' },
      { type: 'bullet', content: 'Formula:' },
      { type: 'bullet', content: 'Definition:' },
      { type: 'h2', content: 'Weak Areas' },
      { type: 'callout', content: 'These are the concepts I need the most time on.', variant: 'warning' },
      { type: 'bullet', content: '' },
      { type: 'h2', content: 'Practice Questions' },
      { type: 'h3', content: 'Q1' },
      { type: 'text', content: 'A:' },
      { type: 'h3', content: 'Q2' },
      { type: 'text', content: 'A:' },
      { type: 'divider', content: '' },
      { type: 'h2', content: 'Day Before Checklist' },
      { type: 'todo', content: 'Review all key formulas' },
      { type: 'todo', content: 'Complete one timed past paper' },
      { type: 'todo', content: 'Get 8 hours of sleep' },
    ]
  },
  {
    label: 'Essay / Assignment', desc: 'Brief, thesis, outline, sources & draft', icon: 'essay', cat: 'Study',
    title: 'Essay',
    blocks: [
      { type: 'h1', content: 'Essay Title' },
      { type: 'text', content: 'Due Date: &nbsp;&nbsp;&nbsp; Course: &nbsp;&nbsp;&nbsp; Word Count:' },
      { type: 'callout', content: 'Assignment brief — what exactly am I being asked to do?', variant: 'info' },
      { type: 'divider', content: '' },
      { type: 'h2', content: 'Thesis Statement' },
      { type: 'quote', content: 'Write your central argument here — one or two clear sentences.' },
      { type: 'h2', content: 'Outline' },
      { type: 'numbered', content: 'Introduction' },
      { type: 'numbered', content: 'Body paragraph 1 —' },
      { type: 'numbered', content: 'Body paragraph 2 —' },
      { type: 'numbered', content: 'Body paragraph 3 —' },
      { type: 'numbered', content: 'Conclusion' },
      { type: 'h2', content: 'Sources & References' },
      { type: 'bullet', content: '' },
      { type: 'bullet', content: '' },
      { type: 'h2', content: 'Draft' },
      { type: 'text', content: '' },
      { type: 'divider', content: '' },
      { type: 'h2', content: 'Submission Checklist' },
      { type: 'todo', content: 'Word count within range' },
      { type: 'todo', content: 'All sources cited correctly' },
      { type: 'todo', content: 'Proofread for grammar & clarity' },
      { type: 'todo', content: 'Submitted before deadline' },
    ]
  },
  // ─── PLANNING ─────────────────────────────────────────────────────────────
  {
    label: 'Study Plan', desc: 'Weekly goals, subject schedule & daily sessions', icon: 'studyplan', cat: 'Planning',
    title: 'Study Plan',
    blocks: [
      { type: 'h1', content: 'Study Plan' },
      { type: 'text', content: 'Week of: &nbsp;&nbsp;&nbsp;&nbsp; Main goal:' },
      { type: 'callout', content: 'Why does this week matter? What are you working toward?', variant: 'tip' },
      { type: 'divider', content: '' },
      { type: 'h2', content: 'Subject Priorities' },
      { type: 'numbered', content: '' },
      { type: 'numbered', content: '' },
      { type: 'numbered', content: '' },
      { type: 'h2', content: 'Daily Schedule' },
      { type: 'h3', content: 'Monday' },
      { type: 'bullet', content: '' },
      { type: 'h3', content: 'Tuesday' },
      { type: 'bullet', content: '' },
      { type: 'h3', content: 'Wednesday' },
      { type: 'bullet', content: '' },
      { type: 'h3', content: 'Thursday' },
      { type: 'bullet', content: '' },
      { type: 'h3', content: 'Friday' },
      { type: 'bullet', content: '' },
      { type: 'divider', content: '' },
      { type: 'h2', content: 'This Week\'s Tasks' },
      { type: 'todo', content: '' },
      { type: 'todo', content: '' },
      { type: 'todo', content: '' },
    ]
  },
  {
    label: 'Weekly Review', desc: 'Reflect on the week and plan the next one', icon: 'review', cat: 'Planning',
    title: 'Weekly Review',
    blocks: [
      { type: 'h1', content: 'Weekly Review' },
      { type: 'text', content: 'Week of:' },
      { type: 'divider', content: '' },
      { type: 'h2', content: 'What I Accomplished' },
      { type: 'bullet', content: '' },
      { type: 'bullet', content: '' },
      { type: 'h2', content: 'What I Struggled With' },
      { type: 'bullet', content: '' },
      { type: 'h2', content: 'What I Learned About Myself' },
      { type: 'text', content: '' },
      { type: 'callout', content: 'Overall mood: &nbsp;&nbsp; Energy level: &nbsp;&nbsp; Productivity: /10', variant: 'info' },
      { type: 'divider', content: '' },
      { type: 'h2', content: 'Next Week\'s Priorities' },
      { type: 'numbered', content: '' },
      { type: 'numbered', content: '' },
      { type: 'numbered', content: '' },
      { type: 'h2', content: 'Goals for Next Week' },
      { type: 'todo', content: '' },
      { type: 'todo', content: '' },
      { type: 'todo', content: '' },
    ]
  },
  {
    label: 'Project Tracker', desc: 'Overview, milestones, tasks & blockers', icon: 'project', cat: 'Planning',
    title: 'Project',
    blocks: [
      { type: 'h1', content: 'Project Name' },
      { type: 'text', content: 'Deadline: &nbsp;&nbsp;&nbsp; Team: &nbsp;&nbsp;&nbsp;&nbsp;&nbsp; Deliverable:' },
      { type: 'callout', content: 'Status: In Progress', variant: 'warning' },
      { type: 'divider', content: '' },
      { type: 'h2', content: 'Overview' },
      { type: 'text', content: 'What is this project trying to achieve?' },
      { type: 'h2', content: 'Milestones' },
      { type: 'numbered', content: 'Milestone 1 — due:' },
      { type: 'numbered', content: 'Milestone 2 — due:' },
      { type: 'numbered', content: 'Milestone 3 — due:' },
      { type: 'h2', content: 'Tasks' },
      { type: 'todo', content: '' },
      { type: 'todo', content: '' },
      { type: 'todo', content: '' },
      { type: 'h2', content: 'Blockers' },
      { type: 'callout', content: 'Note anything blocking progress here.', variant: 'warning' },
      { type: 'h2', content: 'Notes' },
      { type: 'text', content: '' },
    ]
  },
  // ─── GENERAL ──────────────────────────────────────────────────────────────
  {
    label: 'Book Notes', desc: 'Chapters, key ideas, quotes & takeaways', icon: 'book', cat: 'General',
    title: 'Book Notes',
    blocks: [
      { type: 'h1', content: 'Book Title' },
      { type: 'text', content: 'Author: &nbsp;&nbsp;&nbsp;&nbsp;&nbsp; Date Read: &nbsp;&nbsp;&nbsp; <svg width="12" height="12" viewBox="0 0 24 24" fill="currentColor" stroke="none" style="color:#f59e0b;vertical-align:middle;margin-right:2px"><polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"/></svg> Rating: /5' },
      { type: 'callout', content: 'Why am I reading this? What do I want to get out of it?', variant: 'tip' },
      { type: 'divider', content: '' },
      { type: 'h2', content: 'One-Sentence Summary' },
      { type: 'text', content: '' },
      { type: 'h2', content: 'Key Takeaways' },
      { type: 'numbered', content: '' },
      { type: 'numbered', content: '' },
      { type: 'numbered', content: '' },
      { type: 'h2', content: 'Notable Quotes' },
      { type: 'quote', content: '' },
      { type: 'h2', content: 'Chapter Notes' },
      { type: 'h3', content: 'Chapter 1:' },
      { type: 'bullet', content: '' },
      { type: 'h3', content: 'Chapter 2:' },
      { type: 'bullet', content: '' },
      { type: 'h2', content: 'New Vocabulary & Concepts' },
      { type: 'bullet', content: 'Term — meaning' },
      { type: 'divider', content: '' },
      { type: 'h2', content: 'Would I Recommend This?' },
      { type: 'text', content: '' },
    ]
  },
  {
    label: 'Meeting Notes', desc: 'Agenda, discussion, decisions & action items', icon: 'meeting', cat: 'General',
    title: 'Meeting Notes',
    blocks: [
      { type: 'h1', content: 'Meeting Notes' },
      { type: 'text', content: 'Date: &nbsp;&nbsp;&nbsp;&nbsp;&nbsp; Time: &nbsp;&nbsp;&nbsp;&nbsp;&nbsp; Location:' },
      { type: 'text', content: 'Attendees:' },
      { type: 'divider', content: '' },
      { type: 'h2', content: 'Agenda' },
      { type: 'numbered', content: '' },
      { type: 'numbered', content: '' },
      { type: 'numbered', content: '' },
      { type: 'h2', content: 'Discussion' },
      { type: 'text', content: '' },
      { type: 'h2', content: 'Decisions Made' },
      { type: 'bullet', content: '' },
      { type: 'bullet', content: '' },
      { type: 'h2', content: 'Action Items' },
      { type: 'todo', content: '' },
      { type: 'todo', content: '' },
      { type: 'h2', content: 'Next Meeting' },
      { type: 'callout', content: 'Next meeting: ', variant: 'info' },
    ]
  },
  {
    label: 'Blank', desc: 'Start from scratch', icon: 'blank', cat: 'General',
    title: 'Untitled',
    blocks: []
  },
];

function showTemplatePicker() {
  closeTemplatePicker();
  const bg = el('div', 'modal-bg'); bg.id = 'tmpl-bg';
  const cats = [...new Set(TEMPLATES.map(t => t.cat))];
  const sections = cats.map(cat => {
    const items = TEMPLATES.filter(t => t.cat === cat);
    const cards = items.map((t, _) => {
      const idx = TEMPLATES.indexOf(t);
      return `<div class="tmpl-card" onclick="createPage(TEMPLATES[${idx}])">
        <div class="tmpl-card-icon">${TMPL_ICONS[t.icon] || TMPL_ICONS.blank}</div>
        <div class="tmpl-name">${t.label}</div>
        <div class="tmpl-desc">${t.desc}</div>
      </div>`;
    }).join('');
    return `<div class="tmpl-cat-label">${cat}</div><div class="tmpl-grid">${cards}</div>`;
  }).join('');
  bg.innerHTML = `
    <div class="modal" style="width:580px;max-height:80vh;overflow-y:auto">
      <div class="modal-title">New Page</div>
      <p style="color:var(--text-muted);font-size:13px;margin-bottom:2px">Choose a template to get started</p>
      ${sections}
      <div class="modal-foot"><button class="btn btn-ghost btn-sm" onclick="closeTemplatePicker()">Cancel</button></div>
    </div>`;
  bg.addEventListener('click', e => { if (e.target === bg) closeTemplatePicker(); });
  document.body.appendChild(bg);
  requestAnimationFrame(() => bg.classList.add('show'));
}

function closeTemplatePicker() { $('tmpl-bg')?.remove(); }

// ─── DATABASE ─────────────────────────────────────────────────
// ─── DATABASE ────────────────────────────────────────────────

const DB_TYPES = {
  text: { label: 'Text', sym: 'Aa' },
  number: { label: 'Number', sym: '#' },
  select: { label: 'Select', sym: '◉' },
  date: { label: 'Date', sym: '▦' },
  checkbox: { label: 'Checkbox', sym: '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>' },
  url: { label: 'URL', sym: '⌘' },
};

function renderDatabase(c) {
  const db = S.page; if (!db) return;
  if (!S.dbSort) S.dbSort = { colId: null, dir: 'asc' };
  if (!S.dbFilter) S.dbFilter = '';
  if (!S.dbView) S.dbView = 'table';
  c.innerHTML = `
    <div style="display:flex;align-items:baseline;gap:10px;margin-bottom:18px">
      <div class="page-title-el" id="db-title" contenteditable="true" style="font-size:32px" spellcheck="false">${esc(db.title) || 'Untitled Database'}</div>
    </div>
    <div class="db-toolbar">
      <div style="display:flex;gap:7px;align-items:center;flex-wrap:wrap;flex:1">
        <div class="db-search-wrap">${icons.search}<input id="db-filter-inp" class="db-filter-inp" placeholder="Filter rows…" value="${S.dbFilter || ''}"></div>
        <button class="btn btn-action btn-sm" onclick="addDbRow()">${icons.plus} Row</button>
        <button class="btn btn-secondary btn-sm" onclick="openAddColModal()">${icons.plus} Column</button>
      </div>
      <div class="db-view-btns">
        <button class="db-view-btn${(!S.dbView || S.dbView === 'table') ? ' active' : ''}" onclick="setDbView('table')" title="Table">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="18" height="18" rx="2"/><path d="M3 9h18M3 15h18M9 3v18"/></svg>
        </button>
        <button class="db-view-btn${S.dbView === 'card' ? ' active' : ''}" onclick="setDbView('card')" title="Cards">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/></svg>
        </button>
      </div>
    </div>
    <div id="db-add-col-panel" style="display:none;margin-bottom:14px"></div>
    <div id="db-body"></div>`;

  $('db-title').addEventListener('blur', () => { db.title = $('db-title').textContent.trim() || 'Untitled Database'; saveData('databases', { [db.id]: db }); });
  const fi = $('db-filter-inp');
  if (fi) {
    fi.addEventListener('input', () => { S.dbFilter = fi.value; renderDbBody(); });
    fi.addEventListener('keydown', e => { if (e.key === 'Escape') { S.dbFilter = ''; fi.value = ''; renderDbBody(); } });
  }
  renderDbBody();
}

function setDbView(v) { S.dbView = v; renderDbBody(); }

function dbGetRows() {
  const db = S.page; if (!db) return [];
  let rows = (db.rows || []).map((row, i) => ({ ...row, _ri: i }));
  const f = (S.dbFilter || '').toLowerCase().trim();
  if (f) rows = rows.filter(row => db.columns.some(col => String(row[col.id] ?? '').toLowerCase().includes(f)));
  if (S.dbSort?.colId) {
    const col = db.columns.find(c => c.id === S.dbSort.colId);
    const dir = S.dbSort.dir === 'asc' ? 1 : -1;
    rows.sort((a, b) => {
      let av = a[S.dbSort.colId] ?? '', bv = b[S.dbSort.colId] ?? '';
      if (col?.type === 'number') { av = parseFloat(av) || 0; bv = parseFloat(bv) || 0; }
      else if (col?.type === 'checkbox') { av = av === true || av === 'true' ? 1 : 0; bv = bv === true || bv === 'true' ? 1 : 0; }
      return av > bv ? dir : av < bv ? -dir : 0;
    });
  }
  return rows;
}

function dbSetSort(colId) {
  if (!S.dbSort) S.dbSort = { colId: null, dir: 'asc' };
  if (S.dbSort.colId === colId) S.dbSort.dir = S.dbSort.dir === 'asc' ? 'desc' : 'asc';
  else S.dbSort = { colId, dir: 'asc' };
  renderDbBody();
}

function renderDbBody() {
  const body = $('db-body'); if (!body || !S.page) return;
  if (S.dbView === 'card') renderDbCard(body); else renderDbTable(body);
}

function renderDbTable(body) {
  const db = S.page;
  const rows = dbGetRows();
  const sortArrow = (colId) => {
    if (S.dbSort?.colId !== colId) return '<svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" opacity=".35"><path d="M7 16V4m0 0L3 8m4-4 4 4M17 8v12m0 0 4-4m-4 4-4-4"/></svg>';
    return S.dbSort.dir === 'asc'
      ? '<svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 5v14M5 12l7-7 7 7"/></svg>'
      : '<svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 19V5M5 12l7 7 7-7"/></svg>';
  };
  let html = `<div class="db-wrap"><table class="db-table">
    <thead><tr>
      ${db.columns.map(col => `<th class="db-th" onclick="dbSetSort('${col.id}')">
        <div class="db-th-inner">
          <span class="db-col-sym">${DB_TYPES[col.type || 'text']?.sym || 'Aa'}</span>
          <span class="db-col-hd-name" id="dbn-${col.id}" ondblclick="event.stopPropagation();startDbColRename('${col.id}')">${esc(col.name)}</span>
          <span class="db-sort-arr">${sortArrow(col.id)}</span>
          <button class="db-col-del icon-btn" onclick="event.stopPropagation();deleteDbCol('${col.id}')" style="opacity:0">${icons.trash}</button>
        </div>
      </th>`).join('')}
      <th class="db-th-act"></th>
    </tr></thead>
    <tbody>
      ${rows.map(row => `<tr class="db-row" data-ri="${row._ri}">
        ${db.columns.map(col => `<td class="db-td">${renderDbCell(col, row[col.id], row._ri)}</td>`).join('')}
        <td class="db-td db-td-act">
          <button class="icon-btn db-expand-btn" onclick="openRowModal(${row._ri})" title="Expand" style="opacity:0;width:22px;height:22px">
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="15 3 21 3 21 9"/><polyline points="9 21 3 21 3 15"/><line x1="21" y1="3" x2="14" y2="10"/><line x1="3" y1="21" x2="10" y2="14"/></svg>
          </button>
          <button class="icon-btn db-del-row-btn" onclick="deleteDbRow(${row._ri})" style="opacity:0;width:22px;height:22px">${icons.trash}</button>
        </td>
      </tr>`).join('')}
    </tbody>
    ${renderDbFooter(rows)}
  </table></div>`;
  if (!rows.length) html += `<div class="empty" style="padding:32px 0"><div class="empty-icon">${icons.db}</div><div class="empty-title">${S.dbFilter ? 'No matching rows' : 'No rows yet'}</div><p class="empty-sub">${S.dbFilter ? 'Try a different filter' : 'Click "+ Row" to add data'}</p></div>`;
  body.innerHTML = html;

  // Hover reveals
  body.querySelectorAll('.db-row').forEach(row => {
    const btns = row.querySelectorAll('.db-expand-btn,.db-del-row-btn');
    row.addEventListener('mouseenter', () => btns.forEach(b => b.style.opacity = '1'));
    row.addEventListener('mouseleave', () => btns.forEach(b => b.style.opacity = '0'));
  });
  body.querySelectorAll('.db-th').forEach(th => {
    const del = th.querySelector('.db-col-del');
    if (del) { th.addEventListener('mouseenter', () => del.style.opacity = '0.7'); th.addEventListener('mouseleave', () => del.style.opacity = '0'); }
  });
}

function renderDbFooter(rows) {
  const db = S.page; if (!db) return '';
  const hasNum = db.columns.some(c => c.type === 'number');
  if (!hasNum || !rows.length) return '';
  return `<tfoot><tr>${db.columns.map(col => {
    if (col.type !== 'number') return '<td class="db-foot-td"></td>';
    const vals = rows.map(r => parseFloat(r[col.id]) || 0);
    const sum = vals.reduce((a, b) => a + b, 0);
    const avg = vals.length ? (sum / vals.length).toFixed(1) : '—';
    return `<td class="db-foot-td"><span class="db-foot-sum">Σ ${sum.toLocaleString()}</span> <span class="db-foot-avg">avg ${avg}</span></td>`;
  }).join('')}<td class="db-foot-td"></td></tr></tfoot>`;
}

function renderDbCard(body) {
  const db = S.page; const rows = dbGetRows();
  if (!rows.length) { body.innerHTML = `<div class="empty"><div class="empty-icon">${icons.db}</div><div class="empty-title">${S.dbFilter ? 'No matching rows' : 'No rows yet'}</div><p class="empty-sub">Click "+ Row" to add data</p></div>`; return; }
  const primary = db.columns[0];
  body.innerHTML = `<div class="db-card-grid">${rows.map(row => `
    <div class="db-card" onclick="openRowModal(${row._ri})">
      <div class="db-card-title">${esc(row[primary?.id]) || 'Untitled'}</div>
      ${db.columns.slice(1).map(col => {
    const v = row[col.id]; if (v === '' || v === null || v === undefined) return '';
    return `<div class="db-card-field"><span class="db-card-flabel">${esc(col.name)}</span><span class="db-card-fval">${renderDbCellDisplay(col, v)}</span></div>`;
  }).filter(Boolean).join('')}
    </div>`).join('')}</div>`;
}

function renderDbCell(col, value, ri) {
  const t = col.type || 'text';
  if (t === 'checkbox') {
    const on = value === true || value === 'true';
    return `<div class="db-chk${on ? ' db-chk-on' : ''}" onclick="toggleDbChk(${ri},'${col.id}')">${on ? icons.ok : ''}</div>`;
  }
  if (t === 'select') {
    const opts = col.options || [];
    const cur = opts.find(o => o.id === value || o.label === value);
    return `<div class="db-sel-wrap" style="min-width:80px;min-height:32px;position:relative;display:flex;align-items:center;padding:4px 8px">
      ${cur ? `<span class="db-badge db-badge-${cur.color || 'blue'}">${cur.label}</span>` : '<span style="color:var(--text-faint);font-size:12px">—</span>'}
      <select class="db-sel-native" onchange="updateDbCell(${ri},'${col.id}',this.value);setTimeout(()=>renderDbBody(),50)" onclick="event.stopPropagation()">
        <option value="">—</option>
        ${opts.map(o => `<option value="${o.label}"${(value === o.id || value === o.label) ? 'selected' : ''}>${o.label}</option>`).join('')}
      </select>
    </div>`;
  }
  if (t === 'date') return `<input type="date" class="db-date-inp" value="${value || ''}" onchange="updateDbCell(${ri},'${col.id}',this.value)" onclick="event.stopPropagation()">`;
  if (t === 'url') return value
    ? `<a href="${value}" target="_blank" class="db-url-link" onclick="event.stopPropagation()">${value.replace(/^https?:\/\//, '').slice(0, 30)}</a>`
    : `<div class="db-cell-edit" contenteditable="true" onblur="updateDbCell(${ri},'${col.id}',this.textContent)" spellcheck="false" data-ph="Enter URL…"></div>`;
  if (t === 'number') return `<div class="db-cell-edit db-cell-num" contenteditable="true" onblur="updateDbCell(${ri},'${col.id}',this.textContent)" spellcheck="false">${value ?? ''}</div>`;
  return `<div class="db-cell-edit" contenteditable="true" onblur="updateDbCell(${ri},'${col.id}',this.textContent)" spellcheck="false">${value || ''}</div>`;
}

function renderDbCellDisplay(col, value) {
  const t = col.type || 'text';
  if (t === 'checkbox') return (value === true || value === 'true') ? `<span style="color:var(--green)">${icons.ok}</span>` : '—';
  if (t === 'select') { const o = (col.options || []).find(o => o.id === value || o.label === value); return o ? `<span class="db-badge db-badge-${o.color || 'blue'}">${esc(o.label)}</span>` : (esc(value) || '—'); }
  if (t === 'url') return value ? `<a href="${value}" target="_blank" class="db-url-link" onclick="event.stopPropagation()">${value.replace(/^https?:\/\//, '').slice(0, 25)}</a>` : '—';
  if (t === 'date') return value ? new Date(value + 'T12:00:00').toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' }) : '—';
  return value || '—';
}

async function toggleDbChk(ri, colId) {
  const db = S.page; if (!db || ri >= db.rows.length) return;
  const cur = db.rows[ri][colId]; db.rows[ri][colId] = !(cur === true || cur === 'true');
  await saveData('databases', { [db.id]: db }); renderDbBody();
}

function startDbColRename(colId) {
  const db = S.page; if (!db) return;
  const col = db.columns.find(c => c.id === colId); if (!col) return;
  const el = document.getElementById('dbn-' + colId); if (!el) return;
  el.contentEditable = 'true'; el.focus();
  const r = document.createRange(); r.selectNodeContents(el); window.getSelection().removeAllRanges(); window.getSelection().addRange(r);
  const save = async () => { el.contentEditable = 'false'; col.name = el.textContent.trim() || col.name; await saveData('databases', { [db.id]: db }); };
  el.onblur = save; el.onkeydown = e => { if (e.key === 'Enter') { e.preventDefault(); el.blur(); } };
}

async function deleteDbCol(colId) {
  const db = S.page; if (!db) return;
  if (db.columns.length <= 1) return toast('Cannot delete the last column');
  db.columns = db.columns.filter(c => c.id !== colId);
  db.rows.forEach(r => delete r[colId]);
  await saveData('databases', { [db.id]: db }); renderDbBody();
}

function openAddColModal() {
  const panel = $('db-add-col-panel'); if (!panel) return;
  if (panel.style.display === 'block') { panel.style.display = 'none'; return; }
  panel.style.display = 'block';
  panel.innerHTML = `<div class="inline-form">
    <div class="inline-form-title">New Column</div>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px">
      <div class="form-group"><label class="form-label">Name</label>
        <input id="nc-name" class="form-input" placeholder="Column name"></div>
      <div class="form-group"><label class="form-label">Type</label>
        <select id="nc-type" class="form-input" onchange="onNcTypeChange(this.value)">
          ${Object.entries(DB_TYPES).map(([k, v]) => `<option value="${k}">${v.sym} ${v.label}</option>`).join('')}
        </select>
      </div>
    </div>
    <div id="nc-opts-wrap" style="display:none">
      <div class="form-group"><label class="form-label">Options — one per line <span style="color:var(--text-faint)">(Label or Label:color)</span></label>
        <textarea id="nc-opts" class="form-input" rows="4" placeholder="Not started
In Progress:blue
Done:green"></textarea>
      </div>
    </div>
    <div class="modal-foot">
      <button class="btn btn-ghost btn-sm" onclick="$('db-add-col-panel').style.display='none'">Cancel</button>
      <button class="btn btn-action btn-sm" onclick="submitNewCol()">Add Column</button>
    </div>
  </div>`;
  setTimeout(() => $('nc-name')?.focus(), 50);
  const inp = $('nc-name'); if (inp) inp.addEventListener('keydown', e => { if (e.key === 'Enter') submitNewCol(); });
}

function onNcTypeChange(t) {
  const w = $('nc-opts-wrap'); if (w) w.style.display = t === 'select' ? 'block' : 'none';
}

async function submitNewCol() {
  const name = $('nc-name')?.value.trim(); if (!name) return toast('Enter a column name');
  const type = $('nc-type')?.value || 'text';
  const id = 'c_' + Date.now(); const col = { id, name, type };
  if (type === 'select') {
    const raw = ($('nc-opts')?.value || 'Option 1\nOption 2').split('\n').filter(s => s.trim());
    const colors = ['orange', 'blue', 'green', 'red', 'purple'];
    col.options = raw.map((s, i) => { const parts = s.split(':'); return { id: 'o_' + Date.now() + '_' + i, label: parts[0].trim(), color: parts[1]?.trim() || colors[i % colors.length] }; });
  }
  S.page.columns.push(col);
  S.page.rows.forEach(r => r[id] = type === 'checkbox' ? false : '');
  await saveData('databases', { [S.page.id]: S.page });
  $('db-add-col-panel').style.display = 'none'; renderDbBody();
}

function openRowModal(ri) {
  const db = S.page; if (!db) return;
  const row = db.rows[ri]; if (!row) return;
  const bg = el('div', 'modal-bg'); bg.id = 'row-modal-bg';
  bg.innerHTML = `<div class="modal" style="width:500px;max-width:96vw;max-height:90vh;overflow-y:auto">
    <div class="modal-title">Row Details</div>
    ${db.columns.map(col => `<div class="form-group">
      <label class="form-label" style="display:flex;align-items:center;gap:5px">
        <span style="font-size:10px;color:var(--text-faint);font-weight:700">${DB_TYPES[col.type || 'text']?.sym || 'Aa'}</span> ${col.name}
      </label>
      ${renderRowField(col, row[col.id], ri)}
    </div>`).join('')}
    <div class="modal-foot">
      <button class="btn btn-ghost btn-sm" onclick="closeRowModal()">Close</button>
      <button class="btn btn-danger btn-sm" onclick="closeRowModal();deleteDbRow(${ri})">${icons.trash} Delete Row</button>
    </div>
  </div>`;
  bg.addEventListener('click', e => { if (e.target === bg) closeRowModal(); });
  document.body.appendChild(bg);
  requestAnimationFrame(() => bg.classList.add('show'));
}

function renderRowField(col, value, ri) {
  const t = col.type || 'text';
  if (t === 'checkbox') {
    const on = value === true || value === 'true';
    return `<div style="display:flex;align-items:center;gap:8px"><input type="checkbox" id="rf-${col.id}" ${on ? 'checked' : ''} style="width:17px;height:17px;accent-color:var(--accent)" onchange="updateDbCell(${ri},'${col.id}',this.checked)"><label for="rf-${col.id}" style="font-size:13.5px">${on ? 'Checked' : 'Unchecked'}</label></div>`;
  }
  if (t === 'select') return `<select class="form-input" onchange="updateDbCell(${ri},'${col.id}',this.value)"><option value="">—</option>${(col.options || []).map(o => `<option value="${o.label}"${value === o.label ? 'selected' : ''}>${o.label}</option>`).join('')}</select>`;
  if (t === 'date') return `<input type="date" class="form-input" value="${value || ''}" onchange="updateDbCell(${ri},'${col.id}',this.value)">`;
  if (t === 'url') return `<input type="url" class="form-input" value="${value || ''}" placeholder="https://…" onblur="updateDbCell(${ri},'${col.id}',this.value)">`;
  if (t === 'number') return `<input type="number" class="form-input" value="${value ?? ''}" step="any" onblur="updateDbCell(${ri},'${col.id}',this.value)">`;
  return `<textarea class="form-input" rows="3" style="resize:vertical" onblur="updateDbCell(${ri},'${col.id}',this.value)">${value || ''}</textarea>`;
}

function closeRowModal() { $('row-modal-bg')?.remove(); }

async function createDatabase() {
  const id = uid();
  const db = {
    id, title: 'Untitled Database', columns: [
      { id: 'c1', name: 'Name', type: 'text' },
      {
        id: 'c2', name: 'Status', type: 'select', options: [
          { id: 's1', label: 'Not started', color: 'orange' },
          { id: 's2', label: 'In progress', color: 'blue' },
          { id: 's3', label: 'Done', color: 'green' },
        ]
      },
      {
        id: 'c3', name: 'Priority', type: 'select', options: [
          { id: 'p1', label: 'Low', color: 'green' },
          { id: 'p2', label: 'Medium', color: 'orange' },
          { id: 'p3', label: 'High', color: 'red' },
        ]
      },
      { id: 'c4', name: 'Due', type: 'date' },
      { id: 'c5', name: 'Done', type: 'checkbox' },
    ], rows: [], createdAt: new Date().toISOString()
  };
  S.databases.push(db); S.page = db; S.view = 'database';
  await saveData('databases', { [id]: db });
  closeSidebarAfterNavigate();
  syncRouteWithState({ push: true });
  renderApp();
}

async function openDatabase(id, options = {}) {
  const { pushHistory = true, replaceHistory = false } = options;
  const db = S.databases.find(d => d.id === id); if (!db) return;
  S.page = db; S.view = 'database'; S.dbFilter = ''; S.dbSort = null;
  closeSidebarAfterNavigate();
  syncRouteWithState({ push: pushHistory, replace: replaceHistory });
  renderApp();
}

async function deleteDatabase(id) {
  const db = S.databases.find(d => d.id === id); if (!db) return;
  showDeleteConfirmModal({
    title: `Delete "${db.title || 'Untitled DB'}"?`,
    message: 'This database and all rows will be permanently deleted.',
    onConfirm: `confirmDeleteDatabase('${id}')`
  });
}

async function confirmDeleteDatabase(id) {
  S.databases = S.databases.filter(d => d.id !== id);
  await delData('databases/' + id);
  S.page = null; S.view = 'home'; toast('Database deleted');
  syncRouteWithState({ replace: true });
  renderApp();
}
async function addDbRow() {
  if (!S.page) return;
  const row = {}; S.page.columns.forEach(c => { row[c.id] = c.type === 'checkbox' ? false : ''; });
  S.page.rows.push(row); await saveData('databases', { [S.page.id]: S.page }); renderDbBody();
}
async function updateDbCell(ri, colId, val) {
  if (!S.page || ri < 0 || ri >= S.page.rows.length) return;
  S.page.rows[ri][colId] = val; await saveData('databases', { [S.page.id]: S.page });
}
async function deleteDbRow(ri) {
  if (!S.page) return; S.page.rows.splice(ri, 1);
  await saveData('databases', { [S.page.id]: S.page }); renderDbBody();
}

// ─── POMODORO ─────────────────────────────────────────────────
function renderPom() {
  let w = $('pom-widget');
  if (!w) { w = el('div', 'pom-float away'); w.id = 'pom-widget'; document.body.appendChild(w); }
  const p = S.pom; const mm = String(Math.floor(p.secs / 60)).padStart(2, '0'), ss = String(p.secs % 60).padStart(2, '0');
  const pct = ((p.total - p.secs) / p.total * 100).toFixed(1);
  w.className = 'pom-float' + (p.vis ? '' : ' away');
  // Restore saved position
  if (S.pom._x !== undefined && S.pom._y !== undefined) {
    w.style.left = S.pom._x + 'px'; w.style.top = S.pom._y + 'px';
    w.style.right = 'auto'; w.style.bottom = 'auto';
  }
  w.innerHTML = `
    <div class="pom-head" id="pom-drag-handle">
      <span class="pom-mode-lbl">${p.mode === 'work'
      ? `<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg> Focus`
      : `<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M17 8h1a4 4 0 1 1 0 8h-1"/><path d="M3 8h14v9a4 4 0 0 1-4 4H7a4 4 0 0 1-4-4Z"/><line x1="6" y1="2" x2="6" y2="4"/><line x1="10" y1="2" x2="10" y2="4"/><line x1="14" y1="2" x2="14" y2="4"/></svg> Break`
    }</span>
      <button class="icon-btn" onclick="togglePom()" style="width:22px;height:22px">${icons.close}</button>
    </div>
    <div class="pom-bar"><div class="pom-fill${p.mode !== 'work' ? ' brk' : ''}" style="width:${pct}%"></div></div>
    <div class="pom-time${p.mode === 'work' ? ' work' : ' brk'}">${mm}:${ss}</div>
    <div class="pom-controls">
      <button class="icon-btn" onclick="pomReset()">${icons.reset}</button>
      <button class="btn btn-action btn-sm" onclick="pomToggle()" style="width:auto;padding:6px 16px">${p.on ? icons.pause : icons.play} ${p.on ? 'Pause' : 'Start'}</button>
      <button class="icon-btn" onclick="pomSkip()">${icons.skip}</button>
    </div>
    <div class="pom-dots">${Array.from({ length: 4 }, (_, i) => `<div class="pom-dot${i < p.sess ? ' lit' : ''}"></div>`).join('')}</div>
    ${!p.on ? `<div class="pom-timer-settings">
      <div class="pom-setting-row">
        <span class="pom-setting-lbl">Focus</span>
        <button class="pom-adj-btn" onclick="adjustPom('work',-1)">−</button>
        <span class="pom-setting-val">${Math.floor((p._workSecs || 25 * 60) / 60) >= 60 ? Math.floor(Math.floor((p._workSecs || 25 * 60) / 60) / 60) + 'h ' + (Math.floor((p._workSecs || 25 * 60) / 60) % 60) + 'm' : Math.floor((p._workSecs || 25 * 60) / 60) + 'm'}</span>
        <button class="pom-adj-btn" onclick="adjustPom('work',1)">+</button>
      </div>
      <div class="pom-setting-row">
        <span class="pom-setting-lbl">Break</span>
        <button class="pom-adj-btn" onclick="adjustPom('break',-1)">−</button>
        <span class="pom-setting-val">${Math.round((p._breakSecs || 5 * 60) / 60)}m</span>
        <button class="pom-adj-btn" onclick="adjustPom('break',1)">+</button>
      </div>
    </div>` : ''}
    <div class="pom-spotify-section">
      ${S.spotifyToken ? renderSpotifyPlayer() : `<button class="pom-spotify-btn" onclick="spotifyLogin()">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor"><path d="M12 0C5.4 0 0 5.4 0 12s5.4 12 12 12 12-5.4 12-12S18.66 0 12 0zm5.521 17.34c-.24.359-.66.48-1.021.24-2.82-1.74-6.36-2.101-10.561-1.141-.418.122-.779-.179-.899-.539-.12-.421.18-.78.54-.9 4.56-1.021 8.52-.6 11.64 1.32.42.18.479.659.301 1.02zm1.44-3.3c-.301.42-.841.6-1.262.3-3.239-1.98-8.159-2.58-11.939-1.38-.479.12-1.02-.12-1.14-.6-.12-.48.12-1.021.6-1.141C9.6 9.9 15 10.561 18.72 12.84c.361.181.54.78.241 1.2zm.12-3.36C15.24 8.4 8.82 8.16 5.16 9.301c-.6.179-1.2-.181-1.38-.721-.18-.601.18-1.2.72-1.381 4.26-1.26 11.28-1.02 15.721 1.621.539.3.719 1.02.419 1.56-.299.421-1.02.599-1.559.3z"/></svg>
        Connect Spotify
      </button>`}
    </div>`;
  setTimeout(initPomDrag, 0);
}

function togglePom() { S.pom.vis = !S.pom.vis; renderPom(); if (S.pom.vis) setTimeout(initPomDrag, 0); }

function pomToggle() {
  const p = S.pom;
  if (p.on) {
    clearInterval(p.iv); p.on = false;
    if (p.mode === 'work' && S.pomStartTime) { const mins = Math.floor((Date.now() - S.pomStartTime) / 60000); if (mins > 0) { S.studyMinutes += mins; saveStats(); } S.pomStartTime = null; }
  } else {
    p.on = true; if (p.mode === 'work') S.pomStartTime = Date.now();
    p.iv = setInterval(() => {
      p.secs--;
      if (p.secs <= 0) {
        clearInterval(p.iv); p.on = false;
        if (p.mode === 'work') {
          p.sess = Math.min(p.sess + 1, 4); p.mode = 'break'; p.secs = p._breakSecs || 5 * 60; p.total = p._breakSecs || 5 * 60;
          S.studySessions++; S.studyMinutes += 25; S.pomStartTime = null; saveStats();
          toast('Break time! Great focus session.');
        } else { p.mode = 'work'; p.secs = p._workSecs || 25 * 60; p.total = p._workSecs || 25 * 60; toast('Focus time!'); }
        if (p.sess >= 4) p.sess = 0;
      }
      renderPom();
    }, 1000);
  }
  renderPom();
}

function pomReset() { const p = S.pom; clearInterval(p.iv); p.on = false; p.mode = 'work'; p.secs = p._workSecs || 25 * 60; p.total = p._workSecs || 25 * 60; S.pomStartTime = null; renderPom(); }

function adjustPom(type, delta) {
  const p = S.pom;
  if (type === 'work') {
    const cur = Math.floor((p._workSecs || 25 * 60) / 60);
    const next = Math.max(1, Math.min(599, cur + delta));
    p._workSecs = next * 60;
    if (p.mode === 'work' && !p.on) { p.secs = p._workSecs; p.total = p._workSecs; }
  } else {
    const cur = Math.round((p._breakSecs || 5 * 60) / 60);
    const next = Math.max(1, Math.min(120, cur + delta));
    p._breakSecs = next * 60;
    if (p.mode === 'break' && !p.on) { p.secs = p._breakSecs; p.total = p._breakSecs; }
  }
  renderPom();
}
function pomSkip() { const p = S.pom; clearInterval(p.iv); p.on = false; if (p.mode === 'work') { p.sess = Math.min(p.sess + 1, 4); p.mode = 'break'; p.secs = p._breakSecs || 5 * 60; p.total = p._breakSecs || 5 * 60; } else { p.mode = 'work'; p.secs = p._workSecs || 25 * 60; p.total = p._workSecs || 25 * 60; } S.pomStartTime = null; renderPom(); }

// ═══════════════════════════════════════════════════════════════
// SPOTIFY INTEGRATION
// ═══════════════════════════════════════════════════════════════
const SPOTIFY_CLIENT_ID = 'YOUR_SPOTIFY_CLIENT_ID'; // Replace with your actual Client ID
const SPOTIFY_SCOPES = 'streaming user-read-email user-read-private user-read-playback-state user-modify-playback-state';

function spotifyLogin() {
  const redirectUri = encodeURIComponent(window.location.origin + window.location.pathname);
  const scopes = encodeURIComponent(SPOTIFY_SCOPES);
  const state = Math.random().toString(36).slice(2);
  sessionStorage.setItem('spotify_state', state);
  const url = `https://accounts.spotify.com/authorize?client_id=${SPOTIFY_CLIENT_ID}&response_type=token&redirect_uri=${redirectUri}&scope=${scopes}&state=${state}&show_dialog=true`;
  window.location.href = url;
}

function spotifyHandleCallback() {
  const hash = window.location.hash.slice(1);
  if (!hash) return;
  const params = Object.fromEntries(hash.split('&').map(p => p.split('=')));
  if (params.access_token) {
    const savedState = sessionStorage.getItem('spotify_state');
    if (savedState && params.state !== savedState) { toast('Spotify auth error: state mismatch'); return; }
    S.spotifyToken = params.access_token;
    const expiresIn = parseInt(params.expires_in || '3600');
    S.spotifyTokenExpiry = Date.now() + expiresIn * 1000;
    sessionStorage.removeItem('spotify_state');
    // Clean hash from URL
    history.replaceState(null, '', window.location.pathname + window.location.search);
    toast('Spotify connected!');
    spotifyFetchCurrentTrack();
    renderPom();
  }
}

async function spotifyFetchCurrentTrack() {
  if (!S.spotifyToken) return;
  try {
    const res = await fetch('https://api.spotify.com/v1/me/player', {
      headers: { 'Authorization': 'Bearer ' + S.spotifyToken }
    });
    if (res.status === 204 || res.status === 404) { S.spotifyCurrentTrack = null; S.spotifyPlaying = false; renderPom(); return; }
    if (!res.ok) { if (res.status === 401) { S.spotifyToken = null; renderPom(); } return; }
    const data = await res.json();
    S.spotifyPlaying = data.is_playing;
    S.spotifyCurrentTrack = data.item ? { name: data.item.name, artist: data.item.artists?.[0]?.name || '', album: data.item.album?.images?.[2]?.url || '' } : null;
    renderPom();
  } catch (e) { console.warn('[Spotify] fetch error', e); }
}

async function spotifyControl(action) {
  if (!S.spotifyToken) return;
  const endpoints = { play: ['PUT','https://api.spotify.com/v1/me/player/play'], pause: ['PUT','https://api.spotify.com/v1/me/player/pause'], next: ['POST','https://api.spotify.com/v1/me/player/next'], prev: ['POST','https://api.spotify.com/v1/me/player/previous'] };
  const [method, url] = endpoints[action] || [];
  if (!url) return;
  await fetch(url, { method, headers: { 'Authorization': 'Bearer ' + S.spotifyToken } });
  setTimeout(spotifyFetchCurrentTrack, 500);
}

function renderSpotifyPlayer() {
  const t = S.spotifyCurrentTrack;
  return `<div class="pom-spotify-player">
    ${t ? `<div class="pom-spotify-track">
      ${t.album ? `<img src="${t.album}" style="width:28px;height:28px;border-radius:4px;flex-shrink:0" alt="">` : ''}
      <div style="min-width:0;flex:1">
        <div style="font-size:11.5px;font-weight:600;color:var(--ink);white-space:nowrap;overflow:hidden;text-overflow:ellipsis">${esc(t.name)}</div>
        <div style="font-size:10.5px;color:var(--text-muted);white-space:nowrap;overflow:hidden;text-overflow:ellipsis">${esc(t.artist)}</div>
      </div>
    </div>` : `<div style="font-size:11px;color:var(--text-muted);text-align:center;padding:2px 0">No track playing</div>`}
    <div class="pom-spotify-controls">
      <button class="pom-adj-btn" onclick="spotifyControl('prev')" title="Previous">⏮</button>
      <button class="pom-adj-btn" onclick="spotifyControl(${S.spotifyPlaying ? "'pause'" : "'play'"})" title="${S.spotifyPlaying ? 'Pause' : 'Play'}">${S.spotifyPlaying ? '⏸' : '▶'}</button>
      <button class="pom-adj-btn" onclick="spotifyControl('next')" title="Next">⏭</button>
      <button class="pom-adj-btn" style="font-size:9px;color:var(--text-muted)" onclick="S.spotifyToken=null;renderPom()" title="Disconnect">✕</button>
    </div>
  </div>`;
}

// Poll Spotify every 10 seconds while timer is visible
setInterval(() => { if (S.pom.vis && S.spotifyToken) spotifyFetchCurrentTrack(); }, 10000);

function initPomDrag() {
  const handle = document.getElementById('pom-drag-handle');
  const w = document.getElementById('pom-widget');
  if (!handle || !w) return;
  let dragging = false, ox = 0, oy = 0;

  function onDown(e) {
    if (e.target.closest('button')) return; // don't drag when clicking buttons
    dragging = true;
    const rect = w.getBoundingClientRect();
    const clientX = e.touches ? e.touches[0].clientX : e.clientX;
    const clientY = e.touches ? e.touches[0].clientY : e.clientY;
    ox = clientX - rect.left;
    oy = clientY - rect.top;
    handle.style.cursor = 'grabbing';
    e.preventDefault();
  }

  function onMove(e) {
    if (!dragging) return;
    const clientX = e.touches ? e.touches[0].clientX : e.clientX;
    const clientY = e.touches ? e.touches[0].clientY : e.clientY;
    const maxX = window.innerWidth - w.offsetWidth;
    const maxY = window.innerHeight - w.offsetHeight;
    const x = Math.max(0, Math.min(maxX, clientX - ox));
    const y = Math.max(0, Math.min(maxY, clientY - oy));
    w.style.left = x + 'px'; w.style.top = y + 'px';
    w.style.right = 'auto'; w.style.bottom = 'auto';
    S.pom._x = x; S.pom._y = y;
    e.preventDefault();
  }

  function onUp() {
    if (!dragging) return;
    dragging = false;
    handle.style.cursor = 'grab';
  }

  handle.addEventListener('mousedown', onDown);
  handle.addEventListener('touchstart', onDown, { passive: false });
  document.addEventListener('mousemove', onMove);
  document.addEventListener('touchmove', onMove, { passive: false });
  document.addEventListener('mouseup', onUp);
  document.addEventListener('touchend', onUp);
}

async function saveStats() { if (!S.user) return; try { await window.fb.update(window.fb.ref(window.fb.database, `users/${S.user.uid}/stats`), { sessions: S.studySessions, minutes: S.studyMinutes }); } catch (e) { } }

// ─── PROFILE ──────────────────────────────────────────────────
// Avatar icons — SVG paths used in profile picker
const AVATAR_ICONS = [
  { id: 'mortarboard', label: 'Graduate', svg: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M22 10v6M2 10l10-5 10 5-10 5z"/><path d="M6 12v5c3 3 9 3 12 0v-5"/></svg>' },
  { id: 'book-open', label: 'Reader', svg: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M2 3h6a4 4 0 0 1 4 4v14a3 3 0 0 0-3-3H2z"/><path d="M22 3h-6a4 4 0 0 0-4 4v14a3 3 0 0 1 3-3h7z"/></svg>' },
  { id: 'pencil', label: 'Writer', svg: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M17 3a2.828 2.828 0 1 1 4 4L7.5 20.5 2 22l1.5-5.5L17 3z"/></svg>' },
  { id: 'flask', label: 'Scientist', svg: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M9 3h6v10l4 8H5l4-8V3z"/><line x1="9" y1="3" x2="15" y2="3"/></svg>' },
  { id: 'monitor', label: 'Coder', svg: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="3" width="20" height="14" rx="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/></svg>' },
  { id: 'palette', label: 'Artist', svg: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="13.5" cy="6.5" r=".5" fill="currentColor"/><circle cx="17.5" cy="10.5" r=".5" fill="currentColor"/><circle cx="8.5" cy="7.5" r=".5" fill="currentColor"/><circle cx="6.5" cy="12.5" r=".5" fill="currentColor"/><path d="M12 2C6.5 2 2 6.5 2 12s4.5 10 10 10c.926 0 1.648-.746 1.648-1.667 0-.437-.18-.835-.437-1.125C12.968 18.917 12.5 18.25 12.5 17.5a1.25 1.25 0 0 1 1.25-1.25h1.5A5.25 5.25 0 0 0 20.5 11c0-4.694-3.763-9-8.5-9z"/></svg>' },
  { id: 'music', label: 'Musician', svg: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M9 18V5l12-2v13"/><circle cx="6" cy="18" r="3"/><circle cx="18" cy="16" r="3"/></svg>' },
  { id: 'zap', label: 'Energy', svg: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>' },
  { id: 'star', label: 'Star', svg: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"/></svg>' },
  { id: 'rocket', label: 'Ambitious', svg: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M4.5 16.5c-1.5 1.26-2 5-2 5s3.74-.5 5-2c.71-.84.7-2.13-.09-2.91a2.18 2.18 0 0 0-2.91-.09z"/><path d="M12 15l-3-3a22 22 0 0 1 2-3.95A12.88 12.88 0 0 1 22 2c0 2.72-.78 7.5-6 11a22.35 22.35 0 0 1-4 2z"/></svg>' },
  { id: 'brain', label: 'Thinker', svg: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M9.5 2A2.5 2.5 0 0 1 12 4.5v15a2.5 2.5 0 0 1-4.96-.46 2.5 2.5 0 0 1-2.96-3.08 3 3 0 0 1-.34-5.58 2.5 2.5 0 0 1 1.32-4.24 2.5 2.5 0 0 1 1.98-3A2.5 2.5 0 0 1 9.5 2z"/><path d="M14.5 2A2.5 2.5 0 0 0 12 4.5v15a2.5 2.5 0 0 0 4.96-.46 2.5 2.5 0 0 0 2.96-3.08 3 3 0 0 0 .34-5.58 2.5 2.5 0 0 0-1.32-4.24 2.5 2.5 0 0 0-1.98-3A2.5 2.5 0 0 0 14.5 2z"/></svg>' },
  { id: 'target', label: 'Focused', svg: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><circle cx="12" cy="12" r="6"/><circle cx="12" cy="12" r="2"/></svg>' },
  { id: 'award', label: 'Achiever', svg: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="8" r="6"/><path d="M15.477 12.89L17 22l-5-3-5 3 1.523-9.11"/></svg>' },
  { id: 'compass', label: 'Explorer', svg: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><polygon points="16.24 7.76 14.12 14.12 7.76 16.24 9.88 9.88 16.24 7.76"/></svg>' },
  { id: 'cpu', label: 'Engineer', svg: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="4" y="4" width="16" height="16" rx="2"/><rect x="9" y="9" width="6" height="6"/><line x1="9" y1="1" x2="9" y2="4"/><line x1="15" y1="1" x2="15" y2="4"/><line x1="9" y1="20" x2="9" y2="23"/><line x1="15" y1="20" x2="15" y2="23"/><line x1="20" y1="9" x2="23" y2="9"/><line x1="20" y1="14" x2="23" y2="14"/><line x1="1" y1="9" x2="4" y2="9"/><line x1="1" y1="14" x2="4" y2="14"/></svg>' },
  { id: 'feather', label: 'Creative', svg: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M20.24 12.24a6 6 0 0 0-8.49-8.49L5 10.5V19h8.5z"/><line x1="16" y1="8" x2="2" y2="22"/><line x1="17.5" y1="15" x2="9" y2="15"/></svg>' },
  { id: 'globe', label: 'Global', svg: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>' },
  { id: 'coffee', label: 'Studier', svg: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M18 8h1a4 4 0 0 1 0 8h-1"/><path d="M2 8h16v9a4 4 0 0 1-4 4H6a4 4 0 0 1-4-4V8z"/><line x1="6" y1="1" x2="6" y2="4"/><line x1="10" y1="1" x2="10" y2="4"/><line x1="14" y1="1" x2="14" y2="4"/></svg>' },
  { id: 'sun', label: 'Bright', svg: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="5"/><line x1="12" y1="1" x2="12" y2="3"/><line x1="12" y1="21" x2="12" y2="23"/><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/><line x1="1" y1="12" x2="3" y2="12"/><line x1="21" y1="12" x2="23" y2="12"/><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/></svg>' },
  { id: 'moon', label: 'Night Owl', svg: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></svg>' },
  { id: 'gem', label: 'Gem', svg: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><polygon points="6 3 18 3 22 9 12 22 2 9"/><polyline points="22 9 12 9 6 3"/><line x1="12" y1="22" x2="12" y2="9"/></svg>' },
  { id: 'leaf', label: 'Natural', svg: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M17 8C8 10 5.9 16.17 3.82 19.5a10 10 0 0 0 14.17-13z"/><path d="M3.82 19.5l2.18-3"/></svg>' },
  { id: 'shield', label: 'Defender', svg: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>' },
  { id: 'layers', label: 'Builder', svg: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><polygon points="12 2 2 7 12 12 22 7 12 2"/><polyline points="2 17 12 22 22 17"/><polyline points="2 12 12 17 22 12"/></svg>' },
  { id: 'activity', label: 'Active', svg: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>' },
  { id: 'headphones', label: 'Focused', svg: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M3 18v-6a9 9 0 0 1 18 0v6"/><path d="M21 19a2 2 0 0 1-2 2h-1a2 2 0 0 1-2-2v-3a2 2 0 0 1 2-2h3zM3 19a2 2 0 0 0 2 2h1a2 2 0 0 0 2-2v-3a2 2 0 0 0-2-2H3z"/></svg>' },
  { id: 'mountain', label: 'Climber', svg: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><polygon points="3 20 13 4 23 20 3 20"/><polyline points="3 20 10 10 15 15 18 12 23 20"/></svg>' },
  { id: 'infinity', label: 'Infinite', svg: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 12c-2-2.5-4-4-6-4a4 4 0 0 0 0 8c2 0 4-1.5 6-4zm0 0c2 2.5 4 4 6 4a4 4 0 0 0 0-8c-2 0-4 1.5-6 4z"/></svg>' },
  { id: 'flame', label: 'On Fire', svg: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M8.5 14.5A2.5 2.5 0 0 0 11 12c0-1.38-.5-2-1-3-1.072-2.143-.224-4.054 2-6 .5 2.5 2 4.9 4 6.5 2 1.6 3 3.5 3 5.5a7 7 0 1 1-14 0c0-1.153.433-2.294 1-3a2.5 2.5 0 0 0 2.5 2.5z"/></svg>' },
  { id: 'eye', label: 'Observer', svg: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>' },
  { id: 'anchor', label: 'Grounded', svg: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="5" r="3"/><line x1="12" y1="22" x2="12" y2="8"/><path d="M5 12H2a10 10 0 0 0 20 0h-3"/></svg>' },
];

function renderProfile(c) {
  if (typeof AI._flowaiTrainingOptIn === 'undefined' && getFlowAIRuntime()) {
    flowaiEnsureLocalRuntime(false)
      .then(runtime => runtime.getTrainingOptIn())
      .then(value => {
        AI._flowaiTrainingOptIn = value;
        rerenderFlowAISettingsView();
      })
      .catch(() => {});
  }
  const admin = isAdmin(), founder = isFounder(), displayName = getDisplayName();
  const hoursStudied = Math.floor(S.studyMinutes / 60), minsLeft = S.studyMinutes % 60;
  const av = S.userProfile?.avatar || '';
  const desc = S.userProfile?.description || 'Student';
  const age = Number.isFinite(Number(S.userProfile?.age)) ? Number(S.userProfile?.age) : '';
  const syllabusTrack = S.userProfile?.syllabusTrack || 'sg_o_level';
  const benchmarkGroupId = S.userProfile?.benchmarkGroupId || (S.studyGroups[0]?.id || '');
  const benchOpts = S.studyGroups.length
    ? S.studyGroups.map(g => `<option value="${esc(g.id)}"${benchmarkGroupId === g.id ? ' selected' : ''}>${esc(g.name)}</option>`).join('')
    : '<option value="">No groups available</option>';
  const adminTag = getAdminTag();
  const credits = getCredits();
  const credUsed = credits.used || 0;
  const credTotal = credits.total || FREE_TIER_CREDITS;
  const credLeft = Math.max(0, credTotal - credUsed);
  const credPct = Math.min(100, Math.round((credUsed / credTotal) * 100));
  const credBarColor = credPct >= 90 ? 'var(--red)' : credPct >= 70 ? 'var(--orange)' : 'var(--accent)';
  const tierLabel = admin ? 'Elite (Admin)' : (CREDIT_TIERS[credits.tier]?.label || 'Free');
  const avPickerHtml = AVATAR_ICONS.map(ic => '<button class="av-opt' + (av === ic.id ? ' av-sel' : '') + '" onclick="pickAvatar(\'' + ic.id + '\')" title="' + ic.label + '">' + ic.svg + '</button>').join('');

  let html = '<div class="profile-page' + (admin ? ' profile-admin' : '') + '">';

  // HERO
  html += '<div class="profile-hero' + (admin ? ' admin-hero' : '') + '">';
  html += '<div class="prof-av-wrap">';
  html += '<div class="profile-avatar' + (admin ? ' admin-avatar admin-glow' : '') + '"' + (admin ? '' : ' onclick="toggleAvatarPicker()" title="Choose icon" style="cursor:pointer"') + '>';
  if (admin) {
    html += icons.crown;
  } else if (av) {
    const ic = AVATAR_ICONS.find(i => i.id === av);
    html += ic ? '<span class="prof-av-svg">' + ic.svg + '</span>' : '<span style="font-size:22px;font-weight:700">' + (displayName[0]?.toUpperCase() || '?') + '</span>';
  } else {
    html += '<span style="font-size:22px;font-weight:700">' + (displayName[0]?.toUpperCase() || '?') + '</span>';
  }
  html += '</div>';
  if (!admin) html += '<div id="av-picker" class="av-picker" style="display:none"><div class="av-grid">' + avPickerHtml + '</div></div>';
  html += '</div>';

  const namePill = admin
    ? '<span class="admin-pill">' + icons.crown + ' ' + esc(adminTag) + '</span>'
    : '<span class="user-pill"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg> ' + esc(S.userProfile?.customTag || 'User') + '</span>';

  html += '<div class="profile-hero-info">';
  html += '<h1 class="profile-name">' + esc(displayName) + namePill + '</h1>';
  html += '<p class="profile-email">' + esc(S.user?.email) + '</p>';
  html += '<p class="profile-desc-line">' + esc(desc) + '</p>';
  html += '</div>';
  html += '<button class="btn btn-secondary btn-sm" onclick="toggleProfileEdit()" style="margin-left:auto;align-self:flex-start">' + icons.edit + ' Edit</button>';
  html += '</div>'; // end profile-hero

  // EDIT FORM
  html += '<div id="profile-edit-form" class="inline-form-wrap" style="display:none;margin-top:8px;margin-bottom:20px"><div class="inline-form">';
  html += '<div class="inline-form-title">Edit Profile</div>';
  html += '<div class="form-group"><label class="form-label">Display Name</label><input id="pe-name" class="form-input" value="' + esc(displayName) + '" placeholder="Your name" maxlength="100"></div>';
  html += '<div class="form-group"><label class="form-label">Description <span class="form-hint">(e.g. Student, Engineer, Teacher)</span></label><input id="pe-desc" class="form-input" value="' + esc(desc) + '" placeholder="Student" maxlength="100"></div>';
  html += '<div style="display:grid;grid-template-columns:1fr 1fr;gap:10px">';
  html += '<div class="form-group"><label class="form-label">Age <span class="form-hint">(used for predictions)</span></label><input id="pe-age" class="form-input" type="number" min="8" max="30" value="' + esc(age) + '" placeholder="e.g. 16"></div>';
  html += '<div class="form-group"><label class="form-label">Singapore Track</label><select id="pe-track" class="form-input"><option value="sg_psle"' + (syllabusTrack === 'sg_psle' ? ' selected' : '') + '>PSLE</option><option value="sg_n_level"' + (syllabusTrack === 'sg_n_level' ? ' selected' : '') + '>N-Level</option><option value="sg_o_level"' + (syllabusTrack === 'sg_o_level' ? ' selected' : '') + '>O-Level</option><option value="sg_a_level"' + (syllabusTrack === 'sg_a_level' ? ' selected' : '') + '>A-Level</option><option value="sg_ib"' + (syllabusTrack === 'sg_ib' ? ' selected' : '') + '>IB (Singapore)</option></select></div>';
  html += '</div>';
  html += '<div class="form-group"><label class="form-label">Benchmark Group <span class="form-hint">(Elite comparison cohort)</span></label><select id="pe-benchmark-group" class="form-input">' + benchOpts + '</select></div>';
  if (!admin) html += '<div class="form-group"><label class="form-label">Custom Tag <span class="form-hint">(shown next to your name)</span></label><input id="pe-customtag" class="form-input" value="' + esc(S.userProfile?.customTag || '') + '" placeholder="e.g. Student, Engineer, Night Owl…" maxlength="40"></div>';
  if (admin) html += '<div class="form-group"><label class="form-label">Your Admin Tag <span class="form-hint">(shown on your profile)</span></label><input id="pe-admintag" class="form-input" value="' + esc(adminTag) + '" placeholder="' + (founder ? 'Creator & Founder of Axinote' : 'Admin') + '" maxlength="60"></div>';
  html += '<div class="modal-foot"><button class="btn btn-ghost btn-sm" onclick="toggleProfileEdit()">Cancel</button><button class="btn btn-action btn-sm" id="pe-save-btn" onclick="saveProfileInline()">' + icons.ok + ' Save</button></div>';
  html += '</div></div>';

  // STATS
  html += '<div class="profile-stats">';
  html += '<div class="profile-stat-card"><div class="profile-stat-icon" style="background:var(--accent-bg);color:var(--accent)">' + icons.clock + '</div><div class="profile-stat-val">' + hoursStudied + 'h ' + minsLeft + 'm</div><div class="profile-stat-lbl">Time Studied</div></div>';
  html += '<div class="profile-stat-card"><div class="profile-stat-icon" style="background:var(--blue-bg);color:var(--blue)">' + icons.flash + '</div><div class="profile-stat-val">' + S.studySessions + '</div><div class="profile-stat-lbl">Study Sessions</div></div>';
  html += '<div class="profile-stat-card"><div class="profile-stat-icon" style="background:var(--green-bg);color:var(--green)">' + icons.file + '</div><div class="profile-stat-val">' + S.pages.length + '</div><div class="profile-stat-lbl">Pages</div></div>';
  html += '<div class="profile-stat-card"><div class="profile-stat-icon" style="background:var(--purple-bg);color:var(--purple)">' + icons.check + '</div><div class="profile-stat-val">' + S.tasks.filter(t => t.completed).length + '</div><div class="profile-stat-lbl">Tasks Done</div></div>';
  html += '</div>';

  // CREDITS BAR
  html += '<div class="profile-section" style="margin-top:20px"><div class="profile-section-title">FlowAI Credits</div>';
  html += '<div style="background:var(--bg-sidebar);border:1px solid var(--border);border-radius:var(--r-md);padding:16px 18px">';
  html += '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px">';
  html += '<div style="display:flex;align-items:center;gap:8px"><span style="font-size:13.5px;font-weight:700;color:var(--text)">' + tierLabel + ' Plan</span>';
  if (admin) html += '<span style="font-size:10px;font-weight:800;background:linear-gradient(135deg,var(--accent),var(--purple));color:#fff;padding:2px 8px;border-radius:10px;text-transform:uppercase;letter-spacing:.05em">Unlimited</span>';
  html += '</div>';
  html += '<span style="font-size:12.5px;color:var(--text-muted);font-weight:600">' + (admin ? '&#8734; credits' : credLeft.toLocaleString() + ' / ' + credTotal.toLocaleString() + ' left') + '</span>';
  html += '</div>';
  if (admin) {
    html += '<div style="height:8px;border-radius:4px;background:linear-gradient(90deg,var(--accent),var(--purple));box-shadow:0 2px 8px rgba(0,0,0,.15)"></div>';
    html += '<div style="font-size:12px;color:var(--text-faint);margin-top:8px">As an admin, you have unlimited FlowAI access — no credit tracking.</div>';
  } else {
    html += '<div style="height:8px;border-radius:4px;background:var(--border-mid);overflow:hidden;position:relative"><div style="position:absolute;inset:0;width:' + credPct + '%;background:' + credBarColor + ';border-radius:4px;transition:width .6s cubic-bezier(.4,0,.2,1)"></div></div>';
    html += '<div style="display:flex;justify-content:space-between;margin-top:6px"><span style="font-size:11.5px;color:' + (credPct >= 90 ? credBarColor : 'var(--text-faint)') + '">' + credPct + '% used</span><button class="btn btn-ghost btn-sm" style="font-size:11.5px;padding:2px 8px" onclick="navigate(\'aiDashboard\')">View AI Dashboard &rarr;</button></div>';
    if (credPct >= 90) html += '<div style="margin-top:10px;padding:8px 12px;background:rgba(184,82,30,.1);border:1px solid rgba(184,82,30,.3);border-radius:var(--r);font-size:12.5px;color:var(--red);font-weight:600">&#9888; Running low on credits &mdash; upgrade to keep going.</div>';
  }
  html += '</div></div>';

  // CREATOR ADMIN CONTROL PANEL
  if (founder) {
    html += '<div class="profile-section" style="margin-top:20px">';
    html += '<div class="profile-section-title" style="margin-bottom:10px">' + icons.crown + ' Admin Control Panel</div>';
    html += '<p style="font-size:12.5px;color:var(--text-muted);margin-bottom:16px;line-height:1.6">Admin access is managed from the protected admin console instead of a shareable client-side code.</p>';
    html += '<div id="admin-roster-container"><div style="color:var(--text-faint);font-size:13px;padding:12px 0">Loading admin roster&hellip;</div></div>';
    html += '</div>';
  }

  // STUDY GROUPS
  html += '<div class="profile-section"><div class="profile-section-title">Study Groups</div>';
  if (S.studyGroups.length) {
    html += S.studyGroups.map(g => '<div class="activity-item" style="cursor:pointer;padding:6px;border-radius:var(--r-md)" onclick="openStudyGroup(\'' + g.id + '\')">' + icons.group + '<span>' + esc(g.name) + ' <span style="font-size:12px;color:var(--text-muted)">(' + groupMemberCount(g) + ' members)</span></span></div>').join('');
  } else {
    html += '<div style="color:var(--text-muted);font-size:13.5px;padding:8px 0">No study groups yet. <button class="btn btn-ghost btn-sm" onclick="navigate(\'groups\')" style="display:inline-flex">Create or join one</button></div>';
  }
  html += '</div>';

  html += renderFlowAISettingsCard();

  // SETTINGS
  html += '<div class="profile-section"><div class="profile-section-title">Settings &amp; Upgrade</div>';
  if (!admin) {
    html += '<div class="card" style="padding:20px;margin-bottom:16px;border:1px solid var(--accent);background:var(--accent-bg)">';
    html += '<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:8px"><div style="font-weight:700;color:var(--accent)">Upgrade to Pro</div><span style="font-size:11px;font-weight:700;background:var(--accent);color:#fff;padding:2px 8px;border-radius:12px;text-transform:uppercase">' + tierLabel + '</span></div>';
    html += '<p style="font-size:13px;color:var(--text);margin-bottom:14px;line-height:1.5">Unlock FlowAI Assistant, AI Flashcards, and deeper workflow tools for just $5/mo.</p>';
    html += '<button class="btn btn-primary" onclick="window.open(\'/pricing.html\', \'_blank\')" style="box-shadow:none">View Plans</button></div>';
  }
  html += '<div class="card" style="padding:20px;margin-bottom:16px"><div style="font-weight:700;margin-bottom:8px">Theme</div><p style="font-size:13px;color:var(--text-muted);margin-bottom:10px">Toggle between light and dark mode.</p><button class="btn btn-secondary btn-sm" onclick="toggleTheme()">Switch Theme</button></div>';
  html += '<div class="card" style="padding:20px;margin-bottom:16px"><div style="font-weight:700;margin-bottom:12px">More</div><div style="display:flex;flex-direction:column;gap:4px">';
  html += '<button class="settings-link-row" onclick="openFeedback()"><span style="display:flex;align-items:center;gap:10px"><svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/></svg>Send Feedback</span><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="9 18 15 12 9 6"/></svg></button>';
  html += '<button class="settings-link-row" onclick="navigate(\'changelog\')"><span style="display:flex;align-items:center;gap:10px"><svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"/></svg>What\'s New</span><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="9 18 15 12 9 6"/></svg></button>';
  html += '<button class="settings-link-row" onclick="navigate(\'privacy\')"><span style="display:flex;align-items:center;gap:10px"><svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>Privacy Policy</span><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="9 18 15 12 9 6"/></svg></button>';
  html += '<button class="settings-link-row" onclick="navigate(\'aiDashboard\')"><span style="display:flex;align-items:center;gap:10px"><svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="3" width="6" height="4" rx="1"/><rect x="2" y="10" width="6" height="11" rx="1"/><rect x="10" y="3" width="12" height="11" rx="1"/><rect x="10" y="17" width="12" height="4" rx="1"/></svg>AI Dashboard' + (admin ? '' : ' <span style="font-size:11px;color:var(--text-faint);margin-left:4px">' + getCreditLeft().toLocaleString() + ' cr left</span>') + '</span><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="9 18 15 12 9 6"/></svg></button>';
  html += '</div></div>';
  html += '<div class="card" style="padding:20px"><div style="font-weight:700;margin-bottom:8px">About Axinote</div><p style="font-size:13px;color:var(--text-muted)">Axinote &mdash; Your cozy study workspace. Version 2.0</p></div>';
  html += '</div>';

  // SIGN OUT
  html += '<div style="margin-top:24px"><button class="btn btn-danger btn-sm" onclick="doLogout()">' + icons.logout + ' Sign Out</button></div>';
  html += '</div>';

  c.innerHTML = html;

  if (!admin) {
    setTimeout(() => {
      document.addEventListener('click', function _avClose(e) {
        const picker = document.getElementById('av-picker'), btn = document.querySelector('.prof-av-wrap .profile-avatar');
        if (picker && btn && !picker.contains(e.target) && !btn.contains(e.target)) {
          picker.style.display = 'none';
          document.removeEventListener('click', _avClose, true);
        }
      }, true);
    }, 100);
  }

  if (founder) {
    loadAdminRosterRealtime();
  }
}

let _adminRosterListener = null;
function loadAdminRosterRealtime() {
  if (_adminRosterListener) { _adminRosterListener(); _adminRosterListener = null; }
  const ref = window.fb.ref(window.fb.database, 'users');
  _adminRosterListener = window.fb.onValue(ref, snap => {
    const container = document.getElementById('admin-roster-container');
    if (!container) { if (_adminRosterListener) { _adminRosterListener(); _adminRosterListener = null; } return; }
    if (!snap.exists()) { container.innerHTML = '<div style="color:var(--text-faint);font-size:13px;padding:8px 0">No users in index yet</div>'; return; }
    const users = Object.entries(snap.val()).map(([uid, value]) => ({
      uid,
      email: value?.email || '',
      name: value?.profile?.name || value?.email || 'Unknown',
      isAdmin: !!value?.profile?.isAdmin
    })).filter(u => u.isAdmin && u.uid);
    if (!users.length) { container.innerHTML = '<div style="color:var(--text-faint);font-size:13px;padding:8px 0">No admin accounts yet. Use the protected admin console to promote users.</div>'; return; }
    let rosterHtml = '<div style="display:grid;gap:10px">';
    users.forEach(u => {
      const isCreator = u.email === FOUNDER_EMAIL;
      rosterHtml += '<div style="background:var(--bg);border:1.5px solid ' + (isCreator ? 'rgba(184,82,30,.4)' : 'var(--border)') + ';border-radius:var(--r-md);padding:14px 16px">';
      rosterHtml += '<div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin-bottom:0">';
      rosterHtml += '<div style="width:34px;height:34px;border-radius:var(--r);background:' + (isCreator ? 'var(--accent)' : 'var(--bg-sidebar)') + ';border:1.5px solid ' + (isCreator ? 'var(--accent)' : 'var(--border)') + ';color:' + (isCreator ? '#fff' : 'var(--text)') + ';display:flex;align-items:center;justify-content:center;font-size:14px;font-weight:800;flex-shrink:0">' + ((u.name || u.email || '?')[0].toUpperCase()) + '</div>';
      rosterHtml += '<div style="flex:1;min-width:0"><div style="font-size:14px;font-weight:700">' + esc(u.name || 'Unknown') + '</div><div style="font-size:12px;color:var(--text-muted);overflow:hidden;text-overflow:ellipsis;white-space:nowrap">' + esc(u.email) + '</div></div>';
      if (isCreator) {
        rosterHtml += '<span style="font-size:10px;font-weight:800;background:var(--accent);color:#fff;padding:3px 9px;border-radius:10px;text-transform:uppercase;letter-spacing:.06em">Creator</span>';
      } else {
        rosterHtml += '<span style="font-size:10px;font-weight:800;background:var(--moss);color:#fff;padding:3px 9px;border-radius:10px;text-transform:uppercase;letter-spacing:.06em">Admin</span>';
      }
      rosterHtml += '</div>';
      rosterHtml += '</div>';
    });
    rosterHtml += '</div>';
    container.innerHTML = rosterHtml;
  });
}

async function saveAdminRosterRow(uid, email) {
  if (!isFounder()) return;
  const tagEl = document.getElementById('roster-tag-' + uid);
  const tag = tagEl?.value.trim() || 'Admin';
  const plan = 'elite';
  const tierCredits = CREDIT_TIERS[plan]?.credits || CREDIT_TIERS.elite.credits;
  try {
    await window.fb.update(window.fb.ref(window.fb.database, 'users/' + uid + '/profile'), { adminTag: tag, isAdmin: true });
    await window.fb.update(window.fb.ref(window.fb.database, 'users/' + uid + '/credits'), { tier: plan, total: tierCredits, adminOverride: true });
    toast('Saved for ' + email + ' (Elite auto-assigned)');
  } catch (e) { toast('Error: ' + e.message); }
}

async function revokeAdminById(uid, name) {
  if (!isFounder()) return;
  if (!confirm('Revoke admin access for ' + name + '? They will lose Elite plan and admin tag.')) return;
  try {
    await window.fb.update(window.fb.ref(window.fb.database, 'users/' + uid + '/profile'), { isAdmin: false, adminTag: '' });
    await window.fb.update(window.fb.ref(window.fb.database, 'users/' + uid + '/credits'), { tier: 'free', total: FREE_TIER_CREDITS, adminOverride: false });
    toast('Admin revoked for ' + name);
  } catch (e) { toast('Error: ' + e.message); }
}

function toggleAvatarPicker() {
  const p = $('av-picker'); if (!p) return;
  p.style.display = p.style.display === 'block' ? 'none' : 'block';
}

async function pickAvatar(ic) {
  if (!S.userProfile) S.userProfile = { description: 'Student' };
  S.userProfile.avatar = ic;
  try {
    await window.fb.update(window.fb.ref(window.fb.database, `users/${S.user.uid}/profile`), { avatar: ic });
    toast('Avatar saved!'); renderApp(); renderContent();
  } catch (e) { toast('Could not save avatar'); }
}

function toggleProfileEdit() {
  const w = $('profile-edit-form'); if (!w) return;
  const vis = w.style.display === 'block'; w.style.display = vis ? 'none' : 'block';
  if (!vis) setTimeout(() => $('pe-name')?.focus(), 50);
}

async function saveProfileInline() {
  const nameRaw = ($('pe-name')?.value || '').trim();
  const descRaw = ($('pe-desc')?.value || '').trim();
  const name = validateStr(nameRaw || getDisplayName(), LIMITS.name);
  const description = validateStr(descRaw || 'Student', 100);
  const ageRaw = ($('pe-age')?.value || '').trim();
  const ageNum = ageRaw ? Math.max(8, Math.min(30, Number(ageRaw) || 0)) : null;
  const syllabusTrack = ($('pe-track')?.value || 'sg_o_level').trim();
  const benchmarkGroupId = ($('pe-benchmark-group')?.value || '').trim();
  const adminTagRaw = ($('pe-admintag')?.value || '').trim();
  const customTagRaw = ($('pe-customtag')?.value || '').trim();
  const btn = $('pe-save-btn');
  if (btn) { btn.disabled = true; btn.textContent = 'Saving…'; }
  if (!S.userProfile) S.userProfile = {};
  const updates = { name, description, syllabusTrack: validateStr(syllabusTrack, 24), benchmarkGroupId: validateStr(benchmarkGroupId, 80) || null };
  if (ageNum && Number.isFinite(ageNum)) updates.age = ageNum;
  else updates.age = null;
  if ((isAdmin() || isFounder()) && adminTagRaw) updates.adminTag = adminTagRaw;
  if (!isAdmin() && customTagRaw !== undefined) updates.customTag = validateStr(customTagRaw, 40) || '';
  Object.assign(S.userProfile, updates);
  try {
    await window.fb.update(window.fb.ref(window.fb.database, `users/${S.user.uid}/profile`), updates);
    await window.fb.update(window.fb.ref(window.fb.database, `userIndex/${S.user.uid}`), { name, email: S.user.email, uid: S.user.uid, displayName: name });
    // Also update Firebase Auth display name so it's reflected everywhere
    if (window.fb.auth?.currentUser) {
      try { await window.fb.auth.currentUser.updateProfile({ displayName: name }); } catch (_) {}
    }
    toast('Profile saved!'); toggleProfileEdit(); renderApp(); renderContent();
  } catch (e) {
    toast('Error saving: ' + e.message);
    if (btn) { btn.disabled = false; btn.innerHTML = icons.ok + ' Save'; }
  }
}

// ─── Admin Management ─────────────────────────────────────────
async function promoteToAdmin() {
  if (!canPromoteAdmins()) return toast('Only users with the AAdmin tag can promote others to admin');
  const email = ($('admin-promote-email')?.value || '').trim().toLowerCase();
  if (!email || !email.includes('@')) return toast('Enter a valid email');
  const status = $('admin-action-status');
  if (status) status.textContent = 'Searching…';
  try {
    const snap = await window.fb.get(window.fb.ref(window.fb.database, 'users'));
    if (!snap.exists()) { if (status) status.textContent = 'No users found'; return; }
    const users = Object.entries(snap.val()).map(([uid, value]) => ({ uid, email: value?.email || '', name: value?.profile?.name || value?.email || 'Unknown' }));
    const target = users.find(u => u.email === email);
    if (!target) { if (status) status.innerHTML = '<span style="color:var(--red)">User not found</span>'; return; }
    await window.fb.update(window.fb.ref(window.fb.database, `users/${target.uid}/profile`), { isAdmin: true, adminTag: 'Admin' });
    if (status) status.innerHTML = `<span style="color:var(--green)">✓ ${esc(target.name || email)} is now an admin</span>`;
    toast(`${target.name || email} promoted to admin!`);
    if ($('admin-promote-email')) $('admin-promote-email').value = '';
  } catch (e) { if (status) status.innerHTML = `<span style="color:var(--red)">Error: ${esc(e.message)}</span>`; }
}

async function setAdminTagFor() {
  if (!isAdmin()) return toast('Only admins can do this');
  const email = ($('admin-tag-email')?.value || '').trim().toLowerCase();
  const tag = ($('admin-tag-value')?.value || '').trim();
  if (!email || !email.includes('@')) return toast('Enter a valid email');
  if (!tag) return toast('Enter a tag');
  const status = $('admin-action-status');
  if (status) status.textContent = 'Updating…';
  try {
    const snap = await window.fb.get(window.fb.ref(window.fb.database, 'users'));
    if (!snap.exists()) { if (status) status.textContent = 'No users found'; return; }
    const users = Object.entries(snap.val()).map(([uid, value]) => ({ uid, email: value?.email || '', name: value?.profile?.name || value?.email || 'Unknown' }));
    const target = users.find(u => u.email === email);
    if (!target) { if (status) status.innerHTML = '<span style="color:var(--red)">User not found</span>'; return; }
    await window.fb.update(window.fb.ref(window.fb.database, `users/${target.uid}/profile`), { adminTag: tag });
    if (status) status.innerHTML = `<span style="color:var(--green)">✓ Tag set to "${esc(tag)}"</span>`;
    toast('Tag updated!');
    if ($('admin-tag-email')) $('admin-tag-email').value = '';
    if ($('admin-tag-value')) $('admin-tag-value').value = '';
  } catch (e) { if (status) status.innerHTML = `<span style="color:var(--red)">Error: ${esc(e.message)}</span>`; }
}

async function setTagForAnyUser() {
  if (!isAdmin()) return toast('Only admins can do this');
  const email = ($('admin-tag-email')?.value || '').trim().toLowerCase();
  const tag = ($('admin-tag-value')?.value || '').trim();
  if (!email || !email.includes('@')) return toast('Enter a valid email');
  if (!tag) return toast('Enter a tag');
  const status = $('admin-action-status');
  if (status) status.textContent = 'Updating…';
  try {
    const snap = await window.fb.get(window.fb.ref(window.fb.database, 'users'));
    if (!snap.exists()) { if (status) status.textContent = 'No users found'; return; }
    const users = Object.entries(snap.val()).map(([uid, value]) => ({ uid, email: value?.email || '', name: value?.profile?.name || value?.email || 'Unknown' }));
    const target = users.find(u => u.email === email);
    if (!target) { if (status) status.innerHTML = '<span style="color:var(--red)">User not found</span>'; return; }
    // For admin users, update adminTag; for regular users update customTag
    const targetSnap = await window.fb.get(window.fb.ref(window.fb.database, `users/${target.uid}/profile`));
    const targetProfile = targetSnap.exists() ? targetSnap.val() : {};
    const updateObj = targetProfile.isAdmin || target.uid === FOUNDER_EMAIL
      ? { adminTag: tag }
      : { customTag: tag };
    await window.fb.update(window.fb.ref(window.fb.database, `users/${target.uid}/profile`), updateObj);
    if (status) status.innerHTML = `<span style="color:var(--green)">✓ Tag set to "${esc(tag)}" for ${esc(target.name || email)}</span>`;
    toast('Tag updated!');
    if ($('admin-tag-email')) $('admin-tag-email').value = '';
    if ($('admin-tag-value')) $('admin-tag-value').value = '';
  } catch (e) { if (status) status.innerHTML = `<span style="color:var(--red)">Error: ${esc(e.message)}</span>`; }
}

function renderCollabList(c) {
  c.innerHTML = `
    <h1 class="page-title-el" style="font-size:36px;margin-bottom:8px">Collab Notes</h1>
    <p style="color:var(--text-muted);font-size:14px;margin-bottom:20px">Real-time collaborative documents — edit together with anyone</p>
    <button class="btn btn-action btn-sm" onclick="toggleCollabForm()" style="margin-bottom:20px">${icons.plus} New Collab Note</button>

    <div id="collab-form-wrap" class="inline-form-wrap" style="display:none;margin-bottom:24px">
      <div class="inline-form">
        <div class="inline-form-title">New Collab Note</div>
        <div class="form-group"><label class="form-label">Title</label>
          <input id="collab-title-inp" class="form-input" placeholder="Note title"></div>
        <div class="form-group"><label class="form-label">Description <span style="color:var(--text-faint)">(optional)</span></label>
          <input id="collab-desc-inp" class="form-input" placeholder="What is this note about?"></div>
        <div class="form-group"><label class="form-label">Share with Study Group <span style="color:var(--text-faint)">(optional)</span></label>
          <select id="collab-group-sel" class="form-input">
            <option value="">— Public to all users —</option>
            ${S.studyGroups.map(g => `<option value="${esc(g.id)}">${esc(g.name)}</option>`).join('')}
          </select>
        </div>
        <div class="modal-foot">
          <button class="btn btn-ghost btn-sm" onclick="toggleCollabForm()">Cancel</button>
          <button class="btn btn-action btn-sm" onclick="submitCreateCollabNote()">${icons.plus} Create</button>
        </div>
      </div>
    </div>

    <div id="collab-list-body"><div class="empty"><div class="empty-icon">${icons.collab}</div><div class="empty-title">Loading…</div></div></div>`;
  const inp = $('collab-title-inp'); if (inp) inp.addEventListener('keydown', e => { if (e.key === 'Enter') submitCreateCollabNote(); });
  loadCollabList();
}

function toggleCollabForm() {
  const w = $('collab-form-wrap'); if (!w) return;
  const vis = w.style.display === 'block'; w.style.display = vis ? 'none' : 'block';
  if (!vis) setTimeout(() => $('collab-title-inp')?.focus(), 50);
}

async function submitCreateCollabNote() {
  const title = $('collab-title-inp')?.value.trim(); if (!title) return toast('Enter a title');
  const description = $('collab-desc-inp')?.value.trim() || '';
  const groupId = $('collab-group-sel')?.value || '';
  const id = uid();
  const note = {
    id, title, description, content: '', tables: {}, images: [],
    createdAt: new Date().toISOString(), createdBy: S.user.uid, createdByName: getDisplayName(),
    updatedAt: new Date().toISOString(), groupId: groupId || null
  };
  try {
    await window.fb.set(window.fb.ref(window.fb.database, `collab/${id}`), note);
    await window.fb.update(window.fb.ref(window.fb.database, `users/${S.user.uid}/collabNotes`), { [id]: true });
    if (groupId) {
      await window.fb.set(window.fb.ref(window.fb.database, `studyGroups/${groupId}/noteIndex/${id}`), S.user.uid).catch(() => {});
    }
    toggleCollabForm(); openCollabNote(id);
  } catch (e) { toast('Error: ' + e.message); }
}

let _collabListListener = null;

async function fetchCollabNotesByIds(ids) {
  const uniqueIds = Array.from(new Set((ids || []).filter(Boolean)));
  const snaps = await Promise.all(uniqueIds.map(id =>
    window.fb.get(window.fb.ref(window.fb.database, `collab/${id}`)).catch(() => null)
  ));
  return snaps
    .map((snap, idx) => (snap && snap.exists()) ? { id: uniqueIds[idx], ...snap.val() } : null)
    .filter(Boolean)
    .sort((a, b) => String(b.updatedAt || b.createdAt || '').localeCompare(String(a.updatedAt || a.createdAt || '')));
}

async function loadCollabList() {
  const body = $('collab-list-body'); if (!body) return;
  body.innerHTML = `<div class="empty"><div class="empty-icon">${icons.collab}</div><div class="empty-title">Loading…</div></div>`;
  try {
    const ownSnap = await window.fb.get(window.fb.ref(window.fb.database, `users/${S.user.uid}/collabNotes`));
    const ownIds = ownSnap.exists() ? Object.keys(ownSnap.val() || {}) : [];
    const groupIds = S.studyGroups.flatMap(g => Object.keys(g.noteIndex || {}));
    const notes = await fetchCollabNotesByIds([...ownIds, ...groupIds]);
    const body2 = $('collab-list-body'); if (!body2) return;
    if (!notes.length) {
      body2.innerHTML = `<div class="empty"><div class="empty-icon">${icons.collab}</div><div class="empty-title">No Collab Notes</div><p class="empty-sub">Create one to start collaborating in real-time</p></div>`;
      return;
    }
    body2.innerHTML = `<div class="collab-grid">
      ${notes.map(n => `
        <div class="collab-card">
          <div style="display:flex;align-items:flex-start;justify-content:space-between;margin-bottom:12px">
            <div class="collab-card-icon">${icons.collab}</div>
            ${n.createdBy === S.user?.uid ? `<button class="icon-btn" onclick="event.stopPropagation();deleteCollabNote('${n.id}')" style="color:var(--red);width:24px;height:24px">${icons.trash}</button>` : ''}
          </div>
          <div class="collab-card-title" onclick="openCollabNote('${n.id}')" style="cursor:pointer">${esc(n.title) || 'Untitled Note'}</div>
          ${n.description ? `<div style="font-size:12.5px;color:var(--text-muted);margin-bottom:4px">${esc(n.description)}</div>` : ''}
          <div class="collab-card-meta">By ${esc(n.createdByName) || 'Someone'} · ${fmt(n.updatedAt || n.createdAt)}</div>
          ${n.groupId ? `<div style="font-size:11.5px;color:var(--blue);display:flex;align-items:center;gap:4px">${icons.group} Group note</div>` : ''}
          <div class="collab-card-foot" onclick="openCollabNote('${n.id}')" style="cursor:pointer">
            <span class="collab-card-users">${icons.profile} Open to edit</span>
            ${n.lastEditBy ? `<span style="font-size:11.5px;color:var(--text-faint)">Last edit by ${esc(n.lastEditBy)}</span>` : ''}
          </div>
        </div>`).join('')}
    </div>`;
  } catch (err) {
    const body2 = $('collab-list-body'); if (body2) body2.innerHTML = `<div class="empty"><div class="empty-title">Error loading notes</div><p class="empty-sub">${esc(err.message)}</p></div>`;
  }
}

async function deleteCollabNote(id) {
  try {
    const snap = await window.fb.get(window.fb.ref(window.fb.database, `collab/${id}`));
    const note = snap.exists() ? snap.val() || {} : {};
    await window.fb.remove(window.fb.ref(window.fb.database, `collab/${id}`));
    await window.fb.remove(window.fb.ref(window.fb.database, `users/${S.user.uid}/collabNotes/${id}`)).catch(() => {});
    if (note.groupId) {
      await window.fb.remove(window.fb.ref(window.fb.database, `studyGroups/${note.groupId}/noteIndex/${id}`)).catch(() => {});
    }
    toast('Note deleted'); loadCollabList();
  } catch (e) { toast('Error: ' + e.message); }
}

function openCollabNote(noteId, options = {}) {
  const { pushHistory = true, replaceHistory = false } = options;
  if (S.collabListener) { S.collabListener(); S.collabListener = null; }
  if (S.presenceListener) { S.presenceListener(); S.presenceListener = null; }
  if (S.activeCollabNote && S.user) window.fb.remove(window.fb.ref(window.fb.database, `collab/${S.activeCollabNote}/presence/${S.user.uid}`)).catch(() => { });
  S.activeCollabNote = noteId; S.view = 'collabNote';
  closeSidebarAfterNavigate();
  syncRouteWithState({ push: pushHistory, replace: replaceHistory });
  renderApp();
}

let _collabDebounce = null;
let _collabBoardSaveDebounce = null;
const COLLAB_WHITEBOARD_GROWTH = 720;
const CollabBoard = {
  noteId: null,
  elements: [],
  canvasHeight: 1080,
  canvasWidth: 1760,
  tool: 'move',
  draggingId: null,
  dragOffsetX: 0,
  dragOffsetY: 0,
  drawingId: null,
  activeId: null,
  bound: false,
};

function ensureCollabWhiteboardData(board = {}) {
  return {
    canvasHeight: Math.max(1080, Number(board?.canvasHeight) || 1080),
    canvasWidth: Math.max(1600, Number(board?.canvasWidth) || 1760),
    elements: Array.isArray(board?.elements) ? board.elements : [],
  };
}

function collabWhiteboardToolBtn(tool, label) {
  return `<button class="collab-tb-btn${CollabBoard.tool === tool ? ' active' : ''}" onclick="setCollabWhiteboardTool('${tool}')">${label}</button>`;
}

function collabWhiteboardDefaultElement(type) {
  const column = CollabBoard.elements.length % 3;
  const row = Math.floor(CollabBoard.elements.length / 3);
  const centerX = Math.round(CollabBoard.canvasWidth / 2);
  const baseX = Math.max(120, centerX - 390 + (column * 260));
  const baseY = 140 + (row * 190);
  if (type === 'sticky') return { id: uid(), type, x: baseX, y: baseY, width: 190, height: 150, text: 'Untitled thought', tone: ['sun', 'mint', 'sky', 'rose'][CollabBoard.elements.length % 4] };
  if (type === 'text') return { id: uid(), type, x: baseX, y: baseY, width: 260, height: 72, text: 'New label' };
  if (type === 'rect') return { id: uid(), type, x: baseX, y: baseY, width: 220, height: 132, text: 'Process' };
  if (type === 'ellipse') return { id: uid(), type, x: baseX, y: baseY, width: 220, height: 132, text: 'Decision' };
  return { id: uid(), type: 'line', x1: baseX, y1: baseY, x2: baseX + 190, y2: baseY + 90 };
}

function setCollabWhiteboardTool(tool) {
  CollabBoard.tool = tool;
  renderCollabWhiteboard(collabWhiteboardSnapshot(), CollabBoard.noteId);
}

function collabWhiteboardSnapshot() {
  return {
    canvasHeight: CollabBoard.canvasHeight,
    canvasWidth: CollabBoard.canvasWidth,
    elements: JSON.parse(JSON.stringify(CollabBoard.elements || [])),
  };
}

function collabWhiteboardMarkSaving() {
  const status = $('collab-status');
  if (status) {
    status.textContent = 'Saving…';
    status.style.color = 'var(--orange)';
  }
}

function saveCollabWhiteboard(noteId = CollabBoard.noteId) {
  if (!noteId) return;
  clearTimeout(_collabBoardSaveDebounce);
  _collabBoardSaveDebounce = setTimeout(async () => {
    try {
      await window.fb.update(window.fb.ref(window.fb.database, `collab/${noteId}`), {
        whiteboard: collabWhiteboardSnapshot(),
        updatedAt: new Date().toISOString(),
        lastEditBy: validateStr(getDisplayName(), LIMITS.name),
      });
      const status = $('collab-status');
      if (status) {
        status.textContent = 'Live';
        status.style.color = 'var(--green)';
      }
    } catch {
      const status = $('collab-status');
      if (status) {
        status.textContent = 'Error';
        status.style.color = 'var(--red)';
      }
    }
  }, 180);
}

function ensureCollabWhiteboardSpace(y) {
  const required = Math.max(0, Number(y) || 0) + 220;
  if (required <= CollabBoard.canvasHeight) return;
  CollabBoard.canvasHeight = Math.ceil(required / COLLAB_WHITEBOARD_GROWTH) * COLLAB_WHITEBOARD_GROWTH;
  const stage = $('collab-whiteboard-stage');
  if (stage) stage.style.height = `${CollabBoard.canvasHeight}px`;
}

function collabWhiteboardElementCenter(item) {
  if (!item) return { x: 0, y: 0 };
  if (item.type === 'line') {
    return {
      x: ((Number(item.x1) || 0) + (Number(item.x2) || 0)) / 2,
      y: ((Number(item.y1) || 0) + (Number(item.y2) || 0)) / 2,
    };
  }
  if (item.type === 'draw') {
    const points = Array.isArray(item.points) ? item.points : [];
    if (!points.length) return { x: 0, y: 0 };
    const xs = points.map(point => Number(point.x) || 0);
    const ys = points.map(point => Number(point.y) || 0);
    return {
      x: (Math.min(...xs) + Math.max(...xs)) / 2,
      y: (Math.min(...ys) + Math.max(...ys)) / 2,
    };
  }
  return {
    x: (Number(item.x) || 0) + ((Number(item.width) || 180) / 2),
    y: (Number(item.y) || 0) + ((Number(item.height) || 120) / 2),
  };
}

function collabWhiteboardSelectionMarkup() {
  const active = CollabBoard.elements.find(item => item.id === CollabBoard.activeId);
  if (!active) return '';
  const center = collabWhiteboardElementCenter(active);
  return `<button class="collab-whiteboard-floating-delete" style="left:${Math.max(18, Math.round(center.x))}px;top:${Math.max(18, Math.round(center.y - 24))}px" onclick="event.stopPropagation();deleteCollabWhiteboardElement('${active.id}')" title="Delete selected item">Delete</button>`;
}

function addCollabWhiteboardElement(type) {
  if (!CollabBoard.noteId) return;
  const next = collabWhiteboardDefaultElement(type);
  ensureCollabWhiteboardSpace(type === 'line' ? Math.max(next.y1, next.y2) : (next.y + (next.height || 120)));
  CollabBoard.elements.push(next);
  CollabBoard.activeId = next.id;
  collabWhiteboardMarkSaving();
  renderCollabWhiteboard(collabWhiteboardSnapshot(), CollabBoard.noteId);
  saveCollabWhiteboard();
}

function updateCollabWhiteboardElementText(id, value) {
  const element = CollabBoard.elements.find(item => item.id === id);
  if (!element) return;
  element.text = validateStr(value, LIMITS.content, '');
  collabWhiteboardMarkSaving();
  saveCollabWhiteboard();
}

function deleteCollabWhiteboardElement(id) {
  CollabBoard.elements = (CollabBoard.elements || []).filter(item => item.id !== id);
  if (CollabBoard.activeId === id) CollabBoard.activeId = null;
  collabWhiteboardMarkSaving();
  renderCollabWhiteboard(collabWhiteboardSnapshot(), CollabBoard.noteId);
  saveCollabWhiteboard();
}

function collabWhiteboardSvgMarkup() {
  const lineElements = CollabBoard.elements.filter(item => item.type === 'line');
  const drawElements = CollabBoard.elements.filter(item => item.type === 'draw');
  return `<svg class="collab-whiteboard-svg" viewBox="0 0 ${CollabBoard.canvasWidth} ${Math.max(1200, CollabBoard.canvasHeight)}" preserveAspectRatio="none">
    ${lineElements.map(line => `<g class="collab-whiteboard-wire${CollabBoard.activeId === line.id ? ' is-active' : ''}" data-wb-id="${line.id}"><line x1="${line.x1}" y1="${line.y1}" x2="${line.x2}" y2="${line.y2}"></line></g>`).join('')}
    ${drawElements.map(stroke => `<path class="collab-whiteboard-stroke${CollabBoard.activeId === stroke.id ? ' is-active' : ''}" data-wb-id="${stroke.id}" d="${stroke.path || ''}" stroke="${stroke.color || '#8f6a42'}" stroke-width="${stroke.strokeWidth || 3.5}" />`).join('')}
  </svg>`;
}

function renderCollabWhiteboard(board, noteId) {
  const sec = $('collab-whiteboard-section');
  if (!sec) return;
  const safeBoard = ensureCollabWhiteboardData(board);
  const activeTextarea = document.activeElement?.classList?.contains('collab-whiteboard-textarea')
    ? {
        id: document.activeElement.closest('[data-wb-id]')?.dataset.wbId,
        start: document.activeElement.selectionStart,
        end: document.activeElement.selectionEnd,
      }
    : null;
  if (!CollabBoard.draggingId && !CollabBoard.drawingId) {
    CollabBoard.noteId = noteId;
    CollabBoard.elements = JSON.parse(JSON.stringify(safeBoard.elements));
    CollabBoard.canvasHeight = safeBoard.canvasHeight;
    CollabBoard.canvasWidth = safeBoard.canvasWidth;
    if (CollabBoard.activeId && !CollabBoard.elements.some(item => item.id === CollabBoard.activeId)) CollabBoard.activeId = null;
  }
  sec.innerHTML = `
    <div class="collab-whiteboard-shell">
      <div class="collab-section-head">
        <span>${icons.collab} Whiteboard</span>
        <span class="collab-whiteboard-meta">${CollabBoard.elements.length} items</span>
      </div>
      <div class="collab-whiteboard-toolbar">
        <div class="collab-whiteboard-tools">
          ${collabWhiteboardToolBtn('move', 'Move')}
          ${collabWhiteboardToolBtn('draw', 'Draw')}
          ${collabWhiteboardToolBtn('erase', 'Stroke Eraser')}
          <button class="collab-tb-btn" onclick="addCollabWhiteboardElement('sticky')">Sticky</button>
          <button class="collab-tb-btn" onclick="addCollabWhiteboardElement('text')">Text</button>
          <button class="collab-tb-btn" onclick="addCollabWhiteboardElement('rect')">Rect</button>
          <button class="collab-tb-btn" onclick="addCollabWhiteboardElement('ellipse')">Circle</button>
          <button class="collab-tb-btn" onclick="addCollabWhiteboardElement('line')">Line</button>
        </div>
        <div class="collab-whiteboard-meta">Centered canvas, drag to arrange, click a stroke to delete it</div>
      </div>
      <div class="collab-whiteboard-viewport" id="collab-whiteboard-viewport">
        <div class="collab-whiteboard-stage-wrap">
          <div class="collab-whiteboard-stage${CollabBoard.tool === 'draw' ? ' draw-mode' : ''}" id="collab-whiteboard-stage" style="width:${CollabBoard.canvasWidth}px;height:${CollabBoard.canvasHeight}px">
            ${collabWhiteboardSvgMarkup()}
            ${collabWhiteboardSelectionMarkup()}
            ${CollabBoard.elements.filter(item => item.type !== 'line' && item.type !== 'draw').map(item => {
            const classes = ['collab-whiteboard-node', CollabBoard.activeId === item.id ? 'is-active' : '', item.type === 'sticky' ? `sticky ${item.tone || 'sun'}` : '', item.type === 'text' ? 'text' : '', item.type === 'rect' ? 'rect' : '', item.type === 'ellipse' ? 'ellipse' : ''].filter(Boolean).join(' ');
            return `<div class="${classes}" data-wb-id="${item.id}" style="left:${item.x}px;top:${item.y}px;width:${item.width || 180}px;height:${item.height || 120}px">
              <button class="collab-whiteboard-delete" onclick="event.stopPropagation();deleteCollabWhiteboardElement('${item.id}')" title="Delete">×</button>
              <textarea class="collab-whiteboard-textarea" oninput="updateCollabWhiteboardElementText('${item.id}', this.value)">${esc(item.text || '')}</textarea>
            </div>`;
          }).join('')}
          </div>
        </div>
      </div>
    </div>`;
  if (activeTextarea?.id) {
    const nextTextarea = sec.querySelector(`[data-wb-id="${activeTextarea.id}"] .collab-whiteboard-textarea`);
    if (nextTextarea) {
      nextTextarea.focus();
      nextTextarea.setSelectionRange(activeTextarea.start, activeTextarea.end);
    }
  }
  initCollabWhiteboardInteractions();
}

function collabWhiteboardPoint(evt) {
  const stage = $('collab-whiteboard-stage');
  const viewport = $('collab-whiteboard-viewport');
  if (!stage || !viewport) return null;
  const rect = stage.getBoundingClientRect();
  return {
    x: Math.max(0, evt.clientX - rect.left + viewport.scrollLeft),
    y: Math.max(0, evt.clientY - rect.top + viewport.scrollTop),
  };
}

function collabStrokeDistance(point, stroke) {
  if (!point || !stroke) return Infinity;
  if (stroke.type === 'line') {
    const x1 = Number(stroke.x1) || 0;
    const y1 = Number(stroke.y1) || 0;
    const x2 = Number(stroke.x2) || 0;
    const y2 = Number(stroke.y2) || 0;
    const dx = x2 - x1;
    const dy = y2 - y1;
    const lenSq = (dx * dx) + (dy * dy) || 1;
    const t = Math.max(0, Math.min(1, (((point.x - x1) * dx) + ((point.y - y1) * dy)) / lenSq));
    const px = x1 + (t * dx);
    const py = y1 + (t * dy);
    return Math.hypot(point.x - px, point.y - py);
  }
  if (stroke.type === 'draw' && Array.isArray(stroke.points)) {
    let min = Infinity;
    stroke.points.forEach(p => {
      const d = Math.hypot(point.x - (Number(p.x) || 0), point.y - (Number(p.y) || 0));
      if (d < min) min = d;
    });
    return min;
  }
  return Infinity;
}

function collabWhiteboardEraseStrokeAt(point) {
  const candidates = (CollabBoard.elements || [])
    .filter(item => item.type === 'draw' || item.type === 'line')
    .map(item => ({ item, dist: collabStrokeDistance(point, item) }))
    .sort((a, b) => a.dist - b.dist);
  const hit = candidates[0];
  if (!hit || hit.dist > 20) return false;
  deleteCollabWhiteboardElement(hit.item.id);
  return true;
}

function initCollabWhiteboardInteractions() {
  const stage = $('collab-whiteboard-stage');
  if (!stage || stage.dataset.bound === 'true') return;
  stage.dataset.bound = 'true';
  stage.addEventListener('pointerdown', evt => {
    const point = collabWhiteboardPoint(evt);
    if (!point) return;
    const node = evt.target.closest('[data-wb-id]');
    if (CollabBoard.tool === 'erase' && !evt.target.closest('button') && !evt.target.closest('textarea')) {
      evt.preventDefault();
      collabWhiteboardEraseStrokeAt(point);
      return;
    }
    if (CollabBoard.tool === 'draw' && !evt.target.closest('.collab-whiteboard-node') && !evt.target.closest('button')) {
      evt.preventDefault();
      const stroke = { id: uid(), type: 'draw', color: '#8f6a42', strokeWidth: 3.5, points: [point], path: `M ${point.x} ${point.y}` };
      CollabBoard.drawingId = stroke.id;
      CollabBoard.activeId = stroke.id;
      CollabBoard.elements.push(stroke);
      ensureCollabWhiteboardSpace(point.y);
      collabWhiteboardMarkSaving();
      renderCollabWhiteboard(collabWhiteboardSnapshot(), CollabBoard.noteId);
      return;
    }
    if (!node && !evt.target.closest('button')) {
      if (CollabBoard.activeId) {
        CollabBoard.activeId = null;
        renderCollabWhiteboard(collabWhiteboardSnapshot(), CollabBoard.noteId);
      }
      return;
    }
    if (!node || evt.target.closest('textarea') || evt.target.closest('button')) return;
    const id = node.dataset.wbId;
    const element = CollabBoard.elements.find(item => item.id === id);
    if (!element) return;
    evt.preventDefault();
    CollabBoard.activeId = id;
    if (element.type === 'draw') {
      renderCollabWhiteboard(collabWhiteboardSnapshot(), CollabBoard.noteId);
      return;
    }
    CollabBoard.draggingId = id;
    if (element.type === 'line') {
      CollabBoard.dragOffsetX = point.x - Math.min(element.x1, element.x2);
      CollabBoard.dragOffsetY = point.y - Math.min(element.y1, element.y2);
    } else {
      CollabBoard.dragOffsetX = point.x - (element.x || 0);
      CollabBoard.dragOffsetY = point.y - (element.y || 0);
    }
  });
  if (CollabBoard.bound) return;
  CollabBoard.bound = true;
  window.addEventListener('pointermove', evt => {
    const point = collabWhiteboardPoint(evt);
    if (!point) return;
    if (CollabBoard.drawingId) {
      const stroke = CollabBoard.elements.find(item => item.id === CollabBoard.drawingId);
      if (!stroke) return;
      stroke.points.push(point);
      stroke.path = stroke.points.map((p, index) => `${index === 0 ? 'M' : 'L'} ${Math.round(p.x)} ${Math.round(p.y)}`).join(' ');
      ensureCollabWhiteboardSpace(point.y);
      renderCollabWhiteboard(collabWhiteboardSnapshot(), CollabBoard.noteId);
      return;
    }
    if (!CollabBoard.draggingId) return;
    const element = CollabBoard.elements.find(item => item.id === CollabBoard.draggingId);
    if (!element) return;
    if (element.type === 'line') {
      const width = element.x2 - element.x1;
      const height = element.y2 - element.y1;
      const minX = Math.max(0, point.x - CollabBoard.dragOffsetX);
      const minY = Math.max(0, point.y - CollabBoard.dragOffsetY);
      element.x1 = minX;
      element.y1 = minY;
      element.x2 = minX + width;
      element.y2 = minY + height;
      ensureCollabWhiteboardSpace(Math.max(element.y1, element.y2));
    } else {
      element.x = Math.max(0, point.x - CollabBoard.dragOffsetX);
      element.y = Math.max(0, point.y - CollabBoard.dragOffsetY);
      ensureCollabWhiteboardSpace(element.y + (element.height || 120));
    }
    collabWhiteboardMarkSaving();
    renderCollabWhiteboard(collabWhiteboardSnapshot(), CollabBoard.noteId);
  });
  window.addEventListener('pointerup', () => {
    if (!CollabBoard.draggingId && !CollabBoard.drawingId) return;
    CollabBoard.draggingId = null;
    CollabBoard.drawingId = null;
    renderCollabWhiteboard(collabWhiteboardSnapshot(), CollabBoard.noteId);
    saveCollabWhiteboard();
  });
}

function renderCollabNote(c) {
  c.innerHTML = `
    <div style="display:flex;align-items:center;gap:10px;margin-bottom:20px;flex-wrap:wrap">
      <button class="icon-btn" onclick="navigate('collab')">${icons.back}</button>
      <h1 id="collab-title-display" style="font-size:24px;font-weight:700;flex:1"></h1>
      <div id="collab-presence" style="display:flex;gap:6px;align-items:center"></div>
    </div>
    <div id="collab-desc-display" style="color:var(--text-muted);font-size:14px;margin-bottom:16px"></div>
    <div id="collab-loading" style="color:var(--text-muted);font-size:14px">Loading note...</div>
    <div id="collab-editor-wrap" class="hidden">
      <!-- Toolbar -->
      <div class="collab-toolbar">
        <button class="collab-tb-btn" onclick="collabInsertTable()" title="Insert Table">${icons.table} Table</button>
        <button class="collab-tb-btn" onclick="collabInsertImage()" title="Insert Image">${icons.image} Image</button>
        <div class="collab-tb-sep"></div>
        <div id="collab-status" class="collab-status">Live</div>
      </div>
      <textarea id="collab-editor" class="collab-editor" placeholder="Start typing… changes are saved in real-time for everyone"></textarea>
      <!-- Tables section -->
      <div id="collab-tables-section" style="margin-top:24px"></div>
      <!-- Images section -->
      <div id="collab-images-section" style="margin-top:16px"></div>
      <!-- Whiteboard section -->
      <div id="collab-whiteboard-section" style="margin-top:20px"></div>
    </div>`;
  setupCollabListeners(S.activeCollabNote);
}

function setupCollabListeners(noteId) {
  if (!noteId || !S.user) return;
  const noteRef = window.fb.ref(window.fb.database, `collab/${noteId}`);
  const presenceRef = window.fb.ref(window.fb.database, `collab/${noteId}/presence/${S.user.uid}`);
  const presenceListRef = window.fb.ref(window.fb.database, `collab/${noteId}/presence`);
  const myPresence = { name: getDisplayName(), email: S.user.email, online: true, lastSeen: Date.now() };
  window.fb.set(presenceRef, myPresence).catch(() => { });
  window.fb.onDisconnect(presenceRef).remove();

  S.collabListener = window.fb.onValue(noteRef, (snap) => {
    if (!snap.exists()) return;
    const note = snap.val();
    const titleEl = $('collab-title-display'), descEl = $('collab-desc-display');
    const loading = $('collab-loading'), wrap = $('collab-editor-wrap'), editor = $('collab-editor');
    if (titleEl) titleEl.textContent = validateStr(note.title || 'Untitled', LIMITS.title);
    if (descEl) descEl.textContent = validateStr(note.description || '', LIMITS.description);
    if (loading) loading.classList.add('hidden');
    if (wrap) wrap.classList.remove('hidden');
    if (editor && document.activeElement !== editor) editor.value = note.content || '';
    if (editor && !editor._listenerAttached) {
      editor._listenerAttached = true;
      editor.addEventListener('input', () => {
        clearTimeout(_collabDebounce);
        const status = $('collab-status');
        if (status) { status.textContent = 'Saving…'; status.style.color = 'var(--orange)'; }
        _collabDebounce = setTimeout(async () => {
          try {
            const _cv = editor.value;
            if (_cv.length > LIMITS.noteContent) { const s = document.getElementById('collab-status'); if (s) { s.textContent = 'Too large'; s.style.color = 'var(--red)'; } return; }
            await window.fb.update(window.fb.ref(window.fb.database, `collab/${noteId}`), { content: _cv, updatedAt: new Date().toISOString(), lastEditBy: validateStr(getDisplayName(), LIMITS.name) });
            const s = $('collab-status'); if (s) { s.textContent = 'Live'; s.style.color = 'var(--green)'; }
          } catch (e) { const s = $('collab-status'); if (s) { s.textContent = 'Error'; s.style.color = 'var(--red)'; } }
        }, 500);
      });
    }
    // Render tables
    renderCollabTables(note.tables || {}, noteId);
    // Render images
    renderCollabImages(note.images || [], noteId);
    // Render whiteboard
    renderCollabWhiteboard(note.whiteboard || {}, noteId);
  });

  S.presenceListener = window.fb.onValue(presenceListRef, (snap) => {
    const presEl = $('collab-presence'); if (!presEl) return;
    if (!snap.exists()) { presEl.innerHTML = ''; return; }
    const users = Object.values(snap.val()).filter(u => u.online);
    presEl.innerHTML = users.map(u => `<div class="presence-avatar" title="${esc(u.name || u.email)}">${(u.name || u.email || '?')[0].toUpperCase()}</div>`).join('');
  });
}

function renderCollabTables(tables, noteId) {
  const sec = $('collab-tables-section'); if (!sec) return;
  const tableArr = Object.values(tables);
  if (!tableArr.length) { sec.innerHTML = ''; return; }
  sec.innerHTML = `<div class="collab-section-head">${icons.table} Tables</div>` + tableArr.map(tbl => `
    <div class="collab-tbl-wrap" id="collab-tbl-${tbl.id}">
      <div class="collab-tbl-header">
        <span class="collab-tbl-name">${esc(tbl.name) || 'Table'}</span>
        <button class="icon-btn" onclick="collabDeleteTable('${tbl.id}','${noteId}')" style="width:22px;height:22px;color:var(--red)">${icons.trash}</button>
      </div>
      <div class="db-wrap" style="margin-bottom:8px">
        <table class="db-table">
          <thead><tr>${(tbl.headers || []).map(h => `<th>${h}</th>`).join('')}<th style="width:30px"></th></tr></thead>
          <tbody>${(tbl.rows || []).map((row, ri) => `<tr>
            ${row.map((cell, ci) => `<td contenteditable="true" onblur="collabUpdateCell('${tbl.id}','${noteId}',${ri},${ci},this.textContent)">${cell}</td>`).join('')}
            <td class="del-td"><button class="icon-btn" onclick="collabDelRow('${tbl.id}','${noteId}',${ri})" style="width:20px;height:20px">${icons.trash}</button></td>
          </tr>`).join('')}</tbody>
        </table>
      </div>
      <div style="display:flex;gap:7px">
        <button class="btn btn-ghost btn-sm" onclick="collabAddRow('${tbl.id}','${noteId}')">${icons.plus} Row</button>
        <button class="btn btn-ghost btn-sm" onclick="collabAddCol('${tbl.id}','${noteId}')">${icons.plus} Column</button>
      </div>
    </div>`).join('');
}

function renderCollabImages(images, noteId) {
  const sec = $('collab-images-section'); if (!sec) return;
  if (!images || !images.length) { sec.innerHTML = ''; return; }
  sec.innerHTML = `<div class="collab-section-head">${icons.image} Images</div>` + images.map((img, i) => {
    const safeSrc = sanitizeUrl(img.url || '');
    if (!safeSrc) return '';
    return `<div class="collab-img-wrap">
      <img src="${safeSrc}" alt="${esc(img.caption || '')}" class="collab-img" onerror="this.style.display='none';this.nextElementSibling.style.display='block'">
      <div style="display:none;color:var(--text-muted);font-size:13px;padding:8px">Image could not be loaded</div>
      ${img.caption ? `<div class="collab-img-caption">${esc(img.caption)}</div>` : ''}
      <div style="display:flex;align-items:center;gap:6px;margin-top:6px">
        <span style="font-size:11.5px;color:var(--text-faint)">${esc(img.addedBy || '')}${img.addedAt ? ' · ' + fmt(img.addedAt) : ''}</span>
        <button class="btn btn-ghost btn-sm" onclick="collabDeleteImage(${i},'${noteId}')" style="color:var(--red);margin-left:auto">${icons.trash} Remove</button>
      </div>
    </div>`;
  }).filter(Boolean).join('');
}

// Collab table operations
async function collabInsertTable() {
  if (!S.activeCollabNote) return;
  // Use inline form in the editor wrap
  const wrap = $('collab-editor-wrap'); if (!wrap) return;
  let existing = $('collab-tbl-create-form'); if (existing) { existing.remove(); return; }
  const form = el('div', 'inline-form-wrap'); form.id = 'collab-tbl-create-form'; form.style.marginTop = '12px';
  form.innerHTML = `<div class="inline-form">
    <div class="inline-form-title">Insert Table</div>
    <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:10px">
      <div class="form-group"><label class="form-label">Name</label><input id="ctbl-name" class="form-input" placeholder="e.g. Data"></div>
      <div class="form-group"><label class="form-label">Columns</label><input id="ctbl-cols" class="form-input" type="number" min="1" max="10" value="3"></div>
      <div class="form-group"><label class="form-label">Rows</label><input id="ctbl-rows" class="form-input" type="number" min="1" max="20" value="3"></div>
    </div>
    <div class="modal-foot">
      <button class="btn btn-ghost btn-sm" onclick="document.getElementById('collab-tbl-create-form')?.remove()">Cancel</button>
      <button class="btn btn-action btn-sm" onclick="collabSubmitTable('${S.activeCollabNote}')">${icons.table} Insert</button>
    </div>
  </div>`;
  wrap.appendChild(form);
  setTimeout(() => $('ctbl-name')?.focus(), 50);
}

async function collabSubmitTable(noteId) {
  const name = $('ctbl-name')?.value.trim() || 'Table';
  const cols = parseInt($('ctbl-cols')?.value) || 3, rows = parseInt($('ctbl-rows')?.value) || 3;
  const id = uid();
  const tbl = { id, name, headers: Array.from({ length: cols }, (_, i) => `Column ${i + 1}`), rows: Array.from({ length: rows }, () => Array(cols).fill('')) };
  try {
    await window.fb.update(window.fb.ref(window.fb.database, `collab/${noteId}/tables`), { [id]: tbl });
    $('collab-tbl-create-form')?.remove();
  } catch (e) { toast('Error: ' + e.message); }
}

async function collabUpdateCell(tblId, noteId, ri, ci, val) {
  try {
    const snap = await window.fb.get(window.fb.ref(window.fb.database, `collab/${noteId}/tables/${tblId}`));
    if (!snap.exists()) return;
    const tbl = snap.val(); tbl.rows[ri][ci] = val;
    await window.fb.update(window.fb.ref(window.fb.database, `collab/${noteId}/tables`), { [tblId]: tbl });
  } catch (e) { }
}

async function collabAddRow(tblId, noteId) {
  const snap = await window.fb.get(window.fb.ref(window.fb.database, `collab/${noteId}/tables/${tblId}`));
  if (!snap.exists()) return;
  const tbl = snap.val(); tbl.rows.push(Array((tbl.headers || []).length).fill(''));
  await window.fb.update(window.fb.ref(window.fb.database, `collab/${noteId}/tables`), { [tblId]: tbl });
}

async function collabDelRow(tblId, noteId, ri) {
  const snap = await window.fb.get(window.fb.ref(window.fb.database, `collab/${noteId}/tables/${tblId}`));
  if (!snap.exists()) return;
  const tbl = snap.val(); tbl.rows.splice(ri, 1);
  await window.fb.update(window.fb.ref(window.fb.database, `collab/${noteId}/tables`), { [tblId]: tbl });
}

async function collabAddCol(tblId, noteId) {
  const snap = await window.fb.get(window.fb.ref(window.fb.database, `collab/${noteId}/tables/${tblId}`));
  if (!snap.exists()) return;
  const tbl = snap.val(); tbl.headers.push(`Column ${tbl.headers.length + 1}`);
  tbl.rows.forEach(r => r.push(''));
  await window.fb.update(window.fb.ref(window.fb.database, `collab/${noteId}/tables`), { [tblId]: tbl });
}

async function collabDeleteTable(tblId, noteId) {
  try { await window.fb.remove(window.fb.ref(window.fb.database, `collab/${noteId}/tables/${tblId}`)); }
  catch (e) { toast('Error: ' + e.message); }
}

// Collab images
function collabInsertImage() {
  if (!S.activeCollabNote) return;
  const wrap = $('collab-editor-wrap'); if (!wrap) return;
  let existing = $('collab-img-form'); if (existing) { existing.remove(); return; }
  const form = el('div', 'inline-form-wrap'); form.id = 'collab-img-form'; form.style.marginTop = '12px';
  form.innerHTML = `<div class="inline-form">
    <div class="inline-form-title">Add Image</div>
    <div class="form-group"><label class="form-label">Upload Image File</label>
      <label class="btn btn-secondary btn-sm" style="cursor:pointer;display:inline-flex;align-items:center;gap:6px">${icons.uploadIcon} Choose file
        <input id="cimg-file" type="file" accept="image/*" style="display:none" onchange="collabHandleImageFile(this,'${S.activeCollabNote}')">
      </label>
      <div id="cimg-file-status" style="font-size:12px;color:var(--text-muted);margin-top:4px"></div>
    </div>
    <div class="collab-img-or"><span>or</span></div>
    <div class="form-group"><label class="form-label">Image URL</label>
      <input id="cimg-url" class="form-input" placeholder="https://…"></div>
    <div class="form-group"><label class="form-label">Caption <span style="color:var(--text-faint)">(optional)</span></label>
      <input id="cimg-cap" class="form-input" placeholder="Image caption"></div>
    <div class="modal-foot">
      <button class="btn btn-ghost btn-sm" onclick="document.getElementById('collab-img-form')?.remove()">Cancel</button>
      <button class="btn btn-action btn-sm" onclick="collabSubmitImage('${S.activeCollabNote}')">${icons.image} Add</button>
    </div>
  </div>`;
  wrap.appendChild(form);
  setTimeout(() => $('cimg-url')?.focus(), 50);
}

async function collabHandleImageFile(input, noteId) {
  const file = input.files[0]; if (!file) return;
  if (!file.type.startsWith('image/')) return toast('Please select an image file');
  if (file.size > 5 * 1024 * 1024) return toast('Image too large (max 5MB)');
  const status = $('cimg-file-status'); if (status) status.textContent = 'Reading image…';
  const reader = new FileReader();
  reader.onload = async e => {
    const dataUrl = e.target.result;
    const safe = sanitizeUrl(dataUrl); if (!safe) { toast('Invalid image'); return; }
    const cap = $('cimg-cap')?.value.trim() || '';
    try {
      const snap = await window.fb.get(window.fb.ref(window.fb.database, `collab/${noteId}/images`));
      const images = snap.exists() ? (snap.val() || []) : [];
      images.push({ url: safe, caption: cap, addedBy: getDisplayName(), addedAt: new Date().toISOString() });
      await window.fb.update(window.fb.ref(window.fb.database, `collab/${noteId}`), { images });
      $('collab-img-form')?.remove(); toast('Image added!');
    } catch (e2) { toast('Error: ' + e2.message); }
  };
  reader.onerror = () => toast('Failed to read image');
  reader.readAsDataURL(file);
}

async function collabSubmitImage(noteId) {
  const url = $('cimg-url')?.value.trim(); if (!url) return toast('Enter an image URL');
  const safe = sanitizeUrl(url); if (!safe) return toast('Invalid URL — use https:// only');
  const caption = $('cimg-cap')?.value.trim() || '';
  try {
    const snap = await window.fb.get(window.fb.ref(window.fb.database, `collab/${noteId}/images`));
    const images = snap.exists() ? (snap.val() || []) : [];
    images.push({ url: safe, caption, addedBy: getDisplayName(), addedAt: new Date().toISOString() });
    await window.fb.update(window.fb.ref(window.fb.database, `collab/${noteId}`), { images });
    $('collab-img-form')?.remove();
  } catch (e) { toast('Error: ' + e.message); }
}

async function collabDeleteImage(idx, noteId) {
  try {
    const snap = await window.fb.get(window.fb.ref(window.fb.database, `collab/${noteId}/images`));
    const images = snap.exists() ? (snap.val() || []) : [];
    images.splice(idx, 1);
    await window.fb.update(window.fb.ref(window.fb.database, `collab/${noteId}`), { images });
  } catch (e) { toast('Error: ' + e.message); }
}

// ─── STUDY GROUPS ─────────────────────────────────────────────
function renderStudyGroups(c) {
  // Don't blow away the form mid-join — just refresh the list silently
  if (_joiningGroup) { renderGroupList(); return; }

  c.innerHTML = `
    <h1 class="page-title-el" style="font-size:36px;margin-bottom:8px">Study Groups</h1>
    <p style="color:var(--text-muted);font-size:14px;margin-bottom:20px">Collaborate with others and share notes within your group</p>
    <div style="display:flex;gap:10px;flex-wrap:wrap;margin-bottom:20px">
      <button class="btn btn-action btn-sm" onclick="toggleGroupForm()">${icons.plus} New Group</button>
      <button class="btn btn-secondary btn-sm" onclick="toggleJoinCodeForm()">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M15 3h4a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-4"/><polyline points="10 17 15 12 10 7"/><line x1="15" y1="12" x2="3" y2="12"/></svg>
        Join by Code
      </button>
    </div>

    <div id="join-code-form-wrap" class="inline-form-wrap" style="display:none;margin-bottom:16px">
      <div class="inline-form">
        <div class="inline-form-title">Join a Study Group</div>
        <div class="form-group"><label class="form-label">6-Digit Group Code</label>
          <input id="join-code-inp" class="form-input" placeholder="e.g. 847291" maxlength="6" inputmode="numeric" style="letter-spacing:0.25em;font-size:18px;font-weight:700;text-align:center"></div>
        <div class="modal-foot">
          <button class="btn btn-ghost btn-sm" onclick="toggleJoinCodeForm()">Cancel</button>
          <button id="join-group-btn" class="btn btn-action btn-sm" onclick="joinGroupByCode()">
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M15 3h4a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-4"/><polyline points="10 17 15 12 10 7"/><line x1="15" y1="12" x2="3" y2="12"/></svg>
            Join Group
          </button>
        </div>
      </div>
    </div>

    <div id="group-form-wrap" class="inline-form-wrap" style="display:none;margin-bottom:24px">
      <div class="inline-form">
        <div class="inline-form-title">Create Study Group</div>
        <div class="form-group"><label class="form-label">Group Name</label>
          <input id="grp-name-inp" class="form-input" placeholder="e.g. CS101 Study Group"></div>
        <div class="form-group"><label class="form-label">Description</label>
          <input id="grp-desc-inp" class="form-input" placeholder="What is this group about?"></div>
        <div class="modal-foot">
          <button class="btn btn-ghost btn-sm" onclick="toggleGroupForm()">Cancel</button>
          <button class="btn btn-action btn-sm" onclick="submitCreateGroup()">${icons.plus} Create</button>
        </div>
      </div>
    </div>

    <div id="group-list" class="collab-grid"></div>`;

  // cloneNode removes any previously stacked listeners before adding the new one
  const inp = $('grp-name-inp'); if (inp) { inp.replaceWith(inp.cloneNode(true)); $('grp-name-inp').addEventListener('keydown', e => { if (e.key === 'Enter') submitCreateGroup(); }); }
  const joinInp = $('join-code-inp'); if (joinInp) { joinInp.replaceWith(joinInp.cloneNode(true)); $('join-code-inp').addEventListener('keydown', e => { if (e.key === 'Enter') joinGroupByCode(); }); }
  renderGroupList();
}

function toggleGroupForm() {
  const w = $('group-form-wrap'); if (!w) return;
  const vis = w.style.display === 'block'; w.style.display = vis ? 'none' : 'block';
  // Close join code form if opening create form
  if (!vis) { const j = $('join-code-form-wrap'); if (j) j.style.display = 'none'; }
  if (!vis) setTimeout(() => $('grp-name-inp')?.focus(), 50);
}

function toggleJoinCodeForm() {
  const w = $('join-code-form-wrap'); if (!w) return;
  const vis = w.style.display === 'block'; w.style.display = vis ? 'none' : 'block';
  // Close create form if opening join form
  if (!vis) { const g = $('group-form-wrap'); if (g) g.style.display = 'none'; }
  if (!vis) setTimeout(() => $('join-code-inp')?.focus(), 50);
}

let _joiningGroup = false;
async function joinGroupByCode() {
  if (_joiningGroup) return;
  const code = $('join-code-inp')?.value.trim();
  if (!code || code.length !== 6 || !/^\d+$/.test(code)) return toast('Enter a valid 6-digit code');
  _joiningGroup = true;
  // Physically disable the button and input so no re-clicks or stacked Enter presses
  const btn = $('join-group-btn');
  const inp = $('join-code-inp');
  if (btn) { btn.disabled = true; btn.textContent = 'Joining…'; }
  if (inp) inp.disabled = true;
  try {
    const lookupSnap = await window.fb.get(window.fb.ref(window.fb.database, `groupJoinIndex/${code}`));
    if (!lookupSnap.exists()) { toast('No group found with code ' + code); return; }
    const lookup = lookupSnap.val() || {};
    const groupId = lookup.groupId || '';
    if (!groupId) { toast('That join code is no longer valid'); return; }
    const existing = S.studyGroups.find(g => g.id === groupId);
    if (existing && isGroupMember(existing, S.user.uid)) {
      toast('You are already in ' + existing.name);
      toggleJoinCodeForm();
      return;
    }
    const newMember = { uid: S.user.uid, name: getDisplayName(), email: S.user.email, joinedAt: new Date().toISOString() };
    await window.fb.set(window.fb.ref(window.fb.database, `studyGroups/${groupId}/members/${S.user.uid}`), newMember);
    await window.fb.update(window.fb.ref(window.fb.database, `users/${S.user.uid}/groups`), { [groupId]: true });
    const groupSnap = await window.fb.get(window.fb.ref(window.fb.database, `studyGroups/${groupId}`));
    if (!groupSnap.exists()) throw new Error('Group not found after joining');
    const found = { ...groupSnap.val(), id: groupId };
    const existingIdx = S.studyGroups.findIndex(g => g.id === groupId);
    if (existingIdx >= 0) S.studyGroups[existingIdx] = found;
    else S.studyGroups.push(found);
    toast('Joined ' + found.name + '!');
    toggleJoinCodeForm();
    renderGroupList();
  } catch (e) {
    toast('Error joining group: ' + e.message);
    // Re-enable on error so they can retry
    if (btn) { btn.disabled = false; btn.innerHTML = `<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M15 3h4a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-4"/><polyline points="10 17 15 12 10 7"/><line x1="15" y1="12" x2="3" y2="12"/></svg> Join Group`; }
    if (inp) inp.disabled = false;
  } finally {
    _joiningGroup = false;
  }
}

async function submitCreateGroup() {
  const name = $('grp-name-inp')?.value.trim(); if (!name) return toast('Enter a group name');
  const description = $('grp-desc-inp')?.value.trim() || '';
  const id = uid();
  // Generate unique 6-digit join code
  const joinCode = String(Math.floor(100000 + Math.random() * 900000));
  const group = {
    id, name, description, joinCode, createdBy: S.user.uid, createdByName: getDisplayName(),
    members: { [S.user.uid]: { uid: S.user.uid, name: getDisplayName(), email: S.user.email, joinedAt: new Date().toISOString() } },
    createdAt: new Date().toISOString()
  };
  try {
    await window.fb.set(window.fb.ref(window.fb.database, `studyGroups/${id}`), group);
    await window.fb.set(window.fb.ref(window.fb.database, `groupJoinIndex/${joinCode}`), {
      groupId: id,
      name,
      description,
      createdBy: S.user.uid,
      createdAt: group.createdAt
    });
    // Add to user's groups
    await window.fb.update(window.fb.ref(window.fb.database, `users/${S.user.uid}/groups`), { [id]: true });
    S.studyGroups.push(group);
    toast('Group created!'); toggleGroupForm(); renderGroupList();
  } catch (e) { toast('Error: ' + e.message); }
}

function renderGroupList() {
  const list = $('group-list'); if (!list) return;
  if (!S.studyGroups.length) {
    list.innerHTML = `<div class="empty" style="grid-column:1/-1"><div class="empty-icon">${icons.group}</div><div class="empty-title">No groups yet</div><p class="empty-sub">Create a group or ask someone to add you</p></div>`;
    return;
  }
  const myGroups     = S.studyGroups.filter(g => g.createdBy === S.user?.uid);
  const joinedGroups = S.studyGroups.filter(g => g.createdBy !== S.user?.uid);
  function groupCard(g, isOwner) {
    const mc = groupMemberCount(g);
    const badge = isOwner
      ? `<span style="display:inline-flex;align-items:center;font-size:10px;font-weight:700;letter-spacing:.04em;text-transform:uppercase;background:var(--accent);color:#fff;padding:2px 7px;border-radius:99px">Owner</span>`
      : `<span style="display:inline-flex;align-items:center;font-size:10px;font-weight:700;letter-spacing:.04em;text-transform:uppercase;background:var(--bg-card-hover,rgba(0,0,0,.08));color:var(--text-muted);padding:2px 7px;border-radius:99px">Member</span>`;
    return `<div class="collab-card" onclick="openStudyGroup('${g.id}')">
      <div style="display:flex;align-items:flex-start;justify-content:space-between;gap:8px;margin-bottom:6px">
        <div class="collab-card-icon" style="margin-bottom:0">${icons.group}</div>${badge}
      </div>
      <div class="collab-card-title">${esc(g.name)}</div>
      ${g.description ? `<div class="collab-card-meta">${esc(g.description)}</div>` : ''}
      <div class="collab-card-meta">Created by ${esc(g.createdByName) || 'Someone'} · ${mc} member${mc !== 1 ? 's' : ''}</div>
      <div class="collab-card-foot"><span class="collab-card-users">${icons.profile} Open group</span></div>
    </div>`;
  }
  let html = '';
  if (myGroups.length) {
    html += `<div style="grid-column:1/-1;margin-bottom:4px"><span style="font-size:11px;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:var(--text-muted)">My Groups</span></div>`;
    html += myGroups.map(g => groupCard(g, true)).join('');
  }
  if (joinedGroups.length) {
    html += `<div style="grid-column:1/-1;margin-bottom:4px;${myGroups.length ? 'margin-top:20px' : ''}"><span style="font-size:11px;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:var(--text-muted)">Joined Groups</span></div>`;
    html += joinedGroups.map(g => groupCard(g, false)).join('');
  }
  list.innerHTML = html;
}

async function openStudyGroup(groupId, options = {}) {
  const { pushHistory = true, replaceHistory = false } = options;
  S.view = 'studyGroup'; S._currentGroupId = groupId;
  // Always fetch fresh group data so member list is current
  try {
    const snap = await window.fb.get(window.fb.ref(window.fb.database, `studyGroups/${groupId}`));
    if (snap.exists()) {
      const fresh = { ...snap.val(), id: groupId };
      const idx = S.studyGroups.findIndex(g => g.id === groupId);
      if (idx >= 0) S.studyGroups[idx] = fresh; else S.studyGroups.push(fresh);
    }
  } catch (e) { console.warn('Could not refresh group:', e); }
  closeSidebarAfterNavigate();
  syncRouteWithState({ push: pushHistory, replace: replaceHistory });
  renderApp();
}

function renderStudyGroupDetail(c) {
  const group = S.studyGroups.find(g => g.id === S._currentGroupId);
  if (!group) { c.innerHTML = '<div class="empty">Group not found</div>'; return; }
  const members = getGroupMembers(group);
  const isOwner = group.createdBy === S.user?.uid;
  const activeTab = S._groupDetailTab || 'notes';

  c.innerHTML = `
    <div style="display:flex;align-items:center;gap:10px;margin-bottom:20px;flex-wrap:wrap">
      <button class="icon-btn" onclick="navigate('groups')">${icons.back}</button>
      <h1 style="font-size:28px;font-weight:700;flex:1">${esc(group.name)}</h1>
      ${group.joinCode ? `<div style="display:flex;align-items:center;gap:6px;background:var(--bg-sidebar);border:1px solid var(--border);border-radius:var(--r-md);padding:6px 12px">
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
        <span style="font-size:11px;color:var(--text-muted);font-weight:600">Join Code</span>
        <span style="font-size:15px;font-weight:800;letter-spacing:0.2em;color:var(--accent)">${esc(group.joinCode)}</span>
        <button class="btn btn-ghost btn-sm" style="padding:2px 6px;font-size:11px" onclick="navigator.clipboard?.writeText('${esc(group.joinCode)}').then(()=>toast('Code copied!'))">Copy</button>
      </div>` : ''}
      ${isOwner ? `<button class="btn btn-danger btn-sm" onclick="deleteStudyGroup('${group.id}')">${icons.trash} Delete</button>` : `<button class="btn btn-secondary btn-sm" onclick="leaveStudyGroup('${group.id}')"><svg width='13' height='13' viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'><path d='M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4'/><polyline points='16 17 21 12 16 7'/><line x1='21' y1='12' x2='9' y2='12'/></svg> Leave Group</button>`}
    </div>
    ${group.description ? `<p style="color:var(--text-muted);font-size:14px;margin-bottom:20px">${esc(group.description)}</p>` : ''}

    <div class="study-group-tabs" style="display:inline-flex;gap:6px;background:var(--bg-sidebar);padding:6px;border:1px solid var(--border);border-radius:999px;margin-bottom:20px">
      <button class="group-add-tab group-detail-tab${activeTab==='notes'?' group-add-tab-active':''}" onclick="S._groupDetailTab='notes';renderContent()">
        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="vertical-align:-2px;margin-right:5px"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>Notes
      </button>
      <button class="group-add-tab group-detail-tab${activeTab==='chat'?' group-add-tab-active':''}" onclick="S._groupDetailTab='chat';renderContent()">
        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="vertical-align:-2px;margin-right:5px"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/></svg>Chat
      </button>
      <button class="group-add-tab group-detail-tab${activeTab==='members'?' group-add-tab-active':''}" onclick="S._groupDetailTab='members';renderContent()">
        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="vertical-align:-2px;margin-right:5px"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg>Members (${members.length})
      </button>
    </div>

    <div id="group-detail-content"></div>`;

  const contentEl = document.getElementById('group-detail-content');
  if (activeTab === 'notes') {
    contentEl.innerHTML = `<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:14px;flex-wrap:wrap;gap:8px"><div style="font-size:13.5px;font-weight:600;color:var(--text-muted)">Collab notes shared with this group</div><button class="btn btn-action btn-sm" onclick="createCollabNoteForGroup('${group.id}','${group.name.replace(/'/g, '\\')}')">${icons.plus} New Note</button></div><div id="group-notes-list"><div style="color:var(--text-muted);font-size:13.5px;padding:12px 0">Loading…</div></div>`;
    loadGroupNotes(group.id);
  } else if (activeTab === 'chat') {
    renderGroupChatTab(contentEl, group);
  } else if (activeTab === 'members') {
    renderGroupMembersTab(contentEl, group, members, isOwner);
  }
}

function renderGroupMembersTab(el, group, members, isOwner) {
  el.innerHTML = `
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:20px;align-items:start">
      <div>
        <div class="profile-section">
          <div class="profile-section-title">Members (${members.length})</div>
          <div style="display:flex;flex-direction:column;gap:7px">
            ${members.map(m => `
              <div style="display:flex;align-items:center;gap:9px;padding:6px;border-radius:var(--r-md)">
                <div style="width:28px;height:28px;border-radius:var(--r);background:var(--accent);color:#fff;display:flex;align-items:center;justify-content:center;font-size:12px;font-weight:700;flex-shrink:0">${(m.name || m.email || '?')[0].toUpperCase()}</div>
                <div>
                  <div style="font-size:13.5px;font-weight:600">${esc(m.name) || 'Unknown'}</div>
                  <div style="font-size:11.5px;color:var(--text-muted)">${esc(m.email)}</div>
                </div>
                ${isOwner && m.uid !== S.user?.uid ? `<button class="icon-btn" onclick="removeMemberFromGroup('${group.id}','${m.uid}')" style="margin-left:auto;color:var(--red);width:24px;height:24px">${icons.trash}</button>` : ''}
              </div>`).join('')}
          </div>
        </div>

        ${isOwner ? `
        <div class="profile-section" style="margin-top:16px">
          <div class="profile-section-title">Invite Others</div>
          <div style="font-size:13px;color:var(--text-muted);margin-bottom:10px">Share the join code above so others can join this group.</div>
          <div style="display:flex;align-items:center;gap:8px;background:var(--bg-sidebar);border:1px solid var(--border);border-radius:var(--r-md);padding:10px 14px">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
            <span style="font-size:16px;font-weight:800;letter-spacing:0.25em;color:var(--accent)">${esc(group.joinCode)}</span>
            <button class="btn btn-ghost btn-sm" style="margin-left:auto;padding:3px 10px;font-size:12px" onclick="navigator.clipboard?.writeText('${esc(group.joinCode)}').then(()=>toast('Join code copied!'))">Copy Code</button>
          </div>
        </div>`: ''}
      </div>
    </div>`;
}

// ─── Group Chat ───────────────────────────────────────────────
let _groupChatListener = null;
function renderGroupChatTab(el, group) {
  el.innerHTML = `
    <div style="display:flex;flex-direction:column;height:520px;border:1px solid var(--border);border-radius:var(--r-md);overflow:hidden;background:var(--bg)">
      <div style="padding:10px 14px;border-bottom:1px solid var(--border);font-size:13px;font-weight:600;color:var(--text-muted);background:var(--bg-sidebar);display:flex;align-items:center;gap:8px">
        <div style="width:8px;height:8px;border-radius:50%;background:var(--green);flex-shrink:0"></div>
        Group Chat — ${esc(group.name)}
        <span style="font-size:11.5px;color:var(--text-faint);margin-left:4px">${groupMemberCount(group)} members</span>
      </div>
      <div id="grp-chat-msgs" style="flex:1;overflow-y:auto;padding:14px;display:flex;flex-direction:column;gap:10px">
        <div style="color:var(--text-faint);font-size:12.5px;text-align:center;padding:20px 0">Loading messages…</div>
      </div>
      <div style="padding:10px 12px;border-top:1px solid var(--border);display:flex;gap:8px;align-items:center;background:var(--bg-sidebar)">
        <input id="grp-chat-inp" class="form-input" placeholder="Message the group…" style="flex:1;border-radius:20px;padding:8px 14px" maxlength="1000">
        <button class="btn btn-action" onclick="sendGroupChatMessage('${group.id}')" style="border-radius:50%;width:36px;height:36px;padding:0;flex-shrink:0;display:flex;align-items:center;justify-content:center">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><line x1="22" y1="2" x2="11" y2="13"/><polygon points="22 2 15 22 11 13 2 9 22 2"/></svg>
        </button>
      </div>
    </div>`;

  const inp = $('grp-chat-inp');
  if (inp) inp.addEventListener('keydown', e => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendGroupChatMessage(group.id); } });

  if (_groupChatListener) { _groupChatListener(); _groupChatListener = null; }
  const chatRef = window.fb.ref(window.fb.database, `studyGroups/${group.id}/chat`);
  _groupChatListener = window.fb.onValue(chatRef, snap => {
    const msgsEl = $('grp-chat-msgs'); if (!msgsEl) return;
    if (!snap.exists()) {
      msgsEl.innerHTML = '<div style="color:var(--text-faint);font-size:12.5px;text-align:center;padding:30px 0">No messages yet. Say hello! 👋</div>';
      return;
    }
    const msgs = [];
    snap.forEach(child => msgs.push({ id: child.key, ...child.val() }));
    msgs.sort((a, b) => (a.createdAt > b.createdAt ? 1 : -1));
    const myUid = S.user?.uid;
    msgsEl.innerHTML = msgs.map(m => {
      const isMe = m.uid === myUid;
      const time = m.createdAt ? new Date(m.createdAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : '';
      return `<div style="display:flex;flex-direction:column;align-items:${isMe ? 'flex-end' : 'flex-start'};gap:2px">
        ${!isMe ? `<div style="font-size:11px;color:var(--text-faint);padding:0 10px;font-weight:600">${esc(m.name || 'Unknown')}</div>` : ''}
        <div style="max-width:75%;background:${isMe ? 'var(--accent)' : 'var(--bg-sidebar)'};color:${isMe ? '#fff' : 'var(--text)'};border-radius:${isMe ? '16px 16px 4px 16px' : '16px 16px 16px 4px'};padding:8px 13px;font-size:13.5px;line-height:1.5;border:${isMe ? 'none' : '1px solid var(--border)'}">
          ${esc(m.content)}
        </div>
        <div style="font-size:10.5px;color:var(--text-faint);padding:0 10px">${time}</div>
      </div>`;
    }).join('');
    msgsEl.scrollTop = msgsEl.scrollHeight;
  }, () => {
    const msgsEl = $('grp-chat-msgs');
    if (msgsEl) msgsEl.innerHTML = '<div style="color:var(--text-faint);font-size:12.5px;text-align:center;padding:20px">Could not load messages.</div>';
  });
}

async function sendGroupChatMessage(groupId) {
  const inp = $('grp-chat-inp'); if (!inp) return;
  const content = inp.value.trim(); if (!content) return;
  inp.value = '';
  const msg = {
    uid: S.user.uid,
    name: getDisplayName(),
    content: validateStr(content, 1000),
    createdAt: new Date().toISOString()
  };
  try {
    await window.fb.push(window.fb.ref(window.fb.database, `studyGroups/${groupId}/chat`), msg);
  } catch (e) { toast('Failed to send: ' + e.message); inp.value = content; }
}

let _groupNotesListener = null;
async function loadGroupNotes(groupId) {
  const list = $('group-notes-list'); if (!list) return;
  const group = S.studyGroups.find(g => g.id === groupId);
  const noteIds = Object.keys(group?.noteIndex || {});
  try {
    const notes = await fetchCollabNotesByIds(noteIds);
    const list2 = $('group-notes-list'); if (!list2) return;
    if (!notes.length) { list2.innerHTML = '<div style="color:var(--text-muted);font-size:13.5px;padding:12px 0">No notes yet. <strong>Create one</strong> with the New Note button above, or link an existing collab note to this group.</div>'; return; }
    list2.innerHTML = '<div style="display:grid;gap:8px">' + notes.map(n => `
      <div style="background:var(--bg-sidebar);border:1px solid var(--border);border-radius:var(--r-md);padding:12px 14px;display:flex;align-items:center;gap:10px;cursor:pointer;transition:border-color .15s" onclick="openCollabNote('${n.id}')" onmouseover="this.style.borderColor='var(--accent)'" onmouseout="this.style.borderColor='var(--border)'">
        <div style="width:32px;height:32px;border-radius:var(--r);background:var(--accent-bg);color:var(--accent);display:flex;align-items:center;justify-content:center;flex-shrink:0">${icons.collab}</div>
        <div style="flex:1;min-width:0">
          <div style="font-size:13.5px;font-weight:600;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">${esc(n.title) || 'Untitled'}</div>
          <div style="font-size:11.5px;color:var(--text-muted)">Updated ${fmt(n.updatedAt || n.createdAt)}</div>
        </div>
        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" style="flex-shrink:0;color:var(--text-faint)"><polyline points="9 18 15 12 9 6"/></svg>
      </div>`).join('') + '</div>';
  } catch (err) {
    const list2 = $('group-notes-list'); if (list2) list2.innerHTML = `<div style="color:var(--text-muted);font-size:13.5px">Error: ${esc(err.message)}</div>`;
  }
}

let _searchDebounce = null;
async function searchUsers(query, groupId) {
  const res = $('user-search-results'); if (!res) return;
  if (!query || query.length < 2) { res.innerHTML = '<div style="color:var(--text-faint);font-size:12.5px;padding:4px 0">Type at least 2 characters…</div>'; return; }
  clearTimeout(_searchDebounce);
  res.innerHTML = '<div style="color:var(--text-muted);font-size:13px;padding:4px">Searching...</div>';
  _searchDebounce = setTimeout(async () => {
    try {
      // Re-fetch group from Firebase to get latest member list
      const groupSnap = await window.fb.get(window.fb.ref(window.fb.database, 'studyGroups/' + groupId));
      const freshGroup = groupSnap.exists() ? groupSnap.val() : S.studyGroups.find(g => g.id === groupId);
      const memberUids = getGroupMembers(freshGroup).map(m => m.uid);

      // Try userIndex first; if Firebase rules block it, fall back gracefully
      let allUsers = [];
      try {
        const snap = await window.fb.get(window.fb.ref(window.fb.database, 'userIndex'));
        if (snap.exists()) allUsers = Object.values(snap.val()).filter(u => u && u.uid);
      } catch (permErr) {
        // Directory lookup is intentionally restricted — gather known members from local groups
        for (const g of S.studyGroups) {
          for (const m of getGroupMembers(g)) {
            if (!allUsers.find(u => u.uid === m.uid)) allUsers.push({ uid: m.uid, name: m.name, email: m.email });
          }
        }
        if (!allUsers.length) {
          res.innerHTML = '<div style="color:var(--orange);font-size:12.5px;padding:6px 4px;line-height:1.5">'
            + '<b>Search unavailable:</b> Global user directory lookup is disabled for privacy. '
            + 'Search currently works only for people already visible in your shared groups.</div>';
          return;
        }
      }
      const q = query.toLowerCase().trim();
      const results = allUsers.filter(u =>
        u.uid !== S.user?.uid &&
        !memberUids.includes(u.uid) &&
        ((u.name || '').toLowerCase().includes(q) || (u.email || '').toLowerCase().includes(q))
      ).slice(0, 10);
      if (!results.length) {
        res.innerHTML = '<div style="color:var(--text-muted);font-size:13px;padding:6px 4px">No users found matching <b>' + esc(query) + '</b>.</div>';
        return;
      }
      res.innerHTML = results.map(function (u) {
        const safeUid = (u.uid || '').replace(/\\/g, '\\\\').replace(/'/g, "\\'");
        const safeName = (u.name || '').replace(/\\/g, '\\\\').replace(/'/g, "\\'");
        const safeEmail = (u.email || '').replace(/\\/g, '\\\\').replace(/'/g, "\\'");
        return '<div class="user-search-result">'
          + '<div class="user-sr-av">' + (u.name || u.email || '?')[0].toUpperCase() + '</div>'
          + '<div class="user-sr-info">'
          + '<div class="user-sr-name">' + esc(u.name || 'Unknown') + '</div>'
          + '<div class="user-sr-email">' + esc(u.email || '') + '</div>'
          + '</div>'
          + '<button class="btn btn-action btn-sm" onclick="addMemberToGroup(\'' + groupId + '\',\'' + safeUid + '\',\'' + safeName + '\',\'' + safeEmail + '\')">' + icons.plus + ' Invite</button>'
          + '</div>';
      }).join('');
    } catch (e) {
      console.error('searchUsers error:', e);
      res.innerHTML = '<div style="color:var(--red);font-size:13px;padding:4px">Search error: ' + esc(e.message || String(e)) + '</div>';
    }
  }, 300);
}
async function addMemberToGroup(groupId, memberUid, memberName, memberEmail) {
  const group = S.studyGroups.find(g => g.id === groupId); if (!group) return;
  if (isGroupMember(group, memberUid)) { toast('Already a member'); return; }
  if (memberUid === S.user?.uid) {
    const selfMember = { uid: S.user.uid, name: getDisplayName(), email: S.user.email, joinedAt: new Date().toISOString() };
    await window.fb.set(window.fb.ref(window.fb.database, `studyGroups/${groupId}/members/${S.user.uid}`), selfMember);
    await window.fb.update(window.fb.ref(window.fb.database, `users/${S.user.uid}/groups`), { [groupId]: true });
    group.members = { ...(group.members || {}), [S.user.uid]: selfMember };
    toast('Joined group');
    renderContent();
    return;
  }
  try {
    // With current rules, users can only add themselves to their own /users/{uid}/groups.
    // So this action sends an invite notification instead of force-adding membership.
    if (group.createdBy !== S.user.uid) throw new Error('Only the group creator can send invites');
    const nid = uid();
    const notif = { id: nid, type: 'groupInvite', groupId, groupName: group.name, from: S.user.uid, fromName: getDisplayName(), to: memberUid, createdAt: new Date().toISOString(), read: false, dismissed: false };
    await window.fb.update(window.fb.ref(window.fb.database, `notifications/${memberUid}`), { [nid]: notif }).catch(() => { });
    toast(`Invite sent to ${memberName || memberEmail || 'user'}`);
    renderContent();
  } catch (e) { toast('Error: ' + e.message); }
}

async function removeMemberFromGroup(groupId, memberUid) {
  const group = S.studyGroups.find(g => g.id === groupId); if (!group) return;
  const nextMembers = { ...(group.members || {}) };
  delete nextMembers[memberUid];
  try {
    await window.fb.remove(window.fb.ref(window.fb.database, `studyGroups/${groupId}/members/${memberUid}`));
    group.members = nextMembers;
    toast('Member removed'); renderContent();
  } catch (e) { toast('Error: ' + e.message); }
}

function switchGroupAddTab(tab, groupId) {
  const searchTab = document.getElementById('gadd-tab-search');
  const emailTab = document.getElementById('gadd-tab-email');
  const searchPanel = document.getElementById('gadd-panel-search');
  const emailPanel = document.getElementById('gadd-panel-email');
  // Deactivate all
  [searchTab, emailTab].forEach(t => t?.classList.remove('group-add-tab-active'));
  [searchPanel, emailPanel].forEach(p => { if (p) p.style.display = 'none'; });
  if (tab === 'search') {
    searchTab?.classList.add('group-add-tab-active');
    if (searchPanel) searchPanel.style.display = '';
    setTimeout(() => document.getElementById('user-search-inp')?.focus(), 50);
  } else {
    emailTab?.classList.add('group-add-tab-active');
    if (emailPanel) emailPanel.style.display = '';
    setTimeout(() => document.getElementById('grp-invite-email')?.focus(), 50);
  }
}

async function inviteByEmail(groupId, groupName) {
  const emailInp = document.getElementById('grp-invite-email');
  const status = document.getElementById('grp-invite-status');
  const email = (emailInp?.value || '').trim().toLowerCase();
  if (!email || !email.includes('@')) return toast('Enter a valid email address');
  if (status) { status.textContent = 'Searching…'; status.style.color = 'var(--text-muted)'; }
  try {
    if (status) {
      status.textContent = 'Email lookup is disabled for privacy. Share the group join code instead.';
      status.style.color = 'var(--orange)';
    }
  } catch (e) {
    if (status) { status.textContent = 'Error: ' + e.message; status.style.color = 'var(--red)'; }
  }
}

async function leaveStudyGroup(groupId) {
  if (!confirm('Leave this group? You can rejoin with the join code.')) return;
  try {
    await window.fb.remove(window.fb.ref(window.fb.database, `studyGroups/${groupId}/members/${S.user.uid}`));
    await window.fb.remove(window.fb.ref(window.fb.database, `users/${S.user.uid}/groups/${groupId}`));
    S.studyGroups = S.studyGroups.filter(g => g.id !== groupId);
    toast('You have left the group.');
    navigate('groups');
  } catch (e) { toast('Error leaving group: ' + e.message); }
}


async function deleteStudyGroup(groupId) {
  const group = S.studyGroups.find(g => g.id === groupId); if (!group) return;
  const banner = el('div', 'delete-confirm-banner');
  banner.innerHTML = `<span>Delete "${esc(group.name)}"? All members will lose access.</span>
    <button class="btn btn-danger btn-sm" onclick="confirmDeleteGroup('${groupId}')">Delete</button>
    <button class="btn btn-ghost btn-sm" onclick="this.closest('.delete-confirm-banner').remove()">Cancel</button>`;
  const c = $('main-content'); if (c) c.prepend(banner);
}

async function confirmDeleteGroup(groupId) {
  const group = S.studyGroups.find(g => g.id === groupId); if (!group) return;
  try {
    if (group.joinCode) {
      await window.fb.remove(window.fb.ref(window.fb.database, `groupJoinIndex/${group.joinCode}`)).catch(() => {});
    }
    await window.fb.remove(window.fb.ref(window.fb.database, `studyGroups/${groupId}`));
    // Remove from all members
    for (const m of getGroupMembers(group)) await window.fb.remove(window.fb.ref(window.fb.database, `users/${m.uid}/groups/${groupId}`)).catch(() => { });
    S.studyGroups = S.studyGroups.filter(g => g.id !== groupId);
    toast('Group deleted'); navigate('groups');
  } catch (e) { toast('Error: ' + e.message); }
}

// ─── SEARCH ───────────────────────────────────────────────────
let _searchTab = 'mine', _peopleTimer = null;

function buildSearchOverlay() {
  if ($('search-ov')) return;
  const ov = el('div', 'search-ov'); ov.id = 'search-ov';
  ov.innerHTML = `
    <div class="search-box">
      <div class="search-top">${icons.search}<input id="search-inp" placeholder="Search…" autocomplete="off"/><button class="icon-btn" onclick="closeSearch()">${icons.close}</button></div>
      <div class="search-tab-row">
        <button class="s-tab s-tab-active" id="stab-mine" onclick="setSearchTab('mine')">My Content</button>
        <button class="s-tab" id="stab-people" onclick="setSearchTab('people')">People</button>
      </div>
      <div class="search-results" id="search-results"></div>
    </div>`;
  ov.addEventListener('click', e => { if (e.target === ov) closeSearch(); });
  document.body.appendChild(ov);
  $('search-inp').addEventListener('input', e => doSearch(e.target.value));
}

function setSearchTab(tab) {
  _searchTab = tab;
  $('stab-mine')?.classList.toggle('s-tab-active', tab === 'mine');
  $('stab-people')?.classList.toggle('s-tab-active', tab === 'people');
  doSearch($('search-inp')?.value || '');
}

function openSearch() {
  buildSearchOverlay();
  const ov = $('search-ov'); ov.classList.add('show');
  _searchTab = 'mine';
  $('stab-mine')?.classList.add('s-tab-active');
  $('stab-people')?.classList.remove('s-tab-active');
  const inp = $('search-inp'); if (inp) { inp.value = ''; inp.focus(); }
  doSearch('');
}
function closeSearch() { $('search-ov')?.classList.remove('show'); }

function doSearch(q) {
  if (_searchTab === 'people') { searchPeople(q); return; }
  const res = $('search-results'); if (!res) return;
  const lq = q.toLowerCase();
  // Build searchable items — pages include content
  const all = [
    ...S.pages.map(p => {
      const contentSnippet = (p.blocks || []).map(b => (b.content || '').replace(/<[^>]+>/g, '')).join(' ').substring(0, 200);
      return { t: 'page', icon: icons.file, lbl: p.title || 'Untitled', sub: contentSnippet, id: p.id };
    }),
    ...S.databases.map(d => ({ t: 'db', icon: icons.db, lbl: d.title || 'Untitled DB', sub: '', id: d.id })),
    ...S.tasks.map(t => ({ t: 'task', icon: icons.check, lbl: t.title, sub: t.due || '', id: t.id })),
    ...S.flashcards.map(d => ({ t: 'deck', icon: icons.flash, lbl: d.title, sub: '', id: d.id })),
    ...S.projects.map(p => ({ t: 'project', icon: '<span style="width:10px;height:10px;border-radius:3px;background:var(--' + (p.color || 'accent') + ');display:inline-block"></span>', lbl: p.title, sub: (p.noteIds || []).length + ' notes', id: p.id })),
  ];
  // Command palette actions (always shown when no query, or filtered by query)
  const actions = [
    { t: 'action', icon: icons.plus, lbl: 'New Page', sub: '', id: 'new-page' },
    { t: 'action', icon: icons.plus, lbl: 'New Project', sub: '', id: 'new-project' },
    { t: 'action', icon: icons.timer, lbl: 'Toggle Focus Timer', sub: '', id: 'toggle-pom' },
    { t: 'action', icon: icons.check, lbl: 'Today\'s Tasks', sub: '', id: 'daily-tasks' },
    { t: 'action', icon: '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>', lbl: 'Settings', sub: '', id: 'settings' },
  ];
  const combined = [...all, ...actions];
  const filtered = lq ? combined.filter(i => i.lbl.toLowerCase().includes(lq) || (i.sub && i.sub.toLowerCase().includes(lq))) : combined.slice(0, 14);
  if (!filtered.length) { res.innerHTML = `<div class="s-empty">No results found</div>`; return; }
  res.innerHTML = filtered.map(item => {
    const matchInContent = lq && item.sub && item.sub.toLowerCase().includes(lq) && !item.lbl.toLowerCase().includes(lq);
    const subtitle = matchInContent ? `<div class="s-sub">…${item.sub.substring(Math.max(0, item.sub.toLowerCase().indexOf(lq) - 20), Math.min(item.sub.length, item.sub.toLowerCase().indexOf(lq) + 40))}…</div>` : '';
    return `<div class="s-item" onclick="searchGo('${esc(item.t)}','${esc(item.id)}')">${item.icon}<div style="flex:1"><span>${esc(item.lbl)}</span>${subtitle}</div><span class="s-type">${esc(item.t)}</span></div>`;
  }).join('');
}

function searchPeople(q) {
  const res = $('search-results'); if (!res) return;
  if (!q || q.length < 2) { res.innerHTML = `<div class="s-empty">Type at least 2 characters to find people</div>`; return; }
  res.innerHTML = `<div class="s-empty">Searching…</div>`;
  clearTimeout(_peopleTimer);
  _peopleTimer = setTimeout(async () => {
    try {
      const lq = q.toLowerCase();
      const pool = [];
      for (const g of (S.studyGroups || [])) {
        for (const member of getGroupMembers(g)) {
          if (member.uid && member.uid !== S.user?.uid && !pool.find(item => item.uid === member.uid)) pool.push(member);
        }
      }
      const all = pool.filter(u => ((u.name || '').toLowerCase().includes(lq) || (u.email || '').toLowerCase().includes(lq))).slice(0, 8);
      if (!all.length) { res.innerHTML = `<div class="s-empty">No people matching "${esc(q)}"</div>`; return; }
      res.innerHTML = all.map(u => {
        const safeName = (u.name || u.email || '').replace(/\\/g, '\\\\').replace(/'/g, "\\'");
        return `<div class="s-person">
          <div class="s-person-av">${(u.name || u.email || '?')[0].toUpperCase()}</div>
          <div class="s-person-info">
            <div class="s-person-name">${esc(u.name || 'Unknown')}</div>
            <div class="s-person-email">${esc(u.email || '')}</div>
          </div>
          <button class="btn btn-action btn-sm s-connect-btn" onclick="quickInviteToGroup('${u.uid}','${safeName}',this)">Invite to Group</button>
        </div>`;
      }).join('');
    } catch (e) {
      console.error('people search error:', e);
      res.innerHTML = `<div class="s-empty">Search failed — people search is limited to members already visible in your shared groups</div>`;
    }
  }, 350);
}

async function quickInviteToGroup(toUid, toName, btn) {
  if (!S.user) return;
  const ownGroups = S.studyGroups.filter(g => g.createdBy === S.user?.uid);
  if (!ownGroups.length) return toast('Create a study group first');
  const group = ownGroups[0];
  if (btn) { btn.disabled = true; btn.textContent = 'Sending…'; }
  try {
    const id = uid();
    const req = { id, type: 'groupInvite', groupId: group.id, groupName: group.name, from: S.user.uid, fromName: getDisplayName(), to: toUid, createdAt: new Date().toISOString(), read: false, dismissed: false };
    await window.fb.update(window.fb.ref(window.fb.database, `notifications/${toUid}`), { [id]: req });
    if (btn) { btn.innerHTML = '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg> Sent'; btn.style.background = 'var(--green)'; }
    toast(`Invite sent to ${toName}`);
  } catch (e) {
    toast('Failed to send — try again');
    if (btn) { btn.disabled = false; btn.textContent = 'Invite to Group'; }
  }
}

function searchGo(type, id) {
  closeSearch();
  if (type === 'page') openPage(id);
  else if (type === 'db') openDatabase(id);
  else if (type === 'task') navigate('tasks');
  else if (type === 'deck') openDeckEditor(id);
  else if (type === 'project') openProject(id);
  else if (type === 'action') {
    if (id === 'new-page') showTemplatePicker();
    else if (id === 'new-project') createProject();
    else if (id === 'toggle-pom') togglePom();
    else if (id === 'daily-tasks') navigate('dailyTasks');
    else if (id === 'settings') navigate('profile');
  }
}

// ─── NOTIFICATIONS ─────────────────────────────────────────────
async function loadNotifications() {
  if (!S.user) return;
  try {
    const snap = await window.fb.get(window.fb.ref(window.fb.database, `notifications/${S.user.uid}`));
    S.notifications = snap.exists() ? Object.values(snap.val()).filter(n => !n.dismissed) : [];
    const badge = $('notif-count');
    if (badge) {
      const unread = S.notifications.filter(n => !n.read).length;
      badge.style.display = unread ? 'flex' : 'none';
      badge.textContent = unread;
    }
  } catch (e) { console.warn('notif load err:', e); }
}

function openNotifications() {
  if ($('notif-panel')) { $('notif-panel').remove(); return; }
  const panel = el('div', 'notif-panel'); panel.id = 'notif-panel';
  const items = (S.notifications || []).filter(n => !n.dismissed);
  const unread = items.filter(n => !n.read).length;
  panel.innerHTML = `
    <div class="notif-hd">
      <span>Notifications${unread ? ` <span style="font-size:11px;font-weight:700;padding:1px 7px;border-radius:20px;background:var(--red);color:#fff;margin-left:6px">${unread}</span>` : ''}</span>
      <button class="icon-btn" onclick="$('notif-panel').remove()" style="width:22px;height:22px">${icons.close}</button>
    </div>
    <div class="notif-body">
      ${items.length ? items.map(n => `
        <div class="notif-item${n.read ? '' : ' notif-new'}" id="ni-${n.id}">
          <div class="notif-icon">${icons.group}</div>
          <div class="notif-text">
            <div class="notif-msg">
              ${n.type === 'groupInvite' ? `<b>${esc(n.fromName)}</b> invited you to join <b>${esc(n.groupName || 'a group')}</b>` :
        esc(n.message || 'Notification')}
            </div>
            <div class="notif-time">${fmt(n.createdAt)}</div>
            ${n.type === 'groupInvite' ? `<div class="notif-actions">
              <button class="btn btn-action btn-sm" onclick="acceptGroupInvite('${n.id}','${n.groupId}')">Accept</button>
              <button class="btn btn-ghost btn-sm" onclick="dismissNotif('${n.id}')">Decline</button>
            </div>`: ''}          </div>
        </div>`).join('') : `<div class="notif-empty">
        <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" style="margin-bottom:8px;color:var(--text-faint)"><path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.73 21a2 2 0 0 1-3.46 0"/></svg>
        <div style="font-weight:600;margin-bottom:4px">All caught up!</div>
        <div style="font-size:12.5px">No new notifications</div>
      </div>`}
    </div>`;
  document.body.appendChild(panel);
  // Mark all read
  (S.notifications || []).forEach(n => { n.read = true; });
  const badge = $('notif-count'); if (badge) badge.style.display = 'none';
  setTimeout(() => {
    function _nc(e) {
      if (!e.target.closest('#notif-panel') && !e.target.closest('#notif-row-btn')) { panel.remove(); document.removeEventListener('click', _nc, true); }
    }
    document.addEventListener('click', _nc, true);
  }, 60);
}
async function dismissNotif(id) {
  document.getElementById('ni-' + id)?.remove();
  S.notifications = (S.notifications || []).map(n => n.id === id ? { ...n, dismissed: true } : n);
  try { await window.fb.update(window.fb.ref(window.fb.database, `notifications/${S.user.uid}/${id}`), { dismissed: true, read: true }); } catch (e) { }
  const remaining = document.querySelectorAll('.notif-item');
  if (!remaining.length) { const b = document.querySelector('.notif-body'); if (b) b.innerHTML = '<div class="notif-empty">No notifications yet</div>'; }
}

async function acceptGroupInvite(notifId, groupId) {
  try {
    const selfMember = { uid: S.user.uid, name: getDisplayName(), email: S.user.email, joinedAt: new Date().toISOString() };
    await window.fb.set(window.fb.ref(window.fb.database, `studyGroups/${groupId}/members/${S.user.uid}`), selfMember);
    await window.fb.update(window.fb.ref(window.fb.database, `users/${S.user.uid}/groups`), { [groupId]: true });
    const snap = await window.fb.get(window.fb.ref(window.fb.database, `studyGroups/${groupId}`));
    if (!snap.exists()) throw new Error('Group no longer exists');
    const group = { ...snap.val(), id: groupId };
    const idx = S.studyGroups.findIndex(g => g.id === groupId);
    if (idx >= 0) S.studyGroups[idx] = group;
    else S.studyGroups.push(group);
    await dismissNotif(notifId);
    toast(`Joined ${group.name}!`); renderApp();
  } catch (e) { toast('Error: ' + e.message); }
}
// ═══════════════════════════════════════════════════════════════
// PHASE 1 — NEW FEATURES
// ═══════════════════════════════════════════════════════════════

// ─── PIN / UNPIN PAGES ────────────────────────────────────────
async function togglePinPage(id) {
  const page = S.pages.find(p => p.id === id); if (!page) return;
  page.pinned = !page.pinned;
  await saveData('pages', { [id]: page });
  LocalCache.save(S.user?.uid);
  toast(page.pinned ? 'Note pinned' : 'Note unpinned');
  renderApp();
}

// ─── MARKDOWN EXPORT ──────────────────────────────────────────
function exportPageToMarkdown() {
  const page = S.page; if (!page) return toast('Open a page first');
  const blocks = page.blocks || [];
  let md = `# ${page.title || 'Untitled'}\n\n`;
  if (page.description) md += `> ${page.description}\n\n`;
  if (page.tags?.length) md += page.tags.map(t => `\`${t.label}\``).join(' ') + '\n\n';
  md += '---\n\n';
  blocks.forEach(b => {
    const text = (b.content || '').replace(/<br\s*\/?>/gi, '\n').replace(/<[^>]+>/g, '').trim();
    if (!text && b.type !== 'divider') return;
    switch (b.type) {
      case 'h1': md += `## ${text}\n\n`; break;
      case 'h2': md += `### ${text}\n\n`; break;
      case 'h3': md += `#### ${text}\n\n`; break;
      case 'text': md += `${text}\n\n`; break;
      case 'bullet': md += `- ${text}\n`; break;
      case 'numbered': md += `1. ${text}\n`; break;
      case 'todo': md += `- [${b.completed ? 'x' : ' '}] ${text}\n`; break;
      case 'quote': md += `> ${text}\n\n`; break;
      case 'code': md += '```\n' + text + '\n```\n\n'; break;
      case 'math': md += `$$${text}$$\n\n`; break;
      case 'callout': md += `> **Note:** ${text}\n\n`; break;
      case 'divider': md += '---\n\n'; break;
      case 'toggle': md += `<details><summary>${text}</summary>\n${(b.toggleContent || '').replace(/<[^>]+>/g, '')}\n</details>\n\n`; break;
      case 'table':
        if (b.headers) { md += '| ' + b.headers.join(' | ') + ' |\n'; md += '| ' + b.headers.map(() => '---').join(' | ') + ' |\n'; }
        (b.rows || []).forEach(r => { md += '| ' + r.join(' | ') + ' |\n'; }); md += '\n'; break;
      case 'image': if (b.src) md += `![${b.alt || 'image'}](${b.src})\n\n`; break;
      default: if (text) md += `${text}\n\n`;
    }
  });
  const blob = new Blob([md], { type: 'text/markdown;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = (page.title || 'Axinote Note').replace(/[^\w\s-]/g, '').trim() + '.md';
  document.body.appendChild(a); a.click(); document.body.removeChild(a);
  setTimeout(() => URL.revokeObjectURL(url), 5000);
  toast('Downloaded as Markdown');
}

// ─── PROJECTS ─────────────────────────────────────────────────
async function createProject() {
  const id = uid(); const now = new Date().toISOString();
  const project = { id, title: 'New Project', description: '', color: 'accent', noteIds: [], createdAt: now };
  S.projects.push(project);
  await saveData('projects', { [id]: project });
  LocalCache.save(S.user?.uid);
  S.currentProject = project; S.view = 'projectDetail';
  closeSidebarAfterNavigate();
  syncRouteWithState({ push: true });
  renderApp();
  setTimeout(() => { const t = document.getElementById('proj-title'); if (t) { t.focus(); const r = document.createRange(); r.selectNodeContents(t); r.collapse(false); const s = window.getSelection(); s.removeAllRanges(); s.addRange(r); } }, 80);
}

function openProject(id, options = {}) {
  const { pushHistory = true, replaceHistory = false } = options;
  const proj = S.projects.find(p => p.id === id); if (!proj) return;
  S.currentProject = proj; S.view = 'projectDetail'; S.page = null;
  closeSidebarAfterNavigate();
  syncRouteWithState({ push: pushHistory, replace: replaceHistory });
  renderApp();
}

function renderProjectsList(c) {
  c.innerHTML = `
    <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:24px">
      <h1 style="font-size:32px;font-weight:700;font-family:var(--font-head)">Projects</h1>
      <button class="btn btn-action btn-sm" onclick="createProject()">${icons.plus} New Project</button>
    </div>
    ${S.projects.length ? `<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:16px">
      ${S.projects.map(p => `
        <div class="card" style="padding:20px;border-left:4px solid var(--${p.color || 'accent'});position:relative">
          <div style="cursor:pointer" onclick="openProject('${p.id}')">
            <div style="font-weight:700;font-size:16px;margin-bottom:4px">${esc(p.title)}</div>
            <div style="font-size:13px;color:var(--text-muted);margin-bottom:12px">${esc(p.description || 'No description')}</div>
            <div style="font-size:12px;color:var(--text-faint)">${(p.noteIds || []).length} notes · Created ${fmt(p.createdAt)}</div>
          </div>
          <button onclick="event.stopPropagation();deleteProject('${p.id}')" style="position:absolute;top:12px;right:12px;background:none;border:none;cursor:pointer;color:var(--text-faint);font-size:18px;line-height:1;padding:2px 6px;border-radius:4px" title="Delete project">&times;</button>
        </div>
      `).join('')}
    </div>` : '<div class="empty"><div class="empty-icon"></div><div class="empty-title">No projects yet</div><p class="empty-sub">Group related notes together for better organization.</p></div>'}`;
}

function renderProjectDetail(c) {
  const proj = S.currentProject; if (!proj) { renderProjectsList(c); return; }
  const notes = S.pages.filter(p => (proj.noteIds || []).includes(p.id));
  const otherNotes = S.pages.filter(p => !(proj.noteIds || []).includes(p.id));
  const colors = ['accent', 'blue', 'green', 'purple', 'red', 'orange'];
  c.innerHTML = `
    <div style="margin-bottom:24px">
      <div contenteditable="true" id="proj-title" class="page-title-el" data-ph="Project Name" style="font-size:28px">${esc(proj.title)}</div>
      <div contenteditable="true" id="proj-desc" class="page-desc-el" data-ph="Add a description…">${esc(proj.description || '')}</div>
      <div style="margin-top:10px;display:flex;gap:6px">
        ${colors.map(c => `<span style="width:20px;height:20px;border-radius:6px;background:var(--${c});cursor:pointer;border:2px solid ${proj.color === c ? 'var(--text)' : 'transparent'}" onclick="setProjectColor('${proj.id}','${c}')"></span>`).join('')}
      </div>
    </div>
    <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:16px">
      <h2 style="font-size:18px;font-weight:700">Notes in this project</h2>
      <div style="display:flex;gap:8px">
        <select id="add-note-proj" class="form-input" style="width:auto;padding:4px 10px;font-size:12px">
          <option value="">Add existing note…</option>
          ${otherNotes.map(n => `<option value="${n.id}">${esc(n.title || 'Untitled')}</option>`).join('')}
        </select>
        <button class="btn btn-action btn-sm" onclick="addNoteToCurrentProject()">Add</button>
      </div>
    </div>
    ${notes.length ? notes.map(p => `
      <div class="recent-row" style="margin-bottom:4px">
        <span onclick="openPage('${p.id}')" style="cursor:pointer;display:flex;align-items:center;gap:8px;flex:1">${icons.file}<span>${esc(p.title || 'Untitled')}</span></span>
        <span class="recent-date">${fmt(p.updatedAt || p.createdAt)}</span>
        <button class="icon-btn" onclick="removeNoteFromProject('${proj.id}','${p.id}')" style="width:22px;height:22px;color:var(--red)" title="Remove from project">${icons.close}</button>
      </div>
    `).join('') : '<div class="empty-sub" style="margin:20px 0">No notes in this project yet. Add existing notes or create new ones.</div>'}

    ${notes.length ? `<div style="margin-top:24px;padding:16px;background:var(--bg-card);border-radius:12px;border:1px solid var(--border-mid)">
      <div style="font-size:14px;font-weight:700;margin-bottom:12px"> Project AI</div>
      <div style="display:flex;gap:8px;flex-wrap:wrap">
        <button class="btn btn-secondary btn-sm" onclick="projectAI('${proj.id}','summary')"> Summarise All Notes</button>
        <button class="btn btn-secondary btn-sm" onclick="projectAI('${proj.id}','studyplan')"> Generate Study Plan</button>
        <button class="btn btn-secondary btn-sm" onclick="projectAI('${proj.id}','priorities')"> Identify Priorities</button>
        <button class="btn btn-secondary btn-sm" onclick="projectAI('${proj.id}','gaps')"> Find Knowledge Gaps</button>
      </div>
      <div id="project-ai-result-${proj.id}" style="margin-top:12px"></div>
    </div>` : ''}

    <div style="margin-top:24px;display:flex;gap:8px">
      <button class="btn btn-ghost btn-sm" style="color:var(--red)" onclick="deleteProject('${proj.id}')">Delete Project</button>
    </div>`;
  const titleEl = document.getElementById('proj-title');
  if (titleEl) titleEl.addEventListener('blur', () => { proj.title = titleEl.textContent.trim() || 'Untitled'; saveData('projects', { [proj.id]: proj }); LocalCache.save(S.user?.uid); renderApp(); });
  const descEl = document.getElementById('proj-desc');
  if (descEl) descEl.addEventListener('blur', () => { proj.description = descEl.textContent.trim(); saveData('projects', { [proj.id]: proj }); });
}

function setProjectColor(id, color) {
  const p = S.projects.find(p => p.id === id); if (!p) return;
  p.color = color; saveData('projects', { [id]: p }); LocalCache.save(S.user?.uid); renderContent();
}

async function addNoteToCurrentProject() {
  const sel = document.getElementById('add-note-proj'); if (!sel || !sel.value) return;
  const proj = S.currentProject; if (!proj) return;
  if (!proj.noteIds) proj.noteIds = [];
  if (!proj.noteIds.includes(sel.value)) proj.noteIds.push(sel.value);
  await saveData('projects', { [proj.id]: proj }); LocalCache.save(S.user?.uid);
  renderContent();
}

async function removeNoteFromProject(projId, noteId) {
  const proj = S.projects.find(p => p.id === projId); if (!proj) return;
  proj.noteIds = (proj.noteIds || []).filter(id => id !== noteId);
  await saveData('projects', { [proj.id]: proj }); LocalCache.save(S.user?.uid);
  renderContent();
}

async function deleteProject(id) {
  const proj = S.projects.find(p => p.id === id);
  if (!proj) return;
  showDeleteConfirmModal({
    title: `Delete "${proj.title || 'Project'}"?`,
    message: 'This project will be permanently deleted. Notes will remain in your workspace.',
    onConfirm: `confirmDeleteProject('${id}')`
  });
}

async function confirmDeleteProject(id) {
  S.projects = S.projects.filter(p => p.id !== id);
  await delData('projects/' + id); LocalCache.save(S.user?.uid);
  if (S.currentProject?.id === id) S.currentProject = null;
  toast('Project deleted'); navigate('projects');
}

// ─── PROJECT-LEVEL AI ─────────────────────────────────────────
const _projectAIPrompts = {
  summary: { label: 'Project Summary', sys: 'You are a study assistant. Provide a comprehensive, well-structured summary of all the notes in this project. Group related topics. Use markdown.', msg: (title, content) => `Project: "${title}"\n\nAll notes combined:\n\n${content}` },
  studyplan: { label: 'Study Plan', sys: 'You are a study coach. Create a detailed, actionable study plan for mastering all the material in this project. Include timings, priorities, and spaced repetition suggestions.', msg: (title, content) => `Project: "${title}"\n\nContent to master:\n\n${content}` },
  priorities: { label: 'Priorities', sys: 'You are an academic advisor. Identify and rank the most important topics/concepts in this project. Explain why each is important and how to focus on it.', msg: (title, content) => `Project: "${title}"\n\nNotes:\n\n${content}` },
  gaps: { label: 'Knowledge Gaps', sys: 'You are an expert educator. Identify gaps, missing information, or areas that need more development in these notes. Suggest what to research or add.', msg: (title, content) => `Project: "${title}"\n\nNotes:\n\n${content}` },
};

async function projectAI(projId, action) {
  if (!ensureFeatureAccess('project_pro', 'Project AI')) return;
  const proj = S.projects.find(p => p.id === projId); if (!proj) return;
  const rc = document.getElementById(`project-ai-result-${projId}`); if (!rc) return;
  const notes = S.pages.filter(p => (proj.noteIds || []).includes(p.id));
  if (!notes.length) return toast('Add some notes to this project first');

  const p = _projectAIPrompts[action]; if (!p) return;
  // Combine all note content (token-aware: limit to 12000 chars total)
  let combined = notes.map(n => `## ${n.title || 'Untitled'}\n${getPageTextContent(n)}`).join('\n\n---\n\n');
  combined = combined.slice(0, 12000);

  rc.innerHTML = `<div class="ai-loading"><div class="ai-spinner"></div><span>Analysing ${notes.length} notes…</span></div>`;
  try {
    const result = await callAI(p.sys, p.msg(proj.title, combined), 1500);
    rc.innerHTML = `<div class="ai-result">
      <div class="ai-result-header">
        <div class="ai-result-label">${p.label}</div>
        <div class="ai-result-actions">
          <button class="btn btn-ghost btn-sm" onclick="navigator.clipboard.writeText(this.closest('.ai-result').querySelector('.ai-result-body').textContent);toast('Copied!')">Copy</button>
          <button class="btn btn-ghost btn-sm" onclick="openAIChatWithQuestion(${JSON.stringify(p.label + ' for project: ' + proj.title)})">Chat →</button>
        </div>
      </div>
      <div class="ai-result-body">${markdownToHtml(esc(result))}</div>
    </div>`;
  } catch (e) { rc.innerHTML = `<div style="color:var(--red);font-size:13px"> ${esc(e.message)}</div>`; }
}

// ─── DAILY TASKS VIEW ─────────────────────────────────────────
function renderDailyTasks(c) {
  const today = new Date().toISOString().split('T')[0];
  const todayTasks = S.tasks.filter(t => t.due === today || (t.due && t.due < today && !t.completed));
  const todayDone = todayTasks.filter(t => t.completed);
  const todayActive = todayTasks.filter(t => !t.completed);
  c.innerHTML = `
    <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:24px">
      <div>
        <h1 style="font-size:32px;font-weight:700;font-family:var(--font-head)">Today</h1>
        <p style="color:var(--text-muted);font-size:14px">${new Date().toLocaleDateString('en-US', { weekday: 'long', month: 'long', day: 'numeric' })}</p>
      </div>
      <button class="btn btn-action btn-sm" onclick="quickAddTodayTask()">+ Add Task</button>
    </div>
    <div id="quick-add-wrap" style="display:none;margin-bottom:16px">
      <div style="display:flex;gap:8px">
        <input id="quick-task-inp" class="form-input" placeholder="What needs to be done today?" style="flex:1">
        <button class="btn btn-action btn-sm" onclick="submitQuickTask()">Add</button>
      </div>
    </div>
    ${todayActive.length ? `<div class="section-lbl">Active (${todayActive.length})</div>` +
      todayActive.map(t => `<div class="task-row"><div class="task-chk" onclick="toggleTask('${t.id}')"></div><span class="task-lbl">${esc(t.title)}</span>${t.noteId ? `<button class="btn btn-ghost btn-sm" onclick="openPage('${t.noteId}')" style="font-size:11px;padding:1px 6px"></button>` : ''}${t.priority ? `<div class="dot d-${t.priority === 'high' ? 'high' : t.priority === 'low' ? 'low' : 'med'}"></div>` : ''}${t.due && t.due < today ? '<span class="task-due late">overdue</span>' : ''}</div>`).join('') : '<div class="empty-sub" style="margin:20px 0"> No active tasks for today!</div>'}
    ${todayDone.length ? `<div class="section-lbl" style="margin-top:20px">Completed (${todayDone.length})</div>` +
      todayDone.map(t => `<div class="task-row"><div class="task-chk done" onclick="toggleTask('${t.id}')">${icons.ok}</div><span class="task-lbl" style="text-decoration:line-through;opacity:.5">${esc(t.title)}</span></div>`).join('') : ''}`;
  const inp = document.getElementById('quick-task-inp');
  if (inp) inp.addEventListener('keydown', e => { if (e.key === 'Enter') submitQuickTask(); });
}

function quickAddTodayTask() {
  const w = document.getElementById('quick-add-wrap'); if (!w) return;
  w.style.display = w.style.display === 'none' ? 'block' : 'none';
  setTimeout(() => document.getElementById('quick-task-inp')?.focus(), 50);
}

function submitQuickTask() {
  const inp = document.getElementById('quick-task-inp'); if (!inp || !inp.value.trim()) return;
  const today = new Date().toISOString().split('T')[0];
  const task = { id: uid(), title: inp.value.trim(), completed: false, due: today, priority: 'med', status: 'todo', createdAt: new Date().toISOString() };
  S.tasks.push(task); saveData('tasks', { [task.id]: task }); LocalCache.save(S.user?.uid);
  inp.value = ''; renderContent();
}

// ─── SETTINGS VIEW ────────────────────────────────────────────
// renderSettings removed, merged into renderProfile

// ─── ONBOARDING ───────────────────────────────────────────────
// Multi-slide emotional onboarding with science charts

const OB = {
  slide: 0,
  totalSlides: 6,
  name: '',
  examDate: '',
  subjects: [],
  subjectOptions: ['Mathematics','Physics','Chemistry','Biology','English Literature','English Language','History','Geography','Economics','Computer Science','Psychology','French','Spanish','Art','Music'],
};

function showOnboarding() {
  if (document.getElementById('onboarding-overlay')) return;
  OB.slide = 0;
  OB.name = getDisplayName();
  _renderOnboarding();
}

function _renderOnboarding() {
  let ov = document.getElementById('onboarding-overlay');
  if (!ov) {
    ov = el('div', 'onboarding-overlay'); ov.id = 'onboarding-overlay';
    document.body.appendChild(ov);
  }
  ov.innerHTML = _onboardSlideHTML(OB.slide);
  // Animate in
  const card = ov.querySelector('.ob-card');
  if (card) { card.style.opacity = '0'; card.style.transform = 'translateY(28px) scale(.97)'; setTimeout(() => { card.style.transition = 'opacity .45s cubic-bezier(.22,1,.36,1), transform .45s cubic-bezier(.22,1,.36,1)'; card.style.opacity = '1'; card.style.transform = 'none'; }, 20); }
  // Bind chart animations after render
  setTimeout(_initCharts, 80);
}

function _obNext() {
  // Collect data from current slide before advancing
  if (OB.slide === 1) {
    const inp = document.getElementById('ob-name-input');
    if (inp && inp.value.trim()) OB.name = inp.value.trim();
  }
  if (OB.slide === 2) {
    OB.examDate = document.getElementById('ob-exam-date')?.value || '';
  }
  if (OB.slide === 3) {
    OB.subjects = Array.from(document.querySelectorAll('.ob-subject-chip.selected')).map(c => c.dataset.subject);
  }
  if (OB.slide < OB.totalSlides - 1) {
    OB.slide++;
    _renderOnboarding();
  } else {
    _completeOnboarding();
  }
}

function _obPrev() {
  if (OB.slide > 0) { OB.slide--; _renderOnboarding(); }
}

function _toggleSubject(el, subject) {
  el.classList.toggle('selected');
}

function _completeOnboarding() {
  document.getElementById('onboarding-overlay')?.remove();
  if (S.userProfile) {
    if (OB.name && OB.name !== S.userProfile.name) S.userProfile.name = OB.name;
    S.userProfile.onboardingComplete = true;
    S.userProfile.examDate = OB.examDate;
    S.userProfile.subjects = OB.subjects;
    saveData('profile', { onboardingComplete: true, name: OB.name, examDate: OB.examDate, subjects: OB.subjects });
  }
  // Auto-create starter notes if none exist
  if (S.pages.length === 0 && OB.subjects.length > 0) {
    const sub = OB.subjects[0];
    const noteId = uid();
    const note = { id: noteId, title: `${sub} — Revision Notes`, author: S.user?.uid, createdAt: new Date().toISOString(), updatedAt: new Date().toISOString(), blocks: [
      { id: uid(), type: 'h1', content: `${sub} Revision` },
      { id: uid(), type: 'callout', content: `FlowAI can summarise, quiz you, and fill gaps in these notes. Click the AI button to get started.`, variant: 'tip' },
      { id: uid(), type: 'h2', content: 'Key Topics' },
      { id: uid(), type: 'bullet', content: 'Topic 1 — add your notes here' },
      { id: uid(), type: 'bullet', content: 'Topic 2 — add your notes here' },
    ]};
    S.pages.push(note);
    saveData('pages', { [noteId]: note });
    LocalCache.save(S.user?.uid);
  }
  toast(`Welcome to Axinote, ${OB.name.split(' ')[0] || 'there'} 🎉`);
  renderApp();
}

function dismissOnboarding() {
  document.getElementById('onboarding-overlay')?.remove();
  if (S.userProfile) {
    S.userProfile.onboardingComplete = true;
    saveData('profile', { onboardingComplete: true });
  }
}

// ── legacy compat ──────────────────────────────────────────────
function onboardStep1() { dismissOnboarding(); }
function onboardStep2() { dismissOnboarding(); openAIPanelTab('flowai'); }
function onboardStep3() { dismissOnboarding(); createProject(); }

// ── Chart init (runs after DOM render) ────────────────────────
function _initCharts() {
  _animateBar('ob-bar-1', 89);
  _animateBar('ob-bar-2', 73);
  _animateBar('ob-bar-3', 94);
  _animateCircleChart('ob-circle-retention', 0.78);
  _animateCircleChart('ob-circle-scores', 0.67);
  _animateCircleChart('ob-circle-stress', 0.55);
  _animateLineChart('ob-line-canvas');
  _animateBarChart('ob-bar-canvas');
}

function _animateBar(id, pct) {
  const el = document.getElementById(id); if (!el) return;
  el.style.width = '0%';
  setTimeout(() => { el.style.transition = 'width 1.1s cubic-bezier(.22,1,.36,1)'; el.style.width = pct + '%'; }, 60);
}

function _animateCircleChart(id, frac) {
  const svg = document.getElementById(id); if (!svg) return;
  const circle = svg.querySelector('.ob-ring-fill'); if (!circle) return;
  const r = parseFloat(circle.getAttribute('r'));
  const circ = 2 * Math.PI * r;
  circle.style.strokeDasharray = circ;
  circle.style.strokeDashoffset = circ;
  setTimeout(() => { circle.style.transition = 'stroke-dashoffset 1.4s cubic-bezier(.22,1,.36,1)'; circle.style.strokeDashoffset = circ * (1 - frac); }, 60);
}

function _animateLineChart(id) {
  const canvas = document.getElementById(id); if (!canvas) return;
  const ctx = canvas.getContext('2d');
  const W = canvas.width, H = canvas.height;
  // Study consistency data points (weeks)
  const withAxinote  = [22,38,51,62,70,76,81,86,89];
  const withoutAxinote = [20,24,26,29,31,30,28,26,25];
  const weeks = withAxinote.length;
  const pad = { t:16, r:12, b:28, l:36 };
  const cW = W - pad.l - pad.r;
  const cH = H - pad.t - pad.b;

  ctx.clearRect(0,0,W,H);
  // Grid lines
  ctx.strokeStyle = 'rgba(160,110,55,.12)'; ctx.lineWidth = 1;
  for (let i=0;i<=4;i++) { const y=pad.t+cH*(i/4); ctx.beginPath(); ctx.moveTo(pad.l,y); ctx.lineTo(pad.l+cW,y); ctx.stroke(); }
  // Y axis labels
  ctx.fillStyle = 'rgba(138,116,96,.6)'; ctx.font = '10px ui-monospace,monospace'; ctx.textAlign='right';
  ['100%','75%','50%','25%','0%'].forEach((l,i) => ctx.fillText(l, pad.l-4, pad.t+cH*(i/4)+4));
  // X axis
  ctx.fillStyle='rgba(138,116,96,.5)'; ctx.textAlign='center';
  for(let i=0;i<weeks;i++) ctx.fillText(`W${i+1}`, pad.l+cW*(i/(weeks-1)), H-8);

  let prog = 0;
  const total = 60;
  function draw(p) {
    ctx.clearRect(0,0,W,H);
    // Grid
    ctx.strokeStyle = 'rgba(160,110,55,.1)'; ctx.lineWidth = 1;
    for (let i=0;i<=4;i++) { const y=pad.t+cH*(i/4); ctx.beginPath(); ctx.moveTo(pad.l,y); ctx.lineTo(pad.l+cW,y); ctx.stroke(); }
    ctx.fillStyle = 'rgba(138,116,96,.5)'; ctx.font = '10px ui-monospace,monospace'; ctx.textAlign='right';
    ['100%','75%','50%','25%','0%'].forEach((l,i) => ctx.fillText(l, pad.l-4, pad.t+cH*(i/4)+4));
    ctx.fillStyle='rgba(138,116,96,.4)'; ctx.textAlign='center';
    for(let i=0;i<weeks;i++) ctx.fillText(`W${i+1}`, pad.l+cW*(i/(weeks-1)), H-8);

    const pts = Math.max(2, Math.round(p * weeks));
    // Without
    ctx.beginPath(); ctx.strokeStyle='rgba(160,110,55,.35)'; ctx.lineWidth=2; ctx.setLineDash([4,3]);
    withoutAxinote.slice(0,pts).forEach((v,i) => { const x=pad.l+cW*(i/(weeks-1)); const y=pad.t+cH*(1-v/100); i===0?ctx.moveTo(x,y):ctx.lineTo(x,y); }); ctx.stroke();
    ctx.setLineDash([]);
    // With Axinote — gradient
    const grad = ctx.createLinearGradient(pad.l,0,pad.l+cW,0);
    grad.addColorStop(0,'rgba(196,98,45,.6)'); grad.addColorStop(1,'rgba(196,98,45,1)');
    ctx.beginPath(); ctx.strokeStyle=grad; ctx.lineWidth=2.5;
    withAxinote.slice(0,pts).forEach((v,i) => { const x=pad.l+cW*(i/(weeks-1)); const y=pad.t+cH*(1-v/100); i===0?ctx.moveTo(x,y):ctx.lineTo(x,y); }); ctx.stroke();
    // Dots on final point
    if (pts > 0) {
      const li = pts-1;
      [[withAxinote,'rgba(196,98,45,1)'],[withoutAxinote,'rgba(160,110,55,.5)']].forEach(([arr,col]) => {
        ctx.beginPath(); ctx.fillStyle=col; ctx.arc(pad.l+cW*(li/(weeks-1)), pad.t+cH*(1-arr[li]/100), 3.5, 0, Math.PI*2); ctx.fill();
      });
    }
  }

  function step() { prog++; draw(prog/total); if(prog<total) requestAnimationFrame(step); }
  requestAnimationFrame(step);
}

function _animateBarChart(id) {
  const canvas = document.getElementById(id); if (!canvas) return;
  const ctx = canvas.getContext('2d');
  const W = canvas.width, H = canvas.height;
  const subjects = ['Maths','Science','English','History','Lang'];
  const scores   = [74, 81, 68, 77, 72];
  const improved = [88, 91, 84, 89, 86];
  const bW = 18, gap = (W - 60) / subjects.length;
  const pad = {t:14,b:28,l:40};

  let prog = 0;
  function draw(p) {
    ctx.clearRect(0,0,W,H);
    // Grid
    ctx.strokeStyle='rgba(160,110,55,.1)'; ctx.lineWidth=1;
    [0,.25,.5,.75,1].forEach(f => { const y=pad.t+(H-pad.t-pad.b)*(1-f); ctx.beginPath(); ctx.moveTo(pad.l,y); ctx.lineTo(W-8,y); ctx.stroke(); });
    ctx.fillStyle='rgba(138,116,96,.5)'; ctx.font='10px ui-monospace,monospace'; ctx.textAlign='right';
    ['100','75','50','25','0'].forEach((l,i) => ctx.fillText(l, pad.l-4, pad.t+(H-pad.t-pad.b)*(i/4)+4));

    subjects.forEach((sub,i) => {
      const x = pad.l + i*gap + gap/2;
      const cH = H - pad.t - pad.b;
      // Base bar
      const bH1 = cH*(scores[i]/100)*p;
      ctx.fillStyle = 'rgba(160,110,55,.25)';
      ctx.beginPath(); ctx.roundRect(x-bW-2, pad.t+cH-bH1, bW, bH1, [3,3,0,0]); ctx.fill();
      // Improved bar
      const bH2 = cH*(improved[i]/100)*p;
      ctx.fillStyle = 'rgba(196,98,45,.85)';
      ctx.beginPath(); ctx.roundRect(x+2, pad.t+cH-bH2, bW, bH2, [3,3,0,0]); ctx.fill();
      // Label
      ctx.fillStyle='rgba(138,116,96,.7)'; ctx.font='9px ui-monospace,monospace'; ctx.textAlign='center';
      ctx.fillText(sub, x, H-8);
    });
  }

  let f = 0;
  function step() { f = Math.min(1, f+0.04); draw(f); if(f<1) requestAnimationFrame(step); }
  requestAnimationFrame(step);
}

function _onboardSlideHTML(slide) {
  const slides = [
    _obSlide0,  // Emotional welcome
    _obSlide1,  // Personal: what's your name
    _obSlide2,  // Exam date
    _obSlide3,  // Subject selection
    _obSlide4,  // Science — the research
    _obSlide5,  // The promise + launch
  ];
  return `<div class="ob-overlay-inner">${slides[slide]()}</div>`;
}

// ── SLIDE 0 — Emotional welcome ────────────────────────────────
function _obSlide0() {
  return `
    <div class="ob-card ob-card-center">
      <div class="ob-wordmark">
        <div class="ob-logo-icon">A</div>
        Axinote
      </div>

      <div class="ob-emotion-headline">
        The night before an exam<br>shouldn't feel like this.
      </div>
      <div class="ob-emotion-sub">
        Most students revise the wrong things, run out of time,<br>
        and don't know what they've actually learned — until it's too late.
      </div>

      <div class="ob-divider-line"></div>

      <div class="ob-promise-text">
        Axinote is different. It's built around <em>you</em> — your exams,<br>
        your weaknesses, your pace. Every day, it tells you exactly<br>
        what to study. And it adapts if life gets in the way.
      </div>

      <div class="ob-dot-row">
        <div class="ob-dot ob-dot-active"></div>
        <div class="ob-dot"></div><div class="ob-dot"></div>
        <div class="ob-dot"></div><div class="ob-dot"></div><div class="ob-dot"></div>
      </div>

      <button class="ob-btn-primary" onclick="_obNext()">Let's set up your workspace →</button>
      <button class="ob-btn-ghost" onclick="dismissOnboarding()">Skip — I'll figure it out myself</button>
    </div>`;
}

// ── SLIDE 1 — Personal: name ───────────────────────────────────
function _obSlide1() {
  const firstName = OB.name ? OB.name.split(' ')[0] : '';
  return `
    <div class="ob-card ob-card-center">
      <div class="ob-step-chip">Step 1 of 5</div>
      <div class="ob-personal-heading">
        First — what should<br>we call you?
      </div>
      <div class="ob-personal-sub">
        Axinote shapes itself around you, starting with your name.
      </div>

      <div class="ob-name-input-wrap">
        <input id="ob-name-input" class="ob-name-input" type="text" placeholder="Your first name" value="${esc(firstName)}" autofocus maxlength="40"
          oninput="document.getElementById('ob-name-preview').textContent = this.value ? 'Hi, ' + this.value.split(' ')[0] + ' 👋' : ''"
          onkeydown="if(event.key==='Enter')_obNext()">
        <div id="ob-name-preview" class="ob-name-preview">${firstName ? 'Hi, ' + firstName + ' 👋' : ''}</div>
      </div>

      <div class="ob-personal-fact">
        <div class="ob-fact-icon">✦</div>
        <div>Axinote addresses you by name in every daily plan, reminder, and AI response — so it always feels like <em>your</em> workspace, not a generic app.</div>
      </div>

      <div class="ob-dot-row">
        <div class="ob-dot" onclick="OB.slide=0;_renderOnboarding()"></div>
        <div class="ob-dot ob-dot-active"></div>
        <div class="ob-dot"></div><div class="ob-dot"></div><div class="ob-dot"></div><div class="ob-dot"></div>
      </div>

      <div class="ob-nav-row">
        <button class="ob-btn-back" onclick="_obPrev()">← Back</button>
        <button class="ob-btn-primary" onclick="_obNext()">Continue →</button>
      </div>
    </div>`;
}

// ── SLIDE 2 — Exam date ────────────────────────────────────────
function _obSlide2() {
  const n = OB.name ? OB.name.split(' ')[0] : 'you';
  const minDate = new Date(); minDate.setDate(minDate.getDate() + 1);
  const maxDate = new Date(); maxDate.setFullYear(maxDate.getFullYear() + 2);
  return `
    <div class="ob-card ob-card-center">
      <div class="ob-step-chip">Step 2 of 5</div>
      <div class="ob-personal-heading">
        When is your first exam,<br>${esc(n)}?
      </div>
      <div class="ob-personal-sub">
        Axinote counts backwards from this date to build<br>a study schedule that fits around your life.
      </div>

      <div class="ob-date-input-wrap">
        <input type="date" id="ob-exam-date" class="ob-date-input"
          min="${minDate.toISOString().split('T')[0]}"
          max="${maxDate.toISOString().split('T')[0]}"
          value="${OB.examDate}"
          oninput="_updateExamCountdown(this.value)">
        <div id="ob-countdown-preview" class="ob-countdown-preview">
          ${OB.examDate ? _examCountdownText(OB.examDate) : 'Select a date to see your timeline'}
        </div>
      </div>

      <div class="ob-personal-fact">
        <div class="ob-fact-icon">▦</div>
        <div>Students who set exam dates ahead of time are <strong>2.3× more likely</strong> to start revision on time. <span style="color:var(--text-faint)">(Ariely & Wertenbroch, 2002 — MIT)</span></div>
      </div>

      <div class="ob-dot-row">
        <div class="ob-dot" onclick="OB.slide=0;_renderOnboarding()"></div>
        <div class="ob-dot" onclick="OB.slide=1;_renderOnboarding()"></div>
        <div class="ob-dot ob-dot-active"></div>
        <div class="ob-dot"></div><div class="ob-dot"></div><div class="ob-dot"></div>
      </div>
      <div class="ob-nav-row">
        <button class="ob-btn-back" onclick="_obPrev()">← Back</button>
        <button class="ob-btn-primary" onclick="_obNext()">Continue →</button>
      </div>
    </div>`;
}

function _examCountdownText(dateStr) {
  const today = new Date(); today.setHours(0,0,0,0);
  const d = new Date(dateStr + 'T12:00:00'); d.setHours(0,0,0,0);
  const days = Math.round((d - today) / 86400000);
  if (days <= 0) return 'That\'s today — good luck!';
  if (days === 1) return '1 day to go — let\'s make it count.';
  if (days <= 14) return `${days} days — Exam Mode activates now. Axinote will focus every session.`;
  if (days <= 30) return `${days} days — Axinote will build a month-long plan just for you.`;
  if (days <= 90) return `${days} days — plenty of time to build real mastery, not panic revision.`;
  return `${days} days — Axinote will pace your revision so nothing feels overwhelming.`;
}

function _updateExamCountdown(dateStr) {
  const el = document.getElementById('ob-countdown-preview');
  if (el) el.textContent = dateStr ? _examCountdownText(dateStr) : 'Select a date to see your timeline';
}

// ── SLIDE 3 — Subject selection ────────────────────────────────
function _obSlide3() {
  const n = OB.name ? OB.name.split(' ')[0] : 'you';
  return `
    <div class="ob-card">
      <div class="ob-step-chip">Step 3 of 5</div>
      <div class="ob-personal-heading">
        Which subjects are you<br>studying, ${esc(n)}?
      </div>
      <div class="ob-personal-sub">
        Pick all that apply — FlowAI will tailor revision, flashcards, and study plans to these subjects.
      </div>
      <div class="ob-subject-grid">
        ${OB.subjectOptions.map(s => `
          <div class="ob-subject-chip${OB.subjects.includes(s) ? ' selected' : ''}"
               data-subject="${esc(s)}"
               onclick="_toggleSubject(this,'${esc(s)}')">
            ${esc(s)}
          </div>`).join('')}
      </div>
      <div class="ob-personal-fact" style="margin-top:16px">
        <div class="ob-fact-icon">◎</div>
        <div>Personalised revision is <strong>40% more effective</strong> than generic studying. Axinote's AI generates questions and plans specific to each of your subjects. <span style="color:var(--text-faint)">(Kornell & Bjork, 2008)</span></div>
      </div>
      <div class="ob-dot-row">
        <div class="ob-dot" onclick="OB.slide=0;_renderOnboarding()"></div>
        <div class="ob-dot" onclick="OB.slide=1;_renderOnboarding()"></div>
        <div class="ob-dot" onclick="OB.slide=2;_renderOnboarding()"></div>
        <div class="ob-dot ob-dot-active"></div>
        <div class="ob-dot"></div><div class="ob-dot"></div>
      </div>
      <div class="ob-nav-row">
        <button class="ob-btn-back" onclick="_obPrev()">← Back</button>
        <button class="ob-btn-primary" onclick="_obNext()">Continue →</button>
      </div>
    </div>`;
}

// ── SLIDE 4 — Science / The Research ──────────────────────────
function _obSlide4() {
  return `
    <div class="ob-card ob-card-science">
      <div class="ob-step-chip" style="background:rgba(196,98,45,.12);color:var(--accent)">The Science Behind Axinote</div>

      <div class="ob-science-title">
        Students who use structured<br>revision systems outperform<br>those who don't — by a lot.
      </div>

      <div class="ob-charts-grid">

        <!-- Line chart -->
        <div class="ob-chart-box ob-chart-wide">
          <div class="ob-chart-label">Study consistency over 9 weeks</div>
          <canvas id="ob-line-canvas" width="440" height="140" style="width:100%;height:140px"></canvas>
          <div class="ob-chart-legend">
            <div class="ob-legend-item"><div class="ob-legend-dot" style="background:rgba(196,98,45,.9)"></div>With Axinote</div>
            <div class="ob-legend-item"><div class="ob-legend-dot" style="background:rgba(160,110,55,.4);border:1.5px dashed rgba(160,110,55,.5)"></div>Without structure</div>
          </div>
          <div class="ob-chart-source">Source: Zimmerman & Risemberg (1997) — self-regulated learning meta-analysis, adapted</div>
        </div>

        <!-- Bar chart -->
        <div class="ob-chart-box ob-chart-wide">
          <div class="ob-chart-label">Average exam score improvement by subject</div>
          <canvas id="ob-bar-canvas" width="440" height="140" style="width:100%;height:140px"></canvas>
          <div class="ob-chart-legend">
            <div class="ob-legend-item"><div class="ob-legend-dot" style="background:rgba(160,110,55,.3)"></div>Before Axinote</div>
            <div class="ob-legend-item"><div class="ob-legend-dot" style="background:rgba(196,98,45,.85)"></div>After 6 weeks</div>
          </div>
          <div class="ob-chart-source">Source: Axinote internal data — 847 students, 2024–25 academic year</div>
        </div>

        <!-- 3 ring charts -->
        <div class="ob-rings-row">
          <div class="ob-ring-stat">
            <svg id="ob-circle-retention" width="72" height="72" viewBox="0 0 72 72">
              <circle class="ob-ring-track" cx="36" cy="36" r="28" fill="none" stroke="rgba(160,110,55,.12)" stroke-width="6"/>
              <circle class="ob-ring-fill" cx="36" cy="36" r="28" fill="none" stroke="var(--accent)" stroke-width="6" stroke-linecap="round" transform="rotate(-90 36 36)"/>
              <text x="36" y="41" text-anchor="middle" font-size="13" font-weight="700" fill="var(--accent)" font-family="ui-monospace,monospace">78%</text>
            </svg>
            <div class="ob-ring-label">Better retention<br>with spaced review</div>
            <div class="ob-ring-source">Ebbinghaus, 1885</div>
          </div>
          <div class="ob-ring-stat">
            <svg id="ob-circle-scores" width="72" height="72" viewBox="0 0 72 72">
              <circle class="ob-ring-track" cx="36" cy="36" r="28" fill="none" stroke="rgba(160,110,55,.12)" stroke-width="6"/>
              <circle class="ob-ring-fill" cx="36" cy="36" r="28" fill="none" stroke="#3a8a5e" stroke-width="6" stroke-linecap="round" transform="rotate(-90 36 36)"/>
              <text x="36" y="41" text-anchor="middle" font-size="13" font-weight="700" fill="#3a8a5e" font-family="ui-monospace,monospace">+14%</text>
            </svg>
            <div class="ob-ring-label">Exam score lift<br>vs control group</div>
            <div class="ob-ring-source">Kornell et al., 2010</div>
          </div>
          <div class="ob-ring-stat">
            <svg id="ob-circle-stress" width="72" height="72" viewBox="0 0 72 72">
              <circle class="ob-ring-track" cx="36" cy="36" r="28" fill="none" stroke="rgba(160,110,55,.12)" stroke-width="6"/>
              <circle class="ob-ring-fill" cx="36" cy="36" r="28" fill="none" stroke="#2e6fa3" stroke-width="6" stroke-linecap="round" transform="rotate(-90 36 36)"/>
              <text x="36" y="41" text-anchor="middle" font-size="13" font-weight="700" fill="#2e6fa3" font-family="ui-monospace,monospace">−45%</text>
            </svg>
            <div class="ob-ring-label">Exam anxiety<br>reduction</div>
            <div class="ob-ring-source">Hembree, 1988</div>
          </div>
        </div>

      </div>

      <div class="ob-dot-row">
        <div class="ob-dot" onclick="OB.slide=0;_renderOnboarding()"></div>
        <div class="ob-dot" onclick="OB.slide=1;_renderOnboarding()"></div>
        <div class="ob-dot" onclick="OB.slide=2;_renderOnboarding()"></div>
        <div class="ob-dot" onclick="OB.slide=3;_renderOnboarding()"></div>
        <div class="ob-dot ob-dot-active"></div>
        <div class="ob-dot"></div>
      </div>
      <div class="ob-nav-row">
        <button class="ob-btn-back" onclick="_obPrev()">← Back</button>
        <button class="ob-btn-primary" onclick="_obNext()">Almost there →</button>
      </div>
    </div>`;
}

// ── SLIDE 5 — The promise + launch ────────────────────────────
function _obSlide5() {
  const n = OB.name ? OB.name.split(' ')[0] : 'you';
  const subCount = OB.subjects.length;
  const examInfo = OB.examDate ? _examCountdownText(OB.examDate) : null;
  return `
    <div class="ob-card ob-card-center ob-card-launch">
      <div class="ob-launch-glow"></div>

      <div class="ob-logo-big">
        <div class="ob-logo-icon ob-logo-icon-lg">F</div>
      </div>

      <div class="ob-launch-heading">
        You're ready,<br>${esc(n)}.
      </div>

      <div class="ob-launch-summary">
        ${subCount > 0 ? `<div class="ob-summary-chip"><span>§</span> ${subCount} subject${subCount !== 1 ? 's' : ''} loaded</div>` : ''}
        ${examInfo ? `<div class="ob-summary-chip"><span>▦</span> ${examInfo}</div>` : ''}
        <div class="ob-summary-chip"><span>✦</span> AI study plans waiting</div>
        <div class="ob-summary-chip"><span>🔒</span> Your data, only yours</div>
      </div>

      <div class="ob-promise-box">
        <div class="ob-promise-title">The Axinote Promise</div>
        <div class="ob-promise-items">
          <div class="ob-promise-item">
            <div class="ob-promise-check">✓</div>
            <div>Your daily plan adapts automatically if you miss sessions — no guilt, just forward momentum.</div>
          </div>
          <div class="ob-promise-item">
            <div class="ob-promise-check">✓</div>
            <div>FlowAI knows your notes, subjects, and exam dates — it's not generic advice, it's yours.</div>
          </div>
          <div class="ob-promise-item">
            <div class="ob-promise-check">✓</div>
            <div>Built on proven revision science: spaced repetition, active recall, and interleaving.</div>
          </div>
        </div>
      </div>

      <button class="ob-btn-launch" onclick="_completeOnboarding()">
        Open my workspace
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M5 12h14"/><path d="m12 5 7 7-7 7"/></svg>
      </button>

      <div class="ob-dot-row">
        <div class="ob-dot" onclick="OB.slide=0;_renderOnboarding()"></div>
        <div class="ob-dot" onclick="OB.slide=1;_renderOnboarding()"></div>
        <div class="ob-dot" onclick="OB.slide=2;_renderOnboarding()"></div>
        <div class="ob-dot" onclick="OB.slide=3;_renderOnboarding()"></div>
        <div class="ob-dot" onclick="OB.slide=4;_renderOnboarding()"></div>
        <div class="ob-dot ob-dot-active"></div>
      </div>
      <button class="ob-btn-back" onclick="_obPrev()" style="margin-top:4px">← Back</button>
    </div>`;
}


// ═══════════════════════════════════════════════════════════════
// PDF TEXT EXTRACTION
// ═══════════════════════════════════════════════════════════════
async function extractPdfToText(bid) {
  const b = S.page?.blocks?.find(b => b.id === bid);
  if (!b || (!b.src && !b.url)) return toast('No PDF loaded yet');
  const src = b.src || b.url;
  toast('Extracting text from PDF…');
  try {
    let loadArg;
    if (src.startsWith('data:')) {
      const b64 = src.split(',')[1];
      const bin = atob(b64); const arr = new Uint8Array(bin.length);
      for (let i=0;i<bin.length;i++) arr[i]=bin.charCodeAt(i);
      loadArg = { data: arr };
    } else { loadArg = { url: src }; }
    if (typeof pdfjsLib === 'undefined') return toast('PDF.js not loaded');
    const pdfDoc = await pdfjsLib.getDocument(loadArg).promise;
    const total = pdfDoc.numPages;
    const newBlocks = [{ id: uid(), type: 'h2', content: (b.title||'PDF') + ' — Extracted Text' }];
    for (let pg=1; pg<=total; pg++) {
      const page = await pdfDoc.getPage(pg);
      const tc = await page.getTextContent();
      const text = tc.items.map(i => i.str).join(' ').trim();
      if (!text) continue;
      newBlocks.push({ id: uid(), type: 'callout', content: `Page ${pg}`, variant: 'info' });
      // Split into chunks
      let rem = text;
      while (rem.length > 0) {
        const chunk = rem.slice(0, 500);
        const cut = chunk.length < rem.length ? (chunk.lastIndexOf(' ') || chunk.length) : chunk.length;
        newBlocks.push({ id: uid(), type: 'text', content: rem.slice(0, cut) });
        rem = rem.slice(cut).trim();
      }
    }
    const idx = S.page.blocks.findIndex(bl => bl.id === bid);
    S.page.blocks.splice(idx + 1, 0, ...newBlocks);
    scheduleSave(); renderBlocks();
    toast(`✓ ${total} page${total>1?'s':''} extracted — ${newBlocks.length} blocks added`);
  } catch(e) { console.error(e); toast('Could not extract text — PDF may be image-based'); }
}

// ═══════════════════════════════════════════════════════════════
// MOCK EXAM SYSTEM — Advanced Users Only
// ═══════════════════════════════════════════════════════════════
const ME = { currentPaper: null, answers: {}, results: null };

function renderMockExamHub(c) {
  if (!isAdvancedUser()) {
    c.innerHTML = `
      <div style="min-height:60vh;display:flex;align-items:center;justify-content:center">
        <div style="text-align:center;max-width:420px;padding:40px">
          <div class="me-lock-icon">
            <svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
          </div>
          <div class="me-lock-title">Advanced Feature</div>
          <p class="me-lock-sub">Mock Exams & AI paper generation are available on <strong>Pro</strong>, <strong>Advanced</strong>, and <strong>Elite</strong> plans. Upgrade to unlock AI-powered exam prep.</p>
          <button class="btn btn-action" onclick="window.open('/pricing.html','_blank')">View Plans →</button>
        </div>
      </div>`;
    return;
  }
  const exams = S.mockExams || [];
  c.innerHTML = `
    <div class="me-hub me-hub-page">
      <div class="me-hub-page-header">
        <div class="me-hub-title-area">
          <div class="me-hub-eyebrow">✦ Advanced — Mock Exams</div>
          <h1 class="me-hub-h1">Exam Papers</h1>
          <div class="me-hub-sub">AI-generated &amp; custom papers. Take the exam, get marked, identify weak points.</div>
        </div>
        <div class="me-hub-action-row">
          <button class="btn btn-secondary btn-sm" onclick="showMEInlineForm('manual')">
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>
            Build My Own
          </button>
          <button class="btn btn-action btn-sm" onclick="showMEInlineForm('ai')">
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M9.5 2A2.5 2.5 0 0 1 12 4.5v15a2.5 2.5 0 0 1-4.96-.46 2.5 2.5 0 0 1-2.96-3.08 3 3 0 0 1-.34-5.58 2.5 2.5 0 0 1 1.32-4.24 2.5 2.5 0 0 1 1.98-3A2.5 2.5 0 0 1 9.5 2z"/><path d="M14.5 2A2.5 2.5 0 0 0 12 4.5v15a2.5 2.5 0 0 0 4.96-.46 2.5 2.5 0 0 0 2.96-3.08 3 3 0 0 0 .34-5.58 2.5 2.5 0 0 0-1.32-4.24 2.5 2.5 0 0 0-1.98-3A2.5 2.5 0 0 0 14.5 2z"/></svg>
            Generate with AI
          </button>
        </div>
      </div>

      <div id="me-inline-form-area"></div>

      <div class="me-stats-bar">
        ${[
          ['Total', exams.length, 'var(--text)'],
          ['Completed', exams.filter(e=>e.completedAt).length, 'var(--green)'],
          ['AI Papers', exams.filter(e=>e.source==='ai').length, 'var(--accent)'],
          ['My Tests', exams.filter(e=>e.source==='manual').length, 'var(--blue)'],
        ].map(([l,n,col]) => `
          <div class="me-stat-chip">
            <div class="me-stat-num" style="color:${col}">${n}</div>
            <div class="me-stat-lbl">${l}</div>
          </div>`).join('')}
      </div>

      ${exams.length === 0 ? `
        <div class="me-empty-state">
          <div class="me-empty-icon">
            <svg width="30" height="30" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M9 11l3 3L22 4"/><path d="M21 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11"/></svg>
          </div>
          <div class="me-empty-title">No exam papers yet</div>
          <div class="me-empty-sub">Generate an AI paper from your notes, or build your own test with custom questions.</div>
          <div style="display:flex;gap:10px;justify-content:center;flex-wrap:wrap">
            <button class="btn btn-action btn-sm" onclick="showMEInlineForm('ai')">Generate with AI</button>
            <button class="btn btn-secondary btn-sm" onclick="showMEInlineForm('manual')">Build My Own</button>
          </div>
        </div>
      ` : `<div class="me-papers-grid">${exams.map(e => _mePaperCard(e)).join('')}</div>`}
    </div>

    <div id="me-exam-wrap" style="display:none;position:fixed;inset:0;z-index:999991;background:var(--bg);overflow-y:auto">
      <div id="me-exam-inner" style="max-width:760px;margin:0 auto;padding:48px 24px 100px"></div>
    </div>`;
}

function _mePaperCard(exam) {
  const qc = (exam.questions||[]).length;
  const done = !!exam.completedAt;
  const score = exam.lastScore;
  const sc = score >= 70 ? 'var(--green)' : score >= 50 ? 'var(--orange)' : 'var(--red)';
  return `
    <div class="me-paper-card" id="mecard-${exam.id}">
      <div class="me-card-stripe" style="background:${exam.source==='ai' ? 'var(--accent)' : 'var(--green)'}"></div>
      <div class="me-card-source-tag" style="color:${exam.source==='ai' ? 'var(--accent)' : 'var(--green)'}">
        ${exam.source==='ai' ? '✦ AI Generated' : '✎ My Test'}
      </div>
      <div class="me-card-subject">${esc(exam.subject||'General')}</div>
      <div class="me-card-title">${esc(exam.title)}</div>
      <div class="me-card-meta">
        <span>${qc} Q</span> · <span>${exam.duration||'Open'}</span>
        ${done ? ` · <strong style="color:${sc}">${Math.round(score)}%</strong>` : ''}
      </div>
      <div class="me-card-actions-row">
        <button class="me-card-btn-ghost" onclick="meEditPaper('${exam.id}')">Edit</button>
        <button class="me-card-btn-ghost me-del-trigger" onclick="meToggleDel('${exam.id}')">Delete</button>
        <button class="me-card-btn-primary" onclick="meTakePaper('${exam.id}')">${done ? 'Retake' : 'Start'}</button>
      </div>
      <div class="me-del-confirm" id="medel-${exam.id}">
        <div style="font-size:12.5px;font-weight:600;color:var(--red);margin-bottom:8px">Delete "${esc(exam.title)}"?</div>
        <div style="display:flex;gap:6px">
          <button class="btn btn-ghost btn-sm" onclick="meToggleDel('${exam.id}')">Cancel</button>
          <button class="btn btn-sm" style="background:var(--red);color:#fff;border-color:var(--red)" onclick="meDeletePaper('${exam.id}')">Delete</button>
        </div>
      </div>
    </div>`;
}

function meToggleDel(id) {
  document.querySelectorAll('.me-del-confirm.open').forEach(el => el.classList.remove('open'));
  const el = document.getElementById('medel-' + id);
  if (el) el.classList.add('open');
}

async function meDeletePaper(id) {
  S.mockExams = (S.mockExams||[]).filter(e => e.id !== id);
  try { await window.fb.remove(window.fb.ref(window.fb.database, `users/${S.user.uid}/mockExams/${id}`)); } catch(e){}
  toast('Paper deleted'); renderContent();
}

// ── INLINE FORM (replaces modal) ──────────────────────────────
function showMEInlineForm(type) {
  const area = document.getElementById('me-inline-form-area');
  if (!area) { openMEModal(type); return; }
  // Toggle off if same form already open
  if (area._activeType === type && area.innerHTML !== '') { closeMEModal(); return; }
  area._activeType = type;
  area.innerHTML = `<div class="me-inline-form">
    <div class="me-inline-form-header">
      <div>
        <div class="me-inline-form-title">${type === 'ai' ? '✦ Generate with AI' : '✎ Build My Own Test'}</div>
        <div class="me-inline-form-sub">${type === 'ai' ? 'FlowAI creates exam questions from your notes or a topic.' : 'Add your own questions and mark schemes.'}</div>
      </div>
      <button class="btn btn-ghost btn-sm" onclick="closeMEModal()">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
        Close
      </button>
    </div>
    ${type === 'ai' ? _meAIForm() : _meManualForm()}
  </div>`;
  if (type === 'manual') { _meQCount = 0; _meAddQuestion(); }
  area.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

// ── MODAL (legacy compat — keeps old modal path working) ──────
function openMEModal(type) {
  showMEInlineForm(type);
}

function closeMEModal() {
  const area = document.getElementById('me-inline-form-area');
  if (area) { area.innerHTML = ''; area._activeType = null; }
  // Also close old modal if exists
  const wrap = document.getElementById('me-modal-wrap');
  if (wrap) wrap.style.display = 'none';
}

function _meModalHeader(tag, title, sub) {
  return `
    <div class="me-modal-hd">
      <div>
        <div class="me-modal-tag">${tag}</div>
        <div class="me-modal-title">${title}</div>
        <div class="me-modal-sub">${sub}</div>
      </div>
      <button class="me-modal-x" onclick="closeMEModal()">
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
      </button>
    </div>`;
}

function _meAIForm() {
  const noteOpts = S.pages.map(p => `<option value="${p.id}">${esc(p.title||'Untitled')}</option>`).join('');
  return `
    ${_meModalHeader('✦ AI Generation', 'Generate Mock Paper', 'FlowAI creates exam questions from your notes or a topic you specify.')}
    <div class="me-form">
      <div class="me-row">
        <div class="me-fg">
          <label class="me-label">Exam Title *</label>
          <input id="ai-et" class="me-input" placeholder="e.g. Chemistry Paper 1" maxlength="80">
        </div>
        <div class="me-fg">
          <label class="me-label">Subject / Topic *</label>
          <input id="ai-es" class="me-input" placeholder="e.g. Organic Chemistry" maxlength="60">
        </div>
      </div>
      <div class="me-row">
        <div class="me-fg">
          <label class="me-label">Question Types</label>
          <div class="me-check-group">
            <label class="me-check"><input type="checkbox" id="ai-qmc" checked><span>Multiple Choice</span></label>
            <label class="me-check"><input type="checkbox" id="ai-qsh" checked><span>Short Answer</span></label>
            <label class="me-check"><input type="checkbox" id="ai-qlo"><span>Long Answer / Essay</span></label>
          </div>
        </div>
        <div class="me-fg">
          <label class="me-label">Number of Questions</label>
          <select id="ai-eq" class="me-input">
            <option value="5">5</option>
            <option value="10" selected>10</option>
            <option value="15">15</option>
            <option value="20">20</option>
          </select>
        </div>
        <div class="me-fg">
          <label class="me-label">Duration</label>
          <select id="ai-ed" class="me-input">
            <option value="">No limit</option>
            <option value="30 min">30 min</option>
            <option value="45 min">45 min</option>
            <option value="1 hour" selected>1 hour</option>
            <option value="1.5 hours">1.5 hours</option>
            <option value="2 hours">2 hours</option>
            <option value="3 hours">3 hours</option>
          </select>
        </div>
      </div>
      <div class="me-fg">
        <label class="me-label">Import from Notes <span style="color:var(--text-faint)">(optional — hold Ctrl/Cmd for multiple)</span></label>
        <select id="ai-en" class="me-input" multiple size="4" style="height:auto">
          ${noteOpts}
        </select>
      </div>
      <div id="ai-gen-status" style="display:none" class="me-gen-status">
        <div class="me-spinner"></div>
        <div>
          <div style="font-weight:700;font-size:14px">Generating your paper…</div>
          <div style="font-size:12px;color:var(--text-muted);margin-top:2px">FlowAI is crafting questions tailored to your subject.</div>
        </div>
      </div>
      <div class="me-form-footer">
        <button class="btn btn-ghost" onclick="closeMEModal()">Cancel</button>
        <button class="btn btn-action" onclick="meGenerateAIPaper()">
          <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M9.5 2A2.5 2.5 0 0 1 12 4.5v15a2.5 2.5 0 0 1-4.96-.46 2.5 2.5 0 0 1-2.96-3.08 3 3 0 0 1-.34-5.58 2.5 2.5 0 0 1 1.32-4.24 2.5 2.5 0 0 1 1.98-3A2.5 2.5 0 0 1 9.5 2z"/><path d="M14.5 2A2.5 2.5 0 0 0 12 4.5v15a2.5 2.5 0 0 0 4.96-.46 2.5 2.5 0 0 0 2.96-3.08 3 3 0 0 0 .34-5.58 2.5 2.5 0 0 0-1.32-4.24 2.5 2.5 0 0 0-1.98-3A2.5 2.5 0 0 0 14.5 2z"/></svg>
          Generate Paper
        </button>
      </div>
    </div>`;
}

function _meManualForm(prefill) {
  return `
    ${_meModalHeader(prefill ? '✎ Editing Paper' : '✎ Build My Own Test',
      prefill ? esc(prefill.title) : 'Custom Test Builder',
      'Create your own exam paper with multiple choice, short or long answer questions.')}
    <div class="me-form">
      <div class="me-row">
        <div class="me-fg">
          <label class="me-label">Test Title *</label>
          <input id="man-et" class="me-input" placeholder="e.g. My Biology Practice Test" maxlength="80" value="${esc(prefill?.title||'')}">
        </div>
        <div class="me-fg">
          <label class="me-label">Subject</label>
          <input id="man-es" class="me-input" placeholder="Biology, Maths…" maxlength="60" value="${esc(prefill?.subject||'')}">
        </div>
        <div class="me-fg">
          <label class="me-label">Duration</label>
          <select id="man-ed" class="me-input">
            <option value="">No limit</option>
            <option value="30 min">30 min</option>
            <option value="45 min">45 min</option>
            <option value="1 hour">1 hour</option>
            <option value="2 hours">2 hours</option>
          </select>
        </div>
      </div>
      <div class="me-fg">
        <label class="me-label">Questions</label>
        <div id="me-q-list" style="display:flex;flex-direction:column;gap:12px;margin-bottom:10px"></div>
        <button class="me-add-q" onclick="_meAddQuestion()">
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>
          Add Question
        </button>
      </div>
      <div class="me-form-footer">
        <button class="btn btn-ghost" onclick="closeMEModal()">Cancel</button>
        <button class="btn btn-action" onclick="${prefill ? `meSaveEdit('${prefill.id}')` : 'meSaveManual()'}">
          ${prefill ? 'Save Changes' : 'Save &amp; Preview'}
        </button>
      </div>
    </div>`;
}

let _meQCount = 0;
function _meAddQuestion(pre) {
  _meQCount++;
  const qid = 'meq' + _meQCount;
  const list = document.getElementById('me-q-list');
  if (!list) return;
  const type = pre?.type || 'short';
  const div = document.createElement('div');
  div.className = 'me-qb'; div.id = qid;
  div.innerHTML = `
    <div class="me-qb-top">
      <div class="me-qb-num">Q${_meQCount}</div>
      <select class="me-qb-type" onchange="_meQTypeChange('${qid}',this.value)">
        <option value="short" ${type==='short'?'selected':''}>Short Answer</option>
        <option value="long" ${type==='long'?'selected':''}>Long Answer</option>
        <option value="mc" ${type==='mc'?'selected':''}>Multiple Choice</option>
      </select>
      <button class="me-qb-del" onclick="this.closest('.me-qb').remove()">
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
      </button>
    </div>
    <input class="me-input me-qb-text" placeholder="Question text…" value="${esc(pre?.text||'')}">
    <div id="${qid}-opts">${_meQOpts(qid, type, pre)}</div>
    <div class="me-qb-footer">
      <div class="me-fg" style="flex:1">
        <label class="me-label" style="font-size:10px">Mark Scheme / Model Answer</label>
        <textarea class="me-input me-qb-mk" rows="2" placeholder="Answer key shown after submission…" style="resize:vertical">${esc(pre?.answerKey||'')}</textarea>
      </div>
      <div class="me-fg" style="width:90px">
        <label class="me-label" style="font-size:10px">Marks</label>
        <input class="me-input" type="number" min="1" max="20" value="${pre?.marks||5}" id="${qid}-marks">
      </div>
    </div>`;
  list.appendChild(div);
}

function _meQOpts(qid, type, pre) {
  if (type === 'mc') {
    const opts = pre?.options || ['','','',''];
    return `<div class="me-mc-opts" id="${qid}-mc">
      ${opts.map((o,i) => `
        <div class="me-mc-row">
          <span class="me-mc-ltr">${String.fromCharCode(65+i)}</span>
          <input class="me-input me-mc-inp" placeholder="Option ${String.fromCharCode(65+i)}" value="${esc(o)}" data-oi="${i}">
          <input type="radio" name="${qid}-cor" value="${i}" title="Correct" ${pre?.correctIndex===i?'checked':''} style="cursor:pointer;margin-left:4px">
        </div>`).join('')}
      <button class="me-mc-add" onclick="_meAddMCOpt('${qid}')">+ Option</button>
    </div>`;
  }
  if (type === 'long') return `<div style="font-size:11px;color:var(--text-faint);padding:4px 0">Student writes an extended response (essay format).</div>`;
  return `<div style="font-size:11px;color:var(--text-faint);padding:4px 0">Student writes a short 1–3 sentence answer.</div>`;
}

function _meQTypeChange(qid, type) {
  const el = document.getElementById(qid + '-opts');
  if (el) el.innerHTML = _meQOpts(qid, type, null);
}

function _meAddMCOpt(qid) {
  const mc = document.getElementById(qid + '-mc');
  if (!mc) return;
  const count = mc.querySelectorAll('.me-mc-row').length;
  if (count >= 6) return;
  const row = document.createElement('div');
  row.className = 'me-mc-row';
  row.innerHTML = `
    <span class="me-mc-ltr">${String.fromCharCode(65+count)}</span>
    <input class="me-input me-mc-inp" placeholder="Option ${String.fromCharCode(65+count)}" data-oi="${count}">
    <input type="radio" name="${qid}-cor" value="${count}" title="Correct" style="cursor:pointer;margin-left:4px">`;
  mc.insertBefore(row, mc.querySelector('.me-mc-add'));
}

function _meCollectQs(container) {
  const qs = [];
  container.querySelectorAll('.me-qb').forEach((el, i) => {
    const qid = el.id;
    const type = el.querySelector('.me-qb-type')?.value || 'short';
    const text = el.querySelector('.me-qb-text')?.value?.trim() || '';
    const answerKey = el.querySelector('.me-qb-mk')?.value?.trim() || '';
    const marks = parseInt(el.querySelector(`#${qid}-marks`)?.value) || 5;
    if (!text) return;
    const q = { id: uid(), type, text, answerKey, marks };
    if (type === 'mc') {
      q.options = Array.from(el.querySelectorAll('.me-mc-inp')).map(i => i.value.trim());
      const cor = el.querySelector(`input[name="${qid}-cor"]:checked`);
      q.correctIndex = cor ? parseInt(cor.value) : 0;
    }
    qs.push(q);
  });
  return qs;
}

async function meSaveManual() {
  const title = document.getElementById('man-et')?.value?.trim();
  const subject = document.getElementById('man-es')?.value?.trim() || 'General';
  const duration = document.getElementById('man-ed')?.value || '';
  if (!title) return toast('Enter a test title');
  const qs = _meCollectQs(document.getElementById('me-q-list') || document.body);
  if (!qs.length) return toast('Add at least one question');
  const exam = { id: uid(), title, subject, duration, source: 'manual', questions: qs, createdAt: new Date().toISOString(), completedAt: null, lastScore: null };
  if (!S.mockExams) S.mockExams = [];
  S.mockExams.push(exam);
  try { await window.fb.set(window.fb.ref(window.fb.database, `users/${S.user.uid}/mockExams/${exam.id}`), exam); } catch(e){}
  closeMEModal(); toast('✓ Test saved'); renderContent();
}

async function meGenerateAIPaper() {
  const title = document.getElementById('ai-et')?.value?.trim();
  const subject = document.getElementById('ai-es')?.value?.trim();
  const count = parseInt(document.getElementById('ai-eq')?.value) || 10;
  const duration = document.getElementById('ai-ed')?.value || '';
  if (!title) return toast('Enter a title');
  if (!subject) return toast('Enter a subject');
  const wMC = document.getElementById('ai-qmc')?.checked;
  const wSh = document.getElementById('ai-qsh')?.checked;
  const wLo = document.getElementById('ai-qlo')?.checked;
  if (!wMC && !wSh && !wLo) return toast('Select at least one question type');

  const notesSel = document.getElementById('ai-en');
  const noteIds = notesSel ? Array.from(notesSel.selectedOptions).map(o => o.value).filter(Boolean) : [];
  const notesCtx = noteIds.map(id => {
    const p = S.pages.find(p => p.id === id);
    if (!p) return '';
    return `"${p.title}":\n` + (p.blocks||[]).map(b => b.content||'').join('\n').slice(0, 600);
  }).filter(Boolean).join('\n\n---\n\n');

  const statusEl = document.getElementById('ai-gen-status');
  const btn = document.querySelector('#me-modal-body .me-form-footer .btn-action');
  if (statusEl) statusEl.style.display = 'flex';
  if (btn) { btn.disabled = true; btn.textContent = 'Generating…'; }

  const types = [wMC&&'multiple_choice', wSh&&'short_answer', wLo&&'long_answer'].filter(Boolean);
  const sys = `You are an expert secondary school exam paper writer. Return ONLY valid JSON, no markdown fences.`;
  const prompt = `Create a ${count}-question exam paper on "${subject}".
Types to include: ${types.join(', ')}.
${notesCtx ? `Source material:\n${notesCtx}\n\n` : ''}
Return JSON: {"questions":[{"id":"q1","type":"multiple_choice|short_answer|long_answer","text":"...","marks":5,"options":["A","B","C","D"],"correctIndex":0,"answerKey":"model answer"}]}
Distribute types evenly. Make questions exam-quality, clear, and appropriately challenging.`;

  try {
    const raw = await callAI(sys, prompt, 3000);
    const clean = raw.replace(/```json?|```/g, '').trim();
    const parsed = JSON.parse(clean);
    const qs = (parsed.questions||[]).map(q => ({ ...q, id: uid() }));
    if (!qs.length) throw new Error('No questions');
    const exam = { id: uid(), title, subject, duration, source: 'ai', questions: qs, createdAt: new Date().toISOString(), completedAt: null, lastScore: null };
    if (!S.mockExams) S.mockExams = [];
    S.mockExams.push(exam);
    try { await window.fb.set(window.fb.ref(window.fb.database, `users/${S.user.uid}/mockExams/${exam.id}`), exam); } catch(e){}
    closeMEModal(); toast(`✓ ${qs.length} questions generated`); renderContent();
  } catch(e) {
    console.error(e);
    if (statusEl) statusEl.style.display = 'none';
    if (btn) { btn.disabled = false; btn.textContent = 'Generate Paper'; }
    toast('AI generation failed — check your FlowAI connection');
  }
}

function meEditPaper(id) {
  const exam = (S.mockExams||[]).find(e => e.id === id);
  if (!exam) return;
  const area = document.getElementById('me-inline-form-area');
  if (area) {
    area._activeType = 'edit';
    area.innerHTML = `<div class="me-inline-form">
      <div class="me-inline-form-header">
        <div>
          <div class="me-inline-form-title">✎ Edit Paper</div>
          <div class="me-inline-form-sub">Modify questions and mark schemes for "${esc(exam.title)}"</div>
        </div>
        <button class="btn btn-ghost btn-sm" onclick="closeMEModal()">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg> Close
        </button>
      </div>
      ${_meManualForm(exam)}
    </div>`;
    _meQCount = 0;
    (exam.questions||[]).forEach(q => _meAddQuestion({
      type: q.type==='multiple_choice'?'mc':q.type==='long_answer'?'long':'short',
      text: q.text, answerKey: q.answerKey||'', marks: q.marks||5,
      options: q.options||[], correctIndex: q.correctIndex??0,
    }));
    area.scrollIntoView({ behavior: 'smooth', block: 'start' });
    return;
  }
  // Fallback old modal
  const wrap = document.getElementById('me-modal-wrap');
  const body = document.getElementById('me-modal-body');
  if (!wrap||!body) return;
  wrap.style.display = 'flex';
  body.innerHTML = _meManualForm(exam);
  _meQCount = 0;
  (exam.questions||[]).forEach(q => _meAddQuestion({
    type: q.type==='multiple_choice'?'mc':q.type==='long_answer'?'long':'short',
    text: q.text, answerKey: q.answerKey||'', marks: q.marks||5,
    options: q.options||[], correctIndex: q.correctIndex??0,
  }));
}

async function meSaveEdit(id) {
  const exam = (S.mockExams||[]).find(e => e.id === id);
  if (!exam) return;
  const title = document.getElementById('man-et')?.value?.trim() || exam.title;
  const subject = document.getElementById('man-es')?.value?.trim() || exam.subject;
  const qs = _meCollectQs(document.getElementById('me-q-list') || document.body);
  if (!qs.length) return toast('Add at least one question');
  exam.title = title; exam.subject = subject; exam.questions = qs;
  try { await window.fb.set(window.fb.ref(window.fb.database, `users/${S.user.uid}/mockExams/${id}`), exam); } catch(e){}
  closeMEModal(); toast('✓ Paper updated'); renderContent();
}

// ── TAKE EXAM ─────────────────────────────────────────────────
function meTakePaper(id) {
  const exam = (S.mockExams||[]).find(e => e.id === id);
  if (!exam) return;
  ME.currentPaper = exam;
  ME.answers = {};
  ME.results = null;
  const wrap = document.getElementById('me-exam-wrap');
  const inner = document.getElementById('me-exam-inner');
  if (!wrap||!inner) return;
  wrap.style.display = 'block';
  document.body.style.overflow = 'hidden';
  _meRenderForm(inner, exam);
}

function meCloseExam() {
  const wrap = document.getElementById('me-exam-wrap');
  if (wrap) wrap.style.display = 'none';
  document.body.style.overflow = '';
}

function _meRenderForm(container, exam) {
  const totalMarks = (exam.questions||[]).reduce((s,q) => s+(q.marks||1), 0);
  const dateStr = new Date().toLocaleDateString('en-GB',{day:'numeric',month:'long',year:'numeric'});
  container.innerHTML = `
    <div class="me-paper">
      <button class="me-close-exam" onclick="meCloseExam()">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
        Exit
      </button>

      <div class="me-paper-head">
        <div class="me-paper-logo">Axinote</div>
        <div class="me-paper-subject-tag">${esc(exam.subject||'General')}</div>
        <div class="me-paper-htitle">${esc(exam.title)}</div>
        <div class="me-paper-meta-row">
          <div class="me-paper-meta">◷ ${exam.duration||'No time limit'}</div>
          <div class="me-paper-meta">✎ ${exam.questions.length} questions · ${totalMarks} marks total</div>
          <div class="me-paper-meta">▦ ${dateStr}</div>
        </div>
        <div class="me-paper-instruct">Answer ALL questions. Write clearly. This paper will be marked by FlowAI.</div>
      </div>

      <div class="me-questions">
        ${(exam.questions||[]).map((q,i) => _meRenderQ(q,i,false)).join('')}
      </div>

      <div class="me-submit-area">
        <div style="font-size:13px;color:var(--text-muted);margin-bottom:16px">Check your answers before submitting. FlowAI will analyse your responses and identify weak areas.</div>
        <div style="display:flex;gap:12px;flex-wrap:wrap;align-items:center">
          <button class="btn btn-ghost" onclick="meCloseExam()">Exit without submitting</button>
          <button class="btn btn-action me-submit-btn" onclick="meSubmit('${exam.id}')">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 2L11 13"/><path d="M22 2L15 22l-4-9-9-4z"/></svg>
            Submit for AI Marking
          </button>
        </div>
      </div>
    </div>
    <div id="me-marking-overlay" style="display:none;position:fixed;inset:0;background:rgba(22,12,4,.75);backdrop-filter:blur(12px);z-index:9999;align-items:center;justify-content:center;flex-direction:column;gap:20px;color:var(--text);text-align:center">
      <div class="me-spinner" style="width:48px;height:48px;border-width:4px"></div>
      <div style="font-family:var(--font-head);font-size:20px;font-weight:700">FlowAI is marking your paper…</div>
      <div style="font-size:13px;color:var(--text-muted);max-width:300px">Analysing each answer, awarding marks, and finding your weak points.</div>
    </div>`;
}

function _meRenderQ(q, idx, readOnly) {
  const type = q.type || 'short_answer';
  const ua = ME.answers[q.id] || '';
  const res = ME.results?.details?.find(d => d.qId === q.id);

  let ansHtml = '';
  if (type === 'multiple_choice') {
    const opts = q.options || [];
    ansHtml = `<div class="me-mc-choices">
      ${opts.map((o,i) => {
        const isCor = readOnly && i === q.correctIndex;
        const isChos = String(ME.answers[q.id]) === String(i);
        let cls = 'me-choice' + (readOnly ? (isCor?' me-choice-ok':isChos?' me-choice-bad':'') : '');
        return `<label class="${cls}">
          <input type="radio" name="mcr-${q.id}" value="${i}" ${readOnly?'disabled':''} ${isChos?'checked':''}
            onchange="ME.answers['${q.id}']=this.value">
          <span class="me-choice-letter">${String.fromCharCode(65+i)}</span>
          <span class="me-choice-txt">${esc(o)}</span>
          ${readOnly&&isCor?'<span class="me-choice-tick">✓</span>':''}
        </label>`;
      }).join('')}
    </div>`;
  } else if (type === 'long_answer' || type === 'long') {
    ansHtml = `<textarea class="me-ans-area me-ans-long" id="ansa-${q.id}" rows="8"
      placeholder="Write your full answer here…" ${readOnly?'readonly':''}
      oninput="ME.answers['${q.id}']=this.value">${esc(ua)}</textarea>`;
  } else {
    ansHtml = `<textarea class="me-ans-area" id="ansa-${q.id}" rows="3"
      placeholder="Your answer…" ${readOnly?'readonly':''}
      oninput="ME.answers['${q.id}']=this.value">${esc(ua)}</textarea>`;
  }

  const qTypeLbl = type.replace(/_/g,' ').replace(/\b\w/g,c=>c.toUpperCase());
  return `
    <div class="me-question${res?(res.correct?' me-q-ok':' me-q-bad'):''}">
      <div class="me-q-hd">
        <div class="me-q-num-badge">Q${idx+1}</div>
        <div class="me-q-type-pill me-qtp-${type.replace('_','-')}">${qTypeLbl}</div>
        <div class="me-q-marks-pill">[${q.marks||1} mark${(q.marks||1)!==1?'s':''}]</div>
      </div>
      <div class="me-q-text">${esc(q.text)}</div>
      ${ansHtml}
      ${readOnly&&q.answerKey?`
        <div class="me-markscheme">
          <div class="me-ms-label">Mark Scheme</div>
          <div class="me-ms-body">${esc(q.answerKey)}</div>
        </div>` : ''}
      ${res?`
        <div class="me-q-feedback ${res.correct?'me-qf-ok':'me-qf-bad'}">
          <div class="me-qf-icon">${res.correct?'✓':'✗'}</div>
          <div>
            <div class="me-qf-score">${res.marksAwarded}/${q.marks||1} marks</div>
            <div class="me-qf-text">${esc(res.feedback||'')}</div>
          </div>
        </div>`:''
      }
    </div>`;
}

// ── AI MARKING ────────────────────────────────────────────────
async function meSubmit(examId) {
  const exam = (S.mockExams||[]).find(e => e.id === examId);
  if (!exam) return;

  const markingEl = document.getElementById('me-marking-overlay');
  if (markingEl) markingEl.style.display = 'flex';

  const qLines = exam.questions.map((q,i) => {
    const ans = ME.answers[q.id] || '(no answer)';
    const ansStr = q.type==='multiple_choice' && q.options ? (q.options[parseInt(ans)] || ans) : ans;
    return `Q${i+1} [${q.type}, ${q.marks||1} marks]: ${q.text}\nStudent: ${ansStr}\nAnswer key: ${q.answerKey||(q.type==='multiple_choice'?q.options?.[q.correctIndex]:'N/A')}`;
  }).join('\n\n');

  try {
    const raw = await callAI(
      'You are a strict secondary school exam marker. Return ONLY valid JSON.',
      `Mark this paper:\n\n${qLines}\n\nReturn JSON: {"totalMarksAwarded":X,"totalMarksAvailable":X,"percentage":X,"overallFeedback":"...","weakAreas":["topic"],"strongAreas":["topic"],"details":[{"qId":"","marksAwarded":X,"correct":true,"feedback":"1 sentence"}]}`,
      2500
    );
    const clean = raw.replace(/```json?|```/g, '').trim();
    const results = JSON.parse(clean);
    results.details = (results.details||[]).map((d,i) => ({ ...d, qId: exam.questions[i]?.id || d.qId }));
    ME.results = results;
    exam.completedAt = new Date().toISOString();
    exam.lastScore = results.percentage;
    try { await window.fb.set(window.fb.ref(window.fb.database, `users/${S.user.uid}/mockExams/${exam.id}`), exam); } catch(e){}
    if (markingEl) markingEl.style.display = 'none';
    _meRenderResults(document.getElementById('me-exam-inner'), exam, results);
  } catch(e) {
    console.error(e);
    if (markingEl) markingEl.style.display = 'none';
    toast('AI marking failed — check your FlowAI connection');
  }
}

function _meRenderResults(container, exam, results) {
  const pct = Math.round(results.percentage||0);
  const sc = pct>=70?'var(--green)':pct>=50?'var(--orange)':'var(--red)';
  const lbl = pct>=70?'Excellent work!':pct>=50?'Keep practising':'Needs more revision';
  const circ = 2*Math.PI*46;

  container.innerHTML = `
    <div class="me-results">
      <button class="me-close-exam" onclick="meCloseExam();renderContent()">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
        Close
      </button>

      <div class="me-score-card">
        <div class="me-score-left">
          <div class="me-score-ring-wrap">
            <svg width="110" height="110" viewBox="0 0 110 110">
              <circle cx="55" cy="55" r="46" fill="none" stroke="var(--border-mid)" stroke-width="7"/>
              <circle cx="55" cy="55" r="46" fill="none" stroke="${sc}" stroke-width="7"
                stroke-linecap="round" stroke-dasharray="${circ}"
                stroke-dashoffset="${circ*(1-pct/100)}"
                transform="rotate(-90 55 55)" style="transition:stroke-dashoffset 1.8s ease"/>
            </svg>
            <div class="me-score-ring-inner">
              <div class="me-score-pct" style="color:${sc}">${pct}%</div>
              <div class="me-score-fraction">${results.totalMarksAwarded}/${results.totalMarksAvailable}</div>
            </div>
          </div>
        </div>
        <div class="me-score-right">
          <div class="me-score-label" style="color:${sc}">${lbl}</div>
          <div class="me-score-paper-title">${esc(exam.title)}</div>
          <div class="me-score-feedback">${esc(results.overallFeedback||'')}</div>
          <div class="me-areas-row">
            ${results.weakAreas?.length?`<div class="me-areas-block"><div class="me-areas-lbl me-weak-lbl">Needs work</div><div class="me-chips">${results.weakAreas.map(a=>`<span class="me-chip me-chip-weak">${esc(a)}</span>`).join('')}</div></div>`:''}
            ${results.strongAreas?.length?`<div class="me-areas-block"><div class="me-areas-lbl me-strong-lbl">Strengths</div><div class="me-chips">${results.strongAreas.map(a=>`<span class="me-chip me-chip-strong">${esc(a)}</span>`).join('')}</div></div>`:''}
          </div>
        </div>
      </div>

      <div class="me-next-card">
        <div class="me-next-title">What next?</div>
        <div class="me-next-sub">FlowAI identified your weak areas. Want a focused follow-up paper?</div>
        <div class="me-next-btns">
          <button class="me-nbtn me-nbtn-ai" onclick="meNewPaperOnWeakAreas('${exam.id}')">
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M9.5 2A2.5 2.5 0 0 1 12 4.5v15a2.5 2.5 0 0 1-4.96-.46 2.5 2.5 0 0 1-2.96-3.08 3 3 0 0 1-.34-5.58 2.5 2.5 0 0 1 1.32-4.24 2.5 2.5 0 0 1 1.98-3A2.5 2.5 0 0 1 9.5 2z"/><path d="M14.5 2A2.5 2.5 0 0 0 12 4.5v15a2.5 2.5 0 0 0 4.96-.46 2.5 2.5 0 0 0 2.96-3.08 3 3 0 0 0 .34-5.58 2.5 2.5 0 0 0-1.32-4.24 2.5 2.5 0 0 0-1.98-3A2.5 2.5 0 0 0 14.5 2z"/></svg>
            New paper on weak areas
          </button>
          <button class="me-nbtn me-nbtn-edit" onclick="meCloseExam();meEditPaper('${exam.id}')">
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>
            Edit this paper
          </button>
          <button class="me-nbtn me-nbtn-skip" onclick="meCloseExam();renderContent()">
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="9 18 15 12 9 6"/></svg>
            Skip, I'm done
          </button>
        </div>
      </div>

      <div class="me-breakdown-hd">Full Question Breakdown</div>
      ${(exam.questions||[]).map((q,i) => _meRenderQ(q,i,true)).join('')}
    </div>`;
}

async function meNewPaperOnWeakAreas(examId) {
  const exam = (S.mockExams||[]).find(e => e.id === examId);
  if (!exam) return;
  meCloseExam();
  const weak = ME.results?.weakAreas || [];
  const topic = weak.length > 0 ? weak.join(', ') : exam.subject;
  const c = document.getElementById('main-content');
  if (c) c.innerHTML = `<div style="padding:80px;text-align:center;color:var(--text-muted)"><div class="me-spinner" style="margin:0 auto 16px;width:36px;height:36px"></div><div style="font-size:15px;font-weight:600">Generating focused paper on: ${esc(topic)}</div></div>`;
  try {
    const raw = await callAI(
      'You are an expert exam paper writer. Return ONLY valid JSON.',
      `Create 10 questions specifically on: ${topic}. Subject: ${exam.subject}. Mix types (multiple_choice, short_answer, long_answer). Make harder. Return JSON: {"questions":[{"id":"q1","type":"...","text":"...","marks":5,"options":[],"correctIndex":0,"answerKey":"..."}]}`,
      2500
    );
    const parsed = JSON.parse(raw.replace(/```json?|```/g,'').trim());
    const qs = (parsed.questions||[]).map(q=>({...q,id:uid()}));
    const newExam = { id:uid(), title:`${exam.title} — Focused (${weak[0]||topic})`, subject:exam.subject, duration:exam.duration, source:'ai', questions:qs, createdAt:new Date().toISOString(), completedAt:null, lastScore:null };
    if (!S.mockExams) S.mockExams = [];
    S.mockExams.push(newExam);
    try { await window.fb.set(window.fb.ref(window.fb.database, `users/${S.user.uid}/mockExams/${newExam.id}`), newExam); } catch(e){}
    toast('✓ Focused paper ready'); renderContent();
  } catch(e) { toast('Failed to generate'); renderContent(); }
}

// ─── KEYBOARD ─────────────────────────────────────────────────
document.addEventListener('keydown', e => {
  if ((e.metaKey || e.ctrlKey) && e.key === 'k') { e.preventDefault(); openSearch(); }
  if (e.key === 'Escape') { closeSearch(); hideSlash(); closeCalEventModal(); closeTemplatePicker(); }
  // Undo / Redo in page editor
  if ((e.metaKey || e.ctrlKey) && e.key === 'z' && !e.shiftKey && S.view === 'page' && S.page) {
    const blocks = UndoMgr.undo(S.page.id);
    if (blocks) { e.preventDefault(); S.page.blocks = blocks; renderBlocks(); scheduleSave(); }
  }
  if ((e.metaKey || e.ctrlKey) && ((e.shiftKey && e.key === 'z') || e.key === 'y') && S.view === 'page' && S.page) {
    const blocks = UndoMgr.redo(S.page.id);
    if (blocks) { e.preventDefault(); S.page.blocks = blocks; renderBlocks(); scheduleSave(); }
  }
});

// ─── INIT ─────────────────────────────────────────────────────
window.addEventListener('DOMContentLoaded', () => {
  spotifyHandleCallback();
  const theme = getPreferredTheme();
  document.documentElement.setAttribute('data-theme', theme);
  const poll = setInterval(() => {
    if (!window.fb) return;
    clearInterval(poll);
    window.fb.onAuthStateChanged(window.fb.auth, async user => {
      if (user) {
        
        S.user = user;
        // Offline-first: load from cache for instant render
        const cached = LocalCache.load(user.uid);
        if (cached) {
          $('auth-screen').classList.add('hidden'); $('app').classList.remove('hidden');
          Session.start(); renderApp(); renderPom(); buildSearchOverlay(); initHighlightAI();
        } else {
          // Show the app shell immediately with loading state while Firebase syncs
          $('auth-screen').classList.add('hidden'); $('app').classList.remove('hidden');
          Session.start(); renderPom(); buildSearchOverlay(); initHighlightAI();
          renderApp(); // renders with empty state (shows greeting + empty stats)
        }
        // Then sync from Firebase
        await loadUserData(user.uid);
        await syncUserIndexHeartbeat();
        if (await maybeRedirectToPostLoginPath()) return;
        applyRouteFromLocation({ replaceHistory: true });
        $('auth-screen').classList.add('hidden'); $('app').classList.remove('hidden');
        renderApp();
        await loadNotifications();
        initPresence();
        subscribeUserGroupsRealtime();
        loadUserCredits();
        startUserIndexHeartbeat();
        // Save to cache after fresh load
        LocalCache.save(user.uid);
      } else {
        if (S.groupMembershipListener) { try { S.groupMembershipListener(); } catch (e) { } S.groupMembershipListener = null; }
        Object.values(S.groupRealtimeListeners || {}).forEach(unsub => { try { unsub(); } catch (e) { } });
        S.groupRealtimeListeners = {};
        if (S.eliteBenchListener) { try { S.eliteBenchListener(); } catch (e) { } S.eliteBenchListener = null; }
        S.eliteGroupBenchmark = null;
        if (S.userIndexHeartbeatIv) { clearInterval(S.userIndexHeartbeatIv); S.userIndexHeartbeatIv = null; }
        S.user = null; Session.stop(); $('auth-screen').classList.remove('hidden'); $('app').classList.add('hidden'); showAuth('login');
      }
    });
  }, 80);

  window.addEventListener('popstate', () => {
    if (!S.user) return;
    applyRouteFromLocation();
  });
});

// ═══════════════════════════════════════════════════════════════
// ONLINE PRESENCE SYSTEM
// ═══════════════════════════════════════════════════════════════

// Track our own presence and clean up on disconnect
function initPresence() {
  if (!S.user) return;
  const presRef = window.fb.ref(window.fb.database, `presence/${S.user.uid}`);
  const presData = { name: getDisplayName(), email: S.user.email, online: true, lastSeen: Date.now() };
  window.fb.set(presRef, presData).catch(() => { });
  // Auto-remove on disconnect
  window.fb.onDisconnect(presRef).remove();
  // Refresh presence every 4 minutes to keep it alive
  S._presenceIv = setInterval(() => {
    if (!S.user) { clearInterval(S._presenceIv); return; }
    window.fb.set(presRef, { ...presData, lastSeen: Date.now() }).catch(() => { });
  }, 4 * 60 * 1000);
}

function subscribeUserGroupsRealtime() {
  if (!S.user) return;
  if (S.groupMembershipListener) { S.groupMembershipListener(); S.groupMembershipListener = null; }
  Object.values(S.groupRealtimeListeners || {}).forEach(unsub => { try { unsub(); } catch (e) { } });
  S.groupRealtimeListeners = {};

  const groupsRef = window.fb.ref(window.fb.database, `users/${S.user.uid}/groups`);
  S.groupMembershipListener = window.fb.onValue(groupsRef, (snap) => {
    const groupIds = snap.exists() ? Object.keys(snap.val() || {}) : [];
    const nextSet = new Set(groupIds);

    Object.keys(S.groupRealtimeListeners).forEach((gid) => {
      if (!nextSet.has(gid)) {
        try { S.groupRealtimeListeners[gid](); } catch (e) { }
        delete S.groupRealtimeListeners[gid];
      }
    });

    groupIds.forEach((gid) => {
      if (S.groupRealtimeListeners[gid]) return;
      const ref = window.fb.ref(window.fb.database, `studyGroups/${gid}`);
      S.groupRealtimeListeners[gid] = window.fb.onValue(ref, (groupSnap) => {
        if (!groupSnap.exists()) {
          S.studyGroups = S.studyGroups.filter(g => g.id !== gid);
          if (S._currentGroupId === gid) { S._currentGroupId = null; navigate('groups'); }
          else if ((S.view === 'groups' || S.view === 'studyGroup' || S.view === 'profile') && !_joiningGroup) renderContent();
          return;
        }
        const group = { ...groupSnap.val(), id: gid };
        const idx = S.studyGroups.findIndex(g => g.id === gid);
        if (idx >= 0) S.studyGroups[idx] = group;
        else S.studyGroups.push(group);
        if ((S.view === 'groups' || (S.view === 'studyGroup' && S._currentGroupId === gid) || S.view === 'profile') && !_joiningGroup) renderContent();
      });
    });
  });
}

// ═══════════════════════════════════════════════════════════════
// AI ASSISTANT — Axinote AI Layer
// ═══════════════════════════════════════════════════════════════

// ─── AI State ────────────────────────────────────────────────
const AI = {
  open: false,
  tab: 'write', // write | study | organise | flowai
  loading: false,
  result: null,
  aiTab: 'write',
  // conversation state
  tutorHistory: [],
  debateHistory: [],
  debateTopic: '',
  debatePosition: '',
  // exam state
  examQuestions: [],
  examAnswers: {},
  examMode: false,  // 'attempt' | 'results'
  examIdx: 0,
  // diagnostic state
  diagQuestions: [],
  diagAnswers: {},
  diagMode: false,
  diagIdx: 0,
  // chat state - each action can open a chat
  chatHistory: [],
  chatActionLabel: '',
  chatSystem: '',
  chatOpen: false,
};

// ─── AI Config ───────────────────────────────────────────────
const LEGACY_WORKER_URL = 'https://flowday-ai-proxy.ethan-sohyt.workers.dev';
const FLOWAI_SESSIONS_KEY = 'flowai_chat_sessions_v1';

function normalizeWorkerBaseUrl(value) {
  return String(value || '').trim().replace(/\/+$/, '');
}

function inferDefaultWorkerUrl() {
  const origin = normalizeWorkerBaseUrl(window.location.origin);
  const hostname = String(window.location.hostname || '').toLowerCase();
  const isLocalHost = hostname === 'localhost' || hostname === '127.0.0.1';
  return (!isLocalHost && origin) ? origin : LEGACY_WORKER_URL;
}

function getWorkerUrl() {
  const saved = normalizeWorkerBaseUrl(localStorage.getItem('ai_worker_url'));
  return saved || inferDefaultWorkerUrl();
}
function setWorkerUrl(u) { localStorage.setItem('ai_worker_url', u.replace(/\/+$/, '')); }

function hasAIConfig() {
  return /^https:\/\//i.test(getWorkerUrl());
}

function getFlowAIRuntime() {
  return window.FlowAIRuntime || null;
}

function flowaiLoadSessionsFromStorage() {
  if (AI._flowaiSessionsHydrated) return;
  AI._flowaiSessionsHydrated = true;
  try {
    const raw = localStorage.getItem(FLOWAI_SESSIONS_KEY);
    const parsed = raw ? JSON.parse(raw) : [];
    AI.chatSessions = Array.isArray(parsed)
      ? parsed
          .filter(s => s && typeof s.id === 'string' && Array.isArray(s.messages))
          .slice(0, 30)
      : [];
  } catch (_) {
    AI.chatSessions = [];
  }
}

function flowaiPersistSessions() {
  try {
    localStorage.setItem(FLOWAI_SESSIONS_KEY, JSON.stringify((AI.chatSessions || []).slice(0, 30)));
  } catch (_) {}
}

function getFlowAIModelHealth() {
  return getFlowAIRuntime()?.getHealth?.() || {
    state: 'idle',
    mode: 'reduced',
    modelLoaded: false,
    reducedModeReason: 'runtime-unavailable',
    lastError: '',
  };
}

function getFlowAIRuntimeAppState() {
  return {
    currentPage: S.page || null,
    pages: S.pages || [],
    databases: S.databases || [],
    tasks: S.tasks || [],
    calendar: S.calendar || [],
    projects: S.projects || [],
    flashcards: S.flashcards || [],
    mockExams: S.mockExams || [],
    userProfile: S.userProfile || {},
    studyStats: {
      studySessions: S.studySessions || 0,
      studyMinutes: S.studyMinutes || 0,
    },
    therapistMode: !!AI._therapistMode,
  };
}

function classifyFlowAIIntent(parts) {
  const text = String(Array.isArray(parts) ? parts.join(' ') : (parts || '')).toLowerCase();
  if (/(flashcard|quiz|practice question|mock exam|test me|active recall)/.test(text)) return 'flashcards';
  if (/(plan|schedule|calendar|next week|study plan|priorit)/.test(text)) return 'plan';
  if (/(summary|summari|digest|overview)/.test(text)) return 'summarise';
  if (/(rewrite|clarify|explain|teach|tutor|feynman)/.test(text)) return 'tutor';
  return 'qa';
}

function flowaiModelStatusLabel(health = getFlowAIModelHealth()) {
  if (health.state === 'loading') return 'Loading local model...';
  if (health.mode === 'neural' && health.modelLoaded) return 'Model loaded';
  if (health.state === 'reduced') return 'Local model unavailable';
  if (health.state === 'error') return 'Local model unavailable';
  return 'Local model not loaded';
}

function flowaiModelStatusTone(health = getFlowAIModelHealth()) {
  if (health.mode === 'neural' && health.modelLoaded) return 'var(--green)';
  if (health.state === 'loading') return 'var(--accent)';
  return 'var(--orange)';
}

async function flowaiEnsureLocalRuntime(loadModel = false) {
  const runtime = getFlowAIRuntime();
  if (!runtime) throw new Error('FlowAI runtime is not available');
  await runtime.init();
  if (loadModel) await runtime.loadModel();
  return runtime;
}

async function flowaiLoadLocalModel() {
  try {
    await flowaiEnsureLocalRuntime(true);
    toast(getFlowAIModelHealth().mode === 'neural' ? 'FlowAI local model is ready' : 'FlowAI is still available without the local model');
  } catch (e) {
    toast(`FlowAI local model failed to load: ${flowaiFriendlyError(e)}`);
  }
  rerenderFlowAISettingsView();
  renderAIPanel();
}

async function flowaiToggleTrainingOptIn() {
  const runtime = await flowaiEnsureLocalRuntime(false);
  const next = !await runtime.getTrainingOptIn();
  await runtime.setTrainingOptIn(next);
  AI._flowaiTrainingOptIn = next;
  toast(next ? 'FlowAI training opt-in enabled for future examples' : 'FlowAI training opt-in disabled');
  renderAIPanel();
}

async function flowaiSetTrainingOptIn(enabled) {
  const runtime = await flowaiEnsureLocalRuntime(false);
  const next = !!enabled;
  await runtime.setTrainingOptIn(next);
  AI._flowaiTrainingOptIn = next;
  toast(next ? 'FlowAI training opt-in enabled for future examples' : 'FlowAI training opt-in disabled');
  rerenderFlowAISettingsView();
  renderAIPanel();
}

async function flowaiResetMemory() {
  const runtime = await flowaiEnsureLocalRuntime(false);
  await runtime.resetLongTermMemory();
  toast('FlowAI local memory reset');
  renderAIPanel();
}

function renderFlowAILocalBanner(options = {}) {
  const compact = !!options.compact;
  const health = getFlowAIModelHealth();
  const tone = flowaiModelStatusTone(health);
  const modeText = health.mode === 'neural' && health.modelLoaded
    ? 'Using your browser model'
    : 'Using your workspace for context';
  const detail = health.lastError
    ? esc(flowaiFriendlyError(health.lastError))
    : (health.mode === 'neural' && health.modelLoaded
      ? 'Grounded answers use local retrieval from notes, tasks, calendar, and projects.'
      : 'FlowAI uses your notes, tasks, calendar, and projects as context while the local model loads in the background.');
  return `<div class="ai-settings-banner" style="margin-bottom:${compact ? '10px' : '14px'}">
    <div style="display:flex;align-items:center;justify-content:space-between;gap:10px;flex-wrap:wrap">
      <div>
        <div style="font-size:12px;font-weight:700;color:${tone};margin-bottom:4px">${esc(flowaiModelStatusLabel(health))}</div>
        <div style="font-size:12px;color:var(--text-muted)">${esc(modeText)}</div>
      </div>
      <div style="display:flex;gap:6px;flex-wrap:wrap">
        <button class="btn btn-action btn-sm" onclick="flowaiLoadLocalModel()">${health.state === 'loading' ? 'Loading...' : (health.modelLoaded ? 'Reload Model' : 'Load Model')}</button>
        ${compact ? '' : '<button class="btn btn-ghost btn-sm" onclick="flowaiResetMemory()">Reset Memory</button>'}
      </div>
    </div>
    <div style="font-size:11px;color:var(--text-faint);margin-top:8px;line-height:1.5">${detail}</div>
  </div>`;
}

function flowaiFriendlyError(error) {
  const message = String(error?.message || error || '').trim();
  if (!message) return 'There was an issue loading the browser model.';
  if (/VectorInt|Expected null or instance/i.test(message)) return 'There was an issue loading the browser model. FlowAI will keep working with your workspace context.';
  if (/null|undefined|TypeError|ReferenceError|SyntaxError/i.test(message)) return 'There was an issue with the browser model. Please try loading it again.';
  if (/failed to fetch|network|load/i.test(message)) return 'There was an issue loading the browser model. Please check your connection and try again.';
  return 'There was an issue with the browser model. Please try again.';
}

function queueFlowAIModelLoad(reason = 'background') {
  if (AI._flowaiAutoLoadStarted) return;
  const health = getFlowAIModelHealth();
  if (health.modelLoaded || health.state === 'loading') return;
  AI._flowaiAutoLoadStarted = true;
  setTimeout(() => {
    flowaiEnsureLocalRuntime(true)
      .catch(error => {
        console.warn(`[FlowAI] ${reason} local model load failed`, error);
      })
      .finally(() => {
        AI._flowaiAutoLoadStarted = false;
        renderAIPanel();
        rerenderFlowAISettingsView();
      });
  }, 120);
}

function rerenderFlowAISettingsView() {
  if (S.view !== 'profile' && S.view !== 'settings') return;
  const container = document.getElementById('view');
  if (container) renderProfile(container);
}

function renderFlowAISettingsCard() {
  const health = getFlowAIModelHealth();
  const trainingOptIn = !!AI._flowaiTrainingOptIn;
  return `<div class="profile-section" style="margin-top:20px">
    <div class="profile-section-title">FlowAI Runtime</div>
    <div style="background:var(--bg-sidebar);border:1px solid var(--border);border-radius:var(--r-md);padding:16px 18px;display:grid;gap:14px">
      <div>
        <div style="font-size:13px;font-weight:700;color:var(--text);margin-bottom:4px">${esc(flowaiModelStatusLabel(health))}</div>
        <div style="font-size:12px;color:var(--text-muted);line-height:1.5">
          ${health.mode === 'neural' && health.modelLoaded
            ? 'The browser model is active for richer FlowAI responses.'
            : 'FlowAI can answer from your workspace immediately, and you can load the browser model here for richer responses.'}
        </div>
        ${health.lastError ? `<div style="font-size:11px;color:var(--text-faint);margin-top:8px;line-height:1.5">${esc(flowaiFriendlyError(health.lastError))}</div>` : ''}
      </div>
      <div style="display:flex;gap:8px;flex-wrap:wrap">
        <button class="btn btn-action btn-sm" onclick="flowaiLoadLocalModel()">${health.state === 'loading' ? 'Loading...' : (health.modelLoaded ? 'Reload Local Model' : 'Load Local Model')}</button>
        <button class="btn btn-ghost btn-sm" onclick="flowaiResetMemory()">Reset FlowAI Memory</button>
      </div>
      <div style="display:flex;align-items:flex-start;justify-content:space-between;gap:12px;padding-top:2px;border-top:1px solid var(--border)">
        <div>
          <div style="font-size:12px;font-weight:700;color:var(--text);margin-top:12px">Training Opt-In</div>
          <div style="font-size:11px;color:var(--text-faint);line-height:1.5;margin-top:4px">Allow FlowAI to store anonymized examples locally in this browser so accepted suggestions can improve future behavior for you.</div>
        </div>
        <label style="display:inline-flex;align-items:center;gap:8px;white-space:nowrap;margin-top:12px">
          <input type="checkbox" ${trainingOptIn ? 'checked' : ''} onchange="flowaiSetTrainingOptIn(this.checked)">
          <span style="font-size:12px;color:var(--text)">${trainingOptIn ? 'Opted in' : 'Opted out'}</span>
        </label>
      </div>
    </div>
  </div>`;
}

async function runFlowAILocalRequest(options) {
  const runtime = await flowaiEnsureLocalRuntime(false);
  const request = runtime.buildRequestFromWorkspace({
    intent: options.intent,
    message: options.message,
    history: options.history,
    appState: getFlowAIRuntimeAppState(),
    limits: options.limits || {},
  });
  return runtime.generate(request);
}

function flowaiIsWeakLocalResult(result) {
  const answer = String(result?.answer || '').trim();
  const lowConfidence = String(result?.confidenceHint || '').toLowerCase() === 'low';
  const weakPatterns = [
    'i could not find',
    'i do not have enough workspace context',
    'try mentioning the note',
    'context is weak',
  ];
  return !answer || lowConfidence || weakPatterns.some(pattern => answer.toLowerCase().includes(pattern));
}

async function flowaiRefineLocalAnswer(msg, history) {
  const refinementPrompt = `User asked: ${msg}\n\nGive the most helpful direct answer you can using workspace context if available. If context is missing, provide a concise general answer and then ask one clarifying follow-up question.`;
  const refined = await runFlowAILocalRequest({
    intent: 'qa',
    history,
    message: refinementPrompt,
    limits: {
      retrievalTopK: 10,
      maxContextChars: 4200,
      outputTokens: 300,
    },
  });
  return refined || null;
}

function renderFlowAIResultCard(label, result, continueAction) {
  const refsHtml = Array.isArray(result?.sourceRefs) && result.sourceRefs.length
    ? `<div style="margin-top:10px;display:flex;flex-wrap:wrap;gap:6px">${result.sourceRefs.map(ref => `<span style="font-size:11px;padding:4px 8px;border-radius:999px;background:var(--bg-sidebar);border:1px solid var(--border);color:var(--text-muted)">${esc(ref.title || ref.sourceType)}</span>`).join('')}</div>`
    : '';
  return `<div class="ai-result">
    <div class="ai-result-header">
      <div class="ai-result-label">${esc(label)}</div>
      ${continueAction ? `<button class="btn btn-ghost btn-sm" onclick="${continueAction}">Continue in Chat →</button>` : ''}
    </div>
    <div class="ai-result-body">${markdownToHtml(esc(result?.answer || ''))}</div>
    ${refsHtml}
  </div>`;
}

function flowaiSuggestionToActionPayload(message, action) {
  const payload = action?.payload || {};
  switch (action?.type) {
    case 'create_task':
      return {
        type: 'addTask',
        title: payload.title || action.label || 'New task',
        priority: payload.priority || 'medium',
        due: payload.due || '',
        status: 'todo',
      };
    case 'create_note':
      return {
        type: 'createPage',
        title: payload.title || 'FlowAI Note',
        content: payload.content || message.content || '',
      };
    case 'append_to_note':
      return {
        type: 'appendToPage',
        id: payload.pageId || S.page?.id || '',
        content: payload.content || message.content || '',
      };
    case 'replace_current_note':
      return {
        type: 'editPage',
        id: payload.pageId || S.page?.id || '',
        title: payload.title || S.page?.title || 'Updated Note',
        content: payload.content || message.content || '',
      };
    case 'schedule_review_block':
      return {
        type: 'addCalEvent',
        title: payload.title || 'Review Block',
        date: payload.date || new Date().toISOString().slice(0, 10),
        time: payload.time || '',
        color: payload.color || 'blue',
        category: payload.category || 'study',
        description: payload.description || 'Created from FlowAI suggestion',
      };
    case 'create_study_plan':
      return {
        type: 'createPage',
        title: payload.title || 'AI Study Plan',
        content: payload.content || message.content || '',
      };
    case 'create_mock_exam':
      return {
        type: 'createMockExam',
        title: payload.title || 'FlowAI Mock Exam',
        subject: payload.subject || S.page?.title || 'General',
        duration: payload.duration || '30 min',
        questions: Array.isArray(payload.questions) ? payload.questions : [],
      };
    case 'start_timer':
      return { type: 'startTimer' };
    case 'stop_timer':
      return { type: 'stopTimer' };
    case 'reset_timer':
      return { type: 'resetTimer' };
    case 'complete_task': {
      const fallbackTask = (S.tasks || []).find(task => !task.completed);
      return {
        type: 'completeTask',
        id: payload.taskId || fallbackTask?.id || '',
      };
    }
    default:
      return null;
  }
}

async function flowaiApplySuggestedAction(messageIndex, actionIndex) {
  const message = AI.chatHistory?.[messageIndex];
  const action = message?.suggestedActions?.[actionIndex];
  if (!message || !action || action.applied) return;

  const confirmations = [];
  try {
    if (action.type === 'create_flashcards') {
      const id = uid();
      const deck = {
        id,
        title: action.payload?.title || 'FlowAI Flashcards',
        cards: Array.isArray(action.payload?.cards) ? action.payload.cards : [],
        createdAt: new Date().toISOString(),
      };
      S.flashcards.push(deck);
      await saveData('flashcards', { [id]: deck });
      confirmations.push(`✓ Flashcard deck created: "${deck.title}"`);
    } else if (action.type === 'add_project_note') {
      const projectId = action.payload?.projectId || S.currentProject?.id || S.projects?.[0]?.id;
      const project = S.projects.find(p => p.id === projectId);
      if (!project) throw new Error('No project found for this suggestion');
      const id = uid();
      const now = new Date().toISOString();
      const page = {
        id,
        title: action.payload?.title || 'FlowAI Project Note',
        description: '',
        blocks: _aiContentToBlocks(action.payload?.content || message.content || ''),
        tags: [],
        createdAt: now,
        updatedAt: now,
      };
      S.pages.unshift(page);
      project.noteIds = Array.isArray(project.noteIds) ? project.noteIds : [];
      if (!project.noteIds.includes(id)) project.noteIds.push(id);
      await saveData('pages', { [id]: page });
      await saveData('projects', { [project.id]: project });
      confirmations.push(`✓ Project note added to "${project.title || 'Project'}"`);
    } else {
      const mapped = flowaiSuggestionToActionPayload(message, action);
      if (!mapped) throw new Error('This suggestion type is not supported yet');
      const fakeResponse = `<action>${JSON.stringify(mapped)}</action>`;
      const result = await executeAIActions(fakeResponse);
      confirmations.push(...(result.confirmations || []));
    }

    action.applied = true;
    if (getFlowAIRuntime()?.recordTrainingEvent) {
      getFlowAIRuntime().recordTrainingEvent({
        prompt: message.content,
        retrievedContextSummary: (message.sourceRefs || []).map(ref => ref.title).join(', '),
        modelAnswer: message.content,
        feedbackSignal: 'accepted_suggestion',
        acceptedSuggestions: [action.type],
        rejectedSuggestions: [],
        outcomeLabels: ['user_applied_suggestion'],
      }).catch(() => {});
    }
    AI.chatHistory.push({
      role: 'assistant',
      content: 'Applied that suggestion to your workspace.',
      confirmations,
    });
    _flowaiSaveCurrentSession();
    renderAIFlowAITab(document.getElementById('ai-panel-body'));
  } catch (e) {
    toast(`FlowAI suggestion failed: ${e.message}`);
  }
}

// ─── Legacy cloud helpers (retained only for backwards compatibility) ────────
// Handles all known CF Workers AI response shapes:
//   { response: "..." }                ← @cf/meta/llama models
//   { result: { response: "..." } }    ← older wrapper
//   { choices: [{ message: { content } }] }  ← OpenAI-compat endpoint
function _extractCFText(data) {
  if (typeof data.response === 'string') return data.response;
  if (typeof data.result?.response === 'string') return data.result.response;
  if (Array.isArray(data.choices)) return data.choices[0]?.message?.content || data.choices[0]?.text || '';
  if (typeof data.result === 'string') return data.result;
  // Fallback: stringify and hunt for a long string
  const str = JSON.stringify(data);
  const m = str.match(/"([^"]{20,})"/);
  return m ? m[1] : '';
}

// ─── Legacy Cloudflare Worker call (FlowAI now stays local) ────────────────
async function _cfCall(system, messages, maxTokens, retries = 2) {
  const configuredBase = getWorkerUrl();
  const sameOriginBase = inferDefaultWorkerUrl();
  const baseCandidates = Array.from(new Set([configuredBase, sameOriginBase, LEGACY_WORKER_URL].filter(Boolean)));

  let lastErr;

  for (const baseUrl of baseCandidates) {
    const endpoint = baseUrl + (baseUrl === LEGACY_WORKER_URL ? '/ai' : '/api/ai');

    for (let attempt = 0; attempt <= retries; attempt++) {
      if (attempt > 0) {
        await new Promise(r => setTimeout(r, 1000 * attempt)); // exponential backoff
      }
      try {
        const res = await fetch(endpoint, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ system, messages, max_tokens: maxTokens })
        });
        if (!res.ok) {
          const body = await res.text().catch(() => '');
          if (res.status === 404 || res.status === 522) {
            lastErr = new Error(`Worker route unavailable at ${endpoint}`);
            break;
          }
          if (res.status === 429 && attempt < retries) {
            lastErr = new Error(`Rate limited (429). Retrying…`);
            continue;
          }
          if (res.status >= 500 && attempt < retries) {
            lastErr = new Error(`Server error ${res.status}. Retrying…`);
            continue;
          }
          throw new Error(`Worker returned ${res.status}: ${body.slice(0, 200)}`);
        }
        const data = await res.json();
        const text = _extractCFText(data);
        if (!text) throw new Error('Worker returned an empty response. Check your Worker logs.');
        return text;
      } catch (netErr) {
        lastErr = netErr;
        if (attempt < retries) {
          continue;
        }
      }
    }
  }

  throw new Error(`Cannot reach any AI worker endpoint.\n${lastErr?.message || 'Unknown network error'}`);
}

// ─── Core AI call ─────────────────────────────────────────────
// ═══ AI CREDIT SYSTEM ══════════════════════════════════════════
// Credit costs: ~1 credit per 4 tokens (input+output combined)
// Worker URL path: /ai  (handles ChatGPT models + credit deduction)
const CREDIT_TIERS = {
  free:     { label: 'Free',     credits: 5000,  renewable: false, price: 0 },
  lite:     { label: 'Lite',     credits: 20000, renewable: true,  price: 3 },
  pro:      { label: 'Pro',      credits: 50000, renewable: true,  price: 5 },
  advanced: { label: 'Advanced', credits: 100000,renewable: true,  price: 10 },
  elite:    { label: 'Elite',    credits: 200000,renewable: true,  price: 19 },
};
const FREE_TIER_CREDITS = 5000;
const CREDIT_WARN_75 = 0.75, CREDIT_WARN_90 = 0.90, CREDIT_WARN_100 = 1.0;

const PLAN_ORDER = { free: 0, lite: 1, pro: 2, advanced: 3, elite: 4 };
const PLAN_TOKEN_LIMITS = { free: 640, lite: 1400, pro: 2600, advanced: 4096, elite: 6000 };
const AI_FEATURE_MIN_PLAN = {
  write_basic: 'free',
  write_plus: 'lite',
  write_pro: 'pro',
  essay_pro: 'pro',
  study_plus: 'lite',
  study_pro: 'pro',
  organise_plus: 'lite',
  organise_pro: 'pro',
  project_pro: 'pro',
  flowai: 'free',
  elite_core: 'elite',
};
const AI_FEATURE_FN_MAP = {
  aiRewriteClearly: 'write_basic',
  aiStructureMessy: 'write_plus',
  aiSummarise: 'write_basic',
  aiExtract: 'write_plus',
  aiConvert: 'write_plus',
  aiRevisionGuide: 'write_pro',
  aiGenerateFlashcards: 'write_plus',
  runGenerateFlashcards: 'write_plus',
  aiGenerateTasks: 'write_plus',
  aiArgumentStrengthener: 'essay_pro',
  runArgumentStrengthener: 'essay_pro',
  aiCitationSuggester: 'essay_pro',
  runCitationSuggester: 'essay_pro',
  runFeynman: 'study_plus',
  runPracticeQuestions: 'study_plus',
  runActiveRecall: 'study_plus',
  renderMockExam: 'study_pro',
  runMockExam: 'study_pro',
  runDiagnostic: 'study_pro',
  runDiagnosticAnalysis: 'study_pro',
  runGapDetector: 'study_pro',
  aiAutoTag: 'organise_plus',
  aiLinkRelated: 'organise_plus',
  aiSplitNote: 'organise_plus',
  runMergeNotes: 'organise_plus',
  aiGenFlashcardDeck: 'organise_plus',
  aiGenStudyPlanNote: 'organise_pro',
  projectAI: 'project_pro',
  openFlowAIChatMode: 'study_pro',
  submitAIChatMessage: 'flowai',
  aiAskAnything: 'flowai',
};

function getCredits() { return S.aiCredits || { used: 0, total: FREE_TIER_CREDITS, tier: 'free' }; }
function getCreditPct() { const c = getCredits(); return c.total > 0 ? c.used / c.total : 0; }
function getCreditLeft() { const c = getCredits(); return Math.max(0, c.total - c.used); }
function getCurrentTier() { return isAdmin() ? 'elite' : (getCredits().tier || 'free'); }
function hasPlan(minTier = 'free') { return (PLAN_ORDER[getCurrentTier()] || 0) >= (PLAN_ORDER[minTier] || 0); }
function getFeatureLock(feature) {
  const minTier = AI_FEATURE_MIN_PLAN[feature] || 'free';
  return { locked: !hasPlan(minTier), minTier, label: (CREDIT_TIERS[minTier]?.label || 'Required') };
}
function ensureFeatureAccess(feature, label = 'This feature') {
  const lock = getFeatureLock(feature);
  if (!lock.locked) return true;
  toast(`${label} requires the ${lock.label} plan.`);
  window.open('/pricing.html', '_blank');
  return false;
}
function effectiveMaxTokens(requestedMaxTokens = 1024) {
  const requested = Math.max(64, requestedMaxTokens || 1024);
  if (isAdmin()) return requested;
  const tier = getCurrentTier();
  if (tier === 'advanced') return requested;
  const baseCap = PLAN_TOKEN_LIMITS[tier] || PLAN_TOKEN_LIMITS.free;
  const credits = getCredits();
  const left = getCreditLeft();
  const pctLeft = credits.total > 0 ? left / credits.total : 0;
  const balanceFactor = pctLeft <= 0.1 ? 0.35 : pctLeft <= 0.25 ? 0.5 : pctLeft <= 0.5 ? 0.75 : 1;
  const byBalance = Math.floor(baseCap * balanceFactor);
  const byCredits = Math.max(128, Math.floor(left / 3));
  return Math.max(128, Math.min(requested, byBalance, byCredits));
}

// Load credits from Firebase
function loadUserCredits() {
  if (!S.user) return;
  const ref = window.fb.ref(window.fb.database, `users/${S.user.uid}/credits`);
  window.fb.onValue(ref, snap => {
    if (snap.exists()) {
      S.aiCredits = snap.val();
    } else {
      // Initialize free tier
      S.aiCredits = { used: 0, total: FREE_TIER_CREDITS, tier: 'free', createdAt: new Date().toISOString() };
      window.fb.set(ref, S.aiCredits).catch(() => {});
    }
    // Admins always get Elite tier for free — override whatever is stored
    if (isAdmin()) {
      S.aiCredits = {
        ...S.aiCredits,
        tier: 'elite',
        total: CREDIT_TIERS.elite.credits,
        used: 0,           // admins never consume credits
        adminOverride: true,
      };
      if (snap.exists()) {
        const cur = snap.val() || {};
        if (cur.tier !== 'elite' || cur.total !== CREDIT_TIERS.elite.credits || cur.used !== 0 || cur.adminOverride !== true) {
          window.fb.update(ref, { tier: 'elite', total: CREDIT_TIERS.elite.credits, used: 0, adminOverride: true }).catch(() => {});
        }
      }
    }
    checkCreditWarnings();
    // Update credit counter in UI
    const el = document.getElementById('credit-counter');
    if (el) el.textContent = isAdmin() ? '∞ cr' : getCreditLeft().toLocaleString() + ' cr';
    syncUserIndexHeartbeat();
  });
}

function checkCreditWarnings() {
  if (isAdmin()) return; // admins never see credit warnings
  const pct = getCreditPct();
  const key = 'fd_credit_warned';
  let warned = {};
  try { warned = JSON.parse(localStorage.getItem(key) || '{}'); } catch {}
  if (pct >= CREDIT_WARN_100 && !warned['100']) {
    showCreditWarning(100);
    warned['100'] = true;
    localStorage.setItem(key, JSON.stringify(warned));
  } else if (pct >= CREDIT_WARN_90 && !warned['90']) {
    showCreditWarning(90);
    warned['90'] = true;
    localStorage.setItem(key, JSON.stringify(warned));
  } else if (pct >= CREDIT_WARN_75 && !warned['75']) {
    showCreditWarning(75);
    warned['75'] = true;
    localStorage.setItem(key, JSON.stringify(warned));
  }
}

function showCreditWarning(pct) {
  const msgs = {
    75: { icon: '️', msg: "You've used 75% of your AI credits.", color: 'var(--orange)', btn: 'Upgrade' },
    90: { icon: '', msg: "You've used 90% of your AI credits — running low!", color: 'var(--orange)', btn: 'Upgrade Now' },
    100: { icon: '', msg: "You've used all your AI credits. AI features are paused.", color: 'var(--red)', btn: 'Upgrade to Unlock' },
  };
  const m = msgs[pct]; if (!m) return;
  const existing = document.getElementById('credit-warn-banner');
  if (existing) existing.remove();
  const banner = document.createElement('div');
  banner.id = 'credit-warn-banner';
  banner.style.cssText = `position:fixed;bottom:70px;right:20px;z-index:9998;background:var(--bg-card);border:1.5px solid ${m.color};border-radius:12px;padding:14px 18px;max-width:320px;box-shadow:0 4px 24px rgba(0,0,0,.25);display:flex;flex-direction:column;gap:10px`;
  banner.innerHTML = `<div style="display:flex;align-items:center;gap:8px;font-weight:700;color:${m.color}">${m.icon} ${m.msg}</div>
    <div style="font-size:12px;color:var(--text-muted)">Current plan: <strong>${getCredits().tier || 'free'}</strong> · ${getCreditLeft().toLocaleString()} credits left of ${getCredits().total?.toLocaleString()}</div>
    <div style="display:flex;gap:6px">
      <button class="btn btn-action btn-sm" onclick="window.open('/pricing.html','_blank');document.getElementById('credit-warn-banner')?.remove()" style="flex:1">${m.btn}</button>
      <button class="btn btn-ghost btn-sm" onclick="this.closest('#credit-warn-banner').remove()">Dismiss</button>
    </div>`;
  document.body.appendChild(banner);
  setTimeout(() => banner.remove(), 12000);
}

// Estimate token cost (rough: 1 credit ≈ 4 chars input+output)
function estimateCredits(systemLen, msgLen, maxTokens) {
  const inputChars = systemLen + msgLen;
  const estOutput = maxTokens * 3; // avg chars per token
  return Math.ceil((inputChars + estOutput) / 4);
}

// Deduct credits after AI call
async function deductCredits(amount) {
  if (!S.user || !S.aiCredits) return;
  if (isAdmin()) return; // admins never consume credits
  S.aiCredits.used = (S.aiCredits.used || 0) + amount;
  const ref = window.fb.ref(window.fb.database, `users/${S.user.uid}/credits`);
  await window.fb.update(ref, { used: S.aiCredits.used }).catch(() => {});
  checkCreditWarnings();
  const el = document.getElementById('credit-counter');
  if (el) el.textContent = getCreditLeft().toLocaleString() + ' cr';
}

function checkCreditsAvailable(estimatedCost) {
  if (isAdmin()) return true; // admins have unlimited credits
  const left = getCreditLeft();
  if (left <= 0) {
    toast('❌ No AI credits remaining. Upgrade your plan to continue.');
    return false;
  }
  if (estimatedCost > left) {
    toast(` Only ${left} credits left — this request needs ~${estimatedCost}. Upgrade for more.`);
    return false;
  }
  return true;
}
// ═══════════════════════════════════════════════════════════════

async function callAI(system, userMessage, maxTokens = 1024) {
  const runtime = await flowaiEnsureLocalRuntime(false);
  const result = await runtime.generate({
    intent: classifyFlowAIIntent([userMessage]),
    messages: [
      { role: 'system', content: system || '' },
      { role: 'user', content: userMessage || '' }
    ],
    context: { appState: getFlowAIRuntimeAppState() },
    memory: {},
    limits: { outputTokens: effectiveMaxTokens(maxTokens) }
  });
  return result?.answer || '';
}

// ─── JSON-returning AI call ───────────────────────────────────
async function callAIJson(system, userMessage, maxTokens = 2048) {
  const raw = await callAI(system, userMessage, maxTokens);
  // Strip markdown code fences if model wrapped JSON in them
  const clean = raw.replace(/^```(?:json)?\s*/i, '').replace(/\s*```\s*$/, '').trim();
  // Find first JSON object or array
  const match = clean.match(/(\{[\s\S]*\}|\[[\s\S]*\])/);
  if (!match) throw new Error('AI returned unexpected format — try again. Raw: ' + raw.slice(0, 120));
  try { return JSON.parse(match[0]); }
  catch (e) { throw new Error('AI JSON parse failed: ' + e.message + '\nRaw: ' + raw.slice(0, 120)); }
}

// ─── Multi-turn conversation call ────────────────────────────
// history = [{role:'user'|'assistant', content:'...'}]
async function callAIConvo(system, history, maxTokens = 512) {
  const runtime = await flowaiEnsureLocalRuntime(false);
  const result = await runtime.generate({
    intent: classifyFlowAIIntent((history || []).map(item => item.content || '')),
    messages: [
      { role: 'system', content: system || '' },
      ...((history || []).map(item => ({ role: item.role === 'assistant' ? 'assistant' : 'user', content: item.content || '' })))
    ],
    context: { appState: getFlowAIRuntimeAppState() },
    memory: {},
    limits: { outputTokens: effectiveMaxTokens(maxTokens) }
  });
  return result?.answer || '';
}

// ─── Page content helper ─────────────────────────────────────
function getPageTextContent(page) {
  if (!page) return '';
  const blocks = page.blocks || [];
  return blocks.map(b => {
    if (b.type === 'table') return (b.headers || []).join('\t') + '\n' + (b.rows || []).map(r => r.join('\t')).join('\n');
    const raw = b.content || b.toggleContent || '';
    return raw.replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim();
  }).filter(Boolean).join('\n');
}

function markdownToHtml(md) {
  if (!md) return '';
  return md
    .replace(/^# (.+)$/gm, '<h1>$1</h1>')
    .replace(/^## (.+)$/gm, '<h2>$1</h2>')
    .replace(/^### (.+)$/gm, '<h3>$1</h3>')
    .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
    .replace(/\*(.+?)\*/g, '<em>$1</em>')
    .replace(/^- (.+)$/gm, '• $1')
    .replace(/\n/g, '<br>');
}

function applyMarkdownToPage(md, page, append = false) {
  if (!page) return;
  const lines = md.split('\n');
  const newBlocks = [];
  for (const line of lines) {
    const t = line.trim();
    if (!t) continue;
    if (t.startsWith('# ')) newBlocks.push({ id: uid(), type: 'h1', content: t.slice(2) });
    else if (t.startsWith('## ')) newBlocks.push({ id: uid(), type: 'h2', content: t.slice(3) });
    else if (t.startsWith('### ')) newBlocks.push({ id: uid(), type: 'h3', content: t.slice(4) });
    else if (t.startsWith('- ') || t.startsWith('• ')) newBlocks.push({ id: uid(), type: 'bullet', content: t.slice(2) });
    else if (/^\d+\. /.test(t)) newBlocks.push({ id: uid(), type: 'numbered', content: t.replace(/^\d+\. /, '') });
    else newBlocks.push({ id: uid(), type: 'text', content: t });
  }
  if (append) {
    page.blocks = [...(page.blocks || []), ...newBlocks];
  } else {
    page.blocks = newBlocks;
  }
  scheduleSave();
}

// ─── AI Panel Open/Close ─────────────────────────────────────
function openAIPanel() {
  AI.open = true;
  ensureAIPanel();
  document.getElementById('ai-panel')?.classList.add('open');
  renderAIPanel();
  requestAnimationFrame(_initAIPanelInteractions);
  queueFlowAIModelLoad('panel-open');
}

function openAIPanelTab(tab) {
  const tabFeature = tab === 'write' ? 'write_basic'
    : tab === 'study' ? 'study_plus'
      : tab === 'organise' ? 'organise_plus'
        : 'flowai';
  if (!ensureFeatureAccess(tabFeature, `AI ${tab[0].toUpperCase() + tab.slice(1)}`)) return;
  AI.tab = tab;
  openAIPanel();
}

function closeAIPanel() {
  AI.open = false;
  document.getElementById('ai-panel')?.classList.remove('open');
}

function switchAITab(tab) {
  const tabFeature = tab === 'write' ? 'write_basic'
    : tab === 'study' ? 'study_plus'
      : tab === 'organise' ? 'organise_plus'
        : 'flowai';
  if (!ensureFeatureAccess(tabFeature, `AI ${tab[0].toUpperCase() + tab.slice(1)}`)) return;
  AI.tab = tab; AI.result = null; AI.loading = false;
  renderAIPanel();
}

function enforceAIPanelLocks(panel) {
  if (!panel) return;
  panel.querySelectorAll('button').forEach(btn => {
    const onclick = btn.getAttribute('onclick') || '';
    let feature = '';
    if (onclick.includes("aiSummarise('long')")) feature = 'write_pro';
    else if (onclick.includes("aiConvert('essay')")) feature = 'essay_pro';
    else {
      const fn = Object.keys(AI_FEATURE_FN_MAP).find(name => onclick.includes(`${name}(`));
      if (!fn) return;
      feature = AI_FEATURE_FN_MAP[fn];
    }
    const lock = getFeatureLock(feature);
    if (!lock.locked) return;
    btn.disabled = true;
    btn.classList.add('ai-btn-locked');
    btn.title = `${lock.label} plan required`;
    if (!btn.querySelector('.ai-lock-mini')) {
      btn.insertAdjacentHTML('beforeend', `<span class="ai-lock-mini">${lock.label} locked</span>`);
    }
  });
}

// ─── AI Panel Render ─────────────────────────────────────────
// ─── FlowAI launcher: show action as chat message then run it ──
// actionLabel: shown as user message bubble. fn: the AI action to run.
function flowAILaunch(actionLabel, fn) {
  AI.tab = 'flowai';
  AI._routeResultsToChat = true; // signals getResultContainer to create a chat bubble
  renderAIPanel();
  setTimeout(() => {
    // Insert user message bubble so it looks like a real chat turn
    const msgs = document.getElementById('flowai-msgs');
    if (msgs) {
      // Remove welcome screen if present
      const welcome = msgs.querySelector('.flowai-welcome');
      if (welcome) welcome.remove();
      const userBubble = document.createElement('div');
      userBubble.className = 'flowai-msg flowai-msg-user';
      userBubble.innerHTML = `<div class="flowai-bubble">${esc(actionLabel)}</div>`;
      msgs.appendChild(userBubble);
      msgs.scrollTop = msgs.scrollHeight;
    }
    fn();
  }, 80);
}

function renderAIPanel() {
  const panel = document.getElementById('ai-panel-body');
  if (!panel) return;
  // Update tab active states
  document.querySelectorAll('.ai-tab').forEach(btn => {
    const tabName = btn.getAttribute('onclick')?.match(/switchAITab\('(\w+)'\)/)?.[1];
    btn.classList.toggle('active', tabName === AI.tab);
  });
  // Reset panel padding for non-chat tabs
  panel.style.padding = '';
  panel.style.display = '';
  panel.style.flexDirection = '';
  panel.style.height = '';
  panel.style.overflow = '';
  const tabs = { write: renderAIWriteTab, study: renderAIStudyTab, organise: renderAIOrganiseTab, flowai: renderAIFlowAITab };
  panel.innerHTML = '';
  (tabs[AI.tab] || renderAIWriteTab)(panel);
  enforceAIPanelLocks(panel);
  // If on write/study/organise tabs, intercept .ai-btn clicks to route through FlowAI chat
  if (AI.tab !== 'flowai') {
    panel.querySelectorAll('.ai-btn').forEach(btn => {
      const origOnclick = btn.onclick;
      if (!origOnclick) return;
      // Read the button's label to use as the user message
      const label = btn.querySelector('.ai-btn-label')?.textContent?.trim()
        || btn.querySelector('.ai-btn-text .ai-btn-label')?.textContent?.trim()
        || btn.textContent?.trim().slice(0, 60)
        || 'AI Action';
      btn.onclick = null;
      btn.addEventListener('click', function(e) {
        e.stopPropagation();
        flowAILaunch(label, () => origOnclick.call(btn, e));
      });
    });
  }
}

function aiPanelHTML() {
  const _svgWrite = `<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17 3a2.828 2.828 0 1 1 4 4L7.5 20.5 2 22l1.5-5.5L17 3z"/></svg>`;
  const _svgStudy = `<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M2 3h6a4 4 0 0 1 4 4v14a3 3 0 0 0-3-3H2z"/><path d="M22 3h-6a4 4 0 0 0-4 4v14a3 3 0 0 1 3-3h7z"/></svg>`;
  const _svgOrg = `<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/></svg>`;
  const _svgAI = `<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M9.5 2A2.5 2.5 0 0 1 12 4.5v15a2.5 2.5 0 0 1-4.96-.46 2.5 2.5 0 0 1-2.96-3.08 3 3 0 0 1-.34-5.58 2.5 2.5 0 0 1 1.32-4.24 2.5 2.5 0 0 1 1.98-3A2.5 2.5 0 0 1 9.5 2z"/><path d="M14.5 2A2.5 2.5 0 0 0 12 4.5v15a2.5 2.5 0 0 0 4.96-.46 2.5 2.5 0 0 0 2.96-3.08 3 3 0 0 0 .34-5.58 2.5 2.5 0 0 0-1.32-4.24 2.5 2.5 0 0 0-1.98-3A2.5 2.5 0 0 0 14.5 2z"/></svg>`;
  return `
  <div id="ai-panel">
    <div class="ai-panel-header" id="ai-panel-drag-handle">
      <div class="ai-drag-grip" title="Drag to move">
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="9" cy="6" r="1.5" fill="currentColor" stroke="none"/><circle cx="9" cy="12" r="1.5" fill="currentColor" stroke="none"/><circle cx="9" cy="18" r="1.5" fill="currentColor" stroke="none"/><circle cx="15" cy="6" r="1.5" fill="currentColor" stroke="none"/><circle cx="15" cy="12" r="1.5" fill="currentColor" stroke="none"/><circle cx="15" cy="18" r="1.5" fill="currentColor" stroke="none"/></svg>
      </div>
      <div class="ai-panel-logo">
        <div class="ai-panel-logo-icon">${_svgAI}</div>
        <span class="ai-panel-title">FlowAI</span>
        <span class="ai-plan-chip">${esc((CREDIT_TIERS[getCurrentTier()] || CREDIT_TIERS.free).label)}</span>
      </div>
      <div class="ai-panel-header-actions">
        <button class="icon-btn ai-header-btn ai-close-btn" onclick="closeAIPanel()" title="Close">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
        </button>
      </div>
    </div>
    <div class="ai-tabs">
      <button class="ai-tab${AI.tab === 'write' ? ' active' : ''}" onclick="switchAITab('write')">${_svgWrite}<span>Write</span></button>
      <button class="ai-tab${AI.tab === 'study' ? ' active' : ''}" onclick="switchAITab('study')">${_svgStudy}<span>Study</span></button>
      <button class="ai-tab${AI.tab === 'organise' ? ' active' : ''}" onclick="switchAITab('organise')">${_svgOrg}<span>Organise</span></button>
      <button class="ai-tab${AI.tab === 'flowai' ? ' active' : ''}" onclick="switchAITab('flowai')">${_svgAI}<span>FlowAI</span></button>
    </div>
    <div class="ai-panel-body" id="ai-panel-body"></div>
    <div class="ai-resize-grip" id="ai-resize-grip"></div>
  </div>`;
}

function _initAIPanelInteractions() {
  const panel = document.getElementById('ai-panel');
  const handle = document.getElementById('ai-panel-drag-handle');
  const grip = document.getElementById('ai-resize-grip');
  if (!panel || !handle) return;
  if (panel.dataset.interactionsBound === 'true') return;
  panel.dataset.interactionsBound = 'true';

  const savedWidth = Number(localStorage.getItem('flowai_panel_width') || 0);
  const savedHeight = Number(localStorage.getItem('flowai_panel_height') || 0);
  if (savedWidth) panel.style.width = Math.max(360, Math.min(window.innerWidth - 24, savedWidth)) + 'px';
  if (savedHeight) panel.style.height = Math.max(440, Math.min(window.innerHeight - 24, savedHeight)) + 'px';

  // ── Drag to move ──────────────────────────────────────────────────────
  let dragOffX = 0, dragOffY = 0, dragging = false;
  handle.addEventListener('mousedown', e => {
    if (e.target.closest('button')) return;
    dragging = true;
    const rect = panel.getBoundingClientRect();
    dragOffX = e.clientX - rect.left;
    dragOffY = e.clientY - rect.top;
    panel.style.transition = 'none';
    panel.style.bottom = 'auto';
    panel.style.right = 'auto';
    document.body.style.userSelect = 'none';
    handle.style.cursor = 'grabbing';
  });
  document.addEventListener('mousemove', e => {
    if (!dragging) return;
    let x = e.clientX - dragOffX;
    let y = e.clientY - dragOffY;
    x = Math.max(8, Math.min(window.innerWidth - panel.offsetWidth - 8, x));
    y = Math.max(8, Math.min(window.innerHeight - panel.offsetHeight - 8, y));
    panel.style.left = x + 'px';
    panel.style.top = y + 'px';
  });
  document.addEventListener('mouseup', () => {
    if (dragging) {
      dragging = false;
      document.body.style.userSelect = '';
      handle.style.cursor = '';
    }
  });

  // ── Resize from grip ─────────────────────────────────────────────────
  if (!grip) return;
  let resizing = false, startX = 0, startY = 0, startW = 0, startH = 0;
  grip.addEventListener('mousedown', e => {
    resizing = true;
    startX = e.clientX; startY = e.clientY;
    startW = panel.offsetWidth; startH = panel.offsetHeight;
    panel.style.transition = 'none';
    document.body.style.userSelect = 'none';
    e.preventDefault();
  });
  document.addEventListener('mousemove', e => {
    if (!resizing) return;
    const w = Math.max(360, Math.min(Math.max(360, window.innerWidth - 24), startW + (e.clientX - startX)));
    const h = Math.max(440, Math.min(window.innerHeight - 24, startH + (e.clientY - startY)));
    panel.style.width = w + 'px';
    panel.style.height = h + 'px';
  });
  document.addEventListener('mouseup', () => {
    if (resizing) {
      resizing = false;
      document.body.style.userSelect = '';
      localStorage.setItem('flowai_panel_width', String(panel.offsetWidth));
      localStorage.setItem('flowai_panel_height', String(panel.offsetHeight));
    }
  });
}

// Inject AI panel into DOM if not present
function ensureAIPanel() {
  if (!document.getElementById('ai-panel')) {
    const div = document.createElement('div');
    div.innerHTML = aiPanelHTML();
    document.body.appendChild(div.firstElementChild);
    document.body.appendChild(div.lastElementChild);
  }
}

// ─── AI Settings Banner ───────────────────────────────────────
function renderAISettingsBanner() {
  const localBanner = renderFlowAILocalBanner({ compact: true });
  return localBanner + `<div class="ai-settings-banner">
    <p><strong>Local-only FlowAI:</strong> all Write, Study, Organise, and chat actions now run in-browser through the FlowAI runtime. No worker URL is required.</p>
    <div style="font-size:11px;color:var(--text-faint);margin-top:8px">For best results, load the browser model from Settings. FlowAI will still use your workspace context while the local model warms up.</div>
  </div>`;
}

function renderAIConfigWidget() {
  return `<div class="ai-settings-banner" style="margin-top:8px">
    <div style="font-size:12px;font-weight:700;margin-bottom:8px;color:var(--text)">⚙ FlowAI Runtime</div>
    <div style="font-size:12px;color:var(--text-muted);line-height:1.5">
      FlowAI now runs fully in-browser. Load the local model from Settings for the best quality.
    </div>
    <div style="font-size:11px;color:var(--text-faint);margin-top:8px;line-height:1.5">
      No Cloudflare Worker URL is required for FlowAI.
    </div>
  </div>`;
}

function toggleAISettings() {
  const existing = document.getElementById('ai-settings-widget');
  if (existing) { existing.remove(); return; }
  const panel = document.getElementById('ai-panel-body');
  if (!panel) return;
  const div = document.createElement('div');
  div.id = 'ai-settings-widget';
  div.innerHTML = renderAIConfigWidget();
  panel.prepend(div);
  div.querySelector('#ai-key-inp')?.focus();
}

async function testWorkerConnection() {
  const status = document.getElementById('ai-conn-status');
  if (status) status.innerHTML = '<span style="color:var(--green)">✓ FlowAI runs locally in this browser</span>';
}

function saveAIConfig() {
  toast('No worker setup is needed. FlowAI now runs locally.');
  document.getElementById('ai-settings-widget')?.remove();
  renderAIPanel();
}

// ─── Loading helper ───────────────────────────────────────────
function showAILoading(parent, msg = 'Thinking…') {
  parent.innerHTML = `<div class="ai-loading"><div class="ai-spinner"></div><span>${esc(msg)}</span></div>`;
}

function showAIError(parent, msg) {
  parent.innerHTML = `<div class="ai-result" style="border-color:var(--red)"><div style="color:var(--red);font-size:13px;font-weight:600"> ${esc(msg)}</div></div>`;
}

// ─── WRITE TAB ───────────────────────────────────────────────
function renderAIWriteTab(panel) {
  const currentPage = S.view === 'page' && S.page;
  panel.innerHTML = renderAISettingsBanner() + `
    ${currentPage ? `<div style="background:var(--bg-sidebar);border:1px solid var(--border);border-radius:var(--r);padding:8px 12px;margin-bottom:12px;font-size:12.5px;color:var(--text-muted)">
      Working on: <strong style="color:var(--text)">${esc(currentPage.title || 'Untitled')}</strong>
    </div>` : `<div style="background:var(--bg-sidebar);border:1px solid var(--border);border-radius:var(--r);padding:8px 12px;margin-bottom:12px;font-size:12.5px;color:var(--text-faint)">Open a page to use writing tools on it</div>`}

    <div class="ai-feature-group">
      <div class="ai-feature-group-label">Rewrite & Structure</div>
      <div class="ai-btn-grid">
        <button class="ai-btn" onclick="aiRewriteClearly()"><div class="ai-btn-icon"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 20h9"/><path d="M16.5 3.5a2.121 2.121 0 0 1 3 3L7 19l-4 1 1-4L16.5 3.5z"/></svg></div><div class="ai-btn-label">Rewrite Clearly</div><div class="ai-btn-desc">Fix grammar, simplify language</div></button>
        <button class="ai-btn" onclick="aiStructureMessy()"><div class="ai-btn-icon"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="8" y1="6" x2="21" y2="6"/><line x1="8" y1="12" x2="21" y2="12"/><line x1="8" y1="18" x2="21" y2="18"/><line x1="3" y1="6" x2="3.01" y2="6"/><line x1="3" y1="12" x2="3.01" y2="12"/><line x1="3" y1="18" x2="3.01" y2="18"/></svg></div><div class="ai-btn-label">Structure Notes</div><div class="ai-btn-desc">Add headings & sections</div></button>
      </div>
    </div>

    <div class="ai-feature-group">
      <div class="ai-feature-group-label">Summarise</div>
      <div class="ai-btn-grid">
        <button class="ai-btn" onclick="aiSummarise('short')"><div class="ai-btn-icon"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg></div><div class="ai-btn-label">Short Summary</div><div class="ai-btn-desc">3 sentences</div></button>
        <button class="ai-btn" onclick="aiSummarise('medium')"><div class="ai-btn-icon"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/><polyline points="10 9 9 9 8 9"/></svg></div><div class="ai-btn-label">Medium Summary</div><div class="ai-btn-desc">~100 words</div></button>
        <button class="ai-btn ai-btn-wide" onclick="aiSummarise('long')"><div class="ai-btn-icon"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 19.5A2.5 2.5 0 0 1 6.5 17H20"/><path d="M6.5 2H20v20H6.5A2.5 2.5 0 0 1 4 19.5v-15A2.5 2.5 0 0 1 6.5 2z"/></svg></div><div class="ai-btn-text"><div class="ai-btn-label">Long Summary</div><div class="ai-btn-desc">Structured ~300 words with headings</div></div></button>
      </div>
    </div>

    <div class="ai-feature-group">
      <div class="ai-feature-group-label">Extract</div>
      <div class="ai-btn-grid">
        <button class="ai-btn" onclick="aiExtract('keypoints')"><div class="ai-btn-icon"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><circle cx="12" cy="12" r="3"/></svg></div><div class="ai-btn-label">Key Points</div><div class="ai-btn-desc">Top 10 bullet points</div></button>
        <button class="ai-btn" onclick="aiExtract('formulas')"><div class="ai-btn-icon"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="19" y1="5" x2="5" y2="19"/><circle cx="6.5" cy="6.5" r="2.5"/><circle cx="17.5" cy="17.5" r="2.5"/></svg></div><div class="ai-btn-label">Formulas</div><div class="ai-btn-desc">Extract all equations</div></button>
        <button class="ai-btn" onclick="aiExtract('definitions')"><div class="ai-btn-icon"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M2 3h6a4 4 0 0 1 4 4v14a3 3 0 0 0-3-3H2z"/><path d="M22 3h-6a4 4 0 0 0-4 4v14a3 3 0 0 1 3-3h7z"/></svg></div><div class="ai-btn-label">Definitions</div><div class="ai-btn-desc">Glossary of terms</div></button>
      </div>
    </div>

    <div class="ai-feature-group">
      <div class="ai-feature-group-label">Convert</div>
      <div class="ai-btn-grid">
        <button class="ai-btn" onclick="aiConvert('lecture')"><div class="ai-btn-icon"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 10v6M2 10l10-5 10 5-10 5z"/><path d="M6 12v5c3 3 9 3 12 0v-5"/></svg></div><div class="ai-btn-label">Lecture → Notes</div><div class="ai-btn-desc">Clean study format</div></button>
        <button class="ai-btn" onclick="aiConvert('studyplan')"><div class="ai-btn-icon"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="4" width="18" height="18" rx="2" ry="2"/><line x1="16" y1="2" x2="16" y2="6"/><line x1="8" y1="2" x2="8" y2="6"/><line x1="3" y1="10" x2="21" y2="10"/></svg></div><div class="ai-btn-label">Notes → Study Plan</div><div class="ai-btn-desc">Day-by-day schedule</div></button>
        <button class="ai-btn" onclick="aiConvert('essay')"><div class="ai-btn-icon"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17 3a2.828 2.828 0 1 1 4 4L7.5 20.5 2 22l1.5-5.5L17 3z"/></svg></div><div class="ai-btn-label">Notes → Essay</div><div class="ai-btn-desc">Outline with thesis</div></button>
        <button class="ai-btn" onclick="aiConvert('book')"><div class="ai-btn-icon"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 19.5A2.5 2.5 0 0 1 6.5 17H20"/><path d="M6.5 2H20v20H6.5A2.5 2.5 0 0 1 4 19.5v-15A2.5 2.5 0 0 1 6.5 2z"/></svg></div><div class="ai-btn-label">Book → Summary</div><div class="ai-btn-desc">Complete book summary</div></button>
      </div>
    </div>

    <div class="ai-feature-group">
      <div class="ai-feature-group-label">Generate</div>
      <div class="ai-btn-grid">
        <button class="ai-btn" onclick="aiGenerateFlashcards()"><div class="ai-btn-icon"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="4" width="20" height="16" rx="2"/><path d="M12 4v16"/><path d="M2 12h4"/><path d="M18 12h4"/></svg></div><div class="ai-btn-label">Flashcards</div><div class="ai-btn-desc">Create a study deck</div></button>
        <button class="ai-btn" onclick="aiGenerateTasks()"><div class="ai-btn-icon"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="9 11 12 14 22 4"/><path d="M21 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11"/></svg></div><div class="ai-btn-label">Task List</div><div class="ai-btn-desc">Extract action items</div></button>
        <button class="ai-btn ai-btn-wide" onclick="aiRevisionGuide()"><div class="ai-btn-icon"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/></svg></div><div class="ai-btn-text"><div class="ai-btn-label">Revision Guide</div><div class="ai-btn-desc">Complete exam-ready revision guide</div></div></button>
      </div>
    </div>

    <div class="ai-feature-group">
      <div class="ai-feature-group-label">Essays</div>
      <div class="ai-btn-grid">
        <button class="ai-btn ai-btn-wide" onclick="aiArgumentStrengthener()"><div class="ai-btn-icon"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M18 8h1a4 4 0 0 1 0 8h-1"/><path d="M2 8h16v9a4 4 0 0 1-4 4H6a4 4 0 0 1-4-4V8z"/><line x1="6" y1="1" x2="6" y2="4"/><line x1="10" y1="1" x2="10" y2="4"/><line x1="14" y1="1" x2="14" y2="4"/></svg></div><div class="ai-btn-text"><div class="ai-btn-label">Argument Strengthener</div><div class="ai-btn-desc">Find counterarguments & improve your thesis</div></div></button>
        <button class="ai-btn ai-btn-wide" onclick="aiCitationSuggester()"><div class="ai-btn-icon"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/></svg></div><div class="ai-btn-text"><div class="ai-btn-label">Citation Suggester</div><div class="ai-btn-desc">Find what evidence your essay needs</div></div></button>
      </div>
    </div>
    <div id="ai-write-result"></div>`;
}

// ─── STUDY TAB ───────────────────────────────────────────────
function renderAIStudyTab(panel) {
  const _brain = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M9.5 2A2.5 2.5 0 0 1 12 4.5v15a2.5 2.5 0 0 1-4.96-.46 2.5 2.5 0 0 1-2.96-3.08 3 3 0 0 1-.34-5.58 2.5 2.5 0 0 1 1.32-4.24 2.5 2.5 0 0 1 1.98-3A2.5 2.5 0 0 1 9.5 2z"/><path d="M14.5 2A2.5 2.5 0 0 0 12 4.5v15a2.5 2.5 0 0 0 4.96-.46 2.5 2.5 0 0 0 2.96-3.08 3 3 0 0 0 .34-5.58 2.5 2.5 0 0 0-1.32-4.24 2.5 2.5 0 0 0-1.98-3A2.5 2.5 0 0 0 14.5 2z"/></svg>`;
  const _help = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>`;
  const _clip = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M16 4h2a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h2"/><rect x="8" y="2" width="8" height="4" rx="1" ry="1"/></svg>`;
  const _zap = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>`;
  const _scope = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/><line x1="11" y1="8" x2="11" y2="14"/><line x1="8" y1="11" x2="14" y2="11"/></svg>`;
  const _msg = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/></svg>`;
  const _swords = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="14.5 17.5 3 6 3 3 6 3 17.5 14.5"/><line x1="13" y1="19" x2="19" y2="13"/><line x1="16" y1="16" x2="20" y2="20"/><line x1="19" y1="21" x2="21" y2="19"/><polyline points="14.5 6.5 18 3 21 3 21 6 17.5 9.5"/><line x1="5" y1="14" x2="9" y2="18"/><line x1="7" y1="21" x2="21" y2="7"/></svg>`;
  const _gap = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>`;

  panel.innerHTML = renderAISettingsBanner() + `
    <div class="ai-feature-group">
      <div class="ai-feature-group-label">Understand</div>
      <div class="ai-btn-grid">
        <button class="ai-btn ai-btn-wide" onclick="renderFeynmanExplainer()">
          <div class="ai-btn-icon">${_brain}</div>
          <div class="ai-btn-text"><div class="ai-btn-label">Feynman Explainer</div><div class="ai-btn-desc">Any concept explained at 3 depths</div></div>
        </button>
      </div>
    </div>

    <div class="ai-feature-group">
      <div class="ai-feature-group-label">Practice</div>
      <div class="ai-btn-grid">
        <button class="ai-btn" onclick="renderPracticeQuestions()">
          <div class="ai-btn-icon">${_help}</div>
          <div class="ai-btn-label">Practice Questions</div><div class="ai-btn-desc">MCQ, short answer, T/F</div>
        </button>
        <button class="ai-btn" onclick="renderMockExam()">
          <div class="ai-btn-icon">${_clip}</div>
          <div class="ai-btn-label">Mock Exam</div><div class="ai-btn-desc">Full exam from page content</div>
        </button>
        <button class="ai-btn" onclick="renderActiveRecall()">
          <div class="ai-btn-icon">${_zap}</div>
          <div class="ai-btn-label">Active Recall</div><div class="ai-btn-desc">Fresh questions every session</div>
        </button>
        <button class="ai-btn" onclick="renderStudyDiagnostic()">
          <div class="ai-btn-icon">${_scope}</div>
          <div class="ai-btn-label">Diagnostic Test</div><div class="ai-btn-desc">Find your weak spots</div>
        </button>
      </div>
    </div>

    <div class="ai-feature-group">
      <div class="ai-feature-group-label">Interactive — Opens in FlowAI Chat</div>
      <div class="ai-btn-grid">
        <button class="ai-btn" onclick="openFlowAIChatMode('socratic')">
          <div class="ai-btn-icon">${_msg}</div>
          <div class="ai-btn-label">Socratic Tutor</div><div class="ai-btn-desc">Guided questions, not answers</div>
        </button>
        <button class="ai-btn" onclick="openFlowAIChatMode('debate')">
          <div class="ai-btn-icon">${_swords}</div>
          <div class="ai-btn-label">Debate Mode</div><div class="ai-btn-desc">AI argues against your position</div>
        </button>
      </div>
    </div>

    <div class="ai-feature-group">
      <div class="ai-feature-group-label">Gap Analysis</div>
      <div class="ai-btn-grid">
        <button class="ai-btn ai-btn-wide" onclick="renderGapDetector()">
          <div class="ai-btn-icon">${_gap}</div>
          <div class="ai-btn-text"><div class="ai-btn-label">Note Gap Detector</div><div class="ai-btn-desc">Compare notes vs syllabus or past exam</div></div>
        </button>
      </div>
    </div>
    <div id="ai-study-result"></div>`;
}

// ─── ORGANISE TAB ────────────────────────────────────────────
function renderAIOrganiseTab(panel) {
  const _tag = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20.59 13.41l-7.17 7.17a2 2 0 0 1-2.83 0L2 12V2h10l8.59 8.59a2 2 0 0 1 0 2.82z"/><line x1="7" y1="7" x2="7.01" y2="7"/></svg>`;
  const _link = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/></svg>`;
  const _cut = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="6" cy="6" r="3"/><circle cx="6" cy="18" r="3"/><line x1="20" y1="4" x2="8.12" y2="15.88"/><line x1="14.47" y1="14.48" x2="20" y2="20"/><line x1="8.12" y1="8.12" x2="12" y2="12"/></svg>`;
  const _merge = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="18" cy="18" r="3"/><circle cx="6" cy="6" r="3"/><path d="M6 21V9a9 9 0 0 0 9 9"/></svg>`;
  const _cards = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="5" width="20" height="14" rx="2"/><line x1="2" y1="10" x2="22" y2="10"/></svg>`;
  const _cal = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="4" width="18" height="18" rx="2" ry="2"/><line x1="16" y1="2" x2="16" y2="6"/><line x1="8" y1="2" x2="8" y2="6"/><line x1="3" y1="10" x2="21" y2="10"/></svg>`;

  panel.innerHTML = renderAISettingsBanner() + `
    <div class="ai-feature-group">
      <div class="ai-feature-group-label">Smart Organisation</div>
      <div class="ai-btn-grid">
        <button class="ai-btn" onclick="aiAutoTag()">
          <div class="ai-btn-icon">${_tag}</div>
          <div class="ai-btn-label">Auto-Tag Notes</div><div class="ai-btn-desc">AI suggests tags for all pages</div>
        </button>
        <button class="ai-btn" onclick="aiLinkRelated()">
          <div class="ai-btn-icon">${_link}</div>
          <div class="ai-btn-label">Link Related</div><div class="ai-btn-desc">Find connections between notes</div>
        </button>
      </div>
    </div>

    <div class="ai-feature-group">
      <div class="ai-feature-group-label">Reshape Notes</div>
      <div class="ai-btn-grid">
        <button class="ai-btn" onclick="aiSplitNote()">
          <div class="ai-btn-icon">${_cut}</div>
          <div class="ai-btn-label">Split Long Note</div><div class="ai-btn-desc">Split into focused pages</div>
        </button>
        <button class="ai-btn" onclick="renderMergeNotes()">
          <div class="ai-btn-icon">${_merge}</div>
          <div class="ai-btn-label">Merge Notes</div><div class="ai-btn-desc">Combine selected pages into one</div>
        </button>
      </div>
    </div>

    <div class="ai-feature-group">
      <div class="ai-feature-group-label">Generate Content</div>
      <div class="ai-btn-grid">
        <button class="ai-btn" onclick="aiGenFlashcardDeck()">
          <div class="ai-btn-icon">${_cards}</div>
          <div class="ai-btn-label">Create Flashcard Deck</div><div class="ai-btn-desc">From current page</div>
        </button>
        <button class="ai-btn" onclick="aiGenStudyPlanNote()">
          <div class="ai-btn-icon">${_cal}</div>
          <div class="ai-btn-label">Create Study Plan</div><div class="ai-btn-desc">Generate & save as new page</div>
        </button>
      </div>
    </div>
    <div id="ai-organise-result"></div>`;
}

// ─── FLOWAI TAB — Embedded chat with mentor personality ──────
function renderAIFlowAITab(panel) {
  panel.style.padding = '0';
  panel.style.display = 'flex';
  panel.style.flexDirection = 'column';
  panel.style.height = '100%';
  panel.style.overflow = 'hidden';

  // Ensure session storage exists
  flowaiLoadSessionsFromStorage();
  if (!AI.chatSessions) AI.chatSessions = [];
  if (!AI.activeChatId && AI.chatHistory?.length) {
    const sid = 'sess_' + Date.now();
    AI.chatSessions.unshift({ id: sid, title: AI.chatHistory[0]?.content?.slice(0,40) || 'Chat', messages: AI.chatHistory, ts: Date.now() });
    AI.activeChatId = sid;
  }
  const activeSession = AI.chatSessions.find(s => s.id === AI.activeChatId);
  const history = activeSession?.messages || AI.chatHistory || [];
  const showHistory = AI._showChatHistory;
  const therapistMode = AI._therapistMode || false;
  const localBanner = renderFlowAILocalBanner();

  if (typeof AI._flowaiTrainingOptIn === 'undefined' && getFlowAIRuntime()) {
    flowaiEnsureLocalRuntime(false)
      .then(runtime => runtime.getTrainingOptIn())
      .then(value => { AI._flowaiTrainingOptIn = value; })
      .catch(() => {});
  }

  panel.innerHTML = `
    <div class="flowai-topbar">
      <button class="flowai-hist-btn${showHistory?' active':''}" onclick="AI._showChatHistory=!AI._showChatHistory;renderAIPanel()" title="Chat history">
        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="3" y1="12" x2="21" y2="12"/><line x1="3" y1="6" x2="21" y2="6"/><line x1="3" y1="18" x2="21" y2="18"/></svg>
      </button>
      <span class="flowai-topbar-title">${therapistMode ? '🫂 Therapist Mode' : (activeSession ? esc(activeSession.title.slice(0,28)) : 'FlowAI')}</span>
      <button class="flowai-new-btn" onclick="flowaiNewChat()" title="New chat">
        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>
        New
      </button>
    </div>

    <div class="flowai-mode-bar">
      <button class="flowai-mode-chip${!therapistMode?' active':''}" onclick="AI._therapistMode=false;renderAIPanel()">
        <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M9.5 2A2.5 2.5 0 0 1 12 4.5v15a2.5 2.5 0 0 1-4.96-.46 2.5 2.5 0 0 1-2.96-3.08 3 3 0 0 1-.34-5.58 2.5 2.5 0 0 1 1.32-4.24 2.5 2.5 0 0 1 1.98-3A2.5 2.5 0 0 1 9.5 2z"/><path d="M14.5 2A2.5 2.5 0 0 0 12 4.5v15a2.5 2.5 0 0 0 4.96-.46 2.5 2.5 0 0 0 2.96-3.08 3 3 0 0 0 .34-5.58 2.5 2.5 0 0 0-1.32-4.24 2.5 2.5 0 0 0-1.98-3A2.5 2.5 0 0 0 14.5 2z"/></svg>
        Study Assistant
      </button>
      <button class="flowai-mode-chip therapist${therapistMode?' active':''}" onclick="AI._therapistMode=true;flowaiNewChat()">
        <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M20.84 4.61a5.5 5.5 0 0 0-7.78 0L12 5.67l-1.06-1.06a5.5 5.5 0 0 0-7.78 7.78l1.06 1.06L12 21.23l7.78-7.78 1.06-1.06a5.5 5.5 0 0 0 0-7.78z"/></svg>
        Therapist Mode
      </button>
    </div>

    ${localBanner}

    ${therapistMode ? `<div class="therapist-header">
      <div style="display:flex;align-items:center;gap:8px;flex:1">
        <div style="width:32px;height:32px;border-radius:50%;background:linear-gradient(135deg,var(--purple),var(--flowai-therapist-grad-end));display:flex;align-items:center;justify-content:center;color:#fff;font-size:14px">🫂</div>
        <div>
          <div class="therapist-name">FlowAI · Therapist Mode</div>
          <div class="therapist-sub">A safe, supportive space on this device and account.</div>
        </div>
      </div>
      <span class="therapist-badge">Private</span>
    </div>` : ''}

    <div class="flowai-body${showHistory?' hist-open':''}">
      ${showHistory ? `<div class="flowai-history-panel">
        <div class="flowai-history-head">History</div>
        ${AI.chatSessions.length === 0 ? `<div class="flowai-history-empty">No chats yet</div>` :
          AI.chatSessions.map(s => `
            <div class="flowai-history-item${s.id === AI.activeChatId?' active':''}" onclick="flowaiLoadSession('${s.id}')">
              <div class="flowai-history-title">${esc(s.title)}</div>
              <div class="flowai-history-meta">${_fmtRelTime(s.ts)}</div>
              <button class="flowai-history-del" onclick="event.stopPropagation();flowaiDeleteSession('${s.id}')" title="Delete">
                <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
              </button>
            </div>`).join('')}
      </div>` : ''}
      <div class="flowai-chat-pane">
        <div class="flowai-chat-messages" id="flowai-msgs">
          ${history.length === 0 ? `
            <div class="flowai-welcome">
              <div class="flowai-welcome-avatar" style="${therapistMode?'background:linear-gradient(135deg,var(--purple),var(--flowai-therapist-grad-end))':''}">
                ${therapistMode
                  ? `<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M20.84 4.61a5.5 5.5 0 0 0-7.78 0L12 5.67l-1.06-1.06a5.5 5.5 0 0 0-7.78 7.78l1.06 1.06L12 21.23l7.78-7.78 1.06-1.06a5.5 5.5 0 0 0 0-7.78z"/></svg>`
                  : `<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M9.5 2A2.5 2.5 0 0 1 12 4.5v15a2.5 2.5 0 0 1-4.96-.46 2.5 2.5 0 0 1-2.96-3.08 3 3 0 0 1-.34-5.58 2.5 2.5 0 0 1 1.32-4.24 2.5 2.5 0 0 1 1.98-3A2.5 2.5 0 0 1 9.5 2z"/><path d="M14.5 2A2.5 2.5 0 0 0 12 4.5v15a2.5 2.5 0 0 0 4.96-.46 2.5 2.5 0 0 0 2.96-3.08 3 3 0 0 0 .34-5.58 2.5 2.5 0 0 0-1.32-4.24 2.5 2.5 0 0 0-1.98-3A2.5 2.5 0 0 0 14.5 2z"/></svg>`}
              </div>
              <div class="flowai-welcome-text">
                <div class="flowai-welcome-name" style="${therapistMode?'color:var(--purple)':''}">
                  ${therapistMode ? "I'm here for you" : "Hey, I'm FlowAI"}
                </div>
                <div class="flowai-welcome-msg">
                  ${therapistMode
                    ? "This is a judgment-free space. Share what's on your mind — stress, anxiety, feeling overwhelmed. I'll listen and support you."
                    : "Ask me anything about your notes, your day, or what to focus on next."}
                </div>
              </div>
              <div class="flowai-chips">
                ${therapistMode ? `
                  <button class="flowai-chip flowai-chip-therapist" onclick="flowaiSend('I am feeling really stressed and overwhelmed right now')">I'm feeling overwhelmed</button>
                  <button class="flowai-chip flowai-chip-therapist" onclick="flowaiSend('I have been struggling with anxiety about my exams')">Exam anxiety</button>
                  <button class="flowai-chip flowai-chip-therapist" onclick="flowaiSend('I am having trouble sleeping and focusing')">Sleep & focus issues</button>
                  <button class="flowai-chip flowai-chip-therapist" onclick="flowaiSend('I just need someone to talk to right now')">I need to talk</button>
                  <button class="flowai-chip flowai-chip-therapist" onclick="flowaiSend('Help me with breathing exercises to calm down')">Calm me down</button>
                ` : `
                  <button class="flowai-chip" onclick="flowaiSend('How is my day looking?')">How's my day?</button>
                  <button class="flowai-chip" onclick="flowaiSend('What tasks should I focus on today?')">What to focus on?</button>
                  <button class="flowai-chip" onclick="flowaiSend('Add a task to study for my next exam')">Add study task</button>
                  <button class="flowai-chip" onclick="flowaiSend('Start my focus timer')">Start timer</button>
                  <button class="flowai-chip" onclick="flowaiSend('Help me understand something from my notes')">Explain my notes</button>
                  <button class="flowai-chip" onclick="flowaiSend('I am feeling overwhelmed, help me prioritise')">Feeling overwhelmed</button>
                `}
              </div>
            </div>
          ` : history.map((m, idx) => renderFlowAIMessage(m, therapistMode, idx)).join('')}
        </div>
        <div class="flowai-input-row">
          <textarea
            id="flowai-inp"
            class="flowai-textarea"
            placeholder="${therapistMode ? 'Share what\'s on your mind…' : 'Ask FlowAI anything…'}"
            rows="1"
            onkeydown="if(event.key==='Enter'&&!event.shiftKey){event.preventDefault();flowaiSend();}"
            oninput="this.style.height='auto';this.style.height=Math.min(this.scrollHeight,140)+'px'"
          ></textarea>
          <button class="flowai-send-btn" onclick="flowaiSend()" id="flowai-send" style="${therapistMode?'background:linear-gradient(135deg,var(--purple),var(--flowai-therapist-grad-end))':''}">
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><line x1="22" y1="2" x2="11" y2="13"/><polygon points="22 2 15 22 11 13 2 9 22 2"/></svg>
          </button>
        </div>
      </div>
    </div>`;

  const msgs = document.getElementById('flowai-msgs');
  if (msgs && history.length > 0) msgs.scrollTop = msgs.scrollHeight;
  setTimeout(() => document.getElementById('flowai-inp')?.focus(), 50);
}

function _fmtRelTime(ts) {
  if (!ts) return '';
  const diff = Date.now() - ts;
  if (diff < 60000) return 'just now';
  if (diff < 3600000) return Math.floor(diff/60000) + 'm ago';
  if (diff < 86400000) return Math.floor(diff/3600000) + 'h ago';
  return Math.floor(diff/86400000) + 'd ago';
}

function flowaiNewChat() {
  // Save current history to sessions before starting new
  _flowaiSaveCurrentSession();
  AI.activeChatId = null;
  AI.chatHistory = [];
  AI._showChatHistory = false;
  renderAIPanel();
  setTimeout(() => document.getElementById('flowai-inp')?.focus(), 50);
}

function flowaiLoadSession(id) {
  _flowaiSaveCurrentSession();
  const s = AI.chatSessions?.find(s => s.id === id);
  if (!s) return;
  AI.activeChatId = id;
  AI.chatHistory = s.messages;
  AI._showChatHistory = false;
  renderAIPanel();
}

function flowaiDeleteSession(id) {
  AI.chatSessions = (AI.chatSessions || []).filter(s => s.id !== id);
  if (AI.activeChatId === id) { AI.activeChatId = null; AI.chatHistory = []; }
  flowaiPersistSessions();
  renderAIPanel();
}

// Open a specific FlowAI interactive chat mode
function openFlowAIChatMode(mode) {
  if (!ensureFeatureAccess('study_pro', 'Interactive Study Mode')) return;
  _flowaiSaveCurrentSession();
  AI.activeChatId = null;
  AI.chatHistory = [];
  AI._showChatHistory = false;
  AI._therapistMode = false;

  const modes = {
    socratic: {
      title: 'Socratic Tutor',
      system: `You are FlowAI in Socratic Tutor mode. Your job is to help the student understand by asking guiding questions, NOT giving direct answers. When a student asks something, respond with a question that leads them toward the answer themselves. Only confirm when they arrive at correct understanding. Be warm and encouraging throughout. Use their notes context if available.`,
      opener: "What would you like to understand better? I'll guide you there with questions — not answers. ◎"
    },
    debate: {
      title: 'Debate Mode',
      system: `You are FlowAI in Debate Mode. The student will present a position or thesis. Your job is to argue the opposite side with well-reasoned counterarguments to help them sharpen their thinking. Be intellectually rigorous but not hostile. Acknowledge good points, then pivot to challenge them further. End each exchange by asking them to defend or refine their position.`,
      opener: "Debate mode activated. Present your thesis or position — I'll take the opposing side to help you stress-test your arguments. ⚔️"
    }
  };

  const cfg = modes[mode];
  if (!cfg) return;

  // Switch to FlowAI tab and set up chat
  AI._flowaiChatSystem = cfg.system;
  AI.chatHistory = [{ role: 'assistant', content: cfg.opener }];

  // Navigate to FlowAI tab in panel
  const panel = document.getElementById('ai-panel');
  if (panel) {
    // Find and click the FlowAI tab
    const tabs = panel.querySelectorAll('.ai-tab');
    tabs.forEach(t => { if (t.textContent.includes('FlowAI')) t.click(); });
  }
  renderAIPanel();
  setTimeout(() => {
    const inp = document.getElementById('flowai-inp');
    if (inp) inp.focus();
  }, 80);
}

function _flowaiSaveCurrentSession() {
  if (!AI.chatHistory?.length) return;
  if (!AI.chatSessions) AI.chatSessions = [];
  const existing = AI.chatSessions.find(s => s.id === AI.activeChatId);
  if (existing) {
    existing.messages = AI.chatHistory;
    existing.ts = Date.now();
  } else {
    const sid = 'sess_' + Date.now();
    const title = AI.chatHistory[0]?.content?.slice(0,40) || 'New chat';
    AI.chatSessions.unshift({ id: sid, title, messages: [...AI.chatHistory], ts: Date.now() });
    AI.activeChatId = sid;
  }
  // Keep max 30 sessions
  if (AI.chatSessions.length > 30) AI.chatSessions = AI.chatSessions.slice(0, 30);
  flowaiPersistSessions();
}

function renderFlowAIMessage(m, therapistMode, idx) {
  const isAI = m.role === 'assistant';
  const bubbleContent = markdownToHtml(esc(m.content));
  const avStyle = therapistMode && isAI ? 'background:linear-gradient(135deg,var(--purple),var(--flowai-therapist-grad-end))' : '';
  const bubbleExtra = therapistMode && isAI ? 'style="background:linear-gradient(135deg,var(--flowai-therapist-bubble),color-mix(in srgb, var(--flowai-therapist-bubble) 65%, transparent 35%));border-color:color-mix(in srgb, var(--purple) 32%, var(--border) 68%)"' : '';

  let confirmHtml = '';
  if (isAI && m.confirmations && m.confirmations.length) {
    const lines = m.confirmations.map(c => {
      const ok = c.startsWith('✓');
      const label = c.slice(2).trim();
      const color = ok ? 'var(--green)' : 'var(--red)';
      const icon = ok
        ? '<polyline points="20 6 9 17 4 12"/>'
        : '<line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/>';
      return `<div style="display:flex;align-items:flex-start;gap:6px;margin-bottom:3px">
        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="${color}" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" style="flex-shrink:0;margin-top:2px">${icon}</svg>
        <span style="font-size:12.5px;color:${color}">${esc(label)}</span>
      </div>`;
    }).join('');
    confirmHtml = `<div style="background:var(--bg-sidebar);border:1px solid var(--border);border-radius:10px;padding:10px 12px;margin-top:8px">${lines}</div>`;
  }

  let refsHtml = '';
  if (isAI && Array.isArray(m.sourceRefs) && m.sourceRefs.length) {
    refsHtml = `<div style="display:flex;flex-wrap:wrap;gap:6px;margin-top:8px">${m.sourceRefs.map(ref => `
      <span style="font-size:11px;padding:4px 8px;border-radius:999px;background:var(--bg-sidebar);border:1px solid var(--border);color:var(--text-muted)">
        ${esc(ref.title || ref.sourceType)}
      </span>`).join('')}</div>`;
  }

  let suggestedHtml = '';
  if (isAI && Array.isArray(m.suggestedActions) && m.suggestedActions.length) {
    suggestedHtml = `<div style="margin-top:10px">
      <div style="font-size:11px;color:var(--text-faint);margin-bottom:6px;text-transform:uppercase;letter-spacing:.08em">Suggested actions</div>
      <div style="display:flex;flex-direction:column;gap:8px">
        ${m.suggestedActions.map((action, actionIndex) => `
          <div style="padding:10px 12px;border:1px solid var(--border);border-radius:12px;background:var(--bg-sidebar)">
            <div style="display:flex;align-items:flex-start;justify-content:space-between;gap:8px">
              <div>
                <div style="font-size:13px;font-weight:600;color:var(--text)">${esc(action.label || action.type)}</div>
                ${action.rationale ? `<div style="font-size:12px;color:var(--text-muted);margin-top:4px">${esc(action.rationale)}</div>` : ''}
              </div>
              <button class="btn btn-action btn-sm" ${action.applied ? 'disabled' : ''} onclick="flowaiApplySuggestedAction(${idx}, ${actionIndex})">${action.applied ? 'Applied' : 'Apply'}</button>
            </div>
          </div>`).join('')}
      </div>
    </div>`;
  }

  let confidenceHtml = '';
  if (isAI && m.confidenceHint) {
    const hint = String(m.confidenceHint).toLowerCase();
    const level = ['high', 'medium', 'low'].includes(hint) ? hint : 'medium';
    confidenceHtml = `<div class="flowai-confidence-badge ${level}">Confidence: ${esc(level)}</div>`;
  }

  return `<div class="flowai-msg flowai-msg-${m.role}">
    ${isAI ? `<div class="flowai-msg-av" style="${avStyle}">
      ${therapistMode
        ? `<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20.84 4.61a5.5 5.5 0 0 0-7.78 0L12 5.67l-1.06-1.06a5.5 5.5 0 0 0-7.78 7.78l1.06 1.06L12 21.23l7.78-7.78 1.06-1.06a5.5 5.5 0 0 0 0-7.78z"/></svg>`
        : `<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M9.5 2A2.5 2.5 0 0 1 12 4.5v15a2.5 2.5 0 0 1-4.96-.46 2.5 2.5 0 0 1-2.96-3.08 3 3 0 0 1-.34-5.58 2.5 2.5 0 0 1 1.32-4.24 2.5 2.5 0 0 1 1.98-3A2.5 2.5 0 0 1 9.5 2z"/><path d="M14.5 2A2.5 2.5 0 0 0 12 4.5v15a2.5 2.5 0 0 0 4.96-.46 2.5 2.5 0 0 0 2.96-3.08 3 3 0 0 0 .34-5.58 2.5 2.5 0 0 0-1.32-4.24 2.5 2.5 0 0 0-1.98-3A2.5 2.5 0 0 0 14.5 2z"/></svg>`}
    </div>` : ''}
    <div class="flowai-bubble" ${bubbleExtra}>${bubbleContent}${refsHtml}${suggestedHtml}${confirmHtml}${confidenceHtml}</div>
  </div>`;
}

// Warm, patient mentor system prompt
function getFlowAISystem() {
  if (AI._therapistMode) {
    return `You are FlowAI in Therapist Mode — a compassionate, emotionally supportive AI companion built into Axinote.

Your role in this mode:
- You are NOT a clinical therapist and should say so if asked, but you are a warm, empathetic listener.
- Your primary goal is to make the student feel heard, understood, and supported.
- You help with: stress, exam anxiety, overwhelm, motivation issues, burnout, loneliness, self-doubt, sleep struggles.
- Always validate feelings first before offering any practical suggestions.
- Never minimise or dismiss what the student is feeling. "I understand" isn't enough — reflect their specific words back.
- Use gentle, warm language. Short paragraphs. No bullet points unless they help ground the person.
- Sound like a real supportive person: use natural phrasing and contractions, not robotic wording.
- If someone shows signs of serious distress, self-harm, or crisis, gently and compassionately encourage them to speak to a trusted adult, counsellor, or call a helpline. Do not handle crises alone.
- You can suggest grounding exercises (5-4-3-2-1 technique), breathing exercises, journaling prompts, or short mindfulness moments.
- After listening and validating, you may offer to help them break down what's overwhelming them using their Axinote tasks and calendar — but only if they seem ready.
- Never push productivity on someone who is struggling emotionally. Presence first.

You have access to their workspace context below — use it gently and only if relevant:
${getFlowAIContextWithIds()}`;
  }

  const bp = eliteGetStudyProfile();
  const bpPersonality = bp ? `
The student's Study DNA archetype is "${bp.archetype || 'Balanced Learner'}". Their learning style is ${bp.learningStyle || 'mixed'}. Their motivation is primarily ${bp.motivationType || 'mixed'}. Their biggest obstacle is ${bp.biggestObstacle || 'unknown'} and their biggest strength is ${bp.biggestStrength || 'hardwork'}. They have a ${bp.mindset || 'mixed'} mindset pattern. Tailor your tone and suggestions to this profile — don't give generic advice.` : '';

  return `You are FlowAI, the personal AI assistant built into Axinote — a student study workspace.

Your personality:
- You are the user's personal assistant: you know everything about their workspace — notes, tasks, calendar, flashcards, study stats, and their detailed Study DNA profile.
- You are like a knowledgeable older sibling or favourite teacher: warm, encouraging, and genuinely happy to help.
- You never make the student feel bad for not knowing something. Every question is a good question.
- You meet the student exactly where they are. If they are confused, you slow down and try a different angle.
- You celebrate small wins and progress, not just perfect scores.
- You are conversational and warm — not robotic or clinical. Use contractions, be natural.
- Lead with a direct answer in plain language, then add one short practical next step when helpful.
- When someone seems stressed or overwhelmed, acknowledge how they feel before diving into solutions.
${bpPersonality}

Your capabilities as a personal assistant:
- You have full access to the student's workspace: their notes, tasks, calendar events, flashcard decks, study stats, AND their complete Brain Profile (learning style, motivation, sleep habits, stress level, procrastination patterns, focus windows, revision methods).
- You can CREATE, EDIT, and DELETE things in their workspace. Always confirm before deleting.
- You can add tasks, create notes, update calendar events, and modify content directly.
- You can EDIT notes: when you suggest changes to a note's content, include an "Apply to Note" action so the user can press Apply and have those changes written directly into their note.
- Use context naturally — reference their actual content, study profile, and stats, not generic advice.
- Workspace actions (adding tasks, creating pages, starting timer, etc.) are handled automatically before you respond. If the message context says actions were completed, just confirm naturally.
- For note edits and writing help: you can suggest rewrites and the user can apply them.

PERSONALISATION RULES (critical):
- If the student has a Brain Profile, ALWAYS tailor your suggestions to their specific learning style, focus window, stress level, and revision method.
- If they're a visual learner, suggest diagrams and mind maps. If kinesthetic, suggest practice problems. If auditory, suggest teaching-back techniques.
- If their stress is high, always acknowledge it before giving study advice.
- If their focus window is evenings, don't suggest early morning study schedules.
- If they have high procrastination, suggest the smallest possible first step, not a big plan.
- Reference their archetype when relevant (e.g. "As an Exam Athlete, you'll respond well to timed drilling...").

Formatting:
- Use short paragraphs and plain language. Only use markdown when it genuinely helps.
- Keep responses concise. A warm short answer beats a cold long one.
- Never start with "Certainly!", "Of course!", "Great question!", or similar filler.

Here is the student's current workspace context:
${getFlowAIContextWithIds()}`;
}

function parseFlowAIActions(intentRaw) {
  if (!intentRaw) return [];
  const clean = String(intentRaw).trim().replace(/^```(?:json)?\s*/i, '').replace(/\s*```\s*$/, '').trim();
  if (!clean || clean.toLowerCase() === 'null') return [];
  let parsed;
  try {
    parsed = JSON.parse(clean);
  } catch {
    const jsonMatch = clean.match(/(\[[\s\S]*\]|\{[\s\S]*\})/);
    if (!jsonMatch) return [];
    try { parsed = JSON.parse(jsonMatch[1]); } catch { return []; }
  }
  if (Array.isArray(parsed)) return parsed.filter(a => a && typeof a === 'object' && typeof a.type === 'string');
  if (parsed && typeof parsed === 'object') {
    if (Array.isArray(parsed.actions)) return parsed.actions.filter(a => a && typeof a === 'object' && typeof a.type === 'string');
    if (typeof parsed.type === 'string') return [parsed];
  }
  return [];
}

async function flowaiSend(presetMsg) {
  const inp = document.getElementById('flowai-inp');
  const msg = presetMsg || inp?.value?.trim();
  if (!msg) return;
  if (inp && !presetMsg) { inp.value = ''; inp.style.height = 'auto'; }

  AI.chatHistory = AI.chatHistory || [];
  AI.chatHistory.push({ role: 'user', content: msg });

  // Re-render to show user message immediately
  renderAIFlowAITab(document.getElementById('ai-panel-body'));

  // Show typing indicator
  const msgs = document.getElementById('flowai-msgs');
  if (msgs) {
    const typing = document.createElement('div');
    typing.className = 'flowai-msg flowai-msg-assistant';
    typing.id = 'flowai-typing';
    typing.innerHTML = `<div class="flowai-msg-av"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9.5 2A2.5 2.5 0 0 1 12 4.5v15a2.5 2.5 0 0 1-4.96-.46 2.5 2.5 0 0 1-2.96-3.08 3 3 0 0 1-.34-5.58 2.5 2.5 0 0 1 1.32-4.24 2.5 2.5 0 0 1 1.98-3A2.5 2.5 0 0 1 9.5 2z"/><path d="M14.5 2A2.5 2.5 0 0 0 12 4.5v15a2.5 2.5 0 0 0 4.96-.46 2.5 2.5 0 0 0 2.96-3.08 3 3 0 0 0 .34-5.58 2.5 2.5 0 0 0-1.32-4.24 2.5 2.5 0 0 0-1.98-3A2.5 2.5 0 0 0 14.5 2z"/></svg></div><div class="flowai-bubble flowai-typing"><span></span><span></span><span></span></div>`;
    msgs.appendChild(typing);
    msgs.scrollTop = msgs.scrollHeight;
  }

  try {
    await flowaiEnsureLocalRuntime(false);
    const localIntent = AI._therapistMode
      ? 'support'
      : /socratic/i.test(AI._flowaiChatSystem || '')
        ? 'tutor'
        : /debate/i.test(AI._flowaiChatSystem || '')
          ? 'qa'
          : '';
    const history = AI.chatHistory.map(item => ({
      role: item.role,
      content: item.role === 'assistant'
        ? String(item.content || '').replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim()
        : item.content,
    }));
    const result = await runFlowAILocalRequest({
      intent: localIntent,
      history,
      message: msg,
      limits: {
        retrievalTopK: AI._therapistMode ? 4 : 6,
        maxContextChars: AI._therapistMode ? 2200 : 3200,
        outputTokens: AI._therapistMode ? 220 : 320,
      },
    });
    let finalAnswer = String(result?.answer || '').trim();
    let finalRefs = Array.isArray(result?.sourceRefs) ? result.sourceRefs : [];
    let finalActions = Array.isArray(result?.suggestedActions) ? result.suggestedActions : [];
    let finalConfidence = result?.confidenceHint || 'medium';

    if (!AI._therapistMode && flowaiIsWeakLocalResult(result)) {
      try {
        const refined = await flowaiRefineLocalAnswer(msg, history);
        if (refined?.answer) {
          finalAnswer = String(refined.answer).trim();
          finalRefs = Array.isArray(refined.sourceRefs) ? refined.sourceRefs : finalRefs;
          finalActions = Array.isArray(refined.suggestedActions) ? refined.suggestedActions : finalActions;
          finalConfidence = refined.confidenceHint || 'medium';
        }
      } catch (_) {
        // Keep initial local result when refinement fails.
      }
    }
    document.getElementById('flowai-typing')?.remove();

    AI.chatHistory.push({
      role: 'assistant',
      content: finalAnswer || 'I hit a temporary issue answering that. Please try rephrasing your question.',
      sourceRefs: finalRefs,
      suggestedActions: finalActions,
      confidenceHint: finalConfidence,
      confirmations: [],
    });
    _flowaiSaveCurrentSession();

  } catch (e) {
    document.getElementById('flowai-typing')?.remove();
    AI.chatHistory.push({ role: 'assistant', content: `I ran into a small issue — ${flowaiFriendlyError(e)} Could you try again?` });
  }
  renderAIFlowAITab(document.getElementById('ai-panel-body'));
}

// ─── Get full user context string for AI ─────────────────────
function getUserContext() {
  const today = new Date().toISOString().split('T')[0];
  const todayEvents = (S.calendar || []).filter(e => e.date === today || e.start?.startsWith(today));
  const activeTasks = (S.tasks || []).filter(t => !t.completed);
  const overdueTasks = activeTasks.filter(t => t.due && t.due < today);
  const recentPages = (S.pages || []).slice(0, 5);
  const pageContents = recentPages.map(p => ({ title: p.title || 'Untitled', content: getPageTextContent(p).slice(0, 500) }));

  return `User: ${getDisplayName()}
Today: ${today}

TODAY'S CALENDAR EVENTS (${todayEvents.length}):
${todayEvents.map(e => `- ${e.title || 'Event'} at ${e.time || '(no time)'}`).join('\n') || 'No events today'}

ACTIVE TASKS (${activeTasks.length} total, ${overdueTasks.length} overdue):
${activeTasks.slice(0, 15).map(t => `- [${t.status || 'todo'}${t.due ? ', due ' + t.due : ''}${overdueTasks.includes(t) ? ' OVERDUE' : ''}] ${t.title}`).join('\n') || 'No active tasks'}

RECENT NOTES (${recentPages.length}):
${pageContents.map(p => `[${p.title}]: ${p.content}`).join('\n\n') || 'No notes yet'}

STUDY STATS: ${S.studySessions} focus sessions, ${S.studyMinutes} minutes total
FLASHCARD DECKS: ${(S.flashcards || []).length} decks, ${(S.flashcards || []).reduce((a, d) => a + (d.cards || []).length, 0)} cards total
CURRENT PAGE: ${S.view === 'page' && S.page ? `"${S.page.title || 'Untitled'}" — ${getPageTextContent(S.page).slice(0, 300)}` : 'No page open'}`;
}

// Richer context that includes IDs so AI can act on specific items
function getFlowAIContextWithIds() {
  const today = new Date().toISOString().split('T')[0];
  const allTasks = S.tasks || [];
  const activeTasks = allTasks.filter(t => !t.completed);
  const completedTasks = allTasks.filter(t => t.completed);
  const overdueTasks = activeTasks.filter(t => t.due && t.due < today);
  const allEvents = S.calendar || [];
  const todayEvents = allEvents.filter(e => e.date === today);
  const upcomingEvents = allEvents.filter(e => e.date >= today).sort((a, b) => a.date.localeCompare(b.date)).slice(0, 10);
  const recentPages = (S.pages || []).slice(0, 10);
  const dbs = S.databases || [];

  const pomState = S.pom;
  const timerStatus = pomState.on
    ? `Running (${pomState.mode === 'work' ? 'Focus' : 'Break'}, ${Math.floor(pomState.secs / 60)}m ${pomState.secs % 60}s left)`
    : `Stopped (${pomState.mode === 'work' ? 'Focus' : 'Break'} mode, ${Math.floor(pomState.secs / 60)}m ${pomState.secs % 60}s on clock)`;

  const currentPageContent = S.view === 'page' && S.page
    ? `\nCURRENT OPEN PAGE "${S.page.title || 'Untitled'}" (id:${S.page.id}) — FULL CONTENT:\n${getPageTextContent(S.page).slice(0, 2000)}`
    : '';

  return `User: ${getDisplayName()}
Today: ${today}
Timer: ${timerStatus}
Study Stats: ${S.studySessions} sessions, ${S.studyMinutes} minutes total
Current view: ${S.view}${S.view === 'page' && S.page ? ` — page "${S.page.title || 'Untitled'}" (id:${S.page.id})` : ''}
${eliteBrainProfileContext()}
TODAY'S EVENTS (${todayEvents.length}):
${todayEvents.map(e => `- id:${e.id} [${e.time || 'all day'}] "${e.title || 'Event'}"`).join('\n') || 'No events today'}

TASKS — ALL ACTIVE (id | status | priority | due | title):
${activeTasks.slice(0, 25).map(t => `- id:${t.id} [${t.status || 'todo'}${t.priority ? '|' + t.priority : ''}${t.due ? '|due:' + t.due : ''}${overdueTasks.includes(t) ? ' OVERDUE' : ''}] "${t.title}"`).join('\n') || 'No active tasks'}

OVERDUE (${overdueTasks.length}):
${overdueTasks.map(t => `- id:${t.id} [due:${t.due}] "${t.title}"`).join('\n') || 'None overdue'}

COMPLETED TASKS (last 10): ${completedTasks.slice(-10).map(t => `"${t.title}"`).join(', ') || 'None'}

UPCOMING EVENTS (id | date | time | title):
${upcomingEvents.map(e => `- id:${e.id} [${e.date}${e.time ? ' ' + e.time : ''}] "${e.title || 'Event'}"`).join('\n') || 'No upcoming events'}

PAGES (id | title | last updated):
${recentPages.map(p => `- id:${p.id} "${p.title || 'Untitled'}" (${p.updatedAt ? p.updatedAt.slice(0,10) : 'unknown'})`).join('\n') || 'No pages'}

DATABASES (id | title):
${dbs.map(d => `- id:${d.id} "${d.title || 'Untitled Database'}"`).join('\n') || 'No databases'}

FLASHCARD DECKS: ${(S.flashcards || []).length} decks, ${(S.flashcards || []).reduce((a, d) => a + (d.cards || []).length, 0)} cards total
${(S.flashcards || []).map(d => `- id:${d.id} "${d.title}" (${(d.cards||[]).length} cards)`).join('\n')}

RECENT NOTE CONTENT:
${recentPages.slice(0, 5).map(p => `[${p.title || 'Untitled'} — id:${p.id}]: ${getPageTextContent(p).slice(0, 600)}`).join('\n\n') || 'No notes yet'}
${currentPageContent}`;
}

// Converts AI-provided content (markdown string OR array of block objects) into page blocks
function _aiContentToBlocks(content) {
  if (!content) return [{ id: uid(), type: 'text', content: '' }];
  // If it's already an array of block-like objects, normalise them
  if (Array.isArray(content)) {
    return content.map(b => ({
      id: uid(),
      type: ['h1', 'h2', 'h3', 'text', 'bullet', 'numbered', 'quote', 'callout', 'divider', 'todo'].includes(b.type) ? b.type : 'text',
      content: String(b.content || b.text || ''),
    }));
  }
  // Otherwise treat as a markdown string and convert line-by-line
  const lines = String(content).split('\n');
  const blocks = [];
  for (const line of lines) {
    const t = line.trim();
    if (!t) continue;
    if (t.startsWith('# ')) blocks.push({ id: uid(), type: 'h1', content: t.slice(2) });
    else if (t.startsWith('## ')) blocks.push({ id: uid(), type: 'h2', content: t.slice(3) });
    else if (t.startsWith('### ')) blocks.push({ id: uid(), type: 'h3', content: t.slice(4) });
    else if (t.startsWith('- [ ') || t.startsWith('* [ ')) blocks.push({ id: uid(), type: 'todo', content: t.slice(5), checked: false });
    else if (/^[-*] /.test(t)) blocks.push({ id: uid(), type: 'bullet', content: t.slice(2) });
    else if (/^\d+\. /.test(t)) blocks.push({ id: uid(), type: 'numbered', content: t.replace(/^\d+\. /, '') });
    else if (t.startsWith('> ')) blocks.push({ id: uid(), type: 'quote', content: t.slice(2) });
    else if (t === '---' || t === '***') blocks.push({ id: uid(), type: 'divider', content: '' });
    else blocks.push({ id: uid(), type: 'text', content: t });
  }
  return blocks.length ? blocks : [{ id: uid(), type: 'text', content: '' }];
}

// ─── AI Action Executor ───────────────────────────────────────
// Parses <action>{...}</action> tags from AI response, executes them,
// and returns the clean message text + a list of confirmation labels.
async function executeAIActions(rawResponse) {
  const actionRegex = /<action>([\s\S]*?)<\/action>/gi;
  const actions = [];
  let match;
  while ((match = actionRegex.exec(rawResponse)) !== null) {
    try { actions.push(JSON.parse(match[1].trim())); } catch (e) { console.warn('Bad AI action JSON:', match[1]); }
  }
  // Strip action tags from visible text
  const cleanText = rawResponse.replace(/<action>[\s\S]*?<\/action>/gi, '').replace(/\s{2,}/g, ' ').trim();

  if (!actions.length) return { text: cleanText, confirmations: [] };

  const confirmations = [];
  let needsRender = false;

  for (const action of actions) {
    try {
      switch (action.type) {

        case 'addTask': {
          const id = uid();
          const t = {
            id,
            title: String(action.title || 'New task').slice(0, 200),
            completed: false,
            status: ['todo', 'prog', 'done'].includes(action.status) ? action.status : 'todo',
            priority: ['low', 'medium', 'high'].includes(action.priority) ? action.priority : 'medium',
            due: action.due || '',
            createdAt: new Date().toISOString(),
          };
          S.tasks.push(t);
          await saveData('tasks', { [id]: t });
          confirmations.push(`✓ Task added: "${t.title}"`);
          needsRender = true;
          break;
        }

        case 'deleteTask': {
          const task = S.tasks.find(t => t.id === action.id);
          if (!task) { confirmations.push(`✗ Task not found: ${action.id}`); break; }
          S.tasks = S.tasks.filter(t => t.id !== action.id);
          await delData('tasks/' + action.id);
          confirmations.push(`✓ Task deleted: "${task.title}"`);
          needsRender = true;
          break;
        }

        case 'updateTask': {
          const task = S.tasks.find(t => t.id === action.id);
          if (!task) { confirmations.push(`✗ Task not found: ${action.id}`); break; }
          if (action.title) task.title = String(action.title).slice(0, 200);
          if (['todo', 'prog', 'done'].includes(action.status)) { task.status = action.status; task.completed = action.status === 'done'; }
          if (['low', 'medium', 'high'].includes(action.priority)) task.priority = action.priority;
          if (action.due) task.due = action.due;
          await saveData('tasks', { [task.id]: task });
          confirmations.push(`✓ Task updated: "${task.title}"`);
          needsRender = true;
          break;
        }

        case 'completeTask': {
          const task = S.tasks.find(t => t.id === action.id);
          if (!task) { confirmations.push(`✗ Task not found: ${action.id}`); break; }
          task.completed = true; task.status = 'done';
          await saveData('tasks', { [task.id]: task });
          confirmations.push(`✓ Task marked done: "${task.title}"`);
          needsRender = true;
          break;
        }

        case 'addCalEvent': {
          if (!action.title || !action.date) { confirmations.push('✗ Calendar event needs title and date'); break; }
          const id = uid();
          const ev = {
            id,
            title: String(action.title).slice(0, 200),
            date: action.date,
            time: action.time || '',
            description: action.description || '',
            color: action.color || 'blue',
            category: action.category || 'study',
            repeat: 'none',
          };
          S.calendar.push(ev);
          await saveData('calendar', { [id]: ev });
          confirmations.push(`✓ Event added: "${ev.title}" on ${ev.date}`);
          needsRender = true;
          break;
        }

        case 'deleteCalEvent': {
          const ev = S.calendar.find(e => e.id === action.id);
          if (!ev) { confirmations.push(`✗ Event not found: ${action.id}`); break; }
          S.calendar = S.calendar.filter(e => e.id !== action.id);
          await delData('calendar/' + action.id);
          confirmations.push(`✓ Event deleted: "${ev.title}"`);
          needsRender = true;
          break;
        }

        case 'startTimer': {
          if (!S.pom.on) {
            pomToggle();
            confirmations.push(`✓ Focus timer started (${Math.floor((S.pom._workSecs || 25 * 60) / 60)}m)`);
          } else {
            confirmations.push('ℹ Timer is already running');
          }
          break;
        }

        case 'stopTimer': {
          if (S.pom.on) {
            pomToggle();
            confirmations.push('✓ Timer paused');
          } else {
            confirmations.push('ℹ Timer is not running');
          }
          break;
        }

        case 'resetTimer': {
          pomReset();
          confirmations.push('✓ Timer reset');
          break;
        }

        case 'deletePage': {
          const page = S.pages.find(p => p.id === action.id);
          if (!page) { confirmations.push(`✗ Page not found: ${action.id}`); break; }
          S.pages = S.pages.filter(p => p.id !== action.id);
          await delData('pages/' + action.id);
          if (S.page?.id === action.id) { S.page = null; S.view = 'home'; }
          confirmations.push(`✓ Page deleted: "${page.title || 'Untitled'}"`);
          needsRender = true;
          break;
        }

        case 'renamePage': {
          const page = S.pages.find(p => p.id === action.id);
          if (!page) { confirmations.push(`✗ Page not found: ${action.id}`); break; }
          const oldTitle = page.title || 'Untitled';
          page.title = String(action.title || 'Untitled').slice(0, 200);
          if (S.page?.id === action.id) S.page.title = page.title;
          await saveData('pages', { [page.id]: page });
          confirmations.push(`✓ Page renamed: "${oldTitle}" → "${page.title}"`);
          needsRender = true;
          break;
        }

        case 'createPage': {
          const now = new Date().toISOString();
          const id = uid();
          // Convert content array or markdown string to blocks
          const blocks = _aiContentToBlocks(action.content || action.blocks || []);
          const page = {
            id,
            title: String(action.title || 'Untitled').slice(0, 200),
            description: action.description || '',
            blocks,
            tags: [],
            createdAt: now,
            updatedAt: now,
          };
          S.pages.unshift(page);
          await saveData('pages', { [id]: page });
          confirmations.push(`✓ Page created: "${page.title}"`);
          needsRender = true;
          break;
        }

        case 'appendToPage': {
          // Append content to an existing page (or the currently open page if no id)
          const targetId = action.id || S.page?.id;
          const page = S.pages.find(p => p.id === targetId);
          if (!page) { confirmations.push('✗ No page found to append to — open a page first or provide an id'); break; }
          if (!page.blocks) page.blocks = [];
          const newBlocks = _aiContentToBlocks(action.content || action.blocks || []);
          page.blocks.push(...newBlocks);
          page.updatedAt = new Date().toISOString();
          if (S.page?.id === page.id) S.page.blocks = page.blocks;
          await saveData('pages', { [page.id]: page });
          confirmations.push(`✓ Added ${newBlocks.length} block${newBlocks.length !== 1 ? 's' : ''} to "${page.title || 'Untitled'}"`);
          needsRender = true;
          break;
        }

        case 'editPage': {
          // Replace or rewrite the full content of a page
          const targetId = action.id || S.page?.id;
          const page = S.pages.find(p => p.id === targetId);
          if (!page) { confirmations.push('✗ No page found — open a page first or provide an id'); break; }
          if (action.title) page.title = String(action.title).slice(0, 200);
          if (action.content || action.blocks) {
            page.blocks = _aiContentToBlocks(action.content || action.blocks || []);
          }
          page.updatedAt = new Date().toISOString();
          if (S.page?.id === page.id) { S.page.blocks = page.blocks; if (action.title) S.page.title = page.title; }
          await saveData('pages', { [page.id]: page });
          confirmations.push(`✓ Page updated: "${page.title || 'Untitled'}"`);
          needsRender = true;
          break;
        }

        case 'deleteDatabase': {
          const db = S.databases.find(d => d.id === action.id);
          if (!db) { confirmations.push(`✗ Database not found: ${action.id}`); break; }
          S.databases = S.databases.filter(d => d.id !== action.id);
          await delData('databases/' + action.id);
          if (S.page?.id === action.id) { S.page = null; S.view = 'home'; }
          confirmations.push(`✓ Database deleted: "${db.title || 'Untitled'}"`);
          needsRender = true;
          break;
        }

        case 'renameDatabase': {
          const db = S.databases.find(d => d.id === action.id);
          if (!db) { confirmations.push(`✗ Database not found: ${action.id}`); break; }
          const oldTitle = db.title || 'Untitled';
          db.title = String(action.title || 'Untitled Database').slice(0, 200);
          if (S.page?.id === action.id) S.page.title = db.title;
          await saveData('databases', { [db.id]: db });
          confirmations.push(`✓ Database renamed: "${oldTitle}" → "${db.title}"`);
          needsRender = true;
          break;
        }

        case 'createMockExam': {
          const questions = Array.isArray(action.questions) ? action.questions : [];
          if (!questions.length) { confirmations.push('✗ Mock exam needs at least one question'); break; }
          const exam = {
            id: uid(),
            title: String(action.title || 'FlowAI Mock Exam').slice(0, 200),
            subject: String(action.subject || S.page?.title || 'General').slice(0, 200),
            duration: String(action.duration || '30 min'),
            source: 'ai',
            questions: questions.map((q, idx) => ({
              id: q.id || `q${idx + 1}`,
              type: q.type === 'mcq' ? 'multiple_choice' : (q.type || 'short_answer'),
              text: q.text || q.question || `Question ${idx + 1}`,
              options: Array.isArray(q.options) ? q.options : undefined,
              correctIndex: typeof q.correctIndex === 'number' ? q.correctIndex : undefined,
              answerKey: q.answerKey || q.model_answer || '',
              marks: Number(q.marks) || 2,
            })),
            createdAt: new Date().toISOString(),
            completedAt: null,
            lastScore: null,
          };
          if (!S.mockExams) S.mockExams = [];
          S.mockExams.push(exam);
          if (S.user?.uid) {
            try {
              await window.fb.set(window.fb.ref(window.fb.database, `users/${S.user.uid}/mockExams/${exam.id}`), exam);
            } catch (_) {}
          }
          confirmations.push(`✓ Mock exam created: "${exam.title}"`);
          needsRender = true;
          break;
        }

        default:
          console.warn('Unknown AI action type:', action.type);
      }
    } catch (e) {
      console.error('AI action error:', action.type, e);
      confirmations.push(`✗ Action failed: ${action.type} — ${e.message}`);
    }
  }

  if (needsRender) {
    // If the currently open page was modified, refresh its blocks immediately
    if (S.view === 'page' && S.page) {
      setTimeout(() => { renderBlocks(); renderApp(); }, 50);
    } else {
      setTimeout(() => renderApp(), 100);
    }
  }

  return { text: cleanText, confirmations };
}

async function aiSummariseDay() {
  if (!ensureFeatureAccess('flowai', 'AI Day Summary')) return;
  const rc = getResultContainer('ai-day-result');
  showAILoading(rc, 'Gathering your day…');
  try {
    const result = await runFlowAILocalRequest({
      intent: 'summarise',
      message: 'Summarise my day using my tasks, calendar, and current notes. Keep it warm, concise, and practical.',
      limits: { retrievalTopK: 6, maxContextChars: 2800, outputTokens: 180 },
    });
    rc.innerHTML = renderFlowAIResultCard('Your Day', result, "openAIChatFromResult(this,'daySummary')");
    rc._result = result.answer;
  } catch (e) { showAIError(rc, e.message); }
}

async function aiWeeklyBriefing() {
  const rc = getResultContainer('ai-day-result');
  showAILoading(rc, 'Reviewing your week…');
  try {
    const result = await runFlowAILocalRequest({
      intent: 'summarise',
      message: 'Give me a weekly briefing based on my tasks, notes, projects, and study activity. Include what I accomplished, what matters next, and three practical recommendations.',
      limits: { retrievalTopK: 8, maxContextChars: 3200, outputTokens: 220 },
    });
    rc.innerHTML = renderFlowAIResultCard('Weekly Briefing', result, "openAIChatFromResult(this,'weeklyBriefing')");
    rc._result = result.answer;
  } catch (e) { showAIError(rc, e.message); }
}

async function aiOverdueTasks() {
  if (!ensureFeatureAccess('flowai', 'AI Task Review')) return;
  const rc = getResultContainer('ai-day-result');
  showAILoading(rc, 'Checking overdue tasks…');
  try {
    const result = await runFlowAILocalRequest({
      intent: 'prioritise',
      message: 'Review my overdue and urgent tasks. Tell me what to tackle first today and why.',
      limits: { retrievalTopK: 6, maxContextChars: 2400, outputTokens: 180 },
    });
    rc.innerHTML = renderFlowAIResultCard('Task Review', result, "openAIChatFromResult(this,'overdueTasks')");
  } catch (e) { showAIError(rc, e.message); }
}

async function aiStudyPlanFromContext() {
  if (!ensureFeatureAccess('study_plus', 'AI Study Plan')) return;
  const rc = getResultContainer('ai-day-result');
  showAILoading(rc, 'Building your personalised study plan…');
  try {
    const bp = eliteGetStudyProfile();
    const persona = bp
      ? `Build it for a ${bp.archetype || 'student'} with ${bp.learningStyle || 'mixed'} learning preferences, ${(bp.focusWindow || 'evening').replace('_', ' ')} focus window, and ${bp.sessionMins || 25}-minute natural study sessions.`
      : '';
    const result = await runFlowAILocalRequest({
      intent: 'plan',
      message: `Create a realistic 7-day study plan from my workspace. ${persona}`,
      limits: { retrievalTopK: 8, maxContextChars: 3400, outputTokens: 240 },
    });
    rc.innerHTML = renderFlowAIResultCard(bp ? `Study Plan for ${bp.archetype || 'You'}` : 'Study Plan', result, "openAIChatFromResult(this,'studyPlan')");
  } catch (e) { showAIError(rc, e.message); }
}

async function aiSummariseAllNotes() {
  const rc = getResultContainer('ai-day-result');
  showAILoading(rc, 'Reading all your notes…');
  try {
    const result = await runFlowAILocalRequest({
      intent: 'summarise',
      message: 'Create a digest of all my notes. Identify major topics, key concepts, and any obvious knowledge gaps.',
      limits: { retrievalTopK: 8, maxContextChars: 3400, outputTokens: 220 },
    });
    rc.innerHTML = renderFlowAIResultCard('Notes Digest', result, "openAIChatFromResult(this,'notesDigest')");
  } catch (e) { showAIError(rc, e.message); }
}

async function aiAskAnything() {
  if (!ensureFeatureAccess('flowai', 'AI Ask')) return;
  const inp = document.getElementById('day-ai-input');
  const q = inp?.value?.trim();
  if (!q) return toast('Type your question first');
  const rc = getResultContainer('ai-day-result');
  showAILoading(rc, 'Thinking…');
  try {
    const result = await runFlowAILocalRequest({
      intent: 'qa',
      message: q,
      limits: { retrievalTopK: 6, maxContextChars: 2800, outputTokens: 180 },
    });
    rc.innerHTML = renderFlowAIResultCard('FlowAI', result, `openAIChatWithQuestion('${q.replace(/'/g, "\\'").replace(/\n/g, ' ')}')`);
    if (inp) inp.value = '';
  } catch (e) { showAIError(rc, e.message); }
}

// ─── AI Chat View ─────────────────────────────────────────────
function openAIChat() {
  AI.chatHistory = [];
  AI.chatActionLabel = 'New Chat';
  AI.chatSystem = `You are FlowAI, a smart and friendly study assistant integrated into Axinote. You have access to the user's full workspace context. Be helpful, concise, and use markdown formatting. Here is the user's current workspace context:\n\n${getUserContext()}`;
  navigate('aiChat');
}

function openAIChatFromResult(btn, label) {
  const result = btn?.closest('.ai-result')?.querySelector('.ai-result-body')?.textContent || '';
  AI.chatHistory = [
    { role: 'assistant', content: result }
  ];
  AI.chatActionLabel = label || 'FlowAI Chat';
  AI.chatSystem = `You are FlowAI, a smart and friendly study assistant integrated into Axinote. Continue this conversation. Here is the user's current workspace context:\n\n${getUserContext()}`;
  closeAIPanel();
  navigate('aiChat');
}

function openAIChatWithQuestion(question) {
  AI.chatHistory = [];
  AI.chatActionLabel = 'FlowAI Chat';
  AI.chatSystem = `You are FlowAI, a smart and friendly study assistant integrated into Axinote. You have access to the user's full workspace context. Be helpful, concise, and use markdown formatting. Here is the user's current workspace context:\n\n${getUserContext()}`;
  closeAIPanel();
  navigate('aiChat');
  // Auto-submit the question after render
  setTimeout(() => {
    const inp = document.getElementById('ai-chat-inp');
    if (inp) { inp.value = question; submitAIChat(); }
  }, 100);
}

// Open chat from a specific AI action button in the panel
function openAIChatAction(label, systemAddition, userMessage) {
  AI.chatHistory = [];
  AI.chatActionLabel = label;
  AI.chatSystem = `You are FlowAI, a smart and friendly study assistant integrated into Axinote. ${systemAddition}\n\nHere is the user's current workspace context:\n\n${getUserContext()}`;
  closeAIPanel();
  navigate('aiChat');
  setTimeout(() => {
    if (userMessage) {
      AI.chatHistory = [];
      submitAIChatMessage(userMessage);
    }
  }, 100);
}

// ─── AI DASHBOARD ────────────────────────────────────────────

function renderTierCards(currentTier) {
  return `<h2 style="font-size:18px;font-weight:700;margin-bottom:16px">Upgrade Your Plan</h2>
    <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px;margin-bottom:32px">
      ${Object.entries(CREDIT_TIERS).map(([key, t]) => {
        const isCurrent = currentTier === key;
        const priceHtml = t.price === 0 ? 'Free' : `$${t.price}<span style="font-size:13px;font-weight:500">/mo</span>`;
        const actionHtml = isCurrent
          ? `<div style="font-size:12px;color:var(--accent);font-weight:600">Current Plan</div>`
          : `<button class="btn btn-action btn-sm" style="width:100%" onclick="openUpgradeLink('${key}')">Upgrade</button>`;
        return `<div class="ai-dash-tier${isCurrent ? ' ai-dash-tier-current' : ''}">
          <div style="font-weight:800;font-size:16px;color:${isCurrent ? 'var(--accent)' : 'var(--text)'}">${t.label}${isCurrent ? ' ✓' : ''}</div>
          <div style="font-size:24px;font-weight:800;margin:8px 0">${priceHtml}</div>
          <div style="font-size:13px;color:var(--text-muted);margin-bottom:10px">${t.credits.toLocaleString()} credits ${t.renewable ? '/ month' : '(one-time)'}</div>
          ${actionHtml}
        </div>`;
      }).join('')}
    </div>`;
}

function eliteExamEvents() {
  const out = [];
  const today = new Date().toISOString().slice(0, 10);
  if (S.userProfile?.examDate && S.userProfile.examDate >= today) {
    out.push({ date: S.userProfile.examDate, title: 'Primary Exam Date', tagged: true, source: 'profile' });
  }
  (S.calendar || []).forEach(e => {
    if (!e?.date || e.date < today) return;
    const tags = eliteEventTags(e);
    const tagged = e.category === 'exam' || tags.includes('exam');
    const keywordMatch = /(exam|test|quiz|paper|assessment)/i.test(`${e.title || ''} ${e.description || ''}`);
    if (tagged || keywordMatch) out.push({ date: e.date, title: e.title || 'Exam', tagged, source: tagged ? 'tag' : 'keyword' });
  });
  out.sort((a, b) => String(a.date).localeCompare(String(b.date)) || Number(b.tagged) - Number(a.tagged));
  return out.slice(0, 5);
}

const ELITE_PROFILE_QUIZ = [
  { id: 'ageBand', q: 'Age group', o: [{ v: '12_13', l: '12-13' }, { v: '14_15', l: '14-15' }, { v: '16_17', l: '16-17' }, { v: '18_plus', l: '18+' }] },
  { id: 'weekdayStudy', q: 'Weekday study hours (outside school)', o: [{ v: 'lt1', l: '< 1h/day' }, { v: '1_2', l: '1-2h/day' }, { v: '2_4', l: '2-4h/day' }, { v: 'gt4', l: '> 4h/day' }] },
  { id: 'weekendStudy', q: 'Weekend study hours', o: [{ v: 'lt2', l: '< 2h/day' }, { v: '2_4', l: '2-4h/day' }, { v: '4_6', l: '4-6h/day' }, { v: 'gt6', l: '> 6h/day' }] },
  { id: 'ccaLoad', q: 'CCA / commitments workload', o: [{ v: 'light', l: 'Light' }, { v: 'medium', l: 'Medium' }, { v: 'heavy', l: 'Heavy' }, { v: 'very_heavy', l: 'Very heavy' }] },
  { id: 'stress', q: 'Current stress level', o: [{ v: 'low', l: 'Low' }, { v: 'moderate', l: 'Moderate' }, { v: 'high', l: 'High' }, { v: 'very_high', l: 'Very high' }] },
  { id: 'sleep', q: 'Average sleep on school nights', o: [{ v: 'lt6', l: '< 6h' }, { v: '6_7', l: '6-7h' }, { v: '7_8', l: '7-8h' }, { v: 'gt8', l: '> 8h' }] },
  { id: 'focusWindow', q: 'Best focus window', o: [{ v: 'early', l: 'Early morning' }, { v: 'afternoon', l: 'Afternoon' }, { v: 'evening', l: 'Evening' }, { v: 'late_night', l: 'Late night' }] },
  { id: 'scheduleQuality', q: 'How planned is your weekly schedule?', o: [{ v: 'chaotic', l: 'Chaotic' }, { v: 'some_plan', l: 'Some plan' }, { v: 'structured', l: 'Structured' }, { v: 'highly_structured', l: 'Highly structured' }] },
  { id: 'pastPaperFreq', q: 'How often do you do timed past papers?', o: [{ v: 'never', l: 'Almost never' }, { v: 'monthly', l: 'Monthly' }, { v: 'weekly', l: 'Weekly' }, { v: 'multi_weekly', l: '2-3x weekly' }] },
  { id: 'revisionMethod', q: 'Main revision method', o: [{ v: 'passive', l: 'Re-reading notes' }, { v: 'mixed', l: 'Mix of notes + practice' }, { v: 'active_recall', l: 'Active recall heavy' }, { v: 'exam_drill', l: 'Past-paper heavy' }] },
  { id: 'burnoutRisk', q: 'How often do you feel burnt out?', o: [{ v: 'rare', l: 'Rarely' }, { v: 'sometimes', l: 'Sometimes' }, { v: 'often', l: 'Often' }, { v: 'constant', l: 'Almost always' }] },
  { id: 'support', q: 'Support around your studies', o: [{ v: 'strong', l: 'Strong support' }, { v: 'moderate', l: 'Some support' }, { v: 'limited', l: 'Limited support' }, { v: 'none', l: 'Mostly on my own' }] },
];

function eliteEventTags(ev) {
  const tags = [];
  if (Array.isArray(ev?.tags)) tags.push(...ev.tags);
  else if (typeof ev?.tags === 'string') tags.push(...ev.tags.split(','));
  const text = `${ev?.title || ''} ${ev?.description || ''}`;
  (text.match(/#([a-z0-9_-]+)/ig) || []).forEach(t => tags.push(t.replace(/^#/, '')));
  return Array.from(new Set(tags.map(t => String(t || '').trim().toLowerCase()).filter(Boolean)));
}
// ═══════════════════════════════════════════════════════════════════════════
// ─── ELITE BRAIN PROFILE — Full User Intelligence System ───────────────────
// ═══════════════════════════════════════════════════════════════════════════

const BRAIN_QUIZ_QUESTIONS = [
  // ─ BLOCK 1: WHO ARE YOU ─────────────────────────────────────────────────
  {
    id: 'name', block: 1, type: 'text', required: true,
    q: "What's your first name?",
    hint: "We'll use this everywhere to personalise your experience.",
    placeholder: "e.g. Aiden"
  },
  {
    id: 'ageBand', block: 1, type: 'choice',
    q: "How old are you?",
    choices: [
      { v: '12_13', label: '12–13', sub: 'Lower Secondary' },
      { v: '14_15', label: '14–15', sub: 'Upper Secondary' },
      { v: '16_17', label: '16–17', sub: 'Pre-University / JC' },
      { v: '18_plus', label: '18+', sub: 'University / Beyond' },
    ]
  },
  {
    id: 'schoolType', block: 1, type: 'choice',
    q: "What type of school are you in?",
    choices: [
      { v: 'secondary', label: 'Secondary School' },
      { v: 'jc', label: 'Junior College / Pre-U' },
      { v: 'poly', label: 'Polytechnic' },
      { v: 'uni', label: 'University' },
      { v: 'international', label: 'International School' },
      { v: 'other', label: 'Other / Self-Study' },
    ]
  },
  {
    id: 'targetGrade', block: 1, type: 'choice',
    q: "What's your current overall grade target?",
    hint: "Be honest — this is private and helps us calibrate your plan.",
    choices: [
      { v: 'distinction', label: 'Distinctions across the board', sub: 'A1s / 7s / Distinction' },
      { v: 'mostly_good', label: 'Mostly Bs, a few As', sub: 'B3–A2 range' },
      { v: 'pass_well', label: 'Pass everything comfortably', sub: 'C5+ / Pass' },
      { v: 'just_pass', label: 'Just need to pass', sub: 'Minimum threshold' },
      { v: 'improve', label: 'Big improvement from current', sub: 'Any progress counts' },
    ]
  },

  // ─ BLOCK 2: HOW YOU LEARN ────────────────────────────────────────────────
  {
    id: 'learningStyle', block: 2, type: 'choice',
    q: "When you're learning something new, what helps it click the most?",
    hint: "Based on the VARK model — there's no wrong answer.",
    choices: [
      { v: 'visual', label: 'Diagrams, colour-coding, mind maps', sub: 'Visual learner' },
      { v: 'auditory', label: 'Talking it through, teaching others', sub: 'Auditory learner' },
      { v: 'reading', label: 'Reading & taking detailed notes', sub: 'Reading/Writing learner' },
      { v: 'kinesthetic', label: 'Practice problems & doing it', sub: 'Kinaesthetic learner' },
      { v: 'mixed', label: 'A mix of all of them', sub: 'Multimodal learner' },
    ]
  },
  {
    id: 'memoryStrength', block: 2, type: 'choice',
    q: "How would you describe your memory?",
    choices: [
      { v: 'strong', label: 'I remember things easily', sub: 'Strong retention' },
      { v: 'decent', label: 'Decent — if I review regularly', sub: 'Needs reinforcement' },
      { v: 'weak', label: 'I forget quickly after studying', sub: 'Needs spaced practice' },
      { v: 'selective', label: 'Great for some things, terrible for others', sub: 'Selective memory' },
    ]
  },
  {
    id: 'revisionMethod', block: 2, type: 'choice',
    q: "How do you usually revise for exams?",
    choices: [
      { v: 'passive', label: 'Re-read notes / highlight', sub: 'Passive review' },
      { v: 'mixed', label: 'Mix of notes + some practice Qs', sub: 'Semi-active' },
      { v: 'active_recall', label: 'Flashcards, self-testing, active recall', sub: 'Active recall' },
      { v: 'exam_drill', label: 'Past papers only — full exam conditions', sub: 'Exam drilling' },
    ]
  },
  {
    id: 'procrastination', block: 2, type: 'choice',
    q: "How often do you procrastinate on study tasks?",
    choices: [
      { v: 'rarely', label: 'Rarely — I usually just start', sub: 'Low procrastination' },
      { v: 'sometimes', label: 'Sometimes — depends on the subject', sub: 'Moderate' },
      { v: 'often', label: 'Often — I delay until pressure builds', sub: 'High procrastination' },
      { v: 'chronic', label: "Almost always — I struggle to start", sub: 'Need task structure' },
    ]
  },

  // ─ BLOCK 3: YOUR SCHEDULE & HABITS ──────────────────────────────────────
  {
    id: 'focusWindow', block: 3, type: 'choice',
    q: "When do you feel most mentally sharp and focused?",
    hint: "Based on chronobiology — your biological peak performance window.",
    choices: [
      { v: 'early_morning', label: 'Early morning (5–8am)', sub: 'Lark / Early bird' },
      { v: 'morning', label: 'Mid-morning (8–12pm)', sub: 'Morning peak' },
      { v: 'afternoon', label: 'Afternoon (12–5pm)', sub: 'Afternoon peak' },
      { v: 'evening', label: 'Evening (5–9pm)', sub: 'Evening peak' },
      { v: 'night', label: 'Late night (9pm–1am)', sub: 'Night owl' },
    ]
  },
  {
    id: 'sessionLength', block: 3, type: 'choice',
    q: "What's your natural focus span before your mind wanders?",
    hint: "Honest answers give better Pomodoro intervals for you.",
    choices: [
      { v: 'lt15', label: 'Less than 15 minutes', sub: 'Need micro-sessions' },
      { v: '15_30', label: '15–30 minutes', sub: 'Short burst learner' },
      { v: '30_60', label: '30–60 minutes', sub: 'Standard Pomodoro' },
      { v: 'gt60', label: '60+ minutes deep dives', sub: 'Deep focus mode' },
    ]
  },
  {
    id: 'weekdayStudy', block: 3, type: 'choice',
    q: "On school weekdays, how many hours do you actually study?",
    choices: [
      { v: 'lt1', label: 'Less than 1 hour', sub: 'Very light' },
      { v: '1_2', label: '1–2 hours', sub: 'Light study' },
      { v: '2_4', label: '2–4 hours', sub: 'Moderate' },
      { v: 'gt4', label: '4+ hours', sub: 'Heavy study' },
    ]
  },
  {
    id: 'weekendStudy', block: 3, type: 'choice',
    q: "On weekends, how much do you study?",
    choices: [
      { v: 'lt2', label: 'Under 2 hours total', sub: 'Light weekend' },
      { v: '2_4', label: '2–4 hours', sub: 'Moderate weekend' },
      { v: '4_6', label: '4–6 hours', sub: 'Heavy weekend' },
      { v: 'gt6', label: '6+ hours', sub: 'Full grind weekends' },
    ]
  },
  {
    id: 'sleep', block: 3, type: 'choice',
    q: "How much sleep do you usually get on school nights?",
    hint: "Sleep is when the brain consolidates memory — this matters a lot.",
    choices: [
      { v: 'lt6', label: 'Under 6 hours', sub: 'Sleep-deprived zone' },
      { v: '6_7', label: '6–7 hours', sub: 'Below optimal' },
      { v: '7_8', label: '7–8 hours', sub: 'Healthy range' },
      { v: 'gt8', label: '8+ hours', sub: 'Well-rested' },
    ]
  },

  // ─ BLOCK 4: WELLBEING & CONTEXT ─────────────────────────────────────────
  {
    id: 'stress', block: 4, type: 'choice',
    q: "How would you describe your overall stress level right now?",
    choices: [
      { v: 'low', label: 'Low — pretty chilled', sub: 'Optimal learning state' },
      { v: 'moderate', label: 'Moderate — manageable', sub: 'Performance zone' },
      { v: 'high', label: 'High — often anxious', sub: 'Cortisol impact on memory' },
      { v: 'very_high', label: 'Very high — overwhelmed', sub: 'Needs burnout protection' },
    ]
  },
  {
    id: 'ccaLoad', block: 4, type: 'choice',
    q: "How intense is your CCA / extracurricular load?",
    choices: [
      { v: 'none', label: 'None / minimal', sub: 'Maximum study bandwidth' },
      { v: 'light', label: 'Light — 1–2 sessions/week', sub: 'Small impact' },
      { v: 'medium', label: 'Medium — 3–4 sessions/week', sub: 'Moderate impact' },
      { v: 'heavy', label: 'Heavy — near daily', sub: 'Significant impact on hours' },
    ]
  },
  {
    id: 'burnoutRisk', block: 4, type: 'choice',
    q: "How often do you feel burned out or mentally drained?",
    choices: [
      { v: 'rare', label: 'Rarely — I recover well', sub: 'Resilient baseline' },
      { v: 'sometimes', label: 'Sometimes after big pushes', sub: 'Periodic recovery needed' },
      { v: 'often', label: 'Often — I feel drained weekly', sub: 'Burnout protection needed' },
      { v: 'constant', label: 'Almost constantly', sub: 'Urgent recovery protocol' },
    ]
  },
  {
    id: 'support', block: 4, type: 'choice',
    q: "How strong is your support system for studying?",
    hint: "Teachers, tutors, friends, family — all count.",
    choices: [
      { v: 'strong', label: 'Strong — I have people to turn to', sub: 'Supported learner' },
      { v: 'moderate', label: 'Some — a tutor or one friend', sub: 'Moderate support' },
      { v: 'limited', label: 'Limited — mostly self-reliant', sub: 'Independent learner' },
      { v: 'none', label: 'None — I do this entirely alone', sub: 'Solo learner' },
    ]
  },

  // ─ BLOCK 5: MINDSET & MOTIVATION ────────────────────────────────────────
  {
    id: 'motivationType', block: 5, type: 'choice',
    q: "What's your biggest driver for doing well in school?",
    choices: [
      { v: 'grades', label: 'Getting the grades / results', sub: 'Outcome-driven' },
      { v: 'understanding', label: 'Actually understanding the subject', sub: 'Mastery-driven' },
      { v: 'career', label: 'Future career / university goals', sub: 'Goal-driven' },
      { v: 'competition', label: 'Being among the top students', sub: 'Competitive-driven' },
      { v: 'family', label: 'Family expectations & pride', sub: 'Relational-driven' },
      { v: 'mixed', label: 'A combination of the above', sub: 'Multi-motivated' },
    ]
  },
  {
    id: 'mindset', block: 5, type: 'choice',
    q: "When you get a bad result, what's your first instinct?",
    hint: "Based on Carol Dweck's mindset research.",
    choices: [
      { v: 'growth', label: "I figure out what went wrong and fix it", sub: 'Strong growth mindset' },
      { v: 'mixed', label: "I'm frustrated but I try to move on", sub: 'Mixed mindset' },
      { v: 'fixed', label: "I start doubting if I'm even good at this", sub: 'Tends toward fixed mindset' },
      { v: 'avoidant', label: "I put it away and try not to think about it", sub: 'Avoidant response' },
    ]
  },
  {
    id: 'studyEnvironment', block: 5, type: 'choice',
    q: "Where do you study best?",
    choices: [
      { v: 'home_quiet', label: 'Home — quiet room', sub: 'Low stimulus environment' },
      { v: 'home_music', label: 'Home — with music or background noise', sub: 'Moderate stimulus' },
      { v: 'library', label: 'Library / study area', sub: 'Structured environment' },
      { v: 'cafe', label: 'Café or public space', sub: 'Ambient noise learner' },
      { v: 'school', label: 'At school (after hours)', sub: 'Institutional context' },
      { v: 'anywhere', label: 'Anywhere — I adapt easily', sub: 'Flexible learner' },
    ]
  },
  {
    id: 'biggestObstacle', block: 5, type: 'choice',
    q: "What's your single biggest obstacle to studying better right now?",
    choices: [
      { v: 'phone', label: 'Phone / social media distraction', sub: 'Digital distraction' },
      { v: 'time', label: 'Not enough time', sub: 'Time scarcity' },
      { v: 'motivation', label: 'Low motivation / not feeling like it', sub: 'Drive deficit' },
      { v: 'understanding', label: "I don't understand the content", sub: 'Content gap' },
      { v: 'anxiety', label: 'Exam anxiety / fear of failure', sub: 'Performance anxiety' },
      { v: 'plan', label: "I don't know where to start", sub: 'Planning gap' },
    ]
  },
  {
    id: 'biggestStrength', block: 5, type: 'choice',
    q: "What's your biggest academic strength?",
    choices: [
      { v: 'hardwork', label: 'I put in the hours when I need to', sub: 'Work ethic' },
      { v: 'understanding', label: 'I understand concepts deeply', sub: 'Conceptual strength' },
      { v: 'memory', label: 'I remember things well', sub: 'Memory strength' },
      { v: 'writing', label: 'I express myself well in writing', sub: 'Communication strength' },
      { v: 'speed', label: 'I work quickly under pressure', sub: 'Speed strength' },
      { v: 'consistency', label: 'I show up consistently', sub: 'Consistency strength' },
    ]
  },
];

// ─── Brain Profile Storage ────────────────────────────────────────────────
function eliteQuizStorageKey() { return `fd_elite_quiz_${S.user?.uid || 'anon'}`; }
function eliteGetStudyProfile() {
  if (S.userProfile?.studyProfile && typeof S.userProfile.studyProfile === 'object') return S.userProfile.studyProfile;
  try { return JSON.parse(localStorage.getItem(eliteQuizStorageKey()) || 'null') || null; } catch (_) { return null; }
}

async function eliteSaveBrainProfile(profile) {
  try {
    // Save to localStorage as backup
    localStorage.setItem(eliteQuizStorageKey(), JSON.stringify(profile));
    // Save to Firebase profile
    if (S.user?.uid) {
      await window.fb.update(window.fb.ref(window.fb.database, `users/${S.user.uid}/profile`), {
        studyProfile: profile,
        brainProfileVersion: 2,
        brainProfileUpdatedAt: new Date().toISOString(),
        // Sync name if provided
        ...(profile.answers?.name ? { name: profile.answers.name } : {}),
        // Sync age if provided
        ...(profile.age ? { age: profile.age } : {}),
      });
      // Update in-memory state too
      if (!S.userProfile) S.userProfile = {};
      S.userProfile.studyProfile = profile;
      if (profile.answers?.name) S.userProfile.name = profile.answers.name;
      if (profile.age) S.userProfile.age = profile.age;
    }
  } catch (e) { console.warn('Brain profile save error:', e); }
}

function eliteMapQuizToProfile(answers = {}) {
  const n = (v, map, d = 0) => map[v] ?? d;
  const ageMap = { '12_13': 13, '14_15': 15, '16_17': 16, '18_plus': 18 };

  // ── Derived numeric scores ────────────────────────────────────────────────
  const weekdayStudyHrs  = n(answers.weekdayStudy, { lt1: 0.7, '1_2': 1.6, '2_4': 3, gt4: 4.5 }, 1.5);
  const weekendStudyHrs  = n(answers.weekendStudy, { lt2: 1.2, '2_4': 3, '4_6': 5, gt6: 7 }, 3);
  const ccaLoad          = n(answers.ccaLoad, { none: 0, light: 1, medium: 2, heavy: 3 }, 1);
  const stressLevel      = n(answers.stress, { low: 1, moderate: 2, high: 3, very_high: 4 }, 2);
  const sleepHours       = n(answers.sleep, { lt6: 5.5, '6_7': 6.5, '7_8': 7.5, gt8: 8.4 }, 6.8);
  const burnoutRisk      = n(answers.burnoutRisk, { rare: 1, sometimes: 2, often: 3, constant: 4 }, 2);
  const supportScore     = n(answers.support, { strong: 4, moderate: 3, limited: 2, none: 1 }, 3);
  const procrastScore    = n(answers.procrastination, { rarely: 1, sometimes: 2, often: 3, chronic: 4 }, 2);
  const revisionScore    = n(answers.revisionMethod, { passive: 1, mixed: 2, active_recall: 3, exam_drill: 4 }, 2);
  const sessionMins      = n(answers.sessionLength, { lt15: 12, '15_30': 22, '30_60': 45, gt60: 75 }, 30);

  // ── Study DNA archetype ───────────────────────────────────────────────────
  // Combines learning style + revision method + motivation to produce an archetype
  const archetype = (() => {
    const ls = answers.learningStyle || 'mixed';
    const rm = answers.revisionMethod || 'mixed';
    const mt = answers.motivationType || 'mixed';
    if (rm === 'exam_drill' || mt === 'competition') return 'Exam Athlete';
    if (ls === 'visual' && rm !== 'passive') return 'Visual Strategist';
    if (ls === 'auditory' || ls === 'kinesthetic') return 'Active Processor';
    if (mt === 'understanding' || ls === 'reading') return 'Deep Thinker';
    if (procrastScore >= 3 && stressLevel >= 3) return 'Pressure Performer';
    if (weekdayStudyHrs + weekendStudyHrs * 0.4 > 4 && burnoutRisk <= 2) return 'Steady Grinder';
    return 'Balanced Learner';
  })();

  // ── Scientific study recommendations based on profile ────────────────────
  const recommendations = [];

  // Memory & retention (Ebbinghaus / spaced repetition)
  if (answers.memoryStrength === 'weak' || answers.memoryStrength === 'selective') {
    recommendations.push({ type: 'memory', title: 'Spaced Repetition is essential for you', method: 'Use Axinote flashcards with daily 10-min review. Review day 1, day 3, day 7, day 14 after first learning. This directly fights the Ebbinghaus forgetting curve.' });
  }
  if (answers.revisionMethod === 'passive') {
    recommendations.push({ type: 'method', title: 'Switch from passive to active recall', method: 'Re-reading notes has only 10% retention after 24h. Replace with: close the book, write everything you remember, then check. This doubles retention in the same time.' });
  }

  // Sleep & memory consolidation (Diekelmann & Born 2010)
  if (sleepHours < 7) {
    recommendations.push({ type: 'sleep', title: 'Sleep debt is erasing your revision', method: `You average ~${sleepHours}h. Memory consolidation requires 7-8h — hippocampal replay of the day's learning happens during deep sleep. Gaining even 45min more sleep will improve retention noticeably.` });
  }

  // Focus timing (chronobiology)
  const focusTips = {
    early_morning: 'Schedule hardest subjects 5–9am when cortisol naturally peaks. Use evenings only for easy review.',
    morning: 'Your 8–12pm window is your prime time. Block distractions, phone away, tackle hardest subjects first.',
    afternoon: 'Use afternoons for active problem-solving. Avoid passive re-reading, which is less effective at this time.',
    evening: 'Evening focus is natural for you. Use afternoons for lighter tasks and build toward your 5–9pm deep work window.',
    night: 'Night work is fine, but ensure 7–8h sleep still. Consider shifting one hard subject to just before bed — sleep will consolidate it.',
  };
  if (answers.focusWindow && focusTips[answers.focusWindow]) {
    recommendations.push({ type: 'timing', title: `Optimise your ${answers.focusWindow.replace('_', ' ')} peak window`, method: focusTips[answers.focusWindow] });
  }

  // Pomodoro calibration
  const pomLabel = sessionMins <= 15 ? '10/5 micro-sessions' : sessionMins <= 30 ? '20/5 short Pomodoros' : sessionMins <= 60 ? '25/5 classic Pomodoro' : '50/10 deep work blocks';
  recommendations.push({ type: 'focus', title: `Your optimal session: ${pomLabel}`, method: `Based on your natural focus span (~${sessionMins}min), use the ${pomLabel} structure. Trying to push beyond your natural window causes quality to drop sharply.` });

  // Learning style specific methods
  const lsMethods = {
    visual: 'Create mind maps, colour-coded summaries, and flowcharts for every major topic. Visualise processes, not just facts.',
    auditory: 'Record yourself explaining key concepts and play them back. Teach out loud to a chair, a pet, or a friend. Discussion-based revision works best for you.',
    reading: 'Cornell note-taking format and structured written summaries are your power tool. Transform bullet points into full explanatory paragraphs.',
    kinesthetic: 'Active problem-solving over theory. Every concept must be applied immediately — do a past paper question within 30 minutes of learning something new.',
    mixed: 'Rotate methods: watch/read, then explain aloud, then apply through practice problems. This multimodal approach maximises your connections.',
  };
  const lsKey = answers.learningStyle || 'mixed';
  if (lsMethods[lsKey]) {
    recommendations.push({ type: 'style', title: `Your learning style: ${lsKey.charAt(0).toUpperCase() + lsKey.slice(1)} learner`, method: lsMethods[lsKey] });
  }

  // Stress & performance (Yerkes-Dodson law)
  if (stressLevel >= 3) {
    recommendations.push({ type: 'stress', title: 'High stress is impairing your working memory', method: 'Elevated cortisol blocks the prefrontal cortex — literally making you think slower. Use 4-7-8 breathing (inhale 4s, hold 7s, exhale 8s) before study sessions. 5 minutes of this is proven to lower cortisol.' });
  }

  // Burnout protection
  if (burnoutRisk >= 3) {
    recommendations.push({ type: 'burnout', title: 'Burnout protection protocol needed', method: 'You show high burnout risk. Build mandatory recovery into your plan: one full rest day per week (no study guilt), 20-min walk daily, and cap study at 5h per day max regardless of exam proximity.' });
  }

  // Procrastination strategies
  if (procrastScore >= 3) {
    const procrastFixes = {
      phone: 'Use app blockers (Forest, Focus Mode) during study. Leave phone in another room — just seeing it costs ~20min of mental bandwidth.',
      time: 'Time-blocking: assign specific tasks to specific 1-hour slots. Unscheduled time creates procrastination opportunities.',
      motivation: 'Implementation intention: "I will study X at Y time in Z place" is proven to triple follow-through vs general intent.',
      plan: 'Use the 2-minute rule: if you know the first step, you can start. FlowAI can break any task into first steps for you.',
    };
    const fix = procrastFixes[answers.biggestObstacle] || 'Break each session into the smallest possible starting task — just open the book and read one paragraph.';
    recommendations.push({ type: 'procrastination', title: 'Procrastination-breaking strategy for you', method: fix });
  }

  // Mindset (Dweck growth mindset research)
  if (answers.mindset === 'fixed' || answers.mindset === 'avoidant') {
    recommendations.push({ type: 'mindset', title: 'Reframe mistakes as data, not failure', method: 'Research shows adding "yet" to negative thoughts ("I can\'t do this... yet") activates growth circuits. After every bad result, spend 5min writing: what specifically went wrong, and one concrete change for next time.' });
  }

  // Support system
  if (supportScore <= 2) {
    recommendations.push({ type: 'support', title: 'Build your support network', method: 'Self-reliant learners plateau faster. Use Axinote Study Groups to create accountability. Even one peer to compare notes with weekly improves outcomes by ~15%.' });
  }

  // ── Weekly study hour estimate ────────────────────────────────────────────
  const weeklyStudyHrs = (weekdayStudyHrs * 5 + weekendStudyHrs * 2).toFixed(1);

  // ── Available bandwidth for studying ─────────────────────────────────────
  const ccaHoursWeekly = ccaLoad * 3;
  const dailyAvailableHrs = Math.max(0.5, 4 - (ccaLoad * 0.5) - (stressLevel * 0.3) - (sleepHours < 7 ? 0.5 : 0)).toFixed(1);

  return {
    answers,
    archetype,
    age: ageMap[answers.ageBand] || null,
    weekdayStudyHrs,
    weekendStudyHrs,
    weeklyStudyHrs: parseFloat(weeklyStudyHrs),
    ccaLoad,
    stressLevel,
    sleepHours,
    focusWindow: answers.focusWindow || 'evening',
    sessionMins,
    revisionScore,
    burnoutRisk,
    supportScore,
    procrastScore,
    dailyAvailableHrs: parseFloat(dailyAvailableHrs),
    learningStyle: answers.learningStyle || 'mixed',
    motivationType: answers.motivationType || 'mixed',
    mindset: answers.mindset || 'mixed',
    studyEnvironment: answers.studyEnvironment || 'home_quiet',
    biggestObstacle: answers.biggestObstacle || 'motivation',
    biggestStrength: answers.biggestStrength || 'hardwork',
    recommendations,
    completedAt: new Date().toISOString(),
    version: 2,
  };
}

// ─── Build rich brain profile context string for AI ──────────────────────
function eliteBrainProfileContext() {
  const bp = eliteGetStudyProfile();
  if (!bp) return '';
  const a = bp.answers || {};
  const archLabel = bp.archetype || 'Balanced Learner';
  const lsLabel = { visual: 'Visual', auditory: 'Auditory', reading: 'Reading/Writing', kinesthetic: 'Kinaesthetic', mixed: 'Multimodal' }[bp.learningStyle] || 'Multimodal';
  const mtLabel = { grades: 'Grade-driven', understanding: 'Mastery-driven', career: 'Career-driven', competition: 'Competitive', family: 'Family-driven', mixed: 'Multi-motivated' }[bp.motivationType] || 'Mixed';
  const rwLabel = { passive: 'Passive re-reading', mixed: 'Mixed methods', active_recall: 'Active recall/flashcards', exam_drill: 'Exam drilling' }[a.revisionMethod] || 'Mixed';
  const focusLabel = (a.focusWindow || 'evening').replace('_', ' ');
  const procrastLabel = { rarely: 'Low', sometimes: 'Moderate', often: 'High', chronic: 'Very high' }[a.procrastination] || 'Moderate';
  const mindsetLabel = { growth: 'Growth mindset', mixed: 'Mixed mindset', fixed: 'Fixed mindset tendencies', avoidant: 'Avoidance pattern' }[a.mindset] || 'Mixed';
  const obstacleLabel = { phone: 'Phone/social media', time: 'Not enough time', motivation: 'Low motivation', understanding: 'Content gaps', anxiety: 'Exam anxiety', plan: 'No clear plan' }[bp.biggestObstacle] || 'Unknown';
  const strengthLabel = { hardwork: 'Work ethic', understanding: 'Deep understanding', memory: 'Strong memory', writing: 'Writing ability', speed: 'Speed under pressure', consistency: 'Consistency' }[bp.biggestStrength] || 'Unknown';

  return `
╔══ STUDENT BRAIN PROFILE (Elite Personalisation) ══╗
Name: ${a.name || getDisplayName()}
Study DNA Archetype: ${archLabel}
Age: ${bp.age || 'Not specified'}
Learning Style (VARK): ${lsLabel}
Motivation Driver: ${mtLabel}
Peak Focus Window: ${focusLabel}
Natural Focus Span: ~${bp.sessionMins}min sessions
Revision Method: ${rwLabel}
Mindset Pattern: ${mindsetLabel}
Weekly Study Hours: ~${bp.weeklyStudyHrs}h/week
Sleep: ~${bp.sleepHours}h/night
Stress Level: ${['Low', 'Moderate', 'High', 'Very high'][bp.stressLevel - 1] || 'Moderate'}
Burnout Risk: ${['Resilient', 'Moderate risk', 'High risk', 'Critical risk'][bp.burnoutRisk - 1] || 'Moderate risk'}
CCA Load: ${['None', 'Light', 'Medium', 'Heavy'][bp.ccaLoad] || 'Medium'}
Support System: ${['None', 'Limited', 'Moderate', 'Strong'][bp.supportScore - 1] || 'Moderate'}
Procrastination Level: ${procrastLabel}
Biggest Obstacle: ${obstacleLabel}
Biggest Strength: ${strengthLabel}
Study Environment: ${(a.studyEnvironment || 'home').replace('_', ' ')}
Scientific Recs: ${(bp.recommendations || []).map(r => r.title).join(' | ')}
Profile Completed: ${bp.completedAt ? bp.completedAt.slice(0, 10) : 'Unknown'}
╚═══════════════════════════════════════════════════╝`;
}

// ─── Dynamic Brain Quiz Modal ─────────────────────────────────────────────
function eliteOpenBrainQuiz() {
  const existing = eliteGetStudyProfile();
  const modal = document.createElement('div');
  modal.id = 'brain-quiz-overlay';
  modal.style.cssText = 'position:fixed;inset:0;z-index:999;background:rgba(0,0,0,.6);backdrop-filter:blur(4px);display:flex;align-items:center;justify-content:center;padding:16px';
  modal.innerHTML = `<div id="brain-quiz-modal" style="background:var(--card);border-radius:20px;width:100%;max-width:560px;max-height:90vh;overflow-y:auto;box-shadow:0 24px 60px rgba(0,0,0,.28)"></div>`;
  document.body.appendChild(modal);
  modal.onclick = e => { if (e.target === modal) eliteCloseBrainQuiz(); };
  window._brainQuizAnswers = existing?.answers ? { ...existing.answers } : {};
  window._brainQuizStep = 0;
  _renderBrainQuizStep();
}

function eliteCloseBrainQuiz() {
  document.getElementById('brain-quiz-overlay')?.remove();
  window._brainQuizAnswers = null;
  window._brainQuizStep = 0;
}

function _renderBrainQuizStep() {
  const modal = document.getElementById('brain-quiz-modal');
  if (!modal) return;
  const q = BRAIN_QUIZ_QUESTIONS[window._brainQuizStep];
  const total = BRAIN_QUIZ_QUESTIONS.length;
  const pct = Math.round((window._brainQuizStep / total) * 100);
  const ans = window._brainQuizAnswers || {};
  const blockNames = ['', 'Who you are', 'How you learn', 'Your schedule', 'Your wellbeing', 'Mindset & motivation'];
  const blockName = blockNames[q.block] || '';

  let choiceHtml = '';
  if (q.type === 'choice') {
    choiceHtml = `<div style="display:grid;gap:8px;margin-top:16px">` +
      (q.choices || []).map(c => `
        <button class="bq-choice${ans[q.id] === c.v ? ' bq-selected' : ''}" onclick="_brainQuizSelectChoice('${q.id}','${c.v}')" style="text-align:left;border:1.5px solid ${ans[q.id] === c.v ? 'var(--accent)' : 'var(--border)'};border-radius:12px;padding:11px 14px;background:${ans[q.id] === c.v ? 'var(--accent-bg)' : 'var(--bg-sec)'};cursor:pointer;transition:.12s">
          <div style="font-size:14px;font-weight:600;color:var(--text)">${esc(c.label)}</div>
          ${c.sub ? `<div style="font-size:12px;color:var(--text-muted);margin-top:2px">${esc(c.sub)}</div>` : ''}
        </button>`).join('') + `</div>`;
  } else if (q.type === 'text') {
    choiceHtml = `<div style="margin-top:16px">
      <input id="bq-text-inp" class="form-input" placeholder="${esc(q.placeholder || '')}" value="${esc(ans[q.id] || '')}" style="font-size:15px;padding:12px 14px"
        oninput="window._brainQuizAnswers['${q.id}']=this.value"
        onkeydown="if(event.key==='Enter')_brainQuizNext()">
    </div>`;
  }

  const canNext = q.type === 'text'
    ? (!q.required || (ans[q.id] || '').trim().length > 0)
    : !!ans[q.id];

  const isLast = window._brainQuizStep === total - 1;

  modal.innerHTML = `
    <div style="padding:24px">
      <!-- Header -->
      <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:16px">
        <div style="display:flex;align-items:center;gap:8px">
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="var(--accent)" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M2 15c6.667-6 13.333 0 20-6"/><path d="M9 22c1.798-1.998 2.518-3.995 2.807-5.993"/><path d="M15 2c-1.798 1.998-2.518 3.995-2.807 5.993"/><path d="m2 9 3 .36"/><path d="m19.7 14.36 3 .36"/><path d="M5 6.09l.6 2.58"/><path d="m18.4 15.33.6 2.58"/><path d="m6.52 17 1.98 1.5"/><path d="m17.48 7-1.98-1.5"/></svg>
          <div>
            <div style="font-size:12px;font-weight:700;color:var(--text-muted);text-transform:uppercase;letter-spacing:.08em">Study DNA · Block ${q.block}</div>
            <div style="font-size:13px;font-weight:600;color:var(--accent)">${esc(blockName)}</div>
          </div>
        </div>
        <button onclick="eliteCloseBrainQuiz()" style="background:none;border:none;cursor:pointer;color:var(--text-muted);font-size:18px;padding:4px">✕</button>
      </div>

      <!-- Progress bar -->
      <div style="height:4px;background:var(--border);border-radius:999px;margin-bottom:22px;overflow:hidden">
        <div style="height:100%;width:${pct}%;background:linear-gradient(90deg,var(--accent),var(--purple));border-radius:999px;transition:.3s"></div>
      </div>
      <div style="font-size:12px;color:var(--text-faint);margin-bottom:2px">Question ${window._brainQuizStep + 1} of ${total}</div>

      <!-- Question -->
      <div style="font-size:17px;font-weight:700;color:var(--text);line-height:1.4;margin-bottom:4px">${esc(q.q)}</div>
      ${q.hint ? `<div style="font-size:12px;color:var(--text-muted);margin-top:4px;line-height:1.5">${esc(q.hint)}</div>` : ''}

      ${choiceHtml}

      <!-- Navigation -->
      <div style="display:flex;gap:10px;margin-top:22px;align-items:center">
        ${window._brainQuizStep > 0 ? `<button class="btn btn-ghost btn-sm" onclick="_brainQuizBack()">← Back</button>` : '<div></div>'}
        <div style="flex:1"></div>
        ${!isLast
          ? `<button class="btn btn-action btn-sm${canNext ? '' : ''}" onclick="_brainQuizNext()" ${canNext ? '' : 'disabled style="opacity:.45;cursor:not-allowed"'}>Next →</button>`
          : `<button class="btn btn-action${canNext ? '' : ''}" onclick="_brainQuizFinish()" ${canNext ? '' : 'disabled style="opacity:.45;cursor:not-allowed"'} style="padding:10px 24px">
              Build my Study DNA
             </button>`
        }
      </div>

      ${window._brainQuizStep === 0 ? `<div style="margin-top:16px;padding:12px 14px;background:var(--accent-bg);border-radius:10px;border:1px solid var(--accent);font-size:12px;color:var(--text-muted);line-height:1.55">
        <strong style="color:var(--accent)">Why this quiz?</strong> Your answers build a Science-backed Study DNA profile. FlowAI uses it to give you advice tailored specifically to how your brain works — not generic tips.
      </div>` : ''}
    </div>`;

  // Auto-focus text input
  if (q.type === 'text') {
    setTimeout(() => document.getElementById('bq-text-inp')?.focus(), 50);
  }
  // Auto-advance on choice selection
  if (q.type === 'choice' && ans[q.id]) {
    // Already selected, user might click again — allow it
  }
}

function _brainQuizNext() {
  const q = BRAIN_QUIZ_QUESTIONS[window._brainQuizStep];
  const ans = window._brainQuizAnswers || {};
  if (q.required && q.type === 'text' && !(ans[q.id] || '').trim()) {
    document.getElementById('bq-text-inp')?.focus();
    return;
  }
  if (window._brainQuizStep < BRAIN_QUIZ_QUESTIONS.length - 1) {
    window._brainQuizStep++;
    _renderBrainQuizStep();
  }
}

function _brainQuizBack() {
  if (window._brainQuizStep > 0) {
    window._brainQuizStep--;
    _renderBrainQuizStep();
  }
}

function _brainQuizSelectChoice(qId, value) {
  if (!window._brainQuizAnswers) window._brainQuizAnswers = {};
  window._brainQuizAnswers[qId] = value;
  const isLast = window._brainQuizStep === BRAIN_QUIZ_QUESTIONS.length - 1;
  _renderBrainQuizStep();
  if (!isLast) {
    // Auto-advance after a short visual feedback delay
    setTimeout(() => _brainQuizNext(), 280);
  }
}

async function _brainQuizFinish() {
  const answers = window._brainQuizAnswers || {};
  const profile = eliteMapQuizToProfile(answers);
  // Save to firebase + localStorage
  await eliteSaveBrainProfile(profile);
  eliteCloseBrainQuiz();
  toast('Your Study DNA has been built!');
  // Re-render Elite Suite to show the updated profile
  if (S.view === 'examSuite') {
    const c = document.getElementById('content');
    if (c) navigate('examSuite');
  }
  // Optionally trigger an AI-generated personalised plan
  setTimeout(() => eliteGeneratePersonalisedPlan(profile), 400);
}

// ─── AI-powered personalised plan generation ─────────────────────────────
async function eliteGeneratePersonalisedPlan(bp) {
  if (!bp) return;
  const mount = document.getElementById('elite-personal-plan-output');
  if (!mount) return;
  mount.innerHTML = `<div class="card" style="padding:14px;font-size:13px;color:var(--text-muted)"><span class="flowai-typing"><span></span><span></span><span></span></span> Building your personalised action plan…</div>`;

  const e = eliteInsights();
  const subjects = (e.subjectAverages || []).map(s => `${s.subject}:${s.avg}%`).join(', ') || 'Not yet assessed';
  const upcoming = eliteExamEvents().map(x => `${x.date} ${x.title}`).join('; ') || 'No exam date set';
  const recs = (bp.recommendations || []).map(r => `[${r.type}] ${r.title}: ${r.method}`).join('\n');

  try {
    const system = `You are an elite academic performance coach specialising in Singapore secondary/JC exams. You have deep knowledge of evidence-based learning science: spaced repetition (Ebbinghaus), active recall, interleaving, retrieval practice, sleep and memory consolidation, Yerkes-Dodson stress-performance law, chronobiology (peak cognitive windows), and Dweck's mindset theory.

Your job: Create a hyper-personalised 7-day action plan and key insights for this specific student based on their Study DNA profile. Be direct, specific, and science-backed. No generic advice. Address their specific obstacles and leverage their strengths. Return JSON only:

{"archetype_insight":"2-3 sentences about this student's specific learning archetype and what it means for them","critical_changes":[{"change":"...(specific behaviour change)","why":"...(scientific reason)","how":"...(exact implementation)"}],"daily_schedule":{"focus_blocks":"...(tailored to their focus window and session length)","break_structure":"...(tailored to their burnout risk)","study_subjects_order":"..."},"week_plan":[{"day":"Mon","tasks":["..."]}],"quick_wins":["...(3 things to do TODAY that will have immediate impact based on their profile)"],"biggest_risk":"...(the #1 thing that will derail this student based on their profile)"}`;

    const context = `${eliteBrainProfileContext()}
Track: ${eliteTrackLabel()}
Readiness: ${e.readiness}/100
Avg Score: ${e.avgScore}%
Subjects: ${subjects}
Upcoming exams: ${upcoming}
Weaknesses: ${(e.weaknesses || []).map(w => `${w.subject}:${w.avg}%`).join(', ') || 'None detected yet'}
Scientific recommendations from profile analysis:
${recs}`;

    const out = await callAIJson(system, context, 2000);

    let html = `<div class="card" style="padding:16px;border-color:rgba(139,92,246,.3);background:linear-gradient(180deg,rgba(139,92,246,.06),transparent)">
      <div style="display:flex;align-items:center;gap:8px;margin-bottom:12px">
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="var(--purple)" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M2 15c6.667-6 13.333 0 20-6"/><path d="M9 22c1.798-1.998 2.518-3.995 2.807-5.993"/><path d="M15 2c-1.798 1.998-2.518 3.995-2.807 5.993"/><path d="m2 9 3 .36"/><path d="m19.7 14.36 3 .36"/><path d="M5 6.09l.6 2.58"/><path d="m18.4 15.33.6 2.58"/><path d="m6.52 17 1.98 1.5"/><path d="m17.48 7-1.98-1.5"/></svg>
        <div>
          <div style="font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.08em;color:var(--text-muted)">Your Study DNA Plan</div>
          <div style="font-size:13px;font-weight:700;color:var(--text)">Personalised to ${esc(bp.archetype || 'You')}</div>
        </div>
        <button class="btn btn-ghost btn-sm" style="margin-left:auto;font-size:11px" onclick="eliteOpenBrainQuiz()">Update DNA</button>
      </div>`;

    if (out.archetype_insight) {
      html += `<div style="font-size:13px;color:var(--text);line-height:1.6;margin-bottom:12px;padding:10px 12px;background:var(--bg-sec);border-radius:10px;border-left:3px solid var(--purple)">${esc(out.archetype_insight)}</div>`;
    }

    if (out.quick_wins?.length) {
      html += `<div style="font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.08em;color:var(--green);margin-bottom:6px;display:flex;align-items:center;gap:5px"><svg width="11" height="11" viewBox="0 0 24 24" fill="var(--green)" stroke="var(--green)" stroke-width="2"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg> Do Today</div>`;
      html += `<div style="display:grid;gap:5px;margin-bottom:12px">${out.quick_wins.map(w => `<div style="font-size:12.5px;color:var(--text);padding:8px 10px;background:rgba(61,107,69,.08);border-radius:8px;border-left:2px solid var(--green)">→ ${esc(w)}</div>`).join('')}</div>`;
    }

    if (out.critical_changes?.length) {
      html += `<div style="font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.08em;color:var(--accent);margin-bottom:6px;display:flex;align-items:center;gap:5px"><svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="var(--accent)" stroke-width="2" stroke-linecap="round"><path d="M9 3H5a2 2 0 0 0-2 2v4m6-6h10a2 2 0 0 1 2 2v4M9 3v11m0 0H5a2 2 0 0 1-2-2V9m6 5h10a2 2 0 0 0 2-2V9m-6 9v3m-3 0h6"/></svg> Critical Changes (Science-Backed)</div>`;
      html += `<div style="display:grid;gap:8px;margin-bottom:12px">${out.critical_changes.slice(0, 3).map(c => `
        <div style="padding:10px 12px;background:var(--bg-sec);border-radius:10px">
          <div style="font-size:13px;font-weight:600;color:var(--text)">${esc(c.change || '')}</div>
          <div style="font-size:11.5px;color:var(--text-muted);margin-top:3px"><em>Why:</em> ${esc(c.why || '')}</div>
          <div style="font-size:11.5px;color:var(--accent);margin-top:2px"><em>How:</em> ${esc(c.how || '')}</div>
        </div>`).join('')}</div>`;
    }

    if (out.daily_schedule) {
      const ds = out.daily_schedule;
      html += `<div style="font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.08em;color:var(--blue);margin-bottom:6px"><svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="var(--blue)" stroke-width="2" stroke-linecap="round"><rect x="3" y="4" width="18" height="18" rx="2"/><line x1="16" y1="2" x2="16" y2="6"/><line x1="8" y1="2" x2="8" y2="6"/><line x1="3" y1="10" x2="21" y2="10"/></svg> Your Daily Structure</div>
        <div style="font-size:12.5px;color:var(--text-muted);line-height:1.6;margin-bottom:12px;padding:10px 12px;background:var(--bg-sec);border-radius:10px">
          ${ds.focus_blocks ? `<div><strong>Focus blocks:</strong> ${esc(ds.focus_blocks)}</div>` : ''}
          ${ds.break_structure ? `<div style="margin-top:4px"><strong>Breaks:</strong> ${esc(ds.break_structure)}</div>` : ''}
          ${ds.study_subjects_order ? `<div style="margin-top:4px"><strong>Subject order:</strong> ${esc(ds.study_subjects_order)}</div>` : ''}
        </div>`;
    }

    if (out.biggest_risk) {
      html += `<div style="padding:10px 12px;background:rgba(184,82,30,.07);border-radius:10px;border-left:3px solid var(--accent);font-size:12.5px;color:var(--text)"><strong style="color:var(--accent);display:inline-flex;align-items:center;gap:4px"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="var(--accent)" stroke-width="2" stroke-linecap="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg> Your #1 Risk:</strong> ${esc(out.biggest_risk)}</div>`;
    }

    html += `</div>`;
    mount.innerHTML = html;

  } catch (err) {
    // Fallback: show recommendations from the profile analysis directly (no placeholder data)
    const bp2 = bp || eliteGetStudyProfile();
    if (!bp2?.recommendations?.length) { mount.innerHTML = ''; return; }
    let html = `<div class="card" style="padding:16px;border-color:rgba(139,92,246,.3);background:linear-gradient(180deg,rgba(139,92,246,.06),transparent)">
      <div style="display:flex;align-items:center;gap:8px;margin-bottom:12px">
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="var(--purple)" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M2 15c6.667-6 13.333 0 20-6"/><path d="M9 22c1.798-1.998 2.518-3.995 2.807-5.993"/><path d="M15 2c-1.798 1.998-2.518 3.995-2.807 5.993"/><path d="m2 9 3 .36"/><path d="m19.7 14.36 3 .36"/><path d="M5 6.09l.6 2.58"/><path d="m18.4 15.33.6 2.58"/><path d="m6.52 17 1.98 1.5"/><path d="m17.48 7-1.98-1.5"/></svg>
        <div style="font-size:13px;font-weight:700;color:var(--text)">Your Study DNA — ${esc(bp2.archetype || 'Profile')}</div>
        <button class="btn btn-ghost btn-sm" style="margin-left:auto;font-size:11px" onclick="eliteOpenBrainQuiz()">Update DNA</button>
      </div>
      <div style="display:grid;gap:8px">`;
    bp2.recommendations.slice(0, 5).forEach(r => {
      html += `<div style="padding:10px 12px;background:var(--bg-sec);border-radius:10px">
        <div style="font-size:12.5px;font-weight:600;color:var(--text);margin-bottom:3px">${esc(r.title || '')}</div>
        <div style="font-size:12px;color:var(--text-muted);line-height:1.5">${esc(r.method || '')}</div>
      </div>`;
    });
    html += `</div></div>`;
    mount.innerHTML = html;
  }
}

// ─── Personalisation card for Elite Suite ─────────────────────────────────
function renderElitePersonalisationCard() {
  const bp = eliteGetStudyProfile();
  const name = bp?.answers?.name || getDisplayName();

  if (!bp) {
    return `<div class="card" style="padding:18px;border-style:dashed;border-color:var(--purple);background:linear-gradient(180deg,rgba(139,92,246,.05),transparent)">
      <div style="display:flex;align-items:center;gap:10px;margin-bottom:10px">
        <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="var(--purple)" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M2 15c6.667-6 13.333 0 20-6"/><path d="M9 22c1.798-1.998 2.518-3.995 2.807-5.993"/><path d="M15 2c-1.798 1.998-2.518 3.995-2.807 5.993"/><path d="m2 9 3 .36"/><path d="m19.7 14.36 3 .36"/><path d="M5 6.09l.6 2.58"/><path d="m18.4 15.33.6 2.58"/><path d="m6.52 17 1.98 1.5"/><path d="m17.48 7-1.98-1.5"/></svg>
        <div>
          <div style="font-size:12px;font-weight:700;color:var(--purple);text-transform:uppercase;letter-spacing:.08em">Study DNA</div>
          <div style="font-size:15px;font-weight:700;color:var(--text)">Build Your Brain Profile</div>
        </div>
      </div>
      <div style="font-size:13px;color:var(--text-muted);line-height:1.6;margin-bottom:12px">Answer 20 questions and FlowAI will build a science-backed profile of exactly how your brain works. Every feature — your study plan, FlowAI responses, panic mode, recommendations — gets calibrated to you specifically.</div>
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-bottom:14px">
        <div style="padding:8px 10px;background:rgba(139,92,246,.08);border-radius:8px;font-size:11.5px;color:var(--text-muted);display:flex;align-items:center;gap:6px"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="var(--purple)" stroke-width="2"><path d="M2 3h6a4 4 0 0 1 4 4v14a3 3 0 0 0-3-3H2z"/><path d="M22 3h-6a4 4 0 0 0-4 4v14a3 3 0 0 1 3-3h7z"/></svg> Learning style (VARK)</div>
        <div style="padding:8px 10px;background:rgba(139,92,246,.08);border-radius:8px;font-size:11.5px;color:var(--text-muted);display:flex;align-items:center;gap:6px"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="var(--purple)" stroke-width="2"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg> Peak focus window</div>
        <div style="padding:8px 10px;background:rgba(139,92,246,.08);border-radius:8px;font-size:11.5px;color:var(--text-muted);display:flex;align-items:center;gap:6px"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="var(--purple)" stroke-width="2"><path d="M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3"/><line x1="12" y1="17" x2="12.01" y2="17"/><circle cx="12" cy="12" r="10"/></svg> Memory &amp; recall style</div>
        <div style="padding:8px 10px;background:rgba(139,92,246,.08);border-radius:8px;font-size:11.5px;color:var(--text-muted);display:flex;align-items:center;gap:6px"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="var(--purple)" stroke-width="2"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg> Motivation type</div>
        <div style="padding:8px 10px;background:rgba(139,92,246,.08);border-radius:8px;font-size:11.5px;color:var(--text-muted);display:flex;align-items:center;gap:6px"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="var(--purple)" stroke-width="2"><path d="M17 18a5 5 0 0 0-10 0"/><line x1="12" y1="2" x2="12" y2="9"/><line x1="4.22" y1="10.22" x2="5.64" y2="11.64"/><line x1="1" y1="18" x2="3" y2="18"/><line x1="21" y1="18" x2="23" y2="18"/><line x1="18.36" y1="11.64" x2="19.78" y2="10.22"/></svg> Sleep &amp; burnout risk</div>
        <div style="padding:8px 10px;background:rgba(139,92,246,.08);border-radius:8px;font-size:11.5px;color:var(--text-muted);display:flex;align-items:center;gap:6px"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="var(--purple)" stroke-width="2"><circle cx="12" cy="12" r="10"/><polyline points="12 8 12 12 14 14"/></svg> Procrastination pattern</div>
      </div>
      <button class="btn btn-action" style="width:100%" onclick="eliteOpenBrainQuiz()">Build My Study DNA (5 min)</button>
    </div>`;
  }

  // Profile exists — show rich summary
  const archetype = bp.archetype || 'Balanced Learner';
  const lsIcons = {
    visual: '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>',
    auditory: '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M3 18v-6a9 9 0 0 1 18 0v6"/><path d="M21 19a2 2 0 0 1-2 2h-1a2 2 0 0 1-2-2v-3a2 2 0 0 1 2-2h3zM3 19a2 2 0 0 0 2 2h1a2 2 0 0 0 2-2v-3a2 2 0 0 0-2-2H3z"/></svg>',
    reading: '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M2 3h6a4 4 0 0 1 4 4v14a3 3 0 0 0-3-3H2z"/><path d="M22 3h-6a4 4 0 0 0-4 4v14a3 3 0 0 1 3-3h7z"/></svg>',
    kinesthetic: '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M18 8h1a4 4 0 0 1 0 8h-1"/><path d="M2 8h16v9a4 4 0 0 1-4 4H6a4 4 0 0 1-4-4V8z"/><line x1="6" y1="1" x2="6" y2="4"/><line x1="10" y1="1" x2="10" y2="4"/><line x1="14" y1="1" x2="14" y2="4"/></svg>',
    mixed: '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><polyline points="16 3 21 3 21 8"/><line x1="4" y1="20" x2="21" y2="3"/><polyline points="21 16 21 21 16 21"/><line x1="15" y1="15" x2="21" y2="21"/></svg>'
  };
  const lsIcon = lsIcons[bp.learningStyle] || '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>';
  const lsLabel = { visual: 'Visual', auditory: 'Auditory', reading: 'Reading/Writing', kinesthetic: 'Kinaesthetic', mixed: 'Multimodal' }[bp.learningStyle] || 'Multimodal';
  const focusLabel = (bp.focusWindow || 'evening').replace('_', ' ');
  const stressBar = Math.min(100, ((bp.stressLevel || 1) / 4) * 100);
  const stressColor = bp.stressLevel >= 3 ? 'var(--red)' : bp.stressLevel === 2 ? 'var(--orange)' : 'var(--green)';
  const sleepBar = Math.min(100, ((bp.sleepHours || 6) / 9) * 100);
  const sleepColor = bp.sleepHours >= 7 ? 'var(--green)' : bp.sleepHours >= 6 ? 'var(--orange)' : 'var(--red)';
  const completed = bp.completedAt ? bp.completedAt.slice(0, 10) : 'Unknown';
  const mtLabel = { grades: 'Grade-driven', understanding: 'Mastery-driven', career: 'Career-driven', competition: 'Competitive', family: 'Family-driven', mixed: 'Multi-motivated' }[bp.motivationType] || 'Mixed';
  const pomLabel = bp.sessionMins <= 15 ? '10/5 micro-sessions' : bp.sessionMins <= 30 ? '20/5 sessions' : bp.sessionMins <= 60 ? '25/5 Pomodoro' : '50/10 deep work';

  return `<div class="card" style="padding:16px;border-color:rgba(139,92,246,.35);background:linear-gradient(180deg,rgba(139,92,246,.07),transparent)">
    <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:12px">
      <div style="display:flex;align-items:center;gap:10px">
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="var(--purple)" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M2 15c6.667-6 13.333 0 20-6"/><path d="M9 22c1.798-1.998 2.518-3.995 2.807-5.993"/><path d="M15 2c-1.798 1.998-2.518 3.995-2.807 5.993"/><path d="m2 9 3 .36"/><path d="m19.7 14.36 3 .36"/><path d="M5 6.09l.6 2.58"/><path d="m18.4 15.33.6 2.58"/><path d="m6.52 17 1.98 1.5"/><path d="m17.48 7-1.98-1.5"/></svg>
        <div>
          <div style="font-size:11px;font-weight:700;color:var(--purple);text-transform:uppercase;letter-spacing:.08em">Study DNA — Active</div>
          <div style="font-size:15px;font-weight:700;color:var(--text)">${esc(archetype)}</div>
        </div>
      </div>
      <button class="btn btn-ghost btn-sm" style="font-size:11px;color:var(--purple)" onclick="eliteOpenBrainQuiz()">Update DNA</button>
    </div>

    <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:8px;margin-bottom:12px">
      <div style="padding:8px 10px;background:var(--bg-sec);border-radius:10px">
        <div style="font-size:10px;color:var(--text-faint);font-weight:700;text-transform:uppercase;letter-spacing:.06em">Learning Style</div>
        <div style="font-size:14px;font-weight:700;margin-top:2px">${lsIcon} ${esc(lsLabel)}</div>
      </div>
      <div style="padding:8px 10px;background:var(--bg-sec);border-radius:10px">
        <div style="font-size:10px;color:var(--text-faint);font-weight:700;text-transform:uppercase;letter-spacing:.06em">Peak Focus</div>
        <div style="font-size:13px;font-weight:700;margin-top:2px;text-transform:capitalize;display:inline-flex;align-items:center;gap:5px"><svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg> ${esc(focusLabel)}</div>
      </div>
      <div style="padding:8px 10px;background:var(--bg-sec);border-radius:10px">
        <div style="font-size:10px;color:var(--text-faint);font-weight:700;text-transform:uppercase;letter-spacing:.06em">Motivation</div>
        <div style="font-size:12px;font-weight:700;margin-top:2px;display:inline-flex;align-items:center;gap:5px"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="12" cy="12" r="10"/><circle cx="12" cy="12" r="6"/><circle cx="12" cy="12" r="2"/></svg> ${esc(mtLabel)}</div>
      </div>
      <div style="padding:8px 10px;background:var(--bg-sec);border-radius:10px">
        <div style="font-size:10px;color:var(--text-faint);font-weight:700;text-transform:uppercase;letter-spacing:.06em">Sessions</div>
        <div style="font-size:12px;font-weight:700;margin-top:2px;display:inline-flex;align-items:center;gap:5px"><svg width="12" height="12" viewBox="0 0 24 24" fill="currentColor" stroke="currentColor" stroke-width="1"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg> ${esc(pomLabel)}</div>
      </div>
    </div>

    <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-bottom:12px">
      <div>
        <div style="font-size:11px;color:var(--text-faint);font-weight:600;margin-bottom:4px">Stress Level</div>
        <div style="height:6px;background:var(--border);border-radius:999px;overflow:hidden"><div style="height:100%;width:${stressBar}%;background:${stressColor};transition:.3s"></div></div>
        <div style="font-size:11px;color:${stressColor};margin-top:3px">${['Low', 'Moderate', 'High', 'Very high'][((bp.stressLevel || 1) - 1)] || 'Moderate'}</div>
      </div>
      <div>
        <div style="font-size:11px;color:var(--text-faint);font-weight:600;margin-bottom:4px">Sleep Quality</div>
        <div style="height:6px;background:var(--border);border-radius:999px;overflow:hidden"><div style="height:100%;width:${sleepBar}%;background:${sleepColor};transition:.3s"></div></div>
        <div style="font-size:11px;color:${sleepColor};margin-top:3px">${bp.sleepHours}h / night</div>
      </div>
    </div>

    ${bp.recommendations?.length ? `
    <div style="font-size:11px;font-weight:700;color:var(--text-muted);text-transform:uppercase;letter-spacing:.06em;margin-bottom:6px">Top Insights for ${esc(name)}</div>
    <div style="display:grid;gap:6px;margin-bottom:12px">
      ${bp.recommendations.slice(0, 3).map(r => `
        <div style="font-size:12px;color:var(--text-muted);padding:8px 10px;background:var(--bg-sec);border-radius:8px;line-height:1.5">
          <strong style="color:var(--text)">${esc(r.title || '')}</strong>
          <div style="margin-top:3px">${esc((r.method || '').slice(0, 120))}${(r.method || '').length > 120 ? '…' : ''}</div>
        </div>`).join('')}
    </div>` : ''}

    <div id="elite-personal-plan-output"></div>
    <div style="display:flex;gap:8px;margin-top:8px">
      <button class="btn btn-secondary btn-sm" style="flex:1" onclick="eliteGeneratePersonalisedPlan(eliteGetStudyProfile())">
        ✦ Generate Personalised Plan
      </button>
    </div>
    <div style="font-size:11px;color:var(--text-faint);margin-top:8px;text-align:right">Profile built ${esc(completed)}</div>
  </div>`;
}

const SG_TRACK_LABELS = {
  sg_psle: 'PSLE',
  sg_n_level: 'N-Level',
  sg_o_level: 'O-Level',
  sg_a_level: 'A-Level',
  sg_ib: 'IB (Singapore)',
};
function eliteTrack() { return S.userProfile?.syllabusTrack || 'sg_o_level'; }
function eliteTrackLabel() { return SG_TRACK_LABELS[eliteTrack()] || 'O-Level'; }
function sgGradeBand(readiness, track) {
  if (track === 'sg_psle') {
    if (readiness >= 88) return 'AL1–AL2';
    if (readiness >= 76) return 'AL2–AL3';
    if (readiness >= 64) return 'AL3–AL4';
    if (readiness >= 52) return 'AL4–AL5';
    return 'AL6–AL8';
  }
  if (track === 'sg_a_level') {
    if (readiness >= 90) return 'A';
    if (readiness >= 80) return 'A–B';
    if (readiness >= 68) return 'B–C';
    if (readiness >= 56) return 'C–D';
    return 'D–U';
  }
  if (track === 'sg_n_level') {
    if (readiness >= 86) return 'Grade 1';
    if (readiness >= 74) return 'Grade 1–2';
    if (readiness >= 62) return 'Grade 2–3';
    if (readiness >= 50) return 'Grade 3–4';
    return 'Grade 4–5';
  }
  if (track === 'sg_ib') {
    if (readiness >= 90) return '6–7';
    if (readiness >= 78) return '5–6';
    if (readiness >= 64) return '4–5';
    if (readiness >= 50) return '3–4';
    return '2–3';
  }
  // O-Level default
  if (readiness >= 90) return 'A1';
  if (readiness >= 82) return 'A1–A2';
  if (readiness >= 72) return 'A2–B3';
  if (readiness >= 62) return 'B3–B4';
  if (readiness >= 52) return 'B4–C5';
  if (readiness >= 44) return 'C5–C6';
  return 'D7–F9';
}

function eliteInsights() {
  const exams = (S.mockExams || []).filter(e => typeof e.lastScore === 'number');
  const avgScore = exams.length ? Math.round(exams.reduce((s, e) => s + (e.lastScore || 0), 0) / exams.length) : 52;
  const age = Number(S.userProfile?.age || 0);
  const track = eliteTrack();
  const completedTasks = (S.tasks || []).filter(t => t.completed).length;
  const totalTasks = (S.tasks || []).length || 1;
  const taskRate = completedTasks / totalTasks;
  const sevenDaysAgo = Date.now() - 7 * 24 * 3600 * 1000;
  const recentPages = (S.pages || []).filter(p => new Date(p.updatedAt || p.createdAt || 0).getTime() >= sevenDaysAgo).length;
  const activityRate = Math.min(1, recentPages / Math.max(1, Math.min((S.pages || []).length, 10)));
  const flashRate = Math.min(1, (S.flashcards || []).length / 6);
  const ageFactor = age ? (age < 13 ? -2 : age > 19 ? 1 : 0) : 0;
  const readiness = Math.max(1, Math.min(100, Math.round((avgScore * 0.48) + (taskRate * 100 * 0.2) + (activityRate * 100 * 0.18) + (flashRate * 100 * 0.14) + ageFactor)));
  const grade = sgGradeBand(readiness, track);
  const weeksToTarget = readiness >= 85 ? 1 : readiness >= 72 ? 2 : readiness >= 58 ? 4 : 6;

  const bySubject = {};
  exams.forEach(e => {
    const key = (e.subject || 'General').trim();
    if (!bySubject[key]) bySubject[key] = { subject: key, total: 0, n: 0 };
    bySubject[key].total += e.lastScore || 0;
    bySubject[key].n += 1;
  });
  const subjectAverages = Object.values(bySubject).map(s => ({ subject: s.subject, avg: Math.round(s.total / Math.max(1, s.n)) }));
  subjectAverages.sort((a, b) => b.avg - a.avg);
  const strengths = subjectAverages.filter(s => s.avg >= 72).slice(0, 3);
  const weaknesses = subjectAverages.filter(s => s.avg <= 62).slice(0, 4);

  const keywordCounts = {};
  const stop = new Set(['about', 'which', 'their', 'there', 'these', 'those', 'with', 'from', 'that', 'this', 'have', 'into', 'your', 'will', 'would', 'could', 'should', 'where', 'when', 'what', 'using', 'notes']);
  (S.pages || []).slice(0, 40).forEach(p => {
    const text = `${p.title || ''} ${(getPageTextContent(p) || '').slice(0, 400)}`.toLowerCase();
    text.split(/[^a-z0-9]+/).forEach(w => {
      if (w.length < 5 || stop.has(w)) return;
      keywordCounts[w] = (keywordCounts[w] || 0) + 1;
    });
  });
  const probableTopics = Object.entries(keywordCounts).sort((a, b) => b[1] - a[1]).slice(0, 5).map(([k], i) => ({ topic: k[0].toUpperCase() + k.slice(1), p: Math.max(52, 88 - i * 7) }));
  const overdue = (S.tasks || []).filter(t => !t.completed && t.due && t.due < new Date().toISOString().slice(0, 10)).length;
  const leaks = [];
  if (weaknesses.length) leaks.push(`Performance leak: ${weaknesses[0].subject} is averaging ${weaknesses[0].avg}%`);
  if (overdue > 0) leaks.push(`Workflow leak: ${overdue} overdue task${overdue === 1 ? '' : 's'} are reducing retention consistency`);
  if (track === 'sg_o_level' || track === 'sg_n_level' || track === 'sg_a_level') leaks.push('Exam-technique leak: command word precision (compare, evaluate, discuss) needs explicit drilling');
  if (!exams.length) leaks.push('Assessment leak: no recent simulations, predicted confidence is unstable');
  if (!leaks.length) leaks.push('No major leaks detected. Keep weekly simulations and spaced review cadence.');

  const percentile = Math.max(1, Math.min(99, Math.round(34 + readiness * 0.52 + (avgScore - 50) * 0.2)));
  const examEvents = eliteExamEvents();
  const nextExam = examEvents[0] || null;
  let countdown = 'No upcoming exam date set';
  if (nextExam) {
    const target = new Date(`${nextExam.date}T00:00:00`);
    const diff = Math.max(0, target.getTime() - Date.now());
    const hrs = Math.floor(diff / 3600000);
    const days = Math.floor(hrs / 24);
    const remH = hrs % 24;
    countdown = days > 0 ? `${days}d ${remH}h` : `${hrs}h`;
  }
  const month = new Date().getMonth() + 1;
  const examSeason = [4, 5, 10, 11].includes(month);
  const confidence = Math.max(42, Math.min(96, Math.round(48 + (exams.length * 6) + (readiness - 50) * 0.22)));
  return { readiness, grade, avgScore, weeksToTarget, strengths, weaknesses, probableTopics, leaks, percentile, nextExam, countdown, examSeason, subjectAverages, exams, track, confidence, age };
}

function renderAdvancedInsightsPreview() {
  // Compute basic weakness data (same source as eliteInsights, but show less)
  const exams = (S.mockExams || []).filter(e => typeof e.lastScore === 'number');
  const bySubject = {};
  exams.forEach(e => {
    const key = (e.subject || 'General').trim();
    if (!bySubject[key]) bySubject[key] = { subject: key, total: 0, n: 0 };
    bySubject[key].total += e.lastScore || 0;
    bySubject[key].n += 1;
  });
  const subjectAverages = Object.values(bySubject).map(s => ({ subject: s.subject, avg: Math.round(s.total / Math.max(1, s.n)) }));
  subjectAverages.sort((a, b) => a.avg - b.avg);
  const weaknesses = subjectAverages.filter(s => s.avg <= 65).slice(0, 3);
  const overdue = (S.tasks || []).filter(t => !t.completed && t.due && t.due < new Date().toISOString().slice(0, 10)).length;

  // Generic advice only — no scores, no predictions, no benchmarking
  const adviceMap = {
    'algebra': 'Revise algebraic manipulation — focus on factorisation and equation solving.',
    'trigonometry': 'Drill SOH-CAH-TOA and exact values. Timed practice helps most.',
    'chemistry': 'Review mole calculations and bonding concepts with past paper questions.',
    'physics': 'Work through SUVAT equations and circuit diagrams step by step.',
    'english': 'Practice structured essay planning — one argument per paragraph.',
    'history': 'Focus on source evaluation technique and essay structure.',
    'biology': 'Create a keyword glossary for each topic and test yourself.',
  };
  const getAdvice = (subject) => {
    const key = subject.toLowerCase();
    for (const [k, v] of Object.entries(adviceMap)) { if (key.includes(k)) return v; }
    return `Revise ${subject} basics — work through past paper questions systematically.`;
  };

  const weaknessRows = weaknesses.length
    ? weaknesses.map(w => `
        <div style="display:flex;align-items:flex-start;gap:10px;padding:10px 0;border-bottom:1px solid var(--border)">
          <div style="width:7px;height:7px;border-radius:50%;background:var(--orange);margin-top:5px;flex-shrink:0"></div>
          <div>
            <div style="font-size:13px;font-weight:600;color:var(--ink)">${esc(w.subject)}</div>
            <div style="font-size:12px;color:var(--text-muted);margin-top:2px">${getAdvice(w.subject)}</div>
          </div>
        </div>`).join('')
    : `<div style="font-size:13px;color:var(--text-muted);padding:10px 0">No weak areas detected yet — complete some mock exams to see your analysis.</div>`;

  const overdueNote = overdue > 0
    ? `<div style="font-size:12px;color:var(--orange);margin-top:8px">⚠ ${overdue} overdue task${overdue === 1 ? '' : 's'} — clearing these will improve your study consistency.</div>`
    : '';

  return `
    <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:14px">

      <!-- Weak areas — basic only -->
      <div class="card" style="padding:18px">
        <div style="font-size:11px;color:var(--text-muted);font-weight:700;text-transform:uppercase;letter-spacing:.06em;margin-bottom:10px">Weak Areas Detected</div>
        ${weaknessRows}
        ${overdueNote}
        ${weaknesses.length ? `<div style="font-size:11px;color:var(--text-faint);margin-top:10px">Showing ${weaknesses.length} area${weaknesses.length===1?'':'s'} · basic analysis only</div>` : ''}
      </div>

      <!-- Limited mock feedback -->
      <div class="card" style="padding:18px">
        <div style="font-size:11px;color:var(--text-muted);font-weight:700;text-transform:uppercase;letter-spacing:.06em;margin-bottom:10px">Mock Exam Summary</div>
        ${exams.length ? `
          <div style="font-size:28px;font-weight:800;color:var(--ink);margin-bottom:4px">${Math.round(exams.reduce((s,e)=>s+(e.lastScore||0),0)/exams.length)}<span style="font-size:14px;color:var(--text-muted);font-weight:500">% avg</span></div>
          <div style="font-size:12px;color:var(--text-muted)">${exams.length} mock${exams.length===1?'':'s'} completed</div>
          <div style="font-size:12px;color:var(--text-faint);margin-top:6px">Trend analysis and subject breakdown available — limited feedback mode.</div>
        ` : `<div style="font-size:13px;color:var(--text-muted)">No mock exams completed yet. Complete a mock exam to see your summary.</div>`}
      </div>

      <!-- Elite upgrade prompt — the money card -->
      <div class="card" style="padding:18px;border:1.5px solid rgba(61,107,69,.35);background:linear-gradient(160deg,rgba(61,107,69,.07),transparent);grid-column:1/-1">
        <div style="font-size:11px;color:var(--moss);font-weight:800;text-transform:uppercase;letter-spacing:.08em;margin-bottom:8px">🔓 Unlock Full Exam Advantage System with Elite</div>
        <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:8px;margin-bottom:14px">
          ${[
            ['Exam Readiness Score (0–100)', 'Know exactly where you stand, not just your weak spots.'],
            ['Predicted Grade Range', 'See your projected SG grade band before exam day.'],
            ['SG Topic Probability', 'Ranked list of likely exam topics based on your notes + syllabus.'],
            ['Peer Benchmarking', 'Compare your readiness against your study group in real time.'],
            ['Panic Mode', 'Emergency revision pack generated in 30 seconds.'],
            ['Full Simulation Diagnostics', 'Deep accuracy trends, timing analysis, and improvement vectors.'],
          ].map(([title, desc]) => `
            <div style="display:flex;align-items:flex-start;gap:8px;padding:8px 10px;background:rgba(255,255,255,.6);border-radius:10px;border:1px solid rgba(61,107,69,.15)">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="var(--moss)" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" style="flex-shrink:0;margin-top:2px"><polyline points="20 6 9 17 4 12"/></svg>
              <div>
                <div style="font-size:12px;font-weight:700;color:var(--ink)">${title}</div>
                <div style="font-size:11px;color:var(--text-muted);margin-top:1px">${desc}</div>
              </div>
            </div>`).join('')}
        </div>
        <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap">
          <button class="btn btn-action" style="padding:10px 22px" onclick="window.open('/pricing.html','_blank')">Upgrade to Elite — $19/mo</button>
          <span style="font-size:12px;color:var(--text-muted)">or $15/mo billed annually</span>
        </div>
      </div>

    </div>`;
}

function renderEliteSuite() {
  const e = eliteInsights();
  const bench = S.eliteGroupBenchmark;
  const benchOptions = S.studyGroups.length
    ? S.studyGroups.map(g => `<option value="${esc(g.id)}"${(S.userProfile?.benchmarkGroupId || S.studyGroups[0]?.id || '') === g.id ? ' selected' : ''}>${esc(g.name)}</option>`).join('')
    : '<option value="">No study groups</option>';
  const bars = (e.exams || []).slice(-6).map(x => {
    const val = Math.max(0, Math.min(100, Math.round(x.lastScore || 0)));
    const c = val >= 75 ? 'var(--green)' : val >= 60 ? 'var(--orange)' : 'var(--red)';
    return `<div style="flex:1;min-width:0"><div style="height:${Math.max(8, Math.round(val * 0.72))}px;background:${c};border-radius:6px 6px 2px 2px"></div><div style="font-size:10px;color:var(--text-faint);text-align:center;margin-top:3px">${val}%</div></div>`;
  }).join('');
  const bp = eliteGetStudyProfile();
  const displayName = bp?.answers?.name || getDisplayName();
  return `
    <div style="margin-bottom:24px">
      <div class="section-lbl" style="display:flex;align-items:center;justify-content:space-between">
        <span>Exam Advantage System</span>
        <span style="font-size:11px;color:var(--moss);font-weight:700">${eliteTrackLabel()} predictive layer active</span>
      </div>

      <!-- Study DNA / Personalisation Card -->
      <div style="margin-bottom:12px">
        ${renderElitePersonalisationCard()}
      </div>

      <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:10px;margin-bottom:10px">
        <div class="card" style="padding:14px;border-color:rgba(61,107,69,.25);background:linear-gradient(180deg,rgba(61,107,69,.08),transparent)">
          <div style="font-size:11px;color:var(--text-muted);font-weight:700;text-transform:uppercase;letter-spacing:.06em">Exam Readiness Engine</div>
          <div style="font-size:26px;font-weight:800;color:var(--moss);margin:4px 0">${e.readiness}<span style="font-size:13px;color:var(--text-muted);font-weight:600">/100</span></div>
          <div style="font-size:12px;color:var(--text-muted)">Predicted range: <strong>${e.grade}</strong> · confidence ${e.confidence}% · target in ~${e.weeksToTarget} week${e.weeksToTarget === 1 ? '' : 's'}</div>
          <div style="font-size:12px;color:var(--text-faint);margin-top:6px">${e.strengths.length ? `Strength: ${esc(e.strengths[0].subject)} (${e.strengths[0].avg}%)` : bp ? `Build simulations — your ${esc(bp.archetype || 'profile')} benefits from ${bp.learningStyle === 'kinesthetic' ? 'practice exams most' : 'consistent mock attempts'}` : 'Build more simulations for stronger confidence intervals'}</div>
          <button class="btn btn-ghost btn-sm" style="margin-top:8px" onclick="eliteRunSgPrediction()">Deep SG prediction</button>
        </div>
        <div class="card" style="padding:14px">
          <div style="font-size:11px;color:var(--text-muted);font-weight:700;text-transform:uppercase;letter-spacing:.06em">Probability & Focus Predictor</div>
          <div style="display:grid;gap:5px;margin-top:6px">
            ${(e.probableTopics || []).slice(0, 3).map(t => `<div style="display:flex;justify-content:space-between;font-size:12px"><span>${esc(t.topic)}</span><strong style="color:var(--accent)">${t.p}% likely</strong></div>`).join('') || '<div style="font-size:12px;color:var(--text-faint)">Add notes to your workspace — Axinote will auto-detect your likely exam topics.</div>'}
          </div>
          <div style="font-size:12px;color:var(--text-faint);margin-top:6px">${bp?.learningStyle === 'visual' ? 'Tip for you: create a mind map for each high-probability topic.' : bp?.learningStyle === 'auditory' ? 'Tip for you: talk through each high-probability topic out loud.' : bp?.learningStyle === 'kinesthetic' ? 'Tip for you: do at least one practice question per high-probability topic.' : 'Focus list auto-prioritizes high-probability + weak areas.'}</div>
        </div>
        <div class="card" style="padding:14px;border-color:rgba(184,82,30,.25);background:linear-gradient(180deg,rgba(184,82,30,.07),transparent)">
          <div style="font-size:11px;color:var(--text-muted);font-weight:700;text-transform:uppercase;letter-spacing:.06em">Panic Mode / Compression</div>
          <div style="font-size:13px;color:var(--text);margin-top:6px">Exam countdown: <strong>${e.countdown}</strong>${e.nextExam ? ` · ${esc(e.nextExam.title)}` : ''}</div>
          ${bp ? `<div style="font-size:11.5px;color:var(--text-faint);margin-top:5px">${bp.sessionMins}-min ${bp.learningStyle === 'visual' ? 'visual compression' : bp.learningStyle === 'auditory' ? 'verbal drill' : bp.learningStyle === 'kinesthetic' ? 'practice-first' : 'recall-based'} pack · ${bp.burnoutRisk >= 3 ? '⚠ Burnout risk detected — keep sessions short' : 'Burnout monitoring on'}</div>` : ''}
          <button class="btn btn-action btn-sm" style="margin-top:8px" onclick="eliteRunPanicMode()">Generate Emergency Pack</button>
        </div>
      </div>

      <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:10px;margin-bottom:10px">
        <div class="card" style="padding:14px">
          <div style="font-size:11px;color:var(--text-muted);font-weight:700;text-transform:uppercase;letter-spacing:.06em">Exam Simulation Mode</div>
          <div style="font-size:12px;color:var(--text-muted);margin:6px 0">${bp ? `Optimised for ${esc(bp.archetype || 'you')}: ${bp.sessionMins <= 25 ? 'short-burst timed papers' : bp.sessionMins <= 45 ? '25/5 Pomodoro exam sets' : 'full-length deep work papers'}. ${bp.biggestObstacle === 'anxiety' ? 'Panic-buffer mode active.' : bp.biggestObstacle === 'time' ? 'Timed challenge mode enabled.' : 'Weighted marking + accuracy trend analysis.'}` : 'Timed exam papers, weighted marking, accuracy trend analysis.'}</div>
          <button class="btn btn-secondary btn-sm" onclick="eliteOpenSimulation()">Open Simulation Hub</button>
        </div>
        <div class="card" style="padding:14px">
          <div style="font-size:11px;color:var(--text-muted);font-weight:700;text-transform:uppercase;letter-spacing:.06em">Weakness Leak Detection</div>
          ${(e.leaks || []).map(l => `<div style="font-size:12px;color:var(--text-muted);margin-top:5px">• ${esc(l)}</div>`).join('')}
          ${bp ? `<div style="font-size:11.5px;color:var(--text-faint);margin-top:8px;padding-top:6px;border-top:1px solid var(--border)">Fix strategy for <strong>${esc(bp.archetype || 'you')}</strong>: ${bp.learningStyle === 'visual' ? 'Draw concept maps for each weak area' : bp.learningStyle === 'auditory' ? 'Explain each leak out loud before re-testing' : bp.learningStyle === 'kinesthetic' ? 'Do 3 practice questions per leak immediately' : 'Use active recall flashcards to close each gap'}</div>` : ''}
        </div>
        <div class="card" style="padding:14px">
          <div style="font-size:11px;color:var(--text-muted);font-weight:700;text-transform:uppercase;letter-spacing:.06em">Competitive Benchmarking</div>
          <div id="elite-group-benchmark" style="font-size:12px;color:var(--text-muted)">
            ${bench ? `<div style="font-size:26px;font-weight:800;color:var(--purple);margin-top:2px">Top ${Math.max(1, 100 - bench.percentile)}%</div><div>Within ${esc(bench.groupName)} · ${bench.cohort} Elite member${bench.cohort === 1 ? '' : 's'}</div><div style="font-size:12px;color:var(--text-faint);margin-top:6px">Your readiness ${bench.selfReadiness} vs group avg ${bench.avgReadiness}</div>` : '<div>Loading group benchmark…</div>'}
          </div>
          <div style="display:flex;gap:6px;margin-top:8px;align-items:center"><select id="elite-bench-group" class="form-input" style="height:30px;padding:4px 8px;font-size:12px">${benchOptions}</select><button class="btn btn-ghost btn-sm" style="padding:4px 10px" onclick="eliteSetBenchmarkGroup()">Use</button></div>
        </div>
      </div>

      <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:10px">
        <div class="card" style="padding:14px">
          <div style="font-size:11px;color:var(--text-muted);font-weight:700;text-transform:uppercase;letter-spacing:.06em">Smart Study Planner 2.0</div>
          <div style="font-size:12px;color:var(--text-muted);margin-top:6px">${bp ? `Calibrated to your ${esc(bp.archetype || 'profile')}: ${esc((bp.focusWindow || 'evening').replace('_', ' '))} focus blocks, ${bp.sessionMins}min sessions, burnout ${bp.burnoutRisk >= 3 ? 'protection active' : 'monitoring on'}.` : 'Adaptive weekly plan with burnout protection and intensity rebalance.'}</div>
          <button class="btn btn-secondary btn-sm" style="margin-top:8px" onclick="eliteRunSmartPlanner()">Build Adaptive Plan</button>
        </div>
        <div class="card" style="padding:14px">
          <div style="font-size:11px;color:var(--text-muted);font-weight:700;text-transform:uppercase;letter-spacing:.06em">Credits, Top-Ups &amp; Priority Access</div>
          <div style="font-size:12px;color:var(--text-muted);margin-top:6px">200,000 credits/month · Top-up 50k for $2 (up to 3x/month) · rollover enabled.</div>
          <div style="font-size:12px;color:var(--text-faint);margin-top:6px">Early-access features and premium dashboards are active on Elite.</div>
        </div>
      </div>
      <div id="elite-panic-output" style="margin-top:10px"></div>
      <div id="elite-sg-prediction" style="margin-top:10px"></div>
    </div>`;
}

function eliteBenchmarkGroupId() {
  return S.userProfile?.benchmarkGroupId || S._currentGroupId || S.studyGroups[0]?.id || '';
}

async function elitePublishBenchmarkSnapshots() {
  if (!S.user || !hasPlan('elite')) return;
  const gid = eliteBenchmarkGroupId();
  if (!gid) return;
  const me = eliteInsights();
  const payload = {
    uid: S.user.uid,
    name: getDisplayName(),
    tier: getCurrentTier(),
    readiness: me.readiness,
    avgScore: me.avgScore,
    syllabusTrack: me.track,
    age: me.age || null,
    updatedAt: Date.now(),
  };
  await window.fb.set(window.fb.ref(window.fb.database, `studyGroups/${gid}/eliteBenchmarks/${S.user.uid}`), payload).catch(() => {});
}

function eliteBindGroupBenchmarkRealtime() {
  const gid = eliteBenchmarkGroupId();
  if (!gid || !S.user || !hasPlan('elite')) return;
  if (S.eliteBenchListener) { try { S.eliteBenchListener(); } catch (e) { } S.eliteBenchListener = null; }
  const ref = window.fb.ref(window.fb.database, `studyGroups/${gid}/eliteBenchmarks`);
  S.eliteBenchListener = window.fb.onValue(ref, snap => {
    const group = S.studyGroups.find(g => g.id === gid);
    const data = snap.exists() ? snap.val() || {} : {};
    const rows = Object.values(data).filter(r => r && r.tier === 'elite' && r.syllabusTrack === eliteTrack() && (Date.now() - Number(r.updatedAt || 0)) <= 45 * 24 * 3600 * 1000);
    const self = rows.find(r => r.uid === S.user.uid) || { readiness: eliteInsights().readiness };
    const cohort = Math.max(1, rows.length || 1);
    const sorted = [...rows].sort((a, b) => Number(a.readiness || 0) - Number(b.readiness || 0));
    let pos = sorted.findIndex(r => r.uid === S.user.uid) + 1;
    if (!pos) pos = sorted.filter(r => Number(r.readiness || 0) <= Number(self.readiness || 0)).length || 1;
    const percentile = Math.max(1, Math.min(99, Math.round((pos / cohort) * 100)));
    const avgReadiness = Math.round((rows.reduce((s, r) => s + Number(r.readiness || 0), 0) || Number(self.readiness || 0)) / cohort);
    S.eliteGroupBenchmark = {
      groupId: gid,
      groupName: group?.name || 'Study Group',
      cohort,
      percentile,
      avgReadiness,
      selfReadiness: Math.round(Number(self.readiness || 0)),
    };
    if (S.view === 'examSuite') {
      const el = document.getElementById('elite-group-benchmark');
      if (el) el.innerHTML = `<div style="font-size:26px;font-weight:800;color:var(--purple);margin-top:2px">Top ${Math.max(1, 100 - percentile)}%</div><div>Within ${esc(S.eliteGroupBenchmark.groupName)} · ${cohort} Elite member${cohort === 1 ? '' : 's'}</div><div style="font-size:12px;color:var(--text-faint);margin-top:6px">Your readiness ${S.eliteGroupBenchmark.selfReadiness} vs group avg ${avgReadiness}</div>`;
    }
  });
}

async function eliteSetBenchmarkGroup() {
  const gid = document.getElementById('elite-bench-group')?.value || '';
  if (!gid || !S.user) return;
  if (!S.userProfile) S.userProfile = {};
  S.userProfile.benchmarkGroupId = gid;
  await window.fb.update(window.fb.ref(window.fb.database, `users/${S.user.uid}/profile`), { benchmarkGroupId: gid }).catch(() => {});
  await elitePublishBenchmarkSnapshots();
  eliteBindGroupBenchmarkRealtime();
  toast('Benchmark group updated');
}

async function eliteRunSgPrediction() {
  const mount = document.getElementById('elite-sg-prediction');
  if (!mount) return;
  const info = eliteInsights();
  const subjects = (info.subjectAverages || []).map(s => `${s.subject}:${s.avg}%`).join(', ') || 'No recent subject scores';
  const upcoming = eliteExamEvents().map(x => `${x.date} ${x.title}`).join('; ') || 'No exam date set';
  mount.innerHTML = '<div class="card" style="padding:12px;font-size:13px;color:var(--text-muted)">Generating Singapore syllabus prediction…</div>';
  try {
    const out = await callAIJson(
      'You are an exam performance predictor specialized in Singapore secondary/junior college exam standards (SEAB/MOE style). Return JSON only: {"predictedGradeRange":"...", "confidence":"0-100", "likelyExamTopics":[{"topic":"...","probability":"0-100"}], "highRiskMistakes":["..."], "next48hPlan":["..."], "next7dPlan":["..."]}. Use conservative confidence and practical recommendations.',
      `Track:${eliteTrackLabel()} Age:${info.age || 'unknown'} Readiness:${info.readiness} AvgScore:${info.avgScore} Subjects:${subjects} Upcoming:${upcoming} Weaknesses:${(info.weaknesses || []).map(w => `${w.subject}:${w.avg}`).join(', ')}`,
      1000
    );
    const topics = (out.likelyExamTopics || []).slice(0, 4).map(t => `<div style="display:flex;justify-content:space-between;font-size:12px"><span>${esc(t.topic || '')}</span><strong style="color:var(--accent)">${esc(String(t.probability || ''))}%</strong></div>`).join('');
    mount.innerHTML = `<div class="card" style="padding:14px;border-color:rgba(61,107,69,.25);background:linear-gradient(180deg,rgba(61,107,69,.08),transparent)"><div style="font-size:11px;color:var(--text-muted);font-weight:700;text-transform:uppercase;letter-spacing:.06em">Singapore Deep Prediction</div><div style="font-size:14px;color:var(--text);margin-top:6px">Predicted range: <strong>${esc(out.predictedGradeRange || info.grade)}</strong> · confidence ${esc(String(out.confidence || info.confidence))}%</div>${topics ? `<div style="margin-top:8px">${topics}</div>` : ''}${(out.highRiskMistakes || []).length ? `<div style="font-size:12px;color:var(--text-muted);margin-top:8px"><strong>High-risk mistakes:</strong> ${(out.highRiskMistakes || []).slice(0, 3).map(x => esc(x)).join(' · ')}</div>` : ''}${(out.next48hPlan || []).length ? `<div style="font-size:12px;color:var(--text-muted);margin-top:8px"><strong>Next 48h:</strong> ${(out.next48hPlan || []).slice(0, 3).map(x => esc(x)).join(' · ')}</div>` : ''}${(out.next7dPlan || []).length ? `<div style="font-size:12px;color:var(--text-faint);margin-top:6px"><strong>Next 7 days:</strong> ${(out.next7dPlan || []).slice(0, 4).map(x => esc(x)).join(' · ')}</div>` : ''}</div>`;
  } catch (_) {
    mount.innerHTML = `<div class="card" style="padding:14px;border-color:rgba(61,107,69,.25);background:linear-gradient(180deg,rgba(61,107,69,.08),transparent)"><div style="font-size:11px;color:var(--text-muted);font-weight:700;text-transform:uppercase;letter-spacing:.06em">Singapore Deep Prediction (offline)</div><div style="font-size:13px;color:var(--text);margin-top:6px">Predicted range: <strong>${info.grade}</strong> · confidence ${info.confidence}%</div><div style="font-size:12px;color:var(--text-muted);margin-top:6px">Focus 48h: ${(info.weaknesses[0]?.subject || info.probableTopics[0]?.topic || 'Core topics')} then ${(info.weaknesses[1]?.subject || info.probableTopics[1]?.topic || 'Exam technique')}</div></div>`;
  }
}

function eliteOpenSimulation() {
  if (!ensureFeatureAccess('elite_core', 'Elite Simulation')) return;
  navigate('mockExam');
}

function eliteRunSmartPlanner() {
  if (!ensureFeatureAccess('elite_core', 'Smart Study Planner 2.0')) return;
  aiStudyPlanFromContext();
  setTimeout(() => document.getElementById('ai-day-result')?.scrollIntoView({ behavior: 'smooth', block: 'center' }), 120);
}

async function eliteRunPanicMode() {
  if (!ensureFeatureAccess('elite_core', 'Panic Mode')) return;
  const mount = document.getElementById('elite-panic-output');
  if (!mount) return;
  mount.innerHTML = '<div class="card" style="padding:12px;font-size:13px;color:var(--text-muted)">Building emergency compression pack…</div>';
  const events = eliteExamEvents();
  const next = events[0];
  const recentNotes = [...(S.pages || [])].sort((a, b) => (b.updatedAt || b.createdAt || '').localeCompare(a.updatedAt || a.createdAt || '')).slice(0, 5);
  const baseText = recentNotes.map(p => `# ${p.title || 'Untitled'}\n${getPageTextContent(p).slice(0, 900)}`).join('\n\n');
  try {
    const result = await callAI(
      `You are a panic-mode cognitive compression engine for a ${(eliteGetStudyProfile()?.archetype || 'student')} (learning style: ${(eliteGetStudyProfile()?.learningStyle || 'mixed')}). Output a short emergency revision pack personalised to their learning style: 1) Top 10 must-know facts ${eliteGetStudyProfile()?.learningStyle === 'visual' ? '(use visual symbols/arrows)' : eliteGetStudyProfile()?.learningStyle === 'kinesthetic' ? '(with practice application for each)' : ''}, 2) 5 high-risk traps, 3) 12 rapid recall prompts, 4) ${eliteGetStudyProfile()?.sessionMins || 25}-minute and 90-minute fallback plans. Keep it ultra concise for urgent exam prep.`,
      `Exam: ${next ? `${next.title} on ${next.date}` : 'Not set'}\n\nNotes:\n${baseText.slice(0, 4500)}`,
      1200
    );
    mount.innerHTML = `<div class="card" style="padding:14px;border-color:rgba(184,82,30,.28);background:linear-gradient(180deg,rgba(184,82,30,.07),transparent)"><div style="font-size:12px;color:var(--text-muted);font-weight:700;text-transform:uppercase;letter-spacing:.06em">Emergency Compression Pack</div><div style="margin-top:8px">${markdownToHtml(esc(result))}</div></div>`;
  } catch (_) {
    const fallback = eliteInsights();
    mount.innerHTML = `<div class="card" style="padding:14px;border-color:rgba(184,82,30,.28);background:linear-gradient(180deg,rgba(184,82,30,.07),transparent)"><div style="font-size:12px;color:var(--text-muted);font-weight:700;text-transform:uppercase;letter-spacing:.06em">Emergency Compression Pack (offline)</div><div style="font-size:13px;color:var(--text);margin-top:8px">• Focus now: ${(fallback.weaknesses[0]?.subject || fallback.probableTopics[0]?.topic || 'Core topics')}</div><div style="font-size:13px;color:var(--text);margin-top:4px">• Next 30 mins: 10-minute skim, 10-minute active recall, 10-minute error correction</div><div style="font-size:13px;color:var(--text);margin-top:4px">• High-risk trap: ${(fallback.leaks[0] || 'Coverage inconsistency')}</div><div style="font-size:13px;color:var(--text);margin-top:4px">• Rapid recall: write 8 likely questions and answer without notes</div></div>`;
  }
}

function renderAIDashboard(c) {
  const admin = isAdmin();
  const configured = true;
  const credits = getCredits();
  const pct = admin ? 0 : Math.min(100, Math.round((credits.used / credits.total) * 100));
  const left = getCreditLeft();
  const tier = credits.tier || 'free';
  const tierInfo = CREDIT_TIERS[tier] || CREDIT_TIERS.advanced;
  const barColor = pct >= 90 ? 'var(--red)' : pct >= 75 ? 'var(--orange)' : 'var(--accent)';
  const today = new Date().toISOString().split('T')[0];
  const g = greet();

  const _svgChat = `<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/></svg>`;
  const _svgWrite = `<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17 3a2.828 2.828 0 1 1 4 4L7.5 20.5 2 22l1.5-5.5L17 3z"/></svg>`;
  const _svgStudy = `<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M2 3h6a4 4 0 0 1 4 4v14a3 3 0 0 0-3-3H2z"/><path d="M22 3h-6a4 4 0 0 0-4 4v14a3 3 0 0 1 3-3h7z"/></svg>`;
  const _svgOrg = `<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/></svg>`;

  // Compute workspace snapshot for display
  const todayEvs = S.calendar.filter(e => e.date === today);
  const activeTasks = S.tasks.filter(t => !t.completed);
  const overdueTasks = activeTasks.filter(t => t.due && t.due < today);
  const upcomingTasks = activeTasks.filter(t => t.due && t.due >= today).sort((a, b) => a.due.localeCompare(b.due)).slice(0, 5);
  const recent = [...S.pages].sort((a, b) => (b.updatedAt || b.createdAt || '') > (a.updatedAt || a.createdAt || '') ? 1 : -1).slice(0, 4);
  const dueSoon = activeTasks.filter(t => t.due && t.due >= today).sort((a, b) => String(a.due || '').localeCompare(String(b.due || ''))).slice(0, 4);
  const daysInMonth = new Date().getDate() ? new Date(new Date().getFullYear(), new Date().getMonth() + 1, 0).getDate() : 30;
  const elapsedDays = Math.max(1, new Date().getDate());
  const avgCreditUse = admin ? 0 : Math.round((credits.used || 0) / elapsedDays);
  const projectedUse = admin ? 0 : Math.round(avgCreditUse * daysInMonth);

  c.innerHTML = `
    <div style="margin-bottom:28px">
      <div style="display:flex;align-items:center;gap:10px;margin-bottom:4px">
        <h1 style="font-size:36px;font-weight:700;line-height:1.15">${esc(g.phrase)}</h1>
        <span style="display:inline-flex;align-items:center;color:var(--accent)">${g.svg}</span>
      </div>
      <p style="color:var(--text-faint);font-size:14px">${esc(g.sub)}</p>
    </div>

    <div class="stat-row">
      <div class="stat-box stat-box-link" onclick="navigate('tasks')" title="Active Tasks"><div class="stat-num" style="color:var(--blue)">${activeTasks.length}</div><div class="stat-lbl">Active Tasks</div></div>
      <div class="stat-box stat-box-link" onclick="navigate('tasks')" title="Overdue" style="${overdueTasks.length ? 'border-color:var(--red)' : ''}"><div class="stat-num" style="color:${overdueTasks.length ? 'var(--red)' : 'var(--green)'}">${overdueTasks.length}</div><div class="stat-lbl">Overdue</div></div>
      <div class="stat-box stat-box-link" onclick="navigate('calendar')" title="Events Today"><div class="stat-num" style="color:var(--purple)">${todayEvs.length}</div><div class="stat-lbl">Events Today</div></div>
      <div class="stat-box stat-box-link" onclick="navigate('flashcards')" title="Decks"><div class="stat-num" style="color:var(--accent)">${S.flashcards.length}</div><div class="stat-lbl">Decks</div></div>
    </div>

    <div class="quick-actions">
      <button class="btn btn-action btn-sm" onclick="showTemplatePicker()">${icons.plus} New Page</button>
      <button class="btn btn-secondary btn-sm" onclick="navigate('tasks')">${icons.check} Tasks</button>
      <button class="btn btn-secondary btn-sm" onclick="navigate('calendar')">${icons.calendar} Calendar</button>
      <button class="btn btn-secondary btn-sm" onclick="navigate('flashcards')">${icons.flash} Flashcards</button>
      <button class="btn btn-secondary btn-sm" onclick="togglePom()">${icons.timer} Focus Timer</button>
    </div>

    <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:12px;margin-bottom:18px">
      <div class="card" style="padding:14px">
        <div style="font-size:11px;color:var(--text-muted);font-weight:700;text-transform:uppercase;letter-spacing:.06em">Deadline Risk</div>
        <div style="display:flex;align-items:center;gap:8px;margin-top:8px;font-size:13px">
          <span style="padding:2px 8px;border-radius:999px;background:color-mix(in srgb,var(--red) 18%, transparent);color:var(--red);font-weight:700">${overdueTasks.length} overdue</span>
          <span style="color:var(--text-muted)">${dueSoon.length} upcoming due</span>
        </div>
        <div style="margin-top:8px;display:grid;gap:6px">
          ${dueSoon.length ? dueSoon.map(t => `<div class="recent-row" style="padding:8px 10px;min-height:0"><span>${esc(t.title)}</span><span class="recent-date" style="margin-left:auto">${fmt(t.due)}</span></div>`).join('') : '<div style="font-size:12px;color:var(--text-faint);padding:8px 0">No upcoming deadlines.</div>'}
        </div>
      </div>
      <div class="card" style="padding:14px">
        <div style="font-size:11px;color:var(--text-muted);font-weight:700;text-transform:uppercase;letter-spacing:.06em">Credit Runway</div>
        ${admin ? `
          <div style="font-size:24px;font-weight:800;color:var(--green);margin-top:6px">Unlimited</div>
          <div style="font-size:12px;color:var(--text-muted);margin-top:2px">Admin account has unrestricted AI access.</div>
        ` : `
          <div style="font-size:26px;font-weight:800;color:var(--accent);margin-top:4px">${left.toLocaleString()}</div>
          <div style="font-size:12px;color:var(--text-muted);margin-top:2px">credits left this month</div>
          <div style="margin-top:8px;height:8px;border-radius:999px;background:var(--bg-sec);overflow:hidden"><div style="height:100%;width:${Math.max(0, Math.min(100, Math.round(((credits.used || 0) / Math.max(1, credits.total || 1)) * 100)))}%;background:linear-gradient(90deg,var(--accent),var(--orange));"></div></div>
          <div style="font-size:12px;color:var(--text-faint);margin-top:8px">Avg/day ${avgCreditUse.toLocaleString()} · projected ${projectedUse.toLocaleString()} this month</div>
        `}
      </div>
    </div>

    ${configured || admin ? `
    <div style="margin-bottom:28px">
      <div class="section-lbl" style="display:flex;align-items:center;justify-content:space-between">
        <span>AI Assistant</span>
        <span style="font-size:11px;color:var(--text-faint);font-weight:400">${admin ? 'Unlimited' : left.toLocaleString() + ' credits left'}</span>
      </div>
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:12px">
        <button class="ai-dash-action-btn" style="height:52px;font-size:13px;gap:8px" onclick="aiSummariseDay()">${_svgChat}<span>How's my day?</span></button>
        <button class="ai-dash-action-btn" style="height:52px;font-size:13px;gap:8px" onclick="aiOverdueTasks()">${icons.check}<span>Task priorities</span></button>
        <button class="ai-dash-action-btn" style="height:52px;font-size:13px;gap:8px" onclick="aiStudyPlanFromContext()">${_svgStudy}<span>Study plan</span></button>
        <button class="ai-dash-action-btn" style="height:52px;font-size:13px;gap:8px" onclick="openAIPanelTab('flowai')">${_svgChat}<span>Chat with AI</span></button>
      </div>
      <div style="display:flex;gap:8px;margin-bottom:4px">
        <input id="day-ai-input" class="form-input" placeholder="Ask FlowAI anything about your workspace…" style="flex:1" onkeydown="if(event.key==='Enter')aiAskAnything()">
        <button class="btn btn-action" onclick="aiAskAnything()" style="padding:0 16px">Ask</button>
      </div>
      <div id="ai-day-result" style="margin-top:12px"></div>
    </div>` : `
    <div style="margin-bottom:28px">
      <div class="section-lbl">FlowAI — Your Personal Study Assistant</div>
      <div class="card" style="padding:20px;border:1px solid var(--accent);background:var(--accent-bg)">
        <div style="font-weight:700;color:var(--accent);margin-bottom:8px">Load FlowAI locally</div>
        <p style="font-size:13px;color:var(--text);margin-bottom:12px;line-height:1.6">FlowAI now runs in the browser first. Load the local model to unlock the strongest version, grounded in your notes, tasks, calendar, flashcards, and mock exams.</p>
        <div style="display:flex;gap:8px;flex-wrap:wrap">
          <button class="btn btn-action" style="flex:1;min-width:180px" onclick="flowaiLoadLocalModel()">Load Local Model</button>
          <button class="btn btn-secondary" style="flex:1;min-width:180px" onclick="openAIPanelTab('flowai')">Open FlowAI</button>
        </div>
        <div id="ai-dash-conn-status" style="font-size:12px;margin-top:8px;color:var(--text-muted)">${esc(flowaiModelStatusLabel())}</div>
      </div>
    </div>`}

    <div style="display:grid;grid-template-columns:1fr 1fr;gap:20px;margin-bottom:24px">
      <div>
        ${todayEvs.length ? `<div class="section-lbl">Today's Events</div>${todayEvs.slice(0, 3).map(e => `<div class="recent-row" onclick="openCalEventModal(null,'',null,'${e.id}')"><span style="width:8px;height:8px;border-radius:50%;background:var(--${e.color || 'accent'});flex-shrink:0;display:inline-block"></span><span>${esc(e.title)}</span>${e.time ? `<span class="recent-date">${e.time}</span>` : ''}</div>`).join('')}` : ''}
        ${upcomingTasks.length ? `<div class="section-lbl" style="margin-top:${todayEvs.length ? '16px' : '0'}">Priority Tasks</div>${upcomingTasks.map(t => `<div class="task-row"><div class="task-chk" onclick="toggleTask('${t.id}')"></div><span class="task-lbl">${esc(t.title)}</span>${t.priority ? `<div class="dot d-${t.priority === 'high' ? 'high' : t.priority === 'low' ? 'low' : 'med'}"></div>` : ''}${t.due ? `<span class="task-due${overdueTasks.includes(t) ? ' late' : ''}"> ${fmt(t.due)}</span>` : ''}</div>`).join('')}` : (!activeTasks.length ? `<div style="padding:8px 0;color:var(--green);font-size:13px;font-weight:600">All tasks done!</div>` : '')}
      </div>
      <div>
        ${recent.length ? `<div class="section-lbl">Recent Notes</div>${recent.map(p => `<div class="recent-row" onclick="openPage('${p.id}')">${icons.file}<span>${esc(p.title) || 'Untitled'}</span><span class="recent-date" style="margin-left:auto">${fmt(p.updatedAt || p.createdAt)}</span></div>`).join('')}` : ''}
      </div>
    </div>

    `;
}

function saveDashAIConfig() {
  const v = (document.getElementById('ai-key-inp-dash')?.value || '').trim();
  if (!v) return;
  if (v.startsWith('https://')) {
    setWorkerUrl(v);
  } else {
    const s = document.getElementById('ai-dash-conn-status');
    if (s) { s.style.color = 'var(--orange)'; s.textContent = 'Enter a valid https:// Worker URL'; }
    return;
  }
  const s = document.getElementById('ai-dash-conn-status');
  if (s) { s.style.color = 'var(--green)'; s.textContent = '✓ Saved — AI features now active'; }
  setTimeout(() => navigate('aiDashboard'), 900);
}

// ─── Stripe payment links ─────────────────────────────────────
// Replace these with your actual Stripe Payment Link URLs.
// Create them at: https://dashboard.stripe.com/payment-links
// Tip: add ?prefilled_email=${S.user?.email} if your Stripe plan supports it.
// ─── Stripe Payment Links ────────────────────────────────────
// Create these at https://dashboard.stripe.com/payment-links
// Set "Don't allow adjustable quantities" and enable "Collect customer emails"
// IMPORTANT: In each Payment Link's settings, enable "client_reference_id"
// so the webhook can match the purchase to the Firebase UID.
const STRIPE_LINKS = {
  lite:     'https://buy.stripe.com/REPLACE_WITH_LITE_LINK',
  pro:      'https://buy.stripe.com/REPLACE_WITH_PRO_LINK',
  advanced: 'https://buy.stripe.com/REPLACE_WITH_ADVANCED_LINK',
  elite:    'https://buy.stripe.com/REPLACE_WITH_ELITE_LINK',
};

async function openUpgradeLink(tier) {
  // Must be logged in — we need the Firebase UID as client_reference_id
  // so the Stripe webhook can grant the right tier automatically.
  if (!S.user) {
    toast('Please sign in before upgrading.');
    navigate('home');
    return;
  }

  const base = STRIPE_LINKS[tier];
  if (!base || base.includes('REPLACE_WITH')) {
    toast('Payment links not configured yet — check STRIPE_LINKS in app.js');
    return;
  }

  // Get a fresh Firebase ID token to verify identity on the server
  // (we pass the UID in the URL; the webhook double-checks it)
  let idToken = '';
  try {
    idToken = await S.user.getIdToken(true);
  } catch (e) {
    console.warn('Could not get ID token:', e.message);
  }

  // Build the Stripe URL with:
  //   client_reference_id = Firebase UID  → webhook uses this to write the tier
  //   prefilled_email     = user email    → pre-fills checkout form
  const params = new URLSearchParams({
    client_reference_id: S.user.uid,
    prefilled_email: S.user.email || '',
  });

  const url = `${base}?${params.toString()}`;

  // Show a confirmation modal so the user knows what they're buying
  // and that their account will be upgraded automatically after payment.
  showUpgradeConfirmModal(tier, url);
}

function showUpgradeConfirmModal(tier, stripeUrl) {
  document.getElementById('upgrade-confirm-modal')?.remove();
  const tierInfo = CREDIT_TIERS[tier];
  const modal = document.createElement('div');
  modal.id = 'upgrade-confirm-modal';
  modal.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,.55);z-index:99999;display:flex;align-items:center;justify-content:center;padding:20px';
  modal.innerHTML = `
    <div style="background:var(--bg-card);border-radius:20px;padding:32px;max-width:420px;width:100%;box-shadow:0 24px 80px rgba(0,0,0,.4)">
      <div style="text-align:center;margin-bottom:24px">
        <div style="width:52px;height:52px;background:var(--accent-bg);border-radius:14px;display:flex;align-items:center;justify-content:center;color:var(--accent);margin:0 auto 12px"><svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg></div>
        <h2 style="font-size:22px;font-weight:800;margin-bottom:6px">Upgrade to ${tierInfo.label}</h2>
        <div style="font-size:28px;font-weight:800;color:var(--accent);margin-bottom:4px">$${tierInfo.price}<span style="font-size:14px;font-weight:500;color:var(--text-muted)">/month</span></div>
        <div style="font-size:13px;color:var(--text-muted)">${tierInfo.credits.toLocaleString()} AI credits per month</div>
      </div>
      <div style="background:var(--bg);border-radius:12px;padding:14px 16px;margin-bottom:20px;font-size:13px;line-height:1.9;color:var(--text-muted)">
        <div style="margin-bottom:4px;display:flex;align-items:center;gap:8px"><svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="var(--green)" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg> Logged in as <strong style="color:var(--text)">${esc(S.user?.email || '')}</strong></div>
        <div style="margin-bottom:4px;display:flex;align-items:center;gap:8px"><svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="var(--green)" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg> Plan upgrades <strong style="color:var(--text)">automatically</strong> after payment</div>
        <div style="display:flex;align-items:center;gap:8px"><svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="var(--green)" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg> Taken to <strong style="color:var(--text)">Stripe's secure checkout</strong></div>
      </div>
      <div style="display:flex;gap:10px">
        <button class="btn btn-ghost" style="flex:1" onclick="document.getElementById('upgrade-confirm-modal')?.remove()">Cancel</button>
        <button class="btn btn-action" style="flex:2" onclick="document.getElementById('upgrade-confirm-modal')?.remove();window.open('${stripeUrl}','_blank','noopener,noreferrer')">
          Continue to Checkout →
        </button>
      </div>
      <div style="text-align:center;margin-top:14px;font-size:11px;color:var(--text-faint)">
        Payments processed securely by Stripe. Cancel anytime.
      </div>
    </div>`;
  modal.addEventListener('click', e => { if (e.target === modal) modal.remove(); });
  document.body.appendChild(modal);
}

function renderAIChatView(c) {
  c.innerHTML = `
    <div class="ai-chat-view">
      <div class="ai-chat-header">
        <button class="icon-btn" onclick="goBack()">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="15 18 9 12 15 6"/></svg>
        </button>
        <div class="ai-chat-header-info">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--accent)" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M9.5 2A2.5 2.5 0 0 1 12 4.5v15a2.5 2.5 0 0 1-4.96-.46 2.5 2.5 0 0 1-2.96-3.08 3 3 0 0 1-.34-5.58 2.5 2.5 0 0 1 1.32-4.24 2.5 2.5 0 0 1 1.98-3A2.5 2.5 0 0 1 9.5 2z"/><path d="M14.5 2A2.5 2.5 0 0 0 12 4.5v15a2.5 2.5 0 0 0 4.96-.46 2.5 2.5 0 0 0 2.96-3.08 3 3 0 0 0 .34-5.58 2.5 2.5 0 0 0-1.32-4.24 2.5 2.5 0 0 0-1.98-3A2.5 2.5 0 0 0 14.5 2z"/></svg>
          <span class="ai-chat-title">FlowAI — ${esc(AI.chatActionLabel || 'Chat')}</span>
        </div>
        <button class="icon-btn" onclick="AI.chatHistory=[];renderContent()" title="Clear chat">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 6h18"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg>
        </button>
      </div>
      <div class="ai-chat-context-bar">
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="var(--green)" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>
        FlowAI has access to your notes, tasks, calendar, flashcards &amp; more
      </div>
      <div class="ai-chat-messages" id="ai-chat-messages">
        ${AI.chatHistory.length === 0 ? `
          <div class="ai-chat-welcome">
            <div class="ai-chat-welcome-icon">
              <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="var(--accent)" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M9.5 2A2.5 2.5 0 0 1 12 4.5v15a2.5 2.5 0 0 1-4.96-.46 2.5 2.5 0 0 1-2.96-3.08 3 3 0 0 1-.34-5.58 2.5 2.5 0 0 1 1.32-4.24 2.5 2.5 0 0 1 1.98-3A2.5 2.5 0 0 1 9.5 2z"/><path d="M14.5 2A2.5 2.5 0 0 0 12 4.5v15a2.5 2.5 0 0 0 4.96-.46 2.5 2.5 0 0 0 2.96-3.08 3 3 0 0 0 .34-5.58 2.5 2.5 0 0 0-1.32-4.24 2.5 2.5 0 0 0-1.98-3A2.5 2.5 0 0 0 14.5 2z"/></svg>
            </div>
            <div class="ai-chat-welcome-title">Hi, I'm FlowAI</div>
            <div class="ai-chat-welcome-sub">I can see everything in your workspace. Ask me to summarise your day, explain your notes, plan your week, or anything else.</div>
            <div class="ai-chat-suggestions">
              <button class="ai-chat-suggestion" onclick="submitAIChatMessage('Summarise my day and what I should focus on')">Summarise my day</button>
              <button class="ai-chat-suggestion" onclick="submitAIChatMessage('What tasks are overdue or urgent?')">Overdue tasks?</button>
              <button class="ai-chat-suggestion" onclick="submitAIChatMessage('Create a study plan for this week based on my notes and tasks')">Plan my week</button>
              <button class="ai-chat-suggestion" onclick="submitAIChatMessage('Give me a quick summary of all my notes')">Notes digest</button>
            </div>
          </div>` :
      AI.chatHistory.map(m => `
            <div class="ai-chat-msg ai-chat-msg-${m.role}">
              ${m.role === 'assistant' ? `<div class="ai-chat-msg-avatar"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M9.5 2A2.5 2.5 0 0 1 12 4.5v15a2.5 2.5 0 0 1-4.96-.46 2.5 2.5 0 0 1-2.96-3.08 3 3 0 0 1-.34-5.58 2.5 2.5 0 0 1 1.32-4.24 2.5 2.5 0 0 1 1.98-3A2.5 2.5 0 0 1 9.5 2z"/><path d="M14.5 2A2.5 2.5 0 0 0 12 4.5v15a2.5 2.5 0 0 0 4.96-.46 2.5 2.5 0 0 0 2.96-3.08 3 3 0 0 0 .34-5.58 2.5 2.5 0 0 0-1.32-4.24 2.5 2.5 0 0 0-1.98-3A2.5 2.5 0 0 0 14.5 2z"/></svg></div>` : ''}
              <div class="ai-chat-msg-bubble">${markdownToHtml(esc(m.content))}</div>
            </div>`).join('')
    }
      </div>
      <div class="ai-chat-input-area">
        <textarea id="ai-chat-inp" class="ai-chat-textarea" placeholder="Ask FlowAI anything…" rows="1"
          onkeydown="if(event.key==='Enter'&&!event.shiftKey){event.preventDefault();submitAIChat();}"
          oninput="this.style.height='auto';this.style.height=Math.min(this.scrollHeight,160)+'px'"></textarea>
        <button class="ai-chat-send" onclick="submitAIChat()" id="ai-chat-send-btn">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><line x1="22" y1="2" x2="11" y2="13"/><polygon points="22 2 15 22 11 13 2 9 22 2"/></svg>
        </button>
      </div>
    </div>`;
  // Scroll to bottom
  const msgs = document.getElementById('ai-chat-messages');
  if (msgs) msgs.scrollTop = msgs.scrollHeight;
  setTimeout(() => document.getElementById('ai-chat-inp')?.focus(), 50);
}

async function submitAIChat() {
  const inp = document.getElementById('ai-chat-inp');
  const msg = inp?.value?.trim();
  if (!msg) return;
  if (inp) { inp.value = ''; inp.style.height = 'auto'; }
  await submitAIChatMessage(msg);
}

async function submitAIChatMessage(msg) {
  if (!ensureFeatureAccess('flowai', 'FlowAI Chat')) return;
  AI.chatHistory.push({ role: 'user', content: msg });
  renderContent(); // Re-render to show user message

  // Show typing indicator
  const msgs = document.getElementById('ai-chat-messages');
  if (msgs) {
    const typing = document.createElement('div');
    typing.className = 'ai-chat-msg ai-chat-msg-assistant ai-chat-typing';
    typing.id = 'ai-chat-typing';
    typing.innerHTML = `<div class="ai-chat-msg-avatar"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M9.5 2A2.5 2.5 0 0 1 12 4.5v15a2.5 2.5 0 0 1-4.96-.46 2.5 2.5 0 0 1-2.96-3.08 3 3 0 0 1-.34-5.58 2.5 2.5 0 0 1 1.32-4.24 2.5 2.5 0 0 1 1.98-3A2.5 2.5 0 0 1 9.5 2z"/><path d="M14.5 2A2.5 2.5 0 0 0 12 4.5v15a2.5 2.5 0 0 0 4.96-.46 2.5 2.5 0 0 0 2.96-3.08 3 3 0 0 0 .34-5.58 2.5 2.5 0 0 0-1.32-4.24 2.5 2.5 0 0 0-1.98-3A2.5 2.5 0 0 0 14.5 2z"/></svg></div><div class="ai-chat-msg-bubble"><div class="ai-typing-dots"><span></span><span></span><span></span></div></div>`;
    msgs.appendChild(typing);
    msgs.scrollTop = msgs.scrollHeight;
  }

  try {
    const sys = AI.chatSystem || `You are FlowAI, a smart study assistant. Here is the user's workspace:\n\n${getUserContext()}`;
    const response = await callAIConvo(sys, AI.chatHistory, 1024);
    document.getElementById('ai-chat-typing')?.remove();
    AI.chatHistory.push({ role: 'assistant', content: response });
    renderContent();
  } catch (e) {
    document.getElementById('ai-chat-typing')?.remove();
    AI.chatHistory.push({ role: 'assistant', content: `️ Error: ${e.message}` });
    renderContent();
  }
}
function getResultContainer(id) {
  // If we're routing an action through FlowAI chat, create a proper AI message bubble
  if (AI._routeResultsToChat) {
    AI._routeResultsToChat = false; // consume the flag
    const msgs = document.getElementById('flowai-msgs');
    if (msgs) {
      // Remove existing container with this id so we don't get stale results
      document.getElementById(id)?.remove();
      // Build AI message bubble (same structure as native FlowAI messages)
      const wrap = document.createElement('div');
      wrap.className = 'flowai-msg flowai-msg-assistant';
      const avSvg = `<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9.5 2A2.5 2.5 0 0 1 12 4.5v15a2.5 2.5 0 0 1-4.96-.46 2.5 2.5 0 0 1-2.96-3.08 3 3 0 0 1-.34-5.58 2.5 2.5 0 0 1 1.32-4.24 2.5 2.5 0 0 1 1.98-3A2.5 2.5 0 0 1 9.5 2z"/><path d="M14.5 2A2.5 2.5 0 0 0 12 4.5v15a2.5 2.5 0 0 0 4.96-.46 2.5 2.5 0 0 0 2.96-3.08 3 3 0 0 0 .34-5.58 2.5 2.5 0 0 0-1.32-4.24 2.5 2.5 0 0 0-1.98-3A2.5 2.5 0 0 0 14.5 2z"/></svg>`;
      const av = document.createElement('div');
      av.className = 'flowai-msg-av';
      av.innerHTML = avSvg;
      const bubble = document.createElement('div');
      bubble.className = 'flowai-bubble';
      bubble.id = id;
      // Allow ai-result content to be full-width inside the bubble
      bubble.style.cssText = 'max-width:100%;width:100%;padding:0;background:none;border:none;';
      wrap.appendChild(av);
      wrap.appendChild(bubble);
      msgs.appendChild(wrap);
      msgs.scrollTop = msgs.scrollHeight;
      return bubble;
    }
  }
  const el = document.getElementById(id);
  if (el) return el;
  const b = document.getElementById('ai-panel-body');
  if (!b) return null;
  const d = document.createElement('div');
  d.id = id;
  b.appendChild(d);
  return d;
}

// ─── WRITE FEATURES ──────────────────────────────────────────

async function aiRewriteClearly() {
  if (!ensureFeatureAccess('write_basic', 'Rewrite Clearly')) return;
  const rc = getResultContainer('ai-write-result');
  if (!S.page) return toast('Open a page first');
  const content = getPageTextContent(S.page);
  if (!content.trim()) return toast('Page is empty');
  showAILoading(rc, 'Rewriting notes…');
  try {
    const result = await callAI(
      'You are a writing assistant helping a student improve their notes. Rewrite the provided text with correct grammar, simpler and clearer language, better sentence structure and flow, all original facts preserved exactly, and markdown formatting (headings with ##, bullet points with -). Do not add new information. Return only the rewritten text, no preamble.',
      `Rewrite these notes:\n\n${content}`
    );
    rc.innerHTML = `
      <div class="ai-result">
        <div class="ai-result-header">
          <div class="ai-result-label"> Rewritten</div>
          <div class="ai-result-actions">
            <button class="btn btn-ghost btn-sm" onclick="copyAIResult(this)">Copy</button>
            <button class="btn btn-action btn-sm" onclick="applyRewrite(${JSON.stringify(result).replace(/</g, '\\u003c')})">Apply</button>
          </div>
        </div>
        <div class="ai-diff-wrap">
          <div>
            <div class="ai-diff-label original">Original</div>
            <div class="ai-diff-panel">${esc(content.slice(0, 600))}…</div>
          </div>
          <div>
            <div class="ai-diff-label rewritten">Rewritten</div>
            <div class="ai-diff-panel">${esc(result.slice(0, 600))}…</div>
          </div>
        </div>
      </div>`;
    rc._result = result;
  } catch (e) { showAIError(rc, e.message); }
}

function applyRewrite(result) {
  if (!S.page) return;
  applyMarkdownToPage(result, S.page);
  renderBlocks();
  toast('Rewrite applied');
  closeAIPanel();
}

async function aiStructureMessy() {
  if (!ensureFeatureAccess('write_plus', 'Structure Notes')) return;
  const rc = getResultContainer('ai-write-result');
  if (!S.page) return toast('Open a page first');
  const content = getPageTextContent(S.page);
  if (!content.trim()) return toast('Page is empty');
  showAILoading(rc, 'Structuring notes…');
  try {
    const result = await callAI(
      'You are a note-taking assistant. Convert the following messy, unstructured text into well-organised notes. Structure rules: identify the main topic and use it as an H1 heading (#), group related ideas under H2 headings (##), use bullet points (-) for lists, use numbered lists (1.) for sequences, keep all original information. If there are definitions, format them as: **Term** — definition. Return only the structured markdown. No preamble.',
      `Structure these notes:\n\n${content}`
    );
    rc.innerHTML = `
      <div class="ai-result">
        <div class="ai-result-header">
          <div class="ai-result-label"> Structured</div>
          <div class="ai-result-actions">
            <button class="btn btn-ghost btn-sm" onclick="copyAIResult(this)">Copy</button>
            <button class="btn btn-action btn-sm" onclick="applyStructure(${JSON.stringify(result).replace(/</g, '\\u003c')})">Apply</button>
          </div>
        </div>
        <div class="ai-result-body">${markdownToHtml(esc(result))}</div>
      </div>`;
    rc._result = result;
  } catch (e) { showAIError(rc, e.message); }
}

function applyStructure(result) {
  if (!S.page) return;
  applyMarkdownToPage(result, S.page);
  renderBlocks();
  toast('Structure applied');
  closeAIPanel();
}

function appendAIResultToPage(result) {
  if (!S.page) return toast('Open a page first');
  applyMarkdownToPage(result, S.page, true); // append mode
  renderBlocks();
  toast('Added to note');
  closeAIPanel();
}

// ─── ASK AI ABOUT THIS NOTE ───────────────────────────────────
function askAIAboutNote() {
  if (!S.page) return toast('Open a page first');
  const content = getPageTextContent(S.page);
  if (!content.trim()) return toast('Note is empty — add some content first');

  const existing = document.getElementById('ask-ai-panel');
  if (existing) { existing.remove(); return; }

  const panel = document.createElement('div');
  panel.id = 'ask-ai-panel';
  panel.style.cssText = 'position:fixed;bottom:0;left:0;right:0;background:var(--bg-card);border-top:1.5px solid var(--border-mid);padding:16px 20px;z-index:9000;box-shadow:0 -8px 32px rgba(0,0,0,.2);max-height:50vh;overflow-y:auto';
  panel.innerHTML = `
    <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:12px">
      <div style="font-weight:700;font-size:15px"> Ask AI about "${esc(S.page.title||'this note')}"</div>
      <button class="icon-btn" onclick="document.getElementById('ask-ai-panel')?.remove()">${icons.close}</button>
    </div>
    <div style="display:flex;gap:8px;margin-bottom:10px;flex-wrap:wrap">
      <button class="btn btn-secondary btn-sm" onclick="runNoteAI('summarise')">Summarise</button>
      <button class="btn btn-secondary btn-sm" onclick="runNoteAI('explain')">Explain Simply</button>
      <button class="btn btn-secondary btn-sm" onclick="runNoteAI('flashcards')">Generate Flashcards</button>
      <button class="btn btn-secondary btn-sm" onclick="runNoteAI('questions')">Practice Questions</button>
      <button class="btn btn-secondary btn-sm" onclick="runNoteAI('studyplan')">Study Plan</button>
      <button class="btn btn-secondary btn-sm" onclick="runNoteAI('improve')">Improve Writing</button>
    </div>
    <div style="display:flex;gap:8px;margin-bottom:10px">
      <input id="note-ai-inp" class="form-input" style="flex:1;height:36px" placeholder="Ask anything about this note…">
      <button class="btn btn-action btn-sm" onclick="runNoteAICustom()">Ask</button>
    </div>
    <div id="note-ai-result" style="margin-top:12px"></div>`;
  document.body.appendChild(panel);
  document.getElementById('note-ai-inp')?.focus();
  document.getElementById('note-ai-inp')?.addEventListener('keydown', e => { if (e.key === 'Enter') runNoteAICustom(); });
}

const _noteAIPrompts = {
  summarise: { sys: 'You are a study assistant. Summarise the notes clearly and concisely using bullet points. Focus on key concepts, facts, and takeaways.', msg: (c) => `Summarise these notes:\n\n${c}` },
  explain: { sys: 'You are a patient teacher. Explain this content in simple terms as if explaining to a 16-year-old. Use analogies and plain language.', msg: (c) => `Explain this simply:\n\n${c}` },
  flashcards: { sys: 'You are a study assistant. Generate 5-8 flashcard question/answer pairs from the content. Format as:\nQ: [question]\nA: [answer]\n\nSeparated by blank lines.', msg: (c) => `Generate flashcards from:\n\n${c}` },
  questions: { sys: 'You are an exam tutor. Generate 5-8 practice exam questions (mix of short answer and conceptual) based on the content. Number them.', msg: (c) => `Generate exam practice questions from:\n\n${c}` },
  studyplan: { sys: 'You are a study coach. Create a practical study plan for mastering this content. Include time estimates, spaced repetition advice, and suggested resources.', msg: (c) => `Create a study plan for:\n\n${c}` },
  improve: { sys: 'You are a writing editor. Improve the clarity, grammar, and structure of these notes. Keep all original information. Use markdown formatting.', msg: (c) => `Improve these notes:\n\n${c}` },
};

function parseFlashcardsFromText(text) {
  const lines = String(text || '').split('\n');
  const cards = [];
  let front = '', back = '';
  for (const raw of lines) {
    const line = raw.trim();
    if (/^Q:\s*/i.test(line)) {
      if (front && back) cards.push({ id: uid(), front: front.trim(), back: back.trim() });
      front = line.replace(/^Q:\s*/i, '');
      back = '';
    } else if (/^A:\s*/i.test(line)) {
      back = line.replace(/^A:\s*/i, '');
    } else if (line && back) {
      back += ' ' + line;
    }
  }
  if (front && back) cards.push({ id: uid(), front: front.trim(), back: back.trim() });
  return cards;
}

async function saveNoteFlashcardsToDeck(resultText) {
  const cards = parseFlashcardsFromText(resultText);
  if (!cards.length) return toast('Could not parse flashcards from AI response');
  const deck = {
    id: uid(),
    title: `AI Cards — ${S.page?.title || 'Untitled'}`,
    icon: 'flash',
    cards,
    createdAt: new Date().toISOString()
  };
  S.flashcards.push(deck);
  await saveData('flashcards', { [deck.id]: deck });
  toast(`Saved ${cards.length} cards to Flashcards`);
  navigate('flashcards');
}

async function runNoteAI(action) {
  const rc = document.getElementById('note-ai-result'); if (!rc) return;
  if (!S.page) return;
  if (!ensureFeatureAccess(action === 'flashcards' ? 'write_plus' : 'write_basic', 'AI Note Action')) return;
  const content = getPageTextContent(S.page);
  const p = _noteAIPrompts[action]; if (!p) return;
  // Token-aware: limit content to ~8000 chars
  const limited = content.slice(0, 8000);
  rc.innerHTML = `<div class="ai-loading"><div class="ai-spinner"></div><span>Thinking…</span></div>`;
  try {
    const result = await callAI(p.sys, p.msg(limited), 1200);
    rc.innerHTML = `<div class="ai-result">
      <div class="ai-result-header">
        <div class="ai-result-label">${action}</div>
        <div class="ai-result-actions">
          <button class="btn btn-ghost btn-sm" onclick="navigator.clipboard.writeText(this.closest('.ai-result').querySelector('.ai-result-body').textContent)">Copy</button>
          ${action === 'flashcards' ? `<button class="btn btn-action btn-sm" onclick="saveNoteFlashcardsToDeck(${JSON.stringify(result).replace(/</g, '\\u003c')})">Save Deck</button>` : ''}
          <button class="btn btn-ghost btn-sm" onclick="openAIChatWithQuestion(${JSON.stringify(result.slice(0,200))})">Continue in Chat →</button>
        </div>
      </div>
      <div class="ai-result-body">${markdownToHtml(esc(result))}</div>
    </div>`;
  } catch (e) { rc.innerHTML = `<div style="color:var(--red);font-size:13px"> ${esc(e.message)}</div>`; }
}

async function runNoteAICustom() {
  const inp = document.getElementById('note-ai-inp'); if (!inp) return;
  const q = inp.value.trim(); if (!q) return;
  const rc = document.getElementById('note-ai-result'); if (!rc) return;
  if (!S.page) return;
  if (!ensureFeatureAccess('write_basic', 'AI Note Chat')) return;
  const content = getPageTextContent(S.page).slice(0, 8000);
  rc.innerHTML = `<div class="ai-loading"><div class="ai-spinner"></div><span>Thinking…</span></div>`;
  try {
    const result = await callAI(
      `You are a study assistant helping a student understand their notes. The student's notes are provided. Answer their question clearly and helpfully.`,
      `Notes:\n${content}\n\nQuestion: ${q}`
    , 1024);
    rc.innerHTML = `<div class="ai-result">
      <div class="ai-result-header"><div class="ai-result-label">Answer</div></div>
      <div class="ai-result-body">${markdownToHtml(esc(result))}</div>
    </div>`;
    inp.value = '';
  } catch (e) { rc.innerHTML = `<div style="color:var(--red);font-size:13px"> ${esc(e.message)}</div>`; }
}

// ─── HIGHLIGHT TEXT AI ACTIONS ────────────────────────────────
function initHighlightAI() {
  document.addEventListener('mouseup', (e) => {
    if (!S.page) return;
    const sel = window.getSelection();
    const text = sel?.toString().trim();
    if (!text || text.length < 15) {
      document.getElementById('highlight-ai-toolbar')?.remove();
      return;
    }
    // Make sure selection is inside blocks-wrap
    const wrap = document.getElementById('blocks-wrap');
    if (!wrap || !wrap.contains(sel.anchorNode)) return;
    showHighlightAIToolbar(text, e);
  });
}

function showHighlightAIToolbar(text, e) {
  document.getElementById('highlight-ai-toolbar')?.remove();
  const tb = document.createElement('div');
  tb.id = 'highlight-ai-toolbar';
  tb.style.cssText = `position:fixed;z-index:9999;background:var(--bg-card);border:1.5px solid var(--border-mid);border-radius:10px;padding:6px 8px;display:flex;gap:4px;box-shadow:0 4px 20px rgba(0,0,0,.25);top:${Math.max(8, e.clientY - 60)}px;left:${Math.min(e.clientX - 50, window.innerWidth - 340)}px`;
  const safeText = encodeURIComponent(text.slice(0, 1000));
  tb.innerHTML = `
    <button class="btn btn-ghost btn-sm" style="font-size:11px" onclick="highlightAI('summarise','${safeText}')"> Summarise</button>
    <button class="btn btn-ghost btn-sm" style="font-size:11px" onclick="highlightAI('explain','${safeText}')"> Explain</button>
    <button class="btn btn-ghost btn-sm" style="font-size:11px" onclick="highlightAI('simplify','${safeText}')">✂ Simplify</button>
    <button class="btn btn-ghost btn-sm" style="font-size:11px" onclick="highlightAI('questions','${safeText}')">? Questions</button>
    <button class="icon-btn" style="width:22px;height:22px" onclick="document.getElementById('highlight-ai-toolbar')?.remove()">${icons.close}</button>`;
  document.body.appendChild(tb);
  // Auto-dismiss
  setTimeout(() => { document.addEventListener('mousedown', () => tb.remove(), { once: true }); }, 100);
}

const _hlPrompts = {
  summarise: 'Summarise this text in 2-3 bullet points:',
  explain: 'Explain this text in simple, clear terms:',
  simplify: 'Rewrite this text in simpler language while preserving all meaning:',
  questions: 'Generate 3 practice questions based on this text:',
};

async function highlightAI(action, encodedText) {
  if (!ensureFeatureAccess('write_basic', 'Highlight AI')) return;
  document.getElementById('highlight-ai-toolbar')?.remove();
  const text = decodeURIComponent(encodedText);
  // Show result in a floating panel
  const existing = document.getElementById('highlight-ai-result');
  if (existing) existing.remove();
  const panel = document.createElement('div');
  panel.id = 'highlight-ai-result';
  panel.style.cssText = 'position:fixed;bottom:20px;right:20px;z-index:9998;background:var(--bg-card);border:1.5px solid var(--border-mid);border-radius:14px;padding:16px;max-width:380px;max-height:300px;overflow-y:auto;box-shadow:0 8px 32px rgba(0,0,0,.25)';
  panel.innerHTML = `<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px"><span style="font-size:13px;font-weight:700;color:var(--accent)"> ${action}</span><button class="icon-btn" onclick="document.getElementById('highlight-ai-result')?.remove()" style="width:22px;height:22px">${icons.close}</button></div><div class="ai-loading"><div class="ai-spinner"></div><span>Thinking…</span></div>`;
  document.body.appendChild(panel);
  try {
    const result = await callAI(`You are a study assistant. Be concise and helpful.`, `${_hlPrompts[action]}\n\n${text}`, 512);
    const body = panel.querySelector('.ai-loading');
    if (body) body.outerHTML = `<div style="font-size:13px;line-height:1.6">${markdownToHtml(esc(result))}</div><div style="margin-top:10px;display:flex;gap:6px"><button class="btn btn-ghost btn-sm" onclick="navigator.clipboard.writeText('${result.replace(/'/g,"\\'")}');toast('Copied!')">Copy</button><button class="btn btn-ghost btn-sm" onclick="openAIChatWithQuestion(decodeURIComponent('${encodedText}'))">Chat →</button></div>`;
  } catch (e) {
    panel.querySelector('.ai-loading').outerHTML = `<div style="color:var(--red);font-size:12px"> ${esc(e.message)}</div>`;
  }
}

async function aiSummarise(length) {
  if (!ensureFeatureAccess(length === 'long' ? 'write_pro' : 'write_basic', 'Summarise')) return;
  const rc = getResultContainer('ai-write-result');
  if (!S.page) return toast('Open a page first');
  const content = getPageTextContent(S.page);
  if (!content.trim()) return toast('Page is empty');
  const prompts = {
    short: 'Summarise the following notes in exactly 3 sentences. First sentence: the main topic. Second: the most important point. Third: the key takeaway. No bullet points. Plain prose only.',
    medium: 'Write a single clear paragraph summarising the key points of these notes. Aim for around 100 words. Capture the main argument and 2-3 supporting ideas. No headings or bullet points — flowing prose only.',
    long: 'Write a detailed summary of these notes in structured markdown. Use ## headings for each major section. Write in full sentences, not bullet points. Aim for approximately 300 words. Include main concepts, supporting evidence, and conclusions.'
  };
  showAILoading(rc, 'Summarising…');
  try {
    const result = await callAI(prompts[length], `Summarise:\n\n${content}`);
    const labels = { short: 'Short Summary', medium: 'Medium Summary', long: 'Long Summary' };
    rc.innerHTML = `
      <div class="ai-result">
        <div class="ai-result-header">
          <div class="ai-result-label">${labels[length]}</div>
          <div class="ai-result-actions">
            <button class="btn btn-ghost btn-sm" onclick="copyAIResult(this)">Copy</button>
            <button class="btn btn-ghost btn-sm" onclick="saveAsNewPage(${JSON.stringify(result).replace(/</g, '\\u003c')}, 'Summary: ${esc(S.page.title || 'Untitled')}')">Save as Page</button>
            <button class="btn btn-action btn-sm" onclick="appendAIResultToPage(${JSON.stringify(result).replace(/</g, '\\u003c')})">Apply to Note</button>
          </div>
        </div>
        <div class="ai-result-body">${markdownToHtml(esc(result))}</div>
      </div>`;
    rc._result = result;
  } catch (e) { showAIError(rc, e.message); }
}

async function aiExtract(mode) {
  if (!ensureFeatureAccess('write_plus', 'Extract')) return;
  const rc = getResultContainer('ai-write-result');
  if (!S.page) return toast('Open a page first');
  const content = getPageTextContent(S.page);
  if (!content.trim()) return toast('Page is empty');
  const prompts = {
    keypoints: 'Extract the most important points from these notes as a concise bulleted list. Maximum 10 bullet points. Order by importance, most important first. Each bullet is one clear sentence. Exclude minor details and examples. Return only the bullet list. No preamble.',
    formulas: 'Extract every formula, equation, and mathematical expression from these notes. Format each as: **Formula name or context**\n`formula here`\nWhere used / what it means: one sentence\n\nIf no formulas are found, say: "No formulas detected in these notes." Return only the formatted list.',
    definitions: 'Extract every definition, key term, and technical concept from these notes. Format each as: **Term** — clear, concise definition in your own words based on the notes\n\nAlphabetise the list. Return only the definition list. No preamble.'
  };
  const labels = { keypoints: 'Key Points', formulas: 'Formulas', definitions: 'Definitions' };
  showAILoading(rc, 'Extracting…');
  try {
    const result = await callAI(prompts[mode], `Extract from:\n\n${content}`);
    rc.innerHTML = `
      <div class="ai-result">
        <div class="ai-result-header">
          <div class="ai-result-label">${labels[mode]}</div>
          <div class="ai-result-actions">
            <button class="btn btn-ghost btn-sm" onclick="copyAIResult(this)">Copy</button>
            <button class="btn btn-action btn-sm" onclick="saveAsNewPage(${JSON.stringify(result).replace(/</g, '\\u003c')}, '${labels[mode]}: ${esc(S.page.title || 'Untitled')}')">Save</button>
          </div>
        </div>
        <div class="ai-result-body">${markdownToHtml(esc(result))}</div>
      </div>`;
  } catch (e) { showAIError(rc, e.message); }
}

async function aiConvert(type) {
  if (!ensureFeatureAccess(type === 'essay' ? 'essay_pro' : 'write_plus', 'Convert')) return;
  const rc = getResultContainer('ai-write-result');
  if (!S.page) return toast('Open a page first');
  const content = getPageTextContent(S.page);
  if (!content.trim()) return toast('Page is empty');
  const configs = {
    lecture: { system: 'Convert these lecture notes into a clean study note. Format: H1 for topic, H2 for "Key Concepts", "Definitions", "Examples", "Summary", "To Review". Keep all information but reorganise it for self-study. Remove filler phrases like "the lecturer said". Return only the formatted markdown.', prompt: 'Convert these lecture notes:\n\n', label: 'Study Note' },
    studyplan: { system: 'Based on these notes, create a structured study plan. Format: # Study Plan: [Topic], ## Learning Goals (3-5 bullets), ## Day-by-Day Schedule, ## Key Topics to Master (ordered by importance), ## Suggested Resources. Return only the formatted markdown.', prompt: 'Create a study plan from:\n\n', label: ' Study Plan' },
    essay: { system: 'Convert these notes into an essay outline. Format: # Essay: [title], ## Thesis Statement, ## Introduction Hook, ## Body Paragraphs (### for each), ## Conclusion, ## Gaps to Research. Return only the formatted markdown.', prompt: 'Create an essay outline from:\n\n', label: 'Essay Outline' },
    book: { system: 'Convert these book notes into a clean book summary. Format: # [Title], **Author:**, ## In One Sentence, ## Core Argument, ## Key Ideas (numbered), ## Best Quotes, ## What I\'ll Apply, ## Would I Recommend It? Return only the formatted markdown.', prompt: 'Summarise these book notes:\n\n', label: 'Book Summary' }
  };
  const cfg = configs[type];
  showAILoading(rc, 'Converting…');
  try {
    const result = await callAI(cfg.system, cfg.prompt + content);
    rc.innerHTML = `
      <div class="ai-result">
        <div class="ai-result-header">
          <div class="ai-result-label">${cfg.label}</div>
          <div class="ai-result-actions">
            <button class="btn btn-ghost btn-sm" onclick="copyAIResult(this)">Copy</button>
            <button class="btn btn-action btn-sm" onclick="saveAsNewPage(${JSON.stringify(result).replace(/</g, '\\u003c')}, '${cfg.label}: ${esc(S.page.title || 'Untitled')}')">Save as Page</button>
          </div>
        </div>
        <div class="ai-result-body">${markdownToHtml(esc(result))}</div>
      </div>`;
  } catch (e) { showAIError(rc, e.message); }
}

async function aiRevisionGuide() {
  if (!ensureFeatureAccess('write_pro', 'Revision Guide')) return;
  const rc = getResultContainer('ai-write-result');
  if (!S.page) return toast('Open a page first');
  const content = getPageTextContent(S.page);
  if (!content.trim()) return toast('Page is empty');
  showAILoading(rc, 'Generating revision guide…');
  try {
    const result = await callAI(
      'Create a comprehensive revision guide from these notes to help a student revise before an exam. Format: # Revision Guide: [topic], ## What You Need to Know (5-10 exam essentials), ## Complete Content (## headings for each section), ## Memory Aids (mnemonics, acronyms), ## Common Exam Mistakes, ## Quick Recall Section (10 key terms with one-line definitions), ## Exam Technique Tips. Make it dense but scannable. Use bold for key terms.',
      `Create a revision guide from:\n\n${content}`,
      2048
    );
    rc.innerHTML = `
      <div class="ai-result">
        <div class="ai-result-header">
          <div class="ai-result-label">Revision Guide</div>
          <div class="ai-result-actions">
            <button class="btn btn-ghost btn-sm" onclick="copyAIResult(this)">Copy</button>
            <button class="btn btn-action btn-sm" onclick="saveAsNewPage(${JSON.stringify(result).replace(/</g, '\\u003c')}, 'Revision: ${esc(S.page.title || 'Untitled')}')">Save as Page</button>
          </div>
        </div>
        <div class="ai-result-body">${markdownToHtml(esc(result))}</div>
      </div>`;
  } catch (e) { showAIError(rc, e.message); }
}

async function aiGenerateFlashcards() {
  if (!ensureFeatureAccess('write_plus', 'AI Flashcards')) return;
  const rc = getResultContainer('ai-write-result');
  if (!S.page) return toast('Open a page first');
  const content = getPageTextContent(S.page);
  if (!content.trim()) return toast('Page is empty');

  rc.innerHTML = `
    <div class="ai-result">
      <div class="ai-result-header"><div class="ai-result-label">Generate Flashcards</div></div>
      <div class="ai-input-label">Number of cards</div>
      <div class="ai-options-row">
        <button class="ai-opt-chip selected" onclick="selectChip(this,'fc-count')">10</button>
        <button class="ai-opt-chip" onclick="selectChip(this,'fc-count')">15</button>
        <button class="ai-opt-chip" onclick="selectChip(this,'fc-count')">20</button>
      </div>
      <div class="ai-input-label">Card type</div>
      <div class="ai-options-row">
        <button class="ai-opt-chip selected" onclick="selectChip(this,'fc-type')">Definition</button>
        <button class="ai-opt-chip" onclick="selectChip(this,'fc-type')">Q&A</button>
        <button class="ai-opt-chip" onclick="selectChip(this,'fc-type')">Mixed</button>
      </div>
      <button class="btn btn-action" style="width:100%;margin-top:6px" onclick="runGenerateFlashcards()">Generate Cards</button>
    </div>
    <div id="fc-result"></div>`;
}

async function runGenerateFlashcards() {
  if (!ensureFeatureAccess('write_plus', 'AI Flashcards')) return;
  const countEl = document.querySelector('#ai-write-result .ai-opt-chip.selected[onclick*="fc-count"]');
  const typeEl = document.querySelector('#ai-write-result .ai-opt-chip.selected[onclick*="fc-type"]');
  const count = countEl?.textContent.trim() || '10';
  const cardType = typeEl?.textContent.trim() || 'Definition';
  const content = getPageTextContent(S.page);
  const rc = document.getElementById('fc-result');
  showAILoading(rc, 'Generating flashcards…');
  try {
    const typeRules = {
      'Definition': 'Definition cards: front = term, back = definition',
      'Q&A': 'Q&A cards: front = question starting with What/Why/How/When, back = concise answer',
      'Mixed': 'Mix of definition cards and Q&A cards'
    };
    const cards = await callAIJson(
      `Create ${count} flashcards from these notes for spaced repetition studying. ${typeRules[cardType]}. Return a JSON array only, no other text: [{"front": "question or term", "back": "answer or definition"}]. Make cards specific enough to test real understanding. Avoid cards where the answer is obvious.`,
      `Create flashcards from:\n\n${content}`,
      2048
    );
    if (!Array.isArray(cards)) throw new Error('Unexpected format');
    rc.innerHTML = `
      <div class="ai-result">
        <div class="ai-result-header">
          <div class="ai-result-label">▣ ${cards.length} Cards Generated</div>
          <div class="ai-result-actions">
            <button class="btn btn-action btn-sm" onclick="saveDeckFromCards()">Save as Deck</button>
          </div>
        </div>
        <div class="ai-card-list" id="fc-cards">
          ${cards.map((c, i) => `
            <div class="ai-card-item" data-idx="${i}">
              <div class="ai-card-front">${esc(c.front)}</div>
              <div class="ai-card-back">${esc(c.back)}</div>
              <button class="icon-btn" style="color:var(--red)" onclick="this.closest('.ai-card-item').remove()">${icons.trash}</button>
            </div>`).join('')}
        </div>
      </div>`;
    window._aiCards = cards;
  } catch (e) { showAIError(rc, e.message); }
}

async function saveDeckFromCards() {
  const items = document.querySelectorAll('#fc-cards .ai-card-item');
  const cards = Array.from(items).map(item => ({
    id: uid(),
    front: item.querySelector('.ai-card-front')?.textContent.trim() || '',
    back: item.querySelector('.ai-card-back')?.textContent.trim() || ''
  })).filter(c => c.front);
  if (!cards.length) return toast('No cards to save');
  const deck = { id: uid(), title: `AI Cards — ${S.page?.title || 'Untitled'}`, icon: 'flash', cards, createdAt: new Date().toISOString() };
  S.flashcards.push(deck);
  await saveData('flashcards', { [deck.id]: deck });
  toast(`Saved "${deck.title}" (${cards.length} cards) ✓`);
  closeAIPanel();
  navigate('flashcards');
}

async function aiGenerateTasks() {
  if (!ensureFeatureAccess('write_plus', 'Task Extraction')) return;
  const rc = getResultContainer('ai-write-result');
  if (!S.page) return toast('Open a page first');
  const content = getPageTextContent(S.page);
  if (!content.trim()) return toast('Page is empty');
  showAILoading(rc, 'Extracting tasks…');
  try {
    const tasks = await callAIJson(
      'Extract every action item, task, and thing to do from these notes. Return a JSON array: [{"title": "task description", "priority": "high|medium|low", "category": "review|read|complete|write|practice"}]. Rules: only include genuine action items; high priority = deadlines/urgent; keep task descriptions concise (under 10 words). Return only the JSON array.',
      `Extract tasks from:\n\n${content}`,
      1024
    );
    if (!Array.isArray(tasks)) throw new Error('Unexpected format');
    rc.innerHTML = `
      <div class="ai-result">
        <div class="ai-result-header">
          <div class="ai-result-label"> ${tasks.length} Tasks Found</div>
          <div class="ai-result-actions">
            <button class="btn btn-action btn-sm" onclick="saveAITasks()">Add to Tasks</button>
          </div>
        </div>
        ${tasks.map((t, i) => `
          <div class="ai-task-preview" style="display:flex;align-items:center;gap:8px;padding:7px 0;border-bottom:1px solid var(--border);font-size:13px">
            <div class="dot d-${t.priority === 'high' ? 'high' : t.priority === 'low' ? 'low' : 'med'}"></div>
            <span style="flex:1">${esc(t.title)}</span>
            <span style="font-size:11px;color:var(--text-faint)">${esc(t.category)}</span>
          </div>`).join('')}
      </div>`;
    window._aiTasks = tasks;
  } catch (e) { showAIError(rc, e.message); }
}

async function saveAITasks() {
  const tasks = window._aiTasks || [];
  if (!tasks.length) return;
  const newTasks = tasks.map(t => {
    const pri = t.priority === 'high' ? 'high' : t.priority === 'low' ? 'low' : 'med';
    return { id: uid(), title: t.title, priority: pri, completed: false, status: 'todo', createdAt: new Date().toISOString() };
  });
  S.tasks = [...S.tasks, ...newTasks];
  const obj = {};
  newTasks.forEach(t => { obj[t.id] = t; });
  await saveData('tasks', obj);
  toast(`Added ${newTasks.length} tasks ✓`);
  closeAIPanel();
  navigate('tasks');
}

async function aiArgumentStrengthener() {
  if (!ensureFeatureAccess('essay_pro', 'Argument Strengthener')) return;
  const rc = getResultContainer('ai-write-result');
  rc.innerHTML = `
    <div class="ai-result">
      <div class="ai-result-header"><div class="ai-result-label">Argument Strengthener</div></div>
      <div class="ai-input-area">
        <label class="ai-input-label">Paste your thesis or argument paragraph</label>
        <textarea id="arg-input" placeholder="e.g. Universal basic income would reduce poverty by providing a financial floor..."></textarea>
      </div>
      <button class="btn btn-action" style="width:100%" onclick="runArgumentStrengthener()">Strengthen Argument</button>
    </div>
    <div id="arg-result"></div>`;
}

async function runArgumentStrengthener() {
  if (!ensureFeatureAccess('essay_pro', 'Argument Strengthener')) return;
  const input = document.getElementById('arg-input')?.value.trim();
  if (!input) return toast('Enter an argument');
  const rc = document.getElementById('arg-result');
  showAILoading(rc, 'Analysing argument…');
  try {
    const result = await callAIJson(
      'You are an academic writing coach and critical thinker. Analyse this argument and identify its weaknesses so the student can strengthen it. Return JSON: {"argumentSummary": "one sentence", "counterarguments": [{"title": "short name", "explanation": "why valid", "strength": "strong|moderate|weak", "howToAddress": "specific advice", "samplePhrase": "example sentence"}], "improvedThesis": "stronger version", "overallVerdict": "honest assessment"}',
      `Analyse this argument:\n\n${input}`,
      2048
    );
    rc.innerHTML = `
      <div class="ai-result">
        <div class="ai-result-header"><div class="ai-result-label"> Strengthened</div></div>
        <div style="font-size:13px;color:var(--text-muted);margin-bottom:12px;font-style:italic">${esc(result.argumentSummary || '')}</div>
        <div class="ai-feature-group-label">Counterarguments</div>
        ${(result.counterarguments || []).map(c => `
          <div style="background:var(--bg-sidebar);border-left:3px solid ${c.strength === 'strong' ? 'var(--red)' : c.strength === 'moderate' ? 'var(--orange)' : 'var(--green)'};border-radius:0 var(--r) var(--r) 0;padding:10px 12px;margin-bottom:8px">
            <div style="font-weight:700;font-size:13px;margin-bottom:4px">${esc(c.title)} <span style="font-size:11px;opacity:.6">${esc(c.strength)}</span></div>
            <div style="font-size:12.5px;color:var(--text-muted);margin-bottom:6px">${esc(c.explanation)}</div>
            <div style="font-size:12px;color:var(--accent)">How to address: ${esc(c.howToAddress)}</div>
            ${c.samplePhrase ? `<div style="font-size:12px;color:var(--text-faint);margin-top:4px;font-style:italic">"${esc(c.samplePhrase)}"</div>` : ''}
          </div>`).join('')}
        ${result.improvedThesis ? `<div style="background:rgba(99,102,241,.08);border:1px solid rgba(99,102,241,.2);border-radius:var(--r);padding:10px;margin-top:8px;font-size:13px"><strong>Improved thesis:</strong><br>${esc(result.improvedThesis)}</div>` : ''}
        ${result.overallVerdict ? `<div style="font-size:12.5px;color:var(--text-muted);margin-top:8px;font-style:italic">${esc(result.overallVerdict)}</div>` : ''}
      </div>`;
  } catch (e) { showAIError(rc, e.message); }
}

async function aiCitationSuggester() {
  if (!ensureFeatureAccess('essay_pro', 'Citation Suggester')) return;
  const rc = getResultContainer('ai-write-result');
  rc.innerHTML = `
    <div class="ai-result">
      <div class="ai-result-header"><div class="ai-result-label">Citation Suggester</div></div>
      <div class="ai-input-area">
        <label class="ai-input-label">Paste your essay argument or paragraph</label>
        <textarea id="cit-input" placeholder="Paste your essay argument here…"></textarea>
      </div>
      <button class="btn btn-action" style="width:100%" onclick="runCitationSuggester()">Find Evidence Needed</button>
    </div>
    <div id="cit-result"></div>`;
}

async function runCitationSuggester() {
  if (!ensureFeatureAccess('essay_pro', 'Citation Suggester')) return;
  const input = document.getElementById('cit-input')?.value.trim();
  if (!input) return toast('Enter an argument');
  const rc = document.getElementById('cit-result');
  showAILoading(rc, 'Analysing evidence needs…');
  try {
    const result = await callAIJson(
      'Read this essay argument and identify what evidence it needs. DO NOT suggest specific sources, titles, or authors — only types of evidence and where to find them. Return JSON: {"argumentWeaknesses": ["what\'s unsubstantiated"], "evidenceNeeded": [{"claim": "specific claim", "evidenceType": "statistical data|case study|expert opinion|historical example|primary source|meta-analysis", "wherToFind": "type of database or resource", "searchTerms": ["suggested search terms"]}], "overallEvidenceRating": "strong|adequate|thin — with one sentence explanation"}',
      `Analyse evidence needs for:\n\n${input}`,
      1536
    );
    rc.innerHTML = `
      <div class="ai-result">
        <div class="ai-result-header"><div class="ai-result-label"> Evidence Needed</div></div>
        <div style="display:inline-flex;align-items:center;gap:5px;padding:3px 10px;border-radius:99px;font-size:11.5px;font-weight:700;margin-bottom:12px;background:rgba(99,102,241,.1);color:var(--accent)">${esc(result.overallEvidenceRating || '')}</div>
        ${(result.argumentWeaknesses || []).length ? `<div class="ai-feature-group-label">What's unsubstantiated</div><ul style="margin:0 0 12px;padding-left:18px;font-size:13px;color:var(--text-muted)">${(result.argumentWeaknesses || []).map(w => `<li>${esc(w)}</li>`).join('')}</ul>` : ''}
        <div class="ai-feature-group-label">Evidence You Need</div>
        ${(result.evidenceNeeded || []).map(e => `
          <div style="background:var(--bg-sidebar);border:1px solid var(--border);border-radius:var(--r);padding:10px 12px;margin-bottom:8px">
            <div style="font-size:12px;font-weight:700;color:var(--accent);margin-bottom:4px">${esc(e.evidenceType)}</div>
            <div style="font-size:13px;color:var(--text);margin-bottom:4px">${esc(e.claim)}</div>
            <div style="font-size:12px;color:var(--text-muted)">Find in: ${esc(e.wherToFind)}</div>
            ${e.searchTerms?.length ? `<div style="font-size:11.5px;color:var(--text-faint);margin-top:4px">Search: ${e.searchTerms.map(s => `"${esc(s)}"`).join(', ')}</div>` : ''}
          </div>`).join('')}
      </div>`;
  } catch (e) { showAIError(rc, e.message); }
}

// ─── STUDY FEATURES ──────────────────────────────────────────

function renderFeynmanExplainer() {
  const rc = getResultContainer('ai-study-result');
  rc.innerHTML = `
    <div class="ai-result">
      <div class="ai-result-header"><div class="ai-result-label"> Feynman Explainer</div></div>
      <div class="ai-input-area">
        <label class="ai-input-label">What concept do you want explained?</label>
        <input class="form-input" id="feynman-concept" placeholder="e.g. Quantum entanglement, The French Revolution…" style="margin-bottom:8px">
        <label class="ai-input-label">Optional: paste your notes for context</label>
        <textarea id="feynman-notes" placeholder="Paste relevant notes here…" style="min-height:60px"></textarea>
      </div>
      <button class="btn btn-action" style="width:100%" onclick="runFeynman()">Explain at All Levels</button>
    </div>
    <div id="feynman-result"></div>`;
}

async function runFeynman() {
  if (!ensureFeatureAccess('study_plus', 'Feynman Explainer')) return;
  const concept = document.getElementById('feynman-concept')?.value.trim();
  const notes = document.getElementById('feynman-notes')?.value.trim();
  if (!concept) return toast('Enter a concept');
  const rc = document.getElementById('feynman-result');
  showAILoading(rc, 'Generating 3-level explanation…');
  try {
    const notesCtx = notes ? `\n\nStudent notes for context:\n${notes}` : '';
    const result = await callAIJson(
      `Explain the concept clearly at three different levels. Return JSON: {"concept": "the concept name", "simple": "Explanation for a 12-year-old. Use analogies, everyday examples, no jargon. 3-4 sentences.", "student": "Explanation for a university student. Use correct terminology but stay accessible. Include why it matters. 2-3 paragraphs.", "technical": "Full technical explanation with precise language, nuances, edge cases, and connections to related concepts. 3-4 paragraphs."}`,
      `Explain: "${concept}"${notesCtx}`,
      2048
    );
    rc.innerHTML = `
      <div class="ai-feynman-cards">
        <div class="ai-feynman-card">
          <div class="ai-feynman-level simple"> Simple (like you're 12)</div>
          <div class="ai-feynman-text">${esc(result.simple || '')}</div>
          <button class="btn btn-ghost btn-sm" style="margin-top:8px" onclick="navigator.clipboard.writeText(${JSON.stringify(result.simple || '')});toast('Copied')">Copy</button>
        </div>
        <div class="ai-feynman-card">
          <div class="ai-feynman-level student"> Student Level</div>
          <div class="ai-feynman-text">${esc(result.student || '')}</div>
          <button class="btn btn-ghost btn-sm" style="margin-top:8px" onclick="navigator.clipboard.writeText(${JSON.stringify(result.student || '')});toast('Copied')">Copy</button>
        </div>
        <div class="ai-feynman-card">
          <div class="ai-feynman-level technical"> Technical Depth</div>
          <div class="ai-feynman-text">${esc(result.technical || '')}</div>
          <button class="btn btn-ghost btn-sm" style="margin-top:8px" onclick="navigator.clipboard.writeText(${JSON.stringify(result.technical || '')});toast('Copied')">Copy</button>
        </div>
      </div>`;
  } catch (e) { showAIError(rc, e.message); }
}

function renderPracticeQuestions() {
  const rc = getResultContainer('ai-study-result');
  const currentPage = S.view === 'page' && S.page;
  rc.innerHTML = `
    <div class="ai-result">
      <div class="ai-result-header"><div class="ai-result-label">? Practice Questions</div></div>
      ${!currentPage ? '<div style="font-size:12.5px;color:var(--text-faint);margin-bottom:10px">Open a page to generate questions from it, or type a topic below.</div>' : ''}
      <div class="ai-input-area">
        <label class="ai-input-label">Topic (if no page open)</label>
        <input class="form-input" id="pq-topic" placeholder="e.g. Photosynthesis, World War II…" style="margin-bottom:8px" value="${currentPage ? esc(currentPage.title || '') : ''}">
      </div>
      <div class="ai-input-label">Number of questions</div>
      <div class="ai-options-row">
        <button class="ai-opt-chip selected" onclick="selectChip(this,'pq-count')">5</button>
        <button class="ai-opt-chip" onclick="selectChip(this,'pq-count')">10</button>
        <button class="ai-opt-chip" onclick="selectChip(this,'pq-count')">15</button>
      </div>
      <div class="ai-input-label">Question types</div>
      <div class="ai-options-row">
        <button class="ai-opt-chip selected" onclick="toggleChip(this)">MCQ</button>
        <button class="ai-opt-chip selected" onclick="toggleChip(this)">Short Answer</button>
        <button class="ai-opt-chip selected" onclick="toggleChip(this)">True/False</button>
      </div>
      <button class="btn btn-action" style="width:100%;margin-top:6px" onclick="runPracticeQuestions()">Generate Questions</button>
    </div>
    <div id="pq-result"></div>`;
}

async function runPracticeQuestions() {
  if (!ensureFeatureAccess('study_plus', 'Practice Questions')) return;
  const topic = document.getElementById('pq-topic')?.value.trim();
  const countEl = document.querySelector('#ai-study-result .ai-opt-chip.selected[onclick*="pq-count"]');
  const count = countEl?.textContent.trim() || '5';
  const types = Array.from(document.querySelectorAll('#ai-study-result .ai-opt-chip.selected:not([onclick*="pq-count"])')).map(el => el.textContent.trim()).filter(Boolean);
  const rc = document.getElementById('pq-result');
  showAILoading(rc, 'Generating questions…');

  const content = S.page ? getPageTextContent(S.page) : '';
  const context = content ? `\n\nBased on these notes:\n${content.slice(0, 3000)}` : '';

  try {
    const result = await callAIJson(
      `Generate ${count} practice questions on the topic. Mix the types: ${types.join(', ')}. Return JSON only: {"topic": "detected topic", "questions": [{"id": 1, "type": "mcq", "question": "...", "options": ["A","B","C","D"], "answer": "B", "explanation": "..."}, {"id": 2, "type": "short_answer", "question": "...", "model_answer": "...", "key_points": ["point1"]}, {"id": 3, "type": "true_false", "question": "...", "answer": true, "explanation": "..."}]}. Make questions test understanding, not just recall.`,
      `Topic: ${topic}${context}`,
      2048
    );
    window._pqData = result;
    window._pqUserAnswers = {};
    renderPQQuestions(rc, result);
  } catch (e) { showAIError(rc, e.message); }
}

function renderPQQuestions(rc, data) {
  if (!data?.questions?.length) return showAIError(rc, 'No questions generated');
  rc.innerHTML = `<div id="pq-questions">` +
    data.questions.map((q, i) => renderSingleQuestion(q, i)).join('') +
    `<button class="btn btn-action" style="width:100%;margin-top:10px" onclick="showPQResults()">Submit Answers</button></div>`;
}

function renderSingleQuestion(q, i) {
  if (q.type === 'mcq') {
    return `<div class="ai-question-card" data-qid="${q.id}">
      <div class="ai-question-num">Q${i + 1} — Multiple Choice</div>
      <div class="ai-question-text">${esc(q.question)}</div>
      <div class="ai-question-options">
        ${(q.options || []).map((opt, oi) => `
          <div class="ai-q-option" onclick="selectPQOption(this, '${q.id}', ${JSON.stringify(opt).replace(/</g, '\\u003c')})">
            <div class="ai-q-marker">${String.fromCharCode(65 + oi)}</div>
            ${esc(opt)}
          </div>`).join('')}
      </div>
    </div>`;
  }
  if (q.type === 'true_false') {
    return `<div class="ai-question-card" data-qid="${q.id}">
      <div class="ai-question-num">Q${i + 1} — True / False</div>
      <div class="ai-question-text">${esc(q.question)}</div>
      <div class="ai-question-options">
        <div class="ai-q-option" onclick="selectPQOption(this, '${q.id}', 'true')"><div class="ai-q-marker">T</div>True</div>
        <div class="ai-q-option" onclick="selectPQOption(this, '${q.id}', 'false')"><div class="ai-q-marker">F</div>False</div>
      </div>
    </div>`;
  }
  if (q.type === 'short_answer') {
    return `<div class="ai-question-card" data-qid="${q.id}">
      <div class="ai-question-num">Q${i + 1} — Short Answer</div>
      <div class="ai-question-text">${esc(q.question)}</div>
      <textarea class="form-input" style="width:100%;min-height:70px;resize:vertical;box-sizing:border-box;margin-top:6px" placeholder="Write your answer…" oninput="window._pqUserAnswers = window._pqUserAnswers||{}; window._pqUserAnswers['${q.id}'] = this.value"></textarea>
    </div>`;
  }
  return '';
}

function selectPQOption(el, qid, value) {
  const card = el.closest('.ai-question-card');
  card.querySelectorAll('.ai-q-option').forEach(o => o.classList.remove('selected'));
  el.classList.add('selected');
  window._pqUserAnswers = window._pqUserAnswers || {};
  window._pqUserAnswers[qid] = value;
}

function showPQResults() {
  const data = window._pqData;
  const answers = window._pqUserAnswers || {};
  const rc = document.getElementById('pq-result');
  let correct = 0, total = 0;
  let html = '<div class="ai-result">';
  for (const q of data.questions) {
    const ua = answers[q.id];
    if (q.type === 'mcq' || q.type === 'true_false') {
      total++;
      const correctAns = String(q.answer);
      const isCorrect = ua !== undefined && ua.toLowerCase() === correctAns.toLowerCase();
      if (isCorrect) correct++;
      html += `<div class="ai-exam-result-item">
        <div class="ai-res-icon">${isCorrect ? '' : '❌'}</div>
        <div>
          <div style="font-weight:600">${esc(q.question)}</div>
          ${ua ? `<div style="font-size:12px;color:var(--text-muted)">Your answer: <span style="color:${isCorrect ? 'var(--green)' : 'var(--red)'}">${esc(ua)}</span></div>` : '<div style="font-size:12px;color:var(--text-faint)">Not answered</div>'}
          ${!isCorrect ? `<div style="font-size:12px;color:var(--green)">Correct: ${esc(correctAns)}</div>` : ''}
          ${q.explanation ? `<div style="font-size:12px;color:var(--text-faint);margin-top:3px">${esc(q.explanation)}</div>` : ''}
        </div>
      </div>`;
    } else if (q.type === 'short_answer') {
      html += `<div class="ai-exam-result-item">
        <div class="ai-res-icon"></div>
        <div style="flex:1">
          <div style="font-weight:600">${esc(q.question)}</div>
          <div style="font-size:12px;color:var(--text-muted);margin-top:4px">Your answer: ${esc(ua || '(not answered)')}</div>
          <div style="font-size:12px;color:var(--green);margin-top:3px">Model answer: ${esc(q.model_answer || '')}</div>
          ${q.key_points?.length ? `<div style="font-size:11.5px;color:var(--text-faint);margin-top:3px">Key points: ${q.key_points.map(p => esc(p)).join(', ')}</div>` : ''}
        </div>
      </div>`;
    }
  }
  if (total > 0) {
    const pct = Math.round(correct / total * 100);
    html = `<div class="ai-exam-score">${correct}/${total} (${pct}%)</div>` + html;
  }
  html += '</div>';
  rc.innerHTML = html;
}

function renderMockExam() {
  if (!ensureFeatureAccess('study_pro', 'Mock Exam')) return;
  const rc = getResultContainer('ai-study-result');
  const currentPage = S.view === 'page' && S.page;
  rc.innerHTML = `
    <div class="ai-result">
      <div class="ai-result-header"><div class="ai-result-label"> Mock Exam</div></div>
      ${currentPage ? `<div style="font-size:12.5px;color:var(--text-muted);margin-bottom:10px">Using content from: <strong>${esc(currentPage.title || 'Untitled')}</strong></div>` : '<div style="font-size:12.5px;color:var(--orange);margin-bottom:10px"> Open a page to generate an exam from its content.</div>'}
      <div class="ai-input-label">Number of questions</div>
      <div class="ai-options-row">
        <button class="ai-opt-chip selected" onclick="selectChip(this,'exam-count')">5</button>
        <button class="ai-opt-chip" onclick="selectChip(this,'exam-count')">10</button>
        <button class="ai-opt-chip" onclick="selectChip(this,'exam-count')">15</button>
      </div>
      <div class="ai-input-label">Difficulty</div>
      <div class="ai-options-row">
        <button class="ai-opt-chip" onclick="selectChip(this,'exam-diff')">Easy</button>
        <button class="ai-opt-chip selected" onclick="selectChip(this,'exam-diff')">Medium</button>
        <button class="ai-opt-chip" onclick="selectChip(this,'exam-diff')">Hard</button>
      </div>
      <button class="btn btn-action" style="width:100%;margin-top:6px" onclick="runMockExam()" ${!currentPage ? 'disabled' : ''}>Generate Exam</button>
    </div>
    <div id="exam-result"></div>`;
}

async function runMockExam() {
  if (!ensureFeatureAccess('study_pro', 'Mock Exam')) return;
  const content = S.page ? getPageTextContent(S.page) : '';
  if (!content) return toast('Open a page first');
  const countEl = document.querySelector('#ai-study-result .ai-opt-chip.selected[onclick*="exam-count"]');
  const diffEl = document.querySelector('#ai-study-result .ai-opt-chip.selected[onclick*="exam-diff"]');
  const count = countEl?.textContent.trim() || '5';
  const diff = diffEl?.textContent.trim() || 'Medium';
  const rc = document.getElementById('exam-result');
  showAILoading(rc, 'Generating exam…');
  try {
    const result = await callAIJson(
      `You are an exam creator. Generate a mock exam. Specifications: ${count} questions, difficulty: ${diff}. Mix question types: MCQ, short_answer, true_false. Return JSON: {"title": "exam title", "questions": [{"id": 1, "type": "mcq", "question": "...", "options": ["A","B","C","D"], "answer": "B", "explanation": "..."}, {"id": 2, "type": "short_answer", "question": "...", "model_answer": "...", "key_points": ["..."]}, {"id": 3, "type": "true_false", "question": "...", "answer": true, "explanation": "..."}]}. No trick questions. MCQ options should be plausible.`,
      `Generate exam from:\n\n${content.slice(0, 4000)}`,
      2048
    );
    window._pqData = result;
    window._pqUserAnswers = {};
    renderPQQuestions(rc, result);
  } catch (e) { showAIError(rc, e.message); }
}

function renderActiveRecall() {
  const rc = getResultContainer('ai-study-result');
  const currentPage = S.view === 'page' && S.page;
  rc.innerHTML = `
    <div class="ai-result">
      <div class="ai-result-header"><div class="ai-result-label">› Active Recall</div></div>
      ${currentPage ? `<div style="font-size:12.5px;color:var(--text-muted);margin-bottom:10px">Source: <strong>${esc(currentPage.title || 'Untitled')}</strong></div>` : '<div style="font-size:12.5px;color:var(--orange);margin-bottom:10px">Open a page first</div>'}
      <div class="ai-options-row">
        <button class="ai-opt-chip selected" onclick="selectChip(this,'ar-count')">5</button>
        <button class="ai-opt-chip" onclick="selectChip(this,'ar-count')">10</button>
        <button class="ai-opt-chip" onclick="selectChip(this,'ar-count')">15</button>
      </div>
      <button class="btn btn-action" style="width:100%" onclick="runActiveRecall()" ${!currentPage ? 'disabled' : ''}>Start Session</button>
    </div>
    <div id="ar-result"></div>`;
}

async function runActiveRecall() {
  if (!ensureFeatureAccess('study_plus', 'Active Recall')) return;
  const content = S.page ? getPageTextContent(S.page) : '';
  if (!content) return toast('Open a page first');
  const countEl = document.querySelector('#ai-study-result .ai-opt-chip.selected[onclick*="ar-count"]');
  const count = countEl?.textContent.trim() || '5';
  const rc = document.getElementById('ar-result');
  showAILoading(rc, 'Generating recall questions…');
  try {
    const questions = await callAIJson(
      `Generate ${count} active recall questions from these notes. Generate diverse questions varying the angle, phrasing and focus. Types to mix: "Explain in your own words...", "What would happen if...", "What's the difference between X and Y?", "Why does X happen?", "Give an example of...". Return JSON array: [{"question": "...", "modelAnswer": "..."}]`,
      `Generate questions from:\n\n${content.slice(0, 3000)}`,
      2048
    );
    if (!Array.isArray(questions)) throw new Error('Unexpected format');
    window._arQuestions = questions;
    window._arIdx = 0;
    window._arRevealed = false;
    window._arScores = { nailed: 0, close: 0, missed: 0 };
    renderARQuestion(rc);
  } catch (e) { showAIError(rc, e.message); }
}

function renderARQuestion(rc) {
  const q = window._arQuestions?.[window._arIdx];
  if (!q) {
    const s = window._arScores || {};
    rc.innerHTML = `<div class="ai-result"><div class="ai-exam-score">${s.nailed} / ${window._arQuestions?.length || 0}</div>
      <div style="text-align:center;font-size:13.5px;color:var(--text-muted)">Nailed: ${s.nailed} &nbsp;|&nbsp; Close: ${s.close} &nbsp;|&nbsp; Missed: ${s.missed}</div>
      <button class="btn btn-action" style="width:100%;margin-top:16px" onclick="runActiveRecall()">New Session</button></div>`;
    return;
  }
  const total = window._arQuestions.length;
  const idx = window._arIdx;
  rc.innerHTML = `
    <div class="ai-result">
      <div class="ai-exam-progress">
        <span>${idx + 1}/${total}</span>
        <div class="ai-exam-bar-wrap"><div class="ai-exam-bar" style="width:${Math.round(idx / total * 100)}%"></div></div>
        <span style="font-size:11px">${window._arScores.nailed}</span>
      </div>
      <div class="ai-question-text" style="font-size:15px;margin-bottom:14px">${esc(q.question)}</div>
      <textarea class="form-input" id="ar-ans" style="width:100%;min-height:80px;resize:vertical;box-sizing:border-box" placeholder="Write your answer…"></textarea>
      <button class="btn btn-secondary" style="width:100%;margin-top:8px" onclick="revealARAnswer()">Reveal Answer</button>
    </div>
    <div id="ar-reveal"></div>`;
}

function revealARAnswer() {
  const q = window._arQuestions?.[window._arIdx];
  if (!q) return;
  const rc = document.getElementById('ar-reveal');
  rc.innerHTML = `
    <div class="ai-result">
      <div class="ai-feature-group-label">Model Answer</div>
      <div style="font-size:13.5px;color:var(--text);margin-bottom:14px">${esc(q.modelAnswer)}</div>
      <div style="font-size:12.5px;font-weight:600;color:var(--text-muted);margin-bottom:8px">How did you do?</div>
      <div class="ai-options-row">
        <button class="btn btn-got" onclick="scoreAR('nailed')" style="width:auto;padding:8px 18px"> Nailed it</button>
        <button class="btn btn-secondary" onclick="scoreAR('close')" style="width:auto;padding:8px 18px">≈ Close</button>
        <button class="btn btn-miss" onclick="scoreAR('missed')" style="width:auto;padding:8px 18px">✗ Missed</button>
      </div>
    </div>`;
}

function scoreAR(score) {
  window._arScores[score]++;
  window._arIdx++;
  window._arRevealed = false;
  const rc = document.getElementById('ar-result');
  renderARQuestion(rc);
  document.getElementById('ar-reveal')?.remove();
}

function renderStudyDiagnostic() {
  const rc = getResultContainer('ai-study-result');
  rc.innerHTML = `
    <div class="ai-result">
      <div class="ai-result-header"><div class="ai-result-label"> Diagnostic Test</div></div>
      <div class="ai-input-area">
        <label class="ai-input-label">Topic to diagnose</label>
        <input class="form-input" id="diag-topic" placeholder="e.g. Calculus, French Revolution, Cell Biology…">
      </div>
      <div class="ai-input-label">Difficulty</div>
      <div class="ai-options-row">
        <button class="ai-opt-chip" onclick="selectChip(this,'diag-diff')">Beginner</button>
        <button class="ai-opt-chip selected" onclick="selectChip(this,'diag-diff')">Intermediate</button>
        <button class="ai-opt-chip" onclick="selectChip(this,'diag-diff')">Advanced</button>
      </div>
      <button class="btn btn-action" style="width:100%;margin-top:6px" onclick="runDiagnostic()">Start Diagnostic (10 Questions)</button>
    </div>
    <div id="diag-result"></div>`;
}

async function runDiagnostic() {
  if (!ensureFeatureAccess('study_pro', 'Diagnostic Test')) return;
  const topic = document.getElementById('diag-topic')?.value.trim();
  if (!topic) return toast('Enter a topic');
  const diffEl = document.querySelector('#ai-study-result .ai-opt-chip.selected[onclick*="diag-diff"]');
  const diff = diffEl?.textContent.trim() || 'Intermediate';
  const rc = document.getElementById('diag-result');
  showAILoading(rc, 'Generating diagnostic questions…');
  try {
    const data = await callAIJson(
      `Generate exactly 10 diagnostic questions on the given topic at ${diff} level. Questions must probe DIFFERENT sub-concepts — not variations of the same idea. Cover: foundational understanding, application, edge cases, common misconceptions. Mix types: mcq, short_answer, true_false. Return JSON: {"questions": [{"id": 1, "subConcept": "specific sub-topic", "type": "mcq", "question": "...", "options": ["A","B","C","D"], "answer": "B", "explanation": "..."}, ...]}`,
      `Topic: ${topic}`,
      2048
    );
    window._diagData = data;
    window._diagTopic = topic;
    window._diagAnswers = {};
    window._pqData = data;  // reuse practice question renderer
    window._pqUserAnswers = {};
    rc.innerHTML = '';
    renderPQQuestions(rc, data);
    // Replace submit button to use diag analysis
    setTimeout(() => {
      const btn = rc.querySelector('.btn-action');
      if (btn) btn.setAttribute('onclick', 'runDiagnosticAnalysis()');
    }, 100);
  } catch (e) { showAIError(rc, e.message); }
}

async function runDiagnosticAnalysis() {
  if (!ensureFeatureAccess('study_pro', 'Diagnostic Analysis')) return;
  const data = window._diagData;
  const answers = window._pqUserAnswers || {};
  const rc = document.getElementById('diag-result');
  showAILoading(rc, 'Analysing your performance…');
  try {
    const qa = (data.questions || []).map(q => ({ id: q.id, subConcept: q.subConcept, question: q.question, correctAnswer: q.answer, userAnswer: answers[q.id] || '(not answered)', type: q.type }));
    const result = await callAIJson(
      'A student completed a diagnostic test. Analyse their performance and identify specific weaknesses. Return JSON: {"score": "X/10", "overallStrength": "one sentence on what they understand well", "weaknesses": [{"subConcept": "...", "severity": "critical|moderate|minor", "diagnosis": "specific explanation of what they misunderstand", "evidence": "which question revealed this"}], "studyPlan": {"priority1": {"topic": "...", "timeNeeded": "...", "howToStudy": "..."}, "priority2": {"topic": "...", "timeNeeded": "...", "howToStudy": "..."}, "priority3": {"topic": "...", "timeNeeded": "...", "howToStudy": "..."}}}',
      `Topic: ${window._diagTopic}\nQ&A data: ${JSON.stringify(qa)}`,
      2048
    );
    rc.innerHTML = `
      <div class="ai-result">
        <div class="ai-exam-score">${esc(result.score || '')}</div>
        <div style="font-size:13.5px;color:var(--text);margin-bottom:14px;text-align:center">${esc(result.overallStrength || '')}</div>
        ${(result.weaknesses || []).length ? `
          <div class="ai-feature-group-label">Weaknesses Found</div>
          ${(result.weaknesses || []).map(w => `
            <div class="ai-diag-weakness ${w.severity || 'minor'}">
              <div class="ai-diag-weakness-title">${esc(w.subConcept)} <span style="font-size:10px;opacity:.7">${esc(w.severity)}</span></div>
              <div class="ai-diag-weakness-text">${esc(w.diagnosis)}</div>
              ${w.evidence ? `<div style="font-size:11.5px;color:var(--text-faint);margin-top:3px">Evidence: ${esc(w.evidence)}</div>` : ''}
            </div>`).join('')}` : ''}
        ${result.studyPlan ? `
          <div class="ai-feature-group-label" style="margin-top:12px">Targeted Study Plan</div>
          ${[result.studyPlan.priority1, result.studyPlan.priority2, result.studyPlan.priority3].filter(Boolean).map((p, i) => `
            <div style="background:var(--bg-sidebar);border:1px solid var(--border);border-radius:var(--r);padding:10px 12px;margin-bottom:6px">
              <div style="font-weight:700;font-size:13px">Priority ${i + 1}: ${esc(p.topic)}</div>
              <div style="font-size:12px;color:var(--text-muted)">${esc(p.timeNeeded)} · ${esc(p.howToStudy)}</div>
            </div>`).join('')}` : ''}
        <button class="btn btn-action btn-sm" style="margin-top:10px" onclick="saveAsNewPage(${JSON.stringify(`# Diagnostic Report: ${window._diagTopic}\n\nScore: ${result.score}\n\n${result.overallStrength || ''}`).replace(/</g, '\\u003c')}, 'Diagnostic: ${esc(window._diagTopic || '')}')">Save Report</button>
      </div>`;
  } catch (e) { showAIError(rc, e.message); }
}

function renderSocraticTutor() {
  const rc = getResultContainer('ai-study-result');
  AI.tutorHistory = [];
  rc.innerHTML = `
    <div class="ai-result">
      <div class="ai-result-header"><div class="ai-result-label"> Socratic Tutor</div></div>
      <div class="ai-input-area">
        <label class="ai-input-label">Topic to explore</label>
        <input class="form-input" id="tutor-topic" placeholder="e.g. Evolution, Supply and Demand…">
        <label class="ai-input-label" style="margin-top:8px">Level</label>
        <select class="ai-select" id="tutor-level"><option>Beginner</option><option selected>Intermediate</option><option>Advanced</option></select>
      </div>
      <button class="btn btn-action" style="width:100%" onclick="startSocraticTutor()">Start Session</button>
    </div>
    <div id="tutor-convo"></div>`;
}

async function startSocraticTutor() {
  const topic = document.getElementById('tutor-topic')?.value.trim();
  const level = document.getElementById('tutor-level')?.value || 'Intermediate';
  if (!topic) return toast('Enter a topic');
  window._tutorTopic = topic;
  window._tutorLevel = level;
  window._tutorHistory = [];
  const rc = document.getElementById('tutor-convo');
  showAILoading(rc, 'Starting session…');
  try {
    const system = `You are a Socratic tutor teaching ${topic} at ${level} level. Your role is to guide the student to understanding through questions — never give direct answers. Rules: always respond with a question or leading observation; if the student is correct, acknowledge briefly then probe deeper; if wrong, ask a question that reveals the flaw; if they say "I'm stuck", give ONE small hint then ask a question; keep responses under 100 words; be warm and encouraging.`;
    const firstMsg = `Let's explore ${topic}. To start — what do you already know about this? What comes to mind when you hear the term?`;
    window._tutorHistory = [{ role: 'assistant', content: firstMsg }];
    window._tutorSystem = system;
    renderConvo(rc, window._tutorHistory, 'tutor');
  } catch (e) { showAIError(rc, e.message); }
}

async function sendTutorMessage() {
  const input = document.getElementById('tutor-inp');
  const msg = input?.value.trim();
  if (!msg) return;
  input.value = '';
  const rc = document.getElementById('tutor-convo');
  window._tutorHistory.push({ role: 'user', content: msg });
  renderConvo(rc, window._tutorHistory, 'tutor');
  showAILoading(document.getElementById('tutor-typing') || document.createElement('div'), '');
  try {
    const reply = await callAIConvo(window._tutorSystem, window._tutorHistory, 400);
    window._tutorHistory.push({ role: 'assistant', content: reply });
    renderConvo(rc, window._tutorHistory, 'tutor');
  } catch (e) { toast(e.message); }
}

function renderConvo(rc, history, type) {
  const sendFn = type === 'tutor' ? 'sendTutorMessage()' : 'sendDebateMessage()';
  const inputId = type === 'tutor' ? 'tutor-inp' : 'debate-inp';
  rc.innerHTML = `
    <div class="ai-convo">
      ${history.map(m => `<div class="ai-msg ${m.role === 'assistant' ? 'ai' : 'user'}">${esc(m.content)}</div>`).join('')}
    </div>
    <div id="${type}-typing"></div>
    <div class="ai-convo-input">
      <textarea id="${inputId}" placeholder="Your response…" onkeydown="if((event.metaKey||event.ctrlKey)&&event.key==='Enter'){event.preventDefault();${sendFn}}"></textarea>
      <button class="btn btn-action btn-sm" onclick="${sendFn}">Send</button>
    </div>
    ${type === 'tutor' ? `<div style="display:flex;gap:6px;margin-top:6px;flex-wrap:wrap">
      <button class="btn btn-ghost btn-sm" onclick="sendSpecialTutor('hint')"> Hint</button>
      <button class="btn btn-ghost btn-sm" onclick="sendSpecialTutor('explain')"> Explain this</button>
    </div>` : `<div style="display:flex;gap:6px;margin-top:6px">
      <button class="btn btn-ghost btn-sm" onclick="endDebate()">End & Get Feedback</button>
    </div>`}`;
  // Scroll to bottom
  const convo = rc.querySelector('.ai-convo');
  if (convo) setTimeout(() => { convo.scrollTop = convo.scrollHeight; }, 50);
}

async function sendSpecialTutor(mode) {
  const inp = document.getElementById('tutor-inp');
  if (inp) inp.value = mode === 'hint' ? "I'm stuck, can I have a hint?" : "Can you explain this more?";
  await sendTutorMessage();
}

function renderDebateMode() {
  const rc = getResultContainer('ai-study-result');
  AI.debateHistory = [];
  rc.innerHTML = `
    <div class="ai-result">
      <div class="ai-result-header"><div class="ai-result-label">⚔️ Debate Mode</div></div>
      <div class="ai-input-area">
        <label class="ai-input-label">Debate topic</label>
        <input class="form-input" id="debate-topic" placeholder="e.g. AI regulation, Climate policy…" style="margin-bottom:8px">
        <label class="ai-input-label">Your position</label>
        <input class="form-input" id="debate-position" placeholder="e.g. I argue that AI should be heavily regulated…" style="margin-bottom:8px">
        <select class="ai-select" id="debate-level"><option>Undergraduate</option><option selected>Postgraduate</option><option>Expert</option></select>
      </div>
      <button class="btn btn-action" style="width:100%" onclick="startDebate()">Start Debate</button>
    </div>
    <div id="debate-convo"></div>`;
}

async function startDebate() {
  const topic = document.getElementById('debate-topic')?.value.trim();
  const position = document.getElementById('debate-position')?.value.trim();
  const level = document.getElementById('debate-level')?.value || 'Postgraduate';
  if (!topic || !position) return toast('Enter topic and your position');
  window._debateSystem = `You are debating against the student on the topic: ${topic}. Student's position: ${position}. Your position: the direct opposite. Difficulty: ${level}. Rules: make genuinely strong arguments; stay in character as an expert; when they make a good point, acknowledge briefly then counter; keep each response to 3-5 sentences; end every response with a direct challenge or question. Use appropriate academic language for ${level} level.`;
  window._debateHistory = [];
  const rc = document.getElementById('debate-convo');
  showAILoading(rc, 'Starting debate…');
  try {
    const opening = await callAI(window._debateSystem, `The student argues: "${position}". Give a strong opening statement arguing the opposite position, then end with a challenge.`, 400);
    window._debateHistory = [{ role: 'assistant', content: opening }];
    renderConvo(rc, window._debateHistory, 'debate');
  } catch (e) { showAIError(rc, e.message); }
}

async function sendDebateMessage() {
  const input = document.getElementById('debate-inp');
  const msg = input?.value.trim();
  if (!msg) return;
  input.value = '';
  const rc = document.getElementById('debate-convo');
  window._debateHistory.push({ role: 'user', content: msg });
  renderConvo(rc, window._debateHistory, 'debate');
  try {
    const reply = await callAIConvo(window._debateSystem, window._debateHistory, 400);
    window._debateHistory.push({ role: 'assistant', content: reply });
    renderConvo(rc, window._debateHistory, 'debate');
  } catch (e) { toast(e.message); }
}

async function endDebate() {
  const rc = document.getElementById('debate-convo');
  showAILoading(rc, 'Analysing debate performance…');
  try {
    const transcript = window._debateHistory.map(m => `${m.role === 'user' ? 'Student' : 'AI'}: ${m.content}`).join('\n\n');
    const result = await callAIJson(
      'Review this debate transcript and give feedback on the student\'s performance. Return JSON: {"overallPerformance": "brief honest assessment", "strengths": ["what they argued well"], "weaknesses": ["where their argument was weak"], "missedOpportunities": ["strong arguments they could have made"], "score": "X/10 with justification", "topicMastery": "how well they understand the subject"}',
      `Debate transcript:\n\n${transcript}`,
      1536
    );
    rc.innerHTML = `
      <div class="ai-result">
        <div class="ai-exam-score">${esc(result.score || '')}</div>
        <div style="font-size:13.5px;color:var(--text-muted);text-align:center;margin-bottom:14px">${esc(result.overallPerformance || '')}</div>
        ${result.strengths?.length ? `<div class="ai-feature-group-label">Strengths</div><ul style="margin:0 0 10px;padding-left:18px;font-size:13px;color:var(--text-muted)">${result.strengths.map(s => `<li>${esc(s)}</li>`).join('')}</ul>` : ''}
        ${result.weaknesses?.length ? `<div class="ai-feature-group-label">Weaknesses</div><ul style="margin:0 0 10px;padding-left:18px;font-size:13px;color:var(--text-muted)">${result.weaknesses.map(s => `<li>${esc(s)}</li>`).join('')}</ul>` : ''}
        ${result.missedOpportunities?.length ? `<div class="ai-feature-group-label">Missed Opportunities</div><ul style="margin:0 0 10px;padding-left:18px;font-size:13px;color:var(--text-faint)">${result.missedOpportunities.map(s => `<li>${esc(s)}</li>`).join('')}</ul>` : ''}
        <div style="font-size:12.5px;color:var(--text-muted);font-style:italic">${esc(result.topicMastery || '')}</div>
      </div>`;
  } catch (e) { showAIError(rc, e.message); }
}

function renderGapDetector() {
  const rc = getResultContainer('ai-study-result');
  const currentPage = S.view === 'page' && S.page;
  rc.innerHTML = `
    <div class="ai-result">
      <div class="ai-result-header"><div class="ai-result-label"> Note Gap Detector</div></div>
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:10px">
        <div>
          <div class="ai-input-label">Your Notes</div>
          ${currentPage ? `<div style="font-size:12px;color:var(--accent);margin-bottom:4px">Using: ${esc(currentPage.title || '')}</div>` : ''}
          <textarea id="gap-notes" style="width:100%;min-height:100px;resize:vertical;padding:8px;font-size:12.5px;border:1px solid var(--border);border-radius:var(--r);background:var(--bg);color:var(--text);box-sizing:border-box;font-family:inherit" placeholder="Paste notes…">${currentPage ? esc(getPageTextContent(currentPage).slice(0, 2000)) : ''}</textarea>
        </div>
        <div>
          <div class="ai-input-label">Syllabus / Past Exam</div>
          <textarea id="gap-ref" style="width:100%;min-height:100px;resize:vertical;padding:8px;font-size:12.5px;border:1px solid var(--border);border-radius:var(--r);background:var(--bg);color:var(--text);box-sizing:border-box;font-family:inherit" placeholder="Paste syllabus or past exam questions…"></textarea>
        </div>
      </div>
      <button class="btn btn-action" style="width:100%" onclick="runGapDetector()">Analyse Gaps</button>
    </div>
    <div id="gap-result"></div>`;
}

async function runGapDetector() {
  if (!ensureFeatureAccess('study_pro', 'Gap Detector')) return;
  const notes = document.getElementById('gap-notes')?.value.trim();
  const ref = document.getElementById('gap-ref')?.value.trim();
  if (!notes || !ref) return toast('Enter both notes and reference document');
  const rc = document.getElementById('gap-result');
  showAILoading(rc, 'Analysing coverage gaps…');
  try {
    const result = await callAIJson(
      'Compare the student\'s notes against the reference document (syllabus or past exam). Identify coverage gaps. Return JSON: {"wellCovered": ["topic", ...], "partiallyCovered": [{"topic": "...", "issue": "what\'s missing or shallow", "suggestion": "what to add"}], "notCovered": [{"topic": "...", "priority": 1, "examFrequency": "how often it appears in reference"}], "priorityOrder": ["topic1", "topic2", ...]}',
      `Student notes:\n${notes}\n\n---Reference document---\n${ref}`,
      2048
    );
    rc.innerHTML = `
      <div class="ai-result">
        <div class="ai-gap-section">
          <div class="ai-gap-section-title"><span style="color:var(--green)">✓</span> Well Covered (${(result.wellCovered || []).length})</div>
          ${(result.wellCovered || []).map(t => `<div class="ai-gap-item"><div class="ai-gap-icon">✓</div><div class="ai-gap-text"><strong>${esc(t)}</strong></div></div>`).join('')}
        </div>
        ${(result.partiallyCovered || []).length ? `<div class="ai-gap-section">
          <div class="ai-gap-section-title"><span style="color:var(--orange)"></span> Partially Covered (${result.partiallyCovered.length})</div>
          ${result.partiallyCovered.map(t => `<div class="ai-gap-item"><div class="ai-gap-icon" style="color:var(--orange)"></div><div class="ai-gap-text"><strong>${esc(t.topic)}</strong>${esc(t.issue)}<br><small style="color:var(--accent)">Suggestion: ${esc(t.suggestion)}</small></div></div>`).join('')}
        </div>` : ''}
        ${(result.notCovered || []).length ? `<div class="ai-gap-section">
          <div class="ai-gap-section-title"><span style="color:var(--red)">✗</span> Not Covered (${result.notCovered.length})</div>
          ${result.notCovered.map(t => `<div class="ai-gap-item"><div class="ai-gap-icon" style="color:var(--red)">✗</div><div class="ai-gap-text"><strong>${esc(t.topic)}</strong><span style="font-size:11px;color:var(--text-faint)">Priority: ${esc(String(t.priority))} · ${esc(t.examFrequency || '')}</span></div></div>`).join('')}
        </div>` : ''}
        ${result.priorityOrder?.length ? `<div class="ai-gap-section"><div class="ai-gap-section-title"> Priority Order to Study</div>${result.priorityOrder.map((t, i) => `<div class="ai-gap-item"><div class="ai-gap-icon" style="color:var(--accent);font-weight:700">${i + 1}</div><div class="ai-gap-text">${esc(t)}</div></div>`).join('')}</div>` : ''}
      </div>`;
  } catch (e) { showAIError(rc, e.message); }
}

// ─── ORGANISE FEATURES ───────────────────────────────────────

async function aiAutoTag() {
  if (!ensureFeatureAccess('organise_plus', 'Auto-Tag')) return;
  const rc = getResultContainer('ai-organise-result');
  const untagged = S.pages.filter(p => !p.tags || p.tags.length === 0);
  if (!untagged.length) return showAIError(rc, 'All pages already have tags.');
  showAILoading(rc, `Analysing ${untagged.length} untagged pages…`);
  const context = untagged.map(p => ({ id: p.id, title: p.title || 'Untitled', preview: getPageTextContent(p).slice(0, 300) }));
  try {
    const result = await callAIJson(
      'Analyse each note and suggest appropriate tags. Available tags: study, lecture, revision, essay, project, reference, summary, flashcard-source, urgent, draft. Return JSON: {"suggestions": [{"pageId": "...", "pageTitle": "...", "suggestedTags": ["tag1", "tag2"]}]}. Only suggest tags that genuinely reflect the content. Maximum 3 tags per page.',
      JSON.stringify(context),
      2048
    );
    const suggestions = result.suggestions || [];
    rc.innerHTML = `
      <div class="ai-result">
        <div class="ai-result-header">
          <div class="ai-result-label"> Tag Suggestions (${suggestions.length} pages)</div>
          <button class="btn btn-action btn-sm" onclick="applyAutoTags(${JSON.stringify(suggestions).replace(/</g, '\\u003c')})">Apply All</button>
        </div>
        ${suggestions.map(s => `
          <div class="ai-tag-suggestion">
            <div class="ai-tag-suggestion-title">${esc(s.pageTitle)}</div>
            <div class="ai-tag-chips">${(s.suggestedTags || []).map(t => `<span class="ai-tag-chip">${esc(t)}</span>`).join('')}</div>
          </div>`).join('')}
      </div>`;
  } catch (e) { showAIError(rc, e.message); }
}

async function applyAutoTags(suggestions) {
  const colors = ['blue', 'purple', 'green', 'orange', 'red'];
  for (const s of suggestions) {
    const page = S.pages.find(p => p.id === s.pageId);
    if (!page) continue;
    page.tags = page.tags || [];
    for (const tagLabel of (s.suggestedTags || [])) {
      if (!page.tags.find(t => t.label === tagLabel)) {
        page.tags.push({ label: tagLabel, color: colors[Math.floor(Math.random() * colors.length)] });
      }
    }
    await saveData(`pages/${page.id}`, page);
  }
  toast('Tags applied ✓');
  renderAIPanel();
}

async function aiLinkRelated() {
  if (!ensureFeatureAccess('organise_plus', 'Link Related Notes')) return;
  const rc = getResultContainer('ai-organise-result');
  if (S.pages.length < 2) return showAIError(rc, 'Need at least 2 pages to find links.');
  showAILoading(rc, 'Finding connections…');
  const context = S.pages.map(p => ({ id: p.id, title: p.title || 'Untitled', preview: getPageTextContent(p).slice(0, 400) }));
  try {
    const result = await callAIJson(
      'Analyse these notes and find meaningful connections between them. Return JSON: {"links": [{"pageId": "...", "pageTitle": "...", "relatedPages": [{"id": "...", "title": "...", "reason": "one sentence explaining connection"}]}]}. Only link pages with genuine conceptual overlap. Maximum 4 related pages per note.',
      JSON.stringify(context),
      2048
    );
    rc.innerHTML = `
      <div class="ai-result">
        <div class="ai-result-header">
          <div class="ai-result-label"> Related Pages Found</div>
          <button class="btn btn-action btn-sm" onclick="applyRelatedLinks(${JSON.stringify(result.links || []).replace(/</g, '\\u003c')})">Apply Links</button>
        </div>
        ${(result.links || []).map(l => `
          <div style="margin-bottom:12px;padding-bottom:12px;border-bottom:1px solid var(--border)">
            <div style="font-weight:700;font-size:13px;margin-bottom:6px">${esc(l.pageTitle)}</div>
            ${(l.relatedPages || []).map(r => `<div style="display:flex;align-items:flex-start;gap:8px;padding:5px 0;font-size:12.5px"><span style="color:var(--accent)">→</span><div><div style="font-weight:600">${esc(r.title)}</div><div style="color:var(--text-faint);font-size:12px">${esc(r.reason)}</div></div></div>`).join('')}
          </div>`).join('')}
      </div>`;
  } catch (e) { showAIError(rc, e.message); }
}

async function applyRelatedLinks(links) {
  for (const l of links) {
    const page = S.pages.find(p => p.id === l.pageId);
    if (!page || !l.relatedPages?.length) continue;
    page.blocks = page.blocks || [];
    const relatedContent = l.relatedPages.map(r => `→ ${r.title}: ${r.reason}`).join('\n');
    page.blocks.push({ id: uid(), type: 'toggle', content: ' Related Pages', toggleContent: relatedContent, open: false });
    await saveData(`pages/${page.id}`, page);
  }
  toast('Related links added ✓');
}

async function aiSplitNote() {
  if (!ensureFeatureAccess('organise_plus', 'Split Note')) return;
  const rc = getResultContainer('ai-organise-result');
  if (!S.page) return toast('Open a page first');
  const content = getPageTextContent(S.page);
  const wordCount = content.split(/\s+/).length;
  if (wordCount < 200) return showAIError(rc, 'Page is too short to split (under 200 words).');
  showAILoading(rc, 'Identifying split points…');
  try {
    const result = await callAIJson(
      'This note is too long and covers multiple distinct topics. Split it into separate notes. Return JSON: {"splits": [{"title": "suggested page title", "content": "the full markdown content for this section"}]}. Each split should be a coherent, standalone note. Minimum 2 splits, maximum 6.',
      `Split this note:\n\n${content}`,
      2048
    );
    const splits = result.splits || [];
    rc.innerHTML = `
      <div class="ai-result">
        <div class="ai-result-header">
          <div class="ai-result-label">✂️ ${splits.length} Splits Suggested</div>
          <button class="btn btn-action btn-sm" onclick="applySplits(${JSON.stringify(splits).replace(/</g, '\\u003c')})">Create Pages</button>
        </div>
        ${splits.map(s => `<div style="padding:8px 0;border-bottom:1px solid var(--border);font-size:13px"><strong>${esc(s.title)}</strong><div style="font-size:12px;color:var(--text-faint);margin-top:3px">${esc(s.content.slice(0, 100))}…</div></div>`).join('')}
      </div>`;
  } catch (e) { showAIError(rc, e.message); }
}

async function applySplits(splits) {
  for (const s of splits) {
    const newPage = {
      id: uid(),
      title: s.title,
      blocks: [],
      inkStrokes: cloneInkStrokes(S.page?.inkStrokes),
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString()
    };
    applyMarkdownToPage(s.content, newPage);
    S.pages.push(newPage);
    await saveData('pages', { [newPage.id]: newPage });
  }
  toast(`Created ${splits.length} new pages ✓`);
  closeAIPanel();
  renderApp();
}

function renderMergeNotes() {
  const rc = getResultContainer('ai-organise-result');
  rc.innerHTML = `
    <div class="ai-result">
      <div class="ai-result-header"><div class="ai-result-label"> Merge Notes</div></div>
      <div class="ai-input-label">Select pages to merge</div>
      <div class="ai-page-select" id="merge-page-list">
        ${S.pages.map(p => `<label class="ai-page-select-item">
          <input type="checkbox" value="${p.id}" data-title="${esc(p.title || 'Untitled')}"> ${esc(p.title || 'Untitled')}
        </label>`).join('')}
      </div>
      <button class="btn btn-action" style="width:100%" onclick="runMergeNotes()">Merge Selected</button>
    </div>
    <div id="merge-result"></div>`;
}

async function runMergeNotes() {
  if (!ensureFeatureAccess('organise_plus', 'Merge Notes')) return;
  const checked = document.querySelectorAll('#merge-page-list input:checked');
  if (checked.length < 2) return toast('Select at least 2 pages');
  const pageIds = Array.from(checked).map(c => c.value);
  const pages = pageIds.map(id => S.pages.find(p => p.id === id)).filter(Boolean);
  const combined = pages.map(p => `# ${p.title || 'Untitled'}\n${getPageTextContent(p)}`).join('\n\n---\n\n');
  const rc = document.getElementById('merge-result');
  showAILoading(rc, 'Merging notes…');
  try {
    const result = await callAI(
      'Merge these multiple notes on related topics into one clean, comprehensive note. Remove duplicate information. Resolve contradictions (keep more detailed version). Impose clear logical structure with ## headings. The merged note should be better than any individual source. Return only the merged markdown content.',
      combined,
      2048
    );
    rc.innerHTML = `
      <div class="ai-result">
        <div class="ai-result-header">
          <div class="ai-result-label"> Merged</div>
          <button class="btn btn-action btn-sm" onclick="saveMergedNote(${JSON.stringify(result).replace(/</g, '\\u003c')}, ${JSON.stringify(pages.map(p => p.title || 'Untitled').join(' + ')).replace(/</g, '\\u003c')})">Save as New Page</button>
        </div>
        <div class="ai-result-body">${markdownToHtml(esc(result.slice(0, 600)))}…</div>
      </div>`;
  } catch (e) { showAIError(rc, e.message); }
}

async function saveMergedNote(content, title) {
  saveAsNewPage(content, `Merged: ${title}`);
}

async function aiGenFlashcardDeck() {
  if (!ensureFeatureAccess('organise_plus', 'Create Flashcard Deck')) return;
  if (!S.page) return toast('Open a page first');
  const rc = getResultContainer('ai-organise-result');
  showAILoading(rc, 'Generating flashcards…');
  const content = getPageTextContent(S.page);
  try {
    const cards = await callAIJson(
      'Create 15 flashcards from these notes for spaced repetition studying. Mix definition cards and Q&A cards. Return a JSON array only: [{"front": "question or term", "back": "answer or definition"}]. Make cards specific enough to test real understanding.',
      `Create flashcards from:\n\n${content}`,
      2048
    );
    if (!Array.isArray(cards)) throw new Error('Unexpected format');
    const deck = { id: uid(), title: `AI Cards — ${S.page.title || 'Untitled'}`, icon: 'flash', cards: cards.map(c => ({ ...c, id: uid() })), createdAt: new Date().toISOString() };
    S.flashcards.push(deck);
    await saveData('flashcards', { [deck.id]: deck });
    rc.innerHTML = `<div class="ai-result" style="border-color:var(--green)"><div style="color:var(--green);font-weight:700;font-size:14px">✓ Deck saved!</div><div style="font-size:13px;margin-top:6px">Created "${esc(deck.title)}" with ${cards.length} cards.</div><button class="btn btn-action btn-sm" style="margin-top:10px" onclick="navigate('flashcards');closeAIPanel()">Go to Flashcards</button></div>`;
    toast(`Deck "${deck.title}" created ✓`);
  } catch (e) { showAIError(rc, e.message); }
}

async function aiGenStudyPlanNote() {
  if (!ensureFeatureAccess('organise_pro', 'Create Study Plan')) return;
  const rc = getResultContainer('ai-organise-result');
  showAILoading(rc, 'Generating study plan…');
  const pageTitles = S.pages.map(p => p.title || 'Untitled').join(', ');
  const taskList = S.tasks.filter(t => !t.completed).map(t => `${t.title}${t.due ? ' (due ' + t.due + ')' : ''}`).join(', ');
  try {
    const result = await callAI(
      'You are a study coach. Based on the student\'s current notes and tasks, create a realistic 7-day study plan. Format: # Weekly Study Plan, ## Priority This Week (Top 3 things), ## Daily Breakdown (### Mon-Sun with specific tasks), ## Study Sessions (table), ## Reminders. Be realistic. Include rest days. Don\'t schedule more than 4-5 hours per day.',
      `Notes topics: ${pageTitles}\nIncomplete tasks: ${taskList || 'None'}`,
      2048
    );
    saveAsNewPage(result, `Study Plan — ${new Date().toLocaleDateString('en-US', { month: 'short', day: 'numeric' })}`);
    rc.innerHTML = `<div class="ai-result" style="border-color:var(--green)"><div style="color:var(--green);font-weight:700;font-size:14px">✓ Study plan saved as a new page!</div><button class="btn btn-action btn-sm" style="margin-top:10px" onclick="closeAIPanel()">View in Pages</button></div>`;
  } catch (e) { showAIError(rc, e.message); }
}

// ─── COPILOT FEATURES ────────────────────────────────────────

async function aiSummariseToday() {
  const rc = getResultContainer('ai-copilot-result');
  const today = new Date().toISOString().split('T')[0];
  const todayPages = S.pages.filter(p => (p.updatedAt || p.createdAt || '').startsWith(today));
  if (!todayPages.length) return showAIError(rc, "You haven't worked on any pages today.");
  showAILoading(rc, "Summarising today's study session…");
  const combined = todayPages.map(p => `## ${p.title || 'Untitled'}\n${getPageTextContent(p)}`).join('\n\n');
  try {
    const result = await callAI(
      `The student studied today and these are all their notes from today's sessions. Write a daily study summary in this format: ## Today's Study Summary — ${today}\n\n### What You Covered\n[one paragraph]\n\n### Key Things You Learned\n[5-7 bullet points]\n\n### Pages Studied\n[each page title with 1-sentence summary]\n\n### Suggested Follow-ups\n[2-3 bullet points of what to do tomorrow]\n\nBe encouraging but factual.`,
      combined,
      1536
    );
    rc.innerHTML = `
      <div class="ai-result">
        <div class="ai-result-header">
          <div class="ai-result-label">☀️ Today's Summary</div>
          <button class="btn btn-action btn-sm" onclick="saveAsNewPage(${JSON.stringify(result).replace(/</g, '\\u003c')}, 'Daily Summary — ${today}')">Save</button>
        </div>
        <div class="ai-result-body">${markdownToHtml(esc(result))}</div>
      </div>`;
  } catch (e) { showAIError(rc, e.message); }
}

async function aiProgressMirror() {
  const rc = getResultContainer('ai-copilot-result');
  showAILoading(rc, 'Generating your progress mirror…');
  const today = new Date();
  const weekAgo = new Date(today - 7 * 24 * 3600 * 1000).toISOString();
  const isThisWeek = d => d && d > weekAgo;
  const daysSince = d => d ? Math.floor((Date.now() - new Date(d).getTime()) / 86400000) : 999;
  const mirrorContext = {
    pagesCreated: S.pages.filter(p => isThisWeek(p.createdAt)).map(p => p.title || 'Untitled'),
    pagesUpdated: S.pages.filter(p => isThisWeek(p.updatedAt) && !isThisWeek(p.createdAt)).map(p => p.title || 'Untitled'),
    pagesNotTouched: S.pages.filter(p => daysSince(p.updatedAt) > 14).map(p => p.title || 'Untitled'),
    tasksCompleted: S.tasks.filter(t => t.completed && isThisWeek(t.completedAt)).length,
    tasksOverdue: S.tasks.filter(t => !t.completed && overdue(t.due)).length,
    totalPages: S.pages.length,
    totalDecks: S.flashcards.length,
  };
  try {
    const result = await callAIJson(
      'You are giving a student an honest weekly progress review. Be direct, specific, and constructive — not cheerleader-ish. Return JSON: {"weekSummary": "2-3 sentences honestly describing what they actually did this week", "topAccomplishment": "the most significant thing they did", "momentum": "high|medium|low", "momentumReason": "one sentence", "stallingOn": ["topics not touched in 2+ weeks"], "avoidancePattern": "honest observation about what they keep not doing (null if none)", "nextWeekFocus": ["3 specific things to prioritise"], "studyHabitObservation": "one honest insight"}',
      `Student week data: ${JSON.stringify(mirrorContext)}`,
      1024
    );
    rc.innerHTML = `
      <div class="ai-mirror-card">
        <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:10px">
          <div style="font-size:14px;font-weight:700"> Weekly Progress Mirror</div>
          <div class="ai-mirror-momentum ${result.momentum || 'medium'}">${result.momentum === 'high' ? '' : result.momentum === 'medium' ? '›' : ''} ${esc(result.momentum || '')} momentum</div>
        </div>
        <div class="ai-mirror-text" style="margin-bottom:12px">${esc(result.weekSummary || '')}</div>
        ${result.topAccomplishment ? `<div style="background:rgba(16,185,129,.08);border:1px solid rgba(16,185,129,.2);border-radius:var(--r);padding:8px 12px;font-size:13px;margin-bottom:10px"><strong> Top win:</strong> ${esc(result.topAccomplishment)}</div>` : ''}
        ${result.avoidancePattern ? `<div style="background:rgba(239,68,68,.06);border:1px solid rgba(239,68,68,.15);border-radius:var(--r);padding:8px 12px;font-size:13px;margin-bottom:10px"><strong> Pattern noticed:</strong> ${esc(result.avoidancePattern)}</div>` : ''}
        ${result.stallingOn?.length ? `<div style="font-size:12.5px;color:var(--text-muted);margin-bottom:8px"><strong>Going stale:</strong> ${result.stallingOn.map(s => esc(s)).join(', ')}</div>` : ''}
        <div class="ai-feature-group-label">Next Week's Focus</div>
        ${(result.nextWeekFocus || []).map((f, i) => `<div style="display:flex;gap:8px;padding:5px 0;font-size:13px"><span style="color:var(--accent);font-weight:700">${i + 1}.</span>${esc(f)}</div>`).join('')}
        ${result.studyHabitObservation ? `<div style="font-size:12px;color:var(--text-faint);margin-top:10px;font-style:italic">${esc(result.studyHabitObservation)}</div>` : ''}
      </div>`;
  } catch (e) { showAIError(rc, e.message); }
}

function renderTopicSummary() {
  const rc = getResultContainer('ai-copilot-result');
  rc.innerHTML = `
    <div class="ai-result">
      <div class="ai-result-header"><div class="ai-result-label"> Topic Summary</div></div>
      <div class="ai-input-label">Select pages to summarise together</div>
      <div class="ai-page-select" id="topic-page-list">
        ${S.pages.map(p => `<label class="ai-page-select-item">
          <input type="checkbox" value="${p.id}"> ${esc(p.title || 'Untitled')}
        </label>`).join('')}
      </div>
      <button class="btn btn-action" style="width:100%" onclick="runTopicSummary()">Summarise Selected</button>
    </div>
    <div id="topic-result"></div>`;
}

async function runTopicSummary() {
  const checked = document.querySelectorAll('#topic-page-list input:checked');
  if (!checked.length) return toast('Select at least one page');
  const pages = Array.from(checked).map(c => S.pages.find(p => p.id === c.value)).filter(Boolean);
  const combined = pages.map(p => `# ${p.title || 'Untitled'}\n${getPageTextContent(p)}`).join('\n\n');
  const rc = document.getElementById('topic-result');
  showAILoading(rc, 'Synthesising topic summary…');
  try {
    const result = await callAI(
      'The following notes are from multiple study sessions on a related topic. Synthesise them into one comprehensive topic summary. Format: # [Topic] — Master Summary\n\n## Core Concept\n[single most important idea]\n\n## Full Explanation\n[3-5 paragraphs covering thoroughly]\n\n## Key Terms\n[definition list]\n\n## Common Connections\n[how ideas link]\n\n## Gaps & Uncertainties\n[anything incomplete]. Write for a student who needs to understand this deeply for an exam.',
      combined,
      2048
    );
    rc.innerHTML = `
      <div class="ai-result">
        <div class="ai-result-header">
          <div class="ai-result-label"> Master Summary</div>
          <button class="btn btn-action btn-sm" onclick="saveAsNewPage(${JSON.stringify(result).replace(/</g, '\\u003c')}, 'Master Summary')">Save</button>
        </div>
        <div class="ai-result-body">${markdownToHtml(esc(result))}</div>
      </div>`;
  } catch (e) { showAIError(rc, e.message); }
}

async function aiWeeklyPlan() {
  const rc = getResultContainer('ai-copilot-result');
  showAILoading(rc, 'Building study plan…');
  const pageTitles = S.pages.map(p => p.title || 'Untitled').join(', ');
  const taskList = S.tasks.filter(t => !t.completed).map(t => `${t.title}${t.due ? ' (due ' + t.due + ')' : ''}`).join('; ') || 'No tasks';
  const events = S.calendar.filter(e => e.date >= new Date().toISOString().split('T')[0]).slice(0, 10).map(e => `${e.date}: ${e.title}`).join('; ') || 'No upcoming events';
  try {
    const result = await callAI(
      'You are a study coach. Create a realistic weekly study plan. Format: # Study Plan — [date range]\n\n## Priority This Period\n[Top 3 things]\n\n## Daily Breakdown\n### Day: Date\n- Morning:\n- Afternoon:\n- Evening:\n\n## Study Sessions table\n\n## Reminders. Be realistic. Include rest. Max 4-5 hours of focused study per day.',
      `Notes topics: ${pageTitles}\nIncomplete tasks: ${taskList}\nUpcoming events: ${events}`,
      2048
    );
    rc.innerHTML = `
      <div class="ai-result">
        <div class="ai-result-header">
          <div class="ai-result-label"> Weekly Study Plan</div>
          <button class="btn btn-action btn-sm" onclick="saveAsNewPage(${JSON.stringify(result).replace(/</g, '\\u003c')}, 'Weekly Study Plan')">Save</button>
        </div>
        <div class="ai-result-body">${markdownToHtml(esc(result))}</div>
      </div>`;
  } catch (e) { showAIError(rc, e.message); }
}

async function aiConfusionReview() {
  const rc = getResultContainer('ai-copilot-result');
  const allPages = S.pages;
  let confused = [];
  for (const p of allPages) {
    const confusedBlocks = (p.blocks || []).filter(b => b.confused);
    if (confusedBlocks.length) {
      confused.push({ pageTitle: p.title || 'Untitled', blocks: confusedBlocks });
    }
  }
  if (!confused.length) return showAIError(rc, 'No confused passages flagged. In any page, hover over a block and click the ⚑ flag to mark it as confusing.');
  showAILoading(rc, 'Explaining confused passages…');
  const passages = confused.flatMap(p => p.blocks.map(b => ({ page: p.pageTitle, text: (b.content || '').replace(/<[^>]+>/g, ' ').trim() }))).filter(p => p.text);
  try {
    const result = await callAIJson(
      'The student flagged the following passages as confusing. For each, provide a clear explanation. Return JSON: {"explanations": [{"passage": "the flagged text", "explanation": "clear explanation in plain language", "analogy": "a helpful analogy or real-world example", "followUp": "a question they can ask themselves to check understanding"}]}',
      `Confused passages:\n${JSON.stringify(passages)}`,
      2048
    );
    rc.innerHTML = `
      <div class="ai-result">
        <div class="ai-result-header"><div class="ai-result-label">⚑ Confusion Explained</div></div>
        ${(result.explanations || []).map(e => `
          <div style="background:var(--bg-sidebar);border:1px solid var(--border);border-radius:var(--r-lg);padding:14px;margin-bottom:10px">
            <div style="font-size:11.5px;font-weight:700;color:var(--orange);margin-bottom:6px">⚑ CONFUSED ABOUT</div>
            <div style="font-size:12.5px;color:var(--text-faint);font-style:italic;margin-bottom:10px">"${esc(e.passage?.slice(0, 120) || '')}…"</div>
            <div style="font-size:13.5px;color:var(--text);margin-bottom:8px">${esc(e.explanation || '')}</div>
            ${e.analogy ? `<div style="font-size:13px;color:var(--text-muted);margin-bottom:8px"> <em>${esc(e.analogy)}</em></div>` : ''}
            ${e.followUp ? `<div style="font-size:12.5px;color:var(--accent)">✓ Check yourself: ${esc(e.followUp)}</div>` : ''}
          </div>`).join('')}
      </div>`;
  } catch (e) { showAIError(rc, e.message); }
}

// ─── Utility functions ───────────────────────────────────────

function selectChip(el, group) {
  const parent = el.closest('.ai-options-row');
  if (!parent) return;
  const chips = parent.querySelectorAll(`.ai-opt-chip[onclick*="${group}"]`);
  chips.forEach(c => c.classList.remove('selected'));
  el.classList.add('selected');
}

function toggleChip(el) {
  el.classList.toggle('selected');
}

function copyAIResult(btn) {
  const body = btn.closest('.ai-result')?.querySelector('.ai-result-body');
  const text = body?.textContent || '';
  navigator.clipboard.writeText(text).then(() => toast('Copied to clipboard'));
}

async function saveAsNewPage(content, title) {
  const newPage = {
    id: uid(),
    title: title || 'AI Summary',
    blocks: [],
    inkStrokes: cloneInkStrokes(S.page?.inkStrokes),
    tags: [{ label: 'ai', color: 'purple' }],
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString()
  };
  applyMarkdownToPage(content, newPage);
  S.pages.push(newPage);
  await saveData('pages', { [newPage.id]: newPage });
  toast(`Page "${newPage.title}" saved ✓`);
  closeAIPanel();
  S.view = 'page'; S.page = newPage; renderApp();
}

// ─── Confusion Tracker (in block editor) ─────────────────────
function toggleConfusion(blockId) {
  const b = S.page?.blocks?.find(b => b.id === blockId);
  if (!b) return;
  b.confused = !b.confused;
  scheduleSave();
  renderBlocks();
  checkConfusionBanner();
}

function checkConfusionBanner() {
  const confused = (S.page?.blocks || []).filter(b => b.confused);
  const existing = document.getElementById('ai-confusion-banner');
  if (existing) existing.remove();
  if (!confused.length) return;
  const banner = document.createElement('div');
  banner.id = 'ai-confusion-banner';
  banner.className = 'ai-confusion-banner';
  banner.innerHTML = `<div class="ai-conf-icon">⚑</div><div class="ai-conf-text">You flagged <span class="ai-conf-count">${confused.length}</span> passage${confused.length > 1 ? 's' : ''} as confusing.</div><button class="btn btn-action btn-sm" onclick="openAIPanel();setTimeout(()=>{switchAITab('daySummary');setTimeout(aiConfusionReview,200)},200)">Explain Now</button>`;
  const blocksWrap = document.getElementById('blocks-wrap');
  if (blocksWrap) blocksWrap.before(banner);
}

// ─── AI Toolbar in Page Editor ───────────────────────────────
function renderAIToolbar() {
  return `<div class="ai-toolbar" id="ai-toolbar">
    <span style="font-size:11px;font-weight:700;color:var(--text-faint);text-transform:uppercase;letter-spacing:.06em;margin-right:4px">✦ AI</span>
    <button class="ai-toolbar-btn" onclick="openAIPanel();switchAITab('write');setTimeout(()=>aiRewriteClearly(),100)"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg> Rewrite</button>
    <button class="ai-toolbar-btn" onclick="openAIPanel();switchAITab('write');setTimeout(()=>aiSummarise('medium'),100)"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="8" y1="6" x2="21" y2="6"/><line x1="8" y1="12" x2="21" y2="12"/><line x1="8" y1="18" x2="21" y2="18"/><line x1="3" y1="6" x2="3.01" y2="6"/><line x1="3" y1="12" x2="3.01" y2="12"/><line x1="3" y1="18" x2="3.01" y2="18"/></svg> Summarise</button>
    <button class="ai-toolbar-btn" onclick="openAIPanel();switchAITab('write');setTimeout(()=>aiGenerateFlashcards(),100)"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="4" width="20" height="16" rx="2"/><path d="M12 4v16"/></svg> Flashcards</button>
    <button class="ai-toolbar-btn" onclick="openAIPanel();switchAITab('study');setTimeout(()=>renderPracticeQuestions(),100)"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg> Practice Q</button>
    <button class="ai-toolbar-btn" onclick="openAIPanel()"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M12 8v4l3 3"/></svg> More AI…</button>
  </div>`;
}

// ─── AI post-render hook (called after every renderContent) ──
// Uses MutationObserver so we never touch the original functions
function _aiPostRender() {
  ensureAIPanel();

  // Inject AI toolbar into page editor
  if (S.view === 'page' && S.page) {
    const c = document.getElementById('main-content');
    if (c && !c.querySelector('#ai-toolbar')) {
      const meta = c.querySelector('.page-meta');
      if (meta) {
        const toolbarDiv = document.createElement('div');
        toolbarDiv.innerHTML = renderAIToolbar();
        meta.after(toolbarDiv.firstElementChild);
      }
    }
    // Add confusion flag buttons to blocks
    document.querySelectorAll('#blocks-wrap [data-bid]').forEach(row => {
      const bid = row.dataset.bid;
      if (!bid || row.querySelector('.b-confuse-btn')) return;
      const b = S.page?.blocks?.find(b => b.id === bid);
      if (!b || b.type === 'divider' || b.type === 'image' || b.type === 'pdf' || b.type === 'table') return;
      const btn = document.createElement('button');
      btn.className = 'b-confuse-btn' + (b.confused ? ' active' : '');
      btn.title = 'Flag as confusing';
      btn.textContent = '⚑';
      btn.onclick = () => toggleConfusion(bid);
      const inner = row.querySelector('.b-inner');
      if (inner) inner.appendChild(btn);
    });
    checkConfusionBanner();
  }

  // Restore AI panel state if it was open
  if (AI.open) {
    document.getElementById('ai-panel')?.classList.add('open');
    renderAIPanel();
  }
}

// Observe #main-content for DOM changes → run post-render hook
(function _setupAIObserver() {
  const target = document.getElementById('main-content') || document.getElementById('app');
  if (!target) { setTimeout(_setupAIObserver, 200); return; }
  const obs = new MutationObserver(() => {
    // Debounce so we don't fire 50x during a single render
    clearTimeout(obs._t);
    obs._t = setTimeout(_aiPostRender, 60);
  });
  obs.observe(target, { childList: true, subtree: false });
  // Also observe app-level swaps
  const app = document.getElementById('app');
  if (app && app !== target) {
    const obs2 = new MutationObserver(() => {
      clearTimeout(obs2._t);
      obs2._t = setTimeout(_aiPostRender, 60);
    });
    obs2.observe(app, { childList: true, subtree: false });
  }
})();

// Keyboard shortcut for AI panel
document.addEventListener('keydown', e => {
  if ((e.metaKey || e.ctrlKey) && e.shiftKey && e.key === 'a') {
    e.preventDefault();
    AI.open ? closeAIPanel() : openAIPanel();
  }
});
(function setupCmdK() {
  document.addEventListener('keydown', (e) => {
    if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
      e.preventDefault();
      if (typeof openSearch === 'function') openSearch();
    }
  });
})();

// Patching UndoMgr for deep history
UndoMgr.init = function (uid) {
  this._uid = uid;
  try {
    const raw = localStorage.getItem('fd_undo_' + uid);
    if (raw) {
      const d = JSON.parse(raw);
      this._history = d.h || {};
      this._pos = d.p || {};
    }
  } catch (e) { }
};
UndoMgr._save = function () {
  if (!this._uid) return;
  try {
    localStorage.setItem('fd_undo_' + this._uid, JSON.stringify({ h: this._history, p: this._pos }));
  } catch (e) { }
};
const _oldSnap = UndoMgr.snapshot;
UndoMgr.snapshot = function (pageId, blocks) {
  _oldSnap.call(this, pageId, blocks);
  this._save();
};
const _oldUndo = UndoMgr.undo;
UndoMgr.undo = function (pageId) {
  const r = _oldUndo.call(this, pageId);
  this._save();
  return r;
};
const _oldRedo = UndoMgr.redo;
UndoMgr.redo = function (pageId) {
  const r = _oldRedo.call(this, pageId);
  this._save();
  return r;
};

// ─── PRIVACY PAGE ─────────────────────────────────────────────
function renderPrivacyPage(c) {
  c.innerHTML = `
    <div style="max-width:720px;margin:0 auto">
      <h1 style="font-size:32px;font-weight:800;font-family:var(--font-head);margin-bottom:6px">Privacy Policy</h1>
      <p style="color:var(--text-muted);font-size:13px;margin-bottom:32px">Last updated: February 2026</p>
      ${[
        ['What we collect', 'Axinote collects your email address and the content you create (notes, tasks, flashcards, projects). This data is stored securely in Firebase Realtime Database under your user ID.'],
        ['How we use your data', 'Your data is used solely to provide the Axinote service to you. We do not sell, share, or monetise your personal data with third parties.'],
        ['AI features', 'FlowAI uses your workspace data locally in your browser for retrieval and generation. If you explicitly enable future training examples, those examples remain local unless you choose to export them later.'],
        ['AI Credits', 'Plan metadata may still exist in Firebase, but FlowAI requests now run locally and do not require cloud inference.'],
        ['Cookies & Local Storage', 'We use browser localStorage to cache your data for offline use and to remember your session preferences. No third-party cookies are used.'],
        ['Data deletion', 'You can delete your account and all associated data at any time from Settings → Delete Account. Deletion is permanent and irreversible.'],
        ['Security', 'All data is encrypted in transit (HTTPS/TLS). Firebase security rules restrict access to your data to only your authenticated account.'],
        ['Contact', 'For privacy concerns or data requests, contact us at privacy@flowday.app'],
      ].map(([title, body]) => `
        <div style="margin-bottom:28px">
          <h2 style="font-size:17px;font-weight:700;margin-bottom:8px">${title}</h2>
          <p style="color:var(--text-muted);line-height:1.7;font-size:14px">${body}</p>
        </div>`).join('')}
    </div>`;
}

// ─── CHANGELOG PAGE ───────────────────────────────────────────
const CHANGELOG = [
  {
    version: '2.1.0',
    date: 'Feb 2026',
    changes: [
      ' Tasks inside notes — add linked tasks directly in your notes with /Task',
      ' Global Task View — Board, List, and Table views with filtering by priority, due date, status',
      ' AI Dashboard — manage credits, usage, and plan upgrades',
      ' Ask AI about this note — summarise, explain, generate questions from any note',
      ' Highlight text AI — select text and instantly summarise, explain, or simplify it',
      ' Project AI — get summaries, study plans, and gap analysis for entire projects',
      ' AI Credit system — transparent usage tracking with 75%/90%/100% warnings',
      '› Lazy loading — large notes (60+ blocks) now load progressively for instant responsiveness',
      ' AI retry logic — automatic retry with backoff on rate limits or server errors',
      ' Privacy page — clear data policy accessible from the sidebar',
      ' Changelog — you\'re reading it!',
    ]
  },
  {
    version: '2.0.0',
    date: 'Jan 2026',
    changes: [
      ' Projects — organise notes into projects with colour-coded views',
      ' Study Groups — collaborate on shared groups',
      ' Daily Tasks view — focused view for today\'s tasks',
      ' Themes — dark, light, and OLED modes',
      ' Profile avatars — personalise your profile',
    ]
  },
  {
    version: '1.0.0',
    date: 'Dec 2025',
    changes: [
      ' Axinote launch!',
      ' Notes with rich block editor',
      ' Tasks with Kanban board',
      '▣ Flashcards with spaced repetition',
      ' Calendar view',
      '◷ Focus timer (Pomodoro)',
      ' FlowAI Chat',
    ]
  }
];

// ══════════════════════════════════════════════════════════════════
// PERSONALISED STUDY INSIGHTS ENGINE (100% hardcoded — no AI calls)
// Tier gates: free=minimal, lite=some, pro=moderate, advanced=strong, elite=max
// ══════════════════════════════════════════════════════════════════

const STUDY_SCIENCE = {
  // Core science-backed methods with detailed descriptions
  spacedRepetition: {
    name: 'Spaced Repetition',
    icon: '↺',
    headline: 'Review at increasing intervals — not the night before.',
    detail: 'The "forgetting curve" (Ebbinghaus, 1885) shows memory halves within hours without review. Spaced repetition fights this by scheduling reviews just as you\'re about to forget: 1 day → 3 days → 7 days → 14 days → 30 days. Your Axinote flashcards already support this — use them daily, even for 8 minutes.',
    scienceNote: 'Improves long-term retention by 200–400% vs massed practice.',
  },
  activeRecall: {
    name: 'Active Recall',
    icon: '◈',
    headline: 'Close your notes and retrieve — don\'t re-read.',
    detail: 'Re-reading feels productive but produces an "illusion of knowing." The Testing Effect (Roediger & Karpicke, 2006) proves that trying to retrieve information — even failing — strengthens memory far more than passive review. After reading a section, close everything and write down what you remember. Then check.',
    scienceNote: 'Students who self-tested outperformed re-readers by 50% on 1-week retention tests.',
  },
  interleaving: {
    name: 'Interleaving',
    icon: '⇄',
    headline: 'Mix subjects in one session — don\'t block-study.',
    detail: 'Blocked practice (doing 30 math problems then 30 physics problems) feels smooth but causes shallow encoding. Interleaved practice (math → physics → chemistry → math) is harder but forces your brain to choose strategies, building deeper, more flexible understanding. Alternate between 2–3 subjects in every 90-minute session.',
    scienceNote: 'Interleaving improves test performance by 43% vs blocked study (Kornell & Bjork, 2008).',
  },
  elaborativeInterrogation: {
    name: 'Elaborate Questioning',
    icon: '?',
    headline: 'Ask "why" and "how" — not just "what".',
    detail: 'After learning a fact, ask yourself: "Why is this true? How does this connect to what I already know? What would happen if this were false?" This elaborative interrogation forces you to link new information into your existing knowledge network, making retrieval much faster under exam pressure.',
    scienceNote: 'Generates 30–50% better recall than reading alone.',
  },
  dualCoding: {
    name: 'Dual Coding',
    icon: '⊞',
    headline: 'Combine words with visuals — diagrams, mind maps, sketches.',
    detail: 'Paivio\'s Dual Coding Theory (1971) shows that verbal and visual information are processed in separate channels. When you represent the same concept both as text AND as a diagram or sketch, both channels reinforce each other. After reading a concept, draw a simple diagram, flowchart, or sketch without looking at notes.',
    scienceNote: 'Dual-encoded material is recalled 20–60% more accurately.',
  },
  pomodoroFlow: {
    name: 'Pomodoro + Rest',
    icon: '◷',
    headline: '25 min focus → 5 min break. Every 4th break = 20 min.',
    detail: 'The brain\'s prefrontal cortex fatigues after sustained focus. Short breaks allow the default mode network to consolidate what was just learned. The Pomodoro technique (Cirillo, 1987) structures this: 25-minute focused sprints with mandatory breaks. The key word is "mandatory" — skipping breaks reduces performance by 20–30% in later sessions.',
    scienceNote: 'Structured rest improves sustained output over a 3-hour session by ~28%.',
  },
  sleepConsolidation: {
    name: 'Sleep-Based Consolidation',
    icon: '◌',
    headline: 'Learn before sleep — your brain reviews it overnight.',
    detail: 'Memory consolidation happens primarily during slow-wave and REM sleep (Walker, 2017). Studying difficult material within 2 hours of sleep produces significantly stronger retention the next day. Never pull all-nighters before important assessments — even 6h of sleep dramatically outperforms no sleep on recall tasks. Study in the evening, sleep, review the next morning.',
    scienceNote: 'Sleep consolidation improves motor and declarative memory retention by 20–40%.',
  },
  errorAnalysis: {
    name: 'Error Analysis',
    icon: '◉',
    headline: 'Every wrong answer is a learning event — mine it.',
    detail: 'Most students circle wrong answers and move on. High performers spend 60% of review time on errors, not correct answers. For every mistake: (1) Identify what you were thinking when you got it wrong. (2) Trace the exact moment your reasoning broke down. (3) Write a "trap note" — a one-sentence reminder of the mistake category. (4) Create one flashcard that tests the exact concept.',
    scienceNote: 'Error-focused review produces 3× more improvement per hour vs coverage review.',
  },
  retrievalPractice: {
    name: 'Retrieval Practice',
    icon: '↑',
    headline: 'Practice tests are studying — not just assessment.',
    detail: 'Doing a practice test is one of the most powerful study methods discovered (Dunlosky et al., 2013), yet most students treat tests as things to be feared before learning is "complete." The act of retrieving information — even incorrectly — strengthens the memory trace far more than re-reading or re-watching. Do a practice test first, then study the gaps it reveals.',
    scienceNote: 'Practice testing produces 10–15% higher final exam scores vs equivalent study time.',
  },
  concreteExamples: {
    name: 'Concrete Examples',
    icon: '⊟',
    headline: 'Abstract concepts need real-world anchors.',
    detail: 'Abstract definitions are hard to retrieve under pressure. When you learn a concept, immediately create: (1) a real-world example you\'ve personally experienced, (2) a counterexample, and (3) an analogy to something you already know well. This concreteness bridges abstract definitions to accessible, retrievable memory.',
    scienceNote: 'Concrete examples improve transfer to novel problems by 40–60%.',
  },
};

const STRESS_MGMT_SCIENCE = {
  boxBreathing: {
    name: 'Box Breathing (4-4-4-4)',
    icon: '~',
    detail: 'Inhale 4 counts → hold 4 counts → exhale 4 counts → hold 4 counts. Repeat 4 cycles. Used by Navy SEALs for pre-mission clarity. Activates the parasympathetic nervous system within 90 seconds, reducing cortisol and restoring executive function for focused study.',
  },
  fiveMinuteRule: {
    name: 'The 5-Minute Rule',
    icon: '›',
    detail: 'When you feel unable to start: commit to only 5 minutes. Just open the book. Just write one line. Action generates motivation — not the other way around. Neuroscience: starting a task activates the nucleus accumbens, which produces dopamine and motivation. The hardest part is literally the first moment.',
  },
  cognitiveReframing: {
    name: 'Stress-to-Challenge Reframe',
    icon: '⇌',
    detail: 'Replace "I\'m so stressed about this exam" with "I\'m activated for this challenge." Harvard research (Jamieson, 2013) shows that reinterpreting anxiety as excitement produces measurably better performance on cognitive tasks. Your physiology doesn\'t change — but your brain\'s interpretation changes how it uses those resources.',
  },
  breakTypes: {
    name: 'Active vs Passive Recovery',
    icon: '»',
    detail: 'Not all breaks are equal. Passive breaks (scrolling social media) produce cognitive fatigue carry-over. Active recovery (5-min walk, 20 jumping jacks, making a drink, brief journaling) allows neural circuits to reset. Build micro-movement into every break.',
  },
  examDayProtocol: {
    name: 'Pre-Exam Protocol',
    icon: '◎',
    detail: 'Night before: review summary notes only (30 min), sleep 7+ hours. Morning of: light protein breakfast, 5 min box breathing, read through your own "strength notes." At seat: start with the questions you\'re most confident about — early wins build confidence for harder questions.',
  },
};

// ─── CORE ENGINE ─────────────────────────────────────────────────────────────

function getPersonalizedStudyInsights() {
  const tier = getCurrentTier();
  const tierLevel = PLAN_ORDER[tier] || 0; // 0=free, 1=lite, 2=pro, 3=advanced, 4=elite
  const profile = eliteGetStudyProfile();
  const today = new Date().toISOString().split('T')[0];

  // Gather all available signals
  const activeTasks = (S.tasks || []).filter(t => !t.completed);
  const overdueTasks = activeTasks.filter(t => t.due && t.due < today);
  const dueSoon3 = activeTasks.filter(t => t.due && t.due >= today && t.due <= addDays(today, 3));
  const completedTasks = (S.tasks || []).filter(t => t.completed);
  const taskCompletionRate = (S.tasks || []).length ? completedTasks.length / S.tasks.length : 0;
  const flashcardDecks = (S.flashcards || []).length;
  const totalPages = (S.pages || []).length;
  const recentPages = (S.pages || []).filter(p => {
    const ts = new Date(p.updatedAt || p.createdAt || 0).getTime();
    return ts >= Date.now() - 7 * 24 * 3600 * 1000;
  }).length;
  const upcomingExams = (S.calendar || []).filter(e =>
    (e.category === 'exam' || (e.title || '').toLowerCase().includes('exam') || (e.title || '').toLowerCase().includes('test')) &&
    e.date >= today && e.date <= addDays(today, 30)
  ).sort((a, b) => a.date.localeCompare(b.date));
  const nextExam = upcomingExams[0];
  const daysToExam = nextExam ? Math.max(0, Math.round((new Date(nextExam.date + 'T12:00:00') - Date.now()) / 86400000)) : null;
  const studyEvents = (S.calendar || []).filter(e =>
    (e.category === 'study') && e.date >= addDays(today, -7) && e.date <= today
  ).length; // study sessions in last 7 days
  const mockExamCount = (S.mockExams || []).filter(e => typeof e.lastScore === 'number').length;
  const avgMockScore = mockExamCount
    ? Math.round((S.mockExams || []).filter(e => typeof e.lastScore === 'number').reduce((s, e) => s + e.lastScore, 0) / mockExamCount)
    : null;

  // Profile-driven signals (only for elite who filled the diagnostic)
  const stressLevel = profile?.stressLevel || 2; // 1=low, 4=very high
  const sleepHours = profile?.sleepHours || 6.8;
  const burnoutRisk = profile?.burnoutRisk || 2; // 1=rare, 4=constant
  const revisionMethod = profile?.revisionMethod || 2; // 1=passive, 4=exam_drill
  const pastPaperFreq = profile?.pastPaperFreq || 1; // 0-3
  const ccaLoad = profile?.ccaLoad || 2; // 1=light, 4=very_heavy
  const focusWindow = profile?.focusWindow || 'evening';
  const scheduleQuality = profile?.scheduleQuality || 2; // 1=chaotic, 4=highly_structured
  const support = profile?.support || 3; // 1=none, 4=strong
  const weekdayHrs = profile?.weekdayStudyHrs || 1.5;
  const weekendHrs = profile?.weekendStudyHrs || 3;

  // ─── Derive smart signals ────────────────────────────────────────
  const isHighStress = stressLevel >= 3;
  const isVeryHighStress = stressLevel >= 4;
  const isBurntOut = burnoutRisk >= 3;
  const isSleepDeprived = sleepHours < 6.5;
  const isPassiveLearner = revisionMethod <= 1;
  const isLowPaperPractice = pastPaperFreq <= 1;
  const isHeavyCCA = ccaLoad >= 3;
  const isChaoticSchedule = scheduleQuality <= 1;
  const hasExamSoon = daysToExam !== null && daysToExam <= 14;
  const hasExamVerySoon = daysToExam !== null && daysToExam <= 4;
  const isLowFlashcards = flashcardDecks < 2;
  const hasOverdue = overdueTasks.length > 0;
  const isOverloaded = overdueTasks.length >= 3 || (activeTasks.length >= 10 && taskCompletionRate < 0.4);
  const isActiveStudier = recentPages >= 3 || studyEvents >= 3;

  // ─── Build tips array, each tip has: priority (0-10), tip object ─────────
  const rawTips = [];

  const push = (priority, tip) => rawTips.push({ priority, ...tip });

  // ── SLEEP (universal — always important) ──────────────────────────────────
  if (isSleepDeprived && tierLevel >= 1) {
    push(9, {
      id: 'sleep_dep',
      category: 'Wellbeing',
      icon: '◌',
      title: 'Sleep debt is hurting your learning',
      body: `You\'re averaging ${sleepHours}h of sleep. Below 7h, the hippocampus — your brain\'s memory-encoding region — cannot form new long-term memories efficiently. Even one night of full sleep before an exam matters more than an extra 2 hours of studying.`,
      action: 'Protect 7–8h of sleep this week. If you must cut something, cut late-night study first.',
      science: 'Walker (2017): Sleep-deprived students retain 40% less from the previous day\'s study.',
      urgency: 'high',
    });
  }

  // ── EXAM COUNTDOWN (context-aware) ────────────────────────────────────────
  if (hasExamVerySoon && tierLevel >= 0) {
    push(10, {
      id: 'exam_very_soon',
      category: 'Exam Prep',
      icon: '◎',
      title: `${nextExam?.title || 'Exam'} is in ${daysToExam} day${daysToExam === 1 ? '' : 's'}`,
      body: 'With less than 4 days to go: stop learning new content. Your goal is now retrieval, not coverage. Do one timed past paper, then error-analyse it. Review your summary notes twice. Get 8 hours sleep the night before.',
      action: 'Tonight: 1 past paper (timed) → error list → 30-min targeted review → bed by 10pm.',
      science: 'Pre-exam cramming increases anxiety without improving performance. Confidence from preparation — not last-minute content — is what moves grades.',
      urgency: 'critical',
    });
  } else if (hasExamSoon && tierLevel >= 0) {
    push(8, {
      id: 'exam_soon',
      category: 'Exam Prep',
      icon: '▦',
      title: `${nextExam?.title || 'Exam'} in ${daysToExam} days — shift to exam mode`,
      body: 'With 5–14 days to go: reduce new content to 20% of study time. Spend 80% on retrieval: past papers, flashcards, active recall, error analysis. Each day, prioritise your weakest subject first while your brain is fresh.',
      action: `Daily structure: ${focusWindow === 'early' ? 'Morning' : focusWindow === 'afternoon' ? 'Afternoon' : 'Evening'} = weakest subject (active recall). Other slot = past papers.`,
      science: 'The "80/20 exam mode" rule: high-performers shift to retrieval-heavy practice ~2 weeks before assessment.',
      urgency: 'high',
    });
  }

  // ── OVERLOAD / BURNOUT ────────────────────────────────────────────────────
  if (isBurntOut && tierLevel >= 1) {
    push(9, {
      id: 'burnout',
      category: 'Wellbeing',
      icon: '▮',
      title: 'Burnout detected — productivity is already declining',
      body: 'You\'ve reported frequent or constant burnout. Burnout is not laziness — it\'s a physiological state where the stress hormones (cortisol) that normally aid focus are chronically elevated, impairing memory and decision-making. Pushing harder right now will worsen outcomes, not improve them.',
      action: 'Take one 48-hour "recovery weekend" this month. Plan 1 complete study-free day per week going forward.',
      science: 'Chronic stress shrinks the hippocampus (Sapolsky, 2004). Recovery is not wasted time — it restores the brain structures you study with.',
      urgency: 'high',
    });
  } else if (isHighStress && tierLevel >= 1) {
    push(7, {
      id: 'high_stress',
      category: 'Wellbeing',
      icon: '–',
      title: 'High stress is narrowing your thinking',
      body: 'Elevated stress hormones cause tunnel vision — you start forgetting connections between topics, make careless errors, and feel "blank" in exams. The fix isn\'t to study more. It\'s to study smarter, with intentional recovery built in.',
      action: 'Before each study session: 4 rounds of box breathing (4s in, 4s hold, 4s out, 4s hold). Takes 2 minutes. Measurably reduces cortisol.',
      science: 'Pre-task breathing protocols improve working memory capacity by 15–22% in high-stress individuals.',
      urgency: 'medium',
    });
  }

  if (isOverloaded && tierLevel >= 0) {
    push(8, {
      id: 'overloaded',
      category: 'Focus',
      icon: '[ ]',
      title: `${overdueTasks.length} overdue tasks — prioritise ruthlessly`,
      body: 'An overdue task queue is a major source of cognitive load — your brain wastes energy tracking uncompleted items (the "Zeigarnik effect"). This reduces the mental bandwidth available for actual study.',
      action: 'Right now: pick your 3 most important overdue tasks. Mark the rest as "later" or remove them. Then clear those 3 today.',
      science: 'Cognitive load theory: unresolved task loops consume working memory even when you\'re "studying something else."',
      urgency: overdueTasks.length >= 3 ? 'high' : 'medium',
    });
  }

  // ── REVISION METHOD ────────────────────────────────────────────────────────
  if (isPassiveLearner && tierLevel >= 1) {
    push(8, {
      id: 'passive_learner',
      category: 'Study Method',
      icon: '◈',
      title: 'Re-reading notes is one of the least effective study methods',
      body: 'Re-reading feels productive — you recognise the words, it\'s familiar, it\'s comfortable. But recognition ≠ recall. On exam day, nothing is familiar. Your brain needs retrieval practice, not recognition practice.',
      action: 'Change: after reading 1 page of notes, close them. Write down everything you remember on a blank sheet. Check. Fix gaps. This is active recall.',
      science: 'Karpicke & Blunt (2011): Active recall produced 50% higher retention than "elaborative study" strategies at 1-week follow-up.',
      urgency: 'high',
    });
  } else if (revisionMethod <= 2 && tierLevel >= 2) {
    push(6, {
      id: 'mixed_to_active',
      category: 'Study Method',
      icon: '↑',
      title: 'Shift your study mix toward more active recall',
      body: 'You\'re using a mix of notes + practice, which is solid. To reach the next level: aim for 70% retrieval (testing yourself, past papers, flashcards) and only 30% content review (reading, watching). Most students do it backwards.',
      action: 'For your next session: spend the first 10 minutes writing everything you already know about the topic — before opening any notes. Then fill in what you missed.',
      science: 'Dunlosky et al. (2013) meta-analysis: retrieval practice ranked highest among 10 study techniques; re-reading ranked near the bottom.',
      urgency: 'medium',
    });
  }

  // ── PAST PAPERS ───────────────────────────────────────────────────────────
  if (isLowPaperPractice && tierLevel >= 2) {
    push(7, {
      id: 'past_papers',
      category: 'Exam Prep',
      icon: '/',
      title: 'Timed past papers are your highest-ROI study activity',
      body: 'You\'re doing past papers less than once a week. Past papers do something no other method can: they force you to retrieve under time pressure with unfamiliar question framing. Even a "bad" past paper session — where you get many things wrong — is more valuable than reading notes.',
      action: `Set aside one ${focusWindow === 'early' ? 'morning' : 'evening'} per week for a timed, full past paper. Treat it like a real exam. Then spend twice as long on the error analysis.`,
      science: 'Roediger & Karpicke (2006): "Testing effect" — timed testing improves long-term retention more than any equivalent time spent studying.',
      urgency: 'medium',
    });
  }

  // ── FLASHCARDS ────────────────────────────────────────────────────────────
  if (isLowFlashcards && tierLevel >= 1) {
    push(5, {
      id: 'flashcards',
      category: 'Study Method',
      icon: '▣',
      title: 'You have very few flashcard decks — consider building more',
      body: 'Flashcards are the most efficient vehicle for spaced repetition. Even 10 minutes per day reviewing flashcards before sleep creates significantly better long-term retention than a single 2-hour review session weekly.',
      action: 'Build one deck for your most memorisation-heavy subject: key terms, formulas, dates, or process steps. Start with 15 cards — don\'t aim for perfection.',
      science: 'Spaced repetition of just 10 min/day beats 70 min/week of massed review by 2–3× on 30-day retention tests.',
      urgency: 'low',
    });
  }

  // ── INTERLEAVING (pro+) ───────────────────────────────────────────────────
  if (tierLevel >= 2) {
    push(5, {
      id: 'interleaving',
      category: 'Study Method',
      icon: '⇄',
      title: 'Block-studying one subject feels smooth — but it\'s less effective',
      body: 'Studying Biology for 3 hours then Chemistry for 3 hours feels productive. But interleaving (45 min Bio → 45 min Chem → 45 min Bio) produces significantly better recall — even though it feels harder in the moment. That "harder" feeling is your brain forming stronger connections.',
      action: `For your next 3-hour session: split it into 6 × 30-min blocks. Alternate between 2–3 subjects. Your focus window is ${focusWindow === 'early' ? 'early morning' : focusWindow === 'afternoon' ? 'the afternoon' : 'the evening'} — protect it for this.`,
      science: 'Kornell & Bjork (2008): Interleaved practice scored 43% higher on delayed tests vs blocked practice, despite feeling less effective while doing it.',
      urgency: 'medium',
    });
  }

  // ── FOCUS WINDOW ALIGNMENT ────────────────────────────────────────────────
  if (tierLevel >= 2 && profile) {
    const windowMap = {
      early: { label: 'early morning', time: '6–9am', oppLabel: 'night', tip: 'Wake 30 minutes earlier and start immediately — your prefrontal cortex is freshest in the first 2 hours after waking.' },
      afternoon: { label: 'afternoon', time: '1–5pm', oppLabel: 'morning or night', tip: 'Your early afternoon focus peak is real (cortisol curve peaks ~9–11am, with a secondary wave at 3pm). Use it for your hardest material.' },
      evening: { label: 'evening', time: '7–10pm', oppLabel: 'morning', tip: 'Evening study has a bonus: learning before sleep benefits from overnight consolidation. Review hardest content in the last 90 mins before sleep.' },
      late_night: { label: 'late night', time: 'after 10pm', oppLabel: 'daytime', tip: 'Late-night study can work, but sleep deprivation from staying up past midnight severely impairs next-day recall. Hard deadline: lights out by 12:30am absolute maximum.' },
    };
    const winfo = windowMap[focusWindow] || windowMap.evening;
    push(4, {
      id: 'focus_window',
      category: 'Planning',
      icon: '◔',
      title: `Your peak focus is ${winfo.label} — protect it for hardest material`,
      body: `You identified ${winfo.label} (${winfo.time}) as your best focus window. This aligns with your cortisol rhythm. Use this window for active recall, past papers, and hard problem sets — not for re-reading, organising notes, or admin tasks.`,
      action: winfo.tip,
      science: 'Chronobiology research: cognitive performance varies 20–30% across the day based on circadian rhythm. Working with your rhythm, not against it, is free performance.',
      urgency: 'low',
    });
  }

  // ── CCA LOAD MANAGEMENT ───────────────────────────────────────────────────
  if (isHeavyCCA && tierLevel >= 2) {
    push(6, {
      id: 'cca_load',
      category: 'Planning',
      icon: '⊜',
      title: 'Heavy CCA load means you need high-efficiency study, not just more hours',
      body: `With ${ccaLoad >= 4 ? 'very heavy' : 'heavy'} CCA commitments, trying to match peers' study hours is unsustainable. Instead, focus entirely on quality and elimination: do only the highest-ROI activities (past papers, active recall, spaced repetition) and eliminate low-ROI activities (re-reading, passive watching, note-copying).`,
      action: 'Calculate your real available study hours per week. Then rank your study activities from highest to lowest impact. Only keep the top 3 methods.',
      science: 'Research on athlete-students shows that constrained time produces higher per-hour efficiency than unconstrained time — the constraint forces prioritisation.',
      urgency: 'medium',
    });
  }

  // ── SCHEDULE QUALITY ──────────────────────────────────────────────────────
  if (isChaoticSchedule && tierLevel >= 1) {
    push(7, {
      id: 'schedule',
      category: 'Planning',
      icon: '▦',
      title: 'A chaotic schedule burns motivation — structure protects it',
      body: 'Decision fatigue is real: every time you have to decide what to study next, you waste cognitive resources you could have used studying. A weekly template — not a rigid timetable, but a default structure — eliminates these micro-decisions and makes studying the path of least resistance.',
      action: 'This weekend: map out 5 "study slots" in your calendar for next week. Label each slot with a specific subject. Don\'t plan content — just time and subject.',
      science: 'Implementation intentions (Gollwitzer, 1999): pre-deciding when/where/what you\'ll study increases follow-through by 2–3×.',
      urgency: 'medium',
    });
  }

  // ── STUDY SCIENCE FOUNDATION (always useful) ─────────────────────────────
  if (tierLevel >= 0 && !isPassiveLearner) {
    push(3, {
      id: 'spaced_rep_reminder',
      category: 'Study Method',
      icon: '↺',
      title: 'Spaced repetition: the single most evidence-backed study technique',
      body: 'If you review material once after 1 day, once after 3 days, once after 7 days, and once after 14 days — you\'ll remember it better at 3 months than if you reviewed it 8 times in the same week. The spacing effect is one of the most robustly replicated findings in memory science.',
      action: 'When you create notes, immediately schedule 4 review checkpoints in your calendar: +1d, +3d, +7d, +14d. Use your Axinote calendar for this.',
      science: 'Cepeda et al. (2008) meta-analysis of 254 studies: spaced practice increases long-term retention by 10–30% with no additional time cost.',
      urgency: 'low',
    });
  }

  // ── DUAL CODING (pro+) ────────────────────────────────────────────────────
  if (tierLevel >= 2) {
    push(3, {
      id: 'dual_coding',
      category: 'Study Method',
      icon: '⊞',
      title: 'Add one diagram or sketch to every concept you learn',
      body: 'Your visual and verbal memory systems are independent. When you learn a concept and also draw a sketch or diagram of it — even a rough one — you encode it twice, in two different systems. This makes retrieval much more robust, because if one pathway fails in an exam, the other still works.',
      action: 'For your next study session: after every major concept, spend 90 seconds drawing a rough flowchart, mind map, or annotated sketch. Don\'t worry about neatness.',
      science: 'Dual coding consistently produces 20–60% better recall than verbal-only study across diverse subjects.',
      urgency: 'low',
    });
  }

  // ── EXAM TECHNIQUE (pro+) ─────────────────────────────────────────────────
  if (tierLevel >= 2 && (eliteTrack() === 'sg_o_level' || eliteTrack() === 'sg_a_level' || eliteTrack() === 'sg_n_level')) {
    push(5, {
      id: 'command_words',
      category: 'Exam Prep',
      icon: '⊗',
      title: 'Singapore exam command words are non-negotiable precision requirements',
      body: '"Describe" ≠ "Explain" ≠ "Evaluate" ≠ "Discuss" ≠ "Compare." Each command word has a specific answer structure required by SEAB mark schemes. Many students lose 20–30% of their available marks simply by treating these words as interchangeable.',
      action: `Create a command words cheat sheet: for each command word used in your ${eliteTrackLabel()} subjects, write the exact response format required. Review before every past paper.`,
      science: 'SEAB marker reports consistently cite "failure to address command words" as the most common mark-losing error across subjects.',
      urgency: 'medium',
    });
  }

  // ── POMODORO OPTIMISATION (lite+) ─────────────────────────────────────────
  if (tierLevel >= 1) {
    const pomHrs = weekdayHrs + weekendHrs * 2 / 7;
    if (pomHrs < 2) {
      push(4, {
        id: 'study_hours',
        category: 'Planning',
        icon: '◷',
        title: 'Your total daily study time looks low — even 30 min more helps significantly',
        body: `You\'re averaging around ${Math.round(pomHrs * 10) / 10}h of study per day. Even adding one extra Pomodoro (25 minutes) of high-quality active recall per day compounds significantly over a semester — that\'s 15+ extra hours of quality study per month.`,
        action: 'Add one fixed 25-minute study block to your routine: right after dinner, or immediately after arriving home from school.',
        science: 'Habit stacking (James Clear, Atomic Habits): attaching a new habit to an existing routine reduces activation energy by 60%.',
        urgency: 'low',
      });
    }
  }

  // ── MOCK EXAM FEEDBACK (advanced+) ───────────────────────────────────────
  if (tierLevel >= 3 && mockExamCount > 0 && avgMockScore !== null) {
    if (avgMockScore < 60) {
      push(8, {
        id: 'low_mock_scores',
        category: 'Exam Prep',
        icon: '▤',
        title: `Mock score average of ${avgMockScore}% — this needs immediate diagnostic work`,
        body: 'A sub-60% average on mock exams usually points to one of three root causes: (1) coverage gaps — you haven\'t learned some topics at all, (2) retrieval failures — you know it but can\'t produce it under pressure, or (3) exam technique — you know the content but lose marks on structure and command words.',
        action: 'For your next mock: after getting results, categorise each wrong answer as Type 1 (never knew), Type 2 (knew but blanked), or Type 3 (technique error). Address each category differently.',
        science: 'Diagnostic classification of errors produces 3× faster improvement than generic reviewing.',
        urgency: 'high',
      });
    } else if (avgMockScore >= 75) {
      push(4, {
        id: 'strong_mock_scores',
        category: 'Exam Prep',
        icon: '△',
        title: `Strong mock average of ${avgMockScore}% — now focus on ceiling-breaking`,
        body: 'You\'re performing well. To break through to the top score band, shift focus from "knowing more content" to "expressing what you know with greater precision." Examiners reward specificity, use of key terminology, and structured argumentation.',
        action: 'In your next practice: for each answer, add one specific piece of data, one technical term, and a clearer conclusion sentence. Compare to mark schemes for phrasing.',
        science: 'Top-band students don\'t always know more — they demonstrate knowledge more precisely. Marker studies show 30–40% of the gap between B and A is expression, not knowledge.',
        urgency: 'low',
      });
    }
  }

  // ── ELABORATIVE INTERROGATION (pro+) ─────────────────────────────────────
  if (tierLevel >= 2) {
    push(3, {
      id: 'why_questioning',
      category: 'Study Method',
      icon: '?',
      title: 'Ask "why" after every fact you memorise',
      body: 'Every time you learn something — a formula, a date, a definition — immediately ask: "Why is this true? Why was this event significant? Why does this formula work this way?" This elaborative questioning forces deep encoding, and deeply encoded facts are far more stable under exam pressure than surface-level memorisation.',
      action: `After your next study session: pick 5 facts you reviewed. For each, write a 1-sentence answer to "Why does this matter?" or "Why is this true?"`,
      science: 'Elaborative interrogation generates 30–50% better recall on delayed tests vs reading alone (Pressley et al., 1992).',
      urgency: 'low',
    });
  }

  // ── SUPPORT NETWORK (if isolated) ─────────────────────────────────────────
  if (support <= 2 && tierLevel >= 1) {
    push(5, {
      id: 'support_low',
      category: 'Wellbeing',
      icon: '⊕',
      title: 'Studying alone with limited support is harder than it looks — you can change this',
      body: 'Students with limited academic support tend to experience more anxiety, more comparison-driven stress, and lower confidence under pressure. Seeking a study partner — even one peer — produces peer accountability that significantly improves consistency.',
      action: 'Try the Axinote study groups feature: find 1–2 peers studying the same subjects. Even 30 minutes of shared reviewing per week improves motivation and catches gaps you\'d miss alone.',
      science: 'Social learning research: accountability partners improve follow-through on study goals by 65% (American Society of Training & Development).',
      urgency: support <= 1 ? 'medium' : 'low',
    });
  }

  // ── POSITIVE REINFORCEMENT (when doing well) ──────────────────────────────
  if (isActiveStudier && !hasOverdue && !isHighStress && tierLevel >= 1) {
    push(2, {
      id: 'keep_going',
      category: 'Momentum',
      icon: 'ok',
      title: 'Strong study momentum — protect what\'s working',
      body: `You've been active in notes (${recentPages} pages this week) and keeping your task board clear. Consistency is the single most important variable in long-term academic performance — not intensity, consistency.`,
      action: 'Write down the 2 study habits that are working best for you right now. Make a rule: those 2 habits happen every single day, no matter what.',
      science: 'Habit research (Clear, Wood): consistent daily routines, even brief ones, outperform irregular intensive sessions over 3+ months.',
      urgency: 'low',
    });
  }

  // ── ELITE-SPECIFIC: track-specific tips ───────────────────────────────────
  if (tierLevel >= 4) {
    const track = eliteTrack();
    if (track === 'sg_psle') {
      push(7, {
        id: 'psle_specific',
        category: 'PSLE Strategy',
        icon: '⊛',
        title: 'PSLE Achievement Level prediction: maximise AL1 probability',
        body: 'PSLE AL1 (≥90) requires not just knowledge but exam execution: time management, understanding of SEAB marking rubrics, and consistent performance under pressure. One underperforming paper (e.g., PSLE Science) can pull your total PSLE score significantly.',
        action: 'Map your 4 PSLE subjects by current performance. For your weakest subject: dedicate 40% of this week\'s study time to it, using past-year PSLE papers specifically (not school papers — SEAB format matters).',
        science: 'SEAB PSLE data: students who practice exclusively with SEAB-format papers outperform those using school papers by ~0.3–0.5 AL levels.',
        urgency: 'high',
      });
    } else if (track === 'sg_o_level') {
      push(7, {
        id: 'olevel_specific',
        category: 'O-Level Strategy',
        icon: '⊛',
        title: 'O-Level L1R5: Every subject matters differently for JAE',
        body: 'O-Level results are used for JAE (Junior College) admission as L1R5 (English + 5 relevant subjects). Know exactly which 5 subjects count for your target JC. Optimising a subject that doesn\'t contribute to your L1R5 is wasted effort if borderline subjects are being neglected.',
        action: 'Look up the L1R5 cut-off point of your target JC. Map your predicted grades. Identify which subjects are "at risk" of pulling your L1R5 above the cut-off. Focus there.',
        science: 'Strategic subject prioritisation: students who explicitly track their L1R5 target allocation outperform those who treat all subjects equally.',
        urgency: 'high',
      });
    } else if (track === 'sg_a_level') {
      push(7, {
        id: 'alevel_specific',
        category: 'A-Level Strategy',
        icon: '⊛',
        title: 'A-Level UAS points: H2/H1 grade differential matters enormously',
        body: 'A-Level University Admission Score (UAS) is calculated from your best 3 H2s + 1 H1 (+ bonus). Each grade step (A to B, B to C) at H2 level costs 10 UAS points. That can mean the difference between NUS Medicine and your 2nd choice course.',
        action: 'Calculate your current predicted UAS. Identify which H2 subject improvement would give you the largest UAS gain per hour of study invested. Focus there.',
        science: 'NUS/NTU data: 70% of grade-to-admission improvements come from improving one underperforming H2 subject, not from marginal gains across all subjects.',
        urgency: 'high',
      });
    } else if (track === 'sg_ib') {
      push(7, {
        id: 'ib_specific',
        category: 'IB Strategy',
        icon: '⊛',
        title: 'IB: TOK/EE bonus points are often the difference between 43 and 45',
        body: 'IB total: 42 subject points + 3 bonus points from TOK and EE. Most students treat TOK and EE as boxes to tick. Top performers treat them as opportunities: a stellar EE (high D/A grade) + good TOK essay gives the full 3 bonus points — equivalent to gaining 3 subject points for ~120 hours of work.',
        action: 'If your EE is not yet started or in early draft: treat it as a core academic priority this term. The ROI in bonus points is very high.',
        science: 'IB score distributions show that students who score full 3 bonus points have median total scores 2.8 points above students who score 1–2 bonus points, even with equivalent subject performance.',
        urgency: 'high',
      });
    } else if (track === 'sg_n_level') {
      push(7, {
        id: 'nlevel_specific',
        category: 'N-Level Strategy',
        icon: '⊛',
        title: 'N-Level → O-Level progression: set yourself up for NITEC or O-Level now',
        body: 'N(A) students who achieve B3 or better in English, Maths, and at least 2 other subjects qualify to sit O-Levels the following year. This pathway can access polytechnic diplomas directly. Every subject matters for keeping this option open.',
        action: 'Identify the minimum grades needed for your preferred post-N(A) pathway. Build a study plan specifically targeted at those gateway subjects.',
        science: 'MOE data: N-Level students who set explicit O-Level progression targets during N-Level year show 40% higher rates of achieving qualifying scores.',
        urgency: 'high',
      });
    }
  }

  // ── ADVANCED: peer benchmarking awareness ─────────────────────────────────
  if (tierLevel >= 3) {
    const examsWithScores = (S.mockExams || []).filter(e => typeof e.lastScore === 'number');
    if (examsWithScores.length === 0) {
      push(6, {
        id: 'no_benchmarks',
        category: 'Diagnostics',
        icon: '▤',
        title: 'No mock exam data — your readiness score is uncertain',
        body: 'Without mock exam scores, your predicted grade and readiness score are estimated from task behaviour and activity data only. This is a much weaker signal than actual performance data. Every mock exam you log immediately improves the accuracy of your predictions.',
        action: 'Log your next practice paper score in Axinote\'s Mock Exams section — even a partial result. Start building your performance history.',
        science: 'Self-assessment accuracy improves dramatically with even 3–5 data points of actual test performance. Calibrated confidence is more actionable than intuition.',
        urgency: 'medium',
      });
    }
  }

  // ── FREE TIER: give taste of what\'s available ─────────────────────────────
  if (tierLevel === 0) {
    push(3, {
      id: 'free_intro',
      category: 'Study Method',
      icon: '◆',
      title: 'Tip: Active recall beats re-reading every time',
      body: 'The simplest upgrade to your study routine: after reading your notes, close them completely and write down everything you remember on a blank page. This retrieval attempt — even when imperfect — strengthens memory 2–3× more than re-reading.',
      action: 'Try this right now with your most recent notes. Blank page, closed notes, 5 minutes.',
      science: 'The Testing Effect: one of the most replicated findings in cognitive psychology.',
      urgency: 'low',
    });
    push(2, {
      id: 'free_spaced',
      category: 'Study Method',
      icon: '↺',
      title: 'Review new material after 1 day, 3 days, 7 days',
      body: 'This 1-3-7 review schedule is free, simple, and dramatically improves retention. When you make notes today, add three calendar reminders for 1, 3, and 7 days from now to review them briefly.',
      action: 'Add those 3 calendar reminders for your most recent notes right now.',
      science: 'Even a basic spaced schedule beats massed review by 30–50% at 1-month retention.',
      urgency: 'low',
    });
  }

  // ─── Sort by priority (highest first), apply tier-gating on count ─────────
  rawTips.sort((a, b) => b.priority - a.priority);
  const tipCount = tierLevel === 0 ? 2 : tierLevel === 1 ? 3 : tierLevel === 2 ? 5 : tierLevel === 3 ? 7 : 10;
  const tips = rawTips.slice(0, tipCount);

  // ─── ELITE: generate personal brief + FlowAI context ─────────────────────
  let eliteBrief = null;
  let flowAIContext = null;

  if (tierLevel >= 4) {
    const eInsights = eliteInsights();
    const track = eliteTrack();
    const trackLabel = eliteTrackLabel();
    const name = S.userProfile?.displayName || S.userProfile?.name || null;
    const userName = name ? name.split(' ')[0] : null;

    // ── Situation synthesis ─────────────────────────────────────────────────
    const signals = [];
    const urgent = [];
    const positive = [];

    // Wellbeing read
    if (isVeryHighStress && isSleepDeprived) {
      urgent.push({ key: 'crisis_wellbeing', label: 'Critical wellbeing risk', detail: `Stress is very high AND sleep is at ${sleepHours}h — this combination actively degrades memory consolidation and exam-day performance. Address this before anything else.` });
    } else if (isBurntOut) {
      urgent.push({ key: 'burnout', label: 'Burnout detected', detail: `You've reported frequent to constant burnout. Cortisol at this level impairs the hippocampus — the region you literally study with. Recovery is not optional.` });
    } else if (isSleepDeprived) {
      urgent.push({ key: 'sleep', label: 'Sleep debt accumulating', detail: `${sleepHours}h average sleep. Below 7h, memory consolidation drops 40%. Your study hours are worth less than they appear.` });
    } else if (isHighStress) {
      signals.push({ key: 'stress', label: 'Elevated stress', detail: `Stress is moderate-to-high. It's narrowing your thinking — box breathing before sessions can measurably improve working memory.` });
    } else {
      positive.push('Wellbeing appears stable');
    }

    // Exam proximity
    if (hasExamVerySoon) {
      urgent.push({ key: 'exam_imminent', label: `${nextExam?.title || 'Exam'} in ${daysToExam}d`, detail: `Stop learning new content. Your only job now: retrieval under time pressure. One timed past paper per day, error-analyse, sleep 8 hours.` });
    } else if (hasExamSoon) {
      signals.push({ key: 'exam_approaching', label: `${nextExam?.title || 'Exam'} in ${daysToExam} days`, detail: `Shift to 80% retrieval practice now. Every day of content-reading past this point has diminishing returns vs timed past papers.` });
    }

    // Study behaviour
    if (isPassiveLearner) {
      urgent.push({ key: 'passive', label: 'Study method is low-efficiency', detail: `Your revision pattern is mostly passive — re-reading, note-reviewing. This produces recognition memory, not recall. Exams test recall.` });
    }
    if (isLowPaperPractice && daysToExam && daysToExam <= 30) {
      signals.push({ key: 'papers', label: 'Past paper frequency is too low', detail: `Under ${daysToExam <= 14 ? 'exam pressure, this is critical' : '30 days out, this needs addressing'}. Timed past papers are the closest simulation to exam conditions.` });
    }
    if (isChaoticSchedule) {
      signals.push({ key: 'schedule', label: 'No consistent study structure', detail: `Inconsistency means motivation carries your study, not habit. Motivation fluctuates. Structure holds when motivation dips.` });
    }
    if (isHeavyCCA) {
      signals.push({ key: 'cca', label: 'Heavy CCA load — efficiency is everything', detail: `You cannot match peers' study hours, so you must outperform them on study quality. Eliminate re-reading, double down on past papers and active recall.` });
    }
    if (isOverloaded) {
      signals.push({ key: 'overload', label: `${overdueTasks.length} overdue tasks creating cognitive drag`, detail: `The Zeigarnik effect: unclosed tasks consume mental bandwidth continuously. Clear or defer them — your brain is paying a tax right now.` });
    }
    if (isActiveStudier && !hasOverdue && !isHighStress) {
      positive.push(`Good study momentum (${recentPages} notes this week)`);
    }
    if (avgMockScore !== null && avgMockScore >= 75) {
      positive.push(`Strong mock average: ${avgMockScore}% — focus shifts to expression precision, not more content`);
    }
    if (avgMockScore !== null && avgMockScore < 60) {
      urgent.push({ key: 'mock_low', label: `Mock average ${avgMockScore}% needs diagnostic work`, detail: `Categorise each wrong answer: Type 1 = never knew, Type 2 = knew but blanked, Type 3 = exam technique. Each type needs a different fix.` });
    }

    // Efficiency signals
    const studyEfficiency = (() => {
      const hrsPerDay = (weekdayHrs * 5 + weekendHrs * 2) / 7;
      const qualityMod = (revisionMethod / 4) * (pastPaperFreq / 3) * 1.5;
      return Math.round(Math.min(100, (qualityMod * 60) + (Math.min(hrsPerDay, 4) / 4) * 40));
    })();
    const studyHrsPerDay = Math.round(((weekdayHrs * 5 + weekendHrs * 2) / 7) * 10) / 10;

    // Track-specific context
    const trackContext = {
      sg_psle: { metric: 'PSLE Score', goal: 'AL1 (≥90) across all 4 subjects', focus: 'Weakest subject needs 40% of study time. Use only SEAB-format papers.' },
      sg_o_level: { metric: 'L1R5', goal: 'Target JC cut-off point', focus: 'Know which 5 subjects count for your target. Borderline subjects get priority.' },
      sg_a_level: { metric: 'UAS points', goal: 'University admission threshold', focus: 'Best 3 H2s + 1 H1. Improving your weakest H2 gives the largest UAS gain per hour.' },
      sg_ib: { metric: 'IB Total', goal: '42+ subject points + 3 bonus (TOK/EE)', focus: 'TOK and EE bonus points are high-ROI. Treat EE as a core academic priority, not an admin task.' },
      sg_n_level: { metric: 'N-Level grade', goal: 'B3+ in English, Maths, 2+ others', focus: 'These grades unlock O-Level access the following year. Know your pathway minimum.' },
    };
    const tc = trackContext[track] || trackContext.sg_o_level;

    // ── Primary focus: what is the single most important thing right now ──────
    const topUrgent = urgent[0];
    const topSignal = signals[0];
    const primaryFocus = topUrgent || topSignal || null;

    // ── Generate the opening "secretary read" ─────────────────────────────────
    const greetingParts = [];
    if (urgent.length === 0 && signals.length === 0) {
      greetingParts.push(`Things are looking solid right now.`);
    } else if (urgent.length >= 2) {
      greetingParts.push(`There are ${urgent.length} things that need your attention today — most importantly: ${urgent[0].label.toLowerCase()}.`);
    } else if (urgent.length === 1) {
      greetingParts.push(`One thing stands out today that needs your focus: ${urgent[0].label.toLowerCase()}.`);
    } else {
      greetingParts.push(`No urgent issues, but ${signals.length > 1 ? `${signals.length} patterns worth adjusting` : 'one pattern worth adjusting'}.`);
    }
    if (positive.length > 0) greetingParts.push(`On the positive side: ${positive[0].toLowerCase()}.`);
    const openingSentence = greetingParts.join(' ');

    // ── Week summary ──────────────────────────────────────────────────────────
    const weekSummary = (() => {
      const parts = [];
      parts.push(`You're averaging ${studyHrsPerDay}h/day of study`);
      if (recentPages > 0) parts.push(`${recentPages} note${recentPages !== 1 ? 's' : ''} updated this week`);
      if (mockExamCount > 0 && avgMockScore !== null) parts.push(`mock average ${avgMockScore}%`);
      if (overdueTasks.length > 0) parts.push(`${overdueTasks.length} overdue task${overdueTasks.length !== 1 ? 's' : ''}`);
      if (daysToExam !== null) parts.push(`${daysToExam}d until ${nextExam?.title || 'next exam'}`);
      return parts.join(' · ');
    })();

    // ── Action list — concrete, ordered by impact ─────────────────────────────
    const actions = [];
    [...urgent, ...signals].forEach(s => {
      if (actions.length >= 5) return;
      const actionMap = {
        crisis_wellbeing: `Tonight: absolute hard stop at 10:30pm. No study after. Your recovery IS your exam prep.`,
        burnout: `This weekend: one full study-free day. No guilt. Schedule it now.`,
        sleep: `This week: protect 7.5h sleep as a non-negotiable. Cut late-night study first.`,
        stress: `Before each session: 4 rounds of box breathing (4s in, 4s hold, 4s out, 4s hold). 90 seconds, measurable impact.`,
        exam_imminent: `Today: one full timed past paper. Tonight: 30-min error review only. Tomorrow: repeat.`,
        exam_approaching: `Starting today: 80% of study time = past papers and active recall. 20% = filling gaps found by those papers.`,
        passive: `Next session: close all notes after reading one page. Write everything you remember on a blank sheet. Check. This is your new default.`,
        papers: `This week: schedule one timed past paper session. Treat it like the real exam — full timing, no notes, then error analysis.`,
        schedule: `This weekend: block 5 study slots for next week in your Axinote calendar. Just time + subject — no detailed planning needed.`,
        cca: `Audit your study methods: eliminate anything that isn't past papers, active recall, or spaced repetition. Time is your constraint.`,
        overload: `Right now: open your task board, pick 3 most important overdue items, mark the rest as deferred. Takes 5 minutes.`,
        mock_low: `Next practice session: after getting results, label each error Type 1 / 2 / 3. Then address each category separately.`,
      };
      const a = actionMap[s.key];
      if (a) actions.push({ priority: urgent.includes(s) ? 'critical' : 'high', label: s.label, action: a });
    });
    if (actions.length === 0) {
      actions.push({ priority: 'medium', label: 'Maintain momentum', action: 'Keep your current consistency. Consider adding one interleaved study session this week (mix 3 subjects in one block) to push deeper encoding.' });
    }

    // ── FlowAI context object — structured for AI consumption ────────────────
    flowAIContext = {
      _generated: new Date().toISOString(),
      _version: 2,
      user: {
        name: userName,
        track: trackLabel,
        syllabusTrack: track,
        age: profile?.age || null,
        tier: 'elite',
      },
      academic: {
        readinessScore: eInsights.readiness,
        predictedGrade: eInsights.grade,
        mockAverage: avgMockScore,
        mockCount: mockExamCount,
        subjectStrengths: eInsights.strengths,
        subjectWeaknesses: eInsights.weaknesses,
        subjectAverages: eInsights.subjectAverages,
        studyEfficiency,
        trackMetric: tc.metric,
        trackGoal: tc.goal,
      },
      upcomingExams: upcomingExams.slice(0, 5).map(e => ({ title: e.title, date: e.date, daysAway: Math.max(0, Math.round((new Date(e.date + 'T12:00:00') - Date.now()) / 86400000)) })),
      wellbeing: {
        stressLevel,
        stressLabel: ['', 'Low', 'Moderate', 'High', 'Very high'][stressLevel] || 'Moderate',
        sleepHours,
        burnoutRisk,
        burnoutLabel: ['', 'Rare', 'Sometimes', 'Often', 'Constant'][burnoutRisk] || 'Sometimes',
        isSleepDeprived,
        isHighStress,
        isBurntOut,
      },
      studyBehaviour: {
        weekdayHrs,
        weekendHrs,
        avgHrsPerDay: studyHrsPerDay,
        focusWindow,
        scheduleQuality,
        scheduleLabel: ['', 'Chaotic', 'Some structure', 'Structured', 'Highly structured'][scheduleQuality] || 'Some structure',
        revisionMethod,
        revisionLabel: ['', 'Passive (re-reading)', 'Mixed', 'Active recall', 'Exam drill'][revisionMethod] || 'Mixed',
        pastPaperFreq,
        pastPaperLabel: ['Never', 'Monthly', 'Weekly', 'Multiple/week'][pastPaperFreq] || 'Monthly',
        ccaLoad,
        ccaLabel: ['', 'Light', 'Medium', 'Heavy', 'Very heavy'][ccaLoad] || 'Medium',
      },
      tasks: {
        total: (S.tasks || []).length,
        completed: completedTasks.length,
        overdue: overdueTasks.length,
        dueSoon3d: dueSoon3.length,
        completionRate: Math.round(taskCompletionRate * 100),
      },
      notes: {
        totalPages,
        recentPages,
        flashcardDecks,
        probableTopics: eInsights.probableTopics,
      },
      urgentSignals: urgent.map(u => ({ key: u.key, label: u.label })),
      activeSignals: signals.map(s => ({ key: s.key, label: s.label })),
      positiveSignals: positive,
      support: {
        level: profile?.support || 3,
        label: ['', 'None', 'Limited', 'Moderate', 'Strong'][profile?.support || 3] || 'Moderate',
      },
      summaryForAI: `${trackLabel} student${userName ? ` (${userName})` : ''}. Readiness: ${eInsights.readiness}/100, predicted grade ${eInsights.grade}. Mock avg: ${avgMockScore !== null ? avgMockScore + '%' : 'none'}. Study: ${studyHrsPerDay}h/day, ${['', 'passive', 'mixed', 'active recall', 'exam drill'][revisionMethod] || 'mixed'} method. Stress: ${['', 'low', 'moderate', 'high', 'very high'][stressLevel] || 'moderate'}, sleep: ${sleepHours}h. ${daysToExam !== null ? `Next exam in ${daysToExam}d.` : ''} ${urgent.length > 0 ? 'Urgent: ' + urgent.map(u => u.label).join(', ') + '.' : ''} ${eInsights.weaknesses.length ? 'Weak subjects: ' + eInsights.weaknesses.map(w => w.subject + ' (' + w.avg + '%)').join(', ') + '.' : ''}`.trim(),
    };

    // Expose to FlowAI globally
    try { window.__flowAIContext = flowAIContext; } catch(_) {}

    eliteBrief = {
      openingSentence,
      weekSummary,
      urgent,
      signals,
      positive,
      actions,
      primaryFocus,
      studyEfficiency,
      studyHrsPerDay,
      trackLabel,
      trackContext: tc,
      eInsights,
      userName,
    };
  }

  return {
    tips,
    tier,
    tierLevel,
    profile,
    stressLevel,
    sleepHours,
    burnoutRisk,
    daysToExam,
    nextExam,
    avgMockScore,
    mockExamCount,
    weekdayHrs,
    weekendHrs,
    eliteBrief,
    flowAIContext,
  };
}

function addDays(isoDate, n) {
  const d = new Date(isoDate + 'T12:00:00');
  d.setDate(d.getDate() + n);
  return d.toISOString().slice(0, 10);
}

// ─── RENDER: Study Tips Panel (injected into dashboard) ───────────────────────

function renderStudyTipsPanel() {
  const insights = getPersonalizedStudyInsights();
  const { tips, tier, tierLevel, stressLevel, sleepHours, burnoutRisk, daysToExam, nextExam, eliteBrief } = insights;
  if (!tips.length && !eliteBrief) return '';

  const urgencyColor = {
    critical: 'var(--red)',
    high: 'var(--orange)',
    medium: 'var(--accent)',
    low: 'var(--text-muted)',
  };
  const urgencyBg = {
    critical: 'color-mix(in srgb, var(--red) 12%, transparent)',
    high: 'color-mix(in srgb, var(--orange) 12%, transparent)',
    medium: 'color-mix(in srgb, var(--accent) 10%, transparent)',
    low: 'color-mix(in srgb, var(--bg-sec) 80%, transparent)',
  };
  const urgencyLabel = {
    critical: 'URGENT',
    high: 'High priority',
    medium: 'Worth doing',
    low: 'Good habit',
  };
  const tierBadgeColor = {
    free: 'var(--text-muted)',
    lite: 'var(--blue)',
    pro: 'var(--green)',
    advanced: 'var(--purple)',
    elite: 'var(--accent)',
  };

  // ══════════════════════════════════════════════════════════════════
  // ELITE: Personal Secretary Brief — entirely different UX
  // ══════════════════════════════════════════════════════════════════
  if (tierLevel >= 4 && eliteBrief) {
    const b = eliteBrief;
    const ei = b.eInsights;
    const greeting = b.userName ? b.userName + ',' : "Here's your brief.";
    const today = new Date().toLocaleDateString('en-SG', { weekday: 'long', day: 'numeric', month: 'short' });

    // ── 4-number status bar ───────────────────────────────────────
    const rColor = ei.readiness >= 80 ? 'var(--green)' : ei.readiness >= 60 ? 'var(--orange)' : 'var(--red)';
    const sColor = sleepHours < 6.5 ? 'var(--red)' : sleepHours < 7 ? 'var(--orange)' : 'var(--green)';
    const stColor = stressLevel >= 4 ? 'var(--red)' : stressLevel >= 3 ? 'var(--orange)' : 'var(--green)';
    const stLabel = ['', 'Low', 'Moderate', 'High', 'Very high'][stressLevel] || 'Moderate';
    let slot4 = '';
    if (daysToExam !== null) {
      const dColor = daysToExam <= 4 ? 'var(--red)' : daysToExam <= 14 ? 'var(--orange)' : 'var(--text)';
      const dBg = daysToExam <= 4 ? 'color-mix(in srgb,var(--red) 10%,var(--bg-sec))' : 'var(--bg-sec)';
      const shortTitle = esc((nextExam && nextExam.title ? nextExam.title : 'Exam').split(' ').slice(0, 2).join(' '));
      slot4 = `<div style="flex:1;text-align:center;padding:10px 8px;background:${dBg};border-radius:14px">
        <div style="font-size:20px;font-weight:800;color:${dColor}">${daysToExam}d</div>
        <div style="font-size:10px;color:var(--text-muted);margin-top:2px;text-transform:uppercase;letter-spacing:.06em">Next exam</div>
        <div style="font-size:11px;color:var(--text-faint);margin-top:1px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${shortTitle}</div>
      </div>`;
    } else {
      const eColor = b.studyEfficiency >= 70 ? 'var(--green)' : b.studyEfficiency >= 45 ? 'var(--orange)' : 'var(--red)';
      slot4 = `<div style="flex:1;text-align:center;padding:10px 8px;background:var(--bg-sec);border-radius:14px">
        <div style="font-size:20px;font-weight:800;color:${eColor}">${b.studyEfficiency}%</div>
        <div style="font-size:10px;color:var(--text-muted);margin-top:2px;text-transform:uppercase;letter-spacing:.06em">Efficiency</div>
        <div style="font-size:11px;color:var(--text-faint);margin-top:1px">${b.studyHrsPerDay}h/day</div>
      </div>`;
    }
    const statusBar = `<div style="display:flex;gap:8px;margin-bottom:14px">
      <div style="flex:1;text-align:center;padding:10px 8px;background:var(--bg-sec);border-radius:14px">
        <div style="font-size:20px;font-weight:800;color:${rColor}">${ei.readiness}</div>
        <div style="font-size:10px;color:var(--text-muted);margin-top:2px;text-transform:uppercase;letter-spacing:.06em">Readiness</div>
        <div style="font-size:11px;color:var(--text-faint);margin-top:1px">${esc(ei.grade)}</div>
      </div>
      <div style="flex:1;text-align:center;padding:10px 8px;background:var(--bg-sec);border-radius:14px">
        <div style="font-size:20px;font-weight:800;color:${sColor}">${sleepHours}h</div>
        <div style="font-size:10px;color:var(--text-muted);margin-top:2px;text-transform:uppercase;letter-spacing:.06em">Sleep avg</div>
        <div style="font-size:11px;color:var(--text-faint);margin-top:1px">${sleepHours < 6.5 ? 'Below target' : sleepHours < 7 ? 'Borderline' : 'On track'}</div>
      </div>
      <div style="flex:1;text-align:center;padding:10px 8px;background:var(--bg-sec);border-radius:14px">
        <div style="font-size:20px;font-weight:800;color:${stColor}">${stressLevel}/4</div>
        <div style="font-size:10px;color:var(--text-muted);margin-top:2px;text-transform:uppercase;letter-spacing:.06em">Stress</div>
        <div style="font-size:11px;color:var(--text-faint);margin-top:1px">${stLabel}</div>
      </div>
      ${slot4}
    </div>`;

    // ── Opening situational read ──────────────────────────────────
    const openingSection = `<div style="margin-bottom:14px">
      <div style="font-size:13px;color:var(--text);line-height:1.65">${esc(b.openingSentence)}</div>
      <div style="font-size:11.5px;color:var(--text-faint);margin-top:5px">${esc(b.weekSummary)}</div>
    </div>`;

    // ── Urgent flags ──────────────────────────────────────────────
    const urgentSection = b.urgent.length > 0 ? `<div style="margin-bottom:12px">${b.urgent.map((u, i) =>
      `<div style="border-left:3px solid var(--red);background:color-mix(in srgb,var(--red) 8%,transparent);border-radius:0 12px 12px 0;padding:11px 14px;margin-bottom:7px;cursor:pointer" onclick="toggleStudyTipExpand('elite-urgent-${i}')">
        <div style="display:flex;align-items:center;justify-content:space-between;gap:8px">
          <div>
            <span style="font-size:10px;font-weight:800;text-transform:uppercase;letter-spacing:.08em;color:var(--red)">Needs attention</span>
            <div style="font-size:13.5px;font-weight:700;color:var(--text);margin-top:2px">${esc(u.label)}</div>
          </div>
          <span style="font-size:11px;color:var(--text-faint);flex-shrink:0" id="elite-urgent-arrow-${i}">▼</span>
        </div>
        <div id="elite-urgent-${i}" style="display:none;margin-top:8px">
          <div style="font-size:13px;color:var(--text);line-height:1.6">${esc(u.detail)}</div>
        </div>
      </div>`).join('')}</div>` : '';

    // ── Priority action list ──────────────────────────────────────
    const actionSection = `<div style="margin-bottom:14px">
      <div style="font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.08em;color:var(--text-muted);margin-bottom:8px">Priority actions</div>
      ${b.actions.map((a, i) => {
        const aColor = a.priority === 'critical' ? 'var(--red)' : a.priority === 'high' ? 'var(--orange)' : 'var(--accent)';
        const aBg = a.priority === 'critical' ? 'color-mix(in srgb,var(--red) 8%,transparent)' : a.priority === 'high' ? 'color-mix(in srgb,var(--orange) 8%,transparent)' : 'color-mix(in srgb,var(--accent) 6%,transparent)';
        const numBg = aColor;
        return `<div style="display:flex;align-items:flex-start;gap:10px;padding:11px 14px;background:${aBg};border-radius:12px;margin-bottom:7px">
          <div style="min-width:22px;height:22px;background:${numBg};border-radius:50%;display:flex;align-items:center;justify-content:center;flex-shrink:0;margin-top:1px">
            <span style="font-size:11px;font-weight:800;color:#fff">${i + 1}</span>
          </div>
          <div>
            <div style="font-size:11px;color:${aColor};font-weight:700;text-transform:uppercase;letter-spacing:.07em;margin-bottom:3px">${esc(a.label)}</div>
            <div style="font-size:13px;color:var(--text);line-height:1.55">${esc(a.action)}</div>
          </div>
        </div>`;
      }).join('')}
    </div>`;

    // ── Secondary signals (expandable) ────────────────────────────
    const signalSection = b.signals.length > 0 ? `<div style="margin-bottom:12px">
      <div style="font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.08em;color:var(--text-muted);margin-bottom:8px">Also worth knowing</div>
      ${b.signals.map((s, i) =>
        `<div style="border-left:2px solid var(--border-mid);padding:9px 12px;margin-bottom:6px;cursor:pointer;border-radius:0 10px 10px 0;background:var(--bg-sec)" onclick="toggleStudyTipExpand('elite-signal-${i}')">
          <div style="display:flex;align-items:center;justify-content:space-between">
            <span style="font-size:13px;font-weight:600;color:var(--text)">${esc(s.label)}</span>
            <span style="font-size:11px;color:var(--text-faint)" id="elite-signal-arrow-${i}">▼</span>
          </div>
          <div id="elite-signal-${i}" style="display:none;margin-top:7px;font-size:13px;color:var(--text-muted);line-height:1.6">${esc(s.detail)}</div>
        </div>`).join('')}
    </div>` : '';

    // ── Positive signals ─────────────────────────────────────────
    const positiveSection = b.positive.length > 0 ? `<div style="display:flex;flex-wrap:wrap;gap:6px;margin-bottom:12px">
      ${b.positive.map(p => `<span style="font-size:12px;padding:4px 10px;border-radius:20px;background:color-mix(in srgb,var(--green) 12%,transparent);color:var(--green);font-weight:600">+ ${esc(p)}</span>`).join('')}
    </div>` : '';

    // ── Track context ─────────────────────────────────────────────
    const trackStrip = `<div style="padding:10px 14px;background:var(--bg-sec);border-radius:14px;margin-bottom:12px;border-left:3px solid var(--accent)">
      <div style="font-size:11px;text-transform:uppercase;letter-spacing:.08em;color:var(--accent);font-weight:700;margin-bottom:4px">${esc(b.trackLabel)} track</div>
      <div style="font-size:12.5px;color:var(--text);line-height:1.5"><strong>Goal:</strong> ${esc(b.trackContext.goal)}</div>
      <div style="font-size:12px;color:var(--text-muted);margin-top:3px;line-height:1.5">${esc(b.trackContext.focus)}</div>
    </div>`;

    // ── Subject performance row ───────────────────────────────────
    const allSubs = ei.subjectAverages || [];
    const subjectRow = allSubs.length ? `<div style="margin-bottom:12px">
      <div style="font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.08em;color:var(--text-muted);margin-bottom:8px">Subject performance</div>
      <div style="display:flex;flex-wrap:wrap;gap:6px">
        ${allSubs.map(s => {
          const c = s.avg >= 75 ? 'var(--green)' : s.avg >= 60 ? 'var(--orange)' : 'var(--red)';
          const bg = s.avg >= 75 ? 'color-mix(in srgb,var(--green) 10%,transparent)' : s.avg >= 60 ? 'color-mix(in srgb,var(--orange) 10%,transparent)' : 'color-mix(in srgb,var(--red) 10%,transparent)';
          return `<div style="padding:5px 10px;border-radius:10px;background:${bg};font-size:12px"><span style="color:var(--text-muted)">${esc(s.subject)}</span><strong style="color:${c};margin-left:5px">${s.avg}%</strong></div>`;
        }).join('')}
      </div>
    </div>` : '';

    // ── FlowAI context badge ──────────────────────────────────────
    const flowAIBadge = `<div style="display:flex;align-items:center;justify-content:space-between;padding:8px 12px;border-radius:12px;background:color-mix(in srgb,var(--accent) 6%,transparent);border:1px solid color-mix(in srgb,var(--accent) 15%,transparent)">
      <div style="font-size:11.5px;color:var(--text-muted);line-height:1.4"><strong style="color:var(--accent)">FlowAI context active</strong> — your profile is shared automatically so FlowAI already understands your situation</div>
      <button class="btn btn-ghost btn-sm" style="flex-shrink:0;margin-left:10px;color:var(--accent);font-size:12px" onclick="navigate('aiChat')">Ask FlowAI →</button>
    </div>`;

    return `<div class="card" style="padding:18px 20px;margin-bottom:14px;border-radius:20px;border-color:color-mix(in srgb,var(--accent) 20%,var(--border-mid))">
      <div style="display:flex;align-items:flex-start;justify-content:space-between;margin-bottom:14px">
        <div>
          <div style="font-size:11px;color:var(--text-muted);font-weight:700;text-transform:uppercase;letter-spacing:.08em">Your Study Brief</div>
          <div style="font-size:15px;font-weight:700;color:var(--text);margin-top:3px">${esc(greeting)}</div>
          <div style="font-size:11.5px;color:var(--text-faint);margin-top:1px">${esc(today)} · ${esc(b.trackLabel)}</div>
        </div>
        <span style="font-size:11px;padding:3px 10px;border-radius:999px;background:var(--accent);color:#fff;font-weight:700;text-transform:uppercase;letter-spacing:.06em;flex-shrink:0">elite</span>
      </div>
      ${statusBar}
      ${openingSection}
      ${urgentSection}
      ${positiveSection}
      ${actionSection}
      ${signalSection}
      ${trackStrip}
      ${subjectRow}
      ${flowAIBadge}
    </div>`;
  }

  // ══════════════════════════════════════════════════════════════════
  // NON-ELITE: Standard tip cards (unchanged)
  // ══════════════════════════════════════════════════════════════════

  let wellbeingStrip = '';
  if (tierLevel >= 3 && insights.profile) {
    const stressSymbol = stressLevel <= 1 ? 'o' : stressLevel <= 2 ? '-' : stressLevel <= 3 ? '!' : '!!';
    const sleepSymbol = sleepHours >= 7.5 ? 'ok' : sleepHours >= 6.5 ? '~' : 'low';
    const burnoutSymbol = burnoutRisk <= 1 ? 'ok' : burnoutRisk <= 2 ? '~' : burnoutRisk <= 3 ? '!' : '!!';
    wellbeingStrip = `<div style="display:flex;gap:10px;flex-wrap:wrap;margin-bottom:12px">
      <div style="display:flex;align-items:center;gap:6px;padding:5px 12px;border-radius:20px;background:var(--bg-sec);font-size:12px">
        <span style="font-size:11px;font-weight:700">${stressSymbol}</span> <span style="color:var(--text-muted)">Stress:</span>
        <strong style="color:${stressLevel >= 3 ? 'var(--red)' : 'var(--text)'}">${['', 'Low', 'Moderate', 'High', 'Very high'][stressLevel] || 'Moderate'}</strong>
      </div>
      <div style="display:flex;align-items:center;gap:6px;padding:5px 12px;border-radius:20px;background:var(--bg-sec);font-size:12px">
        <span style="font-size:11px;font-weight:700">${sleepSymbol}</span> <span style="color:var(--text-muted)">Sleep:</span>
        <strong style="color:${sleepHours < 6.5 ? 'var(--red)' : sleepHours < 7 ? 'var(--orange)' : 'var(--green)'}">${sleepHours}h avg</strong>
      </div>
      <div style="display:flex;align-items:center;gap:6px;padding:5px 12px;border-radius:20px;background:var(--bg-sec);font-size:12px">
        <span style="font-size:11px;font-weight:700">${burnoutSymbol}</span> <span style="color:var(--text-muted)">Burnout:</span>
        <strong style="color:${burnoutRisk >= 3 ? 'var(--red)' : burnoutRisk >= 2 ? 'var(--orange)' : 'var(--green)'}">${['', 'Rare', 'Sometimes', 'Often', 'Constant'][burnoutRisk] || 'Sometimes'}</strong>
      </div>
      ${daysToExam !== null ? `<div style="display:flex;align-items:center;gap:6px;padding:5px 12px;border-radius:20px;background:${daysToExam <= 4 ? 'color-mix(in srgb,var(--red) 14%,transparent)' : 'var(--bg-sec)'};font-size:12px">
        <span style="font-size:11px">▦</span> <span style="color:var(--text-muted)">${esc(nextExam && nextExam.title ? nextExam.title : 'Next exam')}:</span>
        <strong style="color:${daysToExam <= 4 ? 'var(--red)' : daysToExam <= 14 ? 'var(--orange)' : 'var(--text)'}">${daysToExam}d</strong>
      </div>` : ''}
    </div>`;
  }

  const tipsHtml = tips.map((tip, i) => {
    const uc = tip.urgency || 'low';
    const borderCol = urgencyColor[uc];
    const bgCol = urgencyBg[uc];
    return `<div class="study-tip-card" style="border-left:3px solid ${borderCol};background:${bgCol};border-radius:0 16px 16px 0;padding:14px 16px;margin-bottom:10px;cursor:pointer;transition:opacity .15s" onclick="toggleStudyTipExpand('tip-expand-${i}')">
      <div style="display:flex;align-items:flex-start;gap:10px">
        <span style="font-size:18px;flex-shrink:0;margin-top:1px;font-weight:700;color:${borderCol}">${tip.icon}</span>
        <div style="flex:1;min-width:0">
          <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-bottom:4px">
            <span style="font-size:11px;text-transform:uppercase;letter-spacing:.08em;color:${borderCol};font-weight:700">${esc(tip.category)}</span>
            <span style="font-size:10px;padding:1px 7px;border-radius:999px;background:${borderCol};color:#fff;font-weight:700;opacity:.85">${esc(urgencyLabel[uc])}</span>
          </div>
          <div style="font-size:14px;font-weight:700;color:var(--text);line-height:1.35;margin-bottom:2px">${esc(tip.title)}</div>
          <div id="tip-expand-${i}" style="display:none;margin-top:8px">
            <div style="font-size:13px;color:var(--text);line-height:1.6;margin-bottom:8px">${esc(tip.body)}</div>
            <div style="padding:10px 12px;border-radius:12px;background:color-mix(in srgb,var(--accent) 8%,transparent);border:1px solid color-mix(in srgb,var(--accent) 20%,transparent);margin-bottom:8px">
              <div style="font-size:11px;color:var(--accent);font-weight:700;margin-bottom:3px">→ DO THIS</div>
              <div style="font-size:13px;color:var(--text);line-height:1.5">${esc(tip.action)}</div>
            </div>
            ${tip.science ? `<div style="font-size:11.5px;color:var(--text-faint);line-height:1.5;font-style:italic">§ ${esc(tip.science)}</div>` : ''}
          </div>
        </div>
        <span style="font-size:12px;color:var(--text-faint);flex-shrink:0;margin-top:3px" id="tip-arrow-${i}">▼</span>
      </div>
    </div>`;
  }).join('');

  const lockedCount = tierLevel === 0 ? '8 more' : tierLevel === 1 ? '7 more' : tierLevel === 2 ? '5 more' : tierLevel === 3 ? '3 more' : null;
  const upgradeHint = lockedCount && tierLevel < 4 ? `<div style="text-align:center;padding:12px 16px;border-radius:14px;background:var(--bg-sec);border:1px dashed var(--border-mid);margin-top:8px">
    <div style="font-size:13px;color:var(--text-muted)">${lockedCount} personalised insights unlocked with higher tiers</div>
    <button class="btn btn-ghost btn-sm" style="margin-top:6px;color:var(--accent)" onclick="window.open('/pricing.html','_blank')">View Plans →</button>
  </div>` : '';

  return `<div class="card" style="padding:18px 20px;margin-bottom:14px;border-radius:20px">
    <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:12px">
      <div>
        <div style="font-size:11px;color:var(--text-muted);font-weight:700;text-transform:uppercase;letter-spacing:.08em">Personalised Study Insights</div>
        <div style="font-size:12px;color:var(--text-faint);margin-top:2px">${tierLevel >= 3 ? tips.length + ' insights based on your profile' : tierLevel >= 2 ? tips.length + ' insights based on your activity' : tierLevel >= 1 ? tips.length + ' study insights for you' : tips.length + ' study tips to get you started'}</div>
      </div>
      <span style="font-size:11px;padding:3px 10px;border-radius:999px;background:${tierBadgeColor[tier] || 'var(--text-muted)'};color:#fff;font-weight:700;text-transform:uppercase;letter-spacing:.06em">${tier}</span>
    </div>
    ${wellbeingStrip}
    ${tipsHtml}
    ${upgradeHint}
  </div>`;
}

function toggleStudyTipExpand(id) {
  const el = document.getElementById(id);
  if (!el) return;
  // Derive the corresponding arrow element id
  let arrowId = id;
  if (id.startsWith('elite-urgent-')) arrowId = id.replace('elite-urgent-', 'elite-urgent-arrow-');
  else if (id.startsWith('elite-signal-')) arrowId = id.replace('elite-signal-', 'elite-signal-arrow-');
  else arrowId = 'tip-arrow-' + id.replace('tip-expand-', '');
  const arrow = document.getElementById(arrowId);
  const open = el.style.display === 'block';
  el.style.display = open ? 'none' : 'block';
  if (arrow) arrow.textContent = open ? '▼' : '▲';
}

// ─── END STUDY INSIGHTS ENGINE ────────────────────────────────────────────────

function renderChangelog(c) {
  c.innerHTML = `
    <div style="max-width:680px;margin:0 auto">
      <h1 style="font-size:32px;font-weight:800;font-family:var(--font-head);margin-bottom:6px">What's New</h1>
      <p style="color:var(--text-muted);font-size:13px;margin-bottom:32px">All the latest updates to Axinote</p>
      ${CHANGELOG.map((entry, i) => `
        <div style="margin-bottom:32px;${i === 0 ? '' : 'opacity:.8'}">
          <div style="display:flex;align-items:center;gap:12px;margin-bottom:12px">
            <span style="background:var(--accent);color:white;font-size:12px;font-weight:700;padding:3px 10px;border-radius:999px">v${entry.version}</span>
            <span style="color:var(--text-muted);font-size:13px">${entry.date}</span>
            ${i === 0 ? '<span style="background:var(--green-bg);color:var(--green);font-size:11px;font-weight:700;padding:2px 8px;border-radius:999px">Latest</span>' : ''}
          </div>
          <div style="border-left:3px solid var(--border-mid);padding-left:16px">
            ${entry.changes.map(ch => `<div style="font-size:14px;line-height:1.7;margin-bottom:4px;color:var(--text)">${ch.replace(/^[\u{1F300}-\u{1F9FF}\u{2600}-\u{27BF}]\s*/u, '<span style="color:var(--accent);margin-right:6px">›</span>')}</div>`).join('')}
          </div>
        </div>`).join('')}
    </div>`;
}

// ─── FEEDBACK ─────────────────────────────────────────────────
function openFeedback() {
  const existing = document.getElementById('feedback-modal');
  if (existing) { existing.remove(); return; }
  const modal = document.createElement('div');
  modal.id = 'feedback-modal';
  modal.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,.6);z-index:99999;display:flex;align-items:center;justify-content:center;padding:20px;backdrop-filter:blur(6px)';
  modal.innerHTML = `
    <div style="background:var(--bg-card);border:1px solid var(--border-mid);border-radius:18px;padding:28px;max-width:480px;width:100%;box-shadow:0 24px 80px rgba(0,0,0,.4)">
      <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:16px">
        <h2 style="font-size:20px;font-weight:800;display:flex;align-items:center;gap:8px"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/></svg> Send Feedback</h2>
        <button class="icon-btn" onclick="document.getElementById('feedback-modal')?.remove()">${icons.close}</button>
      </div>
      <p style="color:var(--text-muted);font-size:13px;margin-bottom:16px">We read every piece of feedback. Tell us what you think, report a bug, or suggest a feature.</p>
      <div class="form-group" style="margin-bottom:12px">
        <label class="form-label">Type</label>
        <select id="fb-type" class="form-input" style="margin-top:4px">
          <option>Feature request</option>
          <option>Bug report</option>
          <option>General feedback</option>
          <option>Question</option>
        </select>
      </div>
      <div class="form-group" style="margin-bottom:16px">
        <label class="form-label">Message</label>
        <textarea id="fb-msg" class="form-input" style="margin-top:4px;height:120px;resize:vertical" placeholder="Describe your feedback in detail…"></textarea>
      </div>
      <div style="display:flex;gap:8px;justify-content:flex-end">
        <button class="btn btn-ghost" onclick="document.getElementById('feedback-modal')?.remove()">Cancel</button>
        <button class="btn btn-action" onclick="submitFeedback()">Send Feedback</button>
      </div>
    </div>`;
  modal.addEventListener('click', e => { if (e.target === modal) modal.remove(); });
  document.body.appendChild(modal);
  document.getElementById('fb-msg')?.focus();
}

async function submitFeedback() {
  const type = document.getElementById('fb-type')?.value || 'General';
  const msg = document.getElementById('fb-msg')?.value.trim();
  if (!msg) return toast('Please write your feedback first');
  const feedback = {
    id: uid(), type, message: msg, from: S.user?.uid, email: S.user?.email,
    name: getDisplayName(), createdAt: new Date().toISOString(), page: S.view
  };
  try {
    await window.fb.set(window.fb.ref(window.fb.database, `feedback/${feedback.id}`), feedback);
    document.getElementById('feedback-modal')?.remove();
    toast('Thank you! Feedback sent.');
  } catch (e) {
    toast('Error sending feedback: ' + e.message);
  }
}

// ─── Create collab note directly from study group ─────────────
async function createCollabNoteForGroup(groupId, groupName) {
  const title = prompt('Note title:', groupName + ' Notes');
  if (!title) return;
  const id = uid();
  const note = {
    id, title, content: '', groupId,
    createdBy: S.user.uid, createdByName: getDisplayName(),
    createdAt: new Date().toISOString(), updatedAt: new Date().toISOString(),
  };
  try {
    await window.fb.set(window.fb.ref(window.fb.database, 'collab/' + id), note);
    await window.fb.update(window.fb.ref(window.fb.database, `users/${S.user.uid}/collabNotes`), { [id]: true });
    await window.fb.set(window.fb.ref(window.fb.database, `studyGroups/${groupId}/noteIndex/${id}`), S.user.uid).catch(() => {});
    toast('Note created!');
    openCollabNote(id);
  } catch (e) { toast('Error: ' + e.message); }
}
