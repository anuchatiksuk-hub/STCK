/**
 * Smart School V4.0 — Auth Module
 * Google OAuth + Role-based Access (Admin / Teacher)
 * เพิ่มลงใน index.html โดย <script src="auth.js"></script>
 *
 * วิธีใช้:
 *   1. เพิ่ม <script src="https://accounts.google.com/gsi/client" async></script> ใน <head>
 *   2. เพิ่ม <script src="auth.js"></script> ก่อน </body>
 *   3. เรียก SmartAuth.init({ apiUrl, clientId, onLogin, onLogout })
 *   4. เรียก SmartAuth.requireRole('admin') หรือ SmartAuth.requireRole('teacher')
 *
 * Roles:
 *   admin   — เห็นทุกห้อง, เข้า Admin panel ได้, จัดการ whitelist ได้
 *   teacher — เห็นเฉพาะห้องที่ได้รับมอบหมาย, ไม่เข้า Admin panel
 */

const SmartAuth = (() => {
  // ─── STATE ───────────────────────────────────────────────────────────────
  let _state = {
    user: null,       // { name, email, picture, role, classes[] }
    apiUrl: '',
    clientId: '',
    onLogin: null,
    onLogout: null,
    initialized: false,
  };

  const STORAGE_KEY = 'ss_auth_v4';
  const TOKEN_EXPIRY = 8 * 60 * 60 * 1000; // 8 hours in ms

  // ─── PUBLIC API ──────────────────────────────────────────────────────────

  /**
   * เริ่มต้นระบบ Auth
   * @param {Object} config
   * @param {string} config.apiUrl   - GAS /exec URL
   * @param {string} config.clientId - Google OAuth Client ID
   * @param {Function} config.onLogin   - callback เมื่อ login สำเร็จ (user) => {}
   * @param {Function} config.onLogout  - callback เมื่อ logout
   */
  function init(config) {
    _state.apiUrl    = config.apiUrl    || localStorage.getItem('gasApiUrl') || '';
    _state.clientId  = config.clientId  || '';
    _state.onLogin   = config.onLogin   || (() => {});
    _state.onLogout  = config.onLogout  || (() => {});
    _state.initialized = true;

    // ตรวจสอบ session ที่บันทึกไว้
    const saved = _loadSession();
    if (saved) {
      _state.user = saved;
      _mountUserBadge();
      config.onLogin(saved);
      return;
    }

    // แสดงหน้า Login
    _renderLoginScreen();
  }

  /** ดึงข้อมูล user ปัจจุบัน */
  function getUser() { return _state.user; }

  /** ตรวจสอบ role — return true/false */
  function hasRole(role) {
    if (!_state.user) return false;
    if (_state.user.role === 'admin') return true; // admin ผ่านทุก role
    return _state.user.role === role;
  }

  /**
   * บังคับ role — ถ้าไม่ผ่านจะ redirect หรือซ่อน element
   * @param {string} role - 'admin' | 'teacher'
   * @param {string} [redirectTo] - URL ที่จะ redirect ถ้าไม่มีสิทธิ์ (optional)
   */
  function requireRole(role, redirectTo) {
    if (!hasRole(role)) {
      if (redirectTo) {
        window.location.href = redirectTo;
      } else {
        _showAccessDenied(role);
      }
      return false;
    }
    return true;
  }

  /** ดึงรายการห้องที่ user มีสิทธิ์เข้าถึง */
  function getAllowedClasses() {
    if (!_state.user) return [];
    if (_state.user.role === 'admin') return null; // null = ทุกห้อง
    return _state.user.classes || [];
  }

  /** ตรวจสอบว่า user มีสิทธิ์เข้าถึงห้องนี้ไหม */
  function canAccessClass(className) {
    if (!_state.user) return false;
    if (_state.user.role === 'admin') return true;
    const allowed = _state.user.classes || [];
    return allowed.length === 0 || allowed.includes(className);
  }

  /** Logout */
  function signOut() {
    _clearSession();
    _state.user = null;
    if (typeof google !== 'undefined') {
      try { google.accounts.id.disableAutoSelect(); } catch(e) {}
    }
    if (_state.onLogout) _state.onLogout();
    _renderLoginScreen();
  }

  /** อัปเดต API URL (เรียกตอนผู้ใช้กรอกใหม่) */
  function setApiUrl(url) {
    _state.apiUrl = url;
    localStorage.setItem('gasApiUrl', url);
  }

  // ─── LOGIN SCREEN ─────────────────────────────────────────────────────────

  function _renderLoginScreen() {
    // ลบ screen เก่าถ้ามี
    const old = document.getElementById('ss-login-screen');
    if (old) old.remove();

    const screen = document.createElement('div');
    screen.id = 'ss-login-screen';
    screen.innerHTML = _loginScreenHTML();
    document.body.appendChild(screen);

    // Pre-fill API URL
    const apiInput = document.getElementById('ss-api-input');
    if (apiInput && _state.apiUrl) apiInput.value = _state.apiUrl;

    // Init Google Sign-In button
    _initGoogleButton();

    // Demo login button
    const demoBtn = document.getElementById('ss-demo-btn');
    if (demoBtn) demoBtn.onclick = _handleDemoLogin;

    // Watch API URL input
    if (apiInput) {
      apiInput.addEventListener('input', e => {
        const val = e.target.value.trim();
        if (val.includes('script.google.com')) setApiUrl(val);
      });
    }
  }

  function _loginScreenHTML() {
    return `
    <style>
      #ss-login-screen {
        position: fixed; inset: 0; z-index: 99999;
        background: linear-gradient(135deg, #0a2540 0%, #0d3b6e 45%, #1a1a2e 100%);
        display: flex; align-items: center; justify-content: center;
        font-family: 'Noto Sans Thai', 'Sarabun', sans-serif;
        padding: 20px;
      }
      #ss-login-screen::before {
        content: '';
        position: absolute; inset: 0;
        background:
          radial-gradient(ellipse at 20% 50%, rgba(26,115,232,.15) 0%, transparent 50%),
          radial-gradient(ellipse at 80% 20%, rgba(79,163,224,.1) 0%, transparent 40%);
        pointer-events: none;
      }
      .ss-login-card {
        background: rgba(255,255,255,.97);
        border-radius: 24px;
        padding: 44px 40px 36px;
        width: 100%; max-width: 420px;
        box-shadow: 0 32px 80px rgba(0,0,0,.35), 0 0 0 1px rgba(255,255,255,.1);
        position: relative; z-index: 1;
        animation: ss-card-in .4s cubic-bezier(.34,1.56,.64,1);
      }
      @keyframes ss-card-in {
        from { opacity:0; transform: scale(.9) translateY(20px); }
        to   { opacity:1; transform: none; }
      }
      .ss-logo-wrap {
        width: 68px; height: 68px;
        background: linear-gradient(135deg, #1a73e8, #4fa3e0);
        border-radius: 20px;
        display: flex; align-items: center; justify-content: center;
        margin: 0 auto 22px;
        box-shadow: 0 8px 24px rgba(26,115,232,.4);
        font-size: 32px;
      }
      .ss-login-card h2 {
        text-align: center;
        font-size: 1.55rem; font-weight: 900;
        color: #0f172a; letter-spacing: -.03em;
        margin-bottom: 5px;
      }
      .ss-login-card .ss-sub {
        text-align: center; font-size: .85rem;
        color: #64748b; margin-bottom: 30px; line-height: 1.5;
      }
      .ss-google-btn {
        width: 100%; padding: 13px 20px;
        border: 1.5px solid #e2e8f0; border-radius: 12px;
        background: #fff; cursor: pointer;
        display: flex; align-items: center; justify-content: center; gap: 12px;
        font-size: .9rem; font-weight: 600; color: #0f172a;
        font-family: inherit; transition: all .2s;
        box-shadow: 0 1px 3px rgba(0,0,0,.06);
      }
      .ss-google-btn:hover {
        background: #f8faff; border-color: #1a73e8;
        box-shadow: 0 4px 12px rgba(26,115,232,.15);
        transform: translateY(-1px);
      }
      .ss-google-btn img { width: 20px; height: 20px; }
      .ss-divider {
        display: flex; align-items: center; gap: 12px;
        margin: 18px 0; color: #94a3b8; font-size: .78rem;
      }
      .ss-divider::before, .ss-divider::after {
        content:''; flex:1; height:1px; background:#e2e8f0;
      }
      .ss-demo-btn {
        width: 100%; padding: 11px 20px;
        border: 1.5px solid #e2e8f0; border-radius: 12px;
        background: transparent; cursor: pointer;
        font-size: .88rem; font-weight: 600; color: #475569;
        font-family: inherit; transition: all .2s;
        display: flex; align-items: center; justify-content: center; gap: 8px;
      }
      .ss-demo-btn:hover { background: #f1f5f9; color: #0f172a; }
      .ss-api-section {
        margin-top: 22px;
        padding: 16px;
        background: #f8faff;
        border-radius: 12px;
        border: 1.5px solid #e2e8f0;
      }
      .ss-api-section label {
        display: block; font-size: .74rem; font-weight: 700;
        color: #475569; margin-bottom: 6px; letter-spacing: .04em;
      }
      .ss-api-section input {
        width: 100%; padding: 8px 11px;
        border: 1.5px solid #e2e8f0; border-radius: 8px;
        font-size: .78rem; font-family: monospace; outline: none;
        background: #fff; color: #0f172a; transition: border-color .15s;
      }
      .ss-api-section input:focus { border-color: #1a73e8; }
      .ss-api-section small {
        display: block; margin-top: 5px;
        font-size: .7rem; color: #94a3b8; line-height: 1.4;
      }
      .ss-error-box {
        background: #fef2f2; border: 1px solid #fca5a5;
        border-radius: 10px; padding: 12px 16px;
        font-size: .82rem; color: #991b1b; margin-top: 14px;
        display: none; line-height: 1.5;
      }
      .ss-loading-overlay {
        position: absolute; inset: 0; background: rgba(255,255,255,.92);
        border-radius: 24px; display: none;
        align-items: center; justify-content: center; flex-direction: column;
        gap: 12px; z-index: 10;
      }
      .ss-loading-overlay.show { display: flex; }
      .ss-spinner {
        width: 40px; height: 40px;
        border: 3px solid #e2e8f0; border-top-color: #1a73e8;
        border-radius: 50%; animation: ss-spin .7s linear infinite;
      }
      @keyframes ss-spin { to { transform: rotate(360deg); } }
      .ss-loading-overlay p { font-size: .85rem; font-weight: 600; color: #475569; }
      .ss-footer-note {
        text-align: center; margin-top: 18px;
        font-size: .72rem; color: #94a3b8; line-height: 1.5;
      }
      .ss-footer-note a { color: #1a73e8; text-decoration: none; }
    </style>

    <div class="ss-login-card">
      <div class="ss-loading-overlay" id="ss-loading">
        <div class="ss-spinner"></div>
        <p id="ss-loading-text">กำลังตรวจสอบสิทธิ์...</p>
      </div>

      <div class="ss-logo-wrap">🏫</div>
      <h2>Smart School</h2>
      <p class="ss-sub">ระบบจัดการโรงเรียน V4.0<br>เข้าสู่ระบบด้วยบัญชีโรงเรียน</p>

      <button class="ss-google-btn" id="ss-google-btn">
        <img src="https://www.gstatic.com/firebasejs/ui/2.0.0/images/auth/google.svg" alt="G">
        เข้าสู่ระบบด้วย Google
      </button>

      <div class="ss-error-box" id="ss-error"></div>

      <div class="ss-divider">หรือ</div>

      <button class="ss-demo-btn" id="ss-demo-btn">
        ▶ ทดลองใช้ Demo (ไม่ต้องล็อกอิน)
      </button>

      <div class="ss-api-section">
        <label>🔗 Google Apps Script URL</label>
        <input id="ss-api-input" type="text" placeholder="https://script.google.com/macros/s/.../exec">
        <small>วาง URL จาก GAS Deploy ก่อนกด Login<br>ตั้งค่าครั้งเดียว — จะจำไว้ในเบราว์เซอร์</small>
      </div>

      <p class="ss-footer-note">
        🔒 ข้อมูลของคุณปลอดภัย ไม่มีการแชร์กับบุคคลอื่น<br>
        มีปัญหา? ติดต่อ <a href="mailto:admin@school.th">admin@school.th</a>
      </p>
    </div>`;
  }

  // ─── GOOGLE SIGN-IN ───────────────────────────────────────────────────────

  function _initGoogleButton() {
    if (!_state.clientId) {
      // ไม่มี Client ID — ปุ่ม Google ยังแสดงแต่แจ้งให้ตั้งค่า
      const btn = document.getElementById('ss-google-btn');
      if (btn) {
        btn.onclick = () => {
          _showError('ยังไม่ได้ตั้งค่า Google Client ID<br>กรุณาใส่ Client ID ใน SmartAuth.init({ clientId: "..." })<br>หรือใช้ Demo mode แทน');
        };
      }
      return;
    }

    const tryInit = () => {
      if (typeof google === 'undefined' || !google.accounts) {
        setTimeout(tryInit, 300);
        return;
      }
      google.accounts.id.initialize({
        client_id: _state.clientId,
        callback: _handleGoogleCallback,
        auto_select: false,
        cancel_on_tap_outside: true,
      });
      const btn = document.getElementById('ss-google-btn');
      if (btn) btn.onclick = _triggerGoogleSignIn;
    };
    tryInit();
  }

  function _triggerGoogleSignIn() {
    if (typeof google === 'undefined') {
      _showError('Google SDK ยังโหลดไม่เสร็จ กรุณารอสักครู่แล้วลองใหม่');
      return;
    }
    google.accounts.id.prompt(notification => {
      if (notification.isNotDisplayed()) {
        // Prompt ไม่แสดง — อาจถูก block, ให้ใช้ renderButton แทน
        _renderGoogleFallbackButton();
      }
    });
  }

  function _renderGoogleFallbackButton() {
    const wrap = document.getElementById('ss-google-btn');
    if (!wrap) return;
    const div = document.createElement('div');
    div.id = 'ss-google-render-wrap';
    wrap.parentNode.insertBefore(div, wrap);
    wrap.style.display = 'none';
    google.accounts.id.renderButton(div, {
      theme: 'outline', size: 'large', width: 340,
      text: 'signin_with', locale: 'th',
    });
  }

  async function _handleGoogleCallback(response) {
    _showLoading('กำลังตรวจสอบสิทธิ์...');
    try {
      const payload = _decodeJWT(response.credential);
      if (!payload) throw new Error('Invalid token');

      const email = payload.email;
      const apiInput = document.getElementById('ss-api-input');
      if (apiInput?.value.trim()) setApiUrl(apiInput.value.trim());

      // ตรวจสอบกับ GAS backend
      const result = await _verifyWithBackend(email, payload.name);

      if (!result.allowed) {
        _hideLoading();
        _showAccessDeniedCard(email);
        return;
      }

      const user = {
        name: payload.name,
        email: payload.email,
        picture: payload.picture,
        role: result.role,           // 'admin' | 'teacher'
        classes: result.classes || [], // ห้องที่ teacher รับผิดชอบ
        loginAt: Date.now(),
      };

      _saveSession(user);
      _state.user = user;
      _hideLoading();
      _removeLoginScreen();
      _mountUserBadge();
      if (_state.onLogin) _state.onLogin(user);

    } catch(e) {
      _hideLoading();
      _showError('เกิดข้อผิดพลาด กรุณาลองใหม่อีกครั้ง<br><small>' + e.message + '</small>');
    }
  }

  async function _handleDemoLogin() {
    const apiInput = document.getElementById('ss-api-input');
    if (apiInput?.value.trim()) setApiUrl(apiInput.value.trim());

    _showLoading('กำลังเข้าระบบ Demo...');
    await new Promise(r => setTimeout(r, 800));

    const user = {
      name: 'ครู Demo',
      email: 'demo@school.th',
      picture: null,
      role: 'admin',       // Demo ได้สิทธิ์ admin
      classes: [],
      loginAt: Date.now(),
      isDemo: true,
    };
    _saveSession(user);
    _state.user = user;
    _hideLoading();
    _removeLoginScreen();
    _mountUserBadge();
    if (_state.onLogin) _state.onLogin(user);
  }

  // ─── BACKEND VERIFY ───────────────────────────────────────────────────────

  async function _verifyWithBackend(email, name) {
    if (!_state.apiUrl) {
      // ไม่มี API URL — fallback เป็น demo
      console.warn('[SmartAuth] No API URL set, using fallback');
      return { allowed: true, role: 'teacher', classes: [] };
    }
    const res = await fetch(_state.apiUrl, {
      method: 'POST',
      body: JSON.stringify({ action: 'verifyUser', email, name }),
      headers: { 'Content-Type': 'text/plain' },
    });
    return res.json();
  }

  // ─── USER BADGE (แสดงข้อมูล user ใน topbar) ──────────────────────────────

  function _mountUserBadge() {
    if (!_state.user) return;
    // หา placeholder ใน sidebar (ถ้ามี)
    const target = document.getElementById('ss-user-badge-slot');
    if (!target) return;

    const u = _state.user;
    const roleLabel = { admin: 'ผู้ดูแลระบบ', teacher: 'ครูประจำชั้น' }[u.role] || u.role;
    const roleColor = { admin: '#dc2626', teacher: '#1d4ed8' }[u.role] || '#475569';
    const roleTag = `<span style="display:inline-block;background:${roleColor}20;color:${roleColor};font-size:.65rem;font-weight:800;padding:2px 8px;border-radius:12px;letter-spacing:.02em">${roleLabel}</span>`;

    const avatarHTML = u.picture
      ? `<img src="${u.picture}" alt="" style="width:34px;height:34px;border-radius:50%;object-fit:cover;flex-shrink:0">`
      : `<div style="width:34px;height:34px;border-radius:50%;background:linear-gradient(135deg,#1a73e8,#4fa3e0);display:flex;align-items:center;justify-content:center;font-size:.85rem;font-weight:700;color:#fff;flex-shrink:0">${u.name.charAt(0)}</div>`;

    target.innerHTML = `
      <style>
        #ss-user-badge-slot { cursor: pointer; }
        #ss-user-badge-slot:hover { background: rgba(255,255,255,.07) !important; }
      </style>
      <div onclick="SmartAuth._openUserMenu()" style="display:flex;align-items:center;gap:10px;padding:10px 12px;background:rgba(255,255,255,.05);border-radius:10px;transition:background .2s">
        ${avatarHTML}
        <div style="flex:1;min-width:0">
          <div style="color:#fff;font-size:.82rem;font-weight:600;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">${u.name}</div>
          <div style="margin-top:2px">${roleTag}</div>
        </div>
        <span style="color:rgba(255,255,255,.3);font-size:14px">▾</span>
      </div>`;
  }

  function _openUserMenu() {
    // สร้าง User Menu popup
    const existing = document.getElementById('ss-user-menu');
    if (existing) { existing.remove(); return; }

    const u = _state.user;
    const roleLabel = { admin: 'ผู้ดูแลระบบ', teacher: 'ครูประจำชั้น' }[u.role] || u.role;
    const classesTxt = u.classes?.length
      ? `ห้องที่รับผิดชอบ: ${u.classes.join(', ')}`
      : u.role === 'admin' ? 'เข้าถึงได้ทุกห้อง' : 'ยังไม่ได้กำหนดห้อง';

    const menu = document.createElement('div');
    menu.id = 'ss-user-menu';
    menu.innerHTML = `
      <div style="position:fixed;inset:0;z-index:9998" onclick="document.getElementById('ss-user-menu').remove()"></div>
      <div style="position:fixed;top:70px;left:16px;width:240px;background:#fff;border-radius:14px;box-shadow:0 12px 40px rgba(0,0,0,.18);border:1px solid #e2e8f0;z-index:9999;overflow:hidden;animation:ss-menu-in .15s ease;font-family:'Noto Sans Thai','Sarabun',sans-serif">
        <style>@keyframes ss-menu-in{from{opacity:0;transform:translateY(-6px)}to{opacity:1;transform:none}}</style>
        <div style="padding:16px 16px 12px;border-bottom:1px solid #f1f5f9">
          <div style="font-size:.9rem;font-weight:800;color:#0f172a">${u.name}</div>
          <div style="font-size:.75rem;color:#64748b;margin-top:1px">${u.email}</div>
          <div style="margin-top:8px;display:flex;gap:6px;flex-wrap:wrap">
            <span style="background:${u.role==='admin'?'#fee2e2':'#dbeafe'};color:${u.role==='admin'?'#991b1b':'#1e40af'};font-size:.7rem;font-weight:800;padding:2px 8px;border-radius:10px">${roleLabel}</span>
            ${u.isDemo ? '<span style="background:#fef9c3;color:#854d0e;font-size:.7rem;font-weight:800;padding:2px 8px;border-radius:10px">Demo</span>' : ''}
          </div>
          <div style="font-size:.74rem;color:#94a3b8;margin-top:6px">${classesTxt}</div>
        </div>
        <div style="padding:6px">
          <button onclick="SmartAuth._openProfileModal()" style="width:100%;padding:8px 12px;border:none;background:none;cursor:pointer;display:flex;align-items:center;gap:10px;border-radius:8px;font-size:.85rem;color:#0f172a;font-family:inherit;text-align:left;transition:background .15s" onmouseover="this.style.background='#f8faff'" onmouseout="this.style.background='none'">
            👤 โปรไฟล์
          </button>
          ${u.role === 'admin' ? `
          <button onclick="SmartAuth.openUserManager();document.getElementById('ss-user-menu').remove()" style="width:100%;padding:8px 12px;border:none;background:none;cursor:pointer;display:flex;align-items:center;gap:10px;border-radius:8px;font-size:.85rem;color:#0f172a;font-family:inherit;text-align:left;transition:background .15s" onmouseover="this.style.background='#f8faff'" onmouseout="this.style.background='none'">
            🛡️ จัดการผู้ใช้
          </button>` : ''}
          <hr style="border:none;border-top:1px solid #f1f5f9;margin:4px 0">
          <button onclick="SmartAuth.signOut()" style="width:100%;padding:8px 12px;border:none;background:none;cursor:pointer;display:flex;align-items:center;gap:10px;border-radius:8px;font-size:.85rem;color:#dc2626;font-family:inherit;text-align:left;transition:background .15s" onmouseover="this.style.background='#fef2f2'" onmouseout="this.style.background='none'">
            🚪 ออกจากระบบ
          </button>
        </div>
      </div>`;
    document.body.appendChild(menu);
  }

  function _openProfileModal() {
    document.getElementById('ss-user-menu')?.remove();
    const u = _state.user;
    _showModal('โปรไฟล์', `
      <div style="text-align:center;padding:10px 0 20px">
        ${u.picture
          ? `<img src="${u.picture}" style="width:70px;height:70px;border-radius:50%;margin-bottom:14px">`
          : `<div style="width:70px;height:70px;border-radius:50%;background:linear-gradient(135deg,#1a73e8,#4fa3e0);display:flex;align-items:center;justify-content:center;font-size:1.8rem;color:#fff;margin:0 auto 14px">${u.name.charAt(0)}</div>`}
        <div style="font-size:1.15rem;font-weight:800">${u.name}</div>
        <div style="color:#64748b;font-size:.85rem;margin-top:2px">${u.email}</div>
        <div style="margin-top:10px"><span style="background:${u.role==='admin'?'#fee2e2':'#dbeafe'};color:${u.role==='admin'?'#991b1b':'#1e40af'};font-size:.8rem;font-weight:800;padding:4px 12px;border-radius:12px">${{admin:'ผู้ดูแลระบบ',teacher:'ครูประจำชั้น'}[u.role]||u.role}</span></div>
      </div>
      <div style="background:#f8faff;border-radius:10px;padding:14px;font-size:.84rem">
        <div style="margin-bottom:8px;color:#475569"><strong>ห้องเรียน:</strong> ${u.classes?.length ? u.classes.join(', ') : u.role==='admin'?'ทุกห้อง':'ยังไม่กำหนด'}</div>
        <div style="color:#475569"><strong>เข้าสู่ระบบ:</strong> ${new Date(u.loginAt).toLocaleString('th-TH')}</div>
      </div>
    `);
  }

  // ─── USER MANAGER (Admin เท่านั้น) ───────────────────────────────────────

  /**
   * เปิด Modal จัดการ whitelist ผู้ใช้
   * Admin สามารถเพิ่ม/ลบ email และกำหนด role + ห้อง ได้
   */
  async function openUserManager() {
    if (!hasRole('admin')) {
      _showModal('ข้อผิดพลาด', '<p style="color:#dc2626">ต้องการสิทธิ์ Admin</p>');
      return;
    }

    _showModal('🛡️ จัดการผู้ใช้งาน', `
      <div id="ss-um-loading" style="text-align:center;padding:30px"><div class="ss-spinner" style="margin:0 auto 10px;width:36px;height:36px;border:3px solid #e2e8f0;border-top-color:#1a73e8;border-radius:50%;animation:ss-spin .7s linear infinite"></div><p style="color:#64748b;font-size:.85rem">กำลังโหลด...</p></div>
      <div id="ss-um-content" style="display:none">
        <div style="display:flex;gap:8px;margin-bottom:14px;flex-wrap:wrap">
          <input id="ss-um-email" placeholder="อีเมล เช่น teacher@school.th" style="flex:1;padding:9px 12px;border:1.5px solid #e2e8f0;border-radius:8px;font-size:.85rem;outline:none;font-family:inherit">
          <select id="ss-um-role" style="padding:9px 12px;border:1.5px solid #e2e8f0;border-radius:8px;font-size:.85rem;outline:none;background:#fff;font-family:inherit">
            <option value="teacher">ครูประจำชั้น</option>
            <option value="admin">ผู้ดูแลระบบ</option>
          </select>
        </div>
        <div style="margin-bottom:14px">
          <label style="display:block;font-size:.75rem;font-weight:700;color:#475569;margin-bottom:5px">ห้องที่รับผิดชอบ (คั่นด้วยเครื่องหมาย , เช่น ป.1/1, ป.1/2)</label>
          <input id="ss-um-classes" placeholder="ป.1/1, ป.1/2  (ว่างไว้ = ทุกห้อง)" style="padding:9px 12px;border:1.5px solid #e2e8f0;border-radius:8px;font-size:.85rem;outline:none;width:100%;font-family:inherit">
        </div>
        <button onclick="SmartAuth._addUser()" style="padding:9px 16px;background:#1a73e8;color:#fff;border:none;border-radius:8px;font-family:inherit;font-size:.85rem;font-weight:700;cursor:pointer;margin-bottom:16px">+ เพิ่มผู้ใช้</button>
        <div id="ss-um-list"></div>
      </div>
    `);

    try {
      const result = await _callApi('getUserList', {});
      document.getElementById('ss-um-loading').style.display = 'none';
      document.getElementById('ss-um-content').style.display = 'block';
      _renderUserList(result.users || []);
    } catch(e) {
      document.getElementById('ss-um-loading').innerHTML =
        '<p style="color:#dc2626">โหลดข้อมูลไม่ได้ ตรวจสอบ API URL</p>';
    }
  }

  function _renderUserList(users) {
    const el = document.getElementById('ss-um-list');
    if (!el) return;
    if (!users.length) {
      el.innerHTML = '<p style="text-align:center;color:#94a3b8;padding:20px;font-size:.85rem">ยังไม่มีผู้ใช้ในระบบ</p>';
      return;
    }
    el.innerHTML = `
      <table style="width:100%;border-collapse:collapse;font-size:.82rem">
        <tr style="background:#f8faff">
          <th style="padding:8px 10px;text-align:left;font-weight:700;color:#475569;font-size:.72rem;text-transform:uppercase;letter-spacing:.04em;border-bottom:2px solid #e2e8f0">อีเมล</th>
          <th style="padding:8px 10px;text-align:left;font-weight:700;color:#475569;font-size:.72rem;text-transform:uppercase;letter-spacing:.04em;border-bottom:2px solid #e2e8f0">Role</th>
          <th style="padding:8px 10px;text-align:left;font-weight:700;color:#475569;font-size:.72rem;text-transform:uppercase;letter-spacing:.04em;border-bottom:2px solid #e2e8f0">ห้องเรียน</th>
          <th style="padding:8px 10px;border-bottom:2px solid #e2e8f0"></th>
        </tr>
        ${users.map(u => `
          <tr style="border-bottom:1px solid #f1f5f9">
            <td style="padding:9px 10px">${u.email}</td>
            <td style="padding:9px 10px"><span style="background:${u.role==='admin'?'#fee2e2':'#dbeafe'};color:${u.role==='admin'?'#991b1b':'#1e40af'};font-size:.7rem;font-weight:800;padding:2px 8px;border-radius:10px">${{admin:'Admin',teacher:'ครู'}[u.role]||u.role}</span></td>
            <td style="padding:9px 10px;color:#64748b;font-size:.78rem">${u.classes||'ทุกห้อง'}</td>
            <td style="padding:9px 10px;text-align:right"><button onclick="SmartAuth._removeUser('${u.email}')" style="background:#fee2e2;color:#dc2626;border:none;border-radius:6px;padding:4px 10px;font-size:.75rem;font-weight:700;cursor:pointer;font-family:inherit">ลบ</button></td>
          </tr>`).join('')}
      </table>`;
  }

  async function _addUser() {
    const email   = document.getElementById('ss-um-email')?.value.trim();
    const role    = document.getElementById('ss-um-role')?.value || 'teacher';
    const classes = document.getElementById('ss-um-classes')?.value.trim();

    if (!email || !email.includes('@')) {
      alert('กรุณากรอกอีเมลให้ถูกต้อง'); return;
    }
    try {
      await _callApi('addUser', { email, role, classes });
      const result = await _callApi('getUserList', {});
      _renderUserList(result.users || []);
      document.getElementById('ss-um-email').value = '';
      document.getElementById('ss-um-classes').value = '';
    } catch(e) { alert('เพิ่มไม่สำเร็จ: ' + e.message); }
  }

  async function _removeUser(email) {
    if (!confirm(`ยืนยันการลบ ${email}?`)) return;
    try {
      await _callApi('removeUser', { email });
      const result = await _callApi('getUserList', {});
      _renderUserList(result.users || []);
    } catch(e) { alert('ลบไม่สำเร็จ: ' + e.message); }
  }

  // ─── ROLE-BASED UI HELPERS ────────────────────────────────────────────────

  /**
   * ซ่อน element ที่ไม่มีสิทธิ์ใช้งาน
   * ใช้ attribute: data-require-role="admin" หรือ data-require-role="teacher"
   */
  function applyRoleUI() {
    document.querySelectorAll('[data-require-role]').forEach(el => {
      const required = el.dataset.requireRole;
      if (!hasRole(required)) {
        el.style.display = 'none';
        el.setAttribute('aria-hidden', 'true');
      }
    });

    // ซ่อนห้องที่ teacher ไม่มีสิทธิ์
    if (_state.user?.role === 'teacher' && _state.user?.classes?.length > 0) {
      document.querySelectorAll('[data-class]').forEach(el => {
        const cls = el.dataset.class;
        if (!canAccessClass(cls)) el.style.display = 'none';
      });
    }
  }

  /**
   * กรอง array ของนักเรียน/ข้อมูล ตามสิทธิ์ของ user
   * @param {Array} students - [{cls: 'ป.1/1', ...}]
   */
  function filterByPermission(students) {
    if (!_state.user) return [];
    if (_state.user.role === 'admin') return students;
    const allowed = _state.user.classes || [];
    if (!allowed.length) return students; // teacher ที่ยังไม่กำหนดห้อง เห็นทั้งหมด
    return students.filter(s => allowed.includes(s[2] || s.cls || s.class));
  }

  // ─── SESSION ──────────────────────────────────────────────────────────────

  function _saveSession(user) {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(user));
  }

  function _loadSession() {
    try {
      const raw = localStorage.getItem(STORAGE_KEY);
      if (!raw) return null;
      const user = JSON.parse(raw);
      // ตรวจสอบอายุ session
      if (Date.now() - user.loginAt > TOKEN_EXPIRY) {
        _clearSession();
        return null;
      }
      return user;
    } catch(e) { return null; }
  }

  function _clearSession() {
    localStorage.removeItem(STORAGE_KEY);
  }

  // ─── HELPERS ─────────────────────────────────────────────────────────────

  function _decodeJWT(token) {
    try {
      const base64 = token.split('.')[1].replace(/-/g, '+').replace(/_/g, '/');
      return JSON.parse(atob(base64));
    } catch(e) { return null; }
  }

  async function _callApi(action, data) {
    if (!_state.apiUrl) throw new Error('No API URL');
    const res = await fetch(_state.apiUrl, {
      method: 'POST',
      body: JSON.stringify({ action, ...data }),
      headers: { 'Content-Type': 'text/plain' },
    });
    return res.json();
  }

  function _showError(html) {
    const el = document.getElementById('ss-error');
    if (el) { el.innerHTML = html; el.style.display = 'block'; }
  }

  function _showLoading(text) {
    const el = document.getElementById('ss-loading');
    const txt = document.getElementById('ss-loading-text');
    if (el) el.classList.add('show');
    if (txt) txt.innerText = text || 'กำลังโหลด...';
  }

  function _hideLoading() {
    const el = document.getElementById('ss-loading');
    if (el) el.classList.remove('show');
  }

  function _removeLoginScreen() {
    document.getElementById('ss-login-screen')?.remove();
  }

  function _showAccessDenied(role) {
    _showModal('⛔ ไม่มีสิทธิ์', `
      <div style="text-align:center;padding:20px 0">
        <div style="font-size:3rem;margin-bottom:14px">🔒</div>
        <p style="font-weight:700;margin-bottom:8px">คุณไม่มีสิทธิ์เข้าถึงส่วนนี้</p>
        <p style="color:#64748b;font-size:.85rem">ต้องการสิทธิ์: <strong>${{admin:'ผู้ดูแลระบบ',teacher:'ครูประจำชั้น'}[role]||role}</strong></p>
      </div>`);
  }

  function _showModal(title, bodyHTML) {
    const old = document.getElementById('ss-auth-modal');
    if (old) old.remove();
    const modal = document.createElement('div');
    modal.id = 'ss-auth-modal';
    modal.innerHTML = `
      <style>
        #ss-auth-modal { position:fixed;inset:0;background:rgba(15,23,42,.6);z-index:99990;display:flex;align-items:center;justify-content:center;padding:20px;backdrop-filter:blur(4px);font-family:'Noto Sans Thai','Sarabun',sans-serif }
        #ss-auth-modal .mm { background:#fff;border-radius:18px;width:100%;max-width:480px;max-height:85vh;overflow-y:auto;animation:ss-card-in .25s ease;box-shadow:0 24px 60px rgba(0,0,0,.2) }
        #ss-auth-modal .mh { position:sticky;top:0;background:#fff;padding:18px 20px 14px;border-bottom:1px solid #e2e8f0;display:flex;align-items:center;justify-content:space-between;border-radius:18px 18px 0 0 }
        #ss-auth-modal .mh h3 { font-size:1rem;font-weight:800;color:#0f172a }
        #ss-auth-modal .mc { padding:20px }
        #ss-auth-modal .close-btn { width:28px;height:28px;border-radius:6px;border:none;background:#f1f5f9;color:#475569;cursor:pointer;font-size:16px;display:flex;align-items:center;justify-content:center;transition:all .15s }
        #ss-auth-modal .close-btn:hover { background:#dc2626;color:#fff }
      </style>
      <div class="mm">
        <div class="mh"><h3>${title}</h3><button class="close-btn" onclick="document.getElementById('ss-auth-modal').remove()">✕</button></div>
        <div class="mc">${bodyHTML}</div>
      </div>`;
    modal.addEventListener('click', e => { if (e.target === modal) modal.remove(); });
    document.body.appendChild(modal);
  }

  // ─── EXPOSE PUBLIC ────────────────────────────────────────────────────────
  return {
    init,
    getUser,
    hasRole,
    requireRole,
    getAllowedClasses,
    canAccessClass,
    signOut,
    setApiUrl,
    applyRoleUI,
    filterByPermission,
    openUserManager,
    // Private exposed for onclick handlers
    _openUserMenu,
    _openProfileModal,
    _addUser,
    _removeUser,
  };
})();

// ─── PATCH: Access Denied Card (replaces block behavior with contact-admin UX) ─

SmartAuth._showAccessDeniedCard = function(email) {
  const adminEmail = (SmartAuth._adminContact) || 'admin@school.th';
  const subject    = encodeURIComponent('ขอสิทธิ์เข้าใช้ Smart School');
  const body       = encodeURIComponent(
    'สวัสดีครับ/ค่ะ\n\nขอสิทธิ์เข้าใช้ระบบ Smart School\n\nอีเมลที่ใช้ login: ' + email + '\n\nกรุณาเพิ่มสิทธิ์ให้ด้วยครับ/ค่ะ'
  );

  const card = document.querySelector('.ss-login-card');
  if (!card) return;

  card.innerHTML =
    '<style>' +
    '.ss-denied-icon{width:72px;height:72px;background:linear-gradient(135deg,#fef2f2,#fee2e2);border-radius:50%;border:3px solid #fca5a5;display:flex;align-items:center;justify-content:center;margin:0 auto 20px;font-size:30px}' +
    '.ss-denied-email{background:#f8faff;border:1px solid #e2e8f0;border-radius:8px;padding:8px 14px;font-size:.8rem;font-family:monospace;color:#475569;word-break:break-all;margin:12px 0 20px}' +
    '.ss-contact-btn{display:flex;align-items:center;justify-content:center;gap:9px;width:100%;padding:13px 20px;background:linear-gradient(135deg,#1a73e8,#1557b0);color:#fff;border:none;border-radius:12px;font-size:.9rem;font-weight:700;font-family:inherit;cursor:pointer;text-decoration:none;transition:all .2s;box-shadow:0 4px 14px rgba(26,115,232,.35)}' +
    '.ss-contact-btn:hover{transform:translateY(-2px);box-shadow:0 8px 20px rgba(26,115,232,.4)}' +
    '.ss-retry-btn{display:flex;align-items:center;justify-content:center;gap:8px;width:100%;padding:11px 20px;background:transparent;color:#64748b;border:1.5px solid #e2e8f0;border-radius:12px;font-size:.88rem;font-weight:600;font-family:inherit;cursor:pointer;margin-top:10px;transition:all .2s}' +
    '.ss-retry-btn:hover{background:#f8faff;color:#0f172a}' +
    '.ss-admin-note{background:#fffbeb;border:1px solid #fde68a;border-radius:10px;padding:12px 14px;font-size:.78rem;color:#78350f;margin-top:16px;line-height:1.6;text-align:left}' +
    '</style>' +

    '<div class="ss-denied-icon">\uD83D\uDD12</div>' +
    '<h2 style="color:#991b1b;font-size:1.35rem;text-align:center">ไม่มีสิทธิ์เข้าใช้</h2>' +
    '<p style="text-align:center;color:#64748b;font-size:.85rem;margin-top:6px;line-height:1.6">อีเมลนี้ยังไม่ได้รับอนุญาตให้เข้าใช้ระบบ</p>' +
    '<div class="ss-denied-email">\uD83D\uDCE7 ' + email + '</div>' +
    '<a class="ss-contact-btn" href="mailto:' + adminEmail + '?subject=' + subject + '&body=' + body + '">\u2709\uFE0F ส่งอีเมลขอสิทธิ์จากผู้ดูแลระบบ</a>' +
    '<div class="ss-admin-note"><strong>\uD83D\uDCA1 Admin เพิ่มสิทธิ์ได้ที่:</strong><br>เข้าสู่ระบบ \u2192 เมนู User \u2192 \uD83D\uDEE1\uFE0F จัดการผู้ใช้ \u2192 เพิ่มอีเมล ' + email + '</div>' +
    '<button class="ss-retry-btn" onclick="SmartAuth._retryLogin()">\u2190 ลองบัญชีอื่น</button>' +
    '<p style="text-align:center;margin-top:16px;font-size:.72rem;color:#94a3b8">ผู้ดูแลระบบ: <a href="mailto:' + adminEmail + '" style="color:#1a73e8">' + adminEmail + '</a></p>';
};

SmartAuth._retryLogin = function() {
  // ล้าง Google session ก่อน แล้ว re-render หน้า login
  if (typeof google !== 'undefined') {
    try { google.accounts.id.disableAutoSelect(); } catch(e) {}
  }
  // ลบ screen เก่าแล้วสร้างใหม่
  const old = document.getElementById('ss-login-screen');
  if (old) old.remove();
  // เรียก internal render ผ่านการ logout แล้ว init ใหม่
  localStorage.removeItem('ss_auth_v4');
  window.location.reload();
};

// ─── CONFIG: ตั้งค่าอีเมล admin สำหรับแสดงใน error card ─────────────────────
// เรียกก่อน SmartAuth.init() เช่น:
//   SmartAuth._adminContact = 'director@school.th';
SmartAuth._adminContact = '';
