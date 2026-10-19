// ==========================================================================
// PT JAGAT TEKNOLOGI INDONESIA — MIKROTIK IP WHITELIST PORTAL
// HTMX & Client Controller
// ==========================================================================

document.addEventListener('DOMContentLoaded', () => {
  initHostnameDetection();
  initPublicIPDetection();
  initHTMXEvents();
  initTableSearch();
});

// ==========================================================================
// 1. HOSTNAME & IP DETECTION
// ==========================================================================

function getDeviceName() {
  const ua = navigator.userAgent || '';
  if (/Windows NT 10.0/i.test(ua)) return 'Windows10-PC';
  if (/Windows NT 11.0/i.test(ua) || (/Windows/i.test(ua) && /Win64/i.test(ua))) return 'Windows-PC';
  if (/Macintosh|Mac OS X/i.test(ua)) return 'MacBook';
  if (/Android/i.test(ua)) return 'Android-Device';
  if (/iPhone|iPad/i.test(ua)) return 'iOS-Device';
  if (/Linux/i.test(ua)) return 'Linux-PC';
  return 'Klien-Remote';
}

function initHostnameDetection() {
  const hostnameInput = document.getElementById('input-hostname');
  const hostnameBadge = document.getElementById('client-hostname-text');
  const savedHostname = localStorage.getItem('jti_wl_hostname');

  if (hostnameInput) {
    // If input is empty or defaults to raw IP, populate with saved or detected device name
    const currentVal = hostnameInput.value.trim();
    if (!currentVal || currentVal.includes(':') || /^\d+\.\d+\.\d+\.\d+$/.test(currentVal)) {
      const detected = savedHostname || getDeviceName();
      hostnameInput.value = detected;
      if (hostnameBadge) hostnameBadge.textContent = detected;
    }

    hostnameInput.addEventListener('change', () => {
      const val = hostnameInput.value.trim();
      if (val) {
        localStorage.setItem('jti_wl_hostname', val);
        if (hostnameBadge) hostnameBadge.textContent = val;
      }
    });
  }
}

async function initPublicIPDetection() {
  const ipInput = document.getElementById('input-ip');
  const ipText = document.getElementById('client-ip-text');
  const publicIPBtn = document.getElementById('btn-use-public-ip');
  if (!ipInput || !publicIPBtn) return;

  const currentIP = ipInput.value.trim();
  const isPrivateOrLoopback =
    currentIP === '127.0.0.1' ||
    currentIP === '::1' ||
    currentIP.startsWith('10.') ||
    currentIP.startsWith('192.168.') ||
    /^172\.(1[6-9]|2[0-9]|3[0-1])\./.test(currentIP);

  if (isPrivateOrLoopback) {
    try {
      // Background check for public IP
      const res = await fetch('https://api.ipify.org?format=json', { cache: 'no-store' });
      if (res.ok) {
        const data = await res.json();
        if (data.ip && data.ip !== currentIP) {
          publicIPBtn.style.display = 'inline-flex';
          publicIPBtn.textContent = `Gunakan IP Publik (${data.ip})`;
          publicIPBtn.onclick = () => {
            ipInput.value = data.ip;
            if (ipText) ipText.textContent = data.ip;
            publicIPBtn.style.display = 'none';
            showToast(`IP target diubah ke ${data.ip}`, 'success');
            // Trigger status check for the new IP via HTMX
            htmx.ajax('GET', `/ui/status?ip=${encodeURIComponent(data.ip)}`, {
              target: '#hero-client-card',
              swap: 'outerHTML',
            });
          };
        }
      }
    } catch {
      // Ignore public IP lookup failure if offline / intranet
    }
  }
}

// ==========================================================================
// 2. HTMX EVENT HOOKS & OVERLAY ANIMATION
// ==========================================================================

function initHTMXEvents() {
  // Automatically inject CSRF Token and Bearer Token into HTMX headers
  document.body.addEventListener('htmx:configRequest', (evt) => {
    const csrfToken = document.querySelector('meta[name="csrf-token"]')?.getAttribute('content');
    if (csrfToken) {
      evt.detail.headers['X-CSRF-Token'] = csrfToken;
    }
    const token = localStorage.getItem('jti_wl_token') || getCookie('auth_token');
    if (token) {
      evt.detail.headers['Authorization'] = `Bearer ${token}`;
    }
  });

  // Show switching modal overlay on actions
  document.body.addEventListener('htmx:beforeRequest', (evt) => {
    const elt = evt.detail.elt;
    const action = elt.getAttribute('data-action');

    if (action === 'whitelist') {
      showSwitchingOverlay('Proses mendaftarkan IP ke Whitelist...', 'Menyimpan ke RouterOS firewall & reset koneksi');
    } else if (action === 'unwhitelist') {
      showSwitchingOverlay('Proses menghapus IP dari Whitelist...', 'Menghapus dari RouterOS address-list');
    } else if (action === 'winbox') {
      showSwitchingOverlay('Proses update akses Winbox...', 'Memperbarui service port 8291 RouterOS');
    }

    if (elt.id === 'btn-refresh') {
      elt.classList.add('rotating');
    }
  });

  // Handle HTMX response completion
  document.body.addEventListener('htmx:afterRequest', (evt) => {
    const btnRefresh = document.getElementById('btn-refresh');
    if (btnRefresh) {
      btnRefresh.classList.remove('rotating');
    }

    // Hide overlay after a minimum smooth transition of 600ms
    setTimeout(hideSwitchingOverlay, 600);

    // Re-initialize hostname and inputs if hero card was swapped
    initHostnameDetection();

    // Check for HX-Trigger toast header
    const hxTrigger = evt.detail.xhr.getResponseHeader('HX-Trigger');
    if (hxTrigger) {
      try {
        const triggerData = JSON.parse(hxTrigger);
        if (triggerData.toast) {
          const msg = triggerData.toast.message || triggerData.toast;
          const type = triggerData.toast.type || 'success';
          showToast(msg, type);
        }
      } catch {
        // Not a JSON trigger
      }
    }
  });

  // Handle HTMX response errors
  document.body.addEventListener('htmx:responseError', (evt) => {
    hideSwitchingOverlay();
    const xhr = evt.detail.xhr;
    let errMsg = 'Terjadi kesalahan sistem';

    if (xhr.status === 401) {
      errMsg = 'Sesi telah berakhir atau tidak sah. Mengalihkan ke halaman login...';
      showToast(errMsg, 'error');
      setTimeout(() => {
        window.location.href = '/login';
      }, 1200);
      return;
    } else if (xhr.status === 429) {
      errMsg = 'Terlalu banyak permintaan atau akun terkunci sementara.';
    } else if (xhr.responseText) {
      try {
        const parsed = JSON.parse(xhr.responseText);
        errMsg = parsed.message || parsed.error || xhr.responseText;
      } catch {
        errMsg = xhr.responseText.replace(/^ERROR\s*/i, '');
      }
    }

    showToast(errMsg, 'error');
  });
}

// ==========================================================================
// 3. SWITCHING MODAL OVERLAY
// ==========================================================================

function showSwitchingOverlay(title, subtitle) {
  const overlay = document.getElementById('switching-modal-overlay');
  const titleEl = document.getElementById('switching-title');
  const subEl = document.getElementById('switching-subtitle');

  if (titleEl && title) titleEl.textContent = title;
  if (subEl && subtitle) subEl.textContent = subtitle;

  if (overlay) {
    overlay.classList.add('active');
    overlay.setAttribute('aria-hidden', 'false');
  }
}

function hideSwitchingOverlay() {
  const overlay = document.getElementById('switching-modal-overlay');
  if (overlay) {
    overlay.classList.remove('active');
    overlay.setAttribute('aria-hidden', 'true');
  }
}

// ==========================================================================
// 4. TOAST NOTIFICATIONS
// ==========================================================================

function showToast(message, type = 'success') {
  const container = document.getElementById('toast-container');
  if (!container) return;

  const toast = document.createElement('div');
  toast.className = `toast ${type}`;
  toast.textContent = message;
  container.appendChild(toast);

  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transform = 'translateY(10px)';
    toast.style.transition = 'all 0.3s ease';
    setTimeout(() => toast.remove(), 300);
  }, 3500);
}

// ==========================================================================
// 5. TABLE SEARCH & FILTER
// ==========================================================================

function initTableSearch() {
  const searchInput = document.getElementById('table-search');
  const filterPills = document.querySelectorAll('.filter-pill');

  if (searchInput) {
    searchInput.addEventListener('input', (e) => {
      filterTableRows(e.target.value.toLowerCase().trim(), getActiveFilter());
    });
  }

  filterPills.forEach((pill) => {
    pill.addEventListener('click', (e) => {
      filterPills.forEach((p) => p.classList.remove('active'));
      e.target.classList.add('active');
      const query = searchInput ? searchInput.value.toLowerCase().trim() : '';
      filterTableRows(query, e.target.getAttribute('data-filter'));
    });
  });
}

function getActiveFilter() {
  const activePill = document.querySelector('.filter-pill.active');
  return activePill ? activePill.getAttribute('data-filter') : 'all';
}

function filterTableRows(query, mode = 'all') {
  const rows = document.querySelectorAll('#entries-tbody tr');
  rows.forEach((row) => {
    const address = (row.getAttribute('data-address') || '').toLowerCase();
    const comment = (row.getAttribute('data-comment') || '').toLowerCase();
    const list = (row.getAttribute('data-list') || '').toLowerCase();
    const winbox = row.getAttribute('data-winbox') === 'true';
    const isManaged = row.getAttribute('data-managed') === 'true';

    let matchFilter = true;
    if (mode === 'managed' && !isManaged) matchFilter = false;
    if (mode === 'winbox' && !winbox) matchFilter = false;

    let matchQuery = true;
    if (query) {
      matchQuery = address.includes(query) || comment.includes(query) || list.includes(query);
    }

    row.style.display = matchFilter && matchQuery ? '' : 'none';
  });
}

// ==========================================================================
// 6. TOKEN / AUTH PROMPT MODAL
// ==========================================================================

function promptAuthToken() {
  const dialog = document.getElementById('modal-auth-token');
  if (dialog && typeof dialog.showModal === 'function') {
    dialog.showModal();
  } else {
    const token = prompt('Masukkan AUTH_BEARER_TOKEN:');
    if (token) {
      saveAuthToken(token);
      location.reload();
    }
  }
}

function saveAuthToken(token) {
  token = (token || '').trim();
  if (!token) return;
  localStorage.setItem('jti_wl_token', token);
  document.cookie = `auth_token=${encodeURIComponent(token)}; Path=/; SameSite=Lax; Max-Age=2592000`;
  showToast('Token autentikasi berhasil disimpan', 'success');
}

// Global functions for inline HTML event handlers
window.saveAuthToken = saveAuthToken;
window.showToast = showToast;
window.showSwitchingOverlay = showSwitchingOverlay;
window.hideSwitchingOverlay = hideSwitchingOverlay;

function getCookie(name) {
  const match = document.cookie.match(new RegExp('(^| )' + name + '=([^;]+)'));
  return match ? decodeURIComponent(match[2]) : '';
}
