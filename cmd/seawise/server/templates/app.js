/**
 * SeaWise Client Web UI
 *
 * State machine with 5 states:
 *   SETUP   - no password set, show setup card
 *   LOCKED  - password set but not authenticated, show login card
 *   CONNECT - authenticated but not paired, show connect card
 *   PAIRING - pairing in progress, show waiting spinner + cancel
 *   PAIRED  - connected, show main content with services
 *
 * Single poll loop calls /api/status every 5 seconds.
 * renderState() is the sole owner of UI visibility.
 */

'use strict';

// --- Go template injects WEB_APP_URL before this file loads ---
// const WEB_APP_URL is defined in index.html <script> block

// ===== State Machine =====

const State = Object.freeze({
    SETUP:   'SETUP',
    LOCKED:  'LOCKED',
    CONNECT: 'CONNECT',
    PAIRING: 'PAIRING',
    PAIRED:  'PAIRED',
});

let currentState = null;
let lastStatusJSON = '';
let lastServicesJSON = '';
let lastFrpState = '';
let disconnectToastTimer = null;
let lastPairingState = '';
let pendingDeleteService = null;
let pairingPollInterval = null;

// ===== DOM References =====

const dom = {
    // Screens
    updateBanner:     () => document.getElementById('update-banner'),
    loginScreen:      () => document.getElementById('login-screen'),
    mainContainer:    () => document.getElementById('main-container'),
    setupCard:        () => document.getElementById('setup-card'),
    connectCard:      () => document.getElementById('connect-card'),
    connectForm:      () => document.getElementById('connect-form'),
    waitingApproval:  () => document.getElementById('waiting-approval'),
    mainContent:      () => document.getElementById('main-content'),

    // Header
    statusBadge:      () => document.getElementById('status-badge'),
    statusText:       () => document.getElementById('status-text'),
    settingsWrapper:  () => document.querySelector('.settings-wrapper'),
    settingsDropdown: () => document.getElementById('settings-dropdown'),
    dropdownSetPw:    () => document.getElementById('dropdown-set-pw'),
    dropdownLock:     () => document.getElementById('dropdown-lock'),

    // Setup form
    setupPassword:    () => document.getElementById('setup-password'),
    setupConfirm:     () => document.getElementById('setup-confirm'),
    setupError:       () => document.getElementById('setup-error'),

    // Login form
    loginPassword:    () => document.getElementById('login-password'),
    loginError:       () => document.getElementById('login-error'),

    // Connect form
    serverNameInput:  () => document.getElementById('server-name-input'),

    // Paired content
    serverName:       () => document.getElementById('server-name'),
    userEmail:        () => document.getElementById('user-email'),
    servicesCount:    () => document.getElementById('services-count'),
    servicesList:     () => document.getElementById('services-list'),
    serverIdFooter:   () => document.getElementById('server-id-footer'),
    versionFooter:    () => document.getElementById('version-footer'),

    // Service form
    serviceName:      () => document.getElementById('service-name'),
    serviceHost:      () => document.getElementById('service-host'),
    servicePort:      () => document.getElementById('service-port'),

    // Modals
    disconnectModal:  () => document.getElementById('disconnect-modal'),
    deleteModal:      () => document.getElementById('delete-service-modal'),
    deleteServiceName:() => document.getElementById('delete-service-name'),
    setPasswordModal: () => document.getElementById('set-password-modal'),
    setPwCurrent:     () => document.getElementById('set-pw-current'),
    setPwNew:         () => document.getElementById('set-pw-new'),
    setPwConfirm:     () => document.getElementById('set-pw-confirm'),
    setPwError:       () => document.getElementById('set-pw-error'),

    // Toast
    toastContainer:   () => document.getElementById('toast-container'),
};

// ===== Render State =====

function renderState(data) {
    const state = currentState;

    // Hide everything first
    dom.loginScreen().classList.add('hidden');
    dom.mainContainer().classList.add('hidden');
    dom.setupCard().classList.add('hidden');
    dom.connectCard().classList.add('hidden');
    dom.connectForm().classList.add('hidden');
    dom.waitingApproval().classList.add('hidden');
    dom.mainContent().classList.add('hidden');
    dom.serverIdFooter().classList.add('hidden');

    // Settings visibility
    const settingsWrapper = dom.settingsWrapper();
    if (settingsWrapper) {
        settingsWrapper.style.visibility = (state === State.PAIRED || state === State.CONNECT || state === State.PAIRING) ? 'visible' : 'hidden';
    }

    // Lock button visibility
    const lockBtn = dom.dropdownLock();
    if (lockBtn) {
        if (data && data.password_set && (state === State.PAIRED || state === State.CONNECT || state === State.PAIRING)) {
            lockBtn.classList.remove('hidden');
        } else {
            lockBtn.classList.add('hidden');
        }
    }

    // Status badge
    updateStatusBadge(state, data);

    switch (state) {
        case State.SETUP:
            dom.mainContainer().classList.remove('hidden');
            dom.setupCard().classList.remove('hidden');
            break;

        case State.LOCKED:
            dom.loginScreen().classList.remove('hidden');
            break;

        case State.CONNECT:
            dom.mainContainer().classList.remove('hidden');
            dom.connectCard().classList.remove('hidden');
            dom.connectForm().classList.remove('hidden');
            break;

        case State.PAIRING:
            dom.mainContainer().classList.remove('hidden');
            dom.connectCard().classList.remove('hidden');
            dom.waitingApproval().classList.remove('hidden');
            break;

        case State.PAIRED:
            dom.mainContainer().classList.remove('hidden');
            dom.mainContent().classList.remove('hidden');
            dom.serverIdFooter().classList.remove('hidden');
            if (data) {
                dom.serverName().textContent = data.server_name || 'My Server';
                dom.userEmail().textContent = data.user_email || '-';
                dom.serverIdFooter().textContent = data.server_id || '';
            }
            break;
    }
}

function updateStatusBadge(state, data) {
    const badge = dom.statusBadge();
    const text = dom.statusText();
    if (!badge || !text) return;

    if (state === State.LOCKED && data && data.pairing_state === 'paired') {
        badge.className = 'status-badge online';
        text.textContent = 'Connected';
        return;
    }

    switch (state) {
        case State.PAIRED:
            badge.className = 'status-badge online';
            text.textContent = 'Connected';
            break;
        case State.PAIRING:
            badge.className = 'status-badge pending';
            text.textContent = 'Authorizing...';
            break;
        default:
            badge.className = 'status-badge offline';
            text.textContent = 'Not Connected';
            break;
    }
}

// ===== Determine State =====

function determineState(data) {
    if (!data.password_set) return State.SETUP;
    if (!data.authenticated) return State.LOCKED;
    if (data.pairing_state === 'paired') return State.PAIRED;
    if (data.pairing_state === 'pending') return State.PAIRING;
    return State.CONNECT;
}

// ===== Poll =====

async function poll() {
    try {
        const resp = await fetch('/api/status');
        const data = await resp.json();

        const newState = determineState(data);
        const stateChanged = newState !== currentState;
        const prevState = currentState;
        currentState = newState;

        // Version footer
        if (data.version) {
            dom.versionFooter().textContent = data.version;
        }

        // Update banner
        if (data.latest_version) {
            dom.updateBanner().classList.remove('hidden');
        }

        // Default hostname for server name input
        const nameInput = dom.serverNameInput();
        if (nameInput && !nameInput.value && data.default_hostname) {
            nameInput.value = data.default_hostname;
        }

        // FRP state tracking with debounce
        handleFrpStateChange(data.frp_state || '');

        // Detect transition from paired to unpaired
        if (lastPairingState === 'paired' && data.pairing_state !== 'paired' && prevState === State.PAIRED) {
            showToast('Disconnected from Seawise.io', 'warning');
        }
        lastPairingState = data.pairing_state;

        // Render
        renderState(data);

        // Load services when paired
        if (currentState === State.PAIRED) {
            await loadServices();
        }

    } catch (err) {
        console.error('Poll failed:', err);
    }
}

function handleFrpStateChange(frpState) {
    if (lastFrpState && frpState !== lastFrpState) {
        if (frpState === 'running' && lastFrpState !== 'running') {
            if (disconnectToastTimer) {
                clearTimeout(disconnectToastTimer);
                disconnectToastTimer = null;
            } else {
                showToast('Tunnel connected', 'success');
            }
        } else if (lastFrpState === 'running' && frpState !== 'running') {
            disconnectToastTimer = setTimeout(() => {
                showToast('Tunnel disconnected — reconnecting...', 'warning');
                disconnectToastTimer = null;
            }, 5000);
        }
    }
    lastFrpState = frpState;
}

// ===== Toast Notifications =====

function showToast(message, type = 'error') {
    const container = dom.toastContainer();
    if (!container) return;
    const toast = document.createElement('div');
    toast.className = 'toast ' + type;
    toast.textContent = message;
    container.appendChild(toast);
    setTimeout(() => {
        toast.classList.add('fade-out');
        setTimeout(() => toast.remove(), 200);
    }, 4000);
}

// ===== Auth Functions =====

async function doSetupPassword() {
    const pw = dom.setupPassword().value;
    const confirm = dom.setupConfirm().value;
    const errEl = dom.setupError();
    errEl.classList.add('hidden');

    if (pw.length < 8) {
        errEl.textContent = 'Password must be at least 8 characters';
        errEl.classList.remove('hidden');
        return;
    }
    if (pw !== confirm) {
        errEl.textContent = 'Passwords do not match';
        errEl.classList.remove('hidden');
        return;
    }

    try {
        const resp = await fetch('/api/auth/set-password', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ password: pw })
        });
        if (resp.ok) {
            showToast('Password set! Logging you in...', 'success');
            const loginResp = await fetch('/api/auth/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ password: pw })
            });
            if (loginResp.ok) {
                // Poll immediately to transition to CONNECT state
                await poll();
            } else {
                location.reload();
            }
        } else {
            const data = await resp.json().catch(() => ({}));
            errEl.textContent = data.error || 'Failed to set password';
            errEl.classList.remove('hidden');
        }
    } catch {
        errEl.textContent = 'Connection error';
        errEl.classList.remove('hidden');
    }
}

async function doLogin() {
    const password = dom.loginPassword().value;
    const errorEl = dom.loginError();
    errorEl.classList.add('hidden');

    try {
        const resp = await fetch('/api/auth/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ password })
        });
        const data = await resp.json();
        if (data.error) {
            errorEl.textContent = data.error;
            errorEl.classList.remove('hidden');
            return;
        }
        dom.loginPassword().value = '';
        // Poll immediately to transition state
        await poll();
    } catch {
        errorEl.textContent = 'Login failed';
        errorEl.classList.remove('hidden');
    }
}

async function lockUI() {
    hideSettingsDropdown();
    try {
        await fetch('/api/auth/logout', { method: 'POST' });
        // Poll immediately to transition to LOCKED state
        await poll();
    } catch (err) {
        console.error('Failed to lock:', err);
    }
}

// ===== Settings Dropdown =====

function toggleSettingsDropdown(event) {
    event.stopPropagation();
    const dropdown = dom.settingsDropdown();
    if (!dropdown.classList.contains('hidden')) {
        dropdown.classList.add('hidden');
        return;
    }
    dom.dropdownSetPw().classList.remove('hidden');
    dropdown.classList.remove('hidden');
}

function hideSettingsDropdown() {
    dom.settingsDropdown().classList.add('hidden');
}

document.addEventListener('click', (e) => {
    const wrapper = dom.settingsWrapper();
    if (wrapper && !wrapper.contains(e.target)) {
        hideSettingsDropdown();
    }
});

// ===== Set Password Modal =====

function showSetPasswordModal() {
    hideSettingsDropdown();
    dom.setPwCurrent().value = '';
    dom.setPwNew().value = '';
    dom.setPwConfirm().value = '';
    dom.setPwError().classList.add('hidden');
    dom.setPasswordModal().classList.add('visible');
    dom.setPwCurrent().focus();
}

function hideSetPasswordModal() {
    dom.setPasswordModal().classList.remove('visible');
    dom.setPwNew().value = '';
    dom.setPwConfirm().value = '';
    dom.setPwError().classList.add('hidden');
}

async function doSetPassword() {
    const currentPw = dom.setPwCurrent().value;
    const pw = dom.setPwNew().value;
    const confirm = dom.setPwConfirm().value;
    const errorEl = dom.setPwError();
    errorEl.classList.add('hidden');

    if (!currentPw) { errorEl.textContent = 'Current password is required'; errorEl.classList.remove('hidden'); return; }
    if (pw.length < 8) { errorEl.textContent = 'New password must be at least 8 characters'; errorEl.classList.remove('hidden'); return; }
    if (pw !== confirm) { errorEl.textContent = 'Passwords do not match'; errorEl.classList.remove('hidden'); return; }

    try {
        const resp = await fetch('/api/auth/set-password', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ password: pw, current_password: currentPw })
        });
        const data = await resp.json();
        if (data.error) { errorEl.textContent = data.error; errorEl.classList.remove('hidden'); return; }

        showToast('Password changed', 'success');
        hideSetPasswordModal();
    } catch {
        errorEl.textContent = 'Failed to change password';
        errorEl.classList.remove('hidden');
    }
}

// ===== Pairing =====

async function connectToSeaWise() {
    const serverName = dom.serverNameInput().value || 'My Server';
    try {
        const resp = await fetch('/api/pair/start', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ server_name: serverName })
        });
        const data = await resp.json();
        if (data.error) {
            showToast(data.error);
            return;
        }
        window.open(`${WEB_APP_URL}/connect?code=${data.code}`, '_blank');
        startPairingPoll();
        // Immediate poll to show PAIRING state
        await poll();
    } catch {
        showToast('Failed to connect');
    }
}

function startPairingPoll() {
    if (pairingPollInterval) clearInterval(pairingPollInterval);
    pairingPollInterval = setInterval(async () => {
        try {
            const resp = await fetch('/api/pair/poll');
            const data = await resp.json();
            if (data.state === 'paired') {
                clearInterval(pairingPollInterval);
                pairingPollInterval = null;
                await poll();
            } else if (data.state === 'none' || data.state === 'expired') {
                clearInterval(pairingPollInterval);
                pairingPollInterval = null;
                showToast('Authorization expired. Please try again.', 'warning');
                await poll();
            }
        } catch (err) {
            console.error('Pairing poll failed:', err);
        }
    }, 2000);
}

async function cancelPairing() {
    if (pairingPollInterval) {
        clearInterval(pairingPollInterval);
        pairingPollInterval = null;
    }
    try { await fetch('/api/pair/cancel', { method: 'POST' }); } catch { /* ignore */ }
    await poll();
}

// ===== Disconnect =====

function showDisconnectModal() {
    dom.disconnectModal().classList.add('visible');
}

function hideDisconnectModal() {
    dom.disconnectModal().classList.remove('visible');
}

async function confirmDisconnect() {
    hideDisconnectModal();
    try {
        const resp = await fetch('/api/unpair', { method: 'POST' });
        const data = await resp.json();
        if (data.success) {
            await poll();
        } else {
            showToast(data.error || 'Failed to disconnect');
        }
    } catch {
        showToast('Failed to disconnect');
    }
}

// ===== Services =====

function escapeHtml(str) {
    const div = document.createElement('div');
    div.appendChild(document.createTextNode(str));
    return div.innerHTML;
}

async function loadServices() {
    try {
        const resp = await fetch('/api/services/list');
        const data = await resp.json();
        const services = (data.services && data.services.length > 0)
            ? data.services.map(svc => ({
                id: svc.id,
                name: svc.name,
                host: svc.host,
                port: svc.port,
                subdomain: svc.subdomain,
            }))
            : [];

        const newJSON = JSON.stringify(services);
        if (newJSON !== lastServicesJSON) {
            lastServicesJSON = newJSON;
            renderServices(services);
        }
    } catch (err) {
        console.error('Failed to load services:', err);
    }
}

function renderServices(services) {
    const list = dom.servicesList();
    const count = dom.servicesCount();
    if (!list || !count) return;

    count.textContent = services.length + ' app' + (services.length !== 1 ? 's' : '');

    if (services.length === 0) {
        list.innerHTML = '';
        const emptyState = document.createElement('div');
        emptyState.className = 'empty-state';
        emptyState.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" d="M20.25 6.375c0 2.278-3.694 4.125-8.25 4.125S3.75 8.653 3.75 6.375m16.5 0c0-2.278-3.694-4.125-8.25-4.125S3.75 4.097 3.75 6.375m16.5 0v11.25c0 2.278-3.694 4.125-8.25 4.125s-8.25-1.847-8.25-4.125V6.375m16.5 0v3.75m-16.5-3.75v3.75m16.5 0v3.75C20.25 16.153 16.556 18 12 18s-8.25-1.847-8.25-4.125v-3.75m16.5 0c0 2.278-3.694 4.125-8.25 4.125s-8.25-1.847-8.25-4.125"/></svg>';
        const p = document.createElement('p');
        p.textContent = 'No apps added yet';
        emptyState.appendChild(p);
        list.appendChild(emptyState);
        return;
    }

    // Build service items using DOM methods for safety
    list.innerHTML = '';
    services.forEach(svc => {
        const item = document.createElement('div');
        item.className = 'service-item';

        const icon = document.createElement('div');
        icon.className = 'service-icon';
        icon.textContent = svc.name.charAt(0).toUpperCase();

        const info = document.createElement('div');
        info.className = 'service-info';

        const nameEl = document.createElement('div');
        nameEl.className = 'service-name';
        nameEl.textContent = svc.name;

        const detailsEl = document.createElement('div');
        detailsEl.className = 'service-details';
        detailsEl.textContent = svc.host + ':' + svc.port;

        info.appendChild(nameEl);
        info.appendChild(detailsEl);

        const subdomainEl = document.createElement('span');
        subdomainEl.className = 'service-subdomain';
        subdomainEl.textContent = svc.subdomain;

        const deleteBtn = document.createElement('button');
        deleteBtn.className = 'service-delete';
        deleteBtn.title = 'Remove app';
        deleteBtn.textContent = '\u00D7';
        deleteBtn.addEventListener('click', () => showDeleteServiceModal(svc.id, svc.name));

        item.appendChild(icon);
        item.appendChild(info);
        item.appendChild(subdomainEl);
        item.appendChild(deleteBtn);

        list.appendChild(item);
    });
}

async function addService() {
    const nameEl = dom.serviceName();
    const hostEl = dom.serviceHost();
    const portEl = dom.servicePort();

    const name = nameEl.value.trim();
    const host = hostEl.value.trim();
    const port = parseInt(portEl.value);

    if (!name) { showToast('Please enter an app name', 'warning'); return; }
    if (!host) { showToast('Please enter a host (IP, hostname, or container name)', 'warning'); return; }
    if (!port || port < 1 || port > 65535) { showToast('Please enter a valid port (1-65535)', 'warning'); return; }

    try {
        const resp = await fetch('/api/services/add', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ name, host, port })
        });
        const data = await resp.json();
        if (data.error) { showToast(data.error); return; }

        nameEl.value = '';
        hostEl.value = '';
        portEl.value = '';

        if (data.warning) {
            showToast(data.warning, 'warning');
        } else {
            showToast('App added: ' + name, 'success');
        }

        // Force re-fetch services
        lastServicesJSON = '';
        await loadServices();
    } catch {
        showToast('Failed to add app — check your connection');
    }
}

// ===== Delete Service Modal =====

function showDeleteServiceModal(serviceId, serviceName) {
    pendingDeleteService = { id: serviceId, name: serviceName };
    dom.deleteServiceName().textContent = serviceName;
    dom.deleteModal().classList.add('visible');
}

function hideDeleteServiceModal() {
    dom.deleteModal().classList.remove('visible');
    pendingDeleteService = null;
}

async function confirmDeleteService() {
    if (!pendingDeleteService) return;
    const { id: serviceId, name: serviceName } = pendingDeleteService;
    hideDeleteServiceModal();

    try {
        const resp = await fetch('/api/services/delete', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ service_id: serviceId, service_name: serviceName })
        });
        const data = await resp.json();
        if (data.error) { showToast(data.error); return; }

        showToast('Removed ' + serviceName, 'success');

        // Force re-fetch services
        lastServicesJSON = '';
        await loadServices();
    } catch {
        showToast('Failed to remove ' + serviceName + ' — try again');
    }
}

// ===== Initialization =====

(async () => {
    // Initial poll
    await poll();

    // If we're in PAIRING state on page load (e.g. refresh during pairing), start pairing poll
    if (currentState === State.PAIRING) {
        startPairingPoll();
    }

    // Main poll loop
    setInterval(poll, 5000);
})();
