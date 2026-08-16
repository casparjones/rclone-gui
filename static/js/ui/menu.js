// Main menu (top right), the overlay panel behind it and the two badges.
//
// The panel sections (Configuration / Sync Jobs / Tasks) are owned by their own
// modules. Instead of importing them — which would make menu ↔ feature a cycle —
// they register their reload function here at startup (see main.js).

import { fetchCurrentUser, logout as logoutRequest } from '../api.js';
import { state } from '../state.js';
import { showToast } from '../util/dom.js';

const sectionLoaders = {};

export function setSectionLoaders(loaders) {
    Object.assign(sectionLoaders, loaders);
}

// The file browser is the main view and lists local files — it needs no remote
// at all. A missing remote is therefore only pointed out, never enforced: the
// panel used to open itself here and covered the whole browser on every fresh
// installation.
export function showConfigHintIfEmpty() {
    if (state.configs.length === 0) {
        showToast('No remote configurations found. Add a remote via the menu to sync.', 'info');
    }
}

// Small marker on the menu button as long as no remote exists. Non-blocking,
// disappears as soon as the first configuration is saved.
export function updateConfigHintBadge() {
    const badge = document.getElementById('menu-config-badge');
    if (badge) {
        badge.classList.toggle('is-visible', state.configs.length === 0);
    }
}

// Signed-in user -------------------------------------------------------------
//
// The name in the navbar answers a question the application otherwise leaves
// open: *who* is this session. It matters as soon as there is more than one
// account, and it is the only visible sign that a session exists at all.

// Kept module-local rather than in state.js: nothing outside this module reads
// it, and state.js belongs to another ticket.
let currentUser = null;

export function getCurrentUser() {
    return currentUser;
}

// Called once at startup. A 401 here never reaches us — api.js has already
// navigated to the login page by then. Anything else (a database hiccup, a
// 500) leaves the chip hidden; the application stays usable.
export async function loadCurrentUser() {
    const result = await fetchCurrentUser();

    if (!result.ok || !result.data) {
        return;
    }

    currentUser = result.data;
    renderCurrentUser(currentUser);
}

// The name comes from the server. It is written as a text node — never as
// markup, never through innerHTML — because a user name is as much outside
// input as a file name is.
function renderCurrentUser(user) {
    const chip = document.getElementById('current-user');
    const chipName = document.getElementById('current-user-name');
    const menuName = document.getElementById('menu-user-name');

    if (chipName) {
        chipName.textContent = user.username;
    }
    if (menuName) {
        menuName.textContent = user.username;
    }

    // Role and expiry as a tooltip: useful when it is needed, invisible when it
    // is not. `title` is an attribute, so no escaping question arises.
    if (chip) {
        chip.title = describeSession(user);
        chip.classList.add('is-visible');
    }
}

function describeSession(user) {
    const parts = [`Signed in as ${user.username}`];

    if (user.role) {
        parts.push(`Role: ${user.role}`);
    }

    // Formatted for the local time zone. An unparsable value is simply left
    // out rather than shown as "Invalid Date".
    if (user.session_expires_at) {
        const expires = new Date(user.session_expires_at);
        if (!Number.isNaN(expires.getTime())) {
            parts.push(`Session expires ${expires.toLocaleString()}`);
        }
    }

    return parts.join(' · ');
}

// Sign out. The menu entry is a real link to `/logout`, which does the same
// thing without any JavaScript; this handler exists so the request is a POST
// (a GET that changes state can be triggered by a foreign page) and so the
// answer is a small JSON instead of a page load.
export async function performLogout(event) {
    if (event) {
        event.preventDefault();
    }

    closeMainMenu();

    const result = await logoutRequest();

    if (!result.ok) {
        // The session may well be gone anyway; say so and fall back to the
        // plain link, which is server-side and cannot fail the same way.
        showToast(result.error || 'Sign out failed', 'error');
        return;
    }

    currentUser = null;
    // No `next`: leaving is deliberate, coming back to the same view is not
    // what was asked for.
    window.location.replace('/login');
}

// Main menu (top right) ------------------------------------------------------

export function toggleMainMenu() {
    const menu = document.getElementById('main-menu');
    if (menu.classList.contains('is-open')) {
        closeMainMenu();
    } else {
        openMainMenu();
    }
}

export function openMainMenu() {
    document.getElementById('main-menu').classList.add('is-open');
    document.getElementById('main-menu-btn').setAttribute('aria-expanded', 'true');
}

export function closeMainMenu() {
    document.getElementById('main-menu').classList.remove('is-open');
    document.getElementById('main-menu-btn').setAttribute('aria-expanded', 'false');
}

export function handleDocumentClickForMenu(event) {
    const menu = document.getElementById('main-menu');
    if (!menu || !menu.classList.contains('is-open')) {
        return;
    }

    // Clicks on the button itself are handled by toggleMainMenu()
    if (event.target.closest('#main-menu-btn') || event.target.closest('#main-menu')) {
        return;
    }

    closeMainMenu();
}

// Menu panel (overlay above the file browser) --------------------------------

export function openMenuPanel(section) {
    closeMainMenu();

    const overlay = document.getElementById('menu-overlay');
    overlay.classList.add('is-open');
    document.body.style.overflow = 'hidden';

    showMenuSection(section);

    // Move focus into the panel so ESC/Tab handling applies right away
    document.getElementById('menu-panel').focus();
}

export function closeMenuPanel() {
    const overlay = document.getElementById('menu-overlay');
    if (!overlay.classList.contains('is-open')) {
        return;
    }

    overlay.classList.remove('is-open');
    document.body.style.overflow = '';
    state.currentMenuSection = '';

    // Give focus back to the menu button. The file browser keeps its state,
    // it is never re-rendered when the panel opens or closes.
    document.getElementById('main-menu-btn').focus();
}

export function isMenuPanelOpen() {
    return document.getElementById('menu-overlay').classList.contains('is-open');
}

// Switch the section inside the panel without closing it
export function showMenuSection(section) {
    const titles = {
        config: 'Configuration',
        sync: 'Sync Jobs',
        tasks: 'Tasks'
    };

    if (!titles[section]) {
        return;
    }

    state.currentMenuSection = section;

    document.querySelectorAll('.panel-section').forEach(panel => {
        panel.classList.remove('is-active');
    });
    document.getElementById(section + '-section').classList.add('is-active');

    // Highlight the active entry of the submenu inside the panel
    ['config', 'sync', 'tasks'].forEach(name => {
        const navButton = document.getElementById('panel-nav-' + name);
        if (navButton) {
            navButton.classList.toggle('btn-primary', name === section);
        }
    });

    document.getElementById('menu-panel-title').textContent = titles[section];

    // Refresh the content of the section that just became visible
    const load = sectionLoaders[section];
    if (typeof load === 'function') {
        load();
    }
}

export function handleMenuKeydown(event) {
    // Modal dialogs (sync, progress, log, ...) bring their own ESC and focus
    // handling and are rendered above the panel
    if (document.querySelector('dialog[open]')) {
        return;
    }

    if (event.key === 'Escape') {
        if (isMenuPanelOpen()) {
            closeMenuPanel();
        } else {
            closeMainMenu();
        }
        return;
    }

    if (event.key === 'Tab' && isMenuPanelOpen()) {
        trapFocusInMenuPanel(event);
    }
}

// Keep the keyboard focus inside the open panel
function trapFocusInMenuPanel(event) {
    const panel = document.getElementById('menu-panel');
    const focusable = Array.from(panel.querySelectorAll(
        'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])'
    )).filter(element => element.offsetParent !== null);

    if (focusable.length === 0) {
        event.preventDefault();
        panel.focus();
        return;
    }

    const first = focusable[0];
    const last = focusable[focusable.length - 1];

    if (event.shiftKey && (document.activeElement === first || document.activeElement === panel)) {
        event.preventDefault();
        last.focus();
    } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
    } else if (!panel.contains(document.activeElement)) {
        event.preventDefault();
        first.focus();
    }
}

// Badge on the menu icon showing the number of currently running jobs
export function updateActiveJobBadge(jobs) {
    state.activeJobCount = jobs.filter(job => job.status === 'Running' || job.status === 'Starting').length;

    const menuBadge = document.getElementById('menu-job-badge');
    const syncBadge = document.getElementById('menu-sync-badge');

    [menuBadge, syncBadge].forEach(badge => {
        if (!badge) {
            return;
        }
        badge.textContent = state.activeJobCount;
        badge.classList.toggle('is-visible', state.activeJobCount > 0);
    });
}
