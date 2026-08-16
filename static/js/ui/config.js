// rclone remote configuration: the list in the panel and the create form.

import { state } from '../state.js';
import * as api from '../api.js';
import { showAlert } from '../util/dom.js';
import { updateConfigHintBadge } from './menu.js';
import { clearRemoteCache, clearLastSelectedRemote, getLastSelectedRemote, updateRemoteSelect } from './remote.js';

export async function saveConfig(event) {
    event.preventDefault();

    const config = {
        name: document.getElementById('config-name').value,
        config_type: document.getElementById('config-type').value,
        url: document.getElementById('config-url').value || null,
        username: document.getElementById('config-username').value || null,
        password: document.getElementById('config-password').value || null
    };

    try {
        const result = await api.createConfig(config);

        if (result.ok) {
            showAlert('config-alert', 'Configuration saved successfully!', 'success');
            document.getElementById('config-form').reset();
            loadConfigs();
        } else {
            showAlert('config-alert', 'Error: ' + result.error, 'error');
        }
    } catch (error) {
        showAlert('config-alert', 'Error saving configuration: ' + error.message, 'error');
    }
}

export async function loadConfigs() {
    // The daemon panel belongs to the configuration view and refreshes with it.
    // It builds its own markup, so it also comes up on the very first call.
    ensureRsyncdCard();
    refreshRsyncdStatus();

    try {
        const result = await api.fetchConfigs();

        if (result.ok) {
            state.configs = result.data;
            displayConfigs();
            updateRemoteSelect();
            updateConfigHintBadge();
            return state.configs; // Return for promise handling
        }

        showAlert('config-alert', 'Error loading configurations: ' + result.error, 'error');
        return [];
    } catch (error) {
        showAlert('config-alert', 'Error loading configurations: ' + error.message, 'error');
        return [];
    }
}

function displayConfigs() {
    const configList = document.getElementById('config-list');

    if (state.configs.length === 0) {
        configList.innerHTML = '<div class="text-center text-base-content/60 py-8">No configurations found.</div>';
        return;
    }

    configList.innerHTML = state.configs.map(config => `
        <div class="card bg-base-200 shadow-sm">
            <div class="card-body py-3 px-4">
                <div class="flex items-center justify-between">
                    <div>
                        <div class="font-semibold text-lg">${config.name}</div>
                        <div class="text-sm text-base-content/70">${config.config_type}</div>
                    </div>
                    <button class="btn btn-error btn-sm" onclick="deleteConfig('${config.name}')">
                        <svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4 mr-1" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                        </svg>
                        Delete
                    </button>
                </div>
            </div>
        </div>
    `).join('');
}

export async function deleteConfig(name) {
    if (!confirm('Are you sure you want to delete this configuration?')) {
        return;
    }

    try {
        const result = await api.deleteConfig(name);

        if (result.ok) {
            // Clear cache for deleted remote
            clearRemoteCache(name);

            // Clear last selected remote if it was this one
            if (getLastSelectedRemote() === name) {
                clearLastSelectedRemote();
            }

            showAlert('config-alert', 'Configuration deleted successfully!', 'success');
            loadConfigs();
        } else {
            showAlert('config-alert', 'Error deleting configuration: ' + result.error, 'error');
        }
    } catch (error) {
        showAlert('config-alert', 'Error deleting configuration: ' + error.message, 'error');
    }
}

export async function persistConfigs() {
    try {
        const result = await api.persistConfigs();

        if (result.ok) {
            showAlert('config-alert', 'Configurations saved to file successfully!', 'success');
        } else {
            showAlert('config-alert', 'Error saving configurations: ' + result.error, 'error');
        }
    } catch (error) {
        showAlert('config-alert', 'Error saving configurations: ' + error.message, 'error');
    }
}

// rsync daemon status ---------------------------------------------------------
//
// The daemon that carries the peer-to-peer transport. It belongs here and not
// into the file browser: it is a property of the installation, not of a folder.
//
// Everything below builds its markup at runtime — `static/index.html` has no
// place for it, and the panel has to work without touching that file. Only
// classes that already exist in the stylesheet are used: Tailwind runs as the
// browser build and generates utilities it finds in the *static* DOM, so a
// class that appears nowhere but here would have no rules behind it. daisyUI
// arrives as a plain stylesheet and is complete, hence `badge-*`/`alert-*` are
// safe.
//
// Every value comes from the server and goes in through `textContent`. That
// matters most for `last_error`: it carries daemon output, i.e. text this
// application never wrote.

const RSYNCD_POLL_MS = 5000;

// Guards against a slow answer overwriting a newer one — the panel refreshes
// on every open of the configuration section and on a timer.
let rsyncdRequestId = 0;
let rsyncdPollTimer = null;

// The fields of the detail grid, created once and then only written to.
const rsyncdFields = {};

function setHidden(element, hidden) {
    element.style.display = hidden ? 'none' : '';
}

function rsyncdDetailRow(parent, label) {
    const row = document.createElement('div');
    row.className = 'flex items-center justify-between gap-2 text-sm';

    const name = document.createElement('span');
    name.className = 'text-base-content/70';
    name.textContent = label;

    const value = document.createElement('span');
    value.className = 'font-semibold';
    value.textContent = '–';

    row.appendChild(name);
    row.appendChild(value);
    parent.appendChild(row);

    return { row, value };
}

// Build the card once and hang it under the configuration section. Idempotent:
// `loadConfigs()` runs on every open of the section.
function ensureRsyncdCard() {
    if (document.getElementById('rsyncd-card')) {
        return;
    }

    const section = document.getElementById('config-section');
    if (!section) {
        return;
    }

    const card = document.createElement('div');
    card.id = 'rsyncd-card';
    card.className = 'card bg-base-100 shadow-xl mt-6';

    const body = document.createElement('div');
    body.className = 'card-body';
    card.appendChild(body);

    // Header: title, state badge, manual refresh.
    const header = document.createElement('div');
    header.className = 'flex flex-wrap items-center justify-between gap-2 mb-4';

    const title = document.createElement('h2');
    title.className = 'card-title text-2xl';
    title.textContent = 'rsync Daemon';

    const badge = document.createElement('span');
    badge.id = 'rsyncd-badge';
    badge.className = 'badge badge-sm badge-ghost';
    badge.textContent = 'checking…';
    title.appendChild(badge);

    const refresh = document.createElement('button');
    refresh.type = 'button';
    refresh.id = 'rsyncd-refresh';
    refresh.className = 'btn btn-sm';
    refresh.textContent = 'Refresh';
    // Event delegation is the house rule; this button is created here and owns
    // its listener directly, which is the same thing without the inline
    // attribute the rule is actually about.
    refresh.addEventListener('click', () => refreshRsyncdStatus());

    header.appendChild(title);
    header.appendChild(refresh);
    body.appendChild(header);

    // One-line summary of the state, in plain words.
    const summary = document.createElement('p');
    summary.id = 'rsyncd-summary';
    summary.className = 'text-sm text-base-content/70';
    summary.textContent = 'Reading the daemon status…';
    body.appendChild(summary);

    // The prominent part: whatever the daemon last complained about. The
    // chroot failure lands here, and it cannot be detected at start-up —
    // rsync chroots per connection, so this display is the only warning
    // anybody gets before a transfer fails.
    const error = document.createElement('div');
    error.id = 'rsyncd-error';
    error.className = 'alert alert-error mt-3';
    // Visibility is an inline style, not a class: `.alert` and `.grid` set
    // `display` themselves, and which of two same-specificity rules wins would
    // depend on the order daisyUI and the Tailwind browser build happen to
    // inject their sheets. An inline style has no such argument to lose.
    setHidden(error, true);

    const errorLabel = document.createElement('span');
    errorLabel.className = 'font-bold';
    errorLabel.textContent = 'Last error:';

    const errorText = document.createElement('span');
    errorText.id = 'rsyncd-error-text';
    // Daemon output: multi-line, arbitrarily long, and not ours. Inline styles
    // rather than utility classes — see the note above about Tailwind.
    errorText.style.whiteSpace = 'pre-wrap';
    errorText.style.wordBreak = 'break-word';

    error.appendChild(errorLabel);
    error.appendChild(errorText);
    body.appendChild(error);

    // Details, only meaningful while the daemon is switched on.
    const detail = document.createElement('div');
    detail.id = 'rsyncd-detail';
    detail.className = 'grid lg:grid-cols-2 gap-2 mt-3';
    setHidden(detail, true);

    rsyncdFields.address = rsyncdDetailRow(detail, 'Address');
    rsyncdFields.port = rsyncdDetailRow(detail, 'Port');
    rsyncdFields.modules = rsyncdDetailRow(detail, 'Active modules');
    rsyncdFields.connections = rsyncdDetailRow(detail, 'Connections');
    rsyncdFields.pid = rsyncdDetailRow(detail, 'Process ID');
    rsyncdFields.restarts = rsyncdDetailRow(detail, 'Restarts');
    rsyncdFields.zombies = rsyncdDetailRow(detail, 'Zombie children');

    body.appendChild(detail);
    section.appendChild(card);

    startRsyncdPolling();
}

// Keeps the panel current without a reload. Deliberately cheap: the request
// only goes out while the card is actually on screen — the configuration
// section is hidden most of the time, and a poller running behind a closed
// panel would produce nothing but log noise.
function startRsyncdPolling() {
    if (rsyncdPollTimer !== null) {
        return;
    }

    rsyncdPollTimer = window.setInterval(() => {
        if (document.hidden) {
            return;
        }

        const card = document.getElementById('rsyncd-card');
        // No layout boxes means an ancestor is display:none — the panel is
        // closed or another section is showing.
        if (!card || card.getClientRects().length === 0) {
            return;
        }

        refreshRsyncdStatus();
    }, RSYNCD_POLL_MS);
}

async function refreshRsyncdStatus() {
    if (!document.getElementById('rsyncd-card')) {
        return;
    }

    const requestId = ++rsyncdRequestId;

    let result;
    try {
        result = await api.fetchRsyncdStatus();
    } catch (error) {
        result = { ok: false, data: null, error: error.message, status: 0 };
    }

    // A newer request has already answered.
    if (requestId !== rsyncdRequestId) {
        return;
    }

    renderRsyncdStatus(result);
}

// Three cases, and telling them apart is the whole point of this panel:
//
//   ok && data          the daemon is switched on — running or not
//   ok && data === null the transport is switched off on purpose. The default
//                       installation looks like this, and it must not read as
//                       a fault
//   !ok                 the status could not be read at all
function renderRsyncdStatus(result) {
    const badge = document.getElementById('rsyncd-badge');
    const summary = document.getElementById('rsyncd-summary');
    const detail = document.getElementById('rsyncd-detail');
    const errorBox = document.getElementById('rsyncd-error');
    const errorText = document.getElementById('rsyncd-error-text');

    if (!badge || !summary || !detail || !errorBox || !errorText) {
        return;
    }

    const status = result.ok ? result.data : null;

    // Switched off on purpose: no numbers, no alarm.
    if (result.ok && !status) {
        badge.className = 'badge badge-sm badge-ghost';
        badge.textContent = 'disabled';
        setHidden(detail, true);
        setHidden(errorBox, true);
        errorText.textContent = '';
        // The server explains the switch itself; the environment variable is
        // the part a user can act on.
        const reason = result.error || 'The rsync transport is switched off';
        summary.textContent = (/[.!?]$/.test(reason) ? reason : reason + '.')
            + ' Set RCLONE_GUI_RSYNCD=1 to enable it.';
        return;
    }

    // Could not ask.
    if (!result.ok) {
        badge.className = 'badge badge-sm badge-error';
        badge.textContent = 'unavailable';
        setHidden(detail, true);
        summary.textContent = 'The daemon status could not be read.';
        setHidden(errorBox, false);
        errorText.textContent = result.error || 'unknown error';
        return;
    }

    // Switched on. Running or not, the details are worth showing — the address
    // and the module count say what a peer would reach.
    setHidden(detail, false);

    const modules = Array.isArray(status.modules) ? status.modules : [];
    const active = Array.isArray(status.active_modules) ? status.active_modules : [];

    rsyncdFields.address.value.textContent = status.address || '–';
    rsyncdFields.port.value.textContent = String(status.port);
    rsyncdFields.modules.value.textContent = `${active.length} of ${modules.length}`;
    rsyncdFields.connections.value.textContent = String(status.connections);
    rsyncdFields.pid.value.textContent = status.pid == null ? '–' : String(status.pid);

    // Both count things that are supposed to stay at zero. Highlighted rather
    // than hidden, so a regression is visible instead of merely recorded.
    rsyncdFields.restarts.value.textContent = String(status.restarts);
    rsyncdFields.restarts.value.className = status.restarts > 0 ? 'font-semibold text-warning' : 'font-semibold';

    rsyncdFields.zombies.value.textContent = String(status.zombie_children);
    rsyncdFields.zombies.value.className = status.zombie_children > 0 ? 'font-semibold text-warning' : 'font-semibold';

    if (status.running) {
        badge.className = 'badge badge-sm badge-success';
        badge.textContent = 'running';
        summary.textContent = `Listening on ${status.address}:${status.port},`
            + ` serving ${modules.length} module${modules.length === 1 ? '' : 's'}`
            + ` (${active.length} in use).`;
    } else if (status.already_running_elsewhere) {
        // The one failure a restart cannot fix: port and lock belong to another
        // process.
        badge.className = 'badge badge-sm badge-warning';
        badge.textContent = 'blocked';
        summary.textContent = `Another rsync daemon already holds ${status.address}:${status.port}.`
            + ' This one stays down until that process is gone.';
    } else {
        badge.className = 'badge badge-sm badge-error';
        badge.textContent = 'not running';
        summary.textContent = 'The rsync transport is switched on, but no daemon is running.';
    }

    if (status.last_error) {
        setHidden(errorBox, false);
        // Server text, and daemon output at that — never through innerHTML.
        errorText.textContent = status.last_error;
    } else {
        setHidden(errorBox, true);
        errorText.textContent = '';
    }
}
