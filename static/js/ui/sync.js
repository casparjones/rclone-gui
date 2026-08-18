// Sync modal and the progress dialog that follows a running job.

import { state } from '../state.js';
import * as api from '../api.js';
import { showAlert } from '../util/dom.js';
import { formatBytes } from '../util/format.js';
import { updateRemoteSelect } from './remote.js';

export function openSyncModal(sourcePath) {
    state.currentSyncSource = sourcePath;
    document.getElementById('sync-source').value = sourcePath;
    document.getElementById('sync-modal').showModal();
    updateRemoteSelect();

    // Suggest chunk size based on file/folder
    suggestChunkSize(sourcePath);
}

function suggestChunkSize(sourcePath) {
    // This is a simple heuristic - in a real implementation,
    // you might want to check actual file sizes
    const fileName = sourcePath.split('/').pop().toLowerCase();
    const performanceSelect = document.getElementById('chunk-size');

    if (fileName.includes('video') || fileName.includes('.mp4') || fileName.includes('.avi') || fileName.includes('.mkv')) {
        performanceSelect.value = '32M';
        showAlert('sync-alert', 'Video-Datei erkannt: Aggressives Multi-Threading empfohlen', 'success');
    } else if (fileName.includes('iso') || fileName.includes('.zip') || fileName.includes('.tar')) {
        performanceSelect.value = '64M';
        showAlert('sync-alert', 'Große Archiv-Datei erkannt: Maximum Performance empfohlen', 'success');
    } else {
        performanceSelect.value = '16M';
    }
}

export function closeSyncModal() {
    document.getElementById('sync-modal').close();
    state.currentSyncSource = '';
    state.currentRemotePath = '/';
    state.selectedRemotePath = '/';
    document.getElementById('selected-remote-path').textContent = '/';

    // Alle Auswahlen entfernen - jetzt mit card Selektoren
    document.querySelectorAll('#remote-file-list .card').forEach(item => {
        item.classList.remove('bg-primary/20', 'border-primary');
        item.classList.add('bg-base-200');
    });
}

export async function startSync() {
    const remoteName = document.getElementById('sync-remote').value;

    if (!remoteName) {
        showAlert('sync-alert', 'Please select a remote', 'error');
        return;
    }

    const useMultiThreading = document.getElementById('use-chunking').checked;
    const performanceLevel = document.getElementById('chunk-size').value;

    const syncRequest = {
        source_path: state.currentSyncSource,
        remote_name: remoteName,
        remote_path: state.selectedRemotePath,  // Verwende den ausgewählten Pfad
        use_chunking: useMultiThreading,
        chunk_size: useMultiThreading ? performanceLevel : null
    };

    try {
        const result = await api.startSync(syncRequest);

        if (result.ok) {
            state.currentSyncJobId = result.data;
            closeSyncModal();
            openProgressModal();
            monitorProgress();
        } else {
            showAlert('sync-alert', 'Error starting sync: ' + result.error, 'error');
        }
    } catch (error) {
        showAlert('sync-alert', 'Error starting sync: ' + error.message, 'error');
    }
}

// Progress dialog ------------------------------------------------------------

export function openProgressModal() {
    // Reset icon to spinning state
    setProgressModalIcon('loading');
    document.getElementById('progress-modal').showModal();
}

export function closeProgressModal() {
    document.getElementById('progress-modal').close();
    state.currentSyncJobId = '';
}

function setProgressModalIcon(iconState) {
    const iconContainer = document.getElementById('upload-progress-icon');

    if (iconState === 'loading') {
        iconContainer.innerHTML = `
            <svg xmlns="http://www.w3.org/2000/svg" class="h-6 w-6 text-accent inline mr-2 animate-spin" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
            </svg>
        `;
    } else if (iconState === 'completed') {
        iconContainer.innerHTML = `
            <svg xmlns="http://www.w3.org/2000/svg" class="h-6 w-6 text-success inline mr-2" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
        `;
    } else if (iconState === 'error') {
        iconContainer.innerHTML = `
            <svg xmlns="http://www.w3.org/2000/svg" class="h-6 w-6 text-error inline mr-2" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 14l2-2m0 0l2-2m-2 2l-2-2m2 2l2 2m7-2a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
        `;
    }
}

export async function monitorProgress() {
    if (!state.currentSyncJobId) return;

    try {
        const result = await api.fetchSyncProgress(state.currentSyncJobId);

        if (result.ok) {
            const progress = result.data;
            updateProgressDisplay(progress);

            // `terminal` ist die maschinenlesbare Aussage des Servers, ob der
            // Job fertig ist. Früher stand hier ein Textvergleich auf
            // "Running"/"Starting" — eine Fehlermeldung wie "Failed to spawn
            // rclone process: …" traf keinen der Zweige.
            if (progress.terminal !== true) {
                setTimeout(monitorProgress, 1000);
            }
        }
    } catch (error) {
        console.error('Error monitoring progress:', error);
    }
}

function updateProgressDisplay(progress) {
    document.getElementById('progress-fill').style.width = progress.progress + '%';
    document.getElementById('progress-info').textContent = `Status: ${progress.status}`;
    document.getElementById('progress-details').innerHTML = `
        <p>Progress: ${progress.progress.toFixed(1)}%</p>
        <p>Transferred: ${formatBytes(progress.transferred)}</p>
        <p>Total: ${formatBytes(progress.total)}</p>
    `;

    // Das Icon hängt am maschinenlesbaren `state`
    // (starting|running|completed|failed|cancelled), nicht am Anzeigetext.
    if (progress.state === 'completed') {
        setProgressModalIcon('completed');
    } else if (progress.terminal === true) {
        // Alles andere Beendete ist ein Fehlschlag oder Abbruch — unabhängig
        // davon, wie die Meldung formuliert ist.
        setProgressModalIcon('error');
    } else {
        setProgressModalIcon('loading');
    }
}

// ---------------------------------------------------------------------------
// Sync of the browser selection (toolbar button + confirmation dialog)
// ---------------------------------------------------------------------------
//
// The button in the file-browser toolbar is the second, newer way into a sync:
// it takes what is selected on the left and pushes it into the folder the
// remote pane shows on the right. The old #sync-modal above stays as it is —
// it syncs a single path and is opened from the file list.
//
// The dialog in between is not decoration. A sync is a background run that
// copies a whole tree onto a foreign remote and cannot be undone, so what goes
// where — sources, backend, target remote, target folder, how many entries —
// is named before anything starts.
//
// Everything variable is written with textContent: file names come from the
// file system and are attacker controlled.

import { selectedEntries, selectionCount, clearSelection } from './selection.js';
import { getSyncBackend, onSyncBackendChange } from './syncmode.js';
import { onRemoteTargetChange } from './remotepane.js';
import { showToast } from '../util/dom.js';

// At most this many source paths are listed by name; the rest is counted.
// A selection of a few thousand entries must not turn the dialog into a page.
const MAX_LISTED_SOURCES = 20;

// Last state reported by the remote pane. `listed` is the only trustworthy
// sign that the folder on the right actually exists — a pane showing "choose a
// target above" still reports a path.
let remoteTarget = { path: '/', target: '', backend: '', listed: false };

// True while jobs are being created, so a second click cannot start them twice.
let startInFlight = false;

export function initSelectionSync() {
    const button = document.getElementById('fb-sync');
    if (!button) {
        return;
    }

    button.addEventListener('click', openSyncConfirm);

    onSyncBackendChange(() => updateSyncButton());
    onRemoteTargetChange(info => {
        remoteTarget = info;
        updateSyncButton();
    });
    watchSelection();

    const start = document.getElementById('sync-confirm-start');
    if (start) {
        start.addEventListener('click', startSelectionSync);
    }

    const saveTask = document.getElementById('sync-confirm-save-task');
    if (saveTask) {
        saveTask.addEventListener('change', updateTaskRow);
    }

    updateSyncButton();
}

// The selection lives in selection.js and offers no subscription. Rather than
// reach into that file (it belongs to another ticket) the selection bar is
// observed: it is rewritten on every change of the selection, including
// "clear" and "select all".
function watchSelection() {
    const bar = document.getElementById('fb-selection-bar');
    if (!bar || typeof MutationObserver !== 'function') {
        return;
    }

    const observer = new MutationObserver(() => updateSyncButton());
    observer.observe(bar, {
        attributes: true,
        attributeFilter: ['class'],
        childList: true,
        characterData: true,
        subtree: true
    });
}

// Why the button may or may not be pressed. The title carries the reason: a
// disabled button that does not say what is missing sends people looking.
function syncReadiness() {
    const count = selectionCount();
    const backend = getSyncBackend();
    const targetReady = backend.ready && remoteTarget.listed;

    if (startInFlight) {
        return { enabled: false, title: 'A sync is being started …' };
    }
    if (count === 0 && !targetReady) {
        return { enabled: false, title: 'Select entries and a target folder first' };
    }
    if (count === 0) {
        return { enabled: false, title: 'Select at least one file or folder' };
    }
    if (!backend.available) {
        return { enabled: false, title: 'This sync backend is not available yet' };
    }
    if (!backend.configured) {
        return { enabled: false, title: 'No sync target is configured for this backend' };
    }
    if (!backend.target) {
        return { enabled: false, title: 'Choose a sync target in the right pane' };
    }
    if (!remoteTarget.listed) {
        return { enabled: false, title: 'Open a folder in the right pane to sync into' };
    }

    return {
        enabled: true,
        title: count === 1
            ? `Sync 1 entry to ${backend.target}:${remoteTarget.path}`
            : `Sync ${count} entries to ${backend.target}:${remoteTarget.path}`
    };
}

function updateSyncButton() {
    const button = document.getElementById('fb-sync');
    if (!button) {
        return;
    }

    const readiness = syncReadiness();
    button.disabled = !readiness.enabled;
    button.title = readiness.title;
}

function setConfirmAlert(message, type) {
    const box = document.getElementById('sync-confirm-alert');
    if (!box) {
        return;
    }

    if (!message) {
        box.replaceChildren();
        return;
    }

    // Built as elements, not as markup: the text regularly contains a path or
    // an error string from the server.
    const alert = document.createElement('div');
    alert.className = 'alert ' + (type === 'error' ? 'alert-error' : 'alert-info');
    alert.textContent = message;
    box.replaceChildren(alert);
}

function updateTaskRow() {
    const saveTask = document.getElementById('sync-confirm-save-task');
    const row = document.getElementById('sync-confirm-task-row');
    if (!saveTask || !row) {
        return;
    }
    row.hidden = !saveTask.checked;
}

function openSyncConfirm() {
    if (!syncReadiness().enabled) {
        return;
    }

    const modal = document.getElementById('sync-confirm-modal');
    if (!modal) {
        return;
    }

    const entries = selectedEntries();
    const backend = getSyncBackend();

    const countLabel = document.getElementById('sync-confirm-count');
    if (countLabel) {
        countLabel.textContent = entries.length === 1
            ? '1 entry selected'
            : `${entries.length} entries selected`;
    }

    const list = document.getElementById('sync-confirm-sources');
    if (list) {
        const shown = entries.slice(0, MAX_LISTED_SOURCES).map(entry => {
            const item = document.createElement('li');
            item.className = 'font-mono truncate';
            item.textContent = (entry.is_dir ? '📁 ' : '📄 ') + entry.path;
            return item;
        });
        list.replaceChildren(...shown);
    }

    const more = document.getElementById('sync-confirm-more');
    if (more) {
        const rest = entries.length - MAX_LISTED_SOURCES;
        more.hidden = rest <= 0;
        more.textContent = rest > 0 ? `… and ${rest} more` : '';
    }

    setText('sync-confirm-backend', backend.label || backend.backend);
    setText('sync-confirm-target', backend.target);
    setText('sync-confirm-path', remoteTarget.path);

    // Saving a task carries one name, so it is only offered for a single
    // entry — naming N tasks automatically would invent names nobody asked for.
    const saveTask = document.getElementById('sync-confirm-save-task');
    if (saveTask) {
        saveTask.disabled = entries.length !== 1;
        if (saveTask.disabled) {
            saveTask.checked = false;
        }
    }
    updateTaskRow();

    setConfirmAlert('', 'info');
    modal.showModal();
}

function setText(id, value) {
    const node = document.getElementById(id);
    if (node) {
        node.textContent = value == null ? '' : String(value);
    }
}

// One job per selected entry: /api/sync takes a single source path, and
// nothing in this ticket may change the server. They are started one after the
// other so a failure can be named with its path instead of vanishing in a race.
async function startSelectionSync() {
    if (startInFlight) {
        return;
    }

    const entries = selectedEntries();
    const backend = getSyncBackend();

    if (entries.length === 0 || !backend.ready || !remoteTarget.listed) {
        setConfirmAlert('The selection or the target changed. Close the dialog and try again.', 'error');
        return;
    }

    const useChunking = readChecked('sync-confirm-chunking');
    const chunkSize = document.getElementById('sync-confirm-chunk-size');
    const taskName = taskNameFromForm();
    if (taskName === null) {
        return;
    }

    startInFlight = true;
    updateSyncButton();
    const startButton = document.getElementById('sync-confirm-start');
    if (startButton) {
        startButton.disabled = true;
    }
    setConfirmAlert('Starting …', 'info');

    const started = [];
    const failed = [];

    for (const entry of entries) {
        try {
            const result = await api.startSync({
                source_path: entry.path,
                remote_name: backend.target,
                remote_path: remoteTarget.path,
                use_chunking: useChunking,
                chunk_size: useChunking && chunkSize ? chunkSize.value : null
            });

            if (result.ok) {
                started.push(result.data);
            } else {
                failed.push(`${entry.name}: ${result.error}`);
            }
        } catch (error) {
            failed.push(`${entry.name}: ${error.message}`);
        }
    }

    if (taskName && started.length > 0) {
        await saveAsTask(taskName, entries[0], backend, useChunking, chunkSize);
    }

    startInFlight = false;
    if (startButton) {
        startButton.disabled = false;
    }

    if (started.length === 0) {
        setConfirmAlert('No job was started. ' + failed.join(' · '), 'error');
        updateSyncButton();
        return;
    }

    document.getElementById('sync-confirm-modal').close();
    clearSelection();
    updateSyncButton();

    if (failed.length > 0) {
        showToast(`${started.length} job(s) started, ${failed.length} failed: ${failed.join(' · ')}`, 'error');
    } else {
        showToast(started.length === 1 ? 'Sync job started' : `${started.length} sync jobs started`, 'success');
    }

    // The progress dialog follows one job; with several selected entries that
    // is the first of them. The rest is in the Sync Jobs panel, which refreshes
    // on its own.
    state.currentSyncJobId = started[0];
    openProgressModal();
    monitorProgress();
}

function readChecked(id) {
    const node = document.getElementById(id);
    return !!(node && node.checked);
}

// Returns the task name, '' when none was asked for, or null when the input is
// invalid — the caller then stops and the message is already on screen.
function taskNameFromForm() {
    const saveTask = document.getElementById('sync-confirm-save-task');
    if (!saveTask || !saveTask.checked || saveTask.disabled) {
        return '';
    }

    const input = document.getElementById('sync-confirm-task-name');
    const name = input ? input.value.trim() : '';

    if (!name) {
        setConfirmAlert('Please enter a task name, or uncheck "Also save as task".', 'error');
        return null;
    }
    if (!/^[a-zA-Z0-9_-]+$/.test(name)) {
        setConfirmAlert('A task name may only contain letters, digits, underscore and hyphen.', 'error');
        return null;
    }

    return name;
}

// A failing task must not undo jobs that already run, so it only reports.
async function saveAsTask(name, entry, backend, useChunking, chunkSize) {
    try {
        const result = await api.createTask({
            name: name,
            source_path: entry.path,
            remote_name: backend.target,
            remote_path: remoteTarget.path,
            chunk_size: useChunking && chunkSize ? chunkSize.value : null,
            use_chunking: useChunking
        });

        if (result.ok) {
            showToast(`Task '${name}' saved`, 'success');
        } else {
            showToast('Sync started, but the task was not saved: ' + result.error, 'error');
        }
    } catch (error) {
        showToast('Sync started, but the task was not saved: ' + error.message, 'error');
    }
}

// No entry in main.js: the module is imported there anyway, and wiring itself
// keeps this ticket out of a file three other tickets are editing.
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initSelectionSync, { once: true });
} else {
    initSelectionSync();
}
