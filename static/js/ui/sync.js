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
