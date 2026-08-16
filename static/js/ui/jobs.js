// Sync job list in the panel plus the log viewer.

import * as api from '../api.js';
import { escapeHtml, showToast } from '../util/dom.js';
import { formatBytes, formatDuration } from '../util/format.js';
import { updateActiveJobBadge } from './menu.js';

export async function loadSyncJobs() {
    try {
        const result = await api.fetchSyncJobs();

        if (result.ok) {
            displaySyncJobs(result.data);
            updateActiveJobBadge(result.data);
        }
    } catch (error) {
        console.error('Error loading sync jobs:', error);
    }
}

// Constant icon markup. Everything coming from the server is set with
// textContent below, never interpolated into a template.
const LOG_ICON = '<svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4 mr-1" fill="none" viewBox="0 0 24 24" stroke="currentColor">'
    + '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />'
    + '</svg>';

const TRASH_ICON = '<svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4 mr-1" fill="none" viewBox="0 0 24 24" stroke="currentColor">'
    + '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />'
    + '</svg>';

function el(tag, className, text) {
    const node = document.createElement(tag);
    if (className) {
        node.className = className;
    }
    if (text !== undefined) {
        node.textContent = text;
    }
    return node;
}

function iconButton(className, icon, label, onClick) {
    const button = el('button', className);
    button.innerHTML = icon;
    button.appendChild(document.createTextNode(label));
    button.addEventListener('click', onClick);
    return button;
}

// A row with a left and a right label, used for the three stat lines.
function statRow(className, left, right) {
    const row = el('div', className);
    row.appendChild(el('span', null, left));
    row.appendChild(el('span', null, right));
    return row;
}

function displaySyncJobs(jobs) {
    const syncJobsDiv = document.getElementById('sync-jobs');

    if (jobs.length === 0) {
        syncJobsDiv.innerHTML = '<div class="text-center text-base-content/60 py-8">No sync jobs found.</div>';
        return;
    }

    syncJobsDiv.replaceChildren(...jobs.map(job => {
        // `state` ist der maschinenlesbare Bezeichner des Job-Status
        // (starting/running/completed/failed/cancelled); `status` bleibt der
        // Anzeigetext. Früher wurde hier auf den Anzeigetext verglichen — eine
        // Fehlermeldung wie "Failed to spawn rclone process: …" traf keinen
        // der Zweige und wurde als "info" eingefärbt.
        const statusColor = job.state === 'completed' ? 'badge-success' :
                           job.state === 'failed' ? 'badge-error' :
                           job.state === 'cancelled' ? 'badge-error' :
                           job.state === 'running' ? 'badge-warning' : 'badge-info';

        // Calculate elapsed time - use end_time if available, otherwise current time
        const currentTime = job.end_time || Math.floor(Date.now() / 1000);
        const elapsedSeconds = currentTime - job.start_time;
        const elapsedTime = formatDuration(elapsedSeconds);

        // Calculate estimated remaining time
        let estimatedTimeRemaining = '';
        if (job.state === 'running' && job.progress > 0) {
            const totalEstimatedSeconds = (elapsedSeconds / job.progress) * 100;
            const remainingSeconds = Math.max(0, totalEstimatedSeconds - elapsedSeconds);
            estimatedTimeRemaining = formatDuration(Math.floor(remainingSeconds));
        }

        // Löschbar ist, was der Server als beendet meldet — kein Textvergleich
        // mehr, sonst bleiben Jobs mit ungewohnter Fehlermeldung unlöschbar.
        const isCompleted = job.terminal === true;

        const card = el('div', 'card bg-base-100 shadow-sm');
        const body = el('div', 'card-body py-4 px-5');

        const header = el('div', 'flex items-center justify-between mb-3');
        const headLeft = el('div');
        headLeft.appendChild(el('div', 'font-semibold text-lg', job.source_name || 'Unknown'));
        const meta = el('div', 'flex items-center space-x-2 mt-1');
        meta.appendChild(el('span', `badge ${statusColor}`, job.status));
        meta.appendChild(el('span', 'text-sm text-base-content/70', `ID: ${String(job.id).substring(0, 8)}...`));
        headLeft.appendChild(meta);

        const headRight = el('div', 'text-right');
        headRight.appendChild(el('div', 'text-sm text-base-content/70', 'Progress'));
        headRight.appendChild(el('div', 'text-lg font-bold', `${job.progress.toFixed(1)}%`));

        header.appendChild(headLeft);
        header.appendChild(headRight);
        body.appendChild(header);

        // The bar width is a number from the server; clamped so it can never
        // become a style injection.
        const track = el('div', 'w-full bg-base-300 rounded-full h-3');
        const bar = el('div', 'bg-primary h-3 rounded-full progress-animate');
        bar.style.width = `${Math.min(100, Math.max(0, Number(job.progress) || 0))}%`;
        track.appendChild(bar);
        body.appendChild(track);

        body.appendChild(statRow(
            'flex justify-between text-sm text-base-content/70 mt-2',
            `Transferred: ${formatBytes(job.transferred)}`,
            `Total: ${formatBytes(job.total)}`
        ));
        body.appendChild(statRow(
            'flex justify-between text-sm text-base-content/70 mt-1',
            `Elapsed: ${elapsedTime}`,
            estimatedTimeRemaining ? `Remaining: ${estimatedTimeRemaining}` : ''
        ));

        if (isCompleted) {
            const actions = el('div', 'flex items-center space-x-2 mt-3');
            actions.appendChild(iconButton('btn btn-info btn-sm', LOG_ICON, 'View Log', () => viewSyncLog(job.id)));
            actions.appendChild(iconButton('btn btn-error btn-sm', TRASH_ICON, 'Delete', () => deleteSyncJob(job.id)));
            body.appendChild(actions);
        }

        card.appendChild(body);
        return card;
    }));
}

export async function viewSyncLog(jobId) {
    try {
        const result = await api.fetchSyncLog(jobId);

        if (result.status === 404) {
            showToast('Log file not available - this job was created before logging was enabled. Please restart the server and try a new sync operation.', 'info');
            return;
        }

        if (result.ok) {
            // Create and show log modal
            showLogModal(jobId, result.data);
        } else {
            showToast('Error loading log: ' + result.error, 'error');
        }
    } catch (error) {
        showToast('Error loading log: ' + error.message, 'error');
    }
}

export async function deleteSyncJob(jobId) {
    if (!confirm('Are you sure you want to delete this job and its log file?')) {
        return;
    }

    try {
        const result = await api.deleteSyncJob(jobId);

        if (result.ok) {
            showToast('Job deleted successfully', 'success');
            loadSyncJobs(); // Refresh the job list
        } else {
            showToast('Error deleting job: ' + result.error, 'error');
        }
    } catch (error) {
        showToast('Error deleting job: ' + error.message, 'error');
    }
}

function showLogModal(jobId, logContent) {
    // Create modal dynamically
    const modal = document.createElement('dialog');
    modal.id = 'log-modal';
    modal.className = 'modal';
    modal.innerHTML = `
        <div class="modal-box w-11/12 max-w-4xl">
            <form method="dialog">
                <button class="btn btn-sm btn-circle btn-ghost absolute right-2 top-2">✕</button>
            </form>
            <h3 class="font-bold text-xl mb-4">
                <svg xmlns="http://www.w3.org/2000/svg" class="h-6 w-6 text-info inline mr-2" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                </svg>
                Log for Job ${escapeHtml(String(jobId).substring(0, 8))}...
            </h3>

            <div class="bg-base-300 rounded-lg p-4 max-h-96 overflow-y-auto">
                <pre id="log-modal-content" class="text-sm whitespace-pre-wrap"></pre>
            </div>

            <div class="modal-action">
                <form method="dialog">
                    <button class="btn">Close</button>
                </form>
            </div>
        </div>
    `;

    // The log carries rclone output including file names — the one value in
    // this app an attacker controls most directly. It goes in as text only.
    modal.querySelector('#log-modal-content').textContent = logContent || 'No log content available.';

    // Add modal to page and show it
    document.body.appendChild(modal);
    modal.showModal();

    // Remove modal when closed
    modal.addEventListener('close', () => {
        document.body.removeChild(modal);
    });
}
