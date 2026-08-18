// Sync job list in the panel, the job bar at the bottom edge, and the log
// viewer.
//
// One request feeds all three: `loadSyncJobs()` asks `GET /api/sync` and hands
// the same array to the panel list, to the bar and to the badge in the menu.
// There is no second poller — a job that shows 41 % in the bar and 39 % in the
// panel is the kind of thing nobody can explain afterwards.

import * as api from '../api.js';
import { escapeHtml, showToast } from '../util/dom.js';
import { formatBytes, formatDuration } from '../util/format.js';
import { updateActiveJobBadge } from './menu.js';

// How often the server is actually asked, in milliseconds.
//
// `main.js` calls `loadSyncJobs()` every two seconds and has done so since
// before there was anything to look at. That timer is not owned by this ticket
// and it is not the interesting part anyway: what matters is how often the
// *request* goes out, and that decision belongs where the answer is known —
// here.
//
// While something is running, two seconds is the point: the bar shows a
// progress bar and a transfer rate, and both are worthless if they lag. Once
// every job is terminal, nothing on the server can change on its own, and a
// request every two seconds asks a question whose answer cannot have changed.
// A job started elsewhere (another tab, `--start-task` on the command line) is
// the one thing that can still appear, and ten seconds is soon enough for that.
//
// The earlier bug this guards against was a poll in `sync.js` that never
// stopped; the shape of the mistake is the same, so the rule is written down
// rather than left to the caller.
const ACTIVE_POLL_MS = 2000;
const IDLE_POLL_MS = 10000;

// When the last request went out, and whether the last answer contained a job
// that was still moving. Both are only ever read by `shouldFetchNow()`.
let lastFetchAt = 0;
let sawActiveJob = true;

// A request is skipped, not queued: the next tick asks again, and an answer
// that is at most `IDLE_POLL_MS` old is by definition an answer about jobs
// that have all finished.
function shouldFetchNow() {
    const due = sawActiveJob ? ACTIVE_POLL_MS : IDLE_POLL_MS;
    // A little slack, or a 2000 ms timer and a 2000 ms threshold race each
    // other and every second tick is dropped.
    return Date.now() - lastFetchAt >= due - 250;
}

export async function loadSyncJobs() {
    if (!shouldFetchNow()) {
        return;
    }
    lastFetchAt = Date.now();

    try {
        const result = await api.fetchSyncJobs();

        if (result.ok) {
            sawActiveJob = result.data.some(job => job.terminal !== true);
            displaySyncJobs(result.data);
            updateActiveJobBadge(result.data);
            renderJobBar(result.data);
        }
    } catch (error) {
        // A failed request must not leave the poller convinced that everything
        // is quiet — otherwise a network hiccup during a running job drops the
        // refresh rate for as long as the job lasts.
        sawActiveJob = true;
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
        //
        // `partial` (rsync exit 23/24) gets a colour of its own and not one of
        // its neighbours': green would report a run that lost files as a
        // success, red would raise an alarm over a file that vanished from a
        // live directory while it was being read. It used to fall through to
        // `badge-info` here, which is the same mistake in blue — indistinguishable
        // from a job that has not started yet.
        const statusColor = job.state === 'completed' ? 'badge-success' :
                           job.state === 'partial' ? 'badge-job-partial' :
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
            refreshSyncJobsNow(); // Refresh the job list, past the idle gate
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

// ===========================================================================
// Job bar at the bottom edge (fd3faffe)
// ===========================================================================
//
// Purpose: a running job stays visible without opening the jobs panel. The
// panel remains the full view — log, delete, every job ever run; the bar shows
// only what is happening now and what has just finished.
//
// Three decisions worth knowing:
//
//   1. **Markup and CSS are built here, not in index.html.** The bar is one
//      fixed element and belongs to this module; putting its skeleton in the
//      page would split one feature across two files for no gain. The styling
//      comes from a <style> element injected once, with class names of its own,
//      because Tailwind runs as a browser build and only generates what it
//      finds in the DOM when it scans — a utility class first attached from JS
//      has no rule behind it. The same reason the `.is-open` / `.is-visible`
//      classes elsewhere in this app exist.
//   2. **It must not cover the work area.** The bar is `position: fixed` at the
//      bottom, so while it is visible `document.body` gets a bottom padding of
//      exactly its height, measured after every render. The file list keeps its
//      last row reachable; when the bar goes away the padding goes with it.
//   3. **`partial` is not a shade of green or red.** rsync exits 23 and 24 are
//      terminal but not successful: some files were not transferred. Green
//      would be a lie, red would cry wolf over a file that vanished from a live
//      directory. It gets amber and a half-filled circle, and — unlike the
//      other states — its reason is printed next to it, because the reason is
//      the whole content of the state.
//
// Not implemented, deliberately: **cancelling a job from the bar**. The ticket
// asks for it, but there is no endpoint to call — `src/main.rs` has no cancel
// route, and `JobStatus::Cancelled` in `src/handlers/sync.rs` is marked
// `#[allow(dead_code)]` with the note that the cancel button is a ticket of its
// own. A button that cannot do anything is worse than no button, so there is
// none. The ✕ on a row hides that row from the bar and nothing else — the job
// itself stays in the panel with its log.

const BAR_ID = 'job-bar';
const BAR_STYLE_ID = 'job-bar-style';

// Whether the bar is expanded. Kept across reloads, so a user who folded it
// away does not have to fold it away again on every page load. A literal key
// rather than an entry in `STORAGE_KEYS`: that file is not part of this ticket.
const BAR_OPEN_KEY = 'rclone_gui_job_bar_open';

// How long a finished job stays in the bar.
//
// Two values on purpose. A clean run is worth a short confirmation and then
// the space back. A run that failed or only half succeeded carries a reason
// that the user has to have a chance to read; fifteen seconds is not that
// chance, and the state exists precisely so the outcome is not waved through.
const DONE_TTL_MS = 15000;
const PROBLEM_TTL_MS = 120000;

// Rows the user closed by hand or that outstayed their welcome. Ids only — the
// jobs themselves are untouched and still in the panel.
const dismissed = new Set();

// When a job was first seen in a terminal state. `end_time` from the server
// would be the better source, but it is the server's clock; the bar counts in
// the browser's, which is the one the user is watching.
const finishedAt = new Map();

// Transfer rate, derived. The API carries no speed field, so it is the change
// in `transferred` over the change in wall clock, smoothed: the raw quotient
// between two two-second samples jumps around enough to be unreadable.
const rateSamples = new Map();
const RATE_SMOOTHING = 0.35;

// Jobs this page load has seen in a non-terminal state. The bar reports what
// happened while the user was watching; a job that was already finished when
// the first answer arrived is history and belongs in the panel, not in a strip
// that says "just now".
const sawRunning = new Set();

// The last answer, so a timer can re-render without asking the server again.
let lastJobs = [];
let dismissTimer = null;

// ---------------------------------------------------------------------------
// Chrome
// ---------------------------------------------------------------------------

// Colours are written out rather than taken from daisyUI's variables: the two
// terminal states this bar exists to tell apart must not both end up as
// whatever --color-warning happens to be after a theme change.
const BAR_CSS = `
#${BAR_ID} {
    position: fixed;
    left: 0;
    right: 0;
    bottom: 0;
    z-index: 40;
    display: none;
    background: #ffffff;
    color: #1f2937;
    border-top: 1px solid #d4d8de;
    box-shadow: 0 -2px 10px rgba(0, 0, 0, 0.08);
    font-size: 0.8125rem;
    line-height: 1.35;
}
#${BAR_ID}.is-visible { display: block; }
html[data-theme="dark"] #${BAR_ID} {
    background: #1d232a;
    color: #e5e7eb;
    border-top-color: #2a323c;
    box-shadow: 0 -2px 10px rgba(0, 0, 0, 0.4);
}
#${BAR_ID} .job-bar-head {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    width: 100%;
    padding: 0.4rem 0.85rem;
    background: none;
    border: 0;
    color: inherit;
    font: inherit;
    text-align: left;
    cursor: pointer;
}
#${BAR_ID} .job-bar-head:focus-visible { outline: 2px solid #2563eb; outline-offset: -2px; }
#${BAR_ID} .job-bar-title { font-weight: 600; }
#${BAR_ID} .job-bar-summary { opacity: 0.7; }
#${BAR_ID} .job-bar-caret { margin-left: auto; opacity: 0.6; }
#${BAR_ID} .job-bar-list {
    display: none;
    max-height: 38vh;
    overflow-y: auto;
    padding: 0 0.85rem 0.5rem;
}
#${BAR_ID}.is-open .job-bar-list { display: block; }
#${BAR_ID} .job-bar-row {
    display: grid;
    grid-template-columns: minmax(0, 1fr) auto auto;
    align-items: center;
    gap: 0.15rem 0.6rem;
    padding: 0.4rem 0;
    border-top: 1px solid rgba(128, 128, 128, 0.22);
}
#${BAR_ID} .job-bar-name {
    min-width: 0;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    font-weight: 600;
}
#${BAR_ID} .job-bar-right {
    display: inline-flex;
    align-items: center;
    gap: 0.25rem;
    justify-self: end;
}
#${BAR_ID} .job-bar-stats { opacity: 0.75; white-space: nowrap; font-variant-numeric: tabular-nums; }
#${BAR_ID} .job-bar-hide {
    background: none;
    border: 0;
    color: inherit;
    opacity: 0.55;
    cursor: pointer;
    font: inherit;
    padding: 0 0.25rem;
}
#${BAR_ID} .job-bar-hide:hover { opacity: 1; }
#${BAR_ID} .job-bar-track {
    grid-column: 1 / -1;
    height: 4px;
    border-radius: 2px;
    background: rgba(128, 128, 128, 0.25);
    overflow: hidden;
}
#${BAR_ID} .job-bar-fill {
    display: block;
    height: 100%;
    width: 0;
    border-radius: 2px;
    background: #2563eb;
    transition: width 0.5s ease-in-out;
}
#${BAR_ID} .job-bar-reason {
    grid-column: 1 / -1;
    overflow-wrap: anywhere;
    opacity: 0.9;
}

/* State chips. Shared by the bar and, for the one state that had none, by the
   badge in the panel list. */
.job-chip {
    display: inline-flex;
    align-items: center;
    gap: 0.3rem;
    padding: 0.05rem 0.45rem;
    border-radius: 9999px;
    font-size: 0.72rem;
    font-weight: 600;
    white-space: nowrap;
    color: #ffffff;
}
.job-chip.is-starting  { background: #4b5563; }
.job-chip.is-running   { background: #1d4ed8; }
.job-chip.is-completed { background: #15803d; }
.job-chip.is-partial   { background: #b45309; }
.job-chip.is-failed    { background: #b91c1c; }
.job-chip.is-cancelled { background: #4b5563; }

#${BAR_ID} .job-bar-row.is-completed .job-bar-fill { background: #15803d; }
#${BAR_ID} .job-bar-row.is-partial   .job-bar-fill { background: #b45309; }
#${BAR_ID} .job-bar-row.is-failed    .job-bar-fill { background: #b91c1c; }
#${BAR_ID} .job-bar-row.is-cancelled .job-bar-fill { background: #6b7280; }
#${BAR_ID} .job-bar-row.is-partial .job-bar-reason { color: #b45309; }
#${BAR_ID} .job-bar-row.is-failed  .job-bar-reason { color: #b91c1c; }
html[data-theme="dark"] #${BAR_ID} .job-bar-row.is-partial .job-bar-reason { color: #fbbf24; }
html[data-theme="dark"] #${BAR_ID} .job-bar-row.is-failed  .job-bar-reason { color: #f87171; }

/* The panel list had no colour for 'partial' and fell through to blue. */
.badge-job-partial {
    background-color: #b45309;
    border-color: #b45309;
    color: #ffffff;
}
`;

// Symbol and label per state. The symbols differ in shape, not only in colour:
// ✓ / ◑ / ✕ stay apart on a monochrome screen and for a red-green colour blind
// reader, which is exactly the pair this ticket must not blur.
const STATE_LOOK = {
    starting:  { symbol: '·',  label: 'Starting'  },
    running:   { symbol: '▸',  label: 'Running'   },
    completed: { symbol: '✓',  label: 'Done'      },
    partial:   { symbol: '◑',  label: 'Partial'   },
    failed:    { symbol: '✕',  label: 'Failed'    },
    cancelled: { symbol: '■',  label: 'Cancelled' }
};

function stateOf(job) {
    return STATE_LOOK[job.state] ? job.state : 'starting';
}

function ensureBar() {
    let bar = document.getElementById(BAR_ID);
    if (bar) {
        return bar;
    }

    if (!document.getElementById(BAR_STYLE_ID)) {
        const style = document.createElement('style');
        style.id = BAR_STYLE_ID;
        style.textContent = BAR_CSS;
        document.head.appendChild(style);
    }

    bar = el('div', null);
    bar.id = BAR_ID;
    // A live region: a job finishing is the one thing here a user may be
    // waiting for without looking.
    bar.setAttribute('aria-live', 'polite');

    const head = el('button', 'job-bar-head');
    head.type = 'button';
    head.setAttribute('aria-controls', 'job-bar-list');
    head.appendChild(el('span', 'job-bar-title', 'Jobs'));
    head.appendChild(el('span', 'job-bar-summary', ''));
    head.appendChild(el('span', 'job-bar-caret', '▴'));
    head.addEventListener('click', toggleJobBar);

    const list = el('div', 'job-bar-list');
    list.id = 'job-bar-list';

    bar.appendChild(head);
    bar.appendChild(list);
    document.body.appendChild(bar);

    if (readBarOpen()) {
        bar.classList.add('is-open');
    }

    return bar;
}

function readBarOpen() {
    try {
        return window.localStorage.getItem(BAR_OPEN_KEY) !== '0';
    } catch (error) {
        // Private mode and blocked storage throw here. Expanded is the useful
        // default, and forgetting the choice is not worth an error.
        return true;
    }
}

function toggleJobBar() {
    const bar = document.getElementById(BAR_ID);
    if (!bar) {
        return;
    }
    const open = bar.classList.toggle('is-open');
    try {
        window.localStorage.setItem(BAR_OPEN_KEY, open ? '1' : '0');
    } catch (error) {
        /* see readBarOpen() */
    }
    syncBodyPadding(bar);
}

// The bar is fixed, so it floats over whatever is underneath. Reserving its
// height at the bottom of the document is what keeps the last row of the file
// list reachable. Measured, not guessed: the height depends on how many rows
// are shown and whether the bar is folded.
function syncBodyPadding(bar) {
    const visible = bar.classList.contains('is-visible');
    document.body.style.paddingBottom = visible ? `${bar.offsetHeight}px` : '';
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

// Which jobs the bar shows: everything that is running, plus what has finished
// recently and has not been dismissed. Jobs from an earlier session — finished
// before this page was loaded — are not announced; the bar reports what
// happened while the user was watching, the panel keeps the history.
function jobsForBar(jobs) {
    const now = Date.now();

    return jobs.filter(job => {
        if (dismissed.has(job.id)) {
            return false;
        }
        if (job.terminal !== true) {
            return true;
        }
        const seen = finishedAt.get(job.id);
        if (seen === undefined) {
            return false;
        }
        return now - seen < ttlFor(job);
    });
}

function ttlFor(job) {
    return job.state === 'completed' ? DONE_TTL_MS : PROBLEM_TTL_MS;
}

// Remembers when a job crossed into a terminal state, and forgets jobs that are
// gone from the server so the three maps cannot grow without bound.
function trackLifecycle(jobs) {
    const alive = new Set(jobs.map(job => job.id));

    jobs.forEach(job => {
        if (job.terminal === true && !finishedAt.has(job.id)) {
            // Only jobs this page watched running get a timestamp. One that was
            // already finished when the first answer arrived would otherwise
            // pop up as fresh news on every page load.
            finishedAt.set(job.id, sawRunning.has(job.id) ? Date.now() : 0);
        }
        if (job.terminal !== true) {
            sawRunning.add(job.id);
        }
    });

    [finishedAt, rateSamples].forEach(map => {
        Array.from(map.keys()).forEach(id => {
            if (!alive.has(id)) {
                map.delete(id);
            }
        });
    });
    Array.from(sawRunning).forEach(id => {
        if (!alive.has(id)) {
            sawRunning.delete(id);
        }
    });
    Array.from(dismissed).forEach(id => {
        if (!alive.has(id)) {
            dismissed.delete(id);
        }
    });
}


// Bytes per second, smoothed. Returns null until there are two samples to
// compare — an invented rate in the first two seconds is worse than none.
function transferRate(job) {
    const now = Date.now();
    const previous = rateSamples.get(job.id);
    const transferred = Number(job.transferred) || 0;

    if (!previous) {
        rateSamples.set(job.id, { at: now, transferred: transferred, rate: null });
        return null;
    }

    const seconds = (now - previous.at) / 1000;
    if (seconds < 0.5) {
        return previous.rate;
    }

    // A negative delta means the server restarted its counter; treated as zero
    // rather than as a negative speed.
    const delta = Math.max(0, transferred - previous.transferred);
    const raw = delta / seconds;
    const rate = previous.rate === null
        ? raw
        : previous.rate + RATE_SMOOTHING * (raw - previous.rate);

    rateSamples.set(job.id, { at: now, transferred: transferred, rate: rate });
    return rate;
}

function chip(state) {
    const look = STATE_LOOK[state];
    const node = el('span', `job-chip is-${state}`);
    node.appendChild(el('span', null, look.symbol));
    node.appendChild(el('span', null, look.label));
    return node;
}

function jobRow(job) {
    const state = stateOf(job);
    const row = el('div', `job-bar-row is-${state}`);

    // Every value below comes from the server and goes in as text. `el()` sets
    // textContent; nothing here builds markup from a name or a path.
    row.appendChild(el('span', 'job-bar-name', job.source_name || 'Unknown'));

    const stats = el('span', 'job-bar-stats');
    stats.textContent = statsLine(job, state);
    row.appendChild(stats);

    // Chip and the hide button share one grid cell — the row has three columns
    // and the button is not a fourth one.
    const right = el('span', 'job-bar-right');
    right.appendChild(chip(state));
    row.appendChild(right);

    const track = el('div', 'job-bar-track');
    const fill = el('span', 'job-bar-fill');
    fill.style.width = `${Math.min(100, Math.max(0, Number(job.progress) || 0))}%`;
    track.appendChild(fill);
    row.appendChild(track);

    // The reason is the content of `partial` and of `failed`; `status` carries
    // it (JobStatus serialises the text into that field). For the other states
    // `status` is only the state spelled out and would say nothing twice.
    if (state === 'partial' || state === 'failed') {
        row.appendChild(el('span', 'job-bar-reason', job.status || ''));
    }

    if (job.terminal === true) {
        const hide = el('button', 'job-bar-hide', '✕');
        hide.type = 'button';
        // Named for what it does. It does not cancel and it does not delete.
        hide.title = 'Hide from this bar (the job stays in the jobs panel)';
        hide.setAttribute('aria-label', `Hide ${job.source_name || 'job'} from the job bar`);
        hide.addEventListener('click', () => {
            dismissed.add(job.id);
            renderJobBar(lastJobs);
        });
        right.appendChild(hide);
    }

    return row;
}

function statsLine(job, state) {
    const parts = [`${(Number(job.progress) || 0).toFixed(0)}%`];

    if (job.total) {
        parts.push(`${formatBytes(job.transferred)} / ${formatBytes(job.total)}`);
    } else if (job.transferred) {
        parts.push(formatBytes(job.transferred));
    }

    if (state === 'running') {
        const rate = transferRate(job);
        if (rate !== null && rate > 0) {
            parts.push(`${formatBytes(Math.round(rate))}/s`);
        }

        const elapsed = Math.max(0, Math.floor(Date.now() / 1000) - job.start_time);
        const progress = Number(job.progress) || 0;
        if (progress > 0 && progress < 100 && elapsed > 0) {
            const remaining = (elapsed / progress) * (100 - progress);
            parts.push(`${formatDuration(Math.floor(remaining))} left`);
        }
    } else if (job.terminal === true) {
        const end = job.end_time || Math.floor(Date.now() / 1000);
        parts.push(`in ${formatDuration(Math.max(0, end - job.start_time))}`);
    }

    return parts.join(' · ');
}

export function renderJobBar(jobs) {
    lastJobs = jobs;
    trackLifecycle(jobs);

    const bar = ensureBar();
    const shown = jobsForBar(jobs);

    if (shown.length === 0) {
        bar.classList.remove('is-visible');
        bar.querySelector('.job-bar-list').replaceChildren();
        syncBodyPadding(bar);
        scheduleDismissSweep(jobs);
        return;
    }

    const running = shown.filter(job => job.terminal !== true).length;
    const summary = running > 0
        ? `${running} running`
        : `${shown.length} finished`;
    bar.querySelector('.job-bar-summary').textContent = summary;
    bar.querySelector('.job-bar-caret').textContent = bar.classList.contains('is-open') ? '▾' : '▴';

    // Running jobs first: they are the reason the bar exists, and a finished
    // one must not push them out of sight.
    const order = { running: 0, starting: 0, partial: 1, failed: 1, cancelled: 1, completed: 2 };
    const sorted = shown.slice().sort((a, b) => {
        const byState = (order[stateOf(a)] ?? 3) - (order[stateOf(b)] ?? 3);
        return byState !== 0 ? byState : b.start_time - a.start_time;
    });

    bar.querySelector('.job-bar-list').replaceChildren(...sorted.map(jobRow));
    bar.classList.add('is-visible');
    syncBodyPadding(bar);
    scheduleDismissSweep(jobs);
}

// A finished job leaves the bar on its own schedule, and while nothing is
// running the poll has slowed to ten seconds — so the disappearance gets its
// own timer instead of waiting for the next answer. One timer for the row that
// expires next; it re-renders from the cached list without asking the server.
function scheduleDismissSweep(jobs) {
    if (dismissTimer !== null) {
        window.clearTimeout(dismissTimer);
        dismissTimer = null;
    }

    const now = Date.now();
    let soonest = Infinity;

    jobs.forEach(job => {
        if (job.terminal !== true || dismissed.has(job.id)) {
            return;
        }
        const seen = finishedAt.get(job.id);
        if (!seen) {
            return;
        }
        const left = seen + ttlFor(job) - now;
        if (left > 0 && left < soonest) {
            soonest = left;
        }
    });

    if (soonest !== Infinity) {
        dismissTimer = window.setTimeout(() => {
            dismissTimer = null;
            renderJobBar(lastJobs);
        }, soonest + 50);
    }
}

// Past the idle gate: used where something just changed and waiting up to ten
// seconds for the next tick would look like nothing happened.
export function refreshSyncJobsNow() {
    lastFetchAt = 0;
    sawActiveJob = true;
    return loadSyncJobs();
}

// A job the user just started must appear at once. `api.js` announces it; see
// SYNC_STARTED_EVENT there for why this is an event and not a call.
window.addEventListener(api.SYNC_STARTED_EVENT, () => {
    refreshSyncJobsNow();
});
