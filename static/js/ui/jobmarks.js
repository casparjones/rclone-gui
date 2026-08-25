// Job markers on the rows of the file browser (98379f17).
//
// A sync is a background run. Once it is started the dialog closes and the
// selection is cleared, and nothing on the left-hand side says any more which
// entries are currently being copied. This module puts that back: a row whose
// path belongs to a running job carries a marker with the progress, and the
// marker survives a reload.
//
// Three decisions worth knowing.
//
// **1. The server decides which jobs exist, always.**
// `GET /api/sync` is the single source of truth for liveness. What is kept in
// the browser is one thing only: the mapping from a job id to the source path
// it was started for — because the API does not carry it. `SyncProgress`
// (src/models.rs) serialises `source_name`, the *basename*, and two files
// called `report.pdf` in different folders are indistinguishable by it. So the
// path comes from localStorage and the answer to "is this job still running?"
// comes from the server, never the other way round: every id the server does
// not report is dropped from the store, and a stored id whose job is terminal
// produces no marker. A marker can therefore be missing (storage cleared,
// another browser, a job started by `--start-task`) but it can never outlive
// the job it belongs to.
//
// The clean fix for the missing case is a `source_path` field in
// `SyncProgress` — that is `src/`, another ticket's territory, and it is
// reported rather than built here.
//
// **2. No second poller.**
// `ui/jobs.js` already asks `GET /api/sync` — two seconds while something
// runs, ten when everything is terminal — and hands every answer here. A poll
// of its own would double the requests on the same route and drift out of step
// with the job bar, which is the bug this app already had once. A job the user
// just started is announced through the existing `rclone-gui:sync-started`
// event, the same channel `api.js` uses.
//
// **3. Several jobs per action.**
// `POST /api/sync` takes one source path, so N selected entries become N jobs
// (a collective job is ticket f02360bf). Every job is marked on its own row,
// and a path that has more than one job running says how many.

import { SYNC_STARTED_EVENT } from '../api.js';

// Job id -> source path. Written when a sync is started, pruned against every
// server answer. A literal key, like the job bar's: `STORAGE_KEYS` in state.js
// is shared with other tickets.
const STORAGE_KEY = 'rclone_gui_job_sources';

const ROW_CLASS = 'fb-job-active';
const MARK_CLASS = 'fb-job-mark';

// Source path -> the running jobs for it. Rebuilt from every server answer.
let active = new Map();

function readStore() {
    try {
        const parsed = JSON.parse(window.localStorage.getItem(STORAGE_KEY));
        // A hand-edited or truncated value must not take the file browser with
        // it; anything that is not a plain object is treated as empty.
        if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
            return parsed;
        }
    } catch (error) {
        /* private mode, blocked storage, broken JSON — all mean "nothing known" */
    }
    return {};
}

function writeStore(store) {
    try {
        window.localStorage.setItem(STORAGE_KEY, JSON.stringify(store));
    } catch (error) {
        // Storage full or blocked. The markers are then only good for this
        // page load, which is worth no error message.
    }
}

// Called for every job a start created, with the path it was started for.
// Also nudges the existing poller, so the marker appears with the next answer
// instead of up to ten seconds later.
export function rememberJobSource(jobId, sourcePath) {
    if (!jobId || !sourcePath) {
        return;
    }

    const store = readStore();
    store[String(jobId)] = String(sourcePath);
    writeStore(store);

    window.dispatchEvent(new CustomEvent(SYNC_STARTED_EVENT));
}

// Fed with every answer of `GET /api/sync` from ui/jobs.js.
export function updateJobMarks(jobs) {
    const list = Array.isArray(jobs) ? jobs : [];
    const store = readStore();

    // Prune: the server has just listed every job it knows. An id missing from
    // that list is gone (deleted, or lost in a restart) and its path with it —
    // otherwise the store grows for the lifetime of the browser profile.
    const known = new Set(list.map(job => String(job.id)));
    let pruned = false;
    Object.keys(store).forEach(id => {
        if (!known.has(id)) {
            delete store[id];
            pruned = true;
        }
    });
    if (pruned) {
        writeStore(store);
    }

    const next = new Map();
    list.forEach(job => {
        // Terminal is terminal: the marker says "this is happening now", so it
        // goes away the moment the job stops, whatever its outcome was. The
        // result stays in the job bar and in the panel.
        if (job.terminal === true) {
            return;
        }
        const path = store[String(job.id)];
        if (!path) {
            return;
        }
        const bucket = next.get(path);
        if (bucket) {
            bucket.push(job);
        } else {
            next.set(path, [job]);
        }
    });

    active = next;
    applyJobMarks();
}

// Puts the markers on the rows that are in the DOM right now.
//
// Rows arrive chunk by chunk (browser-render.js), so this runs after every
// chunk as well as after every server answer, and it has to be idempotent.
// One pass over the rows and a map lookup per row — no selector is built from
// a path, which would need escaping a file name into CSS.
export function applyJobMarks(root) {
    const scope = root || document;

    // The common case is "nothing is running": then only the rows that still
    // carry a marker have to be touched.
    if (active.size === 0) {
        scope.querySelectorAll('.fb-row.' + ROW_CLASS).forEach(unmarkRow);
        return;
    }

    scope.querySelectorAll('.fb-row[data-path]').forEach(row => {
        const jobs = active.get(row.dataset.path);
        if (jobs) {
            markRow(row, jobs);
        } else if (row.classList.contains(ROW_CLASS)) {
            unmarkRow(row);
        }
    });
}

function markRow(row, jobs) {
    const name = row.querySelector('.fb-name');
    if (!name) {
        return;
    }

    row.classList.add(ROW_CLASS);

    let mark = name.querySelector('.' + MARK_CLASS);
    if (!mark) {
        mark = document.createElement('span');
        mark.className = MARK_CLASS;

        const spinner = document.createElement('span');
        spinner.className = 'fb-job-spin';
        spinner.textContent = '⟳';
        // The glyph is decoration; the percentage next to it is the content.
        spinner.setAttribute('aria-hidden', 'true');
        mark.appendChild(spinner);

        mark.appendChild(document.createElement('span'));
        // The name cell ellipsises its text, so the marker goes in front of the
        // name where it cannot be cut off.
        name.insertBefore(mark, name.firstChild);
    }

    // The smallest progress of the jobs on this path: with several jobs the row
    // is done when the slowest one is, and an average would claim progress the
    // row has not made.
    const percent = jobs.reduce(
        (lowest, job) => Math.min(lowest, Math.min(100, Math.max(0, Number(job.progress) || 0))),
        100
    );

    // Everything here is text. Job data is server data, and the names in this
    // list are attacker controlled — the reason these modules build elements
    // instead of markup.
    const label = mark.lastChild;
    label.textContent = jobs.length === 1
        ? `${percent.toFixed(0)}%`
        : `${jobs.length}× ${percent.toFixed(0)}%`;

    mark.setAttribute(
        'title',
        jobs.length === 1
            ? `Sync running — ${percent.toFixed(0)}%`
            : `${jobs.length} sync jobs running — ${percent.toFixed(0)}%`
    );
}

function unmarkRow(row) {
    row.classList.remove(ROW_CLASS);
    const mark = row.querySelector('.' + MARK_CLASS);
    if (mark) {
        mark.remove();
    }
}
