// Remote pane: the right half of the sync mode.
//
// This is a *navigator*, not a second file browser. It lists folders, walks
// into them and shows which folder is the current sync target. Files appear so
// the user can see what is already there, but they are inert: no preview, no
// download, no selection, not even a path in the DOM. Everything the left
// browser can do beyond navigation is deliberately absent here.
//
// The module builds its own markup inside #remote-pane at mount time. That
// keeps static/index.html free of a second copy of the browser skeleton and it
// is the only way to add markup without touching a file another ticket owns.
// Only classes that already exist in the static DOM are used — the browser
// build of Tailwind generates nothing it cannot find there, and .fb-*/.ws-*
// come from the <style> block.
//
// Names and paths on this side come from a remote and are therefore attacker
// controlled. The whole pane is built with createElement/textContent; there is
// no innerHTML in this file at all, and no path is ever interpolated into
// markup. A folder called `<img src=x onerror=…>` is a label, nothing else.

import { registerRemotePane, getSyncBackend, onSyncBackendChange } from './syncmode.js';
import { fetchRemoteFiles } from '../api.js';

// ---------------------------------------------------------------------------
// Data source
// ---------------------------------------------------------------------------
//
// The pane never talks to the server itself. It asks whatever object was
// handed to setRemoteSource() — the follow-up ticket "Remote-Pane: rclone als
// Datenquelle" replaces the stub below with an implementation backed by
// /api/files/remote.
//
//   setRemoteSource({
//       // Optional. When true the pane shows a hint instead of a listing as
//       // long as no target is selected. The stub leaves it false.
//       requiresTarget: true,
//
//       // Required. Lists one folder.
//       //   request: { target: string, backend: string, path: string }
//       //     target  – the chosen remote/peer ('' when none is selected)
//       //     backend – 'rclone' | 'rsync'
//       //     path    – folder to list, '/' for the root
//       //
//       //   resolves to RemoteListing:
//       //     {
//       //       path:     string,               // canonical path of the folder
//       //       parent:   string | null,        // null in the root
//       //       segments: [{ name, path }],     // optional, derived when absent
//       //       entries:  [{ name, path, is_dir, size, modified }]
//       //     }
//       //
//       //   Failures: either reject with an Error, or resolve with the
//       //   ApiResponse-shaped `{ ok: false, error: '…' }` that api.js
//       //   produces. Both are rendered as an error state.
//       async list(request) { … }
//   })
//
// Entries with `is_dir === false` are shown but never become navigable, so a
// source may include or omit them freely.
//
// The default source is rclone (see below). initRemotePane() installs it; the
// stub tree that stood here while the pane was built is gone. A test may still
// swap in its own source through setRemoteSource().
let remoteSource = null;

export function setRemoteSource(source) {
    remoteSource = source || null;
    if (elements.root) {
        loadRemotePath('/');
    }
}

export function getRemoteSource() {
    return remoteSource || rcloneSource;
}

// The currently displayed folder — the sync target of this pane.
export function getRemoteTargetPath() {
    return view.path;
}

// --- rclone source ----------------------------------------------------------
//
// Backed by GET /api/files/remote, which runs `rclone lsjson <remote>:<path>`
// against data/cfg/rclone.conf. The endpoint answers with a bare array of
// entries — no path, no parent, no breadcrumb — so the RemoteListing frame
// around it is built here.
//
// The remote name is **not** taken from the request: it is looked up in the
// configured targets that syncmode.js derives from /api/configs. A value that
// is not in that list never reaches the server. That is the client-side half
// of "the remote comes from the configuration"; the server-side half is not in
// this ticket's files.
const rcloneSource = {
    requiresTarget: true,

    async list(request) {
        const remote = configuredRemoteName(request.backend, request.target);
        if (!remote) {
            throw new Error('No configured rclone remote selected.');
        }

        const path = normalisePath(request.path);
        const result = await fetchRemoteFiles(remote, path);

        // Envelope straight through on failure — loadRemotePath() renders
        // `{ ok: false, error }` as the error state.
        if (!result || result.ok !== true) {
            return result;
        }

        const raw = Array.isArray(result.data) ? result.data : [];

        return {
            path: path,
            parent: parentPath(path),
            entries: raw.map(entry => remoteEntry(path, entry)).filter(entry => entry !== null)
        };
    }
};

// Only a name that the configuration actually knows may be sent to the server.
// `getSyncBackend().targets` is built from state.configs (the answer of
// /api/configs), so an entry there is by definition a configured remote; the
// character check below only guards against a name that could be read as
// something other than a remote (`:local:` and friends, a path separator).
function configuredRemoteName(backend, target) {
    const selection = getSyncBackend();

    if (backend !== 'rclone' || selection.backend !== 'rclone') {
        return '';
    }
    if (!target || !selection.targets.some(candidate => candidate.value === target)) {
        return '';
    }
    if (target.includes(':') || target.includes('/') || target.includes('\\')) {
        return '';
    }

    return target;
}

// One entry of the lsjson answer, mapped onto the RemoteListing shape.
//
// The path is derived from the folder we asked for plus the name, not taken
// from the answer: a remote is attacker controlled and a crafted `Path` could
// otherwise make the pane navigate somewhere the breadcrumb does not show. For
// the same reason a name that is not a single path segment is dropped.
function remoteEntry(basePath, entry) {
    if (!entry || typeof entry !== 'object') {
        return null;
    }

    const name = String(entry.name == null ? '' : entry.name);
    if (name === '' || name === '.' || name === '..' || name.includes('/') || name.includes('\\')) {
        return null;
    }

    return {
        name: name,
        path: joinPath(basePath, name),
        is_dir: !!entry.is_dir,
        size: entry.size,
        // rclone reports ModTime as an ISO string; formatTimestamp() also
        // accepts epoch seconds/milliseconds, so both kinds of source work.
        modified: entry.modified
    };
}

// ---------------------------------------------------------------------------
// Module state
// ---------------------------------------------------------------------------

// How many rows go into the DOM per step. Same reasoning as in the file
// browser: a remote folder with thousands of entries must not build thousands
// of nodes before the first paint.
const RENDER_CHUNK = 200;

const elements = {
    root: null,
    up: null,
    reload: null,
    breadcrumb: null,
    target: null,
    list: null
};

const view = {
    // Folder currently shown; this is what the pane reports as sync target.
    path: '/',
    parent: null,
    cursor: { entries: [], index: 0 },
    fillScheduled: false,
    // Request-ID guard: only the newest listing may render. Two clicks in
    // quick succession used to let the slower answer overwrite the faster one.
    token: 0
};

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

export function initRemotePane() {
    // The real data source, installed through the documented entry point.
    setRemoteSource(rcloneSource);

    // No onBackendChange hook: the pane subscribes with onSyncBackendChange()
    // instead, which also fires while the pane is hidden. Having both would
    // load the root twice for every switch.
    registerRemotePane({
        mount: mountRemotePane,
        onShow: onRemotePaneShow
    });
}

function mountRemotePane(container) {
    buildSkeleton(container);
    watchBackendControls();
    loadRemotePath('/');
}

function onRemotePaneShow() {
    // Nothing to re-measure: the pane has no observer and no lazy media. A
    // listing that failed while the pane was hidden is retried here, otherwise
    // the user would have to hunt for the reload button.
    if (elements.list && elements.list.dataset.state === 'error') {
        loadRemotePath(view.path);
    }
}

// ---------------------------------------------------------------------------
// Skeleton
// ---------------------------------------------------------------------------

function buildSkeleton(container) {
    const root = createElement('div');

    // Toolbar --------------------------------------------------------------
    const toolbar = createElement('div', 'fb-toolbar');

    elements.up = createElement('button', 'btn btn-sm', '⬆ Up');
    elements.up.type = 'button';
    elements.up.title = 'Go up one folder';
    elements.up.addEventListener('click', () => {
        if (view.parent != null) {
            loadRemotePath(view.parent);
        }
    });

    elements.reload = createElement('button', 'btn btn-sm btn-ghost', '⟳');
    elements.reload.type = 'button';
    elements.reload.title = 'Reload folder';
    elements.reload.addEventListener('click', () => loadRemotePath(view.path));

    const spacer = createElement('div', 'fb-spacer');
    const note = createElement('span', 'text-sm opacity-70', 'Folders only — files are read-only here');

    toolbar.append(elements.up, elements.reload, spacer, note);

    // Target bar -----------------------------------------------------------
    //
    // The one thing this pane has to answer at a glance: where does the sync
    // go. It sits above the breadcrumb, is filled through textContent and is
    // updated on every successful navigation.
    const targetBar = createElement('div', 'bg-base-200 rounded-lg p-3 mb-4 flex items-center gap-2');
    targetBar.append(createElement('span', 'badge badge-info badge-sm', 'Sync target'));

    elements.target = createElement('span', 'font-semibold fb-name');
    elements.target.id = 'rp-target-path';
    targetBar.append(elements.target);
    targetBar.setAttribute('role', 'status');

    // Breadcrumb -----------------------------------------------------------
    const breadcrumbBox = createElement('div', 'breadcrumbs text-sm mb-4');
    elements.breadcrumb = createElement('ul', 'bg-base-200 rounded-lg p-3');
    elements.breadcrumb.id = 'rp-breadcrumb';
    elements.breadcrumb.addEventListener('click', handleBreadcrumbClick);
    breadcrumbBox.append(elements.breadcrumb);

    // Listing --------------------------------------------------------------
    const listBox = createElement('div', 'overflow-x-auto');

    const head = createElement('div', 'fb-head');
    head.append(
        createElement('div'),
        createElement('div', null, 'Name'),
        createElement('div', 'fb-size', 'Size'),
        createElement('div', 'fb-modified', 'Modified'),
        createElement('div')
    );

    elements.list = createElement('div', 'max-h-96 overflow-y-auto');
    elements.list.id = 'rp-list';
    elements.list.addEventListener('click', handleListClick);
    elements.list.addEventListener('keydown', handleListKeydown);
    elements.list.addEventListener('scroll', scheduleFill);

    listBox.append(head, elements.list);

    root.append(toolbar, targetBar, breadcrumbBox, listBox);

    container.replaceChildren(root);
    elements.root = root;
}

// ---------------------------------------------------------------------------
// Backend / target
// ---------------------------------------------------------------------------
//
// The backend switch and the target select live *above* #remote-pane and
// belong to the mode ticket. The pane does **not** read them out of the DOM
// any more (`#ws-target`, `[data-sync-backend][aria-pressed]`): syncmode.js
// owns that markup and offers getSyncBackend()/onSyncBackendChange() as the
// stable contract. A markup rebuild up there no longer changes what is listed
// down here.
//
// getSyncBackend() also carries the reason a listing is not possible, and the
// three cases stay apart:
//
//   'unavailable'  — the backend does not exist in this build (rsync pairing)
//   'unconfigured' — the backend works, but no target is configured at all
//   'no-target'    — targets exist, the user has not picked one
//
// None of them is an empty folder, and an empty folder is none of them: a
// remote that answers with zero entries renders "This folder is empty."

function currentSelection() {
    return getSyncBackend();
}

// Message and list state per reason. Kept next to each other so it stays
// obvious that the three are distinct states and not one shared "nothing here".
const NOT_READY = {
    unavailable: {
        state: 'unavailable',
        message: 'This backend is not available yet, so there is nothing to browse.'
    },
    unconfigured: {
        state: 'unconfigured',
        message: 'No target is configured for this backend. Add one to browse it.'
    },
    'no-target': {
        state: 'no-target',
        message: 'Choose a target above to browse it.'
    }
};

function watchBackendControls() {
    let previous = null;

    // Fires immediately with the current selection; the initial call is
    // swallowed here because mountRemotePane() loads the root anyway.
    onSyncBackendChange(selection => {
        const key = selection.backend + ' ' + selection.target + ' ' + selection.reason;
        const first = previous === null;
        const changed = previous !== key;
        previous = key;

        if (!first && changed && elements.root) {
            loadRemotePath('/');
        }
    });
}

// ---------------------------------------------------------------------------
// Loading
// ---------------------------------------------------------------------------

export async function loadRemotePath(path) {
    if (!elements.list) {
        return;
    }

    const source = getRemoteSource();
    const selection = currentSelection();
    const target = selection.target;

    if (source.requiresTarget && !selection.ready) {
        const notReady = NOT_READY[selection.reason] || NOT_READY['no-target'];

        // A stale answer that is still in flight must not overwrite this.
        view.token++;
        view.path = normalisePath(path);
        view.parent = null;
        renderTarget(null);
        renderBreadcrumb([]);
        setListMessage(notReady.message, notReady.state);
        updateUpButton();
        return;
    }

    const token = ++view.token;
    setListMessage('Loading …', 'loading');

    let listing = null;
    try {
        listing = await source.list({
            target: target,
            backend: selection.backend,
            path: normalisePath(path)
        });
    } catch (error) {
        if (token === view.token) {
            setListMessage('Folder could not be loaded: ' + (error && error.message ? error.message : error), 'error');
        }
        return;
    }

    // A slower answer for a folder the user already left must not win.
    if (token !== view.token) {
        return;
    }

    // api.js hands back `{ ok, data, error }`; a source may pass that through
    // unchanged instead of unwrapping it.
    if (listing && listing.ok === false) {
        setListMessage('Folder could not be loaded: ' + (listing.error || 'unknown error'), 'error');
        return;
    }
    if (listing && listing.ok === true && listing.data) {
        listing = listing.data;
    }
    if (!listing || !Array.isArray(listing.entries)) {
        setListMessage('The remote returned an unusable listing.', 'error');
        return;
    }

    view.path = normalisePath(listing.path != null ? listing.path : path);
    view.parent = listing.parent != null ? listing.parent : parentPath(view.path);

    renderTarget(target);
    renderBreadcrumb(Array.isArray(listing.segments) ? listing.segments : segmentsFor(view.path));
    renderEntries(listing.entries);
    updateUpButton();
}

function updateUpButton() {
    if (elements.up) {
        elements.up.disabled = view.parent == null;
    }
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

function renderTarget(target) {
    if (!elements.target) {
        return;
    }
    // textContent, not innerHTML: the path comes from the remote.
    elements.target.textContent = target ? `${target}:${view.path}` : view.path;
    elements.target.title = elements.target.textContent;
}

function renderBreadcrumb(segments) {
    if (!elements.breadcrumb) {
        return;
    }

    const items = segments.map((segment, index) => {
        const item = createElement('li');
        const isLast = index === segments.length - 1;
        const label = index === 0 ? `☁️ ${segment.name}` : segment.name;

        if (isLast) {
            item.append(createElement('span', 'font-semibold', label));
        } else {
            const link = createElement('a', 'cursor-pointer', label);
            // dataset, not an onclick attribute: the value is never parsed as
            // markup or as code.
            link.dataset.path = segment.path;
            item.append(link);
        }

        return item;
    });

    elements.breadcrumb.replaceChildren(...items);
}

function renderEntries(entries) {
    const sorted = sortEntries(entries);

    elements.list.dataset.state = 'ok';
    elements.list.replaceChildren();
    elements.list.scrollTop = 0;
    view.cursor = { entries: sorted, index: 0 };

    if (sorted.length === 0) {
        // Its own state, never one of the NOT_READY ones: an empty folder on a
        // configured target is a successful listing, not a missing target.
        elements.list.dataset.state = 'empty';
        elements.list.append(createElement('div', 'fb-message', 'This folder is empty.'));
        return;
    }

    fillViewport();
}

// Folders first, then files, each group by name. The remote side has no sort
// controls on purpose — it is a navigator.
function sortEntries(entries) {
    return entries.slice().sort((a, b) => {
        if (!!a.is_dir !== !!b.is_dir) {
            return a.is_dir ? -1 : 1;
        }
        return String(a.name).localeCompare(String(b.name), undefined, { numeric: true, sensitivity: 'base' });
    });
}

function appendNextChunk() {
    if (view.cursor.index >= view.cursor.entries.length) {
        return false;
    }

    const slice = view.cursor.entries.slice(view.cursor.index, view.cursor.index + RENDER_CHUNK);
    view.cursor.index += slice.length;

    elements.list.append(...slice.map(entryRow));

    return view.cursor.index < view.cursor.entries.length;
}

function fillViewport() {
    if (!elements.list) {
        return;
    }

    for (let step = 0; step < 20; step++) {
        const rect = elements.list.getBoundingClientRect();
        if (elements.list.scrollHeight - elements.list.scrollTop > rect.height + 300) {
            return;
        }
        if (!appendNextChunk()) {
            return;
        }
    }
}

function scheduleFill() {
    if (view.fillScheduled) {
        return;
    }
    view.fillScheduled = true;
    window.requestAnimationFrame(() => {
        view.fillScheduled = false;
        fillViewport();
    });
}

// One row. Built from elements, never from a string — the name is remote data.
//
// The difference between the two kinds of row is structural, not cosmetic:
// a file row carries no data-path and no data-nav, so the delegated handler
// has nothing to act on even if it were reached. There is no code path from a
// file row to a preview, a download or a fetch.
function entryRow(entry) {
    const isDir = !!entry.is_dir;
    const row = createElement('div', isDir ? 'fb-row fb-clickable' : 'fb-row');

    if (isDir) {
        row.dataset.nav = '1';
        row.dataset.path = entry.path != null ? entry.path : joinPath(view.path, entry.name);
        // Focusable from script only, like the left browser: a folder with
        // thousands of entries must not swallow the tab order.
        row.tabIndex = -1;
    } else {
        // Inert, and it says so to assistive technology as well.
        row.setAttribute('aria-disabled', 'true');
        // The dimming has to be inline: the pane may not add CSS classes to
        // static/index.html, and a class invented here would not exist.
        row.style.opacity = '0.55';
        row.style.cursor = 'default';
    }

    const icon = createElement('div', 'fb-icon', isDir ? '📁' : '📄');

    const name = createElement('div', 'fb-name');
    name.textContent = entry.name;
    name.title = entry.name;

    const size = createElement('div', 'fb-meta fb-size', isDir ? '—' : formatBytes(entry.size));
    const modified = createElement('div', 'fb-meta fb-modified', formatTimestamp(entry.modified));
    const actions = createElement('div', 'fb-actions');

    row.append(icon, name, size, modified, actions);
    return row;
}

function setListMessage(message, stateName) {
    if (!elements.list) {
        return;
    }

    view.cursor = { entries: [], index: 0 };
    elements.list.dataset.state = stateName;

    const box = createElement('div', stateName === 'error' ? 'fb-message fb-error' : 'fb-message');
    box.textContent = message;
    elements.list.replaceChildren(box);
}

// ---------------------------------------------------------------------------
// Delegated handlers
// ---------------------------------------------------------------------------
//
// One listener on the list instead of one per row, and the only action a row
// can trigger is navigation. There is no second branch — a file row simply
// falls through.

function handleListClick(event) {
    const row = event.target.closest('.fb-row');
    if (!row || row.dataset.nav !== '1') {
        return;
    }
    loadRemotePath(row.dataset.path);
}

function handleListKeydown(event) {
    if (event.key !== 'Enter') {
        return;
    }

    const row = event.target.closest && event.target.closest('.fb-row');
    if (!row || row.dataset.nav !== '1') {
        return;
    }

    event.preventDefault();
    loadRemotePath(row.dataset.path);
}

function handleBreadcrumbClick(event) {
    const link = event.target.closest('[data-path]');
    if (link) {
        loadRemotePath(link.dataset.path);
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
//
// Small local copies instead of imports from util/format.js: that module
// formats for the local file system (fileIcon() knows about local previews)
// and the remote side only needs these two.

function createElement(tag, className, text) {
    const element = document.createElement(tag);
    if (className) {
        element.className = className;
    }
    if (text != null) {
        element.textContent = text;
    }
    return element;
}

function normalisePath(path) {
    const value = String(path == null || path === '' ? '/' : path);
    if (value === '/') {
        return '/';
    }
    const withLeading = value.startsWith('/') ? value : '/' + value;
    return withLeading.endsWith('/') ? withLeading.slice(0, -1) : withLeading;
}

function parentPath(path) {
    const value = normalisePath(path);
    if (value === '/') {
        return null;
    }
    const cut = value.lastIndexOf('/');
    return cut <= 0 ? '/' : value.slice(0, cut);
}

function joinPath(base, name) {
    const value = normalisePath(base);
    return value === '/' ? '/' + name : value + '/' + name;
}

// Root plus one entry per path segment; the last one is the current folder.
function segmentsFor(path) {
    const segments = [{ name: 'Root', path: '/' }];
    let current = '';

    normalisePath(path).split('/').filter(part => part).forEach(part => {
        current += '/' + part;
        segments.push({ name: part, path: current });
    });

    return segments;
}

function formatBytes(bytes) {
    const value = Number(bytes);
    if (!Number.isFinite(value) || value < 0) {
        return '';
    }
    if (value < 1024) {
        return value + ' B';
    }

    const units = ['KB', 'MB', 'GB', 'TB'];
    let size = value / 1024;
    let unit = 0;
    while (size >= 1024 && unit < units.length - 1) {
        size /= 1024;
        unit++;
    }
    return size.toFixed(1) + ' ' + units[unit];
}

// Seconds or milliseconds since the epoch, or an ISO string — remotes are not
// consistent about this.
function formatTimestamp(value) {
    if (value == null || value === '') {
        return '';
    }

    const numeric = Number(value);
    const date = Number.isFinite(numeric) && numeric > 0
        ? new Date(numeric > 1e12 ? numeric : numeric * 1000)
        : new Date(value);

    return Number.isNaN(date.getTime()) ? '' : date.toLocaleString();
}
