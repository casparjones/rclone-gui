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

//
// Creating a folder is the one thing the pane may *write*. It lives in the
// toolbar, never in a row: a row stays what it was — a label plus, for folders,
// a navigation target. Nothing was added to entryRow() for this feature.
//
// Failures are classified instead of being printed. "Connection failed" is the
// same sentence for a remote whose token expired, a folder that was deleted
// underneath the user, a read-only share and a remote that simply never
// answers — four problems with four different remedies. See classifyFailure().

import { registerRemotePane, getSyncBackend, onSyncBackendChange } from './syncmode.js';
import { fetchRemoteFiles, createRemoteFolder } from '../api.js';
// formatBytes is shared with the left browser on purpose: the pane used to carry
// a private copy, and the two disagreed on the same file (67b61d0d).
import { formatBytes } from '../util/format.js';

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
//       //   request: { target, backend, path, signal }
//       //     target  – the chosen remote/peer ('' when none is selected)
//       //     backend – 'rclone' | 'rsync'
//       //     path    – folder to list, '/' for the root
//       //     signal  – AbortSignal, aborted when the pane stops waiting.
//       //               Honouring it is optional: the pane gives up either
//       //               way, the signal only lets the source release the
//       //               request instead of leaving it open.
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
//       async list(request) { … },
//
//       // Optional. Creates one folder. Absent (or not a function) means the
//       // source cannot create folders — the pane then shows the button
//       // disabled together with `mkdirUnavailable` as the reason, instead of
//       // offering an action that cannot work.
//       //   request: { target, backend, path, name, signal }
//       //     path – folder the new one goes into
//       //     name – a single segment, already validated by the pane
//       //   resolves to anything on success (the pane reloads the folder),
//       //   fails like list(): reject, or resolve `{ ok: false, error, status }`.
//       async mkdir(request) { … },
//
//       // Optional. Shown next to the disabled button when mkdir is missing.
//       mkdirUnavailable: 'why not'
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

// Consumers that need to know *when* the shown folder changes. The sync button
// in the left toolbar hangs on this: it may only be live while the pane really
// shows a listed folder, and nothing else tells it apart from a pane that is
// stuck on "choose a target above".
//
// The listener is called immediately with the current state and after every
// load, successful or not:
//
//   { path, target, backend, listed }
//
// `listed` is false while the pane shows a message instead of a listing — a
// path is then still reported, but nothing may be synced into it.
const targetListeners = new Set();

export function onRemoteTargetChange(listener) {
    if (typeof listener !== 'function') {
        return () => {};
    }

    targetListeners.add(listener);
    listener(remoteTargetState());

    return () => targetListeners.delete(listener);
}

function remoteTargetState() {
    const selection = currentSelection();
    return {
        path: view.path,
        target: selection.target,
        backend: selection.backend,
        listed: selection.ready && view.listed
    };
}

function notifyRemoteTarget() {
    const info = remoteTargetState();
    targetListeners.forEach(listener => {
        try {
            listener(info);
        } catch (error) {
            // One broken subscriber must not keep the others from being told.
            console.error('remote target listener failed:', error);
        }
    });
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
//
// --- Creating folders -------------------------------------------------------
//
// `POST /api/files/remote/mkdir` exists on the server and is called through
// `createRemoteFolder()` in api.js. Button, form, validation and the four error
// kinds all run against it.
//
// There is deliberately no kill switch here any more. A source that cannot
// create folders simply omits `mkdir` and sets `mkdirUnavailable` (see the
// source contract at the top of this file); that path stays in place for
// alternative sources. To take the rclone mkdir out of service, drop the
// `mkdir` entry from `rcloneSource` below and give `mkdirUnavailable` the
// reason — the pane then shows the button disabled with that text.

async function rcloneMkdir(request) {
    const remote = configuredRemoteName(request.backend, request.target);
    if (!remote) {
        throw new Error('No configured rclone remote selected.');
    }

    return createRemoteFolder(remote, normalisePath(request.path), request.name, {
        signal: request.signal
    });
}

const rcloneSource = {
    requiresTarget: true,

    mkdir: rcloneMkdir,

    async list(request) {
        const remote = configuredRemoteName(request.backend, request.target);
        if (!remote) {
            throw new Error('No configured rclone remote selected.');
        }

        const path = normalisePath(request.path);
        const result = await fetchRemoteFiles(remote, path, { signal: request.signal });

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

// How long the pane waits for a listing or for a folder to be created before it
// stops waiting. Neither endpoint has a deadline of its own — rclone keeps
// retrying an unreachable remote — and an infinite "Loading …" is exactly the
// failure the user cannot name. See withDeadline().
const REMOTE_TIMEOUT_MS = 20000;

const elements = {
    root: null,
    up: null,
    reload: null,
    newFolder: null,
    mkdirNote: null,
    mkdirForm: null,
    mkdirInput: null,
    mkdirConfirm: null,
    mkdirCancel: null,
    mkdirMessage: null,
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
    token: 0,
    // A folder creation is in flight. Used to keep the form from being fired
    // twice, never to lock the rest of the pane: navigating away while a
    // creation runs is allowed, the answer then only updates the form.
    creating: false,
    // True while the pane really shows a listing (state 'ok' or 'empty').
    // A message — "choose a target", an error — leaves it false.
    listed: false
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

    // The only write action of this pane. It sits in the toolbar and acts on
    // the folder the breadcrumb shows — there is deliberately no per-row
    // "create inside this one", which would need clickable rows.
    elements.newFolder = createElement('button', 'btn btn-sm', '➕ New folder');
    elements.newFolder.type = 'button';
    elements.newFolder.id = 'rp-new-folder';
    elements.newFolder.addEventListener('click', openMkdirForm);

    // Why the button is dead, in the open, instead of a title attribute nobody
    // hovers over. Empty and hidden as long as creating folders works.
    elements.mkdirNote = createElement('span', 'text-xs opacity-70');
    elements.mkdirNote.id = 'rp-mkdir-note';
    elements.mkdirNote.hidden = true;

    const spacer = createElement('div', 'fb-spacer');
    const note = createElement('span', 'text-sm opacity-70', 'Folders only — files are read-only here');

    toolbar.append(elements.up, elements.reload, elements.newFolder, elements.mkdirNote, spacer, note);

    // Creation form --------------------------------------------------------
    //
    // Not a <dialog>: a modal in the top layer would take the folder out of
    // sight, and the pane must not fight the browser's own dialog handling.
    // Not a <form> either — a submit that escapes would reload the page.
    const mkdirBox = buildMkdirForm();

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

    // Six cells, in the order of #file-head in static/index.html: the row grid
    // (.fb-head/.fb-row) has six columns, and a header with five would put
    // "Name" into the 2rem icon column — that was the bug of 67b61d0d. The
    // first cell stays empty on purpose: this pane has no selection, but the
    // column has to be there or head and rows drift apart.
    const head = createElement('div', 'fb-head');
    head.append(
        createElement('div', 'fb-check'),
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

    root.append(toolbar, mkdirBox, targetBar, breadcrumbBox, listBox);

    container.replaceChildren(root);
    elements.root = root;

    updateMkdirAvailability();
}

// ---------------------------------------------------------------------------
// Create folder
// ---------------------------------------------------------------------------

function buildMkdirForm() {
    const box = createElement('div', 'bg-base-200 rounded-lg p-3 mb-4');
    box.id = 'rp-mkdir-form';
    box.hidden = true;

    const row = createElement('div', 'flex items-center gap-2');

    elements.mkdirInput = createElement('input', 'input input-bordered w-full');
    elements.mkdirInput.type = 'text';
    elements.mkdirInput.id = 'rp-mkdir-name';
    elements.mkdirInput.placeholder = 'Folder name';
    elements.mkdirInput.setAttribute('aria-label', 'Name of the new folder');
    elements.mkdirInput.maxLength = 255;
    elements.mkdirInput.autocomplete = 'off';
    elements.mkdirInput.addEventListener('keydown', handleMkdirKeydown);

    elements.mkdirConfirm = createElement('button', 'btn btn-sm btn-primary', 'Create');
    elements.mkdirConfirm.type = 'button';
    elements.mkdirConfirm.id = 'rp-mkdir-confirm';
    elements.mkdirConfirm.addEventListener('click', submitMkdir);

    elements.mkdirCancel = createElement('button', 'btn btn-sm btn-ghost', 'Cancel');
    elements.mkdirCancel.type = 'button';
    elements.mkdirCancel.id = 'rp-mkdir-cancel';
    elements.mkdirCancel.addEventListener('click', () => closeMkdirForm());

    row.append(elements.mkdirInput, elements.mkdirConfirm, elements.mkdirCancel);

    // Everything the form has to say — validation, progress, the classified
    // failure — goes here. It never replaces the listing: a failed creation
    // must not take the folder the user was looking at off the screen.
    elements.mkdirMessage = createElement('div', 'text-sm mt-2');
    elements.mkdirMessage.id = 'rp-mkdir-message';
    elements.mkdirMessage.setAttribute('role', 'status');
    elements.mkdirMessage.hidden = true;

    box.append(row, elements.mkdirMessage);
    elements.mkdirForm = box;

    return box;
}

// The button is only live where creating a folder can mean anything: a source
// that can do it, a target that is selected, and a folder that was actually
// listed. In every other case it is disabled — an enabled button that answers
// with an error is worse than one that says beforehand it cannot help.
function updateMkdirAvailability() {
    if (!elements.newFolder || !elements.list) {
        return;
    }

    const source = getRemoteSource();
    const supported = typeof source.mkdir === 'function';
    const state = elements.list.dataset.state;
    const listed = state === 'ok' || state === 'empty';

    elements.newFolder.disabled = !supported || !listed || view.creating;

    if (!supported) {
        const reason = source.mkdirUnavailable || 'This source cannot create folders.';
        elements.mkdirNote.textContent = reason;
        elements.mkdirNote.hidden = false;
        elements.newFolder.title = reason;
        closeMkdirForm();
        return;
    }

    elements.mkdirNote.textContent = '';
    elements.mkdirNote.hidden = true;
    elements.newFolder.title = listed
        ? 'Create a folder in the folder shown below'
        : 'Available once a folder is listed';
}

function openMkdirForm() {
    if (!elements.mkdirForm || elements.newFolder.disabled) {
        return;
    }

    elements.mkdirForm.hidden = false;
    elements.mkdirInput.value = '';
    elements.mkdirInput.disabled = false;
    elements.mkdirConfirm.disabled = false;
    setMkdirMessage(null);
    elements.mkdirInput.focus();
}

function closeMkdirForm() {
    if (!elements.mkdirForm) {
        return;
    }
    elements.mkdirForm.hidden = true;
    setMkdirMessage(null);
}

function handleMkdirKeydown(event) {
    if (event.key === 'Enter') {
        event.preventDefault();
        submitMkdir();
        return;
    }
    // Escape closes the form, nothing else: there is no dialog in the top
    // layer here, so this cannot collide with the browser's own handling.
    if (event.key === 'Escape') {
        event.preventDefault();
        closeMkdirForm();
        elements.newFolder.focus();
    }
}

// A name is checked here before anything leaves the browser. Not as a security
// measure — the server has to check as well, it is the only side that can — but
// because a rejected name should say what is wrong with it instead of coming
// back as a backend error five seconds later.
function validateFolderName(raw) {
    const name = String(raw == null ? '' : raw).trim();

    if (name === '') {
        return { error: 'Enter a name for the new folder.' };
    }
    if (name === '.' || name === '..') {
        return { error: '"." and ".." are not folder names.' };
    }
    if (name.includes('/') || name.includes('\\')) {
        return { error: 'A folder name cannot contain "/" or "\\". Create the folders one level at a time.' };
    }
    if (/[\u0000-\u001f\u007f]/.test(name)) {
        return { error: 'A folder name cannot contain control characters.' };
    }
    if (name.length > 255) {
        return { error: 'A folder name may be at most 255 characters long.' };
    }

    return { name: name };
}

async function submitMkdir() {
    if (!elements.mkdirForm || view.creating) {
        return;
    }

    const checked = validateFolderName(elements.mkdirInput.value);
    if (checked.error) {
        setMkdirMessage({ tone: 'error', title: 'That name does not work', detail: checked.error });
        elements.mkdirInput.focus();
        return;
    }

    const source = getRemoteSource();
    if (typeof source.mkdir !== 'function') {
        updateMkdirAvailability();
        return;
    }

    const selection = currentSelection();
    const parent = view.path;

    view.creating = true;
    elements.mkdirInput.disabled = true;
    elements.mkdirConfirm.disabled = true;
    elements.newFolder.disabled = true;
    setMkdirMessage({ tone: 'busy', title: 'Creating …', detail: joinPath(parent, checked.name) });

    let failure = null;
    try {
        const result = await withDeadline(signal => source.mkdir({
            target: selection.target,
            backend: selection.backend,
            path: parent,
            name: checked.name,
            signal: signal
        }));

        // A source may pass the api.js envelope through instead of unwrapping.
        if (result && result.ok === false) {
            failure = failureFromEnvelope(result);
        }
    } catch (error) {
        failure = failureFromError(error);
    }

    view.creating = false;
    elements.mkdirInput.disabled = false;
    elements.mkdirConfirm.disabled = false;

    if (failure) {
        // The form stays open with the name still in it: the user can correct
        // it, try again, or cancel. Nothing else in the pane is touched — the
        // listing, the breadcrumb and the toolbar keep working.
        const kind = classifyFailure(failure);
        const described = describeFailure(kind, 'mkdir');
        setMkdirMessage({
            tone: 'error',
            kind: kind,
            title: described.title,
            hint: described.hint,
            detail: failure.message
        });
        updateMkdirAvailability();
        elements.mkdirInput.focus();
        return;
    }

    closeMkdirForm();

    // Show the result rather than claim it: the folder only counts as created
    // once it comes back in a listing.
    await loadRemotePath(parent);
}

function setMkdirMessage(message) {
    if (!elements.mkdirMessage) {
        return;
    }

    if (!message) {
        elements.mkdirMessage.replaceChildren();
        elements.mkdirMessage.hidden = true;
        delete elements.mkdirMessage.dataset.tone;
        delete elements.mkdirMessage.dataset.errorKind;
        return;
    }

    elements.mkdirMessage.dataset.tone = message.tone;
    if (message.kind) {
        elements.mkdirMessage.dataset.errorKind = message.kind;
    } else {
        delete elements.mkdirMessage.dataset.errorKind;
    }

    const parts = [failureBlock(message)];
    elements.mkdirMessage.replaceChildren(...parts);
    elements.mkdirMessage.hidden = false;
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
        const key = selection.backend + '\u001f' + selection.target + '\u001f' + selection.reason;
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
        view.listed = false;
        renderTarget(null);
        renderBreadcrumb([]);
        setListMessage(notReady.message, notReady.state);
        updateUpButton();
        updateMkdirAvailability();
        notifyRemoteTarget();
        return;
    }

    const token = ++view.token;
    setListMessage('Loading …', 'loading');
    updateMkdirAvailability();

    let listing = null;
    try {
        listing = await withDeadline(signal => source.list({
            target: target,
            backend: selection.backend,
            path: normalisePath(path),
            signal: signal
        }));
    } catch (error) {
        if (token === view.token) {
            setListFailure(failureFromError(error));
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
        setListFailure(failureFromEnvelope(listing));
        return;
    }
    if (listing && listing.ok === true && listing.data) {
        listing = listing.data;
    }
    if (!listing || !Array.isArray(listing.entries)) {
        setListFailure({ status: 0, message: 'The remote returned an unusable listing.', kind: 'unusable' });
        return;
    }

    view.path = normalisePath(listing.path != null ? listing.path : path);
    view.parent = listing.parent != null ? listing.parent : parentPath(view.path);
    view.listed = true;

    renderTarget(target);
    renderBreadcrumb(Array.isArray(listing.segments) ? listing.segments : segmentsFor(view.path));
    renderEntries(listing.entries);
    updateUpButton();
    updateMkdirAvailability();
    notifyRemoteTarget();
}

function updateUpButton() {
    if (elements.up) {
        elements.up.disabled = view.parent == null;
    }
}

// ---------------------------------------------------------------------------
// Failures
// ---------------------------------------------------------------------------
//
// Four kinds of failure need four different reactions from the user, and the
// server tells them apart badly: `GET /api/files/remote` answers HTTP 200 with
// `{ success: false, error: "rclone error: <stderr>" }` for everything. So the
// classification works on whatever is available — the HTTP status when there is
// a meaningful one, otherwise the wording rclone produced — and it is kept in
// one function so a new pattern is added in one place.
//
//   timeout   – nothing came back in time. Retry, or check the remote.
//   auth      – the remote refused the credentials (expired OAuth token,
//               rotated key). Reconnecting the remote is the only fix; retrying
//               will fail the same way.
//   not-found – the path is gone. Going up or reloading helps.
//   denied    – the credentials are fine, the operation is not allowed
//               (read-only share, no write permission on the folder).
//   offline   – the browser never reached our own server.
//   unknown   – anything else; shown as-is rather than mislabelled.
//
// The wording is deliberately different per kind: a user who reads "Retry" for
// an expired token retries forever.

const FAILURE_TEXT = {
    timeout: {
        list: {
            title: 'The remote did not answer in time',
            hint: 'It may be unreachable or very slow. Reload to try again — nothing was changed.'
        },
        mkdir: {
            title: 'The remote did not answer in time',
            hint: 'The folder may still have been created. Reload the listing before trying again.'
        }
    },
    auth: {
        list: {
            title: 'The remote rejected the credentials',
            hint: 'The sign-in for this remote has expired. Reconnect it in the configuration — retrying will fail the same way.'
        },
        mkdir: {
            title: 'The remote rejected the credentials',
            hint: 'The sign-in for this remote has expired. Reconnect it in the configuration, then create the folder again.'
        }
    },
    'not-found': {
        list: {
            title: 'This path does not exist on the remote',
            hint: 'It may have been renamed or deleted. Go up one folder or reload.'
        },
        mkdir: {
            title: 'The folder you are in no longer exists',
            hint: 'The parent path is gone on the remote. Reload the listing and pick an existing folder.'
        }
    },
    denied: {
        list: {
            title: 'No permission to read this folder',
            hint: 'The remote allows the connection but not this folder.'
        },
        mkdir: {
            title: 'No permission to write here',
            hint: 'The remote is read-only for these credentials, or this folder does not allow new entries. Pick a different folder.'
        }
    },
    offline: {
        list: {
            title: 'The server could not be reached',
            hint: 'Check the connection to this application, then reload.'
        },
        mkdir: {
            title: 'The server could not be reached',
            hint: 'Nothing was created. Check the connection and try again.'
        }
    },
    unusable: {
        list: {
            title: 'The remote sent an answer that could not be read',
            hint: 'Reload the folder. If it keeps happening the remote is answering something other than a listing.'
        },
        mkdir: {
            title: 'The remote sent an answer that could not be read',
            hint: 'Reload the listing to see whether the folder was created.'
        }
    },
    unknown: {
        list: {
            title: 'The folder could not be loaded',
            hint: 'The exact message from the remote is below.'
        },
        mkdir: {
            title: 'The folder could not be created',
            hint: 'The exact message from the remote is below.'
        }
    }
};

// Rejections: an Error, an AbortError from the deadline below, or whatever a
// foreign source threw.
function failureFromError(error) {
    if (!error) {
        return { status: 0, message: 'unknown error' };
    }

    const message = error.message ? String(error.message) : String(error);

    // Set by withDeadline(); a source that aborts on its own reports the
    // browser's AbortError, which means the same thing here.
    if (error.remoteKind) {
        return { status: 0, message: message, kind: error.remoteKind };
    }
    if (error.name === 'AbortError') {
        return { status: 0, message: message, kind: 'timeout' };
    }
    // fetch() rejects with a TypeError when it never reached the server. That
    // is our own server, not the remote — a different problem entirely.
    if (error.name === 'TypeError') {
        return { status: 0, message: message, kind: 'offline' };
    }

    return { status: 0, message: message };
}

// `{ ok: false, error, status }` from api.js.
function failureFromEnvelope(result) {
    return {
        status: Number(result && result.status) || 0,
        message: (result && result.error) ? String(result.error) : 'unknown error'
    };
}

function classifyFailure(failure) {
    // A kind that was decided at the source (timeout, offline) is not
    // second-guessed by pattern matching.
    if (failure.kind) {
        return failure.kind;
    }

    const status = Number(failure.status) || 0;

    // An HTTP status is unambiguous where it exists, so it wins over the text.
    // 401 is included for completeness only: api.js turns a lost session into a
    // redirect to the login page, so it never arrives here.
    if (status === 408 || status === 504 || status === 524) {
        return 'timeout';
    }
    if (status === 401) {
        return 'auth';
    }
    if (status === 403) {
        return 'denied';
    }
    if (status === 404 || status === 410) {
        return 'not-found';
    }

    const text = String(failure.message || '').toLowerCase();

    if (/timed out|timeout|deadline exceeded|i\/o timeout/.test(text)) {
        return 'timeout';
    }
    // Before the auth patterns: "403 Forbidden" and "permission denied" are
    // about what these credentials may do, not about who they belong to.
    if (/permission denied|access denied|forbidden|\b403\b|read[- ]only|readonly|not writable|write access|insufficient permission|quota/.test(text)) {
        return 'denied';
    }
    if (/unauthori[sz]ed|\b401\b|invalid_grant|invalid_client|invalid_token|token expired|expired token|refresh token|couldn't fetch token|oauth|authentication|bad credentials|login required/.test(text)) {
        return 'auth';
    }
    if (/directory not found|not found|no such file|does not exist|doesn't exist|\b404\b|couldn't find/.test(text)) {
        return 'not-found';
    }
    if (/failed to fetch|networkerror|load failed|connection refused|could not connect|no route to host|name resolution|dns/.test(text)) {
        return 'offline';
    }

    return 'unknown';
}

function describeFailure(kind, context) {
    const entry = FAILURE_TEXT[kind] || FAILURE_TEXT.unknown;
    return entry[context] || entry.list;
}

// Title, hint and the raw message underneath. The raw message is the one part
// that comes from outside and it goes in through textContent like every other
// remote string.
function failureBlock(message) {
    const box = createElement('div');

    box.append(createElement('div', 'font-semibold', message.title));

    if (message.hint) {
        box.append(createElement('div', 'text-sm mt-1', message.hint));
    }
    if (message.detail) {
        const detail = createElement('div', 'text-xs opacity-70 mt-1');
        detail.textContent = message.detail;
        box.append(detail);
    }

    return box;
}

// The error state of the listing. Keeps `data-state="error"` — the state
// vocabulary of the pane does not change — and adds `data-error-kind`, so the
// four kinds are distinguishable in the DOM and not only to a reader.
//
// The toolbar, the breadcrumb and the target bar are left exactly as they were:
// after a failed listing the user is still standing in the last folder that
// worked and can navigate away from the error.
function setListFailure(failure) {
    if (!elements.list) {
        return;
    }

    const kind = classifyFailure(failure);
    const described = describeFailure(kind, 'list');

    view.cursor = { entries: [], index: 0 };
    view.listed = false;
    elements.list.dataset.state = 'error';
    elements.list.dataset.errorKind = kind;

    const box = createElement('div', 'fb-message fb-error');
    box.append(failureBlock({
        title: described.title,
        hint: described.hint,
        detail: failure.message
    }));

    // Retrying is the same button as in the toolbar, put where the error is.
    // It is offered for every kind: even where retrying cannot help, the user
    // is the one who decides to stop.
    const retry = createElement('button', 'btn btn-sm mt-2', '⟳ Try again');
    retry.type = 'button';
    retry.addEventListener('click', () => loadRemotePath(view.path));
    box.append(retry);

    elements.list.replaceChildren(box);
    updateMkdirAvailability();
    notifyRemoteTarget();
}

// Runs `run(signal)` and stops waiting after REMOTE_TIMEOUT_MS.
//
// Two mechanisms, because they cover different things: the signal lets a source
// abort the actual request, and the race makes the pane give up even when the
// source ignores the signal. Without the race a source that never settles would
// leave "Loading …" on screen forever.
function withDeadline(run) {
    const controller = new AbortController();
    let timer = 0;

    const expired = new Promise((resolve, reject) => {
        timer = window.setTimeout(() => {
            controller.abort();

            const error = new Error(`No answer within ${Math.round(REMOTE_TIMEOUT_MS / 1000)} seconds.`);
            error.remoteKind = 'timeout';
            reject(error);
        }, REMOTE_TIMEOUT_MS);
    });

    // Promise.race attaches a handler to the work as well, so a rejection that
    // arrives after the deadline is consumed and not reported as unhandled.
    const work = Promise.resolve().then(() => run(controller.signal));

    return Promise.race([work, expired]).finally(() => window.clearTimeout(timer));
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
    // A successful listing leaves no trace of the previous failure.
    delete elements.list.dataset.errorKind;
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

    // The cells mirror the left browser one for one (browser-render.js): an
    // empty .fb-check, the icon inside a .fb-thumb-box, name, size, modified,
    // actions. Six cells for six grid columns — with five the name landed in
    // the 2rem icon column and was cut after about two characters (67b61d0d).
    //
    // Empty rather than absent: this pane has no selection and no per row
    // action, and the columns are only kept so the name gets the same 1fr and
    // the same ellipsis as on the left.
    const check = createElement('div', 'fb-check');

    const thumb = createElement('div', 'fb-thumb-box');
    thumb.append(createElement('div', 'fb-icon', isDir ? '📁' : '📄'));

    const name = createElement('div', 'fb-name');
    name.textContent = entry.name;
    name.title = entry.name;

    // Size stays a dash for folders: `rclone lsjson` reports whatever the
    // backend has (an inode size for local, -1 for S3), and neither says
    // anything about the folder. The modification time is real, so the column
    // is not empty and both stay.
    // An unknown size reads as an em dash, exactly like a folder: formatBytes
    // returns '' for -1 (object stores) and for a missing value, and an empty
    // cell in the grid looks like a rendering fault.
    const size = createElement('div', 'fb-meta fb-size', isDir ? '—' : (formatBytes(entry.size) || '—'));
    const modified = createElement('div', 'fb-meta fb-modified', formatTimestamp(entry.modified));
    const actions = createElement('div', 'fb-actions');

    row.append(check, thumb, name, size, modified, actions);
    return row;
}

function setListMessage(message, stateName) {
    if (!elements.list) {
        return;
    }

    view.cursor = { entries: [], index: 0 };
    elements.list.dataset.state = stateName;
    // Plain messages carry no kind; only setListFailure() sets one.
    delete elements.list.dataset.errorKind;

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
// formatBytes comes from util/format.js — one formatter for both panes, see the
// import above. formatTimestamp stays local: remotes are inconsistent about the
// unit (seconds, milliseconds, ISO) where the local backend is not.

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
