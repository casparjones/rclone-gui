// Workspace layout: file browser full width vs. the two-column sync mode.
//
// The important property of this module is what it does *not* do: it never
// moves, rebuilds or re-renders the file browser. Both panes and the divider
// exist in static/index.html from the start; switching the mode only toggles a
// class on the workspace element and sets a CSS custom property for the column
// width.
//
// That is deliberate. The browser keeps an IntersectionObserver (root
// #file-list), a chunk cursor into the current listing and the current
// scroll position. Detaching and re-attaching the subtree — or re-rendering it —
// would silently drop the observer registrations and restart the chunking. A
// pure CSS switch leaves all of it untouched; only the width of the scroll
// container changes, which the observer handles on its own.
//
// After a width change more rows can become visible, so scheduleFill() is asked
// for one more pass. It is guarded by state.fillScheduled and appends only what
// is missing, so it can never start a second chunk run in parallel.

import { state, STORAGE_KEYS } from '../state.js';
import { scheduleFill } from './browser-render.js';
import { openMenuPanel } from './menu.js';
import { fetchConfigs } from '../api.js';

const MODES = ['browser', 'sync'];

// Percent of the workspace width the local pane may take. Both panes stay
// usable at the limits, an accidental drag cannot make one of them disappear.
const MIN_RATIO = 20;
const MAX_RATIO = 80;

// Step of the keyboard resize (arrow keys on the focused divider)
const KEY_STEP = 2;

// The right pane belongs to the follow-up tickets (Remote-Pane, multi select).
// They register themselves here instead of this module importing them, the
// same pattern menu.js uses for its section loaders.
//
//   registerRemotePane({
//       mount(container) {}   // once, when the pane is shown for the first time
//       onShow(container) {}  // every time the sync mode becomes active
//       onResize(container) {} // after the divider was dragged or the mode changed
//       onBackendChange(container, selection) {} // backend or target changed
//   })
//
// All four are optional. `selection` is the object getSyncBackend() returns;
// a module that would rather not implement a hook can call getSyncBackend()
// whenever it needs the current choice, or subscribe with
// onSyncBackendChange(listener).
const remotePane = { hooks: null, mounted: false };

export function registerRemotePane(hooks) {
    remotePane.hooks = hooks || null;

    // A module that registers late (after the user already switched) still gets
    // its mount/show callbacks.
    if (isSyncMode()) {
        notifyRemotePane(true);
    }
}

export function isSyncMode() {
    return state.workspaceMode === 'sync';
}

export function initSyncMode() {
    restoreWorkspaceMode();
    restoreSplitRatio();
    restoreBackendSelection();

    document.querySelectorAll('[data-mode]').forEach(button => {
        button.addEventListener('click', () => setWorkspaceMode(button.dataset.mode));
    });

    initDivider();
    initBackendChooser();

    // No fill here: the file browser has not loaded its first listing yet when
    // initSyncMode() runs. Applying the layout first means the very first
    // render already sees the final width.
    applyMode({ notify: true, fill: false });
    applyRatio();
}

// Mode -----------------------------------------------------------------------

function restoreWorkspaceMode() {
    const stored = localStorage.getItem(STORAGE_KEYS.workspaceMode);
    if (MODES.includes(stored)) {
        state.workspaceMode = stored;
    }
}

export function setWorkspaceMode(mode) {
    if (!MODES.includes(mode)) {
        return;
    }

    if (mode === state.workspaceMode) {
        updateModeButtons();
        return;
    }

    state.workspaceMode = mode;
    localStorage.setItem(STORAGE_KEYS.workspaceMode, mode);
    applyMode({ notify: true, fill: true });
}

function applyMode({ notify, fill }) {
    const workspace = document.getElementById('workspace');
    if (workspace) {
        workspace.classList.toggle('is-split', isSyncMode());
    }

    updateModeButtons();

    // Entering sync mode is the moment the chooser becomes visible — remotes
    // may have been added or removed since it was rendered last.
    if (isSyncMode()) {
        refreshTargets();
        // Entering sync mode may find a list that changed while the browser
        // mode was active, so the subscribers are told here too. They compare
        // against what they showed last, a repeated identical selection costs
        // nothing.
        refreshBackendChooser();
    }

    if (notify) {
        notifyRemotePane(true);
    }

    if (fill) {
        afterWidthChange();
    }
}

function updateModeButtons() {
    document.querySelectorAll('[data-mode]').forEach(button => {
        const active = button.dataset.mode === state.workspaceMode;
        // btn-primary appears in the static markup, so the browser build of
        // Tailwind generates it. A class invented here would not exist in CSS.
        button.classList.toggle('btn-primary', active);
        button.classList.toggle('ws-mode-active', active);
        button.setAttribute('aria-pressed', active ? 'true' : 'false');
    });
}

// Backend choice -------------------------------------------------------------
//
// Which transport the right pane offers is a user choice, not a property of the
// browser: rclone syncs into an rclone remote, rsync into another rclone-gui
// instance that has been paired with this one.
//
// The two cases "you have not configured a target yet" and "this build cannot
// do that yet" are kept strictly apart. `available: false` means the backend
// does not exist server-side; an empty target list of an *available* backend
// means the user has to configure one. Reporting the second as the first would
// send the user into a configuration dialog that cannot help them.
const BACKENDS = {
    rclone: {
        id: 'rclone',
        label: 'rclone remote',
        available: true,
        // The configured rclone remotes are the targets. state.configs is
        // filled by ui/config.js; refreshTargets() falls back to a fetch when
        // the app starts up directly in sync mode and the list is not there yet.
        targets: () => state.configs.map(config => ({
            value: config.name,
            label: config.config_type ? `${config.name} (${config.config_type})` : config.name
        })),
        emptyPlaceholder: 'No remote configured',
        // Shown while the list of remotes is still in flight — saying "no
        // remote configured" there would be a claim we cannot back up yet.
        loadingPlaceholder: 'Loading remotes…',
        emptyHint: 'No rclone remote is configured yet. Add one to pick a sync target.',
        // Where the hint jumps to — a section of the menu panel (ui/menu.js)
        configSection: 'config',
        configAction: 'Open Configuration'
    },
    rsync: {
        id: 'rsync',
        label: 'paired instance',
        // Deliberately false: pairing two rclone-gui instances is the subject
        // of the OAuth2 tickets (8b1f4477 provider, d32a90b9 client/pairing)
        // and there is no endpoint for it yet. Flip this to true — and give
        // targets() a real source — once the pairing API exists.
        available: false,
        targets: () => [],
        emptyPlaceholder: 'Not available yet',
        loadingPlaceholder: 'Not available yet',
        unavailableHint:
            'Pairing with another rclone-gui instance is not implemented yet, so there is nothing to select here. '
            + 'The rclone backend is unaffected.',
        configSection: 'config',
        configAction: ''
    }
};

const BACKEND_IDS = Object.keys(BACKENDS);
const DEFAULT_BACKEND = 'rclone';

// Subscribers that want the current choice without implementing a remote-pane
// hook (see onSyncBackendChange).
const backendListeners = new Set();

// Guards the one-shot config fetch below against parallel calls.
let configFetchInFlight = false;

// Whether the target list of the rclone backend is known at all. Until the
// first answer has arrived, an empty state.configs means "not asked yet", not
// "nothing there" — and the difference matters twice: a restored target must
// not be dropped as stale against a list that does not exist yet, and the hint
// box must not claim "nothing configured" while the answer is in flight.
let configsResolved = false;

// True while the target list of `backendId` is still being loaded. Only rclone
// has an asynchronous list; every other backend answers from data that is
// already in memory.
function isTargetListLoading(backendId) {
    return backendId === 'rclone' && !configsResolved;
}

function restoreBackendSelection() {
    const storedBackend = localStorage.getItem(STORAGE_KEYS.syncBackend);
    if (BACKEND_IDS.includes(storedBackend)) {
        state.syncBackend = storedBackend;
    }

    // Unparsable or foreign content is ignored rather than thrown: a broken
    // localStorage entry must not keep the workspace from starting.
    let storedTargets = null;
    try {
        storedTargets = JSON.parse(localStorage.getItem(STORAGE_KEYS.syncTargets) || 'null');
    } catch (error) {
        storedTargets = null;
    }

    if (storedTargets && typeof storedTargets === 'object') {
        BACKEND_IDS.forEach(id => {
            if (typeof storedTargets[id] === 'string') {
                state.syncTargets[id] = storedTargets[id];
            }
        });
    }
}

function persistBackendSelection() {
    localStorage.setItem(STORAGE_KEYS.syncBackend, state.syncBackend);
    localStorage.setItem(STORAGE_KEYS.syncTargets, JSON.stringify(state.syncTargets));
}

// The current choice, in the shape every consumer gets:
//
//   backend     'rclone' | 'rsync'
//   target      the chosen target, '' when none is selected
//   available   the backend exists in this build
//   configured  at least one target exists for it
//   loading     the target list is still being fetched, so `configured` is not
//               an answer yet — a separate field on purpose, see below
//   ready       available && configured && target !== ''  — only then may the
//               right pane actually talk to the target
//   reason      '' when ready, otherwise 'unavailable' or 'unconfigured' or
//               'no-target' (targets exist, none picked)
//
// `loading` is deliberately *not* a fifth `reason`: consumers switch over the
// four known reasons, and a value they have never seen would fall through to
// whatever their default is. Instead the loading case reports the most
// conservative of the existing reasons — 'no-target', the only one that claims
// nothing and renders no hint box — and anyone who wants to tell "not picked"
// from "not known yet" apart reads the flag.
export function getSyncBackend() {
    const backend = BACKENDS[state.syncBackend] || BACKENDS[DEFAULT_BACKEND];
    const targets = backend.available ? backend.targets() : [];
    const target = state.syncTargets[backend.id] || '';
    const configured = targets.length > 0;
    // An empty list of an available backend is only meaningful once the list
    // has actually been fetched.
    const loading = backend.available && !configured && isTargetListLoading(backend.id);

    let reason = '';
    if (!backend.available) {
        reason = 'unavailable';
    } else if (loading) {
        reason = 'no-target';
    } else if (!configured) {
        reason = 'unconfigured';
    } else if (!target) {
        reason = 'no-target';
    }

    return {
        backend: backend.id,
        label: backend.label,
        target,
        targets,
        available: backend.available,
        configured,
        loading,
        ready: !loading && reason === '',
        reason
    };
}

// Subscribe to backend/target changes. Returns the unsubscribe function.
// The listener is called immediately with the current selection, so a late
// subscriber does not have to ask separately.
export function onSyncBackendChange(listener) {
    if (typeof listener !== 'function') {
        return () => {};
    }

    backendListeners.add(listener);
    listener(getSyncBackend());

    return () => backendListeners.delete(listener);
}

export function setSyncBackend(id) {
    if (!BACKEND_IDS.includes(id) || id === state.syncBackend) {
        renderBackendChooser();
        return;
    }

    commitSelection({ backend: id });
}

export function setSyncTarget(value) {
    commitSelection({ target: typeof value === 'string' ? value : '' });
}

// The single path that changes the selection. Writing, persisting, redrawing
// and reporting used to be four separate steps repeated at every call site, and
// the two places that did only some of them are exactly where the pane fell out
// of sync with the chooser. Here they cannot drift apart any more: nobody
// writes state.syncBackend or state.syncTargets outside this function.
//
// Returns true when the selection actually moved — an unchanged commit is a
// no-op and deliberately does not notify.
function commitSelection({ backend, target }) {
    let changed = false;
    let backendChanged = false;

    if (typeof backend === 'string' && BACKEND_IDS.includes(backend) && backend !== state.syncBackend) {
        state.syncBackend = backend;
        backendChanged = true;
        changed = true;
        // A different backend means a different target list; the rclone one may
        // still have to be fetched.
        refreshTargets();
    }

    if (typeof target === 'string' && target !== (state.syncTargets[state.syncBackend] || '')) {
        state.syncTargets[state.syncBackend] = target;
        changed = true;
    }

    if (!changed) {
        return false;
    }

    persistBackendSelection();
    renderBackendChooser();
    notifyBackendChange();

    // The backend we just switched to may carry a stored target that has
    // meanwhile disappeared. The recursion stops right here: the nested call
    // changes only the target, so it never takes this branch again.
    if (backendChanged) {
        pruneStaleTarget();
    }

    return true;
}

// A stored target that no longer exists — the remote was deleted while the user
// was away, or in the configuration panel a moment ago — must not stay
// selected, and dropping it must not happen quietly: the subscribers would keep
// listing a target that is gone, badge included. This is the second half of the
// fix; renderTargetSelect() used to do the same write inline and told nobody.
//
// While the list is still loading there is nothing to compare against. Dropping
// the target there would wipe a valid selection out of the state *and* out of
// localStorage on every reload, which is exactly what used to happen.
function pruneStaleTarget() {
    const selection = getSyncBackend();

    if (!selection.target || selection.loading) {
        return false;
    }

    if (selection.targets.some(t => t.value === selection.target)) {
        return false;
    }

    return commitSelection({ target: '' });
}

// Redraw the chooser against a target list that may have changed underneath us
// and tell the subscribers about it. Everything that can change the list from
// the *outside* — the configuration panel closing, a finished fetch, entering
// sync mode — goes through here instead of calling renderBackendChooser()
// alone, which is what the pane never heard about.
function refreshBackendChooser({ notify = true } = {}) {
    // commitSelection() already redraws and reports when the prune fires.
    if (pruneStaleTarget()) {
        return;
    }

    renderBackendChooser();

    if (notify) {
        notifyBackendChange();
    }
}

function notifyBackendChange() {
    const selection = getSyncBackend();

    backendListeners.forEach(listener => listener(selection));

    const hooks = remotePane.hooks;
    const container = document.getElementById('remote-pane');
    if (hooks && container && typeof hooks.onBackendChange === 'function') {
        hooks.onBackendChange(container, selection);
    }
}

function initBackendChooser() {
    document.querySelectorAll('[data-sync-backend]').forEach(button => {
        button.addEventListener('click', () => setSyncBackend(button.dataset.syncBackend));
    });

    const select = document.getElementById('ws-target');
    if (select) {
        select.addEventListener('change', () => setSyncTarget(select.value));
    }

    const hint = document.getElementById('ws-backend-hint');
    if (hint) {
        // Delegation instead of an inline handler on the generated button.
        hint.addEventListener('click', event => {
            const action = event.target.closest('[data-config-section]');
            if (action) {
                openMenuPanel(action.dataset.configSection);
            }
        });
    }

    // A remote added or deleted in the panel changes the target list. The panel
    // is owned by ui/menu.js, so instead of a callback there this watches the
    // one class that marks it open and refreshes when it closes again.
    const overlay = document.getElementById('menu-overlay');
    if (overlay && typeof MutationObserver === 'function') {
        let wasOpen = overlay.classList.contains('is-open');
        new MutationObserver(() => {
            const isOpen = overlay.classList.contains('is-open');
            if (wasOpen && !isOpen) {
                // Redrawing alone is not enough: a remote added or deleted in
                // the panel changes what the subscribers may show, and they
                // have no other way of learning about it.
                refreshBackendChooser();
            }
            wasOpen = isOpen;
        }).observe(overlay, { attributes: true, attributeFilter: ['class'] });
    }

    refreshTargets();
    // No notification during init: nobody has subscribed yet, and applyMode()
    // carries the first selection to the pane right afterwards.
    refreshBackendChooser({ notify: false });
}

// state.configs is loaded by ui/config.js in parallel with this module. When
// the app is restored directly into sync mode the list can still be empty here
// — then, and only then, the configuration is fetched once, as a fallback for
// the case that nobody else does it.
//
// The fetch alone does not keep the chooser honest: it only starts the request,
// every caller renders straight afterwards and would see the still-empty list.
// What keeps it honest is `configsResolved`, which this function is the only
// place to set: until it is true, getSyncBackend() reports `loading` and
// neither the hint box nor the deselection logic draws a conclusion from the
// empty list. It is set on *every* outcome — a filled list, a successful fetch
// and a failed one — because after a failure "nothing configured" is the same
// answer the rest of the app gives.
function refreshTargets() {
    if (state.syncBackend !== 'rclone') {
        return;
    }

    // Somebody else (ui/config.js) was faster: the list is there, no fetch and
    // nothing left to wait for.
    if (state.configs.length > 0) {
        configsResolved = true;
        return;
    }

    if (configFetchInFlight) {
        return;
    }

    configFetchInFlight = true;
    fetchConfigs()
        .then(result => {
            // Another module may have filled the list in the meantime; its
            // value wins, this is only a fallback.
            if (result.ok && Array.isArray(result.data) && state.configs.length === 0) {
                state.configs = result.data;
            }
        })
        .catch(() => {
            // Unreachable server: the hint below falls back to "nothing
            // configured", which is what the user sees everywhere else in that
            // case too. Staying in the loading state forever would be worse.
        })
        .finally(() => {
            configFetchInFlight = false;
            configsResolved = true;
            // The list is known now, so a restored target can finally be
            // checked against it — refreshBackendChooser() does that and
            // reports either way.
            refreshBackendChooser();
        });
}

function renderBackendChooser() {
    const selection = getSyncBackend();

    document.querySelectorAll('[data-sync-backend]').forEach(button => {
        const active = button.dataset.syncBackend === selection.backend;
        // btn-primary/ws-mode-active exist in the static markup, so the browser
        // build of Tailwind generates them — an invented class would not exist.
        button.classList.toggle('btn-primary', active);
        button.classList.toggle('ws-mode-active', active);
        button.setAttribute('aria-pressed', active ? 'true' : 'false');
    });

    renderTargetSelect(selection);
    renderBackendHint(selection);
}

function renderTargetSelect(selection) {
    const select = document.getElementById('ws-target');
    if (!select) {
        return;
    }

    const backend = BACKENDS[selection.backend];
    select.replaceChildren();

    const placeholder = document.createElement('option');
    placeholder.value = '';
    if (selection.configured) {
        placeholder.textContent = `Select ${backend.label}…`;
    } else if (selection.loading) {
        placeholder.textContent = backend.loadingPlaceholder || backend.emptyPlaceholder;
    } else {
        placeholder.textContent = backend.emptyPlaceholder;
    }
    select.appendChild(placeholder);

    selection.targets.forEach(target => {
        const option = document.createElement('option');
        option.value = target.value;
        // textContent, never innerHTML: the remote name comes from the user.
        option.textContent = target.label;
        select.appendChild(option);
    });

    // Display only — this function no longer changes the selection. Dropping a
    // target that has gone stale is pruneStaleTarget()'s job, which reports it;
    // doing it here meant writing state in the middle of a render and telling
    // nobody. A stale value that briefly survives until the prune runs simply
    // has no matching <option>, and the select falls back to the placeholder.
    select.value = selection.target;

    select.disabled = !selection.configured;
}

function renderBackendHint(selection) {
    const hint = document.getElementById('ws-backend-hint');
    if (!hint) {
        return;
    }

    const backend = BACKENDS[selection.backend];
    hint.replaceChildren();
    hint.classList.remove('is-actionable', 'is-unavailable');

    if (selection.reason === '' || selection.reason === 'no-target') {
        // Ready, or targets exist and the user simply has not picked one —
        // the select itself says that, no extra box needed. The loading case
        // lands here too (see getSyncBackend): as long as the target list is
        // unknown, no box may claim anything about it.
        return;
    }

    const text = document.createElement('span');

    if (selection.reason === 'unavailable') {
        hint.classList.add('is-unavailable');
        text.textContent = backend.unavailableHint;
        hint.appendChild(text);
        return;
    }

    // 'unconfigured': the backend works, the user is missing a target — this is
    // the case that gets the jump into the configuration submenu.
    hint.classList.add('is-actionable');
    text.textContent = backend.emptyHint;
    hint.appendChild(text);

    if (backend.configAction) {
        const action = document.createElement('button');
        action.type = 'button';
        // btn/btn-sm/btn-primary all appear in the static markup.
        action.className = 'btn btn-sm btn-primary';
        action.dataset.configSection = backend.configSection;
        action.textContent = backend.configAction;
        hint.appendChild(action);
    }
}

// Divider --------------------------------------------------------------------

function restoreSplitRatio() {
    const stored = Number(localStorage.getItem(STORAGE_KEYS.splitRatio));
    if (Number.isFinite(stored) && stored > 0) {
        state.splitRatio = clampRatio(stored);
    }
}

function clampRatio(value) {
    return Math.min(MAX_RATIO, Math.max(MIN_RATIO, Math.round(value * 10) / 10));
}

function applyRatio() {
    const workspace = document.getElementById('workspace');
    if (workspace) {
        // A custom property, not a utility class: the value is continuous and
        // Tailwind cannot generate a class for it anyway.
        workspace.style.setProperty('--ws-left', state.splitRatio + '%');
    }

    const divider = document.getElementById('ws-divider');
    if (divider) {
        divider.setAttribute('aria-valuenow', String(Math.round(state.splitRatio)));
    }
}

function setSplitRatio(value, { persist }) {
    const next = clampRatio(value);
    if (next === state.splitRatio) {
        return;
    }

    state.splitRatio = next;
    applyRatio();

    if (persist) {
        localStorage.setItem(STORAGE_KEYS.splitRatio, String(next));
    }
}

function initDivider() {
    const divider = document.getElementById('ws-divider');
    const workspace = document.getElementById('workspace');
    if (!divider || !workspace) {
        return;
    }

    let dragging = false;

    // Pointer events instead of mousedown/mousemove: one code path for mouse,
    // touch and pen, and the capture keeps the events coming even when the
    // pointer leaves the thin divider during a fast drag.
    divider.addEventListener('pointerdown', event => {
        if (!isSyncMode() || event.button > 0) {
            return;
        }

        dragging = true;
        divider.setPointerCapture(event.pointerId);
        workspace.classList.add('is-dragging');
        event.preventDefault();
    });

    divider.addEventListener('pointermove', event => {
        if (!dragging) {
            return;
        }

        const rect = workspace.getBoundingClientRect();
        if (rect.width <= 0) {
            return;
        }

        // Not persisted while dragging: one write per pointer move would hit
        // localStorage a few hundred times per second.
        setSplitRatio(((event.clientX - rect.left) / rect.width) * 100, { persist: false });
    });

    const endDrag = event => {
        if (!dragging) {
            return;
        }

        dragging = false;
        if (divider.hasPointerCapture(event.pointerId)) {
            divider.releasePointerCapture(event.pointerId);
        }
        workspace.classList.remove('is-dragging');

        localStorage.setItem(STORAGE_KEYS.splitRatio, String(state.splitRatio));
        afterWidthChange();
    };

    divider.addEventListener('pointerup', endDrag);
    divider.addEventListener('pointercancel', endDrag);

    // The divider is focusable, so the split is reachable without a pointer.
    divider.addEventListener('keydown', event => {
        if (!isSyncMode()) {
            return;
        }

        let delta = 0;
        if (event.key === 'ArrowLeft') {
            delta = -KEY_STEP;
        } else if (event.key === 'ArrowRight') {
            delta = KEY_STEP;
        } else if (event.key === 'Home') {
            delta = MIN_RATIO - state.splitRatio;
        } else if (event.key === 'End') {
            delta = MAX_RATIO - state.splitRatio;
        } else {
            return;
        }

        event.preventDefault();
        setSplitRatio(state.splitRatio + delta, { persist: true });
        afterWidthChange();
    });
}

// Width changes --------------------------------------------------------------
//
// A narrower or wider list shows a different number of rows. scheduleFill()
// appends the missing chunks and runs the lazy-thumbnail safety net once, both
// throttled to a single animation frame.
function afterWidthChange() {
    scheduleFill();
    notifyRemotePane(false);
}

function notifyRemotePane(shown) {
    const hooks = remotePane.hooks;
    const container = document.getElementById('remote-pane');
    if (!hooks || !container || !isSyncMode()) {
        return;
    }

    if (!remotePane.mounted && typeof hooks.mount === 'function') {
        remotePane.mounted = true;
        hooks.mount(container);
    }

    if (shown) {
        if (typeof hooks.onShow === 'function') {
            hooks.onShow(container);
        }
        // The pane learns the current backend without having to ask: mount and
        // every show carry the selection along.
        if (typeof hooks.onBackendChange === 'function') {
            hooks.onBackendChange(container, getSyncBackend());
        }
    }

    if (typeof hooks.onResize === 'function') {
        hooks.onResize(container);
    }
}
