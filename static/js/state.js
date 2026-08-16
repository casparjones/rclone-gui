// Shared mutable state of the frontend.
//
// ES modules export live *bindings*, not variables an importer may assign to.
// The state therefore lives in one object whose properties are written by the
// view modules — that keeps the former globals in a single, greppable place.
//
// `window.DEFAULT_PATH` is injected by serve_index() through a classic inline
// script. Classic scripts run before deferred module scripts, so the value is
// always there by the time this module is evaluated.
export const state = {
    currentPath: window.DEFAULT_PATH || '/mnt/home',
    currentRemotePath: '/',
    // The folder currently selected for the upload (not necessarily the one
    // being browsed)
    selectedRemotePath: '/',
    currentSyncSource: '',
    currentSyncJobId: '',
    configs: [],
    tasks: [],

    // File browser: last listing from the server plus the chosen sort order
    currentListing: null,
    fileSort: { key: 'name', dir: 'asc' },

    // View mode of the file browser: 'list', 'icon' or 'preview'
    fileView: 'list',

    // Multi-selection in the file browser: path -> { path, name, is_dir, size }.
    // A Map and not a Set of paths, because the selection bar needs the sizes
    // and a selected entry may live in a folder that is no longer on screen —
    // the selection survives navigation on purpose. Session only, never stored.
    selection: new Map(),

    // Path the last plain selection click happened on. Shift extends from here.
    // Reset whenever the listing or its order changes, so a range can never be
    // computed against a row that is gone.
    selectionAnchor: '',

    // Entries are not rendered in one go. Large folders would otherwise build
    // thousands of DOM nodes before the browser paints anything.
    renderCursor: { entries: [], index: 0 },
    thumbObserver: null,
    fillScheduled: false,

    // Menu panel state (Configuration / Sync Jobs / Tasks live in the overlay)
    currentMenuSection: '',
    activeJobCount: 0,

    // Workspace layout: 'browser' (file browser full width) or 'sync' (two
    // columns, local left / remote right). The file browser DOM is the same in
    // both modes — only the layout around it changes.
    workspaceMode: 'browser',

    // Width of the left column in sync mode, in percent of the workspace
    splitRatio: 55,

    // Sync backend: what the right pane syncs against.
    //   'rclone' – the target is an rclone remote from the configuration
    //   'rsync'  – the target is a paired rclone-gui instance
    syncBackend: 'rclone',

    // Chosen target per backend, kept separately so switching back and forth
    // does not lose the other side's selection. Empty string = nothing chosen.
    syncTargets: { rclone: '', rsync: '' }
};

// localStorage keys, kept together so a rename cannot drift apart
export const STORAGE_KEYS = {
    fileSort: 'rclone-gui-file-sort',
    fileView: 'rclone-gui-file-view',
    lastRemote: 'rclone-gui-last-remote',
    remoteCachePrefix: 'rclone-cache-',
    workspaceMode: 'rclone-gui-workspace-mode',
    splitRatio: 'rclone-gui-split-ratio',
    syncBackend: 'rclone-gui-sync-backend',
    // JSON object { rclone: '<remote>', rsync: '<peer>' } — one key instead of
    // one per backend, so a new backend needs no new storage key.
    syncTargets: 'rclone-gui-sync-targets'
};
