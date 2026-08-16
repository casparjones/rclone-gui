// File browser: navigation, history, sorting and the three view modes.
//
// The browser behaves like a normal file manager: a click on a folder navigates
// into it, the breadcrumb shows the way back and every navigation step becomes a
// history entry (pushState), so browser back/forward work.
//
// All paths come from the server (canonicalised and checked against the
// configured root) and are sent back unchanged. The client never assembles a
// path itself.

import { state, STORAGE_KEYS } from '../state.js';
import { fetchLocalFiles } from '../api.js';
import { escapeHtml, showToast } from '../util/dom.js';
import { downloadEntry } from '../util/download.js';
import {
    renderFiles,
    scheduleFill,
    setFileListMessage
} from './browser-render.js';
import { initPreview, openPreview } from './preview.js';
import { openSyncModal } from './sync.js';
import { handleSelectionClick, initSelection, resetSelectionAnchor } from './selection.js';

const VIEW_MODES = ['list', 'icon', 'preview'];

// Wire up toolbar, delegated row clicks and history handling
export function initFileBrowser() {
    restoreFileSort();
    restoreFileView();

    document.getElementById('file-up').addEventListener('click', navigateUp);
    document.getElementById('file-reload').addEventListener('click', () => {
        loadFiles(state.currentPath, { history: 'none' });
    });

    document.querySelectorAll('[data-sort]').forEach(button => {
        button.addEventListener('click', () => setFileSort(button.dataset.sort));
    });

    document.querySelectorAll('[data-view]').forEach(button => {
        button.addEventListener('click', () => setFileView(button.dataset.view));
    });

    initPreview();
    initSelection();

    const fileList = document.getElementById('file-list');
    fileList.addEventListener('click', handleFileListClick);
    fileList.addEventListener('keydown', handleFileListKeydown);

    // Shift-clicking starts a text selection across the rows, which makes a
    // range look broken. Suppressed here for the list only — a page wide
    // `user-select: none` would also kill selecting a path in the breadcrumb.
    fileList.addEventListener('mousedown', event => {
        if (event.shiftKey && event.target.closest('.fb-row')) {
            event.preventDefault();
        }
    });

    // Scrolling pulls in the next chunk of entries. Throttled to one check per
    // frame, otherwise a fast wheel produces hundreds of layout reads.
    fileList.addEventListener('scroll', scheduleFill);

    // `load` does not bubble, so the delegated listener has to capture. A
    // thumbnail only replaces its type icon once it really decoded; a failed
    // request leaves the icon in place and needs no handling of its own.
    fileList.addEventListener('load', event => {
        const image = event.target;
        if (image && image.classList && image.classList.contains('fb-thumb')) {
            const box = image.closest('.fb-thumb-box');
            if (box) {
                box.classList.add('is-loaded');
            }
        }
    }, true);

    document.getElementById('breadcrumb').addEventListener('click', handleBreadcrumbClick);

    window.addEventListener('popstate', event => {
        const path = (event.state && event.state.path) || pathFromLocation();
        loadFiles(path, { history: 'none' });
    });

    // The path in the URL wins, so a reload or a shared link opens the same
    // folder. Without it we start at the configured default path.
    loadFiles(pathFromLocation() || state.currentPath, { history: 'replace' });
}

function pathFromLocation() {
    const params = new URLSearchParams(window.location.search);
    return params.get('path') || '';
}

export async function loadFiles(path = state.currentPath, options = {}) {
    const historyMode = options.history || 'push';
    setFileListMessage('Loading …');

    let result = null;

    try {
        result = await fetchLocalFiles(path);
    } catch (error) {
        setFileListMessage('Folder could not be loaded: ' + error.message, true);
        showToast('Error loading files: ' + error.message, 'error');
        return;
    }

    if (!result.ok) {
        setFileListMessage('Folder could not be opened: ' + result.error, true);
        showToast('Error loading files: ' + result.error, 'error');
        return;
    }

    state.currentListing = result.data;
    state.currentPath = state.currentListing.path;

    // The selection itself survives the folder change (that is the point), but
    // the shift anchor belonged to the old listing and is dropped.
    resetSelectionAnchor();

    renderBreadcrumb();
    renderFiles();
    updateUpButton();
    updateHistory(historyMode);
}

function updateHistory(mode) {
    if (mode === 'none') {
        return;
    }

    const url = `${window.location.pathname}?path=${encodeURIComponent(state.currentPath)}`;
    const historyState = { path: state.currentPath };

    if (mode === 'replace') {
        window.history.replaceState(historyState, '', url);
    } else if (window.history.state && window.history.state.path === state.currentPath) {
        // Same folder again (e.g. reload): no additional history entry
        window.history.replaceState(historyState, '', url);
    } else {
        window.history.pushState(historyState, '', url);
    }
}

function navigateUp() {
    if (state.currentListing && state.currentListing.parent) {
        loadFiles(state.currentListing.parent);
    }
}

function updateUpButton() {
    const upButton = document.getElementById('file-up');
    if (upButton) {
        upButton.disabled = !(state.currentListing && state.currentListing.parent);
    }
}

// Sorting --------------------------------------------------------------------

function restoreFileSort() {
    try {
        const stored = JSON.parse(localStorage.getItem(STORAGE_KEYS.fileSort));
        if (stored && ['name', 'size', 'modified'].includes(stored.key)) {
            state.fileSort = { key: stored.key, dir: stored.dir === 'desc' ? 'desc' : 'asc' };
        }
    } catch (e) {
        // Broken value in localStorage: keep the default
    }
    updateSortButtons();
}

function setFileSort(key) {
    if (state.fileSort.key === key) {
        state.fileSort.dir = state.fileSort.dir === 'asc' ? 'desc' : 'asc';
    } else {
        state.fileSort = { key: key, dir: 'asc' };
    }

    localStorage.setItem(STORAGE_KEYS.fileSort, JSON.stringify(state.fileSort));
    updateSortButtons();
    // Different order, so the anchor's position is meaningless now.
    resetSelectionAnchor();
    renderFiles();
}

function updateSortButtons() {
    document.querySelectorAll('[data-sort]').forEach(button => {
        const active = button.dataset.sort === state.fileSort.key;
        button.classList.toggle('fb-sort-active', active);
        button.classList.toggle('btn-primary', active);
        button.dataset.arrow = state.fileSort.dir === 'asc' ? '↑' : '↓';
    });
}

// View modes ----------------------------------------------------------------
//
// The mode lives next to the sort order in localStorage, both are independent
// of each other. Only the class on the items container changes; the markup of
// a row is the same in all three modes apart from the thumbnail.

function restoreFileView() {
    const stored = localStorage.getItem(STORAGE_KEYS.fileView);
    if (VIEW_MODES.includes(stored)) {
        state.fileView = stored;
    }
    updateViewButtons();
}

function setFileView(mode) {
    if (!VIEW_MODES.includes(mode) || mode === state.fileView) {
        updateViewButtons();
        return;
    }

    state.fileView = mode;
    localStorage.setItem(STORAGE_KEYS.fileView, mode);
    updateViewButtons();
    renderFiles();
}

function updateViewButtons() {
    document.querySelectorAll('[data-view]').forEach(button => {
        const active = button.dataset.view === state.fileView;
        button.classList.toggle('fb-view-active', active);
        button.classList.toggle('btn-primary', active);
    });
}

// Delegated handlers ---------------------------------------------------------
//
// One listener on the list, not one per row: with 5000 entries per-row
// handlers would be 5000 closures, and rows are replaced chunk by chunk.

function handleFileListClick(event) {
    const row = event.target.closest('.fb-row');
    if (!row) {
        return;
    }

    const path = row.dataset.path;
    const selectable = row.dataset.selectable === '1';

    // The checkbox cell. The native toggle has already happened by now; the
    // selection is the authority and writes the checked state back, so a shift
    // range that decides otherwise still ends up consistent.
    if (event.target.closest('.fb-check')) {
        event.stopPropagation();
        if (selectable) {
            handleSelectionClick(row, event);
        }
        return;
    }

    const actionButton = event.target.closest('[data-action]');

    if (actionButton) {
        event.stopPropagation();
        if (actionButton.dataset.action === 'sync') {
            openSyncModal(path);
        } else if (actionButton.dataset.action === 'download') {
            downloadEntry(path, row.dataset.dir === '1');
        }
        return;
    }

    // Ctrl/Cmd and shift on the row itself select instead of opening. Expected
    // from every file manager, and it is the only way to extend a range with
    // the pointer without hitting the small checkbox.
    if (selectable && (event.shiftKey || event.ctrlKey || event.metaKey)) {
        event.preventDefault();
        handleSelectionClick(row, event);
        return;
    }

    if (row.dataset.nav === '1') {
        loadFiles(path);
        return;
    }

    // A plain file: show it instead of downloading it. The download is still
    // one click away, both in the row and inside the overlay.
    openPreview(path, row);
}

// Rows are focusable from script (see entryMarkup). Enter on a focused row does
// the same as a click, so the preview is reachable without a mouse.
function handleFileListKeydown(event) {
    if (event.key !== 'Enter') {
        return;
    }

    const row = event.target.closest && event.target.closest('.fb-row');
    if (!row || event.target.closest('[data-action]')) {
        return;
    }

    // The checkbox is the one part of a row that is in the tab order. Enter on
    // it must not open the file the row happens to point at — space toggles it,
    // and that arrives here as a native click, not as a keydown.
    if (event.target.closest('.fb-check')) {
        return;
    }

    event.preventDefault();
    if (row.dataset.nav === '1') {
        loadFiles(row.dataset.path);
    } else {
        openPreview(row.dataset.path, row);
    }
}

function handleBreadcrumbClick(event) {
    const link = event.target.closest('[data-path]');
    if (link) {
        loadFiles(link.dataset.path);
    }
}

// Breadcrumb -----------------------------------------------------------------
//
// Segment names and paths come from the file system and go into innerHTML —
// both the label *and* the data-path attribute have to be escaped.
function renderBreadcrumb() {
    const breadcrumb = document.getElementById('breadcrumb');
    const segments = (state.currentListing && state.currentListing.segments) || [];

    breadcrumb.innerHTML = segments.map((segment, index) => {
        const label = index === 0 ? `🏠 ${escapeHtml(segment.name)}` : escapeHtml(segment.name);
        const isLast = index === segments.length - 1;

        if (isLast) {
            return `<li><span class="font-semibold">${label}</span></li>`;
        }
        return `<li><a class="cursor-pointer hover:text-primary" data-path="${escapeHtml(segment.path)}">${label}</a></li>`;
    }).join('');
}
