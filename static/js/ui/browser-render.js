// Rendering half of the file browser: markup, chunked insertion and the lazy
// thumbnails. Navigation, sorting and the view switch live in browser.js.

import { state } from '../state.js';
import { escapeHtml } from '../util/dom.js';
import { fileIcon, formatBytes, formatTimestamp } from '../util/format.js';

// How many entries are added to the DOM per step. A folder with 5000 files
// stays responsive because only the visible part exists as elements.
const RENDER_CHUNK = 200;

// Extensions the server can turn into a thumbnail. Everything else keeps its
// type icon in preview mode, so no pointless request is made.
const THUMBNAIL_EXTENSIONS = ['jpg', 'jpeg', 'png', 'gif', 'webp', 'bmp', 'tif', 'tiff', 'ico'];

export function renderFiles() {
    const fileList = document.getElementById('file-list');
    if (!state.currentListing) {
        return;
    }

    resetThumbObserver();

    const entries = sortEntries(state.currentListing.entries || []);
    state.renderCursor = { entries: entries, index: 0 };

    // The column header only makes sense in list mode
    const head = document.getElementById('file-head');
    if (head) {
        head.classList.toggle('fb-hidden', state.fileView !== 'list');
    }

    // ".." row, the usual way up in a file manager. It is rendered right away
    // and is not part of the chunked entries.
    const parentRow = state.currentListing.parent ? `
        <div class="fb-row fb-clickable" data-path="${escapeHtml(state.currentListing.parent)}" data-nav="1">
            <div class="fb-thumb-box"><div class="fb-icon">⬆️</div></div>
            <div class="fb-name">..</div>
            <div class="fb-meta fb-size"></div>
            <div class="fb-meta fb-modified"></div>
            <div class="fb-actions"></div>
        </div>` : '';

    const empty = entries.length === 0
        ? '<div class="fb-message">This folder is empty.</div>'
        : '';

    fileList.innerHTML = `<div id="fb-items" class="fb-items fb-mode-${state.fileView}">${parentRow}</div>`
        + empty
        + '<div id="fb-sentinel" class="fb-sentinel"></div>';
    fileList.scrollTop = 0;

    if (entries.length === 0) {
        return;
    }

    createThumbObserver(fileList);
    fillViewport();
}

// Folders always come first, the chosen key only orders inside the two groups
function sortEntries(entries) {
    const factor = state.fileSort.dir === 'desc' ? -1 : 1;

    return entries.slice().sort((a, b) => {
        if (a.is_dir !== b.is_dir) {
            return a.is_dir ? -1 : 1;
        }

        let diff = 0;
        if (state.fileSort.key === 'size') {
            diff = (a.size || 0) - (b.size || 0);
        } else if (state.fileSort.key === 'modified') {
            diff = Number(a.modified || 0) - Number(b.modified || 0);
        }

        if (diff === 0) {
            diff = a.name.localeCompare(b.name, undefined, { numeric: true, sensitivity: 'base' });
        }

        return diff * factor;
    });
}

// Renders the next slice of entries. Returns true while entries are left.
function appendNextChunk() {
    const items = document.getElementById('fb-items');
    if (!items || state.renderCursor.index >= state.renderCursor.entries.length) {
        return false;
    }

    const slice = state.renderCursor.entries.slice(state.renderCursor.index, state.renderCursor.index + RENDER_CHUNK);
    state.renderCursor.index += slice.length;

    items.insertAdjacentHTML('beforeend', slice.map(entryMarkup).join(''));
    observeNewThumbs(items);

    return state.renderCursor.index < state.renderCursor.entries.length;
}

// Keeps appending until the sentinel below the list is out of sight again.
// The guard caps the work per call, so a huge folder can never freeze the tab
// in a single pass — the rest follows on the next scroll.
export function fillViewport() {
    const fileList = document.getElementById('file-list');
    const sentinel = document.getElementById('fb-sentinel');
    if (!fileList || !sentinel) {
        return;
    }

    for (let step = 0; step < 20; step++) {
        const listBottom = fileList.getBoundingClientRect().bottom;
        if (sentinel.getBoundingClientRect().top > listBottom + 300) {
            return;
        }
        if (!appendNextChunk()) {
            return;
        }
    }
}

// Scroll handler. Throttled to one check per frame, otherwise a fast wheel
// produces hundreds of layout reads.
export function scheduleFill() {
    if (state.fillScheduled) {
        return;
    }
    state.fillScheduled = true;
    window.requestAnimationFrame(() => {
        state.fillScheduled = false;
        fillViewport();
        loadVisibleThumbs();
    });
}

// Safety net for the observer: a jump over a long distance (scrollbar drag,
// End key) can deliver no intersection for the rows that were skipped, and
// they would keep their icon although they are on screen.
//
// Only the visible band is looked at. Rows sit in document order and their
// positions grow monotonically, so a binary search finds the first visible one
// without touching the rows in between — with 5000 entries that is about a
// dozen measurements instead of 5000.
function loadVisibleThumbs() {
    const fileList = document.getElementById('file-list');
    const items = document.getElementById('fb-items');
    if (!fileList || !items || !items.children.length) {
        return;
    }

    const listRect = fileList.getBoundingClientRect();
    const upper = listRect.top - 300;
    const lower = listRect.bottom + 300;
    const rows = items.children;

    let low = 0;
    let high = rows.length - 1;
    while (low < high) {
        const middle = (low + high) >> 1;
        if (rows[middle].getBoundingClientRect().bottom < upper) {
            low = middle + 1;
        } else {
            high = middle;
        }
    }

    for (let index = low; index < rows.length; index++) {
        if (rows[index].getBoundingClientRect().top > lower) {
            return;
        }
        const image = rows[index].querySelector('img[data-thumb]');
        if (image) {
            const box = image.closest('.fb-thumb-box');
            if (state.thumbObserver && box) {
                state.thumbObserver.unobserve(box);
            }
            loadThumbnail(image);
        }
    }
}

// One row. All values coming from the server are escaped — the names are
// attacker controlled, this must not be weakened.
function entryMarkup(entry) {
    const path = escapeHtml(entry.path);
    const name = escapeHtml(entry.name);
    const size = entry.is_dir ? '—' : formatBytes(entry.size || 0);
    const modified = formatTimestamp(entry.modified);
    const nav = entry.is_dir ? '1' : '0';

    // Files are clickable too now: a click opens the preview instead of a
    // download. `tabindex="-1"` keeps the rows out of the tab order (a folder
    // with 5000 entries would otherwise be untabbable) but makes them
    // focusable from script — the preview gives the focus back to its row.
    return `
        <div class="fb-row fb-clickable" tabindex="-1" data-path="${path}" data-nav="${nav}" data-dir="${entry.is_dir ? '1' : '0'}" title="${name}">
            ${thumbCell(entry, path)}
            <div class="fb-name">${name}</div>
            <div class="fb-meta fb-size">${size}</div>
            <div class="fb-meta fb-modified">${modified}</div>
            <div class="fb-actions">
                <button class="btn btn-ghost btn-xs" data-action="download" title="Download">⬇</button>
                <button class="btn btn-primary btn-xs" data-action="sync" title="Sync to remote">⇪</button>
            </div>
        </div>`;
}

// The type icon is always present. In preview mode an image entry additionally
// gets an <img> without src — the observer fills it in once it scrolls close.
// Until then (and if the server refuses) the icon stays visible.
//
// Deliberately no `loading="lazy"`: the image is hidden until it decoded, and
// Chrome postpones a lazy image that is not rendered indefinitely. Laziness
// comes from the observer, which is why the src is missing here.
function thumbCell(entry, escapedPath) {
    const icon = fileIcon(entry);

    if (state.fileView === 'preview' && wantsThumbnail(entry)) {
        return `<div class="fb-thumb-box"><div class="fb-icon">${icon}</div>`
            + `<img class="fb-thumb" alt="" data-thumb="${escapedPath}"></div>`;
    }

    return `<div class="fb-thumb-box"><div class="fb-icon">${icon}</div></div>`;
}

function wantsThumbnail(entry) {
    if (entry.is_dir || !entry.name.includes('.')) {
        return false;
    }
    return THUMBNAIL_EXTENSIONS.includes(entry.name.split('.').pop().toLowerCase());
}

function createThumbObserver(fileList) {
    if (typeof IntersectionObserver !== 'function') {
        return;
    }

    // The scroll container is the root, not the viewport — the list has its own
    // overflow. The margin starts the request slightly before the tile is seen.
    //
    // Observed is the box, not the <img>: the image is hidden until it decoded
    // and a hidden element has no area, so it would never intersect anything.
    state.thumbObserver = new IntersectionObserver((observed, observer) => {
        observed.forEach(record => {
            if (!record.isIntersecting) {
                return;
            }
            observer.unobserve(record.target);
            loadThumbnail(record.target.querySelector('img[data-thumb]'));
        });
    }, { root: fileList, rootMargin: '300px' });
}

export function resetThumbObserver() {
    if (state.thumbObserver) {
        state.thumbObserver.disconnect();
        state.thumbObserver = null;
    }
}

function observeNewThumbs(items) {
    items.querySelectorAll('img[data-thumb]:not([data-seen])').forEach(image => {
        image.dataset.seen = '1';
        const box = image.closest('.fb-thumb-box');
        if (state.thumbObserver && box) {
            state.thumbObserver.observe(box);
        } else {
            // Without IntersectionObserver there is nothing to wait for. Only
            // the entries already rendered are affected, not the whole folder.
            loadThumbnail(image);
        }
    });
}

function loadThumbnail(image) {
    const path = image && image.dataset.thumb;
    if (!path) {
        return;
    }
    delete image.dataset.thumb;
    image.src = `/api/thumb?path=${encodeURIComponent(path)}`;
}

export function setFileListMessage(message, isError = false) {
    const fileList = document.getElementById('file-list');
    resetThumbObserver();
    state.renderCursor = { entries: [], index: 0 };
    fileList.innerHTML = `<div class="fb-message${isError ? ' fb-error' : ''}">${escapeHtml(message)}</div>`;
}
