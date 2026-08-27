// Multi-selection in the file browser: checkboxes per row/tile, shift ranges,
// "select all" in the header and the selection bar above the list.
//
// The selection lives in `state.selection` (a Map path -> entry) and therefore
// survives navigating into another folder — that is a requirement of the
// ticket, not a side effect. It is deliberately *not* persisted: it is a
// session thing, a reload starts empty.
//
// Nothing in here writes markup from server data. Names go into `textContent`
// or into an attribute that was escaped by the caller — file names are attacker
// controlled and a stored XSS through them has already been fixed once.

import { state } from '../state.js';
import { formatBytes } from '../util/format.js';

// One row of the current listing as we keep it in the selection. Only what the
// selection bar and the follow-up sync ticket need — not the whole entry.
function selectionRecord(entry) {
    return {
        path: entry.path,
        name: entry.name,
        is_dir: !!entry.is_dir,
        size: entry.size == null ? null : Number(entry.size)
    };
}

export function isSelected(path) {
    return state.selection.has(path);
}

export function selectionCount() {
    return state.selection.size;
}

// The selected objects in insertion order. The sync ticket consumes this.
export function selectedEntries() {
    return Array.from(state.selection.values());
}

// Wires the selection bar and the header checkbox. Called once from
// initFileBrowser().
export function initSelection() {
    const clearButton = document.getElementById('fb-selection-clear');
    if (clearButton) {
        clearButton.addEventListener('click', () => {
            clearSelection();
        });
    }

    const selectAll = document.getElementById('fb-select-all');
    if (selectAll) {
        selectAll.addEventListener('change', () => {
            setAllInFolder(selectAll.checked);
        });
    }

    updateSelectionUi();
}

export function clearSelection() {
    state.selection.clear();
    state.selectionAnchor = '';
    syncRenderedRows();
    updateSelectionUi();
}

// A folder change (or a new sort order) invalidates the anchor: it points at a
// position in a list that no longer exists. An anchor pointing nowhere is what
// produces the wild ranges people report, so it is reset rather than repaired.
export function resetSelectionAnchor() {
    state.selectionAnchor = '';
}

// The entries of the folder currently on screen, in the order they are shown.
// renderCursor holds the sorted array, including the part not rendered yet, so
// a range may reach into entries that have no DOM node.
function visibleEntries() {
    return (state.renderCursor && state.renderCursor.entries) || [];
}

function setAllInFolder(selected) {
    visibleEntries().forEach(entry => {
        if (selected) {
            state.selection.set(entry.path, selectionRecord(entry));
        } else {
            state.selection.delete(entry.path);
        }
    });

    state.selectionAnchor = '';
    syncRenderedRows();
    updateSelectionUi();
}

// A click (or a space keypress) on a row checkbox, or a ctrl/shift click on the
// row itself. `event` only supplies the modifier keys.
//
// Plain click toggles the row and becomes the new anchor. Shift extends from
// the anchor to here without dropping what was selected elsewhere — that is the
// behaviour of the file managers people come from. Ctrl/Cmd is the same as a
// plain toggle here; it exists because clicking the *row* with ctrl must select
// instead of navigating.
export function handleSelectionClick(row, event) {
    const path = row.dataset.path;
    if (!path) {
        return;
    }

    const entries = visibleEntries();

    if (event.shiftKey && state.selectionAnchor) {
        const from = entries.findIndex(entry => entry.path === state.selectionAnchor);
        const to = entries.findIndex(entry => entry.path === path);

        if (from !== -1 && to !== -1) {
            const start = Math.min(from, to);
            const end = Math.max(from, to);
            for (let index = start; index <= end; index++) {
                state.selection.set(entries[index].path, selectionRecord(entries[index]));
            }
            syncRenderedRows();
            updateSelectionUi();
            return;
        }
        // Anchor or target gone (list changed underneath): fall through to a
        // plain toggle instead of selecting an arbitrary range.
    }

    toggleRow(row);
}

function toggleRow(row) {
    const path = row.dataset.path;

    if (state.selection.has(path)) {
        state.selection.delete(path);
    } else {
        const size = row.dataset.size === '' ? null : Number(row.dataset.size);
        state.selection.set(path, {
            path: path,
            name: row.dataset.name || '',
            is_dir: row.dataset.dir === '1',
            size: Number.isFinite(size) ? size : null
        });
    }

    state.selectionAnchor = path;
    syncRenderedRows();
    updateSelectionUi();
}

// Brings the rendered rows back in line with the selection. Only rows that
// exist are touched — the rest gets its state from entryMarkup() when the next
// chunk is appended.
export function syncRenderedRows() {
    const items = document.getElementById('fb-items');
    if (!items) {
        return;
    }

    Array.from(items.children).forEach(row => {
        if (row.dataset.selectable !== '1') {
            return;
        }
        const selected = state.selection.has(row.dataset.path);
        const box = row.querySelector('.fb-check-input');
        if (box) {
            box.checked = selected;
        }
        row.classList.toggle('is-selected', selected);
    });
}

// Header checkbox, selection bar and the row classes after a re-render.
export function updateSelectionUi() {
    updateSelectAllBox();
    updateSelectionBar();
}

function updateSelectAllBox() {
    const selectAll = document.getElementById('fb-select-all');
    if (!selectAll) {
        return;
    }

    const entries = visibleEntries();
    const selectedHere = entries.reduce(
        (total, entry) => total + (state.selection.has(entry.path) ? 1 : 0),
        0
    );

    selectAll.disabled = entries.length === 0;
    selectAll.checked = entries.length > 0 && selectedHere === entries.length;
    selectAll.indeterminate = selectedHere > 0 && selectedHere < entries.length;
}

function updateSelectionBar() {
    const bar = document.getElementById('fb-selection-bar');
    const countLabel = document.getElementById('fb-selection-count');
    const sizeLabel = document.getElementById('fb-selection-size');
    if (!bar || !countLabel || !sizeLabel) {
        return;
    }

    const entries = selectedEntries();
    bar.classList.toggle('is-visible', entries.length > 0);

    if (entries.length === 0) {
        countLabel.textContent = '';
        sizeLabel.textContent = '';
        return;
    }

    let bytes = 0;
    let folders = 0;
    entries.forEach(entry => {
        if (entry.is_dir) {
            folders += 1;
        } else if (Number.isFinite(entry.size)) {
            bytes += entry.size;
        }
    });

    const files = entries.length - folders;
    countLabel.textContent = entries.length === 1
        ? '1 item selected'
        : `${entries.length} items selected`;

    // Folder sizes are not part of a listing (rclone lsjson does not walk into
    // them), so they are named instead of silently counted as zero.
    const total = formatBytes(bytes) || '0 B';
    sizeLabel.textContent = folders === 0
        ? total
        : `${total} in ${files} file${files === 1 ? '' : 's'} · ${folders} folder${folders === 1 ? '' : 's'} (size unknown)`;
}
