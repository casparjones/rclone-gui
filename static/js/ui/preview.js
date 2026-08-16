// File preview overlay.
//
// This is the frame only. Which preview a file gets is decided by the *server*
// (`/api/preview/info` sniffs the content, the extension never decides); the
// frame looks up a renderer for the reported kind and falls back to the
// download dialog when there is none.
//
// Extension point for the follow-up tickets (text, image, video):
//
//     import { previewRenderers } from './preview.js';
//     previewRenderers.image = function (info, stage) { … };
//
//   info  – { path, name, size, kind, mime, extension } exactly as the server
//           sent it. `path` is the canonical path and the one to pass on to
//           content endpoints. Nothing in here is trusted markup: names come
//           from the file system, so anything written into the DOM has to go
//           through escapeHtml() or textContent.
//   stage – the empty #preview-stage element; the renderer owns its content.
//           It is cleared again on close, so no clean-up is needed for markup.
//           Anything else (object URLs, timers, media elements) should be
//           released in an optional `previewRenderers[kind].release`.
//
// A renderer may return false to signal "cannot show this after all"; the frame
// then shows the download fallback.

import { fetchPreviewInfo } from '../api.js';
import { escapeHtml } from '../util/dom.js';
import { basename, formatBytes } from '../util/format.js';
import { downloadEntry } from '../util/download.js';

export const previewRenderers = {};

// State of the currently open preview
let previewInfo = null;
let previewReturnFocus = null;
let previewRequestId = 0;

export function initPreview() {
    const modal = document.getElementById('preview-modal');
    if (!modal) {
        return;
    }

    document.getElementById('preview-close').addEventListener('click', closePreview);
    document.getElementById('preview-download').addEventListener('click', () => {
        if (previewInfo) {
            downloadEntry(previewInfo.path, false);
        }
    });

    // Click on the backdrop: with a native <dialog> such a click has the dialog
    // itself as its target, everything inside targets a child of the box.
    modal.addEventListener('click', event => {
        if (event.target === modal) {
            closePreview();
        }
    });

    // ESC is handled by the browser (`cancel`), so there is no own key handler
    // here — the menu handler deliberately bails out while a dialog is open.
    // `close` covers both ways out and is the single place that cleans up.
    modal.addEventListener('close', handlePreviewClosed);
}

// Replaces the file shown in an already open preview — what the image renderer
// uses to page through a folder. The difference to openPreview() is the focus
// target: it stays the row the overlay was opened from, so closing the preview
// after ten arrow presses still returns to a row that exists.
export function showPreviewFor(path) {
    const modal = document.getElementById('preview-modal');
    if (!modal || !modal.open) {
        return;
    }
    openPreview(path, null, { keepFocusTarget: true });
}

export async function openPreview(path, row, options = {}) {
    const modal = document.getElementById('preview-modal');
    if (!modal) {
        // Without the overlay markup the old behaviour is still better than
        // nothing at all.
        downloadEntry(path, false);
        return;
    }

    if (!options.keepFocusTarget) {
        previewReturnFocus = row || null;
    }

    // Paging replaces the content of an open overlay, so the renderer of the
    // *previous* file has to let go of what it holds first — the frame only
    // does that on close.
    releaseActiveRenderer();
    previewInfo = null;

    // Provisional heading until the server answers with the real name
    document.getElementById('preview-title').textContent = basename(path);
    document.getElementById('preview-meta').textContent = '';
    document.getElementById('preview-mime').textContent = '';
    setPreviewStage('<div class="pv-placeholder">Loading …</div>');

    if (!modal.open) {
        modal.showModal();
    }

    // Late answers of an earlier file must not overwrite a newer preview.
    const requestId = ++previewRequestId;

    let result = null;
    try {
        result = await fetchPreviewInfo(path);
    } catch (error) {
        if (requestId === previewRequestId) {
            showPreviewError('Preview could not be loaded: ' + error.message);
        }
        return;
    }

    if (requestId !== previewRequestId || !modal.open) {
        return;
    }

    if (!result.ok || !result.data) {
        showPreviewError(result.error);
        return;
    }

    previewInfo = result.data;
    renderPreview(previewInfo);
}

function renderPreview(info) {
    document.getElementById('preview-title').textContent = info.name || '';
    document.getElementById('preview-meta').textContent = formatBytes(info.size || 0);
    document.getElementById('preview-mime').textContent = info.mime || '';

    const stage = document.getElementById('preview-stage');
    stage.innerHTML = '';

    const renderer = previewRenderers[info.kind];
    if (typeof renderer === 'function') {
        let handled = true;
        try {
            handled = renderer(info, stage) !== false;
        } catch (error) {
            console.error('Preview renderer failed:', error);
            handled = false;
        }
        if (handled) {
            return;
        }
    }

    // No renderer (yet) for this kind. Text, image and video get a labelled
    // placeholder — the follow-up tickets replace it by registering a renderer.
    // Everything else is the documented fallback: say what it is, offer the
    // download.
    stage.innerHTML = previewPlaceholder(info);
}

function previewPlaceholder(info) {
    const placeholders = {
        text: { icon: '📄', text: 'Text preview' },
        image: { icon: '🖼️', text: 'Image preview' },
        video: { icon: '🎬', text: 'Video preview' }
    };

    const known = placeholders[info.kind];
    if (known) {
        return `<div class="pv-placeholder">
            <div class="pv-placeholder-icon">${known.icon}</div>
            <div>${known.text} — detected as ${escapeHtml(info.mime || '')}</div>
            <div class="text-sm opacity-70 mt-1">Rendering follows in a separate ticket. Use Download for now.</div>
        </div>`;
    }

    return `<div class="pv-placeholder">
        <div class="pv-placeholder-icon">📦</div>
        <div>No preview available for this file type.</div>
        <div class="text-sm opacity-70 mt-1">${escapeHtml(info.mime || 'unknown type')} · ${escapeHtml(formatBytes(info.size || 0))}</div>
    </div>`;
}

// Error texts carry server data (paths, MIME types, remote errors). The box is
// built as a node so the message is a text node, not markup.
function showPreviewError(message) {
    document.getElementById('preview-meta').textContent = '';
    document.getElementById('preview-mime').textContent = '';

    const stage = document.getElementById('preview-stage');
    if (!stage) {
        return;
    }

    const box = document.createElement('div');
    box.className = 'pv-placeholder pv-error';
    box.textContent = message == null ? '' : message;

    stage.innerHTML = '';
    stage.appendChild(box);
}

function setPreviewStage(markup) {
    const stage = document.getElementById('preview-stage');
    if (stage) {
        stage.innerHTML = markup;
    }
}

function closePreview() {
    const modal = document.getElementById('preview-modal');
    if (modal && modal.open) {
        modal.close();
    }
}

// Gives the renderer of the file currently on stage the chance to release what
// it holds (object URLs, media elements, key handlers). Called on close and
// before a new file replaces the current one.
function releaseActiveRenderer() {
    const renderer = previewInfo && previewRenderers[previewInfo.kind];
    if (renderer && typeof renderer.release === 'function') {
        try {
            renderer.release();
        } catch (error) {
            console.error('Preview renderer cleanup failed:', error);
        }
    }
}

// Runs for every way out: close button, backdrop click and ESC.
function handlePreviewClosed() {
    // Emptying the stage after the release stops any playback for good.
    releaseActiveRenderer();

    setPreviewStage('');
    previewInfo = null;
    previewRequestId++;

    // Focus goes back to the row the preview was opened from. After navigating
    // away the row is gone — then the file list itself takes the focus.
    const target = previewReturnFocus;
    previewReturnFocus = null;

    if (target && document.body.contains(target)) {
        target.focus();
    } else {
        const fileList = document.getElementById('file-list');
        if (fileList) {
            fileList.focus();
        }
    }
}
