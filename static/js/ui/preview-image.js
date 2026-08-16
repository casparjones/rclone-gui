// Image renderer for the preview overlay.
//
// Registers `previewRenderers.image`. The frame (ui/preview.js) has already
// decided that this file is an image — that decision comes from the server and
// is made on the content, never on the extension.
//
// Three things are worth knowing about this module:
//
//   1. **SVG is active content.** The file is shown by pointing the `src` of an
//      <img> at /api/preview/image. In an image context no browser runs the
//      scripts of an SVG and none of its external references are fetched; on
//      top of that the response carries `Content-Security-Policy: … sandbox`
//      and `X-Content-Type-Options: nosniff`, which cover the case of somebody
//      opening the URL directly. What must never happen is putting the markup
//      into the DOM (innerHTML, inline <svg>, <object>, <embed>) — that is the
//      one path on which a script would run in the origin of the app.
//   2. **No object URLs.** Nothing here calls URL.createObjectURL, so there is
//      nothing to revoke and no way to leak memory over a folder of a thousand
//      images. Reading the bytes into a blob would also drop exactly the
//      response headers named above.
//   3. **Late answers.** Like the text renderer, every render takes a token;
//      `release` and the next render invalidate it, so a slow image that
//      arrives after the user paged on cannot overwrite the newer one.

import { previewRenderers, showPreviewFor } from './preview.js';
import { previewImageUrl, fetchPreviewImageError } from '../api.js';
import { state } from '../state.js';

// Zoom steps. Coarse on purpose — a zoom button is used to compare, not to
// dial in a value.
const ZOOM_STEPS = [0.1, 0.25, 0.5, 0.75, 1, 1.5, 2, 3, 4, 6, 8];
const MIN_ZOOM = ZOOM_STEPS[0];
const MAX_ZOOM = ZOOM_STEPS[ZOOM_STEPS.length - 1];

// Which entries of the current folder count as "the images" for paging. The
// server decides the kind per file, but asking it for every entry of a folder
// would be one request per file; the extension is the cheap approximation and
// it is only used for *ordering*, never for how a file is rendered. A file
// whose extension lies simply shows the error of its own preview.
// Deliberately without 'svgz': the file is gzip, the server sniffs the header
// and classifies it as application/gzip — never as an image. Listing it here
// would make it count while paging and page the user onto an error. The
// reasoning against decompressing it server-side is at the gzip branch of
// `sniff_binary` (src/handlers/preview.rs).
const IMAGE_EXTENSIONS = [
    'jpg', 'jpeg', 'jpe', 'jfif', 'png', 'gif', 'webp', 'svg',
    'bmp', 'tif', 'tiff', 'ico', 'avif'
];

// Everything the currently rendered image holds on to. One object, so
// `release()` cannot forget half of it.
let view = null;
let activeToken = 0;

previewRenderers.image = function (info, stage) {
    const token = ++activeToken;

    const wrap = document.createElement('div');
    wrap.className = 'pv-image';

    const viewport = document.createElement('div');
    viewport.className = 'pv-img-viewport';

    const status = document.createElement('div');
    status.className = 'pv-placeholder';
    status.textContent = 'Loading …';

    const img = document.createElement('img');
    img.className = 'pv-img is-fit';
    // The name comes from the file system and is attacker controlled; it goes
    // into an attribute through the DOM API, never into markup.
    img.alt = info.name || '';
    img.decoding = 'async';
    // No loading="lazy": the overlay image is the reason the overlay is open,
    // and in a hidden tab lazy images never start loading at all.

    viewport.appendChild(status);
    viewport.appendChild(img);
    wrap.appendChild(viewport);

    const bar = buildBar();
    wrap.appendChild(bar.element);
    stage.appendChild(wrap);

    view = {
        token: token,
        info: info,
        img: img,
        viewport: viewport,
        status: status,
        bar: bar,
        zoom: null,        // null = fit to the stage
        base: 0,           // natural width in CSS pixels, 0 until loaded
        loaded: false,
        siblings: siblingImages(info),
        prefetched: [],
        onKeydown: null,
        drag: null
    };

    img.addEventListener('load', () => handleLoaded(token));
    img.addEventListener('error', () => handleError(token));
    img.src = previewImageUrl(info.path);

    bar.element.addEventListener('click', handleBarClick);
    viewport.addEventListener('wheel', handleWheel, { passive: false });
    viewport.addEventListener('dblclick', toggleZoom);
    viewport.addEventListener('pointerdown', startPan);

    // Arrow keys and the zoom shortcuts. The overlay is a native <dialog>, so
    // the key event bubbles to the document while it is open; the handler bails
    // out for anything that is not this preview.
    view.onKeydown = handleKeydown;
    document.addEventListener('keydown', view.onKeydown);

    updateBar();
    return true;
};

// Called by the frame on close *and* before the next file replaces this one.
// Everything acquired above is given back here — there are no object URLs to
// revoke (see the header), but the key handler, the pending request and the
// prefetched neighbours all have to go.
previewRenderers.image.release = function () {
    activeToken++;

    if (!view) {
        return;
    }

    if (view.onKeydown) {
        document.removeEventListener('keydown', view.onKeydown);
    }
    if (view.drag) {
        stopPan();
    }

    // Dropping the src aborts a request that is still running. Without it a
    // half-loaded 40 MB image keeps streaming into a stage that is already gone.
    view.img.removeAttribute('src');
    view.prefetched.forEach(image => image.removeAttribute('src'));
    view.prefetched = [];
    view = null;
};

// ---------------------------------------------------------------------------
// Loading
// ---------------------------------------------------------------------------

function handleLoaded(token) {
    if (!current(token)) {
        return;
    }

    view.loaded = true;
    view.status.hidden = true;
    // SVG without an intrinsic size reports 0 — then the rendered width is the
    // only base there is, and it is the one the fit view is showing anyway.
    view.base = view.img.naturalWidth || Math.round(view.img.getBoundingClientRect().width) || 0;
    updateBar();
    prefetchNeighbours();
}

async function handleError(token) {
    if (!current(token)) {
        return;
    }

    view.status.hidden = false;
    view.status.textContent = 'Image could not be loaded.';
    view.status.classList.add('pv-error');
    view.img.hidden = true;

    // The <img> only knows "it failed". The reason is in the JSON body of the
    // very same URL, so it is worth one extra request to show it.
    const path = view.info.path;
    let result = null;
    try {
        result = await fetchPreviewImageError(path);
    } catch (error) {
        return;
    }

    if (!current(token) || result.ok) {
        return;
    }
    view.status.textContent = 'Image could not be loaded: ' + result.error;
}

// True while `token` is still the render this module is showing. Guards every
// asynchronous continuation.
function current(token) {
    return view !== null && token === activeToken && view.token === token && view.img.isConnected;
}

// ---------------------------------------------------------------------------
// Zoom
// ---------------------------------------------------------------------------

function applyZoom() {
    if (!view) {
        return;
    }

    if (view.zoom === null) {
        view.img.classList.add('is-fit');
        view.img.style.width = '';
        view.img.style.height = '';
    } else {
        // Before the image is loaded there is no base to scale, so fit stays.
        const base = view.base || view.img.naturalWidth;
        if (!base) {
            view.zoom = null;
            applyZoom();
            return;
        }
        view.img.classList.remove('is-fit');
        view.img.style.width = Math.max(1, Math.round(base * view.zoom)) + 'px';
        view.img.style.height = 'auto';
    }

    // The grab cursor belongs on a viewport that can actually be panned, not on
    // one whose zoom factor happens to be above 1: a small image at 200% still
    // fits, a large one is already scrollable at 100%. The size is computed
    // from the numbers, not read back from the layout — a scrollWidth read
    // right after the style change can still see the old box.
    const viewport = view.viewport;
    const width = view.zoom === null ? 0 : (view.base || 0) * view.zoom;
    const height = view.zoom === null || !view.img.naturalWidth
        ? 0
        : (view.img.naturalHeight / view.img.naturalWidth) * width;
    const scrollable = width > viewport.clientWidth || height > viewport.clientHeight;
    viewport.classList.toggle('is-zoomed', scrollable);
    updateBar();
}

// Current factor as a number, also while the fit view is active — that is what
// zooming in from "fit" has to start from.
function effectiveZoom() {
    if (!view) {
        return 1;
    }
    if (view.zoom !== null) {
        return view.zoom;
    }
    const base = view.base || view.img.naturalWidth;
    const shown = view.img.getBoundingClientRect().width;
    if (!base || !shown) {
        return 1;
    }
    return shown / base;
}

function setZoom(value) {
    if (!view) {
        return;
    }
    view.zoom = Math.min(MAX_ZOOM, Math.max(MIN_ZOOM, value));
    applyZoom();
}

function stepZoom(direction) {
    const currentZoom = effectiveZoom();
    if (direction > 0) {
        const next = ZOOM_STEPS.find(step => step > currentZoom + 0.001);
        setZoom(next === undefined ? MAX_ZOOM : next);
    } else {
        const lower = ZOOM_STEPS.filter(step => step < currentZoom - 0.001);
        setZoom(lower.length ? lower[lower.length - 1] : MIN_ZOOM);
    }
}

function fitZoom() {
    if (!view) {
        return;
    }
    view.zoom = null;
    applyZoom();
}

function toggleZoom() {
    if (!view) {
        return;
    }
    if (view.zoom === null) {
        setZoom(1);
    } else {
        fitZoom();
    }
}

function handleWheel(event) {
    // Only with a modifier: a plain wheel scrolls the zoomed image, which is
    // what a scroll container is for.
    if (!view || !(event.ctrlKey || event.metaKey)) {
        return;
    }
    event.preventDefault();
    stepZoom(event.deltaY < 0 ? 1 : -1);
}

// Drag to pan, but only where there is something to pan. Pointer events cover
// mouse, pen and touch in one handler.
function startPan(event) {
    if (!view || event.button !== 0) {
        return;
    }
    const viewport = view.viewport;
    if (viewport.scrollWidth <= viewport.clientWidth && viewport.scrollHeight <= viewport.clientHeight) {
        return;
    }

    event.preventDefault();
    view.drag = {
        x: event.clientX,
        y: event.clientY,
        left: viewport.scrollLeft,
        top: viewport.scrollTop,
        move: movePan,
        end: stopPan
    };
    viewport.classList.add('is-panning');
    window.addEventListener('pointermove', view.drag.move);
    window.addEventListener('pointerup', view.drag.end);
    window.addEventListener('pointercancel', view.drag.end);
}

function movePan(event) {
    if (!view || !view.drag) {
        return;
    }
    view.viewport.scrollLeft = view.drag.left - (event.clientX - view.drag.x);
    view.viewport.scrollTop = view.drag.top - (event.clientY - view.drag.y);
}

function stopPan() {
    if (!view || !view.drag) {
        return;
    }
    window.removeEventListener('pointermove', view.drag.move);
    window.removeEventListener('pointerup', view.drag.end);
    window.removeEventListener('pointercancel', view.drag.end);
    view.viewport.classList.remove('is-panning');
    view.drag = null;
}

// ---------------------------------------------------------------------------
// Paging through the folder
// ---------------------------------------------------------------------------

function extensionOf(name) {
    const dot = String(name || '').lastIndexOf('.');
    return dot > 0 ? name.slice(dot + 1).toLowerCase() : '';
}

// The images of the *current folder*, in the order the browser shows them.
// `renderCursor.entries` is the sorted listing (folders first, then the chosen
// sort order); the raw listing is the fallback for the case where the preview
// was opened before the browser rendered.
function siblingImages(info) {
    const sorted = (state.renderCursor && state.renderCursor.entries) || [];
    const entries = sorted.length ? sorted : ((state.currentListing && state.currentListing.entries) || []);

    const images = entries
        .filter(entry => !entry.is_dir && IMAGE_EXTENSIONS.includes(extensionOf(entry.name)))
        .map(entry => ({ path: entry.path, name: entry.name }));

    const index = images.findIndex(entry => entry.path === info.path);
    if (index === -1) {
        // The file is not part of the listing (deep link, folder changed in the
        // meantime): no paging rather than paging through the wrong folder.
        return { list: [], index: -1 };
    }

    return { list: images, index: index };
}

function stepImage(direction) {
    if (!view) {
        return;
    }
    const siblings = view.siblings;
    if (siblings.index === -1 || siblings.list.length < 2) {
        return;
    }

    const count = siblings.list.length;
    const next = (siblings.index + direction + count) % count;
    if (next === siblings.index) {
        return;
    }

    // The frame releases this renderer and starts over with the new file; the
    // focus target of the overlay stays what it was.
    showPreviewFor(siblings.list[next].path);
}

// Keeps the neighbours warm in the HTTP cache, so paging feels immediate. Two
// requests, not a whole folder — and both are dropped in `release()`.
function prefetchNeighbours() {
    if (!view || view.siblings.index === -1) {
        return;
    }
    const list = view.siblings.list;
    if (list.length < 2) {
        return;
    }

    const count = list.length;
    [1, -1].forEach(offset => {
        const entry = list[(view.siblings.index + offset + count) % count];
        if (!entry || entry.path === view.info.path) {
            return;
        }
        const image = new Image();
        image.src = previewImageUrl(entry.path);
        view.prefetched.push(image);
    });
}

// ---------------------------------------------------------------------------
// Toolbar and keyboard
// ---------------------------------------------------------------------------

function buildBar() {
    const element = document.createElement('div');
    element.className = 'pv-img-bar';

    const nav = document.createElement('div');
    nav.className = 'pv-img-group';
    const prev = barButton('‹', 'prev', 'Previous image (←)');
    const count = document.createElement('span');
    count.className = 'pv-img-count';
    const next = barButton('›', 'next', 'Next image (→)');
    nav.appendChild(prev);
    nav.appendChild(count);
    nav.appendChild(next);

    const zoom = document.createElement('div');
    zoom.className = 'pv-img-group';
    const out = barButton('−', 'zoom-out', 'Zoom out (-)');
    const level = document.createElement('span');
    level.className = 'pv-img-zoom';
    const into = barButton('+', 'zoom-in', 'Zoom in (+)');
    const fit = barButton('Fit', 'fit', 'Fit to window (0)');
    const full = barButton('100%', 'full', 'Original size (1)');
    zoom.appendChild(out);
    zoom.appendChild(level);
    zoom.appendChild(into);
    zoom.appendChild(fit);
    zoom.appendChild(full);

    element.appendChild(nav);
    element.appendChild(zoom);

    return { element: element, nav: nav, count: count, level: level, prev: prev, next: next };
}

function barButton(label, action, title) {
    const button = document.createElement('button');
    button.type = 'button';
    button.className = 'btn btn-xs';
    button.dataset.imgAction = action;
    button.title = title;
    button.setAttribute('aria-label', title);
    button.textContent = label;
    return button;
}

// One delegated listener for the whole bar instead of one per button.
function handleBarClick(event) {
    const button = event.target.closest('[data-img-action]');
    if (!button || !view) {
        return;
    }

    switch (button.dataset.imgAction) {
        case 'prev': stepImage(-1); break;
        case 'next': stepImage(1); break;
        case 'zoom-in': stepZoom(1); break;
        case 'zoom-out': stepZoom(-1); break;
        case 'fit': fitZoom(); break;
        case 'full': setZoom(1); break;
        default: break;
    }
}

function updateBar() {
    if (!view) {
        return;
    }

    const siblings = view.siblings;
    const many = siblings.index !== -1 && siblings.list.length > 1;
    view.bar.nav.hidden = !many;
    if (many) {
        view.bar.count.textContent = `${siblings.index + 1} / ${siblings.list.length}`;
    }

    if (!view.loaded) {
        view.bar.level.textContent = '…';
        return;
    }

    const percent = Math.round(effectiveZoom() * 100);
    view.bar.level.textContent = view.zoom === null ? `Fit · ${percent}%` : `${percent}%`;
}

function handleKeydown(event) {
    const modal = document.getElementById('preview-modal');
    if (!view || !modal || !modal.open || event.defaultPrevented) {
        return;
    }
    // Ctrl/Alt/Meta combinations belong to the browser, not to the overlay.
    if (event.ctrlKey || event.altKey || event.metaKey) {
        return;
    }

    switch (event.key) {
        case 'ArrowLeft':
            event.preventDefault();
            stepImage(-1);
            break;
        case 'ArrowRight':
            event.preventDefault();
            stepImage(1);
            break;
        case '+':
        case '=':
            event.preventDefault();
            stepZoom(1);
            break;
        case '-':
            event.preventDefault();
            stepZoom(-1);
            break;
        case '0':
            event.preventDefault();
            fitZoom();
            break;
        case '1':
            event.preventDefault();
            setZoom(1);
            break;
        default:
            break;
    }
}
