// Video renderer for the preview overlay.
//
// Registers `previewRenderers.video`. The frame (ui/preview.js) has already
// decided that this file is a video, and that decision comes from the server:
// /api/preview/info sniffs the content, the extension never decides.
//
// What is worth knowing about this module:
//
//   1. **The seeking bar is a server property, not a client one.** The
//      <video> element only offers seeking when the response says
//      `Accept-Ranges: bytes` and answers a `Range` with `206` and a correct
//      `Content-Range`. That is what /api/preview/video does; nothing here can
//      make up for a server that does not. Consequently the URL goes straight
//      into `src` — reading the bytes into a blob: URL first would download
//      the whole file up front and throw the range machinery away, which is
//      exactly the opposite of what a two-hour recording needs.
//   2. **No new CSS classes.** Tailwind runs as a browser build and only
//      generates what it finds in the DOM at scan time, and the `pv-` classes
//      live in the <style> block of index.html, which this ticket does not
//      own. The few boxes here are therefore styled through `element.style`,
//      and the existing `pv-placeholder` / `pv-error` classes are reused for
//      status and error text.
//   3. **Playback has to stop when the overlay closes.** A <video> that is
//      merely detached from the DOM keeps its network activity going in some
//      browsers. `release()` pauses it, drops the `src` and calls `load()`,
//      which is the documented way to abort the pending fetch.
//   4. File names are attacker controlled and go into the DOM through
//      `textContent` / DOM properties only — never innerHTML.

import { previewRenderers } from './preview.js';

// URL of the raw video bytes. Deliberately local instead of a fetch helper in
// api.js: this address is never fetched as JSON in the normal case, it is what
// the <video> element loads, range request by range request.
function previewVideoUrl(path) {
    return `/api/preview/video?path=${encodeURIComponent(path)}`;
}

// Everything the currently rendered video holds on to. One object, so
// `release()` cannot forget half of it.
let view = null;
let activeToken = 0;

previewRenderers.video = function (info, stage) {
    const token = ++activeToken;

    const wrap = document.createElement('div');
    wrap.style.display = 'flex';
    wrap.style.flexDirection = 'column';
    wrap.style.alignItems = 'center';
    wrap.style.justifyContent = 'center';
    wrap.style.gap = '0.5rem';
    wrap.style.width = '100%';
    wrap.style.height = '100%';
    wrap.style.minHeight = '0';

    const status = document.createElement('div');
    status.className = 'pv-placeholder';
    status.textContent = 'Loading …';

    const video = document.createElement('video');
    video.controls = true;
    // Metadata is enough to draw the timeline; the rest arrives as the user
    // plays or seeks. `auto` would pull a gigabyte for a preview nobody may
    // even start.
    video.preload = 'metadata';
    video.playsInline = true;
    video.setAttribute('playsinline', '');
    video.style.maxWidth = '100%';
    video.style.maxHeight = '100%';
    video.style.minHeight = '0';
    video.style.background = '#000';
    video.style.borderRadius = '0.375rem';
    video.style.outline = 'none';
    video.hidden = true;
    // The name is only a label here, but it is file system data all the same,
    // so it goes in as a property, never as markup.
    video.title = info.name || '';

    const meta = document.createElement('div');
    meta.className = 'pv-note';
    meta.style.fontSize = '0.8rem';
    meta.style.opacity = '0.7';
    meta.hidden = true;

    wrap.appendChild(status);
    wrap.appendChild(video);
    wrap.appendChild(meta);
    stage.appendChild(wrap);

    view = {
        token: token,
        info: info,
        video: video,
        status: status,
        meta: meta,
        handlers: []
    };

    on(video, 'loadedmetadata', () => handleMetadata(token));
    on(video, 'error', () => handleError(token));
    // A codec the browser cannot decode does not always raise `error` on the
    // element; some browsers only report it on the source. Both paths end in
    // the same place.
    on(video, 'stalled', () => noteSlowLoad(token));

    video.src = previewVideoUrl(info.path);

    return true;
};

// Called by the frame on close *and* before the next file replaces this one.
previewRenderers.video.release = function () {
    activeToken++;

    if (!view) {
        return;
    }

    view.handlers.forEach(entry => entry.target.removeEventListener(entry.type, entry.fn));
    view.handlers = [];

    // The order matters: pause first, then drop the source, then `load()`.
    // That is what actually stops a running download — removing the element
    // from the DOM alone does not.
    const video = view.video;
    try {
        video.pause();
    } catch (error) {
        // A video that never started can throw here; nothing to do about it.
    }
    video.removeAttribute('src');
    // Chrome only aborts the pending request once the media element reloads
    // its (now empty) source.
    try {
        video.load();
    } catch (error) {
        /* same as above */
    }

    view = null;
};

// ---------------------------------------------------------------------------
// Loading
// ---------------------------------------------------------------------------

function handleMetadata(token) {
    if (!current(token)) {
        return;
    }

    view.status.hidden = true;
    view.video.hidden = false;

    const parts = [];
    const width = view.video.videoWidth;
    const height = view.video.videoHeight;
    if (width && height) {
        parts.push(`${width} × ${height}`);
    }
    const duration = view.video.duration;
    if (isFinite(duration) && duration > 0) {
        parts.push(formatDuration(duration));
    }
    if (parts.length) {
        view.meta.textContent = parts.join(' · ');
        view.meta.hidden = false;
    }

    // Focus goes to the player so space and the arrow keys reach it. The
    // overlay is a native <dialog>; ESC stays with the browser either way, and
    // this module registers no key handler of its own.
    try {
        view.video.focus({ preventScroll: true });
    } catch (error) {
        view.video.focus();
    }
}

// Only cosmetic: a long seek into a not yet buffered part looks like a hang
// otherwise.
function noteSlowLoad(token) {
    if (!current(token) || !view.video.hidden) {
        return;
    }
    view.status.textContent = 'Loading … (waiting for data)';
}

async function handleError(token) {
    if (!current(token)) {
        return;
    }

    view.video.hidden = true;
    view.meta.hidden = true;
    view.status.hidden = false;
    view.status.classList.add('pv-error');
    view.status.textContent = 'Video could not be played.';

    // The element only knows "it failed". The reason is either in the JSON
    // body of the very same URL (the server refused it) or it is a codec the
    // browser cannot decode — worth one extra request to tell the two apart.
    const path = view.info.path;
    const mime = view.info.mime || '';
    let reason = '';
    try {
        const response = await fetch(previewVideoUrl(path), {
            headers: { Accept: 'application/json' },
            credentials: 'same-origin'
        });
        if (!response.ok) {
            const body = await response.json();
            reason = body && body.error ? body.error : `HTTP ${response.status}`;
        }
    } catch (error) {
        reason = '';
    }

    if (!current(token)) {
        return;
    }

    if (reason) {
        view.status.textContent = 'Video could not be played: ' + reason;
        return;
    }

    // The server delivered, so the browser is the one that cannot handle it.
    // Saying which format it is beats a bare failure message — the download
    // button in the footer is the way out.
    const canPlay = mime ? view.video.canPlayType(mime) : '';
    view.status.textContent = canPlay
        ? 'Video could not be played. The file may be damaged or use a codec this browser does not support.'
        : `This browser cannot play ${mime || 'this format'}. Use Download to open it in a player.`;
}

// True while `token` is still the render this module is showing. Guards every
// asynchronous continuation.
function current(token) {
    return view !== null && token === activeToken && view.token === token && view.video.isConnected;
}

// Remembers the listener so `release()` can take it off again.
function on(target, type, fn) {
    target.addEventListener(type, fn);
    if (view) {
        view.handlers.push({ target: target, type: type, fn: fn });
    }
}

function formatDuration(seconds) {
    const total = Math.round(seconds);
    const hours = Math.floor(total / 3600);
    const minutes = Math.floor((total % 3600) / 60);
    const rest = total % 60;
    const pad = value => String(value).padStart(2, '0');
    return hours > 0
        ? `${hours}:${pad(minutes)}:${pad(rest)}`
        : `${minutes}:${pad(rest)}`;
}
