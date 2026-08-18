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
//   5. **What this module can and cannot do about an expired session.**
//      There are two requests to /api/preview/video here, and only one of them
//      is ours:
//
//        * the one the <video> element makes itself, from `src`. It is issued
//          by the browser's media stack, range request by range request. No
//          script sees its status code — `error` on the element says "it
//          failed" and nothing else — so a 401 on *that* path cannot be
//          recognised where it happens. Turning it into a fetch is not an
//          option (point 1 above).
//        * the one in `handleError()`, which asks the very same URL for its
//          JSON reason after the element gave up. This one is ours, and it is
//          where the session check lives.
//
//      That is why the second request is worth more than its error message:
//      when the session expires mid-playback, the element fails, we ask, the
//      answer is 401, and `sessionHasExpired()` — the same probe every other
//      caller uses, imported from api.js so there is no second copy of the
//      rule — decides between "signed out" and "this endpoint said no". So the
//      expired session *is* caught, just one step later than elsewhere: after
//      the element has failed, not while it is still loading.
//
//      What stays out of reach: a session that expires while the video plays
//      on from an already buffered part raises nothing until the element needs
//      more data. Until then the user sees no sign of it. That is a property
//      of loading media through `src`, not something left undone here.

import { previewRenderers } from './preview.js';
import { isRedirectingToLogin, redirectToLogin, sessionHasExpired } from '../api.js';

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

    // Already on the way to the login page: another request got there first,
    // and one more question to a server that has stopped answering us would
    // only paint over a page that is being torn down.
    if (isRedirectingToLogin()) {
        return;
    }

    let reason = '';
    try {
        const response = await fetch(previewVideoUrl(path), {
            headers: { Accept: 'application/json' },
            credentials: 'same-origin'
        });

        // A 401 is a question, not a verdict — exactly as in api.js, and asked
        // with the same function so the two cannot drift apart. Only if the
        // probe confirms that the session itself is gone do we leave; a 401
        // that belongs to the endpoint stays a reason to show.
        if (response.status === 401 && (await sessionHasExpired())) {
            redirectToLogin();
            return;
        }

        if (!response.ok) {
            // The body is JSON in the normal case; a 401 from something that
            // is not one of our handlers (a proxy in front of the app) may not
            // be, and then the status alone has to carry the message.
            let body = null;
            try {
                body = await response.json();
            } catch (error) {
                body = null;
            }
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
