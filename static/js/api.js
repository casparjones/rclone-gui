// The only module that talks to the server.
//
// Every endpoint answers with the ApiResponse envelope
// `{ success, data, error }`. `request()` normalises that into
// `{ ok, data, error, status }`:
//
//   ok      – HTTP 2xx *and* success === true
//   error   – result.error, or `HTTP <status>` when the body carries none
//   status  – HTTP status, needed where a 404 means something specific
//
// Session handling ------------------------------------------------------------
//
// Every route except `/login`, `POST /api/auth/login`, `/static/**` and
// `/favicon.ico` needs a valid session. Requests under `/api/` are answered with
// **401 JSON**, never with a redirect — `fetch` would follow a 302 silently and
// hand us the login *page* as if it were an answer.
//
// So the status code is the signal, and it is evaluated here, in the single
// place every request passes through. A session can end at any moment (logout in
// another tab, the 24 h expiry, an operator deleting the row), which is why this
// cannot live in the call sites: there are two dozen of them and each would have
// to get it right.

const LOGIN_PATH = '/login';

let redirecting = false;

export function isRedirectingToLogin() {
    return redirecting;
}

// Where to come back to after signing in. The server sanitises `next` against
// open redirects, but there is no reason to hand it anything but our own
// address in the first place.
function currentLocationAsNext() {
    const { pathname, search, hash } = window.location;
    return `${pathname}${search}${hash}` || '/';
}

// Leave for the login page. Idempotent: the app fires several requests at once
// (the job poller every two seconds among them), and they all see the same 401.
// Only the first one navigates.
export function redirectToLogin() {
    if (redirecting) {
        return;
    }
    redirecting = true;

    // replace(), not assign(): the expired page must not come back with "Back".
    window.location.replace(`${LOGIN_PATH}?next=${encodeURIComponent(currentLocationAsNext())}`);
}

// The answer to a request that has been superseded by the navigation to the
// login page.
//
// Deliberately a promise that never settles rather than an `{ ok: false }`
// result: navigation is already under way, and every caller would otherwise run
// its error branch and flash a toast ("Authentication required") over a page
// that is about to disappear. Nothing leaks — the document is being torn down.
function neverSettles() {
    return new Promise(() => {});
}

// Network and JSON errors are **not** swallowed here — they reject, because the
// callers distinguish "could not reach the server" from "server said no".
//
// A 401 is the one answer no caller ever sees: it means the session is gone,
// and the only sensible reaction is the login page. See below.
async function request(url, options) {
    if (isRedirectingToLogin()) {
        return neverSettles();
    }

    const response = await fetch(url, options);

    if (response.status === 401) {
        redirectToLogin();
        return neverSettles();
    }

    const result = await response.json();

    return {
        ok: response.ok && !!result && result.success === true,
        data: result ? result.data : null,
        error: (result && result.error) || `HTTP ${response.status}`,
        status: response.status
    };
}

function postJson(url, body) {
    return request(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body)
    });
}

// Authentication ---------------------------------------------------------------

// `{ id, username, role, home_path, session_expires_at }`. Behind the guard, so
// a missing session shows up as a 401 and is handled above.
export function fetchCurrentUser() {
    return request('/api/auth/me');
}

// Deletes the session row server-side; a captured cookie stops working. The
// clearing cookie comes back with the answer.
export function logout() {
    return request('/api/auth/logout', { method: 'POST' });
}

// Configuration --------------------------------------------------------------

export function fetchConfigs() {
    return request('/api/configs');
}

export function createConfig(config) {
    return postJson('/api/configs', config);
}

export function deleteConfig(name) {
    return request(`/api/configs/${name}`, { method: 'DELETE' });
}

export function persistConfigs() {
    return request('/api/configs/persist', { method: 'POST' });
}

// rsync daemon ---------------------------------------------------------------

// Status of the rsync daemon that carries the peer-to-peer transport.
//
// The endpoint answers **success even when the daemon is switched off**: the
// envelope then carries `data: null` and an `error` that explains the switch
// (`RCLONE_GUI_RSYNCD`). That is the difference between "deliberately off" and
// "should be running and is not", and it is the reason the caller must look at
// `data` rather than at `ok` alone — see `renderRsyncdStatus()` in
// `ui/config.js`.
export function fetchRsyncdStatus() {
    return request('/api/rsyncd/status');
}

// Files ----------------------------------------------------------------------

export function fetchLocalFiles(path) {
    return request(`/api/files/local?path=${encodeURIComponent(path || '')}`);
}

// The remote name is encoded like every other parameter. It used to go into
// the query string raw, which let a name containing `&` or `#` add or cut off
// parameters — the caller is expected to hand over a *configured* remote, but
// that is no reason to build the URL by hand.
export function fetchRemoteFiles(remoteName, remotePath) {
    const remote = encodeURIComponent(remoteName || '');
    const path = encodeURIComponent(remotePath == null ? '/' : remotePath);
    return request(`/api/files/remote?remote=${remote}&path=${path}`);
}

export function fetchPreviewInfo(path) {
    return request(`/api/preview/info?path=${encodeURIComponent(path)}`);
}

// Text content for the preview. The size limit lives on the server; there is
// deliberately no parameter to raise it, so nothing here can ask for more.
export function fetchPreviewText(path) {
    return request(`/api/preview/text?path=${encodeURIComponent(path)}`);
}

// URL of the raw image bytes for the preview.
//
// This one is deliberately *not* a fetch: the address goes straight into the
// `src` of an <img>. The response carries the headers that make an SVG inert
// (`Content-Security-Policy: … sandbox`, `X-Content-Type-Options: nosniff`,
// content-sniffed Content-Type) — reading the bytes into a blob: URL first
// would throw all of them away, and nothing would be gained: the browser
// caches the URL just as well.
export function previewImageUrl(path) {
    return `/api/preview/image?path=${encodeURIComponent(path)}`;
}

// Only used after an <img> reported an error: the same URL, but read as JSON,
// so the server's reason ("not an image", "too large", …) can be shown instead
// of a bare broken-image icon.
export function fetchPreviewImageError(path) {
    return request(previewImageUrl(path));
}

// Sync -----------------------------------------------------------------------

export function startSync(syncRequest) {
    return postJson('/api/sync', syncRequest);
}

export function fetchSyncJobs() {
    return request('/api/sync');
}

export function fetchSyncProgress(jobId) {
    return request(`/api/sync/${jobId}`);
}

// The log endpoint is the one place where the HTTP status is checked *before*
// the body is parsed: jobs from before logging existed answer 404 with a body
// that is not JSON, and that case gets its own message in the UI.
// It is the second and last place that calls `fetch` directly, so it repeats
// the 401 check — the status is looked at before `response.ok`, otherwise the
// missing session would be reported as "HTTP error! status: 401".
export async function fetchSyncLog(jobId) {
    if (isRedirectingToLogin()) {
        return neverSettles();
    }

    const response = await fetch(`/api/sync-log/${jobId}`);

    if (response.status === 401) {
        redirectToLogin();
        return neverSettles();
    }

    if (!response.ok) {
        return { ok: false, data: null, error: `HTTP error! status: ${response.status}`, status: response.status };
    }

    const result = await response.json();
    return {
        ok: !!result && result.success === true,
        data: result ? result.data : null,
        error: (result && result.error) || `HTTP ${response.status}`,
        status: response.status
    };
}

export function deleteSyncJob(jobId) {
    return request(`/api/sync-delete/${jobId}`, { method: 'DELETE' });
}

// Tasks ----------------------------------------------------------------------

export function fetchTasks() {
    return request('/api/tasks');
}

export function createTask(taskRequest) {
    return postJson('/api/tasks', taskRequest);
}

export function deleteTask(taskId) {
    return request(`/api/tasks/${taskId}`, { method: 'DELETE' });
}

export function startTask(taskName) {
    return postJson('/api/tasks/start', { task_name: taskName });
}
