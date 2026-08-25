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
// A session can end at any moment (logout in another tab, the 24 h expiry, an
// operator deleting the row), which is why the reaction cannot live in the call
// sites: there are two dozen of them and each would have to get it right.
//
// But a 401 alone is **not** the signal. Some endpoints speak to a third party
// and pass its verdict on: `POST /api/files/remote/mkdir` answers 401 when the
// *remote* rejects its credentials, which says nothing about our session.
// Treating that as an expiry logged the user out over a wrong remote password,
// without ever showing what went wrong.
//
// So a 401 is only a *question*, and the answer is fetched from the one endpoint
// that can only ever be turned down by the session guard itself: `/api/auth/me`
// reads the session and nothing else. If it says 401 too, the session is gone;
// if it answers, the session is alive and the original 401 belongs to the
// endpoint and is handed to the caller as an ordinary `{ ok: false }` result.
//
// This was chosen over a list of "endpoints whose 401 is not an expiry": such a
// list ages silently — the next route that talks to a foreign service is
// forgotten, and the bug resurfaces as a user who finds himself signed out for
// no reason. The probe needs no upkeep and costs one small request, only on a
// 401, which is rare in either meaning.

const LOGIN_PATH = '/login';

// Answers only about the session: behind the guard, and its handler does no
// work of its own beyond reading the session the guard put in place.
const SESSION_PROBE_PATH = '/api/auth/me';

let redirecting = false;

// The probe in flight, shared by every 401 that arrives while it runs. The app
// fires several requests at once (the job poller every two seconds among them),
// and a burst of 401s must not become a burst of probes. Cleared when it
// settles, so a later 401 asks again instead of trusting a stale verdict.
let sessionProbe = null;

// Whether the session is really gone, asked at the server rather than guessed
// from the answer we just got.
//
// A probe that cannot reach the server returns `false`: "the network is down"
// is not a verdict, and leaving for the login page would only trade one failed
// request for a failed navigation. The next 401 asks again.
// Exported for the one caller that cannot go through `request()`: the video
// preview needs range requests and a byte stream (`ui/preview-video.js`), so it
// keeps its own `fetch` and asks this function itself when it sees a 401. The
// probe, its de-duplication and its verdict are therefore shared — there is no
// second implementation of the rule that could drift from this one.
export function sessionHasExpired() {
    if (sessionProbe) {
        return sessionProbe;
    }

    const probe = fetch(SESSION_PROBE_PATH, { cache: 'no-store' })
        .then((response) => response.status === 401)
        .catch(() => false);

    sessionProbe = probe;
    // `probe` cannot reject — the `catch` above is part of it — so one handler
    // is enough to release the slot.
    probe.then(() => {
        if (sessionProbe === probe) {
            sessionProbe = null;
        }
    });

    return probe;
}

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
// A 401 whose probe confirms an expired session is the one answer no caller
// ever sees; every other 401 comes back as a normal result with `status: 401`,
// so the call site can tell the user what the remote said.
async function request(url, options) {
    if (isRedirectingToLogin()) {
        return neverSettles();
    }

    const response = await fetch(url, options);

    if (response.status === 401 && (await sessionHasExpired())) {
        redirectToLogin();
        return neverSettles();
    }

    const result = await readJson(response);

    return {
        ok: response.ok && !!result && result.success === true,
        data: result ? result.data : null,
        error: (result && result.error) || `HTTP ${response.status}`,
        status: response.status
    };
}

// The body of an answer that is not a session expiry.
//
// Parse errors keep rejecting — the callers rely on it — except on a 401 that
// survived the probe: that one used to be swallowed by the redirect and may
// come from something that is not one of our handlers at all (a proxy in
// front of the app). Turning it into an envelope keeps such an answer visible
// as "HTTP 401" instead of a `SyntaxError` from deep inside the module.
async function readJson(response) {
    if (response.status !== 401) {
        return response.json();
    }

    try {
        return await response.json();
    } catch {
        return null;
    }
}

// `signal` is the only extra option a caller may hand in, and it is optional
// everywhere. It exists because no endpoint here carries a deadline of its
// own: a request that runs against an unreachable remote stays open until the
// server-side process gives up, and the caller has no way to tell that state
// apart from "still working". An AbortSignal lets the call site stop waiting
// *and* release the socket instead of only stopping to look.
//
// An aborted request rejects with the browser's `AbortError` — it is not
// turned into an `{ ok: false }` envelope, because "we stopped asking" is not
// an answer from the server and the two must not be confused.
function postJson(url, body, options) {
    return request(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
        signal: options ? options.signal : undefined
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
export function fetchRemoteFiles(remoteName, remotePath, options) {
    const remote = encodeURIComponent(remoteName || '');
    const path = encodeURIComponent(remotePath == null ? '/' : remotePath);
    return request(`/api/files/remote?remote=${remote}&path=${path}`, {
        signal: options ? options.signal : undefined
    });
}

// Creates one folder inside `remotePath` on a **configured** remote.
//
//   POST /api/files/remote/mkdir
//   { "remote": "<name from /api/configs>",
//     "path":   "/parent",          // folder the user is standing in
//     "name":   "new folder" }      // single segment, no / \ . ..
//
//   200 { success: true,  data: { path: "/parent/new folder" } }
//   200 { success: false, error: "<reason>" }   // unclassifiable failure
//
// The status code is what makes the failure classifiable, and the server sets
// it (`create_remote_directory` in `src/handlers/files.rs`):
//   400 the request itself · 403 no write permission · 404 parent path gone ·
//   401 credentials **of the remote** rejected · 504 no answer in 15 s.
//
// That 401 is the reason the session check above asks before it redirects: it
// belongs to the remote, not to the user's session.
export function createRemoteFolder(remoteName, remotePath, name, options) {
    return postJson('/api/files/remote/mkdir', {
        remote: remoteName || '',
        path: remotePath == null ? '/' : remotePath,
        name: name
    }, options);
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

// Announced on `window` whenever this module has just asked the server to
// start a job. The job list polls on a timer that slows right down while
// nothing is running (see `ui/jobs.js`), and a job the user started himself
// must not wait for that timer — he is looking at the screen.
//
// A DOM event rather than a direct call: `ui/jobs.js` already imports this
// module, and importing it back would close a cycle for the sake of one
// notification. Listeners are optional by construction; nothing here depends
// on anyone hearing it.
export const SYNC_STARTED_EVENT = 'rclone-gui:sync-started';

// Fired only after the server has accepted the request. A rejected start has
// no job to show, and announcing it would make the list refresh for nothing.
function announceSyncStarted(result) {
    if (result && result.ok) {
        window.dispatchEvent(new CustomEvent(SYNC_STARTED_EVENT));
    }
    return result;
}

export function startSync(syncRequest) {
    return postJson('/api/sync', syncRequest).then(announceSyncStarted);
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

    if (response.status === 401 && (await sessionHasExpired())) {
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

// Fetch from a URL ------------------------------------------------------------
//
// The **server** fetches the URL and puts the result into the user's home; the
// browser only asks for it. That is what makes the SSRF guard possible at all
// (`src/handlers/urlguard.rs`): the address is vetted, and vetted again after
// every redirect, in one place that the client cannot switch off.
//
// `{ url, target_path?, filename? }` — `target_path` is relative to the user's
// home or an absolute path inside it, and is checked server-side *before* any
// side effect. Omitting it means the home folder itself. `filename` is a wish;
// without it the server takes the name from `Content-Disposition` or from the
// URL, and either way it is stripped of path parts.
//
// The answer carries the job id. The fetch is a regular job from there on: it
// shows up in `GET /api/sync` next to the sync jobs, its log is at
// `/api/sync/<id>/log`, and it is announced like any other start so the job
// list refreshes at once instead of waiting for its idle tick.
export function startUrlFetch(fetchRequest) {
    return postJson('/api/download-url', fetchRequest).then(announceSyncStarted);
}

// Asks the server to stop a running fetch. The partial file is removed
// server-side and the job ends as `cancelled` — there is nothing to clean up
// here.
//
// Only the downloader knows these ids; a sync job id answers "Job not found".
// `ui/urlfetch.js` keeps track of which ids belong here, and why it has to.
//
// Announced like a start: what changed has to become visible without waiting
// for the ten-second idle tick.
export function cancelUrlFetch(jobId) {
    return request(`/api/download-url/${encodeURIComponent(jobId)}/cancel`, { method: 'POST' })
        .then(announceSyncStarted);
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

// Starting a task is starting a sync job by another name, so it announces the
// same thing.
export function startTask(taskName) {
    return postJson('/api/tasks/start', { task_name: taskName }).then(announceSyncStarted);
}

// Users ----------------------------------------------------------------------
//
// The admin routes are guarded **server-side** (`require_admin` in
// `src/handlers/users.rs`). Hiding the section from a non-admin is convenience;
// the binding answer is a 403, and every caller here must be able to show it.
// So none of these functions swallow a status: a refusal comes back as an
// ordinary `{ ok: false, error, status }` and the reason the server gave is the
// text the user reads. It is written for a human on purpose ("Ein
// Administrator kann sich die Adminrechte nicht selbst entziehen …"), which is
// why it is passed through instead of being replaced by a generic message.
//
// The password of an account is never part of an answer — `UserView` does not
// have the field at all.

export function fetchUsers() {
    return request('/api/users');
}

// `{ username, password, role?, home_path? }`. `password` is mandatory; a
// missing `role` creates a `user`, a missing `home_path` puts the home under
// `RCLONE_GUI_DEFAULT_PATH/<name>`.
export function createUser(user) {
    return postJson('/api/users', user);
}

// Only the fields that are present are changed; an empty body is rejected with
// 400. `password` here is an admin resetting *another* account — for the own
// one the server points at `changeOwnPassword()` below.
export function updateUser(userId, changes) {
    return request(`/api/users/${encodeURIComponent(userId)}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(changes)
    });
}

// `dataMode` is **mandatory** and must be `keep` or `delete`: what happens to
// the personal rclone configuration is asked, never assumed. `transfer` exists
// as a rejected value (400) and is deliberately not offered here — see
// `parse_delete_mode`.
export function deleteUser(userId, dataMode) {
    return request(
        `/api/users/${encodeURIComponent(userId)}?data=${encodeURIComponent(dataMode)}`,
        { method: 'DELETE' }
    );
}

// The own password, with the old one. **On success every session of the account
// is gone, this one included** — the caller has to go to the login page, or the
// next request is a 401 and the app looks broken.
export function changeOwnPassword(currentPassword, newPassword) {
    return postJson('/api/users/me/password', {
        current_password: currentPassword,
        new_password: newPassword
    });
}
