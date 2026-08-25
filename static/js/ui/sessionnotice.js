// Hinweis vor Sitzungsablauf.
//
// Nicht blockierend: ein Streifen am oberen Rand, kein `<dialog>`, kein
// Overlay. Wer ihn wegklickt, arbeitet weiter; wer ihn ignoriert, wird von der
// bestehenden 401-Behandlung in `api.js` zur Anmeldung geschickt. Diese
// Weiterleitung wird hier **nicht** nachgebaut.
//
// ## Zwei Fristen, und warum die frühere gilt
//
// Eine Sitzung hat zwei Enden (`src/handlers/auth_web.rs`):
//
//   * die **Untätigkeitsfrist** (`session_expires_at`, Standard 24 h) — sie
//     verlängert sich bei Aktivität,
//   * die **absolute Lebensdauer** (`session_absolute_expires_at`, Standard
//     168 h) — sie verlängert sich **nie**.
//
// Nur die erste anzuzeigen wäre falsch, und zwar systematisch: solange ein Tab
// offen ist, fragt `jobs.js` alle 2–10 s den Server, jede dieser Anfragen läuft
// durch den Sitzungswächter, und damit rückt die Untätigkeitsfrist immer weiter
// nach hinten. Sie läuft praktisch nie ab. Was wirklich zuschlägt, ist die
// absolute Frist — und genau der Ausfall soll hier angekündigt werden. Also
// `Math.min` der beiden.
//
// ## Kein zweiter Poller
//
// Der Countdown rechnet **lokal** herunter; der Server wird dafür nie gefragt.
// Es gibt genau zwei Anlässe, an denen dieses Modul eine Anfrage stellt, und
// keiner davon ist getaktet:
//
//   1. einmal, wenn der Hinweis fällig würde. Der beim Laden gelesene Wert der
//      Untätigkeitsfrist ist zu diesem Zeitpunkt möglicherweise überholt (siehe
//      oben), und eine Warnung vor einer Frist, die es nicht mehr gibt, ist
//      schlimmer als keine. Wird sie dabei als verlängert erkannt, verschiebt
//      sich der Termin und es passiert weiter nichts. `REFRESH_MIN_GAP_MS`
//      verhindert, dass daraus doch eine Schleife wird.
//   2. wenn der Nutzer „Keep me signed in" drückt — eine Handlung, keine Uhr.
//
// Der Grund für die Sparsamkeit steht im Ticket: die serverseitige
// Verlängerung greift erst, wenn weniger als die Hälfte des Fensters übrig ist
// (~1 Schreibvorgang je Sitzung alle 12 h statt 43 200/Tag). Ein Countdown, der
// den Wert dauernd nachliest, macht das zunichte.
//
// ## Mehrere Tabs: `localStorage`, nicht `BroadcastChannel`
//
// Gewählt ist eine **Pacht** in `localStorage`: ein Tab schreibt „ich zeige den
// Hinweis" mit Zeitstempel, die anderen sehen das und schweigen; wird der
// Zeitstempel alt (Tab geschlossen, Rechner geschlafen), übernimmt der nächste.
//
// `BroadcastChannel` wäre der elegantere Kanal, kann aber zwei Dinge nicht, auf
// die es hier ankommt:
//
//   * **Es hat kein Gedächtnis.** Ein Tab, der *nach* dem Erscheinen des
//     Hinweises geöffnet wird, hat die Nachricht nie gehört und würde einen
//     zweiten Streifen aufziehen. Die Pacht liest er einfach.
//   * **Es hat keinen Schiedsrichter.** Drei Tabs, die gleichzeitig feststellen
//     „ich müsste jetzt warnen", müssten erst untereinander eine Wahl
//     abhalten. Der `localStorage`-Eintrag *ist* das Ergebnis der Wahl.
//
// Das `storage`-Ereignis liefert dazu genau die Sofortmeldung, für die man
// `BroadcastChannel` genommen hätte: ein Wegklicken in einem Tab räumt den
// Streifen in den anderen weg, ohne auf den nächsten Takt zu warten.
//
// Der Zustand ist per Browser richtig geteilt, weil die Sitzung selbst per
// Browser gilt: es ist ein Cookie, und alle Tabs teilen dieselben zwei Fristen.

import { fetchCurrentUser } from '../api.js';

// Wie lange vorher gewarnt wird.
const WARN_BEFORE_MS = 15 * 60 * 1000;

// Der lokale Takt des Countdowns. Rein im Browser — keine Anfrage.
const TICK_MS = 1000;

// Pacht: wer den Hinweis zeigt, und wann er das zuletzt bestätigt hat.
const LEASE_KEY = 'rclone-gui-session-notice';

// Ab wann eine Pacht als verwaist gilt. Grosszügig gegenüber einem Tab, der
// gerade nicht im Vordergrund ist — Timer werden dort gedrosselt, aber nicht
// angehalten.
const LEASE_STALE_MS = 15 * 1000;

// Mindestabstand zwischen zwei Nachfragen bei `/api/auth/me`. Die Nachfrage ist
// ereignisgetrieben; diese Grenze ist der Riegel dagegen, dass daraus durch
// einen Rechenfehler doch eine wiederkehrende Abfrage wird.
const REFRESH_MIN_GAP_MS = 5 * 60 * 1000;

const STYLE_ID = 'session-notice-style';
const NOTICE_ID = 'session-notice';

// Kennung dieses Tabs. Nur zum Vergleich in der Pacht; nichts daran ist geheim.
const tabId = `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;

let deadline = null;
let warnTimer = null;
let tickTimer = null;
let lastRefreshAt = 0;
let started = false;

// ---------------------------------------------------------------------------
// Fristen
// ---------------------------------------------------------------------------

function parseInstant(value) {
    if (!value) {
        return null;
    }
    const at = new Date(value).getTime();
    return Number.isNaN(at) ? null : at;
}

// Die frühere der beiden Fristen, oder `null`, wenn keine verwertbar ist.
//
// Exportiert, weil das die eine Rechnung ist, bei der ein Fehler unsichtbar
// bleibt: ein falscher Wert sieht wie eine funktionierende Anzeige aus.
export function earlierDeadline(user) {
    const idle = parseInstant(user && user.session_expires_at);
    const absolute = parseInstant(user && user.session_absolute_expires_at);

    const known = [idle, absolute].filter(at => at !== null);
    return known.length === 0 ? null : Math.min(...known);
}

// ---------------------------------------------------------------------------
// Pacht
// ---------------------------------------------------------------------------

function readLease() {
    try {
        const raw = window.localStorage.getItem(LEASE_KEY);
        const parsed = raw ? JSON.parse(raw) : null;
        return parsed && typeof parsed === 'object' ? parsed : null;
    } catch (error) {
        // Privater Modus, gesperrter Speicher, kaputtes JSON. Ohne Pacht zeigt
        // jeder Tab seinen eigenen Hinweis — unschön, aber besser als keiner.
        return null;
    }
}

function writeLease(lease) {
    try {
        window.localStorage.setItem(LEASE_KEY, JSON.stringify(lease));
    } catch (error) {
        /* siehe readLease() */
    }
}

// Ob dieser Tab den Hinweis zeigen darf. Nimmt die Pacht dabei an oder
// bestätigt sie.
function claimLease(forDeadline) {
    const lease = readLease();
    const now = Date.now();

    // Weggeklickt gilt für alle Tabs, aber nur für diese Frist: verlängert sich
    // die Sitzung, ist die nächste Warnung eine neue Aussage.
    if (lease && lease.dismissedFor === forDeadline) {
        return false;
    }

    if (lease && lease.owner !== tabId && now - Number(lease.at || 0) < LEASE_STALE_MS) {
        return false;
    }

    writeLease({ owner: tabId, at: now, dismissedFor: lease ? lease.dismissedFor : null });
    return true;
}

function dismissForAllTabs() {
    writeLease({ owner: null, at: 0, dismissedFor: deadline });
}

// ---------------------------------------------------------------------------
// Darstellung
// ---------------------------------------------------------------------------

// Eigene Klassennamen und ein einmal eingehängtes <style>: Tailwind läuft als
// Browser-Build und erzeugt nur, was es beim Scannen im DOM findet — eine erst
// per JS gesetzte Utility-Klasse hat keine Regel hinter sich. Dasselbe Muster
// wie die Job-Leiste in `jobs.js`.
//
// Keine Backticks in diesem Block: er steht in einem Template-Literal, und
// einer davon beendet die Zeichenkette. Das Ergebnis bliebe gültiges
// JavaScript, und die Seite stürbe erst beim Laden.
const NOTICE_CSS = `
#${NOTICE_ID} {
    position: fixed;
    top: 0.6rem;
    left: 50%;
    transform: translateX(-50%);
    z-index: 60;
    display: none;
    max-width: min(38rem, calc(100vw - 1.2rem));
    /* Der Streifen liegt über der Seite, darf sie aber nicht abfangen: nur er
       selbst nimmt Klicks an, der Platz um ihn herum nicht. */
    pointer-events: none;
}
#${NOTICE_ID}.is-visible { display: block; }
#${NOTICE_ID} .session-notice-box {
    pointer-events: auto;
    display: flex;
    align-items: center;
    gap: 0.7rem;
    flex-wrap: wrap;
    padding: 0.55rem 0.85rem;
    border-radius: 0.55rem;
    border-left: 4px solid #b45309;
    background: #fffbeb;
    color: #1f2937;
    box-shadow: 0 4px 16px rgba(0, 0, 0, 0.18);
    font-size: 0.85rem;
    line-height: 1.35;
}
html[data-theme="dark"] #${NOTICE_ID} .session-notice-box {
    background: #2a2118;
    color: #f3f4f6;
    box-shadow: 0 4px 16px rgba(0, 0, 0, 0.5);
}
#${NOTICE_ID} .session-notice-text { min-width: 0; }
#${NOTICE_ID} .session-notice-left {
    font-variant-numeric: tabular-nums;
    font-weight: 700;
}
#${NOTICE_ID} .session-notice-why { display: block; opacity: 0.75; font-size: 0.78rem; }
#${NOTICE_ID} button {
    border: 1px solid currentColor;
    border-radius: 0.35rem;
    background: none;
    color: inherit;
    cursor: pointer;
    font: inherit;
    font-size: 0.78rem;
    padding: 0.15rem 0.5rem;
    opacity: 0.85;
}
#${NOTICE_ID} button:hover:not(:disabled) { opacity: 1; }
#${NOTICE_ID} button:disabled { opacity: 0.45; cursor: default; }
#${NOTICE_ID} .session-notice-dismiss { border: 0; font-size: 0.95rem; padding: 0 0.3rem; }
`;

function ensureNotice() {
    let notice = document.getElementById(NOTICE_ID);
    if (notice) {
        return notice;
    }

    if (!document.getElementById(STYLE_ID)) {
        const style = document.createElement('style');
        style.id = STYLE_ID;
        style.textContent = NOTICE_CSS;
        document.head.appendChild(style);
    }

    notice = document.createElement('div');
    notice.id = NOTICE_ID;
    // Eine Höflichkeits-Meldung, keine Warnung, die den Screenreader
    // unterbricht: der Hinweis blockiert nichts.
    notice.setAttribute('role', 'status');
    notice.setAttribute('aria-live', 'polite');

    const box = document.createElement('div');
    box.className = 'session-notice-box';

    const text = document.createElement('div');
    text.className = 'session-notice-text';
    const left = document.createElement('span');
    left.className = 'session-notice-left';
    const why = document.createElement('span');
    why.className = 'session-notice-why';
    text.appendChild(left);
    text.appendChild(why);

    const keep = document.createElement('button');
    keep.type = 'button';
    keep.className = 'session-notice-keep';
    keep.textContent = 'Keep me signed in';
    keep.addEventListener('click', () => {
        keep.disabled = true;
        refreshDeadline().then(() => {
            keep.disabled = false;
        });
    });

    const dismiss = document.createElement('button');
    dismiss.type = 'button';
    dismiss.className = 'session-notice-dismiss';
    dismiss.textContent = '✕';
    dismiss.title = 'Hide this notice';
    dismiss.setAttribute('aria-label', 'Hide the session notice');
    dismiss.addEventListener('click', () => {
        dismissForAllTabs();
        hideNotice();
    });

    box.appendChild(text);
    box.appendChild(keep);
    box.appendChild(dismiss);
    notice.appendChild(box);
    document.body.appendChild(notice);

    return notice;
}

function formatLeft(ms) {
    const total = Math.max(0, Math.floor(ms / 1000));
    const minutes = Math.floor(total / 60);
    const seconds = total % 60;
    if (minutes > 0) {
        return `${minutes} min ${String(seconds).padStart(2, '0')} s`;
    }
    return `${seconds} s`;
}

function showNotice(msLeft) {
    const notice = ensureNotice();
    notice.querySelector('.session-notice-left').textContent =
        msLeft <= 0
            ? 'Your session has expired.'
            : `Your session ends in ${formatLeft(msLeft)}.`;
    notice.querySelector('.session-notice-why').textContent =
        msLeft <= 0
            ? 'The next action will take you to the sign-in page.'
            : 'Unsaved input in dialogs would be lost. Nothing is blocked in the meantime.';
    notice.classList.add('is-visible');
}

function hideNotice() {
    const notice = document.getElementById(NOTICE_ID);
    if (notice) {
        notice.classList.remove('is-visible');
    }
}

function isNoticeVisible() {
    const notice = document.getElementById(NOTICE_ID);
    return Boolean(notice && notice.classList.contains('is-visible'));
}

// ---------------------------------------------------------------------------
// Ablauf
// ---------------------------------------------------------------------------

function clearTimers() {
    if (warnTimer !== null) {
        window.clearTimeout(warnTimer);
        warnTimer = null;
    }
    if (tickTimer !== null) {
        window.clearInterval(tickTimer);
        tickTimer = null;
    }
}

// Termin für die Warnung setzen. Liegt er schon in der Vergangenheit, wird
// sofort geprüft.
function schedule() {
    clearTimers();

    if (deadline === null) {
        return;
    }

    const warnAt = deadline - WARN_BEFORE_MS;
    const wait = warnAt - Date.now();

    if (wait <= 0) {
        enterWarnWindow();
        return;
    }

    // setTimeout ist auf ~24,8 Tage begrenzt; eine Frist von 168 h liegt weit
    // darunter, aber ein konfiguriertes Vielfaches davon nicht.
    warnTimer = window.setTimeout(enterWarnWindow, Math.min(wait, 2147483000));
}

// Das Warnfenster ist erreicht. Erst einmal nachfragen, ob die Frist
// inzwischen weiter hinten liegt — danach entscheidet der lokale Takt.
async function enterWarnWindow() {
    const moved = await refreshDeadline();
    if (moved) {
        return;
    }

    clearTimers();
    tick();
    tickTimer = window.setInterval(tick, TICK_MS);
}

// Ein Takt: rein lokal. Keine Anfrage, kein Server.
function tick() {
    if (deadline === null) {
        return;
    }

    const left = deadline - Date.now();

    if (left > WARN_BEFORE_MS) {
        // Die Frist ist von aussen weiter gerückt (anderer Tab, „Keep me
        // signed in"). Zurück in den Wartezustand.
        hideNotice();
        schedule();
        return;
    }

    if (claimLease(deadline)) {
        showNotice(left);
    } else {
        hideNotice();
    }
}

// Fragt `/api/auth/me` **einmal** und übernimmt die Fristen. `true`, wenn die
// Frist danach weiter hinten liegt und wieder gewartet wird.
async function refreshDeadline() {
    if (Date.now() - lastRefreshAt < REFRESH_MIN_GAP_MS) {
        return false;
    }
    lastRefreshAt = Date.now();

    let result;
    try {
        result = await fetchCurrentUser();
    } catch (error) {
        // Kein Netz ist kein Urteil über die Sitzung. Der Countdown läuft mit
        // dem bekannten Wert weiter.
        return false;
    }

    if (!result || !result.ok || !result.data) {
        return false;
    }

    const fresh = earlierDeadline(result.data);
    if (fresh === null || fresh <= deadline) {
        return false;
    }

    deadline = fresh;
    // Das Wegklicken galt für die alte Frist; die neue ist eine neue Aussage.
    writeLease({ owner: null, at: 0, dismissedFor: null });
    hideNotice();
    schedule();
    return true;
}

// Startpunkt. `user` ist die Antwort von `/api/auth/me`, die `menu.js` beim
// Laden schon geholt hat — dieses Modul stellt dafür keine eigene Anfrage.
export function initSessionNotice(user) {
    const found = earlierDeadline(user);
    if (found === null) {
        // Ein Server ohne diese Felder (oder eine unlesbare Zeitangabe) bekommt
        // keinen erratenen Countdown.
        return;
    }

    deadline = found;

    if (!started) {
        started = true;

        // Sofortmeldung zwischen den Tabs: das ist die Rolle, für die man sonst
        // `BroadcastChannel` genommen hätte.
        window.addEventListener('storage', event => {
            if (event.key !== LEASE_KEY || !isNoticeVisible()) {
                return;
            }
            const lease = readLease();
            if (!lease || lease.owner !== tabId) {
                hideNotice();
            }
        });

        // Nach einem Schlaf des Rechners sind die Timer beliebig weit hinterher.
        document.addEventListener('visibilitychange', () => {
            if (!document.hidden && deadline !== null) {
                if (deadline - Date.now() <= WARN_BEFORE_MS) {
                    enterWarnWindow();
                } else {
                    schedule();
                }
            }
        });
    }

    schedule();
}

// Nur für Messungen im Browser: der Zustand, den ein Tester sonst nicht sehen
// kann. Liest, verändert nichts.
export function sessionNoticeState() {
    return {
        deadline: deadline,
        warnBeforeMs: WARN_BEFORE_MS,
        visible: isNoticeVisible(),
        tabId: tabId,
        lease: readLease(),
        ticking: tickTimer !== null,
        waiting: warnTimer !== null
    };
}
