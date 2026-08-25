// „Von URL holen": Bedienung des serverseitigen Downloaders.
//
// Der Server holt die Datei (`POST /api/download-url`), nicht der Browser. Das
// ist der ganze Sinn der Sache — der Abruf läuft als regulärer Job mit Log,
// Fortschritt und Abbruch, und die SSRF-Prüfung liegt serverseitig
// (`src/handlers/downloader.rs`, `src/handlers/urlguard.rs`).
//
// Dieses Modul macht drei Dinge und nichts darüber hinaus:
//
//   1. den Dialog: URL, Zielordner, optionaler Dateiname
//   2. die Übersetzung der Ablehnungen in etwas, das dem Nutzer sagt, was er
//      ändern kann (siehe `explainFetchError`)
//   3. das Merken der eigenen Abruf-Jobs, damit die Job-Anzeige einen
//      Abbrechen-Knopf anbieten kann
//
// ## Warum die Job-IDs hier gemerkt werden
//
// `GET /api/sync` liefert Sync-Jobs und URL-Abrufe in **einer** Liste
// (`list_jobs_handler` in `src/main.rs` führt sie zusammen), und `SyncProgress`
// hat **kein** Feld, das die Herkunft nennt. Abbrechen kann aber nur der
// Downloader: `POST /api/download-url/:id/cancel` kennt nur seine eigenen IDs,
// und für einen Sync-Job gibt es überhaupt keine Abbruchroute (siehe die Notiz
// dazu in `jobs.js`). Ein Abbrechen-Knopf an einer Sync-Zeile wäre also ein
// Knopf, der nichts tut.
//
// Deshalb merkt sich dieses Modul die IDs, die es selbst gestartet hat — in
// `localStorage`, damit ein Reload oder ein zweiter Tab sie noch kennt. Das ist
// eine Krücke, und zwar eine bewusste: der saubere Weg ist ein Feld `kind` in
// `SyncProgress`. Das liegt in `src/`, gehört diesem Ticket nicht und ist im
// Bericht an den Orchestrator als nötiger Fremdeingriff benannt.
//
// Kein eigener Poller: gestartet und abgebrochen wird über `api.js`, das dabei
// `SYNC_STARTED_EVENT` feuert; `jobs.js` hängt an genau diesem Ereignis und
// holt die Liste einmal ausserhalb seines Taktes. Es gibt weiterhin genau eine
// Abfrage von `GET /api/sync`.

import * as api from '../api.js';
import { state } from '../state.js';
import { showToast } from '../util/dom.js';

// Eigene Abruf-Jobs: `{ "<job-id>": <epoch ms> }`. Ein Objekt und keine Liste,
// damit ein doppeltes Eintragen nicht wächst.
const OWN_JOBS_KEY = 'rclone-gui-url-fetch-jobs';

// Wie lange eine gemerkte ID aufbewahrt wird. Der Server räumt beendete Jobs
// nach 24 h weg (`list_sync_jobs` in `src/handlers/sync.rs`); zwei Tage sind
// reichlich und begrenzen den Eintrag gegen unbegrenztes Wachsen.
const OWN_JOBS_TTL_MS = 48 * 60 * 60 * 1000;

// Obergrenze, falls die Aufräumung durch eine Uhrverstellung ausfällt.
const OWN_JOBS_MAX = 200;

let ownJobs = null;

function readOwnJobs() {
    if (ownJobs) {
        return ownJobs;
    }

    ownJobs = {};
    try {
        const raw = window.localStorage.getItem(OWN_JOBS_KEY);
        const parsed = raw ? JSON.parse(raw) : null;
        if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
            const now = Date.now();
            Object.keys(parsed).forEach(id => {
                const at = Number(parsed[id]);
                if (Number.isFinite(at) && now - at < OWN_JOBS_TTL_MS) {
                    ownJobs[id] = at;
                }
            });
        }
    } catch (error) {
        // Privater Modus, gesperrter Speicher, kaputtes JSON. Ohne Gedächtnis
        // fehlt der Abbrechen-Knopf; der Abruf selbst ist davon unberührt.
        ownJobs = {};
    }
    return ownJobs;
}

function writeOwnJobs(jobs) {
    ownJobs = jobs;
    try {
        window.localStorage.setItem(OWN_JOBS_KEY, JSON.stringify(jobs));
    } catch (error) {
        /* siehe readOwnJobs() */
    }
}

function rememberOwnJob(jobId) {
    const jobs = readOwnJobs();
    jobs[String(jobId)] = Date.now();

    const ids = Object.keys(jobs);
    if (ids.length > OWN_JOBS_MAX) {
        ids.sort((a, b) => jobs[a] - jobs[b])
            .slice(0, ids.length - OWN_JOBS_MAX)
            .forEach(id => delete jobs[id]);
    }

    writeOwnJobs(jobs);
}

// Ob dieser Job ein URL-Abruf ist, den dieser Browser gestartet hat.
//
// „Nein" heisst nur „weiss ich nicht" — ein Abruf aus einem anderen Browser
// oder von vor mehr als zwei Tagen fällt hier durch. Die Folge ist ein
// fehlender Abbrechen-Knopf, nie ein falscher: eine ID, die der Downloader
// nicht kennt, beantwortet er mit „Job not found".
export function isUrlFetchJob(jobId) {
    return Object.prototype.hasOwnProperty.call(readOwnJobs(), String(jobId));
}

// Bricht einen laufenden Abruf ab. Der Server entfernt dabei das Bruchstück
// (`.part`) und setzt den Job auf `cancelled` — hier gibt es nichts
// aufzuräumen.
export async function cancelUrlFetch(jobId) {
    try {
        const result = await api.cancelUrlFetch(jobId);
        if (result.ok) {
            showToast('Cancelling the download …', 'info');
        } else {
            showToast('Could not cancel: ' + result.error, 'error');
        }
    } catch (error) {
        showToast('Could not cancel: ' + error.message, 'error');
    }
}

// ---------------------------------------------------------------------------
// Fehlermeldungen
// ---------------------------------------------------------------------------

// Der Downloader lehnt viel ab, und zwar absichtlich: `file:`/`ftp:`, Loopback,
// private Netze, die Cloud-Metadaten-Adresse 169.254.169.254, Weiterleitungs-
// ketten dorthin, DNS-Rebinding, Grössen- und Zeitgrenzen. Seine Meldungen sind
// fachlich korrekt, sagen aber nicht, ob der Nutzer etwas falsch gemacht hat
// oder auf eine bewusste Grenze gestossen ist. Genau das steht hier.
//
// Die Muster sind absichtlich locker (`includes`): die Meldungen kommen aus
// `GuardError::Display` und aus `user_message()` und dürfen sich im Wortlaut
// ändern, ohne dass hier eine Ablehnung unerklärt durchfällt — der Rohtext wird
// ohnehin immer mitgezeigt.
const EXPLANATIONS = [
    {
        match: 'gesperrten Bereich',
        text: 'This address is inside a network the server will not fetch from: '
            + 'loopback, private ranges and the cloud metadata address are blocked '
            + 'on purpose, and a redirect that ends up there is blocked too. '
            + 'This is a deliberate limit, not a typo — use a publicly reachable URL.'
    },
    {
        // With the quote: `MalformedUrl` also says "kein Schema", and the
        // matching runs in order — an address without any scheme is a malformed
        // address, not a rejected scheme. Measured: "nonsense" used to land here.
        match: "Schema '",
        text: 'Only http:// and https:// can be fetched. Schemes like file:, ftp: '
            + 'or gopher: are rejected before anything is contacted.'
    },
    {
        match: 'URL nicht verwertbar',
        text: 'The URL could not be read. Check the scheme, the host and any '
            + 'special characters — it has to be a complete address, e.g. '
            + 'https://example.com/file.zip'
    },
    {
        match: 'Namensauflösung',
        text: 'The host name did not resolve. Check the spelling; if the name only '
            + 'exists inside a private network, it cannot be fetched from here.'
    },
    {
        match: 'Weiterleitungen',
        text: 'The address redirected too many times. Every hop is checked again, '
            + 'and a chain this long is treated as a loop.'
    },
    {
        match: 'überschreitet',
        text: 'The file is larger than the limit for a URL fetch. Nothing was left '
            + 'behind — the partial file is removed.'
    },
    {
        match: 'Zeitgrenze',
        text: 'The fetch ran out of time. A very slow source has to be fetched '
            + 'another way.'
    },
    {
        match: 'gleichzeitige Downloads',
        text: 'Two URL fetches per account run at a time. Wait for one to finish, '
            + 'or cancel it in the job bar.'
    },
    {
        match: 'ausserhalb des erlaubten',
        text: 'The target folder is outside your home directory. Pick a folder '
            + 'inside it.'
    },
    {
        match: 'Dateiname ist nicht verwendbar',
        text: 'That file name cannot be used. Leave the field empty to let the '
            + 'server take the name from the response or from the URL.'
    },
    {
        match: 'kein Ordner',
        text: 'The target is a file, not a folder. Pick a folder.'
    },
    {
        match: 'ungültige HTTP-Antwort',
        text: 'The server at the other end did not answer with usable HTTP.'
    }
];

// `{ hint, detail }` — `hint` kann leer sein, `detail` ist immer der Wortlaut
// des Servers. Beides geht per `textContent` in die Seite.
export function explainFetchError(raw) {
    const detail = String(raw == null ? '' : raw);
    const found = EXPLANATIONS.find(entry => detail.includes(entry.match));
    return { hint: found ? found.text : '', detail: detail };
}

// ---------------------------------------------------------------------------
// Dialog
// ---------------------------------------------------------------------------

function byId(id) {
    return document.getElementById(id);
}

// Der Zielordner wird nicht getippt, sondern gewählt: der aktuelle Ordner
// (Vorauswahl), seine Unterordner aus der zuletzt geladenen Auflistung, und das
// Home. Ein freies Textfeld hätte hier nur eine Fehlerquelle mehr — die
// Wurzelprüfung liegt ohnehin serverseitig und **vor** jeder Nebenwirkung.
function fillTargets(select) {
    const options = [];
    const current = state.currentPath || '';

    if (current) {
        options.push({ value: current, label: 'This folder — ' + current });
    }

    const entries = (state.currentListing && state.currentListing.entries) || [];
    entries
        .filter(entry => entry.is_dir && entry.path)
        .forEach(entry => {
            options.push({ value: entry.path, label: '↳ ' + entry.name });
        });

    // Leerer Wert = Home. Der Server setzt bei fehlendem `target_path` genau
    // das ein, also wird das Feld dann weggelassen.
    options.push({ value: '', label: 'Home folder' });

    select.replaceChildren(...options.map(option => {
        const node = document.createElement('option');
        // Pfade und Namen kommen vom Server und sind Fremdeingabe. `value` und
        // `textContent` sind beides keine Markup-Senken.
        node.value = option.value;
        node.textContent = option.label;
        return node;
    }));

    select.value = current || '';
}

function setMessage(hint, detail) {
    const box = byId('url-fetch-message');
    const hintNode = byId('url-fetch-hint');
    const detailNode = byId('url-fetch-detail');
    if (!box || !hintNode || !detailNode) {
        return;
    }

    hintNode.textContent = hint || '';
    detailNode.textContent = detail ? 'Server: ' + detail : '';
    box.classList.toggle('is-visible', Boolean(hint || detail));
}

export function openUrlFetchDialog() {
    const dialog = byId('url-fetch-modal');
    if (!dialog) {
        return;
    }

    setMessage('', '');
    byId('url-fetch-url').value = '';
    byId('url-fetch-name').value = '';
    fillTargets(byId('url-fetch-target'));
    setBusy(false);

    dialog.showModal();
    byId('url-fetch-url').focus();
}

export function closeUrlFetchDialog() {
    const dialog = byId('url-fetch-modal');
    if (dialog && dialog.open) {
        dialog.close();
    }
}

function setBusy(busy) {
    const start = byId('url-fetch-start');
    if (start) {
        start.disabled = busy;
        start.textContent = busy ? 'Starting …' : 'Fetch';
    }
}

async function submitUrlFetch() {
    const urlField = byId('url-fetch-url');
    const url = urlField.value.trim();

    if (!url) {
        setMessage('Enter the address of the file to fetch.', '');
        urlField.focus();
        return;
    }

    const target = byId('url-fetch-target').value;
    const name = byId('url-fetch-name').value.trim();

    const request = { url: url };
    if (target) {
        request.target_path = target;
    }
    if (name) {
        request.filename = name;
    }

    setBusy(true);

    let result;
    try {
        result = await api.startUrlFetch(request);
    } catch (error) {
        setBusy(false);
        setMessage('The request did not reach the server.', error.message);
        return;
    }

    setBusy(false);

    if (!result.ok) {
        // Der Dialog bleibt offen: eine abgelehnte URL ist etwas, das der
        // Nutzer hier korrigieren soll, und nicht etwas, das er neu eintippt.
        const explained = explainFetchError(result.error);
        setMessage(explained.hint, explained.detail);
        return;
    }

    rememberOwnJob(result.data);
    closeUrlFetchDialog();
    // Der Job selbst ist ab jetzt in der Job-Leiste zu sehen; `api.js` hat das
    // Ereignis dafür schon gefeuert.
    showToast('Fetching started — see the job bar at the bottom.', 'success');
}

export function initUrlFetch() {
    const button = byId('file-url-fetch');
    if (button) {
        button.addEventListener('click', openUrlFetchDialog);
    }

    const start = byId('url-fetch-start');
    if (start) {
        start.addEventListener('click', submitUrlFetch);
    }

    // Enter im URL-Feld startet. Ein `<form>` im Dialog würde mit
    // `method="dialog"` schliessen statt abzuschicken.
    const urlField = byId('url-fetch-url');
    if (urlField) {
        urlField.addEventListener('keydown', event => {
            if (event.key === 'Enter') {
                event.preventDefault();
                submitUrlFetch();
            }
        });
    }
}
