# AGENTS.md — rclone-gui

Verbindliche Arbeitsanweisung für alle Agenten in diesem Repository.
`CLAUDE.md` ist ein Symlink auf diese Datei.

---

## 1. Das Projekt

Web-GUI für rclone: ein Rust-Backend (axum) startet `rclone` als Subprozess und
liefert ein Vanilla-JS-Frontend aus. Kein Framework, kein Build-Step im Frontend.

| | |
|---|---|
| Backend | Rust 2021, axum 0.7, tokio, sqlx (SQLite) |
| Frontend | `static/index.html` + `static/app.js`, Vanilla JS, kein Bundler |
| Datenbank | `data/tasks.db` (SQLite), Schema in `src/database.rs` |
| rclone-Config | `data/cfg/rclone.conf` |
| Job-Logs | `data/log/<job_id>.log` (rclone JSON-Log) |

### Verzeichnisstruktur

```
src/
  main.rs             Routing, CLI (clap), Startup
  models.rs           Serde-Structs für API und Config
  database.rs         SQLite-Schema und Queries
  config_manager.rs   Lesen/Schreiben von rclone.conf
  handlers/
    config.rs         CRUD für rclone-Remotes
    files.rs          Verzeichnis-Auflistung via `rclone lsjson`
    sync.rs           Sync-Jobs: Start, Fortschritt, Log-Parsing
    tasks.rs          Gespeicherte Tasks
static/
  index.html
  app.js
```

### Fallstricke im Frontend

- **Der Marker `<!-- RCLONE_GUI_SCRIPTS -->` in `static/index.html` NICHT entfernen.**
  `serve_index()` ersetzt ihn durch das Inline-Script mit `window.DEFAULT_PATH` und
  `<script type="module" src="/static/js/main.js">`. Ein erklärender Kommentarblock
  steht direkt darüber.

  Fehlt der Marker, schlägt es inzwischen **sichtbar** fehl: `check_index_marker()` warnt
  beim Start auf stderr und im Log, und `serve_index()` liefert HTTP 500 mit Fehlerseite
  statt einer Seite ohne JavaScript. Vorher war es ein stiller Totalausfall — ein Agent
  hatte den damaligen `app.js`-Tag beinahe als Leiche entfernt.

- **`rustfmt src/main.rs` formatiert als Crate-Root potenziell den ganzen Modulbaum mit.**
  Wer nur die eigene Datei formatieren will, prüft das Ergebnis mit `git diff --stat`,
  bevor er abgibt.

- Tailwind läuft als **Browser-Variante** (`@tailwindcss/browser`). Die generiert nur
  Klassen, die sie beim Scannen im DOM findet. Klassen, die erst zur Laufzeit per JS
  hinzugefügt werden, existieren im CSS **nicht**. Für dynamische Sichtbarkeit
  deshalb eigene Klassen im `<style>`-Block verwenden (`.is-open`, `.is-active`,
  `.is-visible`) statt Tailwind-Utilities per `classList.add()`.
- Modale sind native `<dialog>`-Elemente und liegen im Top-Layer. Eigene
  ESC-Behandlung und Fokus-Traps müssen aussteigen, solange ein `<dialog open>`
  vorhanden ist, sonst kollidieren sie mit dem Browserverhalten.

- **`node --check datei.js` ist als Prüfung NICHT ausreichend.** Node behandelt `.js`
  als *Script*; die Dateien unter `static/js/` werden im Browser aber als **ES-Modul**
  geladen, und die Regeln unterscheiden sich. Eine doppelte Funktionsdeklaration ist im
  Script erlaubt und im Modul ein `SyntaxError`.

  Real passiert: zwei `function setHidden` in `config.js`. `node --check` war grün, der
  Entwickler hat abgeliefert, und im Browser riss der `SyntaxError` den **gesamten
  Modulgraph** von `main.js` mit — die komplette Oberfläche war tot, ohne sichtbare
  Fehlermeldung. Gefunden hat es erst ein Tester, der die Seite tatsächlich öffnete.

  Deshalb **immer als Modul prüfen**:
  ```bash
  for f in $(find static/js -name '*.js'); do
      cp "$f" "$SCRATCH/_m.mjs"
      out=$(node --check "$SCRATCH/_m.mjs" 2>&1)
      [ -n "$out" ] && echo "FEHLER in $f: $out"
  done
  ```
  Die Endung `.mjs` ist der ganze Unterschied. Und selbst das ersetzt nicht, die Seite
  einmal wirklich zu öffnen und die Browser-Konsole anzusehen.

### Wie der Sync heute funktioniert

`src/handlers/sync.rs` startet `rclone copy` als Subprozess mit
`--use-json-log --log-file data/log/<job_id>.log`. Der Fortschritt wird **nicht** von
stdout gelesen, sondern aus dieser Logdatei geparst (`parse_progress_from_log`).
`copy` löscht nie im Ziel — das ist Absicht und ändert sich erst mit dem Ticket
„Sync-Option Im Ziel löschen".

### Befehle

```bash
cargo check                  # schnelle Prüfung
cargo build                  # Debug-Build
cargo clippy -- -D warnings  # Lint, muss sauber sein
cargo fmt                    # Formatierung
cargo test                   # Tests
docker compose up --build    # Vollständiger Lauf inkl. rclone-Binary
```

**`rclone` liegt inzwischen auch auf dem Host** — `/usr/bin/rclone`, v1.75.0. Diese Datei
behauptete lange das Gegenteil, und der Orchestrator hat einem Nutzer auf dieser Grundlage
eine falsche Fehlerdiagnose gegeben. Wer eine Aussage über die Umgebung braucht, prüft sie
(`command -v rclone`), statt sie hier abzulesen.

Zwei Einschränkungen bleiben:

- **Die Version auf dem Host ist nicht die des Images** (Container: 1.70.1). Was
  versionsabhängig ist — Ausgabeformate, verfügbare Unterbefehle, Verhalten von
  `obscure`/`reveal` — gehört gegen **beide** geprüft.
- `rsync` gibt es weiterhin **nur im Container**. Alles, was ein echtes rsync-Binary
  braucht, läuft über Docker.

Für Nachweise über `argv` ist ein **Stub** ohnehin besser als das echte Binary: er
kontrolliert das Zeitfenster, in dem man `/proc/<pid>/cmdline` lesen kann.

---

## 2. Ursprüngliche Projektanweisung (aus der früheren CLAUDE.md)

Wortlaut erhalten, weil er den Tasks-Teil der App erklärt. **Dieser Teil ist bereits
umgesetzt** (Commits `23b6c1b`, `ff476bd`) und dient nur noch als Kontext:

> ich möchte in dem tool ein kleine anpassung machen.
> Neu: Tasks
> Beim Sync Button öffnet sich ein Overlay in dem overlay soll man die option haben ein
> Task zu erstellen mit den einstellungen für diesen Sync job, der Task muss ein name
> haben, der alphanumerisch ist. Der Task wird dann in der Datenbank gespeichert. Im
> Frontend gibt es dann ein Tab "Tasks" mit passendem icon, wenn man da drauf klickt
> sieht man angelegte tasks. Man soll tasks über ein Mülleimer löschen können und mit
> einem play button ein Syncjob Starten.
> Die CLI App soll eine option haben --start-task=<taskname> um das selbe zu machen wie
> in der gui, nur über die cli, der output der im log erscheint sollte beim cli auch
> ausgegeben werden

Beachte: der Tasks-Tab wandert im Zuge von Epic 1 in das Menü oben rechts.

---

## 3. Plankton-Board

Alle Arbeit hängt an Tickets im Board **rclone-gui**.

- Projekt-ID: `288b23d8-26ef-4522-baef-582c205eba1b`
- URL: https://plankton.tiny-dev.de/p/rclone-gui
- Spalten: `Todo` `e985933c-6b12-4852-bed0-647ed978c7eb` · `In Progress`
  `55c97254-acdd-4e4a-a3f8-7d30ea4230cd` · `Testing` `3d9ffc04-c12d-464e-9c1f-0822fd6846c2`
  · `Done` `37cc0f4c-7e5e-471a-b838-c9874eb2fcd3`

Zugriff über die Skill-Anleitung `~/.claude/skills/plankton/SKILL.md`.
Token: **letzter** `PLANKTON_TOKEN`-Eintrag in `~/.claude/plankton_secrets.md`
(der erste Eintrag ist ungültig).

```bash
export PLANKTON_TOKEN=$(grep '^PLANKTON_TOKEN=' ~/.claude/plankton_secrets.md | cut -d= -f2- | tail -1)
curl -s -X POST https://plankton.tiny-dev.de/mcp \
  -H "Content-Type: application/json" -H "Authorization: Bearer $PLANKTON_TOKEN" \
  -d '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"get_project","arguments":{"id":"288b23d8-26ef-4522-baef-582c205eba1b"}},"id":1}'
```

> **Wichtig:** `get_project` liefert die `blocks`-Relationen **nicht** zurück — die
> Felder kommen leer. Die Reihenfolge steht deshalb unten in Abschnitt 5 und ist dort
> die maßgebliche Quelle, nicht das Board.

---

## 4. Orchestrator-Flow

Der Orchestrator schreibt **selbst keinen Code**. Er koordiniert nur.

### Ein Durchlauf

1. **Auswählen** — bis zu 4 Tickets aus `Todo`, deren Abhängigkeiten (Abschnitt 5)
   erfüllt sind. Bevorzugt aus demselben Epic, damit Epics abgeschlossen werden.
2. **Konfliktprüfung** — die gewählten Tickets dürfen **nicht dieselben Dateien**
   umschreiben. Jedem Developer wird im Prompt gesagt, welche Dateien ihm gehören und
   welche er nicht anfassen darf.

   **Die Obergrenze ist ein Maximum, kein Ziel.** Es laufen so viele Developer, wie
   sich disjunkte Dateibereiche zuschneiden lassen — notfalls nur einer. Ein
   Merge-Konflikt in einem 1000-Zeilen-File kostet mehr, als der zweite Agent einbringt.

   **Ein Tester und ein Developer dürfen nicht gleichzeitig dieselbe Datei halten.**
   Es ist passiert: `remotepane.js` wurde mitten im Testlauf überschrieben. Der Tester
   hat die ausgelieferte Fassung byte-genau rekonstruiert und separat geprüft — sein
   Urteil galt damit für eine Version, die es im Arbeitsbaum nicht mehr gab, und die
   neue blieb ungetestet. Beim Planen einer Runde also auch die Tester-Dateien als
   belegt behandeln, nicht nur die der Developer.

   Häufige Kollisionspunkte:
   - `static/app.js` — Engpass fast aller Frontend-Tickets. Nur **ein** Agent gleichzeitig.
   - `src/main.rs` — auch rein additive Routen-Registrierungen kollidieren. Nur **einer**.
   - `Cargo.toml` — dito.
3. **Verschieben** nach `In Progress`, Log-Eintrag mit dem Namen des Agenten.
4. **Spawnen** — bis zu 4 Developer und bis zu 2 Tester parallel. Jeder Prompt enthält
   Ticket-ID, Ticket-Beschreibung, Dateibesitz und den Verweis auf diese Datei.
   Tester lesen nur und kollidieren untereinander nie — sie dürfen immer voll besetzt
   werden, solange es Tickets in `Testing` gibt.
5. **Einsammeln** — Ergebnisse prüfen, `cargo check` + `cargo clippy` selbst laufen
   lassen. Bricht der Build, geht das Ticket zurück an den Developer, nicht weiter.
6. **Testing** — Ticket nach `Testing`, Tester prüft gegen die Akzeptanzkriterien und
   schreibt das Ergebnis als **Kommentar** (`add_comment`), nie als Log.
7. **Status-Report** an den Nutzer: was lief, was ist grün, was blockiert.

### Ticket-Fluss (verbindlich)

```
Todo  →  In Progress  →  Testing  →  Done
 ↑                          │
 └──────── Tester findet ───┘
           einen Fehler
```

- **Developer** ziehen von `Todo` nach `In Progress`, bei Fertigstellung nach `Testing`.
- **Tester** prüfen, was in `Testing` liegt:
  - **fehlerfrei → direkt nach `Done`**, mit Kommentar
  - **Fehler gefunden → zurück nach `Todo`**, mit Kommentar, der den Fehler so
    beschreibt, dass ein Developer ihn ohne Rückfrage beheben kann
- Es gibt kein Zwischenlager: ein geprüftes Ticket bleibt nicht in `Testing` liegen.

### Epic-Abschluss

Sobald **alle** Subtickets eines Epics in `Done` sind:

1. Der Orchestrator lässt das Epic **als Ganzes** durchtesten — nicht die Summe der
   Einzelteile, sondern das Zusammenspiel: greifen die Tickets ineinander, ist der
   fachliche Zweck des Epics erfüllt?
2. **Fehlerfrei** → Epic nach `Done`, Commit
   (`feat(epic-<n>): <Titel>` mit Auflistung der Tickets).

   **Zum Zeitpunkt:** Bei mehreren parallelen Developern gehört der Arbeitsbaum
   zeitweise niemandem — ein Commit sammelt dann Arbeit aus fremden, noch offenen
   Tickets mit ein. Das ist passiert und wurde von zwei Agenten gemeldet.

   Regeln daraus:
   - **Nie in einen roten Baum committen.** Vor jedem Commit `cargo check` und
     `cargo test`; ist etwas rot, warten statt committen.
   - Der saubere Zeitpunkt ist eine Lücke, in der **kein** Developer läuft. Lässt sich
     das nicht abwarten, im Commit-Text benennen, dass er über das Epic hinaus Arbeit
     enthält — ein falsch zugeschnittener Commit ist besser als tagelang ungesicherte
     Arbeit, aber er soll nicht so tun, als wäre er sauber.
3. **Fehler** → neue Tickets in `Todo`, Epic bleibt offen.

Der Lauf ist fertig, wenn `Todo`, `In Progress` und `Testing` leer sind.

### Besetzung richtet sich nach dem Engpass
Ist `Testing` voll, laufen bis zu **6 Tester** und entsprechend weniger Developer.
Ist `Testing` leer, laufen bis zu **4 Developer**. Tester lesen nur und kollidieren
untereinander nie — sie dürfen immer voll besetzt werden.

### Abbruchbedingungen

Der Loop endet, wenn `Todo` leer ist oder der Nutzer stoppt. Zusätzlich **anhalten und
nachfragen** bei:

- Zwei aufeinanderfolgenden fehlgeschlagenen Durchläufen am selben Ticket
- Einer Änderung, die bestehende Nutzerdaten in `data/` migrieren oder löschen würde
- Einem Ticket, dessen Beschreibung eine offene Entwurfsentscheidung enthält
  („im Ticket festlegen", „entscheiden") — die trifft der Nutzer, nicht der Agent

---

## 5. Reihenfolge und Abhängigkeiten

Maßgeblich, weil das Board sie nicht ausliefert. Ein Ticket darf erst starten, wenn
alle genannten Vorbedingungen in `Done` sind.

### Epic 1 — UI-Rework (`97ba1490`)
| Ticket | ID | Vorbedingung |
|---|---|---|
| Menü oben rechts | `49eaea02` | — |
| Ordner-Navigation + Breadcrumb | `7a052a6b` | — |
| View-Modi List/Icon/Preview | `6ee90ae5` | `7a052a6b` |
| Datei-Vorschau Text/Bild/Video | `1fd6678b` | `7a052a6b` |
| Download + ZIP | `2a6dbfdb` | — |
| Downloader „Von URL holen" | `27e3e014` | `e1266aec` (Datentrennung) |

### Epic 2 — Sync-Modus (`cf5a9481`)
| Ticket | ID | Vorbedingung |
|---|---|---|
| Modus-Umschalter + Backend-Wahl | `6c8d9a6a` | `49eaea02` |
| Remote-Pane | `59c6503c` | `6c8d9a6a` |
| Mehrfachauswahl + Sync-Button | `73a59321` | `6c8d9a6a`, `7a052a6b` |
| Job-Anzeige im Browser | `ba458bb2` | `73a59321` |
| Sync-Option „Im Ziel löschen" | `7950051d` | `73a59321` |

### Epic 3 — rsync-Transport (`6b8fd434`)
| Ticket | ID | Vorbedingung |
|---|---|---|
| Spike rsync-Daemon + OAuth | `19adf6ba` | — |
| OAuth2-Provider | `8b1f4477` | `19adf6ba`, **`aef5456d` (Auth-Fundament)** |
| OAuth2-Client / Pairing | `d32a90b9` | `8b1f4477` |
| rsync-Daemon Lifecycle | `7dcd5a54` | `19adf6ba` |
| TLS-Terminierung Port 874 | `6e4f59c3` | `7dcd5a54` |
| rsync-Client + Engine-Abstraktion | `7a7bb559` | `7dcd5a54`, `d32a90b9` |
| Remote-Browsing-API | `9e83c167` | `8b1f4477` |
| Security-Hardening Peer | `1f8598ee` | `7dcd5a54` |
| Netzwerk-Doku + Selbsttest | `6a94c4cd` | `6e4f59c3` |
| Docker rsync | `e21c8b54` | — |

### Epic 4 — Nutzer und Freigaben (`5ac838e1`)
| Ticket | ID | Vorbedingung |
|---|---|---|
| **Auth-Fundament** | `aef5456d` | — |
| Benutzerverwaltung | `ee599cf5` | `aef5456d` |
| Datentrennung / Home | `e1266aec` | `aef5456d` |
| Eigene rclone-Remotes pro Nutzer | `65fe551e` | `e1266aec` |
| Anonyme Freigabe-Links | `34e2b138` | `e1266aec`, `2a6dbfdb` |
| Freigaben-Übersicht | `79391607` | `34e2b138` |
| Remote-Freigabe an Nutzer | `8613239e` | `65fe551e`, `34e2b138` |
| [Später] Ordner an Nutzer freigeben | `4fc933cb` | **zurückgestellt, nicht einplanen** |

**`aef5456d` (Auth-Fundament) ist der große Hebel.** Es zieht Auth unter die gesamte
bestehende App und berührt jeden Handler. Es läuft allein, nie parallel zu etwas
anderem.

---

## 6. Regeln für Developer-Agenten

### Umfang
- Genau **ein Ticket**. Keine Nachbarbaustellen, kein Refactoring nebenbei.
- Die Akzeptanzkriterien des Tickets sind die Definition of Done. Alle abhaken.
- Enthält das Ticket eine offene Entscheidung („im Ticket festlegen"), **nicht raten** —
  an den Orchestrator zurückmelden.

### Dateibesitz
Der Prompt nennt die Dateien, die dem Agenten gehören. Andere Dateien werden **nicht**
geändert. Wird eine fremde Datei zwingend gebraucht, zurückmelden statt anfassen.

### Code
- Stil der Umgebung übernehmen: Kommentardichte, Namensgebung, Fehlerbehandlung
  (`anyhow::Result`, `tracing` für Logs).
- Frontend bleibt Vanilla JS, kein Framework, kein Bundler.
- **Bestand:** `static/index.html` lädt Tailwind und daisyUI von `cdn.jsdelivr.net`
  (Zeilen 7–8). Das ist der Ist-Zustand. Keine **weiteren** CDN-Referenzen hinzufügen;
  die bestehenden werden nicht im Rahmen eines fachlichen Tickets entfernt.
- Neue Abhängigkeiten nur, wenn das Ticket sie nahelegt; im Bericht begründen.
- **Bei jeder neuen Abhängigkeit die MSRV gegen den Docker-Builder prüfen.** Der Host
  hat eine neuere Toolchain als das Image — ein Crate mit höherer `rust-version` baut
  lokal problemlos und bricht den Container-Build, ohne dass `cargo check` etwas merkt.
  Real passiert: `zip` 8.6.0 verlangt rustc 1.88, der Builder stand auf 1.87.
  ```bash
  grep "^FROM rust:" Dockerfile                                    # Builder-Version
  grep -rn "rust-version" ~/.cargo/registry/src/*/<crate>-<ver>/Cargo.toml
  ```
  Passt es nicht, im Bericht melden — den Builder anzuheben ist **nicht** deine
  Entscheidung, `Dockerfile` gehört einem anderen Ticket.
- Kein `unwrap()`/`expect()` in Request-Pfaden.
- Jeder vom Client kommende Pfad wird serverseitig kanonisiert und gegen den erlaubten
  Wurzelpfad geprüft — auch über aufgelöste Symlinks. Das ist nicht verhandelbar.
- Keine Secrets in `argv` (systemweit lesbar), nicht in Logs, nicht in die UI.

### Seit der Auth-Middleware: der Start legt ein Admin-Konto an
Ist die Tabelle `users` leer, erzeugt der Start einen Admin (`RCLONE_GUI_ADMIN_USER` /
`RCLONE_GUI_ADMIN_PASSWORD`, sonst `admin` mit Zufallspasswort). Das Passwort wird
**genau einmal** auf die Konsole geschrieben — nie ins Log.

Wer den Server versehentlich aus dem Projektverzeichnis startet, erzeugt damit ein Konto
in der echten `data/tasks.db`, dessen Passwort mit dem Terminal verschwindet. Der
nächste Agent steht dann vor einer Anmeldung, die er nicht passieren kann. Genau das ist
schon passiert.

Deshalb: **immer mit eigenem Datenverzeichnis testen** und das ausgegebene Passwort
festhalten, solange der Lauf dauert.

### Der Server liest `static/` und `data/` relativ zum CWD
Wer den Testserver aus einem eigenen Verzeichnis startet, bekommt die **einkompilierte**
`index.html` (`include_str!`-Fallback) und **404 auf alle JS-Module** — die App ist tot,
ohne dass irgendetwas eine Fehlermeldung ausgibt.

Also entweder aus dem Projektverzeichnis starten (mit `RCLONE_GUI_DEFAULT_PATH` auf den
Testbaum), oder `static/` ins Testverzeichnis symlinken. Ein Tester hat das gefunden,
nachdem seine Messungen unerklärlich leer blieben.

### Testdaten und Scratchpad
Alle Agenten teilen sich **ein** Scratchpad-Verzeichnis. Zwei Agenten haben sich
bereits gegenseitig ihr Testverzeichnis überschrieben, weil beide `testroot` hiessen.

Deshalb: Testverzeichnisse und Wegwerf-Dateien immer mit der **eigenen Ticket-ID** im
Namen anlegen, z.B. `scratchpad/testroot-dc91da86/`. Nach dem Lauf aufräumen.

**Das gilt auch für Hilfsskripte.** Es ist erneut passiert: ein Agent hat die Datei
`cdp.mjs` eines Testers überschrieben, während der damit arbeitete. Generische Namen
wie `cdp.mjs`, `probe.py`, `t3.mjs` oder `run.sh` sind praktisch garantierte
Kollisionen — immer Ticket-ID anhängen (`cdp-d6f2d111.mjs`).

Ebenso: laufende Testserver auf einem eigenen, unwahrscheinlichen Port binden
(`--bind 127.0.0.1:<port>`), Port 8080 ist oft belegt.

### Niemals `pkill -f` zum Aufräumen
`pkill -f rclone-gui` trifft die Testserver **aller** parallel laufenden Agenten. Ein
Tester hat es getan und dabei fremde Prozesse erwischt — nur eine
Berechtigungsverweigerung hat Schlimmeres verhindert.

Eigene Prozesse gezielt über die gemerkte PID beenden, oder über den eigenen Port
(`ss -ltnp 'sport = :<port>'`). Dasselbe gilt für `docker rm -f` mit Mustern:
nur eigene Container mit dem eigenen Namenspräfix.

### Session-Cookies kollidieren zwischen parallelen Agenten
**Cookies sind nicht nach Port getrennt.** Jeder Login auf `127.0.0.1:<irgendein Port>`
überschreibt das `rclone_gui_session` **aller anderen** Agenten auf demselben Host.

Real passiert: Der Browserlauf eines Testers endete in einer Login-Weiterleitung, und
gleichzeitig flog ein fremder Agent aus seiner Sitzung — beide suchten den Fehler in
ihrer eigenen Arbeit.

Deshalb **immer einen eigenen Cookie-Namen setzen**:
```
RCLONE_GUI_SESSION_COOKIE_NAME=rclone_gui_session_<agent-kürzel>
```
Das ist die eigentliche Trennung. Zusätzlich hilft `localhost:<port>` statt
`127.0.0.1:<port>`, aber das trennt nur zwei Gruppen, nicht N Agenten.

**Noch robuster, und der empfohlene Weg:** eine **eigene Loopback-Adresse** je Agent —
`--bind 127.0.1.<n>:<port>`. Der gesamte 127.0.0.0/8-Bereich zeigt auf das lokale
System, und Cookies sind nach **Host** getrennt. Damit können sich zwei Agenten selbst
dann nicht in die Quere kommen, wenn beide den Standard-Cookienamen benutzen. Ein Tester
hatte sich zweimal mitten im Lauf die Sitzung überschreiben lassen und den Fehler in der
Anwendung gesucht — mit eigener Adresse war es weg. Beides zusammen (eigene Adresse
**und** eigener Cookiename) kostet nichts und macht den Lauf reproduzierbar.

Ebenso: **Screenshots sind bei parallelen Agenten unbrauchbar** — mehrere teilen sich
Chrome, und das Bild zeigt womöglich ein fremdes Fenster. Aussagen über die Oberfläche
gehören aus DOM-Messungen im **eigenen** Tab, nicht aus Bildern.

### Browser-Tests brauchen `RCLONE_GUI_SESSION_COOKIE_SECURE=false`
Das Session-Cookie trägt `Secure`. Chrome nimmt es über `http://127.0.0.1` **nicht an** —
die Anmeldung scheint zu gelingen, aber jeder Folgeaufruf ist 401, und die Ursache sieht
nach einem Fehler der Anwendung aus.

Für Browser-Tests deshalb `RCLONE_GUI_SESSION_COOKIE_SECURE=false` setzen. Der Standard
bleibt `true` und wird beim Abschalten gewarnt — das ist Absicht.

### `dispatchEvent` schliesst kein natives `<dialog>`
Ein per `dispatchEvent(new KeyboardEvent('keydown', {key:'Escape'}))` erzeugtes Ereignis
schliesst ein natives `<dialog>` **nicht** — das Schliessen ist Browserverhalten und
hängt an einem echten Tastendruck, nicht am DOM-Event. Wer so prüft, meldet einen
Fehler, den es nicht gibt.

Für ESC-Tests also einen echten Tastendruck senden (z.B. CDP
`Input.dispatchKeyEvent`), oder das `cancel`-Ereignis des Dialogs beobachten.

### Browser-Tests: eine Falle, die schon zweimal zugeschlagen hat
In einem **nicht sichtbaren** Browser-Tab (`document.hidden === true`) feuern
`requestAnimationFrame` und `IntersectionObserver` nicht. Ein Test von Lazy-Loading
oder Chunk-Rendering meldet dort „0 geladen" — das ist Browserverhalten, kein Fehler
der App, und es wurde schon einmal fast als Fehlschlag gewertet und einmal übersehen.
Für solche Prüfungen einen sichtbaren Tab bzw. einen eigenen CDP-Lauf verwenden.

### Vor dem Abschluss
```bash
cargo check && cargo test          # müssen grün sein, ohne Ausnahme
cargo clippy --message-format short -- -D warnings | grep <deine-datei>
```

**Vorbestehende Schuld beachten:** `cargo clippy -- -D warnings` schlägt auf `main`
bereits fehl — 26 Findings, verteilt auf `src/main.rs` (14), `src/handlers/sync.rs` (5),
`src/config_manager.rs` (2), `src/handlers/files.rs` (1). Dazu 161 rustfmt-Abweichungen.
Das ist Bestand und wird im Ticket „Aufräumen: clippy und rustfmt" behoben.

Bis dahin gilt: **die von dir geänderten oder neu angelegten Dateien müssen 0
Clippy-Findings haben.** Fremde Findings nicht mitreparieren — das erzeugt Diffs quer
über andere Tickets. Ebenso **kein globales `cargo fmt`**, nur die eigenen Dateien
(`rustfmt src/pfad/deine_datei.rs`).

### Bericht an den Orchestrator
Kurz und faktisch: geänderte Dateien, getroffene Entscheidungen, was **nicht**
umgesetzt wurde und warum, was der Tester prüfen soll. Keine Erfolgsmeldung ohne
grünen Build.

### Plankton
`add_log` ist serverseitig **deprecated** und wird intern auf `add_comment` umgeleitet
(die API antwortet mit `"add_log is deprecated, use add_comment instead"`). Eine
technische Trennung zwischen Log und Kommentar gibt es dadurch nicht mehr.

Deshalb: **alle** Beiträge mit `add_comment`, aber mit Rollen-Präfix in der ersten Zeile,
damit der Verlauf lesbar bleibt:

- `Developer <ticket-id>:` — Fortschritt und Entscheidungen
- `Tester:` — Prüfergebnisse
- `Orchestrator:` — Prozessvermerke, Verifikation, Querbezüge

Die Argumente von `add_comment` heissen `project_id`, `task_id` und **`text`**
(nicht `content` oder `message`).

---

## 7. Regeln für Tester-Agenten

- Prüfen gegen die **Akzeptanzkriterien des Tickets**, nicht gegen den Eindruck.
- Ergebnis immer als `add_comment`, **niemals** als `add_log`.
- Aufbau: pro Kriterium erfüllt/nicht erfüllt, dann die Fundstellen mit
  `datei.rs:zeile`, dann ein Gesamturteil.
- Wo möglich tatsächlich ausführen (`cargo test`, Docker-Lauf), nicht nur lesen.
  Was nur gelesen und nicht ausgeführt wurde, wird als solches gekennzeichnet.
- Besonders prüfen: Pfad-Escapes (`..`, absolute Pfade, Symlinks), fehlende
  Rechteprüfung, Secrets in Logs oder argv, nicht behandelte Fehlerfälle,
  `unwrap()` in Request-Pfaden.
- Ein durchgefallenes Kriterium ist ein Fehlschlag, auch wenn der Rest gut ist.
  Nicht schönreden.

---

## 8. Git

- Es wird auf `main` gearbeitet. Commits **nur beim Epic-Abschluss** durch den
  Orchestrator, nicht durch Developer-Agenten.
- Commit-Format: `feat(epic-<n>): <Titel>`, im Body die enthaltenen Tickets.
- `data/` enthält Laufzeitdaten (`tasks.db`, Logs, `rclone.conf`) und wird nicht
  committet.
