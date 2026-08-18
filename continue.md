# continue.md — Wiederaufnahme

Stand: 18.08.2026. Vorheriger Lauf endete am Token-Limit, Alle Agenten **geordnet gestoppt**,
nicht abgestürzt.
Arbeitsanweisung: `AGENTS.md`. Board: https://plankton.tiny-dev.de/p/rclone-gui

---

## 1. Zustand des Arbeitsbaums

**Grün, und zwar geprüft, nicht angenommen:**

```
cargo check      0 Fehler
cargo test       343 bestanden, 0 Fehlschläge, 8 ignoriert
JS-Module        alle 21 als ESM syntaktisch sauber
Marker           <!-- RCLONE_GUI_SCRIPTS --> vorhanden
clippy           18 Findings, alle vorbestehend
                 (main.rs 13, sync.rs 5) — Ticket e81f29bb
```

**Alles ist committet** — Branch `feat/epic1-ui-rework-und-sicherheitshaertung`,
Commit `1672d62`, gepusht nach `origin`. Von dort aus weiterarbeiten und später nach
`main` mergen.

**`.env` ist bewusst NICHT im Commit**: dort steht ein echtes Admin-Passwort im
Klartext, und die Datei wird getrackt. Ein Push hätte es nach GitHub getragen, wo es
auch nach dem Löschen in der Historie bliebe. Wer `git add -A` benutzt, muss das
mitdenken — oder `git rm --cached .env` + Eintrag in `.gitignore` + ein `.env.example`
ohne Werte. Das ist eine Entscheidung des Nutzers, weil es alle Klonenden betrifft.

`.gitignore` wurde um `/data/rsyncd/` ergänzt — dort liegt `secrets/rsyncd.secrets` im
Klartext, das wäre sonst mitcommittet worden.

---

## 2. Board

| Spalte | Anzahl |
|---|---|
| Done | **61** |
| Testing | 5 (ungeprüft, siehe unten) |
| In Progress | 0 |
| Todo | 75 |

### In `Testing`, noch von niemandem geprüft
| Ticket | Was |
|---|---|
| `07267d40` | SSRF-Schutz, **Nachbesserung** nach Rückweisung |
| `e3e971ee` | `wait_until_listening` per TCP-Connect statt Logzeile |
| `f581f435` | Gesperrte PID-Datei — nur die `rsyncd.rs`-Hälfte |
| `88b8c455` | stunnel schreibt jetzt ein Log |
| `e2d122fb` | 401-Behandlung in `api.js` |

### Zurück in `Todo`, weil der Agent mittendrin gestoppt wurde

**Korrektur (nachträglich, wichtig):** Die Annahme „Teilarbeit liegt uncommittet im
Arbeitsbaum" war **falsch**. Der Commit `1672d62` wurde gemacht, *während* diese Agenten
liefen, und hat ihre Arbeit **mit eingesammelt** — genau der Fall, vor dem `AGENTS.md`
warnt. Zwei der vier Tickets waren dadurch bereits vollständig umgesetzt; ein Nachfolger
hätte sie beinahe neu geschrieben.

**Also: erst `git log -p` und den Ist-Zustand der Datei ansehen, nicht nur
`git status`.** Ein sauberer Arbeitsbaum heisst hier *nicht*, dass nichts getan wurde.

| Ticket | Stand beim Abbruch |
|---|---|
| `40103f77` | Passwort-Reset per Token. **Praktisch nichts** — Agent war beim Lesen. |
| `0cedda6f` | Audit-Log-Grössengrenze. Weit fortgeschritten; `config/logrotate-rclone-gui.conf` existiert bereits. |
| `8cc0df6b` | `start.sh`-Krücke entfernen. Unklar wie weit. |
| `c9a674ee` | Atomarer Config-Schreibweg. War bei `remove_key_from_contents` / `write_config_atomically` in `config_manager.rs`. |

---

## 3. Epic-Stand

**Epic 1 (UI-Rework) ist bis auf ein Ticket fertig.** 12 von 13 in `Done`; offen nur
`27e3e014` (Downloader „Von URL holen"), dessen Vorbedingung — die Datentrennung —
inzwischen erfüllt ist. **Das ist der kürzeste Weg zu einem abschliessbaren Epic und
damit zum ersten Commit.**

Der SSRF-Baustein (`07267d40`) ist die Grundlage dafür und liegt bereits in `Testing`.

---

## 4. Was der Nutzer zuletzt wollte

1. **`40103f77` Passwort-Reset per Terminal-Token** — ausdrücklicher Wunsch, noch nicht
   gebaut. Begründung im Wortlaut: *„damit ich rein komme wenn ich es mal vergessen
   sollte."* `ADMIN_PASSWORD_DEFAULT` wurde auf seinen Wunsch **verworfen**,
   `RCLONE_GUI_ADMIN_PASSWORD` genügt.
2. **Er testet die Anwendung selbst auf dem Host.** Zwei seiner Fehlermeldungen führten
   zu Tickets: `bb6e1f0b` (erledigt) und `50c8ec48` (rootloser rsync-Daemon, offen).

### Beim Testen auf dem Host: der Admin-Zugang
In `data/tasks.db` liegt ein Konto `admin` mit Home-Pfad `/`, **dessen Passwort niemand
kennt**. Um hineinzukommen:

```bash
cp data/tasks.db data/tasks.db.bak
sqlite3 data/tasks.db "delete from sessions; delete from users;"
RCLONE_GUI_ADMIN_PASSWORD='<passwort>' cargo run -- --bind 127.0.0.1:8080
```

Der Home-Pfad `/` ist ein zweiter Grund für das Neuanlegen: seit der Datentrennung ist
der Home-Pfad die Wurzel des erlaubten Bereichs.

### rsync-Daemon auf dem Host
`RCLONE_GUI_RSYNCD_DIR=$PWD/data/rsyncd` behebt `os error 13`. Danach folgt aber der
nächste Anschlag (Port 873 ist privilegiert), dann chroot, dann uid/gid — deshalb
Ticket `50c8ec48`.

---

## 5. Korrekturen an früheren Annahmen

Diese Datei hat schon einmal Falsches behauptet. Was inzwischen widerlegt ist:

- **`rclone` liegt auf dem Host** (`/usr/bin/rclone`, v1.75.0), nicht nur im Container.
  `AGENTS.md` behauptete lange das Gegenteil, und der Orchestrator hat dem Nutzer auf
  dieser Grundlage eine falsche Fehlerdiagnose gegeben. Im Image ist es **1.70.1** —
  Versionsabhängiges gegen beide prüfen. `rsync` ist weiterhin nur im Container.
- **Eine *verwaiste* `flock` gibt es nicht.** Der Kernel gibt die Sperre mit dem Prozess
  frei, egal wie er stirbt. Wer die PID-Datei hält, **lebt**. Die ursprüngliche Annahme
  von `f581f435` war falsch; die Lösung fragt jetzt `/proc/locks`.
- **`node --check datei.js` ist für `static/js/**` wertlos** — siehe nächster Abschnitt.

---

## 6. Der teuerste Fehler dieses Laufs

`static/js/ui/config.js` deklarierte `setHidden` zweimal. Als ES-Modul ist das ein
`SyntaxError`, der die Importkette von `main.js` nie anlaufen lässt: **die gesamte
Oberfläche war tot**, ohne sichtbare Fehlermeldung.

**Drei Agenten haben brav `node --check` ausgeführt und grün gemeldet** — Node parst
`.js` als CommonJS-Script, und dort sind doppelte Funktionsdeklarationen erlaubt. Der in
`AGENTS.md` vorgeschriebene Prüfschritt konnte diese Fehlerklasse nicht finden.

Gefunden hat es erst ein Tester, der die Seite **tatsächlich öffnete**. Der Prüfschritt
in `AGENTS.md` ist korrigiert (`.mjs`), aber die Lehre ist die grössere:
**ein Werkzeuglauf ersetzt nicht, das Ding einmal anzufassen.**

---

## 7. Was sich in diesem Lauf bewährt hat

Diese Muster haben echte Fehler gefunden, die reines Lesen übersehen hätte — sie gehören
in jeden künftigen Prompt:

- **Gegenprobe bei jedem Null-Ergebnis.** „Kein XSS gefunden" ist wertlos, solange nicht
  gezeigt ist, dass derselbe Aufbau ein echtes XSS **melden würde**. Ein Tester hat so
  bewiesen, dass sein argv-Log-Beweis trägt (365/365 Treffer im Kontrollfall,
  0/2589 im Echtfall).
- **Mutationstest bei Nebenläufigkeit.** Zweimal wurde die Implementierung durch eine
  naive ersetzt, um zu zeigen, dass der Test **durchfällt**. Beim zweiten Mal deckte das
  auf, dass ein atomares `UPDATE` mit nachfolgendem `SELECT` immer noch falsch zählt.
- **Tests wieder verwerfen, die nicht fehlschlagen können.** Ein Entwickler hat einen
  eigenen neuen Test gestrichen, weil er in der Gegenprobe grün blieb: „hätte nur
  Vertrauen erzeugt."
- **Eigene Kopie des Baums**, wenn parallel gearbeitet wird — plus `sha256sum` der
  geprüften Dateien im Ticketkommentar. Sonst gilt ein Urteil für eine Fassung, die es
  nicht mehr gibt.
- **Eigene Chrome-Instanz** statt des geteilten Browsers. Im geteilten Chrome bleiben
  Tabs auf `hidden`, und dort verzögert Chrome das Media-Preload so weit, dass gar keine
  Anfrage kommt — ein Tester hätte fast „funktioniert nicht" gemeldet.
- **Melden statt bauen**, wenn eine fremde Datei im Weg ist. Ein Agent hat ein bereits
  hinzugefügtes Feld **zurückgenommen**, statt `main.rs` anzupassen. Genau richtig.

### Ein wiederkehrendes Muster, fünfmal gefunden
`derive(Debug)` mit einem Geheimnis im Struct: `LoginOutcome`, `ModuleConfig`,
`RcloneConfig`, `ConfigRequest`, `NewShare`. Ein Tester hat `src/**` abschliessend
durchsucht — **die Serie ist bei fünf geschlossen**. Bei jedem neuen Struct mit
Geheimnis: handgeschriebenes `Debug` **und ein Test**, sonst entsteht es wieder.

---

## 8. Fallstricke im Werkzeug

- **Plankton akzeptiert nur volle UUIDs.** `move_task` mit einer Kurz-ID läuft **ohne
  Fehler ins Leere** (`null`), das Ticket bleibt liegen. Ein Agent hat so einen
  Statuswechsel verloren, ohne es zu merken.
- `add_log` ist deprecated und wird auf `add_comment` umgeleitet. Argumente:
  `project_id`, `task_id`, **`text`**.
