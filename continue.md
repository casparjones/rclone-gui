# continue.md — Wiederaufnahme

Stand: 19.08.2026, 00:30. Lauf zur vereinbarten Frist geordnet beendet.
Arbeitsanweisung: `AGENTS.md`. Board: https://plankton.tiny-dev.de/p/rclone-gui

---

## 1. Wo die Arbeit liegt

**Branch `feat/epic1-ui-rework-und-sicherheitshaertung`, gepusht.** Von dort
weiterarbeiten und später nach `main` mergen.

```
1672d62  Epic 1 UI-Rework, Auth-Fundament und Sicherheitshaertung
7f99967  Passwort-Reset, Delete-Option und Haertung des Schreibwegs
```

**`.env` ist bewusst nicht committet** — dort steht ein echtes Admin-Passwort im
Klartext. Die Datei ist inzwischen gitignored; das Risiko ist damit strukturell weg.

### Eine Lehre, die Geld gekostet hat
Der erste Commit entstand, **während Agenten liefen**, und hat ihre Arbeit eingesammelt.
Ein Nachfolger las danach „Teilarbeit liegt uncommittet im Baum", fand einen sauberen
`git status` und hätte zwei fertige Tickets beinahe neu geschrieben.

**Ein sauberer Arbeitsbaum heisst hier nicht, dass nichts getan wurde.**
Vor dem Neuschreiben immer `git log -p -- <datei>` und den Ist-Zustand ansehen.

---

## 2. Zustand des Baums

**Grün, gemessen nach dem Ende aller Agenten:**

```
cargo check      0 Fehler
cargo test       395 bestanden, 0 Fehlschläge, 9 ignoriert
JS-Module        alle 21 als ESM syntaktisch sauber
Marker           <!-- RCLONE_GUI_SCRIPTS --> vorhanden
clippy           18 Findings, alle vorbestehend
                 (main.rs 13, sync.rs 5) — Ticket e81f29bb
```

---

## 3. Board

| Spalte | Anzahl |
|---|---|
| Done | **78** |
| Testing | 2 |
| In Progress | 0 |
| Todo | 74 |

In `Testing` liegen `7f74ec7b` (rsync-Exit-Codes) und `374aff19` (atomares
`save_to_file`). Beide sind gebaut und gemessen, nur die Abnahme fehlt.

---

## 4. Epic-Stand

**Epic 1 (UI-Rework) ist bis auf ein Ticket fertig** — offen nur `27e3e014`
(Downloader „Von URL holen"). Der SSRF-Baustein dafür (`07267d40`) ist **abgenommen**;
was fehlt, ist der produktive Transport (`c9857502`): eine TLS-fähige, **streamende**
Client-Bibliothek in `Cargo.toml`. **Das ist der kürzeste Weg zu einem abgeschlossenen
Epic.**

Beim Einbau zwingend: der Client darf **nicht selbst auflösen** — er bekommt die
geprüften Adressen aus `vet_url` und verbindet nur mit `target.addr`; Redirects führt
`fetch_guarded` selbst, damit jeder Sprung erneut geprüft wird
(`redirect::Policy::none()`). Ein Client mit eigener Auflösung hängt den
Rebinding-Schutz aus.

---

## 5. Beim Testen auf dem Host

### Admin-Zugang
In `data/tasks.db` liegt ein Konto `admin` mit Home-Pfad `/`, dessen Passwort niemand
kennt. **Dafür gibt es jetzt den Reset** (fertig und abgenommen):

```bash
cargo run -- --reset-password=admin      # Token wird einmalig ausgegeben
# dann http://<host>/reset?token=<token> öffnen
```

Alternativ Tabelle leeren und `RCLONE_GUI_ADMIN_PASSWORD` setzen. Der Home-Pfad `/` ist
ein Grund zum Neuanlegen: seit der Datentrennung ist er die Wurzel des erlaubten
Bereichs.

### rsync-Daemon
`RCLONE_GUI_RSYNCD_DIR=$PWD/data/rsyncd` behebt `os error 13`. Danach folgt Port 873
(privilegiert), dann chroot, dann uid/gid — deshalb Ticket `50c8ec48` (rootloser
Betrieb). `/data/rsyncd/` ist gitignored, dort liegen Modul-Geheimnisse im Klartext.

---

## 6. Belegte Umgebungstatsachen

Nicht raten, das hat schon dreimal Zeit gekostet:

- **`rclone` liegt auf dem Host** (`/usr/bin/rclone`, v1.75.0). Im Image ist es
  **1.70.1** — Versionsabhängiges gegen beide prüfen. `rsync` und `stunnel` gibt es
  **nur im Container**.
- **Port 873 ist auf diesem Host nicht bindbar** (`net.ipv4.ip_unprivileged_port_start
  = 1024`). Daemon-Tests laufen im Container oder in `unshare -rn`.
- **Eine verwaiste `flock` gibt es nicht.** Der Kernel gibt die Sperre mit dem Prozess
  frei, egal wie er stirbt. Wer die PID-Datei hält, **lebt**.
- **`peer_port_of_child` ist im Container strukturell nicht verfügbar.** Das
  Verbindungskind läuft unter der uid des Moduls; nach einem uid-Wechsel ist der Prozess
  nicht mehr dumpable, `/proc/<pid>/fd` braucht `CAP_SYS_PTRACE`. Bewusst **nicht**
  vergeben — Rechtezuwachs für ein Logfeld. Der Zeitpfad trägt die Zuordnung allein.
- **`mount` braucht root**, ein 64k-tmpfs geht also nicht überall. Ersatz für einen
  erzwungenen Schreibfehler: Verzeichnis auf 0500 (EACCES).

---

## 7. Der teuerste Fehler des ersten Laufs

`static/js/ui/config.js` deklarierte `setHidden` zweimal. Als ES-Modul ein
`SyntaxError`, der die Importkette von `main.js` nie anlaufen lässt: **die gesamte
Oberfläche war tot**, ohne sichtbare Fehlermeldung.

**Drei Agenten hatten `node --check` ausgeführt und grün gemeldet** — Node parst `.js`
als CommonJS, wo doppelte Funktionsdeklarationen erlaubt sind. Der damals in `AGENTS.md`
vorgeschriebene Prüfschritt konnte die Fehlerklasse gar nicht finden. Gefunden hat es
erst ein Tester, der die Seite **tatsächlich öffnete**.

`AGENTS.md` ist korrigiert (`.mjs`-Kopie). Die grössere Lehre bleibt:
**ein Werkzeuglauf ersetzt nicht, das Ding einmal anzufassen.**

---

## 8. Was sich bewährt hat

Diese Muster haben in zwei Läufen echte Fehler gefunden, die reines Lesen übersehen
hätte. Sie gehören in jeden künftigen Prompt:

- **Jedes Null-Ergebnis braucht eine Gegenprobe.** „Kein XSS gefunden" ist wertlos,
  solange nicht gezeigt ist, dass derselbe Aufbau ein echtes XSS **melden würde**.
  Beispiele, die trugen: 365/365 Treffer im Kontrollfall gegen 0/2589 im Echtfall;
  Log-Suche mit 0 Treffern auf den Token, aber 3 auf `alice` und 27 auf `/reset`.
- **Mutationstest statt grünem Testlauf.** Mehrfach hat ein Agent die Implementierung
  durch die naive ersetzt, um zu zeigen, dass der Test **durchfällt**. Einmal deckte das
  auf, dass ein atomares `UPDATE` mit **nachfolgendem `SELECT`** immer noch falsch zählt
  — der grüne Test hätte das nie gezeigt.
- **Tests wieder verwerfen, die nicht fehlschlagen können.** Ein Entwickler strich einen
  eigenen neuen Test, weil er in der Gegenprobe grün blieb: „hätte nur Vertrauen
  erzeugt."
- **Prüfen, ob der eigene Beweis überhaupt greifen kann.** Drei Agenten stellten fest,
  dass ihr Test in **beiden** Zweigen besteht, und wiesen separat nach, dass der
  Fehlerzweig lief.
- **Eigene Kopie des Baums** bei paralleler Arbeit, plus `sha256sum` der geprüften
  Dateien im Ticketkommentar.
- **Eigene Chrome-Instanz.** Im geteilten Chrome bleiben Tabs auf `hidden`; dort feuern
  `requestAnimationFrame`/`IntersectionObserver` nicht, und Chrome verzögert das
  Media-Preload so weit, dass gar keine Anfrage kommt.
- **Melden statt bauen**, wenn eine fremde Datei im Weg ist. Ein Agent nahm ein bereits
  hinzugefügtes Feld **zurück**, statt `main.rs` anzupassen. Ein anderer **verweigerte**
  ein Ticket, dessen Kriterien heute nicht nachstellbar sind, und hinterlegte stattdessen
  die Vorarbeit.
- **Eigene Fehlurteile korrigieren.** Ein Tester wies ein Ticket zurück, fand die Ursache
  in seiner Umgebung (Zeitzonen), zog es nach `Done` und liess **beide** Kommentare
  stehen.

### Ein Muster, fünfmal gefunden — die Serie ist geschlossen
`derive(Debug)` mit einem Geheimnis im Struct: `LoginOutcome`, `ModuleConfig`,
`RcloneConfig`, `ConfigRequest`, `NewShare`. Ein Tester hat `src/**` abschliessend
durchsucht. Bei jedem neuen Struct mit Geheimnis: handgeschriebenes `Debug` **und ein
Test**, sonst entsteht es wieder.

---

## 9. Fallstricke im Werkzeug

- **Plankton akzeptiert nur volle UUIDs.** `move_task` mit einer Kurz-ID läuft **ohne
  Fehler ins Leere** (`null`); ein Agent hat so einen Statuswechsel verloren, ohne es zu
  merken.
- **Die `blocks`-Prüfung greift nur für manche Spalten** — ein Zug nach `In Progress`
  wurde abgelehnt, derselbe Zug nach `Testing` ging durch. Ticket `763fbf6b`.
- `add_log` ist deprecated und wird auf `add_comment` umgeleitet. Argumente:
  `project_id`, `task_id`, **`text`**.
- **Kein `git checkout --` auf Projektdateien.** Ein Tester löschte damit nicht
  committete Arbeit und musste sie aus einem Backup rekonstruieren — etwa 15 Zeilen
  Doc-Kommentar sind nur sinngleich wiederhergestellt (`rsyncd.rs`, an
  `peer_port_of_child`). Beim nächsten Anfassen gegenlesen.
