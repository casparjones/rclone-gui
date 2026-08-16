# continue.md — Wiederaufnahme

Stand: 15.08.2026, nach Abbruch aller Agenten am Sitzungslimit.
Arbeitsanweisung: `AGENTS.md`. Board: https://plankton.tiny-dev.de/p/rclone-gui

---

## 1. Zustand des Arbeitsbaums

**Grün.** Die abgestürzten Agenten haben nichts Kaputtes hinterlassen.

```
cargo check      sauber
cargo test       141 passed, 0 failed, 3 ignored
node --check     alle 17 JS-Module sauber
clippy           21 Findings, alle vorbestehend
                 (main.rs 14, sync.rs 5, config_manager.rs 2)
```

**Nichts ist committet.** Rund 4200 geänderte Zeilen, 6 neue Rust-Module, das gesamte
`static/js/`-Verzeichnis und `docs/` existieren nur im Arbeitsbaum. Sicherungskopie:
`<scratchpad>/worktree-backup.tar.gz` (Stand vor dieser Runde).

Verwaiste Testcontainer wurden entfernt.

---

## 2. Was die abgestürzten Agenten hinterlassen haben

Vier Agenten starben gleichzeitig am Sitzungslimit. Ihre Abbruchmeldungen sind
irreführend — der tatsächliche Stand wurde nachgeprüft:

| Agent | Ticket | Tatsächlicher Stand |
|---|---|---|
| Dev X | `3ed12cdd` Daemon-Lifecycle | **Praktisch nichts.** Nur ein Kommentar in `rsyncd.rs:48`. `REFUSED_OPTIONS` (Zeile 69) ist **unverändert** — der `--delete`-Fix ist **nicht** umgesetzt. Kein Lifecycle-Code. |
| Dev Z | `1ab74e9c` Argon2 | **Vollständig fertig** — Kostengrenze (`auth.rs:421`), `LoginOutcome`-Debug (`auth.rs:895`), Cookie-Parsing, Passwortrichtlinie. Ticket ist inzwischen in `Testing`. *(Diese Zeile lautete zuerst „Offen: LoginOutcome-Debug" — das war ein Fehler meiner Bestandsaufnahme: gesucht wurde nach `impl fmt::Debug`, im Code steht `impl std::fmt::Debug`.)* |
| Dev AA | `d6f2d111` Sync-Modus | **Weitgehend fertig.** `static/js/ui/syncmode.js` (280 Zeilen), in `main.js:36/56` importiert und aufgerufen, Umschalter im HTML. Verifikation offen. |
| Tester 9 | `dc91da86`, `77e24d88` | Nichts. War beim Serverstart. Komplett neu aufsetzen. |

---

## 3. Dringend offen — vor dem Middleware-Ticket zu erledigen

### `--delete` wird nicht verweigert (Datenverlust)
`rsyncd.rs:69` — `REFUSED_OPTIONS = "copy-links copy-dirlinks copy-unsafe-links"`.
Ein Tester hat am echten Daemon nachgestellt: Push mit `--delete` löscht Dateien und
Symlinks im Share, exit 0. **Ein Peer mit reinen Schreibrechten kann fremde Inhalte
vernichten.**

Fehlt: `delete*` und `remove-source-files` (löscht auf der *Quellseite*).
Wildcard-Abdeckung am echten Daemon nachweisen, nicht annehmen. Scope `rsync:delete`
existiert im Modell noch nicht → vorerst **immer** verweigern, mit Code-Kommentar für
das spätere Scope-Ticket.

### `LoginOutcome` leakt das Session-Token
`auth.rs:884` — abgeleitetes `Debug`. Das `SessionToken`-Feld ist redigiert, aber
`set_cookie: String` enthält dasselbe Token im Klartext und `user` den vollen
Argon2-Hash. Gemessen: `format!("{outcome:?}")` druckt den Cookie vollständig.

Ein `tracing::debug!(?outcome)` im kommenden Login-Handler (`3cc9c90b`) schriebe ein
**gültiges Token** ins Log.

### Kleiner: Cookie-Parsing
`auth.rs:663-676` bricht mit `?` ab, sobald ein Cookie-Paar kein `=` enthält.
`Cookie: flag; rclone_gui_session=<token>` liefert dadurch `None`. Fail-closed, aber
Flag-Cookies sind zulässig.

---

## 4. Board

| Spalte | Anzahl |
|---|---|
| Todo | 83 |
| In Progress | 3 (die abgestürzten Tickets) |
| Testing | 22 |
| Done | **0** |

**Geprüft und bestanden** (warten auf Epic-Abschluss): Menü, Ordner-Navigation,
View-Modi, Download+ZIP, Docker-rsync, alpine-Bump, Engine-Trait, `app.js`-Split,
Thumbnail-Cache, tasks.db aus VCS, Session-Verwaltung, Daemon-Konfiguration,
Daemon-Module.

**Ungetestet in `Testing`**: Vorschau-Grundgerüst, Textvorschau, Bildvorschau,
Auth-Digest-Doku, Stored-XSS-Fix, Pfad-Validierung, 403-statt-404.

---

## 5. Zwei offene Entscheidungen des Nutzers

Beide blockieren den in `AGENTS.md` festgelegten Ablauf und wurden mehrfach gestellt:

**a) Zwischencommit?** Der Auftrag lautet „pro Epic einchecken". Es ist aber noch kein
Epic abschliessbar, und es liegen über 4200 ungesicherte Zeilen im Baum, an denen bis
zu vier Agenten gleichzeitig arbeiten.

**b) Downloader verschieben?** Epic 1 kann **nicht** abgeschlossen werden, weil das
Ticket „Downloader: Von URL holen" (`27e3e014`) auf die Datentrennung aus Epic 4
wartet. Verschiebt man es nach Epic 4, wäre Epic 1 abschliessbar, sobald Videovorschau
und die zwei kleinen Fehlerbehebungen durch sind.

Ohne eine der beiden Entscheidungen erreicht kein Epic den Zustand, in dem laut Auftrag
committet würde.

---

## 6. Wiederaufnahme

Reihenfolge nach Dringlichkeit:

1. **`3ed12cdd` Daemon-Lifecycle** — neu aufsetzen, `--delete`-Fix **zuerst**
   (`rsyncd.rs` + `main.rs`)
2. **`1ab74e9c` abschliessen** — nur noch `LoginOutcome`-Debug und Cookie-Parsing
   (`auth.rs`)
3. **`d6f2d111` verifizieren und abschliessen** (`static/js/**`, `index.html`)
4. **Tester** für Text- und Bildvorschau (`dc91da86`, `77e24d88`)

Dateibesitz-Regeln und Konfliktpunkte: `AGENTS.md` Abschnitt 4.
`src/main.rs`, `static/js/app-weite Dateien` und `Cargo.toml` vertragen jeweils nur
**einen** Agenten gleichzeitig.

---

## 7. Erfahrungen, die Zeit sparen

- In einem **nicht sichtbaren** Browser-Tab feuern `requestAnimationFrame` und
  `IntersectionObserver` **nicht**. Lazy-Loading und Chunk-Rendering sind dort
  stillschweigend ungeprüft. Hat drei Agenten beschäftigt.
- Das Screenshot-Werkzeug der Chrome-Erweiterung löst am `<dialog>` ein **spontanes
  `close`-Event** aus — das Overlay wirkt leer, obwohl das DOM gefüllt ist.
- `alert()` als XSS-Nutzlast blockiert den eigenen Testlauf. `window.__FLAG__=1` nutzen.
- Neue Crates immer gegen den Docker-Builder (`rust:1.88`) prüfen. Höchste MSRV im Baum
  ist bereits 1.88 (`image`, `zip`) — **kein Puffer**.
- Testverzeichnisse im Scratchpad mit **Ticket-ID** im Namen, sonst überschreiben sich
  Agenten gegenseitig.
- `data/tasks.db` ist inzwischen gitignored und **nicht** per `git checkout`
  wiederherstellbar.
