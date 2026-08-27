# Rclone GUI

A Rust-based web application that provides a user-friendly GUI for rclone file synchronization.

## Features

- **Configuration Management**: Create, edit, and manage rclone remote configurations
- **File Browser**: Browse local files with an intuitive interface
- **Remote Browsing**: Navigate remote storage structures
- **Sync Functionality**: Upload files/folders to remotes with progress tracking
- **Task Management**: Create, store, and execute reusable sync tasks
- **CLI Task Execution**: Run tasks from command line for automation
- **Memory Mode**: Optional in-memory configuration for safe testing

## Prerequisites

- Rust (latest stable version)
- rclone installed and accessible in PATH
- Web browser for the GUI

## Installation & Setup

1. Clone or download the source code
2. (Optional) Configure the default file browser path:
   ```bash
   # Create local environment file (recommended for development)
   cp .env.local.example .env.local
   nano .env.local
   
   # OR edit global .env file (will be committed to git)
   nano .env
   ```
3. Build the application:
   ```bash
   cargo build --release
   ```

> **Datenbank:** `data/tasks.db` ist **nicht** Teil des Repositories und wird beim
> ersten Start automatisch angelegt (`init_database()` erzeugt Verzeichnis, Datei und
> Schema). Ein frischer Clone braucht also keinen Migrationsschritt. Die Datei und ihre
> WAL-Begleitdateien (`*.db-wal`, `*.db-shm`) sind in `.gitignore` ausgeschlossen, damit
> ein Testlauf keinen schmutzigen Arbeitsbaum hinterlässt.

### 🔧 Development vs Production Setup

#### **Development (lokale Anpassungen):**
```bash
# 1. Lokale Konfiguration erstellen
cp .env.local.example .env.local

# 2. Persönliche Einstellungen setzen
echo "RCLONE_GUI_DEFAULT_PATH=/home/$(whoami)/Documents" >> .env.local
echo "RUST_LOG=debug" >> .env.local

# 3. Entwicklungsserver starten
./start.sh
```

#### **Production (Server-Deployment):**
```bash
# 1. Standard .env anpassen oder Umgebungsvariablen setzen
export RCLONE_GUI_DEFAULT_PATH=/srv/storage
export RUST_LOG=info

# 2. Production-Build starten
./target/release/rclone-gui --bind 0.0.0.0:8080
```

## Usage

### Basic Usage
```bash
cargo run
```
This starts the server on `http://127.0.0.1:8080`

### Memory Mode (Testing)
```bash
cargo run -- --memory-mode
```
In memory mode, configurations are stored in RAM and not automatically saved to `rclone.conf`. Use the "Save to File" button to persist changes.

### Custom Bind Address
```bash
cargo run -- --bind 0.0.0.0:3000
```

### Command Line Options
- `--memory-mode`: Enable in-memory configuration mode
- `--bind <address>`: Set custom bind address (default: 127.0.0.1:8080)
- `--start-task <task-name>`: Start a task by name and exit (perfect for automation)
- `--help`: Show all available options

### Task Management (CLI)
Execute pre-configured sync tasks from the command line:
```bash
# Run a specific task
./target/release/rclone-gui --start-task my-backup-task

# Task will show progress and exit when complete
# Perfect for cron jobs, scripts, and automation
```

#### Exit codes

`--start-task` exits with a code that a script can branch on. The code is a
stable interface — treat anything not listed here as a failure.

| Code | Meaning | Where it is reported |
|---|---|---|
| `0` | The task completed. Everything was transferred. | stdout, `✅ … completed successfully!` |
| `1` | The task failed, or it could not be started at all (unknown task name, unresolvable account, rejected sync request). Nothing can be assumed about the target. | stderr, `❌ …` |
| `2` | Bad invocation — an unknown flag or a missing argument value. Emitted by the argument parser, before any task runs. | stderr |
| `4` | The task finished **partially**: some of the data arrived, some did not. Not an error, so it goes to stdout. | stdout, `◑ … finished partially: <reason>` |

Code `4` exists because "some files could not be read" and "a source file
vanished mid-run" (rsync exit 23 and 24) are everyday events in a directory
that is being used, not outages. Reporting them as `1` would make a monitoring
script cry wolf; reporting them as `0` would hide real data loss. The
individual rsync code is deliberately **not** passed through — a partial run is
one outcome, and a numeric passthrough would imply a script can tell 23 from
24. The human-readable reason is on stdout, the affected files are in the job
log.

A script that only cares whether everything arrived checks for `0`. One that
tolerates gaps treats `0` and `4` as acceptable and retries on `4`:

```bash
./rclone-gui --start-task my-backup-task
case $? in
  0) echo "complete" ;;
  4) echo "partial - retrying later" ;;
  *) echo "failed" >&2; exit 1 ;;
esac
```

## Web Interface

Open your browser to `http://127.0.0.1:8080` (or your custom bind address) to access the modern GUI.

### Modern UI Features
- **🎨 DaisyUI v5 + Tailwind CSS**: Beautiful, responsive design with consistent components
- **🌓 Theme Toggle**: Switch between light and dark modes (automatically saved)
- **📱 Mobile Responsive**: Works perfectly on desktop, tablet, and mobile devices
- **🎯 Interactive Elements**: Hover effects, smooth animations, and intuitive navigation
- **🔔 Smart Alerts**: Contextual notifications with auto-dismiss functionality

### Configuration Tab
- **Add New Remote**: Create rclone configurations with a clean, guided form
- **Supported Types**: WebDAV, S3, Dropbox, Google Drive, OneDrive, and more
- **Existing Configurations**: Beautiful card-based layout for managing remotes
- **Save to File**: (Memory mode only) Persist configurations to rclone.conf

### File Browser Tab
- **Local Navigation**: Browse your local filesystem with breadcrumb navigation
- **Card-based Layout**: Clean file/folder cards with hover effects
- **File Actions**: Prominent sync buttons with visual feedback
- **Default Path**: Starts at configured path (see configuration below)

### Sync Jobs Tab
- **Real-time Monitoring**: Live progress tracking with animated progress bars
- **Status Badges**: Color-coded status indicators (Running, Completed, Failed)
- **Detailed Progress**: Shows transferred/total bytes with formatted display
- **Job History**: Complete overview of all sync operations

### Tasks Tab (NEW)
- **Task Management**: Create, view, and manage reusable sync configurations
- **One-Click Execution**: Start tasks with a single click
- **Task Creation**: Create tasks directly from sync modal with custom names
- **Persistent Storage**: Tasks stored in SQLite database for reliability
- **Alphanumeric Validation**: Task names must be alphanumeric (plus `-` and `_`)

## Sync Process

### One-Time Sync
1. Navigate to the desired local file/folder in the File Browser
2. Click the "Sync" button next to the item
3. Select the target remote from the dropdown
4. Navigate to the desired destination folder on the remote
5. Click "Start Upload"
6. Monitor progress in the popup or Sync Jobs tab

### Task-Based Sync (NEW)
1. Follow steps 1-4 above to configure your sync
2. Instead of "Start Upload", click "Create Task"
3. Enter a task name (alphanumeric, `-`, `_` allowed)
4. Task is saved and can be reused from the Tasks tab
5. Execute tasks via GUI (Tasks tab → Play button) or CLI (`--start-task task-name`)

## Configuration File

The application creates/manages an `rclone.conf` file in the `data/cfg/` directory. This file follows the standard rclone configuration format and can be used with the rclone command-line tool.

**Wichtig**: 
- Alle rclone-Befehle verwenden automatisch den `--config data/cfg/rclone.conf` Parameter
- Neue Passwörter werden automatisch mit `rclone obscure` verschleiert gespeichert
- Bestehende Konfigurationen werden nicht automatisch verändert

## Konfiguration des File Browser Start-Ordners

Der File Browser startet standardmäßig im Ordner `/mnt/home`. Dieser kann über Umgebungsvariablen konfiguriert werden:

### Methode 1: .env.local Datei (empfohlen für lokale Entwicklung)
1. Erstellen Sie eine lokale Konfigurationsdatei:
   ```bash
   cp .env.local.example .env.local
   ```
2. Bearbeiten Sie `.env.local` (wird nicht in git committed):
   ```bash
   # Ihre persönlichen Einstellungen
   RCLONE_GUI_DEFAULT_PATH=/home/username/Documents
   RUST_LOG=debug
   ```
3. Starten Sie die Anwendung neu

### Methode 2: .env Datei bearbeiten (für dauerhafte Änderungen)
1. Bearbeiten Sie die Datei `.env` im Projektverzeichnis
2. Ändern Sie die Zeile: `RCLONE_GUI_DEFAULT_PATH=/mnt/home`
3. **Achtung**: Diese Änderungen werden in git committed
4. Starten Sie die Anwendung neu

### Methode 3: Umgebungsvariable beim Start
```bash
RCLONE_GUI_DEFAULT_PATH=/home/user cargo run
# oder
RCLONE_GUI_DEFAULT_PATH=/home/user ./start.sh
```

### Methode 4: System-weite Umgebungsvariable
```bash
export RCLONE_GUI_DEFAULT_PATH=/home/user
cargo run
```

### 🔧 Reihenfolge der Konfiguration (Priorität absteigend):
1. **Kommandozeile** (`RCLONE_GUI_DEFAULT_PATH=/path cargo run`)
2. **System-Umgebungsvariablen** (`export RCLONE_GUI_DEFAULT_PATH=...`)
3. **`.env.local`** (lokale Überschreibungen, nicht in git)
4. **`.env`** (Standard-Konfiguration, in git committed)

**Hinweis**: Stellen Sie sicher, dass der angegebene Pfad existiert und die Anwendung Leserechte darauf hat.

## Architecture

- **Backend**: Rust with axum web framework
- **Frontend**: Modern HTML with DaisyUI v5 + Tailwind CSS
- **rclone Integration**: Uses `tokio::process::Command` for rclone operations
- **Configuration**: INI format parsing for rclone.conf
- **Progress Tracking**: Real-time job monitoring with polling
- **UI Framework**: DaisyUI v5 + Tailwind CSS Browser v4 (via CDN)
- **Theme Support**: Light/Dark mode toggle with persistent storage
- **Modern CSS**: Latest Tailwind CSS Browser engine with on-demand compilation

## Development

### Project Structure
```
src/
├── main.rs              # Application entry point with CLI task support
├── models.rs            # Data structures including Task models
├── config_manager.rs    # Configuration management
├── database.rs          # SQLite database operations for tasks
└── handlers/
    ├── mod.rs
    ├── config.rs        # Configuration API endpoints
    ├── files.rs         # File browser endpoints
    ├── sync.rs          # Sync operation endpoints
    └── tasks.rs         # Task management endpoints (NEW)
static/
├── index.html           # Main web interface with Tasks tab
└── app.js              # Frontend JavaScript with task functionality
data/
├── tasks.db             # SQLite database for task storage (auto-created, gitignored)
├── cfg/rclone.conf      # Rclone configuration file
└── log/                 # Sync job logs
```

### Building
```bash
cargo build --release
```

### Running Tests
```bash
cargo test
```

## Security Notes

- The application binds to localhost by default for security
- Passwords are stored in plaintext in rclone.conf (standard rclone behavior)
- Use `--bind 0.0.0.0:port` only in trusted network environments
- Consider using rclone's built-in encryption for sensitive data

## Troubleshooting

### Common Issues

1. **"rclone not found"**: Ensure rclone is installed and in your PATH
2. **Permission errors**: Check file system permissions for the working directory
3. **Port already in use**: Use `--bind` to specify a different port
4. **Sync failures**: Check rclone.conf syntax and remote credentials
5. **"couldn't decrypt password"**: This error is now automatically fixed by password obscuring
6. **"didn't find section in config file"**: Check that the config name matches exactly
7. **Remote connection issues**: Verify URL, username, and password are correct
8. **"413 Request Entity Too Large"**: 
   - Use the built-in multi-threading feature for large files
   - Try conservative performance levels first
   - Check your cloud provider's upload limits
9. **Upload timeouts**: Enable multi-threading with conservative settings
10. **"unknown flag" errors**: Fixed - using only valid rclone flags

### Debug Mode
Set `RUST_LOG=debug` environment variable for detailed logging:
```bash
RUST_LOG=debug cargo run
```

## 🐋 Docker Deployment

### Lokales Docker Build
```bash
# Image bauen
docker build -t rclone-gui:latest .

# Mit Docker Compose starten
docker-compose up -d
```

### GitHub Container Registry
Siehe `Docker.info` für detaillierte Anweisungen zum Deployment über GitHub Container Registry.

### rsync-Transport: Ports, Volumes und Werkzeuge

Das Image bringt neben `rclone` alles mit, was der rsync-Transport zwischen zwei
Instanzen braucht. Basis ist **`alpine:3.22`**; die Versionen sind im `Dockerfile`
über Build-Argumente **gepinnt** und werden beim Start protokolliert.

| Werkzeug | Version | Zweck |
|---|---|---|
| `rclone` | 1.70.1 | bestehende Transport-Engine |
| `rsync` | 3.4.3-r0 | rsync-Transport (mind. 3.2.0, weil `rsync-ssl` erst ab dann mitkommt) |
| `rsync-ssl` | Teil von `rsync` | TLS-Helper, ab rsync 3.2.0 enthalten |
| `openssl` | 3.5.7-r0 | **gewähltes SSL-Backend** für `rsync-ssl` |
| `stunnel` | 5.75-r0 | TLS-Terminierung auf Port 874 (siehe unten) |
| `bash` | 5.2.37-r0 | `rsync-ssl` ist ein Bash-Skript und läuft ohne bash nicht |
| `musl` | 1.2.5-r12 | **Untergrenze für `use chroot = yes`**, siehe unten |

`RSYNC_SSL_TYPE=openssl` ist fest gesetzt. `rsync-ssl` würde sonst zur Laufzeit
raten (`openssl` → `stunnel4` → `stunnel` → `gnutls-cli`); die Wahl soll
reproduzierbar sein und nicht davon abhängen, was zufällig im `PATH` liegt.

Versionen anheben: Werte im `Dockerfile` (`ARG RSYNC_VERSION` usw.) gegen
`docker run --rm alpine:3.22 sh -c 'apk update >/dev/null; apk policy rsync'`
abgleichen. Passt eine gepinnte Version nicht mehr, **bricht der Build ab** —
das ist beabsichtigt und besser als ein stiller Versionssprung.

#### Warum mindestens alpine:3.20 (hier: 3.22)

Das Basis-Image darf **nicht** unter `alpine:3.20` fallen. musl 1.2.4 (alpine:3.19)
implementiert `fchmodat(AT_SYMLINK_NOFOLLOW)` über `/proc/self/fd`. Im chroot des
rsync-Daemons gibt es kein `/proc`, der Aufruf endet in `ENOENT` — und damit bricht
**jeder** Transfer mit `use chroot = yes` ab:

```
rsync: [receiver] failed to set permissions on "/.datei1.txt.XXXXXX"
       (in <modul>): No such file or directory (2)
rsync error: some files/attrs were not transferred (code 23)
```

Die Dateien kommen an, aber mit Modus 0600 statt der Quellrechte. Ab musl 1.2.5
(alpine:3.20) ist der Fehler weg; mit `alpine:3.22` läuft derselbe Aufbau mit
`use chroot = yes` und **ohne** `--no-perms` auf exit 0 durch, mit korrekten
Rechten. Messreihe und Ursachenanalyse: `docs/rsync-transport.md`,
Abschnitt „`use chroot`".

#### Auth-Digest: weiterhin nur MD5

Auch alpine:3.22 baut `rsync` **ohne** `openssl-crypto`. Aus dem gebauten Image:

```
$ rsync --version
Optimizations:
    no SIMD-roll, no asm-roll, no openssl-crypto, asm-MD5
Daemon auth list:
    md5 md4
```

**Entscheidend ist nicht die rsync-Version, sondern der Build.** Ob starke Digests
(`sha512 sha256 sha1`) zur Verfügung stehen, hängt allein daran, ob rsync gegen
`openssl-crypto` gebaut wurde. Debian-Builds sind das, Alpine-Builds sind es in keiner
Version — gemessen von rsync 3.4.1 bis 3.4.3 über alpine:3.19 bis 3.22. Ein Upgrade auf
eine neuere rsync-Version bringt hier also nichts.

Das Anheben des Basis-Images ändert daran nichts. `auth digest = sha512` bleibt mit
diesem Image nicht nutzbar — der Parameter existiert in rsync 3.4.x ohnehin nicht und
würde zwei Instanzen dieses Images gegenseitig aussperren. Die Vertraulichkeit und die
Server-Authentizität liefert deshalb ausschliesslich die TLS-Terminierung auf Port 874.

Dass MD5-Challenge-Response akzeptiert wird, ist eine **bewusste Entscheidung** und
kein offener Punkt: das Secret geht bei Challenge-Response nie über die Leitung, und
die Aushandlung läuft ohnehin komplett im TLS-Tunnel. Einen unverschlüsselten
Direktmodus gibt es nicht — Port 873 bleibt containerintern. Die Alternativen
(Debian-Basis, rsync selbst gegen OpenSSL bauen) sind geprüft und verworfen;
Begründung in `docs/rsync-transport.md`.

#### Startup-Check

`start.sh` ist der Einstiegspunkt des Containers. Vor dem Start der App prüft es,
ob `bash`, `rclone`, `rsync`, `rsync-ssl` und `openssl` vorhanden **und ausführbar**
sind. Fehlt etwas, bricht der Container mit einer benannten Fehlermeldung und
Exit-Code 1 ab — nicht erst beim ersten Sync-Job. `bash` steht mit in der Liste, weil
sowohl `rsync-ssl` als auch `start.sh` selbst Bash-Skripte sind; ohne bash gäbe es
sonst nur einen nichtssagenden Exec-Fehler.

Anschliessend werden alle Versionen geloggt, dazu eine Informationszeile mit der
`Daemon auth list` des vorhandenen rsync (für dieses Image: `md5 md4`). Das ist eine
Feststellung, keine Warnung — siehe „Auth-Digest" oben. Eine **Warnung** gibt es nur,
wenn `rsync` älter als **3.2.0** ist; dann fehlt das Helper-Skript `rsync-ssl` und der
Transport zwischen zwei Instanzen ist nicht nutzbar. Im Container-Image feuert sie
nie, sie zielt auf den Host-/Dev-Betrieb.

Dasselbe Skript funktioniert auch auf dem Host für den Entwicklungsbetrieb.

#### Ports

| Port | Gemappt | Richtung | Bedeutung |
|---|---|---|---|
| 8080 | ja | eingehend | Web-UI / OAuth (im Betrieb hinter einem Reverse Proxy auf 443) |
| 874 | ja | eingehend | rsync über TLS, von stunnel terminiert (siehe „TLS-Terminierung auf Port 874") |
| 873 | **nein** | **nur localhost** | rsync-Daemon, gehärteter Modus — bleibt containerintern |
| 8873 | **nein** | **nur localhost** | derselbe Daemon im **rootlosen** Modus, siehe „Härtungsmodi" |

Der Daemon-Port wird bewusst **nicht** nach aussen gemappt: der rsync-Daemon spricht
unverschlüsselt, authentifiziert allein über MD5-Challenge-Response und ohne
TLS-Peer-Prüfung. Erreichbar ist er ausschliesslich über die TLS-Terminierung auf 874.
Wer 873 **oder** 8873 in `docker-compose.yml` ergänzt, hebt den Schutz auf.

Dass er von aussen nicht erreichbar ist, ist **kein Ratschlag, sondern eine Zusage** — und
sie hängt an drei voneinander unabhängigen Riegeln (`address = 127.0.0.1` plus eine
dparam-Prüfung vor dem Start, ein `/proc/net/tcp`-Verdikt nach dem Start, und ein Abbruch
von `config/rsync-tls.sh` bei einem Backend, das nicht Loopback ist). Einzelheiten und
Messwerte: `docs/rsync-transport.md`, Abschnitt „Netzwerk-Voraussetzungen".

#### Härtungsmodi: Port 873 oder Port 8873

**Der Daemon-Port ist nicht fest** — eine ältere Fassung dieses README behauptete das, und
wer ihr folgte, richtete die TLS-Terminierung auf den falschen Port. Er hängt daran, ob
der Daemon sich härten kann:

| Modus | Erkennung | Port | `use chroot` | `uid`/`gid` |
|---|---|---|---|---|
| gehärtet (`Hardening::Full`) | euid 0 **oder** Datei-Capability `cap_sys_chroot` auf dem rsync-Binary | 873 | ja | ja |
| rootlos (`Hardening::Rootless`) | keins von beidem | **8873** | nein | nein |

**Der ausgelieferte Container ist der gehärtete Fall** — obwohl er als `appuser` (uid 1001)
läuft, denn `setcap cap_sys_chroot,cap_setgid=ep /usr/bin/rsync` im `Dockerfile` gibt dem
Binary die beiden Capabilities. Genau deshalb fragt die Erkennung **nicht** nur
`geteuid() == 0`: eine reine euid-Prüfung hätte den Container als rootlos eingestuft und
die chroot-Härtung **stillschweigend** abgeschaltet. Gefragt werden euid (aus
`/proc/self/status`) **oder** die Capability (über `getcap`), und jede unbeantwortbare
Frage zählt als „nicht privilegiert" — der Daemon kommt dann rootlos hoch und **sagt es**,
statt chroot zu versprechen und darin zu sterben.

**Rootlos kostet echte Absicherung**, und das steht beim Start als Warnung auf stderr und
im Log: kein chroot (die Modulgrenze hängt dann allein an rsyncs eigener Pfadprüfung —
eine fehlende *zweite* Schicht, nicht eine fehlende erste), kein `uid`/`gid`-Wechsel (jedes
Modul wird als der Nutzer bedient, der die Anwendung gestartet hat). Der Modus ist für die
**Host-Entwicklung** gedacht, nicht für den Betrieb.

Gebraucht wird er, weil auf einem gewöhnlichen Host `/etc/rsyncd` nicht beschreibbar ist
(`Permission denied (os error 13)`) und Port 873 nicht bindbar
(`net.ipv4.ip_unprivileged_port_start = 1024`) — es fehlt dort **kein** Binary, sondern der
Port.

| Variable | Bedeutung |
|---|---|
| `RCLONE_GUI_RSYNCD_PORT` | überschreibt den Port in **beiden** Modi. App und `config/rsync-tls.sh` lesen dieselbe Variable, es wird also nur eine Seite gesetzt. |
| `RCLONE_GUI_RSYNCD_DIR` | Verzeichnis für `rsyncd.conf`, `secrets/` und `run/`. Standard: `/etc/rsyncd` gehärtet, `<cwd>/data/rsyncd` rootlos. |

> **`RCLONE_GUI_RSYNCD_DIR` muss ein absoluter Pfad sein.** rsync löst `secrets file`
> selbst auf, und sein Arbeitsverzeichnis ist nicht das der Anwendung. Ein relativer Wert
> bringt den Daemon nicht hoch — gemessen:
>
> ```
> RCLONE_GUI_RSYNCD_DIR=relconf
>   ❌ the rsync daemon did not start: … relconf/secrets/rsyncd.secrets
>      must be an absolute path
> ```
>
> Der Server läuft dann ohne rsync-Transport weiter; die Ursache steht auf der Konsole und
> unter `GET /api/rsyncd/status`. Also **`RCLONE_GUI_RSYNCD_DIR=$PWD/data/rsyncd`**, nicht
> `data/rsyncd`. Absolut gemacht wird nur der *eingebaute Standardwert*, ein ausdrücklich
> gesetzter Wert wird unverändert übernommen.

#### Isolation des Daemons: `use chroot` ohne root

Jedes Modul, das die App erzeugt, steht auf `use chroot = yes` samt eigener
`uid`/`gid`. Das ist die wichtigste Isolationsschicht des Peer-Zugriffs: der
Daemon-Prozess einer Verbindung sieht nur noch den Share-Root als `/` und kommt
selbst über einen Pfadfehler nicht mehr an den Rest des Dateisystems.

Beides verlangt Rechte, die ein unprivilegierter Prozess nicht hat — und der
Container läuft bewusst als `appuser` (uid 1001), also auch der von der App
gestartete Daemon. Gelöst ist das über **Datei-Capabilities auf genau einer
Binärdatei**:

```
setcap cap_sys_chroot,cap_setgid=ep /usr/bin/rsync
```

| Capability | Wofür | Warum nicht mehr |
|---|---|---|
| `cap_sys_chroot` | der `chroot()` in den Share-Root | — |
| `cap_setgid` | `setgroups()` beim Wechsel auf die Modul-`gid` | `setgid`/`setuid` auf die *eigene* Identität brauchen keine Capability |
| ~~`cap_setuid`~~ | **bewusst nicht gesetzt** | wäre ein vollständiger Weg von `appuser` nach uid 0 im Container und damit das Ende von `USER appuser` |

**Warum das und nicht `cap_add` im Compose-File, und warum kein root-Daemon:**

* `CAP_SYS_CHROOT` und `CAP_SETGID` sind ohnehin Teil des Default-Sets von
  Docker. Die Datei-Capability wird daraus beim `exec` gezogen — es braucht
  **kein** `cap_add`, kein `privileged`, keine Compose-Änderung. Wer ein eigenes
  Compose-File oder ein blosses `docker run` benutzt, bekommt chroot ohne eine
  Zeile Zusatzkonfiguration. Ein vergessenes `cap_add` wäre dagegen ein stiller
  Ausfall bei jedem Fremdbetreiber.
* Die Erweiterung hängt an `/usr/bin/rsync`, nicht am ganzen Container. Die App,
  `rclone`, `stunnel` und die Shell bleiben unprivilegiert.
* Der Daemon als root zu starten (die dritte denkbare Variante) hätte verlangt,
  dass entweder der ganze Container als root läuft oder die App eine
  Root-Ausnahme bekommt. Beides ist deutlich mehr Recht als die zwei
  Capabilities auf einer Datei.

`use chroot = yes` bleibt damit erhalten — und mit ihm die Begründung des
alpine-Bumps auf ≥ 3.20 (musl ≥ 1.2.5, siehe Kommentar im `Dockerfile`).

> **Nicht `--cap-drop=SYS_CHROOT` / `SETGID` setzen und nicht
> `--security-opt no-new-privileges`.** Eine Datei-Capability, die nicht im
> Bounding-Set liegt, wird nicht etwa ignoriert: dann scheitert schon das `exec`
> von `rsync` mit `EPERM`, und `rsync` ist gar nicht mehr aufrufbar. Mit
> `no-new-privileges` läuft `rsync` zwar, chrootet aber nicht mehr.

**Der Start prüft das, nicht der erste Transfer.** `start.sh` startet vor der App
einen Wegwerf-Daemon auf `127.0.0.1:18873` mit `use chroot = yes` und denselben
`uid`/`gid`-Zeilen und spricht ihn an. Geprüft wird also das Verhalten, nicht die
Capability-Bits:

* funktioniert es → eine Zeile im Log
  (`🔒 chroot : nutzbar`)
* funktioniert es nicht und `RCLONE_GUI_RSYNCD=1` → **Abbruch mit Exit 1**, mit
  Grund, Ist/Soll der Datei-Capabilities, dem Bounding-Set und den üblichen
  Ursachen
* funktioniert es nicht und der Daemon ist aus (Vorgabe) → Warnung, die App
  startet normal weiter

Vorher meldete sich ein fehlgeschlagener chroot ausschliesslich auf der
Gegenstelle, beim ersten Transfer, als `@ERROR: chroot failed` und Exit 5 — genau
so ist der Fehler unbemerkt in einen ausgelieferten Container gekommen.

#### Beenden: `docker stop`

PID 1 im Container ist `start.sh`, nicht die App. Das ist Absicht:

* Für PID 1 wendet der Kernel die Default-Disposition eines Signals **nicht** an.
  Ein Signal ohne installierten Handler wird schlicht ignoriert.
* `rclone-gui` installiert nur einen Handler für SIGINT (`tokio::signal::ctrl_c`),
  nicht für SIGTERM. Als `exec`-tes PID 1 hat es das SIGTERM von `docker stop`
  deshalb ignoriert: volle 10 Sekunden Gnadenfrist, dann SIGKILL, Exit **137** —
  ohne dass SQLite, der rsync-Daemon oder stunnel geordnet endeten.

`start.sh` bleibt daher PID 1, fängt SIGTERM per `trap` ab (ein Trap wirkt auch
für PID 1) und übersetzt es in SIGINT an die App. Damit läuft der vorhandene
Graceful-Shutdown: Server austrudeln lassen, rsync-Daemon per SIGTERM beenden und
einsammeln, danach stunnel. Gemessen am ausgelieferten Image:

| | vorher | jetzt |
|---|---|---|
| Dauer `docker stop` | 10 s (volles Timeout) | **0,74 s** |
| Exit-Code | 137 (SIGKILL) | **143 (SIGTERM)** |
| rsync-Daemon | hart mitgerissen | SIGTERM, Exit 0, eingesammelt |
| stunnel | hart mitgerissen | `LOG5[ui]: Terminated` |

#### TLS-Terminierung auf Port 874

Der rsync-Daemon selbst spricht Klartext und bindet nur auf `127.0.0.1` — im Container auf
Port 873, rootlos auf 8873 (siehe „Härtungsmodi"). Von aussen erreichbar ist er
ausschliesslich über **stunnel**, das auf Port 874 TLS terminiert und containerintern auf
denselben Loopback-Port weiterreicht — das Rezept aus `man rsyncd.conf`, Abschnitt
*SSL/TLS Daemon Setup*:

```
Peer --TLS--> stunnel 0.0.0.0:874 --Klartext--> rsyncd 127.0.0.1:873
```

Eingerichtet wird das beim Containerstart von `start.sh` über
`config/rsync-tls.sh`; die stunnel-Konfiguration entsteht aus der Vorlage
`config/stunnel-rsyncd.conf.template` und landet als `/etc/rsyncd/stunnel.conf`
(bei jedem Start neu geschrieben — Änderungen gehören in die Vorlage).

| Variable | Vorgabe | Bedeutung |
|---|---|---|
| `RCLONE_GUI_RSYNC_TLS` | `1` | `0` schaltet die Terminierung ab. Dann ist der Daemon von aussen gar nicht erreichbar — einen Klartextweg gibt es nicht. |
| `RCLONE_GUI_RSYNC_TLS_PORT` | `874` | Port, auf dem terminiert wird |
| `RCLONE_GUI_RSYNC_BACKEND` | `127.0.0.1:873`, rootlos `127.0.0.1:8873` | Backend dahinter. `config/rsync-tls.sh` rechnet den Standardwert mit derselben Regel aus wie die App (`rsyncd_default_port()`) und **bricht ab**, wenn der Wert nicht Loopback ist — `127.0.0.1.evil.com:873` wird abgewiesen. |
| `RCLONE_GUI_PEER_HOSTNAME` | aus `RCLONE_GUI_PUBLIC_BASE_URL`, sonst `hostname` | Name(n) im Zertifikat, komma-getrennt |
| `RCLONE_GUI_TLS_CERT` / `_KEY` | leer | eigenes Zertifikat statt der internen CA |

##### Zertifikat: interne CA, verwaltet von der App

Gewählt ist die **von der App verwaltete interne CA**, nicht das Web-UI-Zertifikat:

* Im Container **existiert** kein Web-UI-Zertifikat. Die UI spricht HTTP auf 8080;
  TLS macht im Betrieb ein vorgelagerter Reverse Proxy. Es gäbe also nichts
  wiederzuverwenden.
* Das Pairing übergibt der Gegenstelle ohnehin eine CA (`ca_pem`), gegen die sie
  prüft. Eine eigene CA passt genau dazu und macht den Vertrauensanker so eng wie
  möglich — **eine** Instanz statt einer kompletten öffentlichen CA.
* Erneuerungen bleiben unter Kontrolle der App: das Serverzertifikat wird 30 Tage
  vor Ablauf neu ausgestellt, signiert von derselben CA. Die beim Pairing
  verteilte CA bleibt dabei gültig, die Kopplung überlebt die Rotation.

Erzeugt werden beim ersten Start unter `/etc/rsyncd/certs` (Volume, bleibt erhalten):

| Datei | Modus | Inhalt |
|---|---|---|
| `ca.crt` | 0644 | **öffentlich** — das, was beim Pairing an die Gegenstelle geht |
| `ca.key` | 0600 | privater CA-Schlüssel, verlässt die Instanz nie |
| `srv.crt` / `srv.key` | 0644 / 0600 | Serverzertifikat für stunnel (EC P-256, 825 Tage) |

Wer stattdessen ein eigenes Zertifikat einsetzen will (z.B. dasselbe wie für die
Web-UI), setzt `RCLONE_GUI_TLS_CERT` und `RCLONE_GUI_TLS_KEY`. Eigene Zertifikate
werden **nie** ersetzt oder erneuert, nur beim Start geprüft und bei Ablauf
gemeldet.

##### Der Hostname im Zertifikat ist Pflicht, nicht Kosmetik

`RCLONE_GUI_PEER_HOSTNAME` muss **exakt** der Name sein, unter dem die Gegenstelle
diese Instanz anspricht. `rsync-ssl` ruft `openssl s_client -verify_return_error`
auf und prüft den Hostnamen gegen den SAN. Gemessen an diesem Aufbau:

| Aufruf der Gegenstelle | Ergebnis |
|---|---|
| Name aus dem SAN | `Verify return code: 0 (ok)`, Transfer läuft |
| dieselbe Instanz über die **IP** | `verify error:num=62:hostname mismatch`, exit 5 |
| fremde CA | `verify error:num=20:unable to get local issuer certificate`, exit 5 |
| abgelaufenes Serverzertifikat | `certificate verify failed`, exit 5, **nichts übertragen** |

**Beim Pairing muss deshalb der Hostname mitgeliefert werden, der im SAN steht —
eine IP genügt nicht.** Wer eine IP nutzen muss, trägt sie in
`RCLONE_GUI_PEER_HOSTNAME` ein; sie landet dann als `IP:`-SAN im Zertifikat.

In keinem der Fehlerfälle gibt es einen Rückfall auf Klartext: der Job schlägt fehl.

Ein Mitschnitt der Verbindung auf Port 874 enthält weder Dateinamen noch Inhalte,
auch nicht das RSYNCD-Greeting oder den Modulnamen — ausgehandelt wird TLS 1.3,
das Serverzertifikat ist damit ebenfalls verschlüsselt. Sichtbar bleibt allein der
**Hostname im SNI** des ClientHello; das ist Eigenschaft von TLS und nicht dieser
Konfiguration.

##### `proxy protocol`: bewusst aus — auf beiden Seiten

`protocol = proxy` in stunnel und `proxy protocol = true` in der `rsyncd.conf`
sind **ein Paar**. Nur eine Hälfte zu aktivieren ist der schlimmste Fall: rsync
3.4.3 setzt dann jede Verbindung zurück (`safe_read failed to read 1 bytes:
Connection reset by peer (104)`, exit 12) und schreibt dazu **keine** Logzeile.

Beide Hälften zusammen funktionieren (gemessen, Transfer läuft, echte Client-IP im
Daemon-Log). Trotzdem bleibt beides aus:

* Für die Zugriffskontrolle bringt es nichts — die läuft über `auth users`, nicht
  über `hosts allow`.
* `proxy protocol hosts` kennt rsync 3.4.3 nicht (`Unknown Parameter encountered`,
  zwei Logzeilen **pro Verbindung**). Die Liste vertrauenswürdiger Proxys ist damit
  wirkungslos.
* Die echte Client-IP steht bereits im stunnel-Log und ist dort nicht fälschbar.

**Folge für das Audit-Log:** die Peer-IP kommt aus dem stunnel-Log im
Container-Log, nicht aus dem rsyncd-Log. Dort steht `connect from localhost
(127.0.0.1)`.

```
# stunnel (Container-Log)
LOG5[0]: Service [rsyncd-tls] accepted connection from 192.168.224.3:51840
# rsyncd-Log
[159] connect from localhost (127.0.0.1)
```

#### Volumes

| Host | Container | Inhalt |
|---|---|---|
| `./data` | `/app/data` | `tasks.db`, `rclone.conf`, Job-Logs |
| `./logs` | `/app/logs` | Anwendungslogs |
| `./shares` | `/data` | **Share-Root** – alles hier ist freigegeben |
| `./rsyncd` | `/etc/rsyncd` | Daemon-Konfiguration, `secrets/`, `certs/` |

`/etc/rsyncd` liegt bewusst **ausserhalb** des Share-Roots. Secrets und private
Schlüssel dürfen unter keinen Umständen unter einem freigegebenen Pfad liegen,
sonst sind sie über einen rsync-Share lesbar. Die Unterverzeichnisse `secrets/`
und `certs/` werden im Image mit Modus `0700` angelegt.

Die Host-Verzeichnisse legt Docker beim ersten Start als `root` an; der Container
läuft als UID 1001. Vor dem ersten `up` deshalb:

```bash
mkdir -p data logs shares rsyncd/secrets rsyncd/certs
chmod 700 rsyncd/secrets rsyncd/certs
sudo chown -R 1001:1001 data logs shares rsyncd
```

#### Öffentliche Basis-URL

`RCLONE_GUI_PUBLIC_BASE_URL` ist die von aussen erreichbare Adresse dieser
Instanz. Sie ist das Ziel für OAuth-Redirects und Pairing-Links der Gegenstelle.
Steht dort noch `http://localhost:8080`, schlägt die Kopplung fehl, sobald die
Gegenstelle auf einem anderen Host läuft.

```bash
# .env oder Shell-Umgebung
RCLONE_GUI_PUBLIC_BASE_URL=https://rclone.example.org
```

#### Zwei Instanzen verbinden

##### Was offen sein muss — und was nicht

**Es gibt nur einen Modus: TLS.** Ein unverschlüsselter Direktmodus auf 873 war im
Entwurf vorgesehen und ist **gestrichen** (Entscheidung E2, `docs/rsync-transport.md`) —
die App kennt nur `address = 127.0.0.1` und hat keinen Zweig, der etwas anderes rendern
könnte. Die Empfehlung ist damit keine Wahl, sondern die einzige Bauweise.

| Zweck | Port | Richtung | Nötig wann |
|---|---|---|---|
| Web-UI / OAuth | 443, bzw. der konfigurierte Port (Compose-Standard 8080) | eingehend | immer |
| rsync über TLS | 874 (`RCLONE_GUI_RSYNC_TLS_PORT`) | eingehend | immer |
| Daemon-Backend | 873, rootlos **8873** (`RCLONE_GUI_RSYNCD_PORT`) | **nur localhost** | nie nach aussen |

Dazu zwei Namen, die stimmen müssen, sonst schlägt die Kopplung mit einer Meldung fehl,
die nach etwas anderem aussieht:

* `RCLONE_GUI_PUBLIC_BASE_URL` — die von aussen erreichbare Adresse dieser Instanz. Ziel
  der OAuth-Redirects und Pairing-Links; `http://localhost:8080` funktioniert nur, solange
  beide Instanzen auf demselben Host laufen.
* `RCLONE_GUI_PEER_HOSTNAME` — muss **exakt** der Name sein, unter dem die Gegenstelle
  diese Instanz anspricht. `rsync-ssl` prüft ihn gegen den SAN; eine IP genügt nur, wenn
  sie als `IP:`-SAN im Zertifikat steht.

**Ein Reverse Proxy vor 874 muss durchreichen, nicht terminieren** (nginx `stream` ohne
`ssl`, haproxy `mode tcp`, kein `proxy_protocol`). Das TLS auf 874 gehört stunnel mit dem
Zertifikat dieser Instanz, und die Gegenstelle prüft es gegen die beim Pairing erhaltene
CA — ein Proxy, der selbst terminiert, zeigt das falsche Zertifikat. Lauffähige
Beispielblöcke für nginx, haproxy, ufw und firewalld: `docs/rsync-transport.md`, Abschnitt
„Netzwerk-Voraussetzungen".

Firewall, kurz:

```bash
sudo ufw allow 874/tcp comment 'rclone-gui rsync ueber TLS'
sudo ufw deny  873/tcp   # rsync-Daemon: niemals von aussen
sudo ufw deny  8873/tcp  # derselbe Daemon rootlos
```

##### Aufsetzen

Auf beiden Seiten:

```bash
mkdir -p data logs shares rsyncd/secrets rsyncd/certs
chmod 700 rsyncd/secrets rsyncd/certs
sudo chown -R 1001:1001 data logs shares rsyncd
echo "RCLONE_GUI_PUBLIC_BASE_URL=https://<eigener-hostname>" >> .env
docker compose up -d --build
docker compose logs -f rclone-gui   # Versionen und Startup-Check prüfen
```

Nach oben genanntem Lauf steht auf beiden Seiten: Web-UI auf 8080, Port 874 nach
aussen offen, der Daemon-Port nur intern, Share-Root unter `./shares`, und ein leeres,
persistentes `./rsyncd` für Konfiguration, Secrets und Zertifikate.

##### Gegenprobe von aussen

Von der **Gegenseite** aus, nicht vom eigenen Host — von dort ist Loopback immer
erreichbar und die Antwort damit wertlos:

```bash
# 874 muss antworten und ein Zertifikat zeigen, dem die Pairing-CA traut:
openssl s_client -connect <peer>:874 -servername <peer> \
  -verify_hostname <peer> -CAfile ca.crt -verify_return_error </dev/null
#   -> "Verify return code: 0 (ok)"

# 873 und 8873 muessen verweigert werden oder ins Timeout laufen.
# Eine Antwort ist ein Fehler, kein Feinschliff.
for p in 873 8873; do timeout 5 bash -c "echo | nc -v <peer> $p"; done
```

| Befund | Nächster Schritt |
|---|---|
| 874 verweigert | Port-Mapping (`docker compose ps`), dann Firewall, dann Port-Forwarding am Router |
| 874 antwortet, `certificate verify failed` | Ein Proxy terminiert TLS selbst — auf Passthrough umstellen |
| 874 antwortet, `hostname mismatch` | `RCLONE_GUI_PEER_HOSTNAME` ist nicht der Name, den die Gegenstelle benutzt |
| **873 oder 8873 antwortet** | Port-Mapping bzw. Firewall-Regel entfernen, dann `GET /api/rsyncd/status` prüfen |
| Basis-URL nicht erreichbar | `RCLONE_GUI_PUBLIC_BASE_URL` steht auf `localhost`, oder der Reverse Proxy vor der UI fehlt |

Ein **Selbsttest in der Anwendung** und eine Netzwerk-Übersichtsseite in der
Configuration sind noch offen (Ticket `24d7ad41`); bis dahin ist die Tabelle oben der
Weg von Hand.

Die **TLS-Terminierung auf 874 ist damit vollständig eingerichtet**: stunnel
lauscht nach `docker compose up` auf `0.0.0.0:874`, stellt CA und
Serverzertifikat beim ersten Start selbst aus und reicht nach `127.0.0.1:873`
weiter. Ein `rsync-ssl`-Verbindungsaufbau der Gegenstelle gelingt (gemessen:
Transfer über 874 mit identischer Prüfsumme). Einzelheiten im Abschnitt
„TLS-Terminierung auf Port 874" weiter oben.

> **Was noch fehlt: die Modulregistrierung.** Der rsync-Daemon selbst *wird*
> gestartet — allerdings nur mit `RCLONE_GUI_RSYNCD=1`, und seine Modulliste ist
> beim Start leer, weil es noch keine gespeicherten Pairings gibt. Der Daemon
> läuft dann zwar (auf `127.0.0.1:873` im Container, hinter stunnel) und ist über 874
> erreichbar, hat aber kein Modul, das eine Gegenstelle ansprechen könnte. Bis
> das Ticket zur Pairing-Speicherung durch ist, endet die Kopplung also hier:
> Infrastruktur, TLS und Daemon stehen, die eigentliche Freigabe fehlt.
>
> Deshalb ist `RCLONE_GUI_RSYNCD` voreingestellt **aus**. Ein Daemon ohne
> Pairing-Speicher wäre ein offener Port ohne Nutzen.

## Contributors

- **Original Author**: Base rclone GUI application
- **Claude (Anthropic AI Assistant)**: Task management system implementation (v0.1.0)
  - Complete task management functionality with SQLite persistence
  - CLI task execution with `--start-task` option
  - Web interface enhancements with Tasks tab
  - Database layer and REST API endpoints

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

### Recent Contributions
- **v0.1.0 (2025-10-02)**: Task management system by Claude - See [CHANGELOG.md](CHANGELOG.md) for details

## License

This project is open source. Please ensure compliance with rclone's licensing terms when using this software.