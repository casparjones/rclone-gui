#!/usr/bin/env bash
#
# Rclone GUI Startup Script
#
# Läuft in zwei Modi:
#   * Container: /app/rclone-gui existiert -> Binary direkt starten
#   * Host/Dev:  sonst -> bei Bedarf `cargo build --release` und Debug-Binary starten
#
# In beiden Modi läuft vorher der Startup-Check: fehlt eines der benötigten
# Binaries, bricht der Start hier mit einer klaren Meldung ab — nicht erst beim
# ersten Sync-Job.
#
# Usage: ./start.sh [OPTIONS]   (Optionen werden an rclone-gui durchgereicht)

set -uo pipefail

# SSL-Backend für rsync-ssl explizit festlegen, statt die Heuristik des
# Helper-Skripts (openssl -> stunnel4 -> stunnel -> gnutls-cli) raten zu lassen.
export RSYNC_SSL_TYPE="${RSYNC_SSL_TYPE:-openssl}"

# ---------------------------------------------------------------------------
# Startup-Check
# ---------------------------------------------------------------------------

# Pflicht-Binaries. Ohne diese startet die App nicht.
REQUIRED_BINARIES=(bash rclone rsync rsync-ssl openssl)

check_binaries() {
    local missing=()
    local bin path

    for bin in "${REQUIRED_BINARIES[@]}"; do
        path="$(command -v "$bin" 2>/dev/null)"
        if [ -z "$path" ] || [ ! -x "$path" ]; then
            missing+=("$bin")
        fi
    done

    if [ ${#missing[@]} -ne 0 ]; then
        echo "❌ Start abgebrochen: benötigte Programme fehlen oder sind nicht ausführbar:" >&2
        for bin in "${missing[@]}"; do
            case "$bin" in
                rclone)
                    echo "   - rclone     (Transport-Engine; https://rclone.org/install/)" >&2
                    ;;
                rsync)
                    echo "   - rsync      (rsync-Transport, mindestens 3.2.0; 'apk add rsync')" >&2
                    ;;
                rsync-ssl)
                    echo "   - rsync-ssl  (TLS-Helper, Teil des rsync-Pakets ab 3.2.0; braucht bash)" >&2
                    ;;
                openssl)
                    echo "   - openssl    (SSL-Backend für rsync-ssl, RSYNC_SSL_TYPE=${RSYNC_SSL_TYPE})" >&2
                    ;;
                bash)
                    echo "   - bash       ('apk add bash'; rsync-ssl und start.sh selbst sind Bash-Skripte)" >&2
                    ;;
                *)
                    echo "   - $bin" >&2
                    ;;
            esac
        done
        echo "" >&2
        echo "   Im Container gehören sie alle ins Image (siehe Dockerfile)." >&2
        echo "   Auf dem Host: fehlende Pakete nachinstallieren und erneut starten." >&2
        return 1
    fi

    return 0
}

# Welche Digests bietet dieser rsync für die Daemon-Authentifizierung an?
# Das hängt NICHT an der rsync-Version, sondern daran, ob rsync gegen
# openssl-crypto gebaut wurde. Alpine baut bewusst ohne — deshalb meldet dieses
# Image "md5 md4", auch mit rsync 3.4.3. Siehe docs/rsync-transport.md,
# Abschnitt "Auth-Digest".
rsync_auth_digests() {
    # Achtung: die Ausgabe erst in eine Variable holen und dann filtern. Ein
    # `rsync --version | grep -q ...` beendet grep vorzeitig, rsync stirbt an
    # SIGPIPE und `set -o pipefail` meldet die Pipeline als fehlgeschlagen —
    # das Ergebnis wäre still falsch herum.
    local out
    out="$(rsync --version 2>/dev/null)"

    local digests crypto
    digests="$(printf '%s\n' "$out" |
        awk 'tolower($0) ~ /daemon auth list/ { getline; gsub(/^[[:space:]]+|[[:space:]]+$/, ""); print; exit }')"
    [ -z "$digests" ] && return 1

    case "$out" in
        *"no openssl-crypto"*) crypto="ohne openssl-crypto gebaut" ;;
        *"openssl-crypto"*)    crypto="mit openssl-crypto gebaut" ;;
        *)                     crypto="openssl-crypto unbekannt" ;;
    esac

    printf '%s (%s)\n' "$digests" "$crypto"
}

log_versions() {
    echo "🔎 Laufzeit-Umgebung:"
    echo "   rclone     : $(rclone --version 2>/dev/null | head -1)"
    echo "   rsync      : $(rsync --version 2>/dev/null | head -1)"
    echo "   rsync-ssl  : $(command -v rsync-ssl) (RSYNC_SSL_TYPE=${RSYNC_SSL_TYPE})"
    echo "   openssl    : $(openssl version 2>/dev/null)"
    echo "   bash       : ${BASH_VERSION:-unbekannt} ($(command -v bash))"

    # Informationszeile, keine Warnung: für dieses Image ist "md5 md4" der
    # erwartete Normalzustand und kein Mangel, den ein Betreiber beheben könnte.
    local digests
    if digests="$(rsync_auth_digests)"; then
        echo "   rsync-Auth : ${digests}"
        echo "                Vertraulichkeit und Server-Authentizität liefert die"
        echo "                TLS-Terminierung auf Port 874, nicht der Auth-Digest."
    fi

    # TLS-Terminator für Port 874. Fehlt er, läuft die App weiter — nur der
    # Peer-Sync über rsync ist dann nicht nutzbar (es gibt keinen Klartextweg).
    if command -v stunnel >/dev/null 2>&1; then
        echo "   stunnel    : $(stunnel -version 2>&1 | grep -m1 -i '^stunnel')"
    else
        echo "   stunnel    : nicht installiert (keine TLS-Terminierung auf Port 874)"
    fi
}

# Mindestversion 3.2.0 — Begründung ist die Kompatibilität zwischen zwei
# Instanzen, nicht der Auth-Digest: erst ab 3.2.0 liegt das Helper-Skript
# rsync-ssl dem rsync-Paket bei, und erst ab 3.2.0 spricht rsync Protokoll 31/32
# mit der Digest-Aushandlung, auf der der TLS-Modus dieses Projekts aufsetzt.
# Für das Container-Image feuert das nie (gepinnt auf 3.4.3); es zielt auf einen
# Host-/Dev-Lauf mit einem alten rsync im PATH.
RSYNC_MIN_VERSION="3.2.0"

warn_rsync_version() {
    # rsync --version: "rsync  version 3.4.1  protocol version 32"
    local ver
    ver="$(rsync --version 2>/dev/null | head -1 | awk '{print $3}')"
    [ -z "$ver" ] && return 0

    local major minor patch
    IFS='.' read -r major minor patch <<<"$ver"
    patch="${patch:-0}"

    if [ "$major" -lt 3 ] ||
       { [ "$major" -eq 3 ] && [ "$minor" -lt 2 ]; }; then
        echo "⚠️  rsync $ver ist älter als ${RSYNC_MIN_VERSION}. Ohne das mitgelieferte" >&2
        echo "    rsync-ssl und die Protokollstände ab 3.2.0 ist der rsync-Transport" >&2
        echo "    zwischen zwei Instanzen nicht nutzbar. Bitte aktualisieren." >&2
    fi
}

check_binaries || exit 1
log_versions
warn_rsync_version

# ---------------------------------------------------------------------------
# chroot-Fähigkeit prüfen (Ticket 33eeb98c)
# ---------------------------------------------------------------------------
#
# Die generierte Modulkonfiguration setzt `use chroot = yes` samt `uid`/`gid`.
# Beides verlangt Rechte, die ein unprivilegierter Prozess nicht hat. Im Image
# bekommt /usr/bin/rsync sie als Datei-Capability (`cap_sys_chroot,cap_setgid`,
# siehe Dockerfile); ausserhalb dieses Images — eigener Build, `--cap-drop`,
# `--security-opt no-new-privileges`, ein Dateisystem ohne xattr-Unterstützung —
# kann das fehlen.
#
# Ohne diese Prüfung meldet sich das erst beim ersten Transfer, und zwar auf der
# Gegenstelle: `@ERROR: chroot failed`, exit 5. Genau so ist es unbemerkt in den
# ausgelieferten Container gekommen. Deshalb wird hier vor dem App-Start ein
# echter Wegwerf-Daemon mit chroot gestartet und angesprochen — geprüft wird das
# Verhalten, nicht die Capability-Bits.
RSYNC_CHROOT_PROBE_PORT="${RSYNC_CHROOT_PROBE_PORT:-18873}"

# 0 = chroot funktioniert, 1 = nicht. Gibt den Grund auf stderr aus.
chroot_probe() {
    local dir
    dir="$(mktemp -d 2>/dev/null)" || { echo "kein Temp-Verzeichnis"; return 1; }

    local root="${dir}/share"
    mkdir -p "$root" || { rm -rf "$dir"; echo "Verzeichnis nicht anlegbar"; return 1; }
    echo probe >"${root}/probe.txt"

    # Dieselben Optionen, die src/handlers/rsyncd.rs für ein echtes Modul
    # erzeugt — inklusive uid/gid, denn deren setgroups() ist die zweite Hürde
    # und scheitert unabhängig vom chroot.
    cat >"${dir}/rsyncd.conf" <<EOF
pid file = ${dir}/rsyncd.pid
lock file = ${dir}/rsyncd.lock
log file = ${dir}/rsyncd.log
port = ${RSYNC_CHROOT_PROBE_PORT}
address = 127.0.0.1
[probe]
    path = ${root}
    use chroot = yes
    uid = $(id -u)
    gid = $(id -g)
    read only = true
EOF

    rsync --daemon --no-detach --config="${dir}/rsyncd.conf" >/dev/null 2>&1 &
    local dpid=$!

    # Auf den Listener warten statt blind zu schlafen.
    local i
    for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do
        kill -0 "$dpid" 2>/dev/null || break
        rsync --contimeout=2 "rsync://127.0.0.1:${RSYNC_CHROOT_PROBE_PORT}/" \
            >/dev/null 2>&1 && break
        sleep 0.2
    done

    local out rc
    out="$(rsync --contimeout=5 "rsync://127.0.0.1:${RSYNC_CHROOT_PROBE_PORT}/probe/" 2>&1)"
    rc=$?

    kill "$dpid" 2>/dev/null
    wait "$dpid" 2>/dev/null

    if [ $rc -ne 0 ]; then
        # Die Daemon-Seite ist aussagekräftiger als die Client-Meldung:
        # dort steht `chroot(...) failed` bzw. `setgroups failed`.
        local detail
        detail="$(grep -m1 -E 'chroot|setgroups' "${dir}/rsyncd.log" 2>/dev/null)"
        rm -rf "$dir"
        printf '%s\n' "${detail:-$(printf '%s' "$out" | head -1)}"
        return 1
    fi

    rm -rf "$dir"
    return 0
}

# Liegen CAP_SYS_CHROOT (Bit 18) und CAP_SETGID (Bit 6) im Bounding-Set dieses
# Prozesses? Ohne sie nützt die Datei-Capability nichts — sie verhindert dann
# sogar das exec. Die Maske steht als Hex in /proc/self/status.
bounding_set_report() {
    local bnd
    bnd="$(awk '/^CapBnd:/ {print $2}' /proc/self/status 2>/dev/null)"
    [ -z "$bnd" ] && { echo "<nicht lesbar>"; return; }

    local out=""
    # printf '%d' 0x... rechnet die Hex-Maske in eine Zahl um; das reicht für
    # die beiden untersten 32 Bit, in denen beide Capabilities liegen.
    local mask=$((16#${bnd}))
    (( (mask >> 18) & 1 )) && out="cap_sys_chroot" || out="OHNE cap_sys_chroot"
    (( (mask >> 6)  & 1 )) && out="${out}, cap_setgid" || out="${out}, OHNE cap_setgid"
    echo "${out} (CapBnd=${bnd})"
}

# Fatal nur, wenn der Daemon überhaupt laufen soll. Steht RCLONE_GUI_RSYNCD
# nicht auf 1, startet die App keinen Daemon (src/main.rs) und ein fehlendes
# chroot hindert niemanden — dann bleibt es bei einer Warnung, statt eine
# vollständig funktionsfähige GUI am Start zu hindern.
check_chroot() {
    local reason
    if reason="$(chroot_probe)"; then
        echo "🔒 chroot  : nutzbar (rsync-Daemon isoliert jedes Modul in seinem Share-Root)"
        return 0
    fi

    local fatal=0
    [ "${RCLONE_GUI_RSYNCD:-}" = "1" ] && fatal=1

    {
        if [ "$fatal" -eq 1 ]; then
            echo "❌ Start abgebrochen: der rsync-Daemon kann nicht chrooten."
        else
            echo "⚠️  Der rsync-Daemon könnte nicht chrooten."
        fi
        echo "   Grund: ${reason}"
        echo ""
        echo "   'use chroot = yes' ist die wichtigste Isolationsschicht des"
        echo "   Peer-Zugriffs. Ohne sie liefe jeder Transfer entweder gar nicht"
        echo "   (@ERROR: chroot failed, exit 5) oder ungeschützt."
        echo ""
        echo "   /usr/bin/rsync braucht die Datei-Capabilities cap_sys_chroot und"
        echo "   cap_setgid. Im mitgelieferten Image setzt das Dockerfile sie."
        echo "   Datei-Capabilities: $(getcap /usr/bin/rsync 2>/dev/null || echo '<keine / getcap nicht verfügbar>')"
        echo "   Soll:               /usr/bin/rsync cap_setgid,cap_sys_chroot=ep"
        echo "   Bounding-Set:       $(bounding_set_report)"
        echo ""
        echo "   Beide Hälften müssen stimmen. Eine Datei-Capability, die nicht im"
        echo "   Bounding-Set des Containers liegt, wird nicht etwa ignoriert —"
        echo "   dann scheitert schon das exec von rsync mit EPERM, und rsync ist"
        echo "   gar nicht mehr aufrufbar (auch 'rsync --version' nicht)."
        echo ""
        echo "   Typische Ursachen ausserhalb des Images:"
        echo "     * eigener Build ohne 'setcap cap_sys_chroot,cap_setgid=ep /usr/bin/rsync'"
        echo "     * --cap-drop=SYS_CHROOT / --cap-drop=SETGID (bzw. cap_drop im Compose)"
        echo "     * --security-opt no-new-privileges (blockt Datei-Capabilities)"
        echo "     * Dateisystem ohne xattr-Unterstützung"
    } >&2

    if [ "$fatal" -eq 1 ]; then
        echo "" >&2
        echo "   RCLONE_GUI_RSYNCD=1 verlangt einen nutzbaren Daemon — deshalb" >&2
        echo "   Abbruch hier statt eines Fehlschlags beim ersten Transfer." >&2
        return 1
    fi

    echo "   Der Daemon ist aus (RCLONE_GUI_RSYNCD != 1), die App startet trotzdem." >&2
    return 0
}

check_chroot || exit 1

# ---------------------------------------------------------------------------
# TLS-Terminierung für den rsync-Daemon (Port 874 -> 127.0.0.1:873)
# ---------------------------------------------------------------------------

# Der rsync-Daemon selbst (Port 873) wird hier NICHT gestartet — das ist der
# Daemon-Lebenszyklus in der App. stunnel darf trotzdem vorher hochkommen: es
# baut die Backend-Verbindung erst auf, wenn ein Client anklopft.
RSYNC_TLS_LIB="$(dirname "$0")/config/rsync-tls.sh"
if [ -r "$RSYNC_TLS_LIB" ]; then
    # shellcheck source=config/rsync-tls.sh
    . "$RSYNC_TLS_LIB"
    rsync_tls_start || echo "⚠️  TLS-Terminierung nicht gestartet — Peer-Sync ist nicht nutzbar." >&2
else
    echo "⚠️  ${RSYNC_TLS_LIB} fehlt — keine TLS-Terminierung auf Port 874." >&2
fi

# ---------------------------------------------------------------------------
# App starten und beenden
# ---------------------------------------------------------------------------
#
# Bewusst KEIN `exec`, und das Signal wird unverändert durchgereicht.
#
# Warum kein `exec`: stunnel wird hier gestartet (rsync_tls_start) und hat
# selbst keinen Trap. Nur diese Shell weiss von STUNNEL_PID — mit `exec` wäre
# rclone-gui PID 1 und stunnel liefe nach dessen Ende als Waise weiter, bis der
# Container-Abbau es hart abräumt. Der Trap unten ist also der einzige Ort, an
# dem stunnel geordnet endet; er wirkt auch für PID 1, denn die Sonderregel des
# Kernels (Default-Disposition greift für PID 1 nicht) betrifft nur Signale
# **ohne** installierten Handler.
#
# Warum unverändert durchgereicht: rclone-gui behandelt seit Ticket c417c1c6
# SIGINT **und** SIGTERM gleichwertig (`wait_for_shutdown_signal`, src/main.rs)
# und läuft in beiden Fällen in denselben Graceful-Shutdown — Server austrudeln
# lassen (SERVER_DRAIN_DEADLINE), dann `daemon.shutdown()` für den rsync-Daemon
# (DAEMON_SHUTDOWN_DEADLINE). Früher übersetzte dieses Skript SIGTERM nach
# SIGINT, weil nur `ctrl_c` behandelt wurde. Diese Krücke ist entfallen: sie
# verschleierte, welches Signal der Prozess tatsächlich bekam, und zwang jeden,
# der das Shutdown-Verhalten nachweisen wollte, an start.sh vorbeizuzielen.

APP_PID=""
SHUTTING_DOWN=0

# stunnel beenden. Es hält keinen Zustand, der aufgeräumt werden müsste; es
# soll nur nicht länger auf 874 lauschen als die App, die dahinter steht.
stop_stunnel() {
    [ -n "${STUNNEL_PID:-}" ] || return 0
    kill -TERM "$STUNNEL_PID" 2>/dev/null
    wait "$STUNNEL_PID" 2>/dev/null
    STUNNEL_PID=""
}

# Reihenfolge: erst die App (sie fährt ihren rsync-Daemon selbst herunter),
# dann stunnel. Umgekehrt liefe ein laufender Transfer ins Leere.
#
# $1 ist das empfangene Signal und geht unverändert an die App weiter, damit im
# Log der App dasselbe Signal steht, das der Container bekommen hat.
on_term() {
    local sig="${1:-TERM}"
    [ "$SHUTTING_DOWN" -eq 1 ] && return 0
    SHUTTING_DOWN=1
    echo "🛑 SIG${sig} empfangen — fahre herunter"

    if [ -n "$APP_PID" ] && kill -0 "$APP_PID" 2>/dev/null; then
        kill -"$sig" "$APP_PID" 2>/dev/null
        # Gnadenfrist deutlich unter den 10 s von `docker stop`, damit ein
        # hängender Shutdown immer noch vor dem SIGKILL des Daemons endet.
        local i
        for i in $(seq 1 40); do
            kill -0 "$APP_PID" 2>/dev/null || break
            sleep 0.2
        done
        if kill -0 "$APP_PID" 2>/dev/null; then
            # Ein zweites SIG${sig} brächte nichts — die App hat es bereits
            # bekommen und behandelt. Bleibt nur SIGKILL, und der kommt hier
            # noch vor dem SIGKILL von `docker stop`, damit stunnel unten
            # überhaupt noch abgeräumt wird.
            echo "⚠️  rclone-gui reagiert nicht auf SIG${sig} — SIGKILL folgt." >&2
            kill -KILL "$APP_PID" 2>/dev/null
        fi
    fi
}

trap 'on_term TERM' TERM
trap 'on_term INT' INT

# Auf die App warten und ihren Exit-Code weiterreichen. `wait` kehrt bei einem
# abgefangenen Signal mit >128 zurück, ohne dass das Kind schon beendet wäre —
# deshalb die Schleife statt eines einzelnen `wait`.
run_app() {
    "$@" &
    APP_PID=$!

    local rc=0
    while :; do
        wait "$APP_PID"
        rc=$?
        kill -0 "$APP_PID" 2>/dev/null || break
    done

    stop_stunnel
    echo "👋 rclone-gui beendet (Exit ${rc})"
    exit "$rc"
}

if [ -x "/app/rclone-gui" ]; then
    cd /app || exit 1
    echo "🚀 Starte rclone-gui (Container)"
    run_app /app/rclone-gui "$@"
fi

if [ ! -f "./target/release/rclone-gui" ]; then
    echo "🔨 Building application..."
    cargo build --release || exit 1
fi

echo "🚀 Starte rclone-gui"
run_app ./target/release/rclone-gui "$@"
