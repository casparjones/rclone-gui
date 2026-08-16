# -------- Build Stage --------
# rustc >= 1.88 nötig: die Abhängigkeit `zip` 8.x baut nicht mit 1.87
FROM rust:1.88-slim-bullseye AS builder

# Install musl toolchain & Co
RUN apt-get update && apt-get install -y \
    musl-tools \
    pkg-config \
    libssl-dev \
    && rustup target add x86_64-unknown-linux-musl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy dependency files first
COPY Cargo.toml Cargo.lock ./

# Dummy main to cache deps
RUN mkdir src && echo "fn main() {}" > src/main.rs

# Pre-build deps
RUN cargo build --release --target x86_64-unknown-linux-musl && \
    rm -rf target/x86_64-unknown-linux-musl/release/deps/rclone_gui*

# Copy real code
COPY src/ ./src/
COPY static/ ./static/

# Final build (musl statisch)
RUN cargo build --release --target x86_64-unknown-linux-musl

# Strip Binary
RUN strip target/x86_64-unknown-linux-musl/release/rclone-gui

# -------- Runtime Stage --------
# alpine >= 3.20 ist Pflicht, nicht Geschmackssache: musl 1.2.4 (alpine:3.19)
# implementiert fchmodat(AT_SYMLINK_NOFOLLOW) über /proc/self/fd. Im chroot des
# rsync-Daemons gibt es kein /proc -> ENOENT, und `use chroot = yes` bricht
# jeden Transfer mit exit 23 ab ("failed to set permissions ... No such file or
# directory"). Ab musl 1.2.5 (alpine:3.20) ist das behoben; gemessen in
# docs/rsync-transport.md, Abschnitt "use chroot".
FROM alpine:3.22

# Gepinnte Paketversionen. Beim Anheben: Werte gegen `apk policy <paket>` in
# alpine:3.22 prüfen, sonst schlägt der Build fehl (das ist gewollt).
ARG RSYNC_VERSION=3.4.3-r0
ARG OPENSSL_VERSION=3.5.7-r0
ARG STUNNEL_VERSION=5.75-r0
ARG BASH_VERSION=5.2.37-r0
ARG LIBCAP_VERSION=2.78-r0
ARG RCLONE_REL=1.70.1

# Runtime-Tools installieren (ohne libc!)
RUN apk update && apk upgrade && \
    apk add --no-cache ca-certificates wget unzip && \
    # rsync-Transport: rsync bringt ab 3.2.0 das Helper-Skript rsync-ssl mit.
    # Welche Auth-Digests der Daemon anbietet, hängt NICHT an der Version,
    # sondern daran, ob rsync gegen openssl-crypto gebaut wurde. Alpine baut
    # bewusst ohne -> nur md5/md4, auch mit rsync 3.4.3 (unten im Build-Log
    # nachgewiesen). Das ist akzeptiert: das Secret geht bei
    # Challenge-Response nie über die Leitung, und Vertraulichkeit sowie
    # Server-Authentizität liefert die TLS-Terminierung auf Port 874.
    # rsync-ssl ist ein bash-Skript -> bash ist Pflicht, nicht optional.
    # openssl ist das gewählte SSL-Backend (RSYNC_SSL_TYPE=openssl).
    # stunnel terminiert TLS auf Port 874 und reicht nach 127.0.0.1:873
    # weiter (Ticket 5feb3af2). Konfiguration: config/stunnel-rsyncd.conf.template,
    # gestartet von start.sh über config/rsync-tls.sh.
    # libcap liefert setcap/getcap. Gebraucht für die Datei-Capabilities auf
    # /usr/bin/rsync (siehe die eigene RUN-Schicht unten) und für den
    # Startup-Check in start.sh.
    apk add --no-cache \
        "rsync=${RSYNC_VERSION}" \
        "openssl=${OPENSSL_VERSION}" \
        "stunnel=${STUNNEL_VERSION}" \
        "bash=${BASH_VERSION}" \
        "libcap=${LIBCAP_VERSION}" && \
    # Install rclone directly from GitHub releases
    wget --retry-connrefused --tries=3 -O rclone.zip "https://github.com/rclone/rclone/releases/download/v${RCLONE_REL}/rclone-v${RCLONE_REL}-linux-amd64.zip" && \
    unzip rclone.zip && \
    mv "rclone-v${RCLONE_REL}-linux-amd64/rclone" /usr/local/bin/ && \
    chmod +x /usr/local/bin/rclone && \
    rm -rf rclone.zip "rclone-v${RCLONE_REL}-linux-amd64" && \
    # Verify: alle Transport-Binaries müssen im Image vorhanden sein
    /usr/local/bin/rclone --version && \
    rsync --version | head -1 && \
    test -x /usr/bin/rsync-ssl && \
    bash --version | head -1 && \
    openssl version && \
    stunnel -version 2>&1 | head -1 && \
    # musl >= 1.2.5 ist die eigentliche Voraussetzung für `use chroot = yes`
    /lib/ld-musl-x86_64.so.1 --version 2>&1 | head -2 && \
    # Zur Dokumentation im Build-Log: welche Daemon-Auth-Digests kann dieses
    # rsync? Erwartet wird "md5 md4" (kein openssl-crypto), d.h.
    # `auth digest = sha512` ist mit diesem Image nicht nutzbar — unabhängig
    # von der rsync-Version.
    rsync --version | grep -A2 -i 'daemon auth list'

# ---------------------------------------------------------------------------
# `use chroot = yes` ohne root: Datei-Capabilities auf /usr/bin/rsync
# (Ticket 33eeb98c)
# ---------------------------------------------------------------------------
# Das Problem: der Container läuft als `appuser` (USER appuser, weiter unten),
# also auch der von der App gestartete rsync-Daemon. `chroot()` verlangt
# CAP_SYS_CHROOT, und ein unprivilegierter Prozess hat keine effektiven
# Capabilities — der Daemon scheiterte deshalb im ausgelieferten Container mit
#   chroot("/data/modA") failed: Operation not permitted (1)
#   @ERROR: chroot failed
# obwohl alle bisherigen Nachweise (mit manuell als root gestartetem Daemon)
# durchliefen.
#
# Die Lösung ist die Datei-Capability, NICHT `cap_add` in docker-compose.yml:
#
#   * CAP_SYS_CHROOT und CAP_SETGID liegen ohnehin im Default-Bounding-Set von
#     Docker (gemessen: CapBnd=00000000a80425fb in einem nackten
#     `docker run alpine:3.22`). Eine Datei-Capability wird daraus beim exec in
#     das Permitted-Set gehoben — auch für uid 1001. `cap_add` ist damit
#     überflüssig, und genau das ist der Punkt: wer sein eigenes Compose-File
#     oder ein `docker run` benutzt, bekommt chroot ohne eine Zeile
#     Zusatzkonfiguration. Ein vergessenes `cap_add` wäre sonst ein stiller
#     Ausfall bei jedem Fremdbetreiber.
#   * Die Erweiterung hängt an einer einzigen Binärdatei statt am ganzen
#     Container. Der Rest des Images bleibt unprivilegiert, `USER appuser`
#     bleibt bestehen, die App läuft NICHT als root.
#
# Warum zusätzlich CAP_SETGID, und warum ausdrücklich NICHT CAP_SETUID:
# sobald rsync CAP_SYS_CHROOT besitzt, betrachtet es sich als privilegiert
# genug, um die Modul-Identität zu wechseln, und führt für `uid`/`gid` aus der
# generierten Modulkonfiguration (src/handlers/rsyncd.rs) setgid/setgroups/
# setuid aus. Gemessen: nur mit CAP_SYS_CHROOT bleibt es bei
#   rsync: [Receiver] setgroups failed: Operation not permitted (1)
#   @ERROR: setgroups failed        (exit 5)
# — der chroot selbst gelingt da bereits. `setgroups()` verlangt CAP_SETGID.
# `setgid(1001)`/`setuid(1001)` sind dagegen Wechsel auf die eigene Identität
# und brauchen keine Capability. CAP_SETUID bleibt deshalb draussen: es wäre
# ein vollständiger Weg von appuser nach uid 0 innerhalb des Containers und
# damit die Aufhebung von `USER appuser`. CAP_SETGID erlaubt gid 0, was ohne
# gruppenschreibbare root-Pfade im Image folgenlos bleibt.
#
# Beim Anheben von rsync oder alpine: die Verifikation unten fällt sonst um.
RUN setcap cap_sys_chroot,cap_setgid=ep /usr/bin/rsync && \
    getcap /usr/bin/rsync | grep -q 'cap_setgid.*cap_sys_chroot\|cap_sys_chroot.*cap_setgid'

WORKDIR /app

# Appuser und Verzeichnisse
#   /data          Share-Root, wird nach aussen freigegeben
#   /etc/rsyncd    Daemon-Konfiguration, Secrets und Zertifikate.
#                  Liegt bewusst ausserhalb jedes freigegebenen Pfads, damit
#                  nichts davon über einen rsync-Share lesbar wird.
RUN addgroup -g 1001 appgroup && \
    adduser -u 1001 -G appgroup -s /bin/sh -D appuser && \
    mkdir -p /app/data /app/static /data \
             /etc/rsyncd /etc/rsyncd/secrets /etc/rsyncd/certs && \
    chown -R appuser:appgroup /app /data /etc/rsyncd && \
    chmod 700 /etc/rsyncd/secrets /etc/rsyncd/certs

# Copy binary & static files
COPY --from=builder /app/target/x86_64-unknown-linux-musl/release/rclone-gui /app/
COPY --from=builder /app/static /app/static
COPY .env /app/
COPY start.sh /app/start.sh
# TLS-Terminierung: Helper + stunnel-Vorlage. start.sh sucht sie unter
# $(dirname $0)/config, deshalb liegen sie neben start.sh.
COPY config/ /app/config/

# Berechtigungen & ausführbar machen
RUN chmod +x /app/rclone-gui /app/start.sh /app/config/rsync-tls.sh

USER appuser

# 8080 Web-UI
# 874  rsync über TLS (registrierter Port, wird nach aussen gemappt)
# 873  rsync-Daemon — bleibt containerintern und wird NICHT gemappt
EXPOSE 8080 874

# Volumes für Config, Benutzer-Daten und Daemon-Konfiguration/Secrets/Zertifikate
VOLUME ["/app/data", "/data", "/etc/rsyncd"]

# Healthcheck
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:8080/ || exit 1

# Umgebungsvariablen
ENV RCLONE_GUI_DEFAULT_PATH=/data
ENV RUST_LOG=info
# SSL-Backend für rsync-ssl explizit setzen statt der Heuristik zu überlassen
ENV RSYNC_SSL_TYPE=openssl
# Öffentliche Basis-URL dieser Instanz (OAuth-Redirects, Pairing-Links).
# Im Betrieb über docker-compose.yml / .env überschreiben.
ENV RCLONE_GUI_PUBLIC_BASE_URL=http://localhost:8080

# TLS-Terminierung des rsync-Daemons. Voreinstellung: an. Der Hostname gehört
# als SAN ins Serverzertifikat — eine Gegenstelle, die nur die IP kennt,
# scheitert mit `verify error:num=62:hostname mismatch`. Ohne eigenen Wert wird
# er aus RCLONE_GUI_PUBLIC_BASE_URL abgeleitet.
ENV RCLONE_GUI_RSYNC_TLS=1
# ENV RCLONE_GUI_PEER_HOSTNAME=rclone.example.org

# Startbefehl: start.sh prüft bash/rclone/rsync/rsync-ssl/openssl und die
# chroot-Fähigkeit, richtet die TLS-Terminierung auf Port 874 ein und loggt die
# Versionen, bevor die App übernimmt.
#
# ENTRYPOINT/CMD sind getrennt, damit eigene Argumente die Startlogik nicht
# aushebeln: `docker run <image> --bind 0.0.0.0:9000` ersetzt nur das CMD und
# landet als Argument bei start.sh. Vorher (alles im CMD) scheiterte derselbe
# Aufruf mit `exec: "--bind": executable file not found`.
ENTRYPOINT ["/app/start.sh"]
CMD ["--bind", "0.0.0.0:8080"]

# `docker stop` schickt SIGTERM an PID 1. PID 1 ist start.sh; es fängt das
# Signal ab, fährt App und stunnel geordnet herunter und beendet sich, lange
# bevor die 10-Sekunden-Gnadenfrist abläuft. Siehe den Abschnitt "Beenden" in
# start.sh — und die Erklärung, warum ein `exec`-tes rclone-gui als PID 1
# SIGTERM stillschweigend ignoriert hat.
STOPSIGNAL SIGTERM
