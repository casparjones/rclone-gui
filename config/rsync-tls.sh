#!/usr/bin/env bash
#
# TLS-Terminierung für den rsync-Daemon (Ticket 5feb3af2).
#
# Wird von start.sh eingebunden (`source`) und stellt eine Funktion bereit:
#
#     rsync_tls_start   Zertifikate sicherstellen, stunnel.conf rendern,
#                       stunnel im Hintergrund starten
#
# Aufbau:
#
#     Peer --TLS--> stunnel 0.0.0.0:874 --Klartext--> rsyncd 127.0.0.1:873
#
# Der Daemon bindet nur auf Loopback (src/handlers/rsyncd.rs, DAEMON_ADDRESS)
# und Port 873 wird nicht nach aussen gemappt. stunnel ist damit der einzige
# Weg von aussen zum Daemon.
#
# Zertifikatsstrategie: eine von der App verwaltete interne CA. Begründung in
# README.md, Abschnitt "TLS-Terminierung auf Port 874". Kurz: das Web-UI-
# Zertifikat existiert im Container gar nicht (die UI spricht HTTP, TLS macht
# ein vorgelagerter Reverse Proxy), und beim Pairing wird ohnehin die CA an die
# Gegenstelle übergeben. Wer trotzdem ein eigenes Zertifikat einsetzen will,
# setzt RCLONE_GUI_TLS_CERT und RCLONE_GUI_TLS_KEY.

# ---------------------------------------------------------------------------
# Konfiguration (alles überschreibbar)
# ---------------------------------------------------------------------------

# Verzeichnis für Daemon-Konfiguration, Secrets und Zertifikate.
RSYNCD_DIR="${RSYNCD_DIR:-/etc/rsyncd}"
# TLS-Terminierung an/aus. 0 schaltet sie ab; der Daemon ist dann von aussen
# überhaupt nicht erreichbar (873 ist nicht gemappt) — kein Klartext-Fallback.
RCLONE_GUI_RSYNC_TLS="${RCLONE_GUI_RSYNC_TLS:-1}"
# Port, auf dem terminiert wird, und Backend dahinter.
RCLONE_GUI_RSYNC_TLS_PORT="${RCLONE_GUI_RSYNC_TLS_PORT:-874}"
RCLONE_GUI_RSYNC_TLS_BIND="${RCLONE_GUI_RSYNC_TLS_BIND:-0.0.0.0}"
RCLONE_GUI_RSYNC_BACKEND="${RCLONE_GUI_RSYNC_BACKEND:-127.0.0.1:873}"
# Hostname(n), die ins Zertifikat gehören. Komma-getrennt. Leer -> aus
# RCLONE_GUI_PUBLIC_BASE_URL abgeleitet, sonst `hostname`.
RCLONE_GUI_PEER_HOSTNAME="${RCLONE_GUI_PEER_HOSTNAME:-}"
# Eigenes Zertifikat statt der internen CA (z.B. dasselbe wie für die Web-UI).
RCLONE_GUI_TLS_CERT="${RCLONE_GUI_TLS_CERT:-}"
RCLONE_GUI_TLS_KEY="${RCLONE_GUI_TLS_KEY:-}"
# Laufzeiten der selbst erzeugten Zertifikate, in Tagen.
TLS_CA_DAYS="${TLS_CA_DAYS:-3650}"
TLS_LEAF_DAYS="${TLS_LEAF_DAYS:-825}"
# Ab wann ein selbst ausgestelltes Serverzertifikat erneuert wird (Sekunden).
TLS_RENEW_BEFORE="${TLS_RENEW_BEFORE:-2592000}"   # 30 Tage

# Abgeleitete Pfade.
TLS_DIR="${RSYNCD_DIR}/certs"
TLS_CA_KEY="${TLS_DIR}/ca.key"
TLS_CA_CRT="${TLS_DIR}/ca.crt"
TLS_SRV_KEY="${TLS_DIR}/srv.key"
TLS_SRV_CRT="${TLS_DIR}/srv.crt"
STUNNEL_CONF="${RSYNCD_DIR}/stunnel.conf"
# stunnel-Log. Einzige Quelle der echten Peer-IP fürs Audit-Log; die App sucht
# es per Voreinstellung neben rsyncd.conf (RCLONE_GUI_STUNNEL_LOG überschreibt).
STUNNEL_LOG="${STUNNEL_LOG:-${RSYNCD_DIR}/stunnel.log}"
# Vorlage: im Image unter /app/config, im Repo neben diesem Skript.
STUNNEL_TEMPLATE="${STUNNEL_TEMPLATE:-$(dirname "${BASH_SOURCE[0]}")/stunnel-rsyncd.conf.template}"

# PID des gestarteten stunnel, für start.sh sichtbar.
STUNNEL_PID=""

# ---------------------------------------------------------------------------
# Hilfsfunktionen
# ---------------------------------------------------------------------------

# Der Hostname, der als erster SAN ins Zertifikat kommt. Er muss exakt der
# Name sein, unter dem die Gegenstelle diese Instanz anspricht: rsync-ssl ruft
# `openssl s_client -verify_return_error` auf, und eine Verbindung über die IP
# statt über diesen Namen scheitert mit `verify error:num=62:hostname mismatch`.
tls_peer_names() {
    if [ -n "$RCLONE_GUI_PEER_HOSTNAME" ]; then
        printf '%s\n' "$RCLONE_GUI_PEER_HOSTNAME"
        return 0
    fi

    # Aus der öffentlichen Basis-URL den Host herausschneiden:
    # scheme://host[:port]/... -> host
    local url="${RCLONE_GUI_PUBLIC_BASE_URL:-}"
    if [ -n "$url" ]; then
        local host="${url#*://}"
        host="${host%%/*}"
        host="${host%%:*}"
        if [ -n "$host" ] && [ "$host" != "localhost" ]; then
            printf '%s\n' "$host"
            return 0
        fi
    fi

    printf '%s\n' "$(hostname)"
}

# Baut die subjectAltName-Zeile. Sieht ein Eintrag wie eine IP aus, wird er als
# IP:-SAN eingetragen — sonst wäre die Instanz über ihre IP nicht erreichbar
# (verify error 62), auch wenn der Name im Zertifikat steht.
tls_san_line() {
    local names="$1" entry out=""
    local IFS=','
    for entry in $names; do
        entry="$(printf '%s' "$entry" | tr -d '[:space:]')"
        [ -z "$entry" ] && continue
        if printf '%s' "$entry" | grep -Eq '^([0-9]{1,3}\.){3}[0-9]{1,3}$|^[0-9a-fA-F:]*:[0-9a-fA-F:]*$'; then
            out="${out}${out:+,}IP:${entry}"
        else
            out="${out}${out:+,}DNS:${entry}"
        fi
    done
    printf 'subjectAltName=%s\n' "$out"
}

# Interne CA anlegen, falls sie fehlt. Der öffentliche Teil (ca.crt) ist das,
# was beim Pairing an die Gegenstelle geht; der private Schlüssel verlässt
# diese Instanz nie.
tls_ensure_ca() {
    if [ -s "$TLS_CA_CRT" ] && [ -s "$TLS_CA_KEY" ]; then
        return 0
    fi

    echo "🔐 Erzeuge interne CA für den rsync-Transport (${TLS_CA_CRT})"
    ( umask 077
      openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -noenc \
          -keyout "$TLS_CA_KEY" -out "$TLS_CA_CRT" -days "$TLS_CA_DAYS" \
          -subj "/O=rclone-gui/CN=rclone-gui rsync peer CA" \
          -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
          -addext "keyUsage=critical,keyCertSign,cRLSign" >/dev/null 2>&1 ) || {
        echo "❌ CA konnte nicht erzeugt werden (openssl)" >&2
        return 1
    }
    chmod 600 "$TLS_CA_KEY"
    # ca.crt ist öffentlich und wird an die Gegenstelle übergeben.
    chmod 644 "$TLS_CA_CRT"
}

# Passt das vorhandene Serverzertifikat noch? Prüft Ablauf und ob der
# gewünschte Hostname als SAN drinsteht — ein geänderter
# RCLONE_GUI_PEER_HOSTNAME muss ein neues Zertifikat nach sich ziehen, sonst
# scheitert die Gegenstelle mit `hostname mismatch` und niemand weiss warum.
tls_leaf_is_current() {
    local names="$1" primary entry
    [ -s "$TLS_SRV_CRT" ] && [ -s "$TLS_SRV_KEY" ] || return 1
    openssl x509 -in "$TLS_SRV_CRT" -noout -checkend "$TLS_RENEW_BEFORE" >/dev/null 2>&1 || return 1

    local san
    san="$(openssl x509 -in "$TLS_SRV_CRT" -noout -ext subjectAltName 2>/dev/null)"
    local IFS=','
    for entry in $names; do
        entry="$(printf '%s' "$entry" | tr -d '[:space:]')"
        [ -z "$entry" ] && continue
        printf '%s' "$san" | grep -qE "(DNS|IP Address):${entry}([,[:space:]]|$)" || return 1
    done
    return 0
}

# Serverzertifikat ausstellen bzw. erneuern. Signiert von der internen CA,
# damit eine Erneuerung die beim Pairing verteilte CA nicht entwertet.
tls_ensure_leaf() {
    local names="$1"
    local primary="${names%%,*}"
    primary="$(printf '%s' "$primary" | tr -d '[:space:]')"

    if tls_leaf_is_current "$names"; then
        return 0
    fi

    echo "🔐 Stelle Serverzertifikat für '${primary}' aus (SAN: ${names})"
    local ext csr
    ext="$(mktemp)" || return 1
    csr="$(mktemp)" || { rm -f "$ext"; return 1; }
    {
        tls_san_line "$names"
        echo "basicConstraints=critical,CA:FALSE"
        echo "keyUsage=critical,digitalSignature,keyEncipherment"
        echo "extendedKeyUsage=serverAuth"
    } >"$ext"

    ( umask 077
      openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -noenc \
          -keyout "$TLS_SRV_KEY" -out "$csr" -subj "/O=rclone-gui/CN=${primary}" \
          >/dev/null 2>&1 &&
      openssl x509 -req -in "$csr" -CA "$TLS_CA_CRT" -CAkey "$TLS_CA_KEY" \
          -CAcreateserial -days "$TLS_LEAF_DAYS" -sha256 \
          -extfile "$ext" -out "$TLS_SRV_CRT" >/dev/null 2>&1 )
    local rc=$?
    rm -f "$ext" "$csr"
    if [ $rc -ne 0 ]; then
        echo "❌ Serverzertifikat konnte nicht ausgestellt werden (openssl)" >&2
        return 1
    fi
    chmod 600 "$TLS_SRV_KEY"
    chmod 644 "$TLS_SRV_CRT"
}

# Eigenes Zertifikat des Betreibers: nur prüfen und melden, nie ersetzen.
tls_check_own_cert() {
    if [ ! -r "$RCLONE_GUI_TLS_CERT" ] || [ ! -r "$RCLONE_GUI_TLS_KEY" ]; then
        echo "❌ RCLONE_GUI_TLS_CERT/-KEY gesetzt, aber nicht lesbar:" >&2
        echo "   cert=${RCLONE_GUI_TLS_CERT} key=${RCLONE_GUI_TLS_KEY}" >&2
        return 1
    fi
    if ! openssl x509 -in "$RCLONE_GUI_TLS_CERT" -noout -checkend 0 >/dev/null 2>&1; then
        # Kein Abbruch: ein abgelaufenes Zertifikat bricht die Verbindung
        # ohnehin clientseitig ab (rsync-ssl prüft mit -verify_return_error).
        # Ein stiller Rückfall auf Klartext existiert nicht.
        echo "⚠️  Serverzertifikat ${RCLONE_GUI_TLS_CERT} ist ABGELAUFEN." >&2
        echo "    Gegenstellen brechen die Verbindung ab (verify error:num=10)." >&2
    fi
    return 0
}

# Das Backend muss Loopback sein.
#
# stunnel terminiert TLS und reicht KLARTEXT weiter — das rsync-Protokoll mit
# seiner md5-Challenge, ohne jede Verschlüsselung. Zeigt `connect` auf eine
# andere Maschine, läuft genau der Teil, für den es TLS gibt, unverschlüsselt
# über das Netz, und von aussen sieht die Verbindung trotzdem nach TLS aus.
#
# Deshalb wird hier abgebrochen und nicht gewarnt: eine Warnung im Startlog
# hätte niemand gelesen, und der Zustand ist von aussen nicht erkennbar.
# Gegenstück auf der Anwendungsseite: DAEMON_ADDRESS und
# DaemonHandle::verify_it_listens_on_loopback_only in src/handlers/rsyncd.rs
# (Ticket 4292d027). Beides zusammen heisst: es gibt keinen Klartextweg zum
# Daemon, weder hinein noch heraus.
#
# # Warum das eine Positivpruefung ist und kein Muster (Ticket 7ec1f4db)
#
# Die erste Fassung fragte `case "$host" in 127.*|::1|localhost|...)`. Das Glob
# `127.*` trifft nicht nur Adressen, sondern jeden **Namen**, der so anfaengt:
#
#     RCLONE_GUI_RSYNC_BACKEND=127.0.0.1.evil.com:873   ->   galt als Loopback
#
# Damit haette stunnel Klartext-rsync an einen fremden Rechner weitergereicht —
# genau das, was der Riegel verhindern soll. Ein Angreifer braucht dafuer die
# Umgebungsvariable, es ist also kein Fernangriff; ein Riegel, der bei einem
# zurechtgelegten Namen aufgeht, ist trotzdem keiner.
#
# Deshalb wird jetzt **positiv** geprueft: entweder der Host ist einer von drei
# ausgeschriebenen Namen, oder er ist eine Zahlenadresse, die Feld fuer Feld als
# IPv4 in 127.0.0.0/8 zerlegbar ist. Alles andere wird abgewiesen, auch was
# harmlos aussieht. Ein Muster kann die naechste Schreibweise nicht kennen, eine
# Formatpruefung braucht sie nicht zu kennen.
#
# Die Wertetabelle steht in `every_backend_form_is_judged_by_the_tls_script`
# (src/handlers/rsyncd.rs) und laeuft mit `cargo test` mit. `bash -n` prueft nur
# die Syntax und haette diesen Fehler nie gefunden.
# Hilfsfunktion: der Rest hinter dem Host darf nichts sein oder `:<ziffern>`.
# Ein Glob `:[0-9]*` genuegt dafuer nicht — es liesse `:873:9999` durch.
tls_port_suffix_ok() {
    case "$1" in
        "") return 0 ;;
        :*) case "${1#:}" in ""|*[!0-9]*) return 1 ;; *) return 0 ;; esac ;;
        *) return 1 ;;
    esac
}

tls_backend_is_loopback() {
    local backend="$1" host

    # Aussen liegende Leerzeichen abschneiden — ein Wert aus einer .env-Datei
    # oder einem docker-compose-Block traegt sie leicht mit sich.
    backend="${backend#"${backend%%[![:space:]]*}"}"
    backend="${backend%"${backend##*[![:space:]]}"}"

    # Leer ist kein Loopback. Ohne diesen Zweig kaeme unten der leere Host
    # heraus, und der wuerde durch keine der Pruefungen fallen — aber ein leeres
    # `connect` in der stunnel-Konfiguration ist ein Startfehler, kein Loopback.
    [ -n "$backend" ] || return 1

    # Innen liegende Leerzeichen: ein solcher Wert ist entweder ein Tippfehler
    # oder ein Versuch, die Zerlegung zu verwirren. In beiden Faellen wird er
    # unverandert in `connect = …` gerendert und ist dort ohnehin falsch.
    case "$backend" in
        *[[:space:]]*) return 1 ;;
    esac

    # Host und Port trennen. Drei Formen kommen vor:
    case "$backend" in
        # [::1]:874 und [::1] — IPv6 in eckigen Klammern, Port optional.
        \[*\]*)
            host="${backend#[}"
            host="${host%%]*}"
            # Nach der schliessenden Klammer darf nur nichts oder :<port> stehen.
            tls_port_suffix_ok "${backend#*]}" || return 1
            ;;
        # Mehr als ein Doppelpunkt und keine Klammern: eine nackte
        # IPv6-Adresse. `::1:873` ist nicht entscheidbar — Adresse mit Port oder
        # Adresse ohne? — also gilt der ganze Wert als Adresse. Wer einen Port
        # angeben will, nimmt die Klammerform, so wie es die Vorlage tut.
        *:*:*)
            host="$backend"
            ;;
        # Alles andere: host oder host:port.
        *)
            host="${backend%%:*}"
            tls_port_suffix_ok "${backend#"$host"}" || return 1
            ;;
    esac

    # Ein leerer Host, ein fuehrender oder abschliessender Punkt und eine
    # doppelte Punktfolge sind in keiner der zulaessigen Formen gueltig. Ohne den
    # Zweig waere `127.0.0.1.` eine Loopback-Adresse, weil `read` das leere Feld
    # hinter dem letzten Punkt einfach nach `extra` schreibt.
    case "$host" in
        ""|.*|*.|*..*) return 1 ;;
    esac

    # 1. Die ausgeschriebenen Namen, exakt. `localhost.localdomain` steht mit
    #    drin, weil manche Basisbilder es als kanonischen Namen von 127.0.0.1
    #    fuehren; es ist ein Name aus /etc/hosts, kein aufloesbarer Fremdname.
    case "$host" in
        localhost|localhost.localdomain) return 0 ;;
        ::1|0:0:0:0:0:0:0:1) return 0 ;;
    esac

    # 2. Eine IPv4-Zahlenadresse in 127.0.0.0/8. Zerlegt, nicht geglobbt: vier
    #    Felder, jedes nur Ziffern und hoechstens dreistellig, jedes <= 255, das
    #    erste genau 127. `127.0.0.1.evil.com` hat fuenf Felder und faellt schon
    #    an der Zahl heraus; `127.0.0.1x` faellt an der Ziffernpruefung heraus.
    local a b c d extra
    IFS=. read -r a b c d extra <<<"$host"
    [ -z "$extra" ] || return 1
    local field
    for field in "$a" "$b" "$c" "$d"; do
        case "$field" in
            ""|*[!0-9]*) return 1 ;;
        esac
        [ "${#field}" -le 3 ] || return 1
        [ "$field" -le 255 ] || return 1
    done
    [ "$a" -eq 127 ] || return 1
    return 0
}

# ---------------------------------------------------------------------------
# Einstieg
# ---------------------------------------------------------------------------

rsync_tls_start() {
    if [ "$RCLONE_GUI_RSYNC_TLS" = "0" ]; then
        echo "ℹ️  TLS-Terminierung deaktiviert (RCLONE_GUI_RSYNC_TLS=0)."
        echo "    Der rsync-Daemon ist damit von aussen NICHT erreichbar —"
        echo "    Port 873 bleibt containerintern, einen Klartextweg gibt es nicht."
        return 0
    fi

    if ! command -v stunnel >/dev/null 2>&1; then
        echo "⚠️  stunnel fehlt — keine TLS-Terminierung auf Port ${RCLONE_GUI_RSYNC_TLS_PORT}." >&2
        echo "    Peer-Sync über rsync ist damit nicht nutzbar ('apk add stunnel')." >&2
        return 0
    fi
    if [ ! -r "$STUNNEL_TEMPLATE" ]; then
        echo "⚠️  stunnel-Vorlage nicht gefunden: ${STUNNEL_TEMPLATE}" >&2
        return 0
    fi

    # TLS ist Pflicht, nicht Vorgabe: hinter stunnel liegt Klartext, also darf
    # das Backend den Rechner nicht verlassen. Siehe tls_backend_is_loopback.
    if ! tls_backend_is_loopback "$RCLONE_GUI_RSYNC_BACKEND"; then
        echo "❌ RCLONE_GUI_RSYNC_BACKEND=${RCLONE_GUI_RSYNC_BACKEND} ist keine" >&2
        echo "   Loopback-Adresse. stunnel reicht hinter der TLS-Terminierung" >&2
        echo "   KLARTEXT weiter — das rsync-Protokoll ginge damit unverschlüsselt" >&2
        echo "   über das Netz, während die Verbindung von aussen nach TLS aussieht." >&2
        echo "   Kein Start. Einen unverschlüsselten Peer-Weg gibt es nicht." >&2
        return 1
    fi

    mkdir -p "$TLS_DIR" 2>/dev/null
    chmod 700 "$TLS_DIR" 2>/dev/null

    local cert key
    if [ -n "$RCLONE_GUI_TLS_CERT" ] || [ -n "$RCLONE_GUI_TLS_KEY" ]; then
        tls_check_own_cert || return 1
        cert="$RCLONE_GUI_TLS_CERT"
        key="$RCLONE_GUI_TLS_KEY"
        echo "🔐 Serverzertifikat: eigenes (${cert})"
    else
        local names
        names="$(tls_peer_names)"
        tls_ensure_ca || return 1
        tls_ensure_leaf "$names" || return 1
        cert="$TLS_SRV_CRT"
        key="$TLS_SRV_KEY"
        echo "🔐 Serverzertifikat: intern, gültig für ${names}"
        echo "   CA für das Pairing: ${TLS_CA_CRT}"
    fi

    # Konfiguration rendern. Die Vorlage bleibt unverändert, das Ergebnis wird
    # bei jedem Start neu geschrieben.
    sed -e "s#@ACCEPT@#${RCLONE_GUI_RSYNC_TLS_BIND}:${RCLONE_GUI_RSYNC_TLS_PORT}#" \
        -e "s#@CONNECT@#${RCLONE_GUI_RSYNC_BACKEND}#" \
        -e "s#@CERT@#${cert}#" \
        -e "s#@KEY@#${key}#" \
        -e "s#@LOG@#${STUNNEL_LOG}#" \
        "$STUNNEL_TEMPLATE" >"$STUNNEL_CONF" || {
        echo "❌ ${STUNNEL_CONF} konnte nicht geschrieben werden" >&2
        return 1
    }
    chmod 600 "$STUNNEL_CONF"

    # Das Log vorher anlegen, damit die Rechte feststehen, bevor stunnel die
    # erste Zeile schreibt: es enthält die Adresse jeder Gegenstelle, und
    # stunnel legt die Datei sonst mit der Standard-umask an (0644).
    if ! ( umask 077; touch "$STUNNEL_LOG" ) 2>/dev/null; then
        echo "⚠️  stunnel-Log ${STUNNEL_LOG} nicht anlegbar — das Audit-Log" >&2
        echo "    kennt die echte Client-IP dann nicht (client_source=unavailable)." >&2
    else
        chmod 600 "$STUNNEL_LOG" 2>/dev/null
    fi

    # Einen Trockenlauf gibt es nicht: stunnel 5.75 kennt keinen Test-Schalter
    # (`-test` wird als Dateiname interpretiert). Statt dessen wird unten
    # geprüft, ob der Prozess überlebt — bei einem Konfigurations- oder
    # Zertifikatsfehler beendet er sich sofort und schreibt den Grund ins Log.
    stunnel "$STUNNEL_CONF" &
    STUNNEL_PID=$!

    # Kurz warten und prüfen, dass der Prozess noch lebt. Ein belegter Port
    # oder ein unlesbarer Schlüssel äussert sich als sofortiger Exit.
    local i
    for i in 1 2 3 4 5 6 7 8 9 10; do
        kill -0 "$STUNNEL_PID" 2>/dev/null || break
        if command -v netstat >/dev/null 2>&1; then
            netstat -ltn 2>/dev/null | grep -q ":${RCLONE_GUI_RSYNC_TLS_PORT} " && break
        fi
        sleep 0.2
    done

    if ! kill -0 "$STUNNEL_PID" 2>/dev/null; then
        echo "❌ stunnel ist sofort wieder beendet worden (Port belegt? Schlüssel unlesbar?)" >&2
        STUNNEL_PID=""
        return 1
    fi

    echo "🔒 stunnel läuft (PID ${STUNNEL_PID}): ${RCLONE_GUI_RSYNC_TLS_BIND}:${RCLONE_GUI_RSYNC_TLS_PORT} -> ${RCLONE_GUI_RSYNC_BACKEND}"
    echo "   Die echte Client-IP steht im stunnel-Log ${STUNNEL_LOG} ('accepted connection from'),"
    echo "   nicht im Daemon-Log: 'proxy protocol' ist bewusst aus (siehe README)."
    return 0
}
