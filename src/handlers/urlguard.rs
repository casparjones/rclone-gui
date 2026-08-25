// SSRF-Schutz für den Downloader („Von URL holen").
//
// Der Downloader lässt einen Nutzer eine URL angeben, die *der Server* abruft.
// Damit wird der Server zum Stellvertreter: er sitzt hinter derselben Firewall
// wie die Cloud-Metadaten-Adresse, wie die Datenbank, wie jedes Gerät im
// internen Netz. Ohne Schutz erreicht ein Nutzer über diesen Umweg Ziele, die
// er selbst nicht erreichen darf.
//
// Dieses Modul ist bewusst der eigenständige, testbare Baustein davor. Es
// enthält *keine* axum-Handler; die HTTP-Oberfläche des Downloaders gehört zum
// Folge-Ticket. Was hier steht, ist die Prüfung und ein Minimal-Transport, der
// die Prüfung nachweisbar macht, ohne dass ein Test ins Internet muss.
//
// Die vier Fallen, an denen naive Implementierungen scheitern:
//
// 1. **Namen statt Adressen prüfen.** `evil.example.com` darf auf 127.0.0.1
//    zeigen. Geprüft wird deshalb ausschliesslich die *aufgelöste* IP, nie der
//    Hostname. Nebeneffekt: exotische Schreibweisen wie `http://2130706433/`
//    oder `http://0177.0.0.1/`, die der Systemresolver zu 127.0.0.1 auflöst,
//    sind damit automatisch erschlagen.
//
// 2. **DNS-Rebinding (TOCTOU).** Wer auflöst, prüft und dann erneut auflöst, um
//    zu verbinden, prüft eine andere Adresse als die, mit der er verbindet.
//    [`vet_url`] gibt deshalb einen [`VettedTarget`] mit der *konkreten*
//    Socket-Adresse zurück, und [`TcpTransport`] verbindet ausschliesslich mit
//    dieser Adresse — es löst nie selbst auf. Zusätzlich wird nach dem
//    Verbindungsaufbau die tatsächliche Peer-Adresse ein zweites Mal geprüft
//    (Gürtel und Hosenträger, siehe `connect_vetted`).
//
// 3. **Redirects.** Ein erlaubtes Ziel darf mit `302 Location:
//    http://169.254.169.254/` antworten. Jeder Sprung durchläuft deshalb die
//    volle Prüfung erneut, und die Zahl der Sprünge ist begrenzt.
//
// 4. **IPv4-mapped IPv6.** `::ffff:127.0.0.1` ist Loopback, sieht für eine
//    reine v6-Prüfung aber wie eine gewöhnliche Adresse aus. [`normalize_ip`]
//    packt solche Adressen aus, bevor klassifiziert wird.
//
// Zum Transport: [`TcpTransport`] spricht nur `http`, nicht `https`, und puffert
// den Body im Speicher. Das ist Absicht und reicht für diesen Baustein — er
// existiert, damit Grössen- und Zeitgrenze und die Redirect-Kette in Tests
// tatsächlich *ausgeführt* werden können. Der produktive Downloader (Ticket
// „Downloader Von URL holen") bringt einen TLS-fähigen, streamenden Transport
// mit; er implementiert dafür [`Transport`] und erbt die gesamte Prüfung, indem
// er ausschliesslich über [`vet_url`] an Adressen kommt. Eine
// TLS-Client-Bibliothek fehlt im Baum noch und wäre eine Änderung an
// `Cargo.toml`, die nicht zu diesem Ticket gehört.
#![allow(dead_code)]

use futures::future::BoxFuture;
use std::collections::HashMap;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

// ---------------------------------------------------------------------------
// Fehler
// ---------------------------------------------------------------------------

/// Warum ein Abruf abgelehnt oder abgebrochen wurde.
///
/// Die Varianten sind grob genug, dass eine Fehlermeldung an den Nutzer nichts
/// über das interne Netz verrät: [`GuardError::BlockedAddress`] nennt die
/// Adresse zwar im `Display`, weil sie für das Log gebraucht wird — der
/// Handler, der diesen Fehler später in eine HTTP-Antwort übersetzt, soll dem
/// Nutzer nur die Kategorie zeigen, nicht den Text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GuardError {
    /// Schema ist nicht `http` oder `https` (`file:`, `ftp:`, `gopher:` …).
    UnsupportedScheme(String),
    /// URL liess sich nicht zerlegen.
    MalformedUrl(String),
    /// Der Name liess sich nicht auflösen (oder die Auflösung lief in den Timeout).
    DnsFailure(String),
    /// Die aufgelöste Adresse liegt in einem gesperrten Bereich.
    BlockedAddress(IpAddr),
    /// Mehr Weiterleitungen als erlaubt.
    TooManyRedirects(usize),
    /// Antwort überschreitet die Grössengrenze.
    TooLarge { limit: u64 },
    /// Zeitgrenze für den gesamten Abruf überschritten.
    Timeout,
    /// Der Nutzer hat bereits die erlaubte Zahl gleichzeitiger Downloads.
    TooManyConcurrent { limit: usize },
    /// Gegenstelle hat kein verwertbares HTTP gesprochen.
    BadResponse(String),
    /// Netz-/IO-Fehler.
    Io(String),
}

impl fmt::Display for GuardError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedScheme(s) => {
                write!(f, "Schema '{s}' ist nicht erlaubt, nur http/https")
            }
            Self::MalformedUrl(s) => write!(f, "URL nicht verwertbar: {s}"),
            Self::DnsFailure(h) => write!(f, "Namensauflösung für '{h}' fehlgeschlagen"),
            Self::BlockedAddress(ip) => {
                write!(f, "Zieladresse {ip} liegt in einem gesperrten Bereich")
            }
            Self::TooManyRedirects(n) => write!(f, "mehr als {n} Weiterleitungen"),
            Self::TooLarge { limit } => write!(f, "Antwort überschreitet {limit} Byte"),
            Self::Timeout => write!(f, "Zeitgrenze überschritten"),
            Self::TooManyConcurrent { limit } => {
                write!(f, "bereits {limit} gleichzeitige Downloads")
            }
            Self::BadResponse(s) => write!(f, "ungültige HTTP-Antwort: {s}"),
            Self::Io(s) => write!(f, "IO-Fehler: {s}"),
        }
    }
}

impl std::error::Error for GuardError {}

// ---------------------------------------------------------------------------
// Adressklassifikation
//
// Der Kern. Alles andere in diesem Modul dient nur dazu, dass diese Funktion
// die Adresse zu sehen bekommt, mit der wirklich verbunden wird.
// ---------------------------------------------------------------------------

/// Packt IPv4-in-IPv6 aus, damit die v4-Regeln greifen.
///
/// Betrifft `::ffff:a.b.c.d` (IPv4-mapped, RFC 4291) und `::a.b.c.d`
/// (IPv4-compatible, abgekündigt). Ohne diesen Schritt läuft `::ffff:127.0.0.1`
/// an jeder reinen v6-Prüfung vorbei — der Klassiker, an dem
/// SSRF-Filter scheitern.
pub fn normalize_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(_) => ip,
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            // `to_ipv4` deckt zusätzlich die IPv4-compatible-Form `::a.b.c.d`
            // ab. `::` und `::1` liefert es ebenfalls (als 0.0.0.0 / 0.0.0.1);
            // beide sind über die v4-Regeln ohnehin gesperrt.
            None => match v6.to_ipv4() {
                Some(v4) => IpAddr::V4(v4),
                None => ip,
            },
        },
    }
}

/// `true`, wenn die Adresse nicht abgerufen werden darf.
///
/// Grundhaltung: alles sperren, was nicht eindeutig öffentliches Internet ist.
/// Ein zu Unrecht gesperrter Download ist ärgerlich, ein zu Unrecht erlaubter
/// ist eine Lücke.
pub fn is_blocked_ip(ip: IpAddr) -> bool {
    match normalize_ip(ip) {
        IpAddr::V4(v4) => is_blocked_v4(v4),
        IpAddr::V6(v6) => is_blocked_v6(v6),
    }
}

fn is_blocked_v4(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    let n = u32::from_be_bytes(o);

    // 0.0.0.0/8 — „this network", enthält auch die unspezifizierte Adresse.
    if o[0] == 0 {
        return true;
    }
    // 127.0.0.0/8 Loopback
    if ip.is_loopback() {
        return true;
    }
    // 10/8, 172.16/12, 192.168/16
    if ip.is_private() {
        return true;
    }
    // 169.254.0.0/16 Link-local — hier wohnt 169.254.169.254, die
    // Metadaten-Adresse von AWS/GCP/Azure. Der wichtigste Einzeleintrag
    // dieser ganzen Liste.
    if ip.is_link_local() {
        return true;
    }
    // 100.64.0.0/10 Carrier-Grade NAT (RFC 6598) — im Providernetz und in
    // manchen Container-Fabrics ein internes Netz.
    if n & 0xffc0_0000 == 0x6440_0000 {
        return true;
    }
    // 192.0.0.0/24 IETF-Protokollzuweisungen (u.a. DS-Lite 192.0.0.0/29)
    if n & 0xffff_ff00 == 0xc000_0000 {
        return true;
    }
    // 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24 Dokumentation
    if ip.is_documentation() {
        return true;
    }
    // 198.18.0.0/15 Benchmarking
    if n & 0xfffe_0000 == 0xc612_0000 {
        return true;
    }
    // 224.0.0.0/4 Multicast und 240.0.0.0/4 reserviert (inkl.
    // 255.255.255.255 Broadcast).
    if o[0] >= 224 {
        return true;
    }
    false
}

fn is_blocked_v6(ip: Ipv6Addr) -> bool {
    let s = ip.segments();

    // :: unspezifiziert und ::1 Loopback
    if ip.is_unspecified() || ip.is_loopback() {
        return true;
    }
    // ff00::/8 Multicast
    if ip.is_multicast() {
        return true;
    }
    // fc00::/7 Unique Local (das v6-Gegenstück zu 10/8 & Co.)
    if s[0] & 0xfe00 == 0xfc00 {
        return true;
    }
    // fe80::/10 Link-local
    if s[0] & 0xffc0 == 0xfe80 {
        return true;
    }
    // 100::/64 Discard-Only
    if s[0] == 0x0100 && s[1] == 0 && s[2] == 0 && s[3] == 0 {
        return true;
    }
    // 2001:db8::/32 Dokumentation
    if s[0] == 0x2001 && s[1] == 0x0db8 {
        return true;
    }
    // 2001::/32 Teredo und 2002::/16 6to4 betten IPv4-Adressen ein und sind
    // damit ein zweiter Weg zu internen v4-Zielen. Beide sind ausgestorben;
    // pauschal sperren ist billiger, als die eingebettete Adresse zu prüfen.
    if s[0] == 0x2001 && s[1] == 0x0000 {
        return true;
    }
    if s[0] == 0x2002 {
        return true;
    }
    // 64:ff9b::/96 und 64:ff9b:1::/48 NAT64 — bilden den kompletten
    // v4-Adressraum nach v6 ab, interne Ziele eingeschlossen.
    if s[0] == 0x0064 && s[1] == 0xff9b {
        return true;
    }
    false
}

// ---------------------------------------------------------------------------
// URL-Zerlegung
//
// Bewusst von Hand statt mit dem `url`-Crate: das steckt nicht als direkte
// Abhängigkeit im Baum, und `Cargo.toml` gehört diesem Ticket nicht. Der
// Umfang bleibt überschaubar, weil nur `http`/`https` überhaupt zugelassen
// sind.
// ---------------------------------------------------------------------------

/// Eine akzeptierte `http`/`https`-URL in ihren Bestandteilen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedUrl {
    /// Kleingeschrieben, immer `http` oder `https`.
    pub scheme: String,
    /// Hostname bzw. IP-Literal **ohne** eckige Klammern.
    pub host: String,
    /// Port, notfalls der Standardport des Schemas.
    pub port: u16,
    /// Pfad inklusive Query, beginnt immer mit `/`.
    pub path_and_query: String,
    /// War der Port in der URL ausgeschrieben?
    explicit_port: bool,
    /// Host in der Schreibweise für die URL — v6-Literale mit Klammern.
    host_in_url: String,
}

impl ParsedUrl {
    pub fn is_tls(&self) -> bool {
        self.scheme == "https"
    }

    /// Der Wert für den `Host:`-Header: ohne Port, wenn es der Standard ist.
    pub fn host_header(&self) -> String {
        if self.explicit_port {
            format!("{}:{}", self.host_in_url, self.port)
        } else {
            self.host_in_url.clone()
        }
    }
}

impl fmt::Display for ParsedUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}://{}", self.scheme, self.host_header())?;
        f.write_str(&self.path_and_query)
    }
}

/// Zerlegt eine URL und lehnt alles ab, was nicht `http`/`https` ist.
///
/// Die Userinfo (`http://harmlos.example.com@127.0.0.1/`) wird verworfen — ein
/// gern genommener Trick, um eine Sichtprüfung zu täuschen. Maßgeblich ist der
/// Teil hinter dem **letzten** `@`.
pub fn parse_url(input: &str) -> Result<ParsedUrl, GuardError> {
    let raw = input.trim();
    if raw.is_empty() {
        return Err(GuardError::MalformedUrl("leer".into()));
    }
    // Steuerzeichen in einer URL sind entweder ein Tippfehler oder ein
    // Versuch, Header zu schmuggeln (CR/LF).
    if raw.chars().any(|c| c.is_control() || c == ' ') {
        return Err(GuardError::MalformedUrl("enthält Steuerzeichen".into()));
    }

    let (scheme, rest) = raw
        .split_once("://")
        .ok_or_else(|| GuardError::MalformedUrl("kein Schema".into()))?;
    let scheme = scheme.to_ascii_lowercase();
    if scheme != "http" && scheme != "https" {
        return Err(GuardError::UnsupportedScheme(scheme));
    }
    // `file:///etc/passwd` und `mailto:` haben gar kein `://` bzw. ein anderes
    // Schema und sind damit schon oben heraus. Der Vollständigkeit halber
    // fällt `file://…` hier durch die Schema-Prüfung.

    // Fragment abschneiden (wird nie übertragen), dann Authority vom Pfad
    // trennen.
    let rest = rest.split('#').next().unwrap_or("");
    let (authority, path) = match rest.find(['/', '?']) {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, ""),
    };

    // Userinfo verwerfen.
    let authority = match authority.rfind('@') {
        Some(i) => &authority[i + 1..],
        None => authority,
    };
    if authority.is_empty() {
        return Err(GuardError::MalformedUrl("kein Host".into()));
    }

    let default_port = if scheme == "https" { 443 } else { 80 };
    let (host_in_url, host, port, explicit_port) = if let Some(close) = authority.find(']') {
        // IPv6-Literal: [::1] bzw. [::1]:8080
        if !authority.starts_with('[') {
            return Err(GuardError::MalformedUrl("defekte Adressklammer".into()));
        }
        let inner = &authority[1..close];
        let tail = &authority[close + 1..];
        let (port, explicit) = parse_port_suffix(tail, default_port)?;
        if inner.parse::<Ipv6Addr>().is_err() {
            return Err(GuardError::MalformedUrl(
                "keine gültige IPv6-Adresse".into(),
            ));
        }
        (
            format!("[{inner}]"),
            inner.to_ascii_lowercase(),
            port,
            explicit,
        )
    } else {
        let (h, tail) = match authority.rfind(':') {
            Some(i) => (&authority[..i], &authority[i..]),
            None => (authority, ""),
        };
        if h.is_empty() {
            return Err(GuardError::MalformedUrl("kein Host".into()));
        }
        let (port, explicit) = parse_port_suffix(tail, default_port)?;
        let h = h.to_ascii_lowercase();
        (h.clone(), h, port, explicit)
    };

    let path_and_query = if path.is_empty() {
        "/".to_string()
    } else if let Some(stripped) = path.strip_prefix('?') {
        format!("/?{stripped}")
    } else {
        path.to_string()
    };

    Ok(ParsedUrl {
        scheme,
        host,
        port,
        path_and_query,
        explicit_port,
        host_in_url,
    })
}

/// `""` → Standardport, `":8080"` → 8080. Alles andere ist ein Fehler.
fn parse_port_suffix(tail: &str, default_port: u16) -> Result<(u16, bool), GuardError> {
    if tail.is_empty() {
        return Ok((default_port, false));
    }
    let digits = tail
        .strip_prefix(':')
        .ok_or_else(|| GuardError::MalformedUrl("defekte Portangabe".into()))?;
    let port: u16 = digits
        .parse()
        .map_err(|_| GuardError::MalformedUrl(format!("Port '{digits}' ungültig")))?;
    if port == 0 {
        return Err(GuardError::MalformedUrl("Port 0".into()));
    }
    Ok((port, true))
}

/// Löst ein `Location:` gegen die URL auf, aus der es kam.
///
/// Deckt absolute URLs, schema-relative (`//host/pfad`), wurzel-relative
/// (`/pfad`) und relative Angaben ab. Das Ergebnis geht anschliessend wieder
/// durch [`parse_url`] — eine Weiterleitung auf `file:///etc/passwd` scheitert
/// also an derselben Schema-Prüfung wie eine direkt eingegebene.
pub fn resolve_location(base: &ParsedUrl, location: &str) -> Result<String, GuardError> {
    let loc = location.trim();
    if loc.is_empty() {
        return Err(GuardError::BadResponse("leeres Location".into()));
    }
    if loc.chars().any(|c| c.is_control()) {
        return Err(GuardError::BadResponse("Location mit Steuerzeichen".into()));
    }
    if loc.contains("://") {
        return Ok(loc.to_string());
    }
    if let Some(rest) = loc.strip_prefix("//") {
        return Ok(format!("{}://{}", base.scheme, rest));
    }
    let authority = base.host_header();
    if loc.starts_with('/') {
        return Ok(format!("{}://{}{}", base.scheme, authority, loc));
    }
    // Relativ: alles hinter dem letzten `/` des Basispfads ersetzen, Query
    // fällt dabei weg.
    let base_path = base
        .path_and_query
        .split('?')
        .next()
        .unwrap_or("/")
        .to_string();
    let dir = match base_path.rfind('/') {
        Some(i) => &base_path[..=i],
        None => "/",
    };
    Ok(format!("{}://{}{}{}", base.scheme, authority, dir, loc))
}

// ---------------------------------------------------------------------------
// Namensauflösung
//
// Als Trait, damit Tests eine Zuordnung Name → Adresse vorgeben können. Ohne
// das wäre der interessante Teil dieses Moduls nur mit echtem DNS prüfbar, und
// ein Test, der ins Internet greift, ist kein Test.
// ---------------------------------------------------------------------------

pub trait Resolver: Send + Sync {
    /// Alle Adressen zu `host`. Ein IP-Literal wird nicht hier behandelt,
    /// sondern schon vorher in [`vet_url`] erkannt.
    fn resolve<'a>(
        &'a self,
        host: &'a str,
        port: u16,
    ) -> BoxFuture<'a, Result<Vec<SocketAddr>, GuardError>>;
}

/// Der Resolver des Betriebssystems.
pub struct SystemResolver;

impl Resolver for SystemResolver {
    fn resolve<'a>(
        &'a self,
        host: &'a str,
        port: u16,
    ) -> BoxFuture<'a, Result<Vec<SocketAddr>, GuardError>> {
        Box::pin(async move {
            let addrs = tokio::net::lookup_host((host, port))
                .await
                .map_err(|e| GuardError::DnsFailure(format!("{host}: {e}")))?
                .collect::<Vec<_>>();
            if addrs.is_empty() {
                return Err(GuardError::DnsFailure(format!("{host}: keine Adresse")));
            }
            Ok(addrs)
        })
    }
}

/// Fest verdrahtete Zuordnung für Tests.
pub struct StaticResolver {
    map: HashMap<String, Vec<IpAddr>>,
}

impl StaticResolver {
    pub fn new() -> Self {
        Self {
            map: HashMap::new(),
        }
    }

    pub fn with(mut self, host: &str, addrs: &[IpAddr]) -> Self {
        self.map.insert(host.to_ascii_lowercase(), addrs.to_vec());
        self
    }
}

impl Default for StaticResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl Resolver for StaticResolver {
    fn resolve<'a>(
        &'a self,
        host: &'a str,
        port: u16,
    ) -> BoxFuture<'a, Result<Vec<SocketAddr>, GuardError>> {
        let found = self
            .map
            .get(&host.to_ascii_lowercase())
            .map(|v| v.iter().map(|ip| SocketAddr::new(*ip, port)).collect());
        Box::pin(async move {
            found.ok_or_else(|| GuardError::DnsFailure(format!("{host}: unbekannt")))
        })
    }
}

// ---------------------------------------------------------------------------
// Regelwerk
// ---------------------------------------------------------------------------

/// Grenzen und Schalter für einen Abruf.
#[derive(Debug, Clone)]
pub struct GuardPolicy {
    /// Höchstzahl der Weiterleitungen. 0 heisst: gar keine.
    pub max_redirects: usize,
    /// Obergrenze für den Antwortkörper.
    pub max_bytes: u64,
    /// Zeitgrenze für den *gesamten* Abruf, Weiterleitungen eingerechnet.
    pub total_timeout: Duration,
    /// Zeitgrenze für einen einzelnen Verbindungsaufbau.
    pub connect_timeout: Duration,
    /// Gleichzeitige Downloads je Nutzer (siehe [`DownloadSlots`]).
    pub max_concurrent_per_user: usize,
    /// **Nur für Tests.** Hebt die Adressprüfung auf, damit ein Testserver auf
    /// 127.0.0.1 erreichbar ist. In Produktion niemals setzen — jede
    /// Aktivierung schreibt eine Warnung ins Log.
    pub allow_private_addresses: bool,
}

impl Default for GuardPolicy {
    fn default() -> Self {
        Self {
            max_redirects: 5,
            max_bytes: 512 * 1024 * 1024,
            total_timeout: Duration::from_secs(300),
            connect_timeout: Duration::from_secs(10),
            max_concurrent_per_user: 2,
            allow_private_addresses: false,
        }
    }
}

impl GuardPolicy {
    /// Regelwerk für Tests: erlaubt Loopback, damit ein lokaler Testserver
    /// angesprochen werden kann.
    pub fn for_tests() -> Self {
        Self {
            allow_private_addresses: true,
            total_timeout: Duration::from_secs(5),
            connect_timeout: Duration::from_secs(2),
            ..Self::default()
        }
    }

    fn check_ip(&self, ip: IpAddr) -> Result<(), GuardError> {
        if is_blocked_ip(ip) {
            if self.allow_private_addresses {
                tracing::warn!(
                    address = %ip,
                    "urlguard: gesperrte Adresse zugelassen — allow_private_addresses ist aktiv"
                );
                return Ok(());
            }
            return Err(GuardError::BlockedAddress(ip));
        }
        Ok(())
    }
}

/// Eine URL samt der **einen** Adresse, mit der verbunden werden darf.
///
/// Der Punkt dieses Typs ist, dass zwischen Prüfung und Verbindung keine
/// zweite Namensauflösung mehr stattfindet. Wer ein `VettedTarget` hat,
/// verbindet mit `addr` — nicht mit `url.host`.
///
/// Die Felder sind **privat**: ein `VettedTarget` entsteht ausschliesslich in
/// [`vet_url`], damit die Zusicherung „diese Adresse ist geprüft" im Typ steckt
/// und nicht in der Disziplin des nächsten Implementierers. Ein Transport
/// ausserhalb dieses Moduls kann sich also keins von Hand bauen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VettedTarget {
    url: ParsedUrl,
    addr: SocketAddr,
}

impl VettedTarget {
    /// Die geprüfte Adresse — die einzige, mit der verbunden werden darf.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Die URL des Ziels; liefert Host für `Host:`/SNI und Pfad, **nicht** die
    /// Adresse.
    pub fn url(&self) -> &ParsedUrl {
        &self.url
    }
}

/// Prüft Schema und Zieladresse und liefert die Adresse zurück, die verwendet
/// werden **muss**.
///
/// Aufgelöst wird genau einmal. Liefert der Resolver mehrere Adressen, müssen
/// **alle** zulässig sein — sonst könnte eine Gegenstelle einen erlaubten und
/// einen verbotenen Eintrag zurückgeben und darauf spekulieren, dass der Client
/// später den verbotenen nimmt.
pub async fn vet_url(
    input: &str,
    policy: &GuardPolicy,
    resolver: &dyn Resolver,
) -> Result<VettedTarget, GuardError> {
    let url = parse_url(input)?;

    // IP-Literal: nichts aufzulösen, direkt klassifizieren.
    if let Ok(ip) = url.host.parse::<IpAddr>() {
        policy.check_ip(ip)?;
        return Ok(VettedTarget {
            addr: SocketAddr::new(ip, url.port),
            url,
        });
    }

    let addrs = tokio::time::timeout(
        policy.connect_timeout,
        resolver.resolve(&url.host, url.port),
    )
    .await
    .map_err(|_| GuardError::DnsFailure(format!("{}: Zeitgrenze", url.host)))??;

    if addrs.is_empty() {
        return Err(GuardError::DnsFailure(format!(
            "{}: keine Adresse",
            url.host
        )));
    }
    for a in &addrs {
        policy.check_ip(a.ip())?;
    }
    // Die geprüfte Adresse wird festgehalten; ein späteres, abweichendes
    // DNS-Ergebnis (Rebinding) kann sie nicht mehr ersetzen.
    let addr = addrs[0];
    Ok(VettedTarget { url, addr })
}

// ---------------------------------------------------------------------------
// Gleichzeitige Downloads je Nutzer
// ---------------------------------------------------------------------------

/// Zählt laufende Downloads je Nutzer. Ohne Grenze genügt ein Nutzer mit
/// tausend langsamen URLs, um den Server zu belegen.
#[derive(Debug)]
pub struct DownloadSlots {
    limit: usize,
    running: Mutex<HashMap<String, usize>>,
}

impl DownloadSlots {
    pub fn new(limit: usize) -> Arc<Self> {
        Arc::new(Self {
            limit,
            running: Mutex::new(HashMap::new()),
        })
    }

    /// Belegt einen Platz. Der Platz wird frei, wenn der zurückgegebene Wert
    /// fallen gelassen wird — auch bei einem Abbruch mitten im Download.
    pub fn acquire(self: &Arc<Self>, user: &str) -> Result<DownloadSlot, GuardError> {
        let mut running = match self.running.lock() {
            Ok(g) => g,
            // Ein vergifteter Mutex darf keinen Request-Pfad zum Absturz
            // bringen; der Zähler ist danach zwar unsauber, aber die
            // Grenze wirkt weiter.
            Err(poisoned) => poisoned.into_inner(),
        };
        let entry = running.entry(user.to_string()).or_insert(0);
        if *entry >= self.limit {
            return Err(GuardError::TooManyConcurrent { limit: self.limit });
        }
        *entry += 1;
        Ok(DownloadSlot {
            slots: Arc::clone(self),
            user: user.to_string(),
        })
    }

    /// Aktuell belegte Plätze eines Nutzers (für Tests und Diagnose).
    pub fn in_use(&self, user: &str) -> usize {
        match self.running.lock() {
            Ok(g) => g.get(user).copied().unwrap_or(0),
            Err(p) => p.into_inner().get(user).copied().unwrap_or(0),
        }
    }
}

/// Belegter Platz. Gibt beim Fallenlassen frei.
#[derive(Debug)]
pub struct DownloadSlot {
    slots: Arc<DownloadSlots>,
    user: String,
}

impl Drop for DownloadSlot {
    fn drop(&mut self) {
        let mut running = match self.slots.running.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        if let Some(n) = running.get_mut(&self.user) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                running.remove(&self.user);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Transport
// ---------------------------------------------------------------------------

/// Eine einzelne Antwort — ein Sprung der Redirect-Kette.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HopResponse {
    pub status: u16,
    pub location: Option<String>,
    pub content_type: Option<String>,
    pub body: Vec<u8>,
}

/// Führt genau einen Abruf gegen eine **bereits geprüfte** Adresse aus.
///
/// Implementierungen dürfen unter keinen Umständen selbst auflösen — sonst ist
/// die Rebinding-Lücke wieder offen. Sie verbinden mit `target.addr`.
pub trait Transport: Send + Sync {
    fn perform<'a>(
        &'a self,
        target: &'a VettedTarget,
        policy: &'a GuardPolicy,
        deadline: Instant,
    ) -> BoxFuture<'a, Result<HopResponse, GuardError>>;
}

/// Minimaler HTTP/1.1-Client über TCP, **ohne TLS**.
///
/// Er existiert, damit die Grenzen dieses Moduls in Tests wirklich ausgeführt
/// werden, und als Referenz dafür, wie ein Transport `VettedTarget` zu
/// behandeln hat. Für den produktiven Downloader ist er zu schmal: er puffert
/// den Body im Speicher und spricht kein `https`.
pub struct TcpTransport;

/// Obergrenze für den Kopfteil einer Antwort. Ein Server, der mehr Header
/// schickt, ist entweder kaputt oder versucht, Speicher zu belegen.
const MAX_HEADER_BYTES: usize = 64 * 1024;

/// Obergrenze für eine einzelne Kopfzeile.
const MAX_HEADER_LINE: usize = 8 * 1024;

impl Transport for TcpTransport {
    fn perform<'a>(
        &'a self,
        target: &'a VettedTarget,
        policy: &'a GuardPolicy,
        deadline: Instant,
    ) -> BoxFuture<'a, Result<HopResponse, GuardError>> {
        Box::pin(async move {
            if target.url.is_tls() {
                return Err(GuardError::BadResponse(
                    "TcpTransport spricht kein https".into(),
                ));
            }
            let stream = connect_vetted(target, policy, deadline).await?;
            let request = format!(
                "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: rclone-gui\r\nAccept: */*\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n",
                target.url.path_and_query,
                target.url.host_header()
            );
            let mut reader = BufReader::new(stream);
            with_deadline(deadline, async {
                reader
                    .get_mut()
                    .write_all(request.as_bytes())
                    .await
                    .map_err(|e| GuardError::Io(e.to_string()))
            })
            .await??;

            read_response(&mut reader, policy, deadline).await
        })
    }
}

/// Verbindet mit der geprüften Adresse und prüft die *tatsächliche*
/// Gegenstelle noch einmal.
///
/// Die zweite Prüfung ist der Riegel gegen alles, was zwischen Prüfung und
/// Verbindung noch dazwischenkommen könnte — ein umgeleitetes Routing, ein
/// Fehler weiter oben, der doch wieder aufgelöst hat. Sie kostet nichts.
async fn connect_vetted(
    target: &VettedTarget,
    policy: &GuardPolicy,
    deadline: Instant,
) -> Result<TcpStream, GuardError> {
    policy.check_ip(target.addr.ip())?;
    let connect = TcpStream::connect(target.addr);
    let budget = remaining(deadline)?.min(policy.connect_timeout);
    let stream = tokio::time::timeout(budget, connect)
        .await
        .map_err(|_| GuardError::Timeout)?
        .map_err(|e| GuardError::Io(e.to_string()))?;

    let peer = stream
        .peer_addr()
        .map_err(|e| GuardError::Io(e.to_string()))?;
    policy.check_ip(peer.ip())?;
    Ok(stream)
}

fn remaining(deadline: Instant) -> Result<Duration, GuardError> {
    let now = Instant::now();
    if now >= deadline {
        return Err(GuardError::Timeout);
    }
    Ok(deadline - now)
}

async fn with_deadline<F, T>(deadline: Instant, fut: F) -> Result<T, GuardError>
where
    F: std::future::Future<Output = T>,
{
    tokio::time::timeout(remaining(deadline)?, fut)
        .await
        .map_err(|_| GuardError::Timeout)
}

/// Der Kopfteil einer Antwort, Körper noch ungelesen.
///
/// Getrennt vom Körper, weil der streamende Weg (siehe [`BodySource`]) genau
/// diese Trennung braucht: erst entscheiden, ob es eine Weiterleitung ist und
/// wie die Datei heissen soll, dann die Nutzdaten laufen lassen — ohne sie
/// vorher im Speicher zu haben.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HopHead {
    pub status: u16,
    pub location: Option<String>,
    pub content_type: Option<String>,
    /// Roher `Content-Disposition`-Wert. **Ungeprüfte Fremdeingabe** — wer
    /// daraus einen Dateinamen macht, säubert ihn (siehe
    /// `handlers::downloader::sanitize_filename`).
    pub content_disposition: Option<String>,
    pub content_length: Option<u64>,
    /// `Transfer-Encoding: chunked`. Privat, weil es reine Rahmung ist und den
    /// Aufrufer nichts angeht.
    chunked: bool,
}

impl HopHead {
    /// Eine Weiterleitung, der auch gefolgt werden kann.
    fn is_redirect(&self) -> bool {
        matches!(self.status, 301 | 302 | 303 | 307 | 308) && self.location.is_some()
    }
}

/// Liest Statuszeile und Kopfzeilen — der einzige Header-Parser dieses Moduls.
///
/// Beide Wege (gepuffert und streamend) hängen daran, damit eine Regel wie die
/// frühe Ablehnung einer zu grossen `Content-Length` nicht an einer von zwei
/// Stellen fehlt.
async fn read_head<R>(
    reader: &mut R,
    policy: &GuardPolicy,
    deadline: Instant,
) -> Result<HopHead, GuardError>
where
    R: AsyncBufRead + Unpin,
{
    let mut header_bytes = 0usize;
    let status_line = read_line_limited(reader, deadline, &mut header_bytes).await?;
    let status = parse_status_line(&status_line)?;

    let mut location = None;
    let mut content_type = None;
    let mut content_disposition = None;
    let mut content_length: Option<u64> = None;
    let mut chunked = false;

    loop {
        let line = read_line_limited(reader, deadline, &mut header_bytes).await?;
        let line = line.trim_end_matches(['\r', '\n']);
        if line.is_empty() {
            break;
        }
        let Some((name, value)) = line.split_once(':') else {
            return Err(GuardError::BadResponse("Kopfzeile ohne ':'".into()));
        };
        let name = name.trim().to_ascii_lowercase();
        let value = value.trim();
        match name.as_str() {
            "location" if location.is_none() => location = Some(value.to_string()),
            "content-type" if content_type.is_none() => content_type = Some(value.to_string()),
            "content-disposition" if content_disposition.is_none() => {
                content_disposition = Some(value.to_string())
            }
            "content-length" => {
                let n: u64 = value
                    .parse()
                    .map_err(|_| GuardError::BadResponse("Content-Length ungültig".into()))?;
                // Frühe Ablehnung: wer die Grösse selbst angibt, muss nicht
                // erst übertragen werden.
                if n > policy.max_bytes {
                    return Err(GuardError::TooLarge {
                        limit: policy.max_bytes,
                    });
                }
                content_length = Some(n);
            }
            "transfer-encoding" if value.to_ascii_lowercase().contains("chunked") => {
                chunked = true;
            }
            _ => {}
        }
    }

    Ok(HopHead {
        status,
        location,
        content_type,
        content_disposition,
        content_length,
        chunked,
    })
}

/// Kopfteil **und** Körper, vollständig im Speicher. Der gepufferte Weg für
/// [`TcpTransport`] und die Tests dieses Moduls.
async fn read_response<R>(
    reader: &mut R,
    policy: &GuardPolicy,
    deadline: Instant,
) -> Result<HopResponse, GuardError>
where
    R: AsyncBufRead + Unpin,
{
    let head = read_head(reader, policy, deadline).await?;

    // Bei einer Weiterleitung interessiert der Körper nicht — er wird gar
    // nicht erst gelesen.
    let body = if head.is_redirect() {
        Vec::new()
    } else if head.chunked {
        read_chunked(reader, policy, deadline).await?
    } else {
        read_fixed(reader, policy, deadline, head.content_length).await?
    };

    Ok(HopResponse {
        status: head.status,
        location: head.location,
        content_type: head.content_type,
        body,
    })
}

fn parse_status_line(line: &str) -> Result<u16, GuardError> {
    let mut parts = line.trim_end_matches(['\r', '\n']).split(' ');
    let version = parts
        .next()
        .ok_or_else(|| GuardError::BadResponse("leere Statuszeile".into()))?;
    if !version.starts_with("HTTP/") {
        return Err(GuardError::BadResponse("keine HTTP-Antwort".into()));
    }
    let code = parts
        .next()
        .ok_or_else(|| GuardError::BadResponse("Statuszeile ohne Code".into()))?;
    code.parse::<u16>()
        .map_err(|_| GuardError::BadResponse(format!("Statuscode '{code}' ungültig")))
}

/// Liest eine Zeile mit harter Längenbegrenzung.
///
/// `read_until` hätte keine Grenze — ein Server, der endlos Zeichen ohne `\n`
/// schickt, würde damit den Speicher füllen.
async fn read_line_limited<R>(
    reader: &mut R,
    deadline: Instant,
    header_bytes: &mut usize,
) -> Result<String, GuardError>
where
    R: AsyncBufRead + Unpin,
{
    let mut out: Vec<u8> = Vec::new();
    loop {
        let (chunk, newline_at) = {
            let available = with_deadline(deadline, reader.fill_buf())
                .await?
                .map_err(|e| GuardError::Io(e.to_string()))?;
            if available.is_empty() {
                if out.is_empty() {
                    return Err(GuardError::BadResponse("Verbindung vorzeitig zu".into()));
                }
                break;
            }
            match available.iter().position(|&b| b == b'\n') {
                Some(i) => (available[..=i].to_vec(), Some(i)),
                None => (available.to_vec(), None),
            }
        };
        reader.consume(chunk.len());
        *header_bytes += chunk.len();
        out.extend_from_slice(&chunk);
        if out.len() > MAX_HEADER_LINE || *header_bytes > MAX_HEADER_BYTES {
            return Err(GuardError::BadResponse("Kopfteil zu gross".into()));
        }
        if newline_at.is_some() {
            break;
        }
    }
    String::from_utf8(out).map_err(|_| GuardError::BadResponse("Kopfzeile nicht UTF-8".into()))
}

/// Liest bis `Content-Length` bzw. bis zum Verbindungsende, hart auf
/// `max_bytes` begrenzt.
async fn read_fixed<R>(
    reader: &mut R,
    policy: &GuardPolicy,
    deadline: Instant,
    content_length: Option<u64>,
) -> Result<Vec<u8>, GuardError>
where
    R: AsyncBufRead + Unpin,
{
    let cap = match content_length {
        Some(n) => n.min(policy.max_bytes),
        None => policy.max_bytes,
    };
    // Ist die Grenze `max_bytes` das Bindende — und nicht eine angekündigte,
    // kleinere `Content-Length` —, dann bedeutet „cap erreicht" noch nicht
    // „Antwort zu Ende". Eine angekündigte Länge über `max_bytes` wird schon
    // beim Kopfteil abgewiesen; die Bedingung bleibt trotzdem vollständig,
    // damit `read_fixed` auch für sich genommen richtig ist.
    let limit_is_binding = match content_length {
        Some(n) => n > policy.max_bytes,
        None => true,
    };
    let mut out = Vec::new();
    let mut buf = [0u8; 16 * 1024];
    loop {
        let n = with_deadline(deadline, reader.read(&mut buf))
            .await?
            .map_err(|e| GuardError::Io(e.to_string()))?;
        if n == 0 {
            break;
        }
        // Ein Byte über der Grenze genügt für das Urteil; es wird nicht
        // erst zu Ende gelesen.
        if out.len() as u64 + n as u64 > cap {
            if content_length.is_none() || cap == policy.max_bytes {
                return Err(GuardError::TooLarge {
                    limit: policy.max_bytes,
                });
            }
            out.extend_from_slice(&buf[..(cap as usize - out.len())]);
            break;
        }
        out.extend_from_slice(&buf[..n]);
        if out.len() as u64 >= cap {
            // Die Grenze ist genau getroffen. Steht sie für sich — also als
            // Obergrenze und nicht als angekündigte Länge —, ist damit noch
            // nicht gesagt, dass die Antwort zu Ende ist: ein einziges
            // weiteres Byte macht sie zu gross. Ohne diesen zweiten Read käme
            // bei einer Grenze auf einer Paketgrenze ein abgeschnittener
            // Körper als `Ok` zurück, und der Aufrufer könnte vollständig
            // nicht von abgeschnitten unterscheiden.
            if limit_is_binding {
                let extra = with_deadline(deadline, reader.read(&mut buf))
                    .await?
                    .map_err(|e| GuardError::Io(e.to_string()))?;
                if extra > 0 {
                    return Err(GuardError::TooLarge {
                        limit: policy.max_bytes,
                    });
                }
            }
            break;
        }
    }
    Ok(out)
}

/// Entpackt `Transfer-Encoding: chunked`, ebenfalls auf `max_bytes` begrenzt.
async fn read_chunked<R>(
    reader: &mut R,
    policy: &GuardPolicy,
    deadline: Instant,
) -> Result<Vec<u8>, GuardError>
where
    R: AsyncBufRead + Unpin,
{
    let mut out: Vec<u8> = Vec::new();
    loop {
        // Die Zählung des Kopfteils wird je Chunk zurückgesetzt — begrenzt wird
        // hier die einzelne Grössenzeile, nicht die Zahl der Chunks.
        let mut header_bytes = 0usize;
        let line = read_line_limited(reader, deadline, &mut header_bytes).await?;
        let size_field = line.trim_end_matches(['\r', '\n']);
        // Chunk-Extensions hinter `;` werden verworfen.
        let size_hex = size_field.split(';').next().unwrap_or("").trim();
        let size = u64::from_str_radix(size_hex, 16)
            .map_err(|_| GuardError::BadResponse("Chunk-Grösse ungültig".into()))?;
        if size == 0 {
            // Trailer bis zur Leerzeile schlucken.
            loop {
                let mut hb = 0usize;
                let t = read_line_limited(reader, deadline, &mut hb).await?;
                if t.trim_end_matches(['\r', '\n']).is_empty() {
                    break;
                }
            }
            break;
        }
        if out.len() as u64 + size > policy.max_bytes {
            return Err(GuardError::TooLarge {
                limit: policy.max_bytes,
            });
        }
        let mut chunk = vec![0u8; size as usize];
        with_deadline(deadline, reader.read_exact(&mut chunk))
            .await?
            .map_err(|e| GuardError::Io(e.to_string()))?;
        out.append(&mut chunk);
        // Das CRLF hinter den Nutzdaten.
        let mut hb = 0usize;
        read_line_limited(reader, deadline, &mut hb).await?;
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Abruf mit Redirect-Kette
// ---------------------------------------------------------------------------

/// Ergebnis eines vollständigen Abrufs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuardedFetch {
    /// Die URL, von der der Körper stammt — nach allen Weiterleitungen.
    pub final_url: ParsedUrl,
    /// Die Adresse, mit der zuletzt tatsächlich verbunden wurde.
    pub final_addr: SocketAddr,
    pub status: u16,
    pub content_type: Option<String>,
    pub body: Vec<u8>,
}

/// Holt eine URL unter voller Prüfung, Weiterleitungen eingeschlossen.
///
/// **Jeder** Sprung durchläuft [`vet_url`] erneut. Ein Ziel, das zunächst
/// öffentlich aussieht und dann auf `http://169.254.169.254/` weiterleitet,
/// scheitert am zweiten Durchlauf — nicht am ersten.
pub async fn fetch_guarded(
    url: &str,
    policy: &GuardPolicy,
    resolver: &dyn Resolver,
    transport: &dyn Transport,
) -> Result<GuardedFetch, GuardError> {
    let deadline = Instant::now() + policy.total_timeout;
    let mut current = url.to_string();

    for hop in 0..=policy.max_redirects {
        let target = vet_url(&current, policy, resolver).await?;
        let response = transport.perform(&target, policy, deadline).await?;

        let is_redirect = matches!(response.status, 301 | 302 | 303 | 307 | 308);
        match (is_redirect, response.location.as_deref()) {
            (true, Some(location)) => {
                if hop == policy.max_redirects {
                    return Err(GuardError::TooManyRedirects(policy.max_redirects));
                }
                let next = resolve_location(&target.url, location)?;
                tracing::debug!(from = %target.url, to = %next, "urlguard: Weiterleitung");
                current = next;
            }
            _ => {
                return Ok(GuardedFetch {
                    final_url: target.url,
                    final_addr: target.addr,
                    status: response.status,
                    content_type: response.content_type,
                    body: response.body,
                });
            }
        }
    }

    Err(GuardError::TooManyRedirects(policy.max_redirects))
}

// ---------------------------------------------------------------------------
// Streamender Transport (der produktive Weg)
//
// Warum nicht einfach ein fertiger HTTP-Client?
//
// Weil jeder fertige Client zwei Dinge selbst tut, die er hier nicht tun darf:
// **auflösen** und **Weiterleitungen folgen**. Beides hängt den Schutz dieses
// Moduls aus — eine eigene Auflösung ersetzt die geprüfte Adresse durch eine
// ungeprüfte (Rebinding), und eine eigene Redirect-Verfolgung springt zu einem
// Ziel, das `vet_url` nie gesehen hat.
//
// Deshalb: TLS kommt aus `tokio-rustls`, HTTP/1.1 bleibt hier. `tokio-rustls`
// bekommt einen fertig verbundenen `TcpStream` und hat gar keine Möglichkeit,
// einen Namen aufzulösen; die Redirect-Schleife führt weiterhin
// [`fetch_guarded_stream`], und zwar mit demselben `vet_url` je Sprung wie der
// gepufferte Weg.
//
// Der Unterschied zu [`TcpTransport`] ist genau zweierlei: `https`, und der
// Körper wird **nicht** im Speicher gehalten. Ohne das zweite wäre `max_bytes`
// (512 MiB) eine Speichergrenze und keine Downloadgrenze.
// ---------------------------------------------------------------------------

/// Grösse eines gelesenen Stücks. 64 KiB ist die Grösse, die auch der
/// Datei-Download in `handlers::download` benutzt.
const STREAM_CHUNK: usize = 64 * 1024;

/// Der Körper einer Antwort, stückweise abrufbar.
///
/// Ein leeres Stück heisst „fertig". Die Grössengrenze wird hier ein zweites
/// Mal geprüft, nicht nur am `Content-Length`: eine gelogene oder fehlende
/// Längenangabe darf nicht mehr Bytes durchlassen als erlaubt.
pub trait BodySource: Send {
    fn next_chunk<'a>(
        &'a mut self,
        deadline: Instant,
    ) -> BoxFuture<'a, Result<Vec<u8>, GuardError>>;
}

/// Wie das Ende des Körpers erkannt wird.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Framing {
    /// `Content-Length`: so viele Bytes, dann fertig.
    Length(u64),
    /// `Transfer-Encoding: chunked`.
    Chunked,
    /// Weder noch — der Körper endet mit der Verbindung.
    Eof,
}

/// Streamender Leser über einer bereits gelesenen Kopfzeile.
struct BodyReader<R> {
    reader: R,
    framing: Framing,
    /// Rest des laufenden Chunks (nur `Chunked`).
    chunk_left: u64,
    /// Rest des Körpers (nur `Length`).
    body_left: u64,
    /// Bereits gelesene Nutzbytes — die Grenze gilt für die Summe.
    read_total: u64,
    max_bytes: u64,
    finished: bool,
}

impl<R> BodyReader<R>
where
    R: AsyncBufRead + Unpin + Send,
{
    fn new(reader: R, head: &HopHead, policy: &GuardPolicy) -> Self {
        let framing = if head.chunked {
            Framing::Chunked
        } else {
            match head.content_length {
                Some(n) => Framing::Length(n),
                None => Framing::Eof,
            }
        };
        Self {
            reader,
            framing,
            chunk_left: 0,
            body_left: match framing {
                Framing::Length(n) => n,
                _ => 0,
            },
            read_total: 0,
            max_bytes: policy.max_bytes,
            finished: false,
        }
    }

    /// Liest höchstens `want` Bytes und zählt sie gegen die Grenze.
    async fn read_up_to(&mut self, want: usize, deadline: Instant) -> Result<Vec<u8>, GuardError> {
        let mut buf = vec![0u8; want.min(STREAM_CHUNK)];
        let n = with_deadline(deadline, self.reader.read(&mut buf))
            .await?
            .map_err(|e| GuardError::Io(e.to_string()))?;
        buf.truncate(n);
        self.read_total = self.read_total.saturating_add(n as u64);
        if self.read_total > self.max_bytes {
            return Err(GuardError::TooLarge {
                limit: self.max_bytes,
            });
        }
        Ok(buf)
    }

    async fn next(&mut self, deadline: Instant) -> Result<Vec<u8>, GuardError> {
        if self.finished {
            return Ok(Vec::new());
        }
        match self.framing {
            Framing::Length(_) => {
                if self.body_left == 0 {
                    self.finished = true;
                    return Ok(Vec::new());
                }
                let want = self.body_left.min(STREAM_CHUNK as u64) as usize;
                let chunk = self.read_up_to(want, deadline).await?;
                if chunk.is_empty() {
                    // Angekündigte Länge nicht erreicht: die Datei wäre
                    // abgeschnitten. Das ist ein Fehler, kein Ende.
                    return Err(GuardError::Io(
                        "Verbindung vor dem angekündigten Ende des Körpers geschlossen".into(),
                    ));
                }
                self.body_left -= chunk.len() as u64;
                if self.body_left == 0 {
                    self.finished = true;
                }
                Ok(chunk)
            }
            Framing::Eof => {
                let chunk = self.read_up_to(STREAM_CHUNK, deadline).await?;
                if chunk.is_empty() {
                    self.finished = true;
                }
                Ok(chunk)
            }
            Framing::Chunked => {
                if self.chunk_left == 0 {
                    let mut header_bytes = 0usize;
                    let line =
                        read_line_limited(&mut self.reader, deadline, &mut header_bytes).await?;
                    let size_field = line.trim_end_matches(['\r', '\n']);
                    let size_hex = size_field.split(';').next().unwrap_or("").trim();
                    let size = u64::from_str_radix(size_hex, 16)
                        .map_err(|_| GuardError::BadResponse("Chunk-Grösse ungültig".into()))?;
                    if size == 0 {
                        // Trailer bis zur Leerzeile schlucken.
                        loop {
                            let mut hb = 0usize;
                            let t = read_line_limited(&mut self.reader, deadline, &mut hb).await?;
                            if t.trim_end_matches(['\r', '\n']).is_empty() {
                                break;
                            }
                        }
                        self.finished = true;
                        return Ok(Vec::new());
                    }
                    // Die angekündigte Chunk-Grösse zählt sofort gegen die
                    // Grenze — ein Chunk-Header mit 4 GiB wird abgewiesen,
                    // bevor ein Byte davon gelesen wird.
                    if self.read_total.saturating_add(size) > self.max_bytes {
                        return Err(GuardError::TooLarge {
                            limit: self.max_bytes,
                        });
                    }
                    self.chunk_left = size;
                }
                let want = self.chunk_left.min(STREAM_CHUNK as u64) as usize;
                let chunk = self.read_up_to(want, deadline).await?;
                if chunk.is_empty() {
                    return Err(GuardError::Io("Verbindung mitten im Chunk zu".into()));
                }
                self.chunk_left -= chunk.len() as u64;
                if self.chunk_left == 0 {
                    // Das CRLF hinter den Nutzdaten.
                    let mut hb = 0usize;
                    read_line_limited(&mut self.reader, deadline, &mut hb).await?;
                }
                Ok(chunk)
            }
        }
    }
}

impl<R> BodySource for BodyReader<R>
where
    R: AsyncBufRead + Unpin + Send,
{
    fn next_chunk<'a>(
        &'a mut self,
        deadline: Instant,
    ) -> BoxFuture<'a, Result<Vec<u8>, GuardError>> {
        Box::pin(self.next(deadline))
    }
}

/// Führt einen Sprung aus und lässt den Körper **offen**.
///
/// Was [`StreamingTransport::open`] liefert: Kopfteil und offener Körper.
pub type OpenedHop<'a> = BoxFuture<'a, Result<(HopHead, Box<dyn BodySource>), GuardError>>;

/// Wie [`Transport`], nur ohne den Körper im Speicher. Dieselbe Auflage: die
/// Implementierung löst nicht auf, sie verbindet mit `target.addr()`.
pub trait StreamingTransport: Send + Sync {
    fn open<'a>(
        &'a self,
        target: &'a VettedTarget,
        policy: &'a GuardPolicy,
        deadline: Instant,
    ) -> OpenedHop<'a>;
}

/// Ein Strom, über den gelesen und geschrieben wird — `TcpStream` oder
/// `TlsStream`. Der Hilfstrait existiert nur, weil ein Trait-Objekt nicht zwei
/// Traits auf einmal nennen kann.
trait Duplex: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send> Duplex for T {}

/// HTTP/1.1 über TCP **oder** TLS, streamend. Der produktive Transport.
pub struct StreamingHttpTransport;

/// Die rustls-Konfiguration wird einmal gebaut und geteilt — das Einlesen der
/// Wurzelzertifikate je Abruf wäre reine Verschwendung.
static TLS_CONFIG: std::sync::OnceLock<Arc<tokio_rustls::rustls::ClientConfig>> =
    std::sync::OnceLock::new();

/// Wurzelzertifikate aus `webpki-roots`, Anbieter **ausdrücklich** `ring`.
///
/// `ClientConfig::builder()` würde den prozessweiten Standardanbieter nehmen.
/// Der ist nicht gesetzt, wenn mehr als einer einkompiliert ist — dann
/// paniert der Aufbau. `builder_with_provider` hängt an nichts Globalem.
fn tls_config() -> Result<Arc<tokio_rustls::rustls::ClientConfig>, GuardError> {
    if let Some(cfg) = TLS_CONFIG.get() {
        return Ok(Arc::clone(cfg));
    }
    let mut roots = tokio_rustls::rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let provider = Arc::new(tokio_rustls::rustls::crypto::ring::default_provider());
    let config = tokio_rustls::rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| GuardError::Io(format!("TLS-Konfiguration: {e}")))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    let config = Arc::new(config);
    // `set` kann verlieren, wenn zwei Abrufe gleichzeitig starten; dann gilt
    // die fremde Konfiguration, die identisch ist.
    let _ = TLS_CONFIG.set(Arc::clone(&config));
    Ok(TLS_CONFIG.get().map(Arc::clone).unwrap_or(config))
}

impl StreamingTransport for StreamingHttpTransport {
    fn open<'a>(
        &'a self,
        target: &'a VettedTarget,
        policy: &'a GuardPolicy,
        deadline: Instant,
    ) -> OpenedHop<'a> {
        Box::pin(async move {
            // Die Adresse kommt aus dem `VettedTarget` — hier wird nichts
            // aufgelöst. `connect_vetted` prüft zusätzlich die tatsächliche
            // Gegenstelle nach dem Verbindungsaufbau.
            let tcp = connect_vetted(target, policy, deadline).await?;

            let stream: Box<dyn Duplex> = if target.url().is_tls() {
                let config = tls_config()?;
                // SNI und Zertifikatsprüfung gegen den **Namen** aus der URL,
                // verbunden wird mit der geprüften Adresse. Genau diese
                // Trennung ist der Punkt.
                let server_name = tokio_rustls::rustls::pki_types::ServerName::try_from(
                    target.url().host.clone(),
                )
                .map_err(|_| {
                    GuardError::MalformedUrl(format!(
                        "'{}' ist kein gültiger TLS-Servername",
                        target.url().host
                    ))
                })?;
                let connector = tokio_rustls::TlsConnector::from(config);
                let tls = with_deadline(deadline, connector.connect(server_name, tcp))
                    .await?
                    .map_err(|e| GuardError::Io(format!("TLS-Handshake: {e}")))?;
                Box::new(tls)
            } else {
                Box::new(tcp)
            };

            let request = format!(
                "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: rclone-gui\r\nAccept: */*\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n",
                target.url().path_and_query,
                target.url().host_header()
            );
            let mut reader = BufReader::new(stream);
            with_deadline(deadline, async {
                reader
                    .get_mut()
                    .write_all(request.as_bytes())
                    .await
                    .map_err(|e| GuardError::Io(e.to_string()))
            })
            .await??;

            let head = read_head(&mut reader, policy, deadline).await?;
            let body = BodyReader::new(reader, &head, policy);
            Ok((head, Box::new(body) as Box<dyn BodySource>))
        })
    }
}

/// Ergebnis eines streamenden Abrufs: alles ausser den Nutzdaten.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamedResponse {
    /// Die URL, von der der Körper stammt — nach allen Weiterleitungen.
    pub final_url: ParsedUrl,
    /// Die Adresse, mit der zuletzt tatsächlich verbunden wurde.
    pub final_addr: SocketAddr,
    pub head: HopHead,
}

/// Wie [`fetch_guarded`], nur dass der Körper offen zurückgegeben wird.
///
/// Die Redirect-Schleife bleibt **hier**: jeder Sprung geht durch [`vet_url`],
/// der Körper eines Zwischensprungs wird nicht gelesen, sondern fallen
/// gelassen (womit die Verbindung zugeht).
pub async fn fetch_guarded_stream(
    url: &str,
    policy: &GuardPolicy,
    resolver: &dyn Resolver,
    transport: &dyn StreamingTransport,
) -> Result<(StreamedResponse, Box<dyn BodySource>), GuardError> {
    let deadline = Instant::now() + policy.total_timeout;
    let mut current = url.to_string();

    for hop in 0..=policy.max_redirects {
        let target = vet_url(&current, policy, resolver).await?;
        let (head, body) = transport.open(&target, policy, deadline).await?;

        match (head.is_redirect(), head.location.as_deref()) {
            (true, Some(location)) => {
                if hop == policy.max_redirects {
                    return Err(GuardError::TooManyRedirects(policy.max_redirects));
                }
                let next = resolve_location(target.url(), location)?;
                tracing::debug!(from = %target.url(), to = %next, "urlguard: Weiterleitung");
                // Körper des Zwischensprungs interessiert nicht.
                drop(body);
                current = next;
            }
            _ => {
                return Ok((
                    StreamedResponse {
                        final_url: target.url().clone(),
                        final_addr: target.addr(),
                        head,
                    },
                    body,
                ));
            }
        }
    }

    Err(GuardError::TooManyRedirects(policy.max_redirects))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::net::TcpListener;

    fn ip(s: &str) -> IpAddr {
        s.parse().expect("Testadresse")
    }

    // -- Adressbereiche v4 ------------------------------------------------

    #[test]
    fn blocks_v4_loopback_and_private() {
        for a in [
            "127.0.0.1",
            "127.255.255.254",
            "10.0.0.1",
            "10.255.255.255",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.0.1",
            "192.168.255.255",
        ] {
            assert!(is_blocked_ip(ip(a)), "{a} müsste gesperrt sein");
        }
    }

    #[test]
    fn blocks_v4_link_local_including_metadata() {
        assert!(is_blocked_ip(ip("169.254.0.1")));
        assert!(is_blocked_ip(ip("169.254.169.254")), "Cloud-Metadaten");
        assert!(is_blocked_ip(ip("169.254.255.255")));
    }

    #[test]
    fn blocks_v4_unspecified_multicast_reserved() {
        assert!(is_blocked_ip(ip("0.0.0.0")));
        assert!(is_blocked_ip(ip("0.1.2.3")));
        assert!(is_blocked_ip(ip("224.0.0.1")));
        assert!(is_blocked_ip(ip("239.255.255.255")));
        assert!(is_blocked_ip(ip("240.0.0.1")));
        assert!(is_blocked_ip(ip("255.255.255.255")));
    }

    #[test]
    fn blocks_v4_special_purpose_ranges() {
        assert!(is_blocked_ip(ip("100.64.0.1")), "CGNAT");
        assert!(is_blocked_ip(ip("100.127.255.255")), "CGNAT");
        assert!(is_blocked_ip(ip("192.0.0.1")), "IETF-Zuweisungen");
        assert!(is_blocked_ip(ip("192.0.2.1")), "Doku");
        assert!(is_blocked_ip(ip("198.51.100.1")), "Doku");
        assert!(is_blocked_ip(ip("203.0.113.1")), "Doku");
        assert!(is_blocked_ip(ip("198.18.0.1")), "Benchmarking");
    }

    #[test]
    fn allows_public_v4() {
        for a in [
            "1.1.1.1",
            "8.8.8.8",
            "93.184.216.34",
            "172.32.0.1",
            "9.255.255.255",
            "100.63.255.255",
        ] {
            assert!(!is_blocked_ip(ip(a)), "{a} müsste erlaubt sein");
        }
    }

    // -- Adressbereiche v6 ------------------------------------------------

    #[test]
    fn blocks_v6_loopback_unspecified_multicast() {
        assert!(is_blocked_ip(ip("::1")));
        assert!(is_blocked_ip(ip("::")));
        assert!(is_blocked_ip(ip("ff02::1")));
        assert!(is_blocked_ip(ip("ff00::")));
    }

    #[test]
    fn blocks_v6_unique_local_and_link_local() {
        assert!(is_blocked_ip(ip("fc00::1")));
        assert!(is_blocked_ip(ip("fd00::1")));
        assert!(is_blocked_ip(ip("fdff:ffff:ffff:ffff::1")));
        assert!(is_blocked_ip(ip("fe80::1")));
        assert!(is_blocked_ip(ip("febf::1")));
    }

    #[test]
    fn blocks_v6_embedded_v4_transition_ranges() {
        assert!(is_blocked_ip(ip("2002::1")), "6to4");
        assert!(is_blocked_ip(ip("2001::1")), "Teredo");
        assert!(is_blocked_ip(ip("64:ff9b::1.2.3.4")), "NAT64");
        assert!(is_blocked_ip(ip("100::1")), "Discard");
        assert!(is_blocked_ip(ip("2001:db8::1")), "Doku");
    }

    /// Der Klassiker: die v4-Adresse in v6-Kleidung.
    #[test]
    fn blocks_ipv4_mapped_ipv6() {
        assert!(is_blocked_ip(ip("::ffff:127.0.0.1")));
        assert!(is_blocked_ip(ip("::ffff:169.254.169.254")));
        assert!(is_blocked_ip(ip("::ffff:10.0.0.1")));
        assert!(is_blocked_ip(ip("::ffff:192.168.1.1")));
        // dieselben Adressen in Hex-Schreibweise
        assert!(is_blocked_ip(ip("::ffff:7f00:1")));
        assert!(is_blocked_ip(ip("::ffff:a9fe:a9fe")));
        // IPv4-compatible (abgekündigt)
        assert!(is_blocked_ip(ip("::127.0.0.1")));
    }

    #[test]
    fn ipv4_mapped_public_stays_allowed() {
        assert!(!is_blocked_ip(ip("::ffff:8.8.8.8")));
    }

    #[test]
    fn allows_public_v6() {
        assert!(!is_blocked_ip(ip("2606:4700:4700::1111")));
        assert!(!is_blocked_ip(ip("2a00:1450:4001:800::200e")));
    }

    #[test]
    fn normalize_unwraps_mapped_addresses() {
        assert_eq!(normalize_ip(ip("::ffff:127.0.0.1")), ip("127.0.0.1"));
        assert_eq!(normalize_ip(ip("8.8.8.8")), ip("8.8.8.8"));
        assert_eq!(normalize_ip(ip("2606:4700::1")), ip("2606:4700::1"));
    }

    // -- Schemata ----------------------------------------------------------

    #[test]
    fn rejects_non_http_schemes() {
        for u in [
            "file:///etc/passwd",
            "file://localhost/etc/shadow",
            "ftp://example.com/x",
            "gopher://example.com:70/_x",
            "dict://example.com:2628/",
            "ldap://example.com/",
            "jar:http://example.com/a.jar!/",
        ] {
            let err = parse_url(u).expect_err("müsste abgelehnt werden");
            assert!(
                matches!(
                    err,
                    GuardError::UnsupportedScheme(_) | GuardError::MalformedUrl(_)
                ),
                "{u} → {err:?}"
            );
        }
        // Die drei aus den Akzeptanzkriterien explizit als Schema-Fehler:
        for u in ["file://x/y", "ftp://x/y", "gopher://x/y"] {
            assert!(matches!(
                parse_url(u),
                Err(GuardError::UnsupportedScheme(_))
            ));
        }
    }

    #[test]
    fn scheme_check_is_case_insensitive() {
        assert!(matches!(
            parse_url("FILE://x/y"),
            Err(GuardError::UnsupportedScheme(_))
        ));
        assert_eq!(parse_url("HTTP://example.com/").unwrap().scheme, "http");
    }

    // -- URL-Zerlegung -----------------------------------------------------

    #[test]
    fn parses_basic_urls() {
        let u = parse_url("http://example.com/a/b?c=d").unwrap();
        assert_eq!(u.host, "example.com");
        assert_eq!(u.port, 80);
        assert_eq!(u.path_and_query, "/a/b?c=d");

        let u = parse_url("https://example.com").unwrap();
        assert_eq!(u.port, 443);
        assert_eq!(u.path_and_query, "/");

        let u = parse_url("http://example.com:8080/x").unwrap();
        assert_eq!(u.port, 8080);
        assert_eq!(u.host_header(), "example.com:8080");
    }

    /// `http://harmlos@127.0.0.1/` — die Userinfo darf nicht als Host gelten.
    #[test]
    fn userinfo_does_not_become_the_host() {
        let u = parse_url("http://example.com@127.0.0.1/x").unwrap();
        assert_eq!(u.host, "127.0.0.1");
        let u = parse_url("http://a@b@169.254.169.254:80/x").unwrap();
        assert_eq!(u.host, "169.254.169.254");
    }

    #[test]
    fn fragment_does_not_become_the_host() {
        let u = parse_url("http://127.0.0.1/x#@example.com").unwrap();
        assert_eq!(u.host, "127.0.0.1");
        assert_eq!(u.path_and_query, "/x");
    }

    #[test]
    fn parses_ipv6_literals() {
        let u = parse_url("http://[::1]:8080/x").unwrap();
        assert_eq!(u.host, "::1");
        assert_eq!(u.port, 8080);
        assert_eq!(u.host_header(), "[::1]:8080");
        assert_eq!(
            parse_url("http://[::ffff:127.0.0.1]/").unwrap().host,
            "::ffff:127.0.0.1"
        );
    }

    #[test]
    fn rejects_malformed_urls() {
        for u in [
            "",
            "example.com/x",
            "http://",
            "http://example.com:0/",
            "http://example.com:notaport/",
            "http://exa mple.com/",
            "http://example.com/\r\nX-Injected: 1",
        ] {
            assert!(parse_url(u).is_err(), "{u:?} müsste abgelehnt werden");
        }
    }

    // -- vet_url -----------------------------------------------------------

    fn resolver_to(host: &str, addr: &str) -> StaticResolver {
        StaticResolver::new().with(host, &[ip(addr)])
    }

    #[tokio::test]
    async fn vet_rejects_hostname_pointing_at_loopback() {
        let r = resolver_to("evil.example.com", "127.0.0.1");
        let err = vet_url("http://evil.example.com/x", &GuardPolicy::default(), &r)
            .await
            .expect_err("müsste gesperrt sein");
        assert_eq!(err, GuardError::BlockedAddress(ip("127.0.0.1")));
    }

    #[tokio::test]
    async fn vet_rejects_hostname_pointing_at_metadata() {
        let r = resolver_to("meta.example.com", "169.254.169.254");
        assert_eq!(
            vet_url(
                "http://meta.example.com/latest/meta-data/",
                &GuardPolicy::default(),
                &r
            )
            .await,
            Err(GuardError::BlockedAddress(ip("169.254.169.254")))
        );
    }

    #[tokio::test]
    async fn vet_rejects_hostname_pointing_at_mapped_loopback() {
        let r = resolver_to("evil.example.com", "::ffff:127.0.0.1");
        assert!(matches!(
            vet_url("http://evil.example.com/", &GuardPolicy::default(), &r).await,
            Err(GuardError::BlockedAddress(_))
        ));
    }

    /// Ein erlaubter *und* ein verbotener Eintrag: die Runde ist verloren.
    #[tokio::test]
    async fn vet_rejects_when_any_resolved_address_is_blocked() {
        let r = StaticResolver::new().with("mixed.example.com", &[ip("8.8.8.8"), ip("127.0.0.1")]);
        assert_eq!(
            vet_url("http://mixed.example.com/", &GuardPolicy::default(), &r).await,
            Err(GuardError::BlockedAddress(ip("127.0.0.1")))
        );
    }

    #[tokio::test]
    async fn vet_accepts_public_host_and_pins_the_address() {
        let r = resolver_to("ok.example.com", "93.184.216.34");
        let t = vet_url("http://ok.example.com/f.bin", &GuardPolicy::default(), &r)
            .await
            .unwrap();
        assert_eq!(t.addr, SocketAddr::new(ip("93.184.216.34"), 80));
        assert_eq!(t.url.path_and_query, "/f.bin");
    }

    /// Rebinding: derselbe Name liefert beim zweiten Aufruf eine interne
    /// Adresse. Weil `VettedTarget` die *erste*, geprüfte Adresse festhält und
    /// der Transport nur diese verwendet, kann die zweite Antwort nichts mehr
    /// ausrichten.
    #[tokio::test]
    async fn vetted_address_is_pinned_against_rebinding() {
        struct Rebinding(AtomicUsize);
        impl Resolver for Rebinding {
            fn resolve<'a>(
                &'a self,
                _host: &'a str,
                port: u16,
            ) -> BoxFuture<'a, Result<Vec<SocketAddr>, GuardError>> {
                let n = self.0.fetch_add(1, Ordering::SeqCst);
                let addr = if n == 0 {
                    ip("93.184.216.34")
                } else {
                    ip("127.0.0.1")
                };
                Box::pin(async move { Ok(vec![SocketAddr::new(addr, port)]) })
            }
        }
        let r = Rebinding(AtomicUsize::new(0));
        let t = vet_url("http://rebind.example.com/", &GuardPolicy::default(), &r)
            .await
            .unwrap();
        assert_eq!(t.addr.ip(), ip("93.184.216.34"));
        // Ein zweiter Aufruf sähe die interne Adresse — und würde sie ablehnen.
        assert_eq!(
            vet_url("http://rebind.example.com/", &GuardPolicy::default(), &r).await,
            Err(GuardError::BlockedAddress(ip("127.0.0.1")))
        );
    }

    #[tokio::test]
    async fn vet_rejects_literal_internal_addresses() {
        let r = StaticResolver::new();
        for u in [
            "http://127.0.0.1/",
            "http://169.254.169.254/",
            "http://[::1]/",
            "http://[::ffff:127.0.0.1]/",
            "http://10.1.2.3/",
            "http://192.168.1.1:8080/",
        ] {
            assert!(
                matches!(
                    vet_url(u, &GuardPolicy::default(), &r).await,
                    Err(GuardError::BlockedAddress(_))
                ),
                "{u} müsste gesperrt sein"
            );
        }
    }

    // -- Location-Auflösung ------------------------------------------------

    #[test]
    fn resolves_relative_locations() {
        let base = parse_url("http://example.com/a/b?x=1").unwrap();
        assert_eq!(
            resolve_location(&base, "https://other.example/z").unwrap(),
            "https://other.example/z"
        );
        assert_eq!(
            resolve_location(&base, "//other.example/z").unwrap(),
            "http://other.example/z"
        );
        assert_eq!(
            resolve_location(&base, "/z").unwrap(),
            "http://example.com/z"
        );
        assert_eq!(
            resolve_location(&base, "c").unwrap(),
            "http://example.com/a/c"
        );
    }

    #[test]
    fn rejects_header_injection_in_location() {
        let base = parse_url("http://example.com/").unwrap();
        assert!(resolve_location(&base, "/x\r\nSet-Cookie: a=b").is_err());
        assert!(resolve_location(&base, "").is_err());
    }

    // -- Redirect-Kette über einen Mock-Transport --------------------------

    /// Liefert vorgegebene Antworten und merkt sich, welche Adressen wirklich
    /// angesprochen wurden.
    struct MockTransport {
        responses: Mutex<Vec<HopResponse>>,
        seen: Mutex<Vec<SocketAddr>>,
    }

    impl MockTransport {
        fn new(responses: Vec<HopResponse>) -> Self {
            Self {
                responses: Mutex::new(responses),
                seen: Mutex::new(Vec::new()),
            }
        }
    }

    impl Transport for MockTransport {
        fn perform<'a>(
            &'a self,
            target: &'a VettedTarget,
            _policy: &'a GuardPolicy,
            _deadline: Instant,
        ) -> BoxFuture<'a, Result<HopResponse, GuardError>> {
            self.seen.lock().unwrap().push(target.addr);
            let mut r = self.responses.lock().unwrap();
            let next = if r.is_empty() {
                Err(GuardError::BadResponse("keine Antwort mehr".into()))
            } else {
                Ok(r.remove(0))
            };
            Box::pin(async move { next })
        }
    }

    fn redirect(to: &str) -> HopResponse {
        HopResponse {
            status: 302,
            location: Some(to.to_string()),
            content_type: None,
            body: Vec::new(),
        }
    }

    fn ok_body(body: &str) -> HopResponse {
        HopResponse {
            status: 200,
            location: None,
            content_type: Some("text/plain".into()),
            body: body.as_bytes().to_vec(),
        }
    }

    fn public_resolver() -> StaticResolver {
        StaticResolver::new()
            .with("public.example.com", &[ip("93.184.216.34")])
            .with("second.example.com", &[ip("93.184.216.35")])
    }

    #[tokio::test]
    async fn redirect_to_loopback_is_rejected() {
        let t = MockTransport::new(vec![redirect("http://127.0.0.1/secret")]);
        let err = fetch_guarded(
            "http://public.example.com/start",
            &GuardPolicy::default(),
            &public_resolver(),
            &t,
        )
        .await
        .expect_err("müsste abgewiesen werden");
        assert_eq!(err, GuardError::BlockedAddress(ip("127.0.0.1")));
        // Der zweite Sprung wurde nie angesprochen.
        assert_eq!(t.seen.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn redirect_to_metadata_address_is_rejected() {
        let t = MockTransport::new(vec![redirect(
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        )]);
        assert_eq!(
            fetch_guarded(
                "http://public.example.com/start",
                &GuardPolicy::default(),
                &public_resolver(),
                &t
            )
            .await,
            Err(GuardError::BlockedAddress(ip("169.254.169.254")))
        );
    }

    /// Auch der zweite Sprung wird geprüft, nicht nur der erste.
    #[tokio::test]
    async fn later_hop_to_internal_address_is_rejected() {
        let t = MockTransport::new(vec![
            redirect("http://second.example.com/next"),
            redirect("http://[::1]/secret"),
        ]);
        assert!(matches!(
            fetch_guarded(
                "http://public.example.com/start",
                &GuardPolicy::default(),
                &public_resolver(),
                &t
            )
            .await,
            Err(GuardError::BlockedAddress(_))
        ));
        assert_eq!(t.seen.lock().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn redirect_to_file_scheme_is_rejected() {
        let t = MockTransport::new(vec![redirect("file:///etc/passwd")]);
        assert!(matches!(
            fetch_guarded(
                "http://public.example.com/start",
                &GuardPolicy::default(),
                &public_resolver(),
                &t
            )
            .await,
            Err(GuardError::UnsupportedScheme(_))
        ));
    }

    #[tokio::test]
    async fn redirect_chain_is_capped() {
        let policy = GuardPolicy {
            max_redirects: 2,
            ..GuardPolicy::default()
        };
        let t = MockTransport::new(vec![
            redirect("http://second.example.com/1"),
            redirect("http://public.example.com/2"),
            redirect("http://second.example.com/3"),
        ]);
        assert_eq!(
            fetch_guarded(
                "http://public.example.com/0",
                &policy,
                &public_resolver(),
                &t
            )
            .await,
            Err(GuardError::TooManyRedirects(2))
        );
    }

    #[tokio::test]
    async fn allowed_redirect_chain_completes() {
        let t = MockTransport::new(vec![
            redirect("http://second.example.com/next"),
            ok_body("inhalt"),
        ]);
        let got = fetch_guarded(
            "http://public.example.com/start",
            &GuardPolicy::default(),
            &public_resolver(),
            &t,
        )
        .await
        .unwrap();
        assert_eq!(got.status, 200);
        assert_eq!(got.body, b"inhalt");
        assert_eq!(got.final_url.host, "second.example.com");
        assert_eq!(got.final_addr.ip(), ip("93.184.216.35"));
    }

    // -- Grenzen gegen einen echten lokalen Server -------------------------
    //
    // `GuardPolicy::for_tests()` hebt die Adressprüfung auf, sonst wäre ein
    // Server auf 127.0.0.1 unerreichbar. Geprüft wird hier alles *ausser* der
    // Adressprüfung: Grössengrenze, Zeitgrenze, Redirects über echtes HTTP.

    /// Startet einen Wegwerf-Server, der je Verbindung `reply(n)` schickt.
    /// Gibt die Basis-URL zurück.
    async fn spawn_server<F>(reply: F) -> String
    where
        F: Fn(usize) -> Vec<u8> + Send + Sync + 'static,
    {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.expect("bind");
        let addr = listener.local_addr().expect("local_addr");
        tokio::spawn(async move {
            let mut n = 0usize;
            while let Ok((mut sock, _)) = listener.accept().await {
                let bytes = reply(n);
                n += 1;
                tokio::spawn(async move {
                    // Request lesen und verwerfen — uns interessiert nur die
                    // Antwort.
                    let mut buf = [0u8; 4096];
                    let _ = sock.read(&mut buf).await;
                    let _ = sock.write_all(&bytes).await;
                    let _ = sock.shutdown().await;
                });
            }
        });
        format!("http://127.0.0.1:{}", addr.port())
    }

    #[tokio::test]
    async fn tcp_transport_fetches_body() {
        let base = spawn_server(|_| {
            b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\r\nhallo"
                .to_vec()
        })
        .await;
        let got = fetch_guarded(
            &format!("{base}/x"),
            &GuardPolicy::for_tests(),
            &StaticResolver::new(),
            &TcpTransport,
        )
        .await
        .unwrap();
        assert_eq!(got.status, 200);
        assert_eq!(got.body, b"hallo");
        assert_eq!(got.content_type.as_deref(), Some("text/plain"));
    }

    #[tokio::test]
    async fn tcp_transport_decodes_chunked() {
        let base = spawn_server(|_| {
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhal\r\n\r\n2\r\nlo\r\n0\r\n\r\n"
                .to_vec()
        })
        .await;
        let got = fetch_guarded(
            &format!("{base}/x"),
            &GuardPolicy::for_tests(),
            &StaticResolver::new(),
            &TcpTransport,
        )
        .await
        .unwrap();
        assert_eq!(got.body, b"hal\r\nlo");
    }

    /// Grössengrenze, Fall 1: der Server sagt selbst, wie gross es wird.
    #[tokio::test]
    async fn size_limit_rejects_declared_content_length() {
        let base =
            spawn_server(|_| b"HTTP/1.1 200 OK\r\nContent-Length: 100000\r\n\r\n".to_vec()).await;
        let policy = GuardPolicy {
            max_bytes: 1024,
            ..GuardPolicy::for_tests()
        };
        assert_eq!(
            fetch_guarded(
                &format!("{base}/x"),
                &policy,
                &StaticResolver::new(),
                &TcpTransport
            )
            .await,
            Err(GuardError::TooLarge { limit: 1024 })
        );
    }

    /// Grössengrenze, Fall 2: kein `Content-Length`, der Server schiebt einfach
    /// Daten. Das ist der Fall, der eine Platte füllen würde.
    #[tokio::test]
    async fn size_limit_rejects_undeclared_flood() {
        let base = spawn_server(|_| {
            let mut v = b"HTTP/1.1 200 OK\r\n\r\n".to_vec();
            v.extend(std::iter::repeat_n(b'A', 200_000));
            v
        })
        .await;
        let policy = GuardPolicy {
            max_bytes: 1024,
            ..GuardPolicy::for_tests()
        };
        assert_eq!(
            fetch_guarded(
                &format!("{base}/x"),
                &policy,
                &StaticResolver::new(),
                &TcpTransport
            )
            .await,
            Err(GuardError::TooLarge { limit: 1024 })
        );
    }

    /// Ein Server, der seine Antwort **tröpfeln** lässt: erst `header`, dann
    /// `total` Bytes in Stücken von `piece` mit einer Pause dazwischen.
    ///
    /// Diese Stückelung ist der Punkt: kommt alles in einem einzigen Read an,
    /// überschiesst der erste Read die Grenze und der Fehler fällt sofort auf.
    /// Erst wenn die Grenze **genau** auf einer Stückgrenze liegt, endet das
    /// Lesen exakt auf `cap` — und dann muss aktiv nachgesehen werden, ob noch
    /// etwas kommt.
    async fn spawn_dripping_server(header: &'static str, total: usize, piece: usize) -> String {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.expect("bind");
        let addr = listener.local_addr().expect("local_addr");
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    let _ = sock.read(&mut buf).await;
                    if sock.write_all(header.as_bytes()).await.is_err() {
                        return;
                    }
                    let chunk = vec![b'A'; piece];
                    let mut sent = 0usize;
                    while sent < total {
                        let n = piece.min(total - sent);
                        // Bricht die Gegenseite ab, ist hier Schluss — sonst
                        // liefe der Test gegen die volle Gesamtmenge.
                        if sock.write_all(&chunk[..n]).await.is_err() {
                            return;
                        }
                        sent += n;
                        tokio::time::sleep(Duration::from_millis(5)).await;
                    }
                    let _ = sock.shutdown().await;
                });
            }
        });
        format!("http://127.0.0.1:{}", addr.port())
    }

    /// Grössengrenze, Fall 3: kein `Content-Length`, und die Grenze liegt
    /// **genau auf einer Paketgrenze**.
    ///
    /// Das ist der Fall, der einmal durchgerutscht ist: das Lesen endete exakt
    /// auf `max_bytes`, brach ab und meldete `Ok` mit stillschweigend
    /// abgeschnittenem Körper. Für einen Downloader heisst das: eine korrupte
    /// Datei, die sich als vollständig ausgibt.
    #[tokio::test]
    async fn size_limit_rejects_flood_landing_on_a_packet_boundary() {
        let base = spawn_dripping_server("HTTP/1.1 200 OK\r\n\r\n", 500 * 1024, 1024).await;
        let policy = GuardPolicy {
            max_bytes: 2048, // Vielfaches der Stückgrösse
            ..GuardPolicy::for_tests()
        };
        assert_eq!(
            fetch_guarded(
                &format!("{base}/x"),
                &policy,
                &StaticResolver::new(),
                &TcpTransport
            )
            .await,
            Err(GuardError::TooLarge { limit: 2048 })
        );
    }

    /// Die Gegenseite der Grenze: **genau** `max_bytes` Bytes und dann
    /// Verbindungsende sind vollständig und müssen `Ok` bleiben. Die Grenze
    /// selbst darf kein Fehlalarm werden.
    #[tokio::test]
    async fn body_exactly_at_the_limit_is_accepted() {
        let base = spawn_dripping_server("HTTP/1.1 200 OK\r\n\r\n", 2048, 1024).await;
        let policy = GuardPolicy {
            max_bytes: 2048,
            ..GuardPolicy::for_tests()
        };
        let got = fetch_guarded(
            &format!("{base}/x"),
            &policy,
            &StaticResolver::new(),
            &TcpTransport,
        )
        .await
        .expect("genau an der Grenze ist vollständig, kein Fehler");
        assert_eq!(got.status, 200);
        assert_eq!(got.body.len(), 2048);
    }

    /// Gelogene `Content-Length`: angekündigt sind 10 Bytes, geschickt wird
    /// bis zu 1 GiB. Die angekündigte Länge ist die Grenze — es wird auf 10
    /// Bytes abgeschnitten, der Rest gar nicht erst gepuffert, und es wird
    /// **nicht** auf mehr gewartet (kein Fehlalarm `TooLarge`).
    #[tokio::test]
    async fn lying_content_length_is_cut_at_the_declared_length() {
        let base = spawn_dripping_server(
            "HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n",
            1024 * 1024 * 1024,
            8 * 1024,
        )
        .await;
        let got = fetch_guarded(
            &format!("{base}/x"),
            &GuardPolicy::for_tests(),
            &StaticResolver::new(),
            &TcpTransport,
        )
        .await
        .expect("angekündigte Länge ist die Grenze");
        assert_eq!(got.body.len(), 10);
    }

    #[tokio::test]
    async fn size_limit_rejects_oversized_chunked() {
        let base = spawn_server(|_| {
            let mut v = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
            v.extend_from_slice(b"10000\r\n");
            v.extend(std::iter::repeat_n(b'A', 0x10000));
            v.extend_from_slice(b"\r\n0\r\n\r\n");
            v
        })
        .await;
        let policy = GuardPolicy {
            max_bytes: 1024,
            ..GuardPolicy::for_tests()
        };
        assert_eq!(
            fetch_guarded(
                &format!("{base}/x"),
                &policy,
                &StaticResolver::new(),
                &TcpTransport
            )
            .await,
            Err(GuardError::TooLarge { limit: 1024 })
        );
    }

    /// Zeitgrenze: der Server nimmt die Verbindung an und schweigt.
    #[tokio::test]
    async fn time_limit_aborts_a_stalling_server() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.expect("bind");
        let addr = listener.local_addr().expect("local_addr");
        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((sock, _)) = listener.accept().await {
                // Verbindung offen halten, nichts senden.
                held.push(sock);
            }
        });
        let policy = GuardPolicy {
            total_timeout: Duration::from_millis(250),
            ..GuardPolicy::for_tests()
        };
        let started = Instant::now();
        let err = fetch_guarded(
            &format!("http://127.0.0.1:{}/x", addr.port()),
            &policy,
            &StaticResolver::new(),
            &TcpTransport,
        )
        .await
        .expect_err("müsste in die Zeitgrenze laufen");
        assert_eq!(err, GuardError::Timeout);
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "Abbruch dauerte zu lange: {:?}",
            started.elapsed()
        );
    }

    /// Redirect über echtes HTTP: der lokale Server schickt beim ersten Aufruf
    /// eine Weiterleitung auf sich selbst, beim zweiten den Inhalt.
    #[tokio::test]
    async fn tcp_transport_follows_a_real_redirect() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.expect("bind");
        let addr = listener.local_addr().expect("local_addr");
        let port = addr.port();
        tokio::spawn(async move {
            let mut n = 0usize;
            while let Ok((mut sock, _)) = listener.accept().await {
                let bytes = if n == 0 {
                    format!("HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:{port}/ziel\r\nContent-Length: 0\r\n\r\n")
                        .into_bytes()
                } else {
                    b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nziel".to_vec()
                };
                n += 1;
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    let _ = sock.read(&mut buf).await;
                    let _ = sock.write_all(&bytes).await;
                    let _ = sock.shutdown().await;
                });
            }
        });
        let got = fetch_guarded(
            &format!("http://127.0.0.1:{port}/start"),
            &GuardPolicy::for_tests(),
            &StaticResolver::new(),
            &TcpTransport,
        )
        .await
        .unwrap();
        assert_eq!(got.body, b"ziel");
        assert_eq!(got.final_url.path_and_query, "/ziel");
    }

    /// Und derselbe Server, aber mit scharfem Regelwerk: die Adressprüfung
    /// greift, bevor überhaupt verbunden wird.
    #[tokio::test]
    async fn strict_policy_blocks_the_local_test_server() {
        let base =
            spawn_server(|_| b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nno".to_vec()).await;
        assert_eq!(
            fetch_guarded(
                &format!("{base}/x"),
                &GuardPolicy::default(),
                &StaticResolver::new(),
                &TcpTransport
            )
            .await,
            Err(GuardError::BlockedAddress(ip("127.0.0.1")))
        );
    }

    #[tokio::test]
    async fn tcp_transport_refuses_https() {
        let target = VettedTarget {
            url: parse_url("https://example.com/").unwrap(),
            addr: SocketAddr::new(ip("93.184.216.34"), 443),
        };
        let policy = GuardPolicy::default();
        assert!(matches!(
            TcpTransport
                .perform(&target, &policy, Instant::now() + Duration::from_secs(1))
                .await,
            Err(GuardError::BadResponse(_))
        ));
    }

    // -- Plätze je Nutzer --------------------------------------------------

    #[test]
    fn concurrency_limit_per_user() {
        let slots = DownloadSlots::new(2);
        let a1 = slots.acquire("anna").unwrap();
        let _a2 = slots.acquire("anna").unwrap();
        assert_eq!(
            slots.acquire("anna").unwrap_err(),
            GuardError::TooManyConcurrent { limit: 2 }
        );
        // Ein anderer Nutzer ist davon unberührt.
        let _b1 = slots.acquire("bert").unwrap();
        assert_eq!(slots.in_use("anna"), 2);
        assert_eq!(slots.in_use("bert"), 1);

        drop(a1);
        assert_eq!(slots.in_use("anna"), 1);
        let _a3 = slots.acquire("anna").unwrap();
        assert_eq!(slots.in_use("anna"), 2);
    }

    #[test]
    fn slots_are_released_at_end_of_scope() {
        let slots = DownloadSlots::new(1);
        {
            let _s = slots.acquire("anna").unwrap();
            assert_eq!(slots.in_use("anna"), 1);
        }
        assert_eq!(slots.in_use("anna"), 0);
        assert!(slots.acquire("anna").is_ok());
    }

    /// Der echte Unwind: ein Panic *im* Slot-Scope. Der Test hiess früher so,
    /// prüfte aber nur das Verlassen eines Blocks — das ist etwas anderes.
    #[test]
    fn slots_are_released_on_unwind() {
        let slots = DownloadSlots::new(1);
        let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _s = slots.acquire("anna").unwrap();
            assert_eq!(slots.in_use("anna"), 1);
            panic!("Abbruch mitten im Download");
        }));
        assert!(panicked.is_err());
        // Der Mutex ist durch den Panic nicht vergiftet stehengeblieben, und
        // der Platz ist frei.
        assert_eq!(slots.in_use("anna"), 0);
        assert!(slots.acquire("anna").is_ok());
    }

    // -- Redirect-Kette auf dem streamenden Weg ----------------------------
    //
    // Derselbe Nachweis wie für den gepufferten Weg, aber gegen
    // `fetch_guarded_stream`: der produktive Downloader benutzt
    // ausschliesslich diese Schleife, und ein Schutz, der nur im gepufferten
    // Weg geprüft ist, sagt über ihn nichts.

    /// Körper aus dem Speicher, in einem Stück.
    struct VecBody(Option<Vec<u8>>);

    impl BodySource for VecBody {
        fn next_chunk<'a>(
            &'a mut self,
            _deadline: Instant,
        ) -> BoxFuture<'a, Result<Vec<u8>, GuardError>> {
            let out = self.0.take().unwrap_or_default();
            Box::pin(async move { Ok(out) })
        }
    }

    /// Liefert vorgegebene Kopfteile und merkt sich die angesprochenen
    /// Adressen — das Gegenstück zu [`MockTransport`] für den Strom-Weg.
    struct MockStreamingTransport {
        heads: Mutex<Vec<HopHead>>,
        seen: Mutex<Vec<SocketAddr>>,
    }

    impl MockStreamingTransport {
        fn new(heads: Vec<HopHead>) -> Self {
            Self {
                heads: Mutex::new(heads),
                seen: Mutex::new(Vec::new()),
            }
        }
    }

    impl StreamingTransport for MockStreamingTransport {
        fn open<'a>(
            &'a self,
            target: &'a VettedTarget,
            _policy: &'a GuardPolicy,
            _deadline: Instant,
        ) -> OpenedHop<'a> {
            self.seen.lock().unwrap().push(target.addr);
            let mut heads = self.heads.lock().unwrap();
            let next = if heads.is_empty() {
                Err(GuardError::BadResponse("keine Antwort mehr".into()))
            } else {
                let head = heads.remove(0);
                Ok((
                    head,
                    Box::new(VecBody(Some(b"nutzdaten".to_vec()))) as Box<dyn BodySource>,
                ))
            };
            Box::pin(async move { next })
        }
    }

    fn stream_redirect(to: &str) -> HopHead {
        HopHead {
            status: 302,
            location: Some(to.to_string()),
            content_type: None,
            content_disposition: None,
            content_length: Some(0),
            chunked: false,
        }
    }

    fn stream_ok() -> HopHead {
        HopHead {
            status: 200,
            location: None,
            content_type: Some("application/octet-stream".into()),
            content_disposition: None,
            content_length: Some(9),
            chunked: false,
        }
    }

    #[tokio::test]
    async fn stream_redirect_to_metadata_address_is_rejected() {
        let t = MockStreamingTransport::new(vec![stream_redirect(
            "http://169.254.169.254/latest/meta-data/",
        )]);
        let err = fetch_guarded_stream(
            "http://public.example.com/start",
            &GuardPolicy::default(),
            &public_resolver(),
            &t,
        )
        .await
        .err()
        .expect("müsste abgewiesen werden");
        assert_eq!(err, GuardError::BlockedAddress(ip("169.254.169.254")));
        // Der zweite Sprung wurde nie verbunden.
        assert_eq!(t.seen.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn stream_later_hop_to_loopback_is_rejected() {
        let t = MockStreamingTransport::new(vec![
            stream_redirect("http://second.example.com/next"),
            stream_redirect("http://127.0.0.1/secret"),
        ]);
        let err = fetch_guarded_stream(
            "http://public.example.com/start",
            &GuardPolicy::default(),
            &public_resolver(),
            &t,
        )
        .await
        .err()
        .expect("müsste abgewiesen werden");
        assert_eq!(err, GuardError::BlockedAddress(ip("127.0.0.1")));
        assert_eq!(t.seen.lock().unwrap().len(), 2);
    }

    /// Gegenprobe: ohne Weiterleitung auf eine gesperrte Adresse geht derselbe
    /// Aufbau durch. Ohne das wären die beiden Tests darüber auch grün, wenn
    /// `fetch_guarded_stream` grundsätzlich nichts durchliesse.
    #[tokio::test]
    async fn stream_public_chain_succeeds() {
        let t = MockStreamingTransport::new(vec![
            stream_redirect("http://second.example.com/next"),
            stream_ok(),
        ]);
        let (response, mut body) = fetch_guarded_stream(
            "http://public.example.com/start",
            &GuardPolicy::default(),
            &public_resolver(),
            &t,
        )
        .await
        .expect("öffentliche Kette");
        assert_eq!(
            response.final_addr,
            SocketAddr::new(ip("93.184.216.35"), 80)
        );
        assert_eq!(response.head.content_length, Some(9));
        let chunk = body
            .next_chunk(Instant::now() + Duration::from_secs(1))
            .await
            .expect("Körper");
        assert_eq!(chunk, b"nutzdaten".to_vec());
    }

    #[tokio::test]
    async fn stream_redirect_chain_is_capped() {
        let policy = GuardPolicy {
            max_redirects: 2,
            ..GuardPolicy::default()
        };
        let heads = vec![
            stream_redirect("http://public.example.com/1"),
            stream_redirect("http://public.example.com/2"),
            stream_redirect("http://public.example.com/3"),
            stream_redirect("http://public.example.com/4"),
        ];
        let t = MockStreamingTransport::new(heads);
        assert_eq!(
            fetch_guarded_stream(
                "http://public.example.com/start",
                &policy,
                &public_resolver(),
                &t
            )
            .await
            .err(),
            Some(GuardError::TooManyRedirects(2))
        );
        // Drei Verbindungen: der Startabruf und zwei erlaubte Sprünge.
        assert_eq!(t.seen.lock().unwrap().len(), 3);
    }

    #[tokio::test]
    async fn stream_rejects_non_http_redirect() {
        let t = MockStreamingTransport::new(vec![stream_redirect("file:///etc/passwd")]);
        assert!(matches!(
            fetch_guarded_stream(
                "http://public.example.com/start",
                &GuardPolicy::default(),
                &public_resolver(),
                &t
            )
            .await
            .err(),
            Some(GuardError::UnsupportedScheme(_))
        ));
    }

    /// Rebinding gegen den **streamenden** Weg: der Transport bekommt die
    /// zuerst geprüfte Adresse, nicht die des zweiten DNS-Ergebnisses.
    #[tokio::test]
    async fn stream_transport_sees_only_the_vetted_address() {
        struct Rebinding(AtomicUsize);
        impl Resolver for Rebinding {
            fn resolve<'a>(
                &'a self,
                _host: &'a str,
                port: u16,
            ) -> BoxFuture<'a, Result<Vec<SocketAddr>, GuardError>> {
                let n = self.0.fetch_add(1, Ordering::SeqCst);
                let addr = if n == 0 {
                    ip("93.184.216.34")
                } else {
                    ip("127.0.0.1")
                };
                Box::pin(async move { Ok(vec![SocketAddr::new(addr, port)]) })
            }
        }
        let t = MockStreamingTransport::new(vec![stream_ok()]);
        let (response, _body) = fetch_guarded_stream(
            "http://rebind.example.com/f.bin",
            &GuardPolicy::default(),
            &Rebinding(AtomicUsize::new(0)),
            &t,
        )
        .await
        .expect("erster Abruf");
        assert_eq!(response.final_addr.ip(), ip("93.184.216.34"));
        assert_eq!(
            t.seen.lock().unwrap().as_slice(),
            &[SocketAddr::new(ip("93.184.216.34"), 80)]
        );
    }

    /// **Der Nachweis für Regel 1 am produktiven Transport.**
    ///
    /// Der Mock-Test darüber prüft nur, welche Adresse die Guard-Schleife dem
    /// Transport *übergibt* — nicht, dass `StreamingHttpTransport::open` sie
    /// auch benutzt. Ersetzt man dort `connect_vetted` durch ein eigenes
    /// `TcpStream::connect` auf `target.url().host`, bleibt er grün. Gemessen:
    /// die gesamte Suite bleibt grün. Ein Test, der nicht fehlschlagen kann.
    ///
    /// Hier ist der Unterschied beobachtbar. `t4probe.invalid` ist nach
    /// RFC 2606 garantiert **nicht auflösbar**; der `StaticResolver` bildet
    /// den Namen trotzdem auf den lokalen Testserver ab. Löst der Transport
    /// selbst auf, scheitert der Verbindungsaufbau — nimmt er die Adresse aus
    /// dem `VettedTarget`, gelingt der Abruf. Kein echtes Netzwerkziel nötig.
    #[tokio::test]
    async fn streaming_transport_connects_to_the_vetted_address_without_resolving() {
        let base =
            spawn_server(|_| b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhallo".to_vec()).await;
        let port: u16 = base
            .rsplit(':')
            .next()
            .and_then(|p| p.parse().ok())
            .expect("Port aus der Basis-URL");
        let resolver = StaticResolver::new().with("t4probe.invalid", &[ip("127.0.0.1")]);

        let (response, mut body) = fetch_guarded_stream(
            &format!("http://t4probe.invalid:{port}/f.bin"),
            &GuardPolicy::for_tests(),
            &resolver,
            &StreamingHttpTransport,
        )
        .await
        .expect("der Transport muss die geprüfte Adresse benutzen statt selbst aufzulösen");

        assert_eq!(response.final_addr, SocketAddr::new(ip("127.0.0.1"), port));
        // Der Name bleibt der Name — er geht in `Host:` und SNI, nicht in die
        // Verbindung. Genau diese Trennung ist der Schutz.
        assert_eq!(response.final_url.host, "t4probe.invalid");
        let chunk = body
            .next_chunk(Instant::now() + Duration::from_secs(5))
            .await
            .expect("Körper");
        assert_eq!(chunk, b"hallo".to_vec());
    }

    /// Der Körper wird gegen `max_bytes` gezählt, auch wenn die Gegenstelle
    /// keine Länge nennt (`Framing::Eof`).
    #[tokio::test]
    async fn stream_body_limit_applies_without_content_length() {
        let policy = GuardPolicy {
            max_bytes: 8,
            ..GuardPolicy::default()
        };
        let head = HopHead {
            status: 200,
            location: None,
            content_type: None,
            content_disposition: None,
            content_length: None,
            chunked: false,
        };
        // 32 Byte ohne Längenangabe: der Leser muss bei 8 abbrechen.
        let data = [b'x'; 32];
        let mut reader = BodyReader::new(BufReader::new(&data[..]), &head, &policy);
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut total = 0usize;
        let err = loop {
            match reader.next(deadline).await {
                Ok(chunk) if chunk.is_empty() => panic!("hätte scheitern müssen"),
                Ok(chunk) => total += chunk.len(),
                Err(e) => break e,
            }
        };
        assert_eq!(err, GuardError::TooLarge { limit: 8 });
        assert!(total <= 8, "{total} Byte durchgelassen");
    }
}
