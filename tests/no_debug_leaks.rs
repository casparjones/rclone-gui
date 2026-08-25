//! Strukturelle Absicherung gegen `derive(Debug)` auf Typen mit Geheimnissen.
//!
//! # Warum das hier steht
//!
//! Das Muster „`#[derive(Debug)]` auf einem Typ, in dem ein Geheimnis liegt" wurde
//! in diesem Projekt **achtmal** gefunden — Session-Cookie, Argon2-Hash,
//! Remote-Passwort, `secret_access_key`, PHC-String, lebendes Sitzungstoken,
//! Passwort-Reset-Token, Userinfo einer Nutzer-URL. Fünf Handsuchen haben die
//! letzten beiden Fälle übersehen; gefunden hat sie erst eine **maschinelle
//! Auflistung** aller `derive`-Stellen. Ein Log-Leak erzeugt keine Fehlermeldung,
//! es fällt also niemandem auf. Deshalb hängt die Absicherung nicht mehr an der
//! Aufmerksamkeit des nächsten Entwicklers, sondern an `cargo test`.
//!
//! # Was der Test tut
//!
//! Er liest die `.rs`-Dateien unter `src/` als Text, sammelt jeden Typ mit einem
//! abgeleiteten `Debug` und vergleicht dessen Feldnamen gegen eine Liste
//! verdächtiger Wortstämme. Die Menge der Treffer muss **exakt** [`ACKNOWLEDGED`]
//! entsprechen: ein neuer Treffer bricht den Test, ein verschwundener Treffer
//! ebenfalls. Letzteres ist Absicht — eine Ausnahmeliste, die nur wächst,
//! veraltet, und eine veraltete Ausnahmeliste ist die nächste Entwarnung, die
//! falsch war.
//!
//! # Was er *nicht* leistet
//!
//! Er kennt **nur Namen**. Ein Feld `payload: String`, das ein Token trägt, geht
//! durch. `set_cookie` hätte er gefangen (`cookie`), `url` auch (`url`) — aber das
//! ist Glück, nicht Systematik. Der Fehler wird erst *unmöglich*, wenn jedes
//! Geheimnis in einem redigierenden Newtype steckt (`SessionToken`, `ResetToken`,
//! `ShareToken`): dann ist ein `derive(Debug)` auf dem umgebenden Struct harmlos.
//! Dieser Test ist die Bremse, die Newtypes sind die Lösung. Siehe Folgeticket.
//!
//! Ebenso ungeprüft: `Display`, `Serialize`, `sqlx::FromRow` und Panic-Meldungen.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

// ---------------------------------------------------------------------------
// Konfiguration
// ---------------------------------------------------------------------------

/// Wortstämme, die in einem Feldnamen auf ein Geheimnis hindeuten.
/// Kleingeschrieben, als Teilzeichenkette gesucht (`_`/CamelCase egal).
const SUSPICIOUS: &[&str] = &[
    "auth",
    "bearer",
    "cookie",
    "credential",
    "hash",
    "key",
    "pass",
    "secret",
    "session",
    "signature",
    "token",
    "url",
    "uri",
];

/// Typen, die ihr `Debug` selbst redigieren und deshalb in einem abgeleiteten
/// `Debug` gefahrlos auftauchen dürfen. Wer hier etwas einträgt, muss belegen,
/// dass der Typ `Debug` **von Hand** implementiert und den Wert maskiert.
const REDACTING_TYPES: &[&str] = &[
    "SessionToken",
    "ResetToken",
    "ShareToken",
    "RedactedUrl",
    "RedactedFields",
];

/// Ein geprüfter Treffer: `datei::Typ::feld`.
struct Ack {
    /// Schlüssel in der Form `src/pfad.rs::Typ::feld`.
    key: &'static str,
    /// `true`: bekanntes, noch **offenes** Leck. Der Test verlangt zusätzlich,
    /// dass es weiterhin gefunden wird (siehe [`pending_cases_are_still_found`]).
    pending: bool,
    /// Warum das in Ordnung ist — oder welches Ticket es behebt.
    why: &'static str,
}

/// Jeder Treffer der Feldnamen-Suche, der von Hand angesehen wurde.
///
/// **Kein Eintrag ohne Begründung.** Wer hier etwas hinzufügt, hat das Feld
/// gelesen und weiß, dass es kein Geheimnis trägt — oder trägt es als `pending`
/// mit Ticket ein. Stand: alle 13 Treffer über 70 Typen mit abgeleitetem
/// `Debug` (Ticket `1e6aa483`).
const ACKNOWLEDGED: &[Ack] = &[
    Ack {
        key: "src/handlers/auth.rs::SessionConfig::cookie_name",
        pending: false,
        why: "Der *Name* des Cookies, nicht sein Wert. Ist ohnehin öffentlich, \
              er steht in jedem `Set-Cookie`.",
    },
    Ack {
        key: "src/handlers/auth_web.rs::CurrentUser::session",
        pending: false,
        why: "`database::Session` implementiert `Debug` von Hand und redigiert \
              `id` — den Token-Digest, also den serverseitigen Sitzungsschlüssel \
              (src/database.rs:85). Ebenso `database::User` (src/database.rs:48) \
              für den Passwort-Hash.",
    },
    Ack {
        key: "src/handlers/auth_web.rs::UserInfo::session_expires_at",
        pending: false,
        why: "Ein `DateTime<Utc>` — die Ablauffrist der Sitzung, nicht ihr \
              Schlüssel. Der Typ trägt bewusst weder Hash noch Token.",
    },
    Ack {
        key: "src/handlers/auth_web.rs::UserInfo::session_absolute_expires_at",
        pending: false,
        why: "Wie `session_expires_at`: eine Frist, kein Geheimnis.",
    },
    Ack {
        key: "src/handlers/downloader.rs::UrlFetchRequest::url",
        pending: true,
        why: "FALL 8 DER SERIE, OFFEN. Die Nutzer-URL kann Userinfo tragen \
              (`https://nutzer:geheim@host/...`); ein abgeleitetes `Debug` gibt \
              sie im Klartext aus. `downloader.rs` gehörte beim Bau dieser \
              Absicherung einem anderen Ticket — gemeldet, nicht behoben. Fix: \
              `Debug` von Hand mit `redact_userinfo` (downloader.rs:297), so wie \
              es `FetchFailure` schon macht (downloader.rs:716).",
    },
    Ack {
        key: "src/handlers/rsyncd.rs::DaemonConfig::secrets_file",
        pending: false,
        why: "Der *Pfad* zur Secrets-Datei (`PathBuf`), nicht ihr Inhalt. Das \
              Modul-Secret selbst liegt in `ModuleConfig`, das `Debug` von Hand \
              implementiert (Fall 2 der Serie).",
    },
    Ack {
        key: "src/handlers/rsyncd.rs::DaemonState::sessions",
        pending: false,
        why: "`HashMap<u32, rsyncd::Session>`; dieses `Session` (rsyncd.rs:1786) \
              hält nur Metadaten der Verbindung — Modul, Nutzer, Client-Adresse, \
              Port, Herkunft der Adresse. Kein Anmeldegeheimnis. Nicht zu \
              verwechseln mit `database::Session`.",
    },
    Ack {
        key: "src/handlers/auth_web.rs::Leaky::token",
        pending: false,
        why: "Absichtliche Positivkontrolle im Test \
              `debug_of_the_reset_query_redacts_the_token`: derselbe Token in \
              einem Typ mit abgeleitetem `Debug`, um zu belegen, dass die \
              dortige Prüfung ihn sehen *würde*. Dass dieser Scanner ihn \
              findet, ist der Beweis, dass er einen frisch angelegten Typ \
              fängt — er war vorher nicht in dieser Liste und hat den Wächter \
              rot gemacht.",
    },
    Ack {
        key: "src/handlers/rsyncd.rs::Leaky::secret",
        pending: false,
        why: "Absichtliche Positivkontrolle in einem Test: ein Typ, der sein \
              Geheimnis druckt, um zu belegen, dass die dortige Prüfung es \
              sehen *würde*. Der Wert ist ein im Test erzeugtes Secret, kein \
              Produktivgeheimnis. Dass dieser Scanner ihn findet, ist das \
              erwartete Verhalten.",
    },
    Ack {
        key: "src/handlers/urlguard.rs::ParsedUrl::host_in_url",
        pending: false,
        why: "`parse_url` verwirft die Userinfo, bevor ein `ParsedUrl` entsteht \
              (urlguard.rs:333-337, Test `userinfo_does_not_become_the_host`). \
              Ein `ParsedUrl` kann deshalb keine Zugangsdaten tragen; \
              `host_in_url` ist nur die Schreibweise des Hosts für die URL.",
    },
    Ack {
        key: "src/handlers/urlguard.rs::VettedTarget::url",
        pending: false,
        why: "Feldtyp `ParsedUrl` — siehe `ParsedUrl::host_in_url`: die \
              Userinfo ist beim Parsen bereits weg.",
    },
    Ack {
        key: "src/handlers/urlguard.rs::GuardedFetch::final_url",
        pending: false,
        why: "Feldtyp `ParsedUrl` — siehe `ParsedUrl::host_in_url`.",
    },
    Ack {
        key: "src/handlers/urlguard.rs::StreamedResponse::final_url",
        pending: false,
        why: "Feldtyp `ParsedUrl` — siehe `ParsedUrl::host_in_url`.",
    },
];

/// Was Weg B (Newtypes) bräuchte, damit dieser Scanner überflüssig wird.
///
/// Nur Dokumentation, von keinem Test gelesen — die Felder liegen in Dateien,
/// die beim Bau dieser Absicherung anderen Tickets gehörten.
///
/// | Feld | Datei | Newtype |
/// |---|---|---|
/// | `ResetPageQuery::token` | `auth_web.rs` | `ResetToken` (existiert) |
/// | `ResetForm::token`, `ResetForm::password` | `auth_web.rs` | `ResetToken`, `Secret` |
/// | `LoginForm::password`, `LoginRequest::password` | `auth_web.rs` | `Secret` |
/// | `UrlFetchRequest::url` | `downloader.rs` | `RedactedUrl` (fehlt) |
/// | `RcloneConfig::password`, `ConfigRequest::password` | `models.rs` | `Secret` |
/// | `ConfigRequest::additional_fields` | `models.rs` | `RedactedFields` (existiert, nur für `Debug`) |
/// | `User::password_hash` | `database.rs` | `PasswordHash` |
/// | `Session::id` | `database.rs` | `SessionKey` |
/// | `SessionRefresh::set_cookie` | `auth.rs` | `SetCookieValue` |
/// | `ModuleConfig::secret` | `rsyncd.rs` | `Secret` |
/// | `NewShare::token_hash` | `shares.rs` | `TokenHash` |
///
/// Ein `Secret(String)` ohne `Display`, ohne `Serialize` und mit redigierendem
/// `Debug` deckt die meisten davon ab; `RedactedUrl` maskiert nur die Userinfo
/// und lässt Schema/Host/Pfad stehen.
const _NEWTYPE_CANDIDATES: () = ();

// ---------------------------------------------------------------------------
// Der Scanner
// ---------------------------------------------------------------------------

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Finding {
    /// `src/pfad.rs::Typ::feld`
    key: String,
    /// Zeile der Felddeklaration, 1-basiert.
    line: usize,
    /// Der Wortstamm, der angesprungen ist.
    hit: String,
}

/// Ein Typ mit abgeleitetem `Debug` und den Feldern, die dazu gefunden wurden.
struct DerivedDebugType {
    name: String,
    /// `(feldname, typtext, zeile)`
    fields: Vec<(String, String, usize)>,
}

/// Findet in einem Quelltext alle Typen mit abgeleitetem `Debug`.
///
/// Bewusst textuell und nicht per `syn`: der Test darf keine Abhängigkeit
/// hinzufügen (`Cargo.toml` gehört anderen Tickets), und die Vorlage, die die
/// Fälle 7 und 8 gefunden hat, war ebenfalls eine Textsuche.
fn scan_source(src: &str) -> Vec<DerivedDebugType> {
    let lines: Vec<&str> = src.lines().collect();
    let mut out = Vec::new();
    let mut i = 0usize;

    while i < lines.len() {
        let trimmed = lines[i].trim_start();

        // Attributblock einsammeln — `#[derive(...)]` darf über mehrere Zeilen gehen.
        if trimmed.starts_with("#[") {
            let start = i;
            let mut attr = String::new();
            let mut depth = 0i32;
            loop {
                if i >= lines.len() {
                    break;
                }
                attr.push_str(lines[i]);
                attr.push(' ');
                depth += balance(lines[i]);
                if depth <= 0 {
                    break;
                }
                i += 1;
            }
            // Weitere Attribute derselben Deklaration mitnehmen.
            let mut j = i + 1;
            while j < lines.len() {
                let t = lines[j].trim_start();
                if t.starts_with("#[") {
                    let mut d = 0i32;
                    loop {
                        if j >= lines.len() {
                            break;
                        }
                        attr.push_str(lines[j]);
                        attr.push(' ');
                        d += balance(lines[j]);
                        if d <= 0 {
                            break;
                        }
                        j += 1;
                    }
                    j += 1;
                } else if t.starts_with("//") || t.is_empty() {
                    j += 1;
                } else {
                    break;
                }
            }

            if derives_debug(&attr) && j < lines.len() {
                if let Some(name) = type_name(lines[j]) {
                    let (fields, end) = collect_fields(&lines, j);
                    out.push(DerivedDebugType { name, fields });
                    i = end + 1;
                    continue;
                }
            }
            let _ = start;
        }
        i += 1;
    }
    out
}

/// Klammerbilanz einer Zeile über `[` und `]`.
fn balance(line: &str) -> i32 {
    line.chars().fold(0, |acc, c| match c {
        '[' => acc + 1,
        ']' => acc - 1,
        _ => acc,
    })
}

/// Steht in diesem Attributtext ein `derive(...)`, das `Debug` enthält?
fn derives_debug(attr: &str) -> bool {
    let mut rest = attr;
    while let Some(pos) = rest.find("derive") {
        let after = &rest[pos + "derive".len()..];
        if let Some(open) = after.find('(') {
            let inner = &after[open + 1..];
            let close = inner.find(')').unwrap_or(inner.len());
            let list = &inner[..close];
            if list.split(',').any(|t| t.trim() == "Debug") {
                return true;
            }
            rest = &inner[close.min(inner.len())..];
        } else {
            rest = after;
        }
    }
    false
}

/// Liest den Typnamen aus einer `struct`/`enum`-Zeile.
fn type_name(line: &str) -> Option<String> {
    let t = line.trim_start();
    for kw in ["pub struct ", "struct ", "pub enum ", "enum "] {
        if let Some(rest) = t.strip_prefix(kw) {
            let name: String = rest
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect();
            if !name.is_empty() {
                return Some(name);
            }
        }
        // `pub(crate) struct` und Freunde
        if let Some(p) = t.find(kw) {
            if t[..p].starts_with("pub(") {
                let rest = &t[p + kw.len()..];
                let name: String = rest
                    .chars()
                    .take_while(|c| c.is_alphanumeric() || *c == '_')
                    .collect();
                if !name.is_empty() {
                    return Some(name);
                }
            }
        }
    }
    None
}

/// Sammelt die Felder eines Typs ab der Deklarationszeile `decl`.
///
/// Deckt Structs (Tiefe 1) und Enums mit Struct-Varianten (Tiefe 2) ab.
/// Gibt die Felder und die Zeile der schließenden Klammer zurück.
fn collect_fields(lines: &[&str], decl: usize) -> (Vec<(String, String, usize)>, usize) {
    let mut fields = Vec::new();
    let mut depth = 0i32;
    let mut i = decl;

    while i < lines.len() {
        let line = lines[i];
        let before = depth;

        if before >= 1 {
            if let Some((name, ty)) = field_decl(line) {
                fields.push((name, ty, i + 1));
            }
        }

        for c in line.chars() {
            match c {
                '{' => depth += 1,
                '}' => depth -= 1,
                _ => {}
            }
        }

        // Tuple-Struct oder Unit-Struct: endet mit `;` auf Tiefe 0.
        if depth == 0 && i >= decl && line.trim_end().ends_with(';') && before == 0 {
            return (fields, i);
        }
        if depth == 0 && i > decl {
            return (fields, i);
        }
        if depth == 0 && i == decl && line.contains('{') && line.contains('}') {
            return (fields, i);
        }
        i += 1;
    }
    (fields, lines.len().saturating_sub(1))
}

/// Erkennt `[pub] name: Typ,` als Felddeklaration.
fn field_decl(line: &str) -> Option<(String, String)> {
    let t = line.trim();
    if t.starts_with("//") || t.starts_with("#[") || t.is_empty() {
        return None;
    }
    let t = t.strip_prefix("pub(crate) ").unwrap_or(t);
    let t = t.strip_prefix("pub ").unwrap_or(t);
    let colon = t.find(':')?;
    let name = t[..colon].trim();
    if name.is_empty()
        || !name
            .chars()
            .all(|c| c.is_alphanumeric() || c == '_' || c == 'r')
    {
        return None;
    }
    if !name.chars().next()?.is_alphabetic() && !name.starts_with('_') {
        return None;
    }
    // `::` ist ein Pfad, kein Feld.
    if t[colon..].starts_with("::") {
        return None;
    }
    let ty = t[colon + 1..]
        .trim()
        .trim_end_matches(',')
        .trim()
        .to_string();
    if ty.is_empty() {
        return None;
    }
    Some((name.to_string(), ty))
}

/// Springt einer der Wortstämme in diesem Feldnamen an?
fn suspicious_stem(name: &str) -> Option<&'static str> {
    let lower = name.to_ascii_lowercase();
    SUSPICIOUS.iter().copied().find(|s| lower.contains(s))
}

/// Trägt das Feld einen Typ, der sein `Debug` selbst redigiert?
fn is_redacting(ty: &str) -> bool {
    REDACTING_TYPES.iter().any(|t| ty.contains(t))
}

/// Sucht einen kompletten Quellbaum ab.
fn scan_tree(root: &Path) -> Vec<Finding> {
    let mut out = Vec::new();
    for path in rust_files(root) {
        let rel = path
            .strip_prefix(root.parent().unwrap_or(root))
            .unwrap_or(&path)
            .to_string_lossy()
            .replace('\\', "/");
        let src = fs::read_to_string(&path).expect("Quelldatei lesbar");
        for ty in scan_source(&src) {
            for (field, field_ty, line) in &ty.fields {
                if is_redacting(field_ty) {
                    continue;
                }
                if let Some(hit) = suspicious_stem(field) {
                    out.push(Finding {
                        key: format!("{rel}::{}::{}", ty.name, field),
                        line: *line,
                        hit: hit.to_string(),
                    });
                }
            }
        }
    }
    out.sort();
    out
}

/// Alle `.rs`-Dateien unter `root`, rekursiv.
fn rust_files(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let entries = match fs::read_dir(&dir) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            let p = entry.path();
            if p.is_dir() {
                stack.push(p);
            } else if p.extension().map(|e| e == "rs").unwrap_or(false) {
                out.push(p);
            }
        }
    }
    out.sort();
    out
}

/// `src/` — unabhängig vom Arbeitsverzeichnis.
fn src_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src")
}

// ---------------------------------------------------------------------------
// Der eigentliche Wächter
// ---------------------------------------------------------------------------

#[test]
fn no_new_derive_debug_over_secrets() {
    let findings = scan_tree(&src_dir());
    let found: BTreeSet<String> = findings.iter().map(|f| f.key.clone()).collect();
    let acked: BTreeSet<String> = ACKNOWLEDGED.iter().map(|a| a.key.to_string()).collect();

    let new: Vec<&Finding> = findings
        .iter()
        .filter(|f| !acked.contains(&f.key))
        .collect();
    let stale: Vec<&str> = ACKNOWLEDGED
        .iter()
        .map(|a| a.key)
        .filter(|k| !found.contains(*k))
        .collect();

    let mut msg = String::new();
    if !new.is_empty() {
        msg.push_str(
            "\nNEUE Felder mit verdaechtigem Namen in einem Typ mit abgeleitetem `Debug`.\n\
             Entweder `Debug` von Hand implementieren und den Wert REDIGIEREN (nicht\n\
             entfernen), das Geheimnis in einen Newtype stecken, oder — wenn es kein\n\
             Geheimnis ist — mit Begruendung in ACKNOWLEDGED in tests/no_debug_leaks.rs\n\
             eintragen:\n",
        );
        for f in &new {
            msg.push_str(&format!(
                "  {} (Zeile {}, Stamm \"{}\")\n",
                f.key, f.line, f.hit
            ));
        }
    }
    if !stale.is_empty() {
        msg.push_str(
            "\nVERALTETE ACKNOWLEDGED-Eintraege — der Treffer existiert nicht mehr.\n\
             Bitte aus tests/no_debug_leaks.rs entfernen, damit die Liste nicht verrottet:\n",
        );
        for k in &stale {
            msg.push_str(&format!("  {k}\n"));
        }
    }
    assert!(msg.is_empty(), "{msg}");
}

/// Die Liste darf nicht zur Wegwerfhalde werden: jeder Eintrag braucht eine
/// Begründung, und ein offener Fall braucht einen Hinweis auf den Fix.
#[test]
fn every_acknowledged_entry_carries_a_reason() {
    for ack in ACKNOWLEDGED {
        assert!(
            ack.why.trim().len() > 30,
            "{} steht ohne brauchbare Begruendung in ACKNOWLEDGED",
            ack.key
        );
        if ack.pending {
            assert!(
                ack.why.contains("OFFEN"),
                "{} ist als pending eingetragen, sagt aber nicht, dass es offen ist",
                ack.key
            );
        }
    }
    let mut keys: Vec<&str> = ACKNOWLEDGED.iter().map(|a| a.key).collect();
    keys.sort();
    let before = keys.len();
    keys.dedup();
    assert_eq!(before, keys.len(), "doppelte Schluessel in ACKNOWLEDGED");
}

/// Die bekannten, noch **offenen** Fälle müssen weiter gefunden werden.
///
/// Ohne diese Zusicherung könnte jemand die Wortstammliste beschneiden und der
/// Wächter bliebe grün, während er nichts mehr sieht.
#[test]
fn pending_cases_are_still_found() {
    let findings = scan_tree(&src_dir());
    let found: BTreeSet<String> = findings.into_iter().map(|f| f.key).collect();
    for ack in ACKNOWLEDGED.iter().filter(|a| a.pending) {
        assert!(
            found.contains(ack.key),
            "der offene Fall {} wird nicht mehr gefunden — ist der Scanner \
             stumpf geworden?",
            ack.key
        );
    }
    // Fall 8 der Serie, namentlich: er ist der Grund, dass dieser Test existiert.
    assert!(found.contains("src/handlers/downloader.rs::UrlFetchRequest::url"));
}

/// Die sechs behobenen Fälle haben ihr `Debug` von Hand — es darf nicht
/// zurück auf `derive` fallen. Das prüft nicht der Feldname, sondern der
/// Ableitungsstatus, und fängt damit auch, was die Wortstammliste nicht kennt
/// (`set_cookie` etwa).
#[test]
fn the_six_fixed_cases_still_have_hand_written_debug() {
    // (Datei, Typ)
    const FIXED: &[(&str, &str)] = &[
        ("src/handlers/auth.rs", "LoginOutcome"),
        ("src/handlers/auth.rs", "SessionRefresh"),
        ("src/handlers/rsyncd.rs", "ModuleConfig"),
        ("src/models.rs", "RcloneConfig"),
        ("src/models.rs", "ConfigRequest"),
        ("src/handlers/shares.rs", "NewShare"),
        // Fall 7, in diesem Ticket behoben.
        ("src/handlers/auth_web.rs", "ResetPageQuery"),
    ];
    let root = src_dir();
    for (rel, ty) in FIXED {
        let path = root.parent().unwrap().join(rel);
        let src = fs::read_to_string(&path).unwrap_or_else(|_| panic!("{rel} lesbar"));
        let derived: Vec<&str> = scan_source(&src)
            .iter()
            .filter(|t| t.name == *ty)
            .map(|_| *ty)
            .collect();
        assert!(
            derived.is_empty(),
            "{rel}::{ty} hat wieder ein abgeleitetes `Debug` — der Typ traegt \
             ein Geheimnis und braucht eine redigierende Implementierung von Hand"
        );
        assert!(
            src.contains(&format!("Debug for {ty}")),
            "{rel}::{ty} hat gar kein `Debug` mehr — wurde es beim Umbau \
             verloren, oder heisst der Typ inzwischen anders? Dann diesen \
             Eintrag mitpflegen."
        );
    }
}

// ---------------------------------------------------------------------------
// Positivkontrollen: der Wächter muss anspringen können
// ---------------------------------------------------------------------------
//
// Ein Test, der nicht fehlschlagen kann, ist schlimmer als keiner. Die
// folgenden Fälle sind synthetische Quelltexte — sie belegen, dass der Scanner
// die Formen erkennt, in denen die acht echten Fälle aufgetreten sind.

/// Der Regelfall: ein frisch angelegter Typ mit `derive(Debug)` und einem
/// Klartext-Geheimnis.
#[test]
fn control_a_fresh_type_with_a_plaintext_secret_is_caught() {
    let src = r#"
        /// Was der Client schickt.
        #[derive(Debug, Clone, Deserialize)]
        pub struct NewThing {
            pub name: String,
            /// Never logged.
            pub password: String,
        }
    "#;
    assert_eq!(fields_flagged(src), vec!["NewThing::password"]);
}

/// Genau die Form von Fall 7: ein `Option<String>`-Token hinter einem
/// Doc-Kommentar, der „never logged" behauptet.
#[test]
fn control_case_seven_shape_is_caught() {
    let src = r#"
        #[derive(Debug, Deserialize)]
        pub struct ResetPageQuery {
            /// The token from the link. Never logged.
            pub token: Option<String>,
        }
    "#;
    assert_eq!(fields_flagged(src), vec!["ResetPageQuery::token"]);
}

/// Fall 6: `set_cookie` in einer Enum-Variante. Der Name heisst nicht
/// „password" — gefangen wird er über den Stamm `cookie`.
#[test]
fn control_a_struct_variant_of_an_enum_is_caught() {
    let src = r#"
        #[derive(Debug)]
        pub enum SessionRefresh {
            Unchanged,
            Renewed {
                session: Session,
                set_cookie: Option<String>,
            },
            Expired,
        }
    "#;
    // Beide Felder springen an: `session` über den Stamm `session`,
    // `set_cookie` über `cookie`. Der Scanner unterscheidet nicht, welches
    // davon wirklich ein Geheimnis ist — das tut der Mensch in ACKNOWLEDGED.
    assert_eq!(
        fields_flagged(src),
        vec!["SessionRefresh::session", "SessionRefresh::set_cookie"]
    );
}

/// Ein `derive` über mehrere Zeilen, mit weiteren Attributen dazwischen —
/// so sieht es nach `rustfmt` bei langen Ableitungslisten aus.
#[test]
fn control_a_multiline_derive_with_other_attributes_is_caught() {
    let src = r#"
        #[derive(
            Debug,
            Clone,
            Serialize,
            Deserialize,
        )]
        #[serde(rename_all = "camelCase")]
        #[non_exhaustive]
        pub struct Wide {
            pub id: String,
            pub secret_access_key: String,
        }
    "#;
    assert_eq!(fields_flagged(src), vec!["Wide::secret_access_key"]);
}

/// `pub(crate)` und ein Typ mit Lebenszeit- und Generikparametern.
#[test]
fn control_visibility_and_generics_do_not_hide_a_field() {
    let src = r#"
        #[derive(Debug)]
        pub(crate) struct Holder<'a, T: Clone> {
            pub(crate) inner: &'a T,
            api_token: String,
        }
    "#;
    assert_eq!(fields_flagged(src), vec!["Holder::api_token"]);
}

/// Ein `Debug` von Hand ist **kein** Treffer — sonst wäre die Absicherung
/// nicht abschaltbar und jeder korrekte Fix bliebe rot.
#[test]
fn control_a_hand_written_debug_is_not_flagged() {
    let src = r#"
        #[derive(Clone, Deserialize)]
        pub struct Careful {
            pub token: String,
        }

        impl std::fmt::Debug for Careful {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.debug_struct("Careful")
                    .field("token", &"<redacted>")
                    .finish()
            }
        }
    "#;
    assert!(fields_flagged(src).is_empty());
}

/// Ein redigierender Newtype entschärft das umgebende `derive(Debug)` —
/// das ist der Weg, den das Folgeticket gehen soll.
#[test]
fn control_a_redacting_newtype_is_not_flagged() {
    let src = r#"
        #[derive(Debug)]
        pub struct Wrapper {
            pub token: ResetToken,
            pub other: Option<SessionToken>,
        }
    "#;
    assert!(fields_flagged(src).is_empty());

    // Gegenprobe zur Gegenprobe: als nackter `String` schlaegt es an.
    let plain = src.replace("ResetToken", "String");
    assert_eq!(fields_flagged(&plain), vec!["Wrapper::token"]);
}

/// Was der Wächter **nicht** kann, ausdrücklich festgehalten: ein Feld mit
/// harmlosem Namen, das ein Geheimnis trägt, geht durch. Steht als Test da,
/// damit die Lücke nicht in Vergessenheit gerät — sie ist der Grund für Weg B.
#[test]
fn known_gap_a_harmless_name_carrying_a_secret_slips_through() {
    let src = r#"
        #[derive(Debug)]
        pub struct Sneaky {
            /// Traegt das Sitzungstoken.
            pub payload: String,
        }
    "#;
    assert!(
        fields_flagged(src).is_empty(),
        "der Scanner kennt nur Namen; wenn das hier anspringt, ist er besser \
         geworden — dann diesen Test anpassen"
    );
}

/// Hilfsfunktion der Positivkontrollen: `Typ::feld` für jeden Treffer.
fn fields_flagged(src: &str) -> Vec<String> {
    let mut out = Vec::new();
    for ty in scan_source(src) {
        for (field, field_ty, _) in &ty.fields {
            if is_redacting(field_ty) {
                continue;
            }
            if suspicious_stem(field).is_some() {
                out.push(format!("{}::{}", ty.name, field));
            }
        }
    }
    out.sort();
    out
}

// ---------------------------------------------------------------------------
// Selbstprüfung des Parsers
// ---------------------------------------------------------------------------

/// Der Parser muss **jede** `derive(...Debug...)`-Stelle einem Typ zuordnen.
///
/// Ohne das wäre ein grüner Wächter nichts wert: ein Typ, dessen Deklaration
/// der Parser nicht versteht, wird stillschweigend nicht geprüft — und genau
/// diese Art stiller Lücke hat die Serie achtmal weiterlaufen lassen. Der
/// Zähler ist absichtlich viel einfacher als der Parser: divergieren beide,
/// ist es der Parser, der etwas übersieht.
#[test]
fn the_parser_reaches_every_derive_debug_site() {
    let mut total = 0usize;
    for path in rust_files(&src_dir()) {
        let src = fs::read_to_string(&path).expect("lesbar");
        let attrs = count_debug_derive_attrs(&src);
        let types = scan_source(&src).len();
        assert_eq!(
            attrs,
            types,
            "{}: {attrs} `derive(...Debug...)`-Stellen, aber nur {types} Typen \
             erkannt. Der Parser in dieser Datei uebersieht eine Deklaration \
             (ungewoehnliche Form? Makro?) — bis das geklaert ist, ist der \
             Waechter fuer diese Datei blind.",
            path.display()
        );
        total += types;
    }
    // Zum Zeitpunkt des Tickets waren es 70. Die untere Schranke ist nur ein
    // Rauchmelder dafuer, dass ueberhaupt gescannt wurde — z. B. wenn
    // `src_dir()` ins Leere zeigt.
    assert!(
        total >= 60,
        "nur {total} Typen mit abgeleitetem `Debug` gefunden — laeuft der Scan \
         ueberhaupt auf `src/`?"
    );
}

/// Zählt Attributblöcke mit einem `derive`, das `Debug` enthält.
/// Bewusst naiv gehalten (siehe [`the_parser_reaches_every_derive_debug_site`]).
fn count_debug_derive_attrs(src: &str) -> usize {
    let lines: Vec<&str> = src.lines().collect();
    let mut n = 0;
    let mut i = 0;
    while i < lines.len() {
        if lines[i].trim_start().starts_with("#[") {
            let mut buf = String::new();
            let mut depth = 0i32;
            while i < lines.len() {
                buf.push_str(lines[i]);
                buf.push(' ');
                depth += balance(lines[i]);
                if depth <= 0 {
                    break;
                }
                i += 1;
            }
            if derives_debug(&buf) {
                n += 1;
            }
        }
        i += 1;
    }
    n
}
