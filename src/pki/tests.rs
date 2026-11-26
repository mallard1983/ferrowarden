use super::*;

use std::collections::BTreeSet;
use std::io::Read as _;
use std::sync::Arc;

use rustls::pki_types::PrivateKeyDer;
use rustls::{ClientConfig, ClientConnection, RootCertStore, ServerConfig, ServerConnection};
use x509_parser::extensions::GeneralName;
use x509_parser::prelude::{FromDer, X509Certificate};

/// A fixed "now" for the clock-driven tests (2027-01-15).
fn base() -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(1_800_000_000)
}

fn days(n: u64) -> Duration {
    Duration::from_secs(n * 24 * 60 * 60)
}

/// When the openssl-made fixture was generated, plus an hour (2026-11-26 05:00 UTC).
fn fixture_now() -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(1_795_669_200)
}

struct Dirs {
    _root: tempfile::TempDir,
    pki: PathBuf,
    public: PathBuf,
}

fn dirs() -> Dirs {
    let root = tempfile::tempdir().unwrap();
    let pki = root.path().join("pki");
    let public = root.path().join("ca-public");
    Dirs {
        _root: root,
        pki,
        public,
    }
}

fn config(d: &Dirs, extra: &str) -> PkiConfig {
    let (pki, public, extra) = (d.pki.clone(), d.public.clone(), extra.to_string());
    PkiConfig::from_lookup(|key| match key {
        "PKI_DIR" => Some(pki.display().to_string()),
        "CA_PUBLIC_DIR" => Some(public.display().to_string()),
        "VW_EXTRA_SANS" => Some(extra.clone()),
        _ => None,
    })
    .unwrap()
}

/// Run and return what it logged.
fn run_logged(config: &PkiConfig, now: SystemTime) -> Result<String> {
    let mut log = Vec::new();
    run(config, now, &mut log)?;
    Ok(String::from_utf8(log).unwrap())
}

fn read(d: &Dirs, name: &str) -> Vec<u8> {
    fs::read(d.pki.join(name)).unwrap()
}

fn der_of(pem: &[u8]) -> CertificateDer<'static> {
    pem_to_der(pem, "test certificate").unwrap()
}

fn parse<'a>(der: &'a CertificateDer<'a>) -> X509Certificate<'a> {
    X509Certificate::from_der(der.as_ref()).unwrap().1
}

const LOCAL: &str = "localhost,127.0.0.1";

// ── SAN parsing and configuration ────────────────────────────────────────────

#[test]
fn san_entries_are_classified_like_the_script_did() {
    let sans =
        parse_extra_sans("localhost, 127.0.0.1 ,,::1, vault.lan,2001:db8::1,10.0.0.5,").unwrap();
    let got: Vec<(String, San)> = sans.iter().map(|s| (s.label(), s.san.clone())).collect();
    assert_eq!(
        got,
        vec![
            ("DNS:localhost".into(), San::Dns("localhost".into())),
            ("IP:127.0.0.1".into(), San::Ip("127.0.0.1".parse().unwrap())),
            ("IP:::1".into(), San::Ip("::1".parse().unwrap())),
            ("DNS:vault.lan".into(), San::Dns("vault.lan".into())),
            (
                "IP:2001:db8::1".into(),
                San::Ip("2001:db8::1".parse().unwrap())
            ),
            ("IP:10.0.0.5".into(), San::Ip("10.0.0.5".parse().unwrap())),
        ]
    );
    assert!(parse_extra_sans("").unwrap().is_empty());
    assert!(parse_extra_sans(" , ,").unwrap().is_empty());
    assert!(parse_extra_sans("*.vault.lan,a_b.lan,xn--bcher-kva.example").is_ok());
}

#[test]
fn invalid_san_entries_are_rejected_and_named() {
    for bad in [
        "300.1.1.1",
        "1.2.3",
        "1.2.3.4.5",
        "...",
        "::zz",
        "[::1]",
        "1:2:3",
        "-bad.example",
        "bad-.example",
        "bad..example",
        "bad host",
        "under@score",
        "ünïcode.example",
        "a/b",
        "http://vault.lan",
    ] {
        // Spaces are stripped before classification, so "bad host" becomes "badhost" and is
        // valid; every other entry must be refused with its own text in the message.
        let result = parse_extra_sans(bad);
        if bad == "bad host" {
            assert!(result.is_ok(), "{bad}");
            continue;
        }
        let err = result.expect_err(bad).to_string();
        assert!(err.contains(bad), "{bad}: {err}");
    }
    let long_label = format!("{}.example", "a".repeat(64));
    assert!(parse_extra_sans(&long_label).is_err());
    let long_name = vec!["a".repeat(60); 5].join(".");
    assert!(parse_extra_sans(&long_name).is_err());
    // One bad entry among good ones fails the whole list.
    assert!(parse_extra_sans("localhost,999.0.0.1").is_err());
}

#[test]
fn configuration_defaults_and_overrides() {
    let c = PkiConfig::from_lookup(|_| None).unwrap();
    assert_eq!(c.pki_dir, PathBuf::from("/pki"));
    assert_eq!(c.ca_public_dir, PathBuf::from("/ca-public"));
    assert_eq!(c.hostname, "vaultwarden");
    assert_eq!(c.san_string(), "DNS:vaultwarden");

    // An empty variable takes the default, like ${VAR:-default}.
    let c = PkiConfig::from_lookup(|_| Some(String::new())).unwrap();
    assert_eq!(c.pki_dir, PathBuf::from("/pki"));
    assert_eq!(c.san_string(), "DNS:vaultwarden");

    let c = PkiConfig::from_lookup(|k| match k {
        "VW_HOSTNAME" => Some("vault.internal".into()),
        "VW_EXTRA_SANS" => Some("localhost,127.0.0.1".into()),
        _ => None,
    })
    .unwrap();
    assert_eq!(c.hostname, "vault.internal");
    assert_eq!(
        c.san_string(),
        "DNS:vault.internal,DNS:localhost,IP:127.0.0.1"
    );

    let err = PkiConfig::from_lookup(|k| (k == "VW_HOSTNAME").then(|| "not a name!".to_string()))
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("VW_HOSTNAME") && err.contains("not a name!"),
        "{err}"
    );
}

#[test]
fn the_san_string_keeps_the_scripts_format() {
    let d = dirs();
    assert_eq!(
        config(&d, LOCAL).san_string(),
        "DNS:vaultwarden,DNS:localhost,IP:127.0.0.1"
    );
}

#[test]
fn an_invalid_entry_writes_nothing() {
    // The configuration is validated before `run` can be called, so the
    // directories are never touched.
    let d = dirs();
    let (pki, public) = (d.pki.clone(), d.public.clone());
    let err = PkiConfig::from_lookup(|k| match k {
        "PKI_DIR" => Some(pki.display().to_string()),
        "CA_PUBLIC_DIR" => Some(public.display().to_string()),
        "VW_EXTRA_SANS" => Some("localhost,999.1.1.1".into()),
        _ => None,
    })
    .unwrap_err();
    assert!(err.to_string().contains("999.1.1.1"));
    assert!(!d.pki.exists() && !d.public.exists());
}

// ── A fresh run ──────────────────────────────────────────────────────────────

#[test]
fn a_fresh_run_creates_every_file() {
    let d = dirs();
    let log = run_logged(&config(&d, LOCAL), base()).unwrap();
    assert!(log.contains("[certs] Creating internal CA"), "{log}");
    assert!(
        log.contains(
            "[certs] Issuing Vaultwarden certificate for DNS:vaultwarden,DNS:localhost,IP:127.0.0.1"
        ),
        "{log}"
    );
    assert!(log.trim_end().ends_with("[certs] Done"), "{log}");

    let names: BTreeSet<String> = fs::read_dir(&d.pki)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(
        names,
        [
            "ca.crt",
            "ca.key",
            "vaultwarden.crt",
            "vaultwarden.key",
            "vaultwarden.sans"
        ]
        .map(String::from)
        .into_iter()
        .collect(),
        "no temporary files are left behind"
    );
    assert_eq!(
        fs::read_to_string(d.pki.join("vaultwarden.sans")).unwrap(),
        "DNS:vaultwarden,DNS:localhost,IP:127.0.0.1"
    );
    for key in ["ca.key", "vaultwarden.key"] {
        let pem = String::from_utf8(read(&d, key)).unwrap();
        assert!(pem.starts_with("-----BEGIN PRIVATE KEY-----"), "{key}");
    }
}

#[cfg(unix)]
#[test]
fn modes_are_644_for_public_files_and_600_for_keys() {
    use std::os::unix::fs::PermissionsExt;
    let d = dirs();
    run_logged(&config(&d, LOCAL), base()).unwrap();
    let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
    for f in ["ca.crt", "vaultwarden.crt", "vaultwarden.sans"] {
        assert_eq!(mode(&d.pki.join(f)), 0o644, "{f}");
    }
    for f in ["ca.key", "vaultwarden.key"] {
        assert_eq!(mode(&d.pki.join(f)), 0o600, "{f}");
    }
    assert_eq!(mode(&d.public.join("ca.crt")), 0o644);
    assert_eq!(mode(&d.public), 0o755);
}

#[cfg(unix)]
#[test]
fn modes_are_restored_on_every_run() {
    use std::os::unix::fs::PermissionsExt;
    let d = dirs();
    let c = config(&d, LOCAL);
    run_logged(&c, base()).unwrap();
    fs::set_permissions(d.pki.join("ca.key"), fs::Permissions::from_mode(0o644)).unwrap();
    fs::set_permissions(
        d.pki.join("vaultwarden.crt"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    run_logged(&c, base()).unwrap();
    let mode = |f: &str| fs::metadata(d.pki.join(f)).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode("ca.key"), 0o600);
    assert_eq!(mode("vaultwarden.crt"), 0o644);
}

#[cfg(unix)]
#[test]
fn a_private_key_is_never_group_or_world_readable_while_being_written() {
    use std::os::unix::fs::PermissionsExt;
    // The temporary file is created with mode 0600: the mode check happens on
    // a handle opened the same way write_atomic opens it.
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("k.key");
    write_atomic(&target, b"secret", true).unwrap();
    assert_eq!(
        fs::metadata(&target).unwrap().permissions().mode() & 0o777,
        0o600
    );
    // With a permissive umask the file still ends up 0600 (and was created
    // that way: OpenOptions::mode is applied at creation).
    let loose = dir.path().join("loose.crt");
    write_atomic(&loose, b"public", false).unwrap();
    assert_eq!(
        fs::metadata(&loose).unwrap().permissions().mode() & 0o777,
        0o644
    );
}

#[test]
fn ca_public_holds_only_the_ca_certificate() {
    let d = dirs();
    run_logged(&config(&d, LOCAL), base()).unwrap();
    let published: Vec<String> = fs::read_dir(&d.public)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(published, vec!["ca.crt".to_string()]);
    assert_eq!(
        fs::read(d.public.join("ca.crt")).unwrap(),
        read(&d, "ca.crt")
    );
}

#[test]
fn the_ca_key_appears_nowhere_outside_the_pki_directory() {
    let d = dirs();
    run_logged(&config(&d, LOCAL), base()).unwrap();
    let body = key_body(&read(&d, "ca.key"));
    let root = d.pki.parent().unwrap();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                if path != d.pki {
                    stack.push(path);
                }
            } else if !path.starts_with(&d.pki) {
                let bytes = fs::read(&path).unwrap();
                assert!(
                    !String::from_utf8_lossy(&bytes).contains(&body),
                    "{} holds the CA key",
                    path.display()
                );
            }
        }
    }
}

/// The base64 lines of a PEM private key.
fn key_body(pem: &[u8]) -> String {
    String::from_utf8(pem.to_vec())
        .unwrap()
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect::<Vec<_>>()
        .join("")
}

#[test]
fn the_issued_certificates_carry_the_documented_extensions() {
    let d = dirs();
    run_logged(&config(&d, "localhost,127.0.0.1,::1,vault.lan"), base()).unwrap();

    // CA
    let ca_der = der_of(&read(&d, "ca.crt"));
    let ca = parse(&ca_der);
    assert_eq!(ca.subject().to_string(), "CN=ferrowarden-internal-ca");
    assert_eq!(ca.issuer().to_string(), "CN=ferrowarden-internal-ca");
    assert!(
        ca.raw_serial()[0] & 0x80 == 0,
        "the serial number is positive"
    );
    let bc = ca.basic_constraints().unwrap().unwrap();
    assert!(bc.critical && bc.value.ca && bc.value.path_len_constraint == Some(0));
    let ku = ca.key_usage().unwrap().unwrap();
    assert!(ku.critical);
    assert!(ku.value.key_cert_sign() && ku.value.crl_sign());
    assert!(!ku.value.digital_signature());
    assert_eq!(
        ca.validity().not_after.timestamp() - ca.validity().not_before.timestamp(),
        3650 * 86_400
    );
    assert_eq!(ca.validity().not_before.timestamp(), 1_800_000_000);

    // Server certificate
    let crt_der = der_of(&read(&d, "vaultwarden.crt"));
    let crt = parse(&crt_der);
    assert_eq!(crt.subject().to_string(), "CN=vaultwarden");
    assert_eq!(crt.issuer().to_string(), "CN=ferrowarden-internal-ca");
    let bc = crt.basic_constraints().unwrap().unwrap();
    assert!(bc.critical && !bc.value.ca);
    let ku = crt.key_usage().unwrap().unwrap();
    assert!(ku.critical && ku.value.digital_signature());
    assert!(!ku.value.key_cert_sign());
    let eku = crt.extended_key_usage().unwrap().unwrap();
    assert!(eku.value.server_auth && !eku.value.client_auth && !eku.value.any);
    assert_eq!(
        crt.validity().not_after.timestamp() - crt.validity().not_before.timestamp(),
        825 * 86_400
    );
    let san = crt.subject_alternative_name().unwrap().unwrap();
    let names: Vec<String> = san
        .value
        .general_names
        .iter()
        .map(|n| match n {
            GeneralName::DNSName(s) => format!("DNS:{s}"),
            GeneralName::IPAddress(b) => format!("IP:{}", ip_from_bytes(b)),
            other => panic!("unexpected name {other:?}"),
        })
        .collect();
    assert_eq!(
        names,
        [
            "DNS:vaultwarden",
            "DNS:localhost",
            "IP:127.0.0.1",
            "IP:::1",
            "DNS:vault.lan"
        ]
    );
    // Key identifiers: the server certificate's AKI is the CA's SKI.
    let ca_ski = ca
        .get_extension_unique(&x509_parser::oid_registry::OID_X509_EXT_SUBJECT_KEY_IDENTIFIER)
        .unwrap()
        .unwrap();
    let crt_aki = crt
        .get_extension_unique(&x509_parser::oid_registry::OID_X509_EXT_AUTHORITY_KEY_IDENTIFIER)
        .unwrap()
        .unwrap();
    assert!(
        matches!(crt_aki.parsed_extension(), x509_parser::extensions::ParsedExtension::AuthorityKeyIdentifier(aki)
            if matches!(ca_ski.parsed_extension(), x509_parser::extensions::ParsedExtension::SubjectKeyIdentifier(ski)
                if aki.key_identifier.as_ref().map(|k| k.0) == Some(ski.0)))
    );
    assert!(crt
        .get_extension_unique(&x509_parser::oid_registry::OID_X509_EXT_SUBJECT_KEY_IDENTIFIER)
        .unwrap()
        .is_some());
    // The CA key is ECDSA P-256 and so is the server key.
    assert!(
        crt.public_key().algorithm.algorithm
            == x509_parser::oid_registry::OID_KEY_TYPE_EC_PUBLIC_KEY
    );
}

fn ip_from_bytes(b: &[u8]) -> IpAddr {
    match b.len() {
        4 => IpAddr::from(<[u8; 4]>::try_from(b).unwrap()),
        16 => IpAddr::from(<[u8; 16]>::try_from(b).unwrap()),
        n => panic!("odd address length {n}"),
    }
}

#[test]
fn serial_numbers_are_random_and_positive() {
    let a = random_serial().unwrap().to_bytes();
    let b = random_serial().unwrap().to_bytes();
    assert_ne!(a, b);
    for s in [a, b] {
        assert_eq!(s.len(), 16);
        assert!(
            s[0] & 0x80 == 0 && s[0] != 0,
            "positive, no leading zero byte"
        );
    }
}

// ── Idempotence ──────────────────────────────────────────────────────────────

#[test]
fn a_second_run_changes_nothing() {
    let d = dirs();
    let c = config(&d, LOCAL);
    run_logged(&c, base()).unwrap();
    let before: Vec<Vec<u8>> = [
        "ca.crt",
        "ca.key",
        "vaultwarden.crt",
        "vaultwarden.key",
        "vaultwarden.sans",
    ]
    .iter()
    .map(|f| read(&d, f))
    .collect();
    let log = run_logged(&c, base() + Duration::from_secs(3600)).unwrap();
    assert!(log.contains("[certs] Internal CA exists"), "{log}");
    assert!(
        log.contains("[certs] Vaultwarden certificate is valid"),
        "{log}"
    );
    assert!(!log.contains("Issuing"), "{log}");
    let after: Vec<Vec<u8>> = [
        "ca.crt",
        "ca.key",
        "vaultwarden.crt",
        "vaultwarden.key",
        "vaultwarden.sans",
    ]
    .iter()
    .map(|f| read(&d, f))
    .collect();
    assert_eq!(before, after);
    // The public copy is rewritten, with the same content.
    assert_eq!(
        fs::read(d.public.join("ca.crt")).unwrap(),
        read(&d, "ca.crt")
    );
}

// ── Re-issue triggers ────────────────────────────────────────────────────────

/// What a trigger does to a stack that was just created, and what the next run sees.
struct Trigger {
    name: &'static str,
    /// Changes the directory before the second run.
    prepare: fn(&Dirs),
    /// The extra SANs and clock of the second run.
    extra: &'static str,
    later: u64,
    /// A line the log must contain.
    expect: &'static str,
}

#[test]
fn every_trigger_reissues_the_certificate_and_keeps_the_ca() {
    let triggers = [
        Trigger {
            name: "missing certificate",
            prepare: |d| fs::remove_file(d.pki.join("vaultwarden.crt")).unwrap(),
            extra: LOCAL,
            later: 0,
            expect: "certificate or key is missing",
        },
        Trigger {
            name: "missing key",
            prepare: |d| fs::remove_file(d.pki.join("vaultwarden.key")).unwrap(),
            extra: LOCAL,
            later: 0,
            expect: "certificate or key is missing",
        },
        Trigger {
            name: "expires within 30 days",
            prepare: |_| {},
            extra: LOCAL,
            later: 825 - 10,
            expect: "expires within 30 days",
        },
        Trigger {
            name: "exactly 30 days left",
            prepare: |_| {},
            extra: LOCAL,
            later: 825 - 30 + 1,
            expect: "expires within 30 days",
        },
        Trigger {
            name: "expired",
            prepare: |_| {},
            extra: LOCAL,
            later: 900,
            expect: "expires within 30 days",
        },
        Trigger {
            name: "names changed",
            prepare: |_| {},
            extra: "localhost,127.0.0.1,vault.lan",
            later: 0,
            expect: "names changed",
        },
        Trigger {
            name: "names removed",
            prepare: |_| {},
            extra: "localhost",
            later: 0,
            expect: "names changed",
        },
        Trigger {
            name: "recorded names missing",
            prepare: |d| fs::remove_file(d.pki.join("vaultwarden.sans")).unwrap(),
            extra: LOCAL,
            later: 0,
            expect: "names changed",
        },
        Trigger {
            name: "unreadable certificate",
            prepare: |d| fs::write(d.pki.join("vaultwarden.crt"), "not a certificate").unwrap(),
            extra: LOCAL,
            later: 0,
            expect: "cannot be read",
        },
    ];
    for t in triggers {
        let d = dirs();
        run_logged(&config(&d, LOCAL), base()).unwrap();
        let (ca_crt, ca_key) = (read(&d, "ca.crt"), read(&d, "ca.key"));
        let (old_crt, old_key) = (read(&d, "vaultwarden.crt"), read(&d, "vaultwarden.key"));
        (t.prepare)(&d);

        let c = config(&d, t.extra);
        let now = base() + days(t.later);
        let log = run_logged(&c, now).unwrap_or_else(|e| panic!("{}: {e:#}", t.name));
        assert!(log.contains(t.expect), "{}: {log}", t.name);
        assert!(
            log.contains("Issuing Vaultwarden certificate"),
            "{}: {log}",
            t.name
        );

        assert_eq!(
            read(&d, "ca.crt"),
            ca_crt,
            "{}: the CA certificate is kept",
            t.name
        );
        assert_eq!(read(&d, "ca.key"), ca_key, "{}: the CA key is kept", t.name);
        assert_ne!(read(&d, "vaultwarden.crt"), old_crt, "{}", t.name);
        assert_ne!(read(&d, "vaultwarden.key"), old_key, "{}", t.name);
        assert_eq!(
            fs::read_to_string(d.pki.join("vaultwarden.sans")).unwrap(),
            c.san_string(),
            "{}",
            t.name
        );

        // The new certificate is good: a third run, at the same time, does nothing.
        let again = run_logged(&c, now).unwrap();
        assert!(
            again.contains("Vaultwarden certificate is valid"),
            "{}: {again}",
            t.name
        );
    }
}

#[test]
fn a_certificate_with_plenty_of_time_left_is_kept() {
    let d = dirs();
    let c = config(&d, LOCAL);
    run_logged(&c, base()).unwrap();
    let crt = read(&d, "vaultwarden.crt");
    // 30 days of validity left at the check time is still enough only if more
    // than 30 days remain; 60 days left certainly is.
    let log = run_logged(&c, base() + days(825 - 60)).unwrap();
    assert!(log.contains("certificate is valid"), "{log}");
    assert_eq!(read(&d, "vaultwarden.crt"), crt);
}

#[test]
fn a_certificate_signed_by_another_ca_is_reissued() {
    let d = dirs();
    let c = config(&d, LOCAL);
    run_logged(&c, base()).unwrap();
    let old_crt = read(&d, "vaultwarden.crt");

    // Replace the CA by another one (someone restored a different ca.crt/ca.key).
    let (other_crt, other_key) = create_ca(base()).unwrap();
    fs::write(d.pki.join("ca.crt"), &other_crt).unwrap();
    fs::write(d.pki.join("ca.key"), &other_key).unwrap();

    let log = run_logged(&c, base()).unwrap();
    assert!(log.contains("not signed by the current CA"), "{log}");
    assert_ne!(read(&d, "vaultwarden.crt"), old_crt);
    assert_eq!(
        read(&d, "ca.crt"),
        other_crt.as_bytes(),
        "the CA now in the directory is kept"
    );

    // And the new certificate verifies against it.
    let ca = load_ca(&d.pki.join("ca.crt"), &d.pki.join("ca.key")).unwrap();
    let crt = der_of(&read(&d, "vaultwarden.crt"));
    verify_server_cert(&ca, &crt, &c.sans, base()).unwrap_or_else(|e| panic!("{e}"));
}

#[test]
fn a_missing_ca_key_creates_a_new_ca_and_reissues() {
    for remove in [vec!["ca.key"], vec!["ca.crt"], vec!["ca.crt", "ca.key"]] {
        let d = dirs();
        let c = config(&d, LOCAL);
        run_logged(&c, base()).unwrap();
        let (ca_crt, old_crt) = (read(&d, "ca.crt"), read(&d, "vaultwarden.crt"));
        for f in &remove {
            fs::remove_file(d.pki.join(f)).unwrap();
        }
        let log = run_logged(&c, base()).unwrap();
        assert!(
            log.contains("[certs] Creating internal CA"),
            "{remove:?}: {log}"
        );
        assert!(
            log.contains("Issuing Vaultwarden certificate"),
            "{remove:?}: {log}"
        );
        assert_ne!(read(&d, "ca.crt"), ca_crt, "{remove:?}");
        assert_ne!(read(&d, "vaultwarden.crt"), old_crt, "{remove:?}");
        // The public copy follows the new CA.
        assert_eq!(
            fs::read(d.public.join("ca.crt")).unwrap(),
            read(&d, "ca.crt")
        );
        let ca = load_ca(&d.pki.join("ca.crt"), &d.pki.join("ca.key")).unwrap();
        let crt = der_of(&read(&d, "vaultwarden.crt"));
        verify_server_cert(&ca, &crt, &c.sans, base()).unwrap_or_else(|e| panic!("{e}"));
    }
}

#[test]
fn an_unreadable_ca_key_is_an_error_not_a_new_ca() {
    let d = dirs();
    let c = config(&d, LOCAL);
    run_logged(&c, base()).unwrap();
    let (ca_crt, crt) = (read(&d, "ca.crt"), read(&d, "vaultwarden.crt"));
    fs::write(d.pki.join("ca.key"), "garbage").unwrap();
    let err = run_logged(&c, base()).unwrap_err().to_string();
    assert!(
        err.contains("ca.key") && err.contains("remove ca.crt and ca.key"),
        "{err}"
    );
    assert_eq!(read(&d, "ca.crt"), ca_crt);
    assert_eq!(read(&d, "vaultwarden.crt"), crt);
}

// ── A volume made by the old openssl script ──────────────────────────────────

fn fixture_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src/pki/testdata")
}

fn openssl_volume() -> Dirs {
    let d = dirs();
    fs::create_dir_all(&d.pki).unwrap();
    for f in [
        "ca.crt",
        "ca.key",
        "vaultwarden.crt",
        "vaultwarden.key",
        "vaultwarden.sans",
    ] {
        fs::copy(fixture_dir().join(f), d.pki.join(f)).unwrap();
    }
    d
}

#[test]
fn an_openssl_made_volume_is_reused_as_it_is() {
    let d = openssl_volume();
    let before: Vec<Vec<u8>> = [
        "ca.crt",
        "ca.key",
        "vaultwarden.crt",
        "vaultwarden.key",
        "vaultwarden.sans",
    ]
    .iter()
    .map(|f| read(&d, f))
    .collect();
    let log = run_logged(&config(&d, LOCAL), fixture_now()).unwrap();
    assert!(log.contains("[certs] Internal CA exists"), "{log}");
    assert!(
        log.contains("[certs] Vaultwarden certificate is valid"),
        "{log}"
    );
    assert!(
        !log.contains("Creating") && !log.contains("Issuing"),
        "{log}"
    );
    let after: Vec<Vec<u8>> = [
        "ca.crt",
        "ca.key",
        "vaultwarden.crt",
        "vaultwarden.key",
        "vaultwarden.sans",
    ]
    .iter()
    .map(|f| read(&d, f))
    .collect();
    assert_eq!(
        before, after,
        "ca.crt/ca.key/vaultwarden.* are byte-identical"
    );
    assert_eq!(
        fs::read(d.public.join("ca.crt")).unwrap(),
        fs::read(fixture_dir().join("ca.crt")).unwrap()
    );
}

#[test]
fn a_certificate_issued_under_an_openssl_made_ca_verifies_against_the_old_ca() {
    // Each reason to re-issue, against the CA the openssl script made.
    let cases: [(&str, u64); 3] = [
        ("localhost,127.0.0.1,vault.lan,::1", 0),
        (LOCAL, 800), // within 30 days of the end of the old certificate
        (LOCAL, 2000),
    ];
    for (extra, later) in cases {
        let d = openssl_volume();
        let old_ca = fs::read(fixture_dir().join("ca.crt")).unwrap();
        let old_leaf = read(&d, "vaultwarden.crt");
        let c = config(&d, extra);
        let now = fixture_now() + days(later);
        let log = run_logged(&c, now).unwrap();
        assert!(log.contains("Issuing Vaultwarden certificate"), "{log}");
        assert!(!log.contains("Creating"), "{log}");

        assert_eq!(
            read(&d, "ca.crt"),
            old_ca,
            "the old CA certificate is untouched"
        );
        assert_eq!(
            read(&d, "ca.key"),
            fs::read(fixture_dir().join("ca.key")).unwrap()
        );
        let new_leaf = read(&d, "vaultwarden.crt");
        assert_ne!(new_leaf, old_leaf);

        // Verified straight from the old ca.crt on disk, with webpki alone.
        let ca_der = der_of(&old_ca);
        let anchor = anchor_from_trusted_cert(&ca_der).unwrap();
        let leaf_der = der_of(&new_leaf);
        let end_entity = EndEntityCert::try_from(&leaf_der).unwrap();
        end_entity
            .verify_for_usage(
                ALL_VERIFICATION_ALGS,
                &[anchor],
                &[],
                unix_time(now).unwrap(),
                KeyUsage::server_auth(),
                None,
                None,
            )
            .unwrap();
        for entry in &c.sans {
            end_entity
                .verify_is_valid_for_subject_name(&to_server_name(&entry.san).unwrap())
                .unwrap();
        }

        // The issuer name is the CA's subject, byte for byte, and the authority
        // key identifier is the old CA's own subject key identifier (SHA-1,
        // which openssl chose; OpenSSL clients compare the two).
        let ca_parts = der::parse_cert(&ca_der).unwrap();
        let leaf_parts = der::parse_cert(&leaf_der).unwrap();
        assert_eq!(leaf_parts.issuer_raw, ca_parts.subject_raw);
        let leaf = parse(&leaf_der);
        let aki = leaf
            .get_extension_unique(&x509_parser::oid_registry::OID_X509_EXT_AUTHORITY_KEY_IDENTIFIER)
            .unwrap()
            .unwrap();
        match aki.parsed_extension() {
            x509_parser::extensions::ParsedExtension::AuthorityKeyIdentifier(a) => {
                assert_eq!(
                    a.key_identifier.as_ref().map(|k| k.0.to_vec()),
                    ca_parts.ski.clone()
                );
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(ca_parts.ski.as_ref().map(Vec::len), Some(20));
    }
}

#[test]
fn the_fixture_ca_is_what_the_old_script_makes() {
    // The assumptions the reuse path rests on, checked on the real fixture.
    let ca_der = der_of(&fs::read(fixture_dir().join("ca.crt")).unwrap());
    let parts = der::parse_cert(&ca_der).unwrap();
    assert_eq!(parts.issuer_raw, parts.subject_raw);
    assert_eq!(
        parts.subject,
        vec![der::NameEntry {
            oid: vec![2, 5, 4, 3],
            kind: StringKind::Utf8,
            value: "ferrowarden-internal-ca".into()
        }]
    );
    assert!(parts.ski.is_some());
    let leaf_der = der_of(&fs::read(fixture_dir().join("vaultwarden.crt")).unwrap());
    assert_eq!(
        der::parse_cert(&leaf_der).unwrap().issuer_raw,
        parts.subject_raw
    );
    // The old key loads (PKCS#8 as openssl wrote it).
    load_ca(&fixture_dir().join("ca.crt"), &fixture_dir().join("ca.key")).unwrap();
}

#[test]
fn the_subject_is_reencoded_byte_for_byte_whatever_its_string_type() {
    // A CA whose name uses PrintableString (older openssl) or IA5String.
    for kind in [StringKind::Utf8, StringKind::Printable, StringKind::Ia5] {
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let mut params = CertificateParams::default();
        let mut dn = DistinguishedName::new();
        let text = "Some Internal CA";
        dn.push(
            DnType::CountryName,
            DnValue::PrintableString(PrintableString::try_from("DE").unwrap()),
        );
        dn.push(
            DnType::CommonName,
            match kind {
                StringKind::Utf8 => DnValue::Utf8String(text.into()),
                StringKind::Printable => {
                    DnValue::PrintableString(PrintableString::try_from(text).unwrap())
                }
                StringKind::Ia5 => DnValue::Ia5String(Ia5String::try_from(text).unwrap()),
            },
        );
        params.distinguished_name = dn;
        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        let ca_cert = params.self_signed(&key).unwrap();

        let d = dirs();
        fs::create_dir_all(&d.pki).unwrap();
        fs::write(d.pki.join("ca.crt"), ca_cert.pem()).unwrap();
        fs::write(d.pki.join("ca.key"), key.serialize_pem()).unwrap();
        let c = config(&d, LOCAL);
        run_logged(&c, base()).unwrap_or_else(|e| panic!("{kind:?}: {e:#}"));
        let leaf = der_of(&read(&d, "vaultwarden.crt"));
        assert_eq!(
            der::parse_cert(&leaf).unwrap().issuer_raw,
            der::parse_cert(ca_cert.der()).unwrap().subject_raw,
            "{kind:?}"
        );
    }
}

// ── End to end TLS ───────────────────────────────────────────────────────────

fn roots_from(ca_pem: &[u8]) -> RootCertStore {
    let mut roots = RootCertStore::empty();
    roots.add(der_of(ca_pem)).unwrap();
    roots
}

/// Drive a client and a server connection against each other in memory until
/// both have finished the handshake (or one fails).
fn handshake(
    client: &mut ClientConnection,
    server: &mut ServerConnection,
) -> Result<(), rustls::Error> {
    for _ in 0..20 {
        let mut buf = Vec::new();
        while client.wants_write() {
            client.write_tls(&mut buf).unwrap();
        }
        if !buf.is_empty() {
            server.read_tls(&mut buf.as_slice()).unwrap();
            server.process_new_packets()?;
        }
        let mut buf = Vec::new();
        while server.wants_write() {
            server.write_tls(&mut buf).unwrap();
        }
        if !buf.is_empty() {
            client.read_tls(&mut buf.as_slice()).unwrap();
            client.process_new_packets()?;
        }
        if !client.is_handshaking() && !server.is_handshaking() {
            return Ok(());
        }
    }
    panic!("handshake did not finish");
}

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

#[test]
fn a_rustls_client_trusting_only_the_published_ca_connects_for_every_name() {
    let d = dirs();
    // The real clock: rustls checks validity against it.
    let c = config(&d, "localhost,127.0.0.1,::1,vault.lan");
    run_logged(&c, SystemTime::now()).unwrap();

    let crt_pem = read(&d, "vaultwarden.crt");
    let key_pem = read(&d, "vaultwarden.key");
    let chain = vec![der_of(&crt_pem)];
    let key = PrivateKeyDer::from_pem_slice(&key_pem).unwrap();
    let server_config = Arc::new(
        ServerConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(chain, key)
            .unwrap(),
    );

    // The client sees only what the public volume holds.
    let published = fs::read(d.public.join("ca.crt")).unwrap();
    let client_config = Arc::new(
        ClientConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots_from(&published))
            .with_no_client_auth(),
    );
    for entry in &c.sans {
        let name = to_server_name(&entry.san).unwrap();
        let mut client = ClientConnection::new(client_config.clone(), name).unwrap();
        let mut server = ServerConnection::new(server_config.clone()).unwrap();
        handshake(&mut client, &mut server).unwrap_or_else(|e| panic!("{}: {e}", entry.label()));

        // Application data flows both ways.
        client.writer().write_all(b"ping").unwrap();
        let mut wire = Vec::new();
        client.write_tls(&mut wire).unwrap();
        server.read_tls(&mut wire.as_slice()).unwrap();
        server.process_new_packets().unwrap();
        let mut got = [0u8; 4];
        server.reader().read_exact(&mut got).unwrap();
        assert_eq!(&got, b"ping", "{}", entry.label());
    }

    // A name the certificate does not cover is refused.
    let mut client = ClientConnection::new(
        client_config,
        ServerName::try_from("elsewhere.example").unwrap(),
    )
    .unwrap();
    let mut server = ServerConnection::new(server_config.clone()).unwrap();
    assert!(handshake(&mut client, &mut server).is_err());

    // A client that trusts another CA refuses the server.
    let other = dirs();
    run_logged(&config(&other, LOCAL), SystemTime::now()).unwrap();
    let other_ca = fs::read(other.public.join("ca.crt")).unwrap();
    assert_ne!(other_ca, published);
    let strict = Arc::new(
        ClientConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots_from(&other_ca))
            .with_no_client_auth(),
    );
    let mut client =
        ClientConnection::new(strict, ServerName::try_from("vaultwarden").unwrap()).unwrap();
    let mut server = ServerConnection::new(server_config).unwrap();
    let err = handshake(&mut client, &mut server).unwrap_err();
    assert!(
        matches!(err, rustls::Error::InvalidCertificate(_)),
        "{err:?}"
    );
}

#[test]
fn a_certificate_made_under_an_openssl_ca_works_in_a_tls_handshake() {
    // The whole point of reuse: the CA that clients already trust signs the new certificate.
    let d = openssl_volume();
    let c = config(&d, "localhost,127.0.0.1,vault.lan");
    // Real clock for rustls: re-issue from the real now, under the fixture CA.
    run_logged(&c, SystemTime::now()).unwrap();
    assert_eq!(
        read(&d, "ca.crt"),
        fs::read(fixture_dir().join("ca.crt")).unwrap()
    );
    let key = PrivateKeyDer::from_pem_slice(&read(&d, "vaultwarden.key")).unwrap();
    let server_config = Arc::new(
        ServerConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![der_of(&read(&d, "vaultwarden.crt"))], key)
            .unwrap(),
    );
    let client_config = Arc::new(
        ClientConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots_from(&fs::read(fixture_dir().join("ca.crt")).unwrap()))
            .with_no_client_auth(),
    );
    for name in ["vaultwarden", "localhost", "vault.lan"] {
        let mut client =
            ClientConnection::new(client_config.clone(), ServerName::try_from(name).unwrap())
                .unwrap();
        let mut server = ServerConnection::new(server_config.clone()).unwrap();
        handshake(&mut client, &mut server).unwrap_or_else(|e| panic!("{name}: {e}"));
    }
}

// ── Secrets stay out of the output ───────────────────────────────────────────

#[test]
fn key_material_never_reaches_the_log_or_an_error() {
    let d = dirs();
    let c = config(&d, LOCAL);
    let mut logs = run_logged(&c, base()).unwrap();
    // Every kind of run: fresh, no-op, re-issue.
    logs.push_str(&run_logged(&c, base()).unwrap());
    logs.push_str(&run_logged(&config(&d, "localhost"), base()).unwrap());
    fs::remove_file(d.pki.join("ca.key")).unwrap();
    logs.push_str(&run_logged(&c, base()).unwrap());
    fs::write(
        d.pki.join("ca.key"),
        "-----BEGIN PRIVATE KEY-----\nTUhJU1NFQ1JFVA==\n-----END PRIVATE KEY-----\n",
    )
    .unwrap();
    let err = format!("{:#}", run_logged(&c, base()).unwrap_err());
    logs.push_str(&err);
    assert!(!err.contains("TUhJU1NFQ1JFVA"), "{err}");

    let body = key_body(&read(&d, "vaultwarden.key"));
    assert!(body.len() > 40);
    assert!(!logs.contains(&body), "the server key leaked");
    assert!(!logs.contains(&body[..40]), "the server key leaked in part");
    assert!(!logs.contains("PRIVATE KEY"));
}

#[test]
fn the_log_lines_match_the_scripts() {
    let d = dirs();
    let c = config(&d, LOCAL);
    let log = run_logged(&c, base()).unwrap();
    assert_eq!(
        log.lines().collect::<Vec<_>>(),
        vec![
            "[certs] Creating internal CA".to_string(),
            "[certs] Issuing Vaultwarden certificate for DNS:vaultwarden,DNS:localhost,IP:127.0.0.1".into(),
            format!("[certs] CA certificate published to {}", d.public.join("ca.crt").display()),
            "[certs] Done".into(),
        ]
    );
    let log = run_logged(&c, base()).unwrap();
    assert_eq!(log.lines().next(), Some("[certs] Internal CA exists"));
    assert_eq!(
        log.lines().nth(1),
        Some("[certs] Vaultwarden certificate is valid")
    );
}

// ── The DER reader ───────────────────────────────────────────────────────────

#[test]
fn the_der_reader_refuses_what_it_does_not_understand() {
    assert!(der::parse_cert(&[]).is_err());
    assert!(der::parse_cert(b"not der at all").is_err());
    let ca = der_of(&fs::read(fixture_dir().join("ca.crt")).unwrap());
    // Truncations at every length either parse (never, for a cut certificate) or fail cleanly.
    for cut in (0..ca.len()).step_by(7) {
        assert!(der::parse_cert(&ca[..cut]).is_err(), "cut at {cut}");
    }
    assert!(der::parse_cert(&ca).is_ok());
}

#[test]
fn an_unreadable_pem_certificate_is_an_error() {
    let d = dirs();
    fs::create_dir_all(&d.pki).unwrap();
    fs::write(d.pki.join("ca.crt"), "garbage").unwrap();
    fs::write(d.pki.join("ca.key"), "garbage").unwrap();
    let err = run_logged(&config(&d, LOCAL), base())
        .unwrap_err()
        .to_string();
    assert!(err.contains("ca.crt"), "{err}");
}
