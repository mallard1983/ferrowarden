//! `ferrowarden internal-certs`: the private CA and the Vaultwarden certificate
//! for the internal Docker network.
//!
//! Ferrowarden refuses plain-HTTP vault URLs, so Vaultwarden serves HTTPS on
//! the internal network with a certificate from a private CA that Ferrowarden
//! trusts. This one-shot subcommand creates and renews them, so the default
//! deployment needs no Node, no shell and no openssl: it runs the same static
//! binary as the proxy (docs/tls.md, docs/security.md).
//!
//! It reproduces what `docker/gen-internal-certs.sh` did, file for file:
//!
//! - in `PKI_DIR`: `ca.crt`, `ca.key`, `vaultwarden.crt`, `vaultwarden.key`
//!   and `vaultwarden.sans` (the SAN list the certificate was issued for);
//! - in `CA_PUBLIC_DIR`: a copy of `ca.crt` and nothing else, so Ferrowarden can
//!   trust Vaultwarden without ever seeing the CA private key.
//!
//! The CA (ECDSA P-256, 10 years) is created once and reused, **including a CA
//! an older release made with openssl**: existing installs keep their CA.
//! The server certificate (ECDSA P-256, 825 days) is issued again when it is
//! missing, when it would not verify against the CA 30 days from now (expiring,
//! expired, or signed by another CA), or when the requested names changed.
//!
//! Nothing here prints or logs key material. Files are written atomically
//! (a temporary file in the same directory, synced, renamed), and a private
//! key is created with mode 0600 from the first byte.

mod der;

use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Context, Result};
use rcgen::string::{Ia5String, PrintableString};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, DnValue,
    ExtendedKeyUsagePurpose, IsCa, Issuer, KeyIdMethod, KeyPair, KeyUsagePurpose, SanType,
    SerialNumber, PKCS_ECDSA_P256_SHA256,
};
use rustls::pki_types::{
    pem::PemObject, CertificateDer, IpAddr as PkiIpAddr, ServerName, UnixTime,
};
use time::OffsetDateTime;
use webpki::{anchor_from_trusted_cert, EndEntityCert, KeyUsage, ALL_VERIFICATION_ALGS};

use der::{CertParts, StringKind};

/// The CA lives 10 years.
const CA_VALIDITY: Duration = Duration::from_secs(3650 * 24 * 60 * 60);
/// The Vaultwarden certificate lives 825 days (the longest browsers and
/// platform verifiers used to accept).
const SERVER_VALIDITY: Duration = Duration::from_secs(825 * 24 * 60 * 60);
/// A certificate that would not verify this far ahead is issued again.
const RENEW_WITHIN: Duration = Duration::from_secs(30 * 24 * 60 * 60);

const CA_CN: &str = "ferrowarden-internal-ca";

const CA_CRT: &str = "ca.crt";
const CA_KEY: &str = "ca.key";
const SERVER_CRT: &str = "vaultwarden.crt";
const SERVER_KEY: &str = "vaultwarden.key";
const SERVER_SANS: &str = "vaultwarden.sans";

// ── Configuration ────────────────────────────────────────────────────────────

/// One name the certificate covers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum San {
    Dns(String),
    Ip(IpAddr),
}

/// A SAN as written by the operator, so the SAN string stays what the shell
/// script produced (an IP is kept as typed).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SanEntry {
    pub san: San,
    text: String,
}

impl SanEntry {
    /// The `DNS:name` / `IP:address` form used in `vaultwarden.sans`.
    fn label(&self) -> String {
        match self.san {
            San::Dns(_) => format!("DNS:{}", self.text),
            San::Ip(_) => format!("IP:{}", self.text),
        }
    }
}

/// What the subcommand does, from the environment variables the old script read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PkiConfig {
    pub pki_dir: PathBuf,
    pub ca_public_dir: PathBuf,
    pub hostname: String,
    /// The primary name first, then `VW_EXTRA_SANS` in order.
    pub sans: Vec<SanEntry>,
}

/// Whether `name` is a DNS name a certificate can carry: dot-separated labels
/// of letters, digits, `-` and `_`, none empty, none over 63 characters, none
/// starting or ending with `-`; a leading `*.` wildcard label is allowed.
pub fn is_valid_dns_name(name: &str) -> bool {
    let body = name.strip_prefix("*.").unwrap_or(name);
    if body.is_empty() || name.len() > 253 {
        return false;
    }
    body.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    })
}

/// Classify and validate one SAN entry the way the script classified it
/// (`:` means IPv6, only digits and dots means IPv4, anything else a DNS
/// name), but reject what does not parse instead of passing it to openssl.
fn parse_san(entry: &str) -> Result<SanEntry> {
    let san = if entry.contains(':') {
        San::Ip(IpAddr::V6(entry.parse::<Ipv6Addr>().map_err(|_| {
            anyhow!("VW_EXTRA_SANS: {entry:?} is not a valid IPv6 address")
        })?))
    } else if entry.bytes().all(|b| b.is_ascii_digit() || b == b'.') {
        San::Ip(IpAddr::V4(entry.parse::<Ipv4Addr>().map_err(|_| {
            anyhow!("VW_EXTRA_SANS: {entry:?} is not a valid IPv4 address")
        })?))
    } else if is_valid_dns_name(entry) {
        San::Dns(entry.to_string())
    } else {
        bail!("VW_EXTRA_SANS: {entry:?} is not a valid DNS name");
    };
    Ok(SanEntry {
        san,
        text: entry.to_string(),
    })
}

/// Parse `VW_EXTRA_SANS`: comma-separated, spaces removed, empty entries skipped.
pub fn parse_extra_sans(value: &str) -> Result<Vec<SanEntry>> {
    value
        .split(',')
        .map(|entry| entry.chars().filter(|c| *c != ' ').collect::<String>())
        .filter(|entry| !entry.is_empty())
        .map(|entry| parse_san(&entry))
        .collect()
}

impl PkiConfig {
    /// Read the configuration from the process environment.
    pub fn from_env() -> Result<Self> {
        Self::from_lookup(|key| std::env::var(key).ok())
    }

    /// Read the configuration through `lookup`. An unset or empty variable
    /// takes its default, as `${VAR:-default}` did in the script.
    pub fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> Result<Self> {
        let get = |key: &str, default: &str| {
            lookup(key)
                .filter(|v| !v.is_empty())
                .unwrap_or_else(|| default.to_string())
        };
        let hostname = get("VW_HOSTNAME", "vaultwarden");
        if !is_valid_dns_name(&hostname) {
            bail!("VW_HOSTNAME: {hostname:?} is not a valid DNS name");
        }
        let mut sans = vec![SanEntry {
            san: San::Dns(hostname.clone()),
            text: hostname.clone(),
        }];
        sans.extend(parse_extra_sans(&get("VW_EXTRA_SANS", ""))?);
        Ok(Self {
            pki_dir: PathBuf::from(get("PKI_DIR", "/pki")),
            ca_public_dir: PathBuf::from(get("CA_PUBLIC_DIR", "/ca-public")),
            hostname,
            sans,
        })
    }

    /// The SAN string recorded in `vaultwarden.sans`, e.g.
    /// `DNS:vaultwarden,DNS:localhost,IP:127.0.0.1`.
    pub fn san_string(&self) -> String {
        self.sans
            .iter()
            .map(SanEntry::label)
            .collect::<Vec<_>>()
            .join(",")
    }
}

// ── Entry point ──────────────────────────────────────────────────────────────

/// `ferrowarden internal-certs`: returns the process exit code.
pub fn run_from_env() -> i32 {
    let outcome = PkiConfig::from_env().and_then(|config| {
        let mut out = std::io::stdout().lock();
        run(&config, SystemTime::now(), &mut out)
    });
    match outcome {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("ferrowarden internal-certs: {e:#}");
            1
        }
    }
}

/// Create or renew the CA and the Vaultwarden certificate, and publish the CA
/// certificate. Progress lines go to `log`; key material never does.
pub fn run(config: &PkiConfig, now: SystemTime, log: &mut dyn Write) -> Result<()> {
    let sans = config.san_string();
    let pki = &config.pki_dir;
    fs::create_dir_all(pki).with_context(|| format!("creating {}", pki.display()))?;

    let ca_crt_path = pki.join(CA_CRT);
    let ca_key_path = pki.join(CA_KEY);
    let server_crt_path = pki.join(SERVER_CRT);
    let server_key_path = pki.join(SERVER_KEY);
    let sans_path = pki.join(SERVER_SANS);

    // The CA: reuse what is there (even an openssl-made one), else create it.
    let mut force_issue = false;
    if !(ca_crt_path.is_file() && ca_key_path.is_file()) {
        say(log, "[certs] Creating internal CA")?;
        let (cert_pem, key_pem) = create_ca(now)?;
        // Key first: a crash between the two files leaves one of them missing,
        // which the next run treats as "no CA" and starts over.
        write_atomic(&ca_key_path, key_pem.as_bytes(), true)?;
        write_atomic(&ca_crt_path, cert_pem.as_bytes(), false)?;
        force_issue = true;
    } else {
        say(log, "[certs] Internal CA exists")?;
    }

    let ca = load_ca(&ca_crt_path, &ca_key_path)?;

    let reason = if force_issue {
        Some("the CA is new".to_string())
    } else {
        server_cert_problem(
            config,
            &ca,
            now,
            &server_crt_path,
            &server_key_path,
            &sans_path,
        )
    };

    match reason {
        Some(reason) => {
            if !force_issue {
                say(log, &format!("[certs] {reason}"))?;
            }
            say(
                log,
                &format!("[certs] Issuing Vaultwarden certificate for {sans}"),
            )?;
            let (cert_pem, key_pem) = issue_server_cert(config, &ca, now)?;
            // `vaultwarden.sans` is the commit marker: remove it first and write
            // it last, so a run that dies half-way is redone by the next one
            // instead of leaving a certificate and key that do not match.
            match fs::remove_file(&sans_path) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => {
                    return Err(e).with_context(|| format!("removing {}", sans_path.display()))
                }
            }
            write_atomic(&server_key_path, key_pem.as_bytes(), true)?;
            write_atomic(&server_crt_path, cert_pem.as_bytes(), false)?;
            write_atomic(&sans_path, sans.as_bytes(), false)?;
        }
        None => say(log, "[certs] Vaultwarden certificate is valid")?,
    }

    // The CA certificate is public; other containers run as non-root users.
    // Private keys stay owner-only. Re-applied on every run, as the script did.
    set_modes(&[&ca_crt_path, &server_crt_path, &sans_path], false)?;
    set_modes(&[&ca_key_path, &server_key_path], true)?;

    publish_ca(&config.ca_public_dir, &ca_crt_path)?;
    say(
        log,
        &format!(
            "[certs] CA certificate published to {}",
            config.ca_public_dir.join(CA_CRT).display()
        ),
    )?;
    say(log, "[certs] Done")?;
    Ok(())
}

fn say(log: &mut dyn Write, line: &str) -> Result<()> {
    writeln!(log, "{line}").context("writing the log")
}

// ── The CA ───────────────────────────────────────────────────────────────────

/// The CA as loaded from disk: its certificate and what is needed to sign with it.
struct Ca {
    der: CertificateDer<'static>,
    parts: CertParts,
    key: KeyPair,
}

fn offset_time(t: SystemTime) -> Result<OffsetDateTime> {
    let secs = t
        .duration_since(UNIX_EPOCH)
        .map_err(|_| anyhow!("the system clock is before 1970"))?
        .as_secs();
    OffsetDateTime::from_unix_timestamp(i64::try_from(secs)?)
        .context("the system clock is out of range")
}

fn unix_time(t: SystemTime) -> Result<UnixTime> {
    Ok(UnixTime::since_unix_epoch(
        t.duration_since(UNIX_EPOCH)
            .map_err(|_| anyhow!("the system clock is before 1970"))?,
    ))
}

/// A random positive serial number (16 bytes, top bit clear, never zero).
fn random_serial() -> Result<SerialNumber> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes)
        .map_err(|e| anyhow!("no random numbers from the operating system: {e}"))?;
    bytes[0] = (bytes[0] & 0x7f) | 0x40;
    Ok(SerialNumber::from_slice(&bytes))
}

/// Create the CA: returns the certificate PEM and the key PEM (PKCS#8).
fn create_ca(now: SystemTime) -> Result<(String, String)> {
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).context("generating the CA key")?;
    let mut params = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, CA_CN);
    params.distinguished_name = dn;
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params.not_before = offset_time(now)?;
    params.not_after = offset_time(now + CA_VALIDITY)?;
    params.serial_number = Some(random_serial()?);
    let cert = params
        .self_signed(&key)
        .context("signing the CA certificate")?;
    Ok((cert.pem(), key.serialize_pem()))
}

fn pem_to_der(pem: &[u8], what: &str) -> Result<CertificateDer<'static>> {
    CertificateDer::from_pem_slice(pem).map_err(|e| anyhow!("{what} is not a PEM certificate: {e}"))
}

fn load_ca(crt_path: &Path, key_path: &Path) -> Result<Ca> {
    let crt = fs::read(crt_path).with_context(|| format!("reading {}", crt_path.display()))?;
    let key_pem =
        fs::read_to_string(key_path).with_context(|| format!("reading {}", key_path.display()))?;
    let der = pem_to_der(&crt, &crt_path.display().to_string())?;
    let parts = der::parse_cert(&der).map_err(|e| anyhow!("{}: {e}", crt_path.display()))?;
    let key = KeyPair::from_pem(&key_pem).map_err(|e| {
        anyhow!(
            "{} is not a usable PKCS#8 ECDSA private key ({e}); to start over, remove ca.crt and ca.key (every certificate they signed stops being trusted)",
            key_path.display()
        )
    })?;
    Ok(Ca { der, parts, key })
}

/// The signing identity of an existing CA: its key, a subject name that
/// encodes byte for byte like the certificate's subject, and its subject key
/// identifier (which becomes the authority key identifier of what it signs).
fn ca_issuer(ca: &Ca) -> Result<Issuer<'_, &KeyPair>> {
    let mut dn = DistinguishedName::new();
    for entry in &ca.parts.subject {
        let value = match entry.kind {
            StringKind::Utf8 => DnValue::Utf8String(entry.value.clone()),
            StringKind::Printable => DnValue::PrintableString(
                PrintableString::try_from(entry.value.as_str())
                    .map_err(|e| anyhow!("the CA subject cannot be re-encoded: {e}"))?,
            ),
            StringKind::Ia5 => DnValue::Ia5String(
                Ia5String::try_from(entry.value.as_str())
                    .map_err(|e| anyhow!("the CA subject cannot be re-encoded: {e}"))?,
            ),
        };
        dn.push(DnType::from_oid(&entry.oid), value);
    }
    let mut params = CertificateParams::default();
    params.distinguished_name = dn;
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    if let Some(ski) = &ca.parts.ski {
        params.key_identifier_method = KeyIdMethod::PreSpecified(ski.clone());
    }
    Ok(Issuer::new(params, &ca.key))
}

// ── The Vaultwarden certificate ──────────────────────────────────────────────

fn to_server_name(san: &San) -> Result<ServerName<'static>> {
    Ok(match san {
        San::Dns(name) => ServerName::try_from(name.clone())
            .map_err(|_| anyhow!("{name:?} is not a name a certificate can carry"))?,
        San::Ip(ip) => ServerName::IpAddress(PkiIpAddr::from(*ip)),
    })
}

/// Check `cert_der` against the CA at `at`, for server authentication and for
/// every name in `sans`.
fn verify_server_cert(
    ca: &Ca,
    cert_der: &CertificateDer<'_>,
    sans: &[SanEntry],
    at: SystemTime,
) -> std::result::Result<(), VerifyFailure> {
    let anchor = anchor_from_trusted_cert(&ca.der)
        .map_err(|e| VerifyFailure::Other(format!("the CA certificate is unusable: {e}")))?;
    let time = unix_time(at).map_err(|e| VerifyFailure::Other(e.to_string()))?;
    let end_entity = EndEntityCert::try_from(cert_der)
        .map_err(|e| VerifyFailure::Other(format!("the certificate cannot be read: {e}")))?;
    end_entity
        .verify_for_usage(
            ALL_VERIFICATION_ALGS,
            &[anchor],
            &[],
            time,
            KeyUsage::server_auth(),
            None,
            None,
        )
        .map_err(|e| match e {
            webpki::Error::CertExpired { .. } | webpki::Error::CertNotValidYet { .. } => {
                VerifyFailure::Expiry
            }
            other => VerifyFailure::Chain(other.to_string()),
        })?;
    for entry in sans {
        let name = to_server_name(&entry.san).map_err(|e| VerifyFailure::Other(e.to_string()))?;
        end_entity
            .verify_is_valid_for_subject_name(&name)
            .map_err(|_| VerifyFailure::Names(entry.label()))?;
    }
    Ok(())
}

enum VerifyFailure {
    Expiry,
    Chain(String),
    Names(String),
    Other(String),
}

impl fmt::Display for VerifyFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Expiry => write!(f, "Vaultwarden certificate expires within 30 days"),
            Self::Chain(why) => write!(
                f,
                "Vaultwarden certificate not signed by the current CA ({why})"
            ),
            Self::Names(name) => write!(
                f,
                "Vaultwarden certificate names changed ({name} is not covered)"
            ),
            Self::Other(why) => write!(f, "Vaultwarden certificate cannot be checked ({why})"),
        }
    }
}

/// Why the certificate must be issued again, or `None` if it is good.
fn server_cert_problem(
    config: &PkiConfig,
    ca: &Ca,
    now: SystemTime,
    crt_path: &Path,
    key_path: &Path,
    sans_path: &Path,
) -> Option<String> {
    if !crt_path.is_file() || !key_path.is_file() {
        return Some("Vaultwarden certificate or key is missing".into());
    }
    let cert_der = match fs::read(crt_path)
        .map_err(|e| e.to_string())
        .and_then(|pem| pem_to_der(&pem, "vaultwarden.crt").map_err(|e| e.to_string()))
    {
        Ok(der) => der,
        Err(why) => return Some(format!("Vaultwarden certificate cannot be read ({why})")),
    };
    if let Err(failure) = verify_server_cert(ca, &cert_der, &config.sans, now + RENEW_WITHIN) {
        return Some(failure.to_string());
    }
    match fs::read_to_string(sans_path) {
        Ok(recorded) if recorded == config.san_string() => None,
        _ => Some("Vaultwarden certificate names changed".into()),
    }
}

/// Issue the Vaultwarden certificate: returns the certificate PEM and the key PEM.
fn issue_server_cert(config: &PkiConfig, ca: &Ca, now: SystemTime) -> Result<(String, String)> {
    let key =
        KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).context("generating the Vaultwarden key")?;
    let mut params = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, config.hostname.as_str());
    params.distinguished_name = dn;
    params.subject_alt_names = config
        .sans
        .iter()
        .map(|entry| match &entry.san {
            San::Dns(name) => Ok(SanType::DnsName(
                Ia5String::try_from(name.as_str())
                    .map_err(|e| anyhow!("{name:?} cannot be a certificate name: {e}"))?,
            )),
            San::Ip(ip) => Ok(SanType::IpAddress(*ip)),
        })
        .collect::<Result<_>>()?;
    // ExplicitNoCa writes basicConstraints (critical, CA:FALSE) and a subject key identifier.
    params.is_ca = IsCa::ExplicitNoCa;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    params.use_authority_key_identifier_extension = true;
    params.not_before = offset_time(now)?;
    params.not_after = offset_time(now + SERVER_VALIDITY)?;
    params.serial_number = Some(random_serial()?);

    let issuer = ca_issuer(ca)?;
    let cert = params
        .signed_by(&key, &issuer)
        .context("signing the Vaultwarden certificate")?;

    // Never write something that would not work: the issuer name must match the
    // CA's subject byte for byte, and the result must verify against the CA.
    let issued = der::parse_cert(cert.der())
        .map_err(|e| anyhow!("the issued certificate cannot be read back: {e}"))?;
    if issued.issuer_raw != ca.parts.subject_raw {
        bail!("the issued certificate's issuer name does not match the CA certificate's subject name (the CA's name uses an encoding internal-certs cannot reproduce)");
    }
    verify_server_cert(ca, cert.der(), &config.sans, now)
        .map_err(|e| anyhow!("the issued certificate does not verify against the CA: {e}"))?;

    Ok((cert.pem(), key.serialize_pem()))
}

// ── Files ────────────────────────────────────────────────────────────────────

/// Write `data` to `path` atomically: a temporary file in the same directory,
/// synced, then renamed over the target. A private file is created with mode
/// 0600 from the start (Unix), never written world-readable and then changed.
fn write_atomic(path: &Path, data: &[u8], private: bool) -> Result<()> {
    let dir = path
        .parent()
        .ok_or_else(|| anyhow!("{} has no parent directory", path.display()))?;
    let name = path
        .file_name()
        .ok_or_else(|| anyhow!("{} has no file name", path.display()))?
        .to_string_lossy();
    let tmp = dir.join(format!(".{name}.tmp"));
    // A leftover from a run that was killed.
    let _ = fs::remove_file(&tmp);

    let result = (|| -> std::io::Result<()> {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(if private { 0o600 } else { 0o644 });
        }
        let mut file = options.open(&tmp)?;
        #[cfg(unix)]
        {
            // The process umask can only have removed bits; make the mode exact.
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(fs::Permissions::from_mode(if private {
                0o600
            } else {
                0o644
            }))?;
        }
        let _ = private;
        file.write_all(data)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&tmp, path)?;
        #[cfg(unix)]
        fs::File::open(dir)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result.with_context(|| format!("writing {}", path.display()))
}

/// Set the mode of each file that exists (Unix only; elsewhere there is nothing to set).
#[cfg(unix)]
fn set_modes(paths: &[&Path], private: bool) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mode = if private { 0o600 } else { 0o644 };
    for path in paths.iter().filter(|p| p.is_file()) {
        fs::set_permissions(path, fs::Permissions::from_mode(mode))
            .with_context(|| format!("setting the mode of {}", path.display()))?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn set_modes(_paths: &[&Path], _private: bool) -> Result<()> {
    Ok(())
}

/// Copy the CA certificate (and only that) to the public directory.
fn publish_ca(public_dir: &Path, ca_crt: &Path) -> Result<()> {
    fs::create_dir_all(public_dir).with_context(|| format!("creating {}", public_dir.display()))?;
    let crt = fs::read(ca_crt).with_context(|| format!("reading {}", ca_crt.display()))?;
    write_atomic(&public_dir.join(CA_CRT), &crt, false)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(public_dir, fs::Permissions::from_mode(0o755))
            .with_context(|| format!("setting the mode of {}", public_dir.display()))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests;
