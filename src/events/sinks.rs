//! Event sinks: stdout, rotating JSON-lines file, and RFC 5424 syslog.
//!
//! A sink never fails the caller. [`Sink::write`] reports an I/O problem with
//! a rate-limited `tracing::warn!` (at most once a minute per sink) and
//! carries on, so one broken sink cannot stop the others.

use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use reqwest::Url;
use rustls::pki_types::{pem::PemObject, CertificateDer, ServerName};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::timeout;
use tokio_rustls::{client::TlsStream, TlsConnector};

use super::schema::{Action, Outcome, Reason, SecurityEvent};
use crate::config::EventsConfig;
use crate::error::{FerroError, FerroResult};

/// Minimum time between two warnings about the same failing sink.
const WARN_INTERVAL: Duration = Duration::from_secs(60);
/// Bound on connecting to, and writing to, a remote syslog server, so a hung
/// collector cannot stall the writer task (and with it the other sinks).
const NET_TIMEOUT: Duration = Duration::from_secs(5);
const BACKOFF_MIN: Duration = Duration::from_secs(1);
const BACKOFF_MAX: Duration = Duration::from_secs(60);

// ── Sink wrapper ──────────────────────────────────────────────────────────────

pub enum SinkKind {
    Stdout,
    File(FileSink),
    Syslog(Box<SyslogSink>),
    /// Collects lines in memory (tests).
    #[cfg(test)]
    Memory(Arc<std::sync::Mutex<Vec<String>>>),
}

pub struct Sink {
    name: &'static str,
    kind: SinkKind,
    last_warn: Option<Instant>,
}

impl Sink {
    pub fn new(name: &'static str, kind: SinkKind) -> Self {
        Self {
            name,
            kind,
            last_warn: None,
        }
    }

    /// Build the sinks enabled in `cfg`. File and syslog setup errors are
    /// startup errors.
    pub fn from_config(cfg: &EventsConfig) -> FerroResult<Vec<Sink>> {
        let mut sinks = Vec::new();
        if cfg.stdout {
            sinks.push(Sink::new("stdout", SinkKind::Stdout));
        }
        if !cfg.file.is_empty() {
            let file = FileSink::new(PathBuf::from(&cfg.file), cfg.file_max_bytes, cfg.file_keep)
                .map_err(|e| {
                FerroError::Config(format!("cannot open events file {:?}: {e}", cfg.file))
            })?;
            sinks.push(Sink::new("file", SinkKind::File(file)));
        }
        if !cfg.syslog.is_empty() {
            let syslog = SyslogSink::from_config(cfg)?;
            sinks.push(Sink::new("syslog", SinkKind::Syslog(Box::new(syslog))));
        }
        Ok(sinks)
    }

    /// Write one event. `line` is the event JSON plus a trailing newline.
    pub async fn write(&mut self, event: &SecurityEvent, line: &[u8]) {
        let result = match &mut self.kind {
            SinkKind::Stdout => write_stdout(line),
            SinkKind::File(f) => f.write(line),
            SinkKind::Syslog(s) => s.send_event(event, line).await,
            #[cfg(test)]
            SinkKind::Memory(lines) => {
                lines
                    .lock()
                    .unwrap()
                    .push(String::from_utf8_lossy(line).trim_end().to_string());
                Ok(())
            }
        };
        if let Err(e) = result {
            self.report(&e);
        }
    }

    /// Flush buffered output; called once per batch.
    pub fn flush(&mut self) {
        let result = match &mut self.kind {
            SinkKind::File(f) => f.flush(),
            _ => Ok(()),
        };
        if let Err(e) = result {
            self.report(&e);
        }
    }

    fn report(&mut self, error: &io::Error) {
        let now = Instant::now();
        if self
            .last_warn
            .is_none_or(|t| now.duration_since(t) >= WARN_INTERVAL)
        {
            self.last_warn = Some(now);
            tracing::warn!(sink = self.name, error = %error, "security event sink write failed; events may be lost for this sink");
        }
    }
}

/// One `write_all` of the whole line on a locked handle, so an event line
/// cannot interleave with a tracing line (tracing also writes whole lines).
fn write_stdout(line: &[u8]) -> io::Result<()> {
    let mut out = io::stdout().lock();
    out.write_all(line)
}

// ── File sink with size-based rotation ────────────────────────────────────────

pub struct FileSink {
    path: PathBuf,
    max_bytes: u64,
    keep: u32,
    file: Option<BufWriter<File>>,
    size: u64,
}

impl FileSink {
    pub fn new(path: PathBuf, max_bytes: u64, keep: u32) -> io::Result<Self> {
        let mut sink = Self {
            path,
            max_bytes,
            keep,
            file: None,
            size: 0,
        };
        sink.open()?;
        Ok(sink)
    }

    fn open(&mut self) -> io::Result<()> {
        if let Some(parent) = self.path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)?;
            }
        }
        let mut options = OpenOptions::new();
        options.create(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o640);
        }
        let file = options.open(&self.path)?;
        self.size = file.metadata()?.len();
        self.file = Some(BufWriter::new(file));
        Ok(())
    }

    pub fn write(&mut self, line: &[u8]) -> io::Result<()> {
        if self.file.is_none() {
            self.open()?;
        }
        if self.size > 0 && self.size + line.len() as u64 > self.max_bytes {
            self.rotate()?;
        }
        let file = self.file.as_mut().expect("opened above");
        if let Err(e) = file.write_all(line) {
            // Reopen on the next write instead of reusing a broken handle.
            self.file = None;
            return Err(e);
        }
        self.size += line.len() as u64;
        Ok(())
    }

    pub fn flush(&mut self) -> io::Result<()> {
        if let Some(file) = self.file.as_mut() {
            if let Err(e) = file.flush() {
                self.file = None;
                return Err(e);
            }
        }
        Ok(())
    }

    fn numbered(&self, n: u32) -> PathBuf {
        let mut name: OsString = self.path.clone().into_os_string();
        name.push(format!(".{n}"));
        PathBuf::from(name)
    }

    /// `events.jsonl` → `.1`, `.1` → `.2`, … the oldest (`.keep`) is deleted.
    fn rotate(&mut self) -> io::Result<()> {
        // Close first: an open file cannot be renamed on Windows.
        if let Some(mut file) = self.file.take() {
            let _ = file.flush();
        }
        let oldest = self.numbered(self.keep);
        if oldest.exists() {
            fs::remove_file(&oldest)?;
        }
        for n in (1..self.keep).rev() {
            let from = self.numbered(n);
            if from.exists() {
                fs::rename(&from, self.numbered(n + 1))?;
            }
        }
        fs::rename(&self.path, self.numbered(1))?;
        self.open()
    }
}

// ── Syslog (RFC 5424) ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyslogTransport {
    Udp,
    Tcp,
    Tls,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyslogTarget {
    pub transport: SyslogTransport,
    pub host: String,
    pub port: u16,
}

/// Parse `udp://host:port`, `tcp://host:port` or `tls://host:port`.
pub fn parse_syslog_url(raw: &str) -> Result<SyslogTarget, String> {
    let bad = |why: &str| {
        format!("syslog URL {raw:?} is invalid: {why} (expected udp://host:port, tcp://host:port or tls://host:port)")
    };
    let url = Url::parse(raw).map_err(|_| bad("not a URL"))?;
    let transport = match url.scheme() {
        "udp" => SyslogTransport::Udp,
        "tcp" => SyslogTransport::Tcp,
        "tls" => SyslogTransport::Tls,
        _ => return Err(bad("unsupported scheme")),
    };
    let host = url
        .host_str()
        .filter(|h| !h.is_empty())
        .ok_or_else(|| bad("missing host"))?;
    let port = url.port().ok_or_else(|| bad("missing port"))?;
    if !matches!(url.path(), "" | "/") || url.query().is_some() || url.fragment().is_some() {
        return Err(bad("unexpected path or query"));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(bad("credentials are not supported"));
    }
    Ok(SyslogTarget {
        transport,
        host: host.to_string(),
        port,
    })
}

/// Parse a syslog facility: a name (`auth`, `authpriv`, `local0`..`local7`, …)
/// or a number 0-23.
pub fn parse_facility(raw: &str) -> Result<u8, String> {
    let name = raw.trim().to_ascii_lowercase();
    let code = match name.as_str() {
        "kern" => 0,
        "user" => 1,
        "mail" => 2,
        "daemon" => 3,
        "auth" | "security" => 4,
        "syslog" => 5,
        "lpr" => 6,
        "news" => 7,
        "uucp" => 8,
        "cron" => 9,
        "authpriv" => 10,
        "ftp" => 11,
        "local0" => 16,
        "local1" => 17,
        "local2" => 18,
        "local3" => 19,
        "local4" => 20,
        "local5" => 21,
        "local6" => 22,
        "local7" => 23,
        other => match other.parse::<u8>() {
            Ok(n) if n <= 23 => n,
            _ => {
                return Err(format!(
                    "syslog_facility {raw:?} is invalid: use a name such as auth, authpriv, daemon or local0-local7, or a number 0-23"
                ))
            }
        },
    };
    Ok(code)
}

/// RFC 5424 severity for an event: failures are warnings (internal errors
/// `err`), successes informational, dropped-event reports `err`.
fn severity(event: &SecurityEvent) -> u8 {
    if event.event.action == Action::EventsDropped
        || event.event.reason == Some(Reason::InternalError)
    {
        3
    } else if event.event.outcome == Outcome::Failure {
        4
    } else {
        6
    }
}

/// Build one RFC 5424 message: `<PRI>1 TS HOST ferrowarden PID ACTION - JSON`.
pub fn format_syslog(facility: u8, hostname: &str, event: &SecurityEvent, json: &str) -> String {
    let pri = u16::from(facility) * 8 + u16::from(severity(event));
    format!(
        "<{pri}>1 {ts} {hostname} ferrowarden {pid} {msgid} - {json}",
        ts = event
            .timestamp
            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        pid = std::process::id(),
        msgid = event.event.action.as_str(),
    )
}

/// RFC 6587 octet-counting framing: `<length> <message>`.
pub fn octet_frame(message: &str) -> Vec<u8> {
    let mut out = format!("{} ", message.len()).into_bytes();
    out.extend_from_slice(message.as_bytes());
    out
}

/// A usable RFC 5424 HOSTNAME: printable ASCII without spaces, else `-`.
fn syslog_hostname() -> String {
    let raw = std::env::var("HOSTNAME")
        .ok()
        .or_else(|| fs::read_to_string("/etc/hostname").ok())
        .unwrap_or_default();
    let host = raw.trim();
    if host.is_empty() || host.len() > 255 || !host.bytes().all(|b| b.is_ascii_graphic()) {
        "-".to_string()
    } else {
        host.to_string()
    }
}

enum Conn {
    Udp(UdpSocket),
    Tcp(TcpStream),
    Tls(Box<TlsStream<TcpStream>>),
}

pub struct SyslogSink {
    target: SyslogTarget,
    facility: u8,
    hostname: String,
    tls: Option<TlsConnector>,
    conn: Option<Conn>,
    next_attempt: Instant,
    backoff: Duration,
}

impl SyslogSink {
    pub fn from_config(cfg: &EventsConfig) -> FerroResult<Self> {
        let target = parse_syslog_url(&cfg.syslog).map_err(FerroError::Config)?;
        let facility = parse_facility(&cfg.syslog_facility).map_err(FerroError::Config)?;
        let ca_file = (!cfg.syslog_ca_file.is_empty()).then(|| Path::new(&cfg.syslog_ca_file));
        Self::new(target, facility, ca_file)
    }

    pub fn new(target: SyslogTarget, facility: u8, ca_file: Option<&Path>) -> FerroResult<Self> {
        let tls = match target.transport {
            SyslogTransport::Tls => Some(tls_connector(ca_file)?),
            _ => None,
        };
        Ok(Self {
            target,
            facility,
            hostname: syslog_hostname(),
            tls,
            conn: None,
            next_attempt: Instant::now(),
            backoff: BACKOFF_MIN,
        })
    }

    async fn send_event(&mut self, event: &SecurityEvent, line: &[u8]) -> io::Result<()> {
        let json = String::from_utf8_lossy(line.strip_suffix(b"\n").unwrap_or(line));
        let message = format_syslog(self.facility, &self.hostname, event, &json);
        let frame = match self.target.transport {
            SyslogTransport::Udp => message.into_bytes(),
            SyslogTransport::Tcp | SyslogTransport::Tls => octet_frame(&message),
        };
        self.send(&frame).await
    }

    /// Send one frame. A stale connection is replaced and the frame resent
    /// once; connection attempts back off exponentially (1 s .. 60 s).
    async fn send(&mut self, frame: &[u8]) -> io::Result<()> {
        for attempt in 0..2 {
            let had_conn = self.conn.is_some();
            if !had_conn {
                self.connect().await?;
            }
            match self.write_conn(frame).await {
                Ok(()) => return Ok(()),
                Err(e) => {
                    self.conn = None;
                    if had_conn && attempt == 0 {
                        continue; // stale connection: retry on a fresh one
                    }
                    self.fail();
                    return Err(e);
                }
            }
        }
        unreachable!("loop returns on both attempts")
    }

    fn fail(&mut self) {
        self.next_attempt = Instant::now() + self.backoff;
        self.backoff = (self.backoff * 2).min(BACKOFF_MAX);
    }

    async fn connect(&mut self) -> io::Result<()> {
        if Instant::now() < self.next_attempt {
            return Err(io::Error::other("reconnect backoff in progress"));
        }
        match timeout(NET_TIMEOUT, self.open_conn()).await {
            Ok(Ok(conn)) => {
                self.conn = Some(conn);
                self.backoff = BACKOFF_MIN;
                Ok(())
            }
            Ok(Err(e)) => {
                self.fail();
                Err(e)
            }
            Err(_) => {
                self.fail();
                Err(io::Error::new(io::ErrorKind::TimedOut, "connect timed out"))
            }
        }
    }

    async fn open_conn(&self) -> io::Result<Conn> {
        let host = self.target.host.trim_matches(['[', ']']);
        let addr = (host, self.target.port);
        match self.target.transport {
            SyslogTransport::Udp => {
                let remote = tokio::net::lookup_host(addr)
                    .await?
                    .next()
                    .ok_or_else(|| io::Error::other("syslog host did not resolve"))?;
                let local = if remote.is_ipv4() {
                    "0.0.0.0:0"
                } else {
                    "[::]:0"
                };
                let socket = UdpSocket::bind(local).await?;
                socket.connect(remote).await?;
                Ok(Conn::Udp(socket))
            }
            SyslogTransport::Tcp => Ok(Conn::Tcp(TcpStream::connect(addr).await?)),
            SyslogTransport::Tls => {
                let stream = TcpStream::connect(addr).await?;
                let name = ServerName::try_from(host.to_string())
                    .map_err(|_| io::Error::other("syslog host is not a valid TLS server name"))?;
                let connector = self.tls.as_ref().expect("built for tls transport");
                Ok(Conn::Tls(Box::new(connector.connect(name, stream).await?)))
            }
        }
    }

    async fn write_conn(&mut self, frame: &[u8]) -> io::Result<()> {
        let result = timeout(NET_TIMEOUT, async {
            match self.conn.as_mut().expect("connected") {
                Conn::Udp(s) => s.send(frame).await.map(|_| ()),
                Conn::Tcp(s) => s.write_all(frame).await,
                Conn::Tls(s) => {
                    s.write_all(frame).await?;
                    s.flush().await
                }
            }
        })
        .await;
        result.unwrap_or_else(|_| Err(io::Error::new(io::ErrorKind::TimedOut, "write timed out")))
    }
}

/// TLS client config: webpki roots plus an optional operator CA bundle (PEM).
/// Hostname verification is always on.
fn tls_connector(ca_file: Option<&Path>) -> FerroResult<TlsConnector> {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    if let Some(path) = ca_file {
        let mut added = 0;
        for cert in CertificateDer::pem_file_iter(path)
            .map_err(|e| FerroError::Config(format!("cannot read syslog_ca_file {path:?}: {e}")))?
        {
            let cert = cert.map_err(|e| {
                FerroError::Config(format!(
                    "invalid certificate in syslog_ca_file {path:?}: {e}"
                ))
            })?;
            roots.add(cert).map_err(|e| {
                FerroError::Config(format!(
                    "invalid certificate in syslog_ca_file {path:?}: {e}"
                ))
            })?;
            added += 1;
        }
        if added == 0 {
            return Err(FerroError::Config(format!(
                "syslog_ca_file {path:?} contains no certificates"
            )));
        }
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| FerroError::Internal(format!("TLS setup failed: {e}")))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(TlsConnector::from(Arc::new(config)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    use tokio::io::AsyncReadExt;
    use tokio::net::TcpListener;

    fn event(action: Action) -> SecurityEvent {
        SecurityEvent::new(action)
    }

    fn line(e: &SecurityEvent) -> Vec<u8> {
        let mut l = serde_json::to_vec(e).unwrap();
        l.push(b'\n');
        l
    }

    // ── file ──

    #[test]
    fn file_sink_appends_and_creates_parent_dirs() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("nested/dir/events.jsonl");
        let mut sink = FileSink::new(path.clone(), 1 << 20, 3).unwrap();
        sink.write(b"one\n").unwrap();
        sink.write(b"two\n").unwrap();
        sink.flush().unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "one\ntwo\n");

        // A second sink on the same path appends instead of truncating.
        let mut again = FileSink::new(path.clone(), 1 << 20, 3).unwrap();
        again.write(b"three\n").unwrap();
        again.flush().unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "one\ntwo\nthree\n");
    }

    #[cfg(unix)]
    #[test]
    fn file_sink_creates_file_with_mode_0640() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().unwrap();
        let path = dir.path().join("events.jsonl");
        let _sink = FileSink::new(path.clone(), 1024, 2).unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o640);
    }

    #[test]
    fn file_sink_rotates_by_size_and_keeps_n_files() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("events.jsonl");
        // 10-byte lines, rotate when a file would exceed 25 bytes: 2 lines each.
        let mut sink = FileSink::new(path.clone(), 25, 3).unwrap();
        for i in 0..12 {
            sink.write(format!("line-{i:04}\n").as_bytes()).unwrap();
        }
        sink.flush().unwrap();

        let read = |p: &Path| fs::read_to_string(p).unwrap();
        let n = |i: u32| {
            let mut s = path.clone().into_os_string();
            s.push(format!(".{i}"));
            PathBuf::from(s)
        };
        // Newest data in the base file, older data in .1, .2, .3.
        assert_eq!(read(&path), "line-0010\nline-0011\n");
        assert_eq!(read(&n(1)), "line-0008\nline-0009\n");
        assert_eq!(read(&n(2)), "line-0006\nline-0007\n");
        assert_eq!(read(&n(3)), "line-0004\nline-0005\n");
        // keep = 3: nothing older survives.
        assert!(!n(4).exists());
    }

    #[test]
    fn file_sink_with_keep_one_replaces_the_single_backup() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("e.jsonl");
        let mut sink = FileSink::new(path.clone(), 10, 1).unwrap();
        for i in 0..4 {
            sink.write(format!("{i:08}\n").as_bytes()).unwrap();
        }
        sink.flush().unwrap();
        let mut one = path.clone().into_os_string();
        one.push(".1");
        assert_eq!(fs::read_to_string(&one).unwrap(), "00000002\n");
        assert_eq!(fs::read_to_string(&path).unwrap(), "00000003\n");
    }

    #[test]
    fn file_sink_open_failure_is_an_error_not_a_panic() {
        let dir = tempdir().unwrap();
        // A directory where the file should be.
        assert!(FileSink::new(dir.path().to_path_buf(), 1024, 2).is_err());
    }

    // ── syslog formatting ──

    #[test]
    fn syslog_message_is_rfc5424() {
        let e = event(Action::AgentAuth).reason(Reason::InvalidKey);
        let json = serde_json::to_string(&e).unwrap();
        let msg = format_syslog(4, "host1", &e, &json);
        // auth(4)*8 + warning(4) = 36
        assert!(msg.starts_with("<36>1 "), "{msg}");
        let parts: Vec<&str> = msg.splitn(8, ' ').collect();
        assert!(parts[1].ends_with('Z'));
        assert_eq!(parts[2], "host1");
        assert_eq!(parts[3], "ferrowarden");
        assert_eq!(parts[4], std::process::id().to_string());
        assert_eq!(parts[5], "agent_auth"); // MSGID = action
        assert_eq!(parts[6], "-"); // no structured data
        assert_eq!(parts[7], json);
    }

    #[test]
    fn syslog_severity_follows_outcome() {
        let sev = |e: &SecurityEvent| severity(e);
        assert_eq!(sev(&event(Action::Forward)), 6);
        assert_eq!(
            sev(&event(Action::Forward)
                .outcome(Outcome::Failure)
                .reason(Reason::TargetBlocked)),
            4
        );
        assert_eq!(sev(&event(Action::EventsDropped)), 3);
        assert_eq!(
            sev(&event(Action::Forward)
                .outcome(Outcome::Failure)
                .reason(Reason::InternalError)),
            3
        );
    }

    #[test]
    fn octet_counting_counts_bytes_not_chars() {
        let framed = octet_frame("héllo");
        assert_eq!(framed, "6 héllo".as_bytes());
        assert_eq!(octet_frame(""), b"0 ");
    }

    #[test]
    fn syslog_url_parsing() {
        assert_eq!(
            parse_syslog_url("tls://siem.example:6514").unwrap(),
            SyslogTarget {
                transport: SyslogTransport::Tls,
                host: "siem.example".into(),
                port: 6514
            }
        );
        assert_eq!(
            parse_syslog_url("udp://10.0.0.5:514").unwrap().transport,
            SyslogTransport::Udp
        );
        assert_eq!(parse_syslog_url("tcp://[::1]:514").unwrap().host, "[::1]");
        for bad in [
            "http://h:514",
            "udp://h",
            "tcp://:514",
            "siem.example:514",
            "tcp://h:514/path",
            "tcp://u:p@h:514",
            "",
        ] {
            assert!(parse_syslog_url(bad).is_err(), "{bad:?} must be rejected");
        }
    }

    #[test]
    fn facility_parsing() {
        assert_eq!(parse_facility("auth").unwrap(), 4);
        assert_eq!(parse_facility("AUTHPRIV").unwrap(), 10);
        assert_eq!(parse_facility("local7").unwrap(), 23);
        assert_eq!(parse_facility("16").unwrap(), 16);
        for bad in ["", "24", "authh", "-1"] {
            assert!(parse_facility(bad).is_err(), "{bad:?}");
        }
    }

    // ── syslog transports against local listeners ──

    #[tokio::test]
    async fn syslog_tcp_uses_octet_counting_and_reconnects() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let target = SyslogTarget {
            transport: SyslogTransport::Tcp,
            host: "127.0.0.1".into(),
            port,
        };
        let mut sink = SyslogSink::new(target, 4, None).unwrap();

        let e = event(Action::Startup);
        let l = line(&e);
        sink.send_event(&e, &l).await.unwrap();

        let (mut conn, _) = listener.accept().await.unwrap();
        let mut buf = vec![0u8; 8192];
        let n = conn.read(&mut buf).await.unwrap();
        let text = String::from_utf8(buf[..n].to_vec()).unwrap();
        let (len, rest) = text.split_once(' ').unwrap();
        assert_eq!(len.parse::<usize>().unwrap(), rest.len(), "octet count");
        assert!(rest.starts_with("<38>1 "), "auth + info: {rest}"); // 4*8+6
        assert!(rest.contains(" ferrowarden "));
        assert!(rest.contains(" startup - {"));

        // Server closes; the sink notices on a later write and reconnects.
        drop(conn);
        let mut got = None;
        for _ in 0..5 {
            let _ = sink.send_event(&e, &l).await;
            if let Ok(Ok((c, _))) = timeout(Duration::from_millis(300), listener.accept()).await {
                got = Some(c);
                break;
            }
        }
        assert!(got.is_some(), "sink did not reconnect");
    }

    #[tokio::test]
    async fn syslog_udp_sends_one_datagram_per_event() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = socket.local_addr().unwrap().port();
        let target = SyslogTarget {
            transport: SyslogTransport::Udp,
            host: "127.0.0.1".into(),
            port,
        };
        let mut sink = SyslogSink::new(target, 10, None).unwrap();
        let e = event(Action::AdminAuth).reason(Reason::InvalidAdminKey);
        sink.send_event(&e, &line(&e)).await.unwrap();

        let mut buf = vec![0u8; 8192];
        let n = timeout(Duration::from_secs(2), socket.recv(&mut buf))
            .await
            .unwrap()
            .unwrap();
        let text = String::from_utf8(buf[..n].to_vec()).unwrap();
        // authpriv(10)*8 + warning(4) = 84; UDP has no octet-count prefix.
        assert!(text.starts_with("<84>1 "), "{text}");
        assert!(text.contains(" admin_auth - {"));
        assert!(text.ends_with('}'), "no trailing newline");
    }

    #[tokio::test]
    async fn syslog_connect_failure_backs_off() {
        // A port nothing listens on.
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        drop(l);
        let mut sink = SyslogSink::new(
            SyslogTarget {
                transport: SyslogTransport::Tcp,
                host: "127.0.0.1".into(),
                port,
            },
            4,
            None,
        )
        .unwrap();
        let e = event(Action::Startup);
        assert!(sink.send_event(&e, &line(&e)).await.is_err());
        let err = sink.send_event(&e, &line(&e)).await.unwrap_err();
        assert!(err.to_string().contains("backoff"), "{err}");
    }

    #[test]
    fn tls_connector_needs_a_valid_ca_file() {
        assert!(tls_connector(None).is_ok());
        let dir = tempdir().unwrap();
        let empty = dir.path().join("ca.pem");
        fs::write(&empty, "not a certificate").unwrap();
        assert!(tls_connector(Some(&empty)).is_err());
        assert!(tls_connector(Some(&dir.path().join("missing.pem"))).is_err());
    }

    // ── sink wrapper ──

    #[tokio::test]
    async fn failing_sink_warns_at_most_once_per_interval() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("e.jsonl");
        let mut file = FileSink::new(path.clone(), 1 << 20, 2).unwrap();
        // Break the handle: point the sink at a path that cannot be opened.
        file.file = None;
        file.path = dir.path().to_path_buf();
        let mut sink = Sink::new("file", SinkKind::File(file));
        let e = event(Action::Startup);
        sink.write(&e, &line(&e)).await;
        let first = sink.last_warn.expect("first failure is reported");
        sink.write(&e, &line(&e)).await;
        assert_eq!(sink.last_warn, Some(first), "second failure is suppressed");
    }
}
