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
