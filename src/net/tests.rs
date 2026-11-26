use super::*;
use crate::config::UnlockMode;

fn cfg(allowed: &str, allow_private: bool) -> Config {
    // Vaultwarden at 127.0.0.1:8087, the endpoint agents may never reach.
    let vault = crate::config::VaultConfig {
        url: "http://127.0.0.1:8087".to_string(),
        ..Default::default()
    };
    Config {
        bind_addr: "127.0.0.1:3000".to_string(),
        bw_serve_url: None,
        unlock_mode: UnlockMode::Manual,
        unlock_file: None,
        admin_key: "a".repeat(32).into(),
        keys_file: None,
        tls_enabled: false,
        tls_cert_file: None,
        tls_key_file: None,
        allow_private_targets: allow_private,
        allowed_targets: allowed.to_string(),
        enforce_credential_hosts: true,
        refresh_interval_secs: 0,
        max_response_bytes: 1024,
        forward_timeout_secs: 30,
        trusted_proxies: String::new(),
        api_prefix: String::new(),
        agent_rate_limit_per_minute: 120,
        agent_rate_limit_burst: 20,
        admin_rate_limit_per_minute: 30,
        admin_rate_limit_burst: 5,
        events: Default::default(),
        ui: Default::default(),
        notify: Default::default(),
        vault,
        metrics: Default::default(),
        sessions: Default::default(),
    }
}

#[test]
fn cidr_parse_and_contains() {
    let c = Cidr::parse("192.168.1.0/24").unwrap();
    assert!(c.contains(&"192.168.1.77".parse().unwrap()));
    assert!(!c.contains(&"192.168.2.1".parse().unwrap()));
    let single = Cidr::parse("10.0.0.5").unwrap();
    assert!(single.contains(&"10.0.0.5".parse().unwrap()));
    assert!(!single.contains(&"10.0.0.6".parse().unwrap()));
    assert!(Cidr::parse("10.0.0.0/33").is_none());
    assert!(Cidr::parse("nas.lan").is_none());
    let v6 = Cidr::parse("fd00::/8").unwrap();
    assert!(v6.contains(&"fd12::1".parse().unwrap()));
}

#[test]
fn mapped_ipv4_is_classified_as_ipv4() {
    let ip: IpAddr = "::ffff:127.0.0.1".parse().unwrap();
    assert_eq!(classify(ip), AddrClass::Internal);
}

#[test]
fn classification() {
    for s in [
        "127.0.0.1",
        "10.1.2.3",
        "172.20.0.2",
        "192.168.0.1",
        "169.254.169.254",
        "100.64.0.1",
        "::1",
        "fd00::1",
        "fe80::1",
    ] {
        assert_eq!(classify(s.parse().unwrap()), AddrClass::Internal, "{s}");
    }
    for s in ["0.0.0.0", "255.255.255.255", "224.0.0.1", "::"] {
        assert_eq!(classify(s.parse().unwrap()), AddrClass::Forbidden, "{s}");
    }
    for s in ["1.1.1.1", "93.184.216.34", "2606:4700::1111"] {
        assert_eq!(classify(s.parse().unwrap()), AddrClass::Public, "{s}");
    }
}

#[tokio::test]
async fn blocks_vault_backend_even_when_private_allowed() {
    let p = TargetPolicy::from_config(&cfg("127.0.0.0/8", true));
    let url = Url::parse("http://127.0.0.1:8087/identity/x").unwrap();
    assert!(matches!(
        p.check_url(&url).await,
        Err(FerroError::TargetBlocked(_))
    ));
    // Same IP, different port is a different service and is allowed here.
    let other = Url::parse("http://127.0.0.1:9000/").unwrap();
    assert!(p.check_url(&other).await.is_ok());
}

#[tokio::test]
async fn blocks_vault_backend_by_host_name() {
    let mut c = cfg("", true);
    c.vault.url = "http://vaultwarden:8087".to_string();
    let p = TargetPolicy::from_config(&c);
    let url = Url::parse("http://VAULTWARDEN:8087/identity/x").unwrap();
    assert!(matches!(
        p.check_url(&url).await,
        Err(FerroError::TargetBlocked(_))
    ));
}

#[tokio::test]
async fn private_ip_blocked_by_default_and_allowed_by_cidr() {
    let p = TargetPolicy::from_config(&cfg("", false));
    let url = Url::parse("http://192.168.1.10/api").unwrap();
    assert!(matches!(
        p.check_url(&url).await,
        Err(FerroError::TargetBlocked(_))
    ));
    let meta = Url::parse("http://169.254.169.254/latest/meta-data").unwrap();
    assert!(matches!(
        p.check_url(&meta).await,
        Err(FerroError::TargetBlocked(_))
    ));

    let p = TargetPolicy::from_config(&cfg("192.168.1.0/24", false));
    assert!(p.check_url(&url).await.is_ok());
}

#[tokio::test]
async fn rejects_non_http_scheme() {
    let p = TargetPolicy::from_config(&cfg("", false));
    let url = Url::parse("file:///etc/passwd").unwrap();
    assert!(matches!(
        p.check_url(&url).await,
        Err(FerroError::InvalidTargetUrl(_))
    ));
}

#[tokio::test]
async fn resolver_blocks_localhost_name() {
    let p = Arc::new(TargetPolicy::from_config(&cfg("", false)));
    let r = p.resolver(80);
    let err = match r.resolve("localhost".parse().unwrap()).await {
        Ok(_) => panic!("localhost must be blocked"),
        Err(e) => e,
    };
    assert!(err.downcast_ref::<BlockedTarget>().is_some());
}

#[tokio::test]
async fn resolver_allows_named_internal_host() {
    let p = Arc::new(TargetPolicy::from_config(&cfg("localhost", false)));
    let r = p.resolver(80);
    assert!(r.resolve("localhost".parse().unwrap()).await.is_ok());
}

// ── Notifier endpoints are off-limits to agents ───────────────────────────

fn notify_cfg(allowed: &str, allow_private: bool, urls: [&str; 3]) -> Config {
    let mut c = cfg(allowed, allow_private);
    c.notify.gotify_url = urls[0].to_string();
    c.notify.ntfy_url = urls[1].to_string();
    c.notify.webhook_url = urls[2].to_string();
    c.notify.allow_http = true;
    c
}

fn blocked_with(err: FerroResult<()>) -> String {
    match err {
        Err(FerroError::TargetBlocked(m)) => m,
        other => panic!("expected TargetBlocked, got {other:?}"),
    }
}

#[tokio::test]
async fn notifier_host_names_are_refused_on_every_port_even_when_listed_as_allowed() {
    let c = notify_cfg(
        "gotify.lan,ntfy.lan,notify-sink,mock-api",
        true,
        [
            "http://gotify.lan:8080",
            "https://ntfy.lan/ferrowarden",
            "http://notify-sink:7777/notify",
        ],
    );
    let p = TargetPolicy::from_config(&c);
    for url in [
        "http://gotify.lan:8080/message",
        "http://gotify.lan:9999/anything",
        "https://GOTIFY.lan/",
        "https://ntfy.lan/ferrowarden",
        "http://ntfy.lan:80/other",
        "http://notify-sink:7777/notify",
        "http://notify-sink:7777/__requests__",
        "http://notify-sink/",
    ] {
        let m = blocked_with(p.check_url(&Url::parse(url).unwrap()).await);
        assert!(m.contains("notification endpoint"), "{url}: {m}");
        assert!(!m.contains("gotify") && !m.contains("notify-sink"), "{m}");
    }
    // The host next to it (same address, other name) is not affected.
    for url in [
        "http://mock-api:7777/api/check",
        "http://other.example.com/",
    ] {
        assert!(
            p.check_url(&Url::parse(url).unwrap()).await.is_ok(),
            "{url}"
        );
    }
}

#[tokio::test]
async fn the_resolver_path_refuses_notifier_names_too() {
    let c = notify_cfg("localhost", true, ["", "", "http://localhost:9999/notify"]);
    let p = Arc::new(TargetPolicy::from_config(&c));
    for port in [9999, 80] {
        let r = p.resolver(port);
        let err = match r.resolve("LocalHost".parse().unwrap()).await {
            Ok(_) => panic!("the notifier host must be refused"),
            Err(e) => e,
        };
        let blocked = err.downcast_ref::<BlockedTarget>().expect("BlockedTarget");
        assert!(blocked.0.contains("notification endpoint"), "{blocked}");
    }
    // Without the notifier, the same allowed name resolves.
    let p = Arc::new(TargetPolicy::from_config(&cfg("localhost", true)));
    assert!(p
        .resolver(9999)
        .resolve("localhost".parse().unwrap())
        .await
        .is_ok());
}

#[tokio::test]
async fn a_notifier_ip_literal_is_refused_on_its_port_only() {
    let c = notify_cfg(
        "",
        true,
        ["", "http://127.0.0.1:9999/topic", "http://[::1]:7777/n"],
    );
    let p = TargetPolicy::from_config(&c);
    for url in ["http://127.0.0.1:9999/message", "http://[::1]:7777/x"] {
        blocked_with(p.check_url(&Url::parse(url).unwrap()).await);
    }
    // Another service on the same address is a different target.
    for url in [
        "http://127.0.0.1:9998/",
        "http://127.0.0.1/",
        "http://[::1]:7778/",
    ] {
        assert!(
            p.check_url(&Url::parse(url).unwrap()).await.is_ok(),
            "{url}"
        );
    }
}

#[tokio::test]
async fn an_ip_literal_that_a_notifier_name_resolves_to_is_refused() {
    // `localhost` resolves to loopback addresses; the notifier is there on 9999.
    let c = notify_cfg("", true, ["", "", "http://localhost:9999/n"]);
    let p = TargetPolicy::from_config(&c);
    let resolved: Vec<IpAddr> = tokio::net::lookup_host(("localhost", 9999))
        .await
        .unwrap()
        .map(|a| a.ip())
        .collect();
    assert!(!resolved.is_empty());
    for ip in resolved {
        let url = match ip {
            IpAddr::V4(v4) => format!("http://{v4}:9999/x"),
            IpAddr::V6(v6) => format!("http://[{v6}]:9999/x"),
        };
        blocked_with(p.check_url(&Url::parse(&url).unwrap()).await);
    }
}

#[test]
fn an_address_shared_with_a_notifier_is_the_operators_call_by_name_only() {
    // notify-sink and mock-api share 10.0.0.5:7777 (compose aliases). The
    // operator listed mock-api, so that name still works; any other way
    // to the same address and port is refused.
    let mut c = notify_cfg("mock-api", true, ["", "", "http://notify-sink:7777/n"]);
    c.allow_private_targets = false;
    let p = TargetPolicy::from_config(&c);
    let shared: IpAddr = "10.0.0.5".parse().unwrap();
    let denied = DeniedAddrs {
        vault: Vec::new(),
        notifiers: vec![(shared, 7777)],
    };
    assert!(p.check_ip("mock-api", shared, 7777, &denied).is_ok());
    assert!(p.check_ip("mock-api", shared, 7778, &denied).is_ok());
    let m = p
        .check_ip("notify-sink", shared, 7777, &denied)
        .unwrap_err();
    assert!(m.contains("notification endpoint"), "{m}");
    let m = p.check_ip("10.0.0.5", shared, 7777, &denied).unwrap_err();
    assert!(m.contains("notification endpoint"), "{m}");
    // A name that is not listed falls to the private-address rule anyway.
    assert!(p.check_ip("evil.example", shared, 7777, &denied).is_err());
    // Even listed, the notifier's own name never passes.
    let c = notify_cfg(
        "mock-api,notify-sink",
        false,
        ["", "", "http://notify-sink:7777/n"],
    );
    let p = TargetPolicy::from_config(&c);
    assert!(p.check_ip("notify-sink", shared, 1234, &denied).is_err());
}

#[tokio::test]
async fn without_a_notifier_nothing_extra_is_denied() {
    let p = TargetPolicy::from_config(&cfg("notify-sink", true));
    assert!(p
        .check_url(&Url::parse("http://notify-sink:7777/").unwrap())
        .await
        .is_ok());
}

#[test]
fn client_ip_ignores_xff_from_untrusted_peer() {
    let peer: IpAddr = "203.0.113.9".parse().unwrap();
    assert_eq!(client_ip(peer, Some("1.2.3.4"), &[]), peer);
}

#[test]
fn client_ip_uses_xff_from_trusted_proxy() {
    let trusted = vec![Cidr::parse("10.0.0.0/8").unwrap()];
    let peer: IpAddr = "10.0.0.2".parse().unwrap();
    // Leftmost entry is client-controlled; take the rightmost untrusted.
    let ip = client_ip(peer, Some("6.6.6.6, 198.51.100.7, 10.0.0.3"), &trusted);
    assert_eq!(ip, "198.51.100.7".parse::<IpAddr>().unwrap());
    assert_eq!(client_ip(peer, None, &trusted), peer);
}
