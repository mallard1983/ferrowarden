use super::*;

fn base_config(mode: UnlockMode) -> Config {
    Config {
        bind_addr: "127.0.0.1:3000".to_string(),
        bw_serve_url: None,
        unlock_mode: mode,
        unlock_file: None,
        admin_key: "a".repeat(32).into(),
        keys_file: None,
        tls_enabled: false,
        tls_cert_file: None,
        tls_key_file: None,
        allow_private_targets: false,
        allowed_targets: String::new(),
        enforce_credential_hosts: true,
        refresh_interval_secs: 300,
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
        vault: VaultConfig {
            credentials: vault_creds(Some("test-id"), Some("test-secret")),
            ..Default::default()
        },
        metrics: Default::default(),
        sessions: Default::default(),
        approval: Default::default(),
    }
}

#[test]
fn events_defaults_match_the_documentation() {
    let e = EventsConfig::default();
    assert!(e.stdout);
    assert_eq!(e.buffer_size, 1000);
    assert_eq!(e.queue_size, 10_000);
    assert!(e.file.is_empty() && e.syslog.is_empty() && e.syslog_ca_file.is_empty());
    assert_eq!(e.file_max_bytes, 52_428_800);
    assert_eq!(e.file_keep, 10);
    assert_eq!(e.syslog_facility, "auth");
    assert_eq!(e.enabled_sinks(), vec!["stdout"]);
}

#[test]
fn the_default_backend_needs_its_settings_and_the_error_says_where_to_look() {
    let mut cfg = base_config(UnlockMode::Manual);
    cfg.vault = VaultConfig::default();
    let err = cfg.validate().unwrap_err().to_string();
    assert!(err.contains(ENV_VAULT_CLIENT_ID), "{err}");
    assert!(err.contains(ENV_VAULT_CLIENT_SECRET), "{err}");
    assert!(err.contains("vault.url"), "{err}");
    assert!(err.contains("docs/native-vault.md"), "{err}");
    assert!(!err.contains("bw-serve"), "{err}");
    cfg.vault.credentials = vault_creds(Some("i"), Some("s"));
    assert!(cfg.validate().is_ok());
}

/// Parse `[vault]` the way startup does: from a TOML file's text.
fn from_toml(toml: &str) -> Result<Config, String> {
    config::Config::builder()
        .add_source(config::File::from_str(toml, config::FileFormat::Toml))
        .build()
        .unwrap()
        .try_deserialize()
        .map_err(|e| e.to_string())
}

/// Parse the way startup does: from `FERROWARDEN_*` variables.
fn from_env(vars: &[(&str, &str)]) -> Result<Config, String> {
    let env = vars
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect::<std::collections::HashMap<_, _>>();
    config::Config::builder()
        .add_source(
            config::Environment::with_prefix("FERROWARDEN")
                .prefix_separator("_")
                .separator("__")
                .ignore_empty(true)
                .source(Some(env)),
        )
        .build()
        .unwrap()
        .try_deserialize()
        .map_err(|e| e.to_string())
}

#[test]
fn the_removed_bw_serve_backend_is_a_startup_error_with_a_pointer() {
    // Direct, from a config file and from the environment: never a silent
    // fallback to native.
    let direct = serde_json::from_str::<VaultConfig>(r#"{"backend":"bw-serve"}"#)
        .unwrap_err()
        .to_string();
    let file = from_toml(
        r#"unlock_mode = "manual"
[vault]
backend = "bw-serve"
"#,
    )
    .unwrap_err();
    let env = from_env(&[
        ("FERROWARDEN_UNLOCK_MODE", "manual"),
        ("FERROWARDEN_VAULT__BACKEND", "bw-serve"),
    ])
    .unwrap_err();
    for err in [direct, file, env] {
        assert!(err.contains("removed in 0.3.0"), "{err}");
        assert!(
            err.contains("docs/native-vault.md#upgrading-from-bw-serve"),
            "{err}"
        );
    }
}

#[test]
fn native_is_the_only_accepted_backend_value() {
    let v: VaultConfig = serde_json::from_str(r#"{"backend":"native"}"#).unwrap();
    assert_eq!(v.backend, VaultBackend::Native);
    for bad in ["nope", "Native", "bw_serve", ""] {
        let err = serde_json::from_str::<VaultConfig>(&format!(r#"{{"backend":"{bad}"}}"#))
            .unwrap_err()
            .to_string();
        assert!(err.contains("vault.backend"), "{bad}: {err}");
        assert!(!err.contains("removed in 0.3.0"), "{bad}: {err}");
    }
    let cfg = from_toml(
        r#"unlock_mode = "manual"
[vault]
backend = "native"
"#,
    )
    .unwrap();
    assert_eq!(cfg.vault.backend, VaultBackend::Native);
}

#[test]
fn a_leftover_bw_serve_url_is_a_warning_not_an_error() {
    // From a file and from the environment it is read, so that it can be warned about.
    let cfg = from_toml(
        r#"unlock_mode = "manual"
bw_serve_url = "http://bw-serve:8087"
"#,
    )
    .unwrap();
    assert!(cfg.bw_serve_url.is_some());
    let cfg = from_env(&[
        ("FERROWARDEN_UNLOCK_MODE", "manual"),
        ("FERROWARDEN_BW_SERVE_URL", "http://bw-serve:8087"),
    ])
    .unwrap();
    assert!(cfg.bw_serve_url.is_some());
    assert!(from_toml(r#"unlock_mode = "manual""#)
        .unwrap()
        .bw_serve_url
        .is_none());

    let mut base = base_config(UnlockMode::Manual);
    assert!(base.vault.validate(false).unwrap().is_empty());
    let w = base.vault.validate(true).unwrap();
    assert_eq!(w.len(), 1);
    assert!(
        w[0].contains("bw_serve_url") && w[0].contains("ignored") && w[0].contains("0.3.0"),
        "{w:?}"
    );
    // And the whole configuration still validates with it set.
    base.bw_serve_url = Some("http://bw-serve:8087".to_string());
    assert!(base.validate().is_ok());
}

#[test]
fn events_section_deserializes_partially() {
    let cfg: Config = config::Config::builder()
        .add_source(config::File::from_str(
            "unlock_mode = \"manual\"
[events]
file = \"/tmp/e.jsonl\"
file_keep = 3
",
            config::FileFormat::Toml,
        ))
        .build()
        .unwrap()
        .try_deserialize()
        .unwrap();
    assert_eq!(cfg.events.file, "/tmp/e.jsonl");
    assert_eq!(cfg.events.file_keep, 3);
    assert!(cfg.events.stdout, "unspecified keys keep their defaults");
    assert_eq!(cfg.events.buffer_size, 1000);
}

#[test]
fn invalid_events_settings_fail_validation() {
    type Tweak = Box<dyn Fn(&mut EventsConfig)>;
    let bad: Vec<Tweak> = vec![
        Box::new(|e| e.buffer_size = 0),
        Box::new(|e| e.queue_size = 0),
        Box::new(|e| {
            e.file = "/tmp/e.jsonl".into();
            e.file_keep = 0;
        }),
        Box::new(|e| {
            e.file = "/tmp/e.jsonl".into();
            e.file_max_bytes = 0;
        }),
        Box::new(|e| e.syslog = "http://siem:514".into()),
        Box::new(|e| e.syslog = "udp://siem".into()),
        Box::new(|e| {
            e.syslog = "udp://siem:514".into();
            e.syslog_facility = "nope".into();
        }),
        Box::new(|e| {
            e.syslog = "tcp://siem:514".into();
            e.syslog_ca_file = "/ca.pem".into();
        }),
    ];
    for (i, tweak) in bad.iter().enumerate() {
        let mut cfg = base_config(UnlockMode::Manual);
        tweak(&mut cfg.events);
        assert!(cfg.validate().is_err(), "case {i} should fail");
    }
    let mut ok = base_config(UnlockMode::Manual);
    ok.events.syslog = "tls://siem.example:6514".into();
    ok.events.syslog_ca_file = "/ca.pem".into();
    ok.events.file = "/tmp/e.jsonl".into();
    assert!(ok.validate().is_ok());
}

#[test]
fn zero_rate_limit_fails() {
    let mut cfg = base_config(UnlockMode::Manual);
    cfg.agent_rate_limit_burst = 0;
    assert!(cfg
        .validate()
        .unwrap_err()
        .to_string()
        .contains("rate_limit"));
}

#[test]
fn api_prefix_normalization() {
    assert_eq!(normalize_api_prefix("").unwrap(), "");
    assert_eq!(normalize_api_prefix("/").unwrap(), "");
    assert_eq!(normalize_api_prefix("k7f3q9").unwrap(), "/k7f3q9");
    assert_eq!(normalize_api_prefix("/a-b/c_d/").unwrap(), "/a-b/c_d");
    for bad in ["/a//b", "/a b", "/a?b", "/../x", "/health", "/a.b"] {
        assert!(normalize_api_prefix(bad).is_err(), "{bad} must be rejected");
    }
}

#[test]
fn invalid_trusted_proxy_fails() {
    let mut cfg = base_config(UnlockMode::Manual);
    cfg.trusted_proxies = "10.0.0.0/8, not-an-ip".to_string();
    let err = cfg.validate().unwrap_err();
    assert!(err.to_string().contains("trusted_proxies"));
}

#[test]
fn split_list_trims_and_drops_empty() {
    assert_eq!(
        split_list(" a, ,b ,"),
        vec!["a".to_string(), "b".to_string()]
    );
}

#[test]
fn valid_manual_mode_passes() {
    assert!(base_config(UnlockMode::Manual).validate().is_ok());
}

#[test]
fn valid_file_mode_passes() {
    let mut cfg = base_config(UnlockMode::File);
    cfg.unlock_file = Some(PathBuf::from("/run/secrets/bw_password"));
    assert!(cfg.validate().is_ok());
}

#[test]
fn file_mode_without_unlock_file_fails() {
    let cfg = base_config(UnlockMode::File);
    let err = cfg.validate().unwrap_err();
    assert!(err.to_string().contains("unlock_file"));
}

#[test]
fn short_admin_key_fails() {
    let mut cfg = base_config(UnlockMode::Manual);
    cfg.admin_key = "short".to_string().into();
    let err = cfg.validate().unwrap_err();
    assert!(err.to_string().contains("32 characters"));
}

#[test]
fn the_admin_key_file_is_read_without_touching_the_environment() {
    // Config::load reads the real environment; this is the only test that
    // sets FERROWARDEN_* variables, and it removes them again.
    let key = "k".repeat(40);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("admin_key");
    std::fs::write(
        &path,
        format!(
            "{key}
"
        ),
    )
    .unwrap();
    std::env::remove_var("FERROWARDEN_ADMIN_KEY");
    std::env::set_var("FERROWARDEN_ADMIN_KEY_FILE", &path);
    std::env::set_var("FERROWARDEN_TLS_ENABLED", "false");
    std::env::set_var("FERROWARDEN_VAULT_CLIENT_ID", "load-test-id");
    std::env::set_var("FERROWARDEN_VAULT_CLIENT_SECRET", "load-test-secret");
    std::env::set_var("FERROWARDEN_UNLOCK_MODE", "manual");
    let loaded = Config::load();
    // The key stays out of the process environment.
    let leaked = std::env::var("FERROWARDEN_ADMIN_KEY");
    let in_env_values = std::env::vars().any(|(_, v)| v == key);

    // The removed backend fails the whole load, from the environment too.
    std::env::set_var("FERROWARDEN_VAULT__BACKEND", "bw-serve");
    let removed = Config::load().unwrap_err().to_string();
    std::env::remove_var("FERROWARDEN_VAULT__BACKEND");

    // A missing file is an error, not a silent empty key.
    std::env::set_var("FERROWARDEN_ADMIN_KEY_FILE", dir.path().join("nope"));
    let missing = Config::load().unwrap_err().to_string();
    // A direct variable takes precedence over the file.
    let direct = "d".repeat(40);
    std::env::set_var("FERROWARDEN_ADMIN_KEY", &direct);
    let preferred = Config::load();
    for name in [
        "FERROWARDEN_ADMIN_KEY",
        "FERROWARDEN_ADMIN_KEY_FILE",
        "FERROWARDEN_TLS_ENABLED",
        "FERROWARDEN_VAULT_CLIENT_ID",
        "FERROWARDEN_VAULT_CLIENT_SECRET",
        "FERROWARDEN_UNLOCK_MODE",
    ] {
        std::env::remove_var(name);
    }

    assert_eq!(loaded.unwrap().admin_key.as_str(), key);
    assert!(leaked.is_err(), "the key must not be exported");
    assert!(!in_env_values);
    assert!(
        removed.contains("removed in 0.3.0") && removed.contains("#upgrading-from-bw-serve"),
        "{removed}"
    );
    assert!(missing.contains("does not exist"), "{missing}");
    assert_eq!(preferred.unwrap().admin_key.as_str(), direct);
}

#[test]
fn exactly_32_char_admin_key_passes() {
    let cfg = base_config(UnlockMode::Manual);
    assert_eq!(cfg.admin_key.len(), 32);
    assert!(cfg.validate().is_ok());
}

#[test]
fn tls_enabled_without_cert_fails() {
    let mut cfg = base_config(UnlockMode::Manual);
    cfg.tls_enabled = true;
    cfg.tls_key_file = Some(PathBuf::from("/certs/server.key"));
    let err = cfg.validate().unwrap_err();
    assert!(err.to_string().contains("tls_cert_file"));
}

#[test]
fn tls_enabled_without_key_fails() {
    let mut cfg = base_config(UnlockMode::Manual);
    cfg.tls_enabled = true;
    cfg.tls_cert_file = Some(PathBuf::from("/certs/server.crt"));
    let err = cfg.validate().unwrap_err();
    assert!(err.to_string().contains("tls_key_file"));
}

#[test]
fn tls_enabled_with_both_files_passes() {
    let mut cfg = base_config(UnlockMode::Manual);
    cfg.tls_enabled = true;
    cfg.tls_cert_file = Some(PathBuf::from("/certs/server.crt"));
    cfg.tls_key_file = Some(PathBuf::from("/certs/server.key"));
    assert!(cfg.validate().is_ok());
}

#[test]
fn tls_disabled_no_files_passes() {
    let cfg = base_config(UnlockMode::Manual);
    assert!(!cfg.tls_enabled);
    assert!(cfg.validate().is_ok());
}

#[test]
fn ui_is_disabled_by_default_with_the_documented_defaults() {
    let ui = UiConfig::default();
    assert!(!ui.enabled());
    assert_eq!(ui.bind, "");
    assert_eq!(ui.vaultwarden_url, "https://vaultwarden");
    assert_eq!(ui.vaultwarden_ca_file, "");
    assert!(!ui.insecure_http);
    assert_eq!(ui.session_idle_minutes, 15);
    assert_eq!(ui.session_max_hours, 8);
    assert!(base_config(UnlockMode::Manual).validate().is_ok());
}

#[test]
fn ui_section_deserializes_partially() {
    let ui: UiConfig = serde_json::from_str(r#"{"bind":"0.0.0.0:3001"}"#).unwrap();
    assert!(ui.enabled());
    assert_eq!(ui.session_idle_minutes, 15);
}

#[test]
fn invalid_ui_settings_fail_validation() {
    let with = |f: &dyn Fn(&mut UiConfig)| {
        let mut cfg = base_config(UnlockMode::Manual);
        cfg.ui.bind = "0.0.0.0:3001".to_string();
        f(&mut cfg.ui);
        cfg.validate()
    };
    assert!(with(&|_| {}).is_ok());
    assert!(with(&|u| u.bind = "not an address".into()).is_err());
    assert!(with(&|u| u.session_idle_minutes = 0).is_err());
    assert!(with(&|u| u.session_max_hours = 0).is_err());
    assert!(with(&|u| u.session_idle_minutes = u64::MAX).is_err());
    assert!(with(&|u| u.session_max_hours = u64::MAX).is_err());
    // HTTPS only, except loopback (tests).
    assert!(with(&|u| u.vaultwarden_url = "http://vaultwarden".into()).is_err());
    assert!(with(&|u| u.vaultwarden_url = "http://10.0.0.5".into()).is_err());
    assert!(with(&|u| u.vaultwarden_url = "http://127.0.0.1:8080".into()).is_ok());
    assert!(with(&|u| u.vaultwarden_url = "http://localhost:8080".into()).is_ok());
    assert!(with(&|u| u.vaultwarden_url = "https://vault.example.com".into()).is_ok());
    assert!(with(&|u| u.vaultwarden_url = "ftp://vault".into()).is_err());
    assert!(with(&|u| u.vaultwarden_url = "https://vault/?x=1".into()).is_err());
    assert!(with(&|u| u.vaultwarden_url = "not a url".into()).is_err());
}

// ── [notify] ──────────────────────────────────────────────────────────────

fn tokens_from(env: &[(&str, &str)], files: &[(&str, &[u8])]) -> FerroResult<NotifyTokens> {
    let env: std::collections::HashMap<String, String> = env
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    let files: std::collections::HashMap<String, Vec<u8>> = files
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_vec()))
        .collect();
    NotifyTokens::load(
        |name| env.get(name).cloned(),
        |path| {
            files
                .get(path.to_str().unwrap())
                .cloned()
                .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::NotFound))
        },
    )
}

#[test]
fn notify_defaults_match_the_documentation() {
    let n = NotifyConfig::default();
    assert!(!n.enabled());
    assert_eq!(
        n.events,
        ["blocked", "auth_failure", "vault", "system", "approval"]
    );
    assert_eq!(n.min_interval_secs, 60);
    assert_eq!(n.max_per_hour, 60);
    assert_eq!(n.auth_failure_threshold, 5);
    assert_eq!(n.auth_failure_window_secs, 300);
    assert!(!n.allow_http);
    assert!(n.ca_file.is_empty());
    assert!(base_config(UnlockMode::Manual).validate().is_ok());
}

#[test]
fn notify_section_deserializes_from_a_list_or_a_comma_separated_string() {
    let from = |text: &str| -> Config {
        config::Config::builder()
            .add_source(config::File::from_str(text, config::FileFormat::Toml))
            .build()
            .unwrap()
            .try_deserialize()
            .unwrap()
    };
    let cfg = from(
            "unlock_mode = \"manual\"\n[notify]\nwebhook_url = \"https://hooks.example.com/x\"\nevents = [\"blocked\", \"admin\"]\nmax_per_hour = 5\n",
        );
    assert_eq!(cfg.notify.events, ["blocked", "admin"]);
    assert_eq!(cfg.notify.max_per_hour, 5);
    assert_eq!(
        cfg.notify.min_interval_secs, 60,
        "unspecified keys keep their defaults"
    );
    let cfg = from("unlock_mode = \"manual\"\n[notify]\nevents = \"blocked, vault\"\n");
    assert_eq!(cfg.notify.events, ["blocked", "vault"]);
}

#[test]
fn notify_settings_come_from_the_environment_too() {
    // The same builder the real loader uses, with a fake environment.
    let mut env = std::collections::HashMap::new();
    env.insert("FERROWARDEN_UNLOCK_MODE".to_string(), "manual".to_string());
    env.insert(
        "FERROWARDEN_NOTIFY__WEBHOOK_URL".to_string(),
        "https://hooks.example.com/x".to_string(),
    );
    env.insert(
        "FERROWARDEN_NOTIFY__EVENTS".to_string(),
        "blocked,auth_failure".to_string(),
    );
    env.insert(
        "FERROWARDEN_NOTIFY__MIN_INTERVAL_SECS".to_string(),
        "5".to_string(),
    );
    env.insert(
        "FERROWARDEN_NOTIFY__ALLOW_HTTP".to_string(),
        "true".to_string(),
    );
    // Token variables share the prefix: they must be ignored here.
    env.insert(
        "FERROWARDEN_NOTIFY_GOTIFY_TOKEN".to_string(),
        "not-a-setting".to_string(),
    );
    let cfg: Config = config::Config::builder()
        .add_source(
            config::Environment::with_prefix("FERROWARDEN")
                .prefix_separator("_")
                .separator("__")
                .ignore_empty(true)
                .source(Some(env)),
        )
        .build()
        .unwrap()
        .try_deserialize()
        .unwrap();
    assert_eq!(cfg.notify.webhook_url, "https://hooks.example.com/x");
    assert_eq!(cfg.notify.events, ["blocked", "auth_failure"]);
    assert_eq!(cfg.notify.min_interval_secs, 5);
    assert!(cfg.notify.allow_http);
    assert!(cfg.notify.tokens.gotify.is_none());
}

#[test]
fn notifier_tokens_come_from_the_environment_or_a_file_never_both() {
    assert!(tokens_from(&[], &[]).unwrap().gotify.is_none());
    let t = tokens_from(&[(ENV_GOTIFY_TOKEN, "  direct-token-1 \n")], &[]).unwrap();
    assert_eq!(
        t.gotify.as_deref().map(String::as_str),
        Some("direct-token-1")
    );
    let t = tokens_from(
        &[("FERROWARDEN_NOTIFY_NTFY_TOKEN_FILE", "/run/secrets/ntfy")],
        &[("/run/secrets/ntfy", b"file-token-2\r\n")],
    )
    .unwrap();
    assert_eq!(t.ntfy.as_deref().map(String::as_str), Some("file-token-2"));
    assert!(t.gotify.is_none() && t.webhook.is_none());

    let both = tokens_from(
        &[
            (ENV_WEBHOOK_TOKEN, "tok-one-secret-value"),
            ("FERROWARDEN_NOTIFY_WEBHOOK_TOKEN_FILE", "/f"),
        ],
        &[("/f", b"tok-two-secret-value")],
    )
    .unwrap_err()
    .to_string();
    assert!(both.contains("only one of"), "{both}");
    assert!(!both.contains("secret-value"), "{both}");
}

#[test]
fn bad_token_sources_are_errors_that_never_echo_the_value() {
    let spaced = "s3cr3t token with spaces";
    type Case<'a> = (Vec<(&'a str, &'a str)>, Vec<(&'a str, &'a [u8])>);
    let cases: Vec<Case> = vec![
        // A missing file.
        (
            vec![("FERROWARDEN_NOTIFY_GOTIFY_TOKEN_FILE", "/nope")],
            vec![],
        ),
        // An empty file, a whitespace-only value.
        (
            vec![("FERROWARDEN_NOTIFY_GOTIFY_TOKEN_FILE", "/e")],
            vec![("/e", b"\n")],
        ),
        (vec![(ENV_GOTIFY_TOKEN, "   ")], vec![]),
        // Not valid UTF-8.
        (
            vec![("FERROWARDEN_NOTIFY_GOTIFY_TOKEN_FILE", "/b")],
            vec![("/b", &[0xff, 0xfe, 0x41])],
        ),
        // Not a valid header value: spaces inside, control characters.
        (vec![(ENV_GOTIFY_TOKEN, spaced)], vec![]),
        (vec![(ENV_GOTIFY_TOKEN, "ab\u{1}cd")], vec![]),
        (vec![(ENV_GOTIFY_TOKEN, "tok\u{e9}n")], vec![]),
    ];
    for (env, files) in cases {
        let err = tokens_from(&env, &files).unwrap_err().to_string();
        assert!(err.contains("FERROWARDEN_NOTIFY_GOTIFY_TOKEN"), "{err}");
        for (_, v) in &env {
            if v.len() > 6 && !v.starts_with('/') {
                assert!(!err.contains(v), "{err}");
            }
        }
    }
}

#[test]
fn tokens_are_redacted_in_debug_output_and_not_read_from_the_config_file() {
    let t = tokens_from(&[(ENV_GOTIFY_TOKEN, "gotify-secret-123456")], &[]).unwrap();
    let shown = format!("{t:?}");
    assert!(!shown.contains("gotify-secret"), "{shown}");
    assert!(shown.contains("[redacted]"));
    let mut cfg = base_config(UnlockMode::Manual);
    cfg.notify.tokens = t;
    assert!(!format!("{cfg:?}").contains("gotify-secret"));

    // A `tokens` key in the file is ignored (serde skip), not read.
    let cfg: Config = config::Config::builder()
        .add_source(config::File::from_str(
            "unlock_mode = \"manual\"\n[notify.tokens]\ngotify = \"from-the-file-12345\"\n",
            config::FileFormat::Toml,
        ))
        .build()
        .unwrap()
        .try_deserialize()
        .unwrap();
    assert!(cfg.notify.tokens.gotify.is_none());
}

fn notify_cfg(f: impl Fn(&mut NotifyConfig)) -> FerroResult<()> {
    let mut cfg = base_config(UnlockMode::Manual);
    cfg.notify.webhook_url = "https://hooks.example.com/ferrowarden".into();
    f(&mut cfg.notify);
    cfg.validate()
}

#[test]
fn notify_validation_covers_urls_categories_limits_and_tokens() {
    assert!(notify_cfg(|_| {}).is_ok());
    type Tweak = Box<dyn Fn(&mut NotifyConfig)>;
    let bad: Vec<(&str, Tweak)> = vec![
        (
            "not a url",
            Box::new(|n| n.webhook_url = "not a url".into()),
        ),
        ("no host", Box::new(|n| n.webhook_url = "https://".into())),
        (
            "ftp",
            Box::new(|n| n.webhook_url = "ftp://hooks.example.com/x".into()),
        ),
        (
            "http",
            Box::new(|n| n.webhook_url = "http://hooks.example.com/x".into()),
        ),
        (
            "userinfo",
            Box::new(|n| n.webhook_url = "https://u:p@hooks.example.com/x".into()),
        ),
        (
            "query",
            Box::new(|n| n.webhook_url = "https://hooks.example.com/x?token=abc".into()),
        ),
        (
            "fragment",
            Box::new(|n| n.webhook_url = "https://hooks.example.com/x#f".into()),
        ),
        (
            "bad ntfy",
            Box::new(|n| n.ntfy_url = "ntfy.example.com/topic".into()),
        ),
        (
            "gotify without token",
            Box::new(|n| n.gotify_url = "https://gotify.example.com".into()),
        ),
        (
            "unknown category",
            Box::new(|n| n.events = vec!["blocked".into(), "everything".into()]),
        ),
        ("no categories", Box::new(|n| n.events = vec![])),
        ("zero cap", Box::new(|n| n.max_per_hour = 0)),
        ("zero threshold", Box::new(|n| n.auth_failure_threshold = 0)),
        ("zero window", Box::new(|n| n.auth_failure_window_secs = 0)),
        (
            "huge window",
            Box::new(|n| n.auth_failure_window_secs = 100_000),
        ),
        ("huge interval", Box::new(|n| n.min_interval_secs = 100_000)),
        (
            "missing ca file",
            Box::new(|n| n.ca_file = "/no/such/ca.pem".into()),
        ),
    ];
    for (name, tweak) in &bad {
        assert!(notify_cfg(tweak).is_err(), "{name} should fail");
    }
    // http is fine for this machine, and anywhere with allow_http.
    for url in [
        "http://localhost:8080/x",
        "http://127.0.0.1/x",
        "http://[::1]:9/x",
    ] {
        assert!(notify_cfg(|n| n.webhook_url = url.into()).is_ok(), "{url}");
    }
    assert!(notify_cfg(|n| {
        n.webhook_url = "http://hooks.example.com/x".into();
        n.allow_http = true;
    })
    .is_ok());
    // Gotify with its token.
    assert!(notify_cfg(|n| {
        n.gotify_url = "https://gotify.example.com".into();
        n.tokens.gotify = Some(Zeroizing::new("tok".into()));
    })
    .is_ok());
    // Unknown categories are an error even with no sender.
    let mut cfg = base_config(UnlockMode::Manual);
    cfg.notify.events = vec!["nope".into()];
    assert!(cfg.validate().unwrap_err().to_string().contains("nope"));
    // A disabled notifier with a stray CA file is a mistake worth saying.
    let mut cfg = base_config(UnlockMode::Manual);
    cfg.notify.ca_file = "/x.pem".into();
    assert!(cfg.validate().is_err());
}

#[test]
fn notify_endpoints_list_each_notifier_host_and_port() {
    let n = NotifyConfig {
        gotify_url: "https://Gotify.Example.com/".into(),
        ntfy_url: "https://ntfy.example.com:8443/topic".into(),
        webhook_url: "http://[::1]:7777/n".into(),
        ..NotifyConfig::default()
    };
    assert_eq!(
        n.endpoints(),
        [
            ("gotify.example.com".to_string(), 443),
            ("ntfy.example.com".to_string(), 8443),
            ("::1".to_string(), 7777)
        ]
    );
    assert!(NotifyConfig::default().endpoints().is_empty());
}

#[test]
fn a_disabled_ui_ignores_the_rest_of_its_section() {
    let mut cfg = base_config(UnlockMode::Manual);
    cfg.ui.vaultwarden_url = "garbage".into();
    cfg.ui.session_idle_minutes = 0;
    assert!(cfg.validate().is_ok());
}

// ── [vault] ───────────────────────────────────────────────────────────────

fn vault_creds(id: Option<&str>, secret: Option<&str>) -> VaultCredentials {
    VaultCredentials {
        client_id: id.map(|v| Zeroizing::new(v.to_string())),
        client_secret: secret.map(|v| Zeroizing::new(v.to_string())),
    }
}

#[test]
fn vault_defaults_to_native_and_the_documented_url() {
    let v = VaultConfig::default();
    assert_eq!(v.backend, VaultBackend::Native);
    assert_eq!(v.url, "https://vaultwarden");
    assert_eq!(v.ca_file, "");
    assert_eq!(VaultBackend::Native.as_str(), "native");
    assert!(base_config(UnlockMode::Manual).validate().is_ok());
}

#[test]
fn vault_backend_comes_from_the_file_or_the_environment() {
    let v: VaultConfig =
        serde_json::from_str(r#"{"backend":"native","url":"https://vw.example"}"#).unwrap();
    assert_eq!(v.backend, VaultBackend::Native);
    assert_eq!(v.url, "https://vw.example");
    assert!(serde_json::from_str::<VaultConfig>(r#"{"backend":"nope"}"#).is_err());

    let mut env = std::collections::HashMap::new();
    env.insert("FERROWARDEN_UNLOCK_MODE".to_string(), "manual".to_string());
    env.insert(
        "FERROWARDEN_VAULT__BACKEND".to_string(),
        "native".to_string(),
    );
    env.insert(
        "FERROWARDEN_VAULT__CA_FILE".to_string(),
        "/ca/ca.crt".to_string(),
    );
    // The API key variables share the prefix: they must be ignored here.
    env.insert(
        "FERROWARDEN_VAULT_CLIENT_SECRET".to_string(),
        "not-a-setting".to_string(),
    );
    let cfg: Config = config::Config::builder()
        .add_source(
            config::Environment::with_prefix("FERROWARDEN")
                .prefix_separator("_")
                .separator("__")
                .ignore_empty(true)
                .source(Some(env)),
        )
        .build()
        .unwrap()
        .try_deserialize()
        .unwrap();
    assert_eq!(cfg.vault.backend, VaultBackend::Native);
    assert_eq!(cfg.vault.ca_file, "/ca/ca.crt");
    assert!(cfg.vault.credentials.client_secret.is_none());

    // And unset, the default is native.
    assert_eq!(VaultBackend::default(), VaultBackend::Native);
}

#[test]
fn hidden_passwords_are_refused_unless_the_operator_opts_in() {
    assert!(!VaultConfig::default().allow_hidden_passwords);
    let from_file: VaultConfig =
        serde_json::from_str(r#"{"allow_hidden_passwords":true}"#).unwrap();
    assert!(from_file.allow_hidden_passwords);
    assert!(
        !serde_json::from_str::<VaultConfig>("{}")
            .unwrap()
            .allow_hidden_passwords
    );

    let mut env = std::collections::HashMap::new();
    env.insert("FERROWARDEN_UNLOCK_MODE".to_string(), "manual".to_string());
    env.insert(
        "FERROWARDEN_VAULT__ALLOW_HIDDEN_PASSWORDS".to_string(),
        "true".to_string(),
    );
    let cfg: Config = config::Config::builder()
        .add_source(
            config::Environment::with_prefix("FERROWARDEN")
                .prefix_separator("_")
                .separator("__")
                .ignore_empty(true)
                .source(Some(env)),
        )
        .build()
        .unwrap()
        .try_deserialize()
        .unwrap();
    assert!(cfg.vault.allow_hidden_passwords);
}

#[test]
fn native_mode_needs_a_valid_url_and_the_api_key() {
    let native = |url: &str, id: Option<&str>, secret: Option<&str>| {
        let mut cfg = base_config(UnlockMode::Manual);
        cfg.vault.backend = VaultBackend::Native;
        cfg.vault.url = url.to_string();
        cfg.vault.credentials = vault_creds(id, secret);
        cfg.validate()
    };
    assert!(native("https://vaultwarden", Some("i"), Some("s")).is_ok());
    assert!(native("http://localhost:8000", Some("i"), Some("s")).is_ok());
    for bad in [
        "http://vaultwarden",
        "ftp://x",
        "not a url",
        "https://vw/?a=b",
        "https://vw/#f",
    ] {
        let err = native(bad, Some("i"), Some("s")).unwrap_err().to_string();
        assert!(err.contains("vault.url"), "{bad}: {err}");
    }
    for (id, secret) in [(None, Some("s")), (Some("i"), None), (None, None)] {
        let err = native("https://vaultwarden", id, secret)
            .unwrap_err()
            .to_string();
        assert!(err.contains(ENV_VAULT_CLIENT_ID), "{err}");
        assert!(err.contains(ENV_VAULT_CLIENT_SECRET), "{err}");
    }
}

#[test]
fn the_api_key_comes_from_the_environment_or_a_file_and_is_redacted() {
    let load = |vars: &[(&str, &str)], files: &[(&str, &str)]| {
        let vars: std::collections::HashMap<String, String> = vars
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        let files: std::collections::HashMap<String, String> = files
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        VaultCredentials::load(
            |n| vars.get(n).cloned(),
            |p| {
                files
                    .get(p.to_str().unwrap())
                    .map(|v| v.clone().into_bytes())
                    .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::NotFound))
            },
        )
    };
    let c = load(
        &[
            ("FERROWARDEN_VAULT_CLIENT_ID_FILE", "/run/secrets/id"),
            ("FERROWARDEN_VAULT_CLIENT_SECRET", "direct-secret-value"),
        ],
        &[("/run/secrets/id", "user.abc\n")],
    )
    .unwrap();
    assert_eq!(c.client_id.as_ref().unwrap().as_str(), "user.abc");
    assert_eq!(
        c.client_secret.as_ref().unwrap().as_str(),
        "direct-secret-value"
    );
    // Never in Debug output.
    let dbg = format!("{c:?}");
    assert!(!dbg.contains("direct-secret-value") && !dbg.contains("user.abc"));
    assert!(dbg.contains("[redacted]"));
    // A missing file is an error that names the variable, not the value.
    let err = load(&[("FERROWARDEN_VAULT_CLIENT_ID_FILE", "/nope")], &[])
        .unwrap_err()
        .to_string();
    assert!(err.contains("FERROWARDEN_VAULT_CLIENT_ID_FILE"), "{err}");
    // Nothing set: both absent.
    let none = load(&[], &[]).unwrap();
    assert!(none.client_id.is_none() && none.client_secret.is_none());
}

#[test]
fn deprecated_ui_settings_are_aliases_for_the_vault_settings() {
    // Only the old names set: they are adopted, with a deprecation note.
    let mut vault = VaultConfig::default();
    let mut ui = UiConfig {
        vaultwarden_url: "https://old.example".to_string(),
        vaultwarden_ca_file: "/ca/old.crt".to_string(),
        ..UiConfig::default()
    };
    let notes = vault.resolve_aliases(&mut ui);
    assert_eq!(vault.url, "https://old.example");
    assert_eq!(vault.ca_file, "/ca/old.crt");
    assert_eq!(notes.len(), 2);
    assert!(notes.iter().all(|n| n.contains("deprecated")));

    // New names win when both are set and differ.
    let mut vault = VaultConfig {
        url: "https://new.example".to_string(),
        ca_file: "/ca/new.crt".to_string(),
        ..VaultConfig::default()
    };
    let mut ui = UiConfig {
        vaultwarden_url: "https://old.example".to_string(),
        vaultwarden_ca_file: "/ca/old.crt".to_string(),
        ..UiConfig::default()
    };
    let notes = vault.resolve_aliases(&mut ui);
    assert_eq!(vault.url, "https://new.example");
    assert_eq!(ui.vaultwarden_url, "https://new.example", "written back");
    assert_eq!(ui.vaultwarden_ca_file, "/ca/new.crt");
    assert_eq!(notes.len(), 2);

    // Only the new names, or nothing: no notes.
    let mut vault = VaultConfig {
        ca_file: "/ca/new.crt".to_string(),
        ..VaultConfig::default()
    };
    let mut ui = UiConfig::default();
    assert!(vault.resolve_aliases(&mut ui).is_empty());
    assert_eq!(ui.vaultwarden_ca_file, "/ca/new.crt");
}

// ── Metrics ───────────────────────────────────────────────────────────────────

const METRICS_TOKEN: &str = "0123456789abcdef0123456789abcdef";

fn metrics_cfg(bind: &str, token: Option<&str>, allow: bool) -> MetricsConfig {
    MetricsConfig {
        bind: bind.to_string(),
        allow_unauthenticated: allow,
        credential_labels: false,
        token: MetricsToken(token.map(|t| Zeroizing::new(t.to_string()))),
    }
}

fn load_metrics_token(env: &[(&str, &str)], files: &[(&str, &[u8])]) -> FerroResult<MetricsToken> {
    let env: std::collections::HashMap<String, String> = env
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    let files: std::collections::HashMap<String, Vec<u8>> = files
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_vec()))
        .collect();
    MetricsToken::load(
        |name| env.get(name).cloned(),
        |path| {
            files
                .get(path.to_str().unwrap())
                .cloned()
                .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::NotFound))
        },
    )
}

#[test]
fn metrics_are_off_by_default() {
    let m = MetricsConfig::default();
    assert!(!m.enabled());
    assert!(!m.allow_unauthenticated && !m.credential_labels);
    assert_eq!(m.auth(), MetricsAuth::None);
    assert!(base_config(UnlockMode::Manual).validate().is_ok());
}

#[test]
fn metrics_settings_come_from_the_file_and_the_environment() {
    let from_file: Config = config::Config::builder()
        .add_source(config::File::from_str(
            "unlock_mode = \"manual\"
[metrics]
bind = \"0.0.0.0:9095\"
credential_labels = true
",
            config::FileFormat::Toml,
        ))
        .build()
        .unwrap()
        .try_deserialize()
        .unwrap();
    assert_eq!(from_file.metrics.bind, "0.0.0.0:9095");
    assert!(from_file.metrics.credential_labels);
    assert!(!from_file.metrics.allow_unauthenticated);

    // FERROWARDEN_METRICS__BIND, as the server reads it.
    let env: std::collections::HashMap<String, String> = [
        ("FERROWARDEN_UNLOCK_MODE", "manual"),
        ("FERROWARDEN_METRICS__BIND", "127.0.0.1:9095"),
        ("FERROWARDEN_METRICS__ALLOW_UNAUTHENTICATED", "true"),
        // The token variables are not settings: they must not be picked up
        // as one (and the token is never a field of the file or environment).
        ("FERROWARDEN_METRICS_TOKEN", METRICS_TOKEN),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v.to_string()))
    .collect();
    let from_env: Config = config::Config::builder()
        .add_source(
            config::Environment::with_prefix("FERROWARDEN")
                .prefix_separator("_")
                .separator("__")
                .ignore_empty(true)
                .source(Some(env)),
        )
        .build()
        .unwrap()
        .try_deserialize()
        .unwrap();
    assert_eq!(from_env.metrics.bind, "127.0.0.1:9095");
    assert!(from_env.metrics.allow_unauthenticated);
    assert_eq!(from_env.metrics.auth(), MetricsAuth::None);
}

#[test]
fn a_token_cannot_be_set_in_the_config_file() {
    let cfg: Config = config::Config::builder()
        .add_source(config::File::from_str(
            "unlock_mode = \"manual\"
[metrics]
bind = \"127.0.0.1:9095\"
token = \"from-the-file-0123456789\"
",
            config::FileFormat::Toml,
        ))
        .build()
        .unwrap()
        .try_deserialize()
        .unwrap();
    assert_eq!(cfg.metrics.auth(), MetricsAuth::None);
}

#[test]
fn metrics_startup_rules() {
    let api = "0.0.0.0:3000";
    let ui = "";
    let ok = |c: MetricsConfig| c.validate(api, ui);
    // Off: nothing is checked.
    assert!(ok(metrics_cfg("", None, false)).is_ok());
    // A token: any address.
    assert!(ok(metrics_cfg("0.0.0.0:9095", Some(METRICS_TOKEN), false)).is_ok());
    assert!(ok(metrics_cfg("127.0.0.1:9095", Some(METRICS_TOKEN), false)).is_ok());
    // No token: loopback is fine, anything else is refused ...
    assert!(ok(metrics_cfg("127.0.0.1:9095", None, false)).is_ok());
    assert!(ok(metrics_cfg("[::1]:9095", None, false)).is_ok());
    for bind in [
        "0.0.0.0:9095",
        "[::]:9095",
        "10.1.2.3:9095",
        "192.168.1.5:9095",
    ] {
        let err = ok(metrics_cfg(bind, None, false)).unwrap_err().to_string();
        assert!(err.contains("no token is set"), "{bind}: {err}");
        assert!(err.contains("allow_unauthenticated"), "{err}");
        // ... unless the operator said so.
        assert!(ok(metrics_cfg(bind, None, true)).is_ok(), "{bind}");
    }
    // A token and the flag together are contradictory.
    assert!(ok(metrics_cfg("127.0.0.1:9095", Some(METRICS_TOKEN), true)).is_err());
    // Not an address.
    for bind in ["9095", "localhost:9095", "0.0.0.0", "nonsense"] {
        assert!(ok(metrics_cfg(bind, None, true)).is_err(), "{bind}");
    }
}

#[test]
fn the_metrics_port_must_be_its_own() {
    let cfg = metrics_cfg("0.0.0.0:3000", Some(METRICS_TOKEN), false);
    assert!(cfg
        .validate("0.0.0.0:3000", "")
        .unwrap_err()
        .to_string()
        .contains("bind_addr"));
    assert!(cfg
        .validate("127.0.0.1:3000", "")
        .unwrap_err()
        .to_string()
        .contains("same port"));
    let cfg = metrics_cfg("127.0.0.1:3001", Some(METRICS_TOKEN), false);
    assert!(cfg
        .validate("0.0.0.0:3000", "0.0.0.0:3001")
        .unwrap_err()
        .to_string()
        .contains("ui.bind"));
    assert!(cfg.validate("0.0.0.0:3000", "0.0.0.0:3002").is_ok());
}

#[test]
fn the_full_config_validates_metrics() {
    let mut cfg = base_config(UnlockMode::Manual);
    cfg.metrics = metrics_cfg("0.0.0.0:9095", None, false);
    assert!(cfg.validate().is_err());
    cfg.metrics.allow_unauthenticated = true;
    assert!(cfg.validate().is_ok());
}

#[test]
fn the_metrics_token_comes_from_the_variable_or_the_file() {
    let direct = load_metrics_token(&[("FERROWARDEN_METRICS_TOKEN", METRICS_TOKEN)], &[]).unwrap();
    assert_eq!(direct.0.as_deref().map(String::as_str), Some(METRICS_TOKEN));

    // A file: trailing newlines are removed, nothing else.
    let file_bytes = format!("{METRICS_TOKEN}\r\n").into_bytes();
    let from_file = load_metrics_token(
        &[("FERROWARDEN_METRICS_TOKEN_FILE", "/run/secrets/metrics")],
        &[("/run/secrets/metrics", &file_bytes)],
    )
    .unwrap();
    assert_eq!(
        from_file.0.as_deref().map(String::as_str),
        Some(METRICS_TOKEN)
    );

    // Neither: no token.
    assert!(load_metrics_token(&[], &[]).unwrap().0.is_none());
}

#[test]
fn metrics_token_errors_never_contain_the_token() {
    let both = load_metrics_token(
        &[
            ("FERROWARDEN_METRICS_TOKEN", METRICS_TOKEN),
            ("FERROWARDEN_METRICS_TOKEN_FILE", "/run/secrets/metrics"),
        ],
        &[("/run/secrets/metrics", METRICS_TOKEN.as_bytes())],
    )
    .unwrap_err()
    .to_string();
    assert!(both.contains("only one of"), "{both}");
    assert!(!both.contains(METRICS_TOKEN));

    let short = load_metrics_token(&[("FERROWARDEN_METRICS_TOKEN", "short-token")], &[])
        .unwrap_err()
        .to_string();
    assert!(short.contains("at least 16"), "{short}");
    assert!(!short.contains("short-token"));

    for bad in [
        "has a space in the middle 1234567890",
        "tab\tinside-the-token-1234567890",
        "non-ascii-\u{e9}-0123456789abcdef",
    ] {
        let err = load_metrics_token(&[("FERROWARDEN_METRICS_TOKEN", bad)], &[])
            .unwrap_err()
            .to_string();
        assert!(err.contains("printable"), "{err}");
        assert!(!err.contains(bad));
    }

    // A missing file names the variable, an empty one says so.
    let missing = load_metrics_token(
        &[("FERROWARDEN_METRICS_TOKEN_FILE", "/run/secrets/none")],
        &[],
    )
    .unwrap_err()
    .to_string();
    assert!(
        missing.contains("FERROWARDEN_METRICS_TOKEN_FILE"),
        "{missing}"
    );
    let empty = load_metrics_token(
        &[("FERROWARDEN_METRICS_TOKEN_FILE", "/run/secrets/empty")],
        &[("/run/secrets/empty", b"\n")],
    )
    .unwrap_err()
    .to_string();
    assert!(empty.contains("empty"), "{empty}");
}

#[test]
fn the_metrics_token_is_redacted_in_debug_output() {
    let cfg = metrics_cfg("127.0.0.1:9095", Some(METRICS_TOKEN), false);
    let shown = format!("{cfg:?}");
    assert!(!shown.contains(METRICS_TOKEN));
    assert!(shown.contains("[redacted]"));
    assert_eq!(cfg.auth(), MetricsAuth::Token);
    assert_eq!(cfg.auth().as_str(), "token");
    assert_eq!(MetricsAuth::None.as_str(), "none");
}

// ── Captured sessions ─────────────────────────────────────────────────────────

#[test]
fn sessions_defaults_match_the_documentation() {
    let s = SessionsConfig::default();
    assert!(s.enabled);
    assert_eq!(s.default_ttl_secs, 1800);
    assert_eq!(s.max_ttl_secs, 86_400);
    assert_eq!(s.max_per_key, 32);
    assert!(base_config(UnlockMode::Manual).validate().is_ok());
}

#[test]
fn sessions_settings_come_from_the_file_and_the_environment() {
    let from_file: Config = config::Config::builder()
        .add_source(config::File::from_str(
            "unlock_mode = \"manual\"\n[sessions]\nenabled = false\ndefault_ttl_secs = 60\nmax_ttl_secs = 120\nmax_per_key = 4\n",
            config::FileFormat::Toml,
        ))
        .build()
        .unwrap()
        .try_deserialize()
        .unwrap();
    assert_eq!(
        from_file.sessions,
        SessionsConfig {
            enabled: false,
            default_ttl_secs: 60,
            max_ttl_secs: 120,
            max_per_key: 4
        }
    );
    let mut env = std::collections::HashMap::new();
    env.insert("FERROWARDEN_UNLOCK_MODE".to_string(), "manual".to_string());
    env.insert(
        "FERROWARDEN_SESSIONS__MAX_PER_KEY".to_string(),
        "8".to_string(),
    );
    env.insert(
        "FERROWARDEN_SESSIONS__ENABLED".to_string(),
        "false".to_string(),
    );
    let from_env: Config = config::Config::builder()
        .add_source(
            config::Environment::with_prefix("FERROWARDEN")
                .prefix_separator("_")
                .separator("__")
                .ignore_empty(true)
                .source(Some(env)),
        )
        .build()
        .unwrap()
        .try_deserialize()
        .unwrap();
    assert!(!from_env.sessions.enabled);
    assert_eq!(from_env.sessions.max_per_key, 8);
    assert_eq!(
        from_env.sessions.default_ttl_secs, 1800,
        "the rest keeps its default"
    );
}

#[test]
fn invalid_sessions_settings_fail_validation() {
    let check = |s: SessionsConfig| {
        let mut cfg = base_config(UnlockMode::Manual);
        cfg.sessions = s;
        cfg.validate()
    };
    let ok = SessionsConfig::default();
    assert!(check(ok.clone()).is_ok());
    // Edges that are allowed.
    assert!(check(SessionsConfig {
        default_ttl_secs: 1,
        max_ttl_secs: 1,
        ..ok.clone()
    })
    .is_ok());
    assert!(check(SessionsConfig {
        max_ttl_secs: 7 * 24 * 3600,
        ..ok.clone()
    })
    .is_ok());
    assert!(check(SessionsConfig {
        max_per_key: 1,
        ..ok.clone()
    })
    .is_ok());
    assert!(check(SessionsConfig {
        max_per_key: 256,
        ..ok.clone()
    })
    .is_ok());
    for (what, bad) in [
        (
            "default_ttl_secs",
            SessionsConfig {
                default_ttl_secs: 0,
                ..ok.clone()
            },
        ),
        (
            "max_ttl_secs",
            SessionsConfig {
                default_ttl_secs: 100,
                max_ttl_secs: 99,
                ..ok.clone()
            },
        ),
        (
            "max_ttl_secs",
            SessionsConfig {
                max_ttl_secs: 7 * 24 * 3600 + 1,
                ..ok.clone()
            },
        ),
        (
            "max_per_key",
            SessionsConfig {
                max_per_key: 0,
                ..ok.clone()
            },
        ),
        (
            "max_per_key",
            SessionsConfig {
                max_per_key: 257,
                ..ok.clone()
            },
        ),
    ] {
        let e = check(bad).unwrap_err().to_string();
        assert!(e.contains(&format!("sessions.{what}")), "{what}: {e}");
    }
    // Switched off, the numbers still have to make sense (a typo is not hidden).
    assert!(check(SessionsConfig {
        enabled: false,
        max_per_key: 0,
        ..ok
    })
    .is_err());
}

// ── [approval] and ui.public_url ──────────────────────────────────────────

#[test]
fn approval_defaults_match_the_documentation() {
    let a = ApprovalConfig::default();
    assert_eq!(a.wait_secs, 60);
    assert_eq!(a.pending_ttl_secs, 600);
    assert_eq!(a.max_grant_minutes, 480);
    assert_eq!(a.max_pending_per_key, 3);
    assert_eq!(a.max_requests_per_key_per_hour, 20);
    assert_eq!(a.max_waiters_per_key, 8);
    assert!(base_config(UnlockMode::Manual).validate().is_ok());
    assert_eq!(UiConfig::default().public_url, "");
}

#[test]
fn the_approval_section_comes_from_the_file_and_the_environment() {
    let from_file = from_toml(
        r#"
        unlock_mode = "manual"
        [approval]
        wait_secs = 90
        max_waiters_per_key = 2
        [ui]
        public_url = "https://fw.example.com/"
        "#,
    )
    .unwrap();
    assert_eq!(from_file.approval.wait_secs, 90);
    assert_eq!(from_file.approval.max_waiters_per_key, 2);
    assert_eq!(
        from_file.approval.pending_ttl_secs, 600,
        "the rest keeps its default"
    );
    assert_eq!(from_file.ui.public_url, "https://fw.example.com/");
    let from_env = from_env(&[
        ("FERROWARDEN_UNLOCK_MODE", "manual"),
        ("FERROWARDEN_APPROVAL__WAIT_SECS", "5"),
        ("FERROWARDEN_APPROVAL__PENDING_TTL_SECS", "50"),
        ("FERROWARDEN_APPROVAL__MAX_GRANT_MINUTES", "30"),
        ("FERROWARDEN_APPROVAL__MAX_PENDING_PER_KEY", "4"),
        ("FERROWARDEN_APPROVAL__MAX_REQUESTS_PER_KEY_PER_HOUR", "7"),
        ("FERROWARDEN_UI__PUBLIC_URL", "https://fw.example.com"),
    ])
    .unwrap();
    assert_eq!(from_env.approval.wait_secs, 5);
    assert_eq!(from_env.approval.pending_ttl_secs, 50);
    assert_eq!(from_env.approval.max_grant_minutes, 30);
    assert_eq!(from_env.approval.max_pending_per_key, 4);
    assert_eq!(from_env.approval.max_requests_per_key_per_hour, 7);
    assert_eq!(from_env.ui.public_url, "https://fw.example.com");
    // An unknown key is not silently accepted as a value.
    let bad = from_toml(
        r#"
        unlock_mode = "manual"
        [approval]
        wait_secs = "soon"
        "#,
    );
    assert!(bad.is_err());
}

#[test]
fn invalid_approval_settings_fail_validation() {
    let check = |f: &dyn Fn(&mut ApprovalConfig)| {
        let mut cfg = base_config(UnlockMode::Manual);
        f(&mut cfg.approval);
        cfg.validate()
    };
    // Every edge that is allowed.
    assert!(check(&|a| {
        a.wait_secs = 1;
        a.pending_ttl_secs = 1;
    })
    .is_ok());
    assert!(check(&|a| {
        a.wait_secs = 300;
        a.pending_ttl_secs = 3600;
    })
    .is_ok());
    assert!(check(&|a| a.pending_ttl_secs = a.wait_secs).is_ok());
    assert!(check(&|a| a.max_grant_minutes = 1).is_ok());
    assert!(check(&|a| a.max_grant_minutes = 10_080).is_ok());
    assert!(check(&|a| a.max_pending_per_key = 50).is_ok());
    assert!(check(&|a| a.max_requests_per_key_per_hour = 1000).is_ok());
    assert!(check(&|a| a.max_waiters_per_key = 100).is_ok());
    // And one step beyond each.
    let msg = |f: &dyn Fn(&mut ApprovalConfig)| check(f).unwrap_err().to_string();
    assert!(msg(&|a| a.wait_secs = 0).contains("approval.wait_secs"));
    assert!(msg(&|a| a.wait_secs = 301).contains("approval.wait_secs"));
    assert!(msg(&|a| a.pending_ttl_secs = a.wait_secs - 1).contains("at least approval.wait_secs"));
    assert!(msg(&|a| a.pending_ttl_secs = 3601).contains("approval.pending_ttl_secs"));
    assert!(msg(&|a| a.max_grant_minutes = 0).contains("approval.max_grant_minutes"));
    assert!(msg(&|a| a.max_grant_minutes = 10_081).contains("approval.max_grant_minutes"));
    assert!(msg(&|a| a.max_pending_per_key = 0).contains("approval.max_pending_per_key"));
    assert!(msg(&|a| a.max_pending_per_key = 51).contains("approval.max_pending_per_key"));
    assert!(msg(&|a| a.max_requests_per_key_per_hour = 0).contains("max_requests_per_key_per_hour"));
    assert!(
        msg(&|a| a.max_requests_per_key_per_hour = 1001).contains("max_requests_per_key_per_hour")
    );
    assert!(msg(&|a| a.max_waiters_per_key = 0).contains("approval.max_waiters_per_key"));
    assert!(msg(&|a| a.max_waiters_per_key = 101).contains("approval.max_waiters_per_key"));
    // The wait must fit under the open time: raising it past the default open
    // time alone is fine (300 < 600), past it is an error.
    assert!(check(&|a| a.wait_secs = 300).is_ok());
    assert!(msg(&|a| {
        a.wait_secs = 200;
        a.pending_ttl_secs = 199;
    })
    .contains("at least approval.wait_secs"));
}

#[test]
fn the_public_url_is_validated_and_makes_the_approval_link() {
    let check = |url: &str, insecure: bool| {
        let mut cfg = base_config(UnlockMode::Manual);
        cfg.ui.public_url = url.to_string();
        cfg.ui.insecure_http = insecure;
        cfg.validate()
    };
    for ok in [
        "",
        "https://fw.example.com",
        "https://fw.example.com/",
        "https://fw.example.com:8443/base",
        "https://[2001:db8::1]:3001",
    ] {
        assert!(check(ok, false).is_ok(), "{ok}");
    }
    // `http://` only with `ui.insecure_http`.
    assert!(check("http://fw.lan:3001", false).is_err());
    assert!(check("http://fw.lan:3001", true).is_ok());
    for bad in [
        "fw.example.com",
        "/approvals",
        "ftp://fw.example.com",
        "https://",
        "https://u:p@fw.example.com",
        "https://fw.example.com/?x=1",
        "https://fw.example.com/#f",
        "not a url",
    ] {
        assert!(check(bad, true).is_err(), "{bad}");
    }
    // Validated even when the UI is off (the setting is still wrong).
    assert!(check("nope", false).is_err());
    let err = check("http://fw.lan", false).unwrap_err().to_string();
    assert!(
        err.contains("ui.public_url") && err.contains("insecure_http"),
        "{err}"
    );

    let mut ui = UiConfig::default();
    assert_eq!(ui.approval_link("abc"), None);
    ui.public_url = "https://fw.example.com/".into();
    assert_eq!(
        ui.approval_link("abc").as_deref(),
        Some("https://fw.example.com/approvals/abc")
    );
    ui.public_url = "https://fw.example.com/base".into();
    assert_eq!(
        ui.approval_link("abc").as_deref(),
        Some("https://fw.example.com/base/approvals/abc")
    );
}

#[test]
fn the_approval_category_is_valid_and_on_by_default() {
    let mut cfg = base_config(UnlockMode::Manual);
    cfg.notify.events = vec!["approval".into()];
    assert!(cfg.validate().is_ok());
    assert!(cfg
        .notify
        .categories()
        .contains(crate::notify::Category::Approval));
    cfg.notify.events = vec!["nope".into()];
    assert!(cfg.validate().unwrap_err().to_string().contains("approval"));
    assert!(NotifyConfig::default()
        .categories()
        .contains(crate::notify::Category::Approval));
}
