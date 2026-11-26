use super::*;
use std::collections::HashMap;

pub const FAKE_KEY: &str = "fw_agent_FAKEKEY0123456789";
pub const FAKE_PREFIX: &str = "s3cr3tpr3fix";

fn lookup(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Result<Option<String>, ()> {
    let map: HashMap<String, String> = pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    move |name| Ok(map.get(name).cloned())
}

fn load(pairs: &[(&str, &str)]) -> Result<Config, ConfigError> {
    Config::from_lookup(lookup(pairs))
}

fn msg(r: Result<Config, ConfigError>) -> String {
    r.expect_err("expected a configuration error").0
}

#[test]
fn minimal_https_config_defaults() {
    let c = load(&[(ENV_URL, "https://ferro.example.com"), (ENV_KEY, FAKE_KEY)]).unwrap();
    assert_eq!(c.timeout, Duration::from_secs(400));
    assert_eq!(c.agent_key.as_str(), FAKE_KEY);
    assert!(!c.insecure_http_allowed);
    assert!(!c.uses_insecure_http());
    assert!(c.extra_roots.is_empty());
}

#[test]
fn url_and_key_are_required() {
    assert!(msg(load(&[(ENV_KEY, FAKE_KEY)])).contains(ENV_URL));
    assert!(msg(load(&[(ENV_URL, "https://f.example.com")])).contains(ENV_KEY));
    // Blank counts as unset.
    assert!(msg(load(&[(ENV_URL, "  "), (ENV_KEY, FAKE_KEY)])).contains(ENV_URL));
}

#[test]
fn prefix_is_kept_and_trailing_slash_removed() {
    let url = format!("https://ferro.example.com/{FAKE_PREFIX}/");
    let c = load(&[(ENV_URL, &url), (ENV_KEY, FAKE_KEY)]).unwrap();
    assert_eq!(c.base_url.path(), format!("/{FAKE_PREFIX}"));
    let bare = load(&[(ENV_URL, "https://ferro.example.com/"), (ENV_KEY, FAKE_KEY)]).unwrap();
    assert_eq!(bare.base_url.path(), "/");
}

#[test]
fn plain_http_only_for_loopback_or_when_allowed() {
    for ok in [
        "http://localhost:3000",
        "http://127.0.0.1:3000/p",
        "http://[::1]:3000",
    ] {
        let c = load(&[(ENV_URL, ok), (ENV_KEY, FAKE_KEY)]).unwrap();
        assert!(!c.uses_insecure_http(), "{ok}");
    }
    let url = format!("http://ferro.lan:3000/{FAKE_PREFIX}");
    let refused = msg(load(&[(ENV_URL, &url), (ENV_KEY, FAKE_KEY)]));
    assert!(refused.contains("https://"));
    assert!(!refused.contains(FAKE_PREFIX), "error echoed the URL path");
    let c = load(&[(ENV_URL, &url), (ENV_KEY, FAKE_KEY), (ENV_ALLOW_HTTP, "1")]).unwrap();
    assert!(c.uses_insecure_http());
    assert_eq!(c.host_for_log(), "ferro.lan:3000");
    assert!(msg(load(&[
        (ENV_URL, &url),
        (ENV_KEY, FAKE_KEY),
        (ENV_ALLOW_HTTP, "yes"),
    ]))
    .contains(ENV_ALLOW_HTTP));
    // 0 is the same as unset.
    assert!(load(&[(ENV_URL, &url), (ENV_KEY, FAKE_KEY), (ENV_ALLOW_HTTP, "0")]).is_err());
}

#[test]
fn rejects_bad_urls_without_echoing_them() {
    for bad in [
        "ftp://ferro.example.com/x",
        "not a url",
        "https://user:pw@ferro.example.com/x",
        "https://ferro.example.com/x?a=1",
        "https://ferro.example.com/x#frag",
        "mailto:someone@example.com",
    ] {
        let m = msg(load(&[(ENV_URL, bad), (ENV_KEY, FAKE_KEY)]));
        assert!(
            !m.contains("pw@") && !m.contains("ferro.example.com"),
            "{m}"
        );
    }
}

#[test]
fn key_file_is_trimmed_and_conflicts_with_key() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("agent-key");
    std::fs::write(&path, format!("  {FAKE_KEY}\r\n")).unwrap();
    let p = path.to_str().unwrap();
    let c = load(&[(ENV_URL, "https://f.example.com"), (ENV_KEY_FILE, p)]).unwrap();
    assert_eq!(c.agent_key.as_str(), FAKE_KEY);

    let both = msg(load(&[
        (ENV_URL, "https://f.example.com"),
        (ENV_KEY, FAKE_KEY),
        (ENV_KEY_FILE, p),
    ]));
    assert!(both.contains("only one"));
    assert!(!both.contains(FAKE_KEY));

    std::fs::write(&path, "  \n").unwrap();
    assert!(msg(load(&[
        (ENV_URL, "https://f.example.com"),
        (ENV_KEY_FILE, p)
    ]))
    .contains("empty"));

    let missing = dir.path().join("nope");
    let m = msg(load(&[
        (ENV_URL, "https://f.example.com"),
        (ENV_KEY_FILE, missing.to_str().unwrap()),
    ]));
    assert!(m.contains(ENV_KEY_FILE));
    assert!(!m.contains("nope"), "error echoed the file path");
}

#[test]
fn key_with_whitespace_inside_is_refused() {
    let m = msg(load(&[
        (ENV_URL, "https://f.example.com"),
        (ENV_KEY, "two words"),
    ]));
    assert!(!m.contains("two words"));
    assert!(m.contains("single token"));
}

#[test]
fn timeout_bounds() {
    let base = [(ENV_URL, "https://f.example.com"), (ENV_KEY, FAKE_KEY)];
    let with = |t: &str| {
        let mut v = base.to_vec();
        v.push((ENV_TIMEOUT, t));
        load(&v)
    };
    assert_eq!(with("1").unwrap().timeout, Duration::from_secs(1));
    assert_eq!(with("600").unwrap().timeout, Duration::from_secs(600));
    for bad in ["0", "601", "-5", "abc", "1.5"] {
        assert!(msg(with(bad)).contains(ENV_TIMEOUT), "{bad}");
    }
}

#[test]
fn ca_file_errors() {
    let dir = tempfile::tempdir().unwrap();
    let base = |ca: &str| {
        load(&[
            (ENV_URL, "https://f.example.com"),
            (ENV_KEY, FAKE_KEY),
            (ENV_CA_FILE, ca),
        ])
    };
    let missing = dir.path().join("missing.pem");
    assert!(msg(base(missing.to_str().unwrap())).contains(ENV_CA_FILE));

    let junk = dir.path().join("junk.pem");
    std::fs::write(&junk, "this is not a certificate").unwrap();
    assert!(msg(base(junk.to_str().unwrap())).contains(ENV_CA_FILE));

    let ca = dir.path().join("ca.pem");
    std::fs::write(&ca, include_str!("../testdata/test-ca.pem")).unwrap();
    let c = base(ca.to_str().unwrap()).unwrap();
    assert_eq!(c.extra_roots.len(), 1);
}

#[test]
fn debug_output_hides_key_and_path() {
    let url = format!("https://ferro.example.com/{FAKE_PREFIX}");
    let c = load(&[(ENV_URL, &url), (ENV_KEY, FAKE_KEY)]).unwrap();
    let shown = format!("{c:?}");
    assert!(!shown.contains(FAKE_KEY));
    assert!(!shown.contains(FAKE_PREFIX));
    assert!(shown.contains("ferro.example.com"));
}

#[test]
fn non_unicode_value_is_an_error() {
    let r = Config::from_lookup(|name| if name == ENV_URL { Err(()) } else { Ok(None) });
    assert!(msg(r).contains("UTF-8"));
}
