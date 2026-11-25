
use super::*;
use std::collections::HashMap;

const NAME: &str = "FERROWARDEN_ADMIN_KEY";
const FILE: &str = "FERROWARDEN_ADMIN_KEY_FILE";

fn load(
    both: Both,
    env: &[(&str, &str)],
    files: &[(&str, &[u8])],
) -> FerroResult<Option<Zeroizing<String>>> {
    let env: HashMap<String, String> = env
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    let files: HashMap<String, Vec<u8>> = files
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_vec()))
        .collect();
    load_secret(
        NAME,
        both,
        |n| env.get(n).filter(|v| !v.is_empty()).cloned(),
        |p| {
            files
                .get(p.to_str().unwrap())
                .cloned()
                .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))
        },
    )
}

fn value(r: FerroResult<Option<Zeroizing<String>>>) -> Option<String> {
    r.unwrap().map(|v| v.to_string())
}

#[test]
fn nothing_set_is_none() {
    assert_eq!(value(load(Both::DirectWins, &[], &[])), None);
    // An empty variable counts as unset.
    assert_eq!(value(load(Both::DirectWins, &[(NAME, "")], &[])), None);
}

#[test]
fn the_direct_variable_is_used() {
    assert_eq!(
        value(load(Both::DirectWins, &[(NAME, "direct-value")], &[])),
        Some("direct-value".into())
    );
}

#[test]
fn the_file_is_read_and_trailing_newlines_are_removed() {
    let env = [(FILE, "/run/secrets/k")];
    for (content, want) in [
        (&b"file-value"[..], "file-value"),
        (b"file-value\n", "file-value"),
        (b"file-value\r\n", "file-value"),
        (b"file-value\n\n", "file-value"),
        // Other whitespace is part of the secret.
        (b" file value \n", " file value "),
    ] {
        let got = value(load(Both::DirectWins, &env, &[("/run/secrets/k", content)]));
        assert_eq!(got.as_deref(), Some(want));
    }
}

#[test]
fn the_direct_variable_takes_precedence_without_reading_the_file() {
    // The file does not exist: it must not even be opened.
    let got = value(load(
        Both::DirectWins,
        &[(NAME, "direct-value"), (FILE, "/missing")],
        &[],
    ));
    assert_eq!(got.as_deref(), Some("direct-value"));
}

#[test]
fn both_set_is_an_error_when_the_secret_demands_one_source() {
    let err = load(
        Both::Error,
        &[(NAME, "direct-secret-value"), (FILE, "/f")],
        &[("/f", b"file-secret-value")],
    )
    .unwrap_err()
    .to_string();
    assert!(err.contains("only one of"), "{err}");
    assert!(!err.contains("secret-value"), "{err}");
}

#[test]
fn a_missing_file_names_the_variable_and_the_path() {
    let err = load(Both::DirectWins, &[(FILE, "/run/secrets/gone")], &[])
        .unwrap_err()
        .to_string();
    assert!(err.contains(FILE), "{err}");
    assert!(err.contains("does not exist"), "{err}");
    assert!(err.contains("/run/secrets/gone"), "{err}");
}

#[test]
fn an_unreadable_file_gets_the_uid_hint() {
    let err = load_secret(
        NAME,
        Both::DirectWins,
        |n| (n == FILE).then(|| "/run/secrets/k".to_string()),
        |_| Err(io::Error::from(io::ErrorKind::PermissionDenied)),
    )
    .unwrap_err()
    .to_string();
    assert!(err.contains("cannot read /run/secrets/k"), "{err}");
    assert!(err.contains("as UID"), "{err}");
    assert!(err.contains("chown 999:999"), "{err}");
}

#[test]
fn empty_and_invalid_files_are_errors_that_never_echo_the_value() {
    let env = [(FILE, "/f")];
    for content in [&b""[..], b"\n", b"\r\n"] {
        let err = load(Both::DirectWins, &env, &[("/f", content)])
            .unwrap_err()
            .to_string();
        assert!(err.contains("is empty"), "{err}");
    }
    let err = load(Both::DirectWins, &env, &[("/f", &[0xff, 0xfe, 0x41])])
        .unwrap_err()
        .to_string();
    assert!(err.contains("UTF-8"), "{err}");
}

#[test]
fn loading_from_the_real_environment_never_sets_a_variable() {
    // Unique names: no other test touches them, and the helper must not
    // create the secret variable as a side effect.
    let name = "FW_TEST_SECRET_NEVER_EXPORTED";
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("secret");
    std::fs::write(&path, "value-from-a-file\n").unwrap();
    std::env::set_var(format!("{name}_FILE"), &path);
    let got = load_secret_from_env(name, Both::DirectWins)
        .unwrap()
        .unwrap();
    assert_eq!(got.as_str(), "value-from-a-file");
    assert!(std::env::var(name).is_err());
    std::env::remove_var(format!("{name}_FILE"));
}
