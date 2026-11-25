
use super::*;
use tempfile::tempdir;

#[test]
fn hash_is_deterministic() {
    assert_eq!(hash_token("abc"), hash_token("abc"));
}

#[test]
fn hash_differs_for_different_inputs() {
    assert_ne!(hash_token("abc"), hash_token("xyz"));
}

#[test]
fn hash_matches_known_sha256_vectors() {
    // FIPS 180-2 test vectors. Agent key files store this exact lowercase
    // hex form, so a dependency upgrade that changed it would invalidate
    // every persisted agent key.
    assert_eq!(
        hash_token(""),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    assert_eq!(
        hash_token("abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}

#[test]
fn hash_is_hex_sha256_length() {
    // SHA-256 → 32 bytes → 64 hex chars
    assert_eq!(hash_token("any_token").len(), 64);
}

#[test]
fn load_returns_empty_for_missing_file() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("keys.json");
    let keys = load(&path).unwrap();
    assert!(keys.is_empty());
}

#[test]
fn save_and_load_roundtrip() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("keys.json");

    let keys = vec![
        StoredKey {
            id: "id-1".to_string(),
            name: "agent-one".to_string(),
            token_hash: hash_token("secret-token-one"),
            created_at: Utc::now(),
            credentials: None,
            methods: None,
        },
        StoredKey {
            id: "id-2".to_string(),
            name: "agent-two".to_string(),
            token_hash: hash_token("secret-token-two"),
            created_at: Utc::now(),
            credentials: None,
            methods: None,
        },
    ];

    save(&path, &keys).unwrap();
    let loaded = load(&path).unwrap();

    assert_eq!(loaded.len(), 2);
    assert_eq!(loaded[0].id, "id-1");
    assert_eq!(loaded[1].name, "agent-two");
    assert_eq!(loaded[0].token_hash, hash_token("secret-token-one"));
}

#[test]
fn save_is_atomic_tmp_file_cleaned_up() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("keys.json");
    let tmp = path.with_extension("tmp");

    save(&path, &[]).unwrap();

    assert!(path.exists(), "key file should exist after save");
    assert!(!tmp.exists(), "tmp file should be gone after atomic rename");
}

#[test]
fn save_overwrites_existing_file() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("keys.json");

    let v1 = vec![StoredKey {
        id: "original".to_string(),
        name: "old".to_string(),
        token_hash: "hash1".to_string(),
        created_at: Utc::now(),
        credentials: None,
        methods: None,
    }];
    save(&path, &v1).unwrap();

    save(&path, &[]).unwrap();
    let loaded = load(&path).unwrap();
    assert!(
        loaded.is_empty(),
        "overwrite should replace previous contents"
    );
}

fn write_raw(contents: &str) -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempdir().unwrap();
    let path = dir.path().join("keys.json");
    std::fs::write(&path, contents).unwrap();
    (dir, path)
}

const ONE: &str = r#"{"id":"i","name":"n","token_hash":"h","created_at":"2024-01-01T00:00:00Z"}"#;

#[test]
fn load_accepts_valid_key_file() {
    let (_d, p) = write_raw(&format!("[{ONE}]"));
    let keys = load(&p).unwrap();
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0].id, "i");
}

#[test]
fn load_rejects_duplicate_keys_in_an_entry() {
    let (_d, p) = write_raw(
        r#"[{"id":"i","id":"j","name":"n","token_hash":"h","created_at":"2024-01-01T00:00:00Z"}]"#,
    );
    let e = load(&p).unwrap_err();
    assert_eq!(e.kind(), io::ErrorKind::InvalidData);
    assert!(e.to_string().contains("duplicate key"), "{e}");
}

#[test]
fn load_rejects_unknown_fields() {
    let (_d, p) = write_raw(&format!("[{}]", ONE.replace('}', r#","role":"admin"}"#)));
    let e = load(&p).unwrap_err();
    assert!(e.to_string().contains("unknown field `role`"), "{e}");
}

#[test]
fn load_rejects_malformed_and_trailing_data() {
    let (_d, p) = write_raw("[");
    assert!(load(&p).is_err());
    let (_d, p) = write_raw(&format!("[{ONE}] []"));
    assert!(load(&p).is_err());
}

// ── policy fields ─────────────────────────────────────────────────────────

#[test]
fn legacy_entry_without_policy_loads_deny_all_and_is_marked() {
    let (_d, p) = write_raw(&format!("[{ONE}]"));
    let keys = load(&p).unwrap();
    assert!(!keys[0].policy_set());
    assert_eq!(keys[0].policy(), KeyPolicy::default());
}

#[test]
fn entry_with_both_fields_has_a_policy() {
    let (_d, p) = write_raw(&format!(
        "[{}]",
        ONE.replace('}', r#","credentials":["a_*","a_*"],"methods":["get"]}"#)
    ));
    let keys = load(&p).unwrap();
    assert!(keys[0].policy_set());
    let policy = keys[0].policy();
    assert_eq!(policy.credentials, vec!["a_*".to_string()]);
    assert_eq!(policy.methods, vec!["GET".to_string()]);
}

#[test]
fn explicit_empty_lists_are_a_set_deny_all_policy() {
    let (_d, p) = write_raw(&format!(
        "[{}]",
        ONE.replace('}', r#","credentials":[],"methods":[]}"#)
    ));
    let keys = load(&p).unwrap();
    assert!(keys[0].policy_set());
    assert!(keys[0].policy().credentials.is_empty());
}

#[test]
fn a_single_field_leaves_the_other_denied_and_the_policy_unset() {
    let (_d, p) = write_raw(&format!(
        "[{}]",
        ONE.replace('}', r#","credentials":["*"]}"#)
    ));
    let keys = load(&p).unwrap();
    assert!(!keys[0].policy_set());
    assert_eq!(keys[0].policy().credentials, vec!["*".to_string()]);
    assert!(keys[0].policy().methods.is_empty());
}

#[test]
fn null_policy_fields_fail_the_load() {
    for field in ["credentials", "methods"] {
        let (_d, p) = write_raw(&format!(
            "[{}]",
            ONE.replace('}', &format!(r#","{field}":null}}"#))
        ));
        let e = load(&p).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::InvalidData);
        assert!(e.to_string().contains(&format!("`{field}`")), "{e}");
    }
}

#[test]
fn invalid_policy_values_fail_the_load() {
    for extra in [
        r#","credentials":[""]"#,
        r#","credentials":["a
b"]"#,
        r#","credentials":"*""#,
        r#","methods":["TRACE"]"#,
        r#","methods":["*","GET"]"#,
    ] {
        let (_d, p) = write_raw(&format!("[{}]", ONE.replace('}', &format!("{extra}}}"))));
        assert!(load(&p).is_err(), "{extra}");
    }
}

#[test]
fn policy_roundtrips_and_is_always_written_explicitly() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("keys.json");
    let policy = KeyPolicy::from_raw(vec!["lab_*".into()], vec!["*".into()]).unwrap();
    let keys = vec![StoredKey::new(
        "i".into(),
        "n".into(),
        "h".into(),
        Utc::now(),
        &policy,
    )];
    save(&path, &keys).unwrap();
    let raw = std::fs::read_to_string(&path).unwrap();
    assert!(
        raw.contains("\"credentials\"") && raw.contains("\"methods\""),
        "{raw}"
    );
    let loaded = load(&path).unwrap();
    assert!(loaded[0].policy_set());
    assert_eq!(loaded[0].policy(), policy);
}
