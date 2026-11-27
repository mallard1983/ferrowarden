use super::super::enc::encrypt;
use super::super::enc::test_support::key;
use super::*;

const ORG: &str = "org-1";
const ID_A: &str = "0f9b3a52-1c1e-4a0e-9d57-1a2b3c4d5e6f";
const ID_B: &str = "6c0d7f0e-52d0-4b5b-8a39-0e8a7f6d5c4b";

fn orgs() -> HashMap<String, SymKey> {
    HashMap::from([(ORG.to_string(), key(40))])
}

fn coll(id: &str, name: &str, read_only: Option<bool>, hide: Option<bool>) -> RawCollection {
    RawCollection {
        id: id.to_string(),
        organization_id: Some(ORG.to_string()),
        name: Some(encrypt(&key(40), name.as_bytes()).unwrap()),
        read_only,
        hide_passwords: hide,
    }
}

fn writable(id: &str, name: &str) -> RawCollection {
    coll(id, name, Some(false), Some(false))
}

fn problem(state: ManagedState) -> ManagedProblem {
    match state {
        ManagedState::Unavailable { problem, .. } => problem,
        other => panic!("expected a problem, got {other:?}"),
    }
}

#[test]
fn not_configured_is_off() {
    assert_eq!(
        evaluate(None, &[writable(ID_A, "x")], &orgs()),
        ManagedState::Off
    );
}

#[test]
fn a_writable_collection_is_usable_by_id_or_by_name() {
    let all = [
        writable(ID_A, "Ferrowarden managed"),
        writable(ID_B, "Other"),
    ];
    for setting in [ID_A, "Ferrowarden managed"] {
        match evaluate(Some(setting), &all, &orgs()) {
            ManagedState::Usable(c) => {
                assert_eq!(c.id, ID_A);
                assert_eq!(c.organization_id, ORG);
                assert_eq!(c.name, "Ferrowarden managed");
            }
            other => panic!("{setting}: {other:?}"),
        }
    }
    // An id is compared without regard to letter case.
    let upper = ID_A.to_ascii_uppercase();
    assert!(matches!(
        evaluate(Some(&upper), &all, &orgs()),
        ManagedState::Usable(c) if c.id == ID_A
    ));
}

#[test]
fn names_are_exact_and_case_sensitive() {
    let all = [writable(ID_A, "Ferrowarden managed")];
    for setting in ["ferrowarden managed", "Ferrowarden", "Ferrowarden managed "] {
        // (the setting is trimmed by the config, not here)
        assert_eq!(
            problem(evaluate(Some(setting), &all, &orgs())),
            ManagedProblem::NotFound,
            "{setting:?}"
        );
    }
}

#[test]
fn a_missing_collection_is_not_found() {
    let all = [writable(ID_A, "Mine")];
    assert_eq!(
        problem(evaluate(Some(ID_B), &all, &orgs())),
        ManagedProblem::NotFound
    );
    assert_eq!(
        problem(evaluate(Some("Nope"), &all, &orgs())),
        ManagedProblem::NotFound
    );
    assert_eq!(
        problem(evaluate(Some("Nope"), &[], &orgs())),
        ManagedProblem::NotFound
    );
}

#[test]
fn a_view_only_collection_is_refused() {
    let all = [coll(ID_A, "Mine", Some(true), Some(false))];
    for setting in [ID_A, "Mine"] {
        assert_eq!(
            problem(evaluate(Some(setting), &all, &orgs())),
            ManagedProblem::ReadOnly
        );
    }
}

#[test]
fn a_collection_that_hides_passwords_is_refused() {
    let all = [coll(ID_A, "Mine", Some(false), Some(true))];
    for setting in [ID_A, "Mine"] {
        assert_eq!(
            problem(evaluate(Some(setting), &all, &orgs())),
            ManagedProblem::HidesPasswords
        );
    }
}

#[test]
fn a_flag_the_server_did_not_send_is_not_trusted() {
    let no_read_only = [coll(ID_A, "Mine", None, Some(false))];
    assert_eq!(
        problem(evaluate(Some(ID_A), &no_read_only, &orgs())),
        ManagedProblem::ReadOnly
    );
    let no_hide = [coll(ID_A, "Mine", Some(false), None)];
    assert_eq!(
        problem(evaluate(Some(ID_A), &no_hide, &orgs())),
        ManagedProblem::HidesPasswords
    );
}

#[test]
fn a_name_that_matches_two_collections_is_ambiguous_and_the_id_still_works() {
    let all = [writable(ID_A, "Shared name"), writable(ID_B, "Shared name")];
    assert_eq!(
        problem(evaluate(Some("Shared name"), &all, &orgs())),
        ManagedProblem::Ambiguous
    );
    assert!(matches!(
        evaluate(Some(ID_B), &all, &orgs()),
        ManagedState::Usable(c) if c.id == ID_B
    ));
}

#[test]
fn without_the_organisation_key_nothing_is_written() {
    let none = HashMap::new();
    let all = [writable(ID_A, "Mine")];
    // By id the collection is found, but cannot be encrypted into.
    assert_eq!(
        problem(evaluate(Some(ID_A), &all, &none)),
        ManagedProblem::NoOrganizationKey
    );
    // By name it cannot even be matched (the name cannot be decrypted).
    assert_eq!(
        problem(evaluate(Some("Mine"), &all, &none)),
        ManagedProblem::NotFound
    );
}

#[test]
fn a_collection_without_an_organisation_is_not_usable() {
    let mut c = writable(ID_A, "Mine");
    c.organization_id = None;
    assert_eq!(
        problem(evaluate(Some(ID_A), &[c], &orgs())),
        ManagedProblem::NotFound
    );
}

#[test]
fn a_name_that_will_not_decrypt_never_matches() {
    let mut c = writable(ID_A, "Mine");
    // Encrypted under a different key: the MAC fails.
    c.name = Some(encrypt(&key(99), b"Mine").unwrap());
    assert_eq!(
        problem(evaluate(Some("Mine"), &[c.clone()], &orgs())),
        ManagedProblem::NotFound
    );
    // By id it is still the collection; the name falls back to the setting.
    assert!(matches!(
        evaluate(Some(ID_A), &[c], &orgs()),
        ManagedState::Usable(c) if c.name == ID_A
    ));
}

#[test]
fn problems_have_fixed_codes_and_messages() {
    for p in [
        ManagedProblem::NotFound,
        ManagedProblem::ReadOnly,
        ManagedProblem::HidesPasswords,
        ManagedProblem::Ambiguous,
        ManagedProblem::NoOrganizationKey,
    ] {
        assert!(!p.code().is_empty() && !p.describe().is_empty());
    }
    assert_eq!(ManagedProblem::ReadOnly.code(), "read_only");
    assert_eq!(ManagedProblem::HidesPasswords.code(), "hides_passwords");
}
