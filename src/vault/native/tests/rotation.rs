//! The rotation calls of the native vault against a mock Vaultwarden that
//! implements `GET` and `PUT /api/ciphers/{id}` the way the real server does
//! for a stale write: a `PUT` that names an old revision is refused with a 400
//! whose message says the client copy is out of date.

use super::*;
use crate::vault::model::NEXT_FIELD;

const NEXT: &str = "PENDING-VALUE-0123456789";

/// The harness with `orgitem` (c3, organisation key) in the managed
/// collection and `orgwithkey` (c4, its own key) in the other one.
async fn unlocked_managed() -> Harness {
    let h = managed_harness("Ferrowarden managed").await;
    h.vault.unlock(pw()).await.unwrap();
    h
}

fn next() -> Zeroizing<String> {
    Zeroizing::new(NEXT.to_string())
}

fn cipher(h: &Harness, id: &str) -> Value {
    h.mock
        .lock()
        .unwrap()
        .ciphers
        .iter()
        .find(|c| c["id"] == id)
        .unwrap()
        .clone()
}

fn open(k: &SymKey, v: &Value) -> String {
    EncString::parse(v.as_str().unwrap())
        .unwrap()
        .decrypt_string(k)
        .unwrap()
        .as_str()
        .to_string()
}

async fn password_of(h: &Harness, id: &str) -> String {
    h.vault
        .get_value(Builtin::Password, id, "x")
        .await
        .unwrap()
        .as_str()
        .to_string()
}

async fn next_of(h: &Harness, id: &str) -> Result<String, FerroError> {
    h.vault
        .get_value(Builtin::Next, id, "x")
        .await
        .map(|v| v.as_str().to_string())
}

fn puts(h: &Harness) -> usize {
    h.mock.lock().unwrap().puts.len()
}

#[tokio::test]
async fn start_writes_only_the_pending_field_and_the_password_stays() {
    let h = unlocked_managed().await;
    let before = cipher(&h, "c3");
    h.vault.rotate_start("c3", "orgitem", next()).await.unwrap();

    // One PUT, naming the revision that was read.
    let (id, body) = h.mock.lock().unwrap().puts[0].clone();
    assert_eq!(id, "c3");
    assert_eq!(body["lastKnownRevisionDate"], "2026-11-26T10:00:00.000000Z");
    for m in crate::vault::native::rotate::RESPONSE_ONLY {
        assert!(body.get(m).is_none(), "{m} is not sent");
    }
    assert_eq!(body["organizationId"], "org1");
    // The one member the server needs and a read does not have.
    assert_eq!(body["encryptedFor"], USER_ID);
    // Everything else is what the server had, but the fields.
    for (k, v) in before.as_object().unwrap() {
        if matches!(
            k.as_str(),
            "fields" | "id" | "collectionIds" | "revisionDate" | "encryptedFor"
        ) {
            continue;
        }
        assert_eq!(&body[k], v, "{k}");
    }
    let fields = body["fields"].as_array().unwrap();
    assert_eq!(fields.len(), 2);
    assert_eq!(fields[0], before["fields"][0]);
    assert_eq!(open(&h.acct.org, &fields[1]["name"]), NEXT_FIELD);
    assert_eq!(open(&h.acct.org, &fields[1]["value"]), NEXT);
    assert_eq!(fields[1]["type"], 1);
    assert!(!body.to_string().contains(NEXT));

    // After the next sync the item shows the pending rotation, the current
    // password is untouched and the pending one is reachable as `next`.
    h.vault.sync().await.unwrap();
    let listing = h.vault.list_credentials().await.unwrap();
    let entry = &listing.map["orgitem"][0];
    assert!(entry.has_next);
    assert_eq!(entry.collection_ids, [COLL_MANAGED]);
    assert!(
        entry.fields.iter().all(|f| f.name != NEXT_FIELD),
        "the reserved field is not offered as a field"
    );
    assert_eq!(password_of(&h, "c3").await, "PASS-orgitem");
    assert_eq!(next_of(&h, "c3").await.unwrap(), NEXT);
}

#[tokio::test]
async fn commit_makes_the_pending_value_the_password_and_keeps_the_old_one() {
    let h = unlocked_managed().await;
    h.vault.rotate_start("c3", "orgitem", next()).await.unwrap();
    h.vault.sync().await.unwrap();
    h.vault.rotate_commit("c3", "orgitem").await.unwrap();

    let (_, body) = h.mock.lock().unwrap().puts[1].clone();
    // The second write names the revision the first one produced.
    assert_eq!(body["lastKnownRevisionDate"], "2026-11-26T11:00:01.000000Z");
    let history = body["passwordHistory"].as_array().unwrap();
    assert_eq!(history.len(), 1);
    assert_eq!(open(&h.acct.org, &history[0]["password"]), "PASS-orgitem");
    assert!(history[0]["lastUsedDate"].as_str().unwrap().ends_with('Z'));
    assert!(body["login"]["passwordRevisionDate"].is_string());
    assert_eq!(body["fields"].as_array().unwrap().len(), 1);

    h.vault.sync().await.unwrap();
    assert_eq!(password_of(&h, "c3").await, NEXT);
    assert!(matches!(
        next_of(&h, "c3").await,
        Err(FerroError::CredentialNotFound(_))
    ));
    let listing = h.vault.list_credentials().await.unwrap();
    assert!(!listing.map["orgitem"][0].has_next);
}

#[tokio::test]
async fn abort_removes_the_field_and_leaves_the_password() {
    let h = unlocked_managed().await;
    h.vault.rotate_start("c3", "orgitem", next()).await.unwrap();
    h.vault.rotate_abort("c3", "orgitem").await.unwrap();
    h.vault.sync().await.unwrap();
    assert_eq!(password_of(&h, "c3").await, "PASS-orgitem");
    assert!(next_of(&h, "c3").await.is_err());
    let after = cipher(&h, "c3");
    assert_eq!(after["passwordHistory"], Value::Null, "no history");
    assert_eq!(after["fields"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn a_second_start_and_a_commit_without_a_start_are_refused_without_writing() {
    let h = unlocked_managed().await;
    let e = h.vault.rotate_commit("c3", "orgitem").await.unwrap_err();
    assert!(matches!(e, FerroError::NoRotationPending(n) if n == "orgitem"));
    let e = h.vault.rotate_abort("c3", "orgitem").await.unwrap_err();
    assert!(matches!(e, FerroError::NoRotationPending(_)));
    assert_eq!(puts(&h), 0);

    h.vault.rotate_start("c3", "orgitem", next()).await.unwrap();
    let e = h
        .vault
        .rotate_start("c3", "orgitem", next())
        .await
        .unwrap_err();
    assert!(matches!(e, FerroError::RotationInProgress(n) if n == "orgitem"));
    assert_eq!(puts(&h), 1);
}

#[tokio::test]
async fn an_edit_by_a_person_in_between_is_never_overwritten() {
    let h = unlocked_managed().await;
    h.vault.rotate_start("c3", "orgitem", next()).await.unwrap();

    // A person edits the item's notes in the vault (a new revision).
    let human_notes = enc(&h.acct.org, "a person was here");
    {
        let mut m = h.mock.lock().unwrap();
        let c = m.ciphers.iter_mut().find(|c| c["id"] == "c3").unwrap();
        c["notes"] = human_notes.clone();
        c["revisionDate"] = json!("2026-11-26T11:30:00.000000Z");
        m.revision += 1;
    }
    h.vault.sync().await.unwrap();

    // The commit finds a revision it did not write: refused, and nothing was
    // sent (only the start's PUT happened).
    let e = h.vault.rotate_commit("c3", "orgitem").await.unwrap_err();
    assert!(matches!(e, FerroError::VaultConflict), "{e}");
    assert_eq!(h.mock.lock().unwrap().put_calls, 1);
    assert_eq!(cipher(&h, "c3")["notes"], human_notes);
    assert_eq!(password_of(&h, "c3").await, "PASS-orgitem");

    // Retrying (having re-read the item) goes through, with the person's edit
    // kept.
    h.vault.rotate_commit("c3", "orgitem").await.unwrap();
    assert_eq!(cipher(&h, "c3")["notes"], human_notes);
    h.vault.sync().await.unwrap();
    assert_eq!(password_of(&h, "c3").await, NEXT);
}

#[tokio::test]
async fn the_server_refusing_a_stale_write_is_a_conflict_and_nothing_is_retried() {
    let h = unlocked_managed().await;
    // Someone saves between our read and our write.
    h.mock.lock().unwrap().put_stale_once = true;
    let e = h
        .vault
        .rotate_start("c3", "orgitem", next())
        .await
        .unwrap_err();
    assert!(matches!(e, FerroError::VaultConflict), "{e}");
    assert_eq!(h.mock.lock().unwrap().put_calls, 1, "not sent again");
    assert_eq!(puts(&h), 0, "nothing applied");
    assert!(cipher(&h, "c3")["fields"].as_array().unwrap().len() == 1);
}

#[tokio::test]
async fn other_failures_are_write_failures_and_only_a_401_is_retried() {
    let h = unlocked_managed().await;
    h.mock.lock().unwrap().put_status = Some(500);
    let e = h
        .vault
        .rotate_start("c3", "orgitem", next())
        .await
        .unwrap_err();
    assert!(matches!(e, FerroError::VaultWriteFailed), "{e}");
    assert_eq!(h.mock.lock().unwrap().put_calls, 1, "a 5xx is not retried");
    // A 400 that is not about the revision is not a conflict.
    h.mock.lock().unwrap().put_status = Some(400);
    let e = h
        .vault
        .rotate_start("c3", "orgitem", next())
        .await
        .unwrap_err();
    assert!(matches!(e, FerroError::VaultWriteFailed), "{e}");
    h.mock.lock().unwrap().put_status = None;

    let logins = h.mock.lock().unwrap().logins;
    h.mock.lock().unwrap().put_reject_once = true;
    h.vault.rotate_start("c3", "orgitem", next()).await.unwrap();
    let m = h.mock.lock().unwrap();
    assert_eq!(m.logins, logins + 1, "one fresh login");
    assert_eq!(m.puts.len(), 1, "applied once");
}

#[tokio::test]
async fn an_item_outside_the_managed_collection_is_never_touched() {
    let h = unlocked_managed().await;
    // In another collection of the same organisation.
    let e = h
        .vault
        .rotate_start("c4", "orgwithkey", next())
        .await
        .unwrap_err();
    assert!(matches!(e, FerroError::CredentialNotManaged(_)), "{e}");
    // A personal item, and one that does not exist.
    let e = h
        .vault
        .rotate_start("c1", "plain", next())
        .await
        .unwrap_err();
    assert!(matches!(e, FerroError::CredentialNotManaged(_)), "{e}");
    let e = h.vault.rotate_commit("nope", "nope").await.unwrap_err();
    assert!(matches!(e, FerroError::CredentialNotFound(_)), "{e}");
    let m = h.mock.lock().unwrap();
    assert!(m.gets.is_empty(), "the item was not even read");
    assert_eq!(m.put_calls, 0);
}

#[tokio::test]
async fn an_item_the_server_says_is_elsewhere_is_not_written_even_if_the_cache_says_otherwise() {
    let h = unlocked_managed().await;
    // A person moved the item to another collection since the last sync.
    {
        let mut m = h.mock.lock().unwrap();
        let c = m.ciphers.iter_mut().find(|c| c["id"] == "c3").unwrap();
        c["collectionIds"] = json!([COLL_OTHER]);
    }
    let e = h
        .vault
        .rotate_start("c3", "orgitem", next())
        .await
        .unwrap_err();
    assert!(matches!(e, FerroError::CredentialNotManaged(_)), "{e}");
    let m = h.mock.lock().unwrap();
    assert_eq!(m.gets, ["c3"], "read, then refused");
    assert_eq!(m.put_calls, 0);
}

#[tokio::test]
async fn locked_unconfigured_and_unavailable_refuse_before_any_request() {
    // Locked.
    let h = managed_harness("Ferrowarden managed").await;
    let e = h
        .vault
        .rotate_start("c3", "orgitem", next())
        .await
        .unwrap_err();
    assert!(matches!(e, FerroError::VaultLocked), "{e}");
    assert!(h.mock.lock().unwrap().gets.is_empty());

    // No managed collection configured.
    let h = harness().await;
    h.vault.unlock(pw()).await.unwrap();
    let e = h
        .vault
        .rotate_start("c3", "orgitem", next())
        .await
        .unwrap_err();
    assert!(matches!(e, FerroError::CredentialCreateDisabled), "{e}");

    // The collection became view-only.
    let h = unlocked_managed().await;
    set_collection(&h, COLL_MANAGED, true, false);
    h.vault.sync().await.unwrap();
    let e = h
        .vault
        .rotate_start("c3", "orgitem", next())
        .await
        .unwrap_err();
    assert!(
        matches!(e, FerroError::ManagedCollectionUnavailable(_)),
        "{e}"
    );
    let m = h.mock.lock().unwrap();
    assert!(m.gets.is_empty());
    assert_eq!(m.put_calls, 0);
}

#[tokio::test]
async fn two_pending_fields_are_a_conflict_and_the_value_is_ambiguous() {
    let h = unlocked_managed().await;
    h.vault.rotate_start("c3", "orgitem", next()).await.unwrap();
    {
        let mut m = h.mock.lock().unwrap();
        let c = m.ciphers.iter_mut().find(|c| c["id"] == "c3").unwrap();
        let extra = json!({
            "name": enc(&h.acct.org, "ferrowarden_next"),
            "value": enc(&h.acct.org, "SECOND"),
            "type": 1, "linkedId": null,
        });
        c["fields"].as_array_mut().unwrap().push(extra);
        m.revision += 1;
    }
    h.vault.sync().await.unwrap();
    // Neither a commit nor a start goes on guessing.
    for e in [
        h.vault.rotate_commit("c3", "orgitem").await.unwrap_err(),
        h.vault
            .rotate_start("c3", "orgitem", next())
            .await
            .unwrap_err(),
    ] {
        assert!(matches!(e, FerroError::VaultConflict), "{e}");
    }
    assert!(matches!(
        next_of(&h, "c3").await,
        Err(FerroError::AmbiguousField { .. })
    ));
}

#[tokio::test]
async fn a_lock_forgets_what_was_pinned() {
    let h = unlocked_managed().await;
    h.vault.rotate_start("c3", "orgitem", next()).await.unwrap();
    assert!(!h.vault.pins().is_empty());
    h.vault.lock().await;
    assert!(h.vault.pins().is_empty());
}

#[tokio::test]
async fn nothing_secret_is_in_the_debug_output_of_the_errors() {
    let h = unlocked_managed().await;
    h.mock.lock().unwrap().put_status = Some(500);
    let e = h
        .vault
        .rotate_start("c3", "orgitem", next())
        .await
        .unwrap_err();
    assert!(!format!("{e:?} {e}").contains(NEXT));
}
