//! The rotation calls of the native vault against a mock Vaultwarden that
//! implements `GET` and `PUT /api/ciphers/{id}` the way the real server does
//! for a stale write: a `PUT` that names an old revision is refused with a 400
//! whose message says the client copy is out of date.

use super::*;
use crate::vault::model::{RotationRecord, NEXT_FIELD, ROTATION_FIELD};

const NEXT: &str = "PENDING-VALUE-0123456789";

/// The harness with `orgitem` (c3, organisation key) in the managed
/// collection and `orgwithkey` (c4, its own key) in the other one.
async fn unlocked_managed() -> Harness {
    let h = managed_harness("Ferrowarden managed").await;
    h.vault.unlock(pw()).await.unwrap();
    h
}

/// A second `NativeVault` on the same server and account, unlocked: what a
/// restart of Ferrowarden gives (nothing is remembered in memory).
async fn fresh_vault_on(h: &Harness) -> NativeVault {
    let v = NativeVault::new(&h.config).unwrap();
    v.unlock(pw()).await.unwrap();
    v
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
async fn start_writes_only_the_two_reserved_fields_and_the_password_stays() {
    let h = unlocked_managed().await;
    let before = cipher(&h, "c3");
    let rid = h.vault.rotate_start("c3", "orgitem", next()).await.unwrap();

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
    assert_eq!(fields.len(), 3);
    assert_eq!(fields[0], before["fields"][0]);
    assert_eq!(open(&h.acct.org, &fields[1]["name"]), NEXT_FIELD);
    assert_eq!(open(&h.acct.org, &fields[1]["value"]), NEXT);
    assert_eq!(fields[1]["type"], 1);
    // The record, in a second hidden field: the random id and the two
    // ciphertexts as they are.
    assert_eq!(fields[2]["type"], 1);
    assert_eq!(open(&h.acct.org, &fields[2]["name"]), ROTATION_FIELD);
    let record = RotationRecord::parse(&open(&h.acct.org, &fields[2]["value"])).unwrap();
    assert_eq!(record.from, before["login"]["password"].as_str().unwrap());
    assert_eq!(record.next, fields[1]["value"].as_str().unwrap());
    assert!(!body.to_string().contains("PASS-orgitem"));
    assert!(!body.to_string().contains(NEXT));
    // The rotation id is the record's random id.
    assert_eq!(rid, record.id);

    // After the next sync the item shows the pending rotation, the current
    // password is untouched and the pending one is reachable as `next`.
    h.vault.sync().await.unwrap();
    let listing = h.vault.list_credentials().await.unwrap();
    let entry = &listing.map["orgitem"][0];
    assert!(entry.has_next);
    // The listing carries the id, so that a lost start response is not the end
    // of the rotation.
    assert_eq!(entry.rotation_id.as_deref(), Some(rid.as_str()));
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
    let rid = h.vault.rotate_start("c3", "orgitem", next()).await.unwrap();
    h.vault.sync().await.unwrap();
    h.vault.rotate_commit("c3", "orgitem", &rid).await.unwrap();

    let (_, body) = h.mock.lock().unwrap().puts[1].clone();
    // The second write names the revision the first one produced (the
    // revision of the fresh read).
    assert_eq!(body["lastKnownRevisionDate"], "2026-11-26T11:00:01.000000Z");
    let history = body["passwordHistory"].as_array().unwrap();
    assert_eq!(history.len(), 1);
    assert_eq!(open(&h.acct.org, &history[0]["password"]), "PASS-orgitem");
    assert!(history[0]["lastUsedDate"].as_str().unwrap().ends_with('Z'));
    assert!(body["login"]["passwordRevisionDate"].is_string());
    // Both reserved fields are gone.
    assert_eq!(body["fields"].as_array().unwrap().len(), 1);

    h.vault.sync().await.unwrap();
    assert_eq!(password_of(&h, "c3").await, NEXT);
    assert!(matches!(
        next_of(&h, "c3").await,
        Err(FerroError::CredentialNotFound(_))
    ));
    let listing = h.vault.list_credentials().await.unwrap();
    assert!(!listing.map["orgitem"][0].has_next);
    assert_eq!(listing.map["orgitem"][0].rotation_id, None);
}

#[tokio::test]
async fn abort_removes_the_field_leaves_the_password_and_keeps_the_discarded_value() {
    let h = unlocked_managed().await;
    let rid = h.vault.rotate_start("c3", "orgitem", next()).await.unwrap();
    let pending = cipher(&h, "c3")["fields"][1]["value"].clone();
    h.vault.rotate_abort("c3", "orgitem", &rid).await.unwrap();
    h.vault.sync().await.unwrap();
    assert_eq!(password_of(&h, "c3").await, "PASS-orgitem");
    assert!(next_of(&h, "c3").await.is_err());
    let after = cipher(&h, "c3");
    assert_eq!(after["fields"].as_array().unwrap().len(), 1);
    // The discarded value is the newest history entry, ciphertext as it was
    // on the item: if the service had switched to it, a person can recover it.
    let history = after["passwordHistory"].as_array().unwrap();
    assert_eq!(history.len(), 1);
    assert_eq!(history[0]["password"], pending);
    assert_eq!(open(&h.acct.org, &history[0]["password"]), NEXT);
    assert!(history[0]["lastUsedDate"].as_str().unwrap().ends_with('Z'));
}

#[tokio::test]
async fn a_second_start_and_a_commit_without_a_start_are_refused_without_writing() {
    let h = unlocked_managed().await;
    let e = h
        .vault
        .rotate_commit("c3", "orgitem", "any")
        .await
        .unwrap_err();
    assert!(matches!(e, FerroError::NoRotationPending(n) if n == "orgitem"));
    let e = h
        .vault
        .rotate_abort("c3", "orgitem", "any")
        .await
        .unwrap_err();
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
async fn a_persons_edit_of_the_notes_in_between_is_kept_and_the_commit_goes_through() {
    let h = unlocked_managed().await;
    let rid = h.vault.rotate_start("c3", "orgitem", next()).await.unwrap();

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

    // The commit works on the item as the person left it: their edit is kept.
    h.vault.rotate_commit("c3", "orgitem", &rid).await.unwrap();
    let (_, body) = h.mock.lock().unwrap().puts[1].clone();
    assert_eq!(body["lastKnownRevisionDate"], "2026-11-26T11:30:00.000000Z");
    assert_eq!(cipher(&h, "c3")["notes"], human_notes);
    h.vault.sync().await.unwrap();
    assert_eq!(password_of(&h, "c3").await, NEXT);
}

/// A person changes the item's password (to a new ciphertext, a new revision).
fn person_changes_the_password(h: &Harness) -> Value {
    let changed = enc(&h.acct.org, "PERSON-PASSWORD");
    let mut m = h.mock.lock().unwrap();
    let c = m.ciphers.iter_mut().find(|c| c["id"] == "c3").unwrap();
    c["login"]["password"] = changed.clone();
    c["revisionDate"] = json!("2026-11-26T11:30:00.000000Z");
    m.revision += 1;
    changed
}

#[tokio::test]
async fn a_persons_password_change_in_between_is_never_replaced_by_a_commit() {
    let h = unlocked_managed().await;
    let rid = h.vault.rotate_start("c3", "orgitem", next()).await.unwrap();
    let changed = person_changes_the_password(&h);
    h.vault.sync().await.unwrap();

    // Refused every time (nothing is remembered in memory that a refusal could
    // clear), and nothing is written.
    for _ in 0..2 {
        let e = h
            .vault
            .rotate_commit("c3", "orgitem", &rid)
            .await
            .unwrap_err();
        assert!(matches!(e, FerroError::VaultPasswordChanged), "{e}");
        assert_eq!(e.create_code(), Some("vault_conflict"));
    }
    assert_eq!(puts(&h), 1, "only the start was written");
    assert_eq!(cipher(&h, "c3")["login"]["password"], changed);
    assert_eq!(cipher(&h, "c3")["passwordHistory"], Value::Null);

    // The same after a restart: the record is on the item, not in memory.
    let h2 = fresh_vault_on(&h).await;
    let e = h2.rotate_commit("c3", "orgitem", &rid).await.unwrap_err();
    assert!(matches!(e, FerroError::VaultPasswordChanged), "{e}");
    assert_eq!(puts(&h), 1);

    // An abort is always possible: both fields go, the pending value is the
    // newest history entry, the person's password stays.
    let pending = cipher(&h, "c3")["fields"][1]["value"].clone();
    h.vault.rotate_abort("c3", "orgitem", &rid).await.unwrap();
    let after = cipher(&h, "c3");
    assert_eq!(after["fields"].as_array().unwrap().len(), 1);
    assert_eq!(after["login"]["password"], changed);
    assert_eq!(after["passwordHistory"][0]["password"], pending);
    assert_eq!(after["passwordHistory"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn a_missing_repeated_or_unreadable_record_is_a_conflict_for_a_person_to_fix() {
    for how in ["missing", "twice", "garbled", "empty"] {
        let h = unlocked_managed().await;
        let rid = h.vault.rotate_start("c3", "orgitem", next()).await.unwrap();
        {
            let mut m = h.mock.lock().unwrap();
            let c = m.ciphers.iter_mut().find(|c| c["id"] == "c3").unwrap();
            let fields = c["fields"].as_array_mut().unwrap();
            match how {
                "missing" => {
                    fields.pop();
                }
                "twice" => {
                    let again = fields[2].clone();
                    fields.push(again);
                }
                "garbled" => fields[2]["value"] = json!("not an encstring"),
                _ => fields[2]["value"] = json!(""),
            }
        }
        h.vault.sync().await.unwrap();
        let writes = puts(&h);
        let e = h
            .vault
            .rotate_commit("c3", "orgitem", &rid)
            .await
            .unwrap_err();
        assert!(matches!(e, FerroError::VaultConflict), "{how}: {e}");
        assert_eq!(puts(&h), writes, "{how}: nothing written");
        // A person has to fix it: an abort cannot tell whose rotation it is
        // either, and writes nothing.
        let e = h
            .vault
            .rotate_abort("c3", "orgitem", &rid)
            .await
            .unwrap_err();
        assert!(matches!(e, FerroError::VaultConflict), "{how}: {e}");
        assert_eq!(puts(&h), writes, "{how}: nothing written");
    }
}

#[tokio::test]
async fn the_record_field_is_reserved_and_never_offered() {
    let h = unlocked_managed().await;
    h.vault.rotate_start("c3", "orgitem", next()).await.unwrap();
    h.vault.sync().await.unwrap();
    let listing = h.vault.list_credentials().await.unwrap();
    let entry = &listing.map["orgitem"][0];
    assert!(entry
        .fields
        .iter()
        .all(|f| f.name != ROTATION_FIELD && f.name != NEXT_FIELD));
    // (A `field:` placeholder is planned from this listing, so it is unknown.)
}

#[tokio::test]
async fn a_stray_base_without_a_pending_value_is_dropped_by_the_next_start() {
    let h = unlocked_managed().await;
    let rid = h.vault.rotate_start("c3", "orgitem", next()).await.unwrap();
    {
        // The pending field was removed by hand; the record stayed.
        let mut m = h.mock.lock().unwrap();
        let c = m.ciphers.iter_mut().find(|c| c["id"] == "c3").unwrap();
        c["fields"].as_array_mut().unwrap().remove(1);
        m.revision += 1;
    }
    let _ = rid;
    h.vault.sync().await.unwrap();
    h.vault.rotate_start("c3", "orgitem", next()).await.unwrap();
    // One pending field and one record field, not two.
    assert_eq!(cipher(&h, "c3")["fields"].as_array().unwrap().len(), 3);
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
async fn a_refusal_changed_nothing_an_unknown_outcome_is_said_so_and_only_a_401_is_retried() {
    let h = unlocked_managed().await;
    h.mock.lock().unwrap().put_status = Some(500);
    let e = h
        .vault
        .rotate_start("c3", "orgitem", next())
        .await
        .unwrap_err();
    // A 5xx may have been applied: said so, and not sent again.
    assert!(matches!(e, FerroError::VaultWriteUnknown), "{e}");
    assert_eq!(h.mock.lock().unwrap().put_calls, 1, "a 5xx is not retried");
    // So is a redirect, which no server of ours gives.
    h.mock.lock().unwrap().put_status = Some(302);
    let e = h
        .vault
        .rotate_start("c3", "orgitem", next())
        .await
        .unwrap_err();
    assert!(matches!(e, FerroError::VaultWriteUnknown), "{e}");
    // Any other 4xx may have come after the write was saved: unknown too.
    for unknown in [422, 413, 429, 400] {
        h.mock.lock().unwrap().put_status = Some(unknown);
        let e = h
            .vault
            .rotate_start("c3", "orgitem", next())
            .await
            .unwrap_err();
        assert!(matches!(e, FerroError::VaultWriteUnknown), "{unknown}: {e}");
    }
    // Only a refused login (401 or 403, even after the retry) is a refusal.
    for refused in [401, 403] {
        h.mock.lock().unwrap().put_status = Some(refused);
        let e = h
            .vault
            .rotate_start("c3", "orgitem", next())
            .await
            .unwrap_err();
        assert!(matches!(e, FerroError::VaultWriteFailed), "{refused}: {e}");
    }
    // A 400 that is not about the revision is not a conflict.
    h.mock.lock().unwrap().put_status = Some(400);
    let e = h
        .vault
        .rotate_start("c3", "orgitem", next())
        .await
        .unwrap_err();
    assert!(matches!(e, FerroError::VaultWriteUnknown), "{e}");
    h.mock.lock().unwrap().put_status = None;
    assert_eq!(puts(&h), 0, "nothing was applied by any of them");

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
    let e = h
        .vault
        .rotate_commit("nope", "nope", "any")
        .await
        .unwrap_err();
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
    let rid = h.vault.rotate_start("c3", "orgitem", next()).await.unwrap();
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
        h.vault
            .rotate_commit("c3", "orgitem", &rid)
            .await
            .unwrap_err(),
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
    // Nothing can name either of them, so the listing offers no id.
    let listing = h.vault.list_credentials().await.unwrap();
    assert!(listing.map["orgitem"][0].has_next);
    assert_eq!(listing.map["orgitem"][0].rotation_id, None);
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

// ── What a finish names ───────────────────────────────────────────────────────

#[tokio::test]
async fn a_finish_naming_another_pending_value_writes_nothing() {
    let h = unlocked_managed().await;
    let first = h.vault.rotate_start("c3", "orgitem", next()).await.unwrap();
    h.vault
        .rotate_commit("c3", "orgitem", &first)
        .await
        .unwrap();
    // A second rotation starts; a replayed commit of the first (a lost
    // response, retried) must not finish it.
    let second = h.vault.rotate_start("c3", "orgitem", next()).await.unwrap();
    assert_ne!(
        first, second,
        "a fresh IV, so a fresh id, for the same value"
    );
    let writes = puts(&h);
    for e in [
        h.vault
            .rotate_commit("c3", "orgitem", &first)
            .await
            .unwrap_err(),
        h.vault
            .rotate_abort("c3", "orgitem", &first)
            .await
            .unwrap_err(),
    ] {
        assert!(
            matches!(&e, FerroError::RotationMismatch(n) if n == "orgitem"),
            "{e}"
        );
    }
    assert_eq!(puts(&h), writes, "nothing written");
    assert!(cipher(&h, "c3")["fields"].as_array().unwrap().len() == 3);
    // The one it means works.
    h.vault
        .rotate_commit("c3", "orgitem", &second)
        .await
        .unwrap();
}

#[tokio::test]
async fn a_person_replacing_the_pending_value_is_not_finished_by_the_old_id() {
    let h = unlocked_managed().await;
    let rid = h.vault.rotate_start("c3", "orgitem", next()).await.unwrap();
    // A person replaces the pending value (a new ciphertext, a new revision).
    {
        let mut m = h.mock.lock().unwrap();
        let c = m.ciphers.iter_mut().find(|c| c["id"] == "c3").unwrap();
        c["fields"][1]["value"] = enc(&h.acct.org, "PERSON-CHOSE-THIS");
        c["revisionDate"] = json!("2026-11-26T11:30:00.000000Z");
        m.revision += 1;
    }
    h.vault.sync().await.unwrap();
    // The listing still has the rotation's id (it is the record's).
    let listed = h.vault.list_credentials().await.unwrap().map["orgitem"][0]
        .rotation_id
        .clone();
    assert_eq!(listed.as_deref(), Some(rid.as_str()));
    // The commit is refused, however often it is asked.
    for _ in 0..2 {
        let e = h
            .vault
            .rotate_commit("c3", "orgitem", &rid)
            .await
            .unwrap_err();
        assert!(matches!(e, FerroError::RotationMismatch(_)), "{e}");
    }
    assert_eq!(puts(&h), 1, "only the start was ever written");
    assert_eq!(password_of(&h, "c3").await, "PASS-orgitem");
    // The abort the id names still works: the replaced value goes to the
    // password history, and the reserved fields are gone.
    h.vault.rotate_abort("c3", "orgitem", &rid).await.unwrap();
    let after = cipher(&h, "c3");
    assert_eq!(after["fields"].as_array().unwrap().len(), 1);
    assert_eq!(
        open(&h.acct.org, &after["passwordHistory"][0]["password"]),
        "PERSON-CHOSE-THIS"
    );
}

#[tokio::test]
async fn an_empty_or_blank_pending_value_is_refused_by_the_commit_and_the_placeholder() {
    for blank in ["", "   ", "\t\n"] {
        let h = unlocked_managed().await;
        let rid = h.vault.rotate_start("c3", "orgitem", next()).await.unwrap();
        {
            let mut m = h.mock.lock().unwrap();
            let c = m.ciphers.iter_mut().find(|c| c["id"] == "c3").unwrap();
            // The record names the value that is there, so that it is the
            // value itself that is wrong.
            let new_value = enc(&h.acct.org, blank);
            let mut record =
                RotationRecord::parse(&open(&h.acct.org, &c["fields"][2]["value"])).unwrap();
            record.next = new_value.as_str().unwrap().to_string();
            c["fields"][1]["value"] = new_value;
            c["fields"][2]["value"] = enc(&h.acct.org, &record.to_text());
        }
        h.vault.sync().await.unwrap();
        // The placeholder: as if the item had no pending value.
        assert!(
            matches!(
                next_of(&h, "c3").await,
                Err(FerroError::CredentialNotFound(_))
            ),
            "{blank:?}"
        );
        // The commit: a person has to fix it, and nothing is written.
        let current = h.vault.list_credentials().await.unwrap().map["orgitem"][0]
            .rotation_id
            .clone()
            .unwrap_or(rid);
        let writes = puts(&h);
        let e = h
            .vault
            .rotate_commit("c3", "orgitem", &current)
            .await
            .unwrap_err();
        assert!(matches!(e, FerroError::VaultConflict), "{blank:?}: {e}");
        assert_eq!(puts(&h), writes);
        assert_eq!(password_of(&h, "c3").await, "PASS-orgitem");
    }
}

// ── What a write that did not answer cleanly did ──────────────────────────────

#[tokio::test]
async fn a_success_whose_answer_cannot_be_read_was_applied_and_is_a_success() {
    // A start: the write was applied, only the answer is unreadable. Nothing
    // else is sent, and the rotation can be finished.
    let h = unlocked_managed().await;
    h.mock.lock().unwrap().put_garbage = 1;
    let rid = h.vault.rotate_start("c3", "orgitem", next()).await.unwrap();
    assert_eq!(puts(&h), 1);
    assert_eq!(h.mock.lock().unwrap().put_calls, 1, "not sent again");
    assert_eq!(h.mock.lock().unwrap().gets.len(), 1, "no read after it");
    h.vault.sync().await.unwrap();
    assert_eq!(next_of(&h, "c3").await.unwrap(), NEXT);
    h.vault.rotate_commit("c3", "orgitem", &rid).await.unwrap();

    // The commit and the abort do not need the answer at all.
    let h = unlocked_managed().await;
    let rid = h.vault.rotate_start("c3", "orgitem", next()).await.unwrap();
    h.mock.lock().unwrap().put_garbage = 1;
    h.vault.rotate_abort("c3", "orgitem", &rid).await.unwrap();
    assert_eq!(
        cipher(&h, "c3")["fields"].as_array().unwrap().len(),
        1,
        "applied"
    );
}

#[tokio::test]
async fn a_create_whose_answer_cannot_be_read_was_created() {
    let h = managed_harness(COLL_MANAGED).await;
    h.vault.unlock(pw()).await.unwrap();
    h.mock.lock().unwrap().create_garbage = true;
    let id = h.vault.create_login(new_login()).await.unwrap();
    assert_eq!(id, None, "created, id unknown");
    assert_eq!(h.mock.lock().unwrap().created.len(), 1);
    assert_eq!(
        h.mock.lock().unwrap().create_auth.len(),
        1,
        "not sent again"
    );
}

// ── An item that no longer exists ─────────────────────────────────────────────

#[tokio::test]
async fn an_item_deleted_since_the_sync_is_a_conflict_that_says_so() {
    // Vaultwarden's own answer: a 400 saying the cipher does not exist, for the
    // read and for the write. Also a plain 404.
    for as_404 in [false, true] {
        let h = unlocked_managed().await;
        let rid = h.vault.rotate_start("c3", "orgitem", next()).await.unwrap();
        {
            let mut m = h.mock.lock().unwrap();
            m.missing_is_404 = as_404;
            m.ciphers.retain(|c| c["id"] != "c3");
        }
        // The read finds it gone.
        let e = h
            .vault
            .rotate_commit("c3", "orgitem", &rid)
            .await
            .unwrap_err();
        assert!(matches!(e, FerroError::VaultItemGone), "{as_404}: {e}");
        assert_eq!(e.status_code(), 409);
        assert_eq!(e.create_code(), Some("vault_conflict"));
        assert!(e.to_string().contains("no longer exists"));
    }
    // The write finds it gone (deleted between the read and the write): the
    // same answer, and nothing else is written.
    for as_404 in [false, true] {
        let h = unlocked_managed().await;
        {
            let mut m = h.mock.lock().unwrap();
            m.missing_is_404 = as_404;
            m.vanish_after_get = true;
        }
        let e = h
            .vault
            .rotate_start("c3", "orgitem", next())
            .await
            .unwrap_err();
        assert!(matches!(e, FerroError::VaultItemGone), "{as_404}: {e}");
        assert_eq!(puts(&h), 0);
    }
    // Other 400s stay distinct: not a missing item, an unknown outcome.
    let h = unlocked_managed().await;
    h.mock.lock().unwrap().put_status = Some(400);
    let e = h
        .vault
        .rotate_start("c3", "orgitem", next())
        .await
        .unwrap_err();
    assert!(matches!(e, FerroError::VaultWriteUnknown), "{e}");
}
