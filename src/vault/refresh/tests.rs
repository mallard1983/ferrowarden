use std::sync::Arc;

use super::*;
use crate::config::Config;
use crate::events::EventLog;
use crate::vault::model::{ManagedCollection, ManagedProblem, ManagedState};

fn usable() -> ManagedState {
    ManagedState::Usable(ManagedCollection {
        id: "6c0d7f0e-52d0-4b5b-8a39-0e8a7f6d5c4b".into(),
        organization_id: "org".into(),
        name: "Ferrowarden managed".into(),
        items: 0,
    })
}

fn unavailable(problem: ManagedProblem) -> ManagedState {
    ManagedState::Unavailable {
        setting: "Ferrowarden managed".into(),
        problem,
    }
}

fn state() -> AppState {
    let cfg: Config = serde_json::from_value(serde_json::json!({
        "admin_key": "a".repeat(32),
        "unlock_mode": "manual"
    }))
    .unwrap();
    AppState::new(cfg, Arc::new(EventLog::buffer_only(100)))
}

fn fake(state: &AppState) -> &crate::vault::fake::FakeVault {
    match &*state.vault {
        crate::vault::ActiveVault::Fake(f) => f,
        _ => unreachable!(),
    }
}

fn syncs(state: &AppState) -> Vec<serde_json::Value> {
    state
        .events
        .recent(100)
        .iter()
        .map(|e| serde_json::to_value(&**e).unwrap())
        .filter(|v| v["event"]["action"] == "vault_sync")
        .collect()
}

#[test]
fn startup_needs_a_usable_collection_when_one_is_configured() {
    assert!(check_managed_at_startup(&ManagedState::Off).is_ok());
    assert!(check_managed_at_startup(&usable()).is_ok());
    for problem in [
        ManagedProblem::NotFound,
        ManagedProblem::ReadOnly,
        ManagedProblem::HidesPasswords,
        ManagedProblem::Ambiguous,
        ManagedProblem::NoOrganizationKey,
    ] {
        let message = check_managed_at_startup(&unavailable(problem)).unwrap_err();
        // It says what is wrong and what to do about it.
        assert!(message.contains("vault.managed.collection"), "{message}");
        assert!(message.contains(problem.describe()), "{message}");
        assert!(message.contains("unset"), "{message}");
    }
}

#[tokio::test]
async fn a_collection_that_stops_being_usable_is_reported_once_with_a_warning() {
    let state = state();
    fake(&state).set_managed(usable());
    refresh_credentials(&state).await.unwrap();
    assert!(
        syncs(&state)
            .iter()
            .all(|e| e["ferrowarden"]["details"].get("warnings").is_none()),
        "a usable collection is not news"
    );

    // The owner makes it view-only: the next refresh says so, once.
    fake(&state).set_managed(unavailable(ManagedProblem::ReadOnly));
    refresh_credentials(&state).await.unwrap();
    refresh_credentials(&state).await.unwrap();
    let warned: Vec<_> = syncs(&state)
        .into_iter()
        .filter(|e| e["ferrowarden"]["details"].get("warnings").is_some())
        .collect();
    assert_eq!(warned.len(), 1);
    assert_eq!(
        warned[0]["ferrowarden"]["details"]["warnings"]["managed_collection"],
        "read_only"
    );
    // The event carries the code, not the collection's name.
    assert!(!warned[0].to_string().contains("Ferrowarden managed"));

    // A different problem is news again; fixing it is not a warning.
    fake(&state).set_managed(unavailable(ManagedProblem::HidesPasswords));
    refresh_credentials(&state).await.unwrap();
    assert_eq!(
        syncs(&state)
            .iter()
            .filter(|e| e["ferrowarden"]["details"].get("warnings").is_some())
            .count(),
        2
    );
    fake(&state).set_managed(usable());
    refresh_credentials(&state).await.unwrap();
    assert_eq!(
        syncs(&state)
            .iter()
            .filter(|e| e["ferrowarden"]["details"].get("warnings").is_some())
            .count(),
        2
    );
}

#[tokio::test]
async fn not_configured_says_nothing() {
    let state = state();
    refresh_credentials(&state).await.unwrap();
    refresh_credentials(&state).await.unwrap();
    assert!(syncs(&state)
        .iter()
        .all(|e| e["ferrowarden"]["details"].get("warnings").is_none()));
}
