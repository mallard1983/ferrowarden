//! Which collection Ferrowarden may write to.
//!
//! `vault.managed.collection` names one organisation collection, by id (a
//! UUID) or by name. On every unlock and sync the setting is evaluated against
//! the collections `/api/sync` lists for the account, and the answer is a
//! [`ManagedState`]:
//!
//! * **usable** only when the collection exists, the account does **not**
//!   have "View only" on it, does **not** have "Hide passwords" on it, and the
//!   organisation key needed to encrypt into it is available;
//! * otherwise **unavailable**, with the reason. A flag the server did not
//!   send is not trusted (it counts against the collection).
//!
//! Names are ciphertext under the organisation key and are decrypted here; a
//! name that matches more than one collection is refused (use the id), so
//! Ferrowarden never guesses which one was meant.

use std::collections::HashMap;

use super::api::RawCollection;
use super::enc::{EncString, SymKey};
use crate::vault::model::{ManagedCollection, ManagedProblem, ManagedState};

/// Does `setting` look like a collection id? Matched case-insensitively
/// against the ids of the sync. Anything else is a name.
fn as_id(setting: &str) -> Option<String> {
    uuid::Uuid::parse_str(setting)
        .ok()
        .map(|u| u.hyphenated().to_string())
}

/// A collection's name, when its organisation key is known and the name
/// decrypts.
fn name_of(c: &RawCollection, org: &HashMap<String, SymKey>) -> Option<String> {
    let key = org.get(c.organization_id.as_deref()?)?;
    let text = EncString::parse(c.name.as_deref()?)
        .and_then(|e| e.decrypt_string(key))
        .ok()?;
    Some(text.as_str().to_string())
}

/// Evaluate the setting. `None`: creating is off.
pub fn evaluate(
    setting: Option<&str>,
    collections: &[RawCollection],
    org: &HashMap<String, SymKey>,
) -> ManagedState {
    let Some(setting) = setting else {
        return ManagedState::Off;
    };
    let unavailable = |problem| ManagedState::Unavailable {
        setting: setting.to_string(),
        problem,
    };

    let picked: Vec<&RawCollection> = match as_id(setting) {
        Some(id) => collections
            .iter()
            .filter(|c| c.id.eq_ignore_ascii_case(&id))
            .collect(),
        None => collections
            .iter()
            .filter(|c| name_of(c, org).is_some_and(|n| n == setting))
            .collect(),
    };
    let c = match picked.as_slice() {
        [] => return unavailable(ManagedProblem::NotFound),
        [one] => *one,
        _ => return unavailable(ManagedProblem::Ambiguous),
    };

    let Some(org_id) = c.organization_id.as_deref() else {
        return unavailable(ManagedProblem::NotFound);
    };
    if !org.contains_key(org_id) {
        return unavailable(ManagedProblem::NoOrganizationKey);
    }
    // Only an explicit `false` is trusted.
    if c.read_only != Some(false) {
        return unavailable(ManagedProblem::ReadOnly);
    }
    if c.hide_passwords != Some(false) {
        return unavailable(ManagedProblem::HidesPasswords);
    }
    ManagedState::Usable(ManagedCollection {
        id: c.id.clone(),
        organization_id: org_id.to_string(),
        // The configured text when the name is not readable (an id was given).
        name: name_of(c, org).unwrap_or_else(|| setting.to_string()),
        items: 0,
    })
}

#[cfg(test)]
mod tests;
