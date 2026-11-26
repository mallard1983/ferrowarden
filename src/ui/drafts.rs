//! Unsaved form drafts that survive a sign-in.
//!
//! Saving a policy or creating a key needs a sign-in within the last ten
//! minutes. If that window ran out while the form was open, the POST cannot
//! be honoured, and without this the typed changes would be lost. Instead the
//! handler parks the draft here, sends the browser to sign in again, and the
//! sign-in brings it back to a GET of the draft URL, which shows the editor
//! pre-filled. Nothing is ever saved automatically: the operator reviews the
//! form and submits it again, through the normal path (sudo, confirmation of
//! widening changes).
//!
//! The store is a small in-memory map: random 32-byte ids (the map holds
//! their digests), 15 minutes, at most 16 entries, one use, and bound to the
//! client IP that parked it. The request-check fields can hold whatever the
//! operator typed, so they are wiped when the entry goes.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use zeroize::Zeroizing;

use crate::ui::session::{digest, random_token};

/// How long a parked draft is kept.
pub const DRAFT_TTL: Duration = Duration::from_secs(15 * 60);
/// Most drafts held at once; the oldest is dropped for a new one.
pub const MAX_DRAFTS: usize = 16;

/// Which form a draft belongs to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DraftTarget {
    /// The create-key form.
    NewKey,
    /// The policy editor of the key with this id.
    Key(String),
}

/// The request-check part of the editor.
pub struct RequestDraft {
    pub method: String,
    pub url: Zeroizing<String>,
    pub headers: Zeroizing<String>,
    pub body: Zeroizing<String>,
}

/// What the operator had typed.
pub struct SavedDraft {
    pub target: DraftTarget,
    /// The key name (create form only).
    pub name: String,
    pub patterns: Vec<String>,
    /// The approval patterns.
    pub approval: Vec<String>,
    /// One flag per entry of `policy::METHODS`, in order.
    pub checked: Vec<bool>,
    pub all_methods: bool,
    /// The request-check fields (editor only).
    pub request: Option<RequestDraft>,
}

struct Entry {
    draft: SavedDraft,
    ip: IpAddr,
    parked: Instant,
    seq: u64,
}

#[derive(Default)]
pub struct DraftStore {
    entries: HashMap<[u8; 32], Entry>,
    next_seq: u64,
}

impl DraftStore {
    pub fn new() -> Self {
        Self::default()
    }

    fn purge(&mut self, now: Instant) {
        self.entries
            .retain(|_, e| now.saturating_duration_since(e.parked) < DRAFT_TTL);
    }

    /// Park a draft for `ip`. Returns its id (to put in the URL). `None` only
    /// if the OS RNG fails; the caller then falls back to a plain sign-in
    /// redirect.
    pub fn park(
        &mut self,
        draft: SavedDraft,
        ip: IpAddr,
        now: Instant,
    ) -> Option<Zeroizing<String>> {
        let id = random_token()?;
        self.purge(now);
        while self.entries.len() >= MAX_DRAFTS {
            let Some(oldest) = self
                .entries
                .iter()
                .min_by_key(|(_, e)| e.seq)
                .map(|(k, _)| *k)
            else {
                break;
            };
            self.entries.remove(&oldest);
        }
        self.next_seq += 1;
        self.entries.insert(
            digest(&id),
            Entry {
                draft,
                ip,
                parked: now,
                seq: self.next_seq,
            },
        );
        Some(id)
    }

    /// Take a draft back. It is used up by a successful take. A draft parked
    /// from another address, or for another form, is left alone and counts as
    /// missing; an expired one is dropped.
    pub fn take(
        &mut self,
        id: &str,
        target: &DraftTarget,
        ip: IpAddr,
        now: Instant,
    ) -> Option<SavedDraft> {
        self.purge(now);
        let key = digest(id);
        let entry = self.entries.get(&key)?;
        if entry.ip != ip || &entry.draft.target != target {
            return None;
        }
        self.entries.remove(&key).map(|e| e.draft)
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.entries.len()
    }
}

#[cfg(test)]
mod tests;
