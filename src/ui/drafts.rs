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
mod tests {
    use super::*;

    fn ip(n: u8) -> IpAddr {
        IpAddr::from([192, 168, 1, n])
    }

    fn draft(target: DraftTarget, pattern: &str) -> SavedDraft {
        SavedDraft {
            target,
            name: String::new(),
            patterns: vec![pattern.to_string()],
            checked: vec![true, false],
            all_methods: false,
            request: None,
        }
    }

    #[test]
    fn a_draft_comes_back_once_for_the_same_address_and_form() {
        let mut s = DraftStore::new();
        let now = Instant::now();
        let id = s
            .park(draft(DraftTarget::Key("k1".into()), "lab_*"), ip(1), now)
            .unwrap();
        assert_eq!(id.len(), 43);
        let key = DraftTarget::Key("k1".into());
        // Another address, or another key, does not get it (and does not use it up).
        assert!(s.take(&id, &key, ip(2), now).is_none());
        assert!(s
            .take(&id, &DraftTarget::Key("k2".into()), ip(1), now)
            .is_none());
        assert!(s.take(&id, &DraftTarget::NewKey, ip(1), now).is_none());
        let back = s.take(&id, &key, ip(1), now).unwrap();
        assert_eq!(back.patterns, vec!["lab_*"]);
        assert!(s.take(&id, &key, ip(1), now).is_none(), "single use");
        assert_eq!(s.len(), 0);
    }

    #[test]
    fn drafts_expire_after_fifteen_minutes() {
        let mut s = DraftStore::new();
        let now = Instant::now();
        let id = s.park(draft(DraftTarget::NewKey, "a"), ip(1), now).unwrap();
        let late = now + DRAFT_TTL - Duration::from_secs(1);
        let id2 = s
            .park(draft(DraftTarget::NewKey, "b"), ip(1), late)
            .unwrap();
        assert!(s
            .take(&id, &DraftTarget::NewKey, ip(1), now + DRAFT_TTL)
            .is_none());
        assert!(s
            .take(&id2, &DraftTarget::NewKey, ip(1), now + DRAFT_TTL)
            .is_some());
    }

    #[test]
    fn at_most_sixteen_are_kept_and_the_oldest_goes() {
        let mut s = DraftStore::new();
        let now = Instant::now();
        let ids: Vec<_> = (0..MAX_DRAFTS + 3)
            .map(|i| {
                s.park(draft(DraftTarget::NewKey, &format!("p{i}")), ip(1), now)
                    .unwrap()
            })
            .collect();
        assert_eq!(s.len(), MAX_DRAFTS);
        for id in &ids[..3] {
            assert!(s.take(id, &DraftTarget::NewKey, ip(1), now).is_none());
        }
        for id in &ids[3..] {
            assert!(s.take(id, &DraftTarget::NewKey, ip(1), now).is_some());
        }
    }

    #[test]
    fn unknown_ids_are_missing() {
        let mut s = DraftStore::new();
        assert!(s
            .take("nope", &DraftTarget::NewKey, ip(1), Instant::now())
            .is_none());
    }
}
