
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
