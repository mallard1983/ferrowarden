use super::*;
use reqwest::Url;

fn origin(url: &str) -> Origin {
    Origin::of(&Url::parse(url).unwrap()).unwrap()
}

fn cfg() -> ApprovalConfig {
    ApprovalConfig::default()
}

fn t0() -> DateTime<Utc> {
    DateTime::parse_from_rfc3339("2026-11-26T12:00:00Z")
        .unwrap()
        .with_timezone(&Utc)
}

fn secs(n: i64) -> ChronoDuration {
    ChronoDuration::seconds(n)
}

fn req(items: &[&str]) -> Required {
    items
        .iter()
        .map(|i| {
            (
                (*i).to_string(),
                Reasons {
                    vault_field: true,
                    key_policy: false,
                },
            )
        })
        .collect()
}

struct Ask {
    key_id: String,
    origin: Origin,
}

impl Ask {
    fn new(key: &str, url: &str) -> Self {
        Self {
            key_id: key.to_string(),
            origin: origin(url),
        }
    }

    fn check(
        &self,
        store: &Arc<ApprovalStore>,
        items: &[&str],
        cfg: &ApprovalConfig,
        now: DateTime<Utc>,
    ) -> Check {
        let ask = AskFor {
            key_id: &self.key_id,
            key_name: "agent",
            origin: &self.origin,
            method: "GET",
            url: "https://pve.example.com:8006/api2/json/nodes?secret=1",
            request_id: "req-1",
        };
        store.check(&ask, &req(items), cfg, now).unwrap()
    }
}

fn store() -> Arc<ApprovalStore> {
    Arc::new(ApprovalStore::default())
}

fn pending_id(c: Check) -> (String, bool, Option<WaiterGuard>) {
    match c {
        Check::Wait {
            view,
            created,
            guard,
            ..
        } => (view.id, created, Some(guard)),
        Check::Pending { view, created } => (view.id, created, None),
        Check::Granted => panic!("granted"),
        Check::Denied => panic!("denied"),
        Check::LimitReached => panic!("limit reached"),
    }
}

fn approve(s: &Arc<ApprovalStore>, id: &str, minutes: u32, now: DateTime<Utc>) -> GrantView {
    s.approve(id, new_id().unwrap(), minutes, "tester", now)
        .unwrap()
        .1
}

// ── Which items need approval ─────────────────────────────────────────────────

#[test]
fn either_source_requires_approval_and_neither_can_exempt_the_other() {
    let mut policy =
        KeyPolicy::from_raw(vec!["*".into()], vec!["*".into()], vec![], vec![], vec![]).unwrap();
    let flags: BTreeMap<String, bool> = [
        ("plain".to_string(), false),
        ("field".to_string(), true),
        ("pol_only".to_string(), false),
        ("both".to_string(), true),
    ]
    .into();

    // No policy patterns: only the vault field asks.
    let r = required_items(&policy, &flags);
    assert_eq!(r.keys().collect::<Vec<_>>(), ["both", "field"]);
    assert_eq!(r["field"].names(), ["vault_field"]);

    // A policy list adds its own matches, and says why.
    policy.approval = vec!["pol_*".into(), "both".into()];
    let r = required_items(&policy, &flags);
    assert_eq!(r.keys().collect::<Vec<_>>(), ["both", "field", "pol_only"]);
    assert_eq!(r["pol_only"].names(), ["key_policy"]);
    assert_eq!(r["both"].names(), ["vault_field", "key_policy"]);
    assert_eq!(r["field"].names(), ["vault_field"]);

    // The key policy can never exempt an item that carries the field: an
    // empty list, a narrower one or an unrelated one change nothing for it.
    for list in [
        vec![],
        vec!["other".to_string()],
        vec!["field_x".to_string()],
    ] {
        policy.approval = list;
        assert!(required_items(&policy, &flags).contains_key("field"));
    }

    // `["*"]` asks for everything.
    policy.approval = vec!["*".into()];
    assert_eq!(required_items(&policy, &flags).len(), 4);
}

#[test]
fn the_path_of_a_url_has_no_query_or_fragment_and_is_cut() {
    assert_eq!(path_of("https://h.example.com/a/b?x=1#f"), "/a/b");
    assert_eq!(path_of("https://h.example.com:8006/a?x=1"), "/a");
    assert_eq!(path_of("https://h.example.com?x=1"), "/");
    assert_eq!(path_of("https://h.example.com"), "/");
    assert_eq!(path_of("https://u:p@h.example.com/z"), "/z");
    assert_eq!(path_of("https://h/{{vault:x}}/p?k=v"), "/{{vault:x}}/p");
    assert_eq!(path_of("not a url"), "/");
    let long = format!("https://h.example.com/{}", "a".repeat(500));
    assert_eq!(path_of(&long).chars().count(), MAX_PATH_CHARS);
}

#[test]
fn ids_are_long_random_and_url_safe() {
    let a = new_id().unwrap();
    let b = new_id().unwrap();
    assert_ne!(a, b);
    // 18 random bytes: 144 bits.
    assert_eq!(a.len(), 24);
    assert!(valid_id(&a));
    for bad in ["", "a b", "a/b", "a.b", "../x", &"a".repeat(65)] {
        assert!(!valid_id(bad), "{bad:?}");
    }
}

// ── Grants, denials and reuse ─────────────────────────────────────────────────

#[test]
fn a_grant_covers_the_key_the_items_and_the_origin_of_the_approval() {
    let s = store();
    let c = ApprovalConfig {
        max_pending_per_key: 50,
        ..cfg()
    };
    let a = Ask::new("k1", "https://pve.example.com:8006/x");
    let (id, created, _g) = pending_id(a.check(&s, &["pve", "nas"], &c, t0()));
    assert!(created);
    // The grant covers every item of the approval, for 15 minutes.
    let grant = approve(&s, &id, 15, t0());
    assert_eq!(grant.items, ["nas", "pve"]);
    assert_eq!(grant.expires, t0() + ChronoDuration::minutes(15));
    assert_eq!(grant.approver, "tester");
    assert_eq!(grant.host, "pve.example.com:8006");

    // Any selector of the same item passes: the grant is per item, not per
    // placeholder. A subset of the items passes too.
    assert!(matches!(
        a.check(&s, &["pve"], &c, t0() + secs(60)),
        Check::Granted
    ));
    assert!(matches!(
        a.check(&s, &["nas", "pve"], &c, t0() + secs(60)),
        Check::Granted
    ));
    // Another origin (host, scheme or port), another key, another item: asks.
    for other in [
        Ask::new("k1", "https://pve.example.com:8007/x"),
        Ask::new("k1", "http://pve.example.com:8006/x"),
        Ask::new("k1", "https://other.example.com:8006/x"),
        Ask::new("k2", "https://pve.example.com:8006/x"),
    ] {
        assert!(matches!(
            other.check(&s, &["pve"], &c, t0() + secs(60)),
            Check::Wait { created: true, .. }
        ));
    }
    assert!(matches!(
        a.check(&s, &["pve", "third"], &c, t0() + secs(60)),
        Check::Wait { created: true, .. }
    ));
    // The grant ends at its time.
    assert!(matches!(
        a.check(&s, &["pve"], &c, t0() + ChronoDuration::minutes(15)),
        Check::Wait { .. }
    ));
}

#[test]
fn an_open_approval_for_the_same_key_origin_and_items_is_reused() {
    let s = store();
    let a = Ask::new("k1", "https://pve.example.com:8006/x");
    let (id, created, g1) = pending_id(a.check(&s, &["pve"], &cfg(), t0()));
    assert!(created);
    let (id2, created2, g2) = pending_id(a.check(&s, &["pve"], &cfg(), t0() + secs(5)));
    assert_eq!(id, id2);
    assert!(!created2, "no new prompt");
    drop((g1, g2));
    // Another item set is another approval; the first stays.
    let (id3, created3, _g) = pending_id(a.check(&s, &["pve", "nas"], &cfg(), t0() + secs(6)));
    assert!(created3);
    assert_ne!(id, id3);
    assert_eq!(s.counts(t0() + secs(6)), (2, 0));
    // Once an item has a grant, a request for both asks for the rest only.
    approve(&s, &id, 5, t0() + secs(7));
    let (id4, created4, _g) = pending_id(a.check(&s, &["pve", "nas"], &cfg(), t0() + secs(8)));
    assert!(
        created4,
        "a new approval for the item that is still missing"
    );
    assert!(id4 != id && id4 != id3);
}

#[test]
fn a_denial_stands_for_its_time_and_a_later_approval_replaces_it() {
    let s = store();
    let a = Ask::new("k1", "https://pve.example.com:8006/x");
    let (id, _, _g) = pending_id(a.check(&s, &["pve"], &cfg(), t0()));
    s.deny(&id, Duration::from_secs(600), t0() + secs(10))
        .unwrap();
    // At once, without a new prompt, for any request that includes the item.
    for items in [&["pve"][..], &["nas", "pve"][..]] {
        assert!(matches!(
            a.check(&s, items, &cfg(), t0() + secs(11)),
            Check::Denied
        ));
    }
    assert_eq!(
        s.counts(t0() + secs(11)),
        (0, 0),
        "no new approval was opened"
    );
    // Another key or origin is not affected.
    assert!(matches!(
        Ask::new("k2", "https://pve.example.com:8006/x").check(
            &s,
            &["pve"],
            &cfg(),
            t0() + secs(11)
        ),
        Check::Wait { created: true, .. }
    ));
    // It ends after the window.
    assert!(matches!(
        a.check(&s, &["pve"], &cfg(), t0() + secs(10 + 600)),
        Check::Wait { created: true, .. }
    ));

    // A newer approval (made before the denial, still pending) wins over it.
    let s = store();
    let (first, _, _g1) = pending_id(a.check(&s, &["pve"], &cfg(), t0()));
    let (second, _, _g2) = pending_id(a.check(&s, &["nas", "pve"], &cfg(), t0() + secs(1)));
    s.deny(&first, Duration::from_secs(600), t0() + secs(2))
        .unwrap();
    approve(&s, &second, 5, t0() + secs(3));
    assert!(matches!(
        a.check(&s, &["pve"], &cfg(), t0() + secs(4)),
        Check::Granted
    ));
}

#[test]
fn deciding_twice_or_after_expiry_changes_nothing() {
    let s = store();
    let a = Ask::new("k1", "https://pve.example.com:8006/x");
    let (id, _, _g) = pending_id(a.check(&s, &["pve"], &cfg(), t0()));
    approve(&s, &id, 5, t0());
    // Decided: neither another approval nor a denial, and no second grant.
    assert_eq!(
        s.approve(&id, new_id().unwrap(), 5, "x", t0()).unwrap_err(),
        NotPending
    );
    assert_eq!(
        s.deny(&id, Duration::from_secs(60), t0()).unwrap_err(),
        NotPending
    );
    assert_eq!(s.counts(t0()), (0, 1));

    // Expired (even before the sweep): not pending.
    let (id2, _, _g2) = pending_id(a.check(&s, &["nas"], &cfg(), t0()));
    let late = t0() + secs(cfg().pending_ttl_secs as i64);
    assert_eq!(
        s.approve(&id2, new_id().unwrap(), 5, "x", late)
            .unwrap_err(),
        NotPending
    );
    assert_eq!(
        s.deny(&id2, Duration::from_secs(60), late).unwrap_err(),
        NotPending
    );
    assert!(s.get(&id2, late).is_none());
    // Unknown id.
    assert_eq!(
        s.approve("nope", new_id().unwrap(), 5, "x", t0())
            .unwrap_err(),
        NotPending
    );
}

#[test]
fn a_grant_can_be_revoked_early_and_then_the_next_request_asks_again() {
    let s = store();
    let a = Ask::new("k1", "https://pve.example.com:8006/x");
    let (id, _, _g) = pending_id(a.check(&s, &["pve"], &cfg(), t0()));
    let grant = approve(&s, &id, 60, t0());
    assert!(matches!(
        a.check(&s, &["pve"], &cfg(), t0()),
        Check::Granted
    ));
    let revoked = s.revoke_grant(&grant.id, t0() + secs(1)).unwrap();
    assert_eq!(revoked.id, grant.id);
    assert!(matches!(
        a.check(&s, &["pve"], &cfg(), t0() + secs(2)),
        Check::Wait { created: true, .. }
    ));
    // Twice, unknown and expired ids are all "not live".
    assert_eq!(s.revoke_grant(&grant.id, t0()).unwrap_err(), NotPending);
    assert_eq!(s.revoke_grant("nope", t0()).unwrap_err(), NotPending);
    let (id2, _, _g2) = pending_id(a.check(&s, &["nas"], &cfg(), t0()));
    let g2 = approve(&s, &id2, 1, t0());
    assert_eq!(
        s.revoke_grant(&g2.id, t0() + secs(60)).unwrap_err(),
        NotPending
    );
}

// ── Limits ────────────────────────────────────────────────────────────────────

#[test]
fn a_key_may_have_only_so_many_approvals_open() {
    let s = store();
    let a = Ask::new("k1", "https://pve.example.com:8006/x");
    let c = cfg();
    let mut guards = Vec::new();
    for i in 0..c.max_pending_per_key {
        let (_, created, g) = pending_id(a.check(&s, &[&format!("item{i}")], &c, t0()));
        assert!(created);
        guards.push(g);
    }
    // The next distinct approval is refused; an open one is still reused.
    assert!(matches!(
        a.check(&s, &["item_extra"], &c, t0()),
        Check::LimitReached
    ));
    assert!(matches!(
        a.check(&s, &["item0"], &c, t0()),
        Check::Wait { created: false, .. }
    ));
    // Another key is not affected.
    assert!(matches!(
        Ask::new("k2", "https://pve.example.com:8006/x").check(&s, &["item_extra"], &c, t0()),
        Check::Wait { created: true, .. }
    ));
    // When one of them expires, there is room again.
    let later = t0() + secs(c.pending_ttl_secs as i64);
    assert!(matches!(
        a.check(&s, &["item_extra"], &c, later),
        Check::Wait { created: true, .. }
    ));
}

#[test]
fn new_prompts_per_key_are_limited_in_a_sliding_hour() {
    let s = store();
    let a = Ask::new("k1", "https://pve.example.com:8006/x");
    let c = ApprovalConfig {
        max_requests_per_key_per_hour: 3,
        max_pending_per_key: 50,
        ..cfg()
    };
    for i in 0..3 {
        let (_, created, _g) =
            pending_id(a.check(&s, &[&format!("i{i}")], &c, t0() + secs(i * 60)));
        assert!(created);
    }
    // Reusing an open one does not count; a fourth new one does.
    assert!(matches!(
        a.check(&s, &["i0"], &c, t0() + secs(200)),
        Check::Wait { created: false, .. }
    ));
    assert!(matches!(
        a.check(&s, &["i3"], &c, t0() + secs(200)),
        Check::LimitReached
    ));
    // The window slides: an hour after the first prompt there is room for one.
    let (_, created, _g) = pending_id(a.check(&s, &["i3"], &c, t0() + secs(3600)));
    assert!(created);
    assert!(matches!(
        a.check(&s, &["i4"], &c, t0() + secs(3600)),
        Check::LimitReached
    ));
}

#[test]
fn held_requests_per_key_are_limited_and_counted_until_they_end() {
    let s = store();
    let a = Ask::new("k1", "https://pve.example.com:8006/x");
    let c = ApprovalConfig {
        max_waiters_per_key: 2,
        ..cfg()
    };
    let (id, _, g1) = pending_id(a.check(&s, &["pve"], &c, t0()));
    let (_, _, g2) = pending_id(a.check(&s, &["pve"], &c, t0()));
    assert!(g1.is_some() && g2.is_some());
    // The third is not held: it is told to retry at once.
    match a.check(&s, &["pve"], &c, t0()) {
        Check::Pending { view, created } => {
            assert_eq!(view.id, id);
            assert!(!created);
        }
        _ => panic!("expected an immediate pending"),
    }
    // Another key has its own count.
    assert!(matches!(
        Ask::new("k2", "https://pve.example.com:8006/x").check(&s, &["pve"], &c, t0()),
        Check::Wait { .. }
    ));
    // A request that ends (or whose client goes away) frees its place.
    drop(g1);
    assert!(matches!(
        a.check(&s, &["pve"], &c, t0()),
        Check::Wait { .. }
    ));
}

// ── Waking held requests ──────────────────────────────────────────────────────

#[test]
fn deciding_wakes_the_held_requests_with_the_decision() {
    let s = store();
    let a = Ask::new("k1", "https://pve.example.com:8006/x");
    let wait = |c: Check| match c {
        Check::Wait { rx, guard, .. } => (rx, guard),
        _ => panic!("expected a hold"),
    };
    let (rx_approved, _g1) = wait(a.check(&s, &["pve"], &cfg(), t0()));
    assert_eq!(*rx_approved.borrow(), Decision::Pending);
    let id = s.list(t0()).0[0].id.clone();
    approve(&s, &id, 5, t0());
    assert_eq!(*rx_approved.borrow(), Decision::Approved);

    let (rx_denied, _g2) = wait(a.check(&s, &["nas"], &cfg(), t0()));
    let id = s.get_by_item("nas", t0());
    s.deny(&id, Duration::from_secs(60), t0()).unwrap();
    assert_eq!(*rx_denied.borrow(), Decision::Denied);

    let (rx_expired, _g3) = wait(a.check(&s, &["third"], &cfg(), t0()));
    let swept = s.sweep(t0() + secs(cfg().pending_ttl_secs as i64));
    assert_eq!(swept.expired.len(), 1);
    assert_eq!(*rx_expired.borrow(), Decision::Expired);
}

impl ApprovalStore {
    /// The id of the open approval that has `item` (test helper).
    fn get_by_item(&self, item: &str, now: DateTime<Utc>) -> String {
        self.list(now)
            .0
            .into_iter()
            .find(|p| p.items.iter().any(|n| n.item == item))
            .unwrap()
            .id
    }
}

// ── Clearing and sweeping ─────────────────────────────────────────────────────

#[test]
fn clearing_a_key_drops_its_approvals_grants_and_denials_only() {
    let s = store();
    let k1 = Ask::new("k1", "https://pve.example.com:8006/x");
    let k2 = Ask::new("k2", "https://pve.example.com:8006/x");
    let (granted, _, _g1) = pending_id(k1.check(&s, &["a"], &cfg(), t0()));
    approve(&s, &granted, 30, t0());
    let (denied, _, _g2) = pending_id(k1.check(&s, &["b"], &cfg(), t0()));
    s.deny(&denied, Duration::from_secs(600), t0()).unwrap();
    let (open, _, _g3) = pending_id(k1.check(&s, &["c"], &cfg(), t0()));
    let (other, _, _g4) = pending_id(k2.check(&s, &["a"], &cfg(), t0()));
    approve(&s, &other, 30, t0());

    let cleared = s.clear_key("k1");
    assert_eq!(cleared.pending.len(), 1);
    assert_eq!(cleared.pending[0].id, open);
    assert_eq!(cleared.grants.len(), 1);
    // Nothing of the key is left: it asks again, and the denial is gone.
    assert!(matches!(
        k1.check(&s, &["a"], &cfg(), t0()),
        Check::Wait { created: true, .. }
    ));
    assert!(matches!(
        k1.check(&s, &["b"], &cfg(), t0()),
        Check::Wait { created: true, .. }
    ));
    // The other key keeps its grant.
    assert!(matches!(k2.check(&s, &["a"], &cfg(), t0()), Check::Granted));
}

#[test]
fn clearing_everything_and_the_sweep() {
    let s = store();
    let a = Ask::new("k1", "https://pve.example.com:8006/x");
    let (one, _, _g1) = pending_id(a.check(&s, &["a"], &cfg(), t0()));
    approve(&s, &one, 1, t0());
    let (_two, _, _g2) = pending_id(a.check(&s, &["b"], &cfg(), t0()));
    assert_eq!(s.counts(t0()), (1, 1));

    // The sweep removes what ran out: a grant after its minutes, an
    // approval after its time.
    let swept = s.sweep(t0() + secs(61));
    assert_eq!(swept.grants.len(), 1);
    assert!(swept.expired.is_empty());
    let swept = s.sweep(t0() + secs(cfg().pending_ttl_secs as i64));
    assert_eq!(swept.expired.len(), 1);
    assert_eq!(s.counts(t0() + secs(10_000)), (0, 0));

    let (id, _, _g3) = pending_id(a.check(&s, &["a"], &cfg(), t0()));
    approve(&s, &id, 30, t0());
    let (_p, _, _g4) = pending_id(a.check(&s, &["b"], &cfg(), t0()));
    let cleared = s.clear_all();
    assert_eq!((cleared.pending.len(), cleared.grants.len()), (1, 1));
    assert_eq!(s.counts(t0()), (0, 0));
}

#[test]
fn the_listing_is_ordered_and_never_shows_expired_entries() {
    let s = store();
    let a = Ask::new("k1", "https://pve.example.com:8006/x");
    let (_, _, _g1) = pending_id(a.check(&s, &["b"], &cfg(), t0()));
    let (_, _, _g2) = pending_id(a.check(&s, &["a"], &cfg(), t0() + secs(5)));
    let (pending, grants) = s.list(t0() + secs(6));
    assert_eq!(pending.len(), 2);
    assert!(pending[0].created < pending[1].created);
    assert!(grants.is_empty());
    let (pending, _) = s.list(t0() + secs(cfg().pending_ttl_secs as i64));
    assert_eq!(pending.len(), 1, "the older one has expired");
    // The view carries the URL as sent, never a value.
    let json = pending[0].to_json();
    assert_eq!(json["method"], "GET");
    assert_eq!(json["origin"]["port"], 8006);
    assert!(json["url"].as_str().unwrap().contains("/api2/json/nodes"));
}

// ── Errors, events ────────────────────────────────────────────────────────────

#[test]
fn approval_errors_have_stable_codes_and_statuses() {
    let pending = FerroError::ApprovalPending { id: "abc".into() };
    assert_eq!(pending.status_code(), 403);
    assert_eq!(pending.approval_code(), Some("approval_pending"));
    assert!(pending.to_string().contains("retry the same request"));
    assert!(pending.to_string().contains("admin UI"));
    assert!(pending.to_string().contains("abc"));
    assert_eq!(FerroError::ApprovalDenied.status_code(), 403);
    assert_eq!(
        FerroError::ApprovalDenied.approval_code(),
        Some("approval_denied")
    );
    assert_eq!(FerroError::ApprovalLimitReached.status_code(), 429);
    assert_eq!(
        FerroError::ApprovalLimitReached.approval_code(),
        Some("approval_limit_reached")
    );
    assert_eq!(FerroError::ApprovalNotPending.status_code(), 409);
    assert_eq!(FerroError::GrantNotFound.status_code(), 404);
    assert_eq!(FerroError::Unauthorized.approval_code(), None);
    assert_eq!(refusal_result(&pending), Some("pending"));
    assert_eq!(refusal_result(&FerroError::ApprovalDenied), Some("denied"));
    assert_eq!(
        refusal_result(&FerroError::ApprovalLimitReached),
        Some("limit_reached")
    );
    assert_eq!(refusal_result(&FerroError::VaultLocked), None);
}

#[test]
fn the_debug_output_of_the_store_shows_counts_only() {
    let s = store();
    let a = Ask::new("k1", "https://pve.example.com:8006/x");
    let (id, _, _g) = pending_id(a.check(&s, &["secret_item_name"], &cfg(), t0()));
    let text = format!("{s:?}");
    assert!(text.contains("pending: 1"), "{text}");
    assert!(
        !text.contains("secret_item_name") && !text.contains(&id),
        "{text}"
    );
}

// ── Create approvals: one operation, once ─────────────────────────────────────

fn detail(name: &str) -> CreateDetail {
    CreateDetail {
        name: name.to_string(),
        username: Some("admin".to_string()),
        uris: vec!["https://keycloak.example.com".to_string()],
        charset: "alphanumeric".to_string(),
        length: 32,
        approval_required: false,
        collection: "Ferrowarden managed".to_string(),
    }
}

/// A create ask for `key`, whose operation is identified by `fp`.
fn check_create(
    s: &Arc<ApprovalStore>,
    key: &str,
    fp: &str,
    cfg: &ApprovalConfig,
    now: DateTime<Utc>,
) -> Check {
    let d = detail("agent_keycloak_admin");
    let ask = CreateAsk {
        key_id: key,
        key_name: "agent",
        request_id: "req-9",
        fingerprint: fp,
        detail: &d,
    };
    s.check_create(&ask, cfg, now).unwrap()
}

fn approve_create(s: &Arc<ApprovalStore>, id: &str, now: DateTime<Utc>) -> PendingView {
    s.approve_create(id, Duration::from_secs(600), now).unwrap()
}

#[test]
fn a_create_opens_an_approval_of_the_create_kind_and_a_repeat_reuses_it() {
    let s = store();
    let (id, created, _g) = pending_id(check_create(&s, "k1", "fp-a", &cfg(), t0()));
    assert!(created);
    let view = s.get(&id, t0()).unwrap();
    assert_eq!(view.kind, ApprovalKind::Create);
    assert_eq!(view.create.as_ref().unwrap().name, "agent_keycloak_admin");
    assert_eq!(view.items.len(), 1);
    assert_eq!(view.items[0].item, "agent_keycloak_admin");
    assert_eq!(s.kind_of(&id, t0()), Some(ApprovalKind::Create));
    assert_eq!(s.kind_of("nope", t0()), None);

    // The same operation from the same key: the same approval, no new prompt.
    let (again, created, _g2) = pending_id(check_create(&s, "k1", "fp-a", &cfg(), t0()));
    assert_eq!(again, id);
    assert!(!created);
    assert_eq!(s.counts(t0()).0, 1);

    // Another operation, or another key: its own approval.
    let (other, created, _g3) = pending_id(check_create(&s, "k1", "fp-b", &cfg(), t0()));
    assert!(created && other != id);
    let (other_key, created, _g4) = pending_id(check_create(&s, "k2", "fp-a", &cfg(), t0()));
    assert!(created && other_key != id);
}

#[test]
fn an_approved_create_is_used_up_by_the_first_matching_request() {
    let s = store();
    let (id, _, _g) = pending_id(check_create(&s, "k1", "fp-a", &cfg(), t0()));
    let view = approve_create(&s, &id, t0() + secs(5));
    assert_eq!(view.kind, ApprovalKind::Create);
    // No grant, and the approval is gone from the open list.
    assert_eq!(s.counts(t0() + secs(5)), (0, 0));
    assert!(s.list(t0() + secs(5)).1.is_empty());

    // Not for another operation or another key.
    assert!(!s.consume_create("k1", "fp-b", t0() + secs(6)));
    assert!(!s.consume_create("k2", "fp-a", t0() + secs(6)));
    // The first matching request uses it; the second needs a new approval.
    assert!(matches!(
        check_create(&s, "k1", "fp-a", &cfg(), t0() + secs(7)),
        Check::Granted
    ));
    let (new_id, created, _g) = pending_id(check_create(&s, "k1", "fp-a", &cfg(), t0() + secs(8)));
    assert!(created);
    assert_ne!(new_id, id);
}

#[test]
fn a_woken_request_and_a_retry_cannot_both_use_one_approval() {
    let s = store();
    let (id, _, _g) = pending_id(check_create(&s, "k1", "fp-a", &cfg(), t0()));
    approve_create(&s, &id, t0());
    assert!(s.consume_create("k1", "fp-a", t0()), "the first");
    assert!(!s.consume_create("k1", "fp-a", t0()), "not twice");
}

#[test]
fn an_approved_create_that_is_not_used_expires() {
    let s = store();
    let (id, _, _g) = pending_id(check_create(&s, "k1", "fp-a", &cfg(), t0()));
    approve_create(&s, &id, t0());
    // It is kept for the 600 seconds `approve_create` gives it.
    assert!(!s.consume_create("k1", "fp-a", t0() + secs(601)));

    // The sweep drops it too.
    let (id, _, _g) = pending_id(check_create(&s, "k1", "fp-b", &cfg(), t0() + secs(700)));
    approve_create(&s, &id, t0() + secs(700));
    s.sweep(t0() + secs(2000));
    assert!(!s.consume_create("k1", "fp-b", t0() + secs(701)));
}

#[test]
fn a_denied_create_is_refused_without_a_new_prompt_for_the_cooldown() {
    let s = store();
    let (id, _, _g) = pending_id(check_create(&s, "k1", "fp-a", &cfg(), t0()));
    s.deny(&id, Duration::from_secs(600), t0() + secs(10))
        .unwrap();
    assert!(matches!(
        check_create(&s, "k1", "fp-a", &cfg(), t0() + secs(20)),
        Check::Denied
    ));
    // Only that operation, and only for that key.
    let (_, created, _g2) = pending_id(check_create(&s, "k1", "fp-b", &cfg(), t0() + secs(20)));
    assert!(created);
    let (_, created, _g3) = pending_id(check_create(&s, "k2", "fp-a", &cfg(), t0() + secs(20)));
    assert!(created);
    // After the cooldown it can be asked again.
    let (_, created, _g4) = pending_id(check_create(&s, "k1", "fp-a", &cfg(), t0() + secs(700)));
    assert!(created);
}

#[test]
fn approving_replaces_a_denial_of_the_same_operation() {
    let s = store();
    let (id, _, _g) = pending_id(check_create(&s, "k1", "fp-a", &cfg(), t0()));
    s.deny(&id, Duration::from_secs(600), t0()).unwrap();
    // A later approval of the same operation (a new prompt after the
    // cooldown) clears the denial.
    let (id2, _, _g) = pending_id(check_create(&s, "k1", "fp-a", &cfg(), t0() + secs(601)));
    approve_create(&s, &id2, t0() + secs(602));
    assert!(matches!(
        check_create(&s, "k1", "fp-a", &cfg(), t0() + secs(603)),
        Check::Granted
    ));
}

#[test]
fn the_two_kinds_are_decided_with_their_own_calls_only() {
    let s = store();
    let (create_id, _, _g) = pending_id(check_create(&s, "k1", "fp-a", &cfg(), t0()));
    let ask = Ask::new("k1", "https://pve.example.com:8006/x");
    let (fwd_id, _, _g2) = pending_id(ask.check(&s, &["proxmox_root"], &cfg(), t0()));
    assert_eq!(s.kind_of(&fwd_id, t0()), Some(ApprovalKind::Forward));

    // A create cannot be given a grant, and a forward cannot be approved as
    // a create: each call refuses the other kind and changes nothing.
    assert_eq!(
        s.approve(&create_id, new_id().unwrap(), 5, "x", t0())
            .unwrap_err(),
        NotPending
    );
    assert_eq!(
        s.approve_create(&fwd_id, Duration::from_secs(60), t0())
            .unwrap_err(),
        NotPending
    );
    assert_eq!(s.counts(t0()).0, 2, "both still open");
    assert!(s.list(t0()).1.is_empty(), "no grant was made");
}

#[test]
fn create_approvals_count_towards_the_per_key_limits_with_forwards() {
    let s = store();
    let mut c = cfg();
    c.max_pending_per_key = 2;
    let ask = Ask::new("k1", "https://pve.example.com:8006/x");
    let (_, _, _g1) = pending_id(ask.check(&s, &["a"], &c, t0()));
    let (_, _, _g2) = pending_id(check_create(&s, "k1", "fp-a", &c, t0()));
    // Two open (one of each kind): a third of either kind is over the limit.
    assert!(matches!(
        check_create(&s, "k1", "fp-b", &c, t0()),
        Check::LimitReached
    ));
    assert!(matches!(
        ask.check(&s, &["b"], &c, t0()),
        Check::LimitReached
    ));
    // Another key is not affected.
    let (_, created, _g3) = pending_id(check_create(&s, "k2", "fp-a", &c, t0()));
    assert!(created);

    // The hourly limit counts both kinds too.
    let s = store();
    let mut c = cfg();
    c.max_requests_per_key_per_hour = 2;
    c.max_pending_per_key = 10;
    let (id, _, _g) = pending_id(check_create(&s, "k1", "fp-a", &c, t0()));
    approve_create(&s, &id, t0());
    let (_, _, _g) = pending_id(ask.check(&s, &["a"], &c, t0() + secs(1)));
    assert!(matches!(
        check_create(&s, "k1", "fp-c", &c, t0() + secs(2)),
        Check::LimitReached
    ));
}

#[test]
fn waiters_are_limited_per_key_for_creates_too() {
    let s = store();
    let mut c = cfg();
    c.max_waiters_per_key = 1;
    let first = check_create(&s, "k1", "fp-a", &c, t0());
    assert!(matches!(first, Check::Wait { .. }));
    // The same operation again: reused, but not held (over the waiter limit).
    match check_create(&s, "k1", "fp-a", &c, t0()) {
        Check::Pending { created, .. } => assert!(!created),
        _ => panic!("expected pending"),
    }
}

#[test]
fn clearing_a_key_or_the_vault_drops_create_approvals_and_approved_creates() {
    let s = store();
    let (a, _, _g) = pending_id(check_create(&s, "k1", "fp-a", &cfg(), t0()));
    let (b, _, _g2) = pending_id(check_create(&s, "k1", "fp-b", &cfg(), t0()));
    approve_create(&s, &b, t0());
    let (_, _, _g3) = pending_id(check_create(&s, "k2", "fp-a", &cfg(), t0()));

    let cleared = s.clear_key("k1");
    assert_eq!(cleared.pending.len(), 1);
    assert_eq!(cleared.pending[0].id, a);
    assert_eq!(cleared.pending[0].kind, ApprovalKind::Create);
    // The approved-but-unused one of that key went too.
    assert!(!s.consume_create("k1", "fp-b", t0()));
    assert_eq!(s.counts(t0()).0, 1, "the other key still has one open");

    let cleared = s.clear_all();
    assert_eq!(cleared.pending.len(), 1);
    assert_eq!(s.counts(t0()), (0, 0));
}

#[test]
fn the_views_say_what_a_create_asks_for_and_never_a_value() {
    let s = store();
    let (id, _, _g) = pending_id(check_create(&s, "k1", "fp-a", &cfg(), t0()));
    let v = s.get(&id, t0()).unwrap();
    let j = v.to_json();
    assert_eq!(j["kind"], "create");
    assert_eq!(j["create"]["name"], "agent_keycloak_admin");
    assert_eq!(j["create"]["username"], "admin");
    assert_eq!(j["create"]["generate"]["length"], 32);
    assert_eq!(j["create"]["collection"], "Ferrowarden managed");
    assert!(j.get("method").is_none() && j.get("origin").is_none() && j.get("url").is_none());
    assert_eq!(j["credentials"][0]["credential"], "agent_keycloak_admin");

    // The prompt event names the kind and what is asked.
    let ctx = RequestContext::new("127.0.0.1".parse().unwrap());
    let e = serde_json::to_value(requested_event(
        &ctx,
        &v,
        Some("https://ui/approvals/x".into()),
    ))
    .unwrap();
    let d = &e["ferrowarden"]["details"];
    assert_eq!(d["kind"], "create");
    assert_eq!(d["create"]["name"], "agent_keycloak_admin");
    assert_eq!(d["link"], "https://ui/approvals/x");
    assert!(d.get("host").is_none() && d.get("path").is_none());
    assert!(e.get("url").is_none());

    // A forward still says `forward` and has its request.
    let ask = Ask::new("k1", "https://pve.example.com:8006/x");
    let (fid, _, _g2) = pending_id(ask.check(&s, &["proxmox_root"], &cfg(), t0()));
    let fv = s.get(&fid, t0()).unwrap();
    assert_eq!(fv.to_json()["kind"], "forward");
    assert_eq!(fv.to_json()["method"], "GET");
    let e = serde_json::to_value(requested_event(&ctx, &fv, None)).unwrap();
    assert_eq!(e["ferrowarden"]["details"]["kind"], "forward");
}

// ── Rotate approvals: the same one-shot approval ──────────────────────────────

fn rotate_detail(name: &str) -> RotateDetail {
    RotateDetail {
        name: name.to_string(),
        collection: "Ferrowarden managed".to_string(),
        charset: "alphanumeric".to_string(),
        length: 32,
    }
}

fn check_rotate(
    s: &Arc<ApprovalStore>,
    key: &str,
    fp: &str,
    cfg: &ApprovalConfig,
    now: DateTime<Utc>,
) -> Check {
    let d = rotate_detail("agent_keycloak_svc");
    let ask = RotateAsk {
        key_id: key,
        key_name: "agent",
        request_id: "req-9",
        fingerprint: fp,
        detail: &d,
    };
    s.check_rotate(&ask, cfg, now).unwrap()
}

#[test]
fn a_rotation_opens_an_approval_of_the_rotate_kind_and_a_repeat_reuses_it() {
    let s = store();
    let (id, created, _g) = pending_id(check_rotate(&s, "k1", "fp-a", &cfg(), t0()));
    assert!(created);
    let view = s.get(&id, t0()).unwrap();
    assert_eq!(view.kind, ApprovalKind::Rotate);
    assert_eq!(view.kind.as_str(), "rotate");
    assert!(view.create.is_none());
    assert_eq!(view.rotate.as_ref().unwrap().name, "agent_keycloak_svc");
    assert_eq!(view.items[0].item, "agent_keycloak_svc");
    assert_eq!(s.kind_of(&id, t0()), Some(ApprovalKind::Rotate));
    let json = view.to_json();
    assert_eq!(json["kind"], "rotate");
    assert_eq!(json["rotate"]["name"], "agent_keycloak_svc");
    assert_eq!(json["rotate"]["generate"]["length"], 32);
    assert!(json.get("origin").is_none() && json.get("method").is_none());

    let (again, created, _g2) = pending_id(check_rotate(&s, "k1", "fp-a", &cfg(), t0()));
    assert_eq!((again.as_str(), created), (id.as_str(), false));
    let (other, created, _g3) = pending_id(check_rotate(&s, "k1", "fp-b", &cfg(), t0()));
    assert!(created && other != id);
    let (other_key, created, _g4) = pending_id(check_rotate(&s, "k2", "fp-a", &cfg(), t0()));
    assert!(created && other_key != id);
}

#[test]
fn an_approved_rotation_is_used_up_once_and_is_never_a_grant() {
    let s = store();
    let (id, _, _g) = pending_id(check_rotate(&s, "k1", "fp-a", &cfg(), t0()));
    let view = approve_create(&s, &id, t0() + secs(5));
    assert_eq!(view.kind, ApprovalKind::Rotate);
    assert_eq!(s.counts(t0() + secs(5)), (0, 0), "no grant");
    assert!(!s.consume_create("k2", "fp-a", t0() + secs(6)));
    assert!(matches!(
        check_rotate(&s, "k1", "fp-a", &cfg(), t0() + secs(7)),
        Check::Granted
    ));
    let (_, created, _g) = pending_id(check_rotate(&s, "k1", "fp-a", &cfg(), t0() + secs(8)));
    assert!(created, "used up: the next one asks again");
}

#[test]
fn a_forward_approval_cannot_be_approved_as_a_rotation_and_the_reverse() {
    let s = store();
    let a = Ask::new("k1", "https://pve.example.com:8006/x");
    let (fwd, _, _g) = pending_id(a.check(&s, &["item"], &cfg(), t0()));
    assert!(s
        .approve_create(&fwd, Duration::from_secs(60), t0())
        .is_err());
    let (rot, _, _g2) = pending_id(check_rotate(&s, "k1", "fp-a", &cfg(), t0()));
    assert!(s.approve(&rot, "g1".into(), 5, "x", t0()).is_err());
}

#[test]
fn a_denied_rotation_stands_for_that_operation_only() {
    let s = store();
    let (id, _, _g) = pending_id(check_rotate(&s, "k1", "fp-a", &cfg(), t0()));
    s.deny(&id, Duration::from_secs(300), t0()).unwrap();
    assert!(matches!(
        check_rotate(&s, "k1", "fp-a", &cfg(), t0() + secs(10)),
        Check::Denied
    ));
    let (_, created, _g) = pending_id(check_rotate(&s, "k1", "fp-b", &cfg(), t0() + secs(10)));
    assert!(created, "another operation is asked about");
    // After the cooldown the same operation asks again.
    let (_, created, _g) = pending_id(check_rotate(&s, "k1", "fp-a", &cfg(), t0() + secs(400)));
    assert!(created);
}

#[test]
fn rotate_approvals_count_towards_the_same_limits_as_the_other_kinds() {
    let s = store();
    let mut c = cfg();
    c.max_pending_per_key = 2;
    let _a = pending_id(check_rotate(&s, "k1", "fp-1", &c, t0()));
    let _b = pending_id(check_create(&s, "k1", "fp-2", &c, t0()));
    assert!(matches!(
        check_rotate(&s, "k1", "fp-3", &c, t0()),
        Check::LimitReached
    ));
}
