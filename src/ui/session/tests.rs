
use super::*;

const IDLE: Duration = Duration::from_secs(15 * 60);
const MAX: Duration = Duration::from_secs(8 * 3600);

fn secs(s: u64) -> Duration {
    Duration::from_secs(s)
}

fn store() -> SessionStore {
    SessionStore::new(IDLE, MAX)
}

fn ip(n: u8) -> IpAddr {
    IpAddr::from([192, 168, 1, n])
}

fn pending(now: Instant) -> PendingLogin {
    PendingLogin::new(
        Zeroizing::new("HASH".to_string()),
        "admin@example.test".to_string(),
        TwoFactorRequired {
            providers: vec![Provider::Authenticator, Provider::Email],
            email_hint: None,
        },
        ip(1),
        now,
    )
}

// ── tokens ──

#[test]
fn tokens_are_43_chars_of_base64url_and_unique() {
    let a = random_token().unwrap();
    let b = random_token().unwrap();
    assert_eq!(a.len(), 43);
    assert!(a
        .bytes()
        .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_'));
    assert_ne!(*a, *b);
}

#[test]
fn secret_comparison() {
    assert!(secrets_equal("abc", "abc"));
    assert!(!secrets_equal("abc", "abd"));
    assert!(!secrets_equal("abc", "abcd"));
    assert!(!secrets_equal("", "a"));
    assert!(secrets_equal("", ""));
}

// ── sessions ──

#[test]
fn create_and_lookup_by_hash() {
    let t0 = Instant::now();
    let mut s = store();
    let (id, csrf) = s.create(t0).unwrap();
    // The map holds the digest, never the id.
    assert!(s.sessions.contains_key(&digest(&id)));
    assert!(!s.sessions.keys().any(|k| k.as_slice() == id.as_bytes()));
    match s.lookup(&id, t0 + secs(1)) {
        Lookup::Valid(v) => assert_eq!(*v.csrf, *csrf),
        _ => panic!("expected a valid session"),
    }
    assert!(matches!(s.lookup("nope", t0), Lookup::Missing));
    assert!(matches!(s.lookup("", t0), Lookup::Missing));
}

#[test]
fn idle_timeout_slides_but_absolute_limit_does_not() {
    let t0 = Instant::now();
    let mut s = store();
    let (id, _) = s.create(t0).unwrap();
    // Activity every 10 minutes keeps it alive ...
    let mut t = t0;
    for _ in 0..40 {
        t += secs(600);
        if t.duration_since(t0) >= MAX {
            break;
        }
        assert!(matches!(s.lookup(&id, t), Lookup::Valid(_)));
    }
    // ... until the absolute limit.
    let end = t0 + MAX;
    assert!(matches!(s.lookup(&id, end), Lookup::Expired));
    assert!(matches!(s.lookup(&id, end), Lookup::Missing));
}

#[test]
fn idle_expiry() {
    let t0 = Instant::now();
    let mut s = store();
    let (id, _) = s.create(t0).unwrap();
    assert!(matches!(
        s.lookup(&id, t0 + IDLE - secs(1)),
        Lookup::Valid(_)
    ));
    // The lookup above refreshed the timer; idle from there.
    assert!(matches!(
        s.lookup(&id, t0 + IDLE - secs(1) + IDLE),
        Lookup::Expired
    ));
}

#[test]
fn expires_at_is_the_earlier_of_idle_and_absolute() {
    let t0 = Instant::now();
    let mut s = SessionStore::new(secs(600), secs(1000));
    let (id, _) = s.create(t0).unwrap();
    let Lookup::Valid(v) = s.lookup(&id, t0 + secs(100)) else {
        panic!()
    };
    assert_eq!(v.expires_at, t0 + secs(700));
    let Lookup::Valid(v) = s.lookup(&id, t0 + secs(600)) else {
        panic!()
    };
    assert_eq!(v.expires_at, t0 + secs(1000));
}

#[test]
fn at_most_eight_sessions_and_the_oldest_is_evicted() {
    let t0 = Instant::now();
    let mut s = store();
    let ids: Vec<_> = (0..MAX_SESSIONS)
        .map(|i| s.create(t0 + secs(i as u64)).unwrap().0)
        .collect();
    assert_eq!(s.len(), MAX_SESSIONS);
    let newest = s.create(t0 + secs(100)).unwrap().0;
    assert_eq!(s.len(), MAX_SESSIONS);
    assert!(matches!(s.lookup(&ids[0], t0 + secs(101)), Lookup::Missing));
    assert!(matches!(
        s.lookup(&ids[1], t0 + secs(101)),
        Lookup::Valid(_)
    ));
    assert!(matches!(
        s.lookup(&newest, t0 + secs(101)),
        Lookup::Valid(_)
    ));
}

#[test]
fn expired_sessions_are_dropped_when_a_new_one_starts() {
    let t0 = Instant::now();
    let mut s = store();
    for _ in 0..5 {
        s.create(t0).unwrap();
    }
    s.create(t0 + IDLE + secs(1)).unwrap();
    assert_eq!(s.len(), 1);
}

#[test]
fn destroy_removes_the_session() {
    let t0 = Instant::now();
    let mut s = store();
    let (id, _) = s.create(t0).unwrap();
    assert!(s.destroy(&id));
    assert!(!s.destroy(&id));
    assert!(matches!(s.lookup(&id, t0), Lookup::Missing));
}

#[test]
fn every_session_has_its_own_id_and_csrf() {
    let t0 = Instant::now();
    let mut s = store();
    let (id1, c1) = s.create(t0).unwrap();
    let (id2, c2) = s.create(t0).unwrap();
    assert_ne!(*id1, *id2);
    assert_ne!(*c1, *c2);
    assert_ne!(*id1, *c1);
}

// ── pending login ──

#[test]
fn pending_is_found_by_its_cookie_and_bound_to_the_ip() {
    let t0 = Instant::now();
    let mut slot = PendingSlot::new();
    let id = slot.set(pending(t0)).unwrap();
    assert!(slot.peek(&id, ip(1), t0 + secs(1)).is_ok());
    assert!(matches!(
        slot.peek(&id, ip(2), t0 + secs(1)),
        Err(PendingCheck::WrongIp)
    ));
    assert!(matches!(
        slot.peek("other", ip(1), t0 + secs(1)),
        Err(PendingCheck::Missing)
    ));
    // A wrong IP does not destroy the legitimate pending login.
    assert!(slot.peek(&id, ip(1), t0 + secs(2)).is_ok());
}

#[test]
fn pending_expires_after_three_minutes() {
    let t0 = Instant::now();
    let mut slot = PendingSlot::new();
    let id = slot.set(pending(t0)).unwrap();
    assert!(slot.peek(&id, ip(1), t0 + PENDING_TTL - secs(1)).is_ok());
    assert!(matches!(
        slot.peek(&id, ip(1), t0 + PENDING_TTL),
        Err(PendingCheck::Expired)
    ));
    assert!(slot.is_empty());
    assert!(matches!(
        slot.peek(&id, ip(1), t0 + PENDING_TTL),
        Err(PendingCheck::Missing)
    ));
}

#[test]
fn a_new_password_step_replaces_the_older_pending_login() {
    let t0 = Instant::now();
    let mut slot = PendingSlot::new();
    let first = slot.set(pending(t0)).unwrap();
    let second = slot.set(pending(t0 + secs(5))).unwrap();
    assert!(matches!(
        slot.peek(&first, ip(1), t0 + secs(6)),
        Err(PendingCheck::Missing)
    ));
    assert!(slot.peek(&second, ip(1), t0 + secs(6)).is_ok());
}

#[test]
fn three_wrong_codes_remove_the_pending_login() {
    let t0 = Instant::now();
    let mut slot = PendingSlot::new();
    let id = slot.set(pending(t0)).unwrap();
    for n in 1..=3 {
        let (hash, email) = slot.begin_code_attempt(&id, ip(1), t0).unwrap();
        assert_eq!(hash.as_str(), "HASH");
        assert_eq!(email, "admin@example.test");
        let gone = slot.code_rejected(&id);
        assert_eq!(gone, n == 3, "attempt {n}");
    }
    assert!(slot.is_empty());
    assert!(matches!(
        slot.begin_code_attempt(&id, ip(1), t0),
        Err(PendingCheck::Missing)
    ));
}

#[test]
fn attempts_are_reserved_before_the_call_so_races_cannot_exceed_the_limit() {
    let t0 = Instant::now();
    let mut slot = PendingSlot::new();
    let id = slot.set(pending(t0)).unwrap();
    // Four overlapping requests, none finished yet: the 4th is refused.
    for _ in 0..3 {
        assert!(slot.begin_code_attempt(&id, ip(1), t0).is_ok());
    }
    assert!(slot.begin_code_attempt(&id, ip(1), t0).is_err());
    assert!(slot.is_empty());
}

#[test]
fn a_refunded_attempt_does_not_count() {
    let t0 = Instant::now();
    let mut slot = PendingSlot::new();
    let id = slot.set(pending(t0)).unwrap();
    slot.begin_code_attempt(&id, ip(1), t0).unwrap();
    slot.refund_code_attempt(&id);
    assert_eq!(slot.peek(&id, ip(1), t0).unwrap().attempts(), 0);
}

#[test]
fn email_resend_is_limited_to_once_a_minute() {
    let t0 = Instant::now();
    let mut slot = PendingSlot::new();
    let id = slot.set(pending(t0)).unwrap();
    assert!(slot.begin_email_send(&id, ip(1), t0).unwrap().is_some());
    assert!(slot
        .begin_email_send(&id, ip(1), t0 + secs(59))
        .unwrap()
        .is_none());
    assert!(slot
        .begin_email_send(&id, ip(1), t0 + secs(60))
        .unwrap()
        .is_some());
}

#[test]
fn email_is_only_sent_when_the_server_offered_it() {
    let t0 = Instant::now();
    let mut slot = PendingSlot::new();
    let login = PendingLogin::new(
        Zeroizing::new("H".to_string()),
        "a@b.test".to_string(),
        TwoFactorRequired {
            providers: vec![Provider::Authenticator],
            email_hint: None,
        },
        ip(1),
        t0,
    );
    let id = slot.set(login).unwrap();
    assert!(slot.begin_email_send(&id, ip(1), t0).unwrap().is_none());
}

#[test]
fn clear_wipes_the_slot() {
    let t0 = Instant::now();
    let mut slot = PendingSlot::new();
    slot.set(pending(t0)).unwrap();
    assert!(!slot.is_empty());
    slot.clear();
    assert!(slot.is_empty());
}

#[test]
fn pending_login_is_zeroized_on_drop() {
    // The hash is a `Zeroizing<String>` and the type derives
    // `ZeroizeOnDrop`; both are checked at compile time.
    fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}
    assert_zeroize_on_drop::<PendingLogin>();
    fn assert_hash_type(p: &PendingLogin) -> &Zeroizing<String> {
        &p.auth_hash
    }
    let p = pending(Instant::now());
    assert_eq!(assert_hash_type(&p).as_str(), "HASH");

    // And behaviourally: zeroizing a String wipes its bytes in place.
    use zeroize::Zeroize;
    let mut s = String::from("secret-hash");
    let ptr = s.as_ptr();
    let len = s.len();
    s.zeroize();
    // SAFETY: the String is alive and keeps its allocation (capacity >= len).
    let bytes = unsafe { std::slice::from_raw_parts(ptr, len) };
    assert!(bytes.iter().all(|b| *b == 0));
}
