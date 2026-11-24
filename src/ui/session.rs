//! Server-side state of the admin UI: sessions and the one pending sign-in.
//!
//! Everything is in memory and lost on restart, which is fine: the operator
//! signs in again. Nothing here talks to Vaultwarden and no Vaultwarden token
//! is ever stored — a session only proves that the master password (and second
//! factor) were accepted once.
//!
//! Secrets and how they are kept:
//!
//! * **session id** (32 random bytes, base64url, in the `__Host-fw_session`
//!   cookie): only its SHA-256 is stored, so a memory dump yields no usable
//!   cookie. Lookup is by that hash.
//! * **CSRF token** (32 random bytes): lives in the session, `Zeroizing`.
//! * **pending login** (a correct password, waiting for the second factor):
//!   holds the master password hash in a `Zeroizing` string and wipes it when
//!   removed or dropped.
//!
//! These types deliberately have no `Debug`, so they cannot end up in a log
//! line by accident. Time is passed in, so expiry is tested without sleeping.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::{ZeroizeOnDrop, Zeroizing};

use crate::ui::vw_login::{Provider, TwoFactorRequired};

/// Most concurrent sessions; the oldest is evicted for a new one.
pub const MAX_SESSIONS: usize = 8;
/// Vaultwarden forgets an incomplete two-factor login after this long.
pub const PENDING_TTL: Duration = Duration::from_secs(180);
/// Wrong second-factor codes allowed per pending login.
pub const MAX_CODE_ATTEMPTS: u8 = 3;
/// Minimum time between two "send the email code" requests.
pub const EMAIL_RESEND_INTERVAL: Duration = Duration::from_secs(60);
/// Sensitive actions (creating or revoking a key, saving a policy) need a
/// sign-in this recent: the "sudo window". Not configurable.
pub const SUDO_WINDOW: Duration = Duration::from_secs(10 * 60);
/// Single-use form ids a session may hold at once (the create-key form). The
/// oldest is dropped for a new one; they end with the session.
pub const MAX_FORM_IDS: usize = 8;

// ── Random tokens ─────────────────────────────────────────────────────────────

/// 32 random bytes from the operating system, base64url without padding.
/// `None` only if the OS RNG fails; callers fail the request then.
pub fn random_token() -> Option<Zeroizing<String>> {
    let mut bytes = Zeroizing::new([0u8; 32]);
    getrandom::fill(&mut *bytes).ok()?;
    let mut out = Zeroizing::new(String::with_capacity(43));
    URL_SAFE_NO_PAD.encode_string(*bytes, &mut out);
    Some(out)
}

/// What the stores key on instead of the secret itself.
pub fn digest(token: &str) -> [u8; 32] {
    Sha256::digest(token.as_bytes()).into()
}

/// Constant-time equality of two secret strings. Different lengths are
/// unequal at once (the length of a token is not a secret).
pub fn secrets_equal(a: &str, b: &str) -> bool {
    a.len() == b.len() && bool::from(a.as_bytes().ct_eq(b.as_bytes()))
}

// ── Sessions ──────────────────────────────────────────────────────────────────

struct Session {
    /// Creation order, so "oldest" is never a tie.
    seq: u64,
    created: Instant,
    /// When the password (and second factor) were last accepted. Equal to
    /// `created`: a re-sign-in makes a new session. Never moved by activity.
    authenticated_at: Instant,
    last_seen: Instant,
    csrf: Zeroizing<String>,
    /// Digests of the issued, not yet used form ids, oldest first.
    form_ids: Vec<[u8; 32]>,
}

/// What a handler may know about a valid session.
pub struct SessionView {
    /// The CSRF token to put in forms and to expect in POSTs.
    pub csrf: Zeroizing<String>,
    /// When the session ends if it stays idle, capped by the absolute limit.
    pub expires_at: Instant,
    /// When this session's sign-in happened.
    pub authenticated_at: Instant,
    /// Which session this is (the digest of its id), for the store's
    /// per-session state such as form ids. Not a secret on its own.
    handle: [u8; 32],
}

impl SessionView {
    /// Whole minutes since the sign-in.
    pub fn signed_in_minutes(&self, now: Instant) -> u64 {
        now.saturating_duration_since(self.authenticated_at)
            .as_secs()
            / 60
    }

    /// Is the sign-in recent enough for a sensitive action?
    pub fn sudo_active(&self, now: Instant) -> bool {
        now.saturating_duration_since(self.authenticated_at) < SUDO_WINDOW
    }
}

pub enum Lookup {
    Valid(SessionView),
    /// The session existed but ran out (idle or absolute). It is removed.
    Expired,
    Missing,
}

pub struct SessionStore {
    sessions: HashMap<[u8; 32], Session>,
    next_seq: u64,
    idle: Duration,
    max_age: Duration,
}

impl SessionStore {
    pub fn new(idle: Duration, max_age: Duration) -> Self {
        Self {
            sessions: HashMap::new(),
            next_seq: 0,
            idle,
            max_age,
        }
    }

    fn is_live(&self, s: &Session, now: Instant) -> bool {
        now.duration_since(s.last_seen) < self.idle && now.duration_since(s.created) < self.max_age
    }

    /// Start a session. Returns the session id (for the cookie) and its CSRF
    /// token. Expired sessions are dropped first; at the cap the oldest goes.
    pub fn create(&mut self, now: Instant) -> Option<(Zeroizing<String>, Zeroizing<String>)> {
        let id = random_token()?;
        let csrf = random_token()?;

        let live: Vec<[u8; 32]> = self
            .sessions
            .iter()
            .filter(|(_, s)| self.is_live(s, now))
            .map(|(k, _)| *k)
            .collect();
        self.sessions.retain(|k, _| live.contains(k));
        while self.sessions.len() >= MAX_SESSIONS {
            let Some(oldest) = self
                .sessions
                .iter()
                .min_by_key(|(_, s)| s.seq)
                .map(|(k, _)| *k)
            else {
                break;
            };
            self.sessions.remove(&oldest);
        }

        self.next_seq += 1;
        self.sessions.insert(
            digest(&id),
            Session {
                seq: self.next_seq,
                created: now,
                authenticated_at: now,
                last_seen: now,
                csrf: csrf.clone(),
                form_ids: Vec::new(),
            },
        );
        Some((id, csrf))
    }

    /// Find the session for a cookie value and, if it is live, refresh its
    /// idle timer.
    pub fn lookup(&mut self, id: &str, now: Instant) -> Lookup {
        let key = digest(id);
        let Some(session) = self.sessions.get(&key) else {
            return Lookup::Missing;
        };
        if !self.is_live(session, now) {
            self.sessions.remove(&key);
            return Lookup::Expired;
        }
        let session = self.sessions.get_mut(&key).expect("checked above");
        session.last_seen = now;
        let expires_at = (now + self.idle).min(session.created + self.max_age);
        Lookup::Valid(SessionView {
            csrf: session.csrf.clone(),
            expires_at,
            authenticated_at: session.authenticated_at,
            handle: key,
        })
    }

    /// Issue a single-use form id for the session: 32 random bytes,
    /// base64url. At most [`MAX_FORM_IDS`] stay outstanding. `None` if the
    /// session is gone or the OS RNG fails.
    pub fn issue_form_id(&mut self, view: &SessionView) -> Option<Zeroizing<String>> {
        let id = random_token()?;
        let session = self.sessions.get_mut(&view.handle)?;
        while session.form_ids.len() >= MAX_FORM_IDS {
            session.form_ids.remove(0);
        }
        session.form_ids.push(digest(&id));
        Some(id)
    }

    /// Is this form id issued to the session and still unused? Does not use
    /// it up.
    pub fn form_id_valid(&self, view: &SessionView, id: &str) -> bool {
        let d = digest(id);
        self.sessions
            .get(&view.handle)
            .is_some_and(|s| s.form_ids.contains(&d))
    }

    /// Use a form id up. `true` exactly once per issued id: of two racing
    /// submissions only one gets `true`.
    pub fn consume_form_id(&mut self, view: &SessionView, id: &str) -> bool {
        let d = digest(id);
        let Some(session) = self.sessions.get_mut(&view.handle) else {
            return false;
        };
        match session.form_ids.iter().position(|x| *x == d) {
            Some(i) => {
                session.form_ids.remove(i);
                true
            }
            None => false,
        }
    }

    /// Put a form id back after a submission that created nothing (a
    /// validation error), so the form still on screen keeps working.
    pub fn restore_form_id(&mut self, view: &SessionView, id: &str) {
        let d = digest(id);
        if let Some(session) = self.sessions.get_mut(&view.handle) {
            if !session.form_ids.contains(&d) {
                while session.form_ids.len() >= MAX_FORM_IDS {
                    session.form_ids.remove(0);
                }
                session.form_ids.push(d);
            }
        }
    }

    pub fn destroy(&mut self, id: &str) -> bool {
        self.sessions.remove(&digest(id)).is_some()
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.sessions.len()
    }
}

// ── The pending sign-in ───────────────────────────────────────────────────────

/// A correct master password waiting for its second factor. The hash is what
/// the second token request needs to re-send; the password itself was wiped
/// right after the hash was derived.
#[derive(ZeroizeOnDrop)]
pub struct PendingLogin {
    auth_hash: Zeroizing<String>,
    #[zeroize(skip)]
    pub email: String,
    #[zeroize(skip)]
    pub providers: Vec<Provider>,
    #[zeroize(skip)]
    pub email_hint: Option<String>,
    #[zeroize(skip)]
    client_ip: IpAddr,
    #[zeroize(skip)]
    created: Instant,
    #[zeroize(skip)]
    attempts: u8,
    #[zeroize(skip)]
    last_email_sent: Option<Instant>,
    /// Where to go after the sign-in: already validated by
    /// `web::safe_next`, kept here (not in a URL) through the second step.
    #[zeroize(skip)]
    pub next: Option<String>,
}

impl PendingLogin {
    pub fn new(
        auth_hash: Zeroizing<String>,
        email: String,
        two_factor: TwoFactorRequired,
        client_ip: IpAddr,
        now: Instant,
    ) -> Self {
        Self {
            auth_hash,
            email,
            providers: two_factor.providers,
            email_hint: two_factor.email_hint,
            client_ip,
            created: now,
            attempts: 0,
            last_email_sent: None,
            next: None,
        }
    }

    /// Remember where the sign-in should end up.
    pub fn with_next(mut self, next: Option<String>) -> Self {
        self.next = next;
        self
    }

    pub fn offers(&self, provider: Provider) -> bool {
        self.providers.contains(&provider)
    }

    #[cfg(test)]
    pub fn attempts(&self) -> u8 {
        self.attempts
    }
}

/// What a request learns about the pending login it presented.
#[derive(Debug)]
pub enum PendingCheck {
    Ok,
    Missing,
    /// Presented from another IP than the password step: refused, kept.
    WrongIp,
    /// The TTL ran out; it was removed.
    Expired,
}

/// The single, global pending sign-in. A new password step replaces an older
/// one; Vaultwarden itself only tolerates one incomplete 2FA login per device.
#[derive(Default)]
pub struct PendingSlot {
    slot: Option<([u8; 32], PendingLogin)>,
}

impl PendingSlot {
    pub fn new() -> Self {
        Self::default()
    }

    /// Store a pending login, wiping any older one. Returns the id for the
    /// `__Host-fw_pending` cookie.
    pub fn set(&mut self, login: PendingLogin) -> Option<Zeroizing<String>> {
        let id = random_token()?;
        // Dropping the old value zeroizes it.
        self.slot = Some((digest(&id), login));
        Some(id)
    }

    fn expire(&mut self, now: Instant) -> bool {
        let expired = self
            .slot
            .as_ref()
            .is_some_and(|(_, p)| now.duration_since(p.created) >= PENDING_TTL);
        if expired {
            self.slot = None;
        }
        expired
    }

    /// Match the presented cookie value against the slot.
    fn check(&mut self, id: &str, ip: IpAddr, now: Instant) -> PendingCheck {
        if self.expire(now) {
            // Whoever asks next learns only that nothing is pending, unless
            // it was their cookie.
            return PendingCheck::Expired;
        }
        match &self.slot {
            Some((key, p)) if bool::from(key.ct_eq(&digest(id))) => {
                if p.client_ip == ip {
                    PendingCheck::Ok
                } else {
                    PendingCheck::WrongIp
                }
            }
            _ => PendingCheck::Missing,
        }
    }

    /// Read access for rendering the second-factor page.
    pub fn peek(
        &mut self,
        id: &str,
        ip: IpAddr,
        now: Instant,
    ) -> Result<&PendingLogin, PendingCheck> {
        match self.check(id, ip, now) {
            PendingCheck::Ok => Ok(&self.slot.as_ref().expect("checked").1),
            other => Err(other),
        }
    }

    /// Reserve one code attempt before the upstream call, so concurrent
    /// requests cannot exceed the limit. Returns the hash and email to send.
    /// `None` when the attempts are used up (the login is removed).
    pub fn begin_code_attempt(
        &mut self,
        id: &str,
        ip: IpAddr,
        now: Instant,
    ) -> Result<(Zeroizing<String>, String), PendingCheck> {
        match self.check(id, ip, now) {
            PendingCheck::Ok => {}
            other => return Err(other),
        }
        let p = &mut self.slot.as_mut().expect("checked").1;
        if p.attempts >= MAX_CODE_ATTEMPTS {
            self.slot = None;
            return Err(PendingCheck::Missing);
        }
        p.attempts += 1;
        Ok((p.auth_hash.clone(), p.email.clone()))
    }

    /// The reserved attempt did not reach a verdict (Vaultwarden was down or
    /// rate-limited): give it back. Does nothing if `id` is no longer the
    /// pending login (it was replaced meanwhile).
    pub fn refund_code_attempt(&mut self, id: &str) {
        if let Some((key, p)) = self.slot.as_mut() {
            if bool::from(key.ct_eq(&digest(id))) {
                p.attempts = p.attempts.saturating_sub(1);
            }
        }
    }

    /// A wrong code was counted. Removes (and zeroizes) the login when the
    /// attempts are used up; returns whether it did.
    pub fn code_rejected(&mut self, id: &str) -> bool {
        let used_up = self.slot.as_ref().is_some_and(|(key, p)| {
            bool::from(key.ct_eq(&digest(id))) && p.attempts >= MAX_CODE_ATTEMPTS
        });
        if used_up {
            self.slot = None;
        }
        used_up
    }

    /// May an email code be requested now? Reserves the slot (the 60 s
    /// interval starts) and returns the hash and email to send.
    pub fn begin_email_send(
        &mut self,
        id: &str,
        ip: IpAddr,
        now: Instant,
    ) -> Result<Option<(Zeroizing<String>, String)>, PendingCheck> {
        match self.check(id, ip, now) {
            PendingCheck::Ok => {}
            other => return Err(other),
        }
        let p = &mut self.slot.as_mut().expect("checked").1;
        if !p.offers(Provider::Email) {
            return Ok(None);
        }
        if p.last_email_sent
            .is_some_and(|t| now.duration_since(t) < EMAIL_RESEND_INTERVAL)
        {
            return Ok(None);
        }
        p.last_email_sent = Some(now);
        Ok(Some((p.auth_hash.clone(), p.email.clone())))
    }

    /// Remove and wipe the pending login (success, logout, abandonment).
    pub fn clear(&mut self) {
        self.slot = None;
    }

    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.slot.is_none()
    }
}

#[cfg(test)]
mod tests {
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
}
