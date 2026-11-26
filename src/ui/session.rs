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
mod tests;
