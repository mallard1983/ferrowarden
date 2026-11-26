//! Brute-force protection on the Ferrowarden side.
//!
//! Vaultwarden allows a burst of 10 logins per IP, and every attempt
//! Ferrowarden makes comes from one container IP, so an attacker could spend
//! that whole budget and lock the real operator out. Ferrowarden therefore
//! stops attackers first:
//!
//! * **per client IP**: 5 failures (wrong password or wrong second-factor
//!   code) within 15 minutes lock that IP for 15 minutes;
//! * **global**: 10 failures within 15 minutes across all IPs refuse every
//!   password submission for 15 minutes.
//!
//! The checks run before any key derivation or upstream call. Time is passed
//! in, so the rules are tested without sleeping. The per-IP table is pruned on
//! every use and capped.

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::time::{Duration, Instant};

pub const WINDOW: Duration = Duration::from_secs(15 * 60);
pub const LOCK_DURATION: Duration = Duration::from_secs(15 * 60);
pub const IP_FAILURE_LIMIT: usize = 5;
pub const GLOBAL_FAILURE_LIMIT: usize = 10;
/// Most client IPs tracked at once. When full, the entry with the oldest
/// failure is dropped to make room.
pub const MAX_TRACKED_IPS: usize = 1024;

/// Which limit refused a request (recorded in the event, never shown).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockedBy {
    Ip,
    Global,
}

impl LockedBy {
    pub fn as_str(self) -> &'static str {
        match self {
            LockedBy::Ip => "ip",
            LockedBy::Global => "global",
        }
    }
}

#[derive(Default)]
struct IpRecord {
    failures: VecDeque<Instant>,
    locked_until: Option<Instant>,
}

impl IpRecord {
    fn prune(&mut self, now: Instant) {
        while self
            .failures
            .front()
            .is_some_and(|t| now.duration_since(*t) >= WINDOW)
        {
            self.failures.pop_front();
        }
        if self.locked_until.is_some_and(|t| now >= t) {
            self.locked_until = None;
            // A finished lockout starts from a clean slate.
            self.failures.clear();
        }
    }

    fn is_idle(&self) -> bool {
        self.failures.is_empty() && self.locked_until.is_none()
    }
}

#[derive(Default)]
pub struct Lockouts {
    per_ip: HashMap<IpAddr, IpRecord>,
    global_failures: VecDeque<Instant>,
    global_locked_until: Option<Instant>,
}

impl Lockouts {
    pub fn new() -> Self {
        Self::default()
    }

    fn prune(&mut self, now: Instant) {
        self.per_ip.retain(|_, r| {
            r.prune(now);
            !r.is_idle()
        });
        while self
            .global_failures
            .front()
            .is_some_and(|t| now.duration_since(*t) >= WINDOW)
        {
            self.global_failures.pop_front();
        }
        if self.global_locked_until.is_some_and(|t| now >= t) {
            self.global_locked_until = None;
            self.global_failures.clear();
        }
    }

    /// May this IP submit a password? Both limits apply.
    pub fn check_password(&mut self, ip: IpAddr, now: Instant) -> Result<(), LockedBy> {
        self.prune(now);
        if self.global_locked_until.is_some() {
            return Err(LockedBy::Global);
        }
        self.check_ip(ip)
    }

    /// May this IP submit a second-factor code for a pending login? Only the
    /// per-IP limit applies: the password was already right, and a global
    /// lockout must not strand the operator halfway through a sign-in. The
    /// failures still count against both limits.
    pub fn check_code(&mut self, ip: IpAddr, now: Instant) -> Result<(), LockedBy> {
        self.prune(now);
        self.check_ip(ip)
    }

    fn check_ip(&self, ip: IpAddr) -> Result<(), LockedBy> {
        if self
            .per_ip
            .get(&ip)
            .is_some_and(|r| r.locked_until.is_some())
        {
            Err(LockedBy::Ip)
        } else {
            Ok(())
        }
    }

    /// Count a wrong password or wrong code.
    pub fn record_failure(&mut self, ip: IpAddr, now: Instant) {
        self.prune(now);

        if !self.per_ip.contains_key(&ip) && self.per_ip.len() >= MAX_TRACKED_IPS {
            // Make room: drop the entry whose latest failure is the oldest.
            if let Some(oldest) = self
                .per_ip
                .iter()
                .min_by_key(|(_, r)| r.failures.back().copied())
                .map(|(ip, _)| *ip)
            {
                self.per_ip.remove(&oldest);
            }
        }
        let record = self.per_ip.entry(ip).or_default();
        record.failures.push_back(now);
        if record.failures.len() >= IP_FAILURE_LIMIT && record.locked_until.is_none() {
            record.locked_until = Some(now + LOCK_DURATION);
        }

        self.global_failures.push_back(now);
        if self.global_failures.len() >= GLOBAL_FAILURE_LIMIT && self.global_locked_until.is_none()
        {
            self.global_locked_until = Some(now + LOCK_DURATION);
        }
    }

    /// A correct sign-in clears the failures of that IP (not the global ones).
    pub fn record_success(&mut self, ip: IpAddr) {
        self.per_ip.remove(&ip);
    }

    #[cfg(test)]
    fn tracked_ips(&self) -> usize {
        self.per_ip.len()
    }
}

#[cfg(test)]
mod tests;
