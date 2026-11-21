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
mod tests {
    use super::*;

    fn ip(n: u8) -> IpAddr {
        IpAddr::from([10, 0, 0, n])
    }

    fn secs(s: u64) -> Duration {
        Duration::from_secs(s)
    }

    #[test]
    fn five_failures_lock_the_ip_for_fifteen_minutes() {
        let t0 = Instant::now();
        let mut l = Lockouts::new();
        for i in 0..4 {
            assert!(l.check_password(ip(1), t0 + secs(i)).is_ok());
            l.record_failure(ip(1), t0 + secs(i));
        }
        assert!(l.check_password(ip(1), t0 + secs(5)).is_ok());
        l.record_failure(ip(1), t0 + secs(5));
        // The 5th failure locked it.
        assert_eq!(l.check_password(ip(1), t0 + secs(6)), Err(LockedBy::Ip));
        assert_eq!(l.check_code(ip(1), t0 + secs(6)), Err(LockedBy::Ip));
        // Other IPs are not affected.
        assert!(l.check_password(ip(2), t0 + secs(6)).is_ok());
        // Still locked just before the end, free right after.
        assert_eq!(
            l.check_password(ip(1), t0 + secs(5) + LOCK_DURATION - secs(1)),
            Err(LockedBy::Ip)
        );
        assert!(l
            .check_password(ip(1), t0 + secs(5) + LOCK_DURATION)
            .is_ok());
    }

    #[test]
    fn failures_outside_the_window_do_not_add_up() {
        let t0 = Instant::now();
        let mut l = Lockouts::new();
        for i in 0..4 {
            l.record_failure(ip(1), t0 + secs(i));
        }
        // The first four are older than 15 minutes by now.
        let later = t0 + WINDOW + secs(10);
        l.record_failure(ip(1), later);
        assert!(l.check_password(ip(1), later).is_ok());
    }

    #[test]
    fn a_finished_lockout_starts_clean() {
        let t0 = Instant::now();
        let mut l = Lockouts::new();
        for _ in 0..5 {
            l.record_failure(ip(1), t0);
        }
        let after = t0 + LOCK_DURATION + secs(1);
        assert!(l.check_password(ip(1), after).is_ok());
        // One new failure is not an immediate relock.
        l.record_failure(ip(1), after);
        assert!(l.check_password(ip(1), after).is_ok());
    }

    #[test]
    fn ten_failures_across_ips_lock_every_password_submission() {
        let t0 = Instant::now();
        let mut l = Lockouts::new();
        for i in 0..10u8 {
            // Two failures each from five different IPs: no single IP locks.
            l.record_failure(ip(i / 2 + 1), t0 + secs(u64::from(i)));
        }
        assert_eq!(
            l.check_password(ip(99), t0 + secs(11)),
            Err(LockedBy::Global)
        );
        // A code for an existing pending login is still allowed ...
        assert!(l.check_code(ip(99), t0 + secs(11)).is_ok());
        // ... and a successful sign-in elsewhere does not lift the lock.
        l.record_success(ip(1));
        assert_eq!(
            l.check_password(ip(99), t0 + secs(12)),
            Err(LockedBy::Global)
        );
        assert!(l
            .check_password(ip(99), t0 + secs(9) + LOCK_DURATION)
            .is_ok());
    }

    #[test]
    fn code_failures_count_against_both_limits() {
        let t0 = Instant::now();
        let mut l = Lockouts::new();
        // 5 wrong codes from one IP lock that IP ...
        for i in 0..5 {
            assert!(l.check_code(ip(1), t0 + secs(i)).is_ok());
            l.record_failure(ip(1), t0 + secs(i));
        }
        assert_eq!(l.check_code(ip(1), t0 + secs(6)), Err(LockedBy::Ip));
        // ... and count towards the global limit of 10.
        for i in 0..5 {
            l.record_failure(ip(2), t0 + secs(10 + i));
        }
        assert_eq!(
            l.check_password(ip(3), t0 + secs(20)),
            Err(LockedBy::Global)
        );
    }

    #[test]
    fn locked_out_requests_do_not_extend_the_lock() {
        let t0 = Instant::now();
        let mut l = Lockouts::new();
        for _ in 0..5 {
            l.record_failure(ip(1), t0);
        }
        // Refused attempts are not recorded (the caller only records failures
        // of attempts that were allowed), so the lock ends on schedule.
        for i in 1..100 {
            assert!(l.check_password(ip(1), t0 + secs(i)).is_err());
        }
        assert!(l.check_password(ip(1), t0 + LOCK_DURATION).is_ok());
    }

    #[test]
    fn success_clears_the_ip_failures() {
        let t0 = Instant::now();
        let mut l = Lockouts::new();
        for _ in 0..4 {
            l.record_failure(ip(1), t0);
        }
        l.record_success(ip(1));
        l.record_failure(ip(1), t0 + secs(1));
        assert!(l.check_password(ip(1), t0 + secs(2)).is_ok());
    }

    #[test]
    fn expired_entries_are_pruned() {
        let t0 = Instant::now();
        let mut l = Lockouts::new();
        for n in 0..50 {
            l.record_failure(ip(n), t0);
        }
        assert_eq!(l.tracked_ips(), 50);
        let later = t0 + WINDOW + secs(1);
        assert!(l.check_password(ip(200), later).is_ok());
        assert_eq!(l.tracked_ips(), 0);
    }

    #[test]
    fn the_ip_table_is_capped() {
        let t0 = Instant::now();
        let mut l = Lockouts::new();
        // More distinct IPs than the cap, one failure each (the global limit
        // does not stop recording, only submissions).
        for n in 0..(MAX_TRACKED_IPS as u32 + 500) {
            let addr = IpAddr::from([10, (n >> 16) as u8, (n >> 8) as u8, n as u8]);
            l.record_failure(addr, t0 + Duration::from_millis(u64::from(n)));
            assert!(l.tracked_ips() <= MAX_TRACKED_IPS);
        }
        assert_eq!(l.tracked_ips(), MAX_TRACKED_IPS);
    }
}
