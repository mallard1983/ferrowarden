
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
