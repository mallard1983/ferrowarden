//! Process hardening for the native backend, which keeps the vault's keys in
//! this process's memory.
//!
//! On Linux, best effort and each reported separately:
//! - `PR_SET_DUMPABLE = 0`: the process cannot be ptraced by an unprivileged
//!   process and does not produce a core dump.
//! - `RLIMIT_CORE = 0`: no core file, whatever the system's core pattern says.
//!
//! `mlock` of the key pages is deliberately not done: keys live in many small
//! heap allocations (`Zeroizing` buffers), so locking them would need a
//! dedicated locked arena (an extra crate and allocator discipline) for a
//! small gain over disabling swap for the container (docs/security.md). On
//! other platforms nothing is done.

/// Apply the hardening. Returns the steps that failed (empty on success).
#[cfg(target_os = "linux")]
pub fn apply() -> Vec<&'static str> {
    let mut failed = Vec::new();
    // SAFETY: both calls only read the arguments they are given; no pointer
    // other than to a local `rlimit` is passed.
    unsafe {
        if libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) != 0 {
            failed.push("PR_SET_DUMPABLE");
        }
        let zero = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        if libc::setrlimit(libc::RLIMIT_CORE, &zero) != 0 {
            failed.push("RLIMIT_CORE");
        }
    }
    failed
}

#[cfg(not(target_os = "linux"))]
pub fn apply() -> Vec<&'static str> {
    Vec::new()
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    #[test]
    fn hardening_applies_and_is_observable() {
        // Run in a child-safe way: this changes the test process itself,
        // which is harmless (no core dumps for the test run).
        assert!(super::apply().is_empty());
        // SAFETY: reading the flag takes no pointers.
        let dumpable = unsafe { libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) };
        assert_eq!(dumpable, 0);
    }
}
