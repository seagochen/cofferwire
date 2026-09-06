//! A minimal, deterministic per-key request-rate abuse control.
//!
//! See `docs/spec/11-security-considerations.md`. This bounds request rate over
//! time, which is a different property from the existing concurrent-
//! connection/concurrent-command semaphores (`ConnectionLimit`,
//! `MAX_CONCURRENT_COMMANDS`): those bound how many requests are in flight
//! at once, this bounds how many a given key may make per rolling window.
//! It is driven entirely by a caller-supplied relay-time value, not the wall
//! clock, so it is deterministically testable through the same
//! `exchange_frame_at`/`exchange_blob_frame_at` entry points used for
//! conformance.

use std::collections::{HashMap, VecDeque};
use std::hash::Hash;
use std::sync::Mutex;

/// Bounds requests per key to `max_requests` within a rolling `window_secs`
/// window, and bounds total distinct tracked keys to `max_tracked_keys` so
/// a flood of one-off keys cannot grow memory without bound.
#[derive(Debug)]
pub struct RateLimiter<K> {
    window_secs: u64,
    max_requests: usize,
    max_tracked_keys: usize,
    windows: Mutex<HashMap<K, VecDeque<u64>>>,
}

impl<K: Eq + Hash + Clone> RateLimiter<K> {
    /// Constructs a limiter with the given window, per-key budget, and
    /// tracked-key capacity.
    #[must_use]
    pub fn new(window_secs: u64, max_requests: usize, max_tracked_keys: usize) -> Self {
        Self {
            window_secs,
            max_requests,
            max_tracked_keys,
            windows: Mutex::new(HashMap::new()),
        }
    }

    /// Returns whether a request under `key` at `now_secs` is admitted.
    ///
    /// Fails closed (rejects) if the internal lock is poisoned by a prior
    /// panic, rather than silently recovering a possibly-inconsistent
    /// count.
    pub fn admit(&self, key: K, now_secs: u64) -> bool {
        let Ok(mut windows) = self.windows.lock() else {
            return false;
        };
        if let Some(entries) = windows.get_mut(&key) {
            while entries
                .front()
                .is_some_and(|&oldest| oldest + self.window_secs <= now_secs)
            {
                entries.pop_front();
            }
            if entries.len() >= self.max_requests {
                return false;
            }
            entries.push_back(now_secs);
            return true;
        }
        if windows.len() >= self.max_tracked_keys {
            // A brand-new key when already at capacity is rejected rather
            // than admitted, so a flood of distinct keys cannot bypass the
            // tracked-key bound by always looking "fresh".
            return false;
        }
        let mut entries = VecDeque::with_capacity(1);
        entries.push_back(now_secs);
        windows.insert(key, entries);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::RateLimiter;

    #[test]
    fn admits_up_to_the_limit_then_rejects_within_the_window() {
        let limiter = RateLimiter::new(60, 3, 100);
        assert!(limiter.admit("a", 1_000));
        assert!(limiter.admit("a", 1_010));
        assert!(limiter.admit("a", 1_020));
        assert!(
            !limiter.admit("a", 1_030),
            "fourth request within the window is rejected"
        );
    }

    #[test]
    fn window_rolls_forward_and_readmits() {
        let limiter = RateLimiter::new(60, 2, 100);
        assert!(limiter.admit("a", 1_000));
        assert!(limiter.admit("a", 1_010));
        assert!(!limiter.admit("a", 1_020));
        // The first request (t=1000) falls out of the window once now
        // reaches 1000 + 60 = 1060.
        assert!(limiter.admit("a", 1_060));
    }

    #[test]
    fn distinct_keys_are_tracked_independently() {
        let limiter = RateLimiter::new(60, 1, 100);
        assert!(limiter.admit("a", 1_000));
        assert!(!limiter.admit("a", 1_000));
        assert!(
            limiter.admit("b", 1_000),
            "a different key has its own budget"
        );
    }

    #[test]
    fn tracked_key_capacity_fails_closed_for_new_keys() {
        let limiter = RateLimiter::new(60, 10, 2);
        assert!(limiter.admit("a", 1_000));
        assert!(limiter.admit("b", 1_000));
        assert!(
            !limiter.admit("c", 1_000),
            "a third distinct key is rejected once tracked-key capacity is reached"
        );
        // Existing tracked keys remain usable.
        assert!(limiter.admit("a", 1_001));
    }
}
