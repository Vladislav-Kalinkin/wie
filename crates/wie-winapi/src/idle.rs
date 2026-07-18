//! Host idle / park policy (Phase 6).
//!
//! Clean-room design: park the host thread only on documented blocking waits
//! (`Sleep(n>0)`, empty `GetMessage` under `YieldOnIdle`). Never park pure
//! guest spin loops. Micros stay deterministic via [`IdlePolicy::Yield`] default.

use std::time::Duration;

/// How aggressively the host may sleep while the guest is waiting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum IdlePolicy {
    /// Never park: `Sleep(n>0)` is a no-op; empty message queue yields immediately.
    Busy,
    /// Cooperative only: `Sleep(0)` yields; `Sleep(n>0)` no-op; empty `GetMessage`
    /// returns [`crate::WinApiControlSignal::WaitingForMessage`] without sleeping.
    #[default]
    Yield,
    /// Park the host: `Sleep(n>0)` sleeps (capped); empty-message outer loop parks.
    Park,
}

/// Which runtime entry is requesting a default policy when `WIE_IDLE` is unset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdleContext {
    /// `run-micro` / regression — prefer fast deterministic runs.
    Micro,
    /// Persistent / interactive `run` — prefer low idle CPU.
    Persistent,
}

impl IdlePolicy {
    /// Parse `WIE_IDLE=busy|yield|park`. Unset → depends on [`IdleContext`].
    ///
    /// Legacy: `WIE_HOST_SLEEP=1` alone does **not** change the policy enum, but
    /// enables Sleep parking via [`Self::should_park_sleep`].
    #[must_use]
    pub fn from_env_for(ctx: IdleContext) -> Self {
        if let Some(p) = parse_wie_idle() {
            return p;
        }
        match ctx {
            IdleContext::Micro => Self::Yield,
            IdleContext::Persistent => Self::Park,
        }
    }

    /// Convenience: micro / library default (`WIE_IDLE` or Yield).
    #[must_use]
    pub fn from_env() -> Self {
        Self::from_env_for(IdleContext::Micro)
    }

    /// Short name for profiles / logs.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Busy => "busy",
            Self::Yield => "yield",
            Self::Park => "park",
        }
    }

    /// Whether `Sleep(milliseconds > 0)` should block the host thread.
    #[must_use]
    pub fn should_park_sleep(self) -> bool {
        matches!(self, Self::Park) || host_sleep_legacy_enabled()
    }

    /// Whether the outer run loop should sleep on empty `GetMessage`.
    #[must_use]
    pub fn should_park_message(self) -> bool {
        matches!(self, Self::Park)
    }
}

/// Hard cap for a single `Sleep` park (ms). Default 60_000.
#[must_use]
pub fn idle_sleep_cap_ms() -> u64 {
    parse_u64_env("WIE_IDLE_CAP_MS").unwrap_or(60_000).max(1)
}

/// Quantum for one empty-message park (ms). Default 25.
#[must_use]
pub fn idle_message_park_ms() -> u64 {
    parse_u64_env("WIE_IDLE_PARK_MS").unwrap_or(25).max(1)
}

/// Optional sleep between CPU slices when policy is Park (ms). Default 0 = off.
#[must_use]
pub fn idle_slice_ms() -> u64 {
    parse_u64_env("WIE_IDLE_SLICE_MS").unwrap_or(0)
}

/// Max empty-message park quanta in one persistent run before yielding to the CLI.
/// `0` = unlimited. Default 40 (~1 s at 25 ms).
#[must_use]
pub fn idle_max_message_parks() -> u32 {
    parse_u64_env("WIE_IDLE_MAX_PARKS").map_or(40, |v| u32::try_from(v).unwrap_or(u32::MAX))
}

/// Duration for `Sleep(requested_ms)` under park policy (after cap).
#[must_use]
pub fn sleep_park_duration(requested_ms: u64) -> Duration {
    let ms = requested_ms.min(idle_sleep_cap_ms());
    Duration::from_millis(ms)
}

/// Duration for one empty-message park quantum.
#[must_use]
pub fn message_park_duration() -> Duration {
    Duration::from_millis(idle_message_park_ms())
}

/// Park the host thread for a Sleep request when policy allows.
///
/// - `0` ms → always `yield_now` (cooperative).
/// - `n > 0` → `thread::sleep` only if [`IdlePolicy::should_park_sleep`].
pub fn apply_sleep(policy: IdlePolicy, milliseconds: u64) {
    if milliseconds == 0 {
        std::thread::yield_now();
        return;
    }
    if policy.should_park_sleep() {
        std::thread::sleep(sleep_park_duration(milliseconds));
    }
}

/// Park once for an empty message queue (caller re-enters `GetMessage`).
pub fn apply_message_park() {
    std::thread::sleep(message_park_duration());
}

fn parse_wie_idle() -> Option<IdlePolicy> {
    let v = std::env::var("WIE_IDLE").ok()?;
    if v.eq_ignore_ascii_case("busy") || v == "0" || v.eq_ignore_ascii_case("off") {
        Some(IdlePolicy::Busy)
    } else if v.eq_ignore_ascii_case("park") || v == "1" || v.eq_ignore_ascii_case("true") {
        Some(IdlePolicy::Park)
    } else if v.eq_ignore_ascii_case("yield") {
        Some(IdlePolicy::Yield)
    } else {
        None
    }
}

/// Legacy `WIE_HOST_SLEEP=1` — enables Sleep parking only.
fn host_sleep_legacy_enabled() -> bool {
    std::env::var_os("WIE_HOST_SLEEP").is_some_and(|v| v == "1" || v.eq_ignore_ascii_case("true"))
}

fn parse_u64_env(name: &str) -> Option<u64> {
    std::env::var(name).ok()?.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    #[test]
    fn sleep_zero_does_not_sleep_long() {
        let start = Instant::now();
        apply_sleep(IdlePolicy::Park, 0);
        assert!(start.elapsed() < Duration::from_millis(50));
    }

    #[test]
    fn sleep_nonzero_noop_under_yield() {
        let start = Instant::now();
        apply_sleep(IdlePolicy::Yield, 200);
        assert!(
            start.elapsed() < Duration::from_millis(50),
            "Sleep under Yield must not park"
        );
    }

    #[test]
    fn sleep_nonzero_noop_under_busy() {
        let start = Instant::now();
        apply_sleep(IdlePolicy::Busy, 200);
        assert!(start.elapsed() < Duration::from_millis(50));
    }

    #[test]
    fn sleep_parks_under_park_policy() {
        let start = Instant::now();
        apply_sleep(IdlePolicy::Park, 40);
        let elapsed = start.elapsed();
        assert!(
            elapsed >= Duration::from_millis(30),
            "expected ~40ms park, got {elapsed:?}"
        );
        assert!(
            elapsed < Duration::from_millis(500),
            "park took too long: {elapsed:?}"
        );
    }

    #[test]
    fn sleep_park_duration_respects_cap_helper() {
        let d = sleep_park_duration(u64::MAX);
        assert!(d <= Duration::from_millis(idle_sleep_cap_ms()));
    }

    #[test]
    fn policy_as_str() {
        assert_eq!(IdlePolicy::Busy.as_str(), "busy");
        assert_eq!(IdlePolicy::Yield.as_str(), "yield");
        assert_eq!(IdlePolicy::Park.as_str(), "park");
    }

    #[test]
    fn should_park_flags() {
        assert!(!IdlePolicy::Yield.should_park_sleep());
        assert!(!IdlePolicy::Busy.should_park_sleep());
        assert!(IdlePolicy::Park.should_park_sleep());
        assert!(!IdlePolicy::Yield.should_park_message());
        assert!(IdlePolicy::Park.should_park_message());
    }
}
