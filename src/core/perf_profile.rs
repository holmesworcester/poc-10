//! Lightweight env-gated profiling helpers.
//!
//! This module is intentionally protocol-neutral. It gives command hosts a
//! thread-local place to accumulate coarse phase timings while preserving the
//! normal stdout/stderr contract unless a caller explicitly enables profiling.
//! The current profile surface is scoped to `generate`, where we need to see
//! the relative cost of fact creation, projection, handler dispatch, and sync
//! indexing without adding protocol-visible state.
//!
//! Profiling state is process-local and best-effort. It is not stored in
//! SQLite, not synced, and not part of command semantics. A disabled profile is
//! a no-op; an enabled profile emits diagnostic timing lines only at the command
//! edge.
//!
//! Add helpers here only for reusable runtime timing mechanics. If a metric
//! depends on message meaning, sync visibility, key policy, or other protocol
//! semantics, collect it in the owning protocol module and keep this facade
//! mechanical.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

const GENERATE_PROFILE_ENV: &str = "TOPO_PROFILE_GENERATE";
const RUNTIME_PROFILE_ENV: &str = "TOPO_PROFILE_RUNTIME_PHASES";

thread_local! {
    static ACTIVE_GENERATE_PROFILE: RefCell<Option<GenerateProfileState>> = const { RefCell::new(None) };
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct PhaseStats {
    calls: u64,
    duration: Duration,
}

#[derive(Debug)]
struct GenerateProfileState {
    started: Instant,
    requested_count: usize,
    requested_message_text_bytes: usize,
    generated_facts: Option<usize>,
    message_text_bytes: Option<usize>,
    phases: BTreeMap<&'static str, PhaseStats>,
}

#[derive(Debug, Default)]
struct RuntimeProfileState {
    started: Option<Instant>,
    phases: BTreeMap<&'static str, PhaseStats>,
}

/// Guard for one profiled `generate` command.
pub struct GenerateProfile {
    active: bool,
    finished: bool,
}

impl GenerateProfile {
    pub fn start(requested_count: usize, requested_message_text_bytes: usize) -> Self {
        if !generate_profile_enabled() {
            return Self {
                active: false,
                finished: true,
            };
        }

        ACTIVE_GENERATE_PROFILE.with(|slot| {
            *slot.borrow_mut() = Some(GenerateProfileState {
                started: Instant::now(),
                requested_count,
                requested_message_text_bytes,
                generated_facts: None,
                message_text_bytes: None,
                phases: BTreeMap::new(),
            });
        });
        Self {
            active: true,
            finished: false,
        }
    }

    pub fn finish_success(&mut self, generated_facts: usize, message_text_bytes: usize) {
        if !self.active || self.finished {
            return;
        }
        ACTIVE_GENERATE_PROFILE.with(|slot| {
            if let Some(state) = slot.borrow_mut().as_mut() {
                state.generated_facts = Some(generated_facts);
                state.message_text_bytes = Some(message_text_bytes);
            }
        });
        finish_generate_profile("ok");
        self.finished = true;
    }
}

impl Drop for GenerateProfile {
    fn drop(&mut self) {
        if self.active && !self.finished {
            finish_generate_profile("error");
            self.finished = true;
        }
    }
}

pub fn add_duration(phase: &'static str, duration: Duration) {
    ACTIVE_GENERATE_PROFILE.with(|slot| {
        if let Some(state) = slot.borrow_mut().as_mut() {
            let stats = state.phases.entry(phase).or_default();
            stats.calls = stats.calls.saturating_add(1);
            stats.duration += duration;
        }
    });
}

pub fn measure<T>(phase: &'static str, work: impl FnOnce() -> T) -> T {
    let generate_active = is_generate_profile_active();
    let runtime_active = runtime_profile_state().is_some();
    if !generate_active && !runtime_active {
        return work();
    }
    let started = Instant::now();
    let output = work();
    let elapsed = started.elapsed();
    if generate_active {
        add_duration(phase, elapsed);
    }
    if runtime_active {
        add_runtime_duration(phase, elapsed);
    }
    output
}

pub fn measure_result<T, E>(
    phase: &'static str,
    work: impl FnOnce() -> Result<T, E>,
) -> Result<T, E> {
    measure(phase, work)
}

fn generate_profile_enabled() -> bool {
    std::env::var(GENERATE_PROFILE_ENV)
        .ok()
        .map(|value| {
            let normalized = value.trim().to_ascii_lowercase();
            !(normalized.is_empty() || normalized == "0" || normalized == "false")
        })
        .unwrap_or(false)
}

fn runtime_profile_state() -> Option<&'static Mutex<RuntimeProfileState>> {
    static STATE: OnceLock<Option<Mutex<RuntimeProfileState>>> = OnceLock::new();
    STATE
        .get_or_init(|| {
            runtime_profile_enabled().then(|| Mutex::new(RuntimeProfileState::default()))
        })
        .as_ref()
}

fn runtime_profile_enabled() -> bool {
    std::env::var(RUNTIME_PROFILE_ENV)
        .ok()
        .map(|value| {
            let normalized = value.trim().to_ascii_lowercase();
            !(normalized.is_empty() || normalized == "0" || normalized == "false")
        })
        .unwrap_or(false)
}

fn add_runtime_duration(phase: &'static str, duration: Duration) {
    let Some(state) = runtime_profile_state() else {
        return;
    };
    let mut state = state.lock().expect("runtime profile lock");
    if state.started.is_none() {
        state.started = Some(Instant::now());
    }
    let stats = state.phases.entry(phase).or_default();
    stats.calls = stats.calls.saturating_add(1);
    stats.duration += duration;
}

pub fn emit_runtime_profile(label: &str) {
    if let Some(line) = finish_runtime_profile_line(label) {
        eprintln!("{line}");
    }
}

fn finish_runtime_profile_line(label: &str) -> Option<String> {
    let state = runtime_profile_state()?;
    let mut state = state.lock().expect("runtime profile lock");
    let line = runtime_profile_line(label, &state)?;
    state.started = None;
    state.phases.clear();
    Some(line)
}

fn runtime_profile_line(label: &str, state: &RuntimeProfileState) -> Option<String> {
    let started = state.started?;
    if state.phases.is_empty() {
        return None;
    }
    let mut line = format!(
        "runtime_profile label={} total_ms={}",
        sanitize_label(label),
        millis(started.elapsed())
    );
    for (phase, stats) in &state.phases {
        line.push_str(&format!(
            " {phase}_ms={} {phase}_calls={}",
            millis(stats.duration),
            stats.calls
        ));
    }
    Some(line)
}

fn sanitize_label(label: &str) -> String {
    label.replace(char::is_whitespace, "_")
}

fn is_generate_profile_active() -> bool {
    ACTIVE_GENERATE_PROFILE.with(|slot| slot.borrow().is_some())
}

fn finish_generate_profile(status: &str) {
    let Some(state) = ACTIVE_GENERATE_PROFILE.with(|slot| slot.borrow_mut().take()) else {
        return;
    };
    let mut line = format!(
        "generate_profile status={} requested_count={} requested_message_text_bytes={} generated_facts={} message_text_bytes={} total_ms={}",
        status,
        state.requested_count,
        state.requested_message_text_bytes,
        optional_usize(state.generated_facts),
        optional_usize(state.message_text_bytes),
        millis(state.started.elapsed())
    );
    for (phase, stats) in state.phases {
        line.push_str(&format!(
            " {phase}_ms={} {phase}_calls={}",
            millis(stats.duration),
            stats.calls
        ));
    }
    eprintln!("{line}");
}

fn optional_usize(value: Option<usize>) -> String {
    value
        .map(|value| value.to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

fn millis(duration: Duration) -> u128 {
    duration.as_micros() / 1000
}

// Tests.
// Ordered most-central-first: full profile-line formatting before no-op guards.
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_profile_line_reports_phase_stats() {
        let state = RuntimeProfileState {
            started: Some(Instant::now() - Duration::from_millis(10)),
            phases: BTreeMap::from([
                (
                    "phase_a",
                    PhaseStats {
                        calls: 2,
                        duration: Duration::from_millis(7),
                    },
                ),
                (
                    "phase_b",
                    PhaseStats {
                        calls: 1,
                        duration: Duration::from_millis(3),
                    },
                ),
            ]),
        };

        let line = runtime_profile_line("daemon addr", &state).expect("profile line");

        assert!(line.starts_with("runtime_profile label=daemon_addr total_ms="));
        assert!(line.contains(" phase_a_ms=7 phase_a_calls=2"));
        assert!(line.contains(" phase_b_ms=3 phase_b_calls=1"));
    }

    #[test]
    fn generate_profile_measure_is_noop_without_active_profile() {
        let value = measure("phase", || 42);
        assert_eq!(value, 42);
        assert!(!is_generate_profile_active());
    }

    #[test]
    fn generate_profile_measure_result_preserves_inactive_output() {
        assert_eq!(measure_result("phase", || Ok::<_, &str>(42)), Ok(42));
        assert_eq!(
            measure_result("phase", || Err::<u8, _>("failed")),
            Err("failed")
        );
        assert!(!is_generate_profile_active());
    }
}
