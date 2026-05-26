//! Lightweight env-gated profiling helpers.
//!
//! This module is intentionally protocol-neutral. It gives command hosts a
//! thread-local place to accumulate coarse phase timings while preserving the
//! normal stdout/stderr contract unless a caller explicitly enables profiling.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::time::{Duration, Instant};

const GENERATE_PROFILE_ENV: &str = "TOPO_PROFILE_GENERATE";

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
    if !is_generate_profile_active() {
        return work();
    }
    let started = Instant::now();
    let output = work();
    add_duration(phase, started.elapsed());
    output
}

pub fn measure_result<T, E>(
    phase: &'static str,
    work: impl FnOnce() -> Result<T, E>,
) -> Result<T, E> {
    if !is_generate_profile_active() {
        return work();
    }
    let started = Instant::now();
    let output = work();
    add_duration(phase, started.elapsed());
    output
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_profile_measure_is_noop_without_active_profile() {
        let value = measure("phase", || 42);
        assert_eq!(value, 42);
        assert!(!is_generate_profile_active());
    }
}
