//! Crate module map.
//!
//! This file is intentionally only a manifest. `main.rs` delegates to
//! `match_app`; `core` owns reusable mechanics; `event_modules` own fact
//! semantics; `handlers` own deferred intent effects.

pub mod core;
#[path = "event_modules/registry.rs"]
pub mod event_modules;
#[path = "handlers/registry.rs"]
pub mod handlers;
pub mod match_app;
#[cfg(test)]
pub mod projector_experiment;
pub mod protocol;
