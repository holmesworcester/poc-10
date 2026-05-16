//! Crate module map.
//!
//! This file is intentionally only a manifest. `main.rs` delegates to
//! `match_app`; `core` owns reusable mechanics; `event_modules` own fact
//! semantics; `handlers` own deferred intent effects. `legacy` is the contained
//! compatibility island kept only until the target `WakeLoop` path replaces the
//! old production CLI/daemon wiring.

pub mod commands;
pub mod core;
pub mod demo;
pub mod event_modules;
pub mod handlers;
pub mod legacy;
pub mod match_app;
pub mod protocol;
