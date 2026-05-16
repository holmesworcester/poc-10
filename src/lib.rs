//! Crate module map.
//!
//! This file is intentionally only a manifest. `main.rs` delegates to
//! `match_app`; `core` owns reusable mechanics; `protocol` owns the concrete
//! fact modules, matchers, and intent handlers.

pub mod core;
pub mod match_app;
pub mod protocol;
