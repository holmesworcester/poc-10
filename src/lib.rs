//! Crate module map.
//!
//! This file is intentionally only a manifest. `main.rs` delegates to
//! `context_app`; `core` owns reusable mechanics; `protocol` owns the concrete
//! fact modules, context ranges, and intent handlers.

#[cfg(verus_keep_ghost)]
use vstd::prelude::*;

pub mod context_app;
pub mod core;
pub mod protocol;
