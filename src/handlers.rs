//! Deferred intent handlers.
//!
//! Concrete handlers should appear here only when they own bounded stateful
//! effects. Projection-owned row materialization stays under event modules.

pub mod connection;
pub mod deferred_effects;
pub mod materialize_key_wraps;
pub mod transit;
