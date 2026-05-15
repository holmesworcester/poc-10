//! Deferred intent handlers.
//!
//! Concrete handlers should appear here only when they own bounded stateful
//! effects. Projection-owned row materialization stays under event modules.

pub mod connection;
pub mod materialize_key_wraps;
pub mod purge_event;
pub mod transit;
pub mod unwrap_key_wrap;
