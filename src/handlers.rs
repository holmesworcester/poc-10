//! Deferred intent handlers.
//!
//! Concrete handlers should appear here only when they own bounded stateful
//! effects. Projection-owned row materialization stays under event modules.

pub mod connection;
pub mod handle_sync;
pub mod materialize_key_wraps;
pub mod purge_event;
pub mod purge_retired_recipient_material;
pub mod receive_transit;
pub mod sync_index_update;
pub mod transit;
pub mod unwrap_key_wrap;
