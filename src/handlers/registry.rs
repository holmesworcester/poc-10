//! Deferred intent handlers.
//!
//! Concrete handlers should appear here only when they own bounded stateful
//! effects. Projection-owned row materialization stays under event modules.

pub mod connection;
pub mod connection_response;
pub mod handle_sync;
pub mod materialize_key_wraps;
pub mod network_send;
pub mod purge_cascade;
pub mod purge_event;
pub mod purge_retired_recipient_material;
pub mod receive_transit;
pub mod retention_expiry;
pub mod retention_floor;
pub mod sync_index_update;
pub mod transit;
pub mod unwrap_key_wrap;
