//! `sync_window` event module.
//!
//! Per-workspace range/window selector keyed `(connection_id, workspace_id)`.
//! Wire-only: not signed and not durable; the surrounding connection
//! authenticates the message, and sync jobs choose which windows to
//! request.
//!
//! Translated from poc-6 `events/network/sync_window.py` per `plan.md`
//! lines 204-218.

pub mod event;
pub mod projector;
pub mod registry_meta;
pub mod codec;

pub use event::{SyncWindowEvent, SyncWindowKind, SYNC_WINDOW_TYPE_CODE};
pub use projector::project;
pub use registry_meta::{project_pure, SYNC_WINDOW_META};
pub use codec::{encode, parse, SyncWindowWireError, SYNC_WINDOW_WIRE_SIZE};
