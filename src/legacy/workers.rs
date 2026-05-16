//! Legacy daemon worker catalog.
//!
//! New architecture code should not add workers. Existing workers are kept only
//! to preserve the poc-8 production path until each responsibility has a target
//! owner: projectors plus `WakeLoop` for admission/projection, context
//! matchers for wake decisions, and flat `src/handlers/*.rs` files for bounded
//! deferred effects. The end state deletes this module and `src/legacy/workers/`.

pub mod connection;
pub mod content_purge;
pub mod dependency_unblock;
pub mod disappearing_floor_dispatcher;
pub mod disappearing_minute_expiry;
pub mod encryption;
pub mod event_admission;
pub mod event_lifecycle;
pub mod event_projection;
pub mod event_retention;
pub mod pipeline_helpers;
mod post_admission_purge;
pub mod queue_rows;
pub mod sync;
pub mod transit_in;
pub mod transit_out;
mod worker_catalog;

pub(crate) use post_admission_purge::drain_post_admission_purge_pending;
pub use worker_catalog::{daemon_workers, DaemonWorkerContext};
