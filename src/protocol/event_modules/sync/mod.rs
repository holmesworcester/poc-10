//! Sync domain.
//!
//! Sync is modeled as connection-scoped events plus a domain worker. Projectors
//! put outbound transient sync frames into the connection outbox and inbound
//! transient sync frames into sync-owned work rows; the worker decides what
//! compare/have/need/data items to produce by querying event indexes. This keeps
//! reconciliation protocol logic out of the common admission worker.

pub mod cli;
pub mod compare;
pub mod data;
pub mod frame;
pub mod have_id;
pub mod need_id;
pub mod queries;
pub mod schema;
pub mod worker;

use crate::protocol::event_modules::worker::ProjectionOutput;

pub fn project_record(bytes: &[u8]) -> Result<Option<ProjectionOutput>, String> {
    if frame::codec::is_frame(bytes) {
        return Ok(Some(frame::projector::project(bytes)?));
    }
    Ok(None)
}
