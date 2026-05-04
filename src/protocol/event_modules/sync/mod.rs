//! Sync domain.
//!
//! Sync is modeled as connection-scoped compare/have/need events plus a domain
//! worker. Projectors put outbound transient sync events into the connection
//! outbox by id and inbound transient sync events into sync-owned work rows.
//! The worker decides what follow-up ids to propose by querying event indexes.
//! This keeps reconciliation protocol logic out of the common admission worker.

pub mod cli;
pub mod compare;
pub mod have_id;
pub mod need_id;
pub mod queries;
pub mod schema;
pub mod types;
pub mod worker;

use crate::protocol::event_modules::types::EventRecord;
use crate::protocol::event_modules::worker::ProjectionOutput;

pub fn project_record(bytes: &[u8]) -> Result<Option<ProjectionOutput>, String> {
    if compare::codec::is_event(bytes) {
        return Ok(Some(compare::projector::project(bytes)?));
    }
    if have_id::codec::is_event(bytes) {
        return Ok(Some(have_id::projector::project(bytes)?));
    }
    if need_id::codec::is_event(bytes) {
        return Ok(Some(need_id::projector::project(bytes)?));
    }
    Ok(None)
}

pub fn is_connection_scoped_event(bytes: &[u8]) -> bool {
    compare::codec::is_event(bytes)
        || have_id::codec::is_event(bytes)
        || need_id::codec::is_event(bytes)
}

pub fn record_from_bytes(bytes: Vec<u8>) -> Result<EventRecord, String> {
    if compare::codec::is_event(&bytes) {
        return compare::codec::record_from_bytes(bytes);
    }
    if have_id::codec::is_event(&bytes) {
        return have_id::codec::record_from_bytes(bytes);
    }
    if need_id::codec::is_event(&bytes) {
        return need_id::codec::record_from_bytes(bytes);
    }
    Err("not a sync event".to_string())
}

pub fn inbound_record_from_connection_bytes(bytes: Vec<u8>) -> Result<EventRecord, String> {
    if compare::codec::is_event(&bytes) {
        return compare::codec::inbound_record_from_wire(bytes);
    }
    if have_id::codec::is_event(&bytes) {
        return have_id::codec::inbound_record_from_wire(bytes);
    }
    if need_id::codec::is_event(&bytes) {
        return need_id::codec::inbound_record_from_wire(bytes);
    }
    Err("not a sync event".to_string())
}
