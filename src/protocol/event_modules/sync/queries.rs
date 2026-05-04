//! Read-only sync work views.
//!
//! The worker consumes projected sync work through this file. Keeping scans here
//! avoids teaching the worker the row-table key layout and keeps `schema.rs`
//! focused on declarations and row encoding.

use crate::core::store::Store;
use crate::protocol::event_modules::connection::types::ConnectionId;

use super::schema::{self, InboundSyncEvent};

pub fn inbound_events_for_connection(
    store: &Store,
    connection_id: ConnectionId,
    limit: usize,
) -> Result<Vec<InboundSyncEvent>, String> {
    let prefix = schema::inbound_event_prefix(connection_id);
    store
        .table_rows_with_key_prefix(schema::INBOUND_EVENTS, &prefix, limit)
        .map_err(|err| format!("load inbound sync events: {err}"))?
        .into_iter()
        .map(|(key, value)| schema::decode_inbound_event(key, value))
        .collect()
}
