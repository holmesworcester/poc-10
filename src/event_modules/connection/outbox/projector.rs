use crate::store::{EventId, TableRow};

use super::super::connection_record::types::ConnectionId;
use super::tables;

pub fn queue(connection_id: ConnectionId, event_id: EventId, canonical_bytes: Vec<u8>) -> TableRow {
    let key = super::types::OutboxKey {
        connection_id,
        event_id,
    }
    .to_bytes();
    TableRow {
        table: tables::OUTBOX,
        key,
        value: canonical_bytes,
    }
}
