use crate::core::store::Store;
use crate::protocol::event_modules::identity::endpoint::queries::endpoint_id;
use crate::protocol::event_modules::identity::endpoint::types::EndpointId;

use super::tables;
use super::types::{connection_id_from_bytes, ConnectionId, OutboxItem, OutboxKey};

pub fn remote_endpoint(store: &Store, connection_id: &ConnectionId) -> Result<EndpointId, String> {
    let bytes = store
        .table_row(tables::CONNECTIONS, connection_id)
        .map_err(|err| format!("load connection: {err}"))?
        .ok_or_else(|| "unknown connection".to_string())?;
    endpoint_id(&bytes)
}

pub fn event_bytes(store: &Store, event_id: &[u8; 32]) -> Result<Option<Vec<u8>>, String> {
    store
        .table_row(tables::CONNECTION_EVENTS, event_id)
        .map_err(|err| format!("load connection event: {err}"))
}

pub fn connection_count(store: &Store) -> Result<usize, String> {
    store
        .table_row_count(tables::CONNECTIONS)
        .map_err(|err| format!("count connections: {err}"))
}

pub fn connection_event_count(store: &Store) -> Result<usize, String> {
    store
        .table_row_count(tables::CONNECTION_EVENTS)
        .map_err(|err| format!("count connection events: {err}"))
}

pub fn outbox_items_for_connection(
    store: &Store,
    connection_id: ConnectionId,
) -> Result<Vec<OutboxItem>, String> {
    all_outbox_items(store).map(|items| {
        items
            .into_iter()
            .filter(|item| item.key.connection_id == connection_id)
            .collect()
    })
}

pub fn all_outbox_items(store: &Store) -> Result<Vec<OutboxItem>, String> {
    let rows = store
        .table_rows(tables::OUTBOX)
        .map_err(|err| format!("load outbox: {err}"))?;
    let mut items = Vec::with_capacity(rows.len());
    for (key, value) in rows {
        let key = decode_outbox_key(&key)?;
        let event_bytes = if value.is_empty() {
            let Some(event_bytes) = store
                .event_bytes(&key.event_id)
                .map_err(|err| format!("load outbox event: {err}"))?
            else {
                continue;
            };
            event_bytes
        } else {
            value
        };
        items.push(OutboxItem { key, event_bytes });
    }
    Ok(items)
}

pub fn delete_outbox(store: &Store, keys: &[OutboxKey]) -> Result<(), String> {
    let keys = keys.iter().map(|key| key.to_bytes()).collect::<Vec<_>>();
    delete_outbox_encoded(store, keys)
}

pub fn delete_outbox_encoded(store: &Store, keys: Vec<Vec<u8>>) -> Result<(), String> {
    store
        .delete_table_rows(tables::OUTBOX, keys)
        .map(|_| ())
        .map_err(|err| format!("delete sent outbox rows: {err}"))
}

fn decode_outbox_key(bytes: &[u8]) -> Result<OutboxKey, String> {
    if bytes.len() != 64 {
        return Err("outbox key must be 64 bytes".to_string());
    }
    let connection_id = connection_id_from_bytes(&bytes[..32])?;
    let mut event_id = [0; 32];
    event_id.copy_from_slice(&bytes[32..]);
    Ok(OutboxKey {
        connection_id,
        event_id,
    })
}
