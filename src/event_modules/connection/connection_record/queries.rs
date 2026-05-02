use crate::event_modules::identity::endpoint::queries::endpoint_id;
use crate::event_modules::identity::endpoint::types::EndpointId;
use crate::store::Store;

use super::tables;
use super::types::ConnectionId;

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
