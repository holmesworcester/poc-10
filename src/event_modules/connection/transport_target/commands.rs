use std::net::SocketAddr;

use crate::store::Store;

use super::super::connection_record::types::ConnectionId;
use super::projector;

pub fn record(store: &Store, connection_id: ConnectionId, addr: SocketAddr) -> Result<(), String> {
    store
        .insert_module_rows(projector::transport_target(connection_id, addr))
        .map(|_| ())
        .map_err(|err| format!("record transport target: {err}"))
}
