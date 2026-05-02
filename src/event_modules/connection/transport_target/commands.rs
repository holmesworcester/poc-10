use std::net::SocketAddr;

use crate::store::EventRecord;

use super::super::connection_record::types::ConnectionId;
use super::codec;
use super::types::TransportTargetEvent;

pub fn record(connection_id: ConnectionId, addr: SocketAddr) -> EventRecord {
    let bytes = codec::encode(&TransportTargetEvent {
        connection_id,
        addr,
    });
    codec::record_from_bytes(bytes).expect("encoded transport target is valid")
}
