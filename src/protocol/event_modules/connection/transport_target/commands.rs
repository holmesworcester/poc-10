use std::net::SocketAddr;

use crate::core::store::CommandOutput;

use super::super::types::ConnectionId;
use super::codec;
use super::types::TransportTargetEvent;

pub fn record(connection_id: ConnectionId, addr: SocketAddr) -> CommandOutput<()> {
    let bytes = codec::encode(&TransportTargetEvent {
        connection_id,
        addr,
    });
    CommandOutput::with_events(
        (),
        vec![codec::record_from_bytes(bytes).expect("encoded transport target is valid")],
    )
}
