use crate::event_modules::identity::endpoint;
use crate::store::Store;

use super::super::connection_record::{commands as record_commands, queries, types};
use super::super::connection_request;
use super::{codec, projector};

pub fn accept(store: &Store, bytes: Vec<u8>) -> Result<types::InboundConnection, String> {
    let local = endpoint::commands::ensure_local_keypair(store)?;
    let event = codec::decode(&bytes)?;
    let request_bytes = queries::event_bytes(store, &event.request_id)?
        .ok_or_else(|| "connection ack references an unknown request".to_string())?;
    let request = connection_request::codec::decode(&request_bytes)
        .map_err(|_| "connection ack references a non-request event".to_string())?;
    if request.from_endpoint != local.endpoint {
        return Err("connection ack references another endpoint's request".to_string());
    }

    let projection = projector::inbound(bytes, local.endpoint, event.request_id)?;
    let connection_id = projection.connection_id;
    record_commands::apply(store, projection)?;
    Ok(types::InboundConnection {
        response: None,
        connection_id,
    })
}
