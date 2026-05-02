use crate::event_modules::identity::endpoint;
use crate::store::CommandOutput;

use super::super::connection_record::types;
use super::super::connection_request;
use super::{codec, projector};

pub fn accept(
    local: endpoint::types::EndpointKeypair,
    request_bytes: Vec<u8>,
    bytes: Vec<u8>,
) -> Result<CommandOutput<types::InboundConnection>, String> {
    let event = codec::decode(&bytes)?;
    let request = connection_request::codec::decode(&request_bytes)
        .map_err(|_| "connection ack references a non-request event".to_string())?;
    if request.from_endpoint != local.endpoint {
        return Err("connection ack references another endpoint's request".to_string());
    }

    let projection = projector::inbound(bytes, local.endpoint, event.request_id)?;
    Ok(CommandOutput::with_changes(
        types::InboundConnection {
            outgoing: Vec::new(),
            connection_id: projection.connection_id,
        },
        projection.changes,
    ))
}
