//! Command for accepting a connection ack.
//!
//! The command receives both the ack bytes and the original request bytes. That
//! explicit context is the contract: validation is local and deterministic, and
//! success returns only proposed event output plus the derived connection id.

use crate::protocol::event_modules::identity::endpoint;
use crate::protocol::event_modules::worker::CommandOutput;

use super::super::connection_request;
use super::super::types;
use super::codec;

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
    if event.to_endpoint != local.endpoint {
        return Err("connection ack addressed to a different endpoint".to_string());
    }
    let expected_connection_id = types::connection_id(&event.request_id, &event.from_endpoint);
    if event.connection_id != expected_connection_id {
        return Err("connection ack has an invalid connection id".to_string());
    }

    Ok(CommandOutput::with_events(
        types::InboundConnection {
            outgoing: Vec::new(),
            connection_id: Some(event.connection_id),
        },
        Vec::new(),
    ))
}
