use rand_core::RngCore;

use crate::core::store::{CommandOutput, EventId};
use crate::protocol::event_modules::identity::{endpoint, invite};

use super::super::connection_record::types;
use super::super::transit;
use super::codec;
use super::types::RequestEvent;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboundRequest {
    pub bytes: Vec<u8>,
    pub request_id: EventId,
    pub local_endpoint: endpoint::types::EndpointId,
    pub addr: std::net::SocketAddr,
}

pub fn create(
    local: endpoint::types::EndpointKeypair,
    invite_link: &str,
) -> Result<CommandOutput<OutboundRequest>, String> {
    let invite = invite::commands::parse(invite_link)?;
    let event = RequestEvent {
        from_endpoint: local.endpoint,
        nonce: nonce32(),
        bootstrap_hash: invite::commands::secret_hash(&invite.bootstrap_secret),
    };
    let inner = codec::encode(&event);
    let request_id = types::event_id(&inner);
    let record = codec::record_from_bytes(inner.clone())?;
    Ok(CommandOutput::with_events(
        OutboundRequest {
            bytes: transit::commands::create_bootstrap(&local, invite.endpoint, &inner)?,
            request_id,
            local_endpoint: local.endpoint,
            addr: invite.addr,
        },
        vec![record],
    ))
}

pub fn accept(
    local: endpoint::types::EndpointKeypair,
    bootstrap_hash_is_authorized: bool,
    bytes: Vec<u8>,
) -> Result<CommandOutput<types::InboundConnection>, String> {
    let event = codec::decode(&bytes)?;
    if !bootstrap_hash_is_authorized {
        return Err("invite private key rejected".to_string());
    }

    let request_id = types::event_id(&bytes);
    let connection_id = types::connection_id(&request_id, &local.endpoint);
    let ack = super::super::connection_ack::types::AckEvent {
        from_endpoint: local.endpoint,
        to_endpoint: event.from_endpoint,
        request_id,
        connection_id,
    };
    let ack_bytes = super::super::connection_ack::codec::encode(&ack);
    let outgoing = vec![transit::commands::create_bootstrap(
        &local,
        event.from_endpoint,
        &ack_bytes,
    )?];
    let ack_record = super::super::connection_ack::codec::record_from_bytes(ack_bytes)?;
    Ok(CommandOutput::with_events(
        types::InboundConnection {
            outgoing,
            connection_id: Some(connection_id),
        },
        vec![ack_record],
    ))
}

fn nonce32() -> [u8; 32] {
    let mut nonce = [0; 32];
    rand_core::OsRng.fill_bytes(&mut nonce);
    nonce
}
