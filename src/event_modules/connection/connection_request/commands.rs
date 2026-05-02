use rand_core::RngCore;

use crate::event_modules::identity::{endpoint, invite};
use crate::store::{CommandOutput, EventId};

use super::super::connection_record::types;
use super::super::transit;
use super::types::RequestEvent;
use super::{codec, projector};

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
    let projection = projector::outbound(inner.clone())?;
    Ok(CommandOutput::with_changes(
        OutboundRequest {
            bytes: transit::commands::create_bootstrap(&local, invite.endpoint, &inner)?,
            request_id,
            local_endpoint: local.endpoint,
            addr: invite.addr,
        },
        projection.changes,
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

    let projection = projector::inbound(bytes, local.endpoint, event.bootstrap_hash)?;
    let outgoing = projection
        .emitted_events
        .iter()
        .map(|bytes| transit::commands::create_bootstrap(&local, event.from_endpoint, bytes))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(CommandOutput::with_changes(
        types::InboundConnection {
            outgoing,
            connection_id: projection.connection_id,
        },
        projection.changes,
    ))
}

fn nonce32() -> [u8; 32] {
    let mut nonce = [0; 32];
    rand_core::OsRng.fill_bytes(&mut nonce);
    nonce
}
