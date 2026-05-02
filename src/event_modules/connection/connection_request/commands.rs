use rand_core::RngCore;

use crate::event_modules::identity::{endpoint, invite};
use crate::store::{EventId, Store};

use super::super::connection_record::{commands as record_commands, types};
use super::super::transit;
use super::{codec, projector};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboundRequest {
    pub bytes: Vec<u8>,
    pub request_id: EventId,
    pub local_endpoint: endpoint::types::EndpointId,
    pub addr: std::net::SocketAddr,
}

pub fn create(store: &Store, invite_link: &str) -> Result<OutboundRequest, String> {
    let invite = invite::commands::parse(invite_link)?;
    let local = endpoint::commands::ensure_local_keypair(store)?;
    let event = codec::RequestEvent {
        from_endpoint: local.endpoint,
        nonce: nonce32(),
        bootstrap_hash: invite::commands::secret_hash(&invite.bootstrap_secret),
    };
    let inner = codec::encode(&event);
    let request_id = types::event_id(&inner);
    record_commands::apply(store, projector::outbound(inner.clone())?)?;
    Ok(OutboundRequest {
        bytes: transit::commands::create_bootstrap(store, invite.endpoint, &inner)?,
        request_id,
        local_endpoint: local.endpoint,
        addr: invite.addr,
    })
}

pub fn accept(store: &Store, bytes: Vec<u8>) -> Result<types::InboundConnection, String> {
    let local = endpoint::commands::ensure_local_keypair(store)?;
    let event = codec::decode(&bytes)?;
    if !invite::commands::bootstrap_hash_is_authorized(store, &event.bootstrap_hash)? {
        return Err("invite private key rejected".to_string());
    }

    let projection = projector::inbound(bytes, local.endpoint, event.bootstrap_hash)?;
    let response = projection
        .response
        .as_ref()
        .map(|bytes| transit::commands::create_bootstrap(store, event.from_endpoint, bytes))
        .transpose()?;
    let connection_id = projection.connection_id;
    record_commands::apply(store, projection)?;
    Ok(types::InboundConnection {
        response,
        connection_id,
    })
}

fn nonce32() -> [u8; 32] {
    let mut nonce = [0; 32];
    rand_core::OsRng.fill_bytes(&mut nonce);
    nonce
}
