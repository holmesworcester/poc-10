use crate::event_modules::identity::endpoint::commands::ensure_local_keypair;
use crate::event_modules::identity::endpoint::types::EndpointId;
use crate::store::Store;

use super::super::connection_record::queries;
use super::super::connection_record::types::ConnectionId;
use super::codec::{self, TransitEnvelope};
use super::crypto;

pub fn create_bootstrap(
    store: &Store,
    recipient_endpoint: EndpointId,
    inner: &[u8],
) -> Result<Vec<u8>, String> {
    let local = ensure_local_keypair(store)?;
    let nonce = crypto::nonce();
    let envelope = TransitEnvelope::Bootstrap {
        sender_endpoint: local.endpoint,
        recipient_endpoint,
        nonce,
        ciphertext: Vec::new(),
    };
    let ciphertext = crypto::encrypt(
        &local.secret,
        &recipient_endpoint,
        crypto::BOOTSTRAP_PURPOSE,
        &codec::associated_data(&envelope),
        &nonce,
        inner,
    )?;
    Ok(codec::encode(&TransitEnvelope::Bootstrap {
        sender_endpoint: local.endpoint,
        recipient_endpoint,
        nonce,
        ciphertext,
    }))
}

pub fn create_connection(
    store: &Store,
    connection_id: ConnectionId,
    inner: Vec<u8>,
) -> Result<Vec<u8>, String> {
    let local = ensure_local_keypair(store)?;
    let recipient_endpoint = queries::remote_endpoint(store, &connection_id)?;
    let nonce = crypto::nonce();
    let envelope = TransitEnvelope::Connection {
        connection_id,
        sender_endpoint: local.endpoint,
        recipient_endpoint,
        nonce,
        ciphertext: Vec::new(),
    };
    let ciphertext = crypto::encrypt(
        &local.secret,
        &recipient_endpoint,
        crypto::CONNECTION_PURPOSE,
        &codec::associated_data(&envelope),
        &nonce,
        &inner,
    )?;
    Ok(codec::encode(&TransitEnvelope::Connection {
        connection_id,
        sender_endpoint: local.endpoint,
        recipient_endpoint,
        nonce,
        ciphertext,
    }))
}
