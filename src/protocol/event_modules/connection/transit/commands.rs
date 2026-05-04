use crate::protocol::event_modules::identity::endpoint::types::EndpointId;
use crate::protocol::event_modules::identity::endpoint::types::EndpointKeypair;

use super::super::connection_record::types::ConnectionId;
use super::codec;
use super::crypto;
use super::types::TransitEnvelope;

pub fn create_bootstrap(
    local: &EndpointKeypair,
    recipient_endpoint: EndpointId,
    inner: &[u8],
) -> Result<Vec<u8>, String> {
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
    local: &EndpointKeypair,
    recipient_endpoint: EndpointId,
    connection_id: ConnectionId,
    inner: Vec<u8>,
) -> Result<Vec<u8>, String> {
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
