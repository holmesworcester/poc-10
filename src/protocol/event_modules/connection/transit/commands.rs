//! Transit wrap and unwrap commands.
//!
//! This is the active boundary between connection state and network bytes. It
//! accepts explicit endpoint keys and connection context, then returns opaque
//! transit bytes or recovered inner bytes. It does not admit events or mutate
//! schema; the connection worker decides what to do with the result.

use crate::protocol::event_modules::identity::endpoint::types::EndpointId;
use crate::protocol::event_modules::identity::endpoint::types::EndpointKeypair;

use super::super::types::ConnectionId;
use super::codec::{self, TransitEnvelopeRef};
use super::crypto;
use super::types::TransitEnvelope;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnwrappedTransit {
    pub inners: Vec<Vec<u8>>,
    pub connection_id: Option<ConnectionId>,
}

pub fn create_bootstrap(
    local: &EndpointKeypair,
    recipient_endpoint: EndpointId,
    inner: &[u8],
) -> Result<Vec<u8>, String> {
    // Bootstrap frames are addressed directly to an endpoint because a
    // connection id does not exist yet.
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

pub fn unwrap(
    local: EndpointKeypair,
    bytes: &[u8],
    remote_endpoint: impl FnOnce(&ConnectionId) -> Result<EndpointId, String>,
) -> Result<UnwrappedTransit, String> {
    // The caller supplies remote endpoint lookup for established connections.
    // That keeps storage access in the worker and makes this function a pure
    // cryptographic transform over explicit context.
    match codec::decode_ref(bytes)? {
        TransitEnvelopeRef::Bootstrap {
            sender_endpoint,
            recipient_endpoint,
            nonce,
            ciphertext,
        } => {
            if recipient_endpoint != local.endpoint {
                return Err("bootstrap transit addressed to a different endpoint".to_string());
            }
            let inner = crypto::decrypt(
                &local.secret,
                &sender_endpoint,
                crypto::BOOTSTRAP_PURPOSE,
                &codec::associated_data_bootstrap(&sender_endpoint, &recipient_endpoint, &nonce),
                &nonce,
                ciphertext,
            )?;
            Ok(UnwrappedTransit {
                inners: vec![inner],
                connection_id: None,
            })
        }
        TransitEnvelopeRef::Connection {
            connection_id,
            sender_endpoint,
            recipient_endpoint,
            nonce,
            ciphertext,
        } => {
            if recipient_endpoint != local.endpoint {
                return Err("connection transit addressed to a different endpoint".to_string());
            }
            let remote = remote_endpoint(&connection_id)?;
            if sender_endpoint != remote {
                return Err("connection transit sender does not match connection".to_string());
            }
            let plaintext = crypto::decrypt(
                &local.secret,
                &sender_endpoint,
                crypto::CONNECTION_PURPOSE,
                &codec::associated_data_connection(
                    &connection_id,
                    &sender_endpoint,
                    &recipient_endpoint,
                    &nonce,
                ),
                &nonce,
                ciphertext,
            )?;
            Ok(UnwrappedTransit {
                inners: codec::decode_inner_events(&plaintext)?,
                connection_id: Some(connection_id),
            })
        }
    }
}

pub fn create_connection_batch(
    local: &EndpointKeypair,
    recipient_endpoint: EndpointId,
    connection_id: ConnectionId,
    inners: Vec<Vec<u8>>,
) -> Result<Vec<u8>, String> {
    // Ordinary frames bind sender, recipient, and connection id into the
    // authenticated envelope before encrypting the inner event bytes. The
    // plaintext is a small fixed-format list so one transit envelope can carry a
    // coherent batch of canonical events without making TCP understand them.
    let nonce = crypto::nonce();
    let envelope = TransitEnvelope::Connection {
        connection_id,
        sender_endpoint: local.endpoint,
        recipient_endpoint,
        nonce,
        ciphertext: Vec::new(),
    };
    let plaintext = codec::encode_inner_events(&inners)?;
    let ciphertext = crypto::encrypt(
        &local.secret,
        &recipient_endpoint,
        crypto::CONNECTION_PURPOSE,
        &codec::associated_data(&envelope),
        &nonce,
        &plaintext,
    )?;
    Ok(codec::encode(&TransitEnvelope::Connection {
        connection_id,
        sender_endpoint: local.endpoint,
        recipient_endpoint,
        nonce,
        ciphertext,
    }))
}
