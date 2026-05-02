use crate::event_modules::identity::endpoint::commands::ensure_local_keypair;
use crate::store::Store;

use super::super::connection_record::queries;
use super::super::connection_record::types::ConnectionId;
use super::codec::{self, TransitEnvelope};
use super::crypto;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnwrappedTransit {
    pub inner: Vec<u8>,
    pub connection_id: Option<ConnectionId>,
}

pub fn unwrap(store: &Store, bytes: &[u8]) -> Result<UnwrappedTransit, String> {
    let local = ensure_local_keypair(store)?;
    match codec::decode(bytes)? {
        TransitEnvelope::Bootstrap {
            sender_endpoint,
            recipient_endpoint,
            nonce,
            ciphertext,
        } => {
            if recipient_endpoint != local.endpoint {
                return Err("bootstrap transit addressed to a different endpoint".to_string());
            }
            let envelope = TransitEnvelope::Bootstrap {
                sender_endpoint,
                recipient_endpoint,
                nonce,
                ciphertext: Vec::new(),
            };
            let inner = crypto::decrypt(
                &local.secret,
                &sender_endpoint,
                crypto::BOOTSTRAP_PURPOSE,
                &codec::associated_data(&envelope),
                &nonce,
                &ciphertext,
            )?;
            Ok(UnwrappedTransit {
                inner,
                connection_id: None,
            })
        }
        TransitEnvelope::Connection {
            connection_id,
            sender_endpoint,
            recipient_endpoint,
            nonce,
            ciphertext,
        } => {
            if recipient_endpoint != local.endpoint {
                return Err("connection transit addressed to a different endpoint".to_string());
            }
            let remote = queries::remote_endpoint(store, &connection_id)?;
            if sender_endpoint != remote {
                return Err("connection transit sender does not match connection".to_string());
            }
            let envelope = TransitEnvelope::Connection {
                connection_id,
                sender_endpoint,
                recipient_endpoint,
                nonce,
                ciphertext: Vec::new(),
            };
            let inner = crypto::decrypt(
                &local.secret,
                &sender_endpoint,
                crypto::CONNECTION_PURPOSE,
                &codec::associated_data(&envelope),
                &nonce,
                &ciphertext,
            )?;
            Ok(UnwrappedTransit {
                inner,
                connection_id: Some(connection_id),
            })
        }
    }
}
