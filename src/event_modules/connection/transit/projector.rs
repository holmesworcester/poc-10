use super::super::super::identity::endpoint::types::{EndpointId, EndpointKeypair};
use super::super::connection_record::types::ConnectionId;
use super::codec::{self, TransitEnvelopeRef};
use super::crypto;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnwrappedTransit {
    pub inner: Vec<u8>,
    pub connection_id: Option<ConnectionId>,
}

pub fn unwrap(
    local: EndpointKeypair,
    bytes: &[u8],
    remote_endpoint: impl FnOnce(&ConnectionId) -> Result<EndpointId, String>,
) -> Result<UnwrappedTransit, String> {
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
                &ciphertext,
            )?;
            Ok(UnwrappedTransit {
                inner,
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
            let inner = crypto::decrypt(
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
                &ciphertext,
            )?;
            Ok(UnwrappedTransit {
                inner,
                connection_id: Some(connection_id),
            })
        }
    }
}
