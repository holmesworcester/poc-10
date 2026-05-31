//! Connection-response payload.
//!
//! A response is the connection fact. Its id is the connection id, and the
//! payload records the endpoint pair, answered request id, dependency ids,
//! responder ephemeral public key, handshake hash, and connection secret. The
//! connection secret is local capability material used by established frame
//! handling.
//!
//! This file owns only the typed payload shape. Byte order belongs in
//! `layout.rs`, construction belongs in `create.rs`, and admission belongs in
//! `project.rs`.

use crate::core::facts::FactId;

pub type EndpointId = [u8; 32];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BootstrapResponseFact {
    pub from_endpoint: EndpointId,
    pub to_endpoint: EndpointId,
    pub request_id: FactId,
    pub invite_secret_fact_id: FactId,
    pub initiator_ephemeral_secret_fact_id: FactId,
    pub responder_ephemeral_secret_fact_id: FactId,
    pub responder_ephemeral_public_key: EndpointId,
    pub handshake_hash: [u8; 32],
    pub connection_secret: [u8; 32],
}
