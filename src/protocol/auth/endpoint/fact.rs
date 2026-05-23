//! Local endpoint fact shape for the poc-10 target tree.
//!
//! An endpoint fact stores the connection::frame X25519 keypair together with the
//! Ed25519 signing keypair for events authorised by this endpoint's
//! workspace membership. Endpoint facts are local-only.

use crate::core::crypto::{Ed25519PrivateKey, Ed25519PublicKey};

pub type EndpointId = [u8; 32];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EndpointFact {
    pub endpoint: EndpointId,
    pub secret: [u8; 32],
    pub signing_public_key: Ed25519PublicKey,
    pub signing_secret: Ed25519PrivateKey,
}
