//! Local endpoint types.
//!
//! Endpoint ids are X25519 public keys. The POC stores the matching secret as a
//! local event so deterministic tests and replay see identity creation through
//! the same admission path as other local facts.

pub type EndpointId = [u8; 32];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EndpointKeypair {
    pub endpoint: EndpointId,
    pub secret: [u8; 32],
}
