//! `ConnectionPrekeyEvent` struct: per-endpoint long-lived asymmetric prekey
//! kept *secret* by its owner.

use crate::runtime::control_loop::work_item::EndpointId;

/// Wire type code (per plan.md line: `connection_prekey = 34`).
///
/// Mirrors the Phase 1 stub constant in `connection/event.rs` so a single
/// numeric value identifies this kind on the wire.
pub const CONNECTION_PREKEY_TYPE_CODE: u8 = 34;

/// Per-endpoint long-lived asymmetric prekey, secret half. The endpoint that
/// owns this prekey holds *both* private and public bytes here; the matching
/// `ConnectionPrekeySharedEvent` carries only the public half and is the
/// broadcast form sent to peers.
///
/// `prekey_id` is a 32-byte identifier minted by the owner (e.g. derived
/// from the public key or independently) and used by callers (notably
/// `connection.wrap_bootstrap`) to refer back to a specific prekey.
///
/// The event is signed by the owner endpoint identity. Verification is done
/// by the projector before insertion into `connection_prekeys`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionPrekeyEvent {
    pub prekey_id: [u8; 32],
    pub endpoint_id: EndpointId,
    pub private_key: [u8; 32],
    pub public_key: [u8; 32],
    pub created_at_ms: u64,
    pub ttl_ms: u64,
    pub signature: [u8; 64],
}

impl crate::event_modules::Describe for ConnectionPrekeyEvent {
    fn human_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            ("prekey_id", crate::event_modules::short_id_b64(&self.prekey_id)),
            ("endpoint_id", crate::event_modules::short_id_b64(&self.endpoint_id)),
            ("ttl_ms", self.ttl_ms.to_string()),
        ]
    }
}

impl ConnectionPrekeyEvent {
    /// Bytes signed by the owner endpoint. Excludes the signature itself.
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 + 32 + 32 + 32 + 8 + 8);
        out.extend_from_slice(&self.prekey_id);
        out.extend_from_slice(&self.endpoint_id);
        out.extend_from_slice(&self.private_key);
        out.extend_from_slice(&self.public_key);
        out.extend_from_slice(&self.created_at_ms.to_be_bytes());
        out.extend_from_slice(&self.ttl_ms.to_be_bytes());
        out
    }
}
