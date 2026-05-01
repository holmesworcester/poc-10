//! `ConnectionPrekeySharedEvent` struct: per-endpoint long-lived asymmetric
//! prekey broadcast to peers (public half only).

use crate::runtime::control_loop::work_item::EndpointId;

/// Wire type code (per plan.md line: `connection_prekey_shared = 35`).
pub const CONNECTION_PREKEY_SHARED_TYPE_CODE: u8 = 35;

/// Per-endpoint long-lived asymmetric prekey, public/shared half. Distributed
/// to peers via the connection module so that anyone wanting to send a
/// bootstrap connection_request to this endpoint can seal it to the
/// recipient's prekey public half.
///
/// Signed by the owner endpoint identity; the projector verifies before
/// inserting into `connection_prekeys_shared`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionPrekeySharedEvent {
    pub prekey_id: [u8; 32],
    pub endpoint_id: EndpointId,
    pub public_key: [u8; 32],
    pub created_at_ms: u64,
    pub ttl_ms: u64,
    pub signature: [u8; 64],
}

impl crate::event_modules::Describe for ConnectionPrekeySharedEvent {
    fn human_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            ("prekey_id", crate::event_modules::short_id_b64(&self.prekey_id)),
            ("endpoint_id", crate::event_modules::short_id_b64(&self.endpoint_id)),
            ("ttl_ms", self.ttl_ms.to_string()),
        ]
    }
}

impl ConnectionPrekeySharedEvent {
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 + 32 + 32 + 8 + 8);
        out.extend_from_slice(&self.prekey_id);
        out.extend_from_slice(&self.endpoint_id);
        out.extend_from_slice(&self.public_key);
        out.extend_from_slice(&self.created_at_ms.to_be_bytes());
        out.extend_from_slice(&self.ttl_ms.to_be_bytes());
        out
    }
}
