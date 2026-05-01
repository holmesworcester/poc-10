//! `SelfAddressEvent`: an endpoint's own claimed network address.

use crate::runtime::control_loop::work_item::EndpointId;

/// Wire type code (per plan.md line: `self_address = 38`).
pub const SELF_ADDRESS_TYPE_CODE: u8 = 38;

/// Endpoint claims to be reachable at `(ip, port)`. Signed by the endpoint
/// itself (so `signed_by == endpoint_id` for a well-formed event).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelfAddressEvent {
    pub endpoint_id: EndpointId,
    pub ip: [u8; 16],
    pub port: u16,
    pub created_at_ms: u64,
    pub ttl_ms: u64,
    pub signed_by: EndpointId,
    pub signature: [u8; 64],
}

impl crate::event_modules::Describe for SelfAddressEvent {
    fn human_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            ("endpoint_id", crate::event_modules::short_id_b64(&self.endpoint_id)),
            ("port", self.port.to_string()),
        ]
    }
}

impl SelfAddressEvent {
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 + 16 + 2 + 8 + 8 + 32);
        out.extend_from_slice(&self.endpoint_id);
        out.extend_from_slice(&self.ip);
        out.extend_from_slice(&self.port.to_be_bytes());
        out.extend_from_slice(&self.created_at_ms.to_be_bytes());
        out.extend_from_slice(&self.ttl_ms.to_be_bytes());
        out.extend_from_slice(&self.signed_by);
        out
    }
}
