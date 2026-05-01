//! `ObservedAddressEvent`: one peer's observation of another peer's address.

use crate::runtime::control_loop::work_item::EndpointId;

/// Wire type code (per plan.md line: `observed_address = 37`).
pub const OBSERVED_ADDRESS_TYPE_CODE: u8 = 37;

/// `ObservedAddressEvent`: signed assertion by `observer_endpoint_id` that
/// `subject_endpoint_id` was reachable at `(ip, port)` at `observed_at_ms`.
///
/// The address is 16 bytes IPv6 (or IPv4-mapped IPv6) plus a u16 port,
/// matching `IntroAddress`. The projector verifies the observer's
/// signature and writes a TTL-bounded row into `observed_addresses`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservedAddressEvent {
    pub observer_endpoint_id: EndpointId,
    pub subject_endpoint_id: EndpointId,
    pub ip: [u8; 16],
    pub port: u16,
    pub observed_at_ms: u64,
    pub ttl_ms: u64,
    pub signed_by: EndpointId,
    pub signature: [u8; 64],
}

impl crate::event_modules::Describe for ObservedAddressEvent {
    fn human_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            (
                "observer",
                crate::event_modules::short_id_b64(&self.observer_endpoint_id),
            ),
            (
                "subject",
                crate::event_modules::short_id_b64(&self.subject_endpoint_id),
            ),
            ("port", self.port.to_string()),
        ]
    }
}

impl ObservedAddressEvent {
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 + 32 + 16 + 2 + 8 + 8 + 32);
        out.extend_from_slice(&self.observer_endpoint_id);
        out.extend_from_slice(&self.subject_endpoint_id);
        out.extend_from_slice(&self.ip);
        out.extend_from_slice(&self.port.to_be_bytes());
        out.extend_from_slice(&self.observed_at_ms.to_be_bytes());
        out.extend_from_slice(&self.ttl_ms.to_be_bytes());
        out.extend_from_slice(&self.signed_by);
        out
    }
}
