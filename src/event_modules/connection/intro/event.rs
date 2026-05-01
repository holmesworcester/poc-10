//! `IntroEvent` struct — endpoint-pair introduction.

use crate::runtime::control_loop::work_item::EndpointId;

/// Wire type code (per plan.md line: `intro = 36`).
pub const INTRO_TYPE_CODE: u8 = 36;

/// IPv4/IPv6 address hint carried inside an `IntroEvent`. We store IPv6 (or
/// IPv4-mapped IPv6) bytes plus a u16 port. Same shape used by
/// `observed_address` and `self_address`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct IntroAddress {
    /// 16-byte IPv6 (IPv4 packed as ::ffff:a.b.c.d).
    pub ip: [u8; 16],
    pub port: u16,
}

/// `IntroEvent`: A introduces subjects B and C to each other. Carries
/// per-subject address hints so the recipient can dial without an extra
/// observed-address round-trip.
///
/// `signed_by` is the introducer endpoint identity. Verified by the
/// projector before insertion into `intros`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntroEvent {
    pub subject_a_endpoint_id: EndpointId,
    pub subject_b_endpoint_id: EndpointId,
    pub addresses_a: Vec<IntroAddress>,
    pub addresses_b: Vec<IntroAddress>,
    pub created_at_ms: u64,
    pub signed_by: EndpointId,
    pub signature: [u8; 64],
}

impl crate::event_modules::Describe for IntroEvent {
    fn human_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            (
                "subject_a",
                crate::event_modules::short_id_b64(&self.subject_a_endpoint_id),
            ),
            (
                "subject_b",
                crate::event_modules::short_id_b64(&self.subject_b_endpoint_id),
            ),
            ("addrs_a", self.addresses_a.len().to_string()),
            ("addrs_b", self.addresses_b.len().to_string()),
        ]
    }
}

impl IntroEvent {
    /// Bytes signed by the introducer. Excludes the signature itself.
    pub fn signing_bytes(&self) -> Vec<u8> {
        let n = 32 + 32 + 2 + self.addresses_a.len() * 18 + 2 + self.addresses_b.len() * 18 + 8 + 32;
        let mut out = Vec::with_capacity(n);
        out.extend_from_slice(&self.subject_a_endpoint_id);
        out.extend_from_slice(&self.subject_b_endpoint_id);
        out.extend_from_slice(&(self.addresses_a.len() as u16).to_be_bytes());
        for a in &self.addresses_a {
            out.extend_from_slice(&a.ip);
            out.extend_from_slice(&a.port.to_be_bytes());
        }
        out.extend_from_slice(&(self.addresses_b.len() as u16).to_be_bytes());
        for a in &self.addresses_b {
            out.extend_from_slice(&a.ip);
            out.extend_from_slice(&a.port.to_be_bytes());
        }
        out.extend_from_slice(&self.created_at_ms.to_be_bytes());
        out.extend_from_slice(&self.signed_by);
        out
    }
}
