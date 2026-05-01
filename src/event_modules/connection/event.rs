//! Connection event struct and (TODO) prekey companions.
//!
//! Connections are between two endpoints (daemons). A single `Connection`
//! event carries every workspace the two endpoints share. There is no
//! `workspace_id` on a `Connection` event itself.

use std::collections::BTreeSet;

use crate::runtime::control_loop::work_item::{EndpointId, WorkspaceId};

/// Reserved wire-type codes for connection-related events.
///
/// We pick fresh slots above the existing range. The current event-type
/// constants (`event_modules::EVENT_TYPE_*`) go up to 32 with gaps; using
/// 33+ keeps us out of the way until the registry adopts these for real.
///
/// TODO(plan.md): finalize codes once we wire the connection module into the
/// global `EventRegistry`.
pub const CONNECTION_TYPE_CODE: u8 = 33;
pub const CONNECTION_PREKEY_TYPE_CODE: u8 = 34;
pub const CONNECTION_PREKEY_SHARED_TYPE_CODE: u8 = 35;

/// `Connection`: two endpoints, agreed `shared_workspaces` set, signed.
///
/// Field-level wire layout (see `codec.rs` for the FieldSpec table):
/// - type_code(u8)
/// - created_at_ms(u64) — also used as `signed_at_ms`
/// - endpoint_a([u8; 32])
/// - endpoint_b([u8; 32])
/// - shared_workspaces_count(u16)
/// - shared_workspaces([[u8; 32]; N])
/// - signer([u8; 32])
/// - signature([u8; 64])
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Connection {
    pub created_at_ms: u64,
    pub endpoint_a: EndpointId,
    pub endpoint_b: EndpointId,
    pub shared_workspaces: BTreeSet<WorkspaceId>,
    pub signed_at_ms: u64,
    pub signer: [u8; 32],
    pub signature: [u8; 64],
}

impl crate::event_modules::Describe for Connection {
    fn human_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            (
                "endpoint_a",
                crate::event_modules::short_id_b64(&self.endpoint_a),
            ),
            (
                "endpoint_b",
                crate::event_modules::short_id_b64(&self.endpoint_b),
            ),
            (
                "shared_workspaces",
                self.shared_workspaces.len().to_string(),
            ),
        ]
    }
}

impl Connection {
    /// Bytes signed by the signer. Excludes the signature itself.
    /// Mirrors the wire encoding (sans `signature`) so the digest is
    /// deterministic across encode/parse.
    pub fn signing_bytes(&self) -> Vec<u8> {
        let n = self.shared_workspaces.len();
        let cap = 8 + 32 + 32 + 8 + 2 + n * 32 + 32;
        let mut out = Vec::with_capacity(cap);
        out.extend_from_slice(&self.created_at_ms.to_be_bytes());
        out.extend_from_slice(&self.endpoint_a);
        out.extend_from_slice(&self.endpoint_b);
        out.extend_from_slice(&self.signed_at_ms.to_be_bytes());
        out.extend_from_slice(&(n as u16).to_be_bytes());
        for ws in &self.shared_workspaces {
            out.extend_from_slice(ws);
        }
        out.extend_from_slice(&self.signer);
        out
    }

    /// Canonical event id of this `Connection` event: Blake2b-256 of the
    /// canonical wire bytes (full encoding, including the signature). This
    /// is the value used as `connection_id` in the `connections` and
    /// `connection_shared_workspaces` projection tables, and the same id
    /// the standard event pipeline assigns from `hash_event(&blob)`.
    ///
    /// Because the canonical bytes include the signature, two `Connection`
    /// events that share `(endpoint_a, endpoint_b, signed_at_ms)` but were
    /// signed by different keys (or with otherwise distinct signature
    /// bytes) produce DIFFERENT `connection_id`s.
    pub fn canonical_event_id(&self) -> [u8; 32] {
        let blob = super::codec::encode_connection(self);
        crate::crypto::hash_event(&blob)
    }
}

/// `ConnectionPrekey`: per-endpoint-pair secret half (issuer side).
///
/// TODO(plan.md): port secret/shared split from poc-6 `events/network/`.
/// Phase 1 stub — fields chosen to match the poc-6 layout but neither parsed
/// nor projected yet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionPrekey {
    pub created_at_ms: u64,
    pub local_endpoint_id: EndpointId,
    pub prekey_secret: [u8; 32],
    /// Connection event id this prekey is bound to (once established).
    pub connection_id: Option<[u8; 32]>,
}

/// `ConnectionPrekeyShared`: per-endpoint-pair shared half.
///
/// TODO(plan.md): port from poc-6.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionPrekeyShared {
    pub created_at_ms: u64,
    pub from_endpoint_id: EndpointId,
    pub to_endpoint_id: EndpointId,
    pub prekey_pubkey: [u8; 32],
    pub signer: [u8; 32],
    pub signature: [u8; 64],
}
