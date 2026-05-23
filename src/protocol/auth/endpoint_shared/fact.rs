//! Endpoint-shared fact shape.
//!
//! Endpoint-shared facts describe peer-visible endpoint identity bindings: an
//! endpoint id (X25519 public key) and its signing public key are bound to a
//! workspace and a user authority. Projection receives this payload inside a
//! signed envelope, validates the signer against device-invite or invite-server
//! authority, and then publishes signer context for content, admin, connection,
//! and auth projectors.

use crate::core::crypto::Ed25519PublicKey;
use crate::core::facts::FactId;

pub const ENDPOINT_DEVICE_NAME_BYTES: usize = 64;

pub type EndpointId = [u8; 32];
pub type WorkspaceId = FactId;
pub type UserAuthorityId = FactId;
pub type EndpointSharedId = FactId;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndpointRole {
    Device,
    InviteServer,
}

impl EndpointRole {
    pub const fn as_u8(self) -> u8 {
        match self {
            Self::Device => 1,
            Self::InviteServer => 2,
        }
    }

    pub fn from_u8(value: u8) -> Result<Self, String> {
        match value {
            1 => Ok(Self::Device),
            2 => Ok(Self::InviteServer),
            _ => Err("unknown endpoint role".to_string()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointSharedFact {
    pub created_at_ms: u64,
    pub workspace_id: WorkspaceId,
    pub user_authority_fact_id: UserAuthorityId,
    pub endpoint_id: EndpointId,
    pub signing_public_key: Ed25519PublicKey,
    pub endpoint_role: EndpointRole,
    pub device_name: String,
}
