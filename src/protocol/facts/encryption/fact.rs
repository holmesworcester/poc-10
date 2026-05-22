//! Shared encryption fact shapes for key healing and wrap materialization.
//!
//! Encryption facts describe three related things: who can receive wrapped
//! material, which removal frontier owns a key tree, and which local secrets or
//! signed wraps make encrypted history recoverable. These are protocol payload
//! structs, not persistence rows. Layout code fixes their wire shape, projectors
//! validate their context, and intent handlers derive new facts from them.
//!
//! Keep field-level protocol meaning here. If a new encryption record changes
//! the state machine, add the shape and projection payload variant here, then
//! teach layout, projection, and intent handlers how it is admitted.

use crate::core::crypto::{
    X25519PrivateKey, X25519PublicKey, XChaCha20Poly1305Key, XChaCha20Poly1305Nonce,
};
use crate::core::facts::FactId;

pub type WorkspaceId = FactId;
pub type FrontierId = FactId;
pub type EndpointId = FactId;
pub type RecipientKeyId = FactId;

pub const NO_PREVIOUS_RECIPIENT_KEY: FactId = [0; 32];
pub const KEY_WRAP_CIPHERTEXT_BYTES: usize = 48;

pub type KeyWrapCiphertext = [u8; KEY_WRAP_CIPHERTEXT_BYTES];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WrappedSecretKind {
    FrontierRoot,
    HistoryNode,
}

impl WrappedSecretKind {
    pub fn as_u8(self) -> u8 {
        match self {
            WrappedSecretKind::FrontierRoot => 0,
            WrappedSecretKind::HistoryNode => 1,
        }
    }

    pub fn from_u8(value: u8) -> Result<Self, String> {
        match value {
            0 => Ok(WrappedSecretKind::FrontierRoot),
            1 => Ok(WrappedSecretKind::HistoryNode),
            _ => Err("unknown wrapped secret kind".to_string()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecipientKeyFact {
    pub workspace_id: WorkspaceId,
    pub endpoint_id: EndpointId,
    pub recipient_key: FactId,
    pub previous_recipient_key_id: FactId,
    pub created_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalRecipientKeyFact {
    pub workspace_id: WorkspaceId,
    pub recipient_key_id: RecipientKeyId,
    pub recipient_key: X25519PublicKey,
    pub recipient_secret: X25519PrivateKey,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemovalFrontierFact {
    pub workspace_id: WorkspaceId,
    pub owner_endpoint_id: EndpointId,
    pub created_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalKeySecretFact {
    pub workspace_id: WorkspaceId,
    pub frontier_id: FrontierId,
    pub owner_endpoint_id: EndpointId,
    pub created_at_ms: u64,
    pub key_secret: XChaCha20Poly1305Key,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalHistoryNodeSecretFact {
    pub workspace_id: WorkspaceId,
    pub frontier_id: FrontierId,
    pub owner_endpoint_id: EndpointId,
    pub source_secret_id: FactId,
    pub range_start: u64,
    pub range_width: u64,
    pub bit_depth: u16,
    pub fact_id_prefix: FactId,
    pub tombstone_node_id: FactId,
    pub node_secret: XChaCha20Poly1305Key,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyRequestFact {
    pub workspace_id: WorkspaceId,
    pub requester_endpoint_id: EndpointId,
    pub responder_endpoint_id: EndpointId,
    pub frontier_id: FrontierId,
    pub recipient_key_id: RecipientKeyId,
    pub created_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyWrapFact {
    pub workspace_id: WorkspaceId,
    pub created_at_ms: u64,
    pub signer_endpoint_id: EndpointId,
    pub frontier_id: FrontierId,
    pub wrapped_secret_kind: WrappedSecretKind,
    pub wrapped_secret_id: FactId,
    pub wrapped_source_secret_id: FactId,
    pub wrapped_tombstone_node_id: FactId,
    pub range_start: u64,
    pub range_width: u64,
    pub bit_depth: u16,
    pub fact_id_prefix: FactId,
    pub recipient_key_id: RecipientKeyId,
    pub sender_wrap_public_key: X25519PublicKey,
    pub nonce: XChaCha20Poly1305Nonce,
    pub ciphertext: KeyWrapCiphertext,
}

pub enum ProjectionPayload {
    RecipientKey(RecipientKeyFact),
    RemovalFrontier(RemovalFrontierFact),
    LocalKeySecret(LocalKeySecretFact),
    LocalHistoryNodeSecret(LocalHistoryNodeSecretFact),
    LocalRecipientKey(LocalRecipientKeyFact),
    KeyRequest(KeyRequestFact),
    SignedKeyWrap(crate::protocol::facts::identity::signed_fact::SignedPayload<KeyWrapFact>),
}

pub(crate) struct Codec;

impl crate::core::projectors::FactCodec for Codec {
    type Payload = ProjectionPayload;

    fn decode_fact(fact: &crate::core::facts::Fact) -> Result<Self::Payload, String> {
        match fact.bytes.first().copied() {
            Some(super::layout::TYPE_RECIPIENT_KEY) => {
                super::layout::decode_recipient_key(fact.body())
                    .map(ProjectionPayload::RecipientKey)
            }
            Some(super::layout::TYPE_REMOVAL_FRONTIER) => {
                super::layout::decode_removal_frontier(fact.body())
                    .map(ProjectionPayload::RemovalFrontier)
            }
            Some(super::layout::TYPE_LOCAL_KEY_SECRET) => {
                super::layout::decode_local_key_secret(fact.body())
                    .map(ProjectionPayload::LocalKeySecret)
            }
            Some(super::layout::TYPE_LOCAL_HISTORY_NODE_SECRET) => {
                super::layout::decode_local_history_node_secret(fact.body())
                    .map(ProjectionPayload::LocalHistoryNodeSecret)
            }
            Some(super::layout::TYPE_LOCAL_RECIPIENT_KEY) => {
                super::layout::decode_local_recipient_key(fact.body())
                    .map(ProjectionPayload::LocalRecipientKey)
            }
            Some(super::layout::TYPE_KEY_REQUEST) => {
                super::layout::decode_key_request(fact.body()).map(ProjectionPayload::KeyRequest)
            }
            Some(crate::protocol::facts::identity::signed_fact::TYPE_SIGNED_FACT) => {
                crate::protocol::facts::identity::signed_fact::decode_signed_fact_payload(
                    fact,
                    super::layout::TYPE_KEY_WRAP,
                    "encryption key wrap",
                    super::layout::decode_key_wrap,
                )
                .map(ProjectionPayload::SignedKeyWrap)
            }
            _ => Err("unknown encryption fact type".to_string()),
        }
    }
}
