//! Sealed message and local context fact shapes for the poc-10 target tree.

use crate::core::facts::FactId;

pub const CIPHERTEXT_BYTES: usize = 128;

pub type WorkspaceId = FactId;
pub type FrontierId = FactId;
pub type SignerId = FactId;
pub type PublicKey = [u8; 32];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedMessageFact {
    pub workspace_id: WorkspaceId,
    pub signer_id: SignerId,
    pub frontier_id: FrontierId,
    pub minute: u64,
    pub leaf_id: FactId,
    pub ciphertext: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignerPubkeyFact {
    pub signer_id: SignerId,
    pub public_key: PublicKey,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageDeletionFact {
    pub workspace_id: WorkspaceId,
    pub target_id: FactId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretNodeFact {
    pub workspace_id: WorkspaceId,
    pub frontier_id: FrontierId,
    pub start_minute: u64,
    pub end_minute: u64,
    pub prefix_bytes: u8,
    pub leaf_prefix: FactId,
}
