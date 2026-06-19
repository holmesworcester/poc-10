//! Key-wrap recovery fact shape.
//!
//! The fact is a local instruction to recover the secret carried by one
//! accepted key wrap using one local recipient key.

use crate::core::facts::FactId;

pub type WorkspaceId = FactId;
pub type FrontierId = FactId;
pub type RecipientKeyId = FactId;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyWrapRecoveryFact {
    pub workspace_id: WorkspaceId,
    pub frontier_id: FrontierId,
    pub recipient_key_id: RecipientKeyId,
    pub key_wrap_id: FactId,
    pub local_recipient_key_id: FactId,
}
