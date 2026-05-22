//! Sync fact shape for advertising an encrypted root dependency.
//!
//! `EncryptedRootFact` ties a workspace fact id to the dependency and key wrap
//! needed before that fact can be opened by a peer. The sync layer uses this as
//! routing metadata; it does not interpret encrypted payloads or decide who is
//! authorized to decrypt them. Those responsibilities stay in encryption facts
//! and context projection.

use crate::core::facts::FactId;

pub type WorkspaceId = FactId;
pub type KeyWrapId = FactId;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncryptedRootFact {
    pub workspace_id: WorkspaceId,
    pub fact_id: FactId,
    pub dependency_id: FactId,
    pub key_wrap_id: KeyWrapId,
}
