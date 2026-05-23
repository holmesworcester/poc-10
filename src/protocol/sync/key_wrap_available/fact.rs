//! Sync fact shape for saying a key wrap is available to a peer.
//!
//! This is a compact convergence signal. It lets sync advertise that a specific
//! key-wrap fact can be requested for a workspace without duplicating the wrap
//! payload here. The fact carries identifiers only; validation of the signed
//! wrap and its recipient remains in the auth modules.

use crate::core::facts::FactId;

pub type WorkspaceId = FactId;
pub type KeyWrapId = FactId;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyWrapAvailableFact {
    pub workspace_id: WorkspaceId,
    pub key_wrap_id: KeyWrapId,
}
