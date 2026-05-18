//! Context selectors for local signing capability.
//!
//! The offer is local by construction even though the match scope is the
//! workspace. That split matters: commands may ask "can this workspace sign?"
//! without learning or syncing a private key. The payload ref remains the local
//! secret fact that a command or handler must explicitly load through its own
//! capability boundary.

use crate::core::context::{ContextNeed, ContextOffer, Role, Selector};
use crate::core::facts::{FactId, FactScope};

use super::fact::SignerId;

pub fn local_signer_secret_role() -> Role {
    Role::new("local_signer_secret").expect("valid local signer secret role")
}

/// Need one local signer secret for a concrete workspace signer id.
///
/// This is intentionally exact matching. A broader "any signer in workspace"
/// selector would let commands choose authority that identity has not selected
/// for the proposed event.
pub fn local_signer_secret_need(
    owner: FactId,
    scope: FactScope,
    signer_id: SignerId,
) -> ContextNeed {
    ContextNeed {
        owner,
        role: local_signer_secret_role(),
        scope,
        selector: Selector::from_bytes(signer_id),
    }
}

pub fn local_signer_secret_offer(
    owner: FactId,
    scope: FactScope,
    signer_id: SignerId,
) -> ContextOffer {
    ContextOffer {
        owner,
        role: local_signer_secret_role(),
        scope,
        selector: Selector::from_bytes(signer_id),
    }
}
