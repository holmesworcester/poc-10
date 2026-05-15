//! Context selectors for local signing capability.

use crate::core::context::{ContextNeed, ContextOffer, Role, Selector};
use crate::core::facts::{FactId, FactScope};

use super::fact::SignerId;

pub fn local_signer_secret_role() -> Role {
    Role::new("local_signer_secret").expect("valid local signer secret role")
}

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
        payload_ref: owner,
    }
}
