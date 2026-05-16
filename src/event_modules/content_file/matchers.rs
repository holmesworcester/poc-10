//! Context selectors for content-file descriptor availability.

use crate::core::context::{ContextNeed, ContextOffer, Role, Selector};
use crate::core::facts::{FactId, FactScope};

pub fn file_role() -> Role {
    Role::new("content_file").expect("valid content file role")
}

pub fn file_need(owner: FactId, scope: FactScope, file_id: FactId) -> ContextNeed {
    ContextNeed {
        owner,
        role: file_role(),
        scope,
        selector: Selector::from_bytes(file_id),
    }
}

pub fn file_offer(owner: FactId, scope: FactScope, file_id: FactId) -> ContextOffer {
    ContextOffer {
        owner,
        role: file_role(),
        scope,
        selector: Selector::from_bytes(file_id),
        payload_ref: owner,
    }
}
