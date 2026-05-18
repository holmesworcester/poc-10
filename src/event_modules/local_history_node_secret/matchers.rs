//! Matcher vocabulary for local history secret source material.
//!
//! A local root secret or local history node can serve as the source material
//! for a later history node. The relationship is exact and local: peers cannot
//! satisfy it through sync, and the projector still validates that the payload
//! is the right key-material shape before materializing the child node.

use crate::core::context::{ContextNeed, ContextOffer, Role, Selector};
use crate::core::facts::{FactId, FactScope};

pub fn source_secret_role() -> Role {
    Role::new("local_secret_source").expect("valid local secret source role")
}

pub fn source_secret_need(owner: FactId, source_secret_id: FactId) -> ContextNeed {
    ContextNeed {
        owner,
        role: source_secret_role(),
        scope: FactScope::Local,
        selector: Selector::from_bytes(source_secret_id),
    }
}

pub fn source_secret_offer(owner: FactId, source_secret_id: FactId) -> ContextOffer {
    ContextOffer {
        owner,
        role: source_secret_role(),
        scope: FactScope::Local,
        selector: Selector::from_bytes(source_secret_id),
    }
}
