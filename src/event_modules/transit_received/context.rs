//! Context offer helpers for transit receive provenance.

use crate::core::context::{ContextNeed, ContextOffer, Role, Selector};
use crate::core::facts::{FactId, FactScope};

pub fn transit_received_role() -> Role {
    Role::new("transit_received").expect("valid transit received role")
}

pub fn transit_received_need(owner: FactId, received_fact_id: FactId) -> ContextNeed {
    ContextNeed {
        owner,
        role: transit_received_role(),
        scope: FactScope::Local,
        selector: Selector::from_bytes(received_fact_id),
    }
}

pub fn transit_received_offer(owner: FactId, received_fact_id: FactId) -> ContextOffer {
    ContextOffer {
        owner,
        role: transit_received_role(),
        scope: FactScope::Local,
        selector: Selector::from_bytes(received_fact_id),
        payload_ref: owner,
    }
}
