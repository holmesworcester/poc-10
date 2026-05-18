//! Matcher vocabulary for local connection ephemeral secrets.

use crate::core::context::{ContextNeed, ContextOffer, Role, Selector};
use crate::core::facts::{FactId, FactScope};

pub const CONNECTION_EPHEMERAL_SECRET_ROLE: &str = "connection_ephemeral_secret";

pub fn connection_ephemeral_secret_role() -> Role {
    Role::new(CONNECTION_EPHEMERAL_SECRET_ROLE).expect("valid connection ephemeral secret role")
}

pub fn connection_ephemeral_secret_need(owner: FactId, secret_id: FactId) -> ContextNeed {
    ContextNeed {
        owner,
        role: connection_ephemeral_secret_role(),
        scope: FactScope::Local,
        selector: Selector::from_bytes(secret_id),
    }
}

pub fn connection_ephemeral_secret_offer(owner: FactId, secret_id: FactId) -> ContextOffer {
    ContextOffer {
        owner,
        role: connection_ephemeral_secret_role(),
        scope: FactScope::Local,
        selector: Selector::from_bytes(secret_id),
    }
}
