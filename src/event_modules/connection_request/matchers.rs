//! Matcher vocabulary for connection bootstrap requests.

use crate::core::context::{ContextNeed, ContextOffer, Role, Selector};
use crate::core::facts::{FactId, FactScope};

pub const CONNECTION_INVITE_SECRET_ROLE: &str = "connection_invite_secret";
pub const CONNECTION_REQUEST_ROLE: &str = "connection_request";

pub fn connection_invite_secret_role() -> Role {
    Role::new(CONNECTION_INVITE_SECRET_ROLE).expect("valid connection invite secret role")
}

pub fn connection_request_role() -> Role {
    Role::new(CONNECTION_REQUEST_ROLE).expect("valid connection request role")
}

pub fn invite_secret_need(owner: FactId, invite_secret_id: FactId) -> ContextNeed {
    ContextNeed {
        owner,
        role: connection_invite_secret_role(),
        scope: FactScope::Local,
        selector: Selector::from_bytes(invite_secret_id),
    }
}

pub fn invite_secret_offer(owner: FactId, invite_secret_id: FactId) -> ContextOffer {
    ContextOffer {
        owner,
        role: connection_invite_secret_role(),
        scope: FactScope::Local,
        selector: Selector::from_bytes(invite_secret_id),
    }
}

pub fn connection_request_need(owner: FactId, request_id: FactId) -> ContextNeed {
    ContextNeed {
        owner,
        role: connection_request_role(),
        scope: FactScope::Global,
        selector: Selector::from_bytes(request_id),
    }
}

pub fn connection_request_offer(owner: FactId, request_id: FactId) -> ContextOffer {
    ContextOffer {
        owner,
        role: connection_request_role(),
        scope: FactScope::Global,
        selector: Selector::from_bytes(request_id),
    }
}
