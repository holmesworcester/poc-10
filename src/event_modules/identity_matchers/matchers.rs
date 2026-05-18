//! Context roles shared by target identity projectors.
//!
//! These roles model validated identity facts, not raw dependency presence.
//! A projector emits an offer only after it has decoded the fact, checked its
//! scope, and enforced the authority context currently available in the target
//! tree.

use crate::core::context::{ContextNeed, ContextOffer, Role, Selector};
use crate::core::facts::{FactId, FactScope, ScopeKind};

pub fn workspace_scope(workspace_id: FactId) -> FactScope {
    FactScope::Scoped {
        kind: ScopeKind::new("workspace").expect("valid identity workspace scope"),
        id: workspace_id,
    }
}

pub fn workspace_role() -> Role {
    Role::new("identity_workspace").expect("valid identity workspace role")
}

pub fn invite_secret_role() -> Role {
    Role::new("identity_invite_secret").expect("valid identity invite secret role")
}

pub fn user_invite_role() -> Role {
    Role::new("identity_user_invite").expect("valid identity user invite role")
}

pub fn user_invite_key_role() -> Role {
    Role::new("identity_user_invite_key").expect("valid identity user invite key role")
}

pub fn invite_server_role() -> Role {
    Role::new("identity_invite_server").expect("valid identity invite server role")
}

pub fn invite_server_key_role() -> Role {
    Role::new("identity_invite_server_key").expect("valid identity invite server key role")
}

pub fn user_role() -> Role {
    Role::new("identity_user").expect("valid identity user role")
}

pub fn device_invite_role() -> Role {
    Role::new("identity_device_invite").expect("valid identity device invite role")
}

pub fn device_invite_key_role() -> Role {
    Role::new("identity_device_invite_key").expect("valid identity device invite key role")
}

pub fn endpoint_shared_role() -> Role {
    Role::new("identity_endpoint_shared").expect("valid identity endpoint shared role")
}

pub fn admin_role() -> Role {
    Role::new("identity_admin").expect("valid identity admin role")
}

pub fn exact_need(owner: FactId, role: Role, id: FactId) -> ContextNeed {
    ContextNeed {
        owner,
        role,
        scope: FactScope::Global,
        selector: Selector::from_bytes(id),
    }
}

pub fn exact_offer(owner: FactId, role: Role) -> ContextOffer {
    ContextOffer {
        owner,
        role,
        scope: FactScope::Global,
        selector: Selector::from_bytes(owner),
    }
}

pub fn workspace_offer(owner: FactId) -> ContextOffer {
    exact_offer(owner, workspace_role())
}

pub fn invite_secret_offer(owner: FactId) -> ContextOffer {
    exact_offer(owner, invite_secret_role())
}

pub fn user_invite_offer(owner: FactId) -> ContextOffer {
    exact_offer(owner, user_invite_role())
}

pub fn invite_server_offer(owner: FactId) -> ContextOffer {
    exact_offer(owner, invite_server_role())
}

pub fn scoped_key_need(
    owner: FactId,
    role: Role,
    workspace_id: FactId,
    selector: Vec<u8>,
) -> ContextNeed {
    ContextNeed {
        owner,
        role,
        scope: workspace_scope(workspace_id),
        selector: Selector::from_bytes(selector),
    }
}

pub fn scoped_key_offer(
    owner: FactId,
    role: Role,
    workspace_id: FactId,
    selector: Vec<u8>,
) -> ContextOffer {
    ContextOffer {
        owner,
        role,
        scope: workspace_scope(workspace_id),
        selector: Selector::from_bytes(selector),
    }
}

pub fn user_invite_key_offer(
    owner: FactId,
    workspace_id: FactId,
    public_key: [u8; 32],
) -> ContextOffer {
    scoped_key_offer(
        owner,
        user_invite_key_role(),
        workspace_id,
        public_key.to_vec(),
    )
}

pub fn invite_server_key_offer(
    owner: FactId,
    workspace_id: FactId,
    public_key: [u8; 32],
) -> ContextOffer {
    scoped_key_offer(
        owner,
        invite_server_key_role(),
        workspace_id,
        public_key.to_vec(),
    )
}

pub fn device_invite_key(user_authority_event_id: FactId, public_key: [u8; 32]) -> Vec<u8> {
    let mut key = Vec::with_capacity(64);
    key.extend_from_slice(&user_authority_event_id);
    key.extend_from_slice(&public_key);
    key
}
