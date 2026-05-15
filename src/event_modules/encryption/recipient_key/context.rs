//! Context selectors for recipient-key facts (public, local, superseded).

use super::fact::{RecipientKeyId, WorkspaceId};
use crate::core::context::{ContextNeed, ContextOffer, Role, Selector};
use crate::core::facts::{FactId, FactScope, ScopeKind};

pub fn workspace_scope(workspace_id: WorkspaceId) -> FactScope {
    FactScope::Scoped {
        kind: ScopeKind::new("workspace").expect("valid workspace scope"),
        id: workspace_id,
    }
}

pub fn recipient_key_role() -> Role {
    Role::new("recipient_key").expect("valid recipient key role")
}

pub fn recipient_superseded_role() -> Role {
    Role::new("recipient_superseded").expect("valid recipient superseded role")
}

pub fn local_recipient_key_role() -> Role {
    Role::new("local_recipient_key").expect("valid local recipient key role")
}

pub fn recipient_key_need(
    owner: FactId,
    scope: FactScope,
    recipient_key_id: RecipientKeyId,
) -> ContextNeed {
    ContextNeed {
        owner,
        role: recipient_key_role(),
        scope,
        selector: Selector::from_bytes(recipient_key_id),
    }
}

pub fn recipient_key_offer(
    owner: FactId,
    scope: FactScope,
    recipient_key_id: RecipientKeyId,
) -> ContextOffer {
    ContextOffer {
        owner,
        role: recipient_key_role(),
        scope,
        selector: Selector::from_bytes(recipient_key_id),
        payload_ref: owner,
    }
}

pub fn local_recipient_key_need(
    owner: FactId,
    scope: FactScope,
    recipient_key_id: RecipientKeyId,
) -> ContextNeed {
    ContextNeed {
        owner,
        role: local_recipient_key_role(),
        scope,
        selector: Selector::from_bytes(recipient_key_id),
    }
}

pub fn local_recipient_key_offer(
    owner: FactId,
    scope: FactScope,
    recipient_key_id: RecipientKeyId,
) -> ContextOffer {
    ContextOffer {
        owner,
        role: local_recipient_key_role(),
        scope,
        selector: Selector::from_bytes(recipient_key_id),
        payload_ref: owner,
    }
}

pub fn recipient_superseded_need(
    owner: FactId,
    scope: FactScope,
    recipient_key_id: RecipientKeyId,
) -> ContextNeed {
    ContextNeed {
        owner,
        role: recipient_superseded_role(),
        scope,
        selector: Selector::from_bytes(recipient_key_id),
    }
}

pub fn recipient_superseded_offer(
    owner: FactId,
    scope: FactScope,
    recipient_key_id: RecipientKeyId,
) -> ContextOffer {
    ContextOffer {
        owner,
        role: recipient_superseded_role(),
        scope,
        selector: Selector::from_bytes(recipient_key_id),
        payload_ref: owner,
    }
}
