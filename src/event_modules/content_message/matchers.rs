//! Context selectors for content-message availability.
//!
//! A fact that refers to a message should not decide that the message exists
//! by querying a table. It declares a stable need for the message fact. The
//! content-message projector offers that fact after its own projection
//! validates and applies.

use crate::core::context::{ContextNeed, ContextOffer, Role, Selector};
use crate::core::facts::{FactId, FactScope, ScopeKind};

use super::fact::WorkspaceId;

pub fn message_role() -> Role {
    Role::new("content_message").expect("valid content message role")
}

pub fn deletion_role() -> Role {
    Role::new("content_deleted").expect("valid content deletion role")
}

pub fn workspace_scope(workspace_id: WorkspaceId) -> FactScope {
    FactScope::Scoped {
        kind: ScopeKind::new("workspace").expect("valid workspace scope"),
        id: workspace_id,
    }
}

pub fn message_need(owner: FactId, scope: FactScope, message_id: FactId) -> ContextNeed {
    ContextNeed {
        owner,
        role: message_role(),
        scope,
        selector: Selector::from_bytes(message_id),
    }
}

pub fn message_offer(owner: FactId, scope: FactScope, message_id: FactId) -> ContextOffer {
    ContextOffer {
        owner,
        role: message_role(),
        scope,
        selector: Selector::from_bytes(message_id),
    }
}

pub fn deletion_need(
    owner: FactId,
    scope: FactScope,
    target_id: FactId,
    author_user_id: FactId,
) -> ContextNeed {
    ContextNeed {
        owner,
        role: deletion_role(),
        scope,
        selector: deletion_selector(target_id, author_user_id),
    }
}

pub fn deletion_offer(
    owner: FactId,
    scope: FactScope,
    target_id: FactId,
    author_user_id: FactId,
) -> ContextOffer {
    ContextOffer {
        owner,
        role: deletion_role(),
        scope,
        selector: deletion_selector(target_id, author_user_id),
    }
}

pub fn deletion_selector(target_id: FactId, author_user_id: FactId) -> Selector {
    let mut bytes = Vec::with_capacity(64);
    bytes.extend_from_slice(&target_id);
    bytes.extend_from_slice(&author_user_id);
    Selector::from_bytes(bytes)
}
