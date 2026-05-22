//! Context range vocabulary for the concrete protocol.
//!
//! Most protocol relationships still match one exact byte key. They are encoded
//! as degenerate ranges where `start_key == end_key`; broader relations use the
//! same core-owned overlap query with protocol-owned byte layouts.

use crate::core::context::{ContextKey, ContextNeed, ContextOffer, Role};
use crate::core::facts::{FactId, FactScope, ScopeKind};

pub const CONNECTION_EPHEMERAL_SECRET_ROLE: &str = "connection_ephemeral_secret";
pub const CONNECTION_INVITE_SECRET_ROLE: &str = "connection_invite_secret";
pub const CONNECTION_REQUEST_ROLE: &str = "connection_request";
pub const CONTENT_FILE_ROLE: &str = "content_file";
pub const CONTENT_MESSAGE_ROLE: &str = "content_message";
pub const CONTENT_MESSAGE_META_ROLE: &str = "content_message_meta";
pub const CONTENT_DELETED_ROLE: &str = "content_deleted";
pub const IDENTITY_ADMIN_ROLE: &str = "identity_admin";
pub const IDENTITY_DEVICE_INVITE_ROLE: &str = "identity_device_invite";
pub const IDENTITY_DEVICE_INVITE_KEY_ROLE: &str = "identity_device_invite_key";
pub const IDENTITY_ENDPOINT_SHARED_ROLE: &str = "identity_endpoint_shared";
pub const IDENTITY_INVITE_SECRET_ROLE: &str = "identity_invite_secret";
pub const IDENTITY_INVITE_SERVER_ROLE: &str = "identity_invite_server";
pub const IDENTITY_INVITE_SERVER_KEY_ROLE: &str = "identity_invite_server_key";
pub const IDENTITY_USER_ROLE: &str = "identity_user";
pub const IDENTITY_USER_INVITE_ROLE: &str = "identity_user_invite";
pub const IDENTITY_USER_INVITE_KEY_ROLE: &str = "identity_user_invite_key";
pub const IDENTITY_WORKSPACE_ROLE: &str = "identity_workspace";
pub const LOCAL_RECIPIENT_KEY_ROLE: &str = "local_recipient_key";
pub const LOCAL_SECRET_SOURCE_ROLE: &str = "local_secret_source";
pub const LOCAL_SIGNER_SECRET_ROLE: &str = "local_signer_secret";
pub const RECIPIENT_KEY_ROLE: &str = "recipient_key";
pub const RECIPIENT_SUPERSEDED_ROLE: &str = "recipient_superseded";
pub const REMOVAL_FRONTIER_ROLE: &str = "encryption_removal_frontier";
pub const CONTENT_SIGNER_ROLE: &str = "content_signer";
pub const SYNC_EXACT_FACT_ROLE: &str = "sync_exact_fact";
pub const SYNC_KEY_WRAP_ROLE: &str = "sync_key_wrap";
pub const TRANSIT_RECEIVED_ROLE: &str = "transport_transit_received";

pub fn protocol_role(name: &'static str) -> Role {
    Role::new(name).expect("valid protocol context role")
}

pub fn workspace_scope(workspace_id: FactId) -> FactScope {
    FactScope::Scoped {
        kind: ScopeKind::new("workspace").expect("valid workspace scope"),
        id: workspace_id,
    }
}

pub fn exact_need_for_key(
    owner: FactId,
    role: Role,
    scope: FactScope,
    key: impl Into<Vec<u8>>,
) -> ContextNeed {
    let key = key.into();
    ContextNeed {
        owner,
        role,
        scope,
        start_key: ContextKey::from_bytes(key.clone()),
        end_key: ContextKey::from_bytes(key),
    }
}

pub fn exact_offer_for_key(
    owner: FactId,
    role: Role,
    scope: FactScope,
    key: impl Into<Vec<u8>>,
) -> ContextOffer {
    let key = key.into();
    ContextOffer {
        owner,
        role,
        scope,
        start_key: ContextKey::from_bytes(key.clone()),
        end_key: ContextKey::from_bytes(key),
    }
}

pub fn range_need_for_key_range(
    owner: FactId,
    role: Role,
    scope: FactScope,
    start_key: impl Into<Vec<u8>>,
    end_key: impl Into<Vec<u8>>,
) -> ContextNeed {
    ContextNeed {
        owner,
        role,
        scope,
        start_key: ContextKey::from_bytes(start_key),
        end_key: ContextKey::from_bytes(end_key),
    }
}

pub fn range_offer_for_key_range(
    owner: FactId,
    role: Role,
    scope: FactScope,
    start_key: impl Into<Vec<u8>>,
    end_key: impl Into<Vec<u8>>,
) -> ContextOffer {
    ContextOffer {
        owner,
        role,
        scope,
        start_key: ContextKey::from_bytes(start_key),
        end_key: ContextKey::from_bytes(end_key),
    }
}

pub fn exact_need(owner: FactId, role: Role, id: FactId) -> ContextNeed {
    exact_need_for_key(owner, role, FactScope::Global, id)
}

pub fn exact_offer(owner: FactId, role: Role) -> ContextOffer {
    exact_offer_for_key(owner, role, FactScope::Global, owner)
}

pub fn connection_ephemeral_secret_role() -> Role {
    protocol_role(CONNECTION_EPHEMERAL_SECRET_ROLE)
}

pub fn connection_ephemeral_secret_need(owner: FactId, secret_id: FactId) -> ContextNeed {
    exact_need_for_key(
        owner,
        connection_ephemeral_secret_role(),
        FactScope::Local,
        secret_id,
    )
}

pub fn connection_ephemeral_secret_offer(owner: FactId, secret_id: FactId) -> ContextOffer {
    exact_offer_for_key(
        owner,
        connection_ephemeral_secret_role(),
        FactScope::Local,
        secret_id,
    )
}

pub fn connection_invite_secret_role() -> Role {
    protocol_role(CONNECTION_INVITE_SECRET_ROLE)
}

pub fn connection_invite_secret_need(owner: FactId, invite_secret_id: FactId) -> ContextNeed {
    exact_need_for_key(
        owner,
        connection_invite_secret_role(),
        FactScope::Local,
        invite_secret_id,
    )
}

pub fn connection_invite_secret_offer(owner: FactId, invite_secret_id: FactId) -> ContextOffer {
    exact_offer_for_key(
        owner,
        connection_invite_secret_role(),
        FactScope::Local,
        invite_secret_id,
    )
}

pub fn connection_request_role() -> Role {
    protocol_role(CONNECTION_REQUEST_ROLE)
}

pub fn connection_request_need(owner: FactId, request_id: FactId) -> ContextNeed {
    exact_need_for_key(
        owner,
        connection_request_role(),
        FactScope::Global,
        request_id,
    )
}

pub fn connection_request_offer(owner: FactId, request_id: FactId) -> ContextOffer {
    exact_offer_for_key(
        owner,
        connection_request_role(),
        FactScope::Global,
        request_id,
    )
}

pub fn file_role() -> Role {
    protocol_role(CONTENT_FILE_ROLE)
}

pub fn file_need(owner: FactId, scope: FactScope, file_id: FactId) -> ContextNeed {
    exact_need_for_key(owner, file_role(), scope, file_id)
}

pub fn file_offer(owner: FactId, scope: FactScope, file_id: FactId) -> ContextOffer {
    exact_offer_for_key(owner, file_role(), scope, file_id)
}

pub fn message_role() -> Role {
    protocol_role(CONTENT_MESSAGE_ROLE)
}

pub fn message_need(owner: FactId, scope: FactScope, message_id: FactId) -> ContextNeed {
    exact_need_for_key(owner, message_role(), scope, message_id)
}

pub fn message_offer(owner: FactId, scope: FactScope, message_id: FactId) -> ContextOffer {
    exact_offer_for_key(owner, message_role(), scope, message_id)
}

pub fn message_meta_role() -> Role {
    protocol_role(CONTENT_MESSAGE_META_ROLE)
}

pub fn message_meta_need(owner: FactId, scope: FactScope, message_id: FactId) -> ContextNeed {
    exact_need_for_key(owner, message_meta_role(), scope, message_id)
}

pub fn message_meta_offer(owner: FactId, scope: FactScope, message_id: FactId) -> ContextOffer {
    exact_offer_for_key(owner, message_meta_role(), scope, message_id)
}

pub fn deletion_role() -> Role {
    protocol_role(CONTENT_DELETED_ROLE)
}

pub fn deletion_need(
    owner: FactId,
    scope: FactScope,
    target_id: FactId,
    author_user_id: FactId,
) -> ContextNeed {
    exact_need_for_key(
        owner,
        deletion_role(),
        scope,
        deletion_key(target_id, author_user_id).as_bytes().to_vec(),
    )
}

pub fn deletion_offer(
    owner: FactId,
    scope: FactScope,
    target_id: FactId,
    author_user_id: FactId,
) -> ContextOffer {
    exact_offer_for_key(
        owner,
        deletion_role(),
        scope,
        deletion_key(target_id, author_user_id).as_bytes().to_vec(),
    )
}

pub fn deletion_key(target_id: FactId, author_user_id: FactId) -> ContextKey {
    let mut bytes = Vec::with_capacity(64);
    bytes.extend_from_slice(&target_id);
    bytes.extend_from_slice(&author_user_id);
    ContextKey::from_bytes(bytes)
}

pub fn workspace_role() -> Role {
    protocol_role(IDENTITY_WORKSPACE_ROLE)
}

pub fn invite_secret_role() -> Role {
    protocol_role(IDENTITY_INVITE_SECRET_ROLE)
}

pub fn user_invite_role() -> Role {
    protocol_role(IDENTITY_USER_INVITE_ROLE)
}

pub fn user_invite_key_role() -> Role {
    protocol_role(IDENTITY_USER_INVITE_KEY_ROLE)
}

pub fn invite_server_role() -> Role {
    protocol_role(IDENTITY_INVITE_SERVER_ROLE)
}

pub fn invite_server_key_role() -> Role {
    protocol_role(IDENTITY_INVITE_SERVER_KEY_ROLE)
}

pub fn user_role() -> Role {
    protocol_role(IDENTITY_USER_ROLE)
}

pub fn device_invite_role() -> Role {
    protocol_role(IDENTITY_DEVICE_INVITE_ROLE)
}

pub fn device_invite_key_role() -> Role {
    protocol_role(IDENTITY_DEVICE_INVITE_KEY_ROLE)
}

pub fn endpoint_shared_role() -> Role {
    protocol_role(IDENTITY_ENDPOINT_SHARED_ROLE)
}

pub fn admin_role() -> Role {
    protocol_role(IDENTITY_ADMIN_ROLE)
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
    key: Vec<u8>,
) -> ContextNeed {
    exact_need_for_key(owner, role, workspace_scope(workspace_id), key)
}

pub fn scoped_key_offer(
    owner: FactId,
    role: Role,
    workspace_id: FactId,
    key: Vec<u8>,
) -> ContextOffer {
    exact_offer_for_key(owner, role, workspace_scope(workspace_id), key)
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

pub fn device_invite_key(user_authority_fact_id: FactId, public_key: [u8; 32]) -> Vec<u8> {
    let mut key = Vec::with_capacity(64);
    key.extend_from_slice(&user_authority_fact_id);
    key.extend_from_slice(&public_key);
    key
}

pub fn source_secret_role() -> Role {
    protocol_role(LOCAL_SECRET_SOURCE_ROLE)
}

pub fn source_secret_need(owner: FactId, source_secret_id: FactId) -> ContextNeed {
    exact_need_for_key(
        owner,
        source_secret_role(),
        FactScope::Local,
        source_secret_id,
    )
}

pub fn source_secret_offer(owner: FactId, source_secret_id: FactId) -> ContextOffer {
    exact_offer_for_key(
        owner,
        source_secret_role(),
        FactScope::Local,
        source_secret_id,
    )
}

pub fn local_signer_secret_role() -> Role {
    protocol_role(LOCAL_SIGNER_SECRET_ROLE)
}

pub fn local_signer_secret_need(owner: FactId, scope: FactScope, signer_id: FactId) -> ContextNeed {
    exact_need_for_key(owner, local_signer_secret_role(), scope, signer_id)
}

pub fn local_signer_secret_offer(
    owner: FactId,
    scope: FactScope,
    signer_id: FactId,
) -> ContextOffer {
    exact_offer_for_key(owner, local_signer_secret_role(), scope, signer_id)
}

pub fn transit_received_role() -> Role {
    protocol_role(TRANSIT_RECEIVED_ROLE)
}

pub fn transit_received_need(owner: FactId, received_fact_id: FactId) -> ContextNeed {
    exact_need_for_key(
        owner,
        transit_received_role(),
        FactScope::Local,
        received_fact_id,
    )
}

pub fn transit_received_offer(owner: FactId, received_fact_id: FactId) -> ContextOffer {
    exact_offer_for_key(
        owner,
        transit_received_role(),
        FactScope::Local,
        received_fact_id,
    )
}

pub fn recipient_key_role() -> Role {
    protocol_role(RECIPIENT_KEY_ROLE)
}

pub fn recipient_key_need(
    owner: FactId,
    scope: FactScope,
    recipient_key_id: FactId,
) -> ContextNeed {
    exact_need_for_key(owner, recipient_key_role(), scope, recipient_key_id)
}

pub fn recipient_key_offer(
    owner: FactId,
    scope: FactScope,
    recipient_key_id: FactId,
) -> ContextOffer {
    exact_offer_for_key(owner, recipient_key_role(), scope, recipient_key_id)
}

pub fn local_recipient_key_role() -> Role {
    protocol_role(LOCAL_RECIPIENT_KEY_ROLE)
}

pub fn local_recipient_key_need(
    owner: FactId,
    scope: FactScope,
    recipient_key_id: FactId,
) -> ContextNeed {
    exact_need_for_key(owner, local_recipient_key_role(), scope, recipient_key_id)
}

pub fn local_recipient_key_offer(
    owner: FactId,
    scope: FactScope,
    recipient_key_id: FactId,
) -> ContextOffer {
    exact_offer_for_key(owner, local_recipient_key_role(), scope, recipient_key_id)
}

pub fn frontier_role() -> Role {
    protocol_role(REMOVAL_FRONTIER_ROLE)
}

pub fn frontier_need(owner: FactId, scope: FactScope, frontier_id: FactId) -> ContextNeed {
    exact_need_for_key(owner, frontier_role(), scope, frontier_id)
}

pub fn frontier_offer(owner: FactId, scope: FactScope, frontier_id: FactId) -> ContextOffer {
    exact_offer_for_key(owner, frontier_role(), scope, frontier_id)
}

pub fn recipient_superseded_role() -> Role {
    protocol_role(RECIPIENT_SUPERSEDED_ROLE)
}

pub fn recipient_superseded_need(
    owner: FactId,
    scope: FactScope,
    recipient_key_id: FactId,
) -> ContextNeed {
    exact_need_for_key(owner, recipient_superseded_role(), scope, recipient_key_id)
}

pub fn recipient_superseded_offer(
    owner: FactId,
    scope: FactScope,
    recipient_key_id: FactId,
) -> ContextOffer {
    exact_offer_for_key(owner, recipient_superseded_role(), scope, recipient_key_id)
}

pub fn signer_role() -> Role {
    protocol_role(CONTENT_SIGNER_ROLE)
}

pub fn signer_need(owner: FactId, scope: FactScope, signer_id: FactId) -> ContextNeed {
    exact_need_for_key(owner, signer_role(), scope, signer_id)
}

pub fn signer_offer(owner: FactId, scope: FactScope, signer_id: FactId) -> ContextOffer {
    exact_offer_for_key(owner, signer_role(), scope, signer_id)
}

pub fn exact_fact_role() -> Role {
    protocol_role(SYNC_EXACT_FACT_ROLE)
}

pub fn exact_fact_need(owner: FactId, scope: FactScope, fact_id: FactId) -> ContextNeed {
    exact_need_for_key(owner, exact_fact_role(), scope, fact_id)
}

pub fn exact_fact_offer(owner: FactId, scope: FactScope, fact_id: FactId) -> ContextOffer {
    exact_offer_for_key(owner, exact_fact_role(), scope, fact_id)
}

pub fn key_wrap_role() -> Role {
    protocol_role(SYNC_KEY_WRAP_ROLE)
}

pub fn key_wrap_need(owner: FactId, scope: FactScope, key_wrap_id: FactId) -> ContextNeed {
    exact_need_for_key(owner, key_wrap_role(), scope, key_wrap_id)
}

pub fn key_wrap_offer(owner: FactId, scope: FactScope, key_wrap_id: FactId) -> ContextOffer {
    exact_offer_for_key(owner, key_wrap_role(), scope, key_wrap_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_helpers_encode_only_role_scope_key_and_owner() {
        let owner = [1; 32];
        let scope = workspace_scope([2; 32]);
        let need = exact_fact_need(owner, scope.clone(), [3; 32]);
        let offer = exact_fact_offer([4; 32], scope.clone(), [3; 32]);

        assert_eq!(need.role, exact_fact_role());
        assert_eq!(offer.role, exact_fact_role());
        assert_eq!(need.scope, scope);
        assert_eq!(offer.scope, scope);
        assert_eq!(need.start_key, offer.start_key);
        assert_eq!(need.end_key, offer.end_key);
        assert_eq!(offer.owner, [4; 32]);
    }
}
