//! Exact context matching vocabulary for the concrete protocol.
//!
//! This module owns the need/offer constructors and matcher for exact
//! role/scope/selector matching. Projectors choose which exact context to emit;
//! this matcher owns candidate pairing.

use crate::core::context::{ContextNeed, ContextOffer, Role, Selector};
use crate::core::facts::{FactId, FactScope, ScopeKind};
use crate::core::matchers::{ContextMatch, ContextMatcher};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExactSelectorMatcher {
    role: Role,
}

impl ExactSelectorMatcher {
    pub fn new(role: Role) -> Self {
        Self { role }
    }
}

impl ContextMatcher for ExactSelectorMatcher {
    fn role(&self) -> &Role {
        &self.role
    }

    fn exact_selector_role(&self) -> Option<&Role> {
        Some(&self.role)
    }

    fn match_new_need(
        &self,
        need: &ContextNeed,
        existing_offers: &[ContextOffer],
    ) -> Vec<ContextMatch> {
        if need.role != self.role {
            return Vec::new();
        }
        existing_offers
            .iter()
            .filter_map(|offer| exact_selector_match(need, offer))
            .collect()
    }

    fn match_new_offer(
        &self,
        offer: &ContextOffer,
        existing_needs: &[ContextNeed],
    ) -> Vec<ContextMatch> {
        if offer.role != self.role {
            return Vec::new();
        }
        existing_needs
            .iter()
            .filter_map(|need| exact_selector_match(need, offer))
            .collect()
    }

    fn match_delta(
        &self,
        delta: &crate::core::context::ContextSetDelta,
        available_needs: &[ContextNeed],
        available_offers: &[ContextOffer],
    ) -> Vec<ContextMatch> {
        type ExactKey = (FactScope, Selector);

        let mut matches = BTreeSet::new();
        if delta.added_needs.iter().any(|need| need.role == self.role) {
            let mut offers_by_key = BTreeMap::<ExactKey, Vec<&ContextOffer>>::new();
            for offer in available_offers
                .iter()
                .filter(|offer| offer.role == self.role)
            {
                offers_by_key
                    .entry((offer.scope.clone(), offer.selector.clone()))
                    .or_default()
                    .push(offer);
            }
            for need in delta
                .added_needs
                .iter()
                .filter(|need| need.role == self.role)
            {
                if let Some(offers) =
                    offers_by_key.get(&(need.scope.clone(), need.selector.clone()))
                {
                    for offer in offers {
                        matches.insert(ContextMatch {
                            need_owner: need.owner,
                            offer_owner: offer.owner,
                            payload_ref: offer.payload_ref,
                        });
                    }
                }
            }
        }

        if delta
            .added_offers
            .iter()
            .any(|offer| offer.role == self.role)
        {
            let mut needs_by_key = BTreeMap::<ExactKey, Vec<&ContextNeed>>::new();
            for need in available_needs.iter().filter(|need| need.role == self.role) {
                needs_by_key
                    .entry((need.scope.clone(), need.selector.clone()))
                    .or_default()
                    .push(need);
            }
            for offer in delta
                .added_offers
                .iter()
                .filter(|offer| offer.role == self.role)
            {
                if let Some(needs) =
                    needs_by_key.get(&(offer.scope.clone(), offer.selector.clone()))
                {
                    for need in needs {
                        matches.insert(ContextMatch {
                            need_owner: need.owner,
                            offer_owner: offer.owner,
                            payload_ref: offer.payload_ref,
                        });
                    }
                }
            }
        }

        matches.into_iter().collect()
    }
}

pub fn exact_selector_match(need: &ContextNeed, offer: &ContextOffer) -> Option<ContextMatch> {
    if need.role == offer.role && need.scope == offer.scope && need.selector == offer.selector {
        Some(ContextMatch {
            need_owner: need.owner,
            offer_owner: offer.owner,
            payload_ref: offer.payload_ref,
        })
    } else {
        None
    }
}

pub const CONNECTION_EPHEMERAL_SECRET_ROLE: &str = "connection_ephemeral_secret";
pub const CONNECTION_INVITE_SECRET_ROLE: &str = "connection_invite_secret";
pub const CONNECTION_REQUEST_ROLE: &str = "connection_request";
pub const CONTENT_FILE_ROLE: &str = "content_file";
pub const CONTENT_MESSAGE_ROLE: &str = "content_message";
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
pub const SIGNER_PUBKEY_ROLE: &str = "signer_pubkey";
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

pub fn exact_need_for_selector(
    owner: FactId,
    role: Role,
    scope: FactScope,
    selector: impl Into<Vec<u8>>,
) -> ContextNeed {
    ContextNeed {
        owner,
        role,
        scope,
        selector: Selector::from_bytes(selector),
    }
}

pub fn exact_offer_for_selector(
    owner: FactId,
    role: Role,
    scope: FactScope,
    selector: impl Into<Vec<u8>>,
    payload_ref: FactId,
) -> ContextOffer {
    ContextOffer {
        owner,
        role,
        scope,
        selector: Selector::from_bytes(selector),
        payload_ref,
    }
}

pub fn exact_need(owner: FactId, role: Role, id: FactId) -> ContextNeed {
    exact_need_for_selector(owner, role, FactScope::Global, id)
}

pub fn exact_offer(owner: FactId, role: Role) -> ContextOffer {
    exact_offer_for_selector(owner, role, FactScope::Global, owner, owner)
}

pub fn connection_ephemeral_secret_role() -> Role {
    protocol_role(CONNECTION_EPHEMERAL_SECRET_ROLE)
}

pub fn connection_ephemeral_secret_need(owner: FactId, secret_id: FactId) -> ContextNeed {
    exact_need_for_selector(
        owner,
        connection_ephemeral_secret_role(),
        FactScope::Local,
        secret_id,
    )
}

pub fn connection_ephemeral_secret_offer(owner: FactId, secret_id: FactId) -> ContextOffer {
    exact_offer_for_selector(
        owner,
        connection_ephemeral_secret_role(),
        FactScope::Local,
        secret_id,
        owner,
    )
}

pub fn connection_invite_secret_role() -> Role {
    protocol_role(CONNECTION_INVITE_SECRET_ROLE)
}

pub fn connection_invite_secret_need(owner: FactId, invite_secret_id: FactId) -> ContextNeed {
    exact_need_for_selector(
        owner,
        connection_invite_secret_role(),
        FactScope::Local,
        invite_secret_id,
    )
}

pub fn connection_invite_secret_offer(owner: FactId, invite_secret_id: FactId) -> ContextOffer {
    exact_offer_for_selector(
        owner,
        connection_invite_secret_role(),
        FactScope::Local,
        invite_secret_id,
        owner,
    )
}

pub fn connection_request_role() -> Role {
    protocol_role(CONNECTION_REQUEST_ROLE)
}

pub fn connection_request_need(owner: FactId, request_id: FactId) -> ContextNeed {
    exact_need_for_selector(
        owner,
        connection_request_role(),
        FactScope::Global,
        request_id,
    )
}

pub fn connection_request_offer(owner: FactId, request_id: FactId) -> ContextOffer {
    exact_offer_for_selector(
        owner,
        connection_request_role(),
        FactScope::Global,
        request_id,
        owner,
    )
}

pub fn file_role() -> Role {
    protocol_role(CONTENT_FILE_ROLE)
}

pub fn file_need(owner: FactId, scope: FactScope, file_id: FactId) -> ContextNeed {
    exact_need_for_selector(owner, file_role(), scope, file_id)
}

pub fn file_offer(owner: FactId, scope: FactScope, file_id: FactId) -> ContextOffer {
    exact_offer_for_selector(owner, file_role(), scope, file_id, owner)
}

pub fn message_role() -> Role {
    protocol_role(CONTENT_MESSAGE_ROLE)
}

pub fn message_need(owner: FactId, scope: FactScope, message_id: FactId) -> ContextNeed {
    exact_need_for_selector(owner, message_role(), scope, message_id)
}

pub fn message_offer(owner: FactId, scope: FactScope, message_id: FactId) -> ContextOffer {
    exact_offer_for_selector(owner, message_role(), scope, message_id, owner)
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
    exact_need_for_selector(
        owner,
        deletion_role(),
        scope,
        deletion_selector(target_id, author_user_id)
            .as_bytes()
            .to_vec(),
    )
}

pub fn deletion_offer(
    owner: FactId,
    scope: FactScope,
    target_id: FactId,
    author_user_id: FactId,
) -> ContextOffer {
    exact_offer_for_selector(
        owner,
        deletion_role(),
        scope,
        deletion_selector(target_id, author_user_id)
            .as_bytes()
            .to_vec(),
        owner,
    )
}

pub fn deletion_selector(target_id: FactId, author_user_id: FactId) -> Selector {
    let mut bytes = Vec::with_capacity(64);
    bytes.extend_from_slice(&target_id);
    bytes.extend_from_slice(&author_user_id);
    Selector::from_bytes(bytes)
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
    selector: Vec<u8>,
) -> ContextNeed {
    exact_need_for_selector(owner, role, workspace_scope(workspace_id), selector)
}

pub fn scoped_key_offer(
    owner: FactId,
    role: Role,
    workspace_id: FactId,
    selector: Vec<u8>,
) -> ContextOffer {
    exact_offer_for_selector(owner, role, workspace_scope(workspace_id), selector, owner)
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
    exact_need_for_selector(
        owner,
        source_secret_role(),
        FactScope::Local,
        source_secret_id,
    )
}

pub fn source_secret_offer(owner: FactId, source_secret_id: FactId) -> ContextOffer {
    exact_offer_for_selector(
        owner,
        source_secret_role(),
        FactScope::Local,
        source_secret_id,
        owner,
    )
}

pub fn local_signer_secret_role() -> Role {
    protocol_role(LOCAL_SIGNER_SECRET_ROLE)
}

pub fn local_signer_secret_need(owner: FactId, scope: FactScope, signer_id: FactId) -> ContextNeed {
    exact_need_for_selector(owner, local_signer_secret_role(), scope, signer_id)
}

pub fn local_signer_secret_offer(
    owner: FactId,
    scope: FactScope,
    signer_id: FactId,
) -> ContextOffer {
    exact_offer_for_selector(owner, local_signer_secret_role(), scope, signer_id, owner)
}

pub fn transit_received_role() -> Role {
    protocol_role(TRANSIT_RECEIVED_ROLE)
}

pub fn transit_received_need(owner: FactId, received_fact_id: FactId) -> ContextNeed {
    exact_need_for_selector(
        owner,
        transit_received_role(),
        FactScope::Local,
        received_fact_id,
    )
}

pub fn transit_received_offer(owner: FactId, received_fact_id: FactId) -> ContextOffer {
    exact_offer_for_selector(
        owner,
        transit_received_role(),
        FactScope::Local,
        received_fact_id,
        owner,
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
    exact_need_for_selector(owner, recipient_key_role(), scope, recipient_key_id)
}

pub fn recipient_key_offer(
    owner: FactId,
    scope: FactScope,
    recipient_key_id: FactId,
) -> ContextOffer {
    exact_offer_for_selector(owner, recipient_key_role(), scope, recipient_key_id, owner)
}

pub fn local_recipient_key_role() -> Role {
    protocol_role(LOCAL_RECIPIENT_KEY_ROLE)
}

pub fn local_recipient_key_need(
    owner: FactId,
    scope: FactScope,
    recipient_key_id: FactId,
) -> ContextNeed {
    exact_need_for_selector(owner, local_recipient_key_role(), scope, recipient_key_id)
}

pub fn local_recipient_key_offer(
    owner: FactId,
    scope: FactScope,
    recipient_key_id: FactId,
) -> ContextOffer {
    exact_offer_for_selector(
        owner,
        local_recipient_key_role(),
        scope,
        recipient_key_id,
        owner,
    )
}

pub fn frontier_role() -> Role {
    protocol_role(REMOVAL_FRONTIER_ROLE)
}

pub fn frontier_need(owner: FactId, scope: FactScope, frontier_id: FactId) -> ContextNeed {
    exact_need_for_selector(owner, frontier_role(), scope, frontier_id)
}

pub fn frontier_offer(owner: FactId, scope: FactScope, frontier_id: FactId) -> ContextOffer {
    exact_offer_for_selector(owner, frontier_role(), scope, frontier_id, owner)
}

pub fn recipient_superseded_role() -> Role {
    protocol_role(RECIPIENT_SUPERSEDED_ROLE)
}

pub fn recipient_superseded_need(
    owner: FactId,
    scope: FactScope,
    recipient_key_id: FactId,
) -> ContextNeed {
    exact_need_for_selector(owner, recipient_superseded_role(), scope, recipient_key_id)
}

pub fn recipient_superseded_offer(
    owner: FactId,
    scope: FactScope,
    recipient_key_id: FactId,
) -> ContextOffer {
    exact_offer_for_selector(
        owner,
        recipient_superseded_role(),
        scope,
        recipient_key_id,
        owner,
    )
}

pub fn signer_role() -> Role {
    protocol_role(SIGNER_PUBKEY_ROLE)
}

pub fn signer_need(owner: FactId, scope: FactScope, signer_id: FactId) -> ContextNeed {
    exact_need_for_selector(owner, signer_role(), scope, signer_id)
}

pub fn signer_offer(owner: FactId, scope: FactScope, signer_id: FactId) -> ContextOffer {
    exact_offer_for_selector(owner, signer_role(), scope, signer_id, owner)
}

pub fn exact_fact_role() -> Role {
    protocol_role(SYNC_EXACT_FACT_ROLE)
}

pub fn exact_fact_need(owner: FactId, scope: FactScope, fact_id: FactId) -> ContextNeed {
    exact_need_for_selector(owner, exact_fact_role(), scope, fact_id)
}

pub fn exact_fact_offer(
    owner: FactId,
    scope: FactScope,
    fact_id: FactId,
    payload_ref: FactId,
) -> ContextOffer {
    exact_offer_for_selector(owner, exact_fact_role(), scope, fact_id, payload_ref)
}

pub fn key_wrap_role() -> Role {
    protocol_role(SYNC_KEY_WRAP_ROLE)
}

pub fn key_wrap_need(owner: FactId, scope: FactScope, key_wrap_id: FactId) -> ContextNeed {
    exact_need_for_selector(owner, key_wrap_role(), scope, key_wrap_id)
}

pub fn key_wrap_offer(owner: FactId, scope: FactScope, key_wrap_id: FactId) -> ContextOffer {
    exact_offer_for_selector(owner, key_wrap_role(), scope, key_wrap_id, owner)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_selector_match_requires_role_scope_and_selector() {
        let role = Role::new("exact").unwrap();
        let need = ContextNeed {
            owner: [1; 32],
            role: role.clone(),
            scope: FactScope::Global,
            selector: Selector::from_bytes([2; 32]),
        };
        let offer = ContextOffer {
            owner: [3; 32],
            role,
            scope: FactScope::Global,
            selector: Selector::from_bytes([2; 32]),
            payload_ref: [4; 32],
        };

        let matched = exact_selector_match(&need, &offer).unwrap();
        assert_eq!(matched.need_owner, [1; 32]);
        assert_eq!(matched.offer_owner, [3; 32]);
        assert_eq!(matched.payload_ref, [4; 32]);
    }

    #[test]
    fn exact_selector_matcher_finds_new_need_matches() {
        let role = Role::new("exact").unwrap();
        let matcher = ExactSelectorMatcher::new(role.clone());
        let need = ContextNeed {
            owner: [1; 32],
            role: role.clone(),
            scope: FactScope::Global,
            selector: Selector::from_bytes([2; 32]),
        };
        let offers = vec![
            ContextOffer {
                owner: [3; 32],
                role: role.clone(),
                scope: FactScope::Global,
                selector: Selector::from_bytes([2; 32]),
                payload_ref: [4; 32],
            },
            ContextOffer {
                owner: [5; 32],
                role,
                scope: FactScope::Local,
                selector: Selector::from_bytes([2; 32]),
                payload_ref: [6; 32],
            },
        ];

        let matches = matcher.match_new_need(&need, &offers);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].payload_ref, [4; 32]);
    }

    #[test]
    fn exact_selector_matcher_finds_new_offer_matches() {
        let role = Role::new("exact").unwrap();
        let matcher = ExactSelectorMatcher::new(role.clone());
        let offer = ContextOffer {
            owner: [3; 32],
            role: role.clone(),
            scope: FactScope::Global,
            selector: Selector::from_bytes([2; 32]),
            payload_ref: [4; 32],
        };
        let needs = vec![ContextNeed {
            owner: [1; 32],
            role,
            scope: FactScope::Global,
            selector: Selector::from_bytes([2; 32]),
        }];

        let matches = matcher.match_new_offer(&offer, &needs);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].need_owner, [1; 32]);
    }

    #[test]
    fn exact_helpers_encode_only_role_scope_selector_and_payload_ref() {
        let owner = [1; 32];
        let scope = workspace_scope([2; 32]);
        let need = exact_fact_need(owner, scope.clone(), [3; 32]);
        let offer = exact_fact_offer([4; 32], scope.clone(), [3; 32], [5; 32]);

        assert_eq!(need.role, exact_fact_role());
        assert_eq!(offer.role, exact_fact_role());
        assert_eq!(need.scope, scope);
        assert_eq!(offer.scope, scope);
        assert_eq!(need.selector, offer.selector);
        assert_eq!(offer.payload_ref, [5; 32]);
    }
}
