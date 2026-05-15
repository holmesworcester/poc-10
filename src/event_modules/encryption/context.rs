//! Context selectors and matchers for key wrap materialization.

use crate::core::context::{ContextNeed, ContextOffer, Role, Selector};
use crate::core::facts::{FactId, FactScope};
use crate::core::matchers::{ContextMatch, ContextMatcher};

use super::fact::{FrontierId, RecipientKeyId, WorkspaceId};

pub fn recipient_key_role() -> Role {
    Role::new("recipient_key").expect("valid recipient key role")
}

pub fn frontier_role() -> Role {
    Role::new("removal_frontier").expect("valid removal frontier role")
}

pub fn recipient_superseded_role() -> Role {
    Role::new("recipient_superseded").expect("valid recipient superseded role")
}

pub fn wrap_source_role() -> Role {
    Role::new("wrap_source").expect("valid wrap source role")
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

pub fn frontier_need(owner: FactId, scope: FactScope, frontier_id: FrontierId) -> ContextNeed {
    ContextNeed {
        owner,
        role: frontier_role(),
        scope,
        selector: Selector::from_bytes(frontier_id),
    }
}

pub fn frontier_offer(owner: FactId, scope: FactScope, frontier_id: FrontierId) -> ContextOffer {
    ContextOffer {
        owner,
        role: frontier_role(),
        scope,
        selector: Selector::from_bytes(frontier_id),
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

pub fn proactive_wrap_source_need(
    owner: FactId,
    scope: FactScope,
    workspace_id: WorkspaceId,
    min_frontier_created_at_ms: u64,
) -> ContextNeed {
    let mut selector = Vec::with_capacity(41);
    selector.push(1);
    selector.extend_from_slice(&workspace_id);
    selector.extend_from_slice(&min_frontier_created_at_ms.to_be_bytes());
    ContextNeed {
        owner,
        role: wrap_source_role(),
        scope,
        selector: Selector::from_bytes(selector),
    }
}

pub fn requested_wrap_source_need(
    owner: FactId,
    scope: FactScope,
    workspace_id: WorkspaceId,
    frontier_id: FrontierId,
) -> ContextNeed {
    let mut selector = Vec::with_capacity(65);
    selector.push(2);
    selector.extend_from_slice(&workspace_id);
    selector.extend_from_slice(&frontier_id);
    ContextNeed {
        owner,
        role: wrap_source_role(),
        scope,
        selector: Selector::from_bytes(selector),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WrapSourceKind {
    FrontierRoot,
    HistoryNode {
        start_minute: u64,
        end_minute: u64,
        prefix_bytes: u8,
        leaf_prefix: FactId,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WrapSourceSelector {
    pub workspace_id: WorkspaceId,
    pub frontier_id: FrontierId,
    pub frontier_created_at_ms: u64,
    pub kind: WrapSourceKind,
}

pub fn frontier_root_wrap_source_offer(
    owner: FactId,
    scope: FactScope,
    workspace_id: WorkspaceId,
    frontier_id: FrontierId,
    frontier_created_at_ms: u64,
) -> ContextOffer {
    wrap_source_offer(
        owner,
        scope,
        WrapSourceSelector {
            workspace_id,
            frontier_id,
            frontier_created_at_ms,
            kind: WrapSourceKind::FrontierRoot,
        },
    )
}

pub fn history_node_wrap_source_offer(
    owner: FactId,
    scope: FactScope,
    workspace_id: WorkspaceId,
    frontier_id: FrontierId,
    start_minute: u64,
    end_minute: u64,
    prefix_bytes: u8,
    leaf_prefix: FactId,
) -> ContextOffer {
    wrap_source_offer(
        owner,
        scope,
        WrapSourceSelector {
            workspace_id,
            frontier_id,
            frontier_created_at_ms: 0,
            kind: WrapSourceKind::HistoryNode {
                start_minute,
                end_minute,
                prefix_bytes,
                leaf_prefix,
            },
        },
    )
}

pub fn wrap_source_offer(
    owner: FactId,
    scope: FactScope,
    source: WrapSourceSelector,
) -> ContextOffer {
    ContextOffer {
        owner,
        role: wrap_source_role(),
        scope,
        selector: encode_wrap_source_selector(&source),
        payload_ref: owner,
    }
}

pub fn decode_wrap_source_selector(selector: &Selector) -> Option<WrapSourceSelector> {
    let bytes = selector.as_bytes();
    if bytes.len() != 123 || bytes[0] != 3 {
        return None;
    }
    let workspace_id = bytes[1..33].try_into().ok()?;
    let frontier_id = bytes[33..65].try_into().ok()?;
    let frontier_created_at_ms = u64::from_be_bytes(bytes[65..73].try_into().ok()?);
    match bytes[73] {
        1 => Some(WrapSourceSelector {
            workspace_id,
            frontier_id,
            frontier_created_at_ms,
            kind: WrapSourceKind::FrontierRoot,
        }),
        2 => {
            let start_minute = u64::from_be_bytes(bytes[74..82].try_into().ok()?);
            let end_minute = u64::from_be_bytes(bytes[82..90].try_into().ok()?);
            let prefix_bytes = bytes[90];
            if prefix_bytes > 32 || start_minute > end_minute {
                return None;
            }
            Some(WrapSourceSelector {
                workspace_id,
                frontier_id,
                frontier_created_at_ms,
                kind: WrapSourceKind::HistoryNode {
                    start_minute,
                    end_minute,
                    prefix_bytes,
                    leaf_prefix: bytes[91..123].try_into().ok()?,
                },
            })
        }
        _ => None,
    }
}

pub fn encode_wrap_source_selector(source: &WrapSourceSelector) -> Selector {
    let mut bytes = Vec::with_capacity(123);
    bytes.push(3);
    bytes.extend_from_slice(&source.workspace_id);
    bytes.extend_from_slice(&source.frontier_id);
    bytes.extend_from_slice(&source.frontier_created_at_ms.to_be_bytes());
    match source.kind {
        WrapSourceKind::FrontierRoot => {
            bytes.push(1);
            bytes.extend_from_slice(&[0; 49]);
        }
        WrapSourceKind::HistoryNode {
            start_minute,
            end_minute,
            prefix_bytes,
            leaf_prefix,
        } => {
            bytes.push(2);
            bytes.extend_from_slice(&start_minute.to_be_bytes());
            bytes.extend_from_slice(&end_minute.to_be_bytes());
            bytes.push(prefix_bytes);
            bytes.extend_from_slice(&leaf_prefix);
        }
    }
    Selector::from_bytes(bytes)
}

pub fn decode_proactive_wrap_need(selector: &Selector) -> Option<(WorkspaceId, u64)> {
    let bytes = selector.as_bytes();
    if bytes.len() != 41 || bytes[0] != 1 {
        return None;
    }
    Some((
        bytes[1..33].try_into().ok()?,
        u64::from_be_bytes(bytes[33..41].try_into().ok()?),
    ))
}

pub fn decode_requested_wrap_need(selector: &Selector) -> Option<(WorkspaceId, FrontierId)> {
    let bytes = selector.as_bytes();
    if bytes.len() != 65 || bytes[0] != 2 {
        return None;
    }
    Some((
        bytes[1..33].try_into().ok()?,
        bytes[33..65].try_into().ok()?,
    ))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WrapSourceMatcher {
    role: Role,
}

impl WrapSourceMatcher {
    pub fn new() -> Self {
        Self {
            role: wrap_source_role(),
        }
    }
}

impl Default for WrapSourceMatcher {
    fn default() -> Self {
        Self::new()
    }
}

impl ContextMatcher for WrapSourceMatcher {
    fn role(&self) -> &Role {
        &self.role
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
            .filter_map(|offer| wrap_source_match(need, offer))
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
            .filter_map(|need| wrap_source_match(need, offer))
            .collect()
    }
}

pub fn wrap_source_offer_matches_need(
    need: &ContextNeed,
    offer: &ContextOffer,
) -> Option<WrapSourceSelector> {
    wrap_source_match(need, offer)?;
    decode_wrap_source_selector(&offer.selector)
}

fn wrap_source_match(need: &ContextNeed, offer: &ContextOffer) -> Option<ContextMatch> {
    if need.role != offer.role || need.scope != offer.scope {
        return None;
    }
    let source = decode_wrap_source_selector(&offer.selector)?;
    let matches = if let Some((workspace_id, min_frontier_created_at_ms)) =
        decode_proactive_wrap_need(&need.selector)
    {
        source.workspace_id == workspace_id
            && source.frontier_created_at_ms >= min_frontier_created_at_ms
    } else if let Some((workspace_id, frontier_id)) = decode_requested_wrap_need(&need.selector) {
        source.workspace_id == workspace_id && source.frontier_id == frontier_id
    } else {
        false
    };
    matches.then_some(ContextMatch {
        need_owner: need.owner,
        offer_owner: offer.owner,
        payload_ref: offer.payload_ref,
    })
}
