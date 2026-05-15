//! Context selectors and matchers for poc-10 sync projection.

use crate::core::context::{ContextNeed, ContextOffer, Role, Selector};
use crate::core::facts::{FactId, FactScope, ScopeKind};
use crate::core::matchers::{ContextMatch, ContextMatcher};

use super::fact::{ConnectionId, EventId, KeyWrapId, WorkspaceId};

pub fn range_event_role() -> Role {
    Role::new("sync_range_event").expect("valid range role")
}

pub fn exact_event_role() -> Role {
    Role::new("sync_exact_event").expect("valid exact event role")
}

pub fn key_wrap_role() -> Role {
    Role::new("sync_key_wrap").expect("valid key wrap role")
}

pub fn workspace_scope(workspace_id: WorkspaceId) -> FactScope {
    FactScope::Scoped {
        kind: ScopeKind::new("workspace").expect("valid workspace scope"),
        id: workspace_id,
    }
}

pub fn range_event_need(owner: FactId, scope: FactScope, start: u64, end: u64) -> ContextNeed {
    ContextNeed {
        owner,
        role: range_event_role(),
        scope,
        selector: range_need_selector(start, end),
    }
}

pub fn range_event_offer(
    owner: FactId,
    scope: FactScope,
    timestamp: u64,
    event_id: EventId,
    dependency_id: EventId,
    key_wrap_id: KeyWrapId,
) -> ContextOffer {
    ContextOffer {
        owner,
        role: range_event_role(),
        scope,
        selector: range_offer_selector(timestamp, event_id, dependency_id, key_wrap_id),
        payload_ref: owner,
    }
}

pub fn exact_event_need(owner: FactId, scope: FactScope, event_id: EventId) -> ContextNeed {
    ContextNeed {
        owner,
        role: exact_event_role(),
        scope,
        selector: Selector::from_bytes(event_id),
    }
}

pub fn exact_event_offer(
    owner: FactId,
    scope: FactScope,
    event_id: EventId,
    payload_ref: FactId,
) -> ContextOffer {
    ContextOffer {
        owner,
        role: exact_event_role(),
        scope,
        selector: Selector::from_bytes(event_id),
        payload_ref,
    }
}

pub fn key_wrap_need(owner: FactId, scope: FactScope, key_wrap_id: KeyWrapId) -> ContextNeed {
    ContextNeed {
        owner,
        role: key_wrap_role(),
        scope,
        selector: Selector::from_bytes(key_wrap_id),
    }
}

pub fn key_wrap_offer(owner: FactId, scope: FactScope, key_wrap_id: KeyWrapId) -> ContextOffer {
    ContextOffer {
        owner,
        role: key_wrap_role(),
        scope,
        selector: Selector::from_bytes(key_wrap_id),
        payload_ref: owner,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RangeOfferSelector {
    pub timestamp: u64,
    pub event_id: EventId,
    pub dependency_id: EventId,
    pub key_wrap_id: KeyWrapId,
}

pub fn range_need_selector(start: u64, end: u64) -> Selector {
    let mut bytes = Vec::with_capacity(16);
    bytes.extend_from_slice(&start.to_be_bytes());
    bytes.extend_from_slice(&end.to_be_bytes());
    Selector::from_bytes(bytes)
}

pub fn decode_range_need_selector(selector: &Selector) -> Option<(u64, u64)> {
    let bytes = selector.as_bytes();
    if bytes.len() != 16 {
        return None;
    }
    Some((
        u64::from_be_bytes(bytes[0..8].try_into().ok()?),
        u64::from_be_bytes(bytes[8..16].try_into().ok()?),
    ))
}

pub fn range_offer_selector(
    timestamp: u64,
    event_id: EventId,
    dependency_id: EventId,
    key_wrap_id: KeyWrapId,
) -> Selector {
    let mut bytes = Vec::with_capacity(104);
    bytes.extend_from_slice(&timestamp.to_be_bytes());
    bytes.extend_from_slice(&event_id);
    bytes.extend_from_slice(&dependency_id);
    bytes.extend_from_slice(&key_wrap_id);
    Selector::from_bytes(bytes)
}

pub fn decode_range_offer_selector(selector: &Selector) -> Option<RangeOfferSelector> {
    let bytes = selector.as_bytes();
    if bytes.len() != 104 {
        return None;
    }
    Some(RangeOfferSelector {
        timestamp: u64::from_be_bytes(bytes[0..8].try_into().ok()?),
        event_id: bytes[8..40].try_into().ok()?,
        dependency_id: bytes[40..72].try_into().ok()?,
        key_wrap_id: bytes[72..104].try_into().ok()?,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RangeEventMatcher {
    role: Role,
}

impl RangeEventMatcher {
    pub fn new() -> Self {
        Self {
            role: range_event_role(),
        }
    }
}

impl Default for RangeEventMatcher {
    fn default() -> Self {
        Self::new()
    }
}

impl ContextMatcher for RangeEventMatcher {
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
            .filter_map(|offer| range_event_match(need, offer))
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
            .filter_map(|need| range_event_match(need, offer))
            .collect()
    }
}

pub fn range_event_match(need: &ContextNeed, offer: &ContextOffer) -> Option<ContextMatch> {
    if need.role != offer.role || need.scope != offer.scope {
        return None;
    }
    let (start, end) = decode_range_need_selector(&need.selector)?;
    let offer_selector = decode_range_offer_selector(&offer.selector)?;
    if offer_selector.timestamp < start || offer_selector.timestamp > end {
        return None;
    }
    Some(ContextMatch {
        need_owner: need.owner,
        offer_owner: offer.owner,
        payload_ref: offer.payload_ref,
    })
}

pub fn send_on_connection_key(connection_id: ConnectionId, event_id: EventId) -> Vec<u8> {
    let mut key = Vec::with_capacity(64);
    key.extend_from_slice(&connection_id);
    key.extend_from_slice(&event_id);
    key
}
