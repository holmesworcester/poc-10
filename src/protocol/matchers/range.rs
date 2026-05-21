//! Range context matcher.
//!
//! Range offers are candidate matches when an offered timestamp falls inside a
//! requested inclusive interval under the same role and scope.

use crate::core::context::{ContextNeed, ContextOffer, Role, Selector};
use crate::core::facts::{FactId, FactScope};
use crate::core::matchers::ContextMatcher;

use super::exact::protocol_role;

pub const SYNC_RANGE_FACT_ROLE: &str = "sync_range_fact";

pub fn range_fact_role() -> Role {
    protocol_role(SYNC_RANGE_FACT_ROLE)
}

pub fn range_fact_need(owner: FactId, scope: FactScope, start: u64, end: u64) -> ContextNeed {
    ContextNeed {
        owner,
        role: range_fact_role(),
        scope,
        selector: range_need_selector(start, end),
    }
}

pub fn range_fact_offer(
    owner: FactId,
    scope: FactScope,
    timestamp: u64,
    fact_id: FactId,
    dependency_id: FactId,
    key_wrap_id: FactId,
) -> ContextOffer {
    ContextOffer {
        owner,
        role: range_fact_role(),
        scope,
        selector: range_offer_selector(timestamp, fact_id, dependency_id, key_wrap_id),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RangeOfferSelector {
    pub timestamp: u64,
    pub fact_id: FactId,
    pub dependency_id: FactId,
    pub key_wrap_id: FactId,
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
    fact_id: FactId,
    dependency_id: FactId,
    key_wrap_id: FactId,
) -> Selector {
    let mut bytes = Vec::with_capacity(104);
    bytes.extend_from_slice(&timestamp.to_be_bytes());
    bytes.extend_from_slice(&fact_id);
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
        fact_id: bytes[8..40].try_into().ok()?,
        dependency_id: bytes[40..72].try_into().ok()?,
        key_wrap_id: bytes[72..104].try_into().ok()?,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RangeFactMatcher {
    role: Role,
}

impl RangeFactMatcher {
    pub fn new() -> Self {
        Self {
            role: range_fact_role(),
        }
    }
}

impl Default for RangeFactMatcher {
    fn default() -> Self {
        Self::new()
    }
}

impl ContextMatcher for RangeFactMatcher {
    fn role(&self) -> &Role {
        &self.role
    }

    fn matches(&self, need: &ContextNeed, offer: &ContextOffer) -> bool {
        range_fact_match(need, offer)
    }
}

pub fn range_fact_match(need: &ContextNeed, offer: &ContextOffer) -> bool {
    if need.role != offer.role || need.scope != offer.scope {
        return false;
    }
    let Some((start, end)) = decode_range_need_selector(&need.selector) else {
        return false;
    };
    let Some(offer_selector) = decode_range_offer_selector(&offer.selector) else {
        return false;
    };
    if offer_selector.timestamp < start || offer_selector.timestamp > end {
        return false;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::matchers::workspace_scope;

    #[test]
    fn range_fact_matcher_matches_inclusive_bounds() {
        let scope = workspace_scope([1; 32]);
        let need = range_fact_need([2; 32], scope.clone(), 10, 20);
        let lower = range_fact_offer([3; 32], scope.clone(), 10, [4; 32], [5; 32], [6; 32]);
        let upper = range_fact_offer([7; 32], scope.clone(), 20, [8; 32], [9; 32], [10; 32]);

        assert!(range_fact_match(&need, &lower));
        assert!(range_fact_match(&need, &upper));
    }

    #[test]
    fn range_fact_matcher_rejects_out_of_range_offer() {
        let scope = workspace_scope([1; 32]);
        let need = range_fact_need([2; 32], scope.clone(), 10, 20);
        let offer = range_fact_offer([3; 32], scope, 21, [4; 32], [5; 32], [6; 32]);

        assert!(!range_fact_match(&need, &offer));
    }
}
