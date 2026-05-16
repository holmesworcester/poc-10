//! Coverage context matcher.
//!
//! A coverage offer can satisfy many point needs when the scope, workspace,
//! frontier, time range, and leaf prefix line up. Projectors still validate the
//! matched payload before treating it as protocol authority.

use crate::core::context::{ContextNeed, ContextOffer, Role, Selector};
use crate::core::facts::{FactId, FactScope};
use crate::core::matchers::{ContextMatch, ContextMatcher};

use super::exact::protocol_role;

pub const SECRET_COVERAGE_ROLE: &str = "secret_coverage";

pub fn secret_role() -> Role {
    protocol_role(SECRET_COVERAGE_ROLE)
}

pub fn secret_need(
    owner: FactId,
    scope: FactScope,
    workspace_id: FactId,
    frontier_id: FactId,
    minute: u64,
    leaf_id: FactId,
) -> ContextNeed {
    ContextNeed {
        owner,
        role: secret_role(),
        scope,
        selector: secret_need_selector(workspace_id, frontier_id, minute, leaf_id),
    }
}

pub fn secret_offer(
    owner: FactId,
    scope: FactScope,
    workspace_id: FactId,
    frontier_id: FactId,
    start_minute: u64,
    end_minute: u64,
    prefix_bytes: u8,
    leaf_prefix: FactId,
) -> ContextOffer {
    ContextOffer {
        owner,
        role: secret_role(),
        scope,
        selector: secret_offer_selector(
            workspace_id,
            frontier_id,
            start_minute,
            end_minute,
            prefix_bytes,
            leaf_prefix,
        ),
        payload_ref: owner,
    }
}

// Versioned selectors make persisted context rows self-describing. A need names
// one leaf at one minute; an offer names a closed minute range plus a byte-prefix
// subtree of leaves.
pub fn secret_need_selector(
    workspace_id: FactId,
    frontier_id: FactId,
    minute: u64,
    leaf_id: FactId,
) -> Selector {
    let mut bytes = Vec::with_capacity(105);
    bytes.push(1);
    bytes.extend_from_slice(&workspace_id);
    bytes.extend_from_slice(&frontier_id);
    bytes.extend_from_slice(&minute.to_be_bytes());
    bytes.extend_from_slice(&leaf_id);
    Selector::from_bytes(bytes)
}

pub fn secret_offer_selector(
    workspace_id: FactId,
    frontier_id: FactId,
    start_minute: u64,
    end_minute: u64,
    prefix_bytes: u8,
    leaf_prefix: FactId,
) -> Selector {
    let mut bytes = Vec::with_capacity(114);
    bytes.push(1);
    bytes.extend_from_slice(&workspace_id);
    bytes.extend_from_slice(&frontier_id);
    bytes.extend_from_slice(&start_minute.to_be_bytes());
    bytes.extend_from_slice(&end_minute.to_be_bytes());
    bytes.push(prefix_bytes);
    bytes.extend_from_slice(&leaf_prefix);
    Selector::from_bytes(bytes)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretNeedSelector {
    pub workspace_id: FactId,
    pub frontier_id: FactId,
    pub minute: u64,
    pub leaf_id: FactId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretOfferSelector {
    pub workspace_id: FactId,
    pub frontier_id: FactId,
    pub start_minute: u64,
    pub end_minute: u64,
    pub prefix_bytes: u8,
    pub leaf_prefix: FactId,
}

pub fn decode_secret_need_selector(selector: &Selector) -> Option<SecretNeedSelector> {
    let bytes = selector.as_bytes();
    if bytes.len() != 105 || bytes[0] != 1 {
        return None;
    }
    Some(SecretNeedSelector {
        workspace_id: bytes[1..33].try_into().ok()?,
        frontier_id: bytes[33..65].try_into().ok()?,
        minute: u64::from_be_bytes(bytes[65..73].try_into().ok()?),
        leaf_id: bytes[73..105].try_into().ok()?,
    })
}

pub fn decode_secret_offer_selector(selector: &Selector) -> Option<SecretOfferSelector> {
    let bytes = selector.as_bytes();
    if bytes.len() != 114 || bytes[0] != 1 {
        return None;
    }
    let prefix_bytes = bytes[81];
    if prefix_bytes > 32 {
        return None;
    }
    Some(SecretOfferSelector {
        workspace_id: bytes[1..33].try_into().ok()?,
        frontier_id: bytes[33..65].try_into().ok()?,
        start_minute: u64::from_be_bytes(bytes[65..73].try_into().ok()?),
        end_minute: u64::from_be_bytes(bytes[73..81].try_into().ok()?),
        prefix_bytes,
        leaf_prefix: bytes[82..114].try_into().ok()?,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretCoverageMatcher {
    role: Role,
}

impl SecretCoverageMatcher {
    pub fn new() -> Self {
        Self {
            role: secret_role(),
        }
    }
}

impl Default for SecretCoverageMatcher {
    fn default() -> Self {
        Self::new()
    }
}

impl ContextMatcher for SecretCoverageMatcher {
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
            .filter_map(|offer| secret_coverage_match(need, offer))
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
            .filter_map(|need| secret_coverage_match(need, offer))
            .collect()
    }
}

pub fn secret_offer_matches_need(need: &ContextNeed, offer: &ContextOffer) -> bool {
    secret_coverage_match(need, offer).is_some()
}

fn secret_coverage_match(need: &ContextNeed, offer: &ContextOffer) -> Option<ContextMatch> {
    if need.role != offer.role || need.scope != offer.scope {
        return None;
    }
    let need_owner = need.owner;
    let need = decode_secret_need_selector(&need.selector)?;
    let offer_selector = decode_secret_offer_selector(&offer.selector)?;
    if need.workspace_id != offer_selector.workspace_id
        || need.frontier_id != offer_selector.frontier_id
        || offer_selector.start_minute > offer_selector.end_minute
        || need.minute < offer_selector.start_minute
        || need.minute > offer_selector.end_minute
        || !prefix_matches(
            &need.leaf_id,
            &offer_selector.leaf_prefix,
            offer_selector.prefix_bytes,
        )
    {
        return None;
    }

    Some(ContextMatch {
        need_owner,
        offer_owner: offer.owner,
        payload_ref: offer.payload_ref,
    })
}

fn prefix_matches(value: &FactId, prefix: &FactId, prefix_bytes: u8) -> bool {
    let prefix_bytes = usize::from(prefix_bytes);
    value[..prefix_bytes] == prefix[..prefix_bytes]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::matchers::workspace_scope;

    #[test]
    fn secret_coverage_matches_time_range_and_leaf_prefix() {
        let workspace = [1; 32];
        let frontier = [2; 32];
        let scope = workspace_scope(workspace);
        let mut prefix = [0; 32];
        prefix[0] = 0b1010_1111;
        let mut leaf = [0; 32];
        leaf[0] = 0b1010_1111;
        let need = secret_need([3; 32], scope.clone(), workspace, frontier, 42, leaf);
        let offer = secret_offer([4; 32], scope, workspace, frontier, 40, 50, 1, prefix);
        let matched = secret_coverage_match(&need, &offer).expect("match");

        assert_eq!(matched.need_owner, [3; 32]);
        assert_eq!(matched.offer_owner, [4; 32]);
        assert_eq!(matched.payload_ref, [4; 32]);
    }

    #[test]
    fn secret_coverage_rejects_wrong_prefix() {
        let workspace = [1; 32];
        let frontier = [2; 32];
        let scope = workspace_scope(workspace);
        let mut prefix = [0; 32];
        prefix[0] = 0b1111_0000;
        let mut leaf = [0; 32];
        leaf[0] = 0b1010_1111;
        let need = secret_need([3; 32], scope.clone(), workspace, frontier, 42, leaf);
        let offer = secret_offer([4; 32], scope, workspace, frontier, 40, 50, 1, prefix);

        assert!(secret_coverage_match(&need, &offer).is_none());
    }

    #[test]
    fn secret_coverage_rejects_inverted_offer_range() {
        let workspace = [1; 32];
        let frontier = [2; 32];
        let scope = workspace_scope(workspace);
        let need = secret_need([3; 32], scope.clone(), workspace, frontier, 42, [9; 32]);
        let offer = secret_offer([4; 32], scope, workspace, frontier, 50, 40, 0, [0; 32]);

        assert!(secret_coverage_match(&need, &offer).is_none());
    }
}
