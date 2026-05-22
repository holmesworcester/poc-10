//! Secret coverage context keys.
//!
//! Core only sees byte ranges. This module chooses the coordinate layout for
//! encrypted-message secret coverage and validates candidate overlaps before a
//! projector treats an offer as authoritative.

use crate::core::context::{ContextNeed, ContextOffer, Role, Selector};
use crate::core::facts::{FactId, FactScope};

use super::exact::{protocol_role, range_need_for_selector, range_offer_for_selector};

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
    let key = secret_need_selector(workspace_id, frontier_id, minute, leaf_id);
    range_need_for_selector(
        owner,
        secret_role(),
        scope,
        key.as_bytes().to_vec(),
        key.as_bytes().to_vec(),
    )
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
    let prefix_bytes = prefix_bytes.min(32);
    let start = secret_range_key(
        workspace_id,
        frontier_id,
        start_minute,
        prefix_bound(leaf_prefix, prefix_bytes, BoundSide::Low),
    );
    let end = secret_range_key(
        workspace_id,
        frontier_id,
        end_minute,
        prefix_bound(leaf_prefix, prefix_bytes, BoundSide::High),
    );
    range_offer_for_selector(owner, secret_role(), scope, start, end)
}

// Versioned keys make persisted context rows self-describing. A need names one
// leaf at one minute. An offer names an inclusive coordinate range; projectors
// still validate the intended workspace/frontier/time/prefix semantics.
pub fn secret_need_selector(
    workspace_id: FactId,
    frontier_id: FactId,
    minute: u64,
    leaf_id: FactId,
) -> Selector {
    Selector::from_bytes(secret_range_key(workspace_id, frontier_id, minute, leaf_id))
}

fn secret_range_key(
    workspace_id: FactId,
    frontier_id: FactId,
    minute: u64,
    leaf_id: FactId,
) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(105);
    bytes.push(1);
    bytes.extend_from_slice(&workspace_id);
    bytes.extend_from_slice(&frontier_id);
    bytes.extend_from_slice(&minute.to_be_bytes());
    bytes.extend_from_slice(&leaf_id);
    bytes
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BoundSide {
    Low,
    High,
}

fn prefix_bound(mut prefix: FactId, prefix_bytes: u8, side: BoundSide) -> FactId {
    let prefix_bytes = usize::from(prefix_bytes.min(32));
    match side {
        BoundSide::Low => prefix[prefix_bytes..].fill(0),
        BoundSide::High => prefix[prefix_bytes..].fill(0xff),
    }
    prefix
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
    pub leaf_prefix: FactId,
    pub prefix_bytes: u8,
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

fn decode_secret_offer_range(offer: &ContextOffer) -> Option<SecretOfferSelector> {
    let start = decode_secret_need_selector(&offer.start_key)?;
    let end = decode_secret_need_selector(&offer.end_key)?;
    if start.workspace_id != end.workspace_id
        || start.frontier_id != end.frontier_id
        || start.minute > end.minute
    {
        return None;
    }
    let prefix_bytes = common_prefix_bytes(&start.leaf_id, &end.leaf_id);
    Some(SecretOfferSelector {
        workspace_id: start.workspace_id,
        frontier_id: start.frontier_id,
        start_minute: start.minute,
        end_minute: end.minute,
        leaf_prefix: start.leaf_id,
        prefix_bytes,
    })
}

fn common_prefix_bytes(left: &FactId, right: &FactId) -> u8 {
    left.iter()
        .zip(right.iter())
        .take_while(|(left, right)| left == right)
        .count()
        .min(32) as u8
}

pub fn secret_offer_matches_need(need: &ContextNeed, offer: &ContextOffer) -> bool {
    if need.role != offer.role || need.scope != offer.scope {
        return false;
    }
    if need.start_key != need.end_key {
        return false;
    }
    let Some(need) = decode_secret_need_selector(&need.start_key) else {
        return false;
    };
    let Some(offer_selector) = decode_secret_offer_range(offer) else {
        return false;
    };
    need.workspace_id == offer_selector.workspace_id
        && need.frontier_id == offer_selector.frontier_id
        && need.minute >= offer_selector.start_minute
        && need.minute <= offer_selector.end_minute
        && prefix_matches(
            &need.leaf_id,
            &offer_selector.leaf_prefix,
            offer_selector.prefix_bytes,
        )
}

fn prefix_matches(value: &FactId, prefix: &FactId, prefix_bytes: u8) -> bool {
    let prefix_bytes = usize::from(prefix_bytes.min(32));
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

        assert!(secret_offer_matches_need(&need, &offer));
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

        assert!(!secret_offer_matches_need(&need, &offer));
    }

    #[test]
    fn secret_coverage_rejects_inverted_offer_range() {
        let workspace = [1; 32];
        let frontier = [2; 32];
        let scope = workspace_scope(workspace);
        let need = secret_need([3; 32], scope.clone(), workspace, frontier, 42, [9; 32]);
        let offer = secret_offer([4; 32], scope, workspace, frontier, 50, 40, 0, [0; 32]);

        assert!(!secret_offer_matches_need(&need, &offer));
    }
}
