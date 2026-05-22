//! Wrap-source context keys.
//!
//! Local key material can satisfy proactive recipient-key convergence or a
//! specific remote key request. Core only matches byte ranges; this module
//! encodes the two lookup coordinates and validates candidate overlaps.

use crate::core::context::{ContextNeed, ContextOffer, Role, Selector};
use crate::core::facts::{FactId, FactScope};

use super::exact::{protocol_role, range_need_for_selector, range_offer_for_selector};

pub const WRAP_SOURCE_ROLE: &str = "wrap_source";

const PROACTIVE_DOMAIN: u8 = 1;
const REQUESTED_DOMAIN: u8 = 2;

pub fn wrap_source_role() -> Role {
    protocol_role(WRAP_SOURCE_ROLE)
}

pub fn proactive_wrap_source_need(
    owner: FactId,
    scope: FactScope,
    workspace_id: FactId,
    min_frontier_created_at_ms: u64,
) -> ContextNeed {
    let start = proactive_wrap_key_prefix(workspace_id, min_frontier_created_at_ms);
    let mut end = proactive_wrap_key_prefix(workspace_id, u64::MAX);
    end.extend_from_slice(&[0xff; ENCODED_WRAP_SOURCE_SELECTOR_LEN]);
    range_need_for_selector(owner, wrap_source_role(), scope, start, end)
}

pub fn requested_wrap_source_need(
    owner: FactId,
    scope: FactScope,
    workspace_id: FactId,
    frontier_id: FactId,
) -> ContextNeed {
    let start = requested_wrap_key_prefix(workspace_id, frontier_id);
    let mut end = start.clone();
    end.extend_from_slice(&[0xff; ENCODED_WRAP_SOURCE_SELECTOR_LEN]);
    range_need_for_selector(owner, wrap_source_role(), scope, start, end)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WrapSourceKind {
    FrontierRoot,
    HistoryNode {
        range_start: u64,
        range_width: u64,
        bit_depth: u16,
        fact_id_prefix: FactId,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WrapSourceSelector {
    pub workspace_id: FactId,
    pub frontier_id: FactId,
    pub owner_endpoint_id: FactId,
    pub frontier_created_at_ms: u64,
    pub kind: WrapSourceKind,
}

pub fn frontier_root_wrap_source_offers(
    owner: FactId,
    scope: FactScope,
    workspace_id: FactId,
    frontier_id: FactId,
    owner_endpoint_id: FactId,
    frontier_created_at_ms: u64,
) -> Vec<ContextOffer> {
    wrap_source_offers(
        owner,
        scope,
        WrapSourceSelector {
            workspace_id,
            frontier_id,
            owner_endpoint_id,
            frontier_created_at_ms,
            kind: WrapSourceKind::FrontierRoot,
        },
    )
}

pub fn history_node_wrap_source_offers(
    owner: FactId,
    scope: FactScope,
    workspace_id: FactId,
    frontier_id: FactId,
    owner_endpoint_id: FactId,
    range_start: u64,
    range_width: u64,
    bit_depth: u16,
    fact_id_prefix: FactId,
) -> Vec<ContextOffer> {
    wrap_source_offers(
        owner,
        scope,
        WrapSourceSelector {
            workspace_id,
            frontier_id,
            owner_endpoint_id,
            frontier_created_at_ms: 0,
            kind: WrapSourceKind::HistoryNode {
                range_start,
                range_width,
                bit_depth,
                fact_id_prefix,
            },
        },
    )
}

pub fn wrap_source_offers(
    owner: FactId,
    scope: FactScope,
    source: WrapSourceSelector,
) -> Vec<ContextOffer> {
    let metadata = encode_wrap_source_selector(&source).as_bytes().to_vec();
    let proactive = point_offer(
        owner,
        scope.clone(),
        wrap_offer_key(PROACTIVE_DOMAIN, &source, &metadata),
    );
    let requested = point_offer(
        owner,
        scope,
        wrap_offer_key(REQUESTED_DOMAIN, &source, &metadata),
    );
    vec![proactive, requested]
}

fn point_offer(owner: FactId, scope: FactScope, key: Vec<u8>) -> ContextOffer {
    range_offer_for_selector(owner, wrap_source_role(), scope, key.clone(), key)
}

fn wrap_offer_key(domain: u8, source: &WrapSourceSelector, metadata: &[u8]) -> Vec<u8> {
    let mut key = match domain {
        PROACTIVE_DOMAIN => {
            proactive_wrap_key_prefix(source.workspace_id, source.frontier_created_at_ms)
        }
        REQUESTED_DOMAIN => requested_wrap_key_prefix(source.workspace_id, source.frontier_id),
        _ => unreachable!("wrap source domain is internal"),
    };
    key.extend_from_slice(metadata);
    key
}

fn proactive_wrap_key_prefix(workspace_id: FactId, frontier_created_at_ms: u64) -> Vec<u8> {
    let mut key = Vec::with_capacity(41);
    key.push(PROACTIVE_DOMAIN);
    key.extend_from_slice(&workspace_id);
    key.extend_from_slice(&frontier_created_at_ms.to_be_bytes());
    key
}

fn requested_wrap_key_prefix(workspace_id: FactId, frontier_id: FactId) -> Vec<u8> {
    let mut key = Vec::with_capacity(65);
    key.push(REQUESTED_DOMAIN);
    key.extend_from_slice(&workspace_id);
    key.extend_from_slice(&frontier_id);
    key
}

const ENCODED_WRAP_SOURCE_SELECTOR_LEN: usize = 156;

pub fn decode_wrap_source_selector(selector: &Selector) -> Option<WrapSourceSelector> {
    decode_wrap_source_metadata(selector.as_bytes())
}

fn decode_wrap_source_offer_key(key: &Selector) -> Option<(u8, WrapSourceSelector)> {
    let bytes = key.as_bytes();
    match bytes.first().copied()? {
        PROACTIVE_DOMAIN => {
            let metadata_start = 1 + 32 + 8;
            let source = decode_wrap_source_metadata(bytes.get(metadata_start..)?)?;
            Some((PROACTIVE_DOMAIN, source))
        }
        REQUESTED_DOMAIN => {
            let metadata_start = 1 + 32 + 32;
            let source = decode_wrap_source_metadata(bytes.get(metadata_start..)?)?;
            Some((REQUESTED_DOMAIN, source))
        }
        _ => None,
    }
}

fn decode_wrap_source_metadata(bytes: &[u8]) -> Option<WrapSourceSelector> {
    if bytes.len() != ENCODED_WRAP_SOURCE_SELECTOR_LEN || bytes[0] != 3 {
        return None;
    }
    let workspace_id = bytes[1..33].try_into().ok()?;
    let frontier_id = bytes[33..65].try_into().ok()?;
    let owner_endpoint_id = bytes[65..97].try_into().ok()?;
    let frontier_created_at_ms = u64::from_be_bytes(bytes[97..105].try_into().ok()?);
    match bytes[105] {
        1 => Some(WrapSourceSelector {
            workspace_id,
            frontier_id,
            owner_endpoint_id,
            frontier_created_at_ms,
            kind: WrapSourceKind::FrontierRoot,
        }),
        2 => {
            let range_start = u64::from_be_bytes(bytes[106..114].try_into().ok()?);
            let range_width = u64::from_be_bytes(bytes[114..122].try_into().ok()?);
            let bit_depth = u16::from_be_bytes(bytes[122..124].try_into().ok()?);
            let fact_id_prefix = bytes[124..156].try_into().ok()?;
            if !valid_history_coordinate(range_start, range_width, bit_depth, fact_id_prefix) {
                return None;
            }
            Some(WrapSourceSelector {
                workspace_id,
                frontier_id,
                owner_endpoint_id,
                frontier_created_at_ms,
                kind: WrapSourceKind::HistoryNode {
                    range_start,
                    range_width,
                    bit_depth,
                    fact_id_prefix,
                },
            })
        }
        _ => None,
    }
}

pub fn encode_wrap_source_selector(source: &WrapSourceSelector) -> Selector {
    let mut bytes = Vec::with_capacity(ENCODED_WRAP_SOURCE_SELECTOR_LEN);
    bytes.push(3);
    bytes.extend_from_slice(&source.workspace_id);
    bytes.extend_from_slice(&source.frontier_id);
    bytes.extend_from_slice(&source.owner_endpoint_id);
    bytes.extend_from_slice(&source.frontier_created_at_ms.to_be_bytes());
    match source.kind {
        WrapSourceKind::FrontierRoot => {
            bytes.push(1);
            bytes.extend_from_slice(&[0; 50]);
        }
        WrapSourceKind::HistoryNode {
            range_start,
            range_width,
            bit_depth,
            fact_id_prefix,
        } => {
            bytes.push(2);
            bytes.extend_from_slice(&range_start.to_be_bytes());
            bytes.extend_from_slice(&range_width.to_be_bytes());
            bytes.extend_from_slice(&bit_depth.to_be_bytes());
            bytes.extend_from_slice(&fact_id_prefix);
        }
    }
    Selector::from_bytes(bytes)
}

fn valid_history_coordinate(
    range_start: u64,
    range_width: u64,
    bit_depth: u16,
    fact_id_prefix: FactId,
) -> bool {
    range_width != 0
        && range_width.is_power_of_two()
        && range_start % range_width == 0
        && bit_depth <= 256
        && fact_id_prefix == mask_prefix_to_depth(fact_id_prefix, bit_depth)
        && (range_width == 1 || (bit_depth == 0 && fact_id_prefix == [0; 32]))
}

fn mask_prefix_to_depth(mut prefix: FactId, bit_depth: u16) -> FactId {
    let bit_depth = bit_depth as usize;
    if bit_depth >= 256 {
        return prefix;
    }
    let byte_index = bit_depth / 8;
    let remaining_bits = bit_depth % 8;
    if remaining_bits == 0 {
        prefix[byte_index..].fill(0);
    } else {
        prefix[byte_index] &= 0xff << (8 - remaining_bits);
        prefix[byte_index + 1..].fill(0);
    }
    prefix
}

pub fn decode_proactive_wrap_need(need: &ContextNeed) -> Option<(FactId, u64)> {
    let start = need.start_key.as_bytes();
    let end = need.end_key.as_bytes();
    if start.len() != 41 || start[0] != PROACTIVE_DOMAIN {
        return None;
    }
    if end.len() != 41 + ENCODED_WRAP_SOURCE_SELECTOR_LEN || end[0] != PROACTIVE_DOMAIN {
        return None;
    }
    let workspace_id: FactId = start[1..33].try_into().ok()?;
    if end[1..33] != workspace_id {
        return None;
    }
    Some((
        workspace_id,
        u64::from_be_bytes(start[33..41].try_into().ok()?),
    ))
}

pub fn decode_requested_wrap_need(need: &ContextNeed) -> Option<(FactId, FactId)> {
    let start = need.start_key.as_bytes();
    let end = need.end_key.as_bytes();
    if start.len() != 65 || start[0] != REQUESTED_DOMAIN {
        return None;
    }
    if end.len() != 65 + ENCODED_WRAP_SOURCE_SELECTOR_LEN || end[0] != REQUESTED_DOMAIN {
        return None;
    }
    let workspace_id: FactId = start[1..33].try_into().ok()?;
    let frontier_id: FactId = start[33..65].try_into().ok()?;
    if end[1..33] != workspace_id || end[33..65] != frontier_id {
        return None;
    }
    Some((workspace_id, frontier_id))
}

pub fn wrap_source_offer_matches_need(
    need: &ContextNeed,
    offer: &ContextOffer,
) -> Option<WrapSourceSelector> {
    if need.role != offer.role || need.scope != offer.scope || offer.start_key != offer.end_key {
        return None;
    }
    let (domain, source) = decode_wrap_source_offer_key(&offer.start_key)?;
    match domain {
        PROACTIVE_DOMAIN => {
            let (workspace_id, min_frontier_created_at_ms) = decode_proactive_wrap_need(need)?;
            (source.workspace_id == workspace_id
                && source.frontier_created_at_ms >= min_frontier_created_at_ms)
                .then_some(source)
        }
        REQUESTED_DOMAIN => {
            let (workspace_id, frontier_id) = decode_requested_wrap_need(need)?;
            (source.workspace_id == workspace_id && source.frontier_id == frontier_id)
                .then_some(source)
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::matchers::workspace_scope;

    #[test]
    fn wrap_source_matches_requested_frontier_only() {
        let scope = workspace_scope([1; 32]);
        let need = requested_wrap_source_need([2; 32], scope.clone(), [1; 32], [3; 32]);
        let matching =
            frontier_root_wrap_source_offers([4; 32], scope.clone(), [1; 32], [3; 32], [5; 32], 50);
        let other_frontier =
            frontier_root_wrap_source_offers([6; 32], scope, [1; 32], [7; 32], [5; 32], 50);

        assert!(matching
            .iter()
            .any(|offer| wrap_source_offer_matches_need(&need, offer).is_some()));
        assert!(!other_frontier
            .iter()
            .any(|offer| wrap_source_offer_matches_need(&need, offer).is_some()));
    }

    #[test]
    fn wrap_source_matches_proactive_minimum_creation_time() {
        let scope = workspace_scope([1; 32]);
        let need = proactive_wrap_source_need([2; 32], scope.clone(), [1; 32], 50);
        let old =
            frontier_root_wrap_source_offers([3; 32], scope.clone(), [1; 32], [4; 32], [5; 32], 49);
        let new = frontier_root_wrap_source_offers([6; 32], scope, [1; 32], [7; 32], [8; 32], 50);

        assert!(!old
            .iter()
            .any(|offer| wrap_source_offer_matches_need(&need, offer).is_some()));
        assert!(new
            .iter()
            .any(|offer| wrap_source_offer_matches_need(&need, offer).is_some()));
    }
}
