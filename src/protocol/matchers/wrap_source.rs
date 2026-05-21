//! Wrap-source context matcher.
//!
//! A wrap source advertises local key material that can satisfy proactive
//! rotation work or a specific remote key request. Matching remains candidate
//! lookup; encryption projectors validate payloads and signer authority.

use crate::core::context::{ContextNeed, ContextOffer, Role, Selector};
use crate::core::facts::{FactId, FactScope};
use crate::core::matchers::{
    ContextMatch, ContextMatcher, ContextMatcherDeclaration, ContextRoleDeclaration,
    SelectOnlyMatcherResult, SelectOnlyMatcherSql, SelectorFieldDeclaration, SelectorFieldType,
};
use crate::core::store::{ColumnValue, Store};

use super::exact::protocol_role;
use super::sql;

pub const WRAP_SOURCE_ROLE: &str = "wrap_source";

const WRAP_NEED_SELECTOR_FIELDS: &[SelectorFieldDeclaration] = &[
    SelectorFieldDeclaration {
        name: "variant",
        ty: SelectorFieldType::U8,
        offset: 0,
        len: 1,
    },
    SelectorFieldDeclaration {
        name: "workspace_id",
        ty: SelectorFieldType::FactId,
        offset: 1,
        len: 32,
    },
    SelectorFieldDeclaration {
        name: "min_frontier_created_at_ms",
        ty: SelectorFieldType::U64,
        offset: 33,
        len: 8,
    },
    SelectorFieldDeclaration {
        name: "frontier_id",
        ty: SelectorFieldType::FactId,
        offset: 33,
        len: 32,
    },
];

const WRAP_OFFER_SELECTOR_FIELDS: &[SelectorFieldDeclaration] = &[
    SelectorFieldDeclaration {
        name: "version",
        ty: SelectorFieldType::U8,
        offset: 0,
        len: 1,
    },
    SelectorFieldDeclaration {
        name: "workspace_id",
        ty: SelectorFieldType::FactId,
        offset: 1,
        len: 32,
    },
    SelectorFieldDeclaration {
        name: "frontier_id",
        ty: SelectorFieldType::FactId,
        offset: 33,
        len: 32,
    },
    SelectorFieldDeclaration {
        name: "owner_endpoint_id",
        ty: SelectorFieldType::FactId,
        offset: 65,
        len: 32,
    },
    SelectorFieldDeclaration {
        name: "frontier_created_at_ms",
        ty: SelectorFieldType::U64,
        offset: 97,
        len: 8,
    },
    SelectorFieldDeclaration {
        name: "kind",
        ty: SelectorFieldType::U8,
        offset: 105,
        len: 1,
    },
    SelectorFieldDeclaration {
        name: "range_start",
        ty: SelectorFieldType::U64,
        offset: 106,
        len: 8,
    },
    SelectorFieldDeclaration {
        name: "range_width",
        ty: SelectorFieldType::U64,
        offset: 114,
        len: 8,
    },
    SelectorFieldDeclaration {
        name: "bit_depth",
        ty: SelectorFieldType::U16,
        offset: 122,
        len: 2,
    },
    SelectorFieldDeclaration {
        name: "fact_id_prefix",
        ty: SelectorFieldType::FactId,
        offset: 124,
        len: 32,
    },
];

pub const WRAP_SOURCE_OFFERS_FOR_NEED_SQL: &str = "
SELECT owner, selector
FROM context_offers
WHERE role = :role
  AND scope_key = :scope_key
  AND length(selector) = 156
  AND substr(selector, 1, 1) = x'03'
  AND substr(selector, 2, 32) = :workspace_id
  AND (
    (:need_kind = 1 AND substr(selector, 98, 8) >= :min_frontier_created_at_ms)
    OR (:need_kind = 2 AND substr(selector, 34, 32) = :frontier_id)
  )
ORDER BY owner, selector";

pub const WRAP_SOURCE_NEEDS_FOR_OFFER_SQL: &str = "
SELECT owner, selector
FROM context_needs
WHERE role = :role
  AND scope_key = :scope_key
  AND (
    (
      length(selector) = 41
      AND substr(selector, 1, 1) = x'01'
      AND substr(selector, 2, 32) = :workspace_id
      AND substr(selector, 34, 8) <= :frontier_created_at_ms
    )
    OR
    (
      length(selector) = 65
      AND substr(selector, 1, 1) = x'02'
      AND substr(selector, 2, 32) = :workspace_id
      AND substr(selector, 34, 32) = :frontier_id
    )
  )
ORDER BY owner, selector";

pub const WRAP_SOURCE_CONTEXT_ROLE: ContextRoleDeclaration = ContextRoleDeclaration {
    role: WRAP_SOURCE_ROLE,
    need_selector: WRAP_NEED_SELECTOR_FIELDS,
    offer_selector: WRAP_OFFER_SELECTOR_FIELDS,
    matcher: ContextMatcherDeclaration::SelectOnlySql {
        added_need: SelectOnlyMatcherSql {
            sql: WRAP_SOURCE_OFFERS_FOR_NEED_SQL,
            result: SelectOnlyMatcherResult::OffersForNeed,
        },
        added_offer: SelectOnlyMatcherSql {
            sql: WRAP_SOURCE_NEEDS_FOR_OFFER_SQL,
            result: SelectOnlyMatcherResult::NeedsForOffer,
        },
    },
};

pub fn wrap_source_role() -> Role {
    protocol_role(WRAP_SOURCE_ROLE)
}

pub fn proactive_wrap_source_need(
    owner: FactId,
    scope: FactScope,
    workspace_id: FactId,
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
    workspace_id: FactId,
    frontier_id: FactId,
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

pub fn frontier_root_wrap_source_offer(
    owner: FactId,
    scope: FactScope,
    workspace_id: FactId,
    frontier_id: FactId,
    owner_endpoint_id: FactId,
    frontier_created_at_ms: u64,
) -> ContextOffer {
    wrap_source_offer(
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

pub fn history_node_wrap_source_offer(
    owner: FactId,
    scope: FactScope,
    workspace_id: FactId,
    frontier_id: FactId,
    owner_endpoint_id: FactId,
    range_start: u64,
    range_width: u64,
    bit_depth: u16,
    fact_id_prefix: FactId,
) -> ContextOffer {
    wrap_source_offer(
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
    }
}

pub fn decode_wrap_source_selector(selector: &Selector) -> Option<WrapSourceSelector> {
    let bytes = selector.as_bytes();
    if bytes.len() != 156 || bytes[0] != 3 {
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
    let mut bytes = Vec::with_capacity(156);
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

pub fn decode_proactive_wrap_need(selector: &Selector) -> Option<(FactId, u64)> {
    let bytes = selector.as_bytes();
    if bytes.len() != 41 || bytes[0] != 1 {
        return None;
    }
    Some((
        bytes[1..33].try_into().ok()?,
        u64::from_be_bytes(bytes[33..41].try_into().ok()?),
    ))
}

pub fn decode_requested_wrap_need(selector: &Selector) -> Option<(FactId, FactId)> {
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

    fn declaration(&self) -> Option<ContextRoleDeclaration> {
        Some(WRAP_SOURCE_CONTEXT_ROLE)
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

    fn matching_offers_for_need_from_store(
        &self,
        store: &Store,
        need: &ContextNeed,
    ) -> Result<Option<Vec<ContextOffer>>, String> {
        if need.role != self.role {
            return Ok(Some(Vec::new()));
        }
        let (need_kind, workspace_id, frontier_id, min_frontier_created_at_ms) =
            if let Some((workspace_id, min_frontier_created_at_ms)) =
                decode_proactive_wrap_need(&need.selector)
            {
                (
                    1,
                    workspace_id,
                    [0; 32],
                    min_frontier_created_at_ms.to_be_bytes(),
                )
            } else if let Some((workspace_id, frontier_id)) =
                decode_requested_wrap_need(&need.selector)
            {
                (2, workspace_id, frontier_id, 0u64.to_be_bytes())
            } else {
                return Ok(Some(Vec::new()));
            };
        let scope_key = sql::scope_key_for_sql(&need.scope);
        let params = [
            (":role", ColumnValue::Text(self.role.as_str())),
            (":scope_key", ColumnValue::Bytes(&scope_key)),
            (":need_kind", ColumnValue::I64(need_kind)),
            (":workspace_id", ColumnValue::Bytes(&workspace_id)),
            (":frontier_id", ColumnValue::Bytes(&frontier_id)),
            (
                ":min_frontier_created_at_ms",
                ColumnValue::Bytes(&min_frontier_created_at_ms),
            ),
        ];
        sql::select_offers_for_need(store, WRAP_SOURCE_OFFERS_FOR_NEED_SQL, &params, need).map(Some)
    }

    fn matching_needs_for_offer_from_store(
        &self,
        store: &Store,
        offer: &ContextOffer,
    ) -> Result<Option<Vec<ContextNeed>>, String> {
        if offer.role != self.role {
            return Ok(Some(Vec::new()));
        }
        let Some(selector) = decode_wrap_source_selector(&offer.selector) else {
            return Ok(Some(Vec::new()));
        };
        let scope_key = sql::scope_key_for_sql(&offer.scope);
        let frontier_created_at_ms = selector.frontier_created_at_ms.to_be_bytes();
        let params = [
            (":role", ColumnValue::Text(self.role.as_str())),
            (":scope_key", ColumnValue::Bytes(&scope_key)),
            (":workspace_id", ColumnValue::Bytes(&selector.workspace_id)),
            (":frontier_id", ColumnValue::Bytes(&selector.frontier_id)),
            (
                ":frontier_created_at_ms",
                ColumnValue::Bytes(&frontier_created_at_ms),
            ),
        ];
        sql::select_needs_for_offer(store, WRAP_SOURCE_NEEDS_FOR_OFFER_SQL, &params, offer)
            .map(Some)
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
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::pipeline::{context_need_row, context_offer_row};
    use crate::core::schema::CORE_SCHEMA_SOURCE;
    use crate::core::store::Store;
    use crate::protocol::matchers::workspace_scope;

    #[test]
    fn wrap_source_matches_requested_frontier_only() {
        let scope = workspace_scope([1; 32]);
        let need = requested_wrap_source_need([2; 32], scope.clone(), [1; 32], [3; 32]);
        let matching =
            frontier_root_wrap_source_offer([4; 32], scope.clone(), [1; 32], [3; 32], [5; 32], 50);
        let other_frontier =
            frontier_root_wrap_source_offer([6; 32], scope, [1; 32], [7; 32], [5; 32], 50);

        assert!(wrap_source_match(&need, &matching).is_some());
        assert!(wrap_source_match(&need, &other_frontier).is_none());
    }

    #[test]
    fn wrap_source_matches_proactive_minimum_creation_time() {
        let scope = workspace_scope([1; 32]);
        let need = proactive_wrap_source_need([2; 32], scope.clone(), [1; 32], 50);
        let old =
            frontier_root_wrap_source_offer([3; 32], scope.clone(), [1; 32], [4; 32], [5; 32], 49);
        let new = frontier_root_wrap_source_offer([6; 32], scope, [1; 32], [7; 32], [8; 32], 50);

        assert!(wrap_source_match(&need, &old).is_none());
        assert!(wrap_source_match(&need, &new).is_some());
    }

    #[test]
    fn wrap_source_matcher_uses_declared_sql_candidate_queries() {
        let store =
            Store::open_memory_with_schema_sources(&[CORE_SCHEMA_SOURCE]).expect("open store");
        let scope = workspace_scope([1; 32]);
        let requested = requested_wrap_source_need([2; 32], scope.clone(), [1; 32], [3; 32]);
        let proactive = proactive_wrap_source_need([4; 32], scope.clone(), [1; 32], 50);
        let matching =
            frontier_root_wrap_source_offer([5; 32], scope.clone(), [1; 32], [3; 32], [6; 32], 50);
        let other_frontier =
            frontier_root_wrap_source_offer([7; 32], scope.clone(), [1; 32], [8; 32], [6; 32], 50);
        store
            .insert_table_rows(vec![
                context_need_row(&requested),
                context_need_row(&proactive),
                context_offer_row(&matching),
                context_offer_row(&other_frontier),
            ])
            .expect("insert context rows");

        let matcher = WrapSourceMatcher::new();
        let offers = matcher
            .matching_offers_for_need_from_store(&store, &requested)
            .expect("query offers")
            .expect("sql query");
        assert_eq!(offers, vec![matching.clone()]);

        let needs = matcher
            .matching_needs_for_offer_from_store(&store, &matching)
            .expect("query needs")
            .expect("sql query");
        assert_eq!(needs, vec![requested, proactive]);
    }
}
