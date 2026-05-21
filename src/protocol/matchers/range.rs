//! Range context matcher.
//!
//! Range offers are candidate matches when an offered timestamp falls inside a
//! requested inclusive interval under the same role and scope.

use crate::core::context::{ContextNeed, ContextOffer, Role, Selector};
use crate::core::facts::{FactId, FactScope};
use crate::core::matchers::{
    ContextMatch, ContextMatcher, ContextMatcherDeclaration, ContextRoleDeclaration,
    SelectOnlyMatcherResult, SelectOnlyMatcherSql, SelectorFieldDeclaration, SelectorFieldType,
};
use crate::core::store::{ColumnValue, Store};
use crate::core::wake;

use super::exact::protocol_role;
use super::sql;

pub const SYNC_RANGE_FACT_ROLE: &str = "sync_range_fact";

const RANGE_NEED_SELECTOR_FIELDS: &[SelectorFieldDeclaration] = &[
    SelectorFieldDeclaration {
        name: "start",
        ty: SelectorFieldType::U64,
        offset: 0,
        len: 8,
    },
    SelectorFieldDeclaration {
        name: "end",
        ty: SelectorFieldType::U64,
        offset: 8,
        len: 8,
    },
];

const RANGE_OFFER_SELECTOR_FIELDS: &[SelectorFieldDeclaration] = &[
    SelectorFieldDeclaration {
        name: "timestamp",
        ty: SelectorFieldType::U64,
        offset: 0,
        len: 8,
    },
    SelectorFieldDeclaration {
        name: "fact_id",
        ty: SelectorFieldType::FactId,
        offset: 8,
        len: 32,
    },
    SelectorFieldDeclaration {
        name: "dependency_id",
        ty: SelectorFieldType::FactId,
        offset: 40,
        len: 32,
    },
    SelectorFieldDeclaration {
        name: "key_wrap_id",
        ty: SelectorFieldType::FactId,
        offset: 72,
        len: 32,
    },
];

pub const RANGE_FACT_OFFERS_FOR_NEED_SQL: &str = "
SELECT owner, selector
FROM context_edges
WHERE direction = 'offer'
  AND role = :role
  AND scope_key = :scope_key
  AND length(selector) = 104
  AND substr(selector, 1, 8) >= :start
  AND substr(selector, 1, 8) <= :end
ORDER BY owner, selector";

pub const RANGE_FACT_NEEDS_FOR_OFFER_SQL: &str = "
SELECT owner, selector
FROM context_edges
WHERE direction = 'need'
  AND role = :role
  AND scope_key = :scope_key
  AND length(selector) = 16
  AND substr(selector, 1, 8) <= :timestamp
  AND substr(selector, 9, 8) >= :timestamp
ORDER BY owner, selector";

pub const RANGE_FACT_WAKE_FOR_NEED_SQL: &str = "
SELECT :need_owner AS owner
FROM context_edges
WHERE direction = 'offer'
  AND role = :role
  AND scope_key = :scope_key
  AND length(selector) = 104
  AND substr(selector, 1, 8) >= :start
  AND substr(selector, 1, 8) <= :end
ORDER BY owner, selector";

pub const RANGE_FACT_WAKE_FOR_OFFER_SQL: &str = "
SELECT n.owner
FROM context_edges n
JOIN facts f ON f.id = n.owner
WHERE n.direction = 'need'
  AND n.role = :role
  AND n.scope_key = :scope_key
  AND length(n.selector) = 16
  AND substr(n.selector, 1, 8) <= :timestamp
  AND substr(n.selector, 9, 8) >= :timestamp
ORDER BY f.timestamp, n.owner";

pub const RANGE_FACT_CONTEXT_ROLE: ContextRoleDeclaration = ContextRoleDeclaration {
    role: SYNC_RANGE_FACT_ROLE,
    need_selector: RANGE_NEED_SELECTOR_FIELDS,
    offer_selector: RANGE_OFFER_SELECTOR_FIELDS,
    matcher: ContextMatcherDeclaration::SelectOnlySql {
        added_need: SelectOnlyMatcherSql {
            sql: RANGE_FACT_OFFERS_FOR_NEED_SQL,
            result: SelectOnlyMatcherResult::OffersForNeed,
        },
        added_offer: SelectOnlyMatcherSql {
            sql: RANGE_FACT_NEEDS_FOR_OFFER_SQL,
            result: SelectOnlyMatcherResult::NeedsForOffer,
        },
    },
};

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

    fn declaration(&self) -> Option<ContextRoleDeclaration> {
        Some(RANGE_FACT_CONTEXT_ROLE)
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
            .filter_map(|offer| range_fact_match(need, offer))
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
            .filter_map(|need| range_fact_match(need, offer))
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
        let Some((start, end)) = decode_range_need_selector(&need.selector) else {
            return Ok(Some(Vec::new()));
        };
        let scope_key = sql::scope_key_for_sql(&need.scope);
        let start = start.to_be_bytes();
        let end = end.to_be_bytes();
        let params = [
            (":role", ColumnValue::Text(self.role.as_str())),
            (":scope_key", ColumnValue::Bytes(&scope_key)),
            (":start", ColumnValue::Bytes(&start)),
            (":end", ColumnValue::Bytes(&end)),
        ];
        sql::select_offers_for_need(store, RANGE_FACT_OFFERS_FOR_NEED_SQL, &params, need).map(Some)
    }

    fn matching_needs_for_offer_from_store(
        &self,
        store: &Store,
        offer: &ContextOffer,
    ) -> Result<Option<Vec<ContextNeed>>, String> {
        if offer.role != self.role {
            return Ok(Some(Vec::new()));
        }
        let Some(selector) = decode_range_offer_selector(&offer.selector) else {
            return Ok(Some(Vec::new()));
        };
        let scope_key = sql::scope_key_for_sql(&offer.scope);
        let timestamp = selector.timestamp.to_be_bytes();
        let params = [
            (":role", ColumnValue::Text(self.role.as_str())),
            (":scope_key", ColumnValue::Bytes(&scope_key)),
            (":timestamp", ColumnValue::Bytes(&timestamp)),
        ];
        sql::select_needs_for_offer(store, RANGE_FACT_NEEDS_FOR_OFFER_SQL, &params, offer).map(Some)
    }

    fn wake_select_for_added_need(
        &self,
        need: &ContextNeed,
    ) -> Result<Option<wake::Select>, String> {
        if need.role != self.role {
            return Ok(Some(wake::Select::empty()));
        }
        let Some((start, end)) = decode_range_need_selector(&need.selector) else {
            return Ok(Some(wake::Select::empty()));
        };
        let scope_key = sql::scope_key_for_sql(&need.scope);
        Ok(Some(sql::wake_select(
            RANGE_FACT_WAKE_FOR_NEED_SQL,
            vec![
                wake::Param::bytes(":need_owner", need.owner),
                wake::Param::text(":role", self.role.as_str()),
                wake::Param::bytes(":scope_key", scope_key),
                wake::Param::bytes(":start", start.to_be_bytes()),
                wake::Param::bytes(":end", end.to_be_bytes()),
            ],
        )))
    }

    fn wake_select_for_added_offer(
        &self,
        offer: &ContextOffer,
    ) -> Result<Option<wake::Select>, String> {
        if offer.role != self.role {
            return Ok(Some(wake::Select::empty()));
        }
        let Some(selector) = decode_range_offer_selector(&offer.selector) else {
            return Ok(Some(wake::Select::empty()));
        };
        let scope_key = sql::scope_key_for_sql(&offer.scope);
        Ok(Some(sql::wake_select(
            RANGE_FACT_WAKE_FOR_OFFER_SQL,
            vec![
                wake::Param::text(":role", self.role.as_str()),
                wake::Param::bytes(":scope_key", scope_key),
                wake::Param::bytes(":timestamp", selector.timestamp.to_be_bytes()),
            ],
        )))
    }
}

pub fn range_fact_match(need: &ContextNeed, offer: &ContextOffer) -> Option<ContextMatch> {
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
    fn range_fact_matcher_matches_inclusive_bounds() {
        let scope = workspace_scope([1; 32]);
        let need = range_fact_need([2; 32], scope.clone(), 10, 20);
        let lower = range_fact_offer([3; 32], scope.clone(), 10, [4; 32], [5; 32], [6; 32]);
        let upper = range_fact_offer([7; 32], scope.clone(), 20, [8; 32], [9; 32], [10; 32]);

        assert!(range_fact_match(&need, &lower).is_some());
        assert!(range_fact_match(&need, &upper).is_some());
    }

    #[test]
    fn range_fact_matcher_rejects_out_of_range_offer() {
        let scope = workspace_scope([1; 32]);
        let need = range_fact_need([2; 32], scope.clone(), 10, 20);
        let offer = range_fact_offer([3; 32], scope, 21, [4; 32], [5; 32], [6; 32]);

        assert!(range_fact_match(&need, &offer).is_none());
    }

    #[test]
    fn range_fact_matcher_uses_declared_sql_candidate_queries() {
        let store =
            Store::open_memory_with_schema_sources(&[CORE_SCHEMA_SOURCE]).expect("open store");
        let scope = workspace_scope([1; 32]);
        let need = range_fact_need([2; 32], scope.clone(), 10, 20);
        let matching = range_fact_offer([3; 32], scope.clone(), 12, [4; 32], [5; 32], [6; 32]);
        let too_late = range_fact_offer([7; 32], scope.clone(), 21, [8; 32], [9; 32], [10; 32]);
        store
            .insert_table_rows(vec![
                context_offer_row(&matching),
                context_offer_row(&too_late),
                context_need_row(&need),
            ])
            .expect("insert context rows");

        let matcher = RangeFactMatcher::new();
        let offers = matcher
            .matching_offers_for_need_from_store(&store, &need)
            .expect("query offers")
            .expect("sql query");
        assert_eq!(offers, vec![matching.clone()]);

        let needs = matcher
            .matching_needs_for_offer_from_store(&store, &matching)
            .expect("query needs")
            .expect("sql query");
        assert_eq!(needs, vec![need]);
    }
}
