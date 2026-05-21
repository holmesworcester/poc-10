//! Range context matcher.
//!
//! Range offers are candidate matches when an offered timestamp falls inside a
//! requested inclusive interval under the same role and scope.

use crate::core::context::{ContextNeed, ContextOffer, Role, Selector};
use crate::core::facts::{FactId, FactScope};
use crate::core::select;

use super::exact::protocol_role;
use super::sql;

pub const SYNC_RANGE_FACT_ROLE: &str = "sync_range_fact";

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
JOIN local_fact_admissions a ON a.fact_id = n.owner
WHERE n.direction = 'need'
  AND n.role = :role
  AND n.scope_key = :scope_key
  AND length(n.selector) = 16
  AND substr(n.selector, 1, 8) <= :timestamp
  AND substr(n.selector, 9, 8) >= :timestamp
ORDER BY a.received_at, n.owner";

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

sql::sql_backed_matcher! {
    RangeFactMatcher {
        offers_for_need: RANGE_FACT_OFFERS_FOR_NEED_SQL => range_need_query_params,
        wake_for_need: RANGE_FACT_WAKE_FOR_NEED_SQL => range_need_wake_params,
        wake_for_offer: RANGE_FACT_WAKE_FOR_OFFER_SQL => range_offer_wake_params,
    }
}

fn range_need_query_params(role: &Role, need: &ContextNeed) -> Option<Vec<select::Param>> {
    let Some((start, end)) = decode_range_need_selector(&need.selector) else {
        return None;
    };
    let scope_key = sql::scope_key_for_sql(&need.scope);
    Some(vec![
        select::Param::text(":role", role.as_str()),
        select::Param::bytes(":scope_key", scope_key),
        select::Param::bytes(":start", start.to_be_bytes()),
        select::Param::bytes(":end", end.to_be_bytes()),
    ])
}

fn range_need_wake_params(role: &Role, need: &ContextNeed) -> Option<Vec<select::Param>> {
    let Some((start, end)) = decode_range_need_selector(&need.selector) else {
        return None;
    };
    let scope_key = sql::scope_key_for_sql(&need.scope);
    Some(vec![
        select::Param::bytes(":need_owner", need.owner),
        select::Param::text(":role", role.as_str()),
        select::Param::bytes(":scope_key", scope_key),
        select::Param::bytes(":start", start.to_be_bytes()),
        select::Param::bytes(":end", end.to_be_bytes()),
    ])
}

fn range_offer_wake_params(role: &Role, offer: &ContextOffer) -> Option<Vec<select::Param>> {
    let Some(selector) = decode_range_offer_selector(&offer.selector) else {
        return None;
    };
    let scope_key = sql::scope_key_for_sql(&offer.scope);
    Some(vec![
        select::Param::text(":role", role.as_str()),
        select::Param::bytes(":scope_key", scope_key),
        select::Param::bytes(":timestamp", selector.timestamp.to_be_bytes()),
    ])
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
    use crate::core::matchers::ContextMatcher;
    use crate::core::pipeline::context::{
        insert_context_need_for_test, insert_context_offer_for_test,
    };
    use crate::core::schema::CORE_SCHEMA_SOURCE;
    use crate::core::store::Store;
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

    #[test]
    fn range_fact_matcher_uses_declared_sql_candidate_queries() {
        let store =
            Store::open_memory_with_schema_sources(&[CORE_SCHEMA_SOURCE]).expect("open store");
        let scope = workspace_scope([1; 32]);
        let need = range_fact_need([2; 32], scope.clone(), 10, 20);
        let matching = range_fact_offer([3; 32], scope.clone(), 12, [4; 32], [5; 32], [6; 32]);
        let too_late = range_fact_offer([7; 32], scope.clone(), 21, [8; 32], [9; 32], [10; 32]);
        insert_context_offer_for_test(&store, &matching).expect("insert matching offer");
        insert_context_offer_for_test(&store, &too_late).expect("insert non-matching offer");
        insert_context_need_for_test(&store, &need).expect("insert need");

        let matcher = RangeFactMatcher::new();
        let offers = matcher
            .matching_offers_for_need_from_store(&store, &need)
            .expect("query offers");
        assert_eq!(offers, vec![matching.clone()]);
    }
}
