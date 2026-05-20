//! Coverage context matcher.
//!
//! A coverage offer can satisfy many point needs when the scope, workspace,
//! frontier, time range, and leaf prefix line up. Projectors still validate the
//! matched payload before treating it as protocol authority.

use crate::core::context::{ContextNeed, ContextOffer, Role, Selector};
use crate::core::facts::{FactId, FactScope};
use crate::core::matchers::{
    ContextMatch, ContextMatcher, ContextMatcherDeclaration, ContextRoleDeclaration,
    SelectOnlyMatcherResult, SelectOnlyMatcherSql, SelectorFieldDeclaration, SelectorFieldType,
};
use crate::core::store::{ColumnValue, Store};

use super::exact::protocol_role;
use super::sql;

pub const SECRET_COVERAGE_ROLE: &str = "secret_coverage";

const SECRET_NEED_SELECTOR_FIELDS: &[SelectorFieldDeclaration] = &[
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
        name: "minute",
        ty: SelectorFieldType::U64,
        offset: 65,
        len: 8,
    },
    SelectorFieldDeclaration {
        name: "leaf_id",
        ty: SelectorFieldType::FactId,
        offset: 73,
        len: 32,
    },
];

const SECRET_OFFER_SELECTOR_FIELDS: &[SelectorFieldDeclaration] = &[
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
        name: "start_minute",
        ty: SelectorFieldType::U64,
        offset: 65,
        len: 8,
    },
    SelectorFieldDeclaration {
        name: "end_minute",
        ty: SelectorFieldType::U64,
        offset: 73,
        len: 8,
    },
    SelectorFieldDeclaration {
        name: "prefix_bytes",
        ty: SelectorFieldType::U8,
        offset: 81,
        len: 1,
    },
    SelectorFieldDeclaration {
        name: "leaf_prefix",
        ty: SelectorFieldType::FactId,
        offset: 82,
        len: 32,
    },
];

pub const SECRET_COVERAGE_OFFERS_FOR_NEED_SQL: &str = "
SELECT owner, selector, payload_ref
FROM context_offers
WHERE role = :role
  AND scope_key = :scope_key
  AND length(selector) = 114
  AND substr(selector, 1, 1) = x'01'
  AND substr(selector, 2, 32) = :workspace_id
  AND substr(selector, 34, 32) = :frontier_id
  AND substr(selector, 66, 8) <= :minute
  AND substr(selector, 74, 8) >= :minute
  AND (
    substr(selector, 82, 1) = x'00'
    OR (substr(selector, 82, 1) = x'01' AND substr(selector, 83, 1) = substr(:leaf_id, 1, 1))
    OR (substr(selector, 82, 1) = x'02' AND substr(selector, 83, 2) = substr(:leaf_id, 1, 2))
    OR (substr(selector, 82, 1) = x'03' AND substr(selector, 83, 3) = substr(:leaf_id, 1, 3))
    OR (substr(selector, 82, 1) = x'04' AND substr(selector, 83, 4) = substr(:leaf_id, 1, 4))
    OR (substr(selector, 82, 1) = x'05' AND substr(selector, 83, 5) = substr(:leaf_id, 1, 5))
    OR (substr(selector, 82, 1) = x'06' AND substr(selector, 83, 6) = substr(:leaf_id, 1, 6))
    OR (substr(selector, 82, 1) = x'07' AND substr(selector, 83, 7) = substr(:leaf_id, 1, 7))
    OR (substr(selector, 82, 1) = x'08' AND substr(selector, 83, 8) = substr(:leaf_id, 1, 8))
    OR (substr(selector, 82, 1) = x'09' AND substr(selector, 83, 9) = substr(:leaf_id, 1, 9))
    OR (substr(selector, 82, 1) = x'0A' AND substr(selector, 83, 10) = substr(:leaf_id, 1, 10))
    OR (substr(selector, 82, 1) = x'0B' AND substr(selector, 83, 11) = substr(:leaf_id, 1, 11))
    OR (substr(selector, 82, 1) = x'0C' AND substr(selector, 83, 12) = substr(:leaf_id, 1, 12))
    OR (substr(selector, 82, 1) = x'0D' AND substr(selector, 83, 13) = substr(:leaf_id, 1, 13))
    OR (substr(selector, 82, 1) = x'0E' AND substr(selector, 83, 14) = substr(:leaf_id, 1, 14))
    OR (substr(selector, 82, 1) = x'0F' AND substr(selector, 83, 15) = substr(:leaf_id, 1, 15))
    OR (substr(selector, 82, 1) = x'10' AND substr(selector, 83, 16) = substr(:leaf_id, 1, 16))
    OR (substr(selector, 82, 1) = x'11' AND substr(selector, 83, 17) = substr(:leaf_id, 1, 17))
    OR (substr(selector, 82, 1) = x'12' AND substr(selector, 83, 18) = substr(:leaf_id, 1, 18))
    OR (substr(selector, 82, 1) = x'13' AND substr(selector, 83, 19) = substr(:leaf_id, 1, 19))
    OR (substr(selector, 82, 1) = x'14' AND substr(selector, 83, 20) = substr(:leaf_id, 1, 20))
    OR (substr(selector, 82, 1) = x'15' AND substr(selector, 83, 21) = substr(:leaf_id, 1, 21))
    OR (substr(selector, 82, 1) = x'16' AND substr(selector, 83, 22) = substr(:leaf_id, 1, 22))
    OR (substr(selector, 82, 1) = x'17' AND substr(selector, 83, 23) = substr(:leaf_id, 1, 23))
    OR (substr(selector, 82, 1) = x'18' AND substr(selector, 83, 24) = substr(:leaf_id, 1, 24))
    OR (substr(selector, 82, 1) = x'19' AND substr(selector, 83, 25) = substr(:leaf_id, 1, 25))
    OR (substr(selector, 82, 1) = x'1A' AND substr(selector, 83, 26) = substr(:leaf_id, 1, 26))
    OR (substr(selector, 82, 1) = x'1B' AND substr(selector, 83, 27) = substr(:leaf_id, 1, 27))
    OR (substr(selector, 82, 1) = x'1C' AND substr(selector, 83, 28) = substr(:leaf_id, 1, 28))
    OR (substr(selector, 82, 1) = x'1D' AND substr(selector, 83, 29) = substr(:leaf_id, 1, 29))
    OR (substr(selector, 82, 1) = x'1E' AND substr(selector, 83, 30) = substr(:leaf_id, 1, 30))
    OR (substr(selector, 82, 1) = x'1F' AND substr(selector, 83, 31) = substr(:leaf_id, 1, 31))
    OR (substr(selector, 82, 1) = x'20' AND substr(selector, 83, 32) = substr(:leaf_id, 1, 32))
  )
ORDER BY owner, selector, payload_ref";

pub const SECRET_COVERAGE_NEEDS_FOR_OFFER_SQL: &str = "
SELECT owner, selector
FROM context_needs
WHERE role = :role
  AND scope_key = :scope_key
  AND length(selector) = 105
  AND substr(selector, 1, 1) = x'01'
  AND substr(selector, 2, 32) = :workspace_id
  AND substr(selector, 34, 32) = :frontier_id
  AND substr(selector, 66, 8) >= :start_minute
  AND substr(selector, 66, 8) <= :end_minute
  AND substr(selector, 74, :prefix_len) = :leaf_prefix
ORDER BY owner, selector";

pub const SECRET_COVERAGE_CONTEXT_ROLE: ContextRoleDeclaration = ContextRoleDeclaration {
    role: SECRET_COVERAGE_ROLE,
    need_selector: SECRET_NEED_SELECTOR_FIELDS,
    offer_selector: SECRET_OFFER_SELECTOR_FIELDS,
    matcher: ContextMatcherDeclaration::SelectOnlySql {
        added_need: SelectOnlyMatcherSql {
            sql: SECRET_COVERAGE_OFFERS_FOR_NEED_SQL,
            result: SelectOnlyMatcherResult::OffersForNeed,
        },
        added_offer: SelectOnlyMatcherSql {
            sql: SECRET_COVERAGE_NEEDS_FOR_OFFER_SQL,
            result: SelectOnlyMatcherResult::NeedsForOffer,
        },
    },
};

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

    fn declaration(&self) -> Option<ContextRoleDeclaration> {
        Some(SECRET_COVERAGE_CONTEXT_ROLE)
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

    fn matching_offers_for_need_from_store(
        &self,
        store: &Store,
        need: &ContextNeed,
    ) -> Result<Option<Vec<ContextOffer>>, String> {
        if need.role != self.role {
            return Ok(Some(Vec::new()));
        }
        let Some(selector) = decode_secret_need_selector(&need.selector) else {
            return Ok(Some(Vec::new()));
        };
        let scope_key = sql::scope_key_for_sql(&need.scope);
        let minute = selector.minute.to_be_bytes();
        let params = [
            (":role", ColumnValue::Text(self.role.as_str())),
            (":scope_key", ColumnValue::Bytes(&scope_key)),
            (":workspace_id", ColumnValue::Bytes(&selector.workspace_id)),
            (":frontier_id", ColumnValue::Bytes(&selector.frontier_id)),
            (":minute", ColumnValue::Bytes(&minute)),
            (":leaf_id", ColumnValue::Bytes(&selector.leaf_id)),
        ];
        sql::select_offers_for_need(store, SECRET_COVERAGE_OFFERS_FOR_NEED_SQL, &params, need)
            .map(Some)
    }

    fn matching_needs_for_offer_from_store(
        &self,
        store: &Store,
        offer: &ContextOffer,
    ) -> Result<Option<Vec<ContextNeed>>, String> {
        if offer.role != self.role {
            return Ok(Some(Vec::new()));
        }
        let Some(selector) = decode_secret_offer_selector(&offer.selector) else {
            return Ok(Some(Vec::new()));
        };
        if selector.start_minute > selector.end_minute {
            return Ok(Some(Vec::new()));
        }
        let scope_key = sql::scope_key_for_sql(&offer.scope);
        let start_minute = selector.start_minute.to_be_bytes();
        let end_minute = selector.end_minute.to_be_bytes();
        let prefix_len = i64::from(selector.prefix_bytes);
        let leaf_prefix = selector.leaf_prefix[..usize::from(selector.prefix_bytes)].to_vec();
        let params = [
            (":role", ColumnValue::Text(self.role.as_str())),
            (":scope_key", ColumnValue::Bytes(&scope_key)),
            (":workspace_id", ColumnValue::Bytes(&selector.workspace_id)),
            (":frontier_id", ColumnValue::Bytes(&selector.frontier_id)),
            (":start_minute", ColumnValue::Bytes(&start_minute)),
            (":end_minute", ColumnValue::Bytes(&end_minute)),
            (":prefix_len", ColumnValue::I64(prefix_len)),
            (":leaf_prefix", ColumnValue::Bytes(&leaf_prefix)),
        ];
        sql::select_needs_for_offer(store, SECRET_COVERAGE_NEEDS_FOR_OFFER_SQL, &params, offer)
            .map(Some)
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
    use crate::core::context_change_helpers::{context_need_row, context_offer_row};
    use crate::core::schema_dsl::CORE_SCHEMA_SOURCE;
    use crate::core::store::Store;
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

    #[test]
    fn secret_coverage_matcher_uses_declared_sql_candidate_queries() {
        let store =
            Store::open_memory_with_schema_sources(&[CORE_SCHEMA_SOURCE]).expect("open store");
        let workspace = [1; 32];
        let frontier = [2; 32];
        let scope = workspace_scope(workspace);
        let mut prefix = [0; 32];
        prefix[0] = 0b1010_1111;
        let mut matching_leaf = [0; 32];
        matching_leaf[0] = 0b1010_1111;
        let mut other_leaf = [0; 32];
        other_leaf[0] = 0b1111_0000;

        let need = secret_need(
            [3; 32],
            scope.clone(),
            workspace,
            frontier,
            42,
            matching_leaf,
        );
        let wrong_prefix_need =
            secret_need([4; 32], scope.clone(), workspace, frontier, 42, other_leaf);
        let offer = secret_offer(
            [5; 32],
            scope.clone(),
            workspace,
            frontier,
            40,
            50,
            1,
            prefix,
        );
        store
            .insert_table_rows(vec![
                context_need_row(&need),
                context_need_row(&wrong_prefix_need),
                context_offer_row(&offer),
            ])
            .expect("insert context rows");

        let matcher = SecretCoverageMatcher::new();
        let offers = matcher
            .matching_offers_for_need_from_store(&store, &need)
            .expect("query offers")
            .expect("sql query");
        assert_eq!(offers, vec![offer.clone()]);

        let needs = matcher
            .matching_needs_for_offer_from_store(&store, &offer)
            .expect("query needs")
            .expect("sql query");
        assert_eq!(needs, vec![need]);
    }
}
