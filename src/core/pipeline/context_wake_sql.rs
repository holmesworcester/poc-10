//! SQL helpers for matching pending context changes against current rows.

use super::context_codec::scope_key;
use crate::core::context::ContextSetDelta;
use crate::core::context::{ContextNeed, ContextOffer, Role};
use crate::core::matchers::{ContextMatch, ContextMatcher};
use crate::core::pipeline::{CONTEXT_NEEDS, CONTEXT_OFFERS};
use crate::core::schema_dsl::ColumnType;
use crate::core::store::{ColumnValue, SelectColumn, SelectedRow, SelectedValue, Store};
use std::collections::BTreeSet;

pub(super) fn exact_context_matches(
    store: &Store,
    delta: &ContextSetDelta,
    matchers: &[&dyn ContextMatcher],
) -> rusqlite::Result<Vec<ContextMatch>> {
    let exact_roles = exact_matcher_roles(matchers);
    if exact_roles.is_empty() {
        return Ok(Vec::new());
    }

    let mut matches = BTreeSet::new();
    for need in delta
        .added_needs
        .iter()
        .filter(|need| exact_roles.contains(&need.role))
    {
        for offer_owner in exact_offer_owners_for_need(store, need)? {
            matches.insert(ContextMatch {
                need_owner: need.owner,
                offer_owner,
            });
        }
    }
    for offer in delta
        .added_offers
        .iter()
        .filter(|offer| exact_roles.contains(&offer.role))
    {
        for need_owner in exact_need_owners_for_offer(store, offer)? {
            matches.insert(ContextMatch {
                need_owner,
                offer_owner: offer.owner,
            });
        }
    }
    Ok(matches.into_iter().collect())
}

/// Keep only added needs/offers that still exist at commit time.
///
/// A fact may have been purged or reprojected after the pending context-change
/// row was written. Matching against current rows prevents stale wakeups.
pub(super) fn current_stored_context_delta(
    store: &Store,
    delta: &ContextSetDelta,
) -> rusqlite::Result<ContextSetDelta> {
    let mut current = ContextSetDelta::default();
    for need in &delta.added_needs {
        if context_need_exists(store, need)? {
            current.added_needs.push(need.clone());
        }
    }
    for offer in &delta.added_offers {
        if context_offer_exists(store, offer)? {
            current.added_offers.push(offer.clone());
        }
    }
    Ok(current)
}

fn exact_matcher_roles(matchers: &[&dyn ContextMatcher]) -> BTreeSet<Role> {
    matchers
        .iter()
        .filter_map(|matcher| matcher.exact_selector_role().cloned())
        .collect()
}

fn exact_offer_owners_for_need(
    store: &Store,
    need: &ContextNeed,
) -> rusqlite::Result<Vec<[u8; 32]>> {
    let scope_key = scope_key(&need.scope);
    select_owner_ids(
        store,
        r#"
        SELECT owner
        FROM context_offers
        WHERE role = :role
          AND scope_key = :scope_key
          AND selector = :selector
        ORDER BY owner
        "#,
        CONTEXT_OFFERS,
        &[
            (":role", ColumnValue::Text(need.role.as_str())),
            (":scope_key", ColumnValue::Bytes(&scope_key)),
            (":selector", ColumnValue::Bytes(need.selector.as_bytes())),
        ],
        "exact offer owner",
    )
}

fn exact_need_owners_for_offer(
    store: &Store,
    offer: &ContextOffer,
) -> rusqlite::Result<Vec<[u8; 32]>> {
    let scope_key = scope_key(&offer.scope);
    select_owner_ids(
        store,
        r#"
        SELECT n.owner
        FROM context_needs n
        JOIN facts f ON f.id = n.owner
        WHERE n.role = :role
          AND n.scope_key = :scope_key
          AND n.selector = :selector
        ORDER BY f.timestamp, n.owner
        "#,
        CONTEXT_NEEDS,
        &[
            (":role", ColumnValue::Text(offer.role.as_str())),
            (":scope_key", ColumnValue::Bytes(&scope_key)),
            (":selector", ColumnValue::Bytes(offer.selector.as_bytes())),
        ],
        "exact need owner",
    )
}

fn select_owner_ids(
    store: &Store,
    sql: &str,
    table: crate::core::store::TableName,
    params: &[(&str, ColumnValue<'_>)],
    label: &str,
) -> rusqlite::Result<Vec<[u8; 32]>> {
    store
        .select_only(
            sql,
            &[table, crate::core::schema::FACTS],
            params,
            &[SelectColumn {
                name: "owner",
                ty: ColumnType::Bytes { len: Some(32) },
            }],
        )?
        .into_iter()
        .map(|row| selected_owner_id(row, label))
        .collect()
}

fn selected_owner_id(row: SelectedRow, label: &str) -> rusqlite::Result<[u8; 32]> {
    match row.get("owner") {
        Some(SelectedValue::Bytes(bytes)) => bytes.as_slice().try_into().map_err(|_| {
            rusqlite::Error::InvalidParameterName(format!("{label} should be 32 bytes"))
        }),
        _ => Err(rusqlite::Error::InvalidParameterName(format!(
            "{label} query did not return owner"
        ))),
    }
}

fn context_need_exists(store: &Store, need: &ContextNeed) -> rusqlite::Result<bool> {
    context_row_exists(
        store,
        CONTEXT_NEEDS,
        r#"
        SELECT owner
        FROM context_needs
        WHERE owner = :owner
          AND role = :role
          AND scope_key = :scope_key
          AND selector = :selector
        LIMIT 1
        "#,
        &need.owner,
        &need.role,
        &scope_key(&need.scope),
        need.selector.as_bytes(),
    )
}

fn context_offer_exists(store: &Store, offer: &ContextOffer) -> rusqlite::Result<bool> {
    context_row_exists(
        store,
        CONTEXT_OFFERS,
        r#"
        SELECT owner
        FROM context_offers
        WHERE owner = :owner
          AND role = :role
          AND scope_key = :scope_key
          AND selector = :selector
        LIMIT 1
        "#,
        &offer.owner,
        &offer.role,
        &scope_key(&offer.scope),
        offer.selector.as_bytes(),
    )
}

fn context_row_exists(
    store: &Store,
    table: crate::core::store::TableName,
    sql: &str,
    owner: &[u8; 32],
    role: &Role,
    scope_key: &[u8],
    selector: &[u8],
) -> rusqlite::Result<bool> {
    Ok(!store
        .select_only(
            sql,
            &[table],
            &[
                (":owner", ColumnValue::Bytes(owner)),
                (":role", ColumnValue::Text(role.as_str())),
                (":scope_key", ColumnValue::Bytes(scope_key)),
                (":selector", ColumnValue::Bytes(selector)),
            ],
            &[SelectColumn {
                name: "owner",
                ty: ColumnType::Bytes { len: Some(32) },
            }],
        )?
        .is_empty())
}
