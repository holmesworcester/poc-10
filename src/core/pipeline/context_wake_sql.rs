//! SQL helpers for waking facts after context edge additions.

use super::context_codec::scope_key;
use super::context_rows::{stored_needs_for_role_scope, stored_offers_for_role_scope};
use crate::core::context::ContextSetDelta;
use crate::core::context::{ContextNeed, ContextOffer, Role};
use crate::core::matchers::{ContextMatch, ContextMatcher, ContextWakeSql};
use crate::core::pipeline::{CONTEXT_EDGES, FACTS, PENDING_PROJECTION};
use crate::core::store::{ColumnValue, Store};
use std::collections::{BTreeSet, HashSet};

pub(super) fn wake_exact_context_matches_in_tx(
    store: &Store,
    delta: &ContextSetDelta,
) -> rusqlite::Result<usize> {
    let mut inserted = 0usize;
    for need in &delta.added_needs {
        inserted += wake_exact_offers_for_need_in_tx(store, need)?;
    }
    for offer in &delta.added_offers {
        inserted += wake_exact_needs_for_offer_in_tx(store, offer)?;
    }
    Ok(inserted)
}

pub(super) fn wake_custom_context_matches_in_tx(
    store: &Store,
    delta: &ContextSetDelta,
    matchers: &[&dyn ContextMatcher],
) -> Result<usize, String> {
    let mut inserted = 0usize;
    for matcher in matchers
        .iter()
        .copied()
        .filter(|matcher| matcher.exact_selector_role().is_none())
    {
        for need in delta
            .added_needs
            .iter()
            .filter(|need| matcher.role() == &need.role)
        {
            inserted += wake_custom_need_in_tx(store, matcher, need)?;
        }
        for offer in delta
            .added_offers
            .iter()
            .filter(|offer| matcher.role() == &offer.role)
        {
            inserted += wake_custom_offer_in_tx(store, matcher, offer)?;
        }
    }
    Ok(inserted)
}

pub(super) fn exact_role_delta(
    delta: &ContextSetDelta,
    exact_roles: &BTreeSet<Role>,
) -> ContextSetDelta {
    if exact_roles.is_empty() {
        return ContextSetDelta::default();
    }
    ContextSetDelta {
        added_needs: delta
            .added_needs
            .iter()
            .filter(|need| exact_roles.contains(&need.role))
            .cloned()
            .collect(),
        removed_needs: Vec::new(),
        added_offers: delta
            .added_offers
            .iter()
            .filter(|offer| exact_roles.contains(&offer.role))
            .cloned()
            .collect(),
        removed_offers: Vec::new(),
    }
}

fn wake_exact_offers_for_need_in_tx(store: &Store, need: &ContextNeed) -> rusqlite::Result<usize> {
    let scope_key = scope_key(&need.scope);
    store.insert_typed_rows_from_select_in_tx(
        PENDING_PROJECTION,
        &["owner"],
        r#"
        SELECT :need_owner AS owner
        WHERE EXISTS (
            SELECT 1
            FROM context_edges
            WHERE direction = 'offer'
              AND role = :role
              AND scope_key = :scope_key
              AND selector = :selector
        )
        "#,
        &[CONTEXT_EDGES],
        &[
            (":need_owner", ColumnValue::Bytes(&need.owner)),
            (":role", ColumnValue::Text(need.role.as_str())),
            (":scope_key", ColumnValue::Bytes(&scope_key)),
            (":selector", ColumnValue::Bytes(need.selector.as_bytes())),
        ],
    )
}

fn wake_exact_needs_for_offer_in_tx(
    store: &Store,
    offer: &ContextOffer,
) -> rusqlite::Result<usize> {
    let scope_key = scope_key(&offer.scope);
    store.insert_typed_rows_from_select_in_tx(
        PENDING_PROJECTION,
        &["owner"],
        r#"
        SELECT n.owner
        FROM context_edges n
        JOIN facts f ON f.id = n.owner
        WHERE n.direction = 'need'
          AND n.role = :role
          AND n.scope_key = :scope_key
          AND n.selector = :selector
        ORDER BY f.timestamp, n.owner
        "#,
        &[CONTEXT_EDGES, FACTS],
        &[
            (":role", ColumnValue::Text(offer.role.as_str())),
            (":scope_key", ColumnValue::Bytes(&scope_key)),
            (":selector", ColumnValue::Bytes(offer.selector.as_bytes())),
        ],
    )
}

fn wake_custom_need_in_tx(
    store: &Store,
    matcher: &dyn ContextMatcher,
    need: &ContextNeed,
) -> Result<usize, String> {
    if let Some(plan) = matcher.wake_sql_for_added_need(need)? {
        return execute_context_wake_sql_in_tx(store, &plan)
            .map_err(|err| format!("wake custom need from SQL: {err}"));
    }

    let offers = if let Some(offers) = matcher.matching_offers_for_need_from_store(store, need)? {
        offers
    } else {
        stored_offers_for_role_scope(store, &need.role, &need.scope)?
    };
    let matches = matcher.match_new_need(need, &offers);
    wake_matched_need_owners_in_tx(store, matches)
        .map_err(|err| format!("wake custom need from Rust matcher: {err}"))
}

fn wake_custom_offer_in_tx(
    store: &Store,
    matcher: &dyn ContextMatcher,
    offer: &ContextOffer,
) -> Result<usize, String> {
    if let Some(plan) = matcher.wake_sql_for_added_offer(offer)? {
        return execute_context_wake_sql_in_tx(store, &plan)
            .map_err(|err| format!("wake custom offer from SQL: {err}"));
    }

    let needs = if let Some(needs) = matcher.matching_needs_for_offer_from_store(store, offer)? {
        needs
    } else {
        stored_needs_for_role_scope(store, &offer.role, &offer.scope)?
    };
    let matches = matcher.match_new_offer(offer, &needs);
    wake_matched_need_owners_in_tx(store, matches)
        .map_err(|err| format!("wake custom offer from Rust matcher: {err}"))
}

fn execute_context_wake_sql_in_tx(store: &Store, plan: &ContextWakeSql) -> rusqlite::Result<usize> {
    let params = plan
        .params
        .iter()
        .map(|param| (param.name, param.as_column_value()))
        .collect::<Vec<_>>();
    store.insert_typed_rows_from_select_in_tx(
        PENDING_PROJECTION,
        &["owner"],
        plan.sql,
        plan.allowed_tables,
        &params,
    )
}

fn wake_matched_need_owners_in_tx(
    store: &Store,
    matches: Vec<ContextMatch>,
) -> rusqlite::Result<usize> {
    let mut inserted = 0usize;
    let mut seen = HashSet::new();
    for matched in matches {
        if seen.insert(matched.need_owner)
            && store.insert_typed_row_in_tx(
                PENDING_PROJECTION,
                &[("owner", ColumnValue::Bytes(&matched.need_owner))],
            )?
        {
            inserted += 1;
        }
    }
    Ok(inserted)
}
