//! SQL helpers for matching context changes against current rows.

use super::context_codec::scope_key;
use crate::core::context::ContextSetDelta;
use crate::core::context::{ContextNeed, ContextOffer, Role};
use crate::core::pipeline::{CONTEXT_NEEDS, CONTEXT_OFFERS, FACTS, PENDING_PROJECTION};
use crate::core::schema_dsl::ColumnType;
use crate::core::store::{ColumnValue, SelectColumn, Store};
use std::collections::BTreeSet;

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

pub(super) fn custom_role_delta(
    delta: &ContextSetDelta,
    custom_roles: &BTreeSet<Role>,
) -> ContextSetDelta {
    if custom_roles.is_empty() {
        return ContextSetDelta::default();
    }
    ContextSetDelta {
        added_needs: delta
            .added_needs
            .iter()
            .filter(|need| custom_roles.contains(&need.role))
            .cloned()
            .collect(),
        removed_needs: Vec::new(),
        added_offers: delta
            .added_offers
            .iter()
            .filter(|offer| custom_roles.contains(&offer.role))
            .cloned()
            .collect(),
        removed_offers: Vec::new(),
    }
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

fn wake_exact_offers_for_need_in_tx(store: &Store, need: &ContextNeed) -> rusqlite::Result<usize> {
    let scope_key = scope_key(&need.scope);
    store.insert_typed_rows_from_select_in_tx(
        PENDING_PROJECTION,
        &["owner"],
        r#"
        SELECT :need_owner AS owner
        WHERE EXISTS (
            SELECT 1
            FROM context_offers
            WHERE role = :role
              AND scope_key = :scope_key
              AND selector = :selector
        )
        "#,
        &[CONTEXT_OFFERS],
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
        FROM context_needs n
        JOIN facts f ON f.id = n.owner
        WHERE n.role = :role
          AND n.scope_key = :scope_key
          AND n.selector = :selector
        ORDER BY f.timestamp, n.owner
        "#,
        &[CONTEXT_NEEDS, FACTS],
        &[
            (":role", ColumnValue::Text(offer.role.as_str())),
            (":scope_key", ColumnValue::Bytes(&scope_key)),
            (":selector", ColumnValue::Bytes(offer.selector.as_bytes())),
        ],
    )
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
