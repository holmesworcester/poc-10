//! Typed SQL rows for standing fact context.

use super::context_codec::{
    scope_key, selected_fact_id, selected_role, selected_scope, selected_selector,
    CONTEXT_EDGE_VALUE_COLUMNS, CONTEXT_NEED_DIRECTION, CONTEXT_OFFER_DIRECTION,
};
use crate::core::context::{ContextNeed, ContextOffer, ContextSet, Role};
use crate::core::facts::{FactId, FactScope};
use crate::core::pipeline::CONTEXT_EDGES;
use crate::core::store::{ColumnValue, SelectedRow, Store};

/// Load a fact's standing context, returning `None` when it has none.
pub(crate) fn persisted_context(
    store: &Store,
    owner: &FactId,
) -> Result<Option<ContextSet>, String> {
    let context = stored_context_for_owner(store, owner)?;
    if context.needs.is_empty() && context.offers.is_empty() {
        Ok(None)
    } else {
        Ok(Some(context))
    }
}

/// Load a fact's standing context: the needs and offers it currently owns.
pub(super) fn stored_context_for_owner(
    store: &Store,
    owner: &FactId,
) -> Result<ContextSet, String> {
    Ok(ContextSet {
        needs: stored_needs_for_owner(store, owner)?,
        offers: stored_offers_for_owner(store, owner)?,
    }
    .normalized())
}

pub(super) fn insert_context_need_in_tx(
    store: &Store,
    need: &ContextNeed,
) -> rusqlite::Result<bool> {
    insert_context_edge_in_tx(
        store,
        &need.owner,
        CONTEXT_NEED_DIRECTION,
        &need.role,
        &need.scope,
        need.selector.as_bytes(),
    )
}

pub(super) fn insert_context_offer_in_tx(
    store: &Store,
    offer: &ContextOffer,
) -> rusqlite::Result<bool> {
    insert_context_edge_in_tx(
        store,
        &offer.owner,
        CONTEXT_OFFER_DIRECTION,
        &offer.role,
        &offer.scope,
        offer.selector.as_bytes(),
    )
}

pub(super) fn stored_needs_for_role_scope(
    store: &Store,
    role: &Role,
    scope: &FactScope,
) -> Result<Vec<ContextNeed>, String> {
    let scope_key = scope_key(scope);
    select_context_needs(
        store,
        r#"
        SELECT owner, role, scope_key, selector
        FROM context_edges
        WHERE direction = 'need'
          AND role = :role
          AND scope_key = :scope_key
        ORDER BY owner, selector
        "#,
        &[
            (":role", ColumnValue::Text(role.as_str())),
            (":scope_key", ColumnValue::Bytes(&scope_key)),
        ],
    )
}

pub(super) fn stored_offers_for_role_scope(
    store: &Store,
    role: &Role,
    scope: &FactScope,
) -> Result<Vec<ContextOffer>, String> {
    let scope_key = scope_key(scope);
    select_context_offers(
        store,
        r#"
        SELECT owner, role, scope_key, selector
        FROM context_edges
        WHERE direction = 'offer'
          AND role = :role
          AND scope_key = :scope_key
        ORDER BY owner, selector
        "#,
        &[
            (":role", ColumnValue::Text(role.as_str())),
            (":scope_key", ColumnValue::Bytes(&scope_key)),
        ],
    )
}

pub(super) fn stored_offers_for_exact_match(
    store: &Store,
    role: &Role,
    scope_key: &[u8],
    selector: &[u8],
) -> Result<Vec<ContextOffer>, String> {
    select_context_offers(
        store,
        r#"
        SELECT owner, role, scope_key, selector
        FROM context_edges
        WHERE direction = 'offer'
          AND role = :role
          AND scope_key = :scope_key
          AND selector = :selector
        ORDER BY owner
        "#,
        &[
            (":role", ColumnValue::Text(role.as_str())),
            (":scope_key", ColumnValue::Bytes(scope_key)),
            (":selector", ColumnValue::Bytes(selector)),
        ],
    )
}

fn stored_needs_for_owner(store: &Store, owner: &FactId) -> Result<Vec<ContextNeed>, String> {
    select_context_needs(
        store,
        r#"
        SELECT owner, role, scope_key, selector
        FROM context_edges
        WHERE owner = :owner
          AND direction = 'need'
        ORDER BY owner, role, scope_key, selector
        "#,
        &[(":owner", ColumnValue::Bytes(owner))],
    )
}

fn stored_offers_for_owner(store: &Store, owner: &FactId) -> Result<Vec<ContextOffer>, String> {
    select_context_offers(
        store,
        r#"
        SELECT owner, role, scope_key, selector
        FROM context_edges
        WHERE owner = :owner
          AND direction = 'offer'
        ORDER BY owner, role, scope_key, selector
        "#,
        &[(":owner", ColumnValue::Bytes(owner))],
    )
}

fn select_context_needs(
    store: &Store,
    sql: &str,
    params: &[(&str, ColumnValue<'_>)],
) -> Result<Vec<ContextNeed>, String> {
    store
        .select_only(sql, &[CONTEXT_EDGES], params, CONTEXT_EDGE_VALUE_COLUMNS)
        .map_err(|err| format!("load context needs: {err}"))?
        .into_iter()
        .map(selected_context_need)
        .collect()
}

fn select_context_offers(
    store: &Store,
    sql: &str,
    params: &[(&str, ColumnValue<'_>)],
) -> Result<Vec<ContextOffer>, String> {
    store
        .select_only(sql, &[CONTEXT_EDGES], params, CONTEXT_EDGE_VALUE_COLUMNS)
        .map_err(|err| format!("load context offers: {err}"))?
        .into_iter()
        .map(selected_context_offer)
        .collect()
}

fn insert_context_edge_in_tx(
    store: &Store,
    owner: &FactId,
    direction: &str,
    role: &Role,
    scope: &FactScope,
    selector: &[u8],
) -> rusqlite::Result<bool> {
    store.insert_typed_row_in_tx(
        CONTEXT_EDGES,
        &[
            ("owner", ColumnValue::Bytes(owner)),
            ("direction", ColumnValue::Text(direction)),
            ("role", ColumnValue::Text(role.as_str())),
            ("scope_key", ColumnValue::Bytes(&scope_key(scope))),
            ("selector", ColumnValue::Bytes(selector)),
        ],
    )
}

fn selected_context_need(row: SelectedRow) -> Result<ContextNeed, String> {
    Ok(ContextNeed {
        owner: selected_fact_id(&row, "owner")?,
        role: selected_role(&row)?,
        scope: selected_scope(&row)?,
        selector: selected_selector(&row)?,
    })
}

fn selected_context_offer(row: SelectedRow) -> Result<ContextOffer, String> {
    Ok(ContextOffer {
        owner: selected_fact_id(&row, "owner")?,
        role: selected_role(&row)?,
        scope: selected_scope(&row)?,
        selector: selected_selector(&row)?,
    })
}
