//! Typed SQL rows for standing fact context.

use super::context_codec::{
    scope_key, selected_fact_id, selected_role, selected_scope, selected_selector,
    CONTEXT_ROW_COLUMNS,
};
use crate::core::context::{ContextNeed, ContextOffer, ContextSet, Role};
use crate::core::facts::{FactId, FactScope};
use crate::core::pipeline::{CONTEXT_NEEDS, CONTEXT_OFFERS};
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

pub(super) fn insert_context_offer_in_tx(
    store: &Store,
    offer: &ContextOffer,
) -> rusqlite::Result<bool> {
    store.insert_typed_row_in_tx(
        CONTEXT_OFFERS,
        &[
            ("owner", ColumnValue::Bytes(&offer.owner)),
            ("role", ColumnValue::Text(offer.role.as_str())),
            ("scope_key", ColumnValue::Bytes(&scope_key(&offer.scope))),
            ("selector", ColumnValue::Bytes(offer.selector.as_bytes())),
        ],
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
        FROM context_needs
        WHERE role = :role
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
        FROM context_offers
        WHERE role = :role
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
        FROM context_offers
        WHERE role = :role
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
        FROM context_needs
        WHERE owner = :owner
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
        FROM context_offers
        WHERE owner = :owner
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
        .select_only(sql, &[CONTEXT_NEEDS], params, CONTEXT_ROW_COLUMNS)
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
        .select_only(sql, &[CONTEXT_OFFERS], params, CONTEXT_ROW_COLUMNS)
        .map_err(|err| format!("load context offers: {err}"))?
        .into_iter()
        .map(selected_context_offer)
        .collect()
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
