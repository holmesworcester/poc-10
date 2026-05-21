//! Typed SQL rows for standing fact context.

use super::context_codec::{decode_scope_key, CONTEXT_NEED_DIRECTION, CONTEXT_OFFER_DIRECTION};
use crate::core::context::{scope_key, ContextNeed, ContextOffer, ContextSet, Role, Selector};
use crate::core::facts::{FactId, FactScope};
use crate::core::store::Store;
use rusqlite::params;

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
            (":role", text(role.as_str())),
            (":scope_key", bytes(&scope_key)),
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
            (":role", text(role.as_str())),
            (":scope_key", bytes(&scope_key)),
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
            (":role", text(role.as_str())),
            (":scope_key", bytes(scope_key)),
            (":selector", bytes(selector)),
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
        &[(":owner", bytes(owner))],
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
        &[(":owner", bytes(owner))],
    )
}

fn select_context_needs(
    store: &Store,
    sql: &str,
    params: &[(&str, rusqlite::types::Value)],
) -> Result<Vec<ContextNeed>, String> {
    let mut stmt = store
        .conn()
        .prepare(sql)
        .map_err(|err| format!("load context needs: {err}"))?;
    bind_named_params(&mut stmt, params).map_err(|err| format!("load context needs: {err}"))?;
    let rows = stmt
        .raw_query()
        .mapped(selected_context_need)
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(|err| format!("load context needs: {err}"))?;
    Ok(rows)
}

fn select_context_offers(
    store: &Store,
    sql: &str,
    params: &[(&str, rusqlite::types::Value)],
) -> Result<Vec<ContextOffer>, String> {
    let mut stmt = store
        .conn()
        .prepare(sql)
        .map_err(|err| format!("load context offers: {err}"))?;
    bind_named_params(&mut stmt, params).map_err(|err| format!("load context offers: {err}"))?;
    let rows = stmt
        .raw_query()
        .mapped(selected_context_offer)
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(|err| format!("load context offers: {err}"))?;
    Ok(rows)
}

fn insert_context_edge_in_tx(
    store: &Store,
    owner: &FactId,
    direction: &str,
    role: &Role,
    scope: &FactScope,
    selector: &[u8],
) -> rusqlite::Result<bool> {
    let scope_key = scope_key(scope);
    store
        .conn()
        .execute(
            "INSERT OR IGNORE INTO context_edges
                (owner, direction, role, scope_key, selector)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                owner.as_slice(),
                direction,
                role.as_str(),
                scope_key.as_slice(),
                selector
            ],
        )
        .map(|count| count > 0)
}

fn selected_context_need(row: &rusqlite::Row<'_>) -> rusqlite::Result<ContextNeed> {
    Ok(ContextNeed {
        owner: fact_id_column(row.get::<_, Vec<u8>>(0)?, "owner")?,
        role: Role::new(row.get::<_, String>(1)?).map_err(rusqlite::Error::InvalidParameterName)?,
        scope: decode_scope_key(&row.get::<_, Vec<u8>>(2)?)
            .map_err(rusqlite::Error::InvalidParameterName)?,
        selector: Selector::from_bytes(row.get::<_, Vec<u8>>(3)?),
    })
}

fn selected_context_offer(row: &rusqlite::Row<'_>) -> rusqlite::Result<ContextOffer> {
    Ok(ContextOffer {
        owner: fact_id_column(row.get::<_, Vec<u8>>(0)?, "owner")?,
        role: Role::new(row.get::<_, String>(1)?).map_err(rusqlite::Error::InvalidParameterName)?,
        scope: decode_scope_key(&row.get::<_, Vec<u8>>(2)?)
            .map_err(rusqlite::Error::InvalidParameterName)?,
        selector: Selector::from_bytes(row.get::<_, Vec<u8>>(3)?),
    })
}

fn bind_named_params(
    stmt: &mut rusqlite::Statement<'_>,
    params: &[(&str, rusqlite::types::Value)],
) -> rusqlite::Result<()> {
    for (name, value) in params {
        let index = stmt.parameter_index(name)?.ok_or_else(|| {
            rusqlite::Error::InvalidParameterName(format!(
                "context SQL does not bind parameter {name}"
            ))
        })?;
        stmt.raw_bind_parameter(index, value)?;
    }
    Ok(())
}

fn fact_id_column(bytes: Vec<u8>, name: &str) -> rusqlite::Result<FactId> {
    bytes.try_into().map_err(|_| {
        rusqlite::Error::InvalidParameterName(format!("context SQL column {name} is not a fact id"))
    })
}

fn bytes(value: &[u8]) -> rusqlite::types::Value {
    rusqlite::types::Value::Blob(value.to_vec())
}

fn text(value: &str) -> rusqlite::types::Value {
    rusqlite::types::Value::Text(value.to_string())
}
