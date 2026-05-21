//! Shared SQL-backed context matcher helpers.
//!
//! Protocol matcher modules declare selector fields and SELECT-only candidate
//! queries. Core owns the store, validation, and transaction timing; these
//! helpers only adapt query result rows back into generic need/offer values.

use crate::core::context::{ContextNeed, ContextOffer, Role, Selector};
use crate::core::facts::{FactId, FactScope};
use crate::core::pipeline::{scope_key, CONTEXT_EDGES, FACTS};
use crate::core::schema_dsl::ColumnType;
use crate::core::store::{ColumnValue, SelectColumn, SelectedRow, SelectedValue, Store, TableName};
use crate::core::wake;

pub(crate) const CONTEXT_MATCHER_TABLES: &[TableName] = &[CONTEXT_EDGES];
pub(crate) const CONTEXT_WAKE_TABLES: &[TableName] = &[CONTEXT_EDGES, FACTS];

pub(crate) const OFFER_RESULT_COLUMNS: &[SelectColumn] = &[
    SelectColumn {
        name: "owner",
        ty: ColumnType::Bytes { len: Some(32) },
    },
    SelectColumn {
        name: "selector",
        ty: ColumnType::Bytes { len: None },
    },
];

pub(crate) const NEED_RESULT_COLUMNS: &[SelectColumn] = &[
    SelectColumn {
        name: "owner",
        ty: ColumnType::Bytes { len: Some(32) },
    },
    SelectColumn {
        name: "selector",
        ty: ColumnType::Bytes { len: None },
    },
];

pub(crate) fn scope_key_for_sql(scope: &FactScope) -> Vec<u8> {
    scope_key(scope)
}

pub(crate) fn wake_select(sql: &'static str, params: Vec<wake::Param>) -> wake::Select {
    wake::Select::new(sql, CONTEXT_WAKE_TABLES, params)
}

pub(crate) fn select_offers_for_need(
    store: &Store,
    sql: &str,
    params: &[(&str, ColumnValue<'_>)],
    need: &ContextNeed,
) -> Result<Vec<ContextOffer>, String> {
    let rows = store
        .select_only(sql, CONTEXT_MATCHER_TABLES, params, OFFER_RESULT_COLUMNS)
        .map_err(|err| format!("run context-offer matcher SQL: {err}"))?;
    rows.into_iter()
        .map(|row| selected_offer(row, &need.role, &need.scope))
        .collect()
}

pub(crate) fn select_needs_for_offer(
    store: &Store,
    sql: &str,
    params: &[(&str, ColumnValue<'_>)],
    offer: &ContextOffer,
) -> Result<Vec<ContextNeed>, String> {
    let rows = store
        .select_only(sql, CONTEXT_MATCHER_TABLES, params, NEED_RESULT_COLUMNS)
        .map_err(|err| format!("run context-need matcher SQL: {err}"))?;
    rows.into_iter()
        .map(|row| selected_need(row, &offer.role, &offer.scope))
        .collect()
}

fn selected_offer(
    row: SelectedRow,
    role: &Role,
    scope: &FactScope,
) -> Result<ContextOffer, String> {
    Ok(ContextOffer {
        owner: selected_fact_id(&row, "owner")?,
        role: role.clone(),
        scope: scope.clone(),
        selector: Selector::from_bytes(selected_bytes(&row, "selector")?.to_vec()),
    })
}

fn selected_need(row: SelectedRow, role: &Role, scope: &FactScope) -> Result<ContextNeed, String> {
    Ok(ContextNeed {
        owner: selected_fact_id(&row, "owner")?,
        role: role.clone(),
        scope: scope.clone(),
        selector: Selector::from_bytes(selected_bytes(&row, "selector")?.to_vec()),
    })
}

fn selected_fact_id(row: &SelectedRow, name: &str) -> Result<FactId, String> {
    selected_bytes(row, name)?
        .try_into()
        .map_err(|_| format!("matcher SQL column {name} is not a fact id"))
}

fn selected_bytes<'a>(row: &'a SelectedRow, name: &str) -> Result<&'a [u8], String> {
    match row.get(name) {
        Some(SelectedValue::Bytes(bytes)) => Ok(bytes),
        Some(_) => Err(format!("matcher SQL column {name} is not bytes")),
        None => Err(format!("matcher SQL did not return column {name}")),
    }
}
