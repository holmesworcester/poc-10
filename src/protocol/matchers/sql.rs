//! Shared SQL-backed context matcher helpers.
//!
//! Protocol matcher modules declare selector fields and SELECT-only candidate
//! queries. Core owns the store, validation, and transaction timing; these
//! helpers only adapt query result rows back into generic need/offer values.

use crate::core::context::{scope_key, ContextNeed, ContextOffer, Selector};
use crate::core::facts::{FactId, FactScope};
use crate::core::schema::{CONTEXT_EDGES, LOCAL_FACT_ADMISSIONS};
use crate::core::select;
use crate::core::store::{Store, TableName};

pub(crate) const CONTEXT_MATCHER_TABLES: &[TableName] = &[CONTEXT_EDGES];
pub(crate) const CONTEXT_WAKE_TABLES: &[TableName] = &[CONTEXT_EDGES, LOCAL_FACT_ADMISSIONS];

pub(crate) fn scope_key_for_sql(scope: &FactScope) -> Vec<u8> {
    scope_key(scope)
}

pub(crate) fn wake_select(sql: &'static str, params: Vec<select::Param>) -> select::Select {
    select::Select::new(sql, CONTEXT_WAKE_TABLES, params)
}

pub(crate) fn select_offers_for_need(
    store: &Store,
    sql: &str,
    params: &[select::Param],
    need: &ContextNeed,
) -> Result<Vec<ContextOffer>, String> {
    Ok(
        select_context_edges(store, sql, params, "context-offer matcher SQL")?
            .into_iter()
            .map(|(owner, selector)| ContextOffer {
                owner,
                role: need.role.clone(),
                scope: need.scope.clone(),
                selector,
            })
            .collect(),
    )
}

pub(crate) fn select_needs_for_offer(
    store: &Store,
    sql: &str,
    params: &[select::Param],
    offer: &ContextOffer,
) -> Result<Vec<ContextNeed>, String> {
    Ok(
        select_context_edges(store, sql, params, "context-need matcher SQL")?
            .into_iter()
            .map(|(owner, selector)| ContextNeed {
                owner,
                role: offer.role.clone(),
                scope: offer.scope.clone(),
                selector,
            })
            .collect(),
    )
}

fn select_context_edges(
    store: &Store,
    sql: &str,
    params: &[select::Param],
    label: &str,
) -> Result<Vec<(FactId, Selector)>, String> {
    validate_select_tables(sql)?;
    let mut stmt = store
        .conn()
        .prepare(sql)
        .map_err(|err| format!("run {label}: {err}"))?;
    for param in params {
        let index = stmt
            .parameter_index(param.name)
            .map_err(|err| format!("run {label}: {err}"))?
            .ok_or_else(|| format!("{label} does not bind parameter {}", param.name))?;
        stmt.raw_bind_parameter(
            index,
            param.as_sqlite_value().map_err(|err| err.to_string())?,
        )
        .map_err(|err| format!("run {label}: {err}"))?;
    }
    let rows = stmt
        .raw_query()
        .mapped(|row| {
            Ok((
                selected_fact_id(row.get::<_, Vec<u8>>(0)?, "owner")?,
                Selector::from_bytes(row.get::<_, Vec<u8>>(1)?),
            ))
        })
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(|err| format!("run {label}: {err}"))?;
    Ok(rows)
}

fn validate_select_tables(sql: &str) -> Result<(), String> {
    let tokens = sql_identifier_tokens(sql);
    for window in tokens.windows(2) {
        let keyword = window[0].to_ascii_lowercase();
        if matches!(keyword.as_str(), "from" | "join")
            && !CONTEXT_MATCHER_TABLES
                .iter()
                .any(|table| table.as_str() == window[1])
        {
            return Err(format!("matcher SQL reads undeclared table {}", window[1]));
        }
    }
    Ok(())
}

fn sql_identifier_tokens(sql: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    for ch in sql.chars() {
        if ch.is_ascii_alphanumeric() || ch == '_' || ch == '.' {
            current.push(ch);
        } else if !current.is_empty() {
            tokens.push(std::mem::take(&mut current));
        }
    }
    if !current.is_empty() {
        tokens.push(current);
    }
    tokens
}

fn selected_fact_id(bytes: Vec<u8>, name: &str) -> rusqlite::Result<FactId> {
    bytes.try_into().map_err(|_| {
        rusqlite::Error::InvalidParameterName(format!("matcher SQL column {name} is not a fact id"))
    })
}
