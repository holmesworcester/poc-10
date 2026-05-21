//! Fact storage and generic row-mutation helpers for the runtime
//! [`pipeline`](crate::core::pipeline).
//!
//! [`pipeline`](crate::core::pipeline) decides *what* the runtime does with
//! facts, context, and intents. This module owns the pieces that are still
//! shared across pipeline workers:
//!
//! - **Durable mutations** — [`insert_fact_and_pending_in_tx`],
//!   [`purge_fact_in_tx`], and the pending-projection helper.
//! - **Fact reads** — loading immutable facts from the declared `facts` table.
//! - **Protocol row mutations** — validating and splitting opaque row-table
//!   mutations emitted through [`PipelineEffects`](crate::core::pipeline::PipelineEffects).

use crate::core::facts::{fact_id, Fact, FactId, FactScope, ScopeKind};
use crate::core::intents::{RowMutation, TableDelete};
use crate::core::pipeline::{
    CONTEXT_NEEDS, CONTEXT_OFFERS, FACTS, PENDING_CONTEXT_CHANGES, PENDING_PROJECTION,
    PENDING_TIME_RANGES, TIME_WAKES,
};
use crate::core::schema_dsl::ColumnType;
use crate::core::store::{
    ColumnValue, SelectColumn, SelectedRow, SelectedValue, Store, TableName, TableRow,
};

const FACT_COLUMNS: &[SelectColumn] = &[
    SelectColumn {
        name: "id",
        ty: ColumnType::Bytes { len: Some(32) },
    },
    SelectColumn {
        name: "scope",
        ty: ColumnType::Text,
    },
    SelectColumn {
        name: "scope_kind",
        ty: ColumnType::Text,
    },
    SelectColumn {
        name: "scope_id",
        ty: ColumnType::Bytes { len: Some(32) },
    },
    SelectColumn {
        name: "timestamp",
        ty: ColumnType::U64,
    },
    SelectColumn {
        name: "bytes",
        ty: ColumnType::Bytes { len: None },
    },
];

// === Durable mutations ===

/// Insert a fact and mark it pending for projection.
///
/// Facts are immutable and content-addressed, so a fact that already exists is
/// left untouched. Returns whether the fact was newly inserted.
pub(crate) fn insert_fact_and_pending_in_tx(store: &Store, fact: &Fact) -> rusqlite::Result<bool> {
    if store.table_row(FACTS, &fact.id)?.is_some() {
        return Ok(false);
    }
    let inserted = insert_fact_in_tx(store, fact)?;
    if inserted {
        insert_pending_owner_in_tx(store, fact.id)?;
    }
    Ok(inserted)
}

/// Mark `owner` pending so the next projection pass (re)projects it.
pub(crate) fn insert_pending_owner_in_tx(store: &Store, owner: FactId) -> rusqlite::Result<usize> {
    store
        .insert_typed_row_in_tx(PENDING_PROJECTION, &[("owner", ColumnValue::Bytes(&owner))])
        .map(usize::from)
}

/// Remove a fact and every durable row keyed to it.
///
/// Deletes the fact itself, its context needs and offers, its time wakes, any
/// pending context-change or time-range rows it owns, and its pending-projection
/// marker. Returns whether anything was actually removed.
pub(crate) fn purge_fact_in_tx(store: &Store, owner: FactId) -> rusqlite::Result<bool> {
    let mut changed = store.delete_table_rows_in_tx(FACTS, vec![owner.to_vec()])? > 0;
    for table in [
        CONTEXT_NEEDS,
        CONTEXT_OFFERS,
        TIME_WAKES,
        PENDING_CONTEXT_CHANGES,
        PENDING_TIME_RANGES,
    ] {
        changed |= delete_rows_owned_by(store, table, &owner)?;
    }
    changed |= store.delete_typed_rows_where_in_tx(
        PENDING_PROJECTION,
        &[("owner", ColumnValue::Bytes(&owner))],
    )? > 0;
    Ok(changed)
}

/// Delete every row in `table` whose `owner` column equals `owner`.
///
/// This is the "remove all of one fact's rows from a side table" step that
/// [`purge_fact_in_tx`] repeats for each table. Returns whether any row matched.
fn delete_rows_owned_by(store: &Store, table: TableName, owner: &FactId) -> rusqlite::Result<bool> {
    store
        .delete_typed_rows_where_in_tx(table, &[("owner", ColumnValue::Bytes(owner))])
        .map(|removed| removed > 0)
}

fn insert_fact_in_tx(store: &Store, fact: &Fact) -> rusqlite::Result<bool> {
    let (scope, scope_kind, scope_id) = fact_scope_columns(&fact.scope);
    store.insert_typed_row_in_tx(
        FACTS,
        &[
            ("id", ColumnValue::Bytes(&fact.id)),
            ("scope", ColumnValue::Text(scope)),
            ("scope_kind", ColumnValue::Text(scope_kind)),
            ("scope_id", ColumnValue::Bytes(scope_id)),
            ("timestamp", ColumnValue::U64(fact.timestamp)),
            ("bytes", ColumnValue::Bytes(&fact.bytes)),
        ],
    )
}

fn fact_scope_columns(scope: &FactScope) -> (&'static str, &str, &FactId) {
    match scope {
        FactScope::Global => ("global", "", &EMPTY_FACT_ID),
        FactScope::Local => ("local", "", &EMPTY_FACT_ID),
        FactScope::Scoped { kind, id } => ("scoped", kind.as_str(), id),
    }
}

// === Row mutations ===

/// Reject any row mutation targeting a table this runtime has not registered.
pub(crate) fn validate_row_mutations(
    mutations: &[RowMutation],
    allowed_tables: &[TableName],
) -> Result<(), String> {
    for mutation in mutations {
        validate_row_mutation_table(mutation, allowed_tables)?;
    }
    Ok(())
}

/// Split row mutations into inserts and deletes so a commit can apply them.
pub(crate) fn row_mutation_rows(
    mutations: &[RowMutation],
    allowed_tables: &[TableName],
) -> Result<(Vec<TableRow>, Vec<TableDelete>), String> {
    let mut rows = Vec::new();
    let mut deletes = Vec::<TableDelete>::new();
    for mutation in mutations {
        validate_row_mutation_table(mutation, allowed_tables)?;
        match mutation {
            RowMutation::PutRow(row) => rows.push(row.clone()),
            RowMutation::DeleteRow(delete) => deletes.push(delete.clone()),
        }
    }
    Ok((rows, deletes))
}

fn validate_row_mutation_table(
    mutation: &RowMutation,
    allowed_tables: &[TableName],
) -> Result<(), String> {
    let table = match mutation {
        RowMutation::PutRow(row) => row.table,
        RowMutation::DeleteRow(delete) => delete.table,
    };
    if allowed_tables.contains(&table) {
        Ok(())
    } else {
        Err(format!(
            "row mutation table {} is not registered",
            table.as_str()
        ))
    }
}

/// Adapt a `String` error into the [`rusqlite::Error`] a transaction closure
/// must return, so a non-SQL failure can still abort a commit.
pub(crate) fn sqlite_string_error(err: String) -> rusqlite::Error {
    rusqlite::Error::InvalidParameterName(err)
}

// === Reading and decoding rows ===

/// Load a fact by id, returning `None` when no such fact is stored.
pub fn persisted_fact(store: &Store, id: &FactId) -> Result<Option<Fact>, String> {
    let mut facts = store
        .select_only(
            r#"
            SELECT id, scope, scope_kind, scope_id, timestamp, bytes
            FROM facts
            WHERE id = :id
            LIMIT 1
            "#,
            &[FACTS],
            &[(":id", ColumnValue::Bytes(id))],
            FACT_COLUMNS,
        )
        .map_err(|err| format!("load fact row: {err}"))?
        .into_iter()
        .map(selected_fact)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(facts.pop())
}

/// Load every stored fact.
pub fn persisted_facts(store: &Store) -> Result<Vec<Fact>, String> {
    store
        .select_only(
            r#"
            SELECT id, scope, scope_kind, scope_id, timestamp, bytes
            FROM facts
            ORDER BY id
            "#,
            &[FACTS],
            &[],
            FACT_COLUMNS,
        )
        .map_err(|err| format!("load fact rows: {err}"))?
        .into_iter()
        .map(selected_fact)
        .collect()
}

fn selected_fact(row: SelectedRow) -> Result<Fact, String> {
    let id = selected_fact_id(&row, "id")?;
    let scope_tag = selected_text(&row, "scope")?;
    let scope_kind = selected_text(&row, "scope_kind")?;
    let scope_id = selected_fact_id(&row, "scope_id")?;
    let scope = decode_fact_scope_columns(scope_tag, scope_kind, &scope_id)?;
    let timestamp = selected_u64(&row, "timestamp")?;
    let bytes = selected_bytes(&row, "bytes")?.to_vec();
    if fact_id(&bytes) != id {
        return Err("fact row key does not match fact bytes".to_string());
    }
    Ok(Fact {
        id,
        scope,
        timestamp,
        bytes,
    })
}

/// Rebuild a [`FactScope`] from the three scope columns of a [`FACTS`] row.
fn decode_fact_scope_columns(
    scope: &str,
    scope_kind: &str,
    scope_id: &FactId,
) -> Result<FactScope, String> {
    match scope {
        "global" => {
            if !scope_kind.is_empty() || scope_id != &EMPTY_FACT_ID {
                return Err("global fact scope has scoped columns set".to_string());
            }
            Ok(FactScope::Global)
        }
        "local" => {
            if !scope_kind.is_empty() || scope_id != &EMPTY_FACT_ID {
                return Err("local fact scope has scoped columns set".to_string());
            }
            Ok(FactScope::Local)
        }
        "scoped" => Ok(FactScope::Scoped {
            kind: ScopeKind::new(scope_kind.to_string())?,
            id: *scope_id,
        }),
        other => Err(format!("invalid fact scope {other:?}")),
    }
}

fn selected_fact_id(row: &SelectedRow, name: &str) -> Result<FactId, String> {
    selected_bytes(row, name)?
        .try_into()
        .map_err(|_| format!("fact SQL column {name} is not a fact id"))
}

fn selected_text<'a>(row: &'a SelectedRow, name: &str) -> Result<&'a str, String> {
    match row.get(name) {
        Some(SelectedValue::Text(value)) => Ok(value),
        Some(_) => Err(format!("fact SQL column {name} is not text")),
        None => Err(format!("fact SQL did not return column {name}")),
    }
}

fn selected_u64(row: &SelectedRow, name: &str) -> Result<u64, String> {
    match row.get(name) {
        Some(SelectedValue::U64(value)) => Ok(*value),
        Some(_) => Err(format!("fact SQL column {name} is not u64")),
        None => Err(format!("fact SQL did not return column {name}")),
    }
}

fn selected_bytes<'a>(row: &'a SelectedRow, name: &str) -> Result<&'a [u8], String> {
    match row.get(name) {
        Some(SelectedValue::Bytes(bytes)) => Ok(bytes),
        Some(_) => Err(format!("fact SQL column {name} is not bytes")),
        None => Err(format!("fact SQL did not return column {name}")),
    }
}

/// The all-zero [`FactId`] stored in the scope columns of non-scoped facts.
const EMPTY_FACT_ID: FactId = [0u8; 32];
