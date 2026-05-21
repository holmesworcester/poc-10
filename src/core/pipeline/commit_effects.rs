use crate::core::effects::PipelineEffects;
use crate::core::fact_store::{insert_fact_and_pending_in_tx, purge_fact_in_tx};
use crate::core::intents::{
    Intent, RowMutation, SqlValue, TableDelete, TableDeleteWhere, TableInsert,
};
use crate::core::schema::LOCAL_INTENTS;
use crate::core::store::{
    quoted_identifier, quoted_identifier_list, quoted_table_name, Store, TableName, TableRow,
};
use rusqlite::{params_from_iter, OptionalExtension};
use std::collections::BTreeMap;

use super::dispatch::{record_intent_in_table_in_tx, record_intent_in_tx};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct PipelineEffectCounts {
    pub facts: usize,
    pub intents: usize,
    pub local_intents: usize,
}

pub(crate) fn validate_pipeline_effects(
    effects: &PipelineEffects,
    allowed_tables: &[TableName],
) -> Result<(), String> {
    validate_intents(&effects.intents)?;
    validate_intents(&effects.local_intents)?;
    validate_row_mutations(&effects.row_mutations, allowed_tables)?;
    Ok(())
}

/// Validate that a batch can be written to a single intent queue.
///
/// Intent durability is owned by the destination table. This check only rejects
/// conflicting duplicates within one destination queue.
fn validate_intents(intents: &[Intent]) -> Result<(), String> {
    let mut proposed = BTreeMap::<Vec<u8>, &Intent>::new();
    for intent in intents {
        let key = intent_validation_key(intent);
        if let Some(existing) = proposed.insert(key, intent) {
            if existing != intent {
                return Err(format!(
                    "pipeline emitted conflicting intents for {}",
                    intent.kind.as_str()
                ));
            }
        }
    }
    Ok(())
}

fn intent_validation_key(intent: &Intent) -> Vec<u8> {
    let mut key = intent.kind.as_str().as_bytes().to_vec();
    key.push(0);
    key.extend_from_slice(&intent.key);
    key
}

/// Reject any row mutation targeting a table this runtime has not registered.
fn validate_row_mutations(
    mutations: &[RowMutation],
    allowed_tables: &[TableName],
) -> Result<(), String> {
    for mutation in mutations {
        validate_row_mutation_table(mutation, allowed_tables)?;
    }
    Ok(())
}

/// Split row mutations into inserts and deletes so a commit can apply them.
fn row_mutation_rows(
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
            RowMutation::InsertValues(_) | RowMutation::DeleteWhere(_) => {}
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
        RowMutation::InsertValues(insert) => insert.table,
        RowMutation::DeleteWhere(delete) => delete.table,
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
pub(super) fn sqlite_string_error(err: String) -> rusqlite::Error {
    rusqlite::Error::InvalidParameterName(err)
}

pub(crate) fn commit_pipeline_effects_to_store(
    store: &Store,
    effects: &PipelineEffects,
    allowed_tables: &[TableName],
    label: &str,
) -> Result<PipelineEffectCounts, String> {
    validate_pipeline_effects(effects, allowed_tables)?;
    store
        .write_transaction(|tx| commit_pipeline_effects_in_tx(tx, effects, allowed_tables))
        .map_err(|err| format!("{label}: {err}"))
}

pub(crate) fn commit_pipeline_effects_in_tx(
    tx: &Store,
    effects: &PipelineEffects,
    allowed_tables: &[TableName],
) -> rusqlite::Result<PipelineEffectCounts> {
    for purged in &effects.purged_facts {
        purge_fact_in_tx(tx, *purged)?;
    }

    let mut facts = 0usize;
    for fact in &effects.facts {
        if insert_fact_and_pending_in_tx(tx, fact)? {
            facts += 1;
        }
    }

    let (rows, deletes) =
        row_mutation_rows(&effects.row_mutations, allowed_tables).map_err(sqlite_string_error)?;
    tx.insert_table_rows_in_tx(rows)?;
    for delete in deletes {
        tx.delete_table_rows_in_tx(delete.table, vec![delete.key])?;
    }
    for mutation in &effects.row_mutations {
        match mutation {
            RowMutation::InsertValues(insert) => {
                insert_values_in_tx(tx, insert)?;
            }
            RowMutation::DeleteWhere(delete) => {
                delete_where_in_tx(tx, delete)?;
            }
            RowMutation::PutRow(_) | RowMutation::DeleteRow(_) => {}
        }
    }

    let mut intents = 0usize;
    for intent in &effects.intents {
        if record_intent_in_tx(tx, intent)? {
            intents += 1;
        }
    }

    let mut local_intents = 0usize;
    for intent in &effects.local_intents {
        if record_intent_in_table_in_tx(tx, LOCAL_INTENTS, intent)? {
            local_intents += 1;
        }
    }

    Ok(PipelineEffectCounts {
        facts,
        intents,
        local_intents,
    })
}

fn insert_values_in_tx(store: &Store, insert: &TableInsert) -> rusqlite::Result<usize> {
    validate_columns_and_values(insert.columns, &insert.values, "insert")?;
    let table = quoted_table_name(insert.table)?;
    let columns = quoted_identifier_list(insert.columns)?;
    let placeholders = placeholders(insert.values.len());
    let values = sqlite_values(&insert.values)?;
    let changed = store.conn().execute(
        &format!("INSERT OR IGNORE INTO {table} ({columns}) VALUES ({placeholders})"),
        params_from_iter(values.iter()),
    )?;
    if changed == 0 && !insert_values_match(store, insert, &values)? {
        return Err(rusqlite::Error::InvalidParameterName(format!(
            "conflicting row for {}",
            insert.table.as_str()
        )));
    }
    Ok(changed)
}

fn insert_values_match(
    store: &Store,
    insert: &TableInsert,
    values: &[rusqlite::types::Value],
) -> rusqlite::Result<bool> {
    let table = quoted_table_name(insert.table)?;
    let predicate = where_clause(insert.columns)?;
    store
        .conn()
        .query_row(
            &format!("SELECT 1 FROM {table} WHERE {predicate} LIMIT 1"),
            params_from_iter(values.iter()),
            |_| Ok(()),
        )
        .optional()
        .map(|row| row.is_some())
}

fn delete_where_in_tx(store: &Store, delete: &TableDeleteWhere) -> rusqlite::Result<usize> {
    validate_columns_and_values(delete.columns, &delete.values, "delete")?;
    let table = quoted_table_name(delete.table)?;
    let predicate = where_clause(delete.columns)?;
    let values = sqlite_values(&delete.values)?;
    store.conn().execute(
        &format!("DELETE FROM {table} WHERE {predicate}"),
        params_from_iter(values.iter()),
    )
}

fn validate_columns_and_values(
    columns: &[&str],
    values: &[SqlValue],
    label: &str,
) -> rusqlite::Result<()> {
    if columns.is_empty() {
        return Err(rusqlite::Error::InvalidParameterName(format!(
            "{label} mutation requires at least one column"
        )));
    }
    if columns.len() != values.len() {
        return Err(rusqlite::Error::InvalidParameterName(format!(
            "{label} mutation column/value count mismatch"
        )));
    }
    Ok(())
}

fn sqlite_values(values: &[SqlValue]) -> rusqlite::Result<Vec<rusqlite::types::Value>> {
    values.iter().map(SqlValue::as_sqlite_value).collect()
}

fn where_clause(columns: &[&str]) -> rusqlite::Result<String> {
    columns
        .iter()
        .enumerate()
        .map(|(index, column)| Ok(format!("{} = ?{}", quoted_identifier(column)?, index + 1)))
        .collect::<rusqlite::Result<Vec<_>>>()
        .map(|columns| columns.join(" AND "))
}

fn placeholders(count: usize) -> String {
    (1..=count)
        .map(|index| format!("?{index}"))
        .collect::<Vec<_>>()
        .join(", ")
}
