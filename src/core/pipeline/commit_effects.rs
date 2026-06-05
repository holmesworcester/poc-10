//! Atomic commit path for shared runtime effects.
//!
//! Core is built around a simple rule: runtime work describes what should
//! change, then one commit boundary makes that description durable. Commands,
//! projectors, and intent handlers do not directly mutate all of core state.
//! They return `PipelineEffects`: facts to admit, facts to purge, row
//! mutations, durable intents, and ephemeral intents. A commit is the
//! moment those pending effects are validated, written to SQLite, and made
//! visible together.
//!
//! Commit requests come from three places. `Runtime::submit_command_output`
//! commits effects produced by a user-facing command. Fact projection owns a
//! larger transaction that replaces that fact's context and time wakes, then
//! calls this file to write the projector's shared effects. Intent dispatch
//! owns a larger transaction that deletes the handled queue row, then calls
//! this file to write the handler's shared effects. Those callers own their
//! surrounding pipeline work; this file owns the common effect language inside
//! that work.
//!
//! Committing effects changes the runtime in four ways. Purged facts remove the
//! fact and its core-owned derived rows. New facts enter `facts`,
//! `local_fact_admissions`, and `pending_projection`. Row mutations update
//! protocol or core IO tables the runtime explicitly allowed. Follow-up intents
//! are recorded after the data they depend on, so later handler passes never see
//! queued work for state that failed to commit.
//!
//! The mechanism is deliberately split in two. `validate_pipeline_effects`
//! checks failures that do not need SQL: conflicting duplicate intents inside a
//! batch and row mutations aimed at tables outside the runtime allowlist. The
//! commit functions then rely on the store for the state-dependent checks:
//! content-addressed facts must match their ids, opaque row-table `PutRow`
//! effects must be new rows or exact duplicates, typed-table inserts must match
//! the full supplied row, and intent queue inserts must keep `(kind, key)`
//! stable.
//!
//! That row-table rule is not the rule for all projection state. Context rows
//! and time wakes are replaced by owner in the projection commit boundary
//! before this helper commits shared effects.
//! Typed-table projections can also change visible state by emitting explicit
//! `DeleteWhere` and `InsertValues` mutations in the desired order. The opaque
//! `PutRow` path is narrower: it is for facts whose derived row key should
//! continue to name the same bytes across retries and later context wakeups. If
//! new context should change the value for an existing logical row, the protocol
//! should model that as typed-table delete/insert state or choose a different
//! row key, not rely on `PutRow` as an upsert.
//!
//! The commit order is part of the contract. Purges run first so stale
//! core-owned rows disappear before new facts and derived rows become visible.
//! New facts are admitted and marked pending for projection. Row mutations
//! apply next. Follow-up durable and ephemeral intents are recorded last, so
//! downstream work is not queued until the data it depends on has committed.
//!
//! Keep this file protocol-neutral. It may decide whether an effect is allowed
//! to touch a registered table and whether an idempotent write conflicts with
//! existing SQL state. It must not interpret payload bytes, decide which facts
//! are valid, or know why a protocol table row matters. Add a new effect kind
//! here only when it needs this same all-or-nothing commit boundary; display
//! receipts, command-only output, and protocol policy belong in their owner
//! modules.

use crate::core::effects::PipelineEffects;
use crate::core::fact_store::{
    insert_ephemeral_fact_in_tx, insert_fact_and_pending_with_mode_in_tx, purge_fact_in_tx,
};
use crate::core::intents::{
    Intent, RowMutation, TableDelete, TableDeleteWhere, TableInsert, Value as SqlValue,
};
use crate::core::schema::LOCAL_INTENTS;
use crate::core::store::{
    quoted_identifier, quoted_identifier_list, quoted_table_name, Store, TableName, TableRow,
};
use rusqlite::{params_from_iter, OptionalExtension};
use std::collections::BTreeMap;

use super::dispatch::{record_intent_in_table_in_tx, record_intent_in_tx};
use super::route::FactAdmissionFn;
use super::ProjectionMode;

/// Which follow-up intents may be recorded by this commit path.
#[derive(Debug, Clone, Copy)]
pub(super) enum IntentAdmissionPolicy<'a> {
    /// Normal runtime behavior: record every emitted intent.
    All,
    /// Replay behavior: record only intents whose handlers are replay-allowed.
    AllowKinds(&'a [&'static str]),
}

impl IntentAdmissionPolicy<'_> {
    pub(super) fn pending_projection_mode(self) -> ProjectionMode {
        match self {
            Self::All => ProjectionMode::Normal,
            Self::AllowKinds(_) => ProjectionMode::Replay,
        }
    }

    fn allows(self, intent: &Intent) -> bool {
        match self {
            Self::All => true,
            Self::AllowKinds(kinds) => kinds.contains(&intent.kind.as_str()),
        }
    }
}

/// Remove intents that are not admissible in the current runtime mode.
pub(super) fn suppress_disallowed_intents(
    effects: &mut PipelineEffects,
    policy: IntentAdmissionPolicy<'_>,
) -> usize {
    let durable_before = effects.intents.len();
    effects.intents.retain(|intent| policy.allows(intent));
    let local_before = effects.local_intents.len();
    effects.local_intents.retain(|intent| policy.allows(intent));
    (durable_before - effects.intents.len()) + (local_before - effects.local_intents.len())
}

/// Counts of newly inserted follow-up work after an effect commit.
///
/// These counts are not a full change report. Purges, row mutations, and
/// idempotent duplicates are intentionally omitted because callers use this as
/// a scheduling signal for new facts and intents, not as an audit log.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct PipelineEffectCounts {
    /// Facts newly admitted.
    pub facts: usize,
    /// Durable intents newly queued.
    pub intents: usize,
    /// Ephemeral intents newly queued.
    pub local_intents: usize,
}

/// Validate the stateless parts of an effect batch before opening a transaction.
///
/// This catches pure conflicts first, so callers fail with a useful error before
/// any SQL writes are attempted. Existing-row conflicts are still checked at
/// write time because they depend on the transaction's current view of SQLite.
pub(crate) fn validate_pipeline_effects(
    effects: &PipelineEffects,
    allowed_tables: &[TableName],
) -> Result<(), String> {
    validate_intents(&effects.intents)?;
    validate_intents(&effects.local_intents)?;
    validate_row_mutations(&effects.row_mutations, allowed_tables)?;
    Ok(())
}

pub(crate) fn validate_pipeline_effects_for_admission(
    effects: &PipelineEffects,
    allowed_tables: &[TableName],
    fact_admission: Option<FactAdmissionFn>,
) -> Result<(), String> {
    validate_pipeline_effects(effects, allowed_tables)?;
    validate_fact_admissions(effects, fact_admission)?;
    Ok(())
}

fn validate_fact_admissions(
    effects: &PipelineEffects,
    fact_admission: Option<FactAdmissionFn>,
) -> Result<(), String> {
    let Some(fact_admission) = fact_admission else {
        return Ok(());
    };
    for fact in effects.facts.iter().chain(effects.ephemeral_facts.iter()) {
        fact_admission(fact)?;
    }
    Ok(())
}

/// Validate that a batch can be written to one intent queue.
///
/// Intent durability is owned by the destination table. This check only rejects
/// conflicting duplicates within that one destination queue; the durable and
/// ephemeral queues are allowed to carry the same `(kind, key)` because
/// dispatch defines how durable work shadows local work.
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
///
/// The allowlist is the ownership boundary between core and protocol storage.
/// A row mutation can only name tables declared by the runtime description; the
/// module that constructed the mutation still owns column meaning and payload
/// validation.
fn validate_row_mutations(
    mutations: &[RowMutation],
    allowed_tables: &[TableName],
) -> Result<(), String> {
    for mutation in mutations {
        validate_row_mutation_table(mutation, allowed_tables)?;
    }
    Ok(())
}

/// Split opaque row-table mutations into inserts and deletes for the store.
///
/// Typed-table mutations stay in `row_mutations` because they need declared
/// columns and predicates rather than the generic `row_key/row_value` shape.
/// The split keeps the store's opaque-row API narrow while letting this file
/// apply all row effects in one ordered commit pass.
///
/// This also means opaque `PutRow` is not an update primitive. Inserts run
/// before deletes, so a same-batch delete and put for the same key is not a
/// replacement operation. Use typed-table mutations when projection needs
/// explicit delete-then-insert state changes.
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

/// Validate and commit effects in a new transaction owned by this helper.
///
/// Use this for command submission and other callers that do not already have a
/// larger atomic unit. Projection and intent dispatch usually call
/// `commit_pipeline_effects_in_tx` instead so their own queue/context changes
/// commit with the shared effects.
pub(crate) fn commit_pipeline_effects_to_store(
    store: &Store,
    effects: &PipelineEffects,
    allowed_tables: &[TableName],
    fact_admission: Option<FactAdmissionFn>,
    label: &str,
) -> Result<PipelineEffectCounts, String> {
    validate_pipeline_effects_for_admission(effects, allowed_tables, fact_admission)?;
    store
        .write_transaction(|tx| {
            commit_pipeline_effects_in_tx(
                tx,
                effects,
                allowed_tables,
                fact_admission,
                ProjectionMode::Normal,
            )
        })
        .map_err(|err| format!("{label}: {err}"))
}

/// Write all shared effects into an already-open transaction.
///
/// The order is intentional: purges remove stale core-owned rows first, new
/// facts become pending, rows mutate, and follow-up intents are recorded last.
/// If any step fails, the caller's transaction rolls the whole batch back.
///
/// This function does not open or close the transaction. The caller owns the
/// larger atomic boundary, which is why projection can replace context and time
/// wakes before committing these effects, and dispatch can delete the handled
/// intent row in the same SQL unit.
pub(crate) fn commit_pipeline_effects_in_tx(
    tx: &Store,
    effects: &PipelineEffects,
    allowed_tables: &[TableName],
    fact_admission: Option<FactAdmissionFn>,
    pending_mode: ProjectionMode,
) -> rusqlite::Result<PipelineEffectCounts> {
    validate_fact_admissions(effects, fact_admission).map_err(sqlite_string_error)?;
    for purged in &effects.purged_facts {
        purge_fact_in_tx(tx, *purged)?;
    }

    let mut facts = 0usize;
    for fact in &effects.facts {
        if insert_fact_and_pending_with_mode_in_tx(tx, fact, pending_mode)? {
            facts += 1;
        }
    }

    for fact in &effects.ephemeral_facts {
        insert_ephemeral_fact_in_tx(tx, fact)?;
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

/// Insert a typed-table row idempotently.
///
/// Unlike row tables, typed tables do not have a generic key/value shape. The
/// complete supplied column set is therefore both the insert data and the
/// idempotence check. If SQLite ignores the insert because a primary key or
/// unique index already exists, the existing row must match every supplied
/// column or the effect is rejected as a conflict.
///
/// A typed table can still express changing projection state: emit a
/// `DeleteWhere` for the old logical row before an `InsertValues` for the new
/// row. The typed mutation loop preserves the order chosen by the protocol
/// module.
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

/// Check whether an ignored typed insert was an exact duplicate.
///
/// This is intentionally stricter than "the key already exists": callers that
/// emit typed rows must be able to retry the exact same effect without changing
/// meaning, and must fail if the same database identity already names different
/// column values.
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

/// Delete typed-table rows by an exact column predicate.
///
/// Deletes are idempotent absence requests. Deleting zero rows is successful
/// because callers are asking the commit boundary to make matching rows absent,
/// not asserting that a row must already exist.
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
