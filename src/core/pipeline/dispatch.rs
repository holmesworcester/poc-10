//! Intent queue claiming, handler execution, and handler-output commit.
//!
//! Dispatch owns the lifecycle of one queued intent row. It claims the next
//! row for a registered kind, loads only the facts requested by the handler,
//! calls the handler, and commits the row deletion plus handler effects in one
//! transaction. Retry errors deliberately leave the row queued.
//!
//! Durable and restart-local queues share the same row shape. Durable work wins
//! when both queues contain the same kind, and handling a durable row removes a
//! duplicate local row with the same identity so restart-local retries do not
//! repeat work already accepted durably.

use crate::core::effects::PipelineEffects;
use crate::core::fact_store::persisted_fact;
use crate::core::intents::{HandlerContext, HandlerError, Intent, IntentHandler, IntentKind};
use crate::core::schema::{INTENTS, LOCAL_INTENTS};
use crate::core::store::{Store, TableName};
use rusqlite::{params, params_from_iter, OptionalExtension};

use super::commit_effects::{commit_pipeline_effects_in_tx, validate_pipeline_effects};
use super::WorkStatus;

/// Queue durable idempotent handler work.
pub(crate) fn submit_intent_to_store(store: &Store, intent: Intent) -> Result<bool, String> {
    submit_intent_to_table(store, INTENTS, intent)
}

/// Queue restart-local handler work on this SQLite connection.
pub(crate) fn submit_local_intent_to_store(store: &Store, intent: Intent) -> Result<bool, String> {
    submit_intent_to_table(store, LOCAL_INTENTS, intent)
}

/// Insert one intent into the selected queue.
///
/// Queue identity is `(kind, idempotence_key)`. Re-inserting the same payload is
/// a no-op; a different payload for the same identity rejects because dispatch
/// would no longer know which work item the key names.
fn submit_intent_to_table(store: &Store, table: TableName, intent: Intent) -> Result<bool, String> {
    let inserted = store
        .write_transaction(|tx| record_intent_in_table_in_tx(tx, table, &intent))
        .map_err(|err| format!("submit intent: {err}"))?;
    Ok(inserted)
}

/// Load the next queued row for any registered handler kind.
///
/// Durable queue rows are ordered by stable identity for deterministic tests
/// and replay. Local rows use insertion order so inbound network frames and
/// other restart-local work preserve arrival order within one process.
pub(crate) fn next_queued_intent(
    store: &Store,
    allowed_kinds: &[&str],
) -> Result<Option<QueuedIntent>, String> {
    if allowed_kinds.is_empty() {
        return Ok(None);
    }
    match next_queued_intent_in_table(store, INTENTS, allowed_kinds)? {
        Some(intent) => Ok(Some(intent)),
        None => next_queued_intent_in_table(store, LOCAL_INTENTS, allowed_kinds),
    }
}

/// Run one claimed intent through its handler.
///
/// On success, the handled row and all emitted effects commit together. On
/// retry, no SQL changes are made and the returned status records that dispatch
/// should stop this bounded pass.
pub(crate) fn dispatch_queued_intent(
    handler: &(impl IntentHandler + ?Sized),
    store: &Store,
    allowed_tables: &[TableName],
    queued: QueuedIntent,
) -> Result<WorkStatus, String> {
    let mut status = WorkStatus::idle();
    let context = load_handler_context(store, handler, &queued.intent)?;
    let Some(output) = run_handler(handler, &queued.intent, &context, &mut status)? else {
        return Ok(status);
    };
    validate_pipeline_effects(&output, allowed_tables)?;
    let handled = HandledIntent {
        table: queued.table,
        kind: queued.intent.kind.as_str(),
        idempotence_key: &queued.intent.key,
    };
    status.progressed = commit_handler_output(store, handled, &output, allowed_tables)?;
    Ok(status)
}

/// Return the first queued intent matching a declared handler route.
fn next_queued_intent_in_table(
    store: &Store,
    queue_table: TableName,
    allowed_kinds: &[&str],
) -> Result<Option<QueuedIntent>, String> {
    let table_name = intent_table_name(queue_table).map_err(|err| err.to_string())?;
    let order = if queue_table == LOCAL_INTENTS {
        "rowid"
    } else {
        "kind, idempotence_key"
    };
    let placeholders = (1..=allowed_kinds.len())
        .map(|idx| format!("?{idx}"))
        .collect::<Vec<_>>()
        .join(", ");
    store
        .conn()
        .query_row(
            &format!(
                "SELECT kind, idempotence_key, payload
                 FROM {table_name}
                 WHERE kind IN ({placeholders})
                 ORDER BY {order}
                 LIMIT 1"
            ),
            params_from_iter(allowed_kinds.iter().copied()),
            |row| {
                let kind = IntentKind::new(row.get::<_, String>(0)?).map_err(|err| {
                    rusqlite::Error::InvalidParameterName(format!(
                        "invalid queued intent kind: {err}"
                    ))
                })?;
                Ok(QueuedIntent {
                    table: queue_table,
                    intent: Intent::new(kind, row.get::<_, Vec<u8>>(1)?, row.get::<_, Vec<u8>>(2)?),
                })
            },
        )
        .optional()
        .map_err(|err| format!("load queued intent: {err}"))
}

/// Build the fact/store view a stored-intent handler requested.
fn load_handler_context<'a>(
    store: &'a Store,
    handler: &(impl IntentHandler + ?Sized),
    intent: &Intent,
) -> Result<HandlerContext<'a>, String> {
    let mut facts = Vec::new();
    for id in handler.input_fact_ids(intent)? {
        if let Some(fact) = persisted_fact(store, &id)? {
            facts.push(fact);
        }
    }
    let context = HandlerContext::with_facts(facts);
    Ok(context.with_store(store))
}

/// Run a handler and convert retry markers into report state.
fn run_handler(
    handler: &(impl IntentHandler + ?Sized),
    intent: &Intent,
    context: &HandlerContext<'_>,
    status: &mut WorkStatus,
) -> Result<Option<PipelineEffects>, String> {
    match handler.handle(intent, context) {
        Ok(output) => Ok(Some(output)),
        Err(err) => {
            if matches!(err, HandlerError::Retry(_)) {
                status.retried = true;
                Ok(None)
            } else {
                Err(err.to_string())
            }
        }
    }
}

/// Commit the complete output of one handled intent in a single transaction.
///
/// This is the boundary for intent dispatch: deleting the handled queued intent,
/// purging facts, admitting emitted facts, applying row mutations, and recording
/// follow-up intents all happen together. If the handled row is already gone,
/// nothing commits and the returned value is `false`.
fn commit_handler_output(
    store: &Store,
    handled: HandledIntent<'_>,
    effects: &PipelineEffects,
    allowed_tables: &[TableName],
) -> Result<bool, String> {
    store
        .write_transaction(|tx| {
            if delete_intent_in_tx(tx, handled.table, handled.kind, handled.idempotence_key)? == 0 {
                return Ok(false);
            }
            if handled.table == INTENTS {
                delete_intent_in_tx(tx, LOCAL_INTENTS, handled.kind, handled.idempotence_key)?;
            }

            commit_pipeline_effects_in_tx(tx, effects, allowed_tables)?;
            Ok(true)
        })
        .map_err(|err| format!("commit handler output: {err}"))
}

pub(crate) struct QueuedIntent {
    /// Queue table from which this row was claimed.
    pub(crate) table: TableName,
    pub(crate) intent: Intent,
}

#[derive(Debug, Clone, Copy)]
struct HandledIntent<'a> {
    table: TableName,
    kind: &'a str,
    idempotence_key: &'a [u8],
}

fn delete_intent_in_tx(
    store: &Store,
    table: TableName,
    kind: &str,
    idempotence_key: &[u8],
) -> rusqlite::Result<usize> {
    let table_name = intent_table_name(table)?;
    store.conn().execute(
        &format!("DELETE FROM {table_name} WHERE kind = ?1 AND idempotence_key = ?2"),
        params![kind, idempotence_key],
    )
}

pub(super) fn record_intent_in_tx(store: &Store, intent: &Intent) -> rusqlite::Result<bool> {
    record_intent_in_table_in_tx(store, INTENTS, intent)
}

/// Record an intent row in either queue inside the caller's transaction.
pub(super) fn record_intent_in_table_in_tx(
    store: &Store,
    table: TableName,
    intent: &Intent,
) -> rusqlite::Result<bool> {
    let table_name = intent_table_name(table)?;
    let changed = store.conn().execute(
        &format!(
            "INSERT OR IGNORE INTO {table_name} (kind, idempotence_key, payload)
             VALUES (?1, ?2, ?3)"
        ),
        params![
            intent.kind.as_str(),
            intent.key.as_slice(),
            intent.payload.as_slice()
        ],
    )?;
    if changed == 0 {
        let existing = store
            .conn()
            .query_row(
                &format!(
                    "SELECT payload
                     FROM {table_name}
                     WHERE kind = ?1 AND idempotence_key = ?2"
                ),
                params![intent.kind.as_str(), intent.key.as_slice()],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()?;
        if existing.as_deref() != Some(intent.payload.as_slice()) {
            return Err(rusqlite::Error::InvalidParameterName(format!(
                "conflicting intent row for {}",
                intent.kind.as_str()
            )));
        }
    }
    Ok(changed > 0)
}

fn intent_table_name(table: TableName) -> rusqlite::Result<&'static str> {
    if table == INTENTS {
        Ok("\"intents\"")
    } else if table == LOCAL_INTENTS {
        Ok("\"local_intents\"")
    } else {
        Err(rusqlite::Error::InvalidParameterName(format!(
            "table {} is not an intent queue",
            table.as_str()
        )))
    }
}
