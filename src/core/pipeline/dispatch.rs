//! Intent queue claiming, handler execution, and handler-output commit.
//!
//! Intents are how the runtime represents work that should happen after a fact
//! has projected or after IO produced protocol input. Projection stays
//! deterministic and local to one fact: when it discovers follow-up work, it
//! emits an `Intent` instead of running that work inline. The runtime later
//! dispatches the intent to the protocol handler registered for its kind. This
//! keeps commands, projection, network IO, and background maintenance on the
//! same idempotent queue model.
//!
//! Dispatch owns the lifecycle of one queued intent row. It chooses the next
//! row for a registered kind, loads only the facts requested by the handler,
//! and calls the handler. On success it opens the transaction that deletes the
//! handled row, then delegates the handler's `PipelineEffects` to
//! `commit_effects` inside that same transaction. Retry errors deliberately
//! leave the row queued.
//!
//! This transaction boundary is why dispatch matters. A handler output is
//! visible exactly when its input queue row is consumed: no output without
//! deleting the work item, and no deletion without committing the output. That
//! is the rule that makes handler retries safe after process crashes, missing
//! dependencies, and temporary network failures.
//!
//! Durable and ephemeral queues share the same row shape. Durable work wins
//! when both queues contain the same kind, and handling a durable row removes a
//! duplicate local row with the same identity so ephemeral retries do not
//! repeat work already accepted durably.

use crate::core::effects::PipelineEffects;
use crate::core::fact_store::persisted_fact;
use crate::core::intents::{
    HandlerContext, HandlerError, Intent, IntentHandler, IntentKind, NetworkAccess,
    NetworkAccessPolicy,
};
use crate::core::schema::{INTENTS, LOCAL_INTENTS};
use crate::core::store::{Store, TableName};
use rusqlite::{params, params_from_iter, OptionalExtension};

use super::commit_effects::{
    commit_pipeline_effects_in_tx, suppress_disallowed_intents, validate_pipeline_effects,
    IntentAdmissionPolicy,
};
use super::WorkStatus;

/// Queue durable idempotent handler work.
pub(crate) fn submit_intent_to_store(store: &Store, intent: Intent) -> Result<bool, String> {
    submit_intent_to_table(store, INTENTS, intent)
}

/// Queue ephemeral handler work on this SQLite connection.
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
/// other ephemeral work preserve arrival order within one process.
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
    network_access: NetworkAccessPolicy,
    store: &Store,
    allowed_tables: &[TableName],
    queued: QueuedIntent,
) -> Result<WorkStatus, String> {
    Ok(dispatch_queued_intent_with_policy(
        handler,
        network_access,
        store,
        allowed_tables,
        queued,
        IntentAdmissionPolicy::All,
    )?
    .status)
}

/// Run one claimed intent while suppressing inadmissible follow-up intents.
pub(crate) fn dispatch_queued_intent_filtering_intents(
    handler: &(impl IntentHandler + ?Sized),
    network_access: NetworkAccessPolicy,
    store: &Store,
    allowed_tables: &[TableName],
    queued: QueuedIntent,
    allowed_followup_kinds: &[&'static str],
) -> Result<IntentDispatchReport, String> {
    dispatch_queued_intent_with_policy(
        handler,
        network_access,
        store,
        allowed_tables,
        queued,
        IntentAdmissionPolicy::AllowKinds(allowed_followup_kinds),
    )
}

fn dispatch_queued_intent_with_policy(
    handler: &(impl IntentHandler + ?Sized),
    network_access: NetworkAccessPolicy,
    store: &Store,
    allowed_tables: &[TableName],
    queued: QueuedIntent,
    intent_policy: IntentAdmissionPolicy<'_>,
) -> Result<IntentDispatchReport, String> {
    let mut status = WorkStatus::idle();
    let context = load_handler_context(store, handler, network_access, &queued.intent)?;
    let Some(mut output) = run_handler(handler, &queued.intent, &context, &mut status)? else {
        if status.retried && queued.table == LOCAL_INTENTS {
            rotate_local_retry_to_tail(store, &queued.intent)?;
        }
        return Ok(IntentDispatchReport {
            status,
            suppressed_intents: 0,
        });
    };
    let mut suppressed_intents = suppress_disallowed_intents(&mut output, intent_policy);
    validate_pipeline_effects(&output, allowed_tables)?;
    let handled = HandledIntent {
        table: queued.table,
        kind: queued.intent.kind.as_str(),
        idempotence_key: &queued.intent.key,
    };
    status.progressed = commit_handler_output(store, handled, &output, allowed_tables)?;
    if !status.progressed {
        suppressed_intents = 0;
    }
    Ok(IntentDispatchReport {
        status,
        suppressed_intents,
    })
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
    let queued = store
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
        .map_err(|err| format!("load queued intent: {err}"))?;
    Ok(queued)
}

/// Build the fact/store view a stored-intent handler requested.
fn load_handler_context<'a>(
    store: &'a Store,
    handler: &(impl IntentHandler + ?Sized),
    network_access: NetworkAccessPolicy,
    intent: &Intent,
) -> Result<HandlerContext<'a>, String> {
    let mut facts = Vec::new();
    for id in handler.input_fact_ids(intent)? {
        if let Some(fact) = persisted_fact(store, &id)? {
            facts.push(fact);
        }
    }
    let context = HandlerContext::with_facts(facts);
    Ok(context
        .with_store(store)
        .with_network_access(NetworkAccess::from_policy(network_access)))
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
/// This is the boundary for intent dispatch, not a second implementation of
/// effect commits. Dispatch owns deleting the handled queued intent and
/// removing any shadowed ephemeral duplicate; `commit_effects` owns purging
/// facts, admitting emitted facts, applying row mutations, and recording
/// follow-up intents. Keeping those steps in one transaction means a handler
/// output is visible exactly when its input queue row is consumed.
///
/// If the handled row is already gone, nothing commits and the returned value
/// is `false`.
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

fn rotate_local_retry_to_tail(store: &Store, intent: &Intent) -> Result<bool, String> {
    store
        .write_transaction(|tx| {
            if delete_intent_in_tx(tx, LOCAL_INTENTS, intent.kind.as_str(), &intent.key)? == 0 {
                return Ok(false);
            }
            record_intent_in_table_in_tx(tx, LOCAL_INTENTS, intent)?;
            Ok(true)
        })
        .map_err(|err| format!("rotate local retry intent: {err}"))
}

pub(crate) struct QueuedIntent {
    /// Queue table from which this row was claimed.
    pub(crate) table: TableName,
    pub(crate) intent: Intent,
}

pub(crate) struct IntentDispatchReport {
    pub(crate) status: WorkStatus,
    pub(crate) suppressed_intents: usize,
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
