use crate::core::fact_store::persisted_fact;
use crate::core::intents::{
    HandlerContext, HandlerError, HandlerOutput, Intent, IntentHandler, IntentKind,
};
use crate::core::schema::{INTENTS, LOCAL_INTENTS};
use crate::core::store::{Store, TableName};
use rusqlite::{params, OptionalExtension};

use super::effects::{commit_pipeline_effects_in_tx, PipelineEffectCounts, PipelineEffects};
use super::intent_queue::record_intent_in_table_in_tx;

// === Intent dispatch ===

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DispatchReport {
    pub handled: usize,
    pub facts: usize,
    pub intents: usize,
    pub retries: usize,
}

pub(crate) fn submit_intent_to_store(store: &Store, intent: Intent) -> Result<bool, String> {
    submit_intent_to_table(store, INTENTS, intent)
}

pub(crate) fn submit_local_intent_to_store(store: &Store, intent: Intent) -> Result<bool, String> {
    submit_intent_to_table(store, LOCAL_INTENTS, intent)
}

fn submit_intent_to_table(store: &Store, table: TableName, intent: Intent) -> Result<bool, String> {
    let inserted = store
        .write_transaction(|tx| record_intent_in_table_in_tx(tx, table, &intent))
        .map_err(|err| format!("submit intent: {err}"))?;
    Ok(inserted)
}

/// Dispatch durable queued intents, each with the input facts its handler asks
/// for.
pub(crate) fn dispatch_durable_intents(
    handler: &(impl IntentHandler + ?Sized),
    intent_kind: &str,
    store: &Store,
    allowed_tables: &[TableName],
    limit: usize,
) -> Result<DispatchReport, String> {
    dispatch_stored_intents(handler, intent_kind, store, INTENTS, allowed_tables, limit)
}

/// Shared loop for dispatching queued intents.
///
/// Each iteration follows the prepare/commit/finish rhythm: claim one matching
/// intent, load the handler context, run the handler, then prepare, commit, and
/// finish its output. A `false` from [`finish_handler_output`] means another
/// dispatcher claimed the intent first, so the loop simply moves to the next.
fn dispatch_stored_intents(
    handler: &(impl IntentHandler + ?Sized),
    intent_kind: &str,
    store: &Store,
    queue_table: TableName,
    allowed_tables: &[TableName],
    limit: usize,
) -> Result<DispatchReport, String> {
    let mut report = DispatchReport::default();
    while report.handled < limit {
        let Some(stored) = next_intent_for_kind(store, queue_table, intent_kind)? else {
            break;
        };
        let context = load_handler_context(store, handler, &stored.intent)?;
        let Some(output) = run_handler(handler, &stored.intent, &context, &mut report)? else {
            break;
        };
        let effects = prepare_handler_output(output, allowed_tables)?;
        let handled = HandledIntent {
            table: queue_table,
            kind: stored.intent.kind.as_str(),
            idempotence_key: &stored.intent.key,
        };
        let commit = commit_handler_output(store, handled, &effects, allowed_tables)?;
        if !finish_handler_output(commit, &mut report)? {
            continue;
        }
    }
    Ok(report)
}

/// Dispatch restart-local intents from the temp local-intent queue.
pub(crate) fn dispatch_local_intents(
    handler: &(impl IntentHandler + ?Sized),
    intent_kind: &str,
    store: &Store,
    allowed_tables: &[TableName],
    limit: usize,
) -> Result<DispatchReport, String> {
    dispatch_stored_intents(
        handler,
        intent_kind,
        store,
        LOCAL_INTENTS,
        allowed_tables,
        limit,
    )
}

/// Return the first queued intent for a declared handler route.
fn next_intent_for_kind(
    store: &Store,
    queue_table: TableName,
    intent_kind: &str,
) -> Result<Option<StoredIntent>, String> {
    let table_name = intent_table_name(queue_table).map_err(|err| err.to_string())?;
    let order = if queue_table == LOCAL_INTENTS {
        "rowid"
    } else {
        "kind, idempotence_key"
    };
    store
        .conn()
        .query_row(
            &format!(
                "SELECT kind, idempotence_key, payload
                 FROM {table_name}
                 WHERE kind = ?1
                 ORDER BY {order}
                 LIMIT 1"
            ),
            params![intent_kind],
            |row| {
                let kind = IntentKind::new(row.get::<_, String>(0)?).map_err(|err| {
                    rusqlite::Error::InvalidParameterName(format!(
                        "invalid queued intent kind: {err}"
                    ))
                })?;
                Ok(StoredIntent {
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
    report: &mut DispatchReport,
) -> Result<Option<HandlerOutput>, String> {
    match handler.handle(intent, context) {
        Ok(output) => Ok(Some(output)),
        Err(err) => {
            if is_retryable_handler_error(&err) {
                report.retries += 1;
                Ok(None)
            } else {
                Err(err.to_string())
            }
        }
    }
}

fn prepare_handler_output(
    output: HandlerOutput,
    allowed_tables: &[TableName],
) -> Result<PipelineEffects, String> {
    let effects = PipelineEffects::from(output);
    effects.validate(allowed_tables)?;
    Ok(effects)
}

/// Commit the complete output of one handled intent in a single transaction.
///
/// This is the boundary for intent dispatch: deleting the handled queued intent,
/// purging facts, admitting emitted facts, applying row mutations, and recording
/// follow-up intents all happen together. If the handled row is already gone,
/// nothing commits and the returned [`HandlerCommit::handled`] is `false`.
fn commit_handler_output(
    store: &Store,
    handled: HandledIntent<'_>,
    effects: &PipelineEffects,
    allowed_tables: &[TableName],
) -> Result<HandlerCommit, String> {
    store
        .write_transaction(|tx| {
            if delete_intent_in_tx(tx, handled.table, handled.kind, handled.idempotence_key)? == 0 {
                return Ok(HandlerCommit::default());
            }
            if handled.table == INTENTS {
                delete_intent_in_tx(tx, LOCAL_INTENTS, handled.kind, handled.idempotence_key)?;
            }

            let counts = commit_pipeline_effects_in_tx(tx, effects, allowed_tables)?;

            Ok(HandlerCommit {
                handled: true,
                effects: counts,
            })
        })
        .map_err(|err| format!("commit handler output: {err}"))
}

/// Apply the post-commit effects of a handled intent and update the report.
///
/// Runs only after [`commit_handler_output`] succeeds. Returns whether the commit
/// took effect — `false` only when another dispatcher had already claimed the
/// stored intent.
fn finish_handler_output(
    commit: HandlerCommit,
    report: &mut DispatchReport,
) -> Result<bool, String> {
    if !commit.handled {
        return Ok(false);
    }

    report.handled += 1;
    report.facts += commit.effects.facts;
    report.intents += commit.effects.intents();
    Ok(true)
}

fn is_retryable_handler_error(err: &HandlerError) -> bool {
    matches!(err, HandlerError::Retry(_))
}

struct StoredIntent {
    intent: Intent,
}

#[derive(Debug, Clone, Copy)]
struct HandledIntent<'a> {
    table: TableName,
    kind: &'a str,
    idempotence_key: &'a [u8],
}

/// Counts from one committed handler transaction.
#[derive(Debug, Default)]
struct HandlerCommit {
    /// Whether the transaction took effect. `false` only when the queued intent
    /// row was already gone.
    handled: bool,
    effects: PipelineEffectCounts,
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
