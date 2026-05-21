use crate::core::facts::{Fact, FactId};
use crate::core::intents::{
    HandlerContext, HandlerError, HandlerOutput, Intent, IntentHandler, RowMutation,
};
use crate::core::pipeline::queues::validate_intents_ignoring_key;
use crate::core::pipeline::{persisted_fact, INTENTS, LOCAL_INTENTS};
use crate::core::pipeline_storage::{
    decode_intent_row, insert_fact_and_pending_in_tx, purge_fact_in_tx,
    record_intent_in_table_in_tx, record_intent_in_tx, row_mutation_rows, sqlite_string_error,
    validate_row_mutations,
};
use crate::core::store::{Store, TableName};

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
    store: &Store,
    allowed_tables: &[TableName],
    limit: usize,
) -> Result<DispatchReport, String> {
    dispatch_stored_intents(
        handler,
        store,
        INTENTS,
        HandlerContextMode::InputFacts,
        allowed_tables,
        limit,
    )
}

/// Shared loop for dispatching queued intents.
///
/// Each iteration follows the prepare/commit/finish rhythm: claim one matching
/// intent, load the handler context, run the handler, then prepare, commit, and
/// finish its output. A `false` from [`finish_handler_output`] means another
/// dispatcher claimed the intent first, so the loop simply moves to the next.
fn dispatch_stored_intents(
    handler: &(impl IntentHandler + ?Sized),
    store: &Store,
    queue_table: TableName,
    context_mode: HandlerContextMode,
    allowed_tables: &[TableName],
    limit: usize,
) -> Result<DispatchReport, String> {
    let mut report = DispatchReport::default();
    while report.handled < limit {
        let Some(stored) = claim_stored_intent(store, queue_table, handler)? else {
            break;
        };
        let context = load_handler_context(store, handler, &stored.intent, context_mode)?;
        let Some(output) = run_handler(handler, &stored.intent, &context, &mut report)? else {
            break;
        };
        let output = prepare_handler_output(output, Some(&stored.key), allowed_tables)?;
        let handled = HandledIntent {
            table: queue_table,
            key: &stored.key,
        };
        let commit = commit_handler_output(store, Some(handled), &output, allowed_tables)?;
        if !finish_handler_output(commit, &mut report)? {
            continue;
        }
    }
    Ok(report)
}

/// Dispatch restart-local intents from the temp local-intent queue.
pub(crate) fn dispatch_local_intents(
    handler: &(impl IntentHandler + ?Sized),
    store: &Store,
    allowed_tables: &[TableName],
    limit: usize,
) -> Result<DispatchReport, String> {
    dispatch_stored_intents(
        handler,
        store,
        LOCAL_INTENTS,
        HandlerContextMode::InputFacts,
        allowed_tables,
        limit,
    )
}

/// Return the first queued intent accepted by this handler.
fn claim_stored_intent(
    store: &Store,
    queue_table: TableName,
    handler: &(impl IntentHandler + ?Sized),
) -> Result<Option<StoredIntent>, String> {
    let rows = if queue_table == LOCAL_INTENTS {
        store
            .row_table_rows_in_insertion_order(queue_table)
            .map_err(|err| format!("load local intents: {err}"))?
    } else {
        store
            .table_rows(queue_table)
            .map_err(|err| format!("load stored intents: {err}"))?
    };
    for (key, value) in rows {
        let intent = decode_intent_row(&key, &value)?;
        if handler.accepts(&intent) {
            return Ok(Some(StoredIntent { key, intent }));
        }
    }
    Ok(None)
}

/// Build the fact/store view a stored-intent handler requested.
fn load_handler_context<'a>(
    store: &'a Store,
    handler: &(impl IntentHandler + ?Sized),
    intent: &Intent,
    mode: HandlerContextMode,
) -> Result<HandlerContext<'a>, String> {
    let context = match mode {
        HandlerContextMode::InputFacts => {
            let mut facts = Vec::new();
            for id in handler.input_fact_ids(intent)? {
                if let Some(fact) = persisted_fact(store, &id)? {
                    facts.push(fact);
                }
            }
            HandlerContext::with_facts(facts)
        }
    };
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

/// Validate and split handler output before the commit transaction.
///
/// `handled_intent_key` is the queued intent being consumed, if any. It is kept
/// in the signature while the validation surface is simplified around stored
/// queues.
fn prepare_handler_output(
    output: HandlerOutput,
    handled_intent_key: Option<&[u8]>,
    allowed_tables: &[TableName],
) -> Result<HandlerOutputParts, String> {
    validate_intents_ignoring_key(&output.intents, handled_intent_key)?;
    validate_intents_ignoring_key(&output.local_intents, handled_intent_key)?;
    validate_row_mutations(&output.row_mutations, allowed_tables)?;
    Ok(HandlerOutputParts {
        facts: output.facts,
        purged_facts: output.purged_facts,
        row_mutations: output.row_mutations,
        durable_intents: output.intents,
        local_intents: output.local_intents,
    })
}

/// Commit the complete output of one handled intent in a single transaction.
///
/// This is the boundary for intent dispatch: deleting the handled queued intent,
/// purging facts, admitting emitted facts, applying row mutations, and recording
/// follow-up intents all happen together. If the handled row is already gone,
/// nothing commits and the returned [`HandlerCommit::handled`] is `false`.
fn commit_handler_output(
    store: &Store,
    handled_intent: Option<HandledIntent<'_>>,
    output: &HandlerOutputParts,
    allowed_tables: &[TableName],
) -> Result<HandlerCommit, String> {
    store
        .write_transaction(|tx| {
            if let Some(handled) = handled_intent {
                if tx.delete_table_rows_in_tx(handled.table, vec![handled.key.to_vec()])? == 0 {
                    return Ok(HandlerCommit::default());
                }
                if handled.table == INTENTS {
                    tx.delete_table_rows_in_tx(LOCAL_INTENTS, vec![handled.key.to_vec()])?;
                }
            }

            for purged in &output.purged_facts {
                purge_fact_in_tx(tx, *purged)?;
            }

            let mut facts = 0usize;
            for fact in &output.facts {
                if insert_fact_and_pending_in_tx(tx, fact)? {
                    facts += 1;
                }
            }

            let (rows, deletes) = row_mutation_rows(&output.row_mutations, allowed_tables)
                .map_err(sqlite_string_error)?;
            tx.insert_table_rows_in_tx(rows)?;
            for delete in deletes {
                tx.delete_table_rows_in_tx(delete.table, vec![delete.key])?;
            }

            let mut persisted_intents = 0usize;
            for intent in &output.durable_intents {
                if record_intent_in_tx(tx, intent)? {
                    persisted_intents += 1;
                }
            }

            let mut local_intents = 0usize;
            for intent in &output.local_intents {
                if record_intent_in_table_in_tx(tx, LOCAL_INTENTS, intent)? {
                    local_intents += 1;
                }
            }

            Ok(HandlerCommit {
                handled: true,
                facts,
                persisted_intents,
                local_intents,
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
    report.facts += commit.facts;
    report.intents += commit.persisted_intents + commit.local_intents;
    Ok(true)
}

fn is_retryable_handler_error(err: &HandlerError) -> bool {
    matches!(err, HandlerError::Retry(_))
}

#[derive(Debug, Clone, Copy)]
enum HandlerContextMode {
    InputFacts,
}

struct StoredIntent {
    key: Vec<u8>,
    intent: Intent,
}

#[derive(Debug, Clone, Copy)]
struct HandledIntent<'a> {
    table: TableName,
    key: &'a [u8],
}

/// Counts from one committed handler transaction.
#[derive(Debug, Default)]
struct HandlerCommit {
    /// Whether the transaction took effect. `false` only when the queued intent
    /// row was already gone.
    handled: bool,
    facts: usize,
    persisted_intents: usize,
    local_intents: usize,
}

struct HandlerOutputParts {
    facts: Vec<Fact>,
    purged_facts: Vec<FactId>,
    row_mutations: Vec<RowMutation>,
    durable_intents: Vec<Intent>,
    local_intents: Vec<Intent>,
}
