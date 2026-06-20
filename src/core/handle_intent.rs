//! Intent queue claiming, handler execution, and handler-output commit.
//!
//! Intents are how the runtime represents work that should happen after a fact
//! has projected or after IO produced protocol input. Projection stays
//! deterministic and local to one fact: when it discovers follow-up work, it
//! emits an `Intent` instead of running that work inline. The runtime later
//! dispatches the intent to the protocol handler registered for its kind. This
//! keeps commands, projection, network IO, and background maintenance on the
//! same queue and commit model.
//!
//! Dispatch owns the lifecycle of one queued intent row. The SQL shape is two
//! queues with the same columns: durable `intents` rows and process-local
//! `local_intents` rows. Every insert gets a fresh row id; `kind` only selects
//! the handler, while `intent_key` and `payload` remain handler-owned bytes.
//! `intent_context` and `local_intent_context` attach exact fact inputs to that
//! row. Runtime admission rejects intent kinds that are not in the handler
//! registry; if a stale invalid or unregistered row is already present, dispatch
//! consumes it as terminal input. Durable and local rows are both selected by
//! SQLite insertion order so projection, replay, and live IO all preserve the
//! order in which work was queued.
//!
//! Dispatch loads an intent's attached context fact ids by joining durable
//! `facts` bytes with `local_fact_admissions` metadata and places them in
//! `HandlerContext`; handlers that require an input call
//! `HandlerContext::require_fact`.
//!
//! This transaction boundary is why dispatch matters. The readable process is:
//! load one row, classify whether it can run, consume that exact row, build the
//! transaction-local handler context from attached facts, run the handler inside
//! a savepoint, validate returned effects, and commit those effects before the
//! transaction closes. Terminal rows and stale-version work are consumed without
//! running protocol code. Handler rejection rolls back handler-owned SQL to the
//! savepoint, then commits only the queue consumption. If the outer transaction
//! rolls back, the queued row is still there; if it commits, the row is gone and
//! any returned output is durable. Queue rows do not collapse by `(kind, key)`;
//! protocols that need backpressure express it in their own facts, row mutations,
//! network queues, or handler-local state.

use crate::core::db::{quoted_table_name, Db, TableName};
use crate::core::effects::{RuntimeEffects, StorageRequirement};
use crate::core::facts::{fact_from_storage_row, Fact, FactId};
use crate::core::intents::{HandlerContext, HandlerMode, Intent, IntentHandler, IntentKind};
use crate::core::perf_profile as perf;
use crate::core::schema::{INTENTS, INTENT_CONTEXT, LOCAL_INTENTS, LOCAL_INTENT_CONTEXT};

use crate::core::crypto;
use crate::core::project_fact::commit_effects::{
    commit_runtime_effects_in_tx, sqlite_string_error, validate_runtime_effects_for_admission,
};
use crate::core::project_fact::route::FactAdmissionFn;
use rusqlite::{params, OptionalExtension};
use std::net::SocketAddr;

struct QueuedIntent {
    /// Random row id for the exact queued work item being dispatched.
    intent_id: Vec<u8>,
    /// Queue from which this row was claimed.
    queue: IntentQueue,
    intent: Intent,
    mode: HandlerMode,
}

/// A queued row whose kind resolved to a registered handler.
struct RunnableIntent<'a> {
    queued: QueuedIntent,
    handler: &'a dyn IntentHandler,
    storage_requirement: StorageRequirement,
}

/// A queued row that is terminal before protocol code can run.
struct TerminalIntentDrop {
    /// Random row id for the exact queued work item being dropped.
    intent_id: Vec<u8>,
    /// Queue from which this row was claimed.
    queue: IntentQueue,
}

enum LoadedIntent<'a> {
    Runnable(RunnableIntent<'a>),
    TerminalDrop(TerminalIntentDrop),
}

// =============================================================================
// Runtime Entry Point
// =============================================================================

/// Dispatch one queued intent from the selected queue.
///
/// The caller owns queue order and batching. This function owns one intent row.
///
/// This is the whole intent worker in miniature:
///
/// 1. Load one queued row, its attached context ids, and its registered route.
/// 2. For runnable rows, delete the exact row, load attached facts, run the
///    handler in a savepoint, validate returned effects, and commit those
///    effects in the same transaction.
/// 3. For terminal rows, delete only the exact row and attached context rows.
///
/// Handlers are allowed to observe runtime state, so this is not a
/// pure-evaluation boundary like projection. The queue lifecycle is still
/// centralized: every successful path consumes only the selected row, and
/// handler output becomes visible only through the same commit boundary.
pub(crate) fn dispatch_one_intent(
    store: &Db,
    handlers: &HandlerSet,
    queue: IntentQueue,
    allowed_tables: &[TableName],
    fact_admission: Option<FactAdmissionFn>,
) -> Result<bool, String> {
    let loaded = match perf::measure_result("intent_load", || {
        load_one_intent_input(store, handlers, queue)
    })? {
        None => return Ok(false),
        Some(loaded) => loaded,
    };

    let commit_result = match loaded {
        LoadedIntent::Runnable(input) => perf::measure_result("intent_commit_runnable", || {
            run_and_commit_loaded_intent(
                store,
                input,
                allowed_tables,
                handlers.intent_kinds(),
                fact_admission,
            )
        }),
        LoadedIntent::TerminalDrop(drop) => {
            perf::measure_result("intent_commit_terminal_drop", || {
                drop_terminal_queued_intent(store, drop)
            })
        }
    };
    commit_result
}

// =============================================================================
// Stages
// =============================================================================

/// Stage 1: load and classify one queued intent.
///
/// Durable and local rows use insertion order. This stage does not mutate SQL:
/// it selects one row, loads its attached fact ids, rebuilds the typed `Intent`,
/// and resolves the registered handler route. Invalid persisted kinds and stale
/// unregistered kinds are terminal rows that a later commit stage will delete
/// without running protocol code.
fn load_one_intent_input<'a>(
    store: &'a Db,
    handlers: &'a HandlerSet,
    queue: IntentQueue,
) -> Result<Option<LoadedIntent<'a>>, String> {
    let Some(row) =
        next_intent_row(store, queue).map_err(|err| format!("load queued intent: {err}"))?
    else {
        return Ok(None);
    };
    let QueuedIntentRow {
        intent_id,
        kind,
        intent_key,
        payload,
        mode,
    } = row;
    let context_fact_ids = intent_context_fact_ids(store, queue, &intent_id)
        .map_err(|err| format!("load queued intent context: {err}"))?;
    let kind = match IntentKind::new(kind) {
        Ok(kind) => kind,
        Err(_) => {
            return Ok(Some(LoadedIntent::TerminalDrop(TerminalIntentDrop {
                intent_id,
                queue,
            })));
        }
    };
    let intent = Intent::new(kind, intent_key, payload).with_context_fact_ids(context_fact_ids);
    let Some(entry) = handlers.handler_for_kind(intent.kind.as_str()) else {
        return Ok(Some(LoadedIntent::TerminalDrop(TerminalIntentDrop {
            intent_id,
            queue,
        })));
    };
    Ok(Some(LoadedIntent::Runnable(RunnableIntent {
        queued: QueuedIntent {
            intent_id,
            queue,
            intent,
            mode,
        },
        handler: entry.handler.as_ref(),
        storage_requirement: entry.storage_requirement,
    })))
}

/// Stage 2: commit one runnable intent.
///
/// This is intentionally written as the transaction story, not as a set of
/// hidden callbacks. The order is the contract:
///
/// 1. Check whether this handler route can safely write to the current storage
///    version. Stale-version work is consumed without running the handler.
/// 2. Delete the exact queue row and attached context rows.
/// 3. Load attached retained facts into `HandlerContext`; if any attached fact
///    disappeared, treat the selected row as stale and commit only consumption.
/// 4. Run the handler in a savepoint so handler-owned SQL can be rolled back
///    independently from queue consumption.
/// 5. Validate and commit returned `RuntimeEffects`.
///
/// If the handled row is already gone, nothing commits and the returned value
/// is `false`.
fn run_and_commit_loaded_intent(
    store: &Db,
    input: RunnableIntent<'_>,
    allowed_tables: &[TableName],
    registered_intent_kinds: &[&str],
    fact_admission: Option<FactAdmissionFn>,
) -> Result<bool, String> {
    let RunnableIntent {
        queued,
        handler,
        storage_requirement,
    } = input;
    store
        .write_transaction(|tx| {
            perf::measure_result("intent_commit_tx_body", || {
                if !handler_storage_requirement_satisfied(tx, storage_requirement)
                    .map_err(sqlite_string_error)?
                {
                    // The route targets a storage version this database cannot
                    // currently satisfy. Consume the stale work without allowing the
                    // handler to write rows for an old shape.
                    return consume_queued_intent_in_tx(tx, queued.queue, &queued.intent_id);
                }
                if !consume_queued_intent_in_tx(tx, queued.queue, &queued.intent_id)? {
                    return Ok(false);
                }
                let Some(context) = perf::measure_result("intent_load_handler_context", || {
                    load_handler_context(tx, &queued.intent, queued.mode)
                })
                .map_err(sqlite_string_error)?
                else {
                    // Context rows point at exact retained facts. If one vanished,
                    // the selected intent is stale and there is no safe handler run.
                    return Ok(true);
                };
                let Some(effects) = perf::measure_result("intent_handler_and_validate", || {
                    run_handler_and_validate_effects(
                        tx,
                        handler,
                        &queued.intent,
                        context,
                        storage_requirement,
                        allowed_tables,
                        registered_intent_kinds,
                        fact_admission,
                    )
                })
                .map_err(sqlite_string_error)?
                else {
                    return Ok(true);
                };
                perf::measure_result("intent_commit_runtime_effects", || {
                    commit_runtime_effects_in_tx(
                        tx,
                        &effects,
                        allowed_tables,
                        registered_intent_kinds,
                        fact_admission,
                        queued.mode.is_replay(),
                        false,
                    )
                })?;
                Ok(true)
            })
        })
        .map_err(|err| format!("commit handler output: {err}"))
}

/// Stage 3: consume one terminal row without running protocol code.
///
/// Terminal rows are syntactically invalid or reference an intent kind this
/// runtime no longer registers. They have no safe handler path, so dispatch
/// commits only exact row and context-row deletion.
fn drop_terminal_queued_intent(store: &Db, drop: TerminalIntentDrop) -> Result<bool, String> {
    store
        .write_transaction(|tx| consume_queued_intent_in_tx(tx, drop.queue, &drop.intent_id))
        .map_err(|err| format!("drop terminal intent: {err}"))
}

/// Run one claimed intent through its handler and validate uncommitted effects.
///
/// The handler may use transaction-local SQL through the database handle in its
/// context. Handler errors roll back to the savepoint and return `None`, letting
/// the caller commit only queue consumption. Successful effects are tagged with
/// the route's storage requirement and validated before the transaction commits.
fn run_handler_and_validate_effects(
    tx: &Db,
    handler: &dyn IntentHandler,
    intent: &Intent,
    context: HandlerContext<'_>,
    storage_requirement: StorageRequirement,
    allowed_tables: &[TableName],
    registered_intent_kinds: &[&str],
    fact_admission: Option<FactAdmissionFn>,
) -> Result<Option<RuntimeEffects>, String> {
    match run_handler_in_savepoint(tx, || handler.handle(intent, &context))? {
        Ok(effects) => {
            let effects = effects.with_storage_requirement(storage_requirement);
            validate_runtime_effects_for_admission(
                &effects,
                allowed_tables,
                registered_intent_kinds,
                fact_admission,
            )?;
            Ok(Some(effects))
        }
        Err(_) => Ok(None),
    }
}

fn run_handler_in_savepoint(
    tx: &Db,
    run: impl FnOnce() -> crate::core::intents::HandlerResult,
) -> Result<crate::core::intents::HandlerResult, String> {
    tx.conn()
        .execute_batch("SAVEPOINT intent_handler_run")
        .map_err(|err| format!("open handler savepoint: {err}"))?;
    let result = run();
    match &result {
        Ok(_) => tx
            .conn()
            .execute_batch("RELEASE intent_handler_run")
            .map_err(|err| format!("release handler savepoint: {err}"))?,
        Err(_) => {
            tx.conn()
                .execute_batch("ROLLBACK TO intent_handler_run")
                .map_err(|err| format!("rollback handler savepoint: {err}"))?;
            tx.conn()
                .execute_batch("RELEASE intent_handler_run")
                .map_err(|err| format!("release handler savepoint: {err}"))?;
        }
    }
    Ok(result)
}

fn handler_storage_requirement_satisfied(
    tx: &Db,
    requirement: StorageRequirement,
) -> Result<bool, String> {
    match requirement {
        StorageRequirement::MaintenanceBypass => Ok(true),
        StorageRequirement::Current(version) => tx
            .current_storage_version()
            .map(|stored| stored == Some(version))
            .map_err(|err| format!("read storage version marker: {err}")),
    }
}

// =============================================================================
// Load Stage Helpers
// =============================================================================

/// Return the first queued intent in queue order.
#[cfg(test)]
fn next_queued_intent_in_queue(
    store: &Db,
    queue: IntentQueue,
) -> Result<Option<QueuedIntent>, String> {
    next_intent_row(store, queue)
        .map_err(|err| format!("load queued intent: {err}"))?
        .map(|row| {
            let QueuedIntentRow {
                intent_id,
                kind,
                intent_key,
                payload,
                mode,
            } = row;
            let context_fact_ids = intent_context_fact_ids(store, queue, &intent_id)
                .map_err(|err| format!("load queued intent context: {err}"))?;
            let kind = IntentKind::new(kind)
                .map_err(|err| format!("invalid queued intent kind: {err}"))?;
            Ok(QueuedIntent {
                intent_id,
                queue,
                intent: Intent::new(kind, intent_key, payload)
                    .with_context_fact_ids(context_fact_ids),
                mode,
            })
        })
        .transpose()
}

/// Build the transaction-local fact/database view attached to a queued intent.
fn load_handler_context<'a>(
    store: &'a Db,
    intent: &Intent,
    mode: HandlerMode,
) -> Result<Option<HandlerContext<'a>>, String> {
    let mut facts = Vec::new();
    for id in &intent.context_fact_ids {
        let Some(fact) = load_retained_fact(store, &id)? else {
            return Ok(None);
        };
        facts.push(fact);
    }
    Ok(Some(
        HandlerContext::with_facts(store, facts).with_mode(mode),
    ))
}

fn load_retained_fact(store: &Db, id: &FactId) -> Result<Option<Fact>, String> {
    store
        .conn()
        .query_row(
            "SELECT f.id, m.scope, m.scope_kind, m.scope_id, m.received_at, f.bytes
             FROM facts f
             JOIN local_fact_admissions m ON m.fact_id = f.id
             WHERE f.id = ?1
             LIMIT 1",
            params![id.as_slice()],
            fact_from_storage_row,
        )
        .optional()
        .map_err(|err| format!("load handler fact: {err}"))
}

// =============================================================================
// Registry and Runtime Types
// =============================================================================

/// Factory for one protocol intent handler.
pub type HandlerFactory = fn() -> Box<dyn IntentHandler>;

/// Build the current intent for a recurring operational loop.
///
/// The daemon calls this while the process is online to mint one tick of live
/// work. Returning `Ok(None)` means there is nothing to do this tick. The
/// builder reads the database the same way a handler reads its inputs; it must not
/// depend on persisted scheduler rows, because recurring schedules are
/// in-memory only and never replayed.
pub type RecurringIntentBuilder = fn(&Db, RecurringIntentContext) -> Result<Option<Intent>, String>;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RecurringIntentContext {
    /// Wall-clock time captured by the runtime turn that offered this recurring work.
    pub now_ms: u64,
    /// Current process listen address, when this runtime turn has one.
    pub local_addr: Option<SocketAddr>,
}

/// In-memory declaration for recurring operational intent opportunities.
///
/// Recurring intents are not durable state. Each runtime turn gives declared
/// recurring builders a chance to inspect current state and enqueue bounded
/// local work. There is nothing to wipe on upgrade and nothing to replay:
/// operational repetition belongs here, not in durable time wakes or projectors.
#[derive(Debug, Clone, Copy)]
pub struct RecurringIntentSpec {
    /// Build this turn's intent from current database state, or `None` to skip.
    pub build_intent: RecurringIntentBuilder,
}

/// One handler route in the protocol registry.
///
/// `intent_kind` is the queue routing key that selects this handler for both
/// durable and ephemeral intents.
/// `recurrence` marks live-only operational repetition. A route with a
/// recurrence is offered by each runtime turn.
#[derive(Debug, Clone, Copy)]
pub struct HandlerRoute {
    /// Intent kind handled by this route.
    pub intent_kind: &'static str,
    /// Handler factory.
    pub factory: HandlerFactory,
    /// Storage version required by this handler's committed effects.
    pub storage_requirement: StorageRequirement,
    /// Live-only recurring work offered by runtime turns, if any.
    pub recurrence: Option<RecurringIntentSpec>,
}

/// Instantiated handlers for one runtime pass.
///
/// The set owns concrete handler values so dispatch can borrow trait objects
/// without rebuilding them for every queued row.
pub(crate) struct HandlerSet {
    entries: Vec<HandlerEntry>,
    intent_kinds: Vec<&'static str>,
}

struct HandlerEntry {
    intent_kind: &'static str,
    handler: Box<dyn IntentHandler>,
    storage_requirement: StorageRequirement,
}

impl HandlerSet {
    /// Instantiate all declared routes.
    pub(crate) fn new(routes: &'static [HandlerRoute]) -> Self {
        Self {
            entries: routes
                .iter()
                .map(|route| HandlerEntry {
                    intent_kind: route.intent_kind,
                    handler: (route.factory)(),
                    storage_requirement: route.storage_requirement,
                })
                .collect(),
            intent_kinds: routes.iter().map(|route| route.intent_kind).collect(),
        }
    }

    pub(crate) fn intent_kinds(&self) -> &[&'static str] {
        &self.intent_kinds
    }

    fn handler_for_kind(&self, kind: &str) -> Option<&HandlerEntry> {
        self.entries.iter().find(|entry| entry.intent_kind == kind)
    }
}

/// Verify that an intent can be dispatched by this runtime's handler registry.
pub(crate) fn validate_intent_kind_registered(
    intent: &Intent,
    registered_kinds: &[&str],
) -> Result<(), String> {
    if registered_kinds
        .iter()
        .any(|kind| *kind == intent.kind.as_str())
    {
        Ok(())
    } else {
        Err(format!(
            "intent kind {} is not registered",
            intent.kind.as_str()
        ))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum IntentQueue {
    Durable,
    Local,
}

impl IntentQueue {
    fn table(self) -> TableName {
        match self {
            Self::Durable => INTENTS,
            Self::Local => LOCAL_INTENTS,
        }
    }

    fn context_table(self) -> TableName {
        match self {
            Self::Durable => INTENT_CONTEXT,
            Self::Local => LOCAL_INTENT_CONTEXT,
        }
    }
}

// =============================================================================
// Queue SQL Helpers
// =============================================================================

fn intent_queue_error(message: impl Into<String>) -> rusqlite::Error {
    rusqlite::Error::InvalidParameterName(message.into())
}

/// Insert one queued intent inside the caller's transaction.
pub(crate) fn insert_intent_in_tx(
    db: &Db,
    queue: IntentQueue,
    intent: &Intent,
    mode: HandlerMode,
) -> rusqlite::Result<()> {
    let table_name = quoted_table_name(queue.table())?;
    for _ in 0..8 {
        let intent_id = random_intent_id();
        let changed = db.conn().execute(
            &format!(
                "INSERT OR IGNORE INTO {table_name} (intent_id, kind, intent_key, payload, replay)
                 VALUES (?1, ?2, ?3, ?4, ?5)"
            ),
            params![
                intent_id.as_slice(),
                intent.kind.as_str(),
                intent.handler_key.as_slice(),
                intent.payload.as_slice(),
                replay_flag_for_handler_mode(mode)
            ],
        )?;
        if changed == 1 {
            insert_intent_context_rows_in_tx(db, queue, &intent_id, &intent.context_fact_ids)?;
            return Ok(());
        }
    }
    Err(intent_queue_error(
        "intent id collision while queuing intent",
    ))
}

fn random_intent_id() -> [u8; 16] {
    let random = crypto::random_bytes_32();
    let mut id = [0u8; 16];
    id.copy_from_slice(&random[..16]);
    id[6] = (id[6] & 0x0f) | 0x40;
    id[8] = (id[8] & 0x3f) | 0x80;
    id
}

fn insert_intent_context_rows_in_tx(
    db: &Db,
    queue: IntentQueue,
    intent_id: &[u8],
    fact_ids: &[FactId],
) -> rusqlite::Result<()> {
    let table_name = quoted_table_name(queue.context_table())?;
    for (ordinal, fact_id) in fact_ids.iter().enumerate() {
        db.conn().execute(
            &format!(
                "INSERT INTO {table_name} (intent_id, ordinal, fact_id)
                 VALUES (?1, ?2, ?3)"
            ),
            params![intent_id, ordinal as i64, fact_id.as_slice()],
        )?;
    }
    Ok(())
}

fn replay_flag_for_handler_mode(mode: HandlerMode) -> i64 {
    if mode.is_replay() {
        1
    } else {
        0
    }
}

/// Consume exactly one queue row and its attached context rows.
///
/// Returning `false` means the selected row disappeared before the transaction
/// reached it, so the caller must not run handler code or commit effects.
fn consume_queued_intent_in_tx(
    db: &Db,
    queue: IntentQueue,
    intent_id: &[u8],
) -> rusqlite::Result<bool> {
    if delete_intent_row_in_tx(db, queue, intent_id)? == 0 {
        return Ok(false);
    }
    delete_intent_context_rows_in_tx(db, queue, intent_id)?;
    Ok(true)
}

/// Delete one queued intent row by its queue row id.
fn delete_intent_row_in_tx(
    db: &Db,
    queue: IntentQueue,
    intent_id: &[u8],
) -> rusqlite::Result<usize> {
    let table_name = quoted_table_name(queue.table())?;
    db.conn().execute(
        &format!("DELETE FROM {table_name} WHERE intent_id = ?1"),
        params![intent_id],
    )
}

fn delete_intent_context_rows_in_tx(
    db: &Db,
    queue: IntentQueue,
    intent_id: &[u8],
) -> rusqlite::Result<usize> {
    let table_name = quoted_table_name(queue.context_table())?;
    db.conn().execute(
        &format!("DELETE FROM {table_name} WHERE intent_id = ?1"),
        params![intent_id],
    )
}

/// Select the next queued intent row in queue order.
fn next_intent_row(db: &Db, queue: IntentQueue) -> rusqlite::Result<Option<QueuedIntentRow>> {
    let table_name = quoted_table_name(queue.table())?;
    db.conn()
        .query_row(
            &format!(
                "SELECT intent_id, kind, intent_key, payload, replay
                 FROM {table_name}
                 ORDER BY rowid
                 LIMIT 1"
            ),
            [],
            |row| {
                Ok(QueuedIntentRow {
                    intent_id: row.get(0)?,
                    kind: row.get(1)?,
                    intent_key: row.get(2)?,
                    payload: row.get(3)?,
                    mode: handler_mode_from_replay_flag(row.get(4)?),
                })
            },
        )
        .optional()
}

fn intent_context_fact_ids(
    db: &Db,
    queue: IntentQueue,
    intent_id: &[u8],
) -> rusqlite::Result<Vec<FactId>> {
    let table_name = quoted_table_name(queue.context_table())?;
    let mut stmt = db.conn().prepare(&format!(
        "SELECT fact_id
         FROM {table_name}
         WHERE intent_id = ?1
         ORDER BY ordinal"
    ))?;
    let fact_ids = stmt
        .query_map(params![intent_id], |row| row.get::<_, FactId>(0))?
        .collect();
    fact_ids
}

struct QueuedIntentRow {
    intent_id: Vec<u8>,
    kind: String,
    intent_key: Vec<u8>,
    payload: Vec<u8>,
    mode: HandlerMode,
}

fn handler_mode_from_replay_flag(replay: i64) -> HandlerMode {
    if replay == 0 {
        HandlerMode::Live
    } else {
        HandlerMode::Replay
    }
}

/// Queue ephemeral handler work on this SQLite connection.
pub(crate) fn submit_local_intent_to_db(store: &Db, intent: Intent) -> Result<(), String> {
    submit_intent_to_queue(store, IntentQueue::Local, intent)
}

/// Insert one intent into the selected queue.
///
/// Every insert records a distinct queued work item. Repeated semantic work
/// must be collapsed by the handler's own facts, row writes, network queue, or
/// in-memory state when that protocol needs backpressure.
pub(crate) fn submit_intent_to_queue(
    store: &Db,
    queue: IntentQueue,
    intent: Intent,
) -> Result<(), String> {
    store
        .write_transaction(|tx| insert_intent_in_tx(tx, queue, &intent, HandlerMode::Live))
        .map_err(|err| format!("submit intent: {err}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::effects::{RuntimeEffects, StorageRequirement};
    use crate::core::facts::{Fact, FactScope};
    use crate::core::intents::{
        HandlerError, HandlerResult, IntentKind, RowMutation, TableInsert, Value,
    };
    use crate::core::schema::{
        CORE_SCHEMA_SOURCE, INCOMING_FACTS, INTENT_CONTEXT, PENDING_PROJECTION,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};

    const TEST_TABLE: TableName = TableName::new("test.rows");
    const TEST_HANDLER_STATE_TABLE: &str = "\"test.handler_state\"";

    static AFTER_FACT_CALLS: AtomicUsize = AtomicUsize::new(0);
    static VERSION_GUARD_HANDLER_CALLS: AtomicUsize = AtomicUsize::new(0);

    #[test]
    fn durable_success_deletes_only_claimed_row() {
        let store = Db::open_memory_with_schema_sources(&[CORE_SCHEMA_SOURCE]).expect("open db");
        let intent = test_intent("handled", b"same-key");

        submit_intent_to_queue(&store, IntentQueue::Local, intent.clone()).expect("submit local");
        submit_intent_to_queue(&store, IntentQueue::Durable, intent).expect("submit durable");

        let dispatched = dispatch_intents_for_test(
            &store,
            &HandlerSet::new(NOOP_ROUTES),
            IntentQueue::Durable,
            &[],
            None,
            1,
        )
        .expect("dispatch durable intent");

        assert_eq!(dispatched, 1);
        assert_eq!(store.table_row_count(INTENTS).expect("durable count"), 0);
        assert_eq!(
            store.table_row_count(LOCAL_INTENTS).expect("local count"),
            1,
            "durable success should not collapse a distinct local row"
        );
    }

    #[test]
    fn local_empty_handler_output_consumes_rows_and_continues() {
        let store = Db::open_memory_with_schema_sources(&[CORE_SCHEMA_SOURCE]).expect("open db");
        let first = test_intent("handled", b"first");
        let second = test_intent("handled", b"second");
        submit_intent_to_queue(&store, IntentQueue::Local, first.clone())
            .expect("submit first local");
        submit_intent_to_queue(&store, IntentQueue::Local, second).expect("submit second local");

        let dispatched = dispatch_intents_for_test(
            &store,
            &HandlerSet::new(NOOP_ROUTES),
            IntentQueue::Local,
            &[],
            None,
            8,
        )
        .expect("dispatch local intents");

        assert_eq!(dispatched, 2);
        assert_eq!(
            store.table_row_count(LOCAL_INTENTS).expect("local count"),
            0,
            "empty successful output should still consume local work"
        );
    }

    #[test]
    fn handler_error_drops_row_without_output() {
        let store = Db::open_memory_with_schema_sources(&[CORE_SCHEMA_SOURCE]).expect("open db");
        submit_intent_to_queue(&store, IntentQueue::Durable, test_intent("fatal", b"first"))
            .expect("submit fatal intent");

        let consumed = dispatch_one_intent(
            &store,
            &HandlerSet::new(FATAL_ROUTES),
            IntentQueue::Durable,
            &[],
            None,
        )
        .expect("invalid intent should be dropped");

        assert!(consumed);
        assert_eq!(store.table_row_count(INTENTS).expect("durable count"), 0);
    }

    #[test]
    fn unregistered_queued_intent_drops_row() {
        let store = Db::open_memory_with_schema_sources(&[CORE_SCHEMA_SOURCE]).expect("open db");
        submit_intent_to_queue(
            &store,
            IntentQueue::Durable,
            test_intent("unregistered", b"first"),
        )
        .expect("submit unregistered intent row");

        let consumed = dispatch_one_intent(
            &store,
            &HandlerSet::new(NOOP_ROUTES),
            IntentQueue::Durable,
            &[],
            None,
        )
        .expect("unregistered queued intent should be dropped");

        assert!(consumed);
        assert_eq!(store.table_row_count(INTENTS).expect("durable count"), 0);
    }

    #[test]
    fn invalid_queued_intent_kind_drops_row() {
        let store = Db::open_memory_with_schema_sources(&[CORE_SCHEMA_SOURCE]).expect("open db");
        store
            .write_transaction(|tx| {
                tx.conn().execute(
                    "INSERT INTO intents (intent_id, kind, intent_key, payload, replay)
                     VALUES (?1, 'InvalidKind', ?2, ?3, 0)",
                    params![
                        random_intent_id().as_slice(),
                        b"key".as_slice(),
                        b"payload".as_slice()
                    ],
                )?;
                Ok(())
            })
            .expect("insert invalid intent row");

        let consumed = dispatch_one_intent(
            &store,
            &HandlerSet::new(NOOP_ROUTES),
            IntentQueue::Durable,
            &[],
            None,
        )
        .expect("invalid kind should be dropped");

        assert!(consumed);
        assert_eq!(store.table_row_count(INTENTS).expect("durable count"), 0);
    }

    #[test]
    fn validation_error_leaves_row_queued_without_committing_effects() {
        let store = Db::open_memory_with_schema_sources(&[CORE_SCHEMA_SOURCE]).expect("open db");
        submit_intent_to_queue(
            &store,
            IntentQueue::Durable,
            test_intent("invalid_output", b"first"),
        )
        .expect("submit invalid-output intent");

        let err = dispatch_one_intent(
            &store,
            &HandlerSet::new(INVALID_OUTPUT_ROUTES),
            IntentQueue::Durable,
            &[],
            None,
        )
        .expect_err("invalid handler output should fail before commit");

        assert!(
            err.contains("row mutation table test.rows is not registered"),
            "{err}"
        );
        assert_eq!(store.table_row_count(INTENTS).expect("durable count"), 1);
        assert_eq!(
            next_queued_intent_in_queue(&store, IntentQueue::Durable)
                .expect("next durable intent")
                .expect("queued durable intent")
                .intent
                .handler_key,
            b"first".to_vec(),
            "validation errors should not consume the row"
        );
    }

    #[test]
    fn validation_error_rolls_back_handler_owned_sql() {
        let store = Db::open_memory_with_schema_sources(&[CORE_SCHEMA_SOURCE]).expect("open db");
        store
            .conn()
            .execute(
                &format!(
                    "CREATE TABLE {TEST_HANDLER_STATE_TABLE} (
                         intent_key BLOB NOT NULL
                     )"
                ),
                [],
            )
            .expect("create handler state table");
        submit_intent_to_queue(
            &store,
            IntentQueue::Durable,
            test_intent("write_then_invalid", b"first"),
        )
        .expect("submit invalid-output intent");

        let err = dispatch_one_intent(
            &store,
            &HandlerSet::new(WRITE_THEN_INVALID_ROUTES),
            IntentQueue::Durable,
            &[],
            None,
        )
        .expect_err("invalid handler output should roll back direct handler sql");

        assert!(
            err.contains("row mutation table test.rows is not registered"),
            "{err}"
        );
        assert_eq!(
            handler_state_row_count(&store),
            0,
            "handler-owned sql should share the dispatch transaction"
        );
        assert_eq!(
            store.table_row_count(INTENTS).expect("durable count"),
            1,
            "validation errors should not consume the source row"
        );
    }

    #[test]
    fn handler_output_with_unregistered_followup_intent_errors_before_commit() {
        let store = Db::open_memory_with_schema_sources(&[CORE_SCHEMA_SOURCE]).expect("open db");
        submit_intent_to_queue(
            &store,
            IntentQueue::Durable,
            test_intent("emit_unknown", b"first"),
        )
        .expect("submit emitting intent");

        let err = dispatch_one_intent(
            &store,
            &HandlerSet::new(EMIT_UNKNOWN_ROUTES),
            IntentQueue::Durable,
            &[],
            None,
        )
        .expect_err("unregistered follow-up intent should fail validation");

        assert!(
            err.contains("intent kind unknown_followup is not registered"),
            "{err}"
        );
        assert_eq!(
            store.table_row_count(INTENTS).expect("durable count"),
            1,
            "handler output validation errors should not consume the source row"
        );
    }

    #[test]
    fn handler_fact_effects_are_retained_queued_and_drain_continues() {
        AFTER_FACT_CALLS.store(0, Ordering::SeqCst);
        let store = Db::open_memory_with_schema_sources(&[CORE_SCHEMA_SOURCE]).expect("open db");
        let emitted = emitted_fact();
        submit_intent_to_queue(
            &store,
            IntentQueue::Durable,
            test_intent("emit_fact", b"first"),
        )
        .expect("submit emitting intent");
        submit_intent_to_queue(
            &store,
            IntentQueue::Durable,
            test_intent("zz_after_fact", b"second"),
        )
        .expect("submit following intent");

        let dispatched = dispatch_intents_for_test(
            &store,
            &HandlerSet::new(EMIT_FACT_ROUTES),
            IntentQueue::Durable,
            &[],
            None,
            8,
        )
        .expect("dispatch emitting intent");

        assert_eq!(dispatched, 2);
        assert_eq!(
            AFTER_FACT_CALLS.load(Ordering::SeqCst),
            1,
            "intent drains should keep draining the selected queue after queuing projection work"
        );
        assert_eq!(
            load_retained_fact(&store, &emitted.id).expect("load emitted fact"),
            Some(emitted),
            "intent-created fact should be retained immediately"
        );
        assert_eq!(
            store
                .table_row_count(PENDING_PROJECTION)
                .expect("pending projection count"),
            1,
            "intent-created fact should be queued for projection"
        );
        assert_eq!(
            store
                .table_row_count(INCOMING_FACTS)
                .expect("incoming count"),
            0,
            "intent-created facts should not pass through incoming intake"
        );
        assert_eq!(store.table_row_count(INTENTS).expect("durable count"), 0);
    }

    #[test]
    fn intent_context_rows_load_handler_facts_and_commit_with_queue_row() {
        let store = Db::open_memory_with_schema_sources(&[CORE_SCHEMA_SOURCE]).expect("open db");
        let fact = Fact::new(FactScope::Global, 42, b"handler-context".to_vec());
        crate::core::project_fact::submit_fact_with_admission(&store, fact.clone(), None)
            .expect("retain context fact");
        let intent = test_intent("requires_fact", b"context").with_context_fact_ids([fact.id]);
        submit_intent_to_queue(&store, IntentQueue::Durable, intent)
            .expect("submit context intent");

        assert_eq!(
            store
                .table_row_count(INTENT_CONTEXT)
                .expect("intent context count"),
            1
        );

        let dispatched = dispatch_intents_for_test(
            &store,
            &HandlerSet::new(REQUIRE_CONTEXT_ROUTES),
            IntentQueue::Durable,
            &[],
            None,
            1,
        )
        .expect("dispatch context intent");

        assert_eq!(dispatched, 1);
        assert_eq!(store.table_row_count(INTENTS).expect("durable count"), 0);
        assert_eq!(
            store
                .table_row_count(INTENT_CONTEXT)
                .expect("intent context count"),
            0,
            "committing handler output should clear attached context rows"
        );
    }

    #[test]
    fn intent_context_rows_drop_with_queue_row_on_handler_error() {
        let store = Db::open_memory_with_schema_sources(&[CORE_SCHEMA_SOURCE]).expect("open db");
        let fact = Fact::new(FactScope::Global, 42, b"handler-context".to_vec());
        crate::core::project_fact::submit_fact_with_admission(&store, fact.clone(), None)
            .expect("retain context fact");
        let intent = test_intent("fatal", b"context").with_context_fact_ids([fact.id]);
        submit_intent_to_queue(&store, IntentQueue::Durable, intent)
            .expect("submit context intent");

        dispatch_one_intent(
            &store,
            &HandlerSet::new(FATAL_ROUTES),
            IntentQueue::Durable,
            &[],
            None,
        )
        .expect("fatal handler error should drop the invalid row");

        assert_eq!(store.table_row_count(INTENTS).expect("durable count"), 0);
        assert_eq!(
            store
                .table_row_count(INTENT_CONTEXT)
                .expect("intent context count"),
            0,
            "terminal invalid handler work should clear attached context rows"
        );
    }

    #[test]
    fn missing_context_fact_drops_intent_and_context_rows() {
        let store = Db::open_memory_with_schema_sources(&[CORE_SCHEMA_SOURCE]).expect("open db");
        let intent = test_intent("requires_fact", b"context").with_context_fact_ids([[7; 32]]);
        submit_intent_to_queue(&store, IntentQueue::Durable, intent)
            .expect("submit context intent");

        let consumed = dispatch_one_intent(
            &store,
            &HandlerSet::new(REQUIRE_CONTEXT_ROUTES),
            IntentQueue::Durable,
            &[],
            None,
        )
        .expect("missing attached context should drop the stale row");

        assert!(consumed);
        assert_eq!(store.table_row_count(INTENTS).expect("durable count"), 0);
        assert_eq!(
            store
                .table_row_count(INTENT_CONTEXT)
                .expect("intent context count"),
            0
        );
    }

    #[test]
    fn handler_error_rolls_back_handler_owned_sql_before_dropping_row() {
        let store = Db::open_memory_with_schema_sources(&[CORE_SCHEMA_SOURCE]).expect("open db");
        store
            .conn()
            .execute(
                &format!(
                    "CREATE TABLE {TEST_HANDLER_STATE_TABLE} (
                         intent_key BLOB NOT NULL
                     )"
                ),
                [],
            )
            .expect("create handler state table");
        submit_intent_to_queue(
            &store,
            IntentQueue::Durable,
            test_intent("write_then_fatal", b"first"),
        )
        .expect("submit invalid intent");

        let consumed = dispatch_one_intent(
            &store,
            &HandlerSet::new(WRITE_THEN_FATAL_ROUTES),
            IntentQueue::Durable,
            &[],
            None,
        )
        .expect("handler rejection should drop row");

        assert!(consumed);
        assert_eq!(
            handler_state_row_count(&store),
            0,
            "handler-owned sql should roll back before invalid intent deletion commits"
        );
        assert_eq!(store.table_row_count(INTENTS).expect("durable count"), 0);
    }

    #[test]
    fn intent_rows_preserve_repeated_keys_as_distinct_work() {
        let store = Db::open_memory_with_schema_sources(&[CORE_SCHEMA_SOURCE]).expect("open db");
        let intent = test_intent_with_payload("send", b"key", b"one");

        store
            .write_transaction(|tx| {
                insert_intent_in_tx(tx, IntentQueue::Durable, &intent, HandlerMode::Live)
            })
            .expect("insert first intent row");
        store
            .write_transaction(|tx| {
                insert_intent_in_tx(tx, IntentQueue::Durable, &intent, HandlerMode::Live)
            })
            .expect("insert repeated intent row");

        store
            .write_transaction(|tx| {
                insert_intent_in_tx(
                    tx,
                    IntentQueue::Durable,
                    &test_intent_with_payload("send", b"key", b"two"),
                    HandlerMode::Live,
                )
            })
            .expect("insert repeated key with different payload");

        assert_eq!(store.table_row_count(INTENTS).expect("durable count"), 3);
    }

    #[test]
    fn intent_rows_select_durable_by_insertion_order() {
        let store = Db::open_memory_with_schema_sources(&[CORE_SCHEMA_SOURCE]).expect("open db");
        for intent in [
            test_intent_with_payload("z_kind", b"2", b"z"),
            test_intent_with_payload("a_kind", b"2", b"a2"),
            test_intent_with_payload("a_kind", b"1", b"a1"),
        ] {
            store
                .write_transaction(|tx| {
                    insert_intent_in_tx(tx, IntentQueue::Durable, &intent, HandlerMode::Live)
                })
                .expect("insert durable row");
        }

        let selected = next_intent_row(&store, IntentQueue::Durable)
            .expect("select durable row")
            .expect("durable row");

        assert_eq!(selected.kind, "z_kind");
        assert_eq!(selected.intent_key, b"2");
        assert_eq!(selected.payload, b"z");
    }

    #[test]
    fn local_intent_rows_select_by_insertion() {
        let store = Db::open_memory_with_schema_sources(&[CORE_SCHEMA_SOURCE]).expect("open db");
        let first = test_intent_with_payload("work", b"first", b"1");
        let second = test_intent_with_payload("work", b"second", b"2");
        for intent in [&first, &second] {
            store
                .write_transaction(|tx| {
                    insert_intent_in_tx(tx, IntentQueue::Local, intent, HandlerMode::Live)
                })
                .expect("insert local row");
        }

        assert_eq!(
            next_intent_row(&store, IntentQueue::Local)
                .expect("select first local")
                .expect("first local")
                .intent_key,
            b"first"
        );
    }

    fn dispatch_intents_for_test(
        store: &Db,
        handlers: &HandlerSet,
        queue: IntentQueue,
        allowed_tables: &[TableName],
        fact_admission: Option<FactAdmissionFn>,
        limit: usize,
    ) -> Result<usize, String> {
        let mut dispatched = 0;
        for _ in 0..limit {
            let consumed =
                dispatch_one_intent(store, handlers, queue, allowed_tables, fact_admission)?;
            if !consumed {
                break;
            }
            dispatched += 1;
        }
        Ok(dispatched)
    }

    struct NoopHandler;

    const NOOP_ROUTES: &[HandlerRoute] = &[HandlerRoute {
        intent_kind: "handled",
        factory: noop_handler,
        storage_requirement: StorageRequirement::MaintenanceBypass,
        recurrence: None,
    }];

    const FATAL_ROUTES: &[HandlerRoute] = &[HandlerRoute {
        intent_kind: "fatal",
        factory: fatal_handler,
        storage_requirement: StorageRequirement::MaintenanceBypass,
        recurrence: None,
    }];

    const INVALID_OUTPUT_ROUTES: &[HandlerRoute] = &[HandlerRoute {
        intent_kind: "invalid_output",
        factory: invalid_output_handler,
        storage_requirement: StorageRequirement::MaintenanceBypass,
        recurrence: None,
    }];

    const WRITE_THEN_INVALID_ROUTES: &[HandlerRoute] = &[HandlerRoute {
        intent_kind: "write_then_invalid",
        factory: write_then_invalid_handler,
        storage_requirement: StorageRequirement::MaintenanceBypass,
        recurrence: None,
    }];

    const WRITE_THEN_FATAL_ROUTES: &[HandlerRoute] = &[HandlerRoute {
        intent_kind: "write_then_fatal",
        factory: write_then_fatal_handler,
        storage_requirement: StorageRequirement::MaintenanceBypass,
        recurrence: None,
    }];

    const EMIT_FACT_ROUTES: &[HandlerRoute] = &[
        HandlerRoute {
            intent_kind: "emit_fact",
            factory: emit_fact_handler,
            storage_requirement: StorageRequirement::MaintenanceBypass,
            recurrence: None,
        },
        HandlerRoute {
            intent_kind: "zz_after_fact",
            factory: after_fact_handler,
            storage_requirement: StorageRequirement::MaintenanceBypass,
            recurrence: None,
        },
    ];

    const EMIT_UNKNOWN_ROUTES: &[HandlerRoute] = &[HandlerRoute {
        intent_kind: "emit_unknown",
        factory: emit_unknown_handler,
        storage_requirement: StorageRequirement::MaintenanceBypass,
        recurrence: None,
    }];

    const REQUIRE_CONTEXT_ROUTES: &[HandlerRoute] = &[HandlerRoute {
        intent_kind: "requires_fact",
        factory: require_context_fact_handler,
        storage_requirement: StorageRequirement::MaintenanceBypass,
        recurrence: None,
    }];

    const VERSION_GUARD_ROUTES: &[HandlerRoute] = &[HandlerRoute {
        intent_kind: "handled",
        factory: version_guard_handler,
        storage_requirement: StorageRequirement::Current(7),
        recurrence: None,
    }];
    impl IntentHandler for NoopHandler {
        fn handle(&self, _intent: &Intent, _context: &HandlerContext<'_>) -> HandlerResult {
            Ok(RuntimeEffects::new())
        }
    }

    struct VersionGuardHandler;

    impl IntentHandler for VersionGuardHandler {
        fn handle(&self, _intent: &Intent, _context: &HandlerContext<'_>) -> HandlerResult {
            VERSION_GUARD_HANDLER_CALLS.fetch_add(1, Ordering::SeqCst);
            Ok(RuntimeEffects::new())
        }
    }

    struct FatalHandler;

    impl IntentHandler for FatalHandler {
        fn handle(&self, _intent: &Intent, _context: &HandlerContext<'_>) -> HandlerResult {
            Err(HandlerError::fatal("test fatal"))
        }
    }

    struct InvalidOutputHandler;

    impl IntentHandler for InvalidOutputHandler {
        fn handle(&self, _intent: &Intent, _context: &HandlerContext<'_>) -> HandlerResult {
            Ok(
                RuntimeEffects::new().row_mutation(RowMutation::InsertValues(TableInsert {
                    table: TEST_TABLE,
                    columns: &["owner"],
                    values: vec![Value::Bytes(b"row-key".to_vec())],
                })),
            )
        }
    }

    struct WriteThenInvalidHandler;

    impl IntentHandler for WriteThenInvalidHandler {
        fn handle(&self, intent: &Intent, context: &HandlerContext<'_>) -> HandlerResult {
            context
                .db()
                .conn()
                .execute(
                    &format!(
                        "INSERT INTO {TEST_HANDLER_STATE_TABLE} (intent_key)
                         VALUES (?1)"
                    ),
                    params![intent.handler_key.as_slice()],
                )
                .map_err(|err| HandlerError::fatal(format!("write handler state: {err}")))?;
            Ok(
                RuntimeEffects::new().row_mutation(RowMutation::InsertValues(TableInsert {
                    table: TEST_TABLE,
                    columns: &["owner"],
                    values: vec![Value::Bytes(b"row-key".to_vec())],
                })),
            )
        }
    }

    struct WriteThenFatalHandler;

    impl IntentHandler for WriteThenFatalHandler {
        fn handle(&self, intent: &Intent, context: &HandlerContext<'_>) -> HandlerResult {
            context
                .db()
                .conn()
                .execute(
                    &format!(
                        "INSERT INTO {TEST_HANDLER_STATE_TABLE} (intent_key)
                         VALUES (?1)"
                    ),
                    params![intent.handler_key.as_slice()],
                )
                .map_err(|err| HandlerError::fatal(format!("write handler state: {err}")))?;
            Err(HandlerError::fatal("test fatal after write"))
        }
    }

    struct EmitFactHandler;

    impl IntentHandler for EmitFactHandler {
        fn handle(&self, _intent: &Intent, _context: &HandlerContext<'_>) -> HandlerResult {
            Ok(RuntimeEffects::new().fact(emitted_fact()))
        }
    }

    struct EmitUnknownHandler;

    impl IntentHandler for EmitUnknownHandler {
        fn handle(&self, _intent: &Intent, _context: &HandlerContext<'_>) -> HandlerResult {
            Ok(RuntimeEffects::new().intent(test_intent("unknown_followup", b"child")))
        }
    }

    struct RequireContextFactHandler;

    impl IntentHandler for RequireContextFactHandler {
        fn handle(&self, intent: &Intent, context: &HandlerContext<'_>) -> HandlerResult {
            let fact_id = intent
                .context_fact_ids
                .first()
                .ok_or_else(|| HandlerError::fatal("missing test context id"))?;
            let fact = context.require_fact(fact_id)?;
            if fact.bytes != b"handler-context" {
                return Err(HandlerError::fatal("loaded wrong test context fact"));
            }
            Ok(RuntimeEffects::new())
        }
    }

    struct AfterFactHandler;

    impl IntentHandler for AfterFactHandler {
        fn handle(&self, _intent: &Intent, _context: &HandlerContext<'_>) -> HandlerResult {
            AFTER_FACT_CALLS.fetch_add(1, Ordering::SeqCst);
            Ok(RuntimeEffects::new())
        }
    }

    fn noop_handler() -> Box<dyn IntentHandler> {
        Box::new(NoopHandler)
    }

    fn version_guard_handler() -> Box<dyn IntentHandler> {
        Box::new(VersionGuardHandler)
    }

    fn fatal_handler() -> Box<dyn IntentHandler> {
        Box::new(FatalHandler)
    }

    fn invalid_output_handler() -> Box<dyn IntentHandler> {
        Box::new(InvalidOutputHandler)
    }

    fn write_then_invalid_handler() -> Box<dyn IntentHandler> {
        Box::new(WriteThenInvalidHandler)
    }

    fn write_then_fatal_handler() -> Box<dyn IntentHandler> {
        Box::new(WriteThenFatalHandler)
    }

    fn emit_fact_handler() -> Box<dyn IntentHandler> {
        Box::new(EmitFactHandler)
    }

    fn emit_unknown_handler() -> Box<dyn IntentHandler> {
        Box::new(EmitUnknownHandler)
    }

    fn require_context_fact_handler() -> Box<dyn IntentHandler> {
        Box::new(RequireContextFactHandler)
    }

    fn after_fact_handler() -> Box<dyn IntentHandler> {
        Box::new(AfterFactHandler)
    }

    fn test_intent(kind: &'static str, key: &[u8]) -> Intent {
        test_intent_with_payload(kind, key, &[1])
    }

    fn test_intent_with_payload(kind: &'static str, key: &[u8], payload: &[u8]) -> Intent {
        Intent::new(
            IntentKind::new(kind).expect("valid test kind"),
            key.to_vec(),
            payload.to_vec(),
        )
    }

    fn emitted_fact() -> Fact {
        Fact::new(FactScope::Global, 42, b"handler-emitted-fact".to_vec())
    }

    fn handler_state_row_count(store: &Db) -> usize {
        store
            .conn()
            .query_row(
                &format!("SELECT COUNT(*) FROM {TEST_HANDLER_STATE_TABLE}"),
                [],
                |row| row.get::<_, i64>(0),
            )
            .expect("handler state count") as usize
    }

    #[test]
    fn intent_storage_mismatch_consumes_without_running_handler() {
        VERSION_GUARD_HANDLER_CALLS.store(0, Ordering::SeqCst);
        let store = Db::open_memory_with_schema_sources(&[CORE_SCHEMA_SOURCE]).expect("open db");
        submit_intent_to_queue(
            &store,
            IntentQueue::Durable,
            test_intent("handled", b"guarded"),
        )
        .expect("submit guarded intent");

        let consumed = dispatch_one_intent(
            &store,
            &HandlerSet::new(VERSION_GUARD_ROUTES),
            IntentQueue::Durable,
            &[],
            None,
        )
        .expect("storage mismatch should consume stale-version intent");

        assert!(consumed);
        assert_eq!(VERSION_GUARD_HANDLER_CALLS.load(Ordering::SeqCst), 0);
        assert_eq!(
            store.table_row_count(INTENTS).expect("durable count"),
            0,
            "stale-version intent should be consumed without running handler effects"
        );
    }
}
