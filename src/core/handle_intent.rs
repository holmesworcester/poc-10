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
//! Runtime admission rejects intent kinds that are not in the handler registry;
//! if a stale unregistered row is already present, dispatch reports an invariant
//! error and leaves the row untouched. Durable and local rows are both selected
//! by SQLite insertion order so projection, replay, and live IO all preserve the
//! order in which work was queued.
//!
//! A handler declares exact fact inputs. Dispatch loads those inputs by joining
//! durable `facts` bytes with `local_fact_admissions` metadata and places them
//! in `HandlerContext`; handlers that require an input call
//! `HandlerContext::require_fact`.
//!
//! This transaction boundary is why dispatch matters. Handler-owned SQL and
//! returned runtime effects become visible exactly when the input queue row is
//! consumed: no output without deleting the work item, and no deletion without
//! committing the output. That delete, the handler's direct SQL, and every
//! `RuntimeEffects` write happen inside one SQLite transaction. If the
//! transaction rolls back, the queued row is still there; if it commits, the row
//! is gone and the output is durable. Queue rows do not collapse by `(kind,
//! key)`; protocols that need backpressure express it in their own facts, row
//! mutations, network queues, or handler-local state.

use crate::core::db::{quoted_table_name, Db, TableName};
use crate::core::effects::{RuntimeEffects, StorageRequirement};
use crate::core::facts::{fact_from_storage_row, Fact, FactId};
use crate::core::intents::{HandlerContext, HandlerMode, Intent, IntentHandler, IntentWorkRow};
use crate::core::schema::{INTENTS, LOCAL_INTENTS};

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

struct IntentInput<'a> {
    queued: QueuedIntent,
    handler: &'a dyn IntentHandler,
    storage_requirement: StorageRequirement,
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
/// 1. Load one queued intent and its registered handler route.
/// 2. Delete that exact row, run the handler, and validate returned effects
///    inside one transaction.
/// 3. Commit handler-owned SQL and validated effects together.
///
/// Handlers are allowed to observe runtime state, so this is not a
/// pure-evaluation boundary like projection. The queue lifecycle is still
/// centralized: the queue row is removed only by the same commit boundary that
/// publishes the handler's SQL writes and returned effects.
pub(crate) fn dispatch_one_intent(
    store: &Db,
    handlers: &HandlerSet,
    queue: IntentQueue,
    allowed_tables: &[TableName],
    fact_admission: Option<FactAdmissionFn>,
) -> Result<bool, String> {
    let input = match load_one_intent_input(store, handlers, queue)? {
        None => return Ok(false),
        Some(input) => input,
    };
    run_and_commit_loaded_intent(
        store,
        input,
        allowed_tables,
        handlers.intent_kinds(),
        fact_admission,
    )
}

// =============================================================================
// Stages
// =============================================================================

/// Stage 1: load one queued intent and its registered handler.
///
/// Durable and local rows use insertion order. Replay re-emits work in the
/// order projectors recorded it instead of sorting by handler-owned keys.
fn load_one_intent_input<'a>(
    store: &'a Db,
    handlers: &'a HandlerSet,
    queue: IntentQueue,
) -> Result<Option<IntentInput<'a>>, String> {
    let Some(queued) = next_queued_intent_in_queue(store, queue)? else {
        return Ok(None);
    };
    let entry = handlers.handler_for_intent(&queued.intent)?;
    Ok(Some(IntentInput {
        queued,
        handler: entry.handler.as_ref(),
        storage_requirement: entry.storage_requirement,
    }))
}

/// Stage 2/3: run the handler and commit its terminal outcome.
///
/// Handler reads and handler-owned SQL writes run inside the same transaction
/// that consumes the queued row and commits returned runtime effects.
///
/// If the handled row is already gone, nothing commits and the returned value
/// is `false`.
fn run_and_commit_loaded_intent(
    store: &Db,
    input: IntentInput<'_>,
    allowed_tables: &[TableName],
    registered_intent_kinds: &[&str],
    fact_admission: Option<FactAdmissionFn>,
) -> Result<bool, String> {
    let IntentInput {
        queued,
        handler,
        storage_requirement,
    } = input;
    store
        .write_transaction(|tx| {
            enforce_handler_storage_requirement(tx, storage_requirement)
                .map_err(sqlite_string_error)?;
            if delete_intent_work_row_in_tx(tx, queued.queue.table(), &queued.intent_id)? == 0 {
                return Ok(false);
            }
            let context = load_handler_context(tx, handler, &queued.intent, queued.mode)
                .map_err(sqlite_string_error)?;
            let effects = run_loaded_intent(
                handler,
                &queued.intent,
                context,
                storage_requirement,
                allowed_tables,
                registered_intent_kinds,
                fact_admission,
            )
            .map_err(sqlite_string_error)?;
            commit_runtime_effects_in_tx(
                tx,
                &effects,
                allowed_tables,
                registered_intent_kinds,
                fact_admission,
                queued.mode.is_replay(),
                false,
            )?;
            Ok(true)
        })
        .map_err(|err| format!("commit handler output: {err}"))
}

/// Run one claimed intent through its handler and normalize its uncommitted
/// runtime effects.
///
/// The handler may use transaction-local SQL through the database handle in its
/// context. Returned runtime effects are still validated before the transaction
/// commits.
fn run_loaded_intent(
    handler: &dyn IntentHandler,
    intent: &Intent,
    context: HandlerContext<'_>,
    storage_requirement: StorageRequirement,
    allowed_tables: &[TableName],
    registered_intent_kinds: &[&str],
    fact_admission: Option<FactAdmissionFn>,
) -> Result<RuntimeEffects, String> {
    match handler.handle(intent, &context) {
        Ok(effects) => {
            let effects = effects.with_storage_requirement(storage_requirement);
            validate_runtime_effects_for_admission(
                &effects,
                allowed_tables,
                registered_intent_kinds,
                fact_admission,
            )?;
            Ok(effects)
        }
        Err(err) => Err(err.to_string()),
    }
}

fn enforce_handler_storage_requirement(
    tx: &Db,
    requirement: StorageRequirement,
) -> Result<(), String> {
    match requirement {
        StorageRequirement::MaintenanceBypass => Ok(()),
        StorageRequirement::Current(version) => tx.require_storage_version(version),
    }
}

// =============================================================================
// Load Stage Helpers
// =============================================================================

/// Return the first queued intent in queue order.
fn next_queued_intent_in_queue(
    store: &Db,
    queue: IntentQueue,
) -> Result<Option<QueuedIntent>, String> {
    next_intent_work_row(store, queue.table(), queue.order_by_sql())
        .map_err(|err| format!("load queued intent: {err}"))?
        .map(|row| {
            let QueuedIntentWorkRow { intent_id, work } = row;
            let mode = work.mode;
            Intent::from_work_row(work).map(|intent| QueuedIntent {
                intent_id,
                queue,
                intent,
                mode,
            })
        })
        .transpose()
}

/// Build the transaction-local fact/database view a stored-intent handler
/// requested.
fn load_handler_context<'a>(
    store: &'a Db,
    handler: &(impl IntentHandler + ?Sized),
    intent: &Intent,
    mode: HandlerMode,
) -> Result<HandlerContext<'a>, String> {
    let mut facts = Vec::new();
    for id in handler.input_fact_ids(intent)? {
        if let Some(fact) = load_retained_fact(store, &id)? {
            facts.push(fact);
        }
    }
    let context = HandlerContext::with_facts(facts).with_mode(mode);
    Ok(context.with_db(store))
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
    /// Wall-clock time captured by the live daemon tick that fired this intent.
    pub now_ms: u64,
    /// Current process listen address, when this recurring run came from a daemon.
    pub local_addr: Option<SocketAddr>,
}

/// In-memory schedule for a live-only recurring operational intent.
///
/// Recurring intents are not durable state. The daemon installs these schedules
/// at startup, after replay has finished, and fires them on a fixed cadence
/// while the process runs. There is nothing to wipe on upgrade and nothing to
/// replay: operational repetition belongs here, not in durable time wakes or
/// projectors.
#[derive(Debug, Clone, Copy)]
pub struct RecurringIntentSpec {
    /// Cadence between successive fires once the loop is running.
    pub interval_ms: u64,
    /// Delay from daemon startup before the first fire.
    pub initial_delay_ms: u64,
    /// Build this tick's intent from current database state, or `None` to skip.
    pub build_intent: RecurringIntentBuilder,
}

/// One handler route in the protocol registry.
///
/// `intent_kind` is the queue routing key that selects this handler for both
/// durable and ephemeral intents.
/// `recurrence` marks live-only operational repetition. A route with a
/// recurrence is installed as an in-memory daemon schedule.
#[derive(Debug, Clone, Copy)]
pub struct HandlerRoute {
    /// Intent kind handled by this route.
    pub intent_kind: &'static str,
    /// Handler factory.
    pub factory: HandlerFactory,
    /// Storage version required by this handler's committed effects.
    pub storage_requirement: StorageRequirement,
    /// Live-only recurring schedule installed by the daemon, if any.
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

    fn handler_for_intent(&self, intent: &Intent) -> Result<&HandlerEntry, String> {
        let kind = intent.kind.as_str();
        self.handler_for_kind(kind)
            .ok_or_else(|| format!("no handler registered for intent kind {kind}"))
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

    fn order_by_sql(self) -> &'static str {
        "rowid"
    }
}

// =============================================================================
// Queue SQL Helpers
// =============================================================================

fn intent_queue_error(message: impl Into<String>) -> rusqlite::Error {
    rusqlite::Error::InvalidParameterName(message.into())
}

fn quoted_intent_work_table_name(table: TableName) -> rusqlite::Result<String> {
    if table == INTENTS || table == LOCAL_INTENTS {
        quoted_table_name(table)
    } else {
        Err(intent_queue_error(format!(
            "table {} is not an intent work table",
            table.as_str()
        )))
    }
}

/// Insert one raw intent work row inside the caller's transaction.
pub(crate) fn insert_intent_work_row_in_tx(
    db: &Db,
    table: TableName,
    row: &IntentWorkRow,
) -> rusqlite::Result<()> {
    let table_name = quoted_intent_work_table_name(table)?;
    for _ in 0..8 {
        let intent_id = random_intent_id();
        let changed = db.conn().execute(
            &format!(
                "INSERT OR IGNORE INTO {table_name} (intent_id, kind, intent_key, payload, replay)
                 VALUES (?1, ?2, ?3, ?4, ?5)"
            ),
            params![
                intent_id.as_slice(),
                row.kind.as_str(),
                row.intent_key.as_slice(),
                row.payload.as_slice(),
                replay_flag_for_handler_mode(row.mode)
            ],
        )?;
        if changed == 1 {
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

fn replay_flag_for_handler_mode(mode: HandlerMode) -> i64 {
    if mode.is_replay() {
        1
    } else {
        0
    }
}

/// Delete one raw intent work row by its queue row id.
fn delete_intent_work_row_in_tx(
    db: &Db,
    table: TableName,
    intent_id: &[u8],
) -> rusqlite::Result<usize> {
    let table_name = quoted_intent_work_table_name(table)?;
    db.conn().execute(
        &format!("DELETE FROM {table_name} WHERE intent_id = ?1"),
        params![intent_id],
    )
}

/// Select the next raw intent work row in queue order.
fn next_intent_work_row(
    db: &Db,
    table: TableName,
    order_by_sql: &str,
) -> rusqlite::Result<Option<QueuedIntentWorkRow>> {
    let table_name = quoted_intent_work_table_name(table)?;
    db.conn()
        .query_row(
            &format!(
                "SELECT intent_id, kind, intent_key, payload, replay
                 FROM {table_name}
                 ORDER BY {order_by_sql}
                 LIMIT 1"
            ),
            [],
            |row| {
                Ok(QueuedIntentWorkRow {
                    intent_id: row.get(0)?,
                    work: IntentWorkRow {
                        kind: row.get(1)?,
                        intent_key: row.get(2)?,
                        payload: row.get(3)?,
                        mode: handler_mode_from_replay_flag(row.get(4)?),
                    },
                })
            },
        )
        .optional()
}

struct QueuedIntentWorkRow {
    intent_id: Vec<u8>,
    work: IntentWorkRow,
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
    submit_intent_to_table(store, LOCAL_INTENTS, intent)
}

/// Insert one intent into the selected queue.
///
/// Every insert records a distinct queued work item. Repeated semantic work
/// must be collapsed by the handler's own facts, row writes, network queue, or
/// in-memory state when that protocol needs backpressure.
pub(crate) fn submit_intent_to_table(
    store: &Db,
    table: TableName,
    intent: Intent,
) -> Result<(), String> {
    store
        .write_transaction(|tx| insert_intent_work_row_in_tx(tx, table, &intent.work_row()))
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
    use crate::core::schema::{CORE_SCHEMA_SOURCE, INCOMING_FACTS, PENDING_PROJECTION};
    use std::sync::atomic::{AtomicUsize, Ordering};

    const TEST_TABLE: TableName = TableName::new("test.rows");
    const TEST_HANDLER_STATE_TABLE: &str = "\"test.handler_state\"";

    static AFTER_FACT_CALLS: AtomicUsize = AtomicUsize::new(0);

    #[test]
    fn durable_success_deletes_only_claimed_row() {
        let store = Db::open_memory_with_schema_sources(&[CORE_SCHEMA_SOURCE]).expect("open db");
        let intent = test_intent("handled", b"same-key");

        submit_intent_to_table(&store, LOCAL_INTENTS, intent.clone()).expect("submit local");
        submit_intent_to_table(&store, INTENTS, intent).expect("submit durable");

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
        submit_intent_to_table(&store, LOCAL_INTENTS, first.clone()).expect("submit first local");
        submit_intent_to_table(&store, LOCAL_INTENTS, second).expect("submit second local");

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
    fn fatal_handler_error_leaves_row_queued() {
        let store = Db::open_memory_with_schema_sources(&[CORE_SCHEMA_SOURCE]).expect("open db");
        submit_intent_to_table(&store, INTENTS, test_intent("fatal", b"first"))
            .expect("submit fatal intent");

        let err = dispatch_one_intent(
            &store,
            &HandlerSet::new(FATAL_ROUTES),
            IntentQueue::Durable,
            &[],
            None,
        )
        .expect_err("fatal handler error should escape dispatch");

        assert!(err.contains("test fatal"), "{err}");
        assert_eq!(store.table_row_count(INTENTS).expect("durable count"), 1);
        assert_eq!(
            next_queued_intent_in_queue(&store, IntentQueue::Durable)
                .expect("next durable intent")
                .expect("queued durable intent")
                .intent
                .key,
            b"first".to_vec(),
            "fatal errors should not consume the row"
        );
    }

    #[test]
    fn unregistered_queued_intent_errors_without_consuming_row() {
        let store = Db::open_memory_with_schema_sources(&[CORE_SCHEMA_SOURCE]).expect("open db");
        submit_intent_to_table(&store, INTENTS, test_intent("unregistered", b"first"))
            .expect("submit unregistered intent row");

        let err = dispatch_one_intent(
            &store,
            &HandlerSet::new(NOOP_ROUTES),
            IntentQueue::Durable,
            &[],
            None,
        )
        .expect_err("unregistered queued intent should be an invariant error");

        assert!(
            err.contains("no handler registered for intent kind unregistered"),
            "{err}"
        );
        assert_eq!(store.table_row_count(INTENTS).expect("durable count"), 1);
    }

    #[test]
    fn validation_error_leaves_row_queued_without_committing_effects() {
        let store = Db::open_memory_with_schema_sources(&[CORE_SCHEMA_SOURCE]).expect("open db");
        submit_intent_to_table(&store, INTENTS, test_intent("invalid_output", b"first"))
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
                .key,
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
        submit_intent_to_table(&store, INTENTS, test_intent("write_then_invalid", b"first"))
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
        submit_intent_to_table(&store, INTENTS, test_intent("emit_unknown", b"first"))
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
        submit_intent_to_table(&store, INTENTS, test_intent("emit_fact", b"first"))
            .expect("submit emitting intent");
        submit_intent_to_table(&store, INTENTS, test_intent("zz_after_fact", b"second"))
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
    fn intent_work_rows_preserve_repeated_keys_as_distinct_work() {
        let store = Db::open_memory_with_schema_sources(&[CORE_SCHEMA_SOURCE]).expect("open db");
        let row = IntentWorkRow::new("send", b"key".to_vec(), b"one".to_vec());

        store
            .write_transaction(|tx| insert_intent_work_row_in_tx(tx, INTENTS, &row))
            .expect("insert first intent row");
        store
            .write_transaction(|tx| insert_intent_work_row_in_tx(tx, INTENTS, &row))
            .expect("insert repeated intent row");

        store
            .write_transaction(|tx| {
                insert_intent_work_row_in_tx(
                    tx,
                    INTENTS,
                    &IntentWorkRow::new("send", b"key".to_vec(), b"two".to_vec()),
                )
            })
            .expect("insert repeated key with different payload");

        assert_eq!(store.table_row_count(INTENTS).expect("durable count"), 3);
    }

    #[test]
    fn intent_work_rows_select_durable_by_insertion_order() {
        let store = Db::open_memory_with_schema_sources(&[CORE_SCHEMA_SOURCE]).expect("open db");
        for row in [
            IntentWorkRow::new("z_kind", b"2".to_vec(), b"z".to_vec()),
            IntentWorkRow::new("a_kind", b"2".to_vec(), b"a2".to_vec()),
            IntentWorkRow::new("a_kind", b"1".to_vec(), b"a1".to_vec()),
        ] {
            store
                .write_transaction(|tx| insert_intent_work_row_in_tx(tx, INTENTS, &row))
                .expect("insert durable row");
        }

        let selected = next_intent_work_row(&store, INTENTS, "rowid")
            .expect("select durable row")
            .expect("durable row");

        assert_eq!(selected.work.kind, "z_kind");
        assert_eq!(selected.work.intent_key, b"2");
        assert_eq!(selected.work.payload, b"z");
    }

    #[test]
    fn local_intent_work_rows_select_by_insertion() {
        let store = Db::open_memory_with_schema_sources(&[CORE_SCHEMA_SOURCE]).expect("open db");
        let first = IntentWorkRow::new("work", b"first".to_vec(), b"1".to_vec());
        let second = IntentWorkRow::new("work", b"second".to_vec(), b"2".to_vec());
        for row in [&first, &second] {
            store
                .write_transaction(|tx| insert_intent_work_row_in_tx(tx, LOCAL_INTENTS, row))
                .expect("insert local row");
        }

        assert_eq!(
            next_intent_work_row(&store, LOCAL_INTENTS, "rowid",)
                .expect("select first local")
                .expect("first local")
                .work
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

    const VERSION_GUARD_ROUTES: &[HandlerRoute] = &[HandlerRoute {
        intent_kind: "handled",
        factory: noop_handler,
        storage_requirement: StorageRequirement::Current(7),
        recurrence: None,
    }];
    impl IntentHandler for NoopHandler {
        fn handle(&self, _intent: &Intent, _context: &HandlerContext<'_>) -> HandlerResult {
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
                .db()?
                .conn()
                .execute(
                    &format!(
                        "INSERT INTO {TEST_HANDLER_STATE_TABLE} (intent_key)
                         VALUES (?1)"
                    ),
                    params![intent.key.as_slice()],
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

    fn fatal_handler() -> Box<dyn IntentHandler> {
        Box::new(FatalHandler)
    }

    fn invalid_output_handler() -> Box<dyn IntentHandler> {
        Box::new(InvalidOutputHandler)
    }

    fn write_then_invalid_handler() -> Box<dyn IntentHandler> {
        Box::new(WriteThenInvalidHandler)
    }

    fn emit_fact_handler() -> Box<dyn IntentHandler> {
        Box::new(EmitFactHandler)
    }

    fn emit_unknown_handler() -> Box<dyn IntentHandler> {
        Box::new(EmitUnknownHandler)
    }

    fn after_fact_handler() -> Box<dyn IntentHandler> {
        Box::new(AfterFactHandler)
    }

    fn test_intent(kind: &'static str, key: &[u8]) -> Intent {
        Intent::new(
            IntentKind::new(kind).expect("valid test kind"),
            key.to_vec(),
            vec![1],
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
    fn intent_storage_mismatch_rolls_back_queue_consumption() {
        let store = Db::open_memory_with_schema_sources(&[CORE_SCHEMA_SOURCE]).expect("open db");
        submit_intent_to_table(&store, INTENTS, test_intent("handled", b"guarded"))
            .expect("submit guarded intent");

        let err = dispatch_one_intent(
            &store,
            &HandlerSet::new(VERSION_GUARD_ROUTES),
            IntentQueue::Durable,
            &[],
            None,
        )
        .expect_err("storage mismatch should abort intent commit");

        assert!(
            err.contains("required_version=7 stored_version=missing"),
            "{err}"
        );
        assert_eq!(
            store.table_row_count(INTENTS).expect("durable count"),
            1,
            "failed storage guard must not consume the handled intent"
        );
    }
}
