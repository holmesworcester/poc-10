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
use crate::core::intents::{HandlerContext, HandlerError, Intent, IntentHandler, IntentKind};
use crate::core::schema::{INTENTS, LOCAL_INTENTS};
use crate::core::store::persisted_fact;
use crate::core::store::{Store, TableName};
use rusqlite::{params, params_from_iter, OptionalExtension};

use crate::core::project_fact::commit_effects::{
    commit_pipeline_effects_in_tx, suppress_disallowed_intents,
    validate_pipeline_effects_for_admission, IntentAdmissionPolicy,
};
use crate::core::project_fact::route::FactAdmissionFn;
use std::collections::BTreeSet;
use std::net::SocketAddr;

/// Factory for one protocol intent handler.
pub type HandlerFactory = fn() -> Box<dyn IntentHandler>;

/// Build the current intent for a recurring operational loop.
///
/// The daemon calls this while the process is online to mint one tick of live
/// work. Returning `Ok(None)` means there is nothing to do this tick. The
/// builder reads the store the same way a handler reads its inputs; it must not
/// depend on persisted scheduler rows, because recurring schedules are
/// in-memory only and never replayed.
pub type RecurringIntentBuilder =
    fn(&Store, RecurringIntentContext) -> Result<Option<Intent>, String>;

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
    /// Build this tick's intent from current store state, or `None` to skip.
    pub build_intent: RecurringIntentBuilder,
}

/// One handler route in the protocol registry.
///
/// `name` is a human-facing route name used for exclusion lists. `intent_kind`
/// is the queue routing key that selects this handler for both durable and
/// ephemeral intents.
///
/// `runs_during_replay` answers one question: if this intent is emitted while
/// replay is rebuilding facts and rows, may core record and dispatch it before
/// the replay barrier finishes? Replay-enabled handlers must be deterministic
/// rebuild work over retained facts: no network IO, no fresh randomness, no
/// process-global mutable state, and no operational wall-clock decisions. Every
/// route declares this flag explicitly so adding a route forces a conscious
/// replay decision.
///
/// `recurrence` marks live-only operational repetition. A route with a
/// recurrence is installed as an in-memory daemon schedule and must not run
/// during replay.
#[derive(Debug, Clone, Copy)]
pub struct HandlerRoute {
    /// Human-facing route name used for exclusion lists.
    pub name: &'static str,
    /// Intent kind handled by this route.
    pub intent_kind: &'static str,
    /// Handler factory.
    pub factory: HandlerFactory,
    /// Whether core may dispatch this intent before the replay barrier finishes.
    pub runs_during_replay: bool,
    /// Live-only recurring schedule installed by the daemon, if any.
    pub recurrence: Option<RecurringIntentSpec>,
}

/// Outcome returned by bounded runtime work calls.
///
/// Runtime callers only need to know whether a bounded pass moved work forward
/// and whether any handler asked to retry.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct WorkStatus {
    /// Whether a bounded pass committed or staged any work.
    pub progressed: bool,
    /// Whether a handler asked to leave work queued for a later pass.
    pub retried: bool,
}

impl WorkStatus {
    /// No progress and no retry.
    pub fn idle() -> Self {
        Self::default()
    }

    /// Build status from a simple progressed flag.
    pub fn progressed(progressed: bool) -> Self {
        Self {
            progressed,
            retried: false,
        }
    }

    /// Accumulate status across runtime stages.
    pub fn merge(&mut self, other: Self) {
        self.progressed |= other.progressed;
        self.retried |= other.retried;
    }

    /// Return whether the pass did nothing and hit no retry.
    pub fn is_idle(self) -> bool {
        !self.progressed && !self.retried
    }
}

/// Instantiated handlers for one runtime pass.
///
/// The set owns concrete handler values so dispatch can borrow trait objects
/// without rebuilding them for every queued row. Command processing builds a
/// filtered set to avoid daemon/network side effects; replay builds a filtered
/// set that contains only replay-allowed routes.
pub(crate) struct HandlerSet {
    entries: Vec<HandlerEntry>,
}

struct HandlerEntry {
    intent_kind: &'static str,
    handler: Box<dyn IntentHandler>,
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
                })
                .collect(),
        }
    }

    /// Instantiate every route except the protocol-declared command exclusions.
    pub(crate) fn new_excluding(routes: &'static [HandlerRoute], excluded_names: &[&str]) -> Self {
        Self {
            entries: routes
                .iter()
                .filter(|route| !excluded_names.contains(&route.name))
                .map(|route| HandlerEntry {
                    intent_kind: route.intent_kind,
                    handler: (route.factory)(),
                })
                .collect(),
        }
    }

    /// Instantiate only routes allowed to run before the replay barrier.
    pub(crate) fn new_replay(routes: &'static [HandlerRoute]) -> Self {
        Self {
            entries: routes
                .iter()
                .filter(|route| route.runs_during_replay)
                .map(|route| HandlerEntry {
                    intent_kind: route.intent_kind,
                    handler: (route.factory)(),
                })
                .collect(),
        }
    }

    pub(crate) fn intent_kinds(&self) -> Vec<&'static str> {
        self.entries.iter().map(|entry| entry.intent_kind).collect()
    }

    fn handler_for_kind(&self, kind: &str) -> Option<&dyn IntentHandler> {
        self.entries
            .iter()
            .find(|entry| entry.intent_kind == kind)
            .map(|entry| entry.handler.as_ref())
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct IntentDispatchProgress {
    pub(crate) status: WorkStatus,
    pub(crate) dispatched: usize,
    pub(crate) suppressed_intents: usize,
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
pub(crate) fn submit_intent_to_table(
    store: &Store,
    table: TableName,
    intent: Intent,
) -> Result<bool, String> {
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
/// On success, the handled row and all effects admitted by the intent policy
/// commit together. On retry, no SQL changes are made and the returned status
/// records that dispatch should stop this bounded pass.
pub(crate) fn dispatch_queued_intent_with_policy(
    handler: &(impl IntentHandler + ?Sized),
    store: &Store,
    allowed_tables: &[TableName],
    fact_admission: Option<FactAdmissionFn>,
    queued: QueuedIntent,
    intent_policy: IntentAdmissionPolicy<'_>,
) -> Result<IntentDispatchReport, String> {
    let mut status = WorkStatus::idle();
    let context = load_handler_context(store, handler, &queued.intent)?;
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
    validate_pipeline_effects_for_admission(&output, allowed_tables, fact_admission)?;
    status.progressed = commit_handler_output(
        store,
        queued.table,
        queued.intent.kind.as_str(),
        &queued.intent.key,
        &output,
        allowed_tables,
        fact_admission,
        intent_policy.pending_projection_mode(),
    )?;
    if !status.progressed {
        suppressed_intents = 0;
    }
    Ok(IntentDispatchReport {
        status,
        suppressed_intents,
    })
}

/// Dispatch queued intents with the provided handler set.
///
/// The policy decides which follow-up intents emitted by handlers may be
/// recorded; inadmissible ones are suppressed and counted.
pub(crate) fn dispatch_intents(
    store: &Store,
    handlers: &HandlerSet,
    allowed_tables: &[TableName],
    fact_admission: Option<FactAdmissionFn>,
    limit: usize,
    policy: IntentAdmissionPolicy<'_>,
) -> Result<IntentDispatchProgress, String> {
    let mut progress = IntentDispatchProgress::default();
    let kinds = handlers.intent_kinds();
    let mut retried_local = BTreeSet::<(String, Vec<u8>)>::new();
    for _ in 0..limit {
        let Some(queued) = next_queued_intent(store, &kinds)? else {
            break;
        };
        let kind = queued.intent.kind.as_str();
        let local_retry_key = if queued.table == LOCAL_INTENTS {
            Some((kind.to_owned(), queued.intent.key.clone()))
        } else {
            None
        };
        if local_retry_key
            .as_ref()
            .is_some_and(|key| retried_local.contains(key))
        {
            break;
        }
        let handler = handlers
            .handler_for_kind(kind)
            .ok_or_else(|| format!("no handler registered for intent kind {kind}"))?;
        let report = dispatch_queued_intent_with_policy(
            handler,
            store,
            allowed_tables,
            fact_admission,
            queued,
            policy,
        )?;
        progress.status.merge(report.status);
        progress.suppressed_intents += report.suppressed_intents;
        if report.status.progressed {
            progress.dispatched += 1;
        }
        if report.status.retried {
            if let Some(key) = local_retry_key {
                retried_local.insert(key);
                continue;
            }
            break;
        }
    }
    Ok(progress)
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
    table: TableName,
    kind: &str,
    idempotence_key: &[u8],
    effects: &PipelineEffects,
    allowed_tables: &[TableName],
    fact_admission: Option<FactAdmissionFn>,
    pending_mode: crate::core::project_fact::ProjectionMode,
) -> Result<bool, String> {
    store
        .write_transaction(|tx| {
            if delete_intent_in_tx(tx, table, kind, idempotence_key)? == 0 {
                return Ok(false);
            }
            if table == INTENTS {
                delete_intent_in_tx(tx, LOCAL_INTENTS, kind, idempotence_key)?;
            }

            commit_pipeline_effects_in_tx(
                tx,
                effects,
                allowed_tables,
                fact_admission,
                pending_mode,
            )?;
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

/// Record an intent row in either queue inside the caller's transaction.
pub(crate) fn record_intent_in_table_in_tx(
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
