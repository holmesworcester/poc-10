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
//! handled row, then delegates the handler's `RuntimeEffects` to
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

use crate::core::effects::RuntimeEffects;
use crate::core::intents::{HandlerContext, HandlerError, HandlerMode, Intent, IntentHandler};
use crate::core::schema::{INTENTS, LOCAL_INTENTS};
use crate::core::store::persisted_fact;
use crate::core::store::{IntentWorkRowOrder, Store, TableName};

use crate::core::project_fact::commit_effects::{
    commit_runtime_effects_in_tx, validate_runtime_effects_for_admission, RuntimeEffectMode,
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
/// without rebuilding them for every queued row.
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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IntentQueue {
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

    fn order(self) -> IntentWorkRowOrder {
        match self {
            Self::Durable => IntentWorkRowOrder::StableIdentity,
            Self::Local => IntentWorkRowOrder::Insertion,
        }
    }
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
        .write_transaction(|tx| tx.insert_intent_work_row_in_tx(table, &intent.work_row()))
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
    match next_queued_intent_in_queue(store, IntentQueue::Durable, allowed_kinds)? {
        Some(intent) => Ok(Some(intent)),
        None => next_queued_intent_in_queue(store, IntentQueue::Local, allowed_kinds),
    }
}

struct IntentWork<'a> {
    queued: QueuedIntent,
    handler: &'a dyn IntentHandler,
}

/// Run one claimed intent through its handler.
///
/// On success, the handled row and all effects admitted by the intent policy
/// commit together. On retry, no SQL changes are made and the returned status
/// records that dispatch should stop this bounded pass.
fn handle_intent_with_policy(
    work: IntentWork<'_>,
    store: &Store,
    allowed_tables: &[TableName],
    fact_admission: Option<FactAdmissionFn>,
    handler_mode: HandlerMode,
    effect_mode: RuntimeEffectMode,
) -> Result<IntentDispatchReport, String> {
    let IntentWork { queued, handler } = work;
    let mut status = WorkStatus::idle();
    let context = load_handler_context(store, handler, &queued.intent, handler_mode)?;
    let Some(output) = run_handler(handler, &queued.intent, &context, &mut status)? else {
        if status.retried && queued.queue == IntentQueue::Local {
            rotate_local_retry_to_tail(store, &queued.intent)?;
        }
        return Ok(IntentDispatchReport {
            status,
            emitted_projectable_facts: false,
        });
    };
    validate_runtime_effects_for_admission(&output, allowed_tables, fact_admission)?;
    let emitted_projectable_facts = !output.facts.is_empty() || !output.incoming_facts.is_empty();
    status.progressed = commit_handler_output(
        store,
        &queued,
        &output,
        allowed_tables,
        fact_admission,
        effect_mode.pending_projection_mode(),
    )?;
    Ok(IntentDispatchReport {
        emitted_projectable_facts: status.progressed && emitted_projectable_facts,
        status,
    })
}

/// Dispatch queued intents with the provided handler set.
pub(crate) fn dispatch_intents(
    store: &Store,
    handlers: &HandlerSet,
    allowed_tables: &[TableName],
    fact_admission: Option<FactAdmissionFn>,
    limit: usize,
    handler_mode: HandlerMode,
    effect_mode: RuntimeEffectMode,
) -> Result<IntentDispatchProgress, String> {
    let mut progress = IntentDispatchProgress::default();
    let kinds = handlers.intent_kinds();
    let mut retried_local = BTreeSet::<(String, Vec<u8>)>::new();
    for _ in 0..limit {
        let Some(work) = next_intent_work(store, handlers, &kinds)? else {
            break;
        };
        let kind = work.queued.intent.kind.as_str();
        let local_retry_key = if work.queued.queue == IntentQueue::Local {
            Some((kind.to_owned(), work.queued.intent.key.clone()))
        } else {
            None
        };
        if local_retry_key
            .as_ref()
            .is_some_and(|key| retried_local.contains(key))
        {
            break;
        }
        let report = handle_intent_with_policy(
            work,
            store,
            allowed_tables,
            fact_admission,
            handler_mode,
            effect_mode,
        )?;
        progress.status.merge(report.status);
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
        if report.emitted_projectable_facts {
            break;
        }
    }
    Ok(progress)
}

fn next_intent_work<'a>(
    store: &Store,
    handlers: &'a HandlerSet,
    kinds: &[&str],
) -> Result<Option<IntentWork<'a>>, String> {
    let Some(queued) = next_queued_intent(store, kinds)? else {
        return Ok(None);
    };
    let kind = queued.intent.kind.as_str();
    let handler = handlers
        .handler_for_kind(kind)
        .ok_or_else(|| format!("no handler registered for intent kind {kind}"))?;
    Ok(Some(IntentWork { queued, handler }))
}

/// Return the first queued intent matching a declared handler route.
fn next_queued_intent_in_queue(
    store: &Store,
    queue: IntentQueue,
    allowed_kinds: &[&str],
) -> Result<Option<QueuedIntent>, String> {
    store
        .next_intent_work_row(queue.table(), allowed_kinds, queue.order())
        .map_err(|err| format!("load queued intent: {err}"))?
        .map(|row| Intent::from_work_row(row).map(|intent| QueuedIntent { queue, intent }))
        .transpose()
}

/// Build the fact/store view a stored-intent handler requested.
fn load_handler_context<'a>(
    store: &'a Store,
    handler: &(impl IntentHandler + ?Sized),
    intent: &Intent,
    mode: HandlerMode,
) -> Result<HandlerContext<'a>, String> {
    let mut facts = Vec::new();
    for id in handler.input_fact_ids(intent)? {
        if let Some(fact) = persisted_fact(store, &id)? {
            facts.push(fact);
        }
    }
    let context = HandlerContext::with_facts(facts).with_mode(mode);
    Ok(context.with_store(store))
}

/// Run a handler and convert retry markers into report state.
fn run_handler(
    handler: &(impl IntentHandler + ?Sized),
    intent: &Intent,
    context: &HandlerContext<'_>,
    status: &mut WorkStatus,
) -> Result<Option<RuntimeEffects>, String> {
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
    queued: &QueuedIntent,
    effects: &RuntimeEffects,
    allowed_tables: &[TableName],
    fact_admission: Option<FactAdmissionFn>,
    pending_mode: crate::core::project_fact::ProjectionMode,
) -> Result<bool, String> {
    store
        .write_transaction(|tx| {
            let kind = queued.intent.kind.as_str();
            let idempotence_key = queued.intent.key.as_slice();
            if tx.delete_intent_work_row_in_tx(queued.queue.table(), kind, idempotence_key)? == 0 {
                return Ok(false);
            }
            if queued.queue == IntentQueue::Durable {
                tx.delete_intent_work_row_in_tx(LOCAL_INTENTS, kind, idempotence_key)?;
            }

            commit_runtime_effects_in_tx(
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
            tx.rotate_intent_work_row_to_tail_in_tx(LOCAL_INTENTS, &intent.work_row())
        })
        .map_err(|err| format!("rotate local retry intent: {err}"))
}

pub(crate) struct QueuedIntent {
    /// Queue from which this row was claimed.
    queue: IntentQueue,
    pub(crate) intent: Intent,
}

pub(crate) struct IntentDispatchReport {
    pub(crate) status: WorkStatus,
    pub(crate) emitted_projectable_facts: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::effects::RuntimeEffects;
    use crate::core::facts::{Fact, FactScope};
    use crate::core::intents::{retry_intent, HandlerResult, IntentKind};
    use crate::core::schema::{CORE_SCHEMA_SOURCE, INCOMING_FACTS, PENDING_PROJECTION};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static RETRY_CALLS: AtomicUsize = AtomicUsize::new(0);
    static AFTER_FACT_CALLS: AtomicUsize = AtomicUsize::new(0);

    #[test]
    fn durable_success_deletes_shadowed_local_intent() {
        let store =
            Store::open_memory_with_schema_sources(&[CORE_SCHEMA_SOURCE]).expect("open store");
        let intent = test_intent("handled", b"same-key");

        submit_intent_to_table(&store, LOCAL_INTENTS, intent.clone()).expect("submit local");
        submit_intent_to_table(&store, INTENTS, intent).expect("submit durable");

        let progress = dispatch_intents(
            &store,
            &HandlerSet::new(NOOP_ROUTES),
            &[],
            None,
            1,
            HandlerMode::Live,
            RuntimeEffectMode::Live,
        )
        .expect("dispatch durable intent");

        assert_eq!(progress.dispatched, 1);
        assert!(progress.status.progressed);
        assert_eq!(store.table_row_count(INTENTS).expect("durable count"), 0);
        assert_eq!(
            store.table_row_count(LOCAL_INTENTS).expect("local count"),
            0,
            "durable success should remove the duplicate local retry row"
        );
    }

    #[test]
    fn local_retries_rotate_and_do_not_spin_in_one_drain() {
        RETRY_CALLS.store(0, Ordering::SeqCst);
        let store =
            Store::open_memory_with_schema_sources(&[CORE_SCHEMA_SOURCE]).expect("open store");
        let first = test_intent("retrying", b"first");
        let second = test_intent("retrying", b"second");
        submit_intent_to_table(&store, LOCAL_INTENTS, first.clone()).expect("submit first local");
        submit_intent_to_table(&store, LOCAL_INTENTS, second).expect("submit second local");

        let progress = dispatch_intents(
            &store,
            &HandlerSet::new(RETRY_ROUTES),
            &[],
            None,
            8,
            HandlerMode::Live,
            RuntimeEffectMode::Live,
        )
        .expect("dispatch retrying local intents");

        assert_eq!(RETRY_CALLS.load(Ordering::SeqCst), 2);
        assert_eq!(progress.dispatched, 0);
        assert!(progress.status.retried);
        assert_eq!(
            store.table_row_count(LOCAL_INTENTS).expect("local count"),
            2
        );
        assert_eq!(
            next_queued_intent(&store, &["retrying"])
                .expect("next local")
                .expect("queued local")
                .intent
                .key,
            first.key,
            "the first retried row should be back at the head after both rows had one attempt"
        );
    }

    #[test]
    fn handler_fact_effects_are_retained_queued_and_yield_dispatch() {
        AFTER_FACT_CALLS.store(0, Ordering::SeqCst);
        let store =
            Store::open_memory_with_schema_sources(&[CORE_SCHEMA_SOURCE]).expect("open store");
        let emitted = emitted_fact();
        submit_intent_to_table(&store, INTENTS, test_intent("emit_fact", b"first"))
            .expect("submit emitting intent");
        submit_intent_to_table(&store, INTENTS, test_intent("zz_after_fact", b"second"))
            .expect("submit following intent");

        let progress = dispatch_intents(
            &store,
            &HandlerSet::new(EMIT_FACT_ROUTES),
            &[],
            None,
            8,
            HandlerMode::Live,
            RuntimeEffectMode::Live,
        )
        .expect("dispatch emitting intent");

        assert_eq!(progress.dispatched, 1);
        assert_eq!(
            AFTER_FACT_CALLS.load(Ordering::SeqCst),
            0,
            "dispatcher should yield so projection can run before later handlers"
        );
        assert_eq!(
            persisted_fact(&store, &emitted.id).expect("load emitted fact"),
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
        assert_eq!(store.table_row_count(INTENTS).expect("durable count"), 1);
    }

    struct NoopHandler;

    const NOOP_ROUTES: &[HandlerRoute] = &[HandlerRoute {
        intent_kind: "handled",
        factory: noop_handler,
        recurrence: None,
    }];

    const RETRY_ROUTES: &[HandlerRoute] = &[HandlerRoute {
        intent_kind: "retrying",
        factory: retry_handler,
        recurrence: None,
    }];

    const EMIT_FACT_ROUTES: &[HandlerRoute] = &[
        HandlerRoute {
            intent_kind: "emit_fact",
            factory: emit_fact_handler,
            recurrence: None,
        },
        HandlerRoute {
            intent_kind: "zz_after_fact",
            factory: after_fact_handler,
            recurrence: None,
        },
    ];

    impl IntentHandler for NoopHandler {
        fn handle(&self, _intent: &Intent, _context: &HandlerContext<'_>) -> HandlerResult {
            Ok(RuntimeEffects::new())
        }
    }

    struct RetryHandler;

    impl IntentHandler for RetryHandler {
        fn handle(&self, _intent: &Intent, _context: &HandlerContext<'_>) -> HandlerResult {
            RETRY_CALLS.fetch_add(1, Ordering::SeqCst);
            Err(retry_intent("test retry"))
        }
    }

    struct EmitFactHandler;

    impl IntentHandler for EmitFactHandler {
        fn handle(&self, _intent: &Intent, _context: &HandlerContext<'_>) -> HandlerResult {
            Ok(RuntimeEffects::new().fact(emitted_fact()))
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

    fn retry_handler() -> Box<dyn IntentHandler> {
        Box::new(RetryHandler)
    }

    fn emit_fact_handler() -> Box<dyn IntentHandler> {
        Box::new(EmitFactHandler)
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
}
