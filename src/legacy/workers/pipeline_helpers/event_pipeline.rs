//! Common event pipeline.
//!
//! This module is the narrow gate between canonical event bytes and projected
//! protocol state. It is intentionally boring: admit an event, wait for its
//! dependencies, call exactly one projector through the registry, and write the
//! row-shaped output the projector returned. That shape is the defense against
//! the kernel becoming a second protocol implementation.
//!
//! The worker does not know what any concrete event family means. Those meanings
//! live in event modules. The worker only knows the protocol-wide mechanics that
//! every canonical event shares:
//!
//! ```text
//! command -> ProposedEvent
//!          -> admit canonical bytes by deterministic event id
//!          -> project with Applied direct dependencies plus context updates
//!          -> either apply rows/context updates or let the projector wait for deps
//!          -> mark newly unblocked events ready
//! ```
//!
//! Transit input follows the same rule from the other side, but through an
//! explicit queue: `transit_in` interprets opaque inbound bytes with the
//! protocol registry and writes surviving canonical bytes to `canonical.in`.
//! The event-admission worker drains that queue back into the same one-event
//! helper used by local command batches. Network output is kept outside
//! projection as well: projectors may write protocol queue rows, and a domain
//! worker later turns those rows into opaque transport rows.
//!
//! Future maintainers should be suspicious of changes that make this file more
//! knowledgeable. Domain-specific branching here is usually a sign that an event
//! module is missing a layout, projector, command, query, table, or domain worker.
//! The important invariant is not that this file stays tiny; it is that it stays
//! mechanical enough to audit.
//!
//! If you are trying to understand the code path, start with `run`, then follow
//! the `Work` implementation for the call site. The heart of the file is
//! `process_proposed_event_tx`, the one-event pipeline:
//!
//! ```text
//! process_proposed_event_tx
//!   if transient:
//!     project_transient_event_tx
//!   else:
//!     store_durable_event_tx
//!     if newly inserted:
//!       project_ready_event_tx
//!         -> load_event_context_in_tx
//!         -> project
//!         -> Apply: write_projection_output_in_tx + write_applied_event_outputs_in_tx
//!         -> WaitForDeps: record blocker edges and leave event Blocked
//! dependency_unblock later consumes recently-valid rows and marks waiting
//! dependents ready without recursively projecting inside the admission
//! transaction.
//! ```
//!
//! Every other helper exists to make one of those verbs precise. A good change
//! should make that call tree shorter, clearer, or more obviously correct. A
//! suspicious change adds a second path that stores, projects, unblocks, or sends
//! around this path.
//!
//! Scheduling: this file exposes bounded worker-compatible `Work` values.
//! CLI and daemon call sites choose the order in which admission, projection,
//! and dependency unblock steps run. Each public work item is bounded by a batch
//! size or by the number of proposed command events.
//!
//! Inputs: command outputs, decoded records, received records, transit input,
//! and selected compatibility drain work supplied by CLI/test call sites.
//! State: durable event rows, ready/blocker indexes, retained direct dependency
//! edges, generic context updates, and worker queue rows declared in `workers::queue_rows`.
//! Step: admit local canonical records directly, drain queued canonical transit
//! records, project ready durable events, or run bounded compatibility drains
//! according to the supplied work item.
//! Outputs: durable event rows, projector rows/context updates, `canonical.in`,
//! `event_modules.ready_events`, `event_modules.recently_valid_events`,
//! `event_modules.pending_reprojections`, and `event_modules.applied_shared_events`.
//! Consume: queue rows are deleted only after the relevant event is accepted,
//! rejected, projected, or dependency unblock is applied.
//! Failure: rejected `canonical_in` rows are consumed; projection failures leave
//! ready events ready for retry; transaction rollback preserves unconsumed queue
//! state.
//! Fairness: explicit workers are batch-limited; compatibility helpers are
//! bounded by command event count or caller-provided batch size.

use crate::core::intents::AtomicIntent;
pub use crate::core::intents::TableDelete;
use crate::core::network_queues::{self, InboundNetworkRow};
use crate::core::projection::ProjectionOutput as CoreProjectionOutput;
use crate::core::store::{SchemaDefinition, Store, TableName, TableRow};
use crate::legacy::protocol::event_modules::types::{
    event_id, EventId, EventIndexEntry, EventRecord, EventStatus, ReceiveMetadata,
};

use crate::legacy::protocol::event_modules::rows;
use crate::legacy::workers::dependency_unblock;
use crate::legacy::workers::event_lifecycle;
use crate::legacy::workers::queue_rows as worker_rows;

/// Default upper bound for one ready-event drain.
///
/// This is a scheduling guard, not part of event semantics. A caller can choose
/// a smaller batch to improve fairness or a larger batch to reduce loop
/// overhead; the result must be the same as long as ready events are eventually
/// drained.
pub const DEFAULT_READY_BATCH: usize = 4096;

/// Canonical event proposed by a command before admission.
///
/// Commands are allowed to decide *what event should exist*. They are not
/// allowed to write event rows, projection rows, queue rows, or network rows.
/// `ProposedEvent` keeps the command boundary ergonomic while still making the
/// deterministic event id available immediately for command chaining and CLI
/// output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProposedEvent {
    event_id: EventId,
    record: EventRecord,
    receive: Option<ReceiveMetadata>,
}

impl ProposedEvent {
    pub fn new(record: EventRecord) -> Self {
        Self {
            event_id: event_id(&record.canonical_bytes),
            record,
            receive: None,
        }
    }

    fn contextual(record: EventRecord, receive: Option<ReceiveMetadata>) -> Self {
        Self {
            event_id: event_id(&record.canonical_bytes),
            record,
            receive,
        }
    }

    pub fn event_id(&self) -> EventId {
        self.event_id
    }

    pub fn record(&self) -> &EventRecord {
        &self.record
    }

    fn receive(&self) -> Option<ReceiveMetadata> {
        self.receive
    }

    pub fn into_record(self) -> EventRecord {
        self.record
    }
}

impl From<EventRecord> for ProposedEvent {
    fn from(record: EventRecord) -> Self {
        Self::new(record)
    }
}

/// Compatibility adapter for legacy protocol projectors that still describe
/// table mutations directly. The worker-facing boundary is the target
/// `core::projection::ProjectionOutput`; table writes and deletes are carried as
/// atomic intents and event-update writes are the same atomic table writes plus
/// the normal update reprojection wakeup when applied.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProjectionOutput {
    output: CoreProjectionOutput,
}

impl ProjectionOutput {
    pub fn new(output: CoreProjectionOutput) -> Self {
        Self { output }
    }

    pub fn table_writes(rows: Vec<TableRow>) -> Self {
        projection_table_writes(rows)
    }

    pub fn table_deletes(deletes: Vec<TableDelete>) -> Self {
        projection_table_deletes(deletes)
    }

    pub fn context_updates(updates: Vec<rows::ContextUpdate>) -> Self {
        projection_context_updates(updates)
    }

    pub fn table_writes_and_context_updates(
        rows: Vec<TableRow>,
        updates: Vec<rows::ContextUpdate>,
    ) -> Self {
        projection_table_writes_and_context_updates(rows, updates)
    }

    pub fn table_deletes_and_context_updates(
        deletes: Vec<TableDelete>,
        updates: Vec<rows::ContextUpdate>,
    ) -> Self {
        projection_table_deletes_and_context_updates(deletes, updates)
    }

    pub fn from_atomic_parts(
        rows: Vec<TableRow>,
        deletes: Vec<TableDelete>,
        updates: Vec<rows::ContextUpdate>,
    ) -> Self {
        projection_parts(rows, deletes, updates)
    }

    pub fn push_table_write(&mut self, row: TableRow) {
        self.output =
            std::mem::take(&mut self.output).intent(AtomicIntent::PutRow(row).into_intent());
    }

    pub fn push_table_delete(&mut self, delete: TableDelete) {
        self.output =
            std::mem::take(&mut self.output).intent(AtomicIntent::DeleteRow(delete).into_intent());
    }

    pub fn push_context_update(&mut self, update: rows::ContextUpdate) {
        for row in rows::context_update_rows(vec![update]) {
            self.push_table_write(row);
        }
    }

    pub fn append(&mut self, other: Self) {
        self.output.needs.extend(other.output.needs);
        self.output.offers.extend(other.output.offers);
        self.output.intents.extend(other.output.intents);
    }

    pub fn legacy_rows(&self) -> Vec<TableRow> {
        self.legacy_parts().0
    }

    pub fn legacy_deletes(&self) -> Vec<TableDelete> {
        self.legacy_parts().1
    }

    pub fn legacy_context_updates(&self) -> Vec<rows::ContextUpdate> {
        self.legacy_parts().2
    }

    fn as_core(&self) -> &CoreProjectionOutput {
        &self.output
    }

    fn into_core(self) -> CoreProjectionOutput {
        self.output
    }

    fn legacy_parts(&self) -> (Vec<TableRow>, Vec<TableDelete>, Vec<rows::ContextUpdate>) {
        let allowed_tables = projection_allowed_tables();
        let mut rows = Vec::new();
        let mut deletes = Vec::new();
        let mut updates = Vec::new();
        for intent in &self.output.intents {
            match AtomicIntent::from_intent(intent, &allowed_tables)
                .expect("legacy projection output must carry atomic row intents")
            {
                AtomicIntent::PutRow(row) if row.table == rows::CONTEXT_UPDATES => {
                    updates.push(decode_context_update_row(&row));
                }
                AtomicIntent::PutRow(row) => rows.push(row),
                AtomicIntent::DeleteRow(delete) => deletes.push(delete),
            }
        }
        (rows, deletes, updates)
    }
}

impl From<CoreProjectionOutput> for ProjectionOutput {
    fn from(output: CoreProjectionOutput) -> Self {
        Self::new(output)
    }
}

pub(crate) fn projection_table_writes(rows: Vec<TableRow>) -> ProjectionOutput {
    projection_parts(rows, Vec::new(), Vec::new())
}

pub(crate) fn projection_table_deletes(deletes: Vec<TableDelete>) -> ProjectionOutput {
    projection_parts(Vec::new(), deletes, Vec::new())
}

pub(crate) fn projection_context_updates(updates: Vec<rows::ContextUpdate>) -> ProjectionOutput {
    projection_parts(Vec::new(), Vec::new(), updates)
}

pub(crate) fn projection_table_writes_and_context_updates(
    rows: Vec<TableRow>,
    updates: Vec<rows::ContextUpdate>,
) -> ProjectionOutput {
    projection_parts(rows, Vec::new(), updates)
}

pub(crate) fn projection_table_deletes_and_context_updates(
    deletes: Vec<TableDelete>,
    updates: Vec<rows::ContextUpdate>,
) -> ProjectionOutput {
    projection_parts(Vec::new(), deletes, updates)
}

pub(crate) fn projection_parts(
    rows: Vec<TableRow>,
    deletes: Vec<TableDelete>,
    updates: Vec<rows::ContextUpdate>,
) -> ProjectionOutput {
    let mut output = CoreProjectionOutput::new();
    for row in rows
        .into_iter()
        .chain(rows::context_update_rows(updates).into_iter())
    {
        output = output.intent(AtomicIntent::PutRow(row).into_intent());
    }
    for delete in deletes {
        output = output.intent(AtomicIntent::DeleteRow(delete).into_intent());
    }
    ProjectionOutput::new(output)
}

/// Scheduler-visible decision made by a projector.
///
/// `Apply` means the projector had enough context to write semantic rows.
/// `WaitForDeps` means the event is valid so far but needs named direct
/// dependencies before it can project. The common worker records the wait edges;
/// it does not decide them before asking the projector.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProjectionDecision {
    Apply(ProjectionOutput),
    WaitForDeps(Vec<EventId>),
}

impl ProjectionDecision {
    pub fn apply(output: ProjectionOutput) -> Self {
        Self::Apply(output)
    }

    pub fn wait_for(dependencies: Vec<EventId>) -> Self {
        Self::WaitForDeps(dependencies)
    }
}

impl From<ProjectionOutput> for ProjectionDecision {
    fn from(output: ProjectionOutput) -> Self {
        Self::Apply(output)
    }
}

/// One immediate dependency loaded as generic projector context.
///
/// Dependency context contains the event id and the decoded record. It is
/// intentionally shallow: only dependencies named by the event are loaded here.
/// Deeper walks belong in a domain worker or a module-owned indexed table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DependencyContext {
    pub event_id: EventId,
    pub record: EventRecord,
    pub updates: Vec<Vec<u8>>,
}

/// Generic context every projector receives.
///
/// This is the default context promised by the protocol plan: the current event
/// id, its immediate dependency records, and bounded updates attached to the
/// current event id. If a projector seems to need arbitrary SQL, first ask
/// whether the needed fact should be a dependency, an update, or a module-owned
/// read model consumed by a worker.
///
/// `now_unix_minute` is the local logical clock at projection time, expressed
/// as `floor(logical_time_ms / UNIX_MINUTE_MS)`. Projectors use it to make
/// time-sensitive decisions (e.g. message disappearing-expiry) without
/// reaching into storage themselves. `None` means the clock is not pinned —
/// projectors must treat that as "no time-based decision is safe to make."
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventContext {
    pub event_id: EventId,
    pub dependencies: Vec<DependencyContext>,
    pub updates: Vec<Vec<u8>>,
    pub receive: Option<ReceiveMetadata>,
    pub now_unix_minute: Option<u64>,
}

impl EventContext {
    pub fn dependency(&self, event_id: &EventId) -> Option<&EventRecord> {
        self.dependencies
            .iter()
            .find(|dependency| &dependency.event_id == event_id)
            .map(|dependency| &dependency.record)
    }

    pub fn require_dependency(&self, event_id: &EventId) -> Result<&EventRecord, String> {
        self.dependency(event_id)
            .ok_or_else(|| wait_for_dependency_error(event_id))
    }

    pub fn missing_dependencies_from(&self, dependencies: &[EventId]) -> Vec<EventId> {
        let mut missing = Vec::new();
        for dependency in unique_dependencies(dependencies) {
            if self.dependency(&dependency).is_none() {
                missing.push(dependency);
            }
        }
        missing
    }

    pub fn dependency_updates(&self, event_id: &EventId) -> Option<&[Vec<u8>]> {
        self.dependencies
            .iter()
            .find(|dependency| &dependency.event_id == event_id)
            .map(|dependency| dependency.updates.as_slice())
    }

    pub fn dependency_has_update(&self, event_id: &EventId, update: &[u8]) -> bool {
        self.dependency_updates(event_id)
            .map(|updates| updates.iter().any(|candidate| candidate == update))
            .unwrap_or(false)
    }

    pub fn has_update(&self, update: &[u8]) -> bool {
        self.updates.iter().any(|candidate| candidate == update)
    }
}

/// Event record plus the generic context fetched by the worker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventWithContext<'a> {
    pub record: &'a EventRecord,
    pub context: EventContext,
}

/// Result of a command: a value for the caller plus proposed events to admit.
///
/// The value is command-local information such as a created id, a status report,
/// or bytes that are intentionally not canonical events. The events are the only
/// durable state change path. The API running a command is responsible for
/// admitting them through this worker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandOutput<T> {
    pub value: T,
    pub events: Vec<ProposedEvent>,
}

impl<T> CommandOutput<T> {
    pub fn new(value: T) -> Self {
        Self {
            value,
            events: Vec::new(),
        }
    }

    pub fn with_events(value: T, events: Vec<EventRecord>) -> Self {
        Self {
            value,
            events: events.into_iter().map(ProposedEvent::new).collect(),
        }
    }

    pub fn with_proposed_events(value: T, events: Vec<ProposedEvent>) -> Self {
        Self { value, events }
    }

    pub fn prepend_events(mut self, mut events: Vec<ProposedEvent>) -> Self {
        events.append(&mut self.events);
        self.events = events;
        self
    }
}

/// Decision returned by the registry's receive-side admission gate.
///
/// The gate runs after `record_from_canonical_in` has decoded a receive-side
/// event into an `EventRecord` but before any storage write. It exists to let
/// modules drop events that should not be re-admitted — for example, message
/// events whose ids are already tombstoned, or whose stamped expiry is past.
/// Locally-authored events do not pass through this gate.
///
/// The `WriteRowsAndDrop` variant lets a module record the drop (e.g. by
/// writing a tombstone row) while still skipping the canonical-bytes /
/// admitted-event-index insert. Rows are inserted in the same transaction as
/// the queue consume, so a crash before commit replays the drop on the next
/// tick.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdmitDecision {
    /// Continue the normal admit path: store canonical bytes, project, etc.
    Admit,
    /// Drop the event silently. No storage writes; the canonical_in row is
    /// still consumed so the queue makes progress.
    Drop,
    /// Drop the event, but first insert these rows in the same transaction.
    /// Used to write a `MESSAGE_TOMBSTONES` row when the gate decides an
    /// expired-at-receive message should never have been admitted.
    WriteRowsAndDrop(Vec<TableRow>),
}

/// Protocol registry used by the common worker.
///
/// This trait is the only place where the generic admission/apply loop touches
/// concrete event modules. `event_from_bytes` chooses the module layout.
/// `project_record` chooses the module projector and receives the
/// `EventWithContext` already loaded by this worker. Keeping those decisions
/// behind the registry lets this worker enforce common mechanics without
/// learning event-type vocabulary.
pub trait EventRegistry {
    fn event_from_bytes(&self, bytes: Vec<u8>) -> Result<EventRecord, String>;

    /// Receive-side admission gate.
    ///
    /// Called by the common pipeline for every received record after the
    /// layout has decoded canonical bytes into an `EventRecord` but before
    /// the record has been stored or projected. The gate returns `Admit`
    /// for the normal path; `Drop` to silently discard; or
    /// `WriteRowsAndDrop(rows)` to record the drop with a row write
    /// (e.g. a tombstone) and then discard.
    ///
    /// Locally-authored events do not pass through this gate. Their
    /// canonical-bytes hash already dedupes double-admit attempts; the
    /// gate's job is to defend the receive side from re-admitting events
    /// that local state has already retired.
    ///
    /// The default returns `Admit`.
    fn admit_received_record(
        &self,
        _store: &Store,
        _record: &EventRecord,
    ) -> Result<AdmitDecision, String> {
        Ok(AdmitDecision::Admit)
    }

    /// Project one opaque network row into ordinary worker rows.
    ///
    /// The daemon calls this only through `transit_in`. Protocols that use
    /// encrypted transit envelopes return `canonical.in` rows carrying the
    /// recovered inner bytes and provenance. The common pipeline later admits
    /// those rows with the same dependency, projector, and block/unblock rules
    /// as command-created events.
    fn project_network_in(
        &self,
        _store: &Store,
        _inbound: &InboundNetworkRow,
    ) -> Result<ProjectionOutput, String> {
        Err("event registry does not handle network input".to_string())
    }

    fn record_from_canonical_in(
        &self,
        _store: &Store,
        bytes: Vec<u8>,
        receive: Option<ReceiveMetadata>,
        provenance: Option<worker_rows::TransitProvenance>,
    ) -> Result<ReceivedRecord, String> {
        // The default path is for command-created rows and already-classified
        // local rows. Protocols with envelope boundaries override this method
        // so provenance can decide which receive context, if any, should
        // accompany the canonical bytes into projection.
        if provenance.is_some() {
            return Err("event registry does not handle provenance".to_string());
        }
        let record = self.event_from_bytes(bytes)?;
        Ok(ReceivedRecord { record, receive })
    }

    fn project_record(
        &self,
        store: &Store,
        event: &EventWithContext<'_>,
    ) -> Result<ProjectionDecision, String>;

    /// Run any protocol-specific post-admission drains.
    ///
    /// Called by the common pipeline after any admission path finishes its
    /// own `drain_until_idle`. Protocols may use this hook to fire bounded,
    /// row-triggered worker drains so an in-process CLI admission path
    /// reaches the same end state as a daemon tick before returning to the
    /// caller. The default is a no-op so most protocols pay nothing for the
    /// hook.
    ///
    /// The hook must be bounded and pure operational work: it observes
    /// projector-emitted indicator rows and dispatches to a worker. It must
    /// not invent new semantic events or branch on event type. The pipeline
    /// is intentionally generic: it does not know which workers a protocol
    /// might want to drain here.
    fn post_admission_hook(&self, _store: &Store) -> Result<(), String> {
        Ok(())
    }
}

/// Unit of work accepted by the worker runner.
///
/// Work values are small boundary objects: "admit these records", "drain ready
/// events", or another worker-specific input. They keep callers from reaching into
/// helper functions and make the public entrypoint read like a caller-selected
/// worker step.
pub trait Work<R: EventRegistry> {
    type Output;

    fn execute(self, store: &Store, registry: &R) -> Result<Self::Output, String>;
}

/// Admit already-decoded records through normal dependency handling.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmitRecords {
    pub records: Vec<EventRecord>,
}

/// Admit records with receive-boundary context.
///
/// Public commands admit canonical records. Network admission is the boundary
/// that turns authenticated inbound bytes into receive context, so this work
/// item and its records are only constructible inside the crate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmitReceivedRecords {
    pub(crate) records: Vec<ReceivedRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceivedRecord {
    record: EventRecord,
    receive: Option<ReceiveMetadata>,
}

impl ReceivedRecord {
    pub(crate) fn new(record: EventRecord) -> Self {
        Self {
            record,
            receive: None,
        }
    }

    pub(crate) fn with_receive(record: EventRecord, receive: ReceiveMetadata) -> Self {
        Self {
            record,
            receive: Some(receive),
        }
    }
}

/// Admit a command output and drain ready durable events after admission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmitAndDrain<T> {
    pub output: CommandOutput<T>,
    pub batch_size: usize,
}

/// Drain ready durable events until no ready event remains.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DrainUntilIdle {
    pub batch_size: usize,
}

/// Drain at most one batch of ready durable events.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DrainReadyBatch {
    pub batch_size: usize,
}

/// Summary of event admission and any immediately-applied events.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AdmitReport {
    pub network_frames: usize,
    pub event_ids: Vec<EventId>,
    pub inserted_events: usize,
    pub ready_events: usize,
    pub blocked_events: usize,
    pub blocked_edges: usize,
    pub applied_events: usize,
}

/// Summary of inbound transit frame handling.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TransitInReport {
    pub network_frames: usize,
    pub canonical_rows: usize,
}

/// Summary of a ready-event drain.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ApplyReadyReport {
    pub applied_events: usize,
    pub unblocked_events: usize,
    pub reprojected_events: usize,
    pub blocked_events: usize,
    pub blocked_edges: usize,
}

/// Summary of command admission followed by a ready-event drain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmitAndDrainReport<T> {
    pub value: T,
    pub admitted: AdmitReport,
    pub drained: ApplyReadyReport,
}

/// Run one common event pipeline action.
///
/// The single public function is deliberate. If a caller needs another behavior,
/// add a `Work` value that names the behavior instead of exporting a helper. This
/// keeps the admission/apply boundary small enough to reason about from tests and
/// static checks.
pub fn run<R, W>(store: &Store, registry: &R, work: W) -> Result<W::Output, String>
where
    R: EventRegistry,
    W: Work<R>,
{
    work.execute(store, registry)
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct PipelineStepReport {
    pub admitted: AdmitReport,
    pub drained: ApplyReadyReport,
}

pub(crate) fn enqueue_proposed_events(
    store: &Store,
    events: Vec<ProposedEvent>,
) -> Result<usize, String> {
    let rows = events
        .into_iter()
        .map(|event| worker_rows::canonical_in_row(event.record, event.receive))
        .collect();
    store
        .insert_table_rows(rows)
        .map_err(|err| format!("enqueue canonical in: {err}"))
}

pub(crate) fn drain_canonical_in<R>(
    store: &Store,
    registry: &R,
    limit: usize,
) -> Result<AdmitReport, String>
where
    R: EventRegistry,
{
    let input = worker_rows::claim_canonical_in(store, limit)
        .map_err(|err| format!("claim canonical in: {err}"))?;
    let mut total = AdmitReport::default();
    for canonical in input {
        let key = canonical.key;
        let bytes = canonical.canonical_bytes;
        let receive = canonical.receive;
        let provenance = canonical.provenance;
        let result = store.write_transaction(|store| {
            let mut report = AdmitReport::default();
            let received = registry
                .record_from_canonical_in(store, bytes.clone(), receive, provenance)
                .map_err(module_error)?;
            let decision = registry
                .admit_received_record(store, &received.record)
                .map_err(module_error)?;
            match decision {
                AdmitDecision::Admit => {
                    let proposed = ProposedEvent::contextual(received.record, received.receive);
                    process_proposed_event_tx(store, registry, &proposed, &mut report)?;
                }
                AdmitDecision::Drop => {
                    report
                        .event_ids
                        .push(event_id(&received.record.canonical_bytes));
                }
                AdmitDecision::WriteRowsAndDrop(rows) => {
                    report
                        .event_ids
                        .push(event_id(&received.record.canonical_bytes));
                    store.insert_table_rows_in_tx(rows)?;
                }
            }
            store.delete_table_rows_in_tx(worker_rows::CANONICAL_IN, vec![key.clone()])?;
            Ok(report)
        });
        match result {
            Ok(report) => merge_admit_report(&mut total, report),
            Err(err) => {
                store
                    .delete_table_rows(worker_rows::CANONICAL_IN, vec![key])
                    .map_err(|delete_err| {
                        format!(
                            "drain canonical in: {err}; failed to consume rejected event: {delete_err}"
                        )
                    })?;
                return Err(format!("drain canonical in: {err}"));
            }
        }
    }
    if total.inserted_events > 0 || total.applied_events > 0 {
        registry.post_admission_hook(store)?;
    }
    Ok(total)
}

pub(crate) fn drain_transit_in<R>(
    store: &Store,
    registry: &R,
    limit: usize,
) -> Result<TransitInReport, String>
where
    R: EventRegistry,
{
    let input = network_queues::claim_inbound(store, limit)
        .map_err(|err| format!("claim network in: {err}"))?;
    let mut total = TransitInReport::default();
    for inbound in input {
        let result = store.write_transaction(|store| {
            let changes = registry
                .project_network_in(store, &inbound)
                .map_err(module_error)?;
            let canonical_rows = count_atomic_puts(&changes, worker_rows::CANONICAL_IN)?;
            write_projection_output_in_tx(store, changes)?;
            network_queues::delete_inbound_in_tx(store, std::slice::from_ref(&inbound))?;
            Ok(canonical_rows)
        });
        match result {
            Ok(canonical_rows) => {
                total.network_frames += 1;
                total.canonical_rows += canonical_rows;
            }
            Err(err) => {
                network_queues::delete_inbound(store, std::slice::from_ref(&inbound)).map_err(
                    |delete_err| {
                        format!(
                            "drain transit in: {err}; failed to consume rejected frame: {delete_err}"
                        )
                    },
                )?;
                return Err(format!("drain transit in: {err}"));
            }
        }
    }
    Ok(total)
}

pub(crate) fn drain_ready_events<R>(
    store: &Store,
    registry: &R,
    limit: usize,
) -> Result<ApplyReadyReport, String>
where
    R: EventRegistry,
{
    let mut report = drain_ready(store, registry, limit)?;
    let reproject = drain_pending_reprojections(store, registry, limit)?;
    report.applied_events += reproject.applied_events;
    report.unblocked_events += reproject.unblocked_events;
    report.reprojected_events += reproject.reprojected_events;
    report.blocked_events += reproject.blocked_events;
    report.blocked_edges += reproject.blocked_edges;
    if report.applied_events > 0 || report.reprojected_events > 0 {
        registry.post_admission_hook(store)?;
    }
    Ok(report)
}

pub(crate) fn drain_recently_valid_events(
    store: &Store,
    limit: usize,
) -> Result<ApplyReadyReport, String> {
    store
        .write_transaction(|store| {
            let events = worker_rows::claim_recently_valid_events(store, limit)?;
            let keys = events
                .iter()
                .map(|event| event.key.clone())
                .collect::<Vec<_>>();
            let mut total = ApplyReadyReport::default();
            for event in events {
                total.unblocked_events += unblock_dependents(store, &event.event_id)?;
            }
            store.delete_table_rows_in_tx(worker_rows::RECENTLY_VALID_EVENTS, keys)?;
            Ok(total)
        })
        .map_err(|err| format!("drain recently valid events: {err}"))
}

pub(crate) fn drain_pending_reprojections<R>(
    store: &Store,
    registry: &R,
    limit: usize,
) -> Result<ApplyReadyReport, String>
where
    R: EventRegistry,
{
    store
        .write_transaction(|store| {
            let pending = worker_rows::claim_pending_reprojections(store, limit)?;
            let keys = pending
                .iter()
                .map(|event| event.key.clone())
                .collect::<Vec<_>>();
            let mut total = ApplyReadyReport::default();
            for event in pending {
                let report =
                    reproject_context_update_woken_event_tx(store, registry, &event.event_id)?;
                total.applied_events += report.applied_events;
                total.unblocked_events += report.unblocked_events;
                total.reprojected_events += report.reprojected_events;
                total.blocked_events += report.blocked_events;
                total.blocked_edges += report.blocked_edges;
            }
            store.delete_table_rows_in_tx(worker_rows::PENDING_REPROJECTIONS, keys)?;
            Ok(total)
        })
        .map_err(|err| format!("drain pending reprojections: {err}"))
}

fn admit_proposed_events<R>(
    store: &Store,
    registry: &R,
    events: Vec<ProposedEvent>,
) -> Result<PipelineStepReport, String>
where
    R: EventRegistry,
{
    let admitted = store
        .write_transaction(|store| {
            let mut report = AdmitReport::default();
            for event in events {
                process_proposed_event_tx(store, registry, &event, &mut report)?;
            }
            Ok(report)
        })
        .map_err(|err| format!("admit proposed events: {err}"))?;
    let drained = drain_followups_until_empty(store, registry, DEFAULT_READY_BATCH)?;
    if admitted.inserted_events > 0 || admitted.applied_events > 0 || drained.reprojected_events > 0
    {
        registry.post_admission_hook(store)?;
    }
    Ok(PipelineStepReport { admitted, drained })
}

fn drain_recently_valid_until_empty(
    store: &Store,
    batch_size: usize,
) -> Result<ApplyReadyReport, String> {
    let mut total = ApplyReadyReport::default();
    let limit = batch_size.max(1);
    while store
        .table_row_count(worker_rows::RECENTLY_VALID_EVENTS)
        .map_err(|err| format!("count recently valid events: {err}"))?
        > 0
    {
        let report = dependency_unblock::run(store, dependency_unblock::Work::Drain { limit })?;
        total.applied_events += report.applied_events;
        total.unblocked_events += report.unblocked_events;
        total.reprojected_events += report.reprojected_events;
        total.blocked_events += report.blocked_events;
        total.blocked_edges += report.blocked_edges;
    }
    Ok(total)
}

fn drain_followups_until_empty<R>(
    store: &Store,
    registry: &R,
    batch_size: usize,
) -> Result<ApplyReadyReport, String>
where
    R: EventRegistry,
{
    let mut total = ApplyReadyReport::default();
    let limit = batch_size.max(1);
    loop {
        let reproject = drain_pending_reprojections(store, registry, limit)?;
        let unblock = drain_recently_valid_until_empty(store, limit)?;
        total.applied_events += reproject.applied_events + unblock.applied_events;
        total.unblocked_events += reproject.unblocked_events + unblock.unblocked_events;
        total.reprojected_events += reproject.reprojected_events + unblock.reprojected_events;
        total.blocked_events += reproject.blocked_events + unblock.blocked_events;
        total.blocked_edges += reproject.blocked_edges + unblock.blocked_edges;
        if reproject.reprojected_events == 0 && unblock.unblocked_events == 0 {
            return Ok(total);
        }
    }
}

fn merge_admit_report(total: &mut AdmitReport, next: AdmitReport) {
    total.network_frames += next.network_frames;
    total.event_ids.extend(next.event_ids);
    total.inserted_events += next.inserted_events;
    total.ready_events += next.ready_events;
    total.blocked_events += next.blocked_events;
    total.blocked_edges += next.blocked_edges;
    total.applied_events += next.applied_events;
}

impl<T, R> Work<R> for CommandOutput<T>
where
    R: EventRegistry,
{
    type Output = (T, AdmitReport);

    fn execute(self, store: &Store, registry: &R) -> Result<Self::Output, String> {
        let value = self.value;
        let report = admit_proposed_events(store, registry, self.events)?;
        Ok((value, report.admitted))
    }
}

impl<T, R> Work<R> for AdmitAndDrain<T>
where
    R: EventRegistry,
{
    type Output = AdmitAndDrainReport<T>;

    fn execute(self, store: &Store, registry: &R) -> Result<Self::Output, String> {
        let value = self.output.value;
        let report = admit_proposed_events(store, registry, self.output.events)?;
        let drained = drain_until_idle(store, registry, self.batch_size)?;
        // Re-run the post-admission hook once after the post-drain since a
        // dependent event may have only become Applied as the closure
        // unblocked it. This keeps in-process CLI paths (delete-message,
        // scripted batches, one-shot admission flows) at the same end state
        // as a long-running daemon.
        registry.post_admission_hook(store)?;
        let drained = ApplyReadyReport {
            applied_events: report.drained.applied_events + drained.applied_events,
            unblocked_events: report.drained.unblocked_events + drained.unblocked_events,
            reprojected_events: report.drained.reprojected_events + drained.reprojected_events,
            blocked_events: report.drained.blocked_events + drained.blocked_events,
            blocked_edges: report.drained.blocked_edges + drained.blocked_edges,
        };
        Ok(AdmitAndDrainReport {
            value,
            admitted: report.admitted,
            drained,
        })
    }
}

impl<R> Work<R> for AdmitRecords
where
    R: EventRegistry,
{
    type Output = AdmitReport;

    fn execute(self, store: &Store, registry: &R) -> Result<Self::Output, String> {
        admit_proposed_events(
            store,
            registry,
            self.records.into_iter().map(ProposedEvent::new).collect(),
        )
        .map(|report| report.admitted)
    }
}

impl<R> Work<R> for AdmitReceivedRecords
where
    R: EventRegistry,
{
    type Output = AdmitReport;

    fn execute(self, store: &Store, registry: &R) -> Result<Self::Output, String> {
        admit_proposed_events(
            store,
            registry,
            self.records
                .into_iter()
                .map(|received| ProposedEvent::contextual(received.record, received.receive))
                .collect(),
        )
        .map(|report| report.admitted)
    }
}

impl<R> Work<R> for DrainUntilIdle
where
    R: EventRegistry,
{
    type Output = ApplyReadyReport;

    fn execute(self, store: &Store, registry: &R) -> Result<Self::Output, String> {
        let report = drain_until_idle(store, registry, self.batch_size)?;
        if report.applied_events > 0 || report.reprojected_events > 0 {
            registry.post_admission_hook(store)?;
        }
        Ok(report)
    }
}

impl<R> Work<R> for DrainReadyBatch
where
    R: EventRegistry,
{
    type Output = ApplyReadyReport;

    fn execute(self, store: &Store, registry: &R) -> Result<Self::Output, String> {
        let mut report = drain_ready(store, registry, self.batch_size)?;
        let reproject = drain_pending_reprojections(store, registry, self.batch_size)?;
        let unblock = drain_recently_valid_events(store, self.batch_size)?;
        report.reprojected_events += reproject.reprojected_events;
        report.unblocked_events += unblock.unblocked_events;
        if report.applied_events > 0 || report.reprojected_events > 0 {
            registry.post_admission_hook(store)?;
        }
        Ok(report)
    }
}

// ---------------------------------------------------------------------------
// Canonical event pipeline
// ---------------------------------------------------------------------------

/// Process one proposed event.
///
/// This is the core pipeline. It has exactly two branches:
///
/// 1. Transient records are projected immediately and never inserted into the
///    durable event table.
/// 2. Durable records are inserted by deterministic id, then projected with
///    partial context. The projector decides whether to apply rows now or wait
///    for direct dependencies.
///
/// Duplicate durable events stop after insertion returns `inserted = false`.
/// They do not re-project, rewrite blockers, or re-run module code.
fn process_proposed_event_tx(
    store: &Store,
    modules: &impl EventRegistry,
    event: &ProposedEvent,
    report: &mut AdmitReport,
) -> rusqlite::Result<()> {
    let record = event.record();
    report.event_ids.push(event.event_id());
    if !record.scope.is_durable() {
        project_transient_event_tx(store, modules, record, event.receive())?;
        report.applied_events += 1;
        return Ok(());
    }

    let stored = store_durable_event_tx(store, event, report)?;
    if stored.inserted {
        let apply = if event.receive().is_some() {
            project_ready_event_record_in_tx(
                store,
                modules,
                &stored.event_id,
                record,
                event.receive(),
            )?
        } else {
            project_ready_event_tx(store, modules, &stored.event_id)?
        };
        report.ready_events += apply.applied_events;
        report.applied_events += apply.applied_events;
        report.blocked_events += apply.blocked_events;
        report.blocked_edges += apply.blocked_edges;
    }
    Ok(())
}

fn project_transient_event_tx(
    store: &Store,
    modules: &impl EventRegistry,
    record: &EventRecord,
    receive: Option<ReceiveMetadata>,
) -> rusqlite::Result<()> {
    // Transient events are canonical enough to project and dedupe inside the
    // current process, but they are not durable facts. Letting them wait on
    // durable dependencies would create hidden state that cannot be resumed
    // after a crash.
    if !record.dependencies.is_empty() {
        return Err(module_error(
            "transient events cannot wait on durable dependencies".to_string(),
        ));
    }
    let event_id = event_id(&record.canonical_bytes);
    match project_event_with_context_in_tx(store, modules, &event_id, record, receive)? {
        ProjectionDecision::Apply(changes) => {
            write_projection_output_in_tx(store, changes)?;
        }
        ProjectionDecision::WaitForDeps(dependencies) => {
            return Err(module_error(format!(
                "transient event cannot wait for dependencies: {}",
                dependencies.len()
            )));
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct StoredDurableEvent {
    event_id: EventId,
    inserted: bool,
}

/// Insert a durable event row as schedulable work.
///
/// This helper does not inspect dependencies. Missing context is a projector
/// decision, so every new durable event starts Ready and the projection step can
/// either apply rows or return `WaitForDeps`.
fn store_durable_event_tx(
    store: &Store,
    event: &ProposedEvent,
    report: &mut AdmitReport,
) -> rusqlite::Result<StoredDurableEvent> {
    let record = event.record();
    let id = event.event_id();

    let inserted = event_lifecycle::insert_event(store, record, EventStatus::Ready)?;
    if inserted {
        report.inserted_events += 1;
    }
    Ok(StoredDurableEvent {
        event_id: id,
        inserted,
    })
}

/// Claim and project one ready durable event.
///
/// The projector sees Applied direct dependencies and context updates, then returns a
/// lifecycle decision. Apply moves Ready -> Applied and writes projector rows;
/// WaitForDeps moves Ready -> Blocked and writes blocker edges. Context load,
/// projector call, status change, and row writes all happen in the caller's
/// transaction, so failed projection leaves the event Ready for retry.
fn project_ready_event_tx(
    store: &Store,
    modules: &impl EventRegistry,
    event_id: &EventId,
) -> rusqlite::Result<ApplyReadyReport> {
    let mut report = ApplyReadyReport::default();
    if event_lifecycle::event_status(store, event_id)? != Some(EventStatus::Ready) {
        return Ok(report);
    }
    let bytes = rows::event_bytes(store, event_id)?.ok_or(rusqlite::Error::QueryReturnedNoRows)?;
    let record = modules.event_from_bytes(bytes).map_err(module_error)?;
    let receive = worker_rows::event_receive_context(store, event_id)?;
    let decision = project_event_with_context_in_tx(store, modules, event_id, &record, receive)?;
    apply_projection_decision_in_tx(store, event_id, &record, receive, decision, &mut report)?;
    Ok(report)
}

fn project_ready_event_record_in_tx(
    store: &Store,
    modules: &impl EventRegistry,
    event_id: &EventId,
    record: &EventRecord,
    receive: Option<ReceiveMetadata>,
) -> rusqlite::Result<ApplyReadyReport> {
    let mut report = ApplyReadyReport::default();
    if event_lifecycle::event_status(store, event_id)? != Some(EventStatus::Ready) {
        return Ok(report);
    }
    let decision = project_event_with_context_in_tx(store, modules, event_id, record, receive)?;
    apply_projection_decision_in_tx(store, event_id, record, receive, decision, &mut report)?;
    Ok(report)
}

fn apply_projection_decision_in_tx(
    store: &Store,
    event_id: &EventId,
    record: &EventRecord,
    receive: Option<ReceiveMetadata>,
    decision: ProjectionDecision,
    report: &mut ApplyReadyReport,
) -> rusqlite::Result<()> {
    match decision {
        ProjectionDecision::Apply(changes) => {
            if event_lifecycle::set_event_status(
                store,
                event_id,
                EventStatus::Ready,
                EventStatus::Applied,
            )? {
                write_projection_output_in_tx(store, changes)?;
                write_applied_event_outputs_in_tx(store, event_id, record)?;
                if receive.is_some() {
                    worker_rows::delete_event_receive_context_in_tx(store, event_id)?;
                }
                report.applied_events += 1;
            }
        }
        ProjectionDecision::WaitForDeps(dependencies) => {
            let dependencies = wait_dependencies_for(store, record, dependencies)?;
            if dependencies.is_empty() {
                return Err(module_error(
                    "projector waited without naming a declared dependency".to_string(),
                ));
            }
            if event_lifecycle::set_event_status(
                store,
                event_id,
                EventStatus::Ready,
                EventStatus::Blocked,
            )? {
                if let Some(receive) = receive {
                    store.insert_table_rows_in_tx(vec![worker_rows::event_receive_context_row(
                        *event_id, receive,
                    )])?;
                }
                report.blocked_events += 1;
                report.blocked_edges += write_blockers(store, event_id, &dependencies)?;
            }
        }
    }
    Ok(())
}

fn reproject_context_update_woken_event_tx(
    store: &Store,
    modules: &impl EventRegistry,
    event_id: &EventId,
) -> rusqlite::Result<ApplyReadyReport> {
    let mut report = ApplyReadyReport::default();
    let Some(status) = event_lifecycle::event_status(store, event_id)? else {
        return Ok(report);
    };
    if status == EventStatus::Ready {
        // Ready events will see the new context updates on their normal Ready -> Applied
        // pass. Reprojecting here would race the lifecycle claim path.
        return Ok(report);
    }
    let Some(bytes) = rows::event_bytes(store, event_id)? else {
        return Ok(report);
    };
    let record = modules.event_from_bytes(bytes).map_err(module_error)?;
    match status {
        EventStatus::Applied => {
            match project_event_with_context_in_tx(store, modules, event_id, &record, None)? {
                ProjectionDecision::Apply(changes) => {
                    write_projection_output_in_tx(store, changes)?;
                    report.reprojected_events += 1;
                    Ok(report)
                }
                ProjectionDecision::WaitForDeps(_) => Ok(report),
            }
        }
        EventStatus::Blocked => {
            // Context-update wake is opportunistic for blocked events. If the projector
            // can make a semantic deletion decision from the event bytes plus
            // available context, it writes purge/delete output now. If it still
            // needs a missing dependency, the ordinary missing-dependency edge
            // remains and the event will be tried again when that dependency
            // applies.
            match project_event_with_context_in_tx(store, modules, event_id, &record, None)? {
                ProjectionDecision::Apply(changes) => {
                    if event_lifecycle::set_event_status(
                        store,
                        event_id,
                        EventStatus::Blocked,
                        EventStatus::Applied,
                    )? {
                        event_lifecycle::delete_missing_deps_by_blocked_event(store, event_id)?;
                        write_projection_output_in_tx(store, changes)?;
                        write_applied_event_outputs_in_tx(store, event_id, &record)?;
                        worker_rows::delete_event_receive_context_in_tx(store, event_id)?;
                        report.applied_events += 1;
                        report.reprojected_events += 1;
                    }
                    Ok(report)
                }
                ProjectionDecision::WaitForDeps(_) => Ok(report),
            }
        }
        EventStatus::Ready | EventStatus::Rejected => Ok(report),
    }
}

fn write_applied_event_outputs_in_tx(
    store: &Store,
    event_id: &EventId,
    record: &EventRecord,
) -> rusqlite::Result<()> {
    let mut rows = vec![worker_rows::recently_valid_event_row(*event_id)];
    if record.scope.is_shared() {
        rows.push(worker_rows::applied_shared_event_row(EventIndexEntry {
            event_id: *event_id,
            timestamp: record.timestamp,
            workspace_id: record.workspace_id,
        }));
    }
    store.insert_table_rows_in_tx(rows)?;
    Ok(())
}

/// Load generic context and call the registry projector.
///
/// This is the `get_context -> project` part of the pipeline. The worker always
/// loads the protocol-wide context first so leaf projectors can stay pure
/// functions over event bytes plus bounded facts.
fn project_event_with_context_in_tx(
    store: &Store,
    modules: &impl EventRegistry,
    event_id: &EventId,
    record: &EventRecord,
    receive: Option<ReceiveMetadata>,
) -> rusqlite::Result<ProjectionDecision> {
    let context = load_event_context_in_tx(store, modules, event_id, record, receive)?;
    let event = EventWithContext { record, context };
    modules.project_record(store, &event).map_err(module_error)
}

/// Fetch the generic context shared by all projectors.
///
/// The dependency list comes from the event itself. Only Applied dependencies
/// become dependency records; merely stored, blocked, failed, missing, or purged
/// dependencies are absent from `context.dependencies`. Projectors use that
/// absence to decide whether they still need to block or whether an update makes
/// the event obsolete enough to delete/purge without the missing record. Updates
/// are generic, bounded facts attached to this event id by earlier projections.
fn load_event_context_in_tx(
    store: &Store,
    modules: &impl EventRegistry,
    event_id: &EventId,
    record: &EventRecord,
    receive: Option<ReceiveMetadata>,
) -> rusqlite::Result<EventContext> {
    let mut dependencies = Vec::with_capacity(record.dependencies.len());
    for dependency in unique_dependencies(&record.dependencies) {
        if event_lifecycle::event_is_applied(store, &dependency)? {
            if let Some(bytes) = rows::event_bytes(store, &dependency)? {
                let record = modules.event_from_bytes(bytes).map_err(module_error)?;
                let updates = rows::context_updates(store, &dependency).map_err(module_error)?;
                dependencies.push(DependencyContext {
                    event_id: dependency,
                    record,
                    updates,
                });
            }
        }
    }
    let now_unix_minute = crate::core::logical_clock::logical_time(store)
        .map_err(module_error)?
        .map(|ms| {
            ms / crate::legacy::protocol::event_modules::content::message::types::UNIX_MINUTE_MS
        });
    Ok(EventContext {
        event_id: *event_id,
        dependencies,
        updates: rows::context_updates(store, event_id).map_err(module_error)?,
        receive,
        now_unix_minute,
    })
}

fn write_projection_output_in_tx(
    store: &Store,
    changes: ProjectionOutput,
) -> rusqlite::Result<usize> {
    let changes = changes.into_core();
    if !changes.needs.is_empty() || !changes.offers.is_empty() {
        return Err(module_error(
            "legacy event pipeline cannot persist target context needs/offers yet".to_string(),
        ));
    }

    let mut applied = 0;
    let allowed_tables = projection_allowed_tables();
    for intent in changes.intents {
        match AtomicIntent::from_intent(&intent, &allowed_tables).map_err(module_error)? {
            AtomicIntent::PutRow(row) => {
                let context_update_event_id = context_update_event_id_from_row(&row)?;
                let inserted = store.insert_table_rows_in_tx(vec![row])?;
                applied += inserted;
                if inserted > 0 {
                    if let Some(event_id) = context_update_event_id {
                        enqueue_context_update_reprojections_in_tx(store, &event_id)?;
                    }
                }
            }
            AtomicIntent::DeleteRow(delete) => {
                applied += store.delete_table_rows_in_tx(delete.table, vec![delete.key])?;
            }
        }
    }
    Ok(applied)
}

fn count_atomic_puts(changes: &ProjectionOutput, table: TableName) -> rusqlite::Result<usize> {
    let allowed_tables = projection_allowed_tables();
    let mut count = 0usize;
    for intent in &changes.as_core().intents {
        match AtomicIntent::from_intent(intent, &allowed_tables).map_err(module_error)? {
            AtomicIntent::PutRow(row) if row.table == table => count += 1,
            _ => {}
        }
    }
    Ok(count)
}

fn context_update_event_id_from_row(row: &TableRow) -> rusqlite::Result<Option<EventId>> {
    if row.table != rows::CONTEXT_UPDATES {
        return Ok(None);
    }
    if row.key.len() < 32 {
        return Err(module_error(
            "context update row key is shorter than event id".to_string(),
        ));
    }
    let mut event_id = [0u8; 32];
    event_id.copy_from_slice(&row.key[..32]);
    Ok(Some(event_id))
}

fn decode_context_update_row(row: &TableRow) -> rows::ContextUpdate {
    let mut event_id = [0u8; 32];
    event_id.copy_from_slice(&row.key[..32]);
    rows::ContextUpdate {
        event_id,
        update: row.value.clone(),
    }
}

fn projection_allowed_tables() -> Vec<TableName> {
    crate::legacy::protocol::event_modules::schemas()
        .into_iter()
        .chain(worker_rows::SCHEMAS.iter().copied())
        .chain(network_queues::SCHEMAS.iter().copied())
        .filter_map(|rows| match rows.definition {
            SchemaDefinition::RowTable(table) => Some(table),
            SchemaDefinition::Sql(_) => None,
        })
        .collect()
}

fn enqueue_context_update_reprojections_in_tx(
    store: &Store,
    event_id: &EventId,
) -> rusqlite::Result<usize> {
    let mut rows = vec![worker_rows::pending_reprojection_row(*event_id)];
    for dependent in event_lifecycle::direct_dependents(store, event_id)? {
        rows.push(worker_rows::pending_reprojection_row(dependent));
    }
    store.insert_table_rows_in_tx(rows)
}

fn drain_ready(
    store: &Store,
    modules: &impl EventRegistry,
    limit: usize,
) -> Result<ApplyReadyReport, String> {
    store
        .write_transaction(|store| {
            let mut total = ApplyReadyReport::default();
            let mut processed = 0usize;
            while processed < limit {
                let Some(event_id) = event_lifecycle::next_ready_event(store)? else {
                    break;
                };
                let report = project_ready_event_tx(store, modules, &event_id)?;
                processed += report.applied_events + report.blocked_events;
                total.applied_events += report.applied_events;
                total.unblocked_events += report.unblocked_events;
                total.blocked_events += report.blocked_events;
                total.blocked_edges += report.blocked_edges;
                if report.applied_events == 0 && report.blocked_events == 0 {
                    break;
                }
            }
            Ok(total)
        })
        .map_err(|err| format!("drain ready events: {err}"))
}

fn drain_until_idle(
    store: &Store,
    modules: &impl EventRegistry,
    batch_size: usize,
) -> Result<ApplyReadyReport, String> {
    let mut total = ApplyReadyReport::default();
    loop {
        let report = drain_ready(store, modules, batch_size)?;
        let reproject = drain_pending_reprojections(store, modules, batch_size)?;
        let unblock = drain_recently_valid_events(store, batch_size)?;
        total.applied_events += report.applied_events + reproject.applied_events;
        total.unblocked_events += report.unblocked_events + unblock.unblocked_events;
        total.reprojected_events +=
            report.reprojected_events + reproject.reprojected_events + unblock.reprojected_events;
        total.blocked_events +=
            report.blocked_events + reproject.blocked_events + unblock.blocked_events;
        total.blocked_edges +=
            report.blocked_edges + reproject.blocked_edges + unblock.blocked_edges;
        if report.applied_events == 0
            && reproject.reprojected_events == 0
            && unblock.unblocked_events == 0
        {
            return Ok(total);
        }
    }
}

fn module_error(err: String) -> rusqlite::Error {
    rusqlite::Error::InvalidParameterName(err)
}

const WAIT_FOR_DEPENDENCY_PREFIX: &str = "__wait_for_dependency__:";

fn wait_for_dependency_error(event_id: &EventId) -> String {
    format!("{WAIT_FOR_DEPENDENCY_PREFIX}{}", hex_event_id(event_id))
}

pub(crate) fn is_wait_for_dependency_error(err: &str) -> bool {
    err.starts_with(WAIT_FOR_DEPENDENCY_PREFIX)
}

fn hex_event_id(event_id: &EventId) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(64);
    for byte in event_id {
        out.push(DIGITS[(byte >> 4) as usize] as char);
        out.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    out
}

fn unique_dependencies(dependencies: &[EventId]) -> Vec<EventId> {
    let mut dependencies = dependencies.to_vec();
    dependencies.sort();
    dependencies.dedup();
    dependencies
}

fn wait_dependencies_for(
    store: &Store,
    record: &EventRecord,
    dependencies: Vec<EventId>,
) -> rusqlite::Result<Vec<EventId>> {
    let declared = unique_dependencies(&record.dependencies);
    let mut waiting = Vec::new();
    for dependency in unique_dependencies(&dependencies) {
        if !declared.contains(&dependency) {
            continue;
        }
        if !event_lifecycle::event_is_applied(store, &dependency)? {
            waiting.push(dependency);
        }
    }
    Ok(waiting)
}

fn write_blockers(
    store: &Store,
    event_id: &EventId,
    missing: &[EventId],
) -> rusqlite::Result<usize> {
    let mut inserted = 0;
    for dependency in missing {
        inserted += usize::from(event_lifecycle::insert_blocked_event_missing_dep(
            store, dependency, event_id,
        )?);
    }
    Ok(inserted)
}

fn unblock_dependents(store: &Store, applied_event_id: &EventId) -> rusqlite::Result<usize> {
    let dependents = event_lifecycle::blocked_events_by_missing_dep(store, applied_event_id)?;
    event_lifecycle::delete_blocked_events_by_missing_dep(store, applied_event_id)?;

    let mut unblocked = 0;
    for dependent in dependents {
        // Unblocking only changes status. It does not recursively project the
        // newly unblocked canonical inside the same stack frame, which prevents a large
        // dependency cascade from becoming one unbounded transaction.
        if !event_lifecycle::blocked_event_has_missing_deps(store, &dependent)?
            && event_lifecycle::set_event_status(
                store,
                &dependent,
                EventStatus::Blocked,
                EventStatus::Ready,
            )?
        {
            unblocked += 1;
        }
    }
    Ok(unblocked)
}
