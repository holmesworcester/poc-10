//! Common event-module worker.
//!
//! This module is the narrow gate between canonical event bytes and projected
//! protocol state. It is intentionally boring: admit an event, wait for its
//! dependencies, call exactly one projector through the registry, and write the
//! rows the projector returned. That shape is the defense against the kernel
//! becoming a second protocol implementation.
//!
//! The worker does not know what any concrete event family means. Those meanings
//! live in event modules. The worker only knows the protocol-wide mechanics that
//! every canonical event shares:
//!
//! ```text
//! command -> ProposedEvent
//!          -> admit canonical bytes by deterministic event id
//!          -> block until dependency event ids are applied
//!          -> project ready events into rows
//!          -> mark newly unblocked events ready
//! ```
//!
//! Network input follows the same rule. Core TCP writes opaque bytes into a core
//! inbound queue. The protocol registry asks the owning domain workers to
//! interpret those bytes, but any surviving canonical event bytes come back here
//! for ordinary admission. Network output is also kept outside projection:
//! projectors may write protocol queue rows, and a domain worker later turns
//! those rows into core network queue rows.
//!
//! Future maintainers should be suspicious of changes that make this file more
//! knowledgeable. Domain-specific branching here is usually a sign that an event
//! module is missing a codec, projector, command, query, table, or domain worker.
//! The important invariant is not that this file stays tiny; it is that it stays
//! mechanical enough to audit.

use crate::core::network_queues::{self, InboundNetworkRow, OutboundNetworkRow};
use crate::core::store::{
    event_id, EventId, EventRecord, EventScope, EventStatus, Store, TableRow,
};

use super::Modules;

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
}

impl ProposedEvent {
    pub fn new(record: EventRecord) -> Self {
        Self {
            event_id: event_id(&record.canonical_bytes),
            record,
        }
    }

    pub fn event_id(&self) -> EventId {
        self.event_id
    }

    pub fn record(&self) -> &EventRecord {
        &self.record
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

/// Declarative output of a projector.
///
/// A projector may only return table rows. It may not emit more events, call a
/// worker, send bytes, or query broad state. If projection appears to need one
/// of those powers, the event module should write a queue row and let its domain
/// worker perform the active step later.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProjectionOutput {
    pub rows: Vec<TableRow>,
}

impl ProjectionOutput {
    pub fn rows(rows: Vec<TableRow>) -> Self {
        Self { rows }
    }

    pub fn append(&mut self, mut other: Self) {
        self.rows.append(&mut other.rows);
    }
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
}

/// Protocol registry used by the common worker.
///
/// This trait is the only place where the generic admission/apply loop touches
/// concrete event modules. `record_from_bytes` chooses the module codec.
/// `project_record` chooses the module projector. Keeping those decisions
/// behind the registry lets this worker enforce common mechanics without
/// learning event-type vocabulary.
pub trait EventRegistry {
    fn record_from_bytes(&self, bytes: Vec<u8>) -> Result<EventRecord, String>;
    fn project_record(
        &self,
        store: &Store,
        record: &EventRecord,
    ) -> Result<ProjectionOutput, String>;
}

/// Unit of work accepted by the worker runner.
///
/// Work values are small boundary objects: "admit these records", "drain ready
/// events", "ingest this inbound frame". They keep callers from reaching into
/// helper functions and make the public entrypoint read like a scheduler.
pub trait Work<R: EventRegistry> {
    type Output;

    fn execute(self, store: &Store, registry: &R) -> Result<Self::Output, String>;
}

/// Admit already-decoded records through normal dependency handling.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmitRecords {
    pub records: Vec<EventRecord>,
}

/// Drain ready durable events until no ready event remains.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DrainUntilIdle {
    pub batch_size: usize,
}

/// Ingest one opaque network frame from the core inbound queue.
///
/// The source metadata is transport-level information only. `remember_origin`
/// controls whether an owning domain should record this source as a usable
/// route; replayed or synthetic frames can disable that side effect.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IngestFrame {
    pub inbound: InboundNetworkRow,
    pub remember_origin: bool,
}

/// Summary of inbound-frame processing.
///
/// `outgoing` contains opaque bytes ready for the core outbound queue.
/// `sent_outbox` contains protocol outbox row keys that may be removed after the
/// bytes have been queued for transport. The remaining counters are observability
/// for CLI tests and logs; they are not control signals.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IngestResult {
    pub outgoing: Vec<OutboundNetworkRow>,
    pub sent_outbox: Vec<Vec<u8>>,
    pub established_routes: usize,
    pub sent_events: usize,
    pub received_events: usize,
}

/// Summary of event admission and any immediately-applied events.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AdmitReport {
    pub event_ids: Vec<EventId>,
    pub inserted_events: usize,
    pub ready_events: usize,
    pub blocked_events: usize,
    pub blocked_edges: usize,
    pub applied_events: usize,
}

/// Summary of a ready-event drain.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ApplyReadyReport {
    pub applied_events: usize,
    pub unblocked_events: usize,
}

/// Run one common event-module worker action.
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

impl<T, R> Work<R> for CommandOutput<T>
where
    R: EventRegistry,
{
    type Output = (T, AdmitReport);

    fn execute(self, store: &Store, registry: &R) -> Result<Self::Output, String> {
        run_command(store, registry, self)
    }
}

impl<R> Work<R> for AdmitRecords
where
    R: EventRegistry,
{
    type Output = AdmitReport;

    fn execute(self, store: &Store, registry: &R) -> Result<Self::Output, String> {
        admit_records(store, registry, self.records)
    }
}

impl<R> Work<R> for DrainUntilIdle
where
    R: EventRegistry,
{
    type Output = ApplyReadyReport;

    fn execute(self, store: &Store, registry: &R) -> Result<Self::Output, String> {
        drain_until_idle(store, registry, self.batch_size)
    }
}

impl Work<Modules> for IngestFrame {
    type Output = IngestResult;

    fn execute(self, store: &Store, modules: &Modules) -> Result<Self::Output, String> {
        ingest_frame(store, modules, self)
    }
}

fn ingest_frame(
    store: &Store,
    modules: &Modules,
    work: IngestFrame,
) -> Result<IngestResult, String> {
    // Domain workers may return two kinds of things:
    //
    // * canonical event records they constructed directly;
    // * raw canonical bytes recovered from an opaque wrapper and still needing
    //   normal codec dispatch.
    //
    // Both are admitted below before any outbox drain, so replies see the state
    // caused by the inbound frame that triggered them.
    let mut report = modules.ingest_frame(
        store,
        work.inbound.source.addr(),
        work.remember_origin,
        work.inbound.bytes,
    )?;
    report.events.extend(received_event_records(
        modules,
        report.received_event_bytes,
    )?);
    let outbox = report.drain_outbox_for;
    admit_records(store, modules, report.events)?;

    // Network targets are concrete transport routes. Any protocol-level route
    // identifier must have been resolved before bytes cross into the core
    // outbound queue.
    let target = network_queues::NetworkTarget::new(work.inbound.source.addr());
    let mut outgoing = network_queues::outbound_rows(target, report.outgoing);
    let mut sent_outbox = Vec::new();
    if let Some(route_id) = outbox {
        // For an inbound request on an open socket, drain only the route that
        // can reply on that socket. General background draining is owned by the
        // owning domain worker.
        let drained = modules.drain_outbox_for_route(store, route_id)?;
        outgoing.extend(network_queues::outbound_rows(target, drained.outgoing));
        sent_outbox.extend(drained.sent_outbox);
    }
    Ok(IngestResult {
        outgoing,
        sent_outbox,
        established_routes: report.established_routes,
        sent_events: report.sent_events,
        received_events: report.received_events,
    })
}

fn received_event_records(
    modules: &Modules,
    events: Vec<Vec<u8>>,
) -> Result<Vec<EventRecord>, String> {
    if events.is_empty() {
        return Ok(Vec::new());
    }
    let mut records = Vec::with_capacity(events.len());
    for bytes in events {
        records.push(modules.record_from_bytes(bytes)?);
    }
    Ok(records)
}

fn run_command<T>(
    store: &Store,
    modules: &impl EventRegistry,
    output: CommandOutput<T>,
) -> Result<(T, AdmitReport), String> {
    let report = admit_proposed_events(store, modules, output.events)?;
    Ok((output.value, report))
}

fn admit_records(
    store: &Store,
    modules: &impl EventRegistry,
    records: Vec<EventRecord>,
) -> Result<AdmitReport, String> {
    admit_proposed_events(
        store,
        modules,
        records.into_iter().map(ProposedEvent::new).collect(),
    )
}

fn admit_proposed_events(
    store: &Store,
    modules: &impl EventRegistry,
    events: Vec<ProposedEvent>,
) -> Result<AdmitReport, String> {
    store
        .write_transaction(|store| {
            let mut report = AdmitReport::default();
            admit_events_in_tx(store, modules, events, &mut report)?;
            Ok(report)
        })
        .map_err(|err| format!("admit events: {err}"))
}

fn apply_changes_in_tx(store: &Store, changes: ProjectionOutput) -> rusqlite::Result<usize> {
    store.insert_table_rows_in_tx(changes.rows)
}

fn admit_events_in_tx(
    store: &Store,
    modules: &impl EventRegistry,
    events: Vec<ProposedEvent>,
    report: &mut AdmitReport,
) -> rusqlite::Result<()> {
    for event in events {
        admit_and_apply_event_in_tx(store, modules, &event, report)?;
    }
    Ok(())
}

fn admit_and_apply_event_in_tx(
    store: &Store,
    modules: &impl EventRegistry,
    event: &ProposedEvent,
    report: &mut AdmitReport,
) -> rusqlite::Result<()> {
    let record = event.record();
    report.event_ids.push(event.event_id());
    if record.scope == EventScope::Transient {
        // Transient events are canonical enough to project and dedupe inside the
        // current process, but they are not durable facts. Letting them wait on
        // durable dependencies would create hidden state that cannot be resumed
        // after a crash.
        if !record.dependencies.is_empty() {
            return Err(module_error(
                "transient events cannot wait on durable dependencies".to_string(),
            ));
        }
        let changes = modules
            .project_record(store, record)
            .map_err(module_error)?;
        apply_changes_in_tx(store, changes)?;
        report.applied_events += 1;
        return Ok(());
    }

    let admitted = admit_event_in_tx(store, event, report)?;
    if admitted.inserted && admitted.ready {
        let apply = apply_ready_event_in_tx(store, modules, &admitted.event_id)?;
        report.applied_events += apply.applied_events;
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Admission {
    event_id: EventId,
    inserted: bool,
    ready: bool,
}

fn admit_event_in_tx(
    store: &Store,
    event: &ProposedEvent,
    report: &mut AdmitReport,
) -> rusqlite::Result<Admission> {
    let record = event.record();
    let id = event.event_id();
    let missing = missing_dependencies(store, &record.dependencies)?;
    let status = if missing.is_empty() {
        EventStatus::Ready
    } else {
        EventStatus::Blocked
    };

    let inserted = store.insert_event(record, status)?;
    if inserted {
        report.inserted_events += 1;
        if missing.is_empty() {
            report.ready_events += 1;
        } else {
            report.blocked_events += 1;
            report.blocked_edges += write_blockers(store, &id, &missing)?;
        }
    }
    Ok(Admission {
        event_id: id,
        inserted,
        ready: missing.is_empty(),
    })
}

fn apply_ready_event_in_tx(
    store: &Store,
    modules: &impl EventRegistry,
    event_id: &EventId,
) -> rusqlite::Result<ApplyReadyReport> {
    let mut report = ApplyReadyReport::default();
    if store.set_event_status(event_id, EventStatus::Ready, EventStatus::Applied)? {
        // The status change is the claim. Projection runs only for the worker
        // that successfully moved Ready -> Applied, which keeps duplicate drain
        // attempts idempotent when callers retry.
        let bytes = store
            .event_bytes(event_id)?
            .ok_or(rusqlite::Error::QueryReturnedNoRows)?;
        let record = modules.record_from_bytes(bytes).map_err(module_error)?;
        let changes = modules
            .project_record(store, &record)
            .map_err(module_error)?;
        apply_changes_in_tx(store, changes)?;
        report.applied_events = 1;
        report.unblocked_events = unblock_dependents(store, event_id)?;
    }
    Ok(report)
}

fn drain_ready(
    store: &Store,
    modules: &impl EventRegistry,
    limit: usize,
) -> Result<ApplyReadyReport, String> {
    store
        .write_transaction(|store| {
            let mut total = ApplyReadyReport::default();
            while total.applied_events < limit {
                let Some(event_id) = store.next_ready_event()? else {
                    break;
                };
                let report = apply_ready_event_in_tx(store, modules, &event_id)?;
                total.applied_events += report.applied_events;
                total.unblocked_events += report.unblocked_events;
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
        total.applied_events += report.applied_events;
        total.unblocked_events += report.unblocked_events;
        if report.applied_events == 0 {
            return Ok(total);
        }
    }
}

fn module_error(err: String) -> rusqlite::Error {
    rusqlite::Error::InvalidParameterName(err)
}

fn missing_dependencies(store: &Store, dependencies: &[EventId]) -> rusqlite::Result<Vec<EventId>> {
    let mut dependencies = dependencies.to_vec();
    dependencies.sort();
    dependencies.dedup();

    let mut missing = Vec::new();
    for dependency in dependencies {
        if !store.event_is_applied(&dependency)? {
            missing.push(dependency);
        }
    }
    Ok(missing)
}

fn write_blockers(
    store: &Store,
    event_id: &EventId,
    missing: &[EventId],
) -> rusqlite::Result<usize> {
    let mut inserted = 0;
    for dependency in missing {
        inserted += usize::from(store.insert_dependency_wait(dependency, event_id)?);
    }
    Ok(inserted)
}

fn unblock_dependents(store: &Store, applied_event_id: &EventId) -> rusqlite::Result<usize> {
    let dependents = store.events_waiting_on(applied_event_id)?;
    store.delete_dependency_waits_for(applied_event_id)?;

    let mut unblocked = 0;
    for dependent in dependents {
        // Unblocking only changes status. It does not recursively project the
        // dependent event inside the same stack frame, which prevents a large
        // dependency cascade from becoming one unbounded transaction.
        if !store.event_has_dependency_waits(&dependent)?
            && store.set_event_status(&dependent, EventStatus::Blocked, EventStatus::Ready)?
        {
            unblocked += 1;
        }
    }
    Ok(unblocked)
}
