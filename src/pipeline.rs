use crate::blocking;
use crate::event_modules::Modules;
use crate::store::{
    event_id, CommandOutput, EventId, EventRecord, EventStatus, StateChanges, Store,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameMetadata {
    pub origin: std::net::SocketAddr,
    pub remember_origin: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IngestResult {
    pub outgoing: Vec<Vec<u8>>,
    pub established_routes: usize,
    pub sent_events: usize,
    pub received_events: usize,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AdmitReport {
    pub inserted_events: usize,
    pub ready_events: usize,
    pub blocked_events: usize,
    pub blocked_edges: usize,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ApplyReadyReport {
    pub applied_events: usize,
    pub unblocked_events: usize,
}

pub fn apply_changes(store: &Store, changes: StateChanges) -> Result<AdmitReport, String> {
    store
        .write_transaction(|store| {
            let mut report = AdmitReport::default();
            store.insert_table_rows_in_tx(changes.rows)?;
            for record in changes.events {
                admit_record_in_tx(store, &record, &mut report)?;
            }
            Ok(report)
        })
        .map_err(|err| format!("apply state changes: {err}"))
}

pub fn run_command<T>(store: &Store, output: CommandOutput<T>) -> Result<(T, AdmitReport), String> {
    let report = apply_changes(store, output.changes)?;
    Ok((output.value, report))
}

pub fn admit_records(store: &Store, records: Vec<EventRecord>) -> Result<AdmitReport, String> {
    apply_changes(store, StateChanges::events(records))
}

fn admit_record_in_tx(
    store: &Store,
    record: &EventRecord,
    report: &mut AdmitReport,
) -> rusqlite::Result<()> {
    let id = event_id(&record.canonical_bytes);
    let missing = blocking::missing_dependencies(store, &record.dependencies)?;
    let status = if missing.is_empty() {
        EventStatus::Ready
    } else {
        EventStatus::Blocked
    };

    if store.insert_event(record, status)? {
        report.inserted_events += 1;
        if missing.is_empty() {
            report.ready_events += 1;
        } else {
            report.blocked_events += 1;
            report.blocked_edges += blocking::write_blockers(store, &id, &missing)?;
        }
    }
    Ok(())
}

pub fn apply_ready_event_in_tx(
    store: &Store,
    event_id: &EventId,
) -> rusqlite::Result<ApplyReadyReport> {
    let mut report = ApplyReadyReport::default();
    if store.set_event_status(event_id, EventStatus::Ready, EventStatus::Applied)? {
        report.applied_events = 1;
        report.unblocked_events = blocking::unblock_dependents(store, event_id)?;
    }
    Ok(report)
}

pub fn ingest_frame(
    store: &Store,
    modules: &Modules,
    metadata: FrameMetadata,
    bytes: Vec<u8>,
) -> Result<IngestResult, String> {
    let mut report =
        modules.ingest_frame(store, metadata.origin, metadata.remember_origin, bytes)?;
    report.changes.append(received_event_changes(
        modules,
        report.received_event_bytes,
    )?);
    apply_changes(store, report.changes)?;
    Ok(IngestResult {
        outgoing: report.outgoing,
        established_routes: report.established_routes,
        sent_events: report.sent_events,
        received_events: report.received_events,
    })
}

fn received_event_changes(modules: &Modules, events: Vec<Vec<u8>>) -> Result<StateChanges, String> {
    if events.is_empty() {
        return Ok(StateChanges::default());
    }
    let mut records = Vec::with_capacity(events.len());
    for bytes in events {
        records.push(modules.record_from_bytes(bytes)?);
    }
    Ok(StateChanges::events(records))
}
