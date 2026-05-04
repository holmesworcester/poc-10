use crate::core::blocking;
use crate::core::store::{
    CommandOutput, EventId, EventRecord, EventScope, EventStatus, ProjectionOutput, ProposedEvent,
    Store,
};

pub trait EventRegistry {
    fn record_from_bytes(&self, bytes: Vec<u8>) -> Result<EventRecord, String>;
    fn project_record(
        &self,
        store: &Store,
        record: &EventRecord,
    ) -> Result<ProjectionOutput, String>;
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AdmitReport {
    pub event_ids: Vec<EventId>,
    pub inserted_events: usize,
    pub ready_events: usize,
    pub blocked_events: usize,
    pub blocked_edges: usize,
    pub applied_events: usize,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ApplyReadyReport {
    pub applied_events: usize,
    pub unblocked_events: usize,
}

pub fn apply_changes(store: &Store, changes: ProjectionOutput) -> Result<usize, String> {
    store
        .write_transaction(|store| apply_changes_in_tx(store, changes))
        .map_err(|err| format!("apply state changes: {err}"))
}

pub fn run_command<T>(
    store: &Store,
    modules: &impl EventRegistry,
    output: CommandOutput<T>,
) -> Result<(T, AdmitReport), String> {
    let report = admit_proposed_events(store, modules, output.events)?;
    Ok((output.value, report))
}

pub fn admit_records(
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

pub fn admit_proposed_events(
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
    let missing = blocking::missing_dependencies(store, &record.dependencies)?;
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
            report.blocked_edges += blocking::write_blockers(store, &id, &missing)?;
        }
    }
    Ok(Admission {
        event_id: id,
        inserted,
        ready: missing.is_empty(),
    })
}

pub fn apply_ready_event_in_tx(
    store: &Store,
    modules: &impl EventRegistry,
    event_id: &EventId,
) -> rusqlite::Result<ApplyReadyReport> {
    let mut report = ApplyReadyReport::default();
    if store.set_event_status(event_id, EventStatus::Ready, EventStatus::Applied)? {
        let bytes = store
            .event_bytes(event_id)?
            .ok_or(rusqlite::Error::QueryReturnedNoRows)?;
        let record = modules.record_from_bytes(bytes).map_err(module_error)?;
        let changes = modules
            .project_record(store, &record)
            .map_err(module_error)?;
        apply_changes_in_tx(store, changes)?;
        report.applied_events = 1;
        report.unblocked_events = blocking::unblock_dependents(store, event_id)?;
    }
    Ok(report)
}

fn module_error(err: String) -> rusqlite::Error {
    rusqlite::Error::InvalidParameterName(err)
}
