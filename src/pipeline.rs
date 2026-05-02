use std::net::SocketAddr;

use crate::blocking;
use crate::event_modules::Modules;
use crate::store::{event_id, EventId, EventRecord, EventStatus, Store};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct IngestOptions {
    pub record_transport_target: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IngestResult {
    pub outgoing: Vec<Vec<u8>>,
    pub established_connections: usize,
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

pub fn admit_records(store: &Store, records: Vec<EventRecord>) -> Result<AdmitReport, String> {
    store
        .write_transaction(|store| {
            let mut report = AdmitReport::default();
            for record in records {
                admit_record_in_tx(store, &record, &mut report)?;
            }
            Ok(report)
        })
        .map_err(|err| format!("admit events: {err}"))
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

    if store.insert_event_row(record, status)? {
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
    origin: SocketAddr,
    bytes: Vec<u8>,
    options: IngestOptions,
) -> Result<IngestResult, String> {
    let transit = modules.unwrap_transit(store, &bytes)?;
    if modules.is_connection_event(&transit.inner) {
        return ingest_connection_frame(store, modules, origin, transit.inner, options);
    }
    let connection_id = transit
        .connection_id
        .ok_or_else(|| "sync frame requires connection transit".to_string())?;
    let mut result = IngestResult::default();
    let report = modules.ingest_sync_frame(store, connection_id, &transit.inner)?;
    admit_received_event_bytes(store, modules, report.received_event_bytes)?;
    result.outgoing = report.outgoing;
    result.sent_events += report.sent_events;
    result.received_events += report.received_events;
    Ok(result)
}

fn ingest_connection_frame(
    store: &Store,
    modules: &Modules,
    origin: SocketAddr,
    bytes: Vec<u8>,
    options: IngestOptions,
) -> Result<IngestResult, String> {
    let mut result = IngestResult::default();
    let connection = modules.accept_connection_event(store, bytes)?;
    if let Some(bytes) = connection.response {
        result.outgoing.push(bytes);
    }
    if let Some(connection_id) = connection.connection_id {
        if options.record_transport_target {
            modules.record_transport_target(store, connection_id, origin)?;
        }
        result.established_connections += 1;
    }
    Ok(result)
}

fn admit_received_event_bytes(
    store: &Store,
    modules: &Modules,
    events: Vec<Vec<u8>>,
) -> Result<(), String> {
    if events.is_empty() {
        return Ok(());
    }
    let mut records = Vec::with_capacity(events.len());
    for bytes in events {
        records.push(modules.record_from_bytes(bytes)?);
    }
    admit_records(store, records)?;
    Ok(())
}
