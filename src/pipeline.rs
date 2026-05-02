use std::net::SocketAddr;

use crate::blocking;
use crate::event_modules::{connection, sync};
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

pub fn start_sync(
    store: &Store,
    route: connection::transport_target::types::TransportRoute,
) -> Result<IngestResult, String> {
    let mut result = IngestResult::default();
    let report = sync::compare::commands::start(store, route.connection_id, |bytes| {
        result
            .outgoing
            .push(connection::transit::commands::create_connection(
                store,
                route.connection_id,
                bytes,
            )?);
        Ok(())
    })?;
    result.sent_events += report.sent_events;
    result.received_events += report.received_events;
    Ok(result)
}

pub fn ingest_frame(
    store: &Store,
    origin: SocketAddr,
    bytes: Vec<u8>,
    options: IngestOptions,
) -> Result<IngestResult, String> {
    let transit = connection::transit::projector::unwrap(store, &bytes)?;
    if connection::connection_record::types::is_connection_event(&transit.inner) {
        return ingest_connection_frame(store, origin, transit.inner, options);
    }
    let connection_id = transit
        .connection_id
        .ok_or_else(|| "sync frame requires connection transit".to_string())?;
    ingest_sync_frame(store, connection_id, &transit.inner)
}

fn ingest_connection_frame(
    store: &Store,
    origin: SocketAddr,
    bytes: Vec<u8>,
    options: IngestOptions,
) -> Result<IngestResult, String> {
    let mut result = IngestResult::default();
    let connection = if connection::connection_request::codec::is_request(&bytes) {
        connection::connection_request::commands::accept(store, bytes)?
    } else if connection::connection_ack::codec::is_ack(&bytes) {
        connection::connection_ack::commands::accept(store, bytes)?
    } else {
        return Err("unknown connection event".to_string());
    };
    if let Some(bytes) = connection.response {
        result.outgoing.push(bytes);
    }
    if let Some(connection_id) = connection.connection_id {
        if options.record_transport_target {
            connection::transport_target::commands::record(store, connection_id, origin)?;
        }
        result.established_connections += 1;
    }
    Ok(result)
}

fn ingest_sync_frame(
    store: &Store,
    connection_id: connection::connection_record::types::ConnectionId,
    bytes: &[u8],
) -> Result<IngestResult, String> {
    let mut result = IngestResult::default();
    let report = sync::compare::commands::ingest_frame(store, connection_id, bytes, |bytes| {
        result
            .outgoing
            .push(connection::transit::commands::create_connection(
                store,
                connection_id,
                bytes,
            )?);
        Ok(())
    })?;
    admit_received_event_bytes(store, report.received_event_bytes)?;
    result.sent_events += report.sent_events;
    result.received_events += report.received_events;
    Ok(result)
}

fn admit_received_event_bytes(store: &Store, events: Vec<Vec<u8>>) -> Result<(), String> {
    if events.is_empty() {
        return Ok(());
    }
    let mut records = Vec::with_capacity(events.len());
    for bytes in events {
        records.push(crate::event_modules::record_from_bytes(bytes)?);
    }
    admit_records(store, records)?;
    Ok(())
}
