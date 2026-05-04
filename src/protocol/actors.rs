use std::net::SocketAddr;

use crate::core::control_loop::PipelineActor;
use crate::core::store::{EventRecord, Store};
use crate::protocol::event_modules::Modules;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameMetadata {
    pub origin: SocketAddr,
    pub remember_origin: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IngestResult {
    pub outgoing: Vec<Vec<u8>>,
    pub sent_outbox: Vec<Vec<u8>>,
    pub established_routes: usize,
    pub sent_events: usize,
    pub received_events: usize,
}

pub fn ingest_frame(
    store: &Store,
    modules: &Modules,
    metadata: FrameMetadata,
    bytes: Vec<u8>,
) -> Result<IngestResult, String> {
    let mut report =
        modules.ingest_frame(store, metadata.origin, metadata.remember_origin, bytes)?;
    report.events.extend(received_event_records(
        modules,
        report.received_event_bytes,
    )?);
    let outbox = report.drain_outbox_for;
    PipelineActor::new(store, modules).admit_records(report.events)?;
    let mut outgoing = report.outgoing;
    let mut sent_outbox = Vec::new();
    if let Some(route_id) = outbox {
        let drained = modules.drain_outbox_for_route(store, route_id)?;
        outgoing.extend(drained.outgoing);
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
