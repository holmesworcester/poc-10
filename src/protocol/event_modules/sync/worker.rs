use crate::core::store::{EventRecord, Store};
use crate::protocol::event_modules::connection;
use crate::protocol::event_modules::worker::CommandOutput;

use super::{compare, frame};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Work {
    Start,
    IngestFrame {
        connection_id: connection::types::ConnectionId,
        bytes: Vec<u8>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Output {
    Started(CommandOutput<SyncStartReport>),
    IngestedFrame(SyncFrameReport),
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SyncStartReport {
    pub sent_events: usize,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SyncFrameReport {
    pub events: Vec<EventRecord>,
    pub sent_events: usize,
    pub received_events: usize,
    pub received_event_bytes: Vec<Vec<u8>>,
}

pub fn run(store: &Store, work: Work) -> Result<Output, String> {
    match work {
        Work::Start => start(store).map(Output::Started),
        Work::IngestFrame {
            connection_id,
            bytes,
        } => ingest_frame(store, connection_id, &bytes).map(Output::IngestedFrame),
    }
}

fn start(store: &Store) -> Result<CommandOutput<SyncStartReport>, String> {
    let routes = connection::transport_target::queries::routes(store)?;
    if routes.is_empty() {
        return Ok(CommandOutput::new(SyncStartReport::default()));
    }
    let mut events = Vec::new();
    let mut sent_events = 0;
    for route in routes {
        let report = compare::commands::start(store, route.connection_id, |bytes| {
            events.push(frame::codec::record_from_bytes(bytes)?);
            Ok(())
        })?;
        sent_events += report.sent_events;
    }
    Ok(CommandOutput::with_events(
        SyncStartReport { sent_events },
        events,
    ))
}

fn ingest_frame(
    store: &Store,
    connection_id: connection::types::ConnectionId,
    bytes: &[u8],
) -> Result<SyncFrameReport, String> {
    let mut result = SyncFrameReport::default();
    let report = compare::commands::ingest_frame(store, connection_id, bytes, |bytes| {
        result.events.push(frame::codec::record_from_bytes(bytes)?);
        Ok(())
    })?;
    result.sent_events += report.sent_events;
    result.received_events += report.received_events;
    result.received_event_bytes = report.received_event_bytes;
    Ok(result)
}
