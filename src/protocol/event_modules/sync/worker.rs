//! Sync worker.
//!
//! Sync is an active protocol, not a projector side effect. Projectors write the
//! rows that make sync possible; this worker performs the stateful comparison
//! work and turns its answers back into normal event records. That keeps
//! negentropy out of the kernel while still making every sync message pass
//! through the same event/module discipline as durable content.
//!
//! The current POC has two wake shapes:
//!
//! ```text
//! manual sync start -> compare command for each known connection route
//! inbound sync frame -> compare ingest command for that connection
//! ```
//!
//! Both paths produce connection-scoped sync frame events. Those events are
//! transient protocol facts: they can be projected into the connection outbox,
//! wrapped by the connection worker, and deduped while queued, but they are not
//! part of the durable content history. Durable events received through sync are
//! returned as raw canonical bytes and are admitted by the common event-module
//! worker, not by the sync code.
//!
//! A future dep-aware worker will probably have more queues and cursors, but it
//! should preserve this boundary: sync may query sync-owned indexes and propose
//! sync events; it should not perform TCP IO, mutate content projections, or
//! bypass normal event admission.

use crate::core::store::{EventRecord, Store};
use crate::protocol::event_modules::connection;
use crate::protocol::event_modules::worker::CommandOutput;

use super::{compare, frame};

/// Work accepted by the sync worker.
///
/// `Start` is intentionally explicit because the current control loop is still
/// CLI-driven. `IngestFrame` handles one already-unwrapped sync frame under the
/// connection id recovered by the connection worker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Work {
    Start,
    IngestFrame {
        connection_id: connection::types::ConnectionId,
        bytes: Vec<u8>,
    },
}

/// Result of a sync worker action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Output {
    Started(CommandOutput<SyncStartReport>),
    IngestedFrame(SyncFrameReport),
}

/// Summary of a manual sync start.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SyncStartReport {
    pub sent_events: usize,
}

/// Records and received bytes produced by handling one sync frame.
///
/// `events` are connection-scoped sync frame records that should be admitted so
/// their projector can queue them for connection transit. `received_event_bytes`
/// are durable canonical events learned from the peer and must be admitted by
/// the common event-module worker.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SyncFrameReport {
    pub events: Vec<EventRecord>,
    pub sent_events: usize,
    pub received_events: usize,
    pub received_event_bytes: Vec<Vec<u8>>,
}

/// Run one sync worker action.
///
/// The only public entrypoint mirrors the other workers. Adding a new sync wake
/// should add a `Work` variant and keep the command/query/projection boundary
/// visible here.
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
    // Manual sync fans out over known routes. The route table is owned by the
    // connection domain; sync only borrows the connection id needed to make a
    // connection-scoped compare event.
    let routes = connection::transport_target::queries::routes(store)?;
    if routes.is_empty() {
        return Ok(CommandOutput::new(SyncStartReport::default()));
    }
    let mut events = Vec::new();
    let mut sent_events = 0;
    for route in routes {
        // Compare commands stream outgoing frame bytes through a callback. The
        // worker immediately reifies each frame as an event record so the rest
        // of the system sees ordinary event-module output, not ad hoc protocol
        // messages.
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
    // Inbound compare handling may both request/send more sync frames and
    // deliver durable event bytes. Keep those channels separate: response
    // frames become transient sync events; durable bytes go through normal
    // admission after this worker returns.
    let report = compare::commands::ingest_frame(store, connection_id, bytes, |bytes| {
        result.events.push(frame::codec::record_from_bytes(bytes)?);
        Ok(())
    })?;
    result.sent_events += report.sent_events;
    result.received_events += report.received_events;
    result.received_event_bytes = report.received_event_bytes;
    Ok(result)
}
