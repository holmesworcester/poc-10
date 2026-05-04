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
//! projected inbound sync event rows -> compare/have/need handler for that connection
//! ```
//!
//! Both paths produce connection-scoped sync events. Those events are
//! transient protocol facts: they can be projected into the connection outbox,
//! wrapped by the connection worker, and deduped while queued, but they are not
//! part of the durable content history. Requested durable events are queued by
//! id for the connection worker; sync does not build data packets.
//!
//! A future dep-aware worker will probably have more queues and cursors, but it
//! should preserve this boundary: sync may query sync-owned indexes and propose
//! sync events; it should not perform TCP IO, mutate content projections, or
//! bypass normal event admission.

use crate::core::store::Store;
use crate::protocol::event_modules::connection;
use crate::protocol::event_modules::types::EventRecord;
use crate::protocol::event_modules::worker::CommandOutput;

use super::{compare, queries, schema};

pub const DEFAULT_INBOUND_BATCH: usize = 1024;

/// Work accepted by the sync worker.
///
/// `Start` is intentionally explicit because the current control loop is still
/// CLI-driven. `DrainInboundSync` handles work that has already been projected
/// from transient inbound sync events.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Work {
    Start,
    DrainInboundSync {
        connection_id: connection::types::ConnectionId,
        limit: usize,
    },
}

/// Result of a sync worker action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Output {
    Started(CommandOutput<SyncStartReport>),
    DrainedInboundSync(SyncWorkReport),
}

/// Summary of a manual sync start.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SyncStartReport {
    pub sent_events: usize,
}

/// Records and durable send ids produced by handling inbound sync work.
///
/// `events` are connection-scoped sync records that should be admitted so their
/// projector can queue them for connection transit. `send_event_ids` are
/// durable shared event ids requested by the peer and queued directly to the
/// connection outbox.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SyncWorkReport {
    pub events: Vec<EventRecord>,
    pub processed_work: usize,
    pub sent_events: usize,
    pub send_event_ids: Vec<crate::protocol::event_modules::types::EventId>,
}

/// Run one sync worker action.
///
/// The only public entrypoint mirrors the other workers. Adding a new sync wake
/// should add a `Work` variant and keep the command/query/projection boundary
/// visible here.
pub fn run(store: &Store, work: Work) -> Result<Output, String> {
    match work {
        Work::Start => start(store).map(Output::Started),
        Work::DrainInboundSync {
            connection_id,
            limit,
        } => drain_inbound_events(store, connection_id, limit).map(Output::DrainedInboundSync),
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
        let report = compare::commands::start(store, route.connection_id)?;
        events.extend(report.events);
        sent_events += report.sent_events;
    }
    Ok(CommandOutput::with_events(
        SyncStartReport { sent_events },
        events,
    ))
}

fn drain_inbound_events(
    store: &Store,
    connection_id: connection::types::ConnectionId,
    limit: usize,
) -> Result<SyncWorkReport, String> {
    let mut result = SyncWorkReport::default();
    let limit = limit.max(1);
    let works = queries::inbound_events_for_connection(store, connection_id, limit)?;
    result.processed_work = works.len();
    let mut consumed = Vec::with_capacity(works.len());
    let mut outbox_rows = Vec::new();
    for work in works {
        let report =
            compare::commands::handle_inbound_event(store, work.connection_id, &work.event_bytes)?;
        result.sent_events += report.sent_events;
        result.events.extend(report.events);
        for event_id in report.send_event_ids {
            outbox_rows.push(connection::schema::outbox_row(work.connection_id, event_id));
            result.send_event_ids.push(event_id);
        }
        consumed.push(work.key());
    }
    if !outbox_rows.is_empty() {
        store
            .insert_table_rows(outbox_rows)
            .map_err(|err| format!("queue requested durable events: {err}"))?;
    }
    if !consumed.is_empty() {
        store
            .delete_table_rows(schema::INBOUND_EVENTS, consumed)
            .map_err(|err| format!("delete inbound sync events: {err}"))?;
    }
    Ok(result)
}
