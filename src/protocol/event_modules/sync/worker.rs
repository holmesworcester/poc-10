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
use crate::protocol::event_modules::schema as event_schema;
use crate::protocol::event_modules::types::EventRecord;
use crate::protocol::event_modules::worker::CommandOutput;

use super::{compare, schema};

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
    let connections = connection_ids_with_routes(store)?;
    if connections.is_empty() {
        return Ok(CommandOutput::new(SyncStartReport::default()));
    }
    let mut events = Vec::new();
    let mut sent_events = 0;
    let context = StoreSyncContext { store };
    for connection_id in connections {
        let report = compare::commands::start(&context, connection_id)?;
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
    let works = inbound_events_for_connection(store, connection_id, limit)?;
    result.processed_work = works.len();
    let mut consumed = Vec::with_capacity(works.len());
    let mut outbox_rows = Vec::new();
    for work in works {
        let context = StoreSyncContext { store };
        let report = compare::commands::handle_inbound_event(
            &context,
            work.connection_id,
            &work.event_bytes,
        )?;
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

struct StoreSyncContext<'a> {
    store: &'a Store,
}

impl compare::commands::ReadContext for StoreSyncContext<'_> {
    fn summary(&self) -> Result<[compare::types::BucketSummary; compare::types::BUCKETS], String> {
        let mut summary = [compare::types::BucketSummary::default(); compare::types::BUCKETS];
        for header in event_schema::event_index_entries(self.store)
            .map_err(|err| format!("load event headers: {err}"))?
        {
            let bucket = &mut summary[usize::from(header.partition)];
            bucket.count += 1;
            xor_into(&mut bucket.fingerprint, &fingerprint_id(&header.event_id));
        }
        Ok(summary)
    }

    fn ids_in_bucket(
        &self,
        bucket: u8,
    ) -> Result<Vec<crate::protocol::event_modules::types::EventId>, String> {
        event_schema::event_ids_in_partition(self.store, bucket)
            .map_err(|err| format!("load bucket ids: {err}"))
    }

    fn has_event(
        &self,
        event_id: &crate::protocol::event_modules::types::EventId,
    ) -> Result<bool, String> {
        event_schema::has_shared_event(self.store, event_id)
            .map_err(|err| format!("check event presence: {err}"))
    }
}

fn connection_ids_with_routes(
    store: &Store,
) -> Result<Vec<connection::types::ConnectionId>, String> {
    store
        .table_rows(connection::schema::TRANSPORT_TARGETS)
        .map_err(|err| format!("load transport targets: {err}"))?
        .into_iter()
        .map(|(key, _)| connection::types::connection_id_from_bytes(&key))
        .collect()
}

fn inbound_events_for_connection(
    store: &Store,
    connection_id: connection::types::ConnectionId,
    limit: usize,
) -> Result<Vec<schema::InboundSyncEvent>, String> {
    let prefix = schema::inbound_event_prefix(connection_id);
    store
        .table_rows_with_key_prefix(schema::INBOUND_EVENTS, &prefix, limit)
        .map_err(|err| format!("load inbound sync events: {err}"))?
        .into_iter()
        .map(|(key, value)| schema::decode_inbound_event(key, value))
        .collect()
}

fn fingerprint_id(id: &crate::protocol::event_modules::types::EventId) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"sync-event-id:");
    hasher.update(id);
    *hasher.finalize().as_bytes()
}

fn xor_into(target: &mut [u8; 32], value: &[u8; 32]) {
    for (left, right) in target.iter_mut().zip(value.iter()) {
        *left ^= *right;
    }
}
