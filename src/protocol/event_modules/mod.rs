pub mod connection;
pub mod content;
pub mod identity;
pub mod sync;
pub mod test_events;
pub mod worker;

use std::net::SocketAddr;

use crate::core::network_queues::{self, NetworkTarget, OutboundNetworkRow};
use crate::core::store::{EventRecord, Store};
use crate::protocol::event_modules::worker::{
    CommandOutput, EventRegistry, ProjectionOutput, ProposedEvent,
};

#[derive(Debug, Clone, Copy, Default)]
pub struct Modules;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ModuleFrameReport {
    pub events: Vec<EventRecord>,
    pub outgoing: Vec<Vec<u8>>,
    pub drain_outbox_for: Option<connection::types::ConnectionId>,
    pub established_routes: usize,
    pub sent_events: usize,
    pub received_events: usize,
    pub received_event_bytes: Vec<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboundSync {
    pub target: NetworkTarget,
    pub outgoing: Vec<OutboundNetworkRow>,
    pub sent_outbox: Vec<Vec<u8>>,
    pub sent_events: usize,
}

impl Modules {
    pub fn new() -> Self {
        Self
    }

    pub fn record_from_bytes(&self, bytes: Vec<u8>) -> Result<EventRecord, String> {
        record_from_bytes(bytes)
    }

    pub fn create_invite(
        &self,
        store: &Store,
        public_addr: SocketAddr,
    ) -> Result<CommandOutput<String>, String> {
        let local = self.local_keypair(store)?;
        let invite = identity::invite::commands::create(local.value, public_addr);
        Ok(merge_outputs(local.events, invite))
    }

    pub fn invite_addr(&self, invite: &str) -> Result<SocketAddr, String> {
        identity::invite::commands::addr(invite)
    }

    pub fn generate_content(
        &self,
        store: &Store,
        num_events: usize,
        event_size: usize,
    ) -> Result<CommandOutput<content::content_event::commands::GenerateReport>, String> {
        let start = store
            .max_timestamp()
            .map_err(|err| format!("load max timestamp: {err}"))?
            .saturating_add(1);
        content::content_event::commands::generate(start, num_events, event_size)
    }

    pub fn stage_dependent_events(
        &self,
        store: &Store,
        events: usize,
        deps_per_event: usize,
    ) -> Result<CommandOutput<test_events::dependent_event::commands::StageReport>, String> {
        let start = store
            .max_timestamp()
            .map_err(|err| format!("load max timestamp: {err}"))?
            .saturating_add(1);
        test_events::dependent_event::commands::stage(events, deps_per_event, start)
    }

    pub fn staged_dependent_records(&self, store: &Store) -> Result<Vec<EventRecord>, String> {
        test_events::dependent_event::queries::staged_records(store)
    }

    pub fn create_connection_request(
        &self,
        store: &Store,
        invite: &str,
    ) -> Result<CommandOutput<connection::connection_request::commands::OutboundRequest>, String>
    {
        let local = self.local_keypair(store)?;
        let request = connection::connection_request::commands::create(local.value, invite)?;
        Ok(merge_outputs(local.events, request))
    }

    pub fn ingest_frame(
        &self,
        store: &Store,
        origin: SocketAddr,
        remember_origin: bool,
        bytes: Vec<u8>,
    ) -> Result<ModuleFrameReport, String> {
        let metadata = connection::worker::FrameMetadata {
            origin,
            remember_origin,
        };
        let local = self.existing_local_keypair(store)?;
        let output = connection::worker::run(
            store,
            connection::worker::Work::IngestFrame {
                local,
                metadata,
                bytes,
            },
        )?;
        let connection::worker::Output::InboundFrame(frame) = output else {
            return Err("connection worker returned non-ingest output".to_string());
        };
        match frame {
            connection::worker::InboundFrame::Connection(report) => Ok(ModuleFrameReport {
                events: report.events,
                outgoing: report.outgoing,
                established_routes: report.established_routes,
                ..ModuleFrameReport::default()
            }),
            connection::worker::InboundFrame::ConnectionScoped {
                connection_id,
                inner,
            } => self.ingest_sync_frame(store, connection_id, &inner),
        }
    }

    pub fn start_sync(
        &self,
        store: &Store,
    ) -> Result<CommandOutput<sync::worker::SyncStartReport>, String> {
        match sync::worker::run(store, sync::worker::Work::Start)? {
            sync::worker::Output::Started(output) => Ok(output),
            sync::worker::Output::IngestedFrame(_) => {
                Err("sync worker returned non-start output".to_string())
            }
        }
    }

    pub fn drain_outbox_routes(&self, store: &Store) -> Result<Vec<OutboundSync>, String> {
        let local = self.existing_local_keypair(store)?;
        let output =
            connection::worker::run(store, connection::worker::Work::DrainOutboxRoutes { local })?;
        let connection::worker::Output::OutboundRoutes(outbound) = output else {
            return Err("connection worker returned non-outbox-routes output".to_string());
        };
        Ok(outbound
            .into_iter()
            .map(|outbound| OutboundSync {
                target: NetworkTarget::new(outbound.target),
                outgoing: network_queues::outbound_rows(
                    NetworkTarget::new(outbound.target),
                    outbound.outgoing,
                ),
                sent_outbox: outbound.sent_outbox,
                sent_events: 0,
            })
            .collect())
    }

    pub fn drain_outbox_for_route(
        &self,
        store: &Store,
        connection_id: connection::types::ConnectionId,
    ) -> Result<connection::worker::DrainedOutbox, String> {
        let local = self.existing_local_keypair(store)?;
        let output = connection::worker::run(
            store,
            connection::worker::Work::DrainOutboxForRoute {
                local,
                connection_id,
            },
        )?;
        let connection::worker::Output::DrainedOutbox(drained) = output else {
            return Err("connection worker returned non-outbox-route output".to_string());
        };
        Ok(drained)
    }

    pub fn mark_outbox_sent(&self, store: &Store, sent_outbox: Vec<Vec<u8>>) -> Result<(), String> {
        let output = connection::worker::run(
            store,
            connection::worker::Work::MarkOutboxSent { sent_outbox },
        )?;
        let connection::worker::Output::OutboxMarked = output else {
            return Err("connection worker returned non-mark-outbox output".to_string());
        };
        Ok(())
    }

    pub fn connection_count(&self, store: &Store) -> Result<usize, String> {
        connection::queries::connection_count(store)
    }

    pub fn connection_event_count(&self, store: &Store) -> Result<usize, String> {
        connection::queries::connection_event_count(store)
    }

    fn ingest_sync_frame(
        &self,
        store: &Store,
        connection_id: connection::types::ConnectionId,
        bytes: &[u8],
    ) -> Result<ModuleFrameReport, String> {
        let output = sync::worker::run(
            store,
            sync::worker::Work::IngestFrame {
                connection_id,
                bytes: bytes.to_vec(),
            },
        )?;
        let sync::worker::Output::IngestedFrame(report) = output else {
            return Err("sync worker returned non-ingest output".to_string());
        };
        Ok(ModuleFrameReport {
            events: report.events,
            drain_outbox_for: Some(connection_id),
            sent_events: report.sent_events,
            received_events: report.received_events,
            received_event_bytes: report.received_event_bytes,
            ..ModuleFrameReport::default()
        })
    }

    fn local_keypair(
        &self,
        store: &Store,
    ) -> Result<CommandOutput<identity::endpoint::types::EndpointKeypair>, String> {
        match identity::endpoint::queries::local_keypair(store)? {
            Some(local) => Ok(CommandOutput::new(local)),
            None => Ok(identity::endpoint::commands::create_local_keypair()),
        }
    }

    pub fn project_record(
        &self,
        store: &Store,
        record: &EventRecord,
    ) -> Result<ProjectionOutput, String> {
        let bytes = &record.canonical_bytes;
        if let Some(output) = identity::project_record(bytes)? {
            return Ok(output);
        }
        if connection::is_projection_record(bytes) {
            let local = self.existing_local_keypair(store)?;
            return connection::project_record(store, bytes, local.endpoint);
        }
        if let Some(output) = sync::project_record(bytes)? {
            return Ok(output);
        }
        if let Some(output) = content::project_record(bytes)? {
            return Ok(output);
        }
        if let Some(output) = test_events::project_record(bytes)? {
            return Ok(output);
        }
        let tag = bytes.first().copied().unwrap_or_default();
        Err(format!("unknown event type {tag}"))
    }

    fn existing_local_keypair(
        &self,
        store: &Store,
    ) -> Result<identity::endpoint::types::EndpointKeypair, String> {
        identity::endpoint::queries::local_keypair(store)?
            .ok_or_else(|| "local endpoint is missing".to_string())
    }
}

impl EventRegistry for Modules {
    fn record_from_bytes(&self, bytes: Vec<u8>) -> Result<EventRecord, String> {
        self.record_from_bytes(bytes)
    }

    fn project_record(
        &self,
        store: &Store,
        record: &EventRecord,
    ) -> Result<ProjectionOutput, String> {
        self.project_record(store, record)
    }
}

fn merge_outputs<T>(
    mut events: Vec<ProposedEvent>,
    mut output: CommandOutput<T>,
) -> CommandOutput<T> {
    events.append(&mut output.events);
    output.events = events;
    output
}

pub fn record_from_bytes(bytes: Vec<u8>) -> Result<EventRecord, String> {
    if connection::connection_request::codec::is_request(&bytes) {
        return connection::connection_request::codec::record_from_bytes(bytes);
    }
    if connection::connection_ack::codec::is_ack(&bytes) {
        return connection::connection_ack::codec::record_from_bytes(bytes);
    }
    if sync::frame::codec::is_frame(&bytes) {
        return sync::frame::codec::record_from_bytes(bytes);
    }
    let tag = bytes
        .first()
        .ok_or_else(|| "empty event bytes".to_string())?;
    match *tag {
        identity::endpoint::codec::TYPE_LOCAL_ENDPOINT => {
            identity::endpoint::codec::record_from_bytes(bytes)
        }
        identity::invite::codec::TYPE_INVITE_SECRET => {
            identity::invite::codec::record_from_bytes(bytes)
        }
        connection::transport_target::codec::TYPE_TRANSPORT_TARGET => {
            connection::transport_target::codec::record_from_bytes(bytes)
        }
        content::content_event::codec::TYPE_CONTENT => {
            content::content_event::codec::record_from_bytes(bytes)
        }
        test_events::dependent_event::codec::TYPE_DEPENDENT_EVENT => {
            test_events::dependent_event::codec::record_from_bytes(bytes)
        }
        test_events::dependent_event::codec::TYPE_STAGED_DEPENDENT_EVENT => {
            test_events::dependent_event::codec::staged_record_from_bytes(bytes)
        }
        other => Err(format!("unknown event type {other}")),
    }
}
