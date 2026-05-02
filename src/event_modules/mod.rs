pub mod connection;
pub mod content;
pub mod identity;
pub mod sync;
pub mod test_events;

use std::net::SocketAddr;

use crate::store::{CommandOutput, EventRecord, StateChanges, Store};

#[derive(Debug, Clone, Copy, Default)]
pub struct Modules;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FrameMetadata {
    pub origin: SocketAddr,
    pub remember_origin: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ModuleFrameReport {
    pub changes: StateChanges,
    pub outgoing: Vec<Vec<u8>>,
    pub established_routes: usize,
    pub sent_events: usize,
    pub received_events: usize,
    pub received_event_bytes: Vec<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboundSync {
    pub target: SocketAddr,
    pub outgoing: Vec<Vec<u8>>,
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
        Ok(merge_outputs(local.changes, invite))
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

    pub fn create_connection_request(
        &self,
        store: &Store,
        invite: &str,
    ) -> Result<CommandOutput<connection::connection_request::commands::OutboundRequest>, String>
    {
        let local = self.local_keypair(store)?;
        let request = connection::connection_request::commands::create(local.value, invite)?;
        Ok(merge_outputs(local.changes, request))
    }

    pub fn ingest_frame(
        &self,
        store: &Store,
        origin: SocketAddr,
        remember_origin: bool,
        bytes: Vec<u8>,
    ) -> Result<ModuleFrameReport, String> {
        let metadata = FrameMetadata {
            origin,
            remember_origin,
        };
        let local = self.existing_local_keypair(store)?;
        let transit = connection::transit::projector::unwrap(local, &bytes, |connection_id| {
            connection::connection_record::queries::remote_endpoint(store, connection_id)
        })?;
        if connection::connection_record::types::is_connection_event(&transit.inner) {
            return self.ingest_connection_frame(store, metadata, transit.inner);
        }
        let connection_id = transit
            .connection_id
            .ok_or_else(|| "sync frame requires connection transit".to_string())?;
        self.ingest_sync_frame(store, connection_id, &transit.inner)
    }

    fn ingest_connection_frame(
        &self,
        store: &Store,
        metadata: FrameMetadata,
        bytes: Vec<u8>,
    ) -> Result<ModuleFrameReport, String> {
        let mut result = ModuleFrameReport::default();
        if connection::connection_request::codec::is_request(&bytes) {
            let event = connection::connection_request::codec::decode(&bytes)?;
            let authorized = identity::invite::queries::bootstrap_hash_is_authorized(
                store,
                &event.bootstrap_hash,
            )?;
            let local = self.local_keypair(store)?;
            let connection =
                connection::connection_request::commands::accept(local.value, authorized, bytes)?;
            let connection = merge_outputs(local.changes, connection);
            self.apply_connection_result(metadata, connection, &mut result);
        } else if connection::connection_ack::codec::is_ack(&bytes) {
            let event = connection::connection_ack::codec::decode(&bytes)?;
            let request_bytes =
                connection::connection_record::queries::event_bytes(store, &event.request_id)?
                    .ok_or_else(|| "connection ack references unknown request".to_string())?;
            let local = self.local_keypair(store)?;
            let connection =
                connection::connection_ack::commands::accept(local.value, request_bytes, bytes)?;
            let connection = merge_outputs(local.changes, connection);
            self.apply_connection_result(metadata, connection, &mut result);
        } else {
            return Err("unknown connection event".to_string());
        }
        Ok(result)
    }

    fn apply_connection_result(
        &self,
        metadata: FrameMetadata,
        connection: CommandOutput<connection::connection_record::types::InboundConnection>,
        result: &mut ModuleFrameReport,
    ) {
        result.changes.append(connection.changes);
        result.outgoing.extend(connection.value.outgoing);
        if let Some(connection_id) = connection.value.connection_id {
            if metadata.remember_origin {
                result
                    .changes
                    .append(connection::transport_target::commands::record(
                        connection_id,
                        metadata.origin,
                    ));
            }
            result.established_routes += 1;
        }
    }

    pub fn sync_outbound(&self, store: &Store) -> Result<Vec<OutboundSync>, String> {
        let mut outbound = Vec::new();
        let routes = connection::transport_target::queries::routes(store)?;
        if routes.is_empty() {
            return Ok(outbound);
        }
        let local = self.existing_local_keypair(store)?;
        for route in routes {
            let remote = connection::connection_record::queries::remote_endpoint(
                store,
                &route.connection_id,
            )?;
            let mut result = ModuleFrameReport::default();
            let report = sync::compare::commands::start(store, route.connection_id, |bytes| {
                result
                    .outgoing
                    .push(connection::transit::commands::create_connection(
                        &local,
                        remote,
                        route.connection_id,
                        bytes,
                    )?);
                Ok(())
            })?;
            outbound.push(OutboundSync {
                target: route.addr,
                outgoing: result.outgoing,
                sent_events: report.sent_events,
            });
        }
        Ok(outbound)
    }

    pub fn connection_count(&self, store: &Store) -> Result<usize, String> {
        connection::connection_record::queries::connection_count(store)
    }

    pub fn connection_event_count(&self, store: &Store) -> Result<usize, String> {
        connection::connection_record::queries::connection_event_count(store)
    }

    fn ingest_sync_frame(
        &self,
        store: &Store,
        connection_id: connection::connection_record::types::ConnectionId,
        bytes: &[u8],
    ) -> Result<ModuleFrameReport, String> {
        let mut result = ModuleFrameReport::default();
        let local = self.existing_local_keypair(store)?;
        let remote =
            connection::connection_record::queries::remote_endpoint(store, &connection_id)?;
        let report = sync::compare::commands::ingest_frame(store, connection_id, bytes, |bytes| {
            result
                .outgoing
                .push(connection::transit::commands::create_connection(
                    &local,
                    remote,
                    connection_id,
                    bytes,
                )?);
            Ok(())
        })?;
        result.sent_events += report.sent_events;
        result.received_events += report.received_events;
        result.received_event_bytes = report.received_event_bytes;
        Ok(result)
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

    fn existing_local_keypair(
        &self,
        store: &Store,
    ) -> Result<identity::endpoint::types::EndpointKeypair, String> {
        identity::endpoint::queries::local_keypair(store)?
            .ok_or_else(|| "local endpoint is missing".to_string())
    }
}

fn merge_outputs<T>(mut changes: StateChanges, mut output: CommandOutput<T>) -> CommandOutput<T> {
    changes.append(output.changes);
    output.changes = changes;
    output
}

pub fn record_from_bytes(bytes: Vec<u8>) -> Result<EventRecord, String> {
    let tag = bytes
        .first()
        .ok_or_else(|| "empty event bytes".to_string())?;
    match *tag {
        content::content_event::codec::TYPE_CONTENT => {
            content::content_event::codec::record_from_bytes(bytes)
        }
        test_events::dependent_event::codec::TYPE_DEPENDENT_EVENT => {
            test_events::dependent_event::codec::record_from_bytes(bytes)
        }
        other => Err(format!("unknown event type {other}")),
    }
}
