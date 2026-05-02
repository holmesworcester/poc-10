pub mod connection;
pub mod content;
pub mod identity;
pub mod sync;
pub mod test_events;

use std::net::SocketAddr;

use crate::store::EventRecord;
use crate::store::Store;

#[derive(Debug, Clone, Copy, Default)]
pub struct Modules;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FrameMetadata {
    pub origin: SocketAddr,
    pub remember_origin: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ModuleFrameReport {
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

    pub fn create_invite(&self, store: &Store, public_addr: SocketAddr) -> Result<String, String> {
        identity::invite::commands::create(store, public_addr)
    }

    pub fn invite_addr(&self, invite: &str) -> Result<SocketAddr, String> {
        identity::invite::commands::addr(invite)
    }

    pub fn generate_content(
        &self,
        store: &Store,
        num_events: usize,
        event_size: usize,
    ) -> Result<content::content_event::commands::GenerateReport, String> {
        content::content_event::commands::generate(store, num_events, event_size)
    }

    pub fn create_connection_request(
        &self,
        store: &Store,
        invite: &str,
    ) -> Result<connection::connection_request::commands::OutboundRequest, String> {
        connection::connection_request::commands::create(store, invite)
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
        let transit = connection::transit::projector::unwrap(store, &bytes)?;
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
            let connection = connection::connection_request::commands::accept(store, bytes)?;
            self.apply_connection_result(store, metadata, connection, &mut result)?;
        } else if connection::connection_ack::codec::is_ack(&bytes) {
            let connection = connection::connection_ack::commands::accept(store, bytes)?;
            self.apply_connection_result(store, metadata, connection, &mut result)?;
        } else {
            return Err("unknown connection event".to_string());
        }
        Ok(result)
    }

    fn apply_connection_result(
        &self,
        store: &Store,
        metadata: FrameMetadata,
        connection: connection::connection_record::types::InboundConnection,
        result: &mut ModuleFrameReport,
    ) -> Result<(), String> {
        if let Some(bytes) = connection.response {
            result.outgoing.push(bytes);
        }
        if let Some(connection_id) = connection.connection_id {
            if metadata.remember_origin {
                connection::transport_target::commands::record(
                    store,
                    connection_id,
                    metadata.origin,
                )?;
            }
            result.established_routes += 1;
        }
        Ok(())
    }

    pub fn sync_outbound(&self, store: &Store) -> Result<Vec<OutboundSync>, String> {
        let mut outbound = Vec::new();
        for route in connection::transport_target::queries::routes(store)? {
            let mut result = ModuleFrameReport::default();
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
        result.sent_events += report.sent_events;
        result.received_events += report.received_events;
        result.received_event_bytes = report.received_event_bytes;
        Ok(result)
    }
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
