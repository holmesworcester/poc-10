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

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ModuleSyncReport {
    pub outgoing: Vec<Vec<u8>>,
    pub sent_events: usize,
    pub received_events: usize,
    pub received_event_bytes: Vec<Vec<u8>>,
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

    pub fn unwrap_transit(
        &self,
        store: &Store,
        bytes: &[u8],
    ) -> Result<connection::transit::projector::UnwrappedTransit, String> {
        connection::transit::projector::unwrap(store, bytes)
    }

    pub fn is_connection_event(&self, bytes: &[u8]) -> bool {
        connection::connection_record::types::is_connection_event(bytes)
    }

    pub fn accept_connection_event(
        &self,
        store: &Store,
        bytes: Vec<u8>,
    ) -> Result<connection::connection_record::types::InboundConnection, String> {
        if connection::connection_request::codec::is_request(&bytes) {
            connection::connection_request::commands::accept(store, bytes)
        } else if connection::connection_ack::codec::is_ack(&bytes) {
            connection::connection_ack::commands::accept(store, bytes)
        } else {
            Err("unknown connection event".to_string())
        }
    }

    pub fn record_transport_target(
        &self,
        store: &Store,
        connection_id: connection::connection_record::types::ConnectionId,
        addr: SocketAddr,
    ) -> Result<(), String> {
        connection::transport_target::commands::record(store, connection_id, addr)
    }

    pub fn transport_routes(
        &self,
        store: &Store,
    ) -> Result<Vec<connection::transport_target::types::TransportRoute>, String> {
        connection::transport_target::queries::routes(store)
    }

    pub fn connection_count(&self, store: &Store) -> Result<usize, String> {
        connection::connection_record::queries::connection_count(store)
    }

    pub fn connection_event_count(&self, store: &Store) -> Result<usize, String> {
        connection::connection_record::queries::connection_event_count(store)
    }

    pub fn start_sync(
        &self,
        store: &Store,
        route: connection::transport_target::types::TransportRoute,
    ) -> Result<ModuleSyncReport, String> {
        let mut result = ModuleSyncReport::default();
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

    pub fn ingest_sync_frame(
        &self,
        store: &Store,
        connection_id: connection::connection_record::types::ConnectionId,
        bytes: &[u8],
    ) -> Result<ModuleSyncReport, String> {
        let mut result = ModuleSyncReport::default();
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
