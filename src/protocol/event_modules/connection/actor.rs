use std::net::SocketAddr;

use crate::core::store::{CommandOutput, EventRecord, ProposedEvent, Store};
use crate::protocol::event_modules::identity::{endpoint, invite};

use super::{
    connection_ack, connection_request, queries, tables, transit, transport_target, types,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameMetadata {
    pub origin: SocketAddr,
    pub remember_origin: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InboundFrame {
    Connection(ConnectionFrameReport),
    ConnectionScoped {
        connection_id: types::ConnectionId,
        inner: Vec<u8>,
    },
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ConnectionFrameReport {
    pub events: Vec<EventRecord>,
    pub outgoing: Vec<Vec<u8>>,
    pub established_routes: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboundTransit {
    pub target: SocketAddr,
    pub outgoing: Vec<Vec<u8>>,
    pub sent_outbox: Vec<Vec<u8>>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DrainedOutbox {
    pub outgoing: Vec<Vec<u8>>,
    pub sent_outbox: Vec<Vec<u8>>,
}

pub fn ingest_frame(
    store: &Store,
    local: endpoint::types::EndpointKeypair,
    metadata: FrameMetadata,
    bytes: Vec<u8>,
) -> Result<InboundFrame, String> {
    let transit = transit::commands::unwrap(local, &bytes, |connection_id| {
        queries::remote_endpoint(store, connection_id)
    })?;
    if types::is_connection_event(&transit.inner) {
        return Ok(InboundFrame::Connection(ingest_connection_frame(
            store,
            local,
            metadata,
            transit.inner,
        )?));
    }
    let connection_id = transit
        .connection_id
        .ok_or_else(|| "connection-scoped frame requires connection transit".to_string())?;
    Ok(InboundFrame::ConnectionScoped {
        connection_id,
        inner: transit.inner,
    })
}

pub fn drain_outbox_routes(
    store: &Store,
    local: endpoint::types::EndpointKeypair,
) -> Result<Vec<OutboundTransit>, String> {
    let routes = transport_target::queries::routes(store)?;
    let mut outbound = Vec::new();
    for route in routes {
        let drained = drain_outbox_for_route(store, local, route.connection_id)?;
        if drained.outgoing.is_empty() {
            continue;
        }
        outbound.push(OutboundTransit {
            target: route.addr,
            outgoing: drained.outgoing,
            sent_outbox: drained.sent_outbox,
        });
    }
    Ok(outbound)
}

pub fn drain_outbox_for_route(
    store: &Store,
    local: endpoint::types::EndpointKeypair,
    connection_id: types::ConnectionId,
) -> Result<DrainedOutbox, String> {
    let items = queries::outbox_items_for_connection(store, connection_id)?;
    if items.is_empty() {
        return Ok(DrainedOutbox::default());
    }
    let remote = queries::remote_endpoint(store, &connection_id)?;
    let mut outgoing = Vec::with_capacity(items.len());
    let mut sent_outbox = Vec::with_capacity(items.len());
    for item in items {
        outgoing.push(transit::commands::create_connection(
            &local,
            remote,
            connection_id,
            item.event_bytes,
        )?);
        sent_outbox.push(item.key.to_bytes());
    }
    Ok(DrainedOutbox {
        outgoing,
        sent_outbox,
    })
}

pub fn mark_outbox_sent(store: &Store, sent_outbox: Vec<Vec<u8>>) -> Result<(), String> {
    if sent_outbox.is_empty() {
        return Ok(());
    }
    store
        .delete_table_rows(tables::OUTBOX, sent_outbox)
        .map(|_| ())
        .map_err(|err| format!("delete sent outbox rows: {err}"))
}

fn ingest_connection_frame(
    store: &Store,
    local: endpoint::types::EndpointKeypair,
    metadata: FrameMetadata,
    bytes: Vec<u8>,
) -> Result<ConnectionFrameReport, String> {
    let mut result = ConnectionFrameReport::default();
    if connection_request::codec::is_request(&bytes) {
        result
            .events
            .push(connection_request::codec::record_from_bytes(bytes.clone())?);
        let event = connection_request::codec::decode(&bytes)?;
        let authorized =
            invite::queries::bootstrap_hash_is_authorized(store, &event.bootstrap_hash)?;
        let connection = connection_request::commands::accept(local, authorized, bytes)?;
        apply_connection_result(metadata, connection, &mut result);
    } else if connection_ack::codec::is_ack(&bytes) {
        result
            .events
            .push(connection_ack::codec::record_from_bytes(bytes.clone())?);
        let event = connection_ack::codec::decode(&bytes)?;
        let request_bytes = queries::event_bytes(store, &event.request_id)?
            .ok_or_else(|| "connection ack references unknown request".to_string())?;
        let connection = connection_ack::commands::accept(local, request_bytes, bytes)?;
        apply_connection_result(metadata, connection, &mut result);
    } else {
        return Err("unknown connection event".to_string());
    }
    Ok(result)
}

fn apply_connection_result(
    metadata: FrameMetadata,
    connection: CommandOutput<types::InboundConnection>,
    result: &mut ConnectionFrameReport,
) {
    result.events.extend(
        connection
            .events
            .into_iter()
            .map(ProposedEvent::into_record),
    );
    result.outgoing.extend(connection.value.outgoing);
    if let Some(connection_id) = connection.value.connection_id {
        if metadata.remember_origin {
            let route = transport_target::commands::record(connection_id, metadata.origin);
            result
                .events
                .extend(route.events.into_iter().map(ProposedEvent::into_record));
        }
        result.established_routes += 1;
    }
}
