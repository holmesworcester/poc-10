//! Connection worker.
//!
//! The connection domain is the protocol boundary between transport routes and
//! Topo events. Core TCP can move length-prefixed byte frames, but it cannot say
//! whether those bytes are a bootstrap request, a connection-scoped transit
//! blob, or junk. This worker owns that interpretation for the connection event
//! family.
//!
//! The worker has two jobs:
//!
//! ```text
//! inbound bytes  -> unwrap transit -> connection event or connection-scoped inner bytes
//! outbox rows    -> wrap transit   -> opaque bytes for a concrete transport target
//! ```
//!
//! It deliberately does not own generic event admission, sync decisions, TCP
//! sockets, or length-prefix framing. Accepted connection events are returned as
//! canonical records for the common event-module worker. Connection-scoped inner
//! bytes are returned to the registry so the sync worker, or another domain
//! later, can interpret them under the same connection id. Outbound bytes are
//! returned to the caller to place in core network queues.
//!
//! The most important caution is to keep "connection" and "transport target"
//! separate. A connection id is semantic state established by signed events and
//! transit secrets. A transport target is just where bytes can be sent right
//! now. This worker may resolve one to the other, but core must never need to
//! know that mapping.

use std::net::SocketAddr;

use crate::core::store::{EventRecord, Store};
use crate::protocol::event_modules::identity::{endpoint, invite};
use crate::protocol::event_modules::worker::{CommandOutput, ProposedEvent};

use super::{
    connection_ack, connection_request, queries, tables, transit, transport_target, types,
};

/// Transport metadata attached to one inbound frame.
///
/// `origin` is a concrete route observed by core TCP. `remember_origin` tells
/// the worker whether a successful connection handshake should persist that
/// route as a usable transport target. Tests and replay paths can ingest bytes
/// without mutating route state by setting it to false.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameMetadata {
    pub origin: SocketAddr,
    pub remember_origin: bool,
}

/// Work accepted by the connection worker.
///
/// Each variant is an active connection-domain operation. The variants name the
/// boundary actions explicitly so callers do not reach into helper functions:
/// unwrap one frame, drain available outbox routes, drain one route, or mark
/// successfully queued outbox rows as sent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Work {
    IngestFrame {
        local: endpoint::types::EndpointKeypair,
        metadata: FrameMetadata,
        bytes: Vec<u8>,
    },
    DrainOutboxRoutes {
        local: endpoint::types::EndpointKeypair,
    },
    DrainOutboxForRoute {
        local: endpoint::types::EndpointKeypair,
        connection_id: types::ConnectionId,
    },
    MarkOutboxSent {
        sent_outbox: Vec<Vec<u8>>,
    },
}

/// Result of a connection worker action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Output {
    InboundFrame(InboundFrame),
    OutboundRoutes(Vec<OutboundTransit>),
    DrainedOutbox(DrainedOutbox),
    OutboxMarked,
}

/// Interpretation of one inbound frame after transit unwrapping.
///
/// Connection events can be admitted directly. Connection-scoped inner bytes
/// must be handed to the event family that owns the inner wire format while
/// preserving the connection id recovered from transit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InboundFrame {
    Connection(ConnectionFrameReport),
    ConnectionScoped {
        connection_id: types::ConnectionId,
        inner: Vec<u8>,
    },
}

/// Records and response bytes produced while accepting a connection frame.
///
/// The events are canonical connection-domain facts. `outgoing` is bootstrap or
/// connection response traffic that should go back to the frame origin. Route
/// establishment is reported separately for CLI output and tests.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ConnectionFrameReport {
    pub events: Vec<EventRecord>,
    pub outgoing: Vec<Vec<u8>>,
    pub established_routes: usize,
}

/// Opaque transit bytes ready for one concrete transport target.
///
/// `sent_outbox` carries the protocol outbox keys represented by `outgoing`.
/// The caller deletes those rows only after it has committed the corresponding
/// core outbound network rows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboundTransit {
    pub target: SocketAddr,
    pub outgoing: Vec<Vec<u8>>,
    pub sent_outbox: Vec<Vec<u8>>,
}

/// Result of draining one connection's protocol outbox.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DrainedOutbox {
    pub outgoing: Vec<Vec<u8>>,
    pub sent_outbox: Vec<Vec<u8>>,
}

/// Run one connection worker action.
///
/// This is the only public entrypoint by design. Keeping helpers private makes
/// it clear which effects the connection domain can perform and gives boundary
/// tests one stable surface to check.
pub fn run(store: &Store, work: Work) -> Result<Output, String> {
    match work {
        Work::IngestFrame {
            local,
            metadata,
            bytes,
        } => ingest_frame(store, local, metadata, bytes).map(Output::InboundFrame),
        Work::DrainOutboxRoutes { local } => {
            drain_outbox_routes(store, local).map(Output::OutboundRoutes)
        }
        Work::DrainOutboxForRoute {
            local,
            connection_id,
        } => drain_outbox_for_route(store, local, connection_id).map(Output::DrainedOutbox),
        Work::MarkOutboxSent { sent_outbox } => {
            mark_outbox_sent(store, sent_outbox).map(|()| Output::OutboxMarked)
        }
    }
}

fn ingest_frame(
    store: &Store,
    local: endpoint::types::EndpointKeypair,
    metadata: FrameMetadata,
    bytes: Vec<u8>,
) -> Result<InboundFrame, String> {
    // Transit unwrap is the only place inbound bytes become meaningful. A
    // bootstrap frame has no connection id yet; an ordinary connection transit
    // frame must recover one before any inner bytes are trusted enough to route.
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

fn drain_outbox_routes(
    store: &Store,
    local: endpoint::types::EndpointKeypair,
) -> Result<Vec<OutboundTransit>, String> {
    // Route draining is deliberately route-based, not global "send everything".
    // Slow or absent targets should only starve their own route.
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

fn drain_outbox_for_route(
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
        // The outbox stores canonical inner event bytes. Wrapping happens here,
        // at the connection boundary, so event modules never need socket or
        // encryption context in their projectors.
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

fn mark_outbox_sent(store: &Store, sent_outbox: Vec<Vec<u8>>) -> Result<(), String> {
    if sent_outbox.is_empty() {
        return Ok(());
    }
    // Delete only rows that have been converted into committed core outbound
    // network rows. A crash before this point may resend duplicate protocol
    // events, which is acceptable because event ids and outbox keys dedupe.
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
        // Request acceptance proves the invite/bootstrap authorization before
        // producing an ack. The raw request event is also admitted so the
        // resulting connection has a durable dependency to point at.
        result
            .events
            .push(connection_request::codec::record_from_bytes(bytes.clone())?);
        let event = connection_request::codec::decode(&bytes)?;
        let authorized =
            invite::queries::bootstrap_hash_is_authorized(store, &event.bootstrap_hash)?;
        let connection = connection_request::commands::accept(local, authorized, bytes)?;
        apply_connection_result(metadata, connection, &mut result);
    } else if connection_ack::codec::is_ack(&bytes) {
        // Ack acceptance replays the original request bytes from local storage.
        // This keeps the accept command pure: it receives canonical inputs and
        // proposes connection facts without consulting the store itself.
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
    // Commands return proposed events. This worker strips the proposal wrapper
    // because its caller will admit every returned record through the common
    // event-module worker.
    result.events.extend(
        connection
            .events
            .into_iter()
            .map(ProposedEvent::into_record),
    );
    result.outgoing.extend(connection.value.outgoing);
    if let Some(connection_id) = connection.value.connection_id {
        if metadata.remember_origin {
            // Transport targets are learned facts. They are represented as
            // canonical local events rather than hidden socket state, so replay
            // and tests see the same route table.
            let route = transport_target::commands::record(connection_id, metadata.origin);
            result
                .events
                .extend(route.events.into_iter().map(ProposedEvent::into_record));
        }
        result.established_routes += 1;
    }
}
