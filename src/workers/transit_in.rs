//! Transit in worker.
//!
//! Inputs: accepted TCP streams and queued `core.network.inbound` frames.
//! State: local endpoint secret material and connection route facts read by the
//! protocol transit projector.
//! Step: accept at most one available stream, or claim up to `limit` queued
//! inbound rows, ask the protocol registry to unwrap each row, and write the
//! recovered inner bytes to `canonical.in` with transit provenance.
//! Outputs: `canonical.in` rows for the event admission worker. Normal sync is
//! scheduled by the sync/transit-out workers on later daemon turns, not by
//! invite bootstrap receive.
//! Consume: accepted or queued network rows are deleted after their projection
//! rows are written; rejected rows are deleted so malformed transport bytes do
//! not poison future worker turns.
//! Failure: unwrap/authentication/projection errors stop the turn after the bad
//! network row is consumed. The resulting `canonical.in` rows are not decoded
//! or semantically admitted here.
//! Fairness: `Work::Drain { limit }` bounds queue drains; stream accept handles
//! at most one TCP stream per daemon turn.

use std::cell::RefCell;
use std::collections::HashMap;
use std::net::SocketAddr;

use crate::core::daemon::{StepContext, Worker};
use crate::core::network_queues::{self, InboundNetworkRow, NetworkTarget, OutboundNetworkRow};
use crate::core::store::Store;
use crate::core::tcp;
use crate::protocol::event_modules::connection::{
    connection_request, connection_response, schema as connection_schema, types::ConnectionId,
};
use crate::protocol::event_modules::identity::{endpoint, invite};
use crate::protocol::event_modules::schema as event_schema;
use crate::protocol::event_modules::sync::SyncIndex;
use crate::workers::pipeline_helpers::event_pipeline::{
    self as pipeline, EventRegistry, ProjectionOutput, TransitInReport,
};
use crate::workers::{schema as worker_schema, sync, transit_out, DaemonWorkerContext};

const READY_BATCH: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Work {
    Drain {
        limit: usize,
    },
    Serve {
        listen: SocketAddr,
        accept_count: usize,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Output {
    Drained(TransitInReport),
    Served(crate::protocol::event_modules::connection::types::ServeReport),
}

#[derive(Debug, Default)]
struct ExchangeState {
    sent_events: usize,
    received_events: usize,
    sent_transit_out: RefCell<HashMap<Vec<u8>, Vec<Vec<u8>>>>,
}

#[derive(Debug, Default)]
pub(crate) struct InboundExchangeOutput {
    pub(crate) received_events: usize,
    pub(crate) outbound_rows: Vec<OutboundNetworkRow>,
    pub(crate) sent_transit_out: Vec<Vec<Vec<u8>>>,
}

#[derive(Debug)]
struct DecodedCanonical {
    canonical_bytes: Vec<u8>,
    receive: Option<crate::protocol::event_modules::types::ReceiveMetadata>,
    provenance: Option<worker_schema::TransitProvenance>,
}

pub fn run<R>(
    store: &Store,
    registry: &R,
    sync_index: Option<&SyncIndex>,
    work: Work,
) -> Result<Output, String>
where
    R: EventRegistry,
{
    match work {
        Work::Drain { limit } => {
            pipeline::drain_transit_in(store, registry, limit).map(Output::Drained)
        }
        Work::Serve {
            listen,
            accept_count,
        } => serve(store, registry, sync_index, listen, accept_count).map(Output::Served),
    }
}

fn serve<R>(
    store: &Store,
    registry: &R,
    sync_index: Option<&SyncIndex>,
    listen: SocketAddr,
    accept_count: usize,
) -> Result<crate::protocol::event_modules::connection::types::ServeReport, String>
where
    R: EventRegistry,
{
    let report = tcp::serve(
        store,
        listen,
        accept_count,
        ExchangeState::default(),
        |inbound, state| process_stream_inbound(store, registry, sync_index, inbound, state),
        |rows, state| transit_out::mark_sent_network_rows(store, rows, &state.sent_transit_out),
    )?;
    Ok(
        crate::protocol::event_modules::connection::types::ServeReport {
            local_addr: report.local_addr,
            accepted_connections: report.accepted_connections,
            sent_events: report.value.sent_events,
            received_events: report.value.received_events,
        },
    )
}

fn process_stream_inbound<R>(
    store: &Store,
    registry: &R,
    sync_index: Option<&SyncIndex>,
    inbound: InboundNetworkRow,
    state: &mut ExchangeState,
) -> Result<Vec<OutboundNetworkRow>, String>
where
    R: EventRegistry,
{
    let output = process_inbound_exchange_inner(store, registry, sync_index, inbound)?;
    state.received_events += output.received_events;
    state.sent_events += output.sent_transit_out.iter().map(Vec::len).sum::<usize>();
    transit_out::remember_sent_rows(
        &state.sent_transit_out,
        &output.outbound_rows,
        &output.sent_transit_out,
    )?;
    Ok(output.outbound_rows)
}

pub(crate) fn process_inbound_exchange<R>(
    store: &Store,
    registry: &R,
    inbound: InboundNetworkRow,
) -> Result<InboundExchangeOutput, String>
where
    R: EventRegistry,
{
    process_inbound_exchange_inner(store, registry, None, inbound)
}

pub(crate) fn process_inbound_exchange_with_sync<R>(
    store: &Store,
    registry: &R,
    sync_index: &SyncIndex,
    inbound: InboundNetworkRow,
) -> Result<InboundExchangeOutput, String>
where
    R: EventRegistry,
{
    process_inbound_exchange_inner(store, registry, Some(sync_index), inbound)
}

fn process_inbound_exchange_inner<R>(
    store: &Store,
    registry: &R,
    sync_index: Option<&SyncIndex>,
    inbound: InboundNetworkRow,
) -> Result<InboundExchangeOutput, String>
where
    R: EventRegistry,
{
    let target = NetworkTarget::new(inbound.source.addr());
    let output = registry.project_network_in(store, &inbound)?;
    let decoded = decoded_canonical_rows(&output)?;
    let connection_ids = connection_ids(&decoded);
    let request_ids = bootstrap_request_ids(&decoded);
    let admitted = admit_decoded_canonical(store, registry, decoded)?;
    pipeline::run(
        store,
        registry,
        pipeline::DrainUntilIdle {
            batch_size: READY_BATCH,
        },
    )?;

    let mut out = InboundExchangeOutput {
        received_events: admitted.event_ids.len(),
        ..InboundExchangeOutput::default()
    };
    let response_frames = connection_response_frames(store, registry, &request_ids)?;
    out.outbound_rows
        .extend(network_queues::outbound_rows(target, response_frames));
    if let Some(sync_index) = sync_index {
        let (frames, sent_transit_out) =
            same_stream_sync_responses(store, registry, sync_index, &connection_ids)?;
        out.sent_transit_out.extend(sent_transit_out);
        out.outbound_rows
            .extend(network_queues::outbound_rows(target, frames));
    }
    Ok(out)
}

fn admit_decoded_canonical<R>(
    store: &Store,
    registry: &R,
    decoded: Vec<DecodedCanonical>,
) -> Result<pipeline::AdmitReport, String>
where
    R: EventRegistry,
{
    let mut records = Vec::with_capacity(decoded.len());
    for row in decoded {
        records.push(registry.record_from_canonical_in(
            store,
            row.canonical_bytes,
            row.receive,
            row.provenance,
        )?);
    }
    pipeline::run(store, registry, pipeline::AdmitReceivedRecords { records })
}

fn decoded_canonical_rows(output: &ProjectionOutput) -> Result<Vec<DecodedCanonical>, String> {
    output
        .rows
        .iter()
        .map(|row| {
            if row.table != worker_schema::CANONICAL_IN {
                return Err("transit projector returned a non-canonical row".to_string());
            }
            let (canonical_bytes, receive, provenance) =
                worker_schema::decode_canonical_in(&row.value)?;
            Ok(DecodedCanonical {
                canonical_bytes,
                receive,
                provenance,
            })
        })
        .collect()
}

fn connection_ids(decoded: &[DecodedCanonical]) -> Vec<ConnectionId> {
    let mut out = Vec::new();
    for row in decoded {
        let Some(provenance) = row.provenance else {
            continue;
        };
        let worker_schema::TransitUnwrap::Connection { connection_id } = provenance.unwrapped_with
        else {
            continue;
        };
        if !out.iter().any(|known| known == &connection_id) {
            out.push(connection_id);
        }
    }
    out
}

fn bootstrap_request_ids(decoded: &[DecodedCanonical]) -> Vec<[u8; 32]> {
    let mut out = Vec::new();
    for row in decoded {
        let Some(provenance) = row.provenance else {
            continue;
        };
        if provenance.unwrapped_with != worker_schema::TransitUnwrap::Bootstrap {
            continue;
        }
        if !connection_request::codec::is_request(&row.canonical_bytes) {
            continue;
        }
        let request_id = crate::protocol::event_modules::types::event_id(&row.canonical_bytes);
        if !out.iter().any(|known| known == &request_id) {
            out.push(request_id);
        }
    }
    out
}

fn same_stream_sync_responses<R>(
    store: &Store,
    registry: &R,
    sync_index: &SyncIndex,
    connection_ids: &[ConnectionId],
) -> Result<(Vec<Vec<u8>>, Vec<Vec<Vec<u8>>>), String>
where
    R: EventRegistry,
{
    if connection_ids.is_empty() {
        return Ok((Vec::new(), Vec::new()));
    }
    let local = local_endpoint(store)?;
    let mut frames = Vec::new();
    let mut sent_transit_out = Vec::new();
    for connection_id in connection_ids {
        let output = sync::run(
            store,
            sync_index,
            sync::Work::DrainConnectionIn {
                connection_id: *connection_id,
                limit: sync::DEFAULT_INBOUND_BATCH,
            },
        )?;
        let sync::Output::DrainedIn(report) = output else {
            return Err("sync worker returned non-drain output".to_string());
        };
        if !report.events.is_empty() {
            pipeline::run(
                store,
                registry,
                pipeline::CommandOutput::with_events((), report.events),
            )?;
            pipeline::run(
                store,
                registry,
                pipeline::DrainUntilIdle {
                    batch_size: READY_BATCH,
                },
            )?;
        }
        let drained =
            transit_out::drain_and_wrap_transit_out_for_connection(store, local, *connection_id)?;
        frames.extend(drained.outgoing);
        sent_transit_out.extend(drained.sent_transit_out);
    }
    Ok((frames, sent_transit_out))
}

fn local_endpoint(store: &Store) -> Result<endpoint::types::EndpointKeypair, String> {
    endpoint::commands::local_keypair(store)?.ok_or_else(|| "local endpoint is missing".to_string())
}

fn connection_response_frames<R>(
    store: &Store,
    registry: &R,
    request_ids: &[[u8; 32]],
) -> Result<Vec<Vec<u8>>, String>
where
    R: EventRegistry,
{
    let mut frames = Vec::new();
    let local = local_endpoint(store)?;
    for request_id in request_ids {
        let Some(request) = connection_request_for_response(store, *request_id)? else {
            continue;
        };
        let invite_secret = invite_secret_for_response(store, &request.invite_secret_event_id)?;
        let output = connection_response::commands::create_for_request(
            connection_response::commands::CreateForRequest {
                local,
                request_id: *request_id,
                request: &request,
                invite_secret: &invite_secret,
            },
        )?;
        let frame = output.value.bytes.clone();
        pipeline::run(store, registry, output)
            .map_err(|err| format!("record connection response: {err}"))?;
        pipeline::run(
            store,
            registry,
            pipeline::DrainUntilIdle {
                batch_size: READY_BATCH,
            },
        )?;
        frames.push(frame);
    }
    Ok(frames)
}

fn connection_request_for_response(
    store: &Store,
    request_id: [u8; 32],
) -> Result<Option<connection_request::types::RequestEvent>, String> {
    let Some(bytes) = event_schema::event_bytes(store, &request_id)
        .map_err(|err| format!("load connection request event: {err}"))?
        .or_else(|| connection_schema::connection_event(store, request_id).ok())
    else {
        return Ok(None);
    };
    connection_request::codec::decode(&bytes).map(Some)
}

fn invite_secret_for_response(
    store: &Store,
    invite_secret_event_id: &[u8; 32],
) -> Result<invite::types::InviteSecretEvent, String> {
    let bytes = event_schema::event_bytes(store, invite_secret_event_id)
        .map_err(|err| format!("load invite secret event: {err}"))?
        .ok_or_else(|| "missing invite secret event".to_string())?;
    invite::codec::decode(&bytes)
        .map_err(|_| "connection dependency is not an invite secret".to_string())
}

pub(crate) fn daemon_worker<C>() -> Worker<C>
where
    C: DaemonWorkerContext,
{
    Worker {
        name: "transit_in",
        run: daemon_step::<C>,
    }
}

fn daemon_step<C>(ctx: &mut StepContext<'_, C>) -> Result<(), String>
where
    C: DaemonWorkerContext,
{
    let app = &*ctx.app;
    let accept = ctx.listener.accept_exchange_available(
        app.store(),
        ExchangeState::default(),
        |inbound, state| {
            process_stream_inbound(app.store(), app, Some(app.sync_index()), inbound, state)
        },
        |rows, state| {
            transit_out::mark_sent_network_rows(app.store(), rows, &state.sent_transit_out)
        },
    )?;
    ctx.report
        .add("accepted_connections", accept.accepted_connections);
    ctx.report
        .add("received_events", accept.value.received_events);
    ctx.report.add("sent_events", accept.value.sent_events);

    let report = match run(
        app.store(),
        app,
        None,
        Work::Drain {
            limit: ctx.options.work_limit,
        },
    )
    .map_err(|err| format!("drain transit in: {err}"))?
    {
        Output::Drained(report) => report,
        Output::Served(_) => return Err("transit_in worker returned non-drain output".to_string()),
    };
    ctx.report.add("transit_frames", report.network_frames);
    ctx.report.add("canonical_in", report.canonical_rows);
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::core::network_queues::{self, InboundNetworkRow, NetworkSource};
    use crate::protocol::event_modules::connection::{
        connection_request, connection_response, schema, transit, types,
    };
    use crate::protocol::event_modules::identity::{endpoint, invite};
    use crate::protocol::Protocol;
    use crate::workers::pipeline_helpers::event_pipeline as pipeline;
    use crate::workers::schema as worker_schema;

    use super::*;

    fn keypair() -> endpoint::types::EndpointKeypair {
        endpoint::commands::create_local_keypair().value
    }

    #[test]
    fn drains_network_frames_into_canonical_in_without_admitting_inner_event() {
        let local = keypair();
        let remote = keypair();
        let connection_id: types::ConnectionId = [3; 32];
        let store = Protocol::open_memory_store().expect("open store");
        let connection = connection_response::types::ResponseEvent {
            from_endpoint: remote.endpoint,
            to_endpoint: local.endpoint,
            request_id: [9; 32],
            invite_secret_event_id: [8; 32],
            initiator_ephemeral_secret_event_id: [7; 32],
            responder_ephemeral_secret_event_id: [6; 32],
            responder_ephemeral_public_key: [5; 32],
            handshake_hash: [4; 32],
            connection_secret: [5; 32],
        };
        let mut rows = endpoint::projector::local_endpoint(local);
        rows.push(schema::connection_row(connection_id, remote.endpoint));
        rows.push(schema::connection_event_row(
            connection_id,
            connection_response::codec::encode(&connection),
        ));
        store
            .insert_table_rows(rows)
            .expect("insert connection rows");
        let inner = b"inner canonical bytes".to_vec();
        let frame = transit::commands::create_connection_batch(
            remote.endpoint,
            local.endpoint,
            connection_id,
            &connection.connection_secret,
            vec![inner.clone()],
        )
        .expect("create transit frame");
        let inbound = InboundNetworkRow::new(
            NetworkSource::new("127.0.0.1:41001".parse().expect("source addr")),
            frame,
        );
        network_queues::enqueue_inbound(&store, &[inbound]).expect("enqueue inbound frame");

        let report = match run(&store, &Protocol::new(), None, Work::Drain { limit: 1 })
            .expect("drain transit in")
        {
            Output::Drained(report) => report,
            Output::Served(_) => panic!("expected drain output"),
        };

        assert_eq!(report.network_frames, 1);
        assert_eq!(report.canonical_rows, 1);
        assert_eq!(
            store
                .table_row_count(network_queues::INBOUND_TABLE)
                .expect("count inbound"),
            0,
            "transit_in consumes accepted network rows"
        );
        let queued = worker_schema::claim_canonical_in(&store, 1).expect("claim canonical in");
        assert_eq!(queued.len(), 1);
        assert_eq!(queued[0].canonical_bytes, inner);
        assert!(
            queued[0].provenance.is_some(),
            "canonical admission receives transit provenance as queue metadata"
        );
    }

    #[test]
    fn same_stream_bootstrap_response_is_not_starved_by_stale_canonical_queue() {
        let alice = keypair();
        let bob = keypair();
        let store = Protocol::open_memory_store().expect("open store");
        let protocol = Protocol::new();
        store
            .insert_table_rows(endpoint::projector::local_endpoint(alice))
            .expect("insert alice endpoint");
        let invite_output =
            invite::commands::create(alice, "127.0.0.1:41000".parse().expect("invite addr"));
        let invite_link = invite_output.value.clone();
        pipeline::run(&store, &protocol, invite_output).expect("admit invite secret");
        let stale = invite::codec::record_from_bytes(invite::codec::encode(
            &invite::types::InviteSecretEvent::new([99; 32]),
        ))
        .expect("stale canonical record");
        store
            .insert_table_rows(vec![worker_schema::canonical_in_row(stale, None)])
            .expect("insert stale canonical row");
        let request = connection_request::commands::create(
            bob,
            &invite_link,
            Some("127.0.0.1:41001".parse().expect("bob listen")),
        )
        .expect("create request");
        let request_id = request.value.request_id;
        let inbound = InboundNetworkRow::new(
            NetworkSource::new("127.0.0.1:41001".parse().expect("source addr")),
            request.value.bytes,
        );

        let output = process_inbound_exchange(&store, &protocol, inbound)
            .expect("process same-stream bootstrap request");

        assert_eq!(output.outbound_rows.len(), 1);
        assert!(
            schema::connection_id_for_request(&store, request_id)
                .expect("load request connection")
                .is_some(),
            "the just-received request should be admitted before building the response"
        );
        assert_eq!(
            store
                .table_row_count(worker_schema::CANONICAL_IN)
                .expect("count canonical queue"),
            1,
            "same-stream admission should not consume unrelated queued rows"
        );
    }
}
