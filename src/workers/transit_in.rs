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
use crate::protocol::event_modules::connection::types::ConnectionId;
use crate::protocol::event_modules::identity::endpoint;
use crate::protocol::event_modules::sync::SyncIndex;
use crate::workers::pipeline_helpers::event_pipeline::{
    self as pipeline, EventRegistry, ProjectionOutput, TransitInReport,
};
use crate::workers::{event_admission, schema as worker_schema, sync, transit_out, DaemonWorkerContext};

const READY_BATCH: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Work {
    Drain { limit: usize },
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
    Ok(crate::protocol::event_modules::connection::types::ServeReport {
        local_addr: report.local_addr,
        accepted_connections: report.accepted_connections,
        sent_events: report.value.sent_events,
        received_events: report.value.received_events,
    })
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
    let canonical_rows = decoded.len();
    store
        .insert_table_rows(output.rows)
        .map_err(|err| format!("stage canonical input: {err}"))?;
    let admitted = event_admission::run(
        store,
        registry,
        event_admission::Work::Drain {
            limit: canonical_rows.max(1),
        },
    )?;
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
    if let Some(sync_index) = sync_index {
        let (frames, sent_transit_out) =
            same_stream_sync_responses(store, registry, sync_index, &connection_ids)?;
        out.sent_transit_out.extend(sent_transit_out);
        out.outbound_rows.extend(network_queues::outbound_rows(target, frames));
    }
    Ok(out)
}

fn decoded_canonical_rows(output: &ProjectionOutput) -> Result<Vec<DecodedCanonical>, String> {
    output
        .rows
        .iter()
        .filter(|row| row.table == worker_schema::CANONICAL_IN)
        .map(|row| {
            let (_, _, provenance) = worker_schema::decode_canonical_in(&row.value)?;
            Ok(DecodedCanonical { provenance })
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
    ctx.report.add("received_events", accept.value.received_events);
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
    use crate::protocol::event_modules::connection::{schema, transit, types};
    use crate::protocol::event_modules::identity::endpoint;
    use crate::protocol::Protocol;
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
        let mut rows = endpoint::projector::local_endpoint(local);
        rows.push(schema::connection_row(connection_id, remote.endpoint));
        store
            .insert_table_rows(rows)
            .expect("insert connection rows");
        let inner = b"inner canonical bytes".to_vec();
        let frame = transit::commands::create_connection_batch(
            &remote,
            local.endpoint,
            connection_id,
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
}
