use std::cell::RefCell;
use std::collections::HashMap;
use std::net::SocketAddr;

use crate::core::network_queues::{InboundNetworkRow, NetworkTarget, OutboundNetworkRow};
use crate::core::store::Store;
use crate::core::tcp;
use crate::protocol::event_modules::connection::cli::{
    ConnectSummary, ServeSummary, StreamSummary,
};
use crate::protocol::event_modules::content::cli::GenerateSummary;
use crate::protocol::event_modules::sync::cli::SyncSummary;
use crate::protocol::event_modules::test_events::event_with_deps::cli::{
    EventWithDepsReplaySummary, EventWithDepsStageSummary,
};
use crate::protocol::event_modules::worker::{self, CommandOutput};
use crate::protocol::Protocol;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CountSummary {
    pub events: usize,
    pub payload_bytes: usize,
    pub connections: usize,
    pub connection_events: usize,
    pub ready_events: usize,
    pub blocked_events: usize,
    pub applied_events: usize,
    pub rejected_events: usize,
    pub blocked_edges: usize,
}

impl CountSummary {
    pub fn lines(&self) -> Vec<String> {
        vec![
            format!("events: {}", self.events),
            format!("payload_bytes: {}", self.payload_bytes),
            format!("connections: {}", self.connections),
            format!("connection_events: {}", self.connection_events),
            format!("ready_events: {}", self.ready_events),
            format!("blocked_events: {}", self.blocked_events),
            format!("applied_events: {}", self.applied_events),
            format!("rejected_events: {}", self.rejected_events),
            format!("blocked_edges: {}", self.blocked_edges),
        ]
    }
}

pub fn run_invite(
    store: &Store,
    protocol: &Protocol,
    public_addr: SocketAddr,
) -> Result<Vec<String>, String> {
    let output = protocol
        .modules()
        .create_invite(store, public_addr)
        .map_err(|err| format!("create invite: {err}"))?;
    let (link, _) =
        worker::run(store, protocol, output).map_err(|err| format!("apply invite: {err}"))?;
    Ok(vec![link])
}

pub fn run_connect(
    store: &Store,
    protocol: &Protocol,
    invite: String,
) -> Result<Vec<String>, String> {
    let addr = protocol.modules().invite_addr(&invite)?;
    let output = protocol
        .modules()
        .create_connection_request(store, &invite)?;
    let request = worker::run(store, protocol, output)
        .map_err(|err| format!("record connection request: {err}"))?
        .0;

    let target = NetworkTarget::new(addr);
    let sent_outbox = RefCell::new(HashMap::new());
    let summary = tcp::connect_exchange(
        store,
        target,
        vec![OutboundNetworkRow::new(target, request.bytes)],
        StreamSummary::default(),
        |inbound, summary| {
            handle_inbound_network_row(store, protocol, inbound, true, summary, &sent_outbox)
        },
        |rows, _| mark_sent_network_rows(store, protocol, rows, &sent_outbox),
    )?;
    if summary.established_routes == 0 {
        return Err("connection was not established".to_string());
    }
    let summary = ConnectSummary {
        addr,
        established_routes: summary.established_routes,
    };
    Ok(vec![format!("connected: {}", summary.addr)])
}

pub fn run_sync_routes(store: &Store, protocol: &Protocol) -> Result<Vec<String>, String> {
    worker::run(
        store,
        protocol.modules(),
        worker::DrainUntilIdle {
            batch_size: worker::DEFAULT_READY_BATCH,
        },
    )
    .map_err(|err| format!("drain ready events before sync: {err}"))?;

    let start = protocol
        .modules()
        .start_sync(store)
        .map_err(|err| format!("start sync: {err}"))?;
    let (started, _) =
        worker::run(store, protocol, start).map_err(|err| format!("record sync frames: {err}"))?;

    let mut summary = SyncSummary {
        sent_events: started.sent_events,
        ..SyncSummary::default()
    };

    for outbound in protocol
        .modules()
        .drain_outbox_routes(store)
        .map_err(|err| format!("drain sync outbox: {err}"))?
    {
        let sent_outbox = RefCell::new(HashMap::new());
        remember_sent_outbox(&sent_outbox, &outbound.outgoing, &outbound.sent_outbox)?;
        let stream_summary = tcp::connect_exchange(
            store,
            outbound.target,
            outbound.outgoing,
            StreamSummary::default(),
            |inbound, summary| {
                handle_inbound_network_row(store, protocol, inbound, false, summary, &sent_outbox)
            },
            |rows, _| mark_sent_network_rows(store, protocol, rows, &sent_outbox),
        )?;
        summary.routes_synced += 1;
        summary.sent_events += outbound.sent_events + stream_summary.sent_events;
        summary.received_events += stream_summary.received_events;
    }

    Ok(summary.lines())
}

pub fn run_serve(
    store: &Store,
    protocol: &Protocol,
    listen: SocketAddr,
    accept_count: usize,
) -> Result<Vec<String>, String> {
    let sent_outbox = RefCell::new(HashMap::new());
    let report = tcp::serve(
        store,
        listen,
        accept_count,
        ServeSummary::default(),
        |inbound, summary| {
            let mut stream_summary = StreamSummary::default();
            let outgoing = handle_inbound_network_row(
                store,
                protocol,
                inbound,
                false,
                &mut stream_summary,
                &sent_outbox,
            )?;
            summary.received_events += stream_summary.received_events;
            Ok(outgoing)
        },
        |rows, _| mark_sent_network_rows(store, protocol, rows, &sent_outbox),
    )?;
    println!("listening: {}", report.local_addr);
    let mut summary = report.value;
    summary.accepted_connections = report.accepted_connections;
    Ok(summary.lines())
}

pub fn run_generate(
    store: &Store,
    protocol: &Protocol,
    num_events: usize,
    event_size: usize,
) -> Result<Vec<String>, String> {
    let output = protocol
        .modules()
        .generate_content(store, num_events, event_size)
        .map_err(|err| format!("generate: {err}"))?;
    let (report, admitted) = worker::run(store, protocol, output)
        .map_err(|err| format!("admit generated events: {err}"))?;
    let drained = worker::run(
        store,
        protocol,
        worker::DrainUntilIdle {
            batch_size: worker::DEFAULT_READY_BATCH,
        },
    )
    .map_err(|err| format!("drain generated events: {err}"))?;
    Ok(GenerateSummary {
        generated_events: admitted.inserted_events,
        applied_events: admitted.applied_events + drained.applied_events,
        event_size,
        first_timestamp: report.first_timestamp,
        last_timestamp: report.last_timestamp,
    }
    .lines())
}

pub fn run_generate_event_with_deps(
    store: &Store,
    protocol: &Protocol,
    num_events: usize,
    deps_per_event: usize,
) -> Result<Vec<String>, String> {
    let output = protocol
        .modules()
        .stage_event_with_deps(store, num_events, deps_per_event)
        .map_err(|err| format!("stage event_with_deps: {err}"))?;
    let (report, _) = worker::run(store, protocol, output)
        .map_err(|err| format!("admit staged event_with_deps: {err}"))?;
    Ok(EventWithDepsStageSummary {
        staged_events: report.staged_events,
        deps_per_event: report.deps_per_event,
        dep_edges: report.dep_edges,
        first_timestamp: report.first_timestamp,
        last_timestamp: report.last_timestamp,
    }
    .lines())
}

pub fn run_replay_event_with_deps_reverse(
    store: &Store,
    protocol: &Protocol,
) -> Result<Vec<String>, String> {
    let records = protocol
        .modules()
        .staged_event_with_deps_records(store)
        .map_err(|err| format!("load staged event_with_deps: {err}"))?;
    if records.is_empty() {
        return Err("no staged event_with_deps to replay".to_string());
    }

    let max_deps = records
        .iter()
        .map(|record| record.dependencies.len())
        .max()
        .unwrap_or(0);
    let root_count = records.len().min(max_deps.max(1));
    let reverse_non_roots = records[root_count..].iter().rev().cloned().collect();
    let (_, reverse_report) = worker::run(
        store,
        protocol.modules(),
        CommandOutput::with_events((), reverse_non_roots),
    )
    .map_err(|err| format!("admit reverse event_with_deps: {err}"))?;

    let blocked_after_reverse = store
        .status_counts()
        .map_err(|err| format!("count blocked reverse events: {err}"))?
        .blocked;

    let roots = records[..root_count].to_vec();
    let (_, root_report) = worker::run(
        store,
        protocol.modules(),
        CommandOutput::with_events((), roots),
    )
    .map_err(|err| format!("admit event_with_deps roots: {err}"))?;
    let drain = worker::run(
        store,
        protocol.modules(),
        worker::DrainUntilIdle {
            batch_size: worker::DEFAULT_READY_BATCH,
        },
    )
    .map_err(|err| format!("drain event_with_deps replay: {err}"))?;
    let final_counts = store
        .status_counts()
        .map_err(|err| format!("count event_with_deps replay statuses: {err}"))?;

    Ok(EventWithDepsReplaySummary {
        replayed_events: records.len(),
        blocked_after_reverse,
        applied_events: reverse_report.applied_events
            + root_report.applied_events
            + drain.applied_events,
        ready_events: final_counts.ready,
        blocked_events: final_counts.blocked,
        blocked_edges: final_counts.blocked_edges,
    }
    .lines())
}

pub fn run_count(store: &Store, protocol: &Protocol) -> Result<Vec<String>, String> {
    let events = store
        .event_count()
        .map_err(|err| format!("count events: {err}"))?;
    let payload_bytes = store
        .body_bytes()
        .map_err(|err| format!("count bytes: {err}"))?;
    let connections = protocol.modules().connection_count(store)?;
    let connection_events = protocol.modules().connection_event_count(store)?;
    let statuses = store
        .status_counts()
        .map_err(|err| format!("count event statuses: {err}"))?;
    Ok(CountSummary {
        events,
        payload_bytes,
        connections,
        connection_events,
        ready_events: statuses.ready,
        blocked_events: statuses.blocked,
        applied_events: statuses.applied,
        rejected_events: statuses.rejected,
        blocked_edges: statuses.blocked_edges,
    }
    .lines())
}

fn handle_inbound_network_row(
    store: &Store,
    protocol: &Protocol,
    inbound: InboundNetworkRow,
    remember_origin: bool,
    summary: &mut StreamSummary,
    sent_outbox: &RefCell<HashMap<Vec<u8>, Vec<u8>>>,
) -> Result<Vec<OutboundNetworkRow>, String> {
    let ingest = worker::run(
        store,
        protocol.modules(),
        worker::IngestFrame {
            inbound,
            remember_origin,
        },
    )?;
    summary.established_routes += ingest.established_routes;
    summary.sent_events += ingest.sent_events;
    summary.received_events += ingest.received_events;

    worker::run(
        store,
        protocol,
        worker::DrainUntilIdle {
            batch_size: worker::DEFAULT_READY_BATCH,
        },
    )
    .map_err(|err| format!("drain ready events: {err}"))?;

    remember_sent_outbox(sent_outbox, &ingest.outgoing, &ingest.sent_outbox)?;
    Ok(ingest.outgoing)
}

fn remember_sent_outbox(
    sent_outbox: &RefCell<HashMap<Vec<u8>, Vec<u8>>>,
    rows: &[OutboundNetworkRow],
    outbox_keys: &[Vec<u8>],
) -> Result<(), String> {
    if outbox_keys.is_empty() {
        return Ok(());
    }
    if outbox_keys.len() > rows.len() {
        return Err("more outbox keys than outbound network rows".to_string());
    }
    let first = rows.len() - outbox_keys.len();
    let mut sent_outbox = sent_outbox.borrow_mut();
    for (row, outbox_key) in rows[first..].iter().zip(outbox_keys) {
        sent_outbox.insert(row.key.clone(), outbox_key.clone());
    }
    Ok(())
}

fn mark_sent_network_rows(
    store: &Store,
    protocol: &Protocol,
    rows: &[OutboundNetworkRow],
    sent_outbox: &RefCell<HashMap<Vec<u8>, Vec<u8>>>,
) -> Result<(), String> {
    let mut outbox_keys = Vec::new();
    {
        let mut sent_outbox = sent_outbox.borrow_mut();
        for row in rows {
            if let Some(outbox_key) = sent_outbox.remove(&row.key) {
                outbox_keys.push(outbox_key);
            }
        }
    }
    protocol.modules().mark_outbox_sent(store, outbox_keys)
}
