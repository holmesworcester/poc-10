use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};

use crate::core::store::Store;
use crate::protocol::event_modules::connection::cli::{
    ConnectSummary, ServeSummary, StreamSummary,
};
use crate::protocol::event_modules::content::cli::GenerateSummary;
use crate::protocol::event_modules::sync::cli::SyncSummary;
use crate::protocol::event_modules::test_events::dependent_event::cli::{
    DependentReplaySummary, DependentStageSummary,
};
use crate::protocol::event_modules::worker::{self, CommandOutput};
use crate::protocol::{network, Protocol};

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

    let mut stream = network::connect(addr).map_err(|err| format!("open tcp stream: {err}"))?;
    network::write_frames(&mut stream, vec![request.bytes])?;
    let summary = pump_stream(store, protocol, &mut stream, addr, true)?;
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
        let mut stream =
            network::connect(outbound.target).map_err(|err| format!("open tcp stream: {err}"))?;
        network::write_frames(&mut stream, outbound.outgoing)?;
        protocol
            .modules()
            .mark_outbox_sent(store, outbound.sent_outbox)?;

        let stream_summary = pump_stream(store, protocol, &mut stream, outbound.target, false)?;
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
    let listener = TcpListener::bind(listen).map_err(|err| format!("listen: {err}"))?;
    let local_addr = listener
        .local_addr()
        .map_err(|err| format!("listener local addr: {err}"))?;
    println!("listening: {local_addr}");

    let mut summary = ServeSummary::default();
    for _ in 0..accept_count {
        let (mut stream, peer_addr) = listener
            .accept()
            .map_err(|err| format!("accept tcp stream: {err}"))?;
        stream
            .set_nodelay(true)
            .map_err(|err| format!("set stream nodelay: {err}"))?;
        let stream_summary = pump_stream(store, protocol, &mut stream, peer_addr, false)?;
        summary.accepted_connections += 1;
        summary.received_events += stream_summary.received_events;
    }

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

pub fn run_generate_dependent_events(
    store: &Store,
    protocol: &Protocol,
    num_events: usize,
    deps_per_event: usize,
) -> Result<Vec<String>, String> {
    let output = protocol
        .modules()
        .stage_dependent_events(store, num_events, deps_per_event)
        .map_err(|err| format!("stage dependent events: {err}"))?;
    let (report, _) = worker::run(store, protocol, output)
        .map_err(|err| format!("admit staged dependent events: {err}"))?;
    Ok(DependentStageSummary {
        staged_events: report.staged_events,
        deps_per_event: report.deps_per_event,
        dep_edges: report.dep_edges,
        first_timestamp: report.first_timestamp,
        last_timestamp: report.last_timestamp,
    }
    .lines())
}

pub fn run_replay_dependent_events_reverse(
    store: &Store,
    protocol: &Protocol,
) -> Result<Vec<String>, String> {
    let records = protocol
        .modules()
        .staged_dependent_records(store)
        .map_err(|err| format!("load staged dependent events: {err}"))?;
    if records.is_empty() {
        return Err("no staged dependent events to replay".to_string());
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
    .map_err(|err| format!("admit reverse dependent events: {err}"))?;

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
    .map_err(|err| format!("admit dependent roots: {err}"))?;
    let drain = worker::run(
        store,
        protocol.modules(),
        worker::DrainUntilIdle {
            batch_size: worker::DEFAULT_READY_BATCH,
        },
    )
    .map_err(|err| format!("drain dependent replay: {err}"))?;
    let final_counts = store
        .status_counts()
        .map_err(|err| format!("count dependent replay statuses: {err}"))?;

    Ok(DependentReplaySummary {
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

fn pump_stream(
    store: &Store,
    protocol: &Protocol,
    stream: &mut TcpStream,
    origin: SocketAddr,
    remember_origin: bool,
) -> Result<StreamSummary, String> {
    let mut summary = StreamSummary::default();
    let mut write_open = true;
    loop {
        let bytes = match network::read_frame(stream) {
            Ok(bytes) => bytes,
            Err(err) if is_stream_closed(&err) => break,
            Err(err) => return Err(format!("read frame: {err}")),
        };

        let ingest = worker::run(
            store,
            protocol.modules(),
            worker::IngestFrame {
                metadata: worker::FrameMetadata {
                    origin,
                    remember_origin,
                },
                bytes,
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

        if ingest.outgoing.is_empty() {
            if write_open {
                stream
                    .shutdown(Shutdown::Write)
                    .map_err(|err| format!("shutdown stream write: {err}"))?;
                write_open = false;
            }
        } else {
            network::write_frames(stream, ingest.outgoing)?;
            protocol
                .modules()
                .mark_outbox_sent(store, ingest.sent_outbox)?;
        }
    }
    Ok(summary)
}

fn is_stream_closed(err: &std::io::Error) -> bool {
    matches!(
        err.kind(),
        std::io::ErrorKind::UnexpectedEof
            | std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::BrokenPipe
    )
}
