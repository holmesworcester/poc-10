//! Connection CLI commands and summaries.
//!
//! This file owns the CLI behavior that crosses the connection boundary:
//! outbound bootstrap connects, server-side frame exchange, and marking
//! connection outbox rows sent after core TCP accepts their bytes. It is allowed
//! to invoke the generic TCP pump because connection is the domain that turns
//! route facts and transit bytes into opaque network rows. It must not decode
//! event-specific sync or content meaning; those remain in their own workers.

use std::cell::RefCell;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::thread;
use std::time::{Duration, Instant};

use crate::core::cli::{CliArgs, CliCommand, CliOutput};
use crate::core::network_queues::{self, InboundNetworkRow, NetworkTarget, OutboundNetworkRow};
use crate::core::tcp;
use crate::protocol::cli::Context;
use crate::protocol::event_modules::{sync, worker as event_worker};

use super::connection_request;
use super::worker as connection_worker;

const CONNECT_USAGE: &str = "connect INVITE_LINK";
const DAEMON_USAGE: &str =
    "daemon --listen IP PORT [--duration-ms N] [--idle-ms N] [--ready-batch N]";

pub fn commands() -> Vec<CliCommand<Context>> {
    vec![
        CliCommand {
            name: "connect",
            usage: CONNECT_USAGE,
            help: "Connect to an invite over real TCP.",
            run: run_connect_command,
        },
        CliCommand {
            name: "daemon",
            usage: DAEMON_USAGE,
            help: "Run a bounded or long-lived TCP sync daemon.",
            run: run_daemon_command,
        },
    ]
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectSummary {
    pub addr: SocketAddr,
    pub established_routes: usize,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StreamSummary {
    pub established_routes: usize,
    pub sent_events: usize,
    pub received_events: usize,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ServeSummary {
    pub accepted_connections: usize,
    pub received_events: usize,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DaemonSummary {
    pub local_addr: Option<SocketAddr>,
    pub accepted_connections: usize,
    pub sync_rounds: usize,
    pub routes_synced: usize,
    pub failed_routes: usize,
    pub sent_events: usize,
    pub received_events: usize,
    pub ready_events: usize,
    pub unblocked_events: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DaemonOptions {
    listen: SocketAddr,
    duration: Option<Duration>,
    idle: Duration,
    ready_batch: usize,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct DaemonSyncRound {
    routes_synced: usize,
    failed_routes: usize,
    sent_events: usize,
    received_events: usize,
}

/// Opaque bytes prepared for one route after draining protocol outbox rows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboundSync {
    pub target: NetworkTarget,
    pub outgoing: Vec<OutboundNetworkRow>,
    pub sent_outbox: Vec<Vec<Vec<u8>>>,
    pub sent_events: usize,
}

impl ServeSummary {
    pub fn lines(&self) -> Vec<String> {
        vec![
            format!("accepted_connections: {}", self.accepted_connections),
            format!("received_events: {}", self.received_events),
        ]
    }
}

impl DaemonSummary {
    pub fn lines(&self) -> Vec<String> {
        let mut lines = Vec::new();
        if let Some(local_addr) = self.local_addr {
            lines.push(format!("listening: {local_addr}"));
        }
        lines.extend([
            format!("accepted_connections: {}", self.accepted_connections),
            format!("sync_rounds: {}", self.sync_rounds),
            format!("routes_synced: {}", self.routes_synced),
            format!("failed_routes: {}", self.failed_routes),
            format!("sent_events: {}", self.sent_events),
            format!("received_events: {}", self.received_events),
            format!("ready_events: {}", self.ready_events),
            format!("unblocked_events: {}", self.unblocked_events),
        ]);
        lines
    }
}

impl DaemonOptions {
    fn parse(args: CliArgs<'_>) -> Result<Self, String> {
        let mut listen = None;
        let mut duration = None;
        let mut idle = Duration::from_millis(250);
        let mut ready_batch = event_worker::DEFAULT_READY_BATCH;
        let mut idx = 0;
        while idx < args.values().len() {
            match args.get(idx).expect("index in bounds") {
                "--listen" => {
                    let ip = args.get(idx + 1).ok_or_else(|| DAEMON_USAGE.to_string())?;
                    let port = args.get(idx + 2).ok_or_else(|| DAEMON_USAGE.to_string())?;
                    listen = Some(
                        format!("{ip}:{port}")
                            .parse::<SocketAddr>()
                            .map_err(|_| DAEMON_USAGE.to_string())?,
                    );
                    idx += 3;
                }
                "--duration-ms" => {
                    duration = Some(Duration::from_millis(parse_positive_u64(
                        args.get(idx + 1),
                    )?));
                    idx += 2;
                }
                "--idle-ms" => {
                    idle = Duration::from_millis(parse_positive_u64(args.get(idx + 1))?);
                    idx += 2;
                }
                "--ready-batch" => {
                    ready_batch = args.parse_positive_usize(idx + 1, DAEMON_USAGE)?;
                    idx += 2;
                }
                other => return Err(format!("unknown daemon option `{other}`\n{DAEMON_USAGE}")),
            }
        }
        Ok(Self {
            listen: listen.ok_or_else(|| DAEMON_USAGE.to_string())?,
            duration,
            idle,
            ready_batch,
        })
    }
}

fn parse_positive_u64(value: Option<&str>) -> Result<u64, String> {
    let value = value.ok_or_else(|| DAEMON_USAGE.to_string())?;
    let parsed = value.parse::<u64>().map_err(|_| DAEMON_USAGE.to_string())?;
    if parsed == 0 {
        return Err(DAEMON_USAGE.to_string());
    }
    Ok(parsed)
}

pub fn run_connect_command(context: &mut Context, args: CliArgs<'_>) -> Result<CliOutput, String> {
    args.require_len(1, CONNECT_USAGE)?;
    run_connect(context, args.get(0).expect("length checked").to_string()).map(CliOutput::lines)
}

fn run_daemon_command(context: &mut Context, args: CliArgs<'_>) -> Result<CliOutput, String> {
    run_daemon(context, DaemonOptions::parse(args)?).map(CliOutput::lines)
}

pub fn run_connect(context: &mut Context, invite: String) -> Result<Vec<String>, String> {
    let output = connection_request::commands::create_with_local(&context.store, &invite)
        .map_err(|err| format!("create connection request: {err}"))?;
    let addr = output.value.addr;
    let request = event_worker::run(&context.store, &context.protocol, output)
        .map_err(|err| format!("record connection request: {err}"))?
        .0;

    let target = NetworkTarget::new(addr);
    let sent_outbox = RefCell::new(HashMap::new());
    let summary = tcp::connect_exchange(
        &context.store,
        target,
        vec![OutboundNetworkRow::new(target, request.bytes)],
        StreamSummary::default(),
        |inbound, summary| handle_inbound(context, inbound, true, summary, &sent_outbox),
        |rows, _| mark_sent_network_rows(context, rows, &sent_outbox),
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

pub fn run_serve(
    context: &mut Context,
    listen: SocketAddr,
    accept_count: usize,
) -> Result<Vec<String>, String> {
    let sent_outbox = RefCell::new(HashMap::new());
    let report = tcp::serve(
        &context.store,
        listen,
        accept_count,
        ServeSummary::default(),
        |inbound, summary| {
            let mut stream_summary = StreamSummary::default();
            let outgoing =
                handle_inbound(context, inbound, false, &mut stream_summary, &sent_outbox)?;
            summary.received_events += stream_summary.received_events;
            Ok(outgoing)
        },
        |rows, _| mark_sent_network_rows(context, rows, &sent_outbox),
    )?;
    let mut summary = report.value;
    summary.accepted_connections = report.accepted_connections;
    let mut lines = vec![format!("listening: {}", report.local_addr)];
    lines.extend(summary.lines());
    Ok(lines)
}

fn run_daemon(context: &mut Context, options: DaemonOptions) -> Result<Vec<String>, String> {
    let listener = tcp::listen(options.listen)?;
    let sent_outbox = RefCell::new(HashMap::new());
    let mut summary = DaemonSummary {
        local_addr: Some(listener.local_addr()),
        ..DaemonSummary::default()
    };
    let started = Instant::now();

    loop {
        let accept = listener.accept_available(
            &context.store,
            ServeSummary::default(),
            |inbound, stream_summary| {
                let mut one_stream = StreamSummary::default();
                let outgoing =
                    handle_inbound(context, inbound, false, &mut one_stream, &sent_outbox)?;
                stream_summary.received_events += one_stream.received_events;
                Ok(outgoing)
            },
            |rows, _| mark_sent_network_rows(context, rows, &sent_outbox),
        )?;
        summary.accepted_connections += accept.accepted_connections;
        summary.received_events += accept.value.received_events;

        let ready = event_worker::run(
            &context.store,
            &context.protocol,
            event_worker::DrainReadyBatch {
                batch_size: options.ready_batch,
            },
        )
        .map_err(|err| format!("drain daemon ready batch: {err}"))?;
        summary.ready_events += ready.applied_events;
        summary.unblocked_events += ready.unblocked_events;

        let sync = run_daemon_sync_round(context)?;
        summary.sync_rounds += 1;
        summary.routes_synced += sync.routes_synced;
        summary.failed_routes += sync.failed_routes;
        summary.sent_events += sync.sent_events;
        summary.received_events += sync.received_events;

        if options
            .duration
            .is_some_and(|duration| started.elapsed() >= duration)
        {
            return Ok(summary.lines());
        }
        thread::sleep(options.idle);
    }
}

fn run_daemon_sync_round(context: &Context) -> Result<DaemonSyncRound, String> {
    let start = match sync::worker::run(
        &context.store,
        context.protocol.modules().sync_index(),
        sync::worker::Work::Start {
            range: sync::compare::types::TimestampRange::ROOT,
        },
    )
    .map_err(|err| format!("start daemon sync: {err}"))?
    {
        sync::worker::Output::Started(output) => output,
        sync::worker::Output::DrainedInboundSync(_) => {
            return Err("sync worker returned non-start output".to_string())
        }
    };
    let (started, _) = event_worker::run(&context.store, &context.protocol, start)
        .map_err(|err| format!("record daemon sync events: {err}"))?;

    let mut summary = DaemonSyncRound {
        sent_events: started.sent_events,
        ..DaemonSyncRound::default()
    };
    for outbound in
        drain_outbox_routes(context).map_err(|err| format!("drain daemon outbox: {err}"))?
    {
        match exchange_outbound_route(context, outbound) {
            Ok(stream_summary) => {
                summary.routes_synced += 1;
                summary.sent_events += stream_summary.sent_events;
                summary.received_events += stream_summary.received_events;
            }
            Err(_) => {
                summary.failed_routes += 1;
            }
        }
    }
    Ok(summary)
}

pub fn exchange_outbound_route(
    context: &Context,
    outbound: OutboundSync,
) -> Result<StreamSummary, String> {
    let sent_outbox = RefCell::new(HashMap::new());
    remember_sent_outbox(&sent_outbox, &outbound.outgoing, &outbound.sent_outbox)?;
    tcp::connect_exchange(
        &context.store,
        outbound.target,
        outbound.outgoing,
        StreamSummary::default(),
        |inbound, summary| handle_inbound(context, inbound, false, summary, &sent_outbox),
        |rows, _| mark_sent_network_rows(context, rows, &sent_outbox),
    )
}

pub fn drain_outbox_routes(context: &Context) -> Result<Vec<OutboundSync>, String> {
    let output = connection_worker::run(
        &context.store,
        &context.protocol,
        connection_worker::Work::DrainOutboxRoutes,
    )?;
    let connection_worker::Output::OutboundRoutes(outbound) = output else {
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

fn handle_inbound(
    context: &Context,
    inbound: InboundNetworkRow,
    remember_origin: bool,
    summary: &mut StreamSummary,
    sent_outbox: &RefCell<HashMap<Vec<u8>, Vec<Vec<u8>>>>,
) -> Result<Vec<OutboundNetworkRow>, String> {
    let ingest = connection_worker::run(
        &context.store,
        &context.protocol,
        connection_worker::Work::IngestNetwork {
            inbound,
            remember_origin,
        },
    )?;
    let connection_worker::Output::NetworkIngest(ingest) = ingest else {
        return Err("connection worker returned non-network-ingest output".to_string());
    };
    summary.established_routes += ingest.established_routes;
    summary.sent_events += ingest.sent_events;
    summary.received_events += ingest.received_events;

    event_worker::run(
        &context.store,
        &context.protocol,
        event_worker::DrainUntilIdle {
            batch_size: event_worker::DEFAULT_READY_BATCH,
        },
    )
    .map_err(|err| format!("drain ready events after inbound network: {err}"))?;

    remember_sent_outbox(sent_outbox, &ingest.outgoing, &ingest.sent_outbox)?;
    Ok(ingest.outgoing)
}

fn remember_sent_outbox(
    sent_outbox: &RefCell<HashMap<Vec<u8>, Vec<Vec<u8>>>>,
    rows: &[OutboundNetworkRow],
    outbox_keys: &[Vec<Vec<u8>>],
) -> Result<(), String> {
    if outbox_keys.is_empty() {
        return Ok(());
    }
    if outbox_keys.len() > rows.len() {
        return Err("more outbox keys than outbound network rows".to_string());
    }
    let first = rows.len() - outbox_keys.len();
    let mut sent_outbox = sent_outbox.borrow_mut();
    for (row, row_outbox_keys) in rows[first..].iter().zip(outbox_keys) {
        sent_outbox
            .entry(row.key.clone())
            .or_default()
            .extend(row_outbox_keys.iter().cloned());
    }
    Ok(())
}

fn mark_sent_network_rows(
    context: &Context,
    rows: &[OutboundNetworkRow],
    sent_outbox: &RefCell<HashMap<Vec<u8>, Vec<Vec<u8>>>>,
) -> Result<(), String> {
    let mut outbox_keys = Vec::new();
    {
        let mut sent_outbox = sent_outbox.borrow_mut();
        for row in rows {
            if let Some(mut row_outbox_keys) = sent_outbox.remove(&row.key) {
                outbox_keys.append(&mut row_outbox_keys);
            }
        }
    }
    mark_outbox_sent(context, outbox_keys)
}

fn mark_outbox_sent(context: &Context, sent_outbox: Vec<Vec<u8>>) -> Result<(), String> {
    let output = connection_worker::run(
        &context.store,
        &context.protocol,
        connection_worker::Work::MarkOutboxSent { sent_outbox },
    )?;
    let connection_worker::Output::OutboxMarked = output else {
        return Err("connection worker returned non-mark-outbox output".to_string());
    };
    Ok(())
}
