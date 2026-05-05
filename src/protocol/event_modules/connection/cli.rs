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

use crate::core::cli::{CliArgs, CliCommand, CliOutput};
use crate::core::network_queues::{InboundNetworkRow, NetworkTarget, OutboundNetworkRow};
use crate::core::tcp;
use crate::protocol::cli::Context;
use crate::protocol::event_modules::worker as event_worker;

use super::super::OutboundSync;
use super::worker as connection_worker;

const CONNECT_USAGE: &str = "connect INVITE_LINK";
const ACCEPT_USAGE: &str = "accept INVITE_LINK";

pub fn commands() -> Vec<CliCommand<Context>> {
    vec![
        CliCommand {
            name: "connect",
            usage: CONNECT_USAGE,
            help: "Connect to an invite over real TCP.",
            run: run_connect_command,
        },
        CliCommand {
            name: "accept",
            usage: ACCEPT_USAGE,
            help: "Accept an invite over real TCP.",
            run: run_accept_command,
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

impl ServeSummary {
    pub fn lines(&self) -> Vec<String> {
        vec![
            format!("accepted_connections: {}", self.accepted_connections),
            format!("received_events: {}", self.received_events),
        ]
    }
}

pub fn run_connect_command(context: &mut Context, args: CliArgs<'_>) -> Result<CliOutput, String> {
    args.require_len(1, CONNECT_USAGE)?;
    run_connect(context, args.get(0).expect("length checked").to_string()).map(CliOutput::lines)
}

pub fn run_accept_command(context: &mut Context, args: CliArgs<'_>) -> Result<CliOutput, String> {
    args.require_len(1, ACCEPT_USAGE)?;
    run_connect(context, args.get(0).expect("length checked").to_string()).map(CliOutput::lines)
}

pub fn run_connect(context: &mut Context, invite: String) -> Result<Vec<String>, String> {
    let addr = context.protocol.modules().invite_addr(&invite)?;
    let output = context
        .protocol
        .modules()
        .create_connection_request(&context.store, &invite)?;
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

fn handle_inbound(
    context: &Context,
    inbound: InboundNetworkRow,
    remember_origin: bool,
    summary: &mut StreamSummary,
    sent_outbox: &RefCell<HashMap<Vec<u8>, Vec<Vec<u8>>>>,
) -> Result<Vec<OutboundNetworkRow>, String> {
    let local = context
        .protocol
        .modules()
        .existing_local_keypair(&context.store)?;
    let ingest = connection_worker::run(
        &context.store,
        &context.protocol,
        connection_worker::Work::IngestNetwork {
            local,
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

    context.drain_ready_events()?;

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
    context
        .protocol
        .modules()
        .mark_outbox_sent(&context.store, outbox_keys)
}
