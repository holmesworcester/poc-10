//! Sync CLI commands and summaries.
//!
//! These counters describe the externally visible sync exchange while keeping
//! the top-level CLI independent of sync item internals. The `sync` command is
//! also the temporary POC entrypoint for serving a finite number of inbound TCP
//! streams; once the long-lived control loop exists, that serving mode should
//! become runtime wiring rather than sync command syntax.

use std::net::SocketAddr;

use crate::core::cli::{CliArgs, CliCommand, CliOutput};
use crate::protocol::cli::Context;
use crate::protocol::event_modules::{connection::worker as connection_worker, worker};

use super::worker::{self as sync_worker, SyncSelection};

const SYNC_USAGE: &str = "sync [today] [--listen IP PORT --accept N]";

pub fn commands() -> Vec<CliCommand<Context>> {
    vec![CliCommand {
        name: "sync",
        usage: SYNC_USAGE,
        help: "Start sync, or serve a finite number of inbound sync streams.",
        run: run_sync_command,
    }]
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SyncSummary {
    pub routes_synced: usize,
    pub sent_events: usize,
    pub received_events: usize,
}

impl SyncSummary {
    pub fn lines(&self) -> Vec<String> {
        vec![
            format!("routes_synced: {}", self.routes_synced),
            format!("sent_events: {}", self.sent_events),
            format!("received_events: {}", self.received_events),
        ]
    }
}

fn run_sync_command(context: &mut Context, args: CliArgs<'_>) -> Result<CliOutput, String> {
    let options = SyncOptions::parse(args)?;
    let lines = if let Some(listen) = options.listen {
        if options.selection != SyncSelection::All {
            return Err(format!(
                "sync range selection cannot be used with --listen\n{SYNC_USAGE}"
            ));
        }
        let output = connection_worker::run(
            &context.store,
            &context.protocol,
            connection_worker::Work::Serve {
                listen,
                accept_count: options.accept_count,
            },
        )?;
        let connection_worker::Output::Served(report) = output else {
            return Err("connection worker returned non-serve output".to_string());
        };
        serve_lines(&report)
    } else {
        run_sync_routes(context, options.selection)?
    };
    Ok(CliOutput::lines(lines))
}

fn run_sync_routes(context: &mut Context, selection: SyncSelection) -> Result<Vec<String>, String> {
    worker::run(
        &context.store,
        &context.protocol,
        worker::DrainUntilIdle {
            batch_size: worker::DEFAULT_READY_BATCH,
        },
    )
    .map_err(|err| format!("drain ready events before sync: {err}"))?;

    let start = match sync_worker::run(
        &context.store,
        context.protocol.modules().sync_index(),
        sync_worker::Work::Start { selection },
    )
    .map_err(|err| format!("start sync: {err}"))?
    {
        sync_worker::Output::Started(output) => output,
        sync_worker::Output::DrainedInboundSync(_) => {
            return Err("sync worker returned non-start output".to_string())
        }
    };
    let (started, _) = worker::run(&context.store, &context.protocol, start)
        .map_err(|err| format!("record sync events: {err}"))?;

    let mut summary = SyncSummary {
        sent_events: started.sent_events,
        ..SyncSummary::default()
    };

    let exchanged = connection_worker::run(
        &context.store,
        &context.protocol,
        connection_worker::Work::ExchangeOutboundRoutes,
    )
    .map_err(|err| format!("exchange sync outbox routes: {err}"))?;
    let connection_worker::Output::RoutesExchanged(exchanged) = exchanged else {
        return Err("connection worker returned non-route-exchange output".to_string());
    };
    summary.routes_synced += exchanged.routes_synced;
    summary.sent_events += exchanged.sent_events;
    summary.received_events += exchanged.received_events;

    Ok(summary.lines())
}

struct SyncOptions {
    listen: Option<SocketAddr>,
    accept_count: usize,
    selection: SyncSelection,
}

impl SyncOptions {
    fn parse(args: CliArgs<'_>) -> Result<Self, String> {
        let mut listen = None;
        let mut accept_count = 1usize;
        let mut selection = SyncSelection::All;
        let mut idx = 0;
        while idx < args.values().len() {
            match args.get(idx).expect("index in bounds") {
                "today" => {
                    selection = SyncSelection::Today;
                    idx += 1;
                }
                "--listen" => {
                    let ip = args.get(idx + 1).ok_or_else(|| SYNC_USAGE.to_string())?;
                    let port = args.get(idx + 2).ok_or_else(|| SYNC_USAGE.to_string())?;
                    listen = Some(
                        format!("{ip}:{port}")
                            .parse::<SocketAddr>()
                            .map_err(|_| SYNC_USAGE.to_string())?,
                    );
                    idx += 3;
                }
                "--accept" => {
                    accept_count = args.parse_positive_usize(idx + 1, SYNC_USAGE)?;
                    idx += 2;
                }
                other => return Err(format!("unknown sync option `{other}`\n{SYNC_USAGE}")),
            }
        }
        Ok(Self {
            listen,
            accept_count,
            selection,
        })
    }
}

fn serve_lines(report: &connection_worker::ServeReport) -> Vec<String> {
    let mut lines = Vec::new();
    if let Some(local_addr) = report.local_addr {
        lines.push(format!("listening: {local_addr}"));
    }
    lines.extend([
        format!("accepted_connections: {}", report.accepted_connections),
        format!("received_events: {}", report.received_events),
    ]);
    lines
}
