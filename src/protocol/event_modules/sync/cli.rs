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
use crate::protocol::event_modules::{connection, worker};

const SYNC_USAGE: &str = "sync [--listen IP PORT --accept N]";

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
        connection::cli::run_serve(context, listen, options.accept_count)?
    } else {
        run_sync_routes(context)?
    };
    Ok(CliOutput::lines(lines))
}

fn run_sync_routes(context: &mut Context) -> Result<Vec<String>, String> {
    context
        .drain_ready_events()
        .map_err(|err| format!("drain ready events before sync: {err}"))?;

    let start = context
        .protocol
        .modules()
        .start_sync(&context.store)
        .map_err(|err| format!("start sync: {err}"))?;
    let (started, _) = worker::run(&context.store, &context.protocol, start)
        .map_err(|err| format!("record sync frames: {err}"))?;

    let mut summary = SyncSummary {
        sent_events: started.sent_events,
        ..SyncSummary::default()
    };

    for outbound in context
        .protocol
        .modules()
        .drain_outbox_routes(&context.store)
        .map_err(|err| format!("drain sync outbox: {err}"))?
    {
        let stream_summary = connection::cli::exchange_outbound_route(context, outbound)?;
        summary.routes_synced += 1;
        summary.sent_events += stream_summary.sent_events;
        summary.received_events += stream_summary.received_events;
    }

    Ok(summary.lines())
}

struct SyncOptions {
    listen: Option<SocketAddr>,
    accept_count: usize,
}

impl SyncOptions {
    fn parse(args: CliArgs<'_>) -> Result<Self, String> {
        let mut listen = None;
        let mut accept_count = 1usize;
        let mut idx = 0;
        while idx < args.values().len() {
            match args.get(idx).expect("index in bounds") {
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
        })
    }
}
