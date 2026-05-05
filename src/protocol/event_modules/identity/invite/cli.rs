//! Invite CLI command.
//!
//! Invite creation is local identity behavior: it may create the local endpoint
//! first, then records an invite secret and prints the link. The finite
//! `--listen` form exists for black-box bootstrap tests: it prints the invite
//! before blocking in the connection worker so a separate CLI process can accept
//! it over TCP.

use std::io::Write;
use std::net::SocketAddr;

use crate::core::cli::{CliArgs, CliCommand, CliOutput};
use crate::protocol::cli::Context;
use crate::protocol::event_modules::connection::{
    types as connection_types, worker as connection_worker,
};
use crate::protocol::event_modules::worker;

const INVITE_USAGE: &str = "invite (--public-addr ADDR | --listen IP PORT [--accept N])";

pub fn commands() -> Vec<CliCommand<Context>> {
    vec![CliCommand {
        name: "invite",
        usage: INVITE_USAGE,
        help: "Create an invite link for this endpoint.",
        run: run_invite_command,
    }]
}

fn run_invite_command(context: &mut Context, args: CliArgs<'_>) -> Result<CliOutput, String> {
    let options = InviteOptions::parse(args)?;
    let public_addr = options.public_addr();
    let output = super::commands::create_with_local(&context.store, public_addr)
        .map_err(|err| format!("create invite: {err}"))?;
    let (link, _) = worker::run(&context.store, &context.protocol, output)
        .map_err(|err| format!("apply invite: {err}"))?;
    match options {
        InviteOptions::Print { .. } => Ok(CliOutput::line(link)),
        InviteOptions::Listen {
            listen,
            accept_count,
        } => {
            print_line_now(&link)?;
            let output = connection_worker::run(
                &context.store,
                &context.protocol,
                connection_worker::Work::Serve {
                    listen,
                    accept_count,
                },
            )?;
            let connection_worker::Output::Served(report) = output else {
                return Err("connection worker returned non-serve output".to_string());
            };
            Ok(CliOutput::lines(serve_lines(&report)))
        }
    }
}

enum InviteOptions {
    Print {
        public_addr: SocketAddr,
    },
    Listen {
        listen: SocketAddr,
        accept_count: usize,
    },
}

impl InviteOptions {
    fn parse(args: CliArgs<'_>) -> Result<Self, String> {
        let mut public_addr = None;
        let mut listen = None;
        let mut accept_count = 1usize;
        let mut idx = 0;
        while idx < args.values().len() {
            match args.get(idx).expect("index in bounds") {
                "--public-addr" => {
                    let addr = args
                        .get(idx + 1)
                        .ok_or_else(|| INVITE_USAGE.to_string())?
                        .parse::<SocketAddr>()
                        .map_err(|_| INVITE_USAGE.to_string())?;
                    public_addr = Some(addr);
                    idx += 2;
                }
                "--listen" => {
                    let ip = args.get(idx + 1).ok_or_else(|| INVITE_USAGE.to_string())?;
                    let port = args.get(idx + 2).ok_or_else(|| INVITE_USAGE.to_string())?;
                    listen = Some(
                        format!("{ip}:{port}")
                            .parse::<SocketAddr>()
                            .map_err(|_| INVITE_USAGE.to_string())?,
                    );
                    idx += 3;
                }
                "--accept" => {
                    accept_count = args.parse_positive_usize(idx + 1, INVITE_USAGE)?;
                    idx += 2;
                }
                other => return Err(format!("unknown invite option `{other}`\n{INVITE_USAGE}")),
            }
        }

        match (public_addr, listen) {
            (Some(public_addr), None) => Ok(Self::Print { public_addr }),
            (None, Some(listen)) => Ok(Self::Listen {
                listen,
                accept_count,
            }),
            _ => Err(INVITE_USAGE.to_string()),
        }
    }

    fn public_addr(&self) -> SocketAddr {
        match self {
            Self::Print { public_addr } => *public_addr,
            Self::Listen { listen, .. } => *listen,
        }
    }
}

fn serve_lines(report: &connection_types::ServeReport) -> Vec<String> {
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

fn print_line_now(line: &str) -> Result<(), String> {
    let stdout = std::io::stdout();
    let mut stdout = stdout.lock();
    writeln!(stdout, "{line}").map_err(|err| format!("write invite link: {err}"))?;
    stdout
        .flush()
        .map_err(|err| format!("flush invite link: {err}"))
}
