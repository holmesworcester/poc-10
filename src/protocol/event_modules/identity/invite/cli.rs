//! Invite CLI command.
//!
//! Invite creation is local identity behavior: it may create the local endpoint
//! first, then records an invite secret and prints the link. Keeping the argv
//! shape here means the protocol CLI shell does not need to know which option
//! carries the public address or how an invite is formatted.

use std::io::Write;
use std::net::SocketAddr;

use crate::core::cli::{CliArgs, CliCommand, CliOutput};
use crate::protocol::cli::Context;
use crate::protocol::event_modules::{connection, worker};

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
    let public_addr = match options.mode {
        InviteMode::PublicAddr(addr) | InviteMode::Listen { listen: addr } => addr,
    };
    let output = context
        .protocol
        .modules()
        .create_invite(&context.store, public_addr)
        .map_err(|err| format!("create invite: {err}"))?;
    let (link, _) = worker::run(&context.store, &context.protocol, output)
        .map_err(|err| format!("apply invite: {err}"))?;

    match options.mode {
        InviteMode::PublicAddr(_) => Ok(CliOutput::line(link)),
        InviteMode::Listen { listen } => {
            print_line_now(&link)?;
            connection::cli::run_serve(context, listen, options.accept_count).map(CliOutput::lines)
        }
    }
}

struct InviteOptions {
    mode: InviteMode,
    accept_count: usize,
}

#[derive(Clone, Copy)]
enum InviteMode {
    PublicAddr(SocketAddr),
    Listen { listen: SocketAddr },
}

impl InviteOptions {
    fn parse(args: CliArgs<'_>) -> Result<Self, String> {
        let mut public_addr = None;
        let mut listen = None;
        let mut accept_count = 1usize;
        let mut accept_seen = false;
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
                    accept_seen = true;
                    idx += 2;
                }
                other => return Err(format!("unknown invite option `{other}`\n{INVITE_USAGE}")),
            }
        }

        let mode = match (public_addr, listen) {
            (Some(addr), None) => {
                if accept_seen {
                    return Err(INVITE_USAGE.to_string());
                }
                InviteMode::PublicAddr(addr)
            }
            (None, Some(listen)) => InviteMode::Listen { listen },
            _ => return Err(INVITE_USAGE.to_string()),
        };

        Ok(Self { mode, accept_count })
    }
}

fn print_line_now(line: &str) -> Result<(), String> {
    let stdout = std::io::stdout();
    let mut stdout = stdout.lock();
    writeln!(stdout, "{line}").map_err(|err| format!("write invite link: {err}"))?;
    stdout
        .flush()
        .map_err(|err| format!("flush invite link: {err}"))
}
