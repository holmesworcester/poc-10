//! Invite CLI command.
//!
//! Invite creation is local identity behavior: it may create the local endpoint
//! first, then records an invite secret and prints the link. Keeping the argv
//! shape here means the protocol CLI shell does not need to know which option
//! carries the public address or how an invite is formatted.

use std::net::SocketAddr;

use crate::core::cli::{CliArgs, CliCommand, CliOutput};
use crate::protocol::cli::Context;
use crate::protocol::event_modules::worker;

const INVITE_USAGE: &str = "invite --public-addr ADDR";

pub fn commands() -> Vec<CliCommand<Context>> {
    vec![CliCommand {
        name: "invite",
        usage: INVITE_USAGE,
        help: "Create an invite link for this endpoint.",
        run: run_invite_command,
    }]
}

fn run_invite_command(context: &mut Context, args: CliArgs<'_>) -> Result<CliOutput, String> {
    let public_addr = parse_public_addr(args)?;
    let output = context
        .protocol
        .modules()
        .create_invite(&context.store, public_addr)
        .map_err(|err| format!("create invite: {err}"))?;
    let (link, _) = worker::run(&context.store, &context.protocol, output)
        .map_err(|err| format!("apply invite: {err}"))?;
    Ok(CliOutput::line(link))
}

fn parse_public_addr(args: CliArgs<'_>) -> Result<SocketAddr, String> {
    let mut public_addr = None;
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
            other => return Err(format!("unknown invite option `{other}`\n{INVITE_USAGE}")),
        }
    }
    public_addr.ok_or_else(|| INVITE_USAGE.to_string())
}
