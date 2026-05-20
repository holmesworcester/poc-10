//! Generic protocol application runner.
//!
//! Core can launch any protocol that exports a `ProtocolDescription`: the
//! description names its runtime declaration, daemon declarations, and command
//! table. Core owns the fixed daemon cycle through `core::daemon`: accept
//! network bytes, turn inbound bytes into protocol intents, process declared
//! time wakes, run projections, dispatch intents, run projections again, and
//! finally delete claimed inbound bytes only after receive dispatch did not ask
//! to retry.
//!
//! Core still does not know command semantics. For non-daemon commands it opens
//! the declared runtime, constructs the protocol-owned context, calls the
//! registered function, and prints the returned `CliOutput`.

use crate::core::cli::{self, CliArgs, CliCommand, CliOutput};
use crate::core::daemon::{self, DaemonDescription};
use crate::core::runtime::{Runtime, RuntimeDescription};
use std::path::PathBuf;

pub struct ProtocolDescription<C: 'static> {
    pub name: &'static str,
    pub runtime: RuntimeDescription,
    pub daemon: DaemonDescription,
    pub commands: &'static [CliCommand<C>],
    pub context: fn(Runtime, Option<PathBuf>) -> C,
}

pub fn run<C: 'static>(
    description: &'static ProtocolDescription<C>,
    argv: Vec<String>,
) -> Result<(), String> {
    let parsed = ParsedArgs::parse(argv)?;
    if parsed
        .command
        .first()
        .is_some_and(|command| matches!(command.as_str(), "-h" | "--help" | "help"))
    {
        println!(
            "{}",
            usage(description, &format!("Topo {} CLI", description.name))
        );
        return Ok(());
    }

    let output = run_parsed(description, parsed)?;
    for line in output.lines {
        println!("{line}");
    }
    Ok(())
}

pub fn usage<C: 'static>(description: &ProtocolDescription<C>, reason: &str) -> String {
    let mut lines = vec![reason.to_string(), "usage:".to_string()];
    lines.extend([
        format!(
            "  {} --db PATH start --listen IP PORT [--tick-ms N] [--quiet-ms N]",
            description.name
        ),
        format!("  {} --db PATH stop", description.name),
        format!("  {} --db PATH reset", description.name),
    ]);
    for command in description.commands {
        lines.push(format!(
            "  {} --db PATH {}",
            description.name, command.usage
        ));
    }
    lines.push(String::new());
    lines.push("available commands run through the target core runtime facade".to_string());
    lines.join("\n")
}

fn run_parsed<C: 'static>(
    description: &'static ProtocolDescription<C>,
    parsed: ParsedArgs,
) -> Result<CliOutput, String> {
    let Some(command) = parsed.command.first() else {
        return Err(usage(description, "missing command"));
    };
    match command.as_str() {
        "start" => run_start(description, parsed),
        "stop" => run_stop(parsed),
        "reset" => run_reset(parsed),
        _ => run_protocol_command(description, parsed),
    }
}

fn run_start<C: 'static>(
    description: &'static ProtocolDescription<C>,
    parsed: ParsedArgs,
) -> Result<CliOutput, String> {
    let db = parsed
        .db
        .ok_or_else(|| usage(description, "start requires --db PATH"))?;
    let mut runtime = Runtime::open_disk(&description.runtime, &db)?;
    daemon::start(
        &db,
        CliArgs::new(&parsed.command[1..]),
        |listener, limit| daemon::tick(description.daemon, &mut runtime, listener, limit),
    )
}

fn run_stop(parsed: ParsedArgs) -> Result<CliOutput, String> {
    let db = parsed
        .db
        .ok_or_else(|| "stop requires --db PATH".to_string())?;
    daemon::stop(&db, CliArgs::new(&parsed.command[1..]))
}

fn run_reset(parsed: ParsedArgs) -> Result<CliOutput, String> {
    let db = parsed
        .db
        .ok_or_else(|| "reset requires --db PATH".to_string())?;
    daemon::reset(&db, CliArgs::new(&parsed.command[1..]))
}

fn run_protocol_command<C: 'static>(
    description: &'static ProtocolDescription<C>,
    parsed: ParsedArgs,
) -> Result<CliOutput, String> {
    let Some(command_name) = parsed.command.first() else {
        return Err(usage(description, "missing command"));
    };
    if !description
        .commands
        .iter()
        .any(|command| command.name == command_name)
    {
        return Err(usage(
            description,
            &format!("unknown command `{command_name}`"),
        ));
    }
    let db = parsed
        .db
        .clone()
        .ok_or_else(|| format!("{command_name} requires --db PATH"))?;
    let runtime = Runtime::open_disk(&description.runtime, &db)?;
    let mut context = (description.context)(runtime, parsed.db);
    cli::run(description.commands, &mut context, &parsed.command)
        .map_err(|err| with_usage_footer(description, err))
}

fn with_usage_footer<C: 'static>(description: &ProtocolDescription<C>, err: String) -> String {
    if err.contains("\nusage:\n") {
        usage(description, &err)
    } else {
        err
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedArgs {
    db: Option<PathBuf>,
    command: Vec<String>,
}

impl ParsedArgs {
    fn parse(argv: Vec<String>) -> Result<Self, String> {
        let mut db = None;
        let mut command = Vec::new();
        let mut iter = argv.into_iter();
        while let Some(arg) = iter.next() {
            if !command.is_empty() {
                command.push(arg);
                command.extend(iter);
                break;
            }
            match arg.as_str() {
                "--db" => {
                    let value = iter
                        .next()
                        .ok_or_else(|| "--db requires a path".to_string())?;
                    if db.replace(PathBuf::from(value)).is_some() {
                        return Err("--db may be supplied only once".to_string());
                    }
                }
                _ => command.push(arg),
            }
        }
        Ok(Self { db, command })
    }
}
