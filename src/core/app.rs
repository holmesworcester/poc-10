//! Generic protocol application runner.
//!
//! Core can launch any protocol that exports a `ProtocolDescription`: the
//! description names its runtime declaration, daemon declarations, and command
//! table. Core owns the fixed daemon cycle through `core::daemon`: fire
//! recurring intents, accept network bytes, commit protocol intake effects,
//! process declared time wakes, then drain one projection batch and one intent
//! batch.
//!
//! Core still does not know command semantics. For non-daemon commands it opens
//! the declared runtime, constructs the protocol-owned context, calls the
//! registered function, and prints the returned `CliOutput`. The generic
//! `assert eventually` wrapper repeats that same command path and compares only
//! scalar `field: value` output lines.
//!
//! This file sits between `main.rs` and the protocol. The binary supplies argv;
//! the protocol supplies declarations; this runner supplies the stable process
//! shape: `--db`, daemon lifecycle commands, help, runtime opening, and command
//! dispatch. Change this file when every protocol should gain a new hosting
//! behavior. Change the protocol registry or command modules when only the
//! concrete protocol changes.
//!
//! The runner deliberately returns display lines only at the edge. Commands
//! produce facts, intents, rows, or query output through their own modules; core
//! does not inspect that domain data while routing the CLI.

use crate::core::cli::{self, CliArgs, CliCommand, CliOutput};
use crate::core::daemon::{self, DaemonDescription};
use crate::core::runtime::{Runtime, RuntimeDescription};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::thread;
use std::time::{Duration, Instant};

/// Complete protocol declaration needed by the generic CLI runner.
pub struct ProtocolDescription<C: 'static> {
    /// Product name used in help text.
    pub display_name: &'static str,
    /// Program name used in usage output.
    pub command_name: &'static str,
    /// Runtime schema, projection, matching, and handler declarations.
    pub runtime: RuntimeDescription,
    /// Long-running daemon declarations.
    pub daemon: DaemonDescription,
    /// Non-daemon command registry.
    pub commands: &'static [CliCommand<C>],
    /// Convert an opened runtime into the protocol-owned CLI context.
    pub context: fn(Runtime, Option<PathBuf>) -> C,
}

/// Run one protocol CLI invocation.
///
/// `app` owns the generic command split: help, daemon lifecycle commands, and
/// protocol command dispatch. Protocol modules still own their command parsers
/// and output formatting through their registered `CliCommand`s.
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
            usage(description, &format!("{} CLI", description.display_name))
        );
        return Ok(());
    }

    let output = run_parsed(description, parsed)?;
    for line in output.lines {
        println!("{line}");
    }
    Ok(())
}

/// Build top-level usage with daemon commands plus protocol commands.
pub fn usage<C: 'static>(description: &ProtocolDescription<C>, reason: &str) -> String {
    let mut lines = vec![reason.to_string(), "usage:".to_string()];
    lines.extend([
        format!(
            "  {} --db PATH start --listen IP PORT [--tick-ms N] [--quiet-ms N]",
            description.command_name
        ),
        format!("  {} --db PATH stop", description.command_name),
        format!("  {} --db PATH reset", description.command_name),
        format!(
            "  {} --db PATH assert eventually COMMAND [ARGS...] FIELD OP VALUE [--timeout-ms N] [--poll-ms N]",
            description.command_name
        ),
    ]);
    for command in description.commands {
        lines.push(format!(
            "  {} --db PATH {}",
            description.command_name, command.usage
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
        "assert" => run_assert(description, parsed),
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
    // Recurring operational loops are not durable state. The daemon tick fires
    // due schedules from this in-memory scheduler after startup.
    let mut scheduler =
        daemon::RecurringScheduler::install(description.runtime.handlers, daemon::now_ms());
    daemon::start(
        &db,
        CliArgs::new(&parsed.command[1..]),
        |listener, limit| {
            daemon::tick(
                description.daemon,
                &mut runtime,
                listener,
                &mut scheduler,
                limit,
            )
        },
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

fn run_assert<C: 'static>(
    description: &'static ProtocolDescription<C>,
    parsed: ParsedArgs,
) -> Result<CliOutput, String> {
    let db = parsed
        .db
        .clone()
        .ok_or_else(|| "assert requires --db PATH".to_string())?;
    let assertion = EventuallyAssertion::parse(description, &parsed.command[1..])?;
    let started = Instant::now();
    let timeout = Duration::from_millis(assertion.timeout_ms);
    let poll = Duration::from_millis(assertion.poll_ms);
    let mut polls = 0usize;
    let mut last_observed = String::from("missing field");

    loop {
        polls += 1;
        let command_output = run_protocol_command(
            description,
            ParsedArgs {
                db: Some(db.clone()),
                command: assertion.command.clone(),
            },
        )?;
        let fields = output_fields(&command_output)?;
        if let Some(observed) = fields.get(&assertion.field) {
            last_observed = observed.clone();
            if assertion.op.matches(observed, &assertion.expected)? {
                return Ok(CliOutput::lines(vec![
                    "ok: true".to_string(),
                    format!("command: {}", assertion.command.join(" ")),
                    format!("field: {}", assertion.field),
                    format!("op: {}", assertion.op.as_str()),
                    format!("expected: {}", assertion.expected),
                    format!("observed: {observed}"),
                    format!("elapsed_ms: {}", started.elapsed().as_millis()),
                    format!("polls: {polls}"),
                ]));
            }
        }

        if started.elapsed() >= timeout {
            return Err(format!(
                "assert eventually timed out after {}ms: {} {} {} {}, last observed {}",
                assertion.timeout_ms,
                assertion.command.join(" "),
                assertion.field,
                assertion.op.as_str(),
                assertion.expected,
                last_observed,
            ));
        }
        thread::sleep(poll);
    }
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
    let _turn = daemon::RuntimeTurnLock::acquire(&db)?;
    let runtime = Runtime::open_disk(&description.runtime, &db)?;
    let mut context = (description.context)(runtime, parsed.db);
    cli::run(
        description.command_name,
        description.commands,
        &mut context,
        &parsed.command,
    )
    .map_err(|err| with_usage_footer(description, err))
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct EventuallyAssertion {
    command: Vec<String>,
    field: String,
    op: CompareOp,
    expected: String,
    timeout_ms: u64,
    poll_ms: u64,
}

impl EventuallyAssertion {
    fn parse<C: 'static>(
        description: &ProtocolDescription<C>,
        args: &[String],
    ) -> Result<Self, String> {
        let (args, timeout_ms, poll_ms) = parse_assert_options(description, args)?;
        if args.first().map(String::as_str) != Some("eventually") {
            return Err(assert_usage(description));
        }
        let body = &args[1..];
        if body.len() < 4 {
            return Err(assert_usage(description));
        }

        let field_index = body.len() - 3;
        let command = body[..field_index].to_vec();
        let Some(command_name) = command.first().map(String::as_str) else {
            return Err(assert_usage(description));
        };
        if matches!(command_name, "assert" | "start" | "stop" | "reset") {
            return Err("assert eventually can wrap only protocol commands".to_string());
        }
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

        Ok(Self {
            command,
            field: body[field_index].clone(),
            op: CompareOp::parse(description, &body[field_index + 1])?,
            expected: body[field_index + 2].clone(),
            timeout_ms,
            poll_ms,
        })
    }
}

fn parse_assert_options<C: 'static>(
    description: &ProtocolDescription<C>,
    args: &[String],
) -> Result<(Vec<String>, u64, u64), String> {
    let mut remaining = Vec::new();
    let mut timeout_ms = 30_000u64;
    let mut poll_ms = 250u64;
    let mut index = 0usize;
    while index < args.len() {
        match args[index].as_str() {
            "--timeout-ms" => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| assert_usage(description))?;
                timeout_ms = parse_positive_u64(description, value)?;
                index += 2;
            }
            "--poll-ms" => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| assert_usage(description))?;
                poll_ms = parse_positive_u64(description, value)?;
                index += 2;
            }
            _ => {
                remaining.push(args[index].clone());
                index += 1;
            }
        }
    }
    Ok((remaining, timeout_ms, poll_ms))
}

fn parse_positive_u64<C: 'static>(
    description: &ProtocolDescription<C>,
    value: &str,
) -> Result<u64, String> {
    value
        .parse::<u64>()
        .ok()
        .filter(|value| *value > 0)
        .ok_or_else(|| assert_usage(description))
}

fn assert_usage<C: 'static>(description: &ProtocolDescription<C>) -> String {
    format!(
        "assert eventually COMMAND [ARGS...] FIELD OP VALUE [--timeout-ms N] [--poll-ms N]\nusage:\n  {} --db PATH assert eventually COMMAND [ARGS...] FIELD OP VALUE [--timeout-ms N] [--poll-ms N]",
        description.command_name
    )
}

fn output_fields(output: &CliOutput) -> Result<BTreeMap<String, String>, String> {
    let mut fields = BTreeMap::new();
    for line in &output.lines {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let key = key.trim();
        if key.is_empty() {
            continue;
        }
        if fields
            .insert(key.to_string(), value.trim().to_string())
            .is_some()
        {
            return Err(format!("assert eventually saw duplicate field `{key}`"));
        }
    }
    Ok(fields)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CompareOp {
    Eq,
    Ne,
    Gt,
    Gte,
    Lt,
    Lte,
}

impl CompareOp {
    fn parse<C: 'static>(
        description: &ProtocolDescription<C>,
        value: &str,
    ) -> Result<Self, String> {
        match value {
            "=" | "==" | "eq" => Ok(Self::Eq),
            "!=" | "ne" => Ok(Self::Ne),
            ">" | "gt" => Ok(Self::Gt),
            ">=" | "gte" => Ok(Self::Gte),
            "<" | "lt" => Ok(Self::Lt),
            "<=" | "lte" => Ok(Self::Lte),
            _ => Err(assert_usage(description)),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Eq => "==",
            Self::Ne => "!=",
            Self::Gt => ">",
            Self::Gte => ">=",
            Self::Lt => "<",
            Self::Lte => "<=",
        }
    }

    fn matches(self, observed: &str, expected: &str) -> Result<bool, String> {
        match self {
            Self::Eq => Ok(observed == expected),
            Self::Ne => Ok(observed != expected),
            Self::Gt | Self::Gte | Self::Lt | Self::Lte => {
                let observed = observed
                    .parse::<u64>()
                    .map_err(|_| format!("observed value {observed:?} is not numeric"))?;
                let expected = expected
                    .parse::<u64>()
                    .map_err(|_| format!("expected value {expected:?} is not numeric"))?;
                Ok(match self {
                    Self::Gt => observed > expected,
                    Self::Gte => observed >= expected,
                    Self::Lt => observed < expected,
                    Self::Lte => observed <= expected,
                    Self::Eq | Self::Ne => unreachable!(),
                })
            }
        }
    }
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
