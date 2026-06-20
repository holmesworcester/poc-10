//! Generic protocol application runner.
//!
//! This file owns product-independent CLI hosting for a protocol declaration. It
//! parses top-level argv, prints help, handles daemon lifecycle commands, opens
//! the selected runtime for command turns, dispatches registered protocol
//! commands, and implements the generic `assert eventually` polling wrapper.
//!
//! `main.rs` supplies argv. The protocol supplies a `ProtocolDescription`: names,
//! runtime and daemon declarations, the command table, and a context builder.
//! This runner supplies the stable process shape around those declarations:
//! `--db`, optional command time, daemon lifecycle commands, help text, runtime
//! opening, command dispatch, and display-line printing.
//!
//! The file does not own fact layouts, projector policy, handler policy, row
//! meaning, or concrete command semantics. Change it when every protocol should
//! gain a process-level hosting behavior. Change the protocol registry or
//! command modules when only one protocol's behavior changes.

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
    pub context: fn(Runtime, Option<PathBuf>, Option<u64>) -> C,
}

// =============================================================================
// Central Procedure
// =============================================================================

/// Run one protocol CLI invocation.
///
/// This is the process edge for a protocol binary. It parses top-level options,
/// handles help before touching storage, runs the selected command path, and
/// prints the returned display lines. Protocol modules still own command
/// argument parsing and output construction through their registered
/// `CliCommand`s.
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

// =============================================================================
// Command Dispatch Stages
// =============================================================================

/// Route parsed top-level command words to the generic hosting stage.
///
/// The split here is intentionally shallow: daemon lifecycle words are owned by
/// this runner, `assert` is the generic polling wrapper, and every other command
/// must be present in the protocol command table.
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

/// Start the long-running daemon for the selected database.
///
/// Startup opens the runtime once, installs process-local recurring work, and
/// then delegates listener parsing, stop-file handling, and daemon turn driving
/// to `core::daemon`.
fn run_start<C: 'static>(
    description: &'static ProtocolDescription<C>,
    parsed: ParsedArgs,
) -> Result<CliOutput, String> {
    let db = parsed
        .db
        .ok_or_else(|| usage(description, "start requires --db PATH"))?;
    let mut runtime = Runtime::open_disk(&description.runtime, &db)?;
    // Recurring operational loops are not durable state. Runtime turns offer
    // them from this in-memory scheduler after startup.
    let mut scheduler = daemon::RecurringScheduler::install(description.runtime.handlers);
    daemon::start(
        &db,
        CliArgs::new(&parsed.command[1..]),
        |listener, limit| {
            daemon::runtime_turn(
                description.daemon,
                &mut runtime,
                daemon::RuntimeTurnHost::daemon(listener),
                &mut scheduler,
                limit,
            )
        },
    )
}

/// Stop a running daemon for the selected database.
///
/// The command is database-scoped but does not open the protocol runtime; daemon
/// lifecycle storage is owned by `core::daemon`.
fn run_stop(parsed: ParsedArgs) -> Result<CliOutput, String> {
    let db = parsed
        .db
        .ok_or_else(|| "stop requires --db PATH".to_string())?;
    daemon::stop(&db, CliArgs::new(&parsed.command[1..]))
}

/// Reset daemon lifecycle state for the selected database.
///
/// This clears daemon-owned process coordination state without interpreting
/// protocol commands or protocol rows.
fn run_reset(parsed: ParsedArgs) -> Result<CliOutput, String> {
    let db = parsed
        .db
        .ok_or_else(|| "reset requires --db PATH".to_string())?;
    daemon::reset(&db, CliArgs::new(&parsed.command[1..]))
}

/// Poll one protocol command until a scalar output field satisfies a comparison.
///
/// `assert eventually` reuses the normal protocol-command path on every poll, so
/// it observes whatever runtime progress that path performs before command
/// dispatch. The assertion layer only parses `field: value` display lines; it
/// does not inspect protocol state directly.
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
                at: parsed.at,
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

/// Run a registered protocol command inside one serialized command turn.
///
/// The runner validates the command name, acquires the database turn lock, opens
/// the declared runtime, performs the command-turn runtime work, builds the
/// protocol-owned CLI context, and then delegates argument parsing and output to
/// the registered command function.
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
    let mut runtime = Runtime::open_disk(&description.runtime, &db)?;
    let mut scheduler = daemon::RecurringScheduler::install(description.runtime.handlers);
    daemon::runtime_turn(
        description.daemon,
        &mut runtime,
        daemon::RuntimeTurnHost::local(),
        &mut scheduler,
        daemon::DEFAULT_WORK_LIMIT,
    )?;
    let mut context = (description.context)(runtime, parsed.db, parsed.at);
    cli::run(
        description.command_name,
        description.commands,
        &mut context,
        &parsed.command,
    )
    .map_err(|err| with_usage_footer(description, err))
}

// =============================================================================
// Usage Helpers
// =============================================================================

/// Build top-level usage with daemon commands plus protocol commands.
///
/// Usage is generated from the protocol declaration so the generic daemon,
/// assertion, and command-time forms stay consistent across binaries while each
/// protocol owns only its concrete command usage strings.
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
            "  {} --db PATH [--at TIMESTAMP_MS] {}",
            description.command_name, command.usage
        ));
    }
    lines.push(String::new());
    lines.push("available commands run through the target core runtime facade".to_string());
    lines.join("\n")
}

/// Attach the top-level command list when a command reports its own usage block.
fn with_usage_footer<C: 'static>(description: &ProtocolDescription<C>, err: String) -> String {
    if err.contains("\nusage:\n") {
        usage(description, &err)
    } else {
        err
    }
}

// =============================================================================
// Assert Eventually Helpers
// =============================================================================

/// Parsed form of the generic polling assertion.
///
/// The wrapped command is always a protocol command. The comparison is evaluated
/// against one scalar `field: value` line from that command's `CliOutput`.
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
    /// Parse `assert eventually` body words and validate the wrapped command.
    ///
    /// Option flags may appear anywhere in the assertion words. The final three
    /// non-option words are the field name, comparison operator, and expected
    /// value; all preceding non-option words form the wrapped protocol command.
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

/// Remove assertion options and return remaining assertion words plus timing.
///
/// Unknown words are preserved for the command/field/operator/value split.
/// Timing defaults keep ordinary CLI use responsive while allowing slower
/// daemon-observed conditions to opt into longer waits.
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

/// Parse a strictly positive millisecond option for assertion timing.
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

/// Build the focused usage text for malformed `assert eventually` invocations.
fn assert_usage<C: 'static>(description: &ProtocolDescription<C>) -> String {
    format!(
        "assert eventually COMMAND [ARGS...] FIELD OP VALUE [--timeout-ms N] [--poll-ms N]\nusage:\n  {} --db PATH assert eventually COMMAND [ARGS...] FIELD OP VALUE [--timeout-ms N] [--poll-ms N]",
        description.command_name
    )
}

/// Extract unique scalar output fields from protocol command display lines.
///
/// Lines without `:` are ignored. Duplicate field names are rejected because an
/// assertion should compare against exactly one observed value.
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

/// Supported comparisons for `assert eventually`.
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
    /// Parse the user-facing comparison operator spelling.
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

    /// Return the canonical operator spelling used in successful output.
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

    /// Compare one observed output value against the expected value.
    ///
    /// Equality is string equality. Ordering comparisons are numeric `u64`
    /// comparisons so status counters and timestamps can be asserted directly.
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

// =============================================================================
// Argument Parsing Helpers
// =============================================================================

/// Parsed top-level argv before command-specific parsing.
///
/// Only process-wide options live here. Once the first command word is seen, all
/// remaining words are preserved for the selected command path.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedArgs {
    db: Option<PathBuf>,
    at: Option<u64>,
    command: Vec<String>,
}

impl ParsedArgs {
    /// Parse process-wide `--db` and `--at` options from argv.
    ///
    /// The parser stops option handling at the first command word so
    /// protocol-owned command arguments can reuse ordinary flag syntax without
    /// being interpreted by the app runner.
    fn parse(argv: Vec<String>) -> Result<Self, String> {
        let mut db = None;
        let mut at = None;
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
                "--at" => {
                    let value = iter
                        .next()
                        .ok_or_else(|| "--at requires a timestamp".to_string())?;
                    let value = value
                        .parse::<u64>()
                        .map_err(|_| "--at requires a u64 timestamp".to_string())?;
                    if i64::try_from(value).is_err() {
                        return Err("--at timestamp exceeds SQLite integer range".to_string());
                    }
                    if at.replace(value).is_some() {
                        return Err("--at may be supplied only once".to_string());
                    }
                }
                _ => command.push(arg),
            }
        }
        Ok(Self { db, at, command })
    }
}
