//! CLI summaries for dependency-cascade tests.
//!
//! The output names the observable admission behavior: how many events were
//! staged, how many were blocked by reverse replay, and whether the final drain
//! applied everything. These summaries are intentionally close to the event
//! module so black-box tests can stay small.

use crate::core::cli::{CliArgs, CliCommand, CliOutput};
use crate::protocol::cli::Context;
use crate::protocol::event_modules::schema as event_schema;
use crate::protocol::event_modules::worker::{self, CommandOutput};

const GENERATE_DEPS_USAGE: &str = "generate-deps NUM_EVENTS DEPS_PER_EVENT";
const REPLAY_DEPS_REVERSE_USAGE: &str = "replay-deps-reverse";

pub fn commands() -> Vec<CliCommand<Context>> {
    vec![
        CliCommand {
            name: "generate-deps",
            usage: GENERATE_DEPS_USAGE,
            help: "Stage dependency-bearing test events.",
            run: run_generate_command,
        },
        CliCommand {
            name: "replay-deps-reverse",
            usage: REPLAY_DEPS_REVERSE_USAGE,
            help: "Replay staged dependency-bearing events in reverse order.",
            run: run_replay_reverse_command,
        },
    ]
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventWithDepsStageSummary {
    pub staged_events: usize,
    pub deps_per_event: usize,
    pub dep_edges: usize,
    pub first_timestamp: u64,
    pub last_timestamp: u64,
}

impl EventWithDepsStageSummary {
    pub fn lines(&self) -> Vec<String> {
        vec![
            format!("staged_events: {}", self.staged_events),
            format!("deps_per_event: {}", self.deps_per_event),
            format!("dep_edges: {}", self.dep_edges),
            format!("first_timestamp: {}", self.first_timestamp),
            format!("last_timestamp: {}", self.last_timestamp),
        ]
    }
}

fn run_generate_command(context: &mut Context, args: CliArgs<'_>) -> Result<CliOutput, String> {
    args.require_len(2, GENERATE_DEPS_USAGE)?;
    let num_events = args.parse_positive_usize(0, GENERATE_DEPS_USAGE)?;
    let deps_per_event = args.parse_positive_usize(1, GENERATE_DEPS_USAGE)?;
    let output = context
        .protocol
        .modules()
        .stage_event_with_deps(&context.store, num_events, deps_per_event)
        .map_err(|err| format!("stage event_with_deps: {err}"))?;
    let (report, _) = worker::run(&context.store, &context.protocol, output)
        .map_err(|err| format!("admit staged event_with_deps: {err}"))?;
    Ok(CliOutput::lines(
        EventWithDepsStageSummary {
            staged_events: report.staged_events,
            deps_per_event: report.deps_per_event,
            dep_edges: report.dep_edges,
            first_timestamp: report.first_timestamp,
            last_timestamp: report.last_timestamp,
        }
        .lines(),
    ))
}

fn run_replay_reverse_command(
    context: &mut Context,
    args: CliArgs<'_>,
) -> Result<CliOutput, String> {
    args.require_len(0, REPLAY_DEPS_REVERSE_USAGE)?;
    let records = context
        .protocol
        .modules()
        .staged_event_with_deps_records(&context.store)
        .map_err(|err| format!("load staged event_with_deps: {err}"))?;
    if records.is_empty() {
        return Err("no staged event_with_deps to replay".to_string());
    }

    let max_deps = records
        .iter()
        .map(|record| record.dependencies.len())
        .max()
        .unwrap_or(0);
    let root_count = records.len().min(max_deps.max(1));
    let reverse_non_roots = records[root_count..].iter().rev().cloned().collect();
    let (_, reverse_report) = worker::run(
        &context.store,
        context.protocol.modules(),
        CommandOutput::with_events((), reverse_non_roots),
    )
    .map_err(|err| format!("admit reverse event_with_deps: {err}"))?;

    let blocked_after_reverse = event_schema::status_counts(&context.store)
        .map_err(|err| format!("count blocked reverse events: {err}"))?
        .blocked;

    let roots = records[..root_count].to_vec();
    let (_, root_report) = worker::run(
        &context.store,
        context.protocol.modules(),
        CommandOutput::with_events((), roots),
    )
    .map_err(|err| format!("admit event_with_deps roots: {err}"))?;
    let drain = context
        .drain_ready_events()
        .map_err(|err| format!("drain event_with_deps replay: {err}"))?;
    let final_counts = event_schema::status_counts(&context.store)
        .map_err(|err| format!("count event_with_deps replay statuses: {err}"))?;

    Ok(CliOutput::lines(
        EventWithDepsReplaySummary {
            replayed_events: records.len(),
            blocked_after_reverse,
            applied_events: reverse_report.applied_events
                + root_report.applied_events
                + drain.applied_events,
            ready_events: final_counts.ready,
            blocked_events: final_counts.blocked,
            blocked_edges: final_counts.blocked_edges,
        }
        .lines(),
    ))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventWithDepsReplaySummary {
    pub replayed_events: usize,
    pub blocked_after_reverse: usize,
    pub applied_events: usize,
    pub ready_events: usize,
    pub blocked_events: usize,
    pub blocked_edges: usize,
}

impl EventWithDepsReplaySummary {
    pub fn lines(&self) -> Vec<String> {
        vec![
            format!("replayed_events: {}", self.replayed_events),
            format!("blocked_after_reverse: {}", self.blocked_after_reverse),
            format!("applied_events: {}", self.applied_events),
            format!("ready_events: {}", self.ready_events),
            format!("blocked_events: {}", self.blocked_events),
            format!("blocked_edges: {}", self.blocked_edges),
        ]
    }
}
