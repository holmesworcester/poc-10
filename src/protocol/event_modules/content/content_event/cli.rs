//! Content-event CLI command and summary.
//!
//! `generate` creates this one event type, so its argv shape and output live at
//! the leaf module rather than the content domain root. If the content domain
//! later gains commands spanning several event types, those can live in a
//! separate domain-root `cli.rs`.

use crate::core::cli::{CliArgs, CliCommand, CliOutput};
use crate::protocol::cli::Context;
use crate::protocol::event_modules::worker;

const GENERATE_USAGE: &str = "generate NUM_EVENTS EVENT_SIZE_BYTES";

pub fn commands() -> Vec<CliCommand<Context>> {
    vec![CliCommand {
        name: "generate",
        usage: GENERATE_USAGE,
        help: "Generate content events.",
        run: run_generate_command,
    }]
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenerateSummary {
    pub generated_events: usize,
    pub applied_events: usize,
    pub event_size: usize,
    pub first_timestamp: u64,
    pub last_timestamp: u64,
}

impl GenerateSummary {
    pub fn lines(&self) -> Vec<String> {
        vec![
            format!("generated_events: {}", self.generated_events),
            format!("applied_events: {}", self.applied_events),
            format!("event_size_bytes: {}", self.event_size),
            format!("first_timestamp: {}", self.first_timestamp),
            format!("last_timestamp: {}", self.last_timestamp),
        ]
    }
}

fn run_generate_command(context: &mut Context, args: CliArgs<'_>) -> Result<CliOutput, String> {
    args.require_len(2, GENERATE_USAGE)?;
    let num_events = args.parse_positive_usize(0, GENERATE_USAGE)?;
    let event_size = args.parse_positive_usize(1, GENERATE_USAGE)?;
    let output = context
        .protocol
        .modules()
        .generate_content(&context.store, num_events, event_size)
        .map_err(|err| format!("generate: {err}"))?;
    let (report, admitted) = worker::run(&context.store, &context.protocol, output)
        .map_err(|err| format!("admit generated events: {err}"))?;
    let drained = context.drain_ready_events()?;
    Ok(CliOutput::lines(
        GenerateSummary {
            generated_events: admitted.inserted_events,
            applied_events: admitted.applied_events + drained.applied_events,
            event_size,
            first_timestamp: report.first_timestamp,
            last_timestamp: report.last_timestamp,
        }
        .lines(),
    ))
}
