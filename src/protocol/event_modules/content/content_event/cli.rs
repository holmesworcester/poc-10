//! Content-event CLI command and summary.
//!
//! `generate` creates this one event type, so its argv shape and output live at
//! the leaf module rather than the content domain root. If the content domain
//! later gains commands spanning several event types, those can live in a
//! separate domain-root `cli.rs`.

use crate::core::cli::{CliArgs, CliCommand, CliOutput};
use crate::protocol::cli::Context;
use crate::protocol::event_modules::schema as event_schema;
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
    let read = GenerateContext {
        max_timestamp: event_schema::max_timestamp(&context.store)
            .map_err(|err| format!("load max timestamp: {err}"))?,
    };
    let output = super::commands::generate_next(&read, num_events, event_size)
        .map_err(|err| format!("generate: {err}"))?;
    let report = worker::run(
        &context.store,
        &context.protocol,
        worker::AdmitAndDrain {
            output,
            batch_size: worker::DEFAULT_READY_BATCH,
        },
    )
    .map_err(|err| format!("admit and drain generated events: {err}"))?;
    Ok(CliOutput::lines(
        GenerateSummary {
            generated_events: report.admitted.inserted_events,
            applied_events: report.admitted.applied_events + report.drained.applied_events,
            event_size,
            first_timestamp: report.value.first_timestamp,
            last_timestamp: report.value.last_timestamp,
        }
        .lines(),
    ))
}

struct GenerateContext {
    max_timestamp: u64,
}

impl super::commands::GenerateRead for GenerateContext {
    fn max_timestamp(&self) -> Result<u64, String> {
        Ok(self.max_timestamp)
    }
}
