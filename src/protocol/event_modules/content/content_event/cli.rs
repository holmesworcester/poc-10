//! Content-event CLI command and summary.
//!
//! `generate` creates this one event type, so its argv shape and output live at
//! the leaf module rather than the content domain root. If the content domain
//! later gains commands spanning several event types, those can live in a
//! separate domain-root `cli.rs`.

use crate::core::cli::{CliArgs, CliCommand, CliOutput};
use crate::protocol::cli::Context;
use crate::protocol::event_modules::worker;

use super::schema;

const GENERATE_USAGE: &str = "generate WORKSPACE_ID_HEX NUM_EVENTS EVENT_SIZE_BYTES";
const CONTENT_COUNT_USAGE: &str = "content-count WORKSPACE_ID_HEX";

pub fn commands() -> Vec<CliCommand<Context>> {
    vec![
        CliCommand {
            name: "generate",
            usage: GENERATE_USAGE,
            help: "Generate content events.",
            run: run_generate_command,
        },
        CliCommand {
            name: "content-count",
            usage: CONTENT_COUNT_USAGE,
            help: "Print content counts for one workspace.",
            run: run_content_count_command,
        },
    ]
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
    args.require_len(3, GENERATE_USAGE)?;
    let workspace_id = parse_hex_id(args.get(0).expect("length checked"), GENERATE_USAGE)?;
    let num_events = args.parse_positive_usize(1, GENERATE_USAGE)?;
    let event_size = args.parse_positive_usize(2, GENERATE_USAGE)?;
    let output = context
        .protocol
        .modules()
        .generate_content(&context.store, workspace_id, num_events, event_size)
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

fn run_content_count_command(
    context: &mut Context,
    args: CliArgs<'_>,
) -> Result<CliOutput, String> {
    args.require_len(1, CONTENT_COUNT_USAGE)?;
    let workspace_id = parse_hex_id(args.get(0).expect("length checked"), CONTENT_COUNT_USAGE)?;
    let events = schema::count_for_workspace(&context.store, workspace_id)?;
    let payload_bytes = schema::payload_bytes_for_workspace(&context.store, workspace_id)?;
    Ok(CliOutput::lines(vec![
        format!("workspace_id: {}", args.get(0).expect("length checked")),
        format!("content_events: {events}"),
        format!("content_payload_bytes: {payload_bytes}"),
    ]))
}

fn parse_hex_id(value: &str, usage: &str) -> Result<[u8; 32], String> {
    if value.len() != 64 {
        return Err(usage.to_string());
    }
    let mut out = [0; 32];
    let bytes = value.as_bytes();
    for idx in 0..32 {
        out[idx] = (hex_value(bytes[idx * 2], usage)? << 4) | hex_value(bytes[idx * 2 + 1], usage)?;
    }
    Ok(out)
}

fn hex_value(byte: u8, usage: &str) -> Result<u8, String> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(usage.to_string()),
    }
}
