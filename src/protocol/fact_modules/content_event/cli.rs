//! CLI adapter for content-event commands.

use crate::core::cli::{CliArgs, CliOutput};
use crate::core::command_context::{CommandContext, CommandOutput};
use crate::protocol::fact_modules::content_event::{commands, queries};

pub const GENERATE_USAGE: &str = "generate WORKSPACE_ID_HEX COUNT EVENT_SIZE_BYTES";
pub const CONTENT_COUNT_USAGE: &str = "content-count WORKSPACE_ID_HEX";

pub fn generate(
    ctx: &CommandContext<'_>,
    args: CliArgs<'_>,
) -> Result<CommandOutput<commands::GenerateReceipt>, String> {
    args.require_len(3, GENERATE_USAGE)?;
    let workspace_id = decode_hex_32(args.get(0).expect("length checked"), "workspace id")?;
    let count = args.parse_positive_usize(1, GENERATE_USAGE)?;
    let event_size_bytes = args.parse_positive_usize(2, GENERATE_USAGE)?;
    commands::generate(ctx, workspace_id, count, event_size_bytes)
}

pub fn generated_output(receipt: &commands::GenerateReceipt, applied_events: usize) -> CliOutput {
    CliOutput::lines(vec![
        format!("workspace_id: {}", encode_hex(&receipt.workspace_id)),
        format!("generated_events: {}", receipt.generated_events),
        format!("applied_events: {applied_events}"),
        format!("event_size_bytes: {}", receipt.event_size_bytes),
        format!("first_timestamp: {}", receipt.first_timestamp),
        format!("last_timestamp: {}", receipt.last_timestamp),
    ])
}

pub fn content_count(
    ctx: &CommandContext<'_>,
    args: CliArgs<'_>,
) -> Result<queries::ContentCount, String> {
    args.require_len(1, CONTENT_COUNT_USAGE)?;
    let workspace_id = decode_hex_32(args.get(0).expect("length checked"), "workspace id")?;
    queries::count_for_workspace(ctx.store(), workspace_id)
}

pub fn content_count_output(count: queries::ContentCount) -> CliOutput {
    CliOutput::lines(vec![
        format!("content_events: {}", count.content_events),
        format!("content_payload_bytes: {}", count.content_payload_bytes),
        format!("max_event_timestamp: {}", count.max_timestamp),
    ])
}

fn decode_hex_32(value: &str, label: &str) -> Result<[u8; 32], String> {
    if value.len() != 64 {
        return Err(format!("{label} must be 64 hex characters"));
    }
    let mut out = [0; 32];
    let bytes = value.as_bytes();
    for index in 0..32 {
        out[index] =
            (hex_nibble(bytes[index * 2], label)? << 4) | hex_nibble(bytes[index * 2 + 1], label)?;
    }
    Ok(out)
}

fn hex_nibble(byte: u8, label: &str) -> Result<u8, String> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(format!("{label} contains a non-hex character")),
    }
}

fn encode_hex(bytes: &[u8; 32]) -> String {
    let mut out = String::with_capacity(64);
    for byte in bytes {
        use std::fmt::Write;
        let _ = write!(out, "{byte:02x}");
    }
    out
}
