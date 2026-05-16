//! CLI adapter for content-event commands.
//!
//! This file owns only argv parsing and text formatting. Fact construction and
//! projected-state reads live in the module-local command/query surfaces;
//! runtime draining, handler dispatch, and persistence stay at the root
//! app/runtime boundary.

use crate::core::cli::{decode_hex_32_named as decode_hex_32, encode_hex, CliArgs, CliOutput};
use crate::core::command_context::{CommandContext, CommandOutput};
use crate::protocol::facts::content::event::{commands, queries};

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

pub fn generated_output(receipt: &commands::GenerateReceipt, applied_facts: usize) -> CliOutput {
    CliOutput::lines(vec![
        format!("workspace_id: {}", encode_hex(&receipt.workspace_id)),
        format!("generated_facts: {}", receipt.generated_facts),
        format!("applied_facts: {applied_facts}"),
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
        format!("content_facts: {}", count.content_events),
        format!("content_payload_bytes: {}", count.content_payload_bytes),
        format!("max_event_timestamp: {}", count.max_timestamp),
    ])
}
