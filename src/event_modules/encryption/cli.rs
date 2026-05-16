//! CLI adapter for encryption key commands.

use crate::core::cli::{CliArgs, CliOutput};
use crate::core::command_context::{CommandContext, CommandOutput};

use super::commands;

pub const KEY_RECIPIENT_USAGE: &str = "key-recipient WORKSPACE_ID_HEX";
pub const KEY_ROTATE_RECIPIENT_USAGE: &str = "key-rotate-recipient WORKSPACE_ID_HEX";
pub const KEY_FRONTIER_USAGE: &str = "key-frontier WORKSPACE_ID_HEX";
pub const KEY_WRAP_USAGE: &str =
    "key-wrap WORKSPACE_ID_HEX REMOVAL_FRONTIER_ID_HEX RECIPIENT_KEY_ID_HEX";
pub const KEY_ACCESS_USAGE: &str = "key-access WORKSPACE_ID_HEX REMOVAL_FRONTIER_ID_HEX";

pub fn key_recipient(
    ctx: &CommandContext<'_>,
    args: CliArgs<'_>,
) -> Result<CommandOutput<commands::CreateRecipientKeyReceipt>, String> {
    let workspace = args.get(0).ok_or_else(|| KEY_RECIPIENT_USAGE.to_string())?;
    commands::create_recipient_key(
        ctx,
        commands::CreateRecipientKey {
            created_at_ms: ctx.next_timestamp(),
            workspace_id: decode_hex_32(workspace)?,
            previous_recipient_key_id:
                crate::event_modules::encryption::fact::NO_PREVIOUS_RECIPIENT_KEY,
        },
    )
}

pub fn rotate_recipient(
    ctx: &CommandContext<'_>,
    args: CliArgs<'_>,
    previous_recipient_key_id: [u8; 32],
) -> Result<CommandOutput<commands::CreateRecipientKeyReceipt>, String> {
    args.require_len(1, KEY_ROTATE_RECIPIENT_USAGE)?;
    let workspace = args.get(0).expect("length checked");
    commands::create_recipient_key(
        ctx,
        commands::CreateRecipientKey {
            created_at_ms: ctx.next_timestamp(),
            workspace_id: decode_hex_32(workspace)?,
            previous_recipient_key_id,
        },
    )
}

pub fn key_recipient_rotation(
    ctx: &CommandContext<'_>,
    args: CliArgs<'_>,
    previous_recipient_key_id: [u8; 32],
) -> Result<CommandOutput<commands::CreateRecipientKeyReceipt>, String> {
    rotate_recipient(ctx, args, previous_recipient_key_id)
}

pub fn key_recipient_output(receipt: &commands::CreateRecipientKeyReceipt) -> CliOutput {
    CliOutput::lines(vec![
        format!(
            "local_recipient_key_id: {}",
            encode_hex(&receipt.local_recipient_key_id)
        ),
        format!(
            "recipient_key_id: {}",
            encode_hex(&receipt.recipient_key_id)
        ),
        format!("recipient_key: {}", encode_hex(&receipt.recipient_key)),
    ])
}

pub fn key_frontier(
    ctx: &CommandContext<'_>,
    args: CliArgs<'_>,
) -> Result<CommandOutput<commands::CreateKeyFrontierReceipt>, String> {
    args.require_len(1, KEY_FRONTIER_USAGE)?;
    commands::create_key_frontier(
        ctx,
        commands::CreateKeyFrontier {
            created_at_ms: ctx.next_timestamp(),
            workspace_id: decode_hex_32(args.get(0).expect("length checked"))?,
        },
    )
}

pub fn key_frontier_output(receipt: &commands::CreateKeyFrontierReceipt) -> CliOutput {
    CliOutput::lines(vec![
        format!("workspace_id: {}", encode_hex(&receipt.workspace_id)),
        format!(
            "removal_frontier_id: {}",
            encode_hex(&receipt.removal_frontier_id)
        ),
        format!(
            "local_key_secret_id: {}",
            encode_hex(&receipt.local_key_secret_id)
        ),
        format!(
            "local_signer_secret_id: {}",
            encode_hex(&receipt.local_signer_secret_id)
        ),
    ])
}

pub fn key_wrap_args(args: CliArgs<'_>) -> Result<commands::KeyWrapQuery, String> {
    args.require_len(3, KEY_WRAP_USAGE)?;
    Ok(commands::KeyWrapQuery {
        workspace_id: decode_hex_32(args.get(0).expect("length checked"))?,
        removal_frontier_id: decode_hex_32(args.get(1).expect("length checked"))?,
        recipient_key_id: decode_hex_32(args.get(2).expect("length checked"))?,
    })
}

pub fn key_wrap_output(
    workspace_id: &[u8; 32],
    removal_frontier_id: &[u8; 32],
    recipient_key_id: &[u8; 32],
    key_wrap_id: &[u8; 32],
) -> CliOutput {
    CliOutput::lines(vec![
        format!("workspace_id: {}", encode_hex(workspace_id)),
        format!("removal_frontier_id: {}", encode_hex(removal_frontier_id)),
        format!("recipient_key_id: {}", encode_hex(recipient_key_id)),
        format!("key_wrap_id: {}", encode_hex(key_wrap_id)),
    ])
}

pub fn key_wrap_lookup_output(lookup: &commands::KeyWrapLookup) -> CliOutput {
    key_wrap_output(
        &lookup.workspace_id,
        &lookup.removal_frontier_id,
        &lookup.recipient_key_id,
        &lookup.key_wrap_id,
    )
}

pub fn key_access_args(args: CliArgs<'_>) -> Result<commands::KeyAccessQuery, String> {
    args.require_len(2, KEY_ACCESS_USAGE)?;
    Ok(commands::KeyAccessQuery {
        workspace_id: decode_hex_32(args.get(0).expect("length checked"))?,
        removal_frontier_id: decode_hex_32(args.get(1).expect("length checked"))?,
    })
}

pub fn key_access_status_output(status: &commands::KeyAccessStatus) -> CliOutput {
    key_access_output(
        &status.workspace_id,
        &status.removal_frontier_id,
        status.access,
    )
}

pub fn history_node_output(receipt: &commands::CreateHistoryNodeReceipt) -> CliOutput {
    CliOutput::lines(vec![
        format!("workspace_id: {}", encode_hex(&receipt.workspace_id)),
        format!(
            "removal_frontier_id: {}",
            encode_hex(&receipt.removal_frontier_id)
        ),
        format!(
            "local_history_node_secret_id: {}",
            encode_hex(&receipt.local_history_node_secret_id)
        ),
        format!(
            "source_secret_id: {}",
            encode_hex(&receipt.source_secret_id)
        ),
        format!("range_start: {}", receipt.range_start),
        format!("range_width: {}", receipt.range_width),
        format!(
            "tombstoned_node_id: {}",
            encode_hex(&receipt.tombstone_node_id)
        ),
    ])
}

pub fn chop_now_output(receipt: &commands::ChopNowReceipt) -> CliOutput {
    CliOutput::lines(vec![
        format!("workspace_id: {}", encode_hex(&receipt.workspace_id)),
        format!("floor_minute: {}", receipt.floor_minute),
        format!(
            "subtree_tombstones_written: {}",
            receipt.subtree_tombstones_written
        ),
        format!(
            "boundary_descend_tombstones_written: {}",
            receipt.boundary_descend_tombstones_written
        ),
        format!(
            "right_side_siblings_materialized: {}",
            receipt.right_side_siblings_materialized
        ),
        format!("purged_event_bytes: {}", receipt.purged_event_bytes),
        format!(
            "subsumed_message_tombstones_gcd: {}",
            receipt.subsumed_message_tombstones_gcd
        ),
        format!(
            "subsumed_leaf_tombstones_gcd: {}",
            receipt.subsumed_leaf_tombstones_gcd
        ),
    ])
}

pub fn key_access_output(
    workspace_id: &[u8; 32],
    removal_frontier_id: &[u8; 32],
    access: bool,
) -> CliOutput {
    CliOutput::lines(vec![
        format!("workspace_id: {}", encode_hex(workspace_id)),
        format!("removal_frontier_id: {}", encode_hex(removal_frontier_id)),
        format!("access: {}", if access { "yes" } else { "no" }),
    ])
}

fn decode_hex_32(value: &str) -> Result<[u8; 32], String> {
    if value.len() != 64 {
        return Err("workspace id must be 64 hex characters".to_string());
    }
    let mut out = [0u8; 32];
    let bytes = value.as_bytes();
    for index in 0..32 {
        let hi = hex_nibble(bytes[index * 2])?;
        let lo = hex_nibble(bytes[index * 2 + 1])?;
        out[index] = (hi << 4) | lo;
    }
    Ok(out)
}

fn hex_nibble(byte: u8) -> Result<u8, String> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err("hex value contains non-hex character".to_string()),
    }
}

fn encode_hex(bytes: &[u8; 32]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(64);
    for byte in bytes {
        out.push(DIGITS[(byte >> 4) as usize] as char);
        out.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    out
}
