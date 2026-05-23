//! CLI adapter for auth key-material commands.
//!
//! This file owns only argv parsing and text formatting. Key construction and
//! read-model decisions live in `commands.rs`; runtime draining, handler
//! dispatch, and persistence stay at the root app/runtime boundary.

use crate::core::cli::{decode_hex_32_named as core_decode_hex_32, encode_hex, CliArgs, CliOutput};
use crate::core::command_context::{CommandContext, CommandOutput};

use super::commands;

pub const KEY_RECIPIENT_USAGE: &str = "key-recipient WORKSPACE_ID_HEX";
pub const KEY_ROTATE_RECIPIENT_USAGE: &str = "key-rotate-recipient WORKSPACE_ID_HEX";
pub const KEY_FRONTIER_USAGE: &str = "key-frontier WORKSPACE_ID_HEX";
pub const KEY_WRAP_USAGE: &str =
    "key-wrap WORKSPACE_ID_HEX REMOVAL_FRONTIER_ID_HEX RECIPIENT_KEY_ID_HEX";
pub const KEY_ACCESS_USAGE: &str = "key-access WORKSPACE_ID_HEX REMOVAL_FRONTIER_ID_HEX";
pub const KEY_DERIVE_USAGE: &str = "key-derive [LIMIT]";
pub const KEY_NODE_USAGE: &str = "key-node WORKSPACE_ID_HEX REMOVAL_FRONTIER_ID_HEX SOURCE_SECRET_ID_HEX RANGE_START RANGE_WIDTH [TOMBSTONE_NODE_ID_HEX]";
pub const KEYS_USAGE: &str = "keys WORKSPACE_ID_HEX";
pub const CHOP_NOW_USAGE: &str = "chop-now WORKSPACE_ID_HEX FLOOR_MINUTE";

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
                crate::protocol::auth::recipient_key::fact::NO_PREVIOUS_RECIPIENT_KEY,
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

pub fn key_recipient_rotation_output(
    receipt: &commands::CreateRecipientKeyReceipt,
    superseded_recipient_keys: usize,
) -> CliOutput {
    let mut output = key_recipient_output(receipt);
    output.lines.push(format!(
        "superseded_recipient_keys: {superseded_recipient_keys}"
    ));
    output
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

pub fn key_derive_limit(args: CliArgs<'_>) -> Result<usize, String> {
    if args.values().len() > 1 {
        return Err(KEY_DERIVE_USAGE.to_string());
    }
    args.get(0)
        .map(|value| {
            value
                .parse::<usize>()
                .map_err(|_| KEY_DERIVE_USAGE.to_string())
        })
        .transpose()
        .map(|limit| limit.unwrap_or(512))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyNodeArgs {
    pub workspace_id: [u8; 32],
    pub removal_frontier_id: [u8; 32],
    pub source_secret_id: [u8; 32],
    pub range_start: u64,
    pub range_width: u64,
    pub tombstone_node_id: [u8; 32],
}

pub fn key_node_args(args: CliArgs<'_>) -> Result<KeyNodeArgs, String> {
    if args.values().len() != 5 && args.values().len() != 6 {
        return Err(KEY_NODE_USAGE.to_string());
    }
    let range_start = args
        .get(3)
        .expect("length checked")
        .parse::<u64>()
        .map_err(|_| "key-node range_start must be a u64".to_string())?;
    let range_width = args
        .get(4)
        .expect("length checked")
        .parse::<u64>()
        .map_err(|_| "key-node range_width must be a u64".to_string())?;
    let tombstone_node_id = if let Some(value) = args.get(5) {
        core_decode_hex_32(value, "tombstone node id")?
    } else {
        [0; 32]
    };
    Ok(KeyNodeArgs {
        workspace_id: core_decode_hex_32(args.get(0).expect("length checked"), "workspace id")?,
        removal_frontier_id: core_decode_hex_32(
            args.get(1).expect("length checked"),
            "removal frontier id",
        )?,
        source_secret_id: core_decode_hex_32(
            args.get(2).expect("length checked"),
            "source secret id",
        )?,
        range_start,
        range_width,
        tombstone_node_id,
    })
}

pub fn keys_workspace_id(args: CliArgs<'_>) -> Result<[u8; 32], String> {
    args.require_len(1, KEYS_USAGE)?;
    core_decode_hex_32(args.get(0).expect("length checked"), "workspace id")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChopNowArgs {
    pub workspace_id: [u8; 32],
    pub floor_minute: u64,
}

pub fn chop_now_args(args: CliArgs<'_>) -> Result<ChopNowArgs, String> {
    args.require_len(2, CHOP_NOW_USAGE)?;
    Ok(ChopNowArgs {
        workspace_id: core_decode_hex_32(args.get(0).expect("length checked"), "workspace id")?,
        floor_minute: args
            .get(1)
            .expect("length checked")
            .parse::<u64>()
            .map_err(|_| "chop-now floor minute must be a u64".to_string())?,
    })
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
        format!("purged_secret_bytes: {}", receipt.purged_secret_bytes),
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

pub fn keys_output(report: &commands::KeyStatusReport) -> CliOutput {
    let mut lines = vec![
        format!("recipient_keys: {}", report.recipient_keys),
        "recipient_key_tombstones: 0".to_string(),
        format!("local_recipient_keys: {}", report.local_recipient_keys),
        format!("removal_frontiers: {}", report.removal_frontiers.len()),
        format!("key_wraps: {}", report.key_wraps),
        format!("local_key_secrets: {}", report.local_key_secrets),
        format!(
            "local_history_node_secrets: {}",
            report.local_history_node_secrets
        ),
        "local_history_minute_nodes: 0".to_string(),
        format!("local_history_leaves: {}", report.local_history_leaves),
        "local_history_trie_internals: 0".to_string(),
        "local_history_time_internals: 0".to_string(),
        format!(
            "local_history_node_tombstones: {}",
            report.local_history_node_tombstones
        ),
        format!("message_tombstones: {}", report.message_tombstones),
        format!("cover_summary: {}", encode_hex(&report.cover_summary)),
    ];
    for frontier in &report.removal_frontiers {
        lines.push(format!(
            "frontier: {} access={}",
            encode_hex(&frontier.frontier_id),
            if frontier.access { "yes" } else { "no" }
        ));
    }
    for leaf in &report.history_leaves {
        lines.push(format!(
            "history_node: {} frontier={} start={} width=1 bit_depth=256 prefix={} fact_id_in_minute={} tombstones=none",
            encode_hex(&leaf.node_id),
            encode_hex(&leaf.frontier_id),
            leaf.minute,
            encode_hex(&leaf.fact_id_in_minute),
            encode_hex(&leaf.fact_id_in_minute)
        ));
    }
    CliOutput::lines(lines)
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
    core_decode_hex_32(value, "workspace id")
}
