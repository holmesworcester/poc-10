//! Command host functions for the concrete `match` protocol.
//!
//! Fact-scope `cli.rs` modules own argv parsing, text formatting, and command
//! output construction. Core owns runtime opening and final printing. These
//! host functions add the protocol-specific runtime context between those two:
//! they borrow read-only command context, submit fact/intent output when a
//! command authors work, and drain only local projection/intent work that the
//! CLI command itself is responsible for observing.

use crate::core::cli::{
    decode_hex_32_named as core_decode_hex_32, encode_hex as core_encode_hex,
    encode_hex_32 as core_encode_hex_32, CliArgs, CliOutput,
};
use crate::core::clock;
use crate::core::command_context::{
    CommandClock, IdentityVault, LocalEncryptionCapability, LocalSigningCapability, WorkspaceId,
};
use crate::core::daemon;
use crate::core::runtime::Runtime;
use crate::protocol::facts::sync;
use crate::protocol::facts::{content, encryption, identity};
use crate::protocol::intents::content::purge_below_retention_floor::{
    purge_below_retention_floor_intent, PurgeBelowRetentionFloor,
};
use crate::protocol::registry::CLI_EFFECT_HANDLER_ROUTES;
use std::collections::BTreeSet;
use std::path::PathBuf;

pub(crate) const DELETE_FILE_USAGE: &str = "delete-file WORKSPACE_ID_HEX FILE_SELECTOR";
pub(crate) const KEY_DERIVE_USAGE: &str = "key-derive [LIMIT]";
pub(crate) const KEY_NODE_USAGE: &str = "key-node WORKSPACE_ID_HEX REMOVAL_FRONTIER_ID_HEX SOURCE_SECRET_ID_HEX RANGE_START RANGE_WIDTH [TOMBSTONE_NODE_ID_HEX]";
pub(crate) const KEYS_USAGE: &str = "keys WORKSPACE_ID_HEX";
pub(crate) const CHOP_NOW_USAGE: &str = "chop-now WORKSPACE_ID_HEX FLOOR_MINUTE";
pub(crate) const DISAPPEARING_SET_USAGE: &str =
    "disappearing-set WORKSPACE_ID_HEX TTL_MINUTES [--floor MINUTE]";
pub(crate) const DISAPPEARING_STATUS_USAGE: &str = "disappearing-status WORKSPACE_ID_HEX";
pub(crate) const DISAPPEARING_TIGHTEN_USAGE: &str =
    "disappearing-tighten WORKSPACE_ID_HEX TTL_MINUTES [--yes|-y]";
pub(crate) const DISAPPEARING_COMPACT_USAGE: &str = "disappearing-compact WORKSPACE_ID_HEX";
pub(crate) const SYNC_STATUS_USAGE: &str = "sync-status";
pub(crate) const NEGENTROPY_DRAIN_USAGE: &str = "negentropy-drain [LIMIT]";
pub(crate) const CLOCK_USAGE: &str = "clock [set TIMESTAMP|advance DELTA|clear]";

fn command_error(reason: &str) -> String {
    reason.to_string()
}

pub struct MatchCliContext {
    db: Option<PathBuf>,
    runtime: Runtime,
}

impl MatchCliContext {
    pub fn new(runtime: Runtime, db: Option<PathBuf>) -> Self {
        Self { db, runtime }
    }

    fn db_path(&self, command: &str) -> Result<&PathBuf, String> {
        self.db
            .as_ref()
            .ok_or_else(|| command_error(&format!("{command} requires --db PATH")))
    }

    fn runtime(&self) -> &Runtime {
        &self.runtime
    }

    fn runtime_mut(&mut self) -> &mut Runtime {
        &mut self.runtime
    }

    fn drain_local_work(&mut self) -> Result<(), String> {
        process_runtime_until_idle(&mut self.runtime)
    }
}

pub(crate) fn accept(ctx: &mut MatchCliContext, args: CliArgs<'_>) -> Result<CliOutput, String> {
    let from_listen_addr = daemon::current_listen_addr(ctx.db_path("accept")?)?;
    let clock = SystemClock;
    let vault = EmptyVault;
    let output = {
        let command_context = ctx.runtime().command_context(&clock, &vault);
        identity::invite::cli::accept(&command_context, args, from_listen_addr)?
    };
    let receipt = ctx.runtime_mut().submit_command_output(output)?;
    Ok(identity::invite::cli::accept_output(&receipt))
}

pub(crate) fn accept_invite_server(
    ctx: &mut MatchCliContext,
    args: CliArgs<'_>,
) -> Result<CliOutput, String> {
    let from_listen_addr = daemon::current_listen_addr(ctx.db_path("accept-invite-server")?)?;
    let clock = SystemClock;
    let vault = EmptyVault;
    let output = {
        let command_context = ctx.runtime().command_context(&clock, &vault);
        identity::invite::cli::accept_invite_server(&command_context, args, from_listen_addr)?
    };
    let receipt = ctx.runtime_mut().submit_command_output(output)?;
    Ok(identity::invite::cli::accept_output(&receipt))
}

pub(crate) fn accept_link(
    ctx: &mut MatchCliContext,
    args: CliArgs<'_>,
) -> Result<CliOutput, String> {
    let from_listen_addr = daemon::current_listen_addr(ctx.db_path("accept-link")?)?;
    let clock = SystemClock;
    let vault = EmptyVault;
    let output = {
        let command_context = ctx.runtime().command_context(&clock, &vault);
        identity::invite::cli::accept_link(&command_context, args, from_listen_addr)?
    };
    let receipt = ctx.runtime_mut().submit_command_output(output)?;
    Ok(identity::invite::cli::accept_output(&receipt))
}

pub(crate) fn identity(ctx: &mut MatchCliContext, args: CliArgs<'_>) -> Result<CliOutput, String> {
    let clock = SystemClock;
    let vault = EmptyVault;
    let command_context = ctx.runtime().command_context(&clock, &vault);
    identity::endpoint_shared::cli::identity(&command_context, args)
}

pub(crate) fn peers(ctx: &mut MatchCliContext, args: CliArgs<'_>) -> Result<CliOutput, String> {
    let clock = SystemClock;
    let vault = EmptyVault;
    let command_context = ctx.runtime().command_context(&clock, &vault);
    identity::endpoint_shared::cli::peers(&command_context, args)
}

pub(crate) fn invite(ctx: &mut MatchCliContext, args: CliArgs<'_>) -> Result<CliOutput, String> {
    let clock = SystemClock;
    let vault = EmptyVault;
    let output = {
        let command_context = ctx.runtime().command_context(&clock, &vault);
        identity::invite::cli::invite(&command_context, args)?
    };
    let receipt = ctx.runtime_mut().submit_command_output(output)?;
    ctx.drain_local_work()?;
    Ok(identity::invite::cli::invite_output(&receipt))
}

pub(crate) fn invite_server(
    ctx: &mut MatchCliContext,
    args: CliArgs<'_>,
) -> Result<CliOutput, String> {
    let clock = SystemClock;
    let vault = EmptyVault;
    let output = {
        let command_context = ctx.runtime().command_context(&clock, &vault);
        identity::invite::cli::invite_server(&command_context, args)?
    };
    let receipt = ctx.runtime_mut().submit_command_output(output)?;
    ctx.drain_local_work()?;
    Ok(identity::invite::cli::invite_output(&receipt))
}

pub(crate) fn link(ctx: &mut MatchCliContext, args: CliArgs<'_>) -> Result<CliOutput, String> {
    let clock = SystemClock;
    let vault = EmptyVault;
    let output = {
        let command_context = ctx.runtime().command_context(&clock, &vault);
        identity::invite::cli::link(&command_context, args)?
    };
    let receipt = ctx.runtime_mut().submit_command_output(output)?;
    ctx.drain_local_work()?;
    Ok(identity::invite::cli::invite_output(&receipt))
}

pub(crate) fn create_workspace(
    ctx: &mut MatchCliContext,
    args: CliArgs<'_>,
) -> Result<CliOutput, String> {
    let clock = SystemClock;
    let vault = EmptyVault;
    let output = {
        let command_context = ctx.runtime().command_context(&clock, &vault);
        identity::workspace::cli::create_workspace(&command_context, args)?
    };
    let receipt = ctx.runtime_mut().submit_command_output(output)?;
    ctx.drain_local_work()?;
    let workspace = identity::workspace::queries::workspace_by_id(
        ctx.runtime().store(),
        receipt.workspace_fact_id,
    )?;
    let bootstrap_user_id = identity::user::queries::users_in_workspace(
        ctx.runtime().store(),
        receipt.workspace_fact_id,
    )?
    .first()
    .map(|user| user.user_id);
    Ok(identity::workspace::cli::created_workspace_output(
        &workspace,
        bootstrap_user_id,
    ))
}

pub(crate) fn workspaces(
    ctx: &mut MatchCliContext,
    args: CliArgs<'_>,
) -> Result<CliOutput, String> {
    let clock = SystemClock;
    let vault = EmptyVault;
    let output = {
        let command_context = ctx.runtime().command_context(&clock, &vault);
        identity::workspace::cli::workspaces(&command_context, args)?
    };
    Ok(identity::workspace::cli::workspaces_output(&output))
}

pub(crate) fn count(ctx: &mut MatchCliContext, args: CliArgs<'_>) -> Result<CliOutput, String> {
    args.require_len(0, identity::workspace::cli::COUNT_USAGE)?;
    let report = identity::workspace::runtime_counts::runtime_count_report(ctx.runtime())?;
    Ok(identity::workspace::cli::count_report_output(&report))
}

pub(crate) fn users(ctx: &mut MatchCliContext, args: CliArgs<'_>) -> Result<CliOutput, String> {
    let clock = SystemClock;
    let vault = EmptyVault;
    let output = {
        let command_context = ctx.runtime().command_context(&clock, &vault);
        identity::user::cli::users(&command_context, args)?
    };
    Ok(identity::user::cli::users_output(&output))
}

pub(crate) fn key_recipient(
    ctx: &mut MatchCliContext,
    args: CliArgs<'_>,
) -> Result<CliOutput, String> {
    let clock = SystemClock;
    let vault = EmptyVault;
    let output = {
        let command_context = ctx.runtime().command_context(&clock, &vault);
        encryption::cli::key_recipient(&command_context, args)?
    };
    let receipt = ctx.runtime_mut().submit_command_output(output)?;
    ctx.drain_local_work()?;
    Ok(encryption::cli::key_recipient_output(&receipt))
}

pub(crate) fn key_recipient_rotation(
    ctx: &mut MatchCliContext,
    args: CliArgs<'_>,
) -> Result<CliOutput, String> {
    let workspace_id = args
        .get(0)
        .ok_or_else(|| encryption::cli::KEY_ROTATE_RECIPIENT_USAGE.to_string())
        .and_then(|value| decode_hex_32(value, "workspace id"))?;
    ctx.drain_local_work()?;
    let previous = encryption::commands::recipient_key_for_rotation(ctx.runtime(), workspace_id)?
        .ok_or_else(|| "no existing local recipient key to rotate".to_string())?;
    let clock = SystemClock;
    let vault = EmptyVault;
    let output = {
        let command_context = ctx.runtime().command_context(&clock, &vault);
        encryption::cli::key_recipient_rotation(&command_context, args, previous)?
    };
    let receipt = ctx.runtime_mut().submit_command_output(output)?;
    ctx.drain_local_work()?;
    let mut output = encryption::cli::key_recipient_output(&receipt);
    output
        .lines
        .push("old_active_recipient_keys: 1".to_string());
    output
        .lines
        .push("tombstoned_recipient_keys: 1".to_string());
    Ok(output)
}

pub(crate) fn key_frontier(
    ctx: &mut MatchCliContext,
    args: CliArgs<'_>,
) -> Result<CliOutput, String> {
    let clock = SystemClock;
    let vault = EmptyVault;
    let output = {
        let command_context = ctx.runtime().command_context(&clock, &vault);
        encryption::cli::key_frontier(&command_context, args)?
    };
    let receipt = ctx.runtime_mut().submit_command_output(output)?;
    ctx.drain_local_work()?;
    Ok(encryption::cli::key_frontier_output(&receipt))
}

pub(crate) fn key_wrap(ctx: &mut MatchCliContext, args: CliArgs<'_>) -> Result<CliOutput, String> {
    let query = encryption::cli::key_wrap_args(args)?;
    ctx.drain_local_work()?;
    let lookup = encryption::commands::lookup_key_wrap(ctx.runtime(), query)?;
    Ok(encryption::cli::key_wrap_lookup_output(&lookup))
}

pub(crate) fn key_access(
    ctx: &mut MatchCliContext,
    args: CliArgs<'_>,
) -> Result<CliOutput, String> {
    let query = encryption::cli::key_access_args(args)?;
    ctx.drain_local_work()?;
    let status = encryption::commands::key_access(ctx.runtime(), query)?;
    Ok(encryption::cli::key_access_status_output(&status))
}

pub(crate) fn key_derive(
    ctx: &mut MatchCliContext,
    args: CliArgs<'_>,
) -> Result<CliOutput, String> {
    if args.values().len() > 1 {
        return Err("key-derive [LIMIT]".to_string());
    }
    let limit = args
        .get(0)
        .map(|value| {
            value
                .parse::<usize>()
                .map_err(|_| "key-derive [LIMIT]".to_string())
        })
        .transpose()?
        .unwrap_or(512);
    let before = encryption::commands::local_key_secret_count(ctx.runtime());
    let scanned_key_wraps = encryption::commands::key_wrap_count(ctx.runtime())?;
    for _ in 0..4 {
        ctx.runtime_mut().process_projection_until_idle(8, limit)?;
        let dispatched = ctx
            .runtime_mut()
            .dispatch_intents_excluding(CLI_EFFECT_HANDLER_ROUTES, limit)?;
        if dispatched.is_idle() {
            break;
        }
    }
    ctx.runtime_mut().process_projection_until_idle(8, limit)?;
    let after = encryption::commands::local_key_secret_count(ctx.runtime());
    Ok(CliOutput::lines(vec![
        format!("scanned_key_wraps: {scanned_key_wraps}"),
        format!("derived_key_secrets: {}", after.saturating_sub(before)),
        "failed_key_wraps: 0".to_string(),
        "admitted_events: 0".to_string(),
    ]))
}

pub(crate) fn key_node(ctx: &mut MatchCliContext, args: CliArgs<'_>) -> Result<CliOutput, String> {
    if args.values().len() != 5 && args.values().len() != 6 {
        return Err("key-node WORKSPACE_ID_HEX REMOVAL_FRONTIER_ID_HEX SOURCE_SECRET_ID_HEX RANGE_START RANGE_WIDTH [TOMBSTONE_NODE_ID_HEX]".to_string());
    }
    ctx.drain_local_work()?;
    let workspace_id = decode_hex_32(args.get(0).unwrap(), "workspace id")?;
    let frontier_id = decode_hex_32(args.get(1).unwrap(), "removal frontier id")?;
    let source_secret_id = decode_hex_32(args.get(2).unwrap(), "source secret id")?;
    let range_start = args
        .get(3)
        .unwrap()
        .parse::<u64>()
        .map_err(|_| "key-node range_start must be a u64".to_string())?;
    let range_width = args
        .get(4)
        .unwrap()
        .parse::<u64>()
        .map_err(|_| "key-node range_width must be a u64".to_string())?;
    let tombstone_node_id = if let Some(value) = args.get(5) {
        decode_hex_32(value, "tombstone node id")?
    } else {
        [0; 32]
    };
    let output = encryption::commands::create_history_node(
        ctx.runtime(),
        encryption::commands::CreateHistoryNode {
            created_at_ms: SystemClock.next_timestamp(),
            workspace_id,
            removal_frontier_id: frontier_id,
            source_secret_id,
            range_start,
            range_width,
            tombstone_node_id,
        },
    )?;
    let receipt = ctx.runtime_mut().submit_command_output(output)?;
    ctx.drain_local_work()?;
    Ok(encryption::cli::history_node_output(&receipt))
}

pub(crate) fn keys(ctx: &mut MatchCliContext, args: CliArgs<'_>) -> Result<CliOutput, String> {
    if args.values().len() != 1 {
        return Err("keys WORKSPACE_ID_HEX".to_string());
    }
    ctx.drain_local_work()?;
    let workspace_id = decode_hex_32(args.get(0).unwrap(), "workspace id")?;
    let store = ctx.runtime().store();

    let leaves = history_leaf_rows(store, workspace_id)?;
    let local_history_rows = store
        .table_rows_with_key_prefix(
            crate::protocol::facts::encryption::local_history_node_secret::rows::LOCAL_HISTORY_NODE_SECRET_ROWS,
            &workspace_id,
            usize::MAX,
        )
        .map_err(|err| format!("load local history rows: {err}"))?;
    let message_tombstones = store
        .table_rows_with_key_prefix(
            content::message::rows::MESSAGE_TOMBSTONE_ROWS,
            &workspace_id,
            usize::MAX,
        )
        .map_err(|err| format!("load message tombstones: {err}"))?;
    let file_tombstones = store
        .table_rows_with_key_prefix(
            content::file_deletion::rows::FILE_DELETION_ROWS,
            &workspace_id,
            usize::MAX,
        )
        .map_err(|err| format!("load file deletion rows: {err}"))?;
    let local_key_secret_frontiers =
        encryption::commands::local_key_secret_frontiers(ctx.runtime(), workspace_id);
    let recipient_keys = ctx
        .runtime()
        .facts()
        .filter_map(|fact| encryption::layout::decode_recipient_key(&fact.bytes).ok())
        .filter(|key| key.workspace_id == workspace_id)
        .count();
    let local_recipient_keys = ctx
        .runtime()
        .facts()
        .filter_map(|fact| encryption::layout::decode_local_recipient_key(&fact.bytes).ok())
        .filter(|key| key.workspace_id == workspace_id)
        .count();
    let removal_frontiers = ctx
        .runtime()
        .facts()
        .filter_map(|fact| {
            encryption::layout::decode_removal_frontier(&fact.bytes)
                .ok()
                .map(|frontier| (fact.id, frontier))
        })
        .filter(|(_, frontier)| frontier.workspace_id == workspace_id)
        .collect::<Vec<_>>();
    let key_wraps = encryption::commands::workspace_key_wrap_count(ctx.runtime(), workspace_id)?;

    let mut lines = vec![
        format!("recipient_keys: {recipient_keys}"),
        "recipient_key_tombstones: 0".to_string(),
        format!("local_recipient_keys: {local_recipient_keys}"),
        format!("removal_frontiers: {}", removal_frontiers.len()),
        format!("key_wraps: {key_wraps}"),
        format!("local_key_secrets: {}", local_key_secret_frontiers.len()),
        format!(
            "local_history_node_secrets: {}",
            local_history_rows.len() + leaves.len()
        ),
        "local_history_minute_nodes: 0".to_string(),
        format!("local_history_leaves: {}", leaves.len()),
        "local_history_trie_internals: 0".to_string(),
        "local_history_time_internals: 0".to_string(),
        format!(
            "local_history_node_tombstones: {}",
            message_tombstones.len() + file_tombstones.len()
        ),
        format!("message_tombstones: {}", message_tombstones.len()),
        format!("cover_summary: {}", cover_summary(&leaves)),
    ];
    for (frontier_id, _) in removal_frontiers {
        let access = local_key_secret_frontiers
            .iter()
            .any(|local_frontier_id| *local_frontier_id == frontier_id);
        lines.push(format!(
            "frontier: {} access={}",
            encode_hex_32(&frontier_id),
            if access { "yes" } else { "no" }
        ));
    }
    for leaf in leaves {
        lines.push(format!(
            "history_node: {} frontier={} start={} width=1 bit_depth=256 prefix={} fact_id_in_minute={} tombstones=none",
            encode_hex_32(&leaf.node_id),
            encode_hex_32(&leaf.frontier_id),
            leaf.minute,
            encode_hex_32(&leaf.fact_id_in_minute),
            encode_hex_32(&leaf.fact_id_in_minute)
        ));
    }
    Ok(CliOutput::lines(lines))
}

pub(crate) fn chop_now(ctx: &mut MatchCliContext, args: CliArgs<'_>) -> Result<CliOutput, String> {
    if args.values().len() != 2 {
        return Err("chop-now WORKSPACE_ID_HEX FLOOR_MINUTE".to_string());
    }
    ctx.drain_local_work()?;
    let workspace_id = decode_hex_32(args.get(0).unwrap(), "workspace id")?;
    let floor_minute = args
        .get(1)
        .unwrap()
        .parse::<u64>()
        .map_err(|_| "chop-now floor minute must be a u64".to_string())?;
    let receipt = encryption::commands::chop_now(
        ctx.runtime_mut(),
        encryption::commands::ChopNow {
            workspace_id,
            floor_minute,
            created_at_ms: SystemClock.next_timestamp(),
        },
    )?;
    Ok(encryption::cli::chop_now_output(&receipt))
}

pub(crate) fn disappearing_set(
    ctx: &mut MatchCliContext,
    cli_args: CliArgs<'_>,
) -> Result<CliOutput, String> {
    let args = parse_disappearing_set_args(cli_args.values())?;
    ctx.drain_local_work()?;
    let now_ms = next_cli_timestamp(ctx.runtime())?;
    let output = encryption::disappearing_messages_setting::commands::author_set_with_auto_floor(
        ctx.runtime().store(),
        encryption::disappearing_messages_setting::commands::AuthorSetting {
            workspace_id: args.workspace_id,
            now_ms,
            ttl_minutes: args.ttl_minutes,
            explicit_floor: args.explicit_floor,
        },
    )?;
    let receipt = ctx.runtime_mut().submit_command_output(output)?;
    ctx.drain_local_work()?;
    let delta = receipt
        .new_floor_minute
        .saturating_sub(receipt.previous_floor_minute);
    Ok(CliOutput::lines(vec![
        format!(
            "setting_fact_id: {}",
            encode_hex_32(&receipt.setting_fact_id)
        ),
        format!("ttl_minutes: {}", args.ttl_minutes),
        format!("previous_floor_minute: {}", receipt.previous_floor_minute),
        format!("new_floor_minute: {}", receipt.new_floor_minute),
        format!("floor_delta_minutes: {delta}"),
    ]))
}

pub(crate) fn disappearing_status(
    ctx: &mut MatchCliContext,
    args: CliArgs<'_>,
) -> Result<CliOutput, String> {
    if args.values().len() != 1 {
        return Err("disappearing-status WORKSPACE_ID_HEX".to_string());
    }
    let workspace_id = decode_hex_32(args.get(0).unwrap(), "workspace id")?;
    ctx.drain_local_work()?;
    let store = ctx.runtime().store();
    let active = encryption::disappearing_messages_setting::queries::active_for_workspace(
        store,
        workspace_id,
    )?;
    let setting_fact_id = active
        .as_ref()
        .map(|row| encode_hex_32(&row.setting_id))
        .unwrap_or_else(|| "none".to_string());
    let ttl = active
        .as_ref()
        .map(|row| row.ttl_minutes.to_string())
        .unwrap_or_else(|| "unset".to_string());
    let setting_floor = active.as_ref().map(|row| row.retire_minute).unwrap_or(0);
    let now_minute = clock::logical_time(store)?.map(|ms| ms / 60_000);
    let now_minute_str = now_minute
        .map(|minute| minute.to_string())
        .unwrap_or_else(|| "unset".to_string());
    let horizon_floor = now_minute
        .map(|minute| minute.saturating_sub(30 * 24 * 60))
        .unwrap_or(0);
    let effective_floor = setting_floor.max(horizon_floor);
    if horizon_floor > 0 {
        apply_horizon_floor(store, workspace_id, horizon_floor)?;
    }
    let raw_message_tombstones = store
        .table_rows_with_key_prefix(
            content::message::rows::MESSAGE_TOMBSTONE_ROWS,
            &workspace_id,
            usize::MAX,
        )
        .map_err(|err| format!("load message tombstones: {err}"))?;
    let message_tombstones = raw_message_tombstones
        .into_iter()
        .map(|(key, value)| content::message::rows::decode_message_tombstone_row(&key, &value))
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .filter(|row| row.authored_minute >= horizon_floor)
        .count();
    let live_messages = content_message_rows(store, workspace_id)?
        .into_iter()
        .filter(|row| row.minute >= horizon_floor)
        .count();
    let last_chopped_floor = if horizon_floor > setting_floor && horizon_floor > 0 {
        horizon_floor.to_string()
    } else {
        "none".to_string()
    };

    Ok(CliOutput::lines(vec![
        format!("workspace: {}", encode_hex_32(&workspace_id)),
        format!("setting_fact_id: {setting_fact_id}"),
        format!("current_ttl_minutes: {ttl}"),
        format!("current_floor_minute: {setting_floor}"),
        format!("last_chopped_floor: {last_chopped_floor}"),
        format!("now_minute: {now_minute_str}"),
        format!("horizon_floor: {horizon_floor}"),
        format!("effective_floor: {effective_floor}"),
        format!("live_messages: {live_messages}"),
        format!("message_tombstones: {message_tombstones}"),
        "leaf_tombstones: 0".to_string(),
        "pending_purges: 0".to_string(),
    ]))
}

fn apply_horizon_floor(
    store: &crate::core::store::Store,
    workspace_id: [u8; 32],
    horizon_floor: u64,
) -> Result<(), String> {
    let retired = content_message_rows(store, workspace_id)?
        .into_iter()
        .filter(|row| row.minute < horizon_floor)
        .collect::<Vec<_>>();
    if retired.is_empty() {
        return Ok(());
    }
    let tombstones = retired
        .iter()
        .map(|row| {
            content::message::rows::message_tombstone_row(
                row.workspace_id,
                row.message_id,
                row.author_user_id,
                row.created_at_ms,
            )
        })
        .collect::<Vec<_>>();
    let keys = retired
        .iter()
        .map(|row| content::message::rows::content_message_key(row.workspace_id, row.message_id))
        .collect::<Vec<_>>();
    store
        .write_transaction(|tx| {
            tx.insert_table_rows_in_tx(tombstones)?;
            tx.delete_table_rows_in_tx(content::message::rows::CONTENT_MESSAGE_ROWS, keys.clone())?;
            tx.delete_table_rows_in_tx(content::message::rows::OPENED_MESSAGE_ROWS, keys.clone())?;
            Ok(())
        })
        .map_err(|err| format!("apply horizon floor: {err}"))
}

pub(crate) fn disappearing_tighten(
    ctx: &mut MatchCliContext,
    cli_args: CliArgs<'_>,
) -> Result<CliOutput, String> {
    let args = parse_disappearing_tighten_args(cli_args.values())?;
    if !args.yes {
        return Err("disappearing-tighten requires --yes in the target CLI".to_string());
    }
    ctx.drain_local_work()?;
    let now_ms = next_cli_timestamp(ctx.runtime())?;
    let input = encryption::disappearing_messages_setting::commands::AuthorTighten {
        workspace_id: args.workspace_id,
        now_ms,
        ttl_minutes: args.ttl_minutes,
    };
    let plan = encryption::disappearing_messages_setting::commands::plan_tighten(
        ctx.runtime().store(),
        input,
    )?;
    let output = encryption::disappearing_messages_setting::commands::author_tighten(
        ctx.runtime().store(),
        input,
    )?;
    let receipt = ctx.runtime_mut().submit_command_output(output)?;
    ctx.drain_local_work()?;
    enqueue_floor_retention(
        ctx.runtime_mut(),
        args.workspace_id,
        receipt.setting_fact_id,
        receipt.target_floor_minute,
    )?;
    ctx.drain_local_work()?;
    Ok(CliOutput::lines(vec![
        format!(
            "setting_fact_id: {}",
            encode_hex_32(&receipt.setting_fact_id)
        ),
        format!("ttl_minutes: {}", args.ttl_minutes),
        format!("previous_floor_minute: {}", receipt.previous_floor_minute),
        format!("new_floor_minute: {}", receipt.target_floor_minute),
        format!("messages_below_floor: {}", plan.messages_below_floor),
    ]))
}

pub(crate) fn disappearing_compact(
    ctx: &mut MatchCliContext,
    args: CliArgs<'_>,
) -> Result<CliOutput, String> {
    if args.values().len() != 1 {
        return Err("disappearing-compact WORKSPACE_ID_HEX".to_string());
    }
    let workspace_id = decode_hex_32(args.get(0).unwrap(), "workspace id")?;
    ctx.drain_local_work()?;
    let now_ms = next_cli_timestamp(ctx.runtime())?;
    let output = encryption::disappearing_messages_setting::commands::author_compact(
        ctx.runtime().store(),
        encryption::disappearing_messages_setting::commands::AuthorCompact {
            workspace_id,
            now_ms,
        },
    )?;
    let receipt = ctx.runtime_mut().submit_command_output(output)?;
    ctx.drain_local_work()?;
    let delta = receipt
        .new_floor_minute
        .saturating_sub(receipt.previous_floor_minute);
    Ok(CliOutput::lines(vec![
        format!(
            "setting_fact_id: {}",
            encode_hex_32(&receipt.setting_fact_id)
        ),
        format!("ttl_minutes: {}", receipt.ttl_minutes),
        format!("previous_floor_minute: {}", receipt.previous_floor_minute),
        format!("new_floor_minute: {}", receipt.new_floor_minute),
        format!("floor_delta_minutes: {delta}"),
    ]))
}

pub(crate) fn send(ctx: &mut MatchCliContext, args: CliArgs<'_>) -> Result<CliOutput, String> {
    let workspace_id = args
        .get(0)
        .ok_or_else(|| content::message::cli::SEND_USAGE.to_string())
        .and_then(|value| decode_hex_32(value, "workspace id"))?;
    let text = args
        .get(1)
        .ok_or_else(|| content::message::cli::SEND_USAGE.to_string())?
        .to_string();
    let clock = FixedClock(next_cli_timestamp(ctx.runtime())?);
    let vault = content::message::authoring::ContentMessageVault::for_workspace(
        ctx.runtime(),
        workspace_id,
    )?;
    let output = {
        let command_context = ctx.runtime().command_context(&clock, &vault);
        content::message::cli::send(&command_context, args)?
    };
    let receipt = ctx.runtime_mut().submit_command_output(output)?;
    ctx.drain_local_work()?;
    Ok(content::message::cli::send_output(&receipt, &text))
}

pub(crate) fn react(ctx: &mut MatchCliContext, args: CliArgs<'_>) -> Result<CliOutput, String> {
    let clock = FixedClock(next_cli_timestamp(ctx.runtime())?);
    let vault = EmptyVault;
    let output = {
        let command_context = ctx.runtime().command_context(&clock, &vault);
        content::message::cli::react(&command_context, args)?
    };
    let receipt = ctx.runtime_mut().submit_command_output(output)?;
    ctx.drain_local_work()?;
    Ok(content::message::cli::react_output(&receipt))
}

pub(crate) fn send_file(ctx: &mut MatchCliContext, args: CliArgs<'_>) -> Result<CliOutput, String> {
    let workspace_id = args
        .get(0)
        .ok_or_else(|| content::message::cli::SEND_FILE_USAGE.to_string())
        .and_then(|value| decode_hex_32(value, "workspace id"))?;
    let clock = FixedClock(next_cli_timestamp(ctx.runtime())?);
    let vault = content::message::authoring::ContentMessageVault::for_workspace(
        ctx.runtime(),
        workspace_id,
    )?;
    let output = {
        let command_context = ctx.runtime().command_context(&clock, &vault);
        content::message::cli::send_file(&command_context, args)?
    };
    let receipt = ctx.runtime_mut().submit_command_output(output)?;
    ctx.drain_local_work()?;
    Ok(content::message::cli::send_file_output(&receipt))
}

pub(crate) fn files(ctx: &mut MatchCliContext, args: CliArgs<'_>) -> Result<CliOutput, String> {
    ctx.drain_local_work()?;
    let clock = SystemClock;
    let vault = EmptyVault;
    let command_context = ctx.runtime().command_context(&clock, &vault);
    content::message::cli::files(&command_context, args)
}

pub(crate) fn save_file(ctx: &mut MatchCliContext, args: CliArgs<'_>) -> Result<CliOutput, String> {
    ctx.drain_local_work()?;
    let clock = SystemClock;
    let vault = EmptyVault;
    let command_context = ctx.runtime().command_context(&clock, &vault);
    content::message::cli::save_file(&command_context, args)
}

pub(crate) fn delete_file(
    ctx: &mut MatchCliContext,
    args: CliArgs<'_>,
) -> Result<CliOutput, String> {
    if args.values().len() != 2 {
        return Err(DELETE_FILE_USAGE.to_string());
    }
    ctx.drain_local_work()?;
    let workspace_id = decode_hex_32(args.get(0).unwrap(), "workspace id")?;
    let file = resolve_file_selector(ctx.runtime().store(), workspace_id, args.get(1).unwrap())?;
    let clock = FixedClock(next_cli_timestamp(ctx.runtime())?);
    let vault = EmptyVault;
    let output = {
        let command_context = ctx.runtime().command_context(&clock, &vault);
        content::file_deletion::commands::delete_file(
            &command_context,
            workspace_id,
            file.file_fact_id,
            file.author_user_id,
        )?
    };
    let receipt = ctx.runtime_mut().submit_command_output(output)?;
    ctx.drain_local_work()?;
    Ok(CliOutput::lines(vec![
        format!("workspace_id: {}", encode_hex_32(&receipt.workspace_id)),
        format!("fact_id: {}", encode_hex_32(&receipt.deletion_fact_id)),
        format!("target_file_id: {}", encode_hex_32(&receipt.target_file_id)),
        format!("created_at_ms: {}", receipt.created_at_ms),
    ]))
}

pub(crate) fn delete_message(
    ctx: &mut MatchCliContext,
    args: CliArgs<'_>,
) -> Result<CliOutput, String> {
    let clock = FixedClock(next_cli_timestamp(ctx.runtime())?);
    let vault = EmptyVault;
    let output = {
        let command_context = ctx.runtime().command_context(&clock, &vault);
        content::message::cli::delete_message(&command_context, args)?
    };
    let receipt = ctx.runtime_mut().submit_command_output(output)?;
    ctx.drain_local_work()?;
    Ok(content::message::cli::delete_message_output(&receipt))
}

pub(crate) fn messages(ctx: &mut MatchCliContext, args: CliArgs<'_>) -> Result<CliOutput, String> {
    ctx.drain_local_work()?;
    let clock = SystemClock;
    let vault = EmptyVault;
    let command_context = ctx.runtime().command_context(&clock, &vault);
    content::message::cli::messages(&command_context, args)
}

pub(crate) fn view(ctx: &mut MatchCliContext, args: CliArgs<'_>) -> Result<CliOutput, String> {
    ctx.drain_local_work()?;
    let clock = SystemClock;
    let vault = EmptyVault;
    let command_context = ctx.runtime().command_context(&clock, &vault);
    content::message::cli::view(&command_context, args)
}

pub(crate) fn grant_admin(
    ctx: &mut MatchCliContext,
    args: CliArgs<'_>,
) -> Result<CliOutput, String> {
    let clock = SystemClock;
    let vault = EmptyVault;
    let output = {
        let command_context = ctx.runtime().command_context(&clock, &vault);
        identity::admin::cli::grant_admin(&command_context, args)?
    };
    let receipt = ctx.runtime_mut().submit_command_output(output)?;
    ctx.runtime_mut().process_projection_until_idle(8, 64)?;
    Ok(identity::admin::cli::grant_admin_output(&receipt))
}

pub(crate) fn generate(ctx: &mut MatchCliContext, args: CliArgs<'_>) -> Result<CliOutput, String> {
    let clock = SystemClock;
    let vault = EmptyVault;
    let output = {
        let command_context = ctx.runtime().command_context(&clock, &vault);
        content::event::cli::generate(&command_context, args)?
    };
    let receipt = ctx.runtime_mut().submit_command_output(output)?;
    ctx.drain_local_work()?;
    Ok(content::event::cli::generated_output(
        &receipt,
        receipt.generated_facts,
    ))
}

pub(crate) fn generate_deps(
    ctx: &mut MatchCliContext,
    args: CliArgs<'_>,
) -> Result<CliOutput, String> {
    let args = sync::cascade_fact::cli::parse_generate_deps_args(args)?;
    let receipt = sync::cascade_fact::commands::generate_deps(
        ctx.runtime().store(),
        args.count,
        args.deps_per_fact,
    )?;
    Ok(sync::cascade_fact::cli::generate_deps_output(&receipt))
}

pub(crate) fn replay_deps_reverse(
    ctx: &mut MatchCliContext,
    args: CliArgs<'_>,
) -> Result<CliOutput, String> {
    args.require_len(0, sync::cascade_fact::cli::REPLAY_DEPS_REVERSE_USAGE)?;
    let receipt = sync::cascade_fact::commands::replay_deps_reverse(ctx.runtime_mut())?;
    Ok(sync::cascade_fact::cli::replay_deps_reverse_output(
        &receipt,
    ))
}

pub(crate) fn negentropy_drain(
    ctx: &mut MatchCliContext,
    args: CliArgs<'_>,
) -> Result<CliOutput, String> {
    if args.values().len() > 1 {
        return Err("negentropy-drain [LIMIT]".to_string());
    }
    if let Some(value) = args.get(0) {
        let _ = value
            .parse::<usize>()
            .map_err(|_| "negentropy-drain [LIMIT]".to_string())?;
    }
    ctx.drain_local_work()?;
    let status = crate::protocol::facts::sync::shared_fact::sync_status(ctx.runtime().store())?;
    Ok(CliOutput::lines(vec![
        "drained: 0".to_string(),
        "removed_from_index: 0".to_string(),
        format!("remaining_pending: {}", status.pending_purges),
        format!("new_root_count: {}", status.root_count),
        format!(
            "new_root_fingerprint: {}",
            encode_hex_bytes(&status.root_fingerprint)
        ),
    ]))
}

pub(crate) fn sync_status(
    ctx: &mut MatchCliContext,
    args: CliArgs<'_>,
) -> Result<CliOutput, String> {
    if !args.values().is_empty() {
        return Err("sync-status".to_string());
    }
    ctx.drain_local_work()?;
    let status = crate::protocol::facts::sync::shared_fact::sync_status(ctx.runtime().store())?;
    Ok(CliOutput::lines(vec![
        format!("indexed_facts: {}", status.indexed_facts),
        format!("root_count: {}", status.root_count),
        format!(
            "root_fingerprint: {}",
            encode_hex_bytes(&status.root_fingerprint)
        ),
        format!("pending_purges: {}", status.pending_purges),
    ]))
}

pub(crate) fn content_count(
    ctx: &mut MatchCliContext,
    args: CliArgs<'_>,
) -> Result<CliOutput, String> {
    let clock = SystemClock;
    let vault = EmptyVault;
    let output = {
        let command_context = ctx.runtime().command_context(&clock, &vault);
        content::event::cli::content_count(&command_context, args)?
    };
    Ok(content::event::cli::content_count_output(output))
}

pub(crate) fn clock(ctx: &mut MatchCliContext, args: CliArgs<'_>) -> Result<CliOutput, String> {
    match args.values() {
        [] => {}
        [command, value] if command == "set" => {
            let timestamp = value
                .parse::<u64>()
                .map_err(|_| "clock set requires a u64 timestamp".to_string())?;
            clock::set_logical_time(ctx.runtime().store(), timestamp)?;
        }
        [command, value] if command == "advance" => {
            let delta = value
                .parse::<u64>()
                .map_err(|_| "clock advance requires a u64 delta".to_string())?;
            clock::advance_logical_time(ctx.runtime().store(), delta)?;
        }
        [command] if command == "clear" => {
            clock::clear_logical_time(ctx.runtime().store())?;
        }
        _ => {
            return Err(command_error(
                "clock usage: clock [set TIMESTAMP|advance DELTA|clear]",
            ));
        }
    }

    let logical_time = clock::logical_time(ctx.runtime().store())?;
    let observed_max = content::event::queries::max_timestamp(ctx.runtime().store())?;
    let next_timestamp = clock::next_timestamp(ctx.runtime().store(), observed_max)?;
    let logical_time = logical_time
        .map(|timestamp| timestamp.to_string())
        .unwrap_or_else(|| "unset".to_string());
    Ok(CliOutput::lines(vec![
        format!("logical_time: {logical_time}"),
        format!("max_event_timestamp: {observed_max}"),
        format!("next_timestamp: {next_timestamp}"),
    ]))
}

fn next_cli_timestamp(runtime: &Runtime) -> Result<u64, String> {
    let observed_max = max_cli_timestamp(runtime.store())?;
    clock::next_timestamp(runtime.store(), observed_max)
}

fn max_cli_timestamp(store: &crate::core::store::Store) -> Result<u64, String> {
    let mut max_timestamp = content::event::queries::max_timestamp(store)?;
    max_timestamp = max_timestamp.max(content::message::queries::max_created_at_ms(store)?);
    Ok(max_timestamp)
}

fn enqueue_floor_retention(
    runtime: &mut Runtime,
    workspace_id: [u8; 32],
    setting_id: [u8; 32],
    floor_minute: u64,
) -> Result<usize, String> {
    let mut queued = 0usize;
    for message in content_message_rows(runtime.store(), workspace_id)? {
        if message.minute >= floor_minute {
            continue;
        }
        if runtime.submit_intent(purge_below_retention_floor_intent(
            PurgeBelowRetentionFloor {
                workspace_id,
                setting_id,
                target_id: message.message_id,
            },
        ))? {
            queued += 1;
        }
    }
    Ok(queued)
}

#[derive(Debug, Clone)]
struct HistoryLeafRow {
    node_id: [u8; 32],
    frontier_id: [u8; 32],
    minute: u64,
    fact_id_in_minute: [u8; 32],
}

fn history_leaf_rows(
    store: &crate::core::store::Store,
    workspace_id: [u8; 32],
) -> Result<Vec<HistoryLeafRow>, String> {
    let messages = content_message_rows(store, workspace_id)?;
    let live_message_ids = messages
        .iter()
        .map(|message| message.message_id)
        .collect::<BTreeSet<_>>();
    let default_frontier = first_removal_frontier_id(store, workspace_id)?.unwrap_or([0; 32]);
    let mut leaves = messages
        .into_iter()
        .map(|message| HistoryLeafRow {
            node_id: message.message_id,
            frontier_id: default_frontier,
            minute: message.minute,
            fact_id_in_minute: nonzero_or(message.leaf_id, message.message_id),
        })
        .collect::<Vec<_>>();
    for file in content_file_rows(store, workspace_id)? {
        if !live_message_ids.contains(&file.message_id) {
            continue;
        }
        leaves.push(HistoryLeafRow {
            node_id: file.file_fact_id,
            frontier_id: default_frontier,
            minute: file.created_at_ms / content::message::fact::UNIX_MINUTE_MS,
            fact_id_in_minute: file.file_id,
        });
    }
    leaves.sort_by_key(|leaf| (leaf.minute, leaf.node_id));
    Ok(leaves)
}

fn content_message_rows(
    store: &crate::core::store::Store,
    workspace_id: [u8; 32],
) -> Result<Vec<content::message::rows::ContentMessageRow>, String> {
    let mut rows = store
        .table_rows_with_key_prefix(
            content::message::rows::CONTENT_MESSAGE_ROWS,
            &workspace_id,
            usize::MAX,
        )
        .map_err(|err| format!("load message rows: {err}"))?
        .into_iter()
        .map(|(key, value)| content::message::rows::decode_content_message_row(&key, &value))
        .collect::<Result<Vec<_>, _>>()?;
    rows.sort_by_key(|row| (row.created_at_ms, row.message_id));
    Ok(rows)
}

fn content_file_rows(
    store: &crate::core::store::Store,
    workspace_id: [u8; 32],
) -> Result<Vec<content::file::rows::ContentFileRow>, String> {
    let mut rows = store
        .table_rows_with_key_prefix(content::file::rows::FILE_ROWS, &workspace_id, usize::MAX)
        .map_err(|err| format!("load file rows: {err}"))?
        .into_iter()
        .map(|(key, value)| content::file::rows::decode_content_file_row(&key, &value))
        .collect::<Result<Vec<_>, _>>()?;
    rows.sort_by_key(|row| (row.created_at_ms, row.file_fact_id));
    Ok(rows)
}

fn resolve_file_selector(
    store: &crate::core::store::Store,
    workspace_id: [u8; 32],
    selector: &str,
) -> Result<content::file::rows::ContentFileRow, String> {
    let files = content_file_rows(store, workspace_id)?;
    if let Some(index) = selector.strip_prefix('#') {
        let index = index
            .parse::<usize>()
            .map_err(|_| "file selector index must be a positive integer".to_string())?;
        if index == 0 {
            return Err("file selector index must be a positive integer".to_string());
        }
        return files
            .get(index - 1)
            .cloned()
            .ok_or_else(|| "file selector does not match a file".to_string());
    }
    let id = decode_hex_32(selector, "file id")?;
    files
        .into_iter()
        .find(|file| file.file_fact_id == id || file.file_id == id)
        .ok_or_else(|| "file selector does not match a file".to_string())
}

fn first_removal_frontier_id(
    store: &crate::core::store::Store,
    workspace_id: [u8; 32],
) -> Result<Option<[u8; 32]>, String> {
    let mut rows = store
        .table_rows_with_key_prefix(
            encryption::removal_frontier::rows::REMOVAL_FRONTIER_ROWS,
            &workspace_id,
            usize::MAX,
        )
        .map_err(|err| format!("load removal frontier rows: {err}"))?
        .into_iter()
        .filter_map(|(key, value)| {
            encryption::removal_frontier::rows::decode_removal_frontier_row(&key, &value).ok()
        })
        .collect::<Vec<_>>();
    rows.sort_by_key(|row| (row.created_at_ms, row.removal_frontier_id));
    Ok(rows.first().map(|row| row.removal_frontier_id))
}

fn nonzero_or(value: [u8; 32], fallback: [u8; 32]) -> [u8; 32] {
    if value.iter().all(|byte| *byte == 0) {
        fallback
    } else {
        value
    }
}

fn cover_summary(leaves: &[HistoryLeafRow]) -> String {
    let mut hash = blake3::Hasher::new();
    for leaf in leaves {
        hash.update(&leaf.node_id);
        hash.update(&leaf.minute.to_be_bytes());
        hash.update(&leaf.fact_id_in_minute);
    }
    encode_hex_bytes(hash.finalize().as_bytes())
}

struct DisappearingSetArgs {
    workspace_id: [u8; 32],
    ttl_minutes: u32,
    explicit_floor: Option<u64>,
}

fn parse_disappearing_set_args(values: &[String]) -> Result<DisappearingSetArgs, String> {
    if values.len() < 2 {
        return Err("disappearing-set WORKSPACE_ID_HEX TTL_MINUTES [--floor MINUTE]".to_string());
    }
    let workspace_id = decode_hex_32(&values[0], "workspace id")?;
    let ttl_minutes = values[1]
        .parse::<u32>()
        .map_err(|_| "disappearing-set ttl must be a u32".to_string())?;
    let mut explicit_floor = None;
    let mut idx = 2;
    while idx < values.len() {
        match values[idx].as_str() {
            "--floor" => {
                let value = values
                    .get(idx + 1)
                    .ok_or_else(|| "disappearing-set --floor requires a value".to_string())?;
                explicit_floor = Some(
                    value
                        .parse::<u64>()
                        .map_err(|_| "disappearing-set floor must be a u64".to_string())?,
                );
                idx += 2;
            }
            arg if arg.starts_with("--floor=") => {
                let value = arg.trim_start_matches("--floor=");
                explicit_floor = Some(
                    value
                        .parse::<u64>()
                        .map_err(|_| "disappearing-set floor must be a u64".to_string())?,
                );
                idx += 1;
            }
            _ => {
                return Err(
                    "disappearing-set WORKSPACE_ID_HEX TTL_MINUTES [--floor MINUTE]".to_string(),
                );
            }
        }
    }
    Ok(DisappearingSetArgs {
        workspace_id,
        ttl_minutes,
        explicit_floor,
    })
}

struct DisappearingTightenArgs {
    workspace_id: [u8; 32],
    ttl_minutes: u32,
    yes: bool,
}

fn parse_disappearing_tighten_args(values: &[String]) -> Result<DisappearingTightenArgs, String> {
    if values.len() < 2 {
        return Err("disappearing-tighten WORKSPACE_ID_HEX TTL_MINUTES [--yes|-y]".to_string());
    }
    let workspace_id = decode_hex_32(&values[0], "workspace id")?;
    let ttl_minutes = values[1]
        .parse::<u32>()
        .map_err(|_| "disappearing-tighten ttl must be a u32".to_string())?;
    let mut yes = false;
    for value in &values[2..] {
        match value.as_str() {
            "--yes" | "-y" => yes = true,
            _ => {
                return Err(
                    "disappearing-tighten WORKSPACE_ID_HEX TTL_MINUTES [--yes|-y]".to_string(),
                );
            }
        }
    }
    Ok(DisappearingTightenArgs {
        workspace_id,
        ttl_minutes,
        yes,
    })
}

fn process_runtime_until_idle(runtime: &mut Runtime) -> Result<(), String> {
    for _ in 0..4 {
        runtime.process_projection_until_idle(8, 512)?;
        let dispatched = runtime.dispatch_intents_excluding(CLI_EFFECT_HANDLER_ROUTES, 512)?;
        if dispatched.is_idle() {
            runtime.process_projection_until_idle(8, 512)?;
            return Ok(());
        }
    }
    Ok(())
}

fn decode_hex_32(value: &str, label: &str) -> Result<[u8; 32], String> {
    core_decode_hex_32(value, label)
}

fn encode_hex_32(bytes: &[u8; 32]) -> String {
    core_encode_hex_32(bytes)
}

fn encode_hex_bytes(bytes: &[u8]) -> String {
    core_encode_hex(bytes)
}

struct SystemClock;

impl CommandClock for SystemClock {
    fn next_timestamp(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_millis() as u64)
            .unwrap_or(0)
    }
}

struct FixedClock(u64);

impl CommandClock for FixedClock {
    fn next_timestamp(&self) -> u64 {
        self.0
    }
}

struct EmptyVault;

impl IdentityVault for EmptyVault {
    fn local_signing_capability(
        &self,
        _workspace_id: WorkspaceId,
    ) -> Result<LocalSigningCapability, String> {
        Err("no local signing capability".to_string())
    }

    fn local_encryption_capability(
        &self,
        _workspace_id: WorkspaceId,
    ) -> Result<LocalEncryptionCapability, String> {
        Err("no local encryption capability".to_string())
    }
}
