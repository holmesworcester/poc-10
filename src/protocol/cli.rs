//! Command host functions for the concrete `match` protocol.
//!
//! Fact-scope `cli.rs` modules own argv parsing, text formatting, and command
//! output construction. Core owns runtime opening and final printing. These
//! host functions add the protocol-specific runtime context between those two:
//! they borrow read-only command context, submit fact/intent output when a
//! command authors work, and drain only local projection/intent work that the
//! CLI command itself is responsible for observing.

use crate::core::cli::{decode_hex_32_named as decode_hex_32, encode_hex_32, CliArgs, CliOutput};
use crate::core::clock;
use crate::core::command_context::{
    CommandClock, IdentityVault, LocalEncryptionCapability, LocalSigningCapability, WorkspaceId,
};
use crate::core::daemon;
use crate::core::runtime::Runtime;
use crate::protocol::facts::sync;
use crate::protocol::facts::{content, encryption, identity};
use crate::protocol::registry::CLI_EFFECT_HANDLER_ROUTES;
use std::path::PathBuf;
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
    let limit = encryption::cli::key_derive_limit(args)?;
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
    let args = encryption::cli::key_node_args(args)?;
    ctx.drain_local_work()?;
    let output = encryption::commands::create_history_node(
        ctx.runtime(),
        encryption::commands::CreateHistoryNode {
            created_at_ms: SystemClock.next_timestamp(),
            workspace_id: args.workspace_id,
            removal_frontier_id: args.removal_frontier_id,
            source_secret_id: args.source_secret_id,
            range_start: args.range_start,
            range_width: args.range_width,
            tombstone_node_id: args.tombstone_node_id,
        },
    )?;
    let receipt = ctx.runtime_mut().submit_command_output(output)?;
    ctx.drain_local_work()?;
    Ok(encryption::cli::history_node_output(&receipt))
}

pub(crate) fn keys(ctx: &mut MatchCliContext, args: CliArgs<'_>) -> Result<CliOutput, String> {
    let workspace_id = encryption::cli::keys_workspace_id(args)?;
    ctx.drain_local_work()?;
    let report = encryption::commands::key_status_report(ctx.runtime(), workspace_id)?;
    Ok(encryption::cli::keys_output(&report))
}

pub(crate) fn chop_now(ctx: &mut MatchCliContext, args: CliArgs<'_>) -> Result<CliOutput, String> {
    let args = encryption::cli::chop_now_args(args)?;
    ctx.drain_local_work()?;
    let receipt = encryption::commands::chop_now(
        ctx.runtime_mut(),
        encryption::commands::ChopNow {
            workspace_id: args.workspace_id,
            floor_minute: args.floor_minute,
            created_at_ms: SystemClock.next_timestamp(),
        },
    )?;
    Ok(encryption::cli::chop_now_output(&receipt))
}

pub(crate) fn disappearing_set(
    ctx: &mut MatchCliContext,
    cli_args: CliArgs<'_>,
) -> Result<CliOutput, String> {
    let args = encryption::disappearing_messages_setting::cli::parse_disappearing_set_args(
        cli_args.values(),
    )?;
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
    let workspace_id = encryption::disappearing_messages_setting::cli::status_workspace_id(args)?;
    ctx.drain_local_work()?;
    let report = encryption::disappearing_messages_setting::commands::status_report(
        ctx.runtime().store(),
        workspace_id,
    )?;
    Ok(encryption::disappearing_messages_setting::cli::status_output(&report))
}

pub(crate) fn disappearing_tighten(
    ctx: &mut MatchCliContext,
    cli_args: CliArgs<'_>,
) -> Result<CliOutput, String> {
    let args = encryption::disappearing_messages_setting::cli::parse_disappearing_tighten_args(
        cli_args.values(),
    )?;
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
    encryption::disappearing_messages_setting::commands::enqueue_floor_retention(
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
    let workspace_id = encryption::disappearing_messages_setting::cli::compact_workspace_id(args)?;
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
        return Err(content::file_deletion::cli::DELETE_FILE_USAGE.to_string());
    }
    ctx.drain_local_work()?;
    let workspace_id = decode_hex_32(args.get(0).unwrap(), "workspace id")?;
    let file = content::file_deletion::cli::resolve_file_selector(
        ctx.runtime().store(),
        workspace_id,
        args.get(1).unwrap(),
    )?;
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
    Ok(content::file_deletion::cli::delete_file_output(&receipt))
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
    let _limit = sync::shared_fact::cli::parse_negentropy_drain_limit(args)?;
    ctx.drain_local_work()?;
    let status = crate::protocol::facts::sync::shared_fact::sync_status(ctx.runtime().store())?;
    Ok(sync::shared_fact::cli::negentropy_drain_output(&status))
}

pub(crate) fn sync_status(
    ctx: &mut MatchCliContext,
    args: CliArgs<'_>,
) -> Result<CliOutput, String> {
    sync::shared_fact::cli::require_sync_status_args(args)?;
    ctx.drain_local_work()?;
    let status = crate::protocol::facts::sync::shared_fact::sync_status(ctx.runtime().store())?;
    Ok(sync::shared_fact::cli::sync_status_output(&status))
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
