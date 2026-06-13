//! Command host functions for the concrete Context protocol.
//!
//! Fact-scope `cli.rs` modules own argv parsing, text formatting, and command
//! output construction. Core owns runtime opening and final printing. These
//! host functions add the protocol-specific runtime context between those two:
//! they pass the store and command clock to command/query modules, submit
//! authored facts when a command authors work, and drain only local
//! projection/intent work that the CLI command itself is responsible for
//! observing.
//!
//! This file is a command router, not a domain model. Each function should stay
//! thin: parse through the owning fact module, pass `Store`/`CommandClock` to
//! the owning command or query helper, submit `CommandOutput` when the command
//! authors work, and format with the owning module's CLI helpers. If the code starts proving
//! authority, constructing payload bytes, or interpreting projected rows, move
//! that logic back to the fact, intent, or query module that owns it.
//!
//! The settling calls are intentional. CLI commands often need command-visible
//! projection results before reporting or before reading dependent state, but
//! they should not run daemon-only network handlers. `MatchCliContext` therefore
//! asks runtime to drain the command-safe handler set declared in the registry.

use crate::core::cli::{decode_hex_32_named as decode_hex_32, encode_hex_32, CliArgs, CliOutput};
use crate::core::clock;
use crate::core::command::{CommandClock, CommandOutput};
use crate::core::daemon;
use crate::core::replay::{ReplayOrder, ReplayReport, StateSummary};
use crate::core::runtime::Runtime;
use crate::core::store::Store;
use crate::protocol::connection;
use crate::protocol::sync;
use crate::protocol::{auth, content};
use std::path::{Path, PathBuf};

const COMMAND_SETTLE_ROUNDS: usize = 4;
const COMMAND_SETTLE_LIMIT: usize = 4096;

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
            .ok_or_else(|| format!("{command} requires --db PATH"))
    }

    fn runtime(&self) -> &Runtime {
        &self.runtime
    }

    fn runtime_mut(&mut self) -> &mut Runtime {
        &mut self.runtime
    }

    fn with_command_inputs<T>(
        &self,
        run: impl FnOnce(&Store, &dyn CommandClock) -> Result<T, String>,
    ) -> Result<T, String> {
        let clock = SystemClock;
        run(self.runtime.store(), &clock)
    }

    fn settle_local_command_work(&mut self) -> Result<(), String> {
        self.runtime
            .process_command_work_until_idle(COMMAND_SETTLE_ROUNDS, COMMAND_SETTLE_LIMIT)
            .map(|_| ())
    }

    // Commands that author facts usually need to read their projected output
    // immediately. Runtime owns the actual projection/intent schedule; the
    // protocol host only chooses where command-visible settling is required.
    fn submit_and_settle<T>(&mut self, output: CommandOutput<T>) -> Result<T, String> {
        let receipt = self.runtime.submit_command_output(output)?;
        self.settle_local_command_work()?;
        Ok(receipt)
    }
}

pub(crate) fn accept(ctx: &mut MatchCliContext, args: CliArgs<'_>) -> Result<CliOutput, String> {
    let from_listen_addr = daemon::current_listen_addr(ctx.db_path("accept")?)?;
    let output = ctx.with_command_inputs(|store, clock| {
        auth::invite::cli::accept(store, clock, args, from_listen_addr)
    })?;
    let receipt = ctx.submit_and_settle(output)?;
    Ok(auth::invite::cli::accept_output(&receipt))
}

pub(crate) fn accept_invite_server(
    ctx: &mut MatchCliContext,
    args: CliArgs<'_>,
) -> Result<CliOutput, String> {
    let from_listen_addr = daemon::current_listen_addr(ctx.db_path("accept-invite-server")?)?;
    let output = ctx.with_command_inputs(|store, clock| {
        auth::invite::cli::accept_invite_server(store, clock, args, from_listen_addr)
    })?;
    let receipt = ctx.submit_and_settle(output)?;
    Ok(auth::invite::cli::accept_output(&receipt))
}

pub(crate) fn accept_link(
    ctx: &mut MatchCliContext,
    args: CliArgs<'_>,
) -> Result<CliOutput, String> {
    let from_listen_addr = daemon::current_listen_addr(ctx.db_path("accept-link")?)?;
    let output = ctx.with_command_inputs(|store, clock| {
        auth::invite::cli::accept_link(store, clock, args, from_listen_addr)
    })?;
    let receipt = ctx.submit_and_settle(output)?;
    Ok(auth::invite::cli::accept_output(&receipt))
}

pub(crate) fn connect(ctx: &mut MatchCliContext, args: CliArgs<'_>) -> Result<CliOutput, String> {
    args.require_len(2, connection::request::commands::CONNECT_USAGE)?;
    let target_endpoint = decode_hex_32(
        args.get(0)
            .ok_or(connection::request::commands::CONNECT_USAGE)?,
        "endpoint id",
    )?;
    let dialed_addr = args
        .get(1)
        .ok_or(connection::request::commands::CONNECT_USAGE)?
        .parse()
        .map_err(|_| "connect address must be HOST:PORT".to_string())?;
    let from_listen_addr = daemon::current_listen_addr(ctx.db_path("connect")?)?;
    let output = ctx.with_command_inputs(|store, clock| {
        connection::request::commands::connect(
            store,
            connection::request::commands::Connect {
                created_at_ms: clock.next_timestamp(),
                target_endpoint,
                dialed_addr,
                from_listen_addr,
            },
        )
    })?;
    let receipt = ctx.submit_and_settle(output)?;
    Ok(CliOutput::line(format!(
        "connecting: request_id={}",
        encode_hex_32(&receipt.request_id)
    )))
}

pub(crate) fn identity(ctx: &mut MatchCliContext, args: CliArgs<'_>) -> Result<CliOutput, String> {
    auth::endpoint_shared::cli::identity(ctx.runtime().store(), args)
}

pub(crate) fn peers(ctx: &mut MatchCliContext, args: CliArgs<'_>) -> Result<CliOutput, String> {
    auth::endpoint_shared::cli::peers(ctx.runtime().store(), args)
}

pub(crate) fn invite(ctx: &mut MatchCliContext, args: CliArgs<'_>) -> Result<CliOutput, String> {
    let output =
        ctx.with_command_inputs(|store, clock| auth::invite::cli::invite(store, clock, args))?;
    let receipt = ctx.submit_and_settle(output)?;
    Ok(auth::invite::cli::invite_output(&receipt))
}

pub(crate) fn invite_server(
    ctx: &mut MatchCliContext,
    args: CliArgs<'_>,
) -> Result<CliOutput, String> {
    let output = ctx
        .with_command_inputs(|store, clock| auth::invite::cli::invite_server(store, clock, args))?;
    let receipt = ctx.submit_and_settle(output)?;
    Ok(auth::invite::cli::invite_output(&receipt))
}

pub(crate) fn link(ctx: &mut MatchCliContext, args: CliArgs<'_>) -> Result<CliOutput, String> {
    let output =
        ctx.with_command_inputs(|store, clock| auth::invite::cli::link(store, clock, args))?;
    let receipt = ctx.submit_and_settle(output)?;
    Ok(auth::invite::cli::invite_output(&receipt))
}

pub(crate) fn create_workspace(
    ctx: &mut MatchCliContext,
    args: CliArgs<'_>,
) -> Result<CliOutput, String> {
    let output = ctx.with_command_inputs(|store, clock| {
        auth::workspace::cli::create_workspace(store, clock, args)
    })?;
    let receipt = ctx.submit_and_settle(output)?;
    let workspace = auth::workspace::queries::workspace_by_id(
        ctx.runtime().store(),
        receipt.workspace_fact_id,
    )?;
    let bootstrap_user_id =
        auth::user::queries::users_in_workspace(ctx.runtime().store(), receipt.workspace_fact_id)?
            .first()
            .map(|user| user.user_id);
    Ok(auth::workspace::cli::created_workspace_output(
        &workspace,
        bootstrap_user_id,
    ))
}

pub(crate) fn workspaces(
    ctx: &mut MatchCliContext,
    args: CliArgs<'_>,
) -> Result<CliOutput, String> {
    let output = auth::workspace::cli::workspaces(ctx.runtime().store(), args)?;
    Ok(auth::workspace::cli::workspaces_output(&output))
}

pub(crate) fn count(ctx: &mut MatchCliContext, args: CliArgs<'_>) -> Result<CliOutput, String> {
    args.require_len(0, auth::workspace::cli::COUNT_USAGE)?;
    let report = auth::workspace::queries::runtime_count_report(ctx.runtime())?;
    Ok(auth::workspace::cli::count_report_output(&report))
}

pub(crate) fn users(ctx: &mut MatchCliContext, args: CliArgs<'_>) -> Result<CliOutput, String> {
    let output = auth::user::cli::users(ctx.runtime().store(), args)?;
    Ok(auth::user::cli::users_output(&output))
}

pub(crate) fn key_recipient(
    ctx: &mut MatchCliContext,
    args: CliArgs<'_>,
) -> Result<CliOutput, String> {
    let output = ctx.with_command_inputs(|store, clock| {
        auth::key_wrap::cli::key_recipient(store, clock, args)
    })?;
    let receipt = ctx.submit_and_settle(output)?;
    Ok(auth::key_wrap::cli::key_recipient_output(&receipt))
}

pub(crate) fn key_recipient_rotation(
    ctx: &mut MatchCliContext,
    args: CliArgs<'_>,
) -> Result<CliOutput, String> {
    let workspace_id = args
        .get(0)
        .ok_or_else(|| auth::key_wrap::cli::KEY_ROTATE_RECIPIENT_USAGE.to_string())
        .and_then(|value| decode_hex_32(value, "workspace id"))?;
    ctx.settle_local_command_work()?;
    let previous =
        auth::key_wrap::commands::recipient_key_for_rotation(ctx.runtime(), workspace_id)?
            .ok_or_else(|| "no existing local recipient key to rotate".to_string())?;
    let output = ctx.with_command_inputs(|store, clock| {
        auth::key_wrap::cli::key_recipient_rotation(store, clock, args, previous)
    })?;
    let receipt = ctx.submit_and_settle(output)?;
    Ok(auth::key_wrap::cli::key_recipient_rotation_output(
        &receipt, 1,
    ))
}

pub(crate) fn key_frontier(
    ctx: &mut MatchCliContext,
    args: CliArgs<'_>,
) -> Result<CliOutput, String> {
    let output = ctx.with_command_inputs(|store, clock| {
        auth::key_wrap::cli::key_frontier(store, clock, args)
    })?;
    let receipt = ctx.submit_and_settle(output)?;
    Ok(auth::key_wrap::cli::key_frontier_output(&receipt))
}

pub(crate) fn key_wrap(ctx: &mut MatchCliContext, args: CliArgs<'_>) -> Result<CliOutput, String> {
    let query = auth::key_wrap::cli::key_wrap_args(args)?;
    ctx.settle_local_command_work()?;
    let lookup = auth::key_wrap::commands::lookup_key_wrap(ctx.runtime(), query)?;
    Ok(auth::key_wrap::cli::key_wrap_lookup_output(&lookup))
}

pub(crate) fn key_access(
    ctx: &mut MatchCliContext,
    args: CliArgs<'_>,
) -> Result<CliOutput, String> {
    let query = auth::key_wrap::cli::key_access_args(args)?;
    ctx.settle_local_command_work()?;
    let status = auth::key_wrap::commands::key_access(ctx.runtime(), query)?;
    Ok(auth::key_wrap::cli::key_access_status_output(&status))
}

pub(crate) fn key_derive(
    ctx: &mut MatchCliContext,
    args: CliArgs<'_>,
) -> Result<CliOutput, String> {
    let limit = auth::key_wrap::cli::key_derive_limit(args)?;
    let before = auth::key_wrap::commands::local_key_secret_count(ctx.runtime());
    let scanned_key_wraps = auth::key_wrap::commands::key_wrap_count(ctx.runtime())?;
    ctx.runtime_mut()
        .process_command_work_until_idle(4, limit)?;
    let after = auth::key_wrap::commands::local_key_secret_count(ctx.runtime());
    Ok(CliOutput::lines(vec![
        format!("scanned_key_wraps: {scanned_key_wraps}"),
        format!("derived_key_secrets: {}", after.saturating_sub(before)),
        "failed_key_wraps: 0".to_string(),
    ]))
}

pub(crate) fn key_node(ctx: &mut MatchCliContext, args: CliArgs<'_>) -> Result<CliOutput, String> {
    let args = auth::key_wrap::cli::key_node_args(args)?;
    ctx.settle_local_command_work()?;
    let output = auth::key_wrap::commands::create_history_node(
        ctx.runtime(),
        auth::key_wrap::commands::CreateHistoryNode {
            created_at_ms: SystemClock.next_timestamp(),
            workspace_id: args.workspace_id,
            removal_frontier_id: args.removal_frontier_id,
            source_secret_id: args.source_secret_id,
            range_start: args.range_start,
            range_width: args.range_width,
            tombstone_node_id: args.tombstone_node_id,
        },
    )?;
    let receipt = ctx.submit_and_settle(output)?;
    Ok(auth::key_wrap::cli::history_node_output(&receipt))
}

pub(crate) fn keys(ctx: &mut MatchCliContext, args: CliArgs<'_>) -> Result<CliOutput, String> {
    let workspace_id = auth::key_wrap::cli::keys_workspace_id(args)?;
    ctx.settle_local_command_work()?;
    let report = auth::key_wrap::commands::key_status_report(ctx.runtime(), workspace_id)?;
    Ok(auth::key_wrap::cli::keys_output(&report))
}

pub(crate) fn chop_now(ctx: &mut MatchCliContext, args: CliArgs<'_>) -> Result<CliOutput, String> {
    let args = auth::key_wrap::cli::chop_now_args(args)?;
    ctx.settle_local_command_work()?;
    let receipt = auth::key_wrap::commands::chop_now(
        ctx.runtime_mut(),
        auth::key_wrap::commands::ChopNow {
            workspace_id: args.workspace_id,
            floor_minute: args.floor_minute,
            created_at_ms: SystemClock.next_timestamp(),
        },
    )?;
    Ok(auth::key_wrap::cli::chop_now_output(&receipt))
}

pub(crate) fn disappearing_set(
    ctx: &mut MatchCliContext,
    cli_args: CliArgs<'_>,
) -> Result<CliOutput, String> {
    let args = content::retention_policy::cli::parse_disappearing_set_args(cli_args.values())?;
    ctx.settle_local_command_work()?;
    let now_ms = next_cli_timestamp(ctx.runtime())?;
    let output = content::retention_policy::commands::author_set_with_auto_floor(
        ctx.runtime().store(),
        content::retention_policy::commands::AuthorPolicy {
            workspace_id: args.workspace_id,
            now_ms,
            ttl_minutes: args.ttl_minutes,
            explicit_floor: args.explicit_floor,
        },
    )?;
    let receipt = ctx.submit_and_settle(output)?;
    let delta = receipt
        .new_floor_minute
        .saturating_sub(receipt.previous_floor_minute);
    Ok(CliOutput::lines(vec![
        format!("policy_fact_id: {}", encode_hex_32(&receipt.policy_fact_id)),
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
    let workspace_id = content::retention_policy::cli::status_workspace_id(args)?;
    ctx.settle_local_command_work()?;
    settle_due_message_time_wakes(ctx)?;
    let report =
        content::retention_policy::commands::status_report(ctx.runtime().store(), workspace_id)?;
    Ok(content::retention_policy::cli::status_output(&report))
}

fn settle_due_message_time_wakes(ctx: &mut MatchCliContext) -> Result<(), String> {
    let Some(now_ms) = clock::logical_time(ctx.runtime().store())? else {
        return Ok(());
    };
    let now_minute = now_ms / content::retention_policy::commands::UNIX_MINUTE_MS;
    for _ in 0..COMMAND_SETTLE_ROUNDS {
        let due = ctx.runtime_mut().process_due_time_range(
            content::message::expiration_timeline(),
            None,
            now_minute,
            COMMAND_SETTLE_LIMIT,
        )?;
        ctx.settle_local_command_work()?;
        if due == 0 {
            return Ok(());
        }
    }
    Ok(())
}

pub(crate) fn disappearing_tighten(
    ctx: &mut MatchCliContext,
    cli_args: CliArgs<'_>,
) -> Result<CliOutput, String> {
    let args = content::retention_policy::cli::parse_disappearing_tighten_args(cli_args.values())?;
    if !args.yes {
        return Err("disappearing-tighten requires --yes in the target CLI".to_string());
    }
    ctx.settle_local_command_work()?;
    let now_ms = next_cli_timestamp(ctx.runtime())?;
    let input = content::retention_policy::commands::AuthorTighten {
        workspace_id: args.workspace_id,
        now_ms,
        ttl_minutes: args.ttl_minutes,
    };
    let plan = content::retention_policy::commands::plan_tighten(ctx.runtime().store(), input)?;
    let output = content::retention_policy::commands::author_tighten(ctx.runtime().store(), input)?;
    let receipt = ctx.submit_and_settle(output)?;
    ctx.settle_local_command_work()?;
    Ok(CliOutput::lines(vec![
        format!("policy_fact_id: {}", encode_hex_32(&receipt.policy_fact_id)),
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
    let workspace_id = content::retention_policy::cli::compact_workspace_id(args)?;
    ctx.settle_local_command_work()?;
    let now_ms = next_cli_timestamp(ctx.runtime())?;
    let output = content::retention_policy::commands::author_compact(
        ctx.runtime().store(),
        content::retention_policy::commands::AuthorCompact {
            workspace_id,
            now_ms,
        },
    )?;
    let receipt = ctx.submit_and_settle(output)?;
    let delta = receipt
        .new_floor_minute
        .saturating_sub(receipt.previous_floor_minute);
    Ok(CliOutput::lines(vec![
        format!("policy_fact_id: {}", encode_hex_32(&receipt.policy_fact_id)),
        format!("ttl_minutes: {}", receipt.ttl_minutes),
        format!("previous_floor_minute: {}", receipt.previous_floor_minute),
        format!("new_floor_minute: {}", receipt.new_floor_minute),
        format!("floor_delta_minutes: {delta}"),
    ]))
}

pub(crate) fn send(ctx: &mut MatchCliContext, args: CliArgs<'_>) -> Result<CliOutput, String> {
    let _workspace_id = args
        .get(0)
        .ok_or_else(|| content::message::cli::SEND_USAGE.to_string())
        .and_then(|value| decode_hex_32(value, "workspace id"))?;
    let text = args
        .get(1)
        .ok_or_else(|| content::message::cli::SEND_USAGE.to_string())?
        .to_string();
    let timestamp = next_cli_timestamp(ctx.runtime())?;
    let clock = FixedClock(timestamp);
    let output = content::message::cli::send(ctx.runtime().store(), &clock, args)?;
    let receipt = ctx.submit_and_settle(output)?;
    Ok(content::message::cli::send_output(&receipt, &text))
}

pub(crate) fn react(ctx: &mut MatchCliContext, args: CliArgs<'_>) -> Result<CliOutput, String> {
    let _workspace_id = args
        .get(0)
        .ok_or_else(|| content::message::cli::REACT_USAGE.to_string())
        .and_then(|value| decode_hex_32(value, "workspace id"))?;
    let timestamp = next_cli_timestamp(ctx.runtime())?;
    let clock = FixedClock(timestamp);
    let output = content::message::cli::react(ctx.runtime().store(), &clock, args)?;
    let receipt = ctx.submit_and_settle(output)?;
    Ok(content::message::cli::react_output(&receipt))
}

pub(crate) fn send_file(ctx: &mut MatchCliContext, args: CliArgs<'_>) -> Result<CliOutput, String> {
    let _workspace_id = args
        .get(0)
        .ok_or_else(|| content::message::cli::SEND_FILE_USAGE.to_string())
        .and_then(|value| decode_hex_32(value, "workspace id"))?;
    let timestamp = next_cli_timestamp(ctx.runtime())?;
    let clock = FixedClock(timestamp);
    let output = content::message::cli::send_file(ctx.runtime().store(), &clock, args)?;
    let receipt = ctx.submit_and_settle(output)?;
    Ok(content::message::cli::send_file_output(&receipt))
}

pub(crate) fn files(ctx: &mut MatchCliContext, args: CliArgs<'_>) -> Result<CliOutput, String> {
    ctx.settle_local_command_work()?;
    content::message::cli::files(ctx.runtime().store(), args)
}

pub(crate) fn save_file(ctx: &mut MatchCliContext, args: CliArgs<'_>) -> Result<CliOutput, String> {
    ctx.settle_local_command_work()?;
    content::message::cli::save_file(ctx.runtime().store(), args)
}

pub(crate) fn delete_file(
    ctx: &mut MatchCliContext,
    args: CliArgs<'_>,
) -> Result<CliOutput, String> {
    if args.values().len() != 2 {
        return Err(content::file_deletion::cli::DELETE_FILE_USAGE.to_string());
    }
    ctx.settle_local_command_work()?;
    let workspace_id = decode_hex_32(args.get(0).unwrap(), "workspace id")?;
    let file = content::file_deletion::cli::resolve_file_selector(
        ctx.runtime().store(),
        workspace_id,
        args.get(1).unwrap(),
    )?;
    let timestamp = next_cli_timestamp(ctx.runtime())?;
    let clock = FixedClock(timestamp);
    let output = content::file_deletion::commands::delete_file(
        ctx.runtime().store(),
        &clock,
        workspace_id,
        file.file_fact_id,
        file.author_user_id,
    )?;
    let receipt = ctx.submit_and_settle(output)?;
    Ok(content::file_deletion::cli::delete_file_output(&receipt))
}

pub(crate) fn delete_message(
    ctx: &mut MatchCliContext,
    args: CliArgs<'_>,
) -> Result<CliOutput, String> {
    let _workspace_id = args
        .get(0)
        .ok_or_else(|| content::message::cli::DELETE_MESSAGE_USAGE.to_string())
        .and_then(|value| decode_hex_32(value, "workspace id"))?;
    let timestamp = next_cli_timestamp(ctx.runtime())?;
    let clock = FixedClock(timestamp);
    let output = content::message::cli::delete_message(ctx.runtime().store(), &clock, args)?;
    let receipt = ctx.submit_and_settle(output)?;
    Ok(content::message::cli::delete_message_output(&receipt))
}

pub(crate) fn messages(ctx: &mut MatchCliContext, args: CliArgs<'_>) -> Result<CliOutput, String> {
    ctx.settle_local_command_work()?;
    content::message::cli::messages(ctx.runtime().store(), args)
}

pub(crate) fn view(ctx: &mut MatchCliContext, args: CliArgs<'_>) -> Result<CliOutput, String> {
    ctx.settle_local_command_work()?;
    content::message::cli::view(ctx.runtime().store(), args)
}

pub(crate) fn grant_admin(
    ctx: &mut MatchCliContext,
    args: CliArgs<'_>,
) -> Result<CliOutput, String> {
    let output =
        ctx.with_command_inputs(|store, clock| auth::admin::cli::grant_admin(store, clock, args))?;
    let receipt = ctx.runtime_mut().submit_command_output(output)?;
    ctx.runtime_mut().process_projection_until_idle(8, 64)?;
    Ok(auth::admin::cli::grant_admin_output(&receipt))
}

pub(crate) fn generate(ctx: &mut MatchCliContext, args: CliArgs<'_>) -> Result<CliOutput, String> {
    let parse_started = std::time::Instant::now();
    args.require_len(3, content::message::cli::GENERATE_USAGE)?;
    let _workspace_id = args
        .get(0)
        .ok_or_else(|| content::message::cli::GENERATE_USAGE.to_string())
        .and_then(|value| decode_hex_32(value, "workspace id"))?;
    let requested_count = args.parse_positive_usize(1, content::message::cli::GENERATE_USAGE)?;
    let requested_message_text_bytes =
        args.parse_positive_usize(2, content::message::cli::GENERATE_USAGE)?;
    let mut profile = crate::core::perf_profile::GenerateProfile::start(
        requested_count,
        requested_message_text_bytes,
    );
    crate::core::perf_profile::add_duration("parse", parse_started.elapsed());

    let timestamp = crate::core::perf_profile::measure_result("timestamp", || {
        next_cli_timestamp(ctx.runtime())
    })?;
    let clock = crate::core::perf_profile::measure_result("context_setup", || {
        Ok::<FixedClock, String>(FixedClock(timestamp))
    })?;
    let output = crate::core::perf_profile::measure_result("command_build", || {
        content::message::cli::generate(ctx.runtime().store(), &clock, args)
    })?;
    let receipt = crate::core::perf_profile::measure_result("commit", || {
        ctx.runtime_mut().submit_command_output(output)
    })?;
    crate::core::perf_profile::measure_result("settle", || ctx.settle_local_command_work())?;
    profile.finish_success(receipt.generated_facts, receipt.message_text_bytes);
    Ok(content::message::cli::generated_output(
        &receipt,
        receipt.generated_facts,
    ))
}

pub(crate) fn sync_status(
    ctx: &mut MatchCliContext,
    args: CliArgs<'_>,
) -> Result<CliOutput, String> {
    sync::shared_fact::cli::require_sync_status_args(args)?;
    ctx.settle_local_command_work()?;
    let status = crate::protocol::sync::shared_fact::sync_status(ctx.runtime().store())?;
    Ok(sync::shared_fact::cli::sync_status_output(&status))
}

pub(crate) fn sync_range(
    ctx: &mut MatchCliContext,
    args: CliArgs<'_>,
) -> Result<CliOutput, String> {
    let parsed = sync::shared_fact::cli::parse_sync_range_args(args)?;
    ctx.settle_local_command_work()?;
    let connection_id = sync::shared_fact::connection_id_for_peer_or_connection(
        ctx.runtime().store(),
        parsed.workspace_id,
        parsed.peer_or_connection_id,
    )?
    .ok_or_else(|| "sync-range could not find an authorized connection".to_string())?;
    ctx.runtime_mut().submit_intent(
        crate::protocol::connection::send_facts_on_connection::send_shareable_range_on_connection_intent(
            connection_id,
            parsed.start_ms,
            parsed.end_ms,
            parsed.include_deps,
        ),
    )?;
    Ok(sync::shared_fact::cli::sync_range_output(
        sync::shared_fact::cli::SyncRangeDispatched {
            connection_id,
            workspace_id: parsed.workspace_id,
            start_ms: parsed.start_ms,
            end_ms: parsed.end_ms,
            include_deps: parsed.include_deps,
            queued: true,
        },
    ))
}

pub(crate) fn content_count(
    ctx: &mut MatchCliContext,
    args: CliArgs<'_>,
) -> Result<CliOutput, String> {
    let output = content::message::cli::content_count(ctx.runtime().store(), args)?;
    Ok(content::message::cli::content_count_output(output))
}

pub(crate) fn clock(ctx: &mut MatchCliContext, args: CliArgs<'_>) -> Result<CliOutput, String> {
    let observed_max = max_cli_timestamp(ctx.runtime().store())?;
    clock::run_cli(ctx.runtime().store(), args, observed_max)
}

// Replay diagnostics.
//
// These commands exercise the core replay entry point and the deterministic
// state summary without requiring an actual upgrade. `replay` rebuilds derived
// state in place; `state-summary` hashes replay-relevant state; `replay-check`
// proves replay idempotence and projection-order independence on scratch copies;
// `intent-registry` lists each route's replay/recurring/command-excluded policy.

pub const REPLAY_USAGE: &str = "replay [--reverse | --scramble --seed N]";
pub const STATE_SUMMARY_USAGE: &str = "state-summary";
pub const REPLAY_CHECK_USAGE: &str = "replay-check";
pub const INTENT_REGISTRY_USAGE: &str = "intent-registry";

pub(crate) fn replay(ctx: &mut MatchCliContext, args: CliArgs<'_>) -> Result<CliOutput, String> {
    let order = parse_replay_order(args)?;
    let report = ctx
        .runtime_mut()
        .replay(crate::protocol::app::REPLAYABLE_DAEMON_TIME_WAKES, order)?;
    Ok(replay_report_output(order, &report))
}

pub(crate) fn state_summary(
    ctx: &mut MatchCliContext,
    args: CliArgs<'_>,
) -> Result<CliOutput, String> {
    args.require_len(0, STATE_SUMMARY_USAGE)?;
    let summary = ctx.runtime().state_summary()?;
    Ok(state_summary_output(&summary))
}

pub(crate) fn replay_check(
    ctx: &mut MatchCliContext,
    args: CliArgs<'_>,
) -> Result<CliOutput, String> {
    args.require_len(0, REPLAY_CHECK_USAGE)?;
    let db = ctx.db_path("replay-check")?.clone();
    let scratch = scratch_dir_for(&db);
    std::fs::create_dir_all(&scratch)
        .map_err(|err| format!("create replay-check scratch dir: {err}"))?;
    let result = ctx
        .runtime()
        .replay_check(&scratch, crate::protocol::app::REPLAYABLE_DAEMON_TIME_WAKES);
    let _ = std::fs::remove_dir_all(&scratch);
    Ok(replay_check_output(&result?))
}

pub(crate) fn intent_registry(
    ctx: &mut MatchCliContext,
    args: CliArgs<'_>,
) -> Result<CliOutput, String> {
    args.require_len(0, INTENT_REGISTRY_USAGE)?;
    let excluded = ctx.runtime().command_excluded_handlers();
    let routes = ctx.runtime().handler_routes();
    let mut lines = vec![format!("routes: {}", routes.len())];
    for route in routes {
        // The three policy questions that drive dispatch: may replay run this,
        // is it a recurring loop, and may a synchronous command run it.
        lines.push(format!(
            "route_{}: kind={} replay={} recurring={} command_excluded={}",
            route.name,
            route.intent_kind,
            route.runs_during_replay,
            route.recurrence.is_some(),
            excluded.contains(&route.name),
        ));
    }
    Ok(CliOutput::lines(lines))
}

fn replay_check_output(report: &crate::core::replay::ReplayCheckReport) -> CliOutput {
    let mut lines = vec![
        format!("ok: {}", report.mismatched.is_empty()),
        format!("passes: {}", report.passes.len()),
        format!("state_hash: {}", encode_hex_32(&report.canonical_hash)),
        format!("mismatched_passes: {}", report.mismatched.len()),
    ];
    for pass in &report.passes {
        for diff in &pass.area_diffs {
            lines.push(format!("diff_{}_{}", pass.name, diff));
        }
    }
    CliOutput::lines(lines)
}

fn parse_replay_order(args: CliArgs<'_>) -> Result<ReplayOrder, String> {
    match args.values() {
        [] => Ok(ReplayOrder::Canonical),
        [flag] if flag == "--reverse" => Ok(ReplayOrder::Reverse),
        [scramble, seed_flag, seed] if scramble == "--scramble" && seed_flag == "--seed" => {
            let seed = seed.parse::<u64>().map_err(|_| REPLAY_USAGE.to_string())?;
            Ok(ReplayOrder::Scramble { seed })
        }
        _ => Err(REPLAY_USAGE.to_string()),
    }
}

fn replay_order_label(order: ReplayOrder) -> String {
    match order {
        ReplayOrder::Canonical => "canonical".to_string(),
        ReplayOrder::Reverse => "reverse".to_string(),
        ReplayOrder::Scramble { seed } => format!("scramble:{seed}"),
    }
}

fn replay_report_output(order: ReplayOrder, report: &ReplayReport) -> CliOutput {
    CliOutput::lines(vec![
        format!("order: {}", replay_order_label(order)),
        format!(
            "dropped_durable_intents: {}",
            report.dropped_durable_intents
        ),
        format!("dropped_local_intents: {}", report.dropped_local_intents),
        format!("wiped_tables: {}", report.wiped_tables),
        format!("retained_facts: {}", report.retained_facts),
        format!("projected_facts: {}", report.projected_facts),
        format!("emitted_facts: {}", report.emitted_facts),
        format!("purged_facts: {}", report.purged_facts),
        format!("semantic_time_wakes: {}", report.semantic_time_wakes),
        format!("standing_time_wakes: {}", report.standing_time_wakes),
        format!("replay_allowed_intents: {}", report.replay_allowed_intents),
        format!("context_edges: {}", report.context_edges),
        format!("row_mutations: {}", report.row_mutations),
        format!(
            "suppressed_live_only_work: {}",
            report.suppressed_live_only_work
        ),
        format!("network_rows: {}", report.network_rows),
    ])
}

fn state_summary_output(summary: &StateSummary) -> CliOutput {
    let mut lines = vec![
        format!("state_hash: {}", encode_hex_32(&summary.state_hash)),
        format!("areas: {}", summary.areas.len()),
    ];
    for area in &summary.areas {
        lines.push(format!(
            "area_{}: {} {}",
            area.area,
            area.count,
            encode_hex_32(&area.hash)
        ));
    }
    CliOutput::lines(lines)
}

fn scratch_dir_for(db: &Path) -> PathBuf {
    let parent = db.parent().unwrap_or_else(|| Path::new("."));
    parent.join(format!(".topo-replay-check-{}", std::process::id()))
}

fn next_cli_timestamp(runtime: &Runtime) -> Result<u64, String> {
    let observed_max = max_cli_timestamp(runtime.store())?;
    clock::next_timestamp(runtime.store(), observed_max)
}

fn max_cli_timestamp(store: &crate::core::store::Store) -> Result<u64, String> {
    content::message::queries::max_created_at_ms(store)
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
