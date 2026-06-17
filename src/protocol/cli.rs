//! Command host functions for the concrete Context protocol.
//!
//! Fact-scope `cli.rs` modules own argv parsing, text formatting, and command
//! output construction. Core owns runtime opening and final printing. These
//! host functions add the protocol-specific runtime context between those two:
//! they pass the current store and command clock to command/query modules and
//! submit authored facts when a command authors work.
//!
//! This file is a command router, not a domain model. Each function should stay
//! thin: parse through the owning fact module, pass `Db`/`CommandClock` to
//! the owning command or query helper, submit `AuthoredFacts` when the command
//! authors work, and format with the owning module's CLI helpers. If the code
//! starts proving authority, constructing payload bytes, or interpreting
//! projected rows, move that logic back to the fact, intent, or query module
//! that owns it.

use crate::core::cli::{decode_hex_32_named as decode_hex_32, encode_hex_32, CliArgs, CliOutput};
use crate::core::command::{AuthoredFacts, CommandClock};
use crate::core::daemon;
use crate::core::db::Db;
use crate::core::replay::{ReplayOrder, ReplayReport};
use crate::core::replay_check::StateSummary;
use crate::core::runtime::Runtime;
use crate::protocol::connection;
use crate::protocol::sync;
use crate::protocol::{auth, content};
use std::path::{Path, PathBuf};

pub struct MatchCliContext {
    db: Option<PathBuf>,
    explicit_at_ms: Option<u64>,
    runtime: Runtime,
}

impl MatchCliContext {
    pub fn new(runtime: Runtime, db: Option<PathBuf>, explicit_at_ms: Option<u64>) -> Self {
        Self {
            db,
            explicit_at_ms,
            runtime,
        }
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
        &mut self,
        run: impl FnOnce(&Db, &dyn CommandClock) -> Result<T, String>,
    ) -> Result<T, String> {
        let clock = FixedClock(self.command_timestamp()?);
        run(self.runtime.db(), &clock)
    }

    fn command_timestamp(&self) -> Result<u64, String> {
        next_cli_timestamp(self.runtime.db(), self.explicit_at_ms)
    }

    fn explicit_at_ms(&self) -> Option<u64> {
        self.explicit_at_ms
    }

    fn query_db<T>(&mut self, run: impl FnOnce(&Db) -> Result<T, String>) -> Result<T, String> {
        run(self.runtime.db())
    }

    fn query_runtime<T>(
        &mut self,
        run: impl FnOnce(&Runtime) -> Result<T, String>,
    ) -> Result<T, String> {
        run(&self.runtime)
    }

    fn submit_authored_facts<T>(&mut self, output: AuthoredFacts<T>) -> Result<T, String> {
        self.runtime.submit_authored_facts(output)
    }
}

pub(crate) fn accept(ctx: &mut MatchCliContext, args: CliArgs<'_>) -> Result<CliOutput, String> {
    let from_listen_addr = daemon::current_listen_addr(ctx.db_path("accept")?)?;
    let output = ctx.with_command_inputs(|store, clock| {
        auth::invite_secret::cli::accept(store, clock, args, from_listen_addr)
    })?;
    let receipt = ctx.submit_authored_facts(output)?;
    Ok(auth::invite_secret::cli::accept_output(&receipt))
}

pub(crate) fn accept_invite_server(
    ctx: &mut MatchCliContext,
    args: CliArgs<'_>,
) -> Result<CliOutput, String> {
    let from_listen_addr = daemon::current_listen_addr(ctx.db_path("accept-invite-server")?)?;
    let output = ctx.with_command_inputs(|store, clock| {
        auth::invite_secret::cli::accept_invite_server(store, clock, args, from_listen_addr)
    })?;
    let receipt = ctx.submit_authored_facts(output)?;
    Ok(auth::invite_secret::cli::accept_output(&receipt))
}

pub(crate) fn accept_link(
    ctx: &mut MatchCliContext,
    args: CliArgs<'_>,
) -> Result<CliOutput, String> {
    let from_listen_addr = daemon::current_listen_addr(ctx.db_path("accept-link")?)?;
    let output = ctx.with_command_inputs(|store, clock| {
        auth::invite_secret::cli::accept_link(store, clock, args, from_listen_addr)
    })?;
    let receipt = ctx.submit_authored_facts(output)?;
    Ok(auth::invite_secret::cli::accept_output(&receipt))
}

pub(crate) fn connect(ctx: &mut MatchCliContext, args: CliArgs<'_>) -> Result<CliOutput, String> {
    args.require_len(2, connection::request::api::CONNECT_USAGE)?;
    let target_endpoint = decode_hex_32(
        args.get(0).ok_or(connection::request::api::CONNECT_USAGE)?,
        "endpoint id",
    )?;
    let dialed_addr = args
        .get(1)
        .ok_or(connection::request::api::CONNECT_USAGE)?
        .parse()
        .map_err(|_| "connect address must be HOST:PORT".to_string())?;
    let from_listen_addr = daemon::current_listen_addr(ctx.db_path("connect")?)?;
    let output = ctx.with_command_inputs(|store, clock| {
        connection::request::api::connect(
            store,
            connection::request::api::Connect {
                created_at_ms: clock.next_timestamp(),
                target_endpoint,
                dialed_addr,
                from_listen_addr,
            },
        )
    })?;
    let receipt = ctx.submit_authored_facts(output)?;
    Ok(CliOutput::line(format!(
        "connecting: request_id={}",
        encode_hex_32(&receipt.request_id)
    )))
}

pub(crate) fn identity(ctx: &mut MatchCliContext, args: CliArgs<'_>) -> Result<CliOutput, String> {
    ctx.query_db(|store| auth::endpoint_shared::cli::identity(store, args))
}

pub(crate) fn peers(ctx: &mut MatchCliContext, args: CliArgs<'_>) -> Result<CliOutput, String> {
    ctx.query_db(|store| auth::endpoint_shared::cli::peers(store, args))
}

pub(crate) fn invite(ctx: &mut MatchCliContext, args: CliArgs<'_>) -> Result<CliOutput, String> {
    let output = ctx
        .with_command_inputs(|store, clock| auth::invite_secret::cli::invite(store, clock, args))?;
    let receipt = ctx.submit_authored_facts(output)?;
    Ok(auth::invite_secret::cli::invite_output(&receipt))
}

pub(crate) fn invite_server(
    ctx: &mut MatchCliContext,
    args: CliArgs<'_>,
) -> Result<CliOutput, String> {
    let output = ctx.with_command_inputs(|store, clock| {
        auth::invite_secret::cli::invite_server(store, clock, args)
    })?;
    let receipt = ctx.submit_authored_facts(output)?;
    Ok(auth::invite_secret::cli::invite_output(&receipt))
}

pub(crate) fn link(ctx: &mut MatchCliContext, args: CliArgs<'_>) -> Result<CliOutput, String> {
    let output =
        ctx.with_command_inputs(|store, clock| auth::invite_secret::cli::link(store, clock, args))?;
    let receipt = ctx.submit_authored_facts(output)?;
    Ok(auth::invite_secret::cli::invite_output(&receipt))
}

pub(crate) fn create_workspace(
    ctx: &mut MatchCliContext,
    args: CliArgs<'_>,
) -> Result<CliOutput, String> {
    let output = ctx.with_command_inputs(|store, clock| {
        auth::workspace::cli::create_workspace(store, clock, args)
    })?;
    let receipt = ctx.submit_authored_facts(output)?;
    Ok(auth::workspace::cli::created_workspace_output(&receipt))
}

pub(crate) fn workspaces(
    ctx: &mut MatchCliContext,
    args: CliArgs<'_>,
) -> Result<CliOutput, String> {
    let output = ctx.query_db(|store| auth::workspace::cli::workspaces(store, args))?;
    Ok(auth::workspace::cli::workspaces_output(&output))
}

pub(crate) fn count(ctx: &mut MatchCliContext, args: CliArgs<'_>) -> Result<CliOutput, String> {
    args.require_len(0, auth::workspace::cli::COUNT_USAGE)?;
    let report = ctx.query_runtime(auth::workspace::queries::runtime_count_report)?;
    Ok(auth::workspace::cli::count_report_output(&report))
}

pub(crate) fn users(ctx: &mut MatchCliContext, args: CliArgs<'_>) -> Result<CliOutput, String> {
    let output = ctx.query_db(|store| auth::user::cli::users(store, args))?;
    Ok(auth::user::cli::users_output(&output))
}

pub(crate) fn key_recipient(
    ctx: &mut MatchCliContext,
    args: CliArgs<'_>,
) -> Result<CliOutput, String> {
    let output = ctx.with_command_inputs(|store, clock| {
        auth::key_wrap::cli::key_recipient(store, clock, args)
    })?;
    let receipt = ctx.submit_authored_facts(output)?;
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
    let previous = ctx
        .query_runtime(|runtime| {
            auth::key_wrap::queries::recipient_key_for_rotation(runtime, workspace_id)
        })?
        .ok_or_else(|| "no existing local recipient key to rotate".to_string())?;
    let output = ctx.with_command_inputs(|store, clock| {
        auth::key_wrap::cli::key_recipient_rotation(store, clock, args, previous)
    })?;
    let receipt = ctx.submit_authored_facts(output)?;
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
    let receipt = ctx.submit_authored_facts(output)?;
    Ok(auth::key_wrap::cli::key_frontier_output(&receipt))
}

pub(crate) fn key_wrap(ctx: &mut MatchCliContext, args: CliArgs<'_>) -> Result<CliOutput, String> {
    let query = auth::key_wrap::cli::key_wrap_args(args)?;
    let lookup =
        ctx.query_runtime(|runtime| auth::key_wrap::queries::lookup_key_wrap(runtime, query))?;
    Ok(auth::key_wrap::cli::key_wrap_lookup_output(&lookup))
}

pub(crate) fn key_access(
    ctx: &mut MatchCliContext,
    args: CliArgs<'_>,
) -> Result<CliOutput, String> {
    let query = auth::key_wrap::cli::key_access_args(args)?;
    let now_ms = ctx.explicit_at_ms();
    let status =
        ctx.query_runtime(|runtime| auth::key_wrap::queries::key_access(runtime, query, now_ms))?;
    Ok(auth::key_wrap::cli::key_access_status_output(&status))
}

pub(crate) fn key_derive(
    ctx: &mut MatchCliContext,
    args: CliArgs<'_>,
) -> Result<CliOutput, String> {
    let _limit = auth::key_wrap::cli::key_derive_limit(args)?;
    let scanned_key_wraps = ctx.query_runtime(auth::key_wrap::queries::key_wrap_count)?;
    Ok(CliOutput::lines(vec![
        format!("scanned_key_wraps: {scanned_key_wraps}"),
        "derived_key_secrets: 0".to_string(),
        "failed_key_wraps: 0".to_string(),
    ]))
}

pub(crate) fn key_node(ctx: &mut MatchCliContext, args: CliArgs<'_>) -> Result<CliOutput, String> {
    let args = auth::key_wrap::cli::key_node_args(args)?;
    let created_at_ms = ctx.command_timestamp()?;
    let output = auth::key_wrap::api::create_history_node(
        ctx.runtime().db(),
        auth::key_wrap::api::CreateHistoryNode {
            created_at_ms,
            workspace_id: args.workspace_id,
            removal_frontier_id: args.removal_frontier_id,
            source_secret_id: args.source_secret_id,
            range_start: args.range_start,
            range_width: args.range_width,
            tombstone_node_id: args.tombstone_node_id,
        },
    )?;
    let receipt = ctx.submit_authored_facts(output)?;
    Ok(auth::key_wrap::cli::history_node_output(&receipt))
}

pub(crate) fn keys(ctx: &mut MatchCliContext, args: CliArgs<'_>) -> Result<CliOutput, String> {
    let workspace_id = auth::key_wrap::cli::keys_workspace_id(args)?;
    let report = ctx.query_runtime(|runtime| {
        auth::key_wrap::queries::key_status_report(runtime, workspace_id)
    })?;
    Ok(auth::key_wrap::cli::keys_output(&report))
}

pub(crate) fn disappearing_set(
    ctx: &mut MatchCliContext,
    cli_args: CliArgs<'_>,
) -> Result<CliOutput, String> {
    let args = content::retention_policy::cli::parse_disappearing_set_args(cli_args.values())?;
    let now_ms = ctx.command_timestamp()?;
    let output = content::retention_policy::api::author_set_with_auto_floor(
        ctx.runtime().db(),
        content::retention_policy::api::AuthorPolicy {
            workspace_id: args.workspace_id,
            now_ms,
            ttl_minutes: args.ttl_minutes,
            explicit_floor: args.explicit_floor,
        },
    )?;
    let receipt = ctx.submit_authored_facts(output)?;
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
    let now_ms = ctx.explicit_at_ms();
    let report = ctx.query_db(|store| {
        content::retention_policy::queries::status_report(store, workspace_id, now_ms)
    })?;
    Ok(content::retention_policy::cli::status_output(&report))
}

pub(crate) fn disappearing_tighten(
    ctx: &mut MatchCliContext,
    cli_args: CliArgs<'_>,
) -> Result<CliOutput, String> {
    let args = content::retention_policy::cli::parse_disappearing_tighten_args(cli_args.values())?;
    if !args.yes {
        return Err("disappearing-tighten requires --yes in the target CLI".to_string());
    }
    let now_ms = ctx.command_timestamp()?;
    let input = content::retention_policy::api::AuthorTighten {
        workspace_id: args.workspace_id,
        now_ms,
        ttl_minutes: args.ttl_minutes,
    };
    let plan = content::retention_policy::api::plan_tighten(ctx.runtime().db(), input)?;
    let output = content::retention_policy::api::author_tighten(ctx.runtime().db(), input)?;
    let receipt = ctx.submit_authored_facts(output)?;
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
    let now_ms = ctx.command_timestamp()?;
    let output = content::retention_policy::api::author_compact(
        ctx.runtime().db(),
        content::retention_policy::api::AuthorCompact {
            workspace_id,
            now_ms,
        },
    )?;
    let receipt = ctx.submit_authored_facts(output)?;
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
    let timestamp = ctx.command_timestamp()?;
    let clock = FixedClock(timestamp);
    let output = content::message::cli::send(ctx.runtime().db(), &clock, args)?;
    let receipt = ctx.submit_authored_facts(output)?;
    Ok(content::message::cli::send_output(&receipt, &text))
}

pub(crate) fn react(ctx: &mut MatchCliContext, args: CliArgs<'_>) -> Result<CliOutput, String> {
    let _workspace_id = args
        .get(0)
        .ok_or_else(|| content::message::cli::REACT_USAGE.to_string())
        .and_then(|value| decode_hex_32(value, "workspace id"))?;
    let timestamp = ctx.command_timestamp()?;
    let clock = FixedClock(timestamp);
    let output = content::message::cli::react(ctx.runtime().db(), &clock, args)?;
    let receipt = ctx.submit_authored_facts(output)?;
    Ok(content::message::cli::react_output(&receipt))
}

pub(crate) fn send_file(ctx: &mut MatchCliContext, args: CliArgs<'_>) -> Result<CliOutput, String> {
    let _workspace_id = args
        .get(0)
        .ok_or_else(|| content::message::cli::SEND_FILE_USAGE.to_string())
        .and_then(|value| decode_hex_32(value, "workspace id"))?;
    let timestamp = ctx.command_timestamp()?;
    let clock = FixedClock(timestamp);
    let output = content::message::cli::send_file(ctx.runtime().db(), &clock, args)?;
    let receipt = ctx.submit_authored_facts(output)?;
    Ok(content::message::cli::send_file_output(&receipt))
}

pub(crate) fn files(ctx: &mut MatchCliContext, args: CliArgs<'_>) -> Result<CliOutput, String> {
    ctx.query_db(|store| content::message::cli::files(store, args))
}

pub(crate) fn save_file(ctx: &mut MatchCliContext, args: CliArgs<'_>) -> Result<CliOutput, String> {
    ctx.query_db(|store| content::message::cli::save_file(store, args))
}

pub(crate) fn delete_file(
    ctx: &mut MatchCliContext,
    args: CliArgs<'_>,
) -> Result<CliOutput, String> {
    if args.values().len() != 2 {
        return Err(content::file_deletion::cli::DELETE_FILE_USAGE.to_string());
    }
    let workspace_id = decode_hex_32(args.get(0).unwrap(), "workspace id")?;
    let file = ctx.query_db(|store| {
        content::file_deletion::cli::resolve_file_selector(
            store,
            workspace_id,
            args.get(1).unwrap(),
        )
    })?;
    let timestamp = ctx.command_timestamp()?;
    let clock = FixedClock(timestamp);
    let output = content::file_deletion::api::delete_file(
        ctx.runtime().db(),
        &clock,
        workspace_id,
        file.file_fact_id,
        file.author_user_id,
    )?;
    let receipt = ctx.submit_authored_facts(output)?;
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
    let timestamp = ctx.command_timestamp()?;
    let clock = FixedClock(timestamp);
    let output = content::message::cli::delete_message(ctx.runtime().db(), &clock, args)?;
    let receipt = ctx.submit_authored_facts(output)?;
    Ok(content::message::cli::delete_message_output(&receipt))
}

pub(crate) fn messages(ctx: &mut MatchCliContext, args: CliArgs<'_>) -> Result<CliOutput, String> {
    ctx.query_db(|store| content::message::cli::messages(store, args))
}

pub(crate) fn view(ctx: &mut MatchCliContext, args: CliArgs<'_>) -> Result<CliOutput, String> {
    ctx.query_db(|store| content::message::cli::view(store, args))
}

pub(crate) fn grant_admin(
    ctx: &mut MatchCliContext,
    args: CliArgs<'_>,
) -> Result<CliOutput, String> {
    let output =
        ctx.with_command_inputs(|store, clock| auth::admin::cli::grant_admin(store, clock, args))?;
    let receipt = ctx.submit_authored_facts(output)?;
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

    let timestamp =
        crate::core::perf_profile::measure_result("timestamp", || ctx.command_timestamp())?;
    let clock = crate::core::perf_profile::measure_result("context_setup", || {
        Ok::<FixedClock, String>(FixedClock(timestamp))
    })?;
    let output = crate::core::perf_profile::measure_result("command_build", || {
        content::message::cli::generate(ctx.runtime().db(), &clock, args)
    })?;
    let receipt = crate::core::perf_profile::measure_result("commit", || {
        ctx.runtime_mut().submit_authored_facts(output)
    })?;
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
    let status = ctx.query_db(crate::protocol::sync::shared_fact::sync_status)?;
    Ok(sync::shared_fact::cli::sync_status_output(&status))
}

pub(crate) fn sync(ctx: &mut MatchCliContext, args: CliArgs<'_>) -> Result<CliOutput, String> {
    match sync::local_setting::parse_sync_args(args)? {
        sync::local_setting::SyncCliCommand::Show => {
            let setting = ctx.query_db(sync::local_setting::current_setting)?;
            Ok(sync::local_setting::sync_setting_output(setting.as_ref()))
        }
        sync::local_setting::SyncCliCommand::Set(mode) => {
            let output = ctx.with_command_inputs(|_store, clock| {
                sync::local_setting::author_setting(clock, mode)
            })?;
            let receipt = ctx.submit_authored_facts(output)?;
            Ok(sync::local_setting::sync_setting_receipt_output(&receipt))
        }
    }
}

pub(crate) fn content_count(
    ctx: &mut MatchCliContext,
    args: CliArgs<'_>,
) -> Result<CliOutput, String> {
    let output = ctx.query_db(|store| content::message::cli::content_count(store, args))?;
    Ok(content::message::cli::content_count_output(output))
}

// Replay diagnostics.
//
// These commands exercise the core replay entry point and the deterministic
// state summary without requiring an actual upgrade. `replay` rebuilds derived
// state in place; `state-summary` hashes replay-relevant state; `replay-check`
// proves replay idempotence and projection-order independence on scratch copies;
// `intent-registry` lists each handler route's intent kind and recurring policy.

pub const REPLAY_USAGE: &str = "replay [--reverse | --scramble --seed N]";
pub const STATE_SUMMARY_USAGE: &str = "state-summary";
pub const REPLAY_CHECK_USAGE: &str = "replay-check";
pub const INTENT_REGISTRY_USAGE: &str = "intent-registry";

pub(crate) fn replay(ctx: &mut MatchCliContext, args: CliArgs<'_>) -> Result<CliOutput, String> {
    let order = parse_replay_order(args)?;
    let report = ctx.runtime_mut().replay(order)?;
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
    let result = ctx.runtime().replay_check(&scratch);
    let _ = std::fs::remove_dir_all(&scratch);
    Ok(replay_check_output(&result?))
}

pub(crate) fn intent_registry(
    ctx: &mut MatchCliContext,
    args: CliArgs<'_>,
) -> Result<CliOutput, String> {
    args.require_len(0, INTENT_REGISTRY_USAGE)?;
    let routes = ctx.runtime().handler_routes();
    let mut lines = vec![format!("routes: {}", routes.len())];
    for (index, route) in routes.iter().enumerate() {
        lines.push(format!(
            "route_{index}: kind={} recurring={}",
            route.intent_kind,
            route.recurrence.is_some(),
        ));
    }
    Ok(CliOutput::lines(lines))
}

fn replay_check_output(report: &crate::core::replay_check::ReplayCheckReport) -> CliOutput {
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
        format!("emitted_facts: {}", report.emitted_facts),
        format!("purged_facts: {}", report.purged_facts),
        format!("standing_time_wakes: {}", report.standing_time_wakes),
        format!("context_edges: {}", report.context_edges),
        format!("row_mutations: {}", report.row_mutations),
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

fn next_cli_timestamp(store: &Db, explicit_at_ms: Option<u64>) -> Result<u64, String> {
    if let Some(timestamp) = explicit_at_ms {
        return Ok(timestamp);
    }
    let observed_max = content::message::queries::max_created_at_ms(store)?;
    Ok(SystemClock
        .next_timestamp()
        .max(observed_max.saturating_add(1)))
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
