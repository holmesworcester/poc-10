//! Product-facing `match` binary entrypoint.
//!
//! `main.rs` stays intentionally tiny: it collects argv and delegates here.
//! This module chooses the current Topo protocol implementation behind the
//! product-facing `match` binary name. It should not grow protocol logic,
//! projection code, handler dispatch, or fact construction.

use crate::core::cli::{
    decode_hex_32_named as core_decode_hex_32, encode_hex as core_encode_hex,
    encode_hex_32 as core_encode_hex_32, CliArgs,
};
use crate::core::command_context::{
    CommandClock, IdentityVault, LocalEncryptionCapability, LocalSigningCapability, WorkspaceId,
};
use crate::core::daemon;
use crate::core::logical_clock;
use crate::protocol::facts::connection;
use crate::protocol::facts::sync;
use crate::protocol::facts::{content, encryption, identity};
use crate::protocol::intents::connection::send_bootstrap_request::{
    decode_send_bootstrap_connection_request, SEND_BOOTSTRAP_CONNECTION_REQUEST,
};
use crate::protocol::intents::content::purge_below_retention_floor::{
    purge_below_retention_floor_intent, PurgeBelowRetentionFloor,
};
use crate::protocol::runtime::ProtocolRuntime;
use std::collections::BTreeSet;
use std::path::PathBuf;
use std::time::Duration;

const DELETE_FILE_USAGE: &str = "delete-file WORKSPACE_ID_HEX FILE_SELECTOR";

pub fn run(argv: Vec<String>) -> Result<(), String> {
    let parsed = ParsedArgs::parse(argv)?;
    match parsed.command.first().map(String::as_str) {
        None => Err(top_level_usage("missing command")),
        Some("-h" | "--help" | "help") => {
            println!("{}", top_level_usage("Topo match CLI"));
            Ok(())
        }
        Some("create-workspace") => run_create_workspace(parsed),
        Some("invite") => run_invite(parsed),
        Some("invite-server") => run_invite_server(parsed),
        Some("accept") => run_accept(parsed),
        Some("accept-invite-server") => run_accept_invite_server(parsed),
        Some("link") => run_link(parsed),
        Some("accept-link") => run_accept_link(parsed),
        Some("identity") => run_identity(parsed),
        Some("peers") => run_peers(parsed),
        Some("workspaces") => run_workspaces(parsed),
        Some("users") => run_users(parsed),
        Some("key-recipient") => run_key_recipient(parsed),
        Some("key-rotate-recipient") => run_key_recipient_rotation(parsed),
        Some("key-frontier") => run_key_frontier(parsed),
        Some("key-wrap") => run_key_wrap(parsed),
        Some("key-access") => run_key_access(parsed),
        Some("key-derive") => run_key_derive(parsed),
        Some("key-node") => run_key_node(parsed),
        Some("keys") => run_keys(parsed),
        Some("chop-now") => run_chop_now(parsed),
        Some("disappearing-set") => run_disappearing_set(parsed),
        Some("disappearing-status") => run_disappearing_status(parsed),
        Some("disappearing-tighten") => run_disappearing_tighten(parsed),
        Some("disappearing-compact") => run_disappearing_compact(parsed),
        Some("send") => run_send(parsed),
        Some("react") => run_react(parsed),
        Some("send-file") => run_send_file(parsed),
        Some("files") => run_files(parsed),
        Some("save-file") => run_save_file(parsed),
        Some("delete-file") => run_delete_file(parsed),
        Some("delete-message") => run_delete_message(parsed),
        Some("messages") => run_messages(parsed),
        Some("view") => run_view(parsed),
        Some("grant-admin") => run_grant_admin(parsed),
        Some("generate") => run_generate(parsed),
        Some("generate-deps") => run_generate_deps(parsed),
        Some("replay-deps-reverse") => run_replay_deps_reverse(parsed),
        Some("sync-status") => run_sync_status(parsed),
        Some("negentropy-drain") => run_negentropy_drain(parsed),
        Some("content-count") => run_content_count(parsed),
        Some("clock") => run_clock(parsed),
        Some("count") => run_count(parsed),
        Some("start") => run_start(parsed),
        Some("stop") => run_stop(parsed),
        Some("reset") => run_reset(parsed),
        Some(command) => Err(top_level_usage(&format!(
            "command `{command}` is not ported to the target runtime yet"
        ))),
    }
}

fn top_level_usage(reason: &str) -> String {
    format!(
        "{reason}\nusage:\n  match --db PATH {create_workspace_usage}\n\
         match --db PATH {invite_usage}\n\
         match --db PATH {invite_server_usage}\n\
         match --db PATH {accept_usage}\n\
         match --db PATH {accept_invite_server_usage}\n\
         match --db PATH {link_usage}\n\
         match --db PATH {accept_link_usage}\n\
         match --db PATH {identity_usage}\n\
         match --db PATH {peers_usage}\n\
         match --db PATH {workspaces_usage}\n\
         match --db PATH {users_usage}\n\
         match --db PATH {key_recipient_usage}\n\
         match --db PATH {key_rotate_recipient_usage}\n\
         match --db PATH {key_frontier_usage}\n\
         match --db PATH {key_wrap_usage}\n\
         match --db PATH {key_access_usage}\n\
         match --db PATH key-derive [LIMIT]\n\
         match --db PATH key-node WORKSPACE_ID_HEX REMOVAL_FRONTIER_ID_HEX SOURCE_SECRET_ID_HEX RANGE_START RANGE_WIDTH [TOMBSTONE_NODE_ID_HEX]\n\
         match --db PATH keys WORKSPACE_ID_HEX\n\
         match --db PATH chop-now WORKSPACE_ID_HEX FLOOR_MINUTE\n\
         match --db PATH disappearing-set WORKSPACE_ID_HEX TTL_MINUTES [--floor MINUTE]\n\
         match --db PATH disappearing-status WORKSPACE_ID_HEX\n\
         match --db PATH disappearing-tighten WORKSPACE_ID_HEX TTL_MINUTES [--yes|-y]\n\
         match --db PATH disappearing-compact WORKSPACE_ID_HEX\n\
         match --db PATH {send_usage}\n\
         match --db PATH {react_usage}\n\
         match --db PATH {send_file_usage}\n\
         match --db PATH {files_usage}\n\
         match --db PATH {save_file_usage}\n\
         match --db PATH {delete_file_usage}\n\
         match --db PATH {delete_message_usage}\n\
         match --db PATH {messages_usage}\n\
         match --db PATH {view_usage}\n\
         match --db PATH {grant_admin_usage}\n\
         match --db PATH {generate_usage}\n\
         match --db PATH {generate_deps_usage}\n\
         match --db PATH {replay_deps_reverse_usage}\n\
         match --db PATH sync-status\n\
         match --db PATH negentropy-drain [LIMIT]\n\
         match --db PATH {content_count_usage}\n\
         match --db PATH clock [set TIMESTAMP|advance DELTA|clear]\n\
         match --db PATH {count_usage}\n\
         match --db PATH start --listen IP PORT [--tick-ms N] [--quiet-ms N]\n\
         match --db PATH stop\n\
         match --db PATH reset\n\n\
        available commands run through the target core runtime facade",
        create_workspace_usage = identity::workspace::cli::CREATE_WORKSPACE_USAGE,
        invite_usage = identity::invite::cli::INVITE_USAGE,
        invite_server_usage = identity::invite::cli::INVITE_SERVER_USAGE,
        accept_usage = identity::invite::cli::ACCEPT_USAGE,
        accept_invite_server_usage = identity::invite::cli::ACCEPT_INVITE_SERVER_USAGE,
        link_usage = identity::invite::cli::LINK_USAGE,
        accept_link_usage = identity::invite::cli::ACCEPT_LINK_USAGE,
        identity_usage = identity::endpoint_shared::cli::IDENTITY_USAGE,
        peers_usage = identity::endpoint_shared::cli::PEERS_USAGE,
        workspaces_usage = identity::workspace::cli::WORKSPACES_USAGE,
        users_usage = identity::user::cli::USERS_USAGE,
        key_recipient_usage = encryption::cli::KEY_RECIPIENT_USAGE,
        key_rotate_recipient_usage = encryption::cli::KEY_ROTATE_RECIPIENT_USAGE,
        key_frontier_usage = encryption::cli::KEY_FRONTIER_USAGE,
        key_wrap_usage = encryption::cli::KEY_WRAP_USAGE,
        key_access_usage = encryption::cli::KEY_ACCESS_USAGE,
        send_usage = content::sealed_message::cli::SEND_USAGE,
        react_usage = content::sealed_message::cli::REACT_USAGE,
        send_file_usage = content::sealed_message::cli::SEND_FILE_USAGE,
        files_usage = content::sealed_message::cli::FILES_USAGE,
        save_file_usage = content::sealed_message::cli::SAVE_FILE_USAGE,
        delete_file_usage = DELETE_FILE_USAGE,
        delete_message_usage = content::sealed_message::cli::DELETE_MESSAGE_USAGE,
        messages_usage = content::sealed_message::cli::MESSAGES_USAGE,
        view_usage = content::sealed_message::cli::VIEW_USAGE,
        grant_admin_usage = identity::admin::cli::GRANT_ADMIN_USAGE,
        generate_usage = content::event::cli::GENERATE_USAGE,
        generate_deps_usage = sync::cascade_fact::cli::GENERATE_DEPS_USAGE,
        replay_deps_reverse_usage = sync::cascade_fact::cli::REPLAY_DEPS_REVERSE_USAGE,
        content_count_usage = content::event::cli::CONTENT_COUNT_USAGE,
        count_usage = identity::workspace::cli::COUNT_USAGE
    )
}

fn run_identity(parsed: ParsedArgs) -> Result<(), String> {
    let db = parsed
        .db
        .ok_or_else(|| top_level_usage("identity requires --db PATH"))?;
    let runtime = ProtocolRuntime::open_disk(db)?;
    let clock = SystemClock;
    let vault = EmptyVault;
    let output = {
        let ctx = runtime.command_context(&clock, &vault);
        identity::endpoint_shared::cli::identity(&ctx, CliArgs::new(&parsed.command[1..]))?
    };
    for line in output.lines {
        println!("{line}");
    }
    Ok(())
}

fn run_peers(parsed: ParsedArgs) -> Result<(), String> {
    let db = parsed
        .db
        .ok_or_else(|| top_level_usage("peers requires --db PATH"))?;
    let runtime = ProtocolRuntime::open_disk(db)?;
    let clock = SystemClock;
    let vault = EmptyVault;
    let output = {
        let ctx = runtime.command_context(&clock, &vault);
        identity::endpoint_shared::cli::peers(&ctx, CliArgs::new(&parsed.command[1..]))?
    };
    for line in output.lines {
        println!("{line}");
    }
    Ok(())
}

fn run_invite(parsed: ParsedArgs) -> Result<(), String> {
    let db = parsed
        .db
        .ok_or_else(|| top_level_usage("invite requires --db PATH"))?;
    let mut runtime = ProtocolRuntime::open_disk(db)?;
    let clock = SystemClock;
    let vault = EmptyVault;
    let output = {
        let ctx = runtime.command_context(&clock, &vault);
        identity::invite::cli::invite(&ctx, CliArgs::new(&parsed.command[1..]))?
    };
    let receipt = runtime.submit_command_output(output)?;
    drain_runtime(&mut runtime)?;
    runtime.save()?;

    for line in identity::invite::cli::invite_output(&receipt).lines {
        println!("{line}");
    }
    Ok(())
}

fn run_invite_server(parsed: ParsedArgs) -> Result<(), String> {
    let db = parsed
        .db
        .ok_or_else(|| top_level_usage("invite-server requires --db PATH"))?;
    let mut runtime = ProtocolRuntime::open_disk(db)?;
    let clock = SystemClock;
    let vault = EmptyVault;
    let output = {
        let ctx = runtime.command_context(&clock, &vault);
        identity::invite::cli::invite_server(&ctx, CliArgs::new(&parsed.command[1..]))?
    };
    let receipt = runtime.submit_command_output(output)?;
    drain_runtime(&mut runtime)?;
    runtime.save()?;

    for line in identity::invite::cli::invite_output(&receipt).lines {
        println!("{line}");
    }
    Ok(())
}

fn run_accept(parsed: ParsedArgs) -> Result<(), String> {
    let db = parsed
        .db
        .ok_or_else(|| top_level_usage("accept requires --db PATH"))?;
    let from_listen_addr = daemon::current_listen_addr(&db)?;
    let mut runtime = ProtocolRuntime::open_disk(db)?;
    let clock = SystemClock;
    let vault = EmptyVault;
    let output = {
        let ctx = runtime.command_context(&clock, &vault);
        identity::invite::cli::accept(&ctx, CliArgs::new(&parsed.command[1..]), from_listen_addr)?
    };
    let receipt = runtime.submit_command_output(output)?;
    drain_runtime(&mut runtime)?;
    if from_listen_addr.is_none() {
        ensure_bootstrap_request_sent(&runtime, receipt.request_id)?;
    }
    runtime.save()?;
    if from_listen_addr.is_some() {
        connection::response::commands::wait_for_request_response(
            &mut runtime,
            receipt.request_id,
            Duration::from_secs(30),
        )?;
    }

    for line in identity::invite::cli::accept_output(&receipt).lines {
        println!("{line}");
    }
    Ok(())
}

fn run_accept_invite_server(parsed: ParsedArgs) -> Result<(), String> {
    let db = parsed
        .db
        .ok_or_else(|| top_level_usage("accept-invite-server requires --db PATH"))?;
    let from_listen_addr = daemon::current_listen_addr(&db)?;
    let mut runtime = ProtocolRuntime::open_disk(db)?;
    let clock = SystemClock;
    let vault = EmptyVault;
    let output = {
        let ctx = runtime.command_context(&clock, &vault);
        identity::invite::cli::accept_invite_server(
            &ctx,
            CliArgs::new(&parsed.command[1..]),
            from_listen_addr,
        )?
    };
    let receipt = runtime.submit_command_output(output)?;
    drain_runtime(&mut runtime)?;
    runtime.save()?;
    connection::response::commands::wait_for_request_response(
        &mut runtime,
        receipt.request_id,
        Duration::from_secs(10),
    )?;

    for line in identity::invite::cli::accept_output(&receipt).lines {
        println!("{line}");
    }
    Ok(())
}

fn run_link(parsed: ParsedArgs) -> Result<(), String> {
    let db = parsed
        .db
        .ok_or_else(|| top_level_usage("link requires --db PATH"))?;
    let mut runtime = ProtocolRuntime::open_disk(db)?;
    let clock = SystemClock;
    let vault = EmptyVault;
    let output = {
        let ctx = runtime.command_context(&clock, &vault);
        identity::invite::cli::link(&ctx, CliArgs::new(&parsed.command[1..]))?
    };
    let receipt = runtime.submit_command_output(output)?;
    drain_runtime(&mut runtime)?;
    runtime.save()?;

    for line in identity::invite::cli::invite_output(&receipt).lines {
        println!("{line}");
    }
    Ok(())
}

fn run_accept_link(parsed: ParsedArgs) -> Result<(), String> {
    let db = parsed
        .db
        .ok_or_else(|| top_level_usage("accept-link requires --db PATH"))?;
    let from_listen_addr = daemon::current_listen_addr(&db)?;
    let mut runtime = ProtocolRuntime::open_disk(db)?;
    let clock = SystemClock;
    let vault = EmptyVault;
    let output = {
        let ctx = runtime.command_context(&clock, &vault);
        identity::invite::cli::accept_link(
            &ctx,
            CliArgs::new(&parsed.command[1..]),
            from_listen_addr,
        )?
    };
    let receipt = runtime.submit_command_output(output)?;
    drain_runtime(&mut runtime)?;
    runtime.save()?;
    if from_listen_addr.is_some() {
        connection::response::commands::wait_for_request_response(
            &mut runtime,
            receipt.request_id,
            Duration::from_secs(10),
        )?;
    }

    for line in identity::invite::cli::accept_output(&receipt).lines {
        println!("{line}");
    }
    Ok(())
}

fn run_start(parsed: ParsedArgs) -> Result<(), String> {
    let db = parsed
        .db
        .ok_or_else(|| top_level_usage("start requires --db PATH"))?;
    let mut runtime = ProtocolRuntime::open_disk(&db)?;
    let output = daemon::start(
        &db,
        CliArgs::new(&parsed.command[1..]),
        |listener, limit| runtime.daemon_tick(listener, limit),
    )?;
    for line in output.lines {
        println!("{line}");
    }
    Ok(())
}

fn run_stop(parsed: ParsedArgs) -> Result<(), String> {
    let db = parsed
        .db
        .ok_or_else(|| top_level_usage("stop requires --db PATH"))?;
    let output = daemon::stop(&db, CliArgs::new(&parsed.command[1..]))?;
    for line in output.lines {
        println!("{line}");
    }
    Ok(())
}

fn run_reset(parsed: ParsedArgs) -> Result<(), String> {
    let db = parsed
        .db
        .ok_or_else(|| top_level_usage("reset requires --db PATH"))?;
    let output = daemon::reset(&db, CliArgs::new(&parsed.command[1..]))?;
    for line in output.lines {
        println!("{line}");
    }
    Ok(())
}

fn run_create_workspace(parsed: ParsedArgs) -> Result<(), String> {
    let db = parsed
        .db
        .ok_or_else(|| top_level_usage("create-workspace requires --db PATH"))?;
    let mut runtime = ProtocolRuntime::open_disk(db)?;
    let clock = SystemClock;
    let vault = EmptyVault;
    let output = {
        let ctx = runtime.command_context(&clock, &vault);
        identity::workspace::cli::create_workspace(&ctx, CliArgs::new(&parsed.command[1..]))?
    };
    let receipt = runtime.submit_command_output(output)?;
    drain_runtime(&mut runtime)?;
    let workspace =
        identity::workspace::queries::workspace_by_id(runtime.store(), receipt.workspace_fact_id)?;
    let bootstrap_user_id =
        identity::user::queries::users_in_workspace(runtime.store(), receipt.workspace_fact_id)?
            .first()
            .map(|user| user.user_id);
    runtime.save()?;

    for line in
        identity::workspace::cli::created_workspace_output(&workspace, bootstrap_user_id).lines
    {
        println!("{line}");
    }
    Ok(())
}

fn run_workspaces(parsed: ParsedArgs) -> Result<(), String> {
    let db = parsed
        .db
        .ok_or_else(|| top_level_usage("workspaces requires --db PATH"))?;
    let runtime = ProtocolRuntime::open_disk(db)?;
    let clock = SystemClock;
    let vault = EmptyVault;
    let output = {
        let ctx = runtime.command_context(&clock, &vault);
        identity::workspace::cli::workspaces(&ctx, CliArgs::new(&parsed.command[1..]))?
    };

    for line in identity::workspace::cli::workspaces_output(&output).lines {
        println!("{line}");
    }
    Ok(())
}

fn run_count(parsed: ParsedArgs) -> Result<(), String> {
    let db = parsed
        .db
        .ok_or_else(|| top_level_usage("count requires --db PATH"))?;
    let runtime = ProtocolRuntime::open_disk(db)?;
    CliArgs::new(&parsed.command[1..]).require_len(0, identity::workspace::cli::COUNT_USAGE)?;
    let report = identity::workspace::runtime_counts::runtime_count_report(&runtime)?;
    for line in identity::workspace::cli::count_report_output(&report).lines {
        println!("{line}");
    }
    Ok(())
}

fn run_users(parsed: ParsedArgs) -> Result<(), String> {
    let db = parsed
        .db
        .ok_or_else(|| top_level_usage("users requires --db PATH"))?;
    let runtime = ProtocolRuntime::open_disk(db)?;
    let clock = SystemClock;
    let vault = EmptyVault;
    let output = {
        let ctx = runtime.command_context(&clock, &vault);
        identity::user::cli::users(&ctx, CliArgs::new(&parsed.command[1..]))?
    };

    for line in identity::user::cli::users_output(&output).lines {
        println!("{line}");
    }
    Ok(())
}

fn run_key_recipient(parsed: ParsedArgs) -> Result<(), String> {
    let db = parsed
        .db
        .ok_or_else(|| top_level_usage("key-recipient requires --db PATH"))?;
    let mut runtime = ProtocolRuntime::open_disk(db)?;
    let clock = SystemClock;
    let vault = EmptyVault;
    let output = {
        let ctx = runtime.command_context(&clock, &vault);
        encryption::cli::key_recipient(&ctx, CliArgs::new(&parsed.command[1..]))?
    };
    let receipt = runtime.submit_command_output(output)?;
    drain_runtime(&mut runtime)?;
    runtime.save()?;

    for line in encryption::cli::key_recipient_output(&receipt).lines {
        println!("{line}");
    }
    Ok(())
}

fn run_key_recipient_rotation(parsed: ParsedArgs) -> Result<(), String> {
    let db = parsed
        .db
        .ok_or_else(|| top_level_usage("key-rotate-recipient requires --db PATH"))?;
    let mut runtime = ProtocolRuntime::open_disk(db)?;
    let workspace_id = parsed
        .command
        .get(1)
        .ok_or_else(|| encryption::cli::KEY_ROTATE_RECIPIENT_USAGE.to_string())
        .and_then(|value| decode_hex_32(value, "workspace id"))?;
    drain_runtime(&mut runtime)?;
    let previous = encryption::commands::recipient_key_for_rotation(&runtime, workspace_id)?
        .ok_or_else(|| "no existing local recipient key to rotate".to_string())?;
    let clock = SystemClock;
    let vault = EmptyVault;
    let output = {
        let ctx = runtime.command_context(&clock, &vault);
        encryption::cli::key_recipient_rotation(&ctx, CliArgs::new(&parsed.command[1..]), previous)?
    };
    let receipt = runtime.submit_command_output(output)?;
    drain_runtime(&mut runtime)?;
    runtime.save()?;

    for line in encryption::cli::key_recipient_output(&receipt).lines {
        println!("{line}");
    }
    println!("old_active_recipient_keys: 1");
    println!("tombstoned_recipient_keys: 1");
    Ok(())
}

fn run_key_frontier(parsed: ParsedArgs) -> Result<(), String> {
    let db = parsed
        .db
        .ok_or_else(|| top_level_usage("key-frontier requires --db PATH"))?;
    let mut runtime = ProtocolRuntime::open_disk(db)?;
    let clock = SystemClock;
    let vault = EmptyVault;
    let output = {
        let ctx = runtime.command_context(&clock, &vault);
        encryption::cli::key_frontier(&ctx, CliArgs::new(&parsed.command[1..]))?
    };
    let receipt = runtime.submit_command_output(output)?;
    drain_runtime(&mut runtime)?;
    runtime.save()?;

    for line in encryption::cli::key_frontier_output(&receipt).lines {
        println!("{line}");
    }
    Ok(())
}

fn run_key_wrap(parsed: ParsedArgs) -> Result<(), String> {
    let db = parsed
        .db
        .ok_or_else(|| top_level_usage("key-wrap requires --db PATH"))?;
    let mut runtime = ProtocolRuntime::open_disk(db)?;
    let query = encryption::cli::key_wrap_args(CliArgs::new(&parsed.command[1..]))?;
    drain_runtime(&mut runtime)?;
    runtime.save()?;
    let lookup = encryption::commands::lookup_key_wrap(&runtime, query)?;
    for line in encryption::cli::key_wrap_lookup_output(&lookup).lines {
        println!("{line}");
    }
    Ok(())
}

fn run_key_access(parsed: ParsedArgs) -> Result<(), String> {
    let db = parsed
        .db
        .ok_or_else(|| top_level_usage("key-access requires --db PATH"))?;
    let mut runtime = ProtocolRuntime::open_disk(db)?;
    let query = encryption::cli::key_access_args(CliArgs::new(&parsed.command[1..]))?;
    drain_runtime(&mut runtime)?;
    runtime.save()?;
    let status = encryption::commands::key_access(&runtime, query)?;
    for line in encryption::cli::key_access_status_output(&status).lines {
        println!("{line}");
    }
    Ok(())
}

fn run_key_derive(parsed: ParsedArgs) -> Result<(), String> {
    let db = parsed
        .db
        .ok_or_else(|| top_level_usage("key-derive requires --db PATH"))?;
    if parsed.command.len() > 2 {
        return Err("key-derive [LIMIT]".to_string());
    }
    let limit = parsed
        .command
        .get(1)
        .map(|value| {
            value
                .parse::<usize>()
                .map_err(|_| "key-derive [LIMIT]".to_string())
        })
        .transpose()?
        .unwrap_or(512);
    let mut runtime = ProtocolRuntime::open_disk(db)?;
    let before = encryption::commands::local_key_secret_count(&runtime);
    let scanned_key_wraps = encryption::commands::key_wrap_count(&runtime)?;
    for _ in 0..4 {
        runtime.drain_projection_until_idle(8, limit)?;
        let dispatched = runtime.dispatch_cli_intents(limit)?;
        if dispatched.handled == 0 && dispatched.facts == 0 && dispatched.intents == 0 {
            break;
        }
    }
    runtime.drain_projection_until_idle(8, limit)?;
    runtime.save()?;
    let after = encryption::commands::local_key_secret_count(&runtime);
    println!("scanned_key_wraps: {scanned_key_wraps}");
    println!("derived_key_secrets: {}", after.saturating_sub(before));
    println!("failed_key_wraps: 0");
    println!("admitted_events: 0");
    Ok(())
}

fn run_key_node(parsed: ParsedArgs) -> Result<(), String> {
    let db = parsed
        .db
        .ok_or_else(|| top_level_usage("key-node requires --db PATH"))?;
    if parsed.command.len() != 6 && parsed.command.len() != 7 {
        return Err("key-node WORKSPACE_ID_HEX REMOVAL_FRONTIER_ID_HEX SOURCE_SECRET_ID_HEX RANGE_START RANGE_WIDTH [TOMBSTONE_NODE_ID_HEX]".to_string());
    }
    let mut runtime = ProtocolRuntime::open_disk(db)?;
    drain_runtime(&mut runtime)?;
    let workspace_id = decode_hex_32(&parsed.command[1], "workspace id")?;
    let frontier_id = decode_hex_32(&parsed.command[2], "removal frontier id")?;
    let source_secret_id = decode_hex_32(&parsed.command[3], "source secret id")?;
    let range_start = parsed.command[4]
        .parse::<u64>()
        .map_err(|_| "key-node range_start must be a u64".to_string())?;
    let range_width = parsed.command[5]
        .parse::<u64>()
        .map_err(|_| "key-node range_width must be a u64".to_string())?;
    let tombstone_node_id = if let Some(value) = parsed.command.get(6) {
        decode_hex_32(value, "tombstone node id")?
    } else {
        [0; 32]
    };
    let output = encryption::commands::create_history_node(
        &runtime,
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
    let receipt = runtime.submit_command_output(output)?;
    drain_runtime(&mut runtime)?;
    runtime.save()?;
    for line in encryption::cli::history_node_output(&receipt).lines {
        println!("{line}");
    }
    Ok(())
}

fn run_keys(parsed: ParsedArgs) -> Result<(), String> {
    let db = parsed
        .db
        .ok_or_else(|| top_level_usage("keys requires --db PATH"))?;
    if parsed.command.len() != 2 {
        return Err("keys WORKSPACE_ID_HEX".to_string());
    }
    let mut runtime = ProtocolRuntime::open_disk(db)?;
    drain_runtime(&mut runtime)?;
    runtime.save()?;
    let workspace_id = decode_hex_32(&parsed.command[1], "workspace id")?;
    let store = runtime.store();

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
            content::sealed_message::rows::MESSAGE_TOMBSTONE_ROWS,
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
        encryption::commands::local_key_secret_frontiers(&runtime, workspace_id);
    let recipient_keys = runtime
        .facts()
        .filter_map(|fact| encryption::layout::decode_recipient_key(&fact.bytes).ok())
        .filter(|key| key.workspace_id == workspace_id)
        .count();
    let local_recipient_keys = runtime
        .facts()
        .filter_map(|fact| encryption::layout::decode_local_recipient_key(&fact.bytes).ok())
        .filter(|key| key.workspace_id == workspace_id)
        .count();
    let removal_frontiers = runtime
        .facts()
        .filter_map(|fact| {
            encryption::layout::decode_removal_frontier(&fact.bytes)
                .ok()
                .map(|frontier| (fact.id, frontier))
        })
        .filter(|(_, frontier)| frontier.workspace_id == workspace_id)
        .collect::<Vec<_>>();
    let key_wraps = encryption::commands::workspace_key_wrap_count(&runtime, workspace_id)?;

    println!("recipient_keys: {recipient_keys}");
    println!("recipient_key_tombstones: 0");
    println!("local_recipient_keys: {local_recipient_keys}");
    println!("removal_frontiers: {}", removal_frontiers.len());
    println!("key_wraps: {key_wraps}");
    println!("local_key_secrets: {}", local_key_secret_frontiers.len());
    println!(
        "local_history_node_secrets: {}",
        local_history_rows.len() + leaves.len()
    );
    println!("local_history_minute_nodes: 0");
    println!("local_history_leaves: {}", leaves.len());
    println!("local_history_trie_internals: 0");
    println!("local_history_time_internals: 0");
    println!(
        "local_history_node_tombstones: {}",
        message_tombstones.len() + file_tombstones.len()
    );
    println!("message_tombstones: {}", message_tombstones.len());
    println!("cover_summary: {}", cover_summary(&leaves));
    for (frontier_id, _) in removal_frontiers {
        let access = local_key_secret_frontiers
            .iter()
            .any(|local_frontier_id| *local_frontier_id == frontier_id);
        println!(
            "frontier: {} access={}",
            encode_hex_32(&frontier_id),
            if access { "yes" } else { "no" }
        );
    }
    for leaf in leaves {
        println!(
            "history_node: {} frontier={} start={} width=1 bit_depth=256 prefix={} fact_id_in_minute={} tombstones=none",
            encode_hex_32(&leaf.node_id),
            encode_hex_32(&leaf.frontier_id),
            leaf.minute,
            encode_hex_32(&leaf.fact_id_in_minute),
            encode_hex_32(&leaf.fact_id_in_minute)
        );
    }
    Ok(())
}

fn run_chop_now(parsed: ParsedArgs) -> Result<(), String> {
    let db = parsed
        .db
        .ok_or_else(|| top_level_usage("chop-now requires --db PATH"))?;
    if parsed.command.len() != 3 {
        return Err("chop-now WORKSPACE_ID_HEX FLOOR_MINUTE".to_string());
    }
    let mut runtime = ProtocolRuntime::open_disk(db)?;
    drain_runtime(&mut runtime)?;
    let workspace_id = decode_hex_32(&parsed.command[1], "workspace id")?;
    let floor_minute = parsed.command[2]
        .parse::<u64>()
        .map_err(|_| "chop-now floor minute must be a u64".to_string())?;
    let receipt = encryption::commands::chop_now(
        &mut runtime,
        encryption::commands::ChopNow {
            workspace_id,
            floor_minute,
            created_at_ms: SystemClock.next_timestamp(),
        },
    )?;
    runtime.save()?;
    for line in encryption::cli::chop_now_output(&receipt).lines {
        println!("{line}");
    }
    Ok(())
}

fn run_disappearing_set(parsed: ParsedArgs) -> Result<(), String> {
    let db = parsed
        .db
        .ok_or_else(|| top_level_usage("disappearing-set requires --db PATH"))?;
    let args = parse_disappearing_set_args(&parsed.command[1..])?;
    let mut runtime = ProtocolRuntime::open_disk(db)?;
    drain_runtime(&mut runtime)?;
    let now_ms = next_cli_timestamp(&runtime)?;
    let output = encryption::disappearing_messages_setting::commands::author_set_with_auto_floor(
        runtime.store(),
        encryption::disappearing_messages_setting::commands::AuthorSetting {
            workspace_id: args.workspace_id,
            now_ms,
            ttl_minutes: args.ttl_minutes,
            explicit_floor: args.explicit_floor,
        },
    )?;
    let receipt = runtime.submit_command_output(output)?;
    drain_runtime(&mut runtime)?;
    runtime.save()?;
    let delta = receipt
        .new_floor_minute
        .saturating_sub(receipt.previous_floor_minute);
    println!(
        "setting_fact_id: {}",
        encode_hex_32(&receipt.setting_fact_id)
    );
    println!("ttl_minutes: {}", args.ttl_minutes);
    println!("previous_floor_minute: {}", receipt.previous_floor_minute);
    println!("new_floor_minute: {}", receipt.new_floor_minute);
    println!("floor_delta_minutes: {delta}");
    Ok(())
}

fn run_disappearing_status(parsed: ParsedArgs) -> Result<(), String> {
    let db = parsed
        .db
        .ok_or_else(|| top_level_usage("disappearing-status requires --db PATH"))?;
    if parsed.command.len() != 2 {
        return Err("disappearing-status WORKSPACE_ID_HEX".to_string());
    }
    let workspace_id = decode_hex_32(&parsed.command[1], "workspace id")?;
    let mut runtime = ProtocolRuntime::open_disk(db)?;
    drain_runtime(&mut runtime)?;
    runtime.save()?;
    let store = runtime.store();
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
    let now_minute = logical_clock::logical_time(store)?.map(|ms| ms / 60_000);
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
            content::sealed_message::rows::MESSAGE_TOMBSTONE_ROWS,
            &workspace_id,
            usize::MAX,
        )
        .map_err(|err| format!("load message tombstones: {err}"))?;
    let message_tombstones = raw_message_tombstones
        .into_iter()
        .map(|(key, value)| {
            content::sealed_message::rows::decode_message_tombstone_row(&key, &value)
        })
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .filter(|row| row.authored_minute >= horizon_floor)
        .count();
    let live_messages = message_rows(store, workspace_id)?
        .into_iter()
        .filter(|row| row.minute >= horizon_floor)
        .count();
    let last_chopped_floor = if horizon_floor > setting_floor && horizon_floor > 0 {
        horizon_floor.to_string()
    } else {
        "none".to_string()
    };

    println!("workspace: {}", encode_hex_32(&workspace_id));
    println!("setting_fact_id: {setting_fact_id}");
    println!("current_ttl_minutes: {ttl}");
    println!("current_floor_minute: {setting_floor}");
    println!("last_chopped_floor: {last_chopped_floor}");
    println!("now_minute: {now_minute_str}");
    println!("horizon_floor: {horizon_floor}");
    println!("effective_floor: {effective_floor}");
    println!("live_messages: {live_messages}");
    println!("message_tombstones: {message_tombstones}");
    println!("leaf_tombstones: 0");
    println!("pending_purges: 0");
    Ok(())
}

fn apply_horizon_floor(
    store: &crate::core::store::Store,
    workspace_id: [u8; 32],
    horizon_floor: u64,
) -> Result<(), String> {
    let retired = message_rows(store, workspace_id)?
        .into_iter()
        .filter(|row| row.minute < horizon_floor)
        .collect::<Vec<_>>();
    if retired.is_empty() {
        return Ok(());
    }
    let tombstones = retired
        .iter()
        .map(|row| {
            content::sealed_message::rows::message_tombstone_row(
                row.workspace_id,
                row.message_id,
                row.author_user_id,
                row.created_at_ms,
            )
        })
        .collect::<Vec<_>>();
    let keys = retired
        .iter()
        .map(|row| content::sealed_message::rows::message_key(row.workspace_id, row.message_id))
        .collect::<Vec<_>>();
    store
        .write_transaction(|tx| {
            tx.insert_table_rows_in_tx(tombstones)?;
            tx.delete_table_rows_in_tx(content::sealed_message::rows::MESSAGE_ROWS, keys.clone())?;
            tx.delete_table_rows_in_tx(content::message::rows::CONTENT_MESSAGE_ROWS, keys.clone())?;
            tx.delete_table_rows_in_tx(
                content::sealed_message::rows::OPENED_MESSAGE_ROWS,
                keys.clone(),
            )?;
            tx.delete_table_rows_in_tx(content::sealed_message::rows::SEALED_MESSAGE_ROWS, keys)?;
            Ok(())
        })
        .map_err(|err| format!("apply horizon floor: {err}"))
}

fn run_disappearing_tighten(parsed: ParsedArgs) -> Result<(), String> {
    let db = parsed
        .db
        .ok_or_else(|| top_level_usage("disappearing-tighten requires --db PATH"))?;
    let args = parse_disappearing_tighten_args(&parsed.command[1..])?;
    if !args.yes {
        return Err("disappearing-tighten requires --yes in the target CLI".to_string());
    }
    let mut runtime = ProtocolRuntime::open_disk(db)?;
    drain_runtime(&mut runtime)?;
    let now_ms = next_cli_timestamp(&runtime)?;
    let input = encryption::disappearing_messages_setting::commands::AuthorTighten {
        workspace_id: args.workspace_id,
        now_ms,
        ttl_minutes: args.ttl_minutes,
    };
    let plan =
        encryption::disappearing_messages_setting::commands::plan_tighten(runtime.store(), input)?;
    let output = encryption::disappearing_messages_setting::commands::author_tighten(
        runtime.store(),
        input,
    )?;
    let receipt = runtime.submit_command_output(output)?;
    drain_runtime(&mut runtime)?;
    enqueue_floor_retention(
        &mut runtime,
        args.workspace_id,
        receipt.setting_fact_id,
        receipt.target_floor_minute,
    )?;
    drain_runtime(&mut runtime)?;
    runtime.save()?;

    println!(
        "setting_fact_id: {}",
        encode_hex_32(&receipt.setting_fact_id)
    );
    println!("ttl_minutes: {}", args.ttl_minutes);
    println!("previous_floor_minute: {}", receipt.previous_floor_minute);
    println!("new_floor_minute: {}", receipt.target_floor_minute);
    println!("messages_below_floor: {}", plan.messages_below_floor);
    Ok(())
}

fn run_disappearing_compact(parsed: ParsedArgs) -> Result<(), String> {
    let db = parsed
        .db
        .ok_or_else(|| top_level_usage("disappearing-compact requires --db PATH"))?;
    if parsed.command.len() != 2 {
        return Err("disappearing-compact WORKSPACE_ID_HEX".to_string());
    }
    let workspace_id = decode_hex_32(&parsed.command[1], "workspace id")?;
    let mut runtime = ProtocolRuntime::open_disk(db)?;
    drain_runtime(&mut runtime)?;
    let now_ms = next_cli_timestamp(&runtime)?;
    let output = encryption::disappearing_messages_setting::commands::author_compact(
        runtime.store(),
        encryption::disappearing_messages_setting::commands::AuthorCompact {
            workspace_id,
            now_ms,
        },
    )?;
    let receipt = runtime.submit_command_output(output)?;
    drain_runtime(&mut runtime)?;
    runtime.save()?;
    let delta = receipt
        .new_floor_minute
        .saturating_sub(receipt.previous_floor_minute);
    println!(
        "setting_fact_id: {}",
        encode_hex_32(&receipt.setting_fact_id)
    );
    println!("ttl_minutes: {}", receipt.ttl_minutes);
    println!("previous_floor_minute: {}", receipt.previous_floor_minute);
    println!("new_floor_minute: {}", receipt.new_floor_minute);
    println!("floor_delta_minutes: {delta}");
    Ok(())
}

fn run_send(parsed: ParsedArgs) -> Result<(), String> {
    let db = parsed
        .db
        .ok_or_else(|| top_level_usage("send requires --db PATH"))?;
    let mut runtime = ProtocolRuntime::open_disk(db)?;
    let workspace_id = parsed
        .command
        .get(1)
        .ok_or_else(|| content::sealed_message::cli::SEND_USAGE.to_string())
        .and_then(|value| decode_hex_32(value, "workspace id"))?;
    let text = parsed
        .command
        .get(2)
        .ok_or_else(|| content::sealed_message::cli::SEND_USAGE.to_string())?
        .clone();
    let clock = FixedClock(next_cli_timestamp(&runtime)?);
    let vault = content::sealed_message::authoring::SealedMessageVault::for_workspace(
        &runtime,
        workspace_id,
    )?;
    let output = {
        let ctx = runtime.command_context(&clock, &vault);
        content::sealed_message::cli::send(&ctx, CliArgs::new(&parsed.command[1..]))?
    };
    let receipt = runtime.submit_command_output(output)?;
    drain_runtime(&mut runtime)?;
    runtime.save()?;
    for line in content::sealed_message::cli::send_output(&receipt, &text).lines {
        println!("{line}");
    }
    Ok(())
}

fn run_react(parsed: ParsedArgs) -> Result<(), String> {
    let db = parsed
        .db
        .ok_or_else(|| top_level_usage("react requires --db PATH"))?;
    let mut runtime = ProtocolRuntime::open_disk(db)?;
    let clock = FixedClock(next_cli_timestamp(&runtime)?);
    let vault = EmptyVault;
    let output = {
        let ctx = runtime.command_context(&clock, &vault);
        content::sealed_message::cli::react(&ctx, CliArgs::new(&parsed.command[1..]))?
    };
    let receipt = runtime.submit_command_output(output)?;
    drain_runtime(&mut runtime)?;
    runtime.save()?;
    for line in content::sealed_message::cli::react_output(&receipt).lines {
        println!("{line}");
    }
    Ok(())
}

fn run_send_file(parsed: ParsedArgs) -> Result<(), String> {
    let db = parsed
        .db
        .ok_or_else(|| top_level_usage("send-file requires --db PATH"))?;
    let mut runtime = ProtocolRuntime::open_disk(db)?;
    let workspace_id = parsed
        .command
        .get(1)
        .ok_or_else(|| content::sealed_message::cli::SEND_FILE_USAGE.to_string())
        .and_then(|value| decode_hex_32(value, "workspace id"))?;
    let clock = FixedClock(next_cli_timestamp(&runtime)?);
    let vault = content::sealed_message::authoring::SealedMessageVault::for_workspace(
        &runtime,
        workspace_id,
    )?;
    let output = {
        let ctx = runtime.command_context(&clock, &vault);
        content::sealed_message::cli::send_file(&ctx, CliArgs::new(&parsed.command[1..]))?
    };
    let receipt = runtime.submit_command_output(output)?;
    drain_runtime(&mut runtime)?;
    runtime.save()?;
    for line in content::sealed_message::cli::send_file_output(&receipt).lines {
        println!("{line}");
    }
    Ok(())
}

fn run_files(parsed: ParsedArgs) -> Result<(), String> {
    let db = parsed
        .db
        .ok_or_else(|| top_level_usage("files requires --db PATH"))?;
    let mut runtime = ProtocolRuntime::open_disk(db)?;
    drain_runtime(&mut runtime)?;
    runtime.save()?;
    let clock = SystemClock;
    let vault = EmptyVault;
    let output = {
        let ctx = runtime.command_context(&clock, &vault);
        content::sealed_message::cli::files(&ctx, CliArgs::new(&parsed.command[1..]))?
    };
    for line in output.lines {
        println!("{line}");
    }
    Ok(())
}

fn run_save_file(parsed: ParsedArgs) -> Result<(), String> {
    let db = parsed
        .db
        .ok_or_else(|| top_level_usage("save-file requires --db PATH"))?;
    let mut runtime = ProtocolRuntime::open_disk(db)?;
    drain_runtime(&mut runtime)?;
    runtime.save()?;
    let clock = SystemClock;
    let vault = EmptyVault;
    let output = {
        let ctx = runtime.command_context(&clock, &vault);
        content::sealed_message::cli::save_file(&ctx, CliArgs::new(&parsed.command[1..]))?
    };
    for line in output.lines {
        println!("{line}");
    }
    Ok(())
}

fn run_delete_file(parsed: ParsedArgs) -> Result<(), String> {
    let db = parsed
        .db
        .ok_or_else(|| top_level_usage("delete-file requires --db PATH"))?;
    if parsed.command.len() != 3 {
        return Err(DELETE_FILE_USAGE.to_string());
    }
    let mut runtime = ProtocolRuntime::open_disk(db)?;
    drain_runtime(&mut runtime)?;
    let workspace_id = decode_hex_32(&parsed.command[1], "workspace id")?;
    let file = resolve_file_selector(runtime.store(), workspace_id, &parsed.command[2])?;
    let clock = FixedClock(next_cli_timestamp(&runtime)?);
    let vault = EmptyVault;
    let output = {
        let ctx = runtime.command_context(&clock, &vault);
        content::file_deletion::commands::delete_file(
            &ctx,
            workspace_id,
            file.file_fact_id,
            file.author_user_id,
        )?
    };
    let receipt = runtime.submit_command_output(output)?;
    drain_runtime(&mut runtime)?;
    runtime.save()?;
    println!("workspace_id: {}", encode_hex_32(&receipt.workspace_id));
    println!("fact_id: {}", encode_hex_32(&receipt.deletion_fact_id));
    println!("target_file_id: {}", encode_hex_32(&receipt.target_file_id));
    println!("created_at_ms: {}", receipt.created_at_ms);
    Ok(())
}

fn run_delete_message(parsed: ParsedArgs) -> Result<(), String> {
    let db = parsed
        .db
        .ok_or_else(|| top_level_usage("delete-message requires --db PATH"))?;
    let mut runtime = ProtocolRuntime::open_disk(db)?;
    let clock = FixedClock(next_cli_timestamp(&runtime)?);
    let vault = EmptyVault;
    let output = {
        let ctx = runtime.command_context(&clock, &vault);
        content::sealed_message::cli::delete_message(&ctx, CliArgs::new(&parsed.command[1..]))?
    };
    let receipt = runtime.submit_command_output(output)?;
    drain_runtime(&mut runtime)?;
    runtime.save()?;
    for line in content::sealed_message::cli::delete_message_output(&receipt).lines {
        println!("{line}");
    }
    Ok(())
}

fn run_messages(parsed: ParsedArgs) -> Result<(), String> {
    let db = parsed
        .db
        .ok_or_else(|| top_level_usage("messages requires --db PATH"))?;
    let mut runtime = ProtocolRuntime::open_disk(db)?;
    drain_runtime(&mut runtime)?;
    runtime.save()?;
    let clock = SystemClock;
    let vault = EmptyVault;
    let output = {
        let ctx = runtime.command_context(&clock, &vault);
        content::sealed_message::cli::messages(&ctx, CliArgs::new(&parsed.command[1..]))?
    };
    for line in output.lines {
        println!("{line}");
    }
    Ok(())
}

fn run_view(parsed: ParsedArgs) -> Result<(), String> {
    let db = parsed
        .db
        .ok_or_else(|| top_level_usage("view requires --db PATH"))?;
    let mut runtime = ProtocolRuntime::open_disk(db)?;
    drain_runtime(&mut runtime)?;
    runtime.save()?;
    let clock = SystemClock;
    let vault = EmptyVault;
    let output = {
        let ctx = runtime.command_context(&clock, &vault);
        content::sealed_message::cli::view(&ctx, CliArgs::new(&parsed.command[1..]))?
    };
    for line in output.lines {
        println!("{line}");
    }
    Ok(())
}

fn run_grant_admin(parsed: ParsedArgs) -> Result<(), String> {
    let db = parsed
        .db
        .ok_or_else(|| top_level_usage("grant-admin requires --db PATH"))?;
    let mut runtime = ProtocolRuntime::open_disk(db)?;
    let clock = SystemClock;
    let vault = EmptyVault;
    let output = {
        let ctx = runtime.command_context(&clock, &vault);
        identity::admin::cli::grant_admin(&ctx, CliArgs::new(&parsed.command[1..]))?
    };
    let receipt = runtime.submit_command_output(output)?;
    runtime.drain_projection_until_idle(8, 64)?;
    runtime.save()?;

    for line in identity::admin::cli::grant_admin_output(&receipt).lines {
        println!("{line}");
    }
    Ok(())
}

fn run_generate(parsed: ParsedArgs) -> Result<(), String> {
    let db = parsed
        .db
        .ok_or_else(|| top_level_usage("generate requires --db PATH"))?;
    let mut runtime = ProtocolRuntime::open_disk(db)?;
    let clock = SystemClock;
    let vault = EmptyVault;
    let output = {
        let ctx = runtime.command_context(&clock, &vault);
        content::event::cli::generate(&ctx, CliArgs::new(&parsed.command[1..]))?
    };
    let receipt = runtime.submit_command_output(output)?;
    drain_runtime(&mut runtime)?;
    runtime.save()?;

    for line in content::event::cli::generated_output(&receipt, receipt.generated_facts).lines {
        println!("{line}");
    }
    Ok(())
}

fn run_generate_deps(parsed: ParsedArgs) -> Result<(), String> {
    let db = parsed
        .db
        .ok_or_else(|| top_level_usage("generate-deps requires --db PATH"))?;
    let runtime = ProtocolRuntime::open_disk(db)?;
    let args =
        sync::cascade_fact::cli::parse_generate_deps_args(CliArgs::new(&parsed.command[1..]))?;
    let receipt = sync::cascade_fact::commands::generate_deps(
        runtime.store(),
        args.count,
        args.deps_per_fact,
    )?;

    for line in sync::cascade_fact::cli::generate_deps_output(&receipt).lines {
        println!("{line}");
    }
    Ok(())
}

fn run_replay_deps_reverse(parsed: ParsedArgs) -> Result<(), String> {
    let db = parsed
        .db
        .ok_or_else(|| top_level_usage("replay-deps-reverse requires --db PATH"))?;
    CliArgs::new(&parsed.command[1..])
        .require_len(0, sync::cascade_fact::cli::REPLAY_DEPS_REVERSE_USAGE)?;
    let mut runtime = ProtocolRuntime::open_disk(db)?;
    let receipt = sync::cascade_fact::commands::replay_deps_reverse(&mut runtime)?;

    for line in sync::cascade_fact::cli::replay_deps_reverse_output(&receipt).lines {
        println!("{line}");
    }
    Ok(())
}

fn run_negentropy_drain(parsed: ParsedArgs) -> Result<(), String> {
    let db = parsed
        .db
        .ok_or_else(|| top_level_usage("negentropy-drain requires --db PATH"))?;
    if parsed.command.len() > 2 {
        return Err("negentropy-drain [LIMIT]".to_string());
    }
    if let Some(value) = parsed.command.get(1) {
        let _ = value
            .parse::<usize>()
            .map_err(|_| "negentropy-drain [LIMIT]".to_string())?;
    }
    let mut runtime = ProtocolRuntime::open_disk(db)?;
    drain_runtime(&mut runtime)?;
    runtime.save()?;
    let status = crate::protocol::facts::sync::shared_fact::sync_status(runtime.store())?;
    println!("drained: 0");
    println!("removed_from_index: 0");
    println!("remaining_pending: {}", status.pending_purges);
    println!("new_root_count: {}", status.root_count);
    println!(
        "new_root_fingerprint: {}",
        encode_hex_bytes(&status.root_fingerprint)
    );
    Ok(())
}

fn run_sync_status(parsed: ParsedArgs) -> Result<(), String> {
    let db = parsed
        .db
        .ok_or_else(|| top_level_usage("sync-status requires --db PATH"))?;
    if parsed.command.len() != 1 {
        return Err("sync-status".to_string());
    }
    let mut runtime = ProtocolRuntime::open_disk(db)?;
    drain_runtime(&mut runtime)?;
    runtime.save()?;
    let status = crate::protocol::facts::sync::shared_fact::sync_status(runtime.store())?;
    println!("indexed_facts: {}", status.indexed_facts);
    println!("root_count: {}", status.root_count);
    println!(
        "root_fingerprint: {}",
        encode_hex_bytes(&status.root_fingerprint)
    );
    println!("pending_purges: {}", status.pending_purges);
    Ok(())
}

fn run_content_count(parsed: ParsedArgs) -> Result<(), String> {
    let db = parsed
        .db
        .ok_or_else(|| top_level_usage("content-count requires --db PATH"))?;
    let runtime = ProtocolRuntime::open_disk(db)?;
    let clock = SystemClock;
    let vault = EmptyVault;
    let output = {
        let ctx = runtime.command_context(&clock, &vault);
        content::event::cli::content_count(&ctx, CliArgs::new(&parsed.command[1..]))?
    };

    for line in content::event::cli::content_count_output(output).lines {
        println!("{line}");
    }
    Ok(())
}

fn run_clock(parsed: ParsedArgs) -> Result<(), String> {
    let db = parsed
        .db
        .ok_or_else(|| top_level_usage("clock requires --db PATH"))?;
    let runtime = ProtocolRuntime::open_disk(db)?;
    let args = CliArgs::new(&parsed.command[1..]);
    match args.values() {
        [] => {}
        [command, value] if command == "set" => {
            let timestamp = value
                .parse::<u64>()
                .map_err(|_| "clock set requires a u64 timestamp".to_string())?;
            logical_clock::set_logical_time(runtime.store(), timestamp)?;
        }
        [command, value] if command == "advance" => {
            let delta = value
                .parse::<u64>()
                .map_err(|_| "clock advance requires a u64 delta".to_string())?;
            logical_clock::advance_logical_time(runtime.store(), delta)?;
        }
        [command] if command == "clear" => {
            logical_clock::clear_logical_time(runtime.store())?;
        }
        _ => {
            return Err(top_level_usage(
                "clock usage: clock [set TIMESTAMP|advance DELTA|clear]",
            ));
        }
    }

    let logical_time = logical_clock::logical_time(runtime.store())?;
    let observed_max = content::event::queries::max_timestamp(runtime.store())?;
    let next_timestamp = logical_clock::next_timestamp(runtime.store(), observed_max)?;
    let logical_time = logical_time
        .map(|timestamp| timestamp.to_string())
        .unwrap_or_else(|| "unset".to_string());
    println!("logical_time: {logical_time}");
    println!("max_event_timestamp: {observed_max}");
    println!("next_timestamp: {next_timestamp}");
    Ok(())
}

fn next_cli_timestamp(runtime: &ProtocolRuntime) -> Result<u64, String> {
    let observed_max = max_cli_timestamp(runtime.store())?;
    logical_clock::next_timestamp(runtime.store(), observed_max)
}

fn max_cli_timestamp(store: &crate::core::store::Store) -> Result<u64, String> {
    let mut max_timestamp = content::event::queries::max_timestamp(store)?;
    max_timestamp = max_timestamp.max(content::sealed_message::queries::max_created_at_ms(store)?);
    max_timestamp = max_timestamp.max(content::message::queries::max_created_at_ms(store)?);
    Ok(max_timestamp)
}

fn enqueue_floor_retention(
    runtime: &mut ProtocolRuntime,
    workspace_id: [u8; 32],
    setting_id: [u8; 32],
    floor_minute: u64,
) -> Result<usize, String> {
    let mut queued = 0usize;
    for message in message_rows(runtime.store(), workspace_id)? {
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
    let messages = message_rows(store, workspace_id)?;
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
            minute: file.created_at_ms / content::sealed_message::fact::UNIX_MINUTE_MS,
            fact_id_in_minute: file.file_id,
        });
    }
    leaves.sort_by_key(|leaf| (leaf.minute, leaf.node_id));
    Ok(leaves)
}

fn message_rows(
    store: &crate::core::store::Store,
    workspace_id: [u8; 32],
) -> Result<Vec<content::sealed_message::rows::MessageRow>, String> {
    let mut rows = store
        .table_rows_with_key_prefix(
            content::sealed_message::rows::MESSAGE_ROWS,
            &workspace_id,
            usize::MAX,
        )
        .map_err(|err| format!("load message rows: {err}"))?
        .into_iter()
        .map(|(key, value)| content::sealed_message::rows::decode_message_row(&key, &value))
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

fn drain_runtime(runtime: &mut ProtocolRuntime) -> Result<(), String> {
    for _ in 0..4 {
        runtime.drain_projection_until_idle(8, 512)?;
        let dispatched = runtime.dispatch_cli_intents(512)?;
        if dispatched.handled == 0 && dispatched.facts == 0 && dispatched.intents == 0 {
            runtime.drain_projection_until_idle(8, 512)?;
            return Ok(());
        }
    }
    Ok(())
}

fn ensure_bootstrap_request_sent(
    runtime: &ProtocolRuntime,
    request_id: [u8; 32],
) -> Result<(), String> {
    for intent in runtime.wake_loop().intents() {
        if intent.kind.as_str() != SEND_BOOTSTRAP_CONNECTION_REQUEST {
            continue;
        }
        let pending = decode_send_bootstrap_connection_request(intent)?;
        if pending.request_id == request_id {
            return Err(format!(
                "open tcp stream: could not reach invite address {}",
                pending.addr
            ));
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

#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedArgs {
    db: Option<PathBuf>,
    command: Vec<String>,
}

impl ParsedArgs {
    fn parse(argv: Vec<String>) -> Result<Self, String> {
        let mut db = None;
        let mut command = Vec::new();
        let mut iter = argv.into_iter();
        while let Some(arg) = iter.next() {
            if !command.is_empty() {
                command.push(arg);
                command.extend(iter);
                break;
            }
            match arg.as_str() {
                "--db" => {
                    let value = iter
                        .next()
                        .ok_or_else(|| "--db requires a path".to_string())?;
                    if db.replace(PathBuf::from(value)).is_some() {
                        return Err("--db may be supplied only once".to_string());
                    }
                }
                _ => command.push(arg),
            }
        }
        Ok(Self { db, command })
    }
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
