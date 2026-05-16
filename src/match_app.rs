//! Product-facing `match` binary entrypoint.
//!
//! `main.rs` stays intentionally tiny: it collects argv and delegates here.
//! This module chooses the current Topo protocol implementation behind the
//! product-facing `match` binary name. It should not grow protocol logic,
//! projection code, handler dispatch, or fact construction.

use crate::core::cli::CliArgs;
use crate::core::command_context::{
    CommandClock, IdentityVault, LocalEncryptionCapability, LocalSigningCapability, WorkspaceId,
};
use crate::core::daemon;
use crate::core::logical_clock;
use crate::protocol::fact_modules::cascade_event;
use crate::protocol::fact_modules::connection_response;
use crate::protocol::fact_modules::sealed_message;
use crate::protocol::fact_modules::{
    content_event, disappearing_messages_setting, identity_invite, identity_user,
    identity_workspace,
};
use crate::protocol::fact_modules::{encryption, identity_admin, identity_endpoint_shared};
use crate::protocol::intent_handlers::retention_floor;
use crate::protocol::runtime::ProtocolRuntime;
use std::path::PathBuf;
use std::time::Duration;

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
        Some("key-node") => run_key_node(parsed),
        Some("keys") => run_keys(parsed),
        Some("chop-now") => run_chop_now(parsed),
        Some("disappearing-set") => run_disappearing_set(parsed),
        Some("disappearing-status") => run_disappearing_status(parsed),
        Some("disappearing-tighten") => run_disappearing_tighten(parsed),
        Some("disappearing-compact") => run_disappearing_compact(parsed),
        Some("send") => run_send(parsed),
        Some("messages") => run_messages(parsed),
        Some("view") => run_view(parsed),
        Some("grant-admin") => run_grant_admin(parsed),
        Some("generate") => run_generate(parsed),
        Some("generate-deps") => run_generate_deps(parsed),
        Some("replay-deps-reverse") => run_replay_deps_reverse(parsed),
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
         match --db PATH key-node WORKSPACE_ID_HEX REMOVAL_FRONTIER_ID_HEX SOURCE_SECRET_ID_HEX RANGE_START RANGE_WIDTH [TOMBSTONE_NODE_ID_HEX]\n\
         match --db PATH keys WORKSPACE_ID_HEX\n\
         match --db PATH chop-now WORKSPACE_ID_HEX FLOOR_MINUTE\n\
         match --db PATH disappearing-set WORKSPACE_ID_HEX TTL_MINUTES [--floor MINUTE]\n\
         match --db PATH disappearing-status WORKSPACE_ID_HEX\n\
         match --db PATH disappearing-tighten WORKSPACE_ID_HEX TTL_MINUTES [--yes|-y]\n\
         match --db PATH disappearing-compact WORKSPACE_ID_HEX\n\
         match --db PATH {send_usage}\n\
         match --db PATH {messages_usage}\n\
         match --db PATH {view_usage}\n\
         match --db PATH {grant_admin_usage}\n\
         match --db PATH {generate_usage}\n\
         match --db PATH {generate_deps_usage}\n\
         match --db PATH {replay_deps_reverse_usage}\n\
         match --db PATH negentropy-drain [LIMIT]\n\
         match --db PATH {content_count_usage}\n\
         match --db PATH clock [set TIMESTAMP|advance DELTA|clear]\n\
         match --db PATH {count_usage}\n\
         match --db PATH start --listen IP PORT [--tick-ms N] [--quiet-ms N]\n\
         match --db PATH stop\n\
         match --db PATH reset\n\n\
        available commands run through the target core runtime facade",
        create_workspace_usage = identity_workspace::cli::CREATE_WORKSPACE_USAGE,
        invite_usage = identity_invite::cli::INVITE_USAGE,
        invite_server_usage = identity_invite::cli::INVITE_SERVER_USAGE,
        accept_usage = identity_invite::cli::ACCEPT_USAGE,
        accept_invite_server_usage = identity_invite::cli::ACCEPT_INVITE_SERVER_USAGE,
        link_usage = identity_invite::cli::LINK_USAGE,
        accept_link_usage = identity_invite::cli::ACCEPT_LINK_USAGE,
        identity_usage = identity_endpoint_shared::cli::IDENTITY_USAGE,
        peers_usage = identity_endpoint_shared::cli::PEERS_USAGE,
        workspaces_usage = identity_workspace::cli::WORKSPACES_USAGE,
        users_usage = identity_user::cli::USERS_USAGE,
        key_recipient_usage = encryption::cli::KEY_RECIPIENT_USAGE,
        key_rotate_recipient_usage = encryption::cli::KEY_ROTATE_RECIPIENT_USAGE,
        key_frontier_usage = encryption::cli::KEY_FRONTIER_USAGE,
        key_wrap_usage = encryption::cli::KEY_WRAP_USAGE,
        key_access_usage = encryption::cli::KEY_ACCESS_USAGE,
        send_usage = sealed_message::cli::SEND_USAGE,
        messages_usage = sealed_message::cli::MESSAGES_USAGE,
        view_usage = sealed_message::cli::VIEW_USAGE,
        grant_admin_usage = identity_admin::cli::GRANT_ADMIN_USAGE,
        generate_usage = content_event::cli::GENERATE_USAGE,
        generate_deps_usage = cascade_event::cli::GENERATE_DEPS_USAGE,
        replay_deps_reverse_usage = cascade_event::cli::REPLAY_DEPS_REVERSE_USAGE,
        content_count_usage = content_event::cli::CONTENT_COUNT_USAGE,
        count_usage = identity_workspace::cli::COUNT_USAGE
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
        identity_endpoint_shared::cli::identity(&ctx, CliArgs::new(&parsed.command[1..]))?
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
        identity_endpoint_shared::cli::peers(&ctx, CliArgs::new(&parsed.command[1..]))?
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
        identity_invite::cli::invite(&ctx, CliArgs::new(&parsed.command[1..]))?
    };
    let receipt = runtime.submit_command_output(output)?;
    runtime.drain_projection_until_idle(8, 64)?;
    runtime.save()?;

    for line in identity_invite::cli::invite_output(&receipt).lines {
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
        identity_invite::cli::invite_server(&ctx, CliArgs::new(&parsed.command[1..]))?
    };
    let receipt = runtime.submit_command_output(output)?;
    drain_runtime(&mut runtime)?;
    runtime.save()?;

    for line in identity_invite::cli::invite_output(&receipt).lines {
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
        identity_invite::cli::accept(&ctx, CliArgs::new(&parsed.command[1..]), from_listen_addr)?
    };
    let receipt = runtime.submit_command_output(output)?;
    runtime.dispatch_intents(64)?;
    runtime.drain_projection_until_idle(8, 64)?;
    runtime.save()?;
    if from_listen_addr.is_some() {
        connection_response::commands::wait_for_request_response(
            &mut runtime,
            receipt.request_id,
            Duration::from_secs(10),
        )?;
    }

    for line in identity_invite::cli::accept_output(&receipt).lines {
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
        identity_invite::cli::accept_invite_server(
            &ctx,
            CliArgs::new(&parsed.command[1..]),
            from_listen_addr,
        )?
    };
    let receipt = runtime.submit_command_output(output)?;
    runtime.dispatch_intents(64)?;
    runtime.drain_projection_until_idle(8, 64)?;
    runtime.save()?;
    connection_response::commands::wait_for_request_response(
        &mut runtime,
        receipt.request_id,
        Duration::from_secs(10),
    )?;

    for line in identity_invite::cli::accept_output(&receipt).lines {
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
        identity_invite::cli::link(&ctx, CliArgs::new(&parsed.command[1..]))?
    };
    let receipt = runtime.submit_command_output(output)?;
    runtime.drain_projection_until_idle(8, 64)?;
    runtime.save()?;

    for line in identity_invite::cli::invite_output(&receipt).lines {
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
        identity_invite::cli::accept_link(
            &ctx,
            CliArgs::new(&parsed.command[1..]),
            from_listen_addr,
        )?
    };
    let receipt = runtime.submit_command_output(output)?;
    runtime.dispatch_intents(64)?;
    runtime.drain_projection_until_idle(8, 64)?;
    runtime.save()?;
    if from_listen_addr.is_some() {
        connection_response::commands::wait_for_request_response(
            &mut runtime,
            receipt.request_id,
            Duration::from_secs(10),
        )?;
    }

    for line in identity_invite::cli::accept_output(&receipt).lines {
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
        identity_workspace::cli::create_workspace(&ctx, CliArgs::new(&parsed.command[1..]))?
    };
    let receipt = runtime.submit_command_output(output)?;
    runtime.drain_projection_until_idle(8, 64)?;
    let workspace =
        identity_workspace::queries::workspace_by_id(runtime.store(), receipt.workspace_fact_id)?;
    let bootstrap_user_id =
        identity_user::queries::users_in_workspace(runtime.store(), receipt.workspace_fact_id)?
            .first()
            .map(|user| user.user_id);
    runtime.save()?;

    for line in
        identity_workspace::cli::created_workspace_output(&workspace, bootstrap_user_id).lines
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
        identity_workspace::cli::workspaces(&ctx, CliArgs::new(&parsed.command[1..]))?
    };

    for line in identity_workspace::cli::workspaces_output(&output).lines {
        println!("{line}");
    }
    Ok(())
}

fn run_count(parsed: ParsedArgs) -> Result<(), String> {
    let db = parsed
        .db
        .ok_or_else(|| top_level_usage("count requires --db PATH"))?;
    let runtime = ProtocolRuntime::open_disk(db)?;
    CliArgs::new(&parsed.command[1..]).require_len(0, identity_workspace::cli::COUNT_USAGE)?;
    let report = identity_workspace::runtime_counts::runtime_count_report(&runtime)?;
    for line in identity_workspace::cli::count_report_output(&report).lines {
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
        identity_user::cli::users(&ctx, CliArgs::new(&parsed.command[1..]))?
    };

    for line in identity_user::cli::users_output(&output).lines {
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
    runtime.drain_projection_until_idle(8, 64)?;
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

    let sealed_messages = sealed_message_rows(store, workspace_id)?;
    let local_history_rows = store
        .table_rows_with_key_prefix(
            crate::protocol::fact_modules::local_history_node_secret::rows::LOCAL_HISTORY_NODE_SECRET_ROWS,
            &workspace_id,
            usize::MAX,
        )
        .map_err(|err| format!("load local history rows: {err}"))?;
    let message_tombstones = store
        .table_rows_with_key_prefix(
            sealed_message::rows::MESSAGE_TOMBSTONE_ROWS,
            &workspace_id,
            usize::MAX,
        )
        .map_err(|err| format!("load message tombstones: {err}"))?;
    let local_key_secrets = runtime
        .facts()
        .filter_map(|fact| encryption::layout::decode_local_key_secret(&fact.bytes).ok())
        .filter(|secret| secret.workspace_id == workspace_id)
        .collect::<Vec<_>>();
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
    let key_wraps = store
        .table_rows(encryption::rows::KEY_WRAP_ROWS)
        .map_err(|err| format!("load key wraps: {err}"))?
        .into_iter()
        .filter_map(|(key, value)| encryption::rows::decode_key_wrap_row(&key, &value).ok())
        .filter(|row| row.wrap.workspace_id == workspace_id)
        .count();

    println!("recipient_keys: {recipient_keys}");
    println!("recipient_key_tombstones: 0");
    println!("local_recipient_keys: {local_recipient_keys}");
    println!("removal_frontiers: {}", removal_frontiers.len());
    println!("key_wraps: {key_wraps}");
    println!("local_key_secrets: {}", local_key_secrets.len());
    println!("local_history_node_secrets: {}", local_history_rows.len());
    println!("local_history_minute_nodes: 0");
    println!("local_history_leaves: {}", sealed_messages.len());
    println!("local_history_trie_internals: 0");
    println!("local_history_time_internals: 0");
    println!("local_history_node_tombstones: 0");
    println!("message_tombstones: {}", message_tombstones.len());
    println!("cover_summary: {}", cover_summary(&sealed_messages));
    for (frontier_id, _) in removal_frontiers {
        let access = local_key_secrets
            .iter()
            .any(|secret| secret.frontier_id == frontier_id);
        println!(
            "frontier: {} access={}",
            encode_hex_32(&frontier_id),
            if access { "yes" } else { "no" }
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
    let output = disappearing_messages_setting::commands::author_set_with_auto_floor(
        runtime.store(),
        disappearing_messages_setting::commands::AuthorSetting {
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
        "setting_event_id: {}",
        encode_hex_32(&receipt.setting_event_id)
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
    let active = disappearing_messages_setting::queries::active_for_workspace(store, workspace_id)?;
    let setting_event_id = active
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
    let live_messages = sealed_message_rows(store, workspace_id)?.len();
    let message_tombstones = store
        .table_rows_with_key_prefix(
            sealed_message::rows::MESSAGE_TOMBSTONE_ROWS,
            &workspace_id,
            usize::MAX,
        )
        .map_err(|err| format!("load message tombstones: {err}"))?
        .len();

    println!("workspace: {}", encode_hex_32(&workspace_id));
    println!("setting_event_id: {setting_event_id}");
    println!("current_ttl_minutes: {ttl}");
    println!("current_floor_minute: {setting_floor}");
    println!("last_chopped_floor: none");
    println!("now_minute: {now_minute_str}");
    println!("horizon_floor: {horizon_floor}");
    println!("effective_floor: {effective_floor}");
    println!("live_messages: {live_messages}");
    println!("message_tombstones: {message_tombstones}");
    println!("leaf_tombstones: 0");
    println!("pending_purges: 0");
    Ok(())
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
    let input = disappearing_messages_setting::commands::AuthorTighten {
        workspace_id: args.workspace_id,
        now_ms,
        ttl_minutes: args.ttl_minutes,
    };
    let plan = disappearing_messages_setting::commands::plan_tighten(runtime.store(), input)?;
    let output = disappearing_messages_setting::commands::author_tighten(runtime.store(), input)?;
    let receipt = runtime.submit_command_output(output)?;
    drain_runtime(&mut runtime)?;
    enqueue_floor_retention(
        &mut runtime,
        args.workspace_id,
        receipt.setting_event_id,
        receipt.target_floor_minute,
    )?;
    drain_runtime(&mut runtime)?;
    runtime.save()?;

    println!(
        "setting_event_id: {}",
        encode_hex_32(&receipt.setting_event_id)
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
    let output = disappearing_messages_setting::commands::author_compact(
        runtime.store(),
        disappearing_messages_setting::commands::AuthorCompact {
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
        "setting_event_id: {}",
        encode_hex_32(&receipt.setting_event_id)
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
        .ok_or_else(|| sealed_message::cli::SEND_USAGE.to_string())
        .and_then(|value| decode_hex_32(value, "workspace id"))?;
    let text = parsed
        .command
        .get(2)
        .ok_or_else(|| sealed_message::cli::SEND_USAGE.to_string())?
        .clone();
    let clock = FixedClock(next_cli_timestamp(&runtime)?);
    let vault =
        sealed_message::authoring::SealedMessageVault::for_workspace(&runtime, workspace_id)?;
    let output = {
        let ctx = runtime.command_context(&clock, &vault);
        sealed_message::cli::send(&ctx, CliArgs::new(&parsed.command[1..]))?
    };
    let receipt = runtime.submit_command_output(output)?;
    drain_runtime(&mut runtime)?;
    runtime.save()?;
    for line in sealed_message::cli::send_output(&receipt, &text).lines {
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
        sealed_message::cli::messages(&ctx, CliArgs::new(&parsed.command[1..]))?
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
        sealed_message::cli::view(&ctx, CliArgs::new(&parsed.command[1..]))?
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
        identity_admin::cli::grant_admin(&ctx, CliArgs::new(&parsed.command[1..]))?
    };
    let receipt = runtime.submit_command_output(output)?;
    runtime.drain_projection_until_idle(8, 64)?;
    runtime.save()?;

    for line in identity_admin::cli::grant_admin_output(&receipt).lines {
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
        content_event::cli::generate(&ctx, CliArgs::new(&parsed.command[1..]))?
    };
    let receipt = runtime.submit_command_output(output)?;
    let _report = runtime.drain_projection_until_idle(8, 1024)?;
    runtime.save()?;

    for line in content_event::cli::generated_output(&receipt, receipt.generated_events).lines {
        println!("{line}");
    }
    Ok(())
}

fn run_generate_deps(parsed: ParsedArgs) -> Result<(), String> {
    let db = parsed
        .db
        .ok_or_else(|| top_level_usage("generate-deps requires --db PATH"))?;
    let runtime = ProtocolRuntime::open_disk(db)?;
    let args = cascade_event::cli::parse_generate_deps_args(CliArgs::new(&parsed.command[1..]))?;
    let receipt =
        cascade_event::commands::generate_deps(runtime.store(), args.count, args.deps_per_event)?;

    for line in cascade_event::cli::generate_deps_output(&receipt).lines {
        println!("{line}");
    }
    Ok(())
}

fn run_replay_deps_reverse(parsed: ParsedArgs) -> Result<(), String> {
    let db = parsed
        .db
        .ok_or_else(|| top_level_usage("replay-deps-reverse requires --db PATH"))?;
    CliArgs::new(&parsed.command[1..])
        .require_len(0, cascade_event::cli::REPLAY_DEPS_REVERSE_USAGE)?;
    let mut runtime = ProtocolRuntime::open_disk(db)?;
    let receipt = cascade_event::commands::replay_deps_reverse(&mut runtime)?;

    for line in cascade_event::cli::replay_deps_reverse_output(&receipt).lines {
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
    let (count, fingerprint) = root_summary(&runtime);
    println!("drained: 0");
    println!("removed_from_index: 0");
    println!("remaining_pending: 0");
    println!("new_root_count: {count}");
    println!("new_root_fingerprint: {}", encode_hex_bytes(&fingerprint));
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
        content_event::cli::content_count(&ctx, CliArgs::new(&parsed.command[1..]))?
    };

    for line in content_event::cli::content_count_output(output).lines {
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
    let observed_max = content_event::queries::max_timestamp(runtime.store())?;
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
    let mut max_timestamp = content_event::queries::max_timestamp(store)?;
    for (key, value) in store
        .table_rows(sealed_message::rows::SEALED_MESSAGE_ROWS)
        .map_err(|err| format!("load sealed messages for clock: {err}"))?
    {
        let row = sealed_message::rows::decode_sealed_message_row(&key, &value);
        if let Ok(row) = row {
            max_timestamp = max_timestamp.max(row.created_at_ms);
        }
    }
    Ok(max_timestamp)
}

fn enqueue_floor_retention(
    runtime: &mut ProtocolRuntime,
    workspace_id: [u8; 32],
    setting_id: [u8; 32],
    floor_minute: u64,
) -> Result<usize, String> {
    let mut queued = 0usize;
    for message in sealed_message_rows(runtime.store(), workspace_id)? {
        if message.minute >= floor_minute {
            continue;
        }
        if runtime.submit_intent(retention_floor::apply_retention_floor_intent(
            retention_floor::ApplyRetentionFloor {
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

fn sealed_message_rows(
    store: &crate::core::store::Store,
    workspace_id: [u8; 32],
) -> Result<Vec<sealed_message::rows::SealedMessageRow>, String> {
    store
        .table_rows_with_key_prefix(
            sealed_message::rows::SEALED_MESSAGE_ROWS,
            &workspace_id,
            usize::MAX,
        )
        .map_err(|err| format!("load sealed message rows: {err}"))?
        .into_iter()
        .map(|(key, value)| sealed_message::rows::decode_sealed_message_row(&key, &value))
        .collect()
}

fn root_summary(runtime: &ProtocolRuntime) -> (u64, [u8; 32]) {
    let mut facts = runtime
        .facts()
        .filter(|fact| fact.scope != crate::core::facts::FactScope::Local)
        .filter(|fact| !is_sync_control_fact(fact.bytes.first().copied()))
        .collect::<Vec<_>>();
    facts.sort_by_key(|fact| (fact.timestamp, fact.id));
    let mut fingerprint = [0u8; 32];
    for fact in &facts {
        let mut hash = blake3::Hasher::new();
        hash.update(b"topo:sync-range-summary:v1:");
        hash.update(&fact.timestamp.to_be_bytes());
        hash.update(&fact.id);
        let digest = hash.finalize();
        for (dst, src) in fingerprint.iter_mut().zip(digest.as_bytes()) {
            *dst ^= *src;
        }
    }
    (facts.len() as u64, fingerprint)
}

fn is_sync_control_fact(tag: Option<u8>) -> bool {
    matches!(
        tag,
        Some(crate::protocol::fact_modules::sync_compare::layout::TYPE_SYNC_COMPARE)
            | Some(crate::protocol::fact_modules::sync_have_id::layout::TYPE_SYNC_HAVE_ID)
            | Some(crate::protocol::fact_modules::sync_need_id::layout::TYPE_SYNC_NEED_ID)
            | Some(crate::protocol::fact_modules::sync_range_request::layout::TYPE_SYNC_RANGE_REQUEST)
            | Some(crate::protocol::fact_modules::sync_shared_event::layout::TYPE_SHARED_EVENT)
            | Some(crate::protocol::fact_modules::sync_encrypted_root::layout::TYPE_ENCRYPTED_ROOT)
            | Some(crate::protocol::fact_modules::sync_key_wrap_available::layout::TYPE_KEY_WRAP_AVAILABLE)
    )
}

fn cover_summary(messages: &[sealed_message::rows::SealedMessageRow]) -> String {
    let mut hash = blake3::Hasher::new();
    for message in messages {
        hash.update(&message.message_id);
        hash.update(&message.minute.to_be_bytes());
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
        let dispatched = runtime.dispatch_intents(512)?;
        if dispatched.handled == 0 && dispatched.facts == 0 && dispatched.intents == 0 {
            runtime.drain_projection_until_idle(8, 512)?;
            return Ok(());
        }
    }
    Ok(())
}

fn decode_hex_32(value: &str, label: &str) -> Result<[u8; 32], String> {
    if value.len() != 64 {
        return Err(format!("{label} must be 64 hex characters"));
    }
    let mut out = [0u8; 32];
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

fn encode_hex_32(bytes: &[u8; 32]) -> String {
    encode_hex_bytes(bytes)
}

fn encode_hex_bytes(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write;
        let _ = write!(out, "{byte:02x}");
    }
    out
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
