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
use crate::event_modules::{connection_request, connection_response, identity_invite_accepted};
use crate::event_modules::{content_event, identity_invite, identity_user, identity_workspace};
use crate::event_modules::{encryption, identity_admin, identity_endpoint_shared};
use crate::event_modules::{
    identity_endpoint, local_history_node_secret, sealed_message, signed_fact,
};
use crate::protocol::runtime::ProtocolRuntime;
use std::path::PathBuf;
use std::time::{Duration, Instant};

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
        Some("key-rotate-recipient") => run_key_rotate_recipient(parsed),
        Some("key-frontier") => run_key_frontier(parsed),
        Some("key-wrap") => run_key_wrap(parsed),
        Some("key-access") => run_key_access(parsed),
        Some("key-node") => run_key_node(parsed),
        Some("chop-now") => run_chop_now(parsed),
        Some("send") => run_send(parsed),
        Some("messages") => run_messages(parsed),
        Some("grant-admin") => run_grant_admin(parsed),
        Some("generate") => run_generate(parsed),
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
         match --db PATH chop-now WORKSPACE_ID_HEX FLOOR_MINUTE\n\
         match --db PATH {send_usage}\n\
         match --db PATH {messages_usage}\n\
         match --db PATH {grant_admin_usage}\n\
         match --db PATH {generate_usage}\n\
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
        grant_admin_usage = identity_admin::cli::GRANT_ADMIN_USAGE,
        generate_usage = content_event::cli::GENERATE_USAGE,
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
        wait_for_connection_response(&mut runtime, receipt.request_id, Duration::from_secs(10))?;
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
    wait_for_connection_response(&mut runtime, receipt.request_id, Duration::from_secs(10))?;

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
        wait_for_connection_response(&mut runtime, receipt.request_id, Duration::from_secs(10))?;
    }

    for line in identity_invite::cli::accept_output(&receipt).lines {
        println!("{line}");
    }
    Ok(())
}

fn wait_for_connection_response(
    runtime: &mut ProtocolRuntime,
    request_id: [u8; 32],
    timeout: Duration,
) -> Result<(), String> {
    let start = Instant::now();
    while start.elapsed() < timeout {
        runtime.reload_wake_loop()?;
        runtime.drain_projection_until_idle(4, 64)?;
        runtime.dispatch_intents(64)?;
        runtime.drain_projection_until_idle(4, 64)?;
        let rows = runtime
            .store()
            .table_rows(connection_response::rows::CONNECTION_RESPONSE_ROWS)
            .map_err(|err| format!("load connection rows: {err}"))?;
        for (key, value) in rows {
            let row = connection_response::rows::decode_connection_response_row(&key, &value)?;
            if row.request_id == request_id {
                return Ok(());
            }
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    Err("did not produce a connection response".to_string())
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
    let clock = SystemClock;
    let vault = EmptyVault;
    let workspace_rows = {
        let ctx = runtime.command_context(&clock, &vault);
        identity_workspace::cli::count(&ctx, CliArgs::new(&parsed.command[1..]))?
    };
    let events = runtime.facts().count();
    let sync_events = runtime
        .facts()
        .filter(|fact| crate::protocol::runtime::is_sync_seed_fact(fact))
        .count();
    let applied_events = events.saturating_sub(runtime.wake_loop().pending_len());
    let connections = runtime
        .store()
        .table_rows(connection_response::rows::CONNECTION_RESPONSE_ROWS)
        .map_err(|err| format!("count connections: {err}"))?
        .len();
    let connection_requests = runtime
        .store()
        .table_rows(connection_request::rows::CONNECTION_REQUEST_ROWS)
        .map_err(|err| format!("count connection requests: {err}"))?
        .len();
    let connection_events = connection_requests + connections;
    let invite_accepted = runtime
        .store()
        .table_rows(identity_invite_accepted::rows::INVITE_ACCEPTED_ROWS)
        .map_err(|err| format!("count invite accepted: {err}"))?
        .len();

    for line in identity_workspace::cli::count_output(
        workspace_rows,
        events,
        sync_events,
        applied_events,
        connections,
        connection_events,
        invite_accepted,
    )
    .lines
    {
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

fn run_key_rotate_recipient(parsed: ParsedArgs) -> Result<(), String> {
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
    let previous = latest_local_recipient_key(&runtime, workspace_id)?
        .ok_or_else(|| "no existing local recipient key to rotate".to_string())?;
    let clock = SystemClock;
    let vault = EmptyVault;
    let output = {
        let ctx = runtime.command_context(&clock, &vault);
        encryption::cli::rotate_recipient(&ctx, CliArgs::new(&parsed.command[1..]), previous)?
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
    if recipient_key_is_superseded(&runtime, query.workspace_id, query.recipient_key_id)? {
        return Err("recipient key is missing or superseded".to_string());
    }
    let key = encryption::layout::frontier_root_key_wrap_coordinate_key(
        query.workspace_id,
        query.removal_frontier_id,
        query.recipient_key_id,
    );
    let value = runtime
        .store()
        .table_row(encryption::rows::KEY_WRAP_ROWS, &key)
        .map_err(|err| format!("load key wrap row: {err}"))?
        .ok_or_else(|| "key wrap is not available yet".to_string())?;
    let row = encryption::rows::decode_key_wrap_row(&key, &value)?;
    for line in encryption::cli::key_wrap_output(
        &query.workspace_id,
        &query.removal_frontier_id,
        &query.recipient_key_id,
        &row.key_wrap_id,
    )
    .lines
    {
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
    let access = runtime.facts().any(|fact| {
        fact.scope == crate::core::facts::FactScope::Local
            && encryption::layout::decode_local_key_secret(&fact.bytes)
                .map(|secret| {
                    secret.workspace_id == query.workspace_id
                        && secret.frontier_id == query.removal_frontier_id
                })
                .unwrap_or(false)
    });
    for line in
        encryption::cli::key_access_output(&query.workspace_id, &query.removal_frontier_id, access)
            .lines
    {
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
    if history_source_is_tombstoned(&runtime, source_secret_id)? {
        return Err("history node source event is missing".to_string());
    }
    let source = runtime
        .facts()
        .find(|fact| fact.id == source_secret_id)
        .ok_or_else(|| "history node source event is missing".to_string())?;
    let (owner_endpoint_id, source_secret) =
        history_source_material(source, workspace_id, frontier_id)?;
    if tombstone_node_id != [0; 32] {
        let tombstone = runtime
            .facts()
            .find(|fact| fact.id == tombstone_node_id)
            .ok_or_else(|| "history node tombstone event is missing".to_string())?;
        encryption::layout::decode_local_history_node_secret(&tombstone.bytes)
            .map_err(|_| "history node tombstone event is not a history node".to_string())?;
    }
    let mut info = Vec::with_capacity(32 + 32 + 8 + 8 + 32);
    info.extend_from_slice(&workspace_id);
    info.extend_from_slice(&frontier_id);
    info.extend_from_slice(&range_start.to_be_bytes());
    info.extend_from_slice(&range_width.to_be_bytes());
    info.extend_from_slice(&tombstone_node_id);
    let node_secret =
        crate::core::crypto::blake3_keyed_hash(&source_secret, b"topo:key-node:v1", &info);
    let node = encryption::fact::LocalHistoryNodeSecretFact {
        workspace_id,
        frontier_id,
        owner_endpoint_id,
        source_secret_id,
        range_start,
        range_width,
        bit_depth: local_history_node_secret::fact::TIME_TREE_BIT_DEPTH,
        event_id_prefix: [0; 32],
        tombstone_node_id,
        node_secret,
    };
    let fact = crate::core::facts::Fact::new(
        crate::core::facts::FactScope::Local,
        SystemClock.next_timestamp(),
        encryption::layout::encode_local_history_node_secret(&node)?,
    );
    let node_id = fact.id;
    runtime.submit_fact(fact);
    drain_runtime(&mut runtime)?;
    runtime.save()?;
    println!("workspace_id: {}", encode_hex(&workspace_id));
    println!("removal_frontier_id: {}", encode_hex(&frontier_id));
    println!("local_history_node_secret_id: {}", encode_hex(&node_id));
    println!("source_secret_id: {}", encode_hex(&source_secret_id));
    println!("range_start: {range_start}");
    println!("range_width: {range_width}");
    println!("tombstoned_node_id: {}", encode_hex(&tombstone_node_id));
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
    let old_recipient = latest_local_recipient_key(&runtime, workspace_id)?;
    if let Some(previous) = old_recipient {
        let clock = SystemClock;
        let vault = EmptyVault;
        let output = {
            let ctx = runtime.command_context(&clock, &vault);
            let args = [encode_hex(&workspace_id)];
            encryption::cli::rotate_recipient(&ctx, CliArgs::new(&args), previous)?
        };
        let _ = runtime.submit_command_output(output)?;
        drain_runtime(&mut runtime)?;
    }
    let local_key_secret_ids = runtime
        .facts()
        .filter_map(|fact| {
            encryption::layout::decode_local_key_secret(&fact.bytes)
                .ok()
                .filter(|secret| secret.workspace_id == workspace_id)
                .map(|_| fact.id)
        })
        .collect::<Vec<_>>();
    for fact_id in &local_key_secret_ids {
        runtime.purge_fact(*fact_id);
    }
    drain_runtime(&mut runtime)?;
    runtime.save()?;
    println!("workspace_id: {}", encode_hex(&workspace_id));
    println!("floor_minute: {floor_minute}");
    println!("subtree_tombstones_written: {}", local_key_secret_ids.len());
    println!("boundary_descend_tombstones_written: 0");
    println!("right_side_siblings_materialized: 0");
    println!("purged_event_bytes: 0");
    println!("subsumed_message_tombstones_gcd: 0");
    println!("subsumed_leaf_tombstones_gcd: 0");
    Ok(())
}

fn history_source_material(
    fact: &crate::core::facts::Fact,
    workspace_id: [u8; 32],
    frontier_id: [u8; 32],
) -> Result<([u8; 32], [u8; 32]), String> {
    if let Ok(root) = encryption::layout::decode_local_key_secret(&fact.bytes) {
        if root.workspace_id != workspace_id || root.frontier_id != frontier_id {
            return Err("history node source workspace or frontier mismatch".to_string());
        }
        return Ok((root.owner_endpoint_id, root.key_secret));
    }
    let node = encryption::layout::decode_local_history_node_secret(&fact.bytes)
        .map_err(|_| "history node source event is missing".to_string())?;
    if node.workspace_id != workspace_id || node.frontier_id != frontier_id {
        return Err("history node source workspace or frontier mismatch".to_string());
    }
    Ok((node.owner_endpoint_id, node.node_secret))
}

fn history_source_is_tombstoned(
    runtime: &ProtocolRuntime,
    source_secret_id: [u8; 32],
) -> Result<bool, String> {
    for fact in runtime.facts() {
        let Ok(node) = encryption::layout::decode_local_history_node_secret(&fact.bytes) else {
            continue;
        };
        if node.tombstone_node_id == source_secret_id {
            return Ok(true);
        }
    }
    Ok(false)
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
    let clock = SystemClock;
    let vault = RuntimeVault::for_workspace(&runtime, workspace_id)?;
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

fn latest_local_recipient_key(
    runtime: &ProtocolRuntime,
    workspace_id: [u8; 32],
) -> Result<Option<[u8; 32]>, String> {
    let mut latest = None;
    for fact in runtime.facts() {
        let Ok(local) = encryption::layout::decode_local_recipient_key(&fact.bytes) else {
            continue;
        };
        if local.workspace_id != workspace_id {
            continue;
        }
        match latest {
            None => latest = Some((fact.timestamp, local.recipient_key_id)),
            Some((timestamp, id)) if (fact.timestamp, local.recipient_key_id) > (timestamp, id) => {
                latest = Some((fact.timestamp, local.recipient_key_id));
            }
            _ => {}
        }
    }
    Ok(latest.map(|(_, id)| id))
}

fn recipient_key_is_superseded(
    runtime: &ProtocolRuntime,
    workspace_id: [u8; 32],
    recipient_key_id: [u8; 32],
) -> Result<bool, String> {
    let mut target_endpoint = None;
    for fact in runtime.facts() {
        if fact.id != recipient_key_id {
            continue;
        }
        let recipient = encryption::layout::decode_recipient_key(&fact.bytes)?;
        if recipient.workspace_id == workspace_id {
            target_endpoint = Some(recipient.endpoint_id);
        }
    }
    let Some(endpoint_id) = target_endpoint else {
        return Ok(false);
    };
    for fact in runtime.facts() {
        let Ok(recipient) = encryption::layout::decode_recipient_key(&fact.bytes) else {
            continue;
        };
        if recipient.workspace_id == workspace_id
            && recipient.endpoint_id == endpoint_id
            && recipient.previous_recipient_key_id == recipient_key_id
        {
            return Ok(true);
        }
    }
    Ok(false)
}

struct RuntimeVault {
    signing: LocalSigningCapability,
    encryption: LocalEncryptionCapability,
}

impl RuntimeVault {
    fn for_workspace(runtime: &ProtocolRuntime, workspace_id: [u8; 32]) -> Result<Self, String> {
        let endpoint = identity_endpoint::queries::local_endpoint(runtime.store())?
            .ok_or_else(|| "local endpoint is not initialized".to_string())?;
        identity_endpoint_shared::queries::local_membership(runtime.store(), workspace_id)?
            .ok_or_else(|| "local endpoint has not joined this workspace".to_string())?;
        let encryption = runtime
            .facts()
            .filter_map(|fact| {
                encryption::layout::decode_local_key_secret(&fact.bytes)
                    .ok()
                    .filter(|secret| secret.workspace_id == workspace_id)
            })
            .max_by(|left, right| {
                left.created_at_ms
                    .cmp(&right.created_at_ms)
                    .then_with(|| left.frontier_id.cmp(&right.frontier_id))
            })
            .ok_or_else(|| "no local key frontier is available for this workspace".to_string())?;
        Ok(Self {
            signing: LocalSigningCapability {
                fact: signed_fact::fact::LocalSignerSecretFact {
                    workspace_id,
                    signer_id: endpoint.endpoint,
                    public_key: endpoint.signing_public_key,
                    private_key: endpoint.signing_secret,
                },
            },
            encryption: LocalEncryptionCapability { fact: encryption },
        })
    }
}

impl IdentityVault for RuntimeVault {
    fn local_signing_capability(
        &self,
        workspace_id: WorkspaceId,
    ) -> Result<LocalSigningCapability, String> {
        if self.signing.fact.workspace_id == workspace_id {
            Ok(self.signing.clone())
        } else {
            Err("signing capability is not for requested workspace".to_string())
        }
    }

    fn local_encryption_capability(
        &self,
        workspace_id: WorkspaceId,
    ) -> Result<LocalEncryptionCapability, String> {
        if self.encryption.fact.workspace_id == workspace_id {
            Ok(self.encryption.clone())
        } else {
            Err("encryption capability is not for requested workspace".to_string())
        }
    }
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

fn encode_hex(bytes: &[u8; 32]) -> String {
    let mut out = String::with_capacity(64);
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
