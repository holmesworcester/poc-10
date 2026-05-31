use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use topo::protocol::app::{MATCH_PROTOCOL, MATCH_RUNTIME, REPLAYABLE_DAEMON_TIME_WAKES};

fn rust_files(root: &Path) -> Vec<PathBuf> {
    let mut pending = vec![root.to_path_buf()];
    let mut files = Vec::new();
    while let Some(dir) = pending.pop() {
        for entry in std::fs::read_dir(&dir).expect("read dir") {
            let path = entry.expect("dir entry").path();
            if path.is_dir() {
                pending.push(path);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                files.push(path);
            }
        }
    }
    files
}

#[test]
fn executable_protocol_tables_name_the_target_surfaces() {
    assert_eq!(MATCH_PROTOCOL.display_name, "Context");
    assert_eq!(MATCH_PROTOCOL.command_name, "con");
    assert_eq!(MATCH_RUNTIME.schema_sources.len(), 2);
    assert!(MATCH_RUNTIME
        .schema_sources
        .iter()
        .any(|source| source.ddl.contains("network_out")));

    assert!(MATCH_PROTOCOL
        .commands
        .iter()
        .any(|command| command.name == "send"));
    assert!(!MATCH_PROTOCOL
        .commands
        .iter()
        .any(|command| command.name == "assert"));
    assert!(MATCH_RUNTIME
        .handlers
        .iter()
        .any(|handler| handler.name == "receive_network_frame"));
}

#[test]
fn protocol_context_ranges_are_core_owned_and_domain_encoded() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let scopes = ["auth", "connection", "content", "sync"];
    let forbidden_fact_module_files = scopes
        .iter()
        .flat_map(|scope| rust_files(&root.join("src/protocol").join(scope)))
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| matches!(name, "matchers.rs" | "context.rs" | "selectors.rs"))
        })
        .map(|path| {
            path.strip_prefix(root)
                .expect("repo-relative path")
                .display()
                .to_string()
        })
        .collect::<Vec<_>>();

    assert!(
        forbidden_fact_module_files.is_empty(),
        "fact modules must emit core context ranges directly or call domain-owned range encoders, not own context/selector/matcher source-of-truth files:\n{}",
        forbidden_fact_module_files.join("\n")
    );

    assert!(
        !root.join("src/protocol/context_keys.rs").exists(),
        "central protocol context-key manifests recreate a role registry; use core ranges and domain-owned encoders"
    );
    assert!(
        !root.join("src/protocol/context_keys").exists(),
        "central protocol context-key directories recreate a matcher namespace; use core ranges and domain-owned encoders"
    );

    // Nontrivial protocol range encoders live with the domain that validates
    // them: secret-coverage ranges in the local-history-node-secret family and
    // wrap-source ranges in the key-wrap family, both inside their `project.rs`.
    for (required, marker) in [
        (
            "src/protocol/auth/local_history_node_secret/project.rs",
            "secret coverage coordinate scheme",
        ),
        (
            "src/protocol/auth/key_wrap/project.rs",
            "wrap-source coordinate scheme",
        ),
    ] {
        let path = root.join(required);
        assert!(
            path.is_file(),
            "domain-owned protocol range encoder is missing: {required}"
        );
        let text = std::fs::read_to_string(&path).expect("read range encoder module");
        assert!(
            text.to_lowercase().contains(marker),
            "range encoder module {required} should document its {marker}"
        );
    }
}

#[test]
fn sync_advertisement_fact_families_stay_retired() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let registry = std::fs::read_to_string(root.join("src/protocol/registry.rs"))
        .expect("read protocol registry");
    let sync_manifest =
        std::fs::read_to_string(root.join("src/protocol/sync.rs")).expect("read sync manifest");

    for family in ["encrypted_root", "key_wrap_available"] {
        let module_path = root.join("src/protocol/sync").join(family);
        let manifest_path = root.join("src/protocol/sync").join(format!("{family}.rs"));
        assert!(
            !module_path.exists() && !manifest_path.exists(),
            "retired sync advertisement family still exists: {family}"
        );
        assert!(
            !registry.contains(&format!("sync::{family}::")),
            "retired sync advertisement family is still registered: {family}"
        );
        assert!(
            !sync_manifest.contains(&format!("pub mod {family};")),
            "retired sync advertisement family is still exposed: {family}"
        );
    }
}

#[test]
fn runtime_handler_routes_are_unique_and_command_excluded_handlers_are_explicit() {
    let names = MATCH_RUNTIME
        .handlers
        .iter()
        .map(|handler| handler.name)
        .collect::<BTreeSet<_>>();
    assert_eq!(
        names.len(),
        MATCH_RUNTIME.handlers.len(),
        "runtime handler route names must be unique"
    );

    for required in [
        "send_bootstrap_connection_request",
        "send_network_frame",
        "receive_network_frame",
    ] {
        assert!(
            names.contains(required),
            "runtime handler route missing {required}"
        );
    }

    for excluded in [
        "send_bootstrap_connection_request",
        "send_facts_on_connection",
        "send_network_frame",
        "receive_network_frame",
    ] {
        assert!(
            MATCH_RUNTIME.command_excluded_handlers.contains(&excluded),
            "command runtime should exclude network handler {excluded}"
        );
    }
}

#[test]
fn replayable_time_wakes_exclude_wall_clock_connection_retry() {
    // Replay admits wall-clock context only through replayable semantic
    // timelines whose high-water mark derives from retained state. The
    // disappearing-message expiry timeline qualifies; the operational
    // connection peer-retry timeline does not, so it must never be a replayable
    // wake even though it remains a live daemon wake.
    let replayable: Vec<String> = REPLAYABLE_DAEMON_TIME_WAKES
        .iter()
        .map(|wake| (wake.timeline)().as_str().to_string())
        .collect();

    assert!(
        replayable
            .iter()
            .any(|name| name == "content_message_expiry"),
        "disappearing-message expiry is replayable protocol state: {replayable:?}"
    );
    assert!(
        !replayable
            .iter()
            .any(|name| name == "connection_peer_retry"),
        "replay must not admit the wall-clock connection_peer_retry timeline: {replayable:?}"
    );
}

#[test]
fn every_handler_route_declares_its_replay_decision_consistently() {
    // The `runs_during_replay` flag is a required struct field, so omitting it
    // does not compile. This test pins the poc-10 policy classification and the
    // invariants that tie the flag to command exclusion and recurrence.
    let replay_decision = |name: &str| {
        MATCH_RUNTIME
            .handlers
            .iter()
            .find(|handler| handler.name == name)
            .map(|handler| handler.runs_during_replay)
    };

    // Deterministic rebuild work over retained facts runs during replay.
    for replay_route in ["share_fact_with_sync", "create_key_wrap", "unwrap_key_wrap"] {
        assert_eq!(
            replay_decision(replay_route),
            Some(true),
            "{replay_route} rebuilds deterministic state and must run during replay"
        );
    }

    // Live session prompts, send packaging, response work, and network IO do not.
    for live_route in [
        "send_bootstrap_connection_request",
        "create_connection_response",
        "send_sync_compare_response",
        "send_needed_fact_id",
        "send_requested_fact",
        "seed_connection_sync",
        "send_facts_on_connection",
        "send_network_frame",
        "receive_network_frame",
    ] {
        assert_eq!(
            replay_decision(live_route),
            Some(false),
            "{live_route} is live-only work and must not run during replay"
        );
    }

    // A network-capable (command-excluded) route must never run during replay,
    // and a recurring (live-only) route must never run during replay.
    for handler in MATCH_RUNTIME.handlers {
        if MATCH_RUNTIME
            .command_excluded_handlers
            .contains(&handler.name)
        {
            assert!(
                !handler.runs_during_replay,
                "command-excluded network handler {} must not run during replay",
                handler.name
            );
        }
        if handler.recurrence.is_some() {
            assert!(
                !handler.runs_during_replay,
                "recurring live-only handler {} must not run during replay",
                handler.name
            );
        }
    }
}
