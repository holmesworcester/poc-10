use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use topo::core::daemon::{self, RuntimeTurnHost};
use topo::core::effects::StorageRequirement;
use topo::core::runtime::Runtime;
use topo::protocol::app::{MATCH_PROTOCOL, MATCH_RUNTIME};
use topo::protocol::versioning::check_version::CHECK_VERSION;
use topo::protocol::versioning::CURRENT_PROTOCOL_VERSION;

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
        .any(|source| source.ddl.contains("network_outgoing")));

    assert!(MATCH_PROTOCOL
        .commands
        .iter()
        .any(|command| command.name == "send"));
    assert!(!MATCH_PROTOCOL
        .commands
        .iter()
        .any(|command| command.name == "assert"));
    assert!(MATCH_PROTOCOL.daemon.inbound_network_intake.is_some());
}

#[test]
fn fresh_runtime_initializes_protocol_marker_through_runtime_turn() {
    let mut runtime = Runtime::open_memory(&MATCH_RUNTIME).expect("runtime");

    assert_eq!(
        runtime
            .db()
            .current_storage_version()
            .expect("read storage version marker"),
        None
    );

    let mut scheduler = daemon::RecurringScheduler::install(MATCH_RUNTIME.handlers);
    daemon::runtime_turn(
        MATCH_PROTOCOL.daemon,
        &mut runtime,
        RuntimeTurnHost::local(),
        &mut scheduler,
        32,
    )
    .expect("runtime turn");

    assert_eq!(
        runtime
            .db()
            .current_storage_version()
            .expect("read storage version marker after turn"),
        Some(CURRENT_PROTOCOL_VERSION)
    );
}

#[test]
fn model_routes_declare_projector_routes() {
    assert_projector_route(
        topo::protocol::content::message::TYPE_CONTENT_MESSAGE,
        "content::message::project::ContentMessageProjector",
    );
    assert_projector_route(
        topo::protocol::auth::workspace::TYPE_WORKSPACE,
        "auth::workspace::project::WorkspaceProjector",
    );
}

fn assert_projector_route(tag: u8, expected_project: &str) {
    let route = MATCH_RUNTIME
        .fact_routes
        .iter()
        .find(|route| route.tag == tag)
        .expect("model route");

    assert_eq!(route.projector_info.project, expected_project);
}

#[test]
fn projector_and_handler_routes_declare_storage_requirements() {
    for route in MATCH_RUNTIME.fact_routes {
        let expected =
            if route.tag == topo::protocol::versioning::local_update::TYPE_VERSIONING_UPDATE {
                StorageRequirement::MaintenanceBypass
            } else {
                StorageRequirement::Current(CURRENT_PROTOCOL_VERSION)
            };
        assert_eq!(
            route.storage_requirement, expected,
            "fact route {} should declare its storage requirement",
            route.projector_info.project
        );
    }

    for route in MATCH_RUNTIME.handlers {
        let expected = if route.intent_kind == CHECK_VERSION {
            StorageRequirement::MaintenanceBypass
        } else {
            StorageRequirement::Current(CURRENT_PROTOCOL_VERSION)
        };
        assert_eq!(
            route.storage_requirement, expected,
            "handler route {} should declare its storage requirement",
            route.intent_kind
        );
    }
}

#[test]
fn projector_and_handler_owner_modules_declare_storage_requirements() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let protocol = root.join("src/protocol");
    let missing_projectors = rust_files(&protocol)
        .into_iter()
        .filter_map(|path| {
            let text = std::fs::read_to_string(&path).expect("read protocol file");
            (text.contains("pub const PROJECTOR_INFO")
                && !text.contains("pub const STORAGE_REQUIREMENT"))
            .then(|| {
                path.strip_prefix(root)
                    .expect("repo-relative projector path")
                    .display()
                    .to_string()
            })
        })
        .collect::<Vec<_>>();
    assert!(
        missing_projectors.is_empty(),
        "projector modules must declare STORAGE_REQUIREMENT:\n{}",
        missing_projectors.join("\n")
    );

    for handler in [
        "src/protocol/auth/create_key_wrap.rs",
        "src/protocol/auth/unwrap_key_wrap.rs",
        "src/protocol/connection/create_connection.rs",
        "src/protocol/connection/maintain_connections.rs",
        "src/protocol/connection/queue_outgoing_frame.rs",
        "src/protocol/connection/send_facts_on_connection.rs",
        "src/protocol/sync/maintain_sync.rs",
        "src/protocol/sync/seed_connection.rs",
        "src/protocol/sync/send_compare_response.rs",
        "src/protocol/sync/send_needed_fact_id.rs",
        "src/protocol/sync/send_requested_fact.rs",
        "src/protocol/sync/share_fact_with_sync.rs",
        "src/protocol/versioning/check_version.rs",
    ] {
        let text = std::fs::read_to_string(root.join(handler)).expect("read handler module");
        assert!(
            text.contains("pub const STORAGE_REQUIREMENT"),
            "{handler} must declare STORAGE_REQUIREMENT for its handler route"
        );
    }
}

#[test]
fn protocol_write_allowlist_does_not_register_old_version_tables() {
    let offenders = MATCH_RUNTIME
        .row_mutation_tables
        .iter()
        .filter_map(|table| {
            let name = table.as_str();
            [
                "_old",
                "_legacy",
                "_previous",
                "_deprecated",
                "_v0",
                "_v1_old",
            ]
            .iter()
            .any(|marker| name.contains(marker))
            .then_some(name)
        })
        .collect::<Vec<_>>();

    assert!(
        offenders.is_empty(),
        "protocol write allowlist must target current tables only:\n{}",
        offenders.join("\n")
    );
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
fn runtime_handler_routes_are_unique_by_intent_kind() {
    let kinds = MATCH_RUNTIME
        .handlers
        .iter()
        .map(|handler| handler.intent_kind)
        .collect::<BTreeSet<_>>();
    assert_eq!(
        kinds.len(),
        MATCH_RUNTIME.handlers.len(),
        "runtime handler intent kinds must be unique"
    );

    for required in ["queue_outgoing_frame"] {
        assert!(
            kinds.contains(required),
            "runtime handler route missing {required}"
        );
    }
}

#[test]
fn replay_policy_lives_at_handler_edges() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let registry =
        std::fs::read_to_string(root.join("src/protocol/registry.rs")).expect("read registry");
    assert!(
        !registry.contains("runs_during_replay") && !registry.contains("replay ="),
        "handler replay policy belongs in handlers, not HANDLER_ROUTES"
    );

    for handler in [
        "src/protocol/connection/create_connection.rs",
        "src/protocol/connection/maintain_connections.rs",
        "src/protocol/connection/send_facts_on_connection.rs",
        "src/protocol/connection/queue_outgoing_frame.rs",
        "src/protocol/sync/seed_connection.rs",
        "src/protocol/sync/send_compare_response.rs",
        "src/protocol/sync/send_needed_fact_id.rs",
        "src/protocol/sync/send_requested_fact.rs",
    ] {
        let text = std::fs::read_to_string(root.join(handler)).expect("read handler");
        assert!(
            text.contains("context.is_replay()"),
            "{handler} must explicitly no-op live/session work during replay"
        );
    }

    let share_fact =
        std::fs::read_to_string(root.join("src/protocol/sync/share_fact_with_sync.rs"))
            .expect("read share handler");
    assert!(
        share_fact.contains("changed && !context.is_replay()"),
        "share_fact_with_sync should rebuild sync rows during replay but skip live tail advertisements"
    );
}

#[test]
fn live_negotiation_projectors_own_replay_noop_policy() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let registry =
        std::fs::read_to_string(root.join("src/protocol/registry.rs")).expect("read registry");
    assert!(
        !registry.contains("not_replayed") && !registry.contains("replayed:"),
        "fact replay policy belongs in projectors, not route metadata"
    );

    for projector in [
        "src/protocol/connection/request/project.rs",
        "src/protocol/connection/connection/project.rs",
        "src/protocol/sync/have_id/project.rs",
        "src/protocol/sync/need_id/project.rs",
    ] {
        let text = std::fs::read_to_string(root.join(projector)).expect("read projector");
        assert!(
            text.contains("context.is_replay()"),
            "{projector} must explicitly no-op its live session/negotiation projection during replay"
        );
    }

    for truth_tag in [
        topo::protocol::connection::fact_receipt::encode::TYPE_CONNECTION_FACT_RECEIPT,
        topo::protocol::auth::endpoint_shared::encode::TYPE_ENDPOINT_SHARED,
        topo::protocol::content::message::TYPE_CONTENT_MESSAGE,
        topo::protocol::auth::key_wrap::encode::TYPE_KEY_WRAP,
    ] {
        assert!(
            MATCH_RUNTIME
                .fact_routes
                .iter()
                .any(|route| route.tag == truth_tag),
            "durable truth fact tag {truth_tag} must remain routed for replay projection"
        );
    }
}
