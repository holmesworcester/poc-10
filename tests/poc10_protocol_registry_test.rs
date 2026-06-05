use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use topo::core::intents::NetworkAccessPolicy;
use topo::core::pipeline::FactPipeline;
use topo::protocol::app::{MATCH_PROTOCOL, MATCH_RUNTIME};

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
fn model_routes_declare_first_class_pipeline_stages() {
    assert_staged_route(
        topo::protocol::content::message::TYPE_CONTENT_MESSAGE,
        "content::message::decode::Codec",
        "content::message::authenticate::ContentMessageAuthenticator",
        "content::message::adapt::ContentMessageAdapter",
        "content::message::project::ContentMessageProjector",
    );
    assert_staged_route(
        topo::protocol::auth::workspace::TYPE_WORKSPACE,
        "auth::workspace::decode::Codec",
        "auth::workspace::authenticate::WorkspaceAuthenticator",
        "auth::workspace::adapt::WorkspaceAdapter",
        "auth::workspace::project::WorkspaceProjector",
    );
}

fn assert_staged_route(
    tag: u8,
    expected_decode: &str,
    expected_authenticate: &str,
    expected_adapt: &str,
    expected_project: &str,
) {
    let route = MATCH_RUNTIME
        .fact_routes
        .iter()
        .find(|route| route.tag == tag)
        .expect("model route");

    let FactPipeline::Staged {
        decode,
        authenticate,
        adapt,
        project,
    } = route.pipeline
    else {
        panic!("model route {tag} should use the staged pipeline");
    };

    assert_eq!(decode, expected_decode);
    assert_eq!(authenticate, expected_authenticate);
    assert_eq!(adapt, expected_adapt);
    assert_eq!(project, expected_project);
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

    for required in ["send_network_frame", "receive_network_frame"] {
        assert!(
            names.contains(required),
            "runtime handler route missing {required}"
        );
    }

    for excluded in [
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
fn runtime_network_access_is_declared_only_for_the_network_send_route() {
    let network_enabled = MATCH_RUNTIME
        .handlers
        .iter()
        .filter(|route| route.network_access.allows_network())
        .map(|route| route.name)
        .collect::<BTreeSet<_>>();
    let expected: BTreeSet<&str> = ["send_network_frame"].into_iter().collect();

    assert_eq!(
        network_enabled, expected,
        "only the route that lowers connection frames to core network IO may receive network access"
    );

    for route in MATCH_RUNTIME.handlers {
        if route.runs_during_replay {
            assert_eq!(
                route.network_access,
                NetworkAccessPolicy::Denied,
                "replay route {} must never have network access",
                route.name
            );
        }
    }
}

#[test]
fn replay_classification_marks_only_deterministic_rebuild_handlers() {
    // Replay-enabled handlers must be deterministic fact/row rebuild work over
    // retained facts. Exactly the three rebuild handlers may run during replay;
    // everything else (network IO, send packaging, live response/seed work) is
    // rebuilt after the barrier and must stay replay=false. Adding a route that
    // flips this set should fail here, not silently replay live-only work.
    let replayable = MATCH_RUNTIME
        .handlers
        .iter()
        .filter(|route| route.runs_during_replay)
        .map(|route| route.name)
        .collect::<BTreeSet<_>>();
    let expected: BTreeSet<&str> = ["create_key_wrap", "share_fact_with_sync", "unwrap_key_wrap"]
        .into_iter()
        .collect();
    assert_eq!(
        replayable, expected,
        "only deterministic rebuild handlers may run during replay"
    );

    for live_only in [
        "create_connection",
        "send_network_frame",
        "receive_network_frame",
        "send_facts_on_connection",
    ] {
        let route = MATCH_RUNTIME
            .handlers
            .iter()
            .find(|route| route.name == live_only)
            .unwrap_or_else(|| panic!("missing route {live_only}"));
        assert!(
            !route.runs_during_replay,
            "live-only handler {live_only} must not run during replay"
        );
    }

    // A recurring schedule is live-only operational repetition by definition, so
    // a route carrying one must never be dispatched during replay.
    for route in MATCH_RUNTIME.handlers.iter() {
        if route.recurrence.is_some() {
            assert!(
                !route.runs_during_replay,
                "recurring route {} must not run during replay",
                route.name
            );
        }
    }
}

#[test]
fn only_transport_and_negotiation_facts_are_not_replayed() {
    use topo::protocol::{connection, sync};

    // Durable facts whose projection materializes live session/negotiation state
    // must be retained but not re-projected on replay, so a rebuild never
    // resurrects a dead connection or a stale sync negotiation. The handshake
    // request/response facts and sync need/have advertisements are this
    // category. Everything else is durable truth that replay rebuilds
    // deterministically.
    let not_replayed: BTreeSet<u8> = MATCH_RUNTIME
        .fact_routes
        .iter()
        .filter(|route| !route.replayed)
        .map(|route| route.tag)
        .collect();
    let expected: BTreeSet<u8> = [
        connection::request::layout::TYPE_CONNECTION_REQUEST,
        connection::connection::layout::TYPE_CONNECTION,
        sync::have_id::layout::TYPE_SYNC_HAVE_ID,
        sync::need_id::layout::TYPE_SYNC_NEED_ID,
    ]
    .into_iter()
    .collect();
    assert_eq!(
        not_replayed, expected,
        "only connection handshake and sync need/have negotiation facts may be not-replayed"
    );

    // Truth facts — including the connection fact receipt that carries the
    // durable learned address — must stay replayed.
    let replayed: BTreeSet<u8> = MATCH_RUNTIME
        .fact_routes
        .iter()
        .filter(|route| route.replayed)
        .map(|route| route.tag)
        .collect();
    for truth_tag in [
        connection::fact_receipt::layout::TYPE_CONNECTION_FACT_RECEIPT,
        topo::protocol::auth::endpoint_shared::layout::TYPE_ENDPOINT_SHARED,
        topo::protocol::content::message::TYPE_CONTENT_MESSAGE,
        topo::protocol::auth::key_wrap::layout::TYPE_KEY_WRAP,
    ] {
        assert!(
            replayed.contains(&truth_tag),
            "durable truth fact tag {truth_tag} must be replayed"
        );
    }
}
