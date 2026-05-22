use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

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
    assert_eq!(MATCH_PROTOCOL.name, "match");
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
        .any(|handler| handler.name == "receive_transit_frame"));
}

#[test]
fn protocol_context_ranges_are_core_owned_and_domain_encoded() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let scopes = [
        "connection",
        "content",
        "encryption",
        "identity",
        "sync",
        "transport",
    ];
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
            "src/protocol/encryption/local_history_node_secret/project.rs",
            "secret coverage coordinate scheme",
        ),
        (
            "src/protocol/encryption/key_wrap/project.rs",
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
        "receive_transit_frame",
    ] {
        assert!(
            names.contains(required),
            "runtime handler route missing {required}"
        );
    }

    for excluded in [
        "send_facts_on_connection",
        "send_network_frame",
        "receive_transit_frame",
    ] {
        assert!(
            MATCH_RUNTIME.command_excluded_handlers.contains(&excluded),
            "command runtime should exclude network handler {excluded}"
        );
    }
}
