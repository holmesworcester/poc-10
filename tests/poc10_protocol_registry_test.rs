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
    assert!(MATCH_PROTOCOL
        .commands
        .iter()
        .any(|command| command.name == "assert"));
    assert!(MATCH_RUNTIME
        .handlers
        .iter()
        .any(|handler| handler.name == "receive_transit_frame"));
}

#[test]
fn context_matcher_plumbing_is_centralized_by_matching_relation() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let forbidden_fact_module_files = rust_files(&root.join("src/protocol/facts"))
        .into_iter()
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
        "fact modules must emit protocol-defined needs/offers, not own matcher/context/selector files:\n{}",
        forbidden_fact_module_files.join("\n")
    );

    let matcher_files = rust_files(&root.join("src/protocol/matchers"))
        .into_iter()
        .filter_map(|path| {
            path.file_stem()
                .and_then(|name| name.to_str())
                .map(str::to_string)
        })
        .collect::<BTreeSet<_>>();
    let expected = BTreeSet::from([
        "coverage".to_string(),
        "exact".to_string(),
        "wrap_source".to_string(),
    ]);

    assert_eq!(
        matcher_files, expected,
        "protocol matchers should stay organized by generic matching relation"
    );

    assert!(
        root.join("src/protocol/matchers.rs").is_file(),
        "protocol matchers need a root manifest file instead of a mod.rs"
    );
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
