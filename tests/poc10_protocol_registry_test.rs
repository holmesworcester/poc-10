use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use topo::protocol::{IntentExecutionKind, PROTOCOL};

fn source_text(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()))
}

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

fn role_names_declared_in(text: &str) -> Vec<String> {
    let mut roles = Vec::new();
    let mut rest = text;
    while let Some(start) = rest.find("Role::new(\"") {
        let after_start = &rest[start + "Role::new(\"".len()..];
        let Some(end) = after_start.find('"') else {
            break;
        };
        roles.push(after_start[..end].to_string());
        rest = &after_start[end + 1..];
    }
    let mut rest = text;
    while let Some(start) = rest.find("_ROLE: &str = \"") {
        let after_start = &rest[start + "_ROLE: &str = \"".len()..];
        let Some(end) = after_start.find('"') else {
            break;
        };
        roles.push(after_start[..end].to_string());
        rest = &after_start[end + 1..];
    }
    roles
}

fn production_text_before_unit_tests(text: &str) -> &str {
    text.find("#[cfg(test)]")
        .map(|index| &text[..index])
        .unwrap_or(text)
}

#[test]
fn protocol_registry_names_the_target_surfaces() {
    assert_eq!(PROTOCOL.name, "match");
    assert_eq!(PROTOCOL.schemas.len(), 3);

    assert!(PROTOCOL
        .facts
        .iter()
        .any(|fact| fact.module == "encryption" && fact.name == "key_wrap"));
    assert!(PROTOCOL
        .facts
        .iter()
        .any(|fact| fact.module == "content::sealed_message" && fact.name == "sealed_message"));
    assert!(PROTOCOL
        .context_matchers
        .iter()
        .any(|matcher| matcher.role == "secret_coverage"));
    assert!(PROTOCOL
        .handlers
        .iter()
        .any(|handler| handler.module == "transport::receive_transit_frame"));
}

#[test]
fn target_context_roles_are_registered() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let declared_roles = rust_files(&root.join("src/protocol/matchers"))
        .into_iter()
        .flat_map(|path| {
            let text = source_text(&path);
            role_names_declared_in(production_text_before_unit_tests(&text))
        })
        .collect::<BTreeSet<_>>();
    let registered_roles = PROTOCOL
        .context_matchers
        .iter()
        .map(|matcher| matcher.role.to_string())
        .collect::<BTreeSet<_>>();

    let missing = declared_roles
        .difference(&registered_roles)
        .cloned()
        .collect::<Vec<_>>();
    assert!(
        missing.is_empty(),
        "every target ContextNeed/ContextOffer role introduced by fact modules needs a protocol registry matcher:\n{}",
        missing.join("\n")
    );
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
        "range".to_string(),
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
fn duplicate_fact_names_are_known_migration_debt() {
    let mut by_name = BTreeMap::<&str, Vec<&str>>::new();
    for fact in PROTOCOL.facts {
        by_name.entry(fact.name).or_default().push(fact.module);
    }

    let mut duplicates = by_name
        .into_iter()
        .filter_map(|(name, mut modules)| {
            modules.sort_unstable();
            modules.dedup();
            (modules.len() > 1).then_some((
                name.to_string(),
                modules.into_iter().map(str::to_string).collect::<Vec<_>>(),
            ))
        })
        .collect::<Vec<_>>();
    duplicates.sort();

    let expected = vec![
        (
            "local_history_node_secret".to_string(),
            vec![
                "encryption".to_string(),
                "encryption::local_history_node_secret".to_string(),
            ],
        ),
        (
            "removal_frontier".to_string(),
            vec![
                "encryption".to_string(),
                "encryption::removal_frontier".to_string(),
            ],
        ),
    ];

    assert_eq!(
        duplicates, expected,
        "new duplicate fact names must not enter the protocol registry silently; collapse the known encryption split duplicates instead of adding more"
    );
}

#[test]
fn fact_type_tags_are_globally_unique() {
    let mut by_tag = BTreeMap::<u8, Vec<String>>::new();
    for fact in PROTOCOL.facts {
        by_tag
            .entry(fact.tag)
            .or_default()
            .push(format!("{}/{}", fact.module, fact.name));
    }

    let duplicates = by_tag
        .into_iter()
        .filter_map(|(tag, facts)| (facts.len() > 1).then_some((tag, facts)))
        .collect::<Vec<_>>();

    assert!(
        duplicates.is_empty(),
        "fact tags must be globally unique so runtime dispatch never guesses between fact types:\n{duplicates:?}"
    );
}

#[test]
fn handler_intents_are_declared_intents() {
    for handler in PROTOCOL.handlers {
        for handled_kind in handler.intents {
            assert!(
                PROTOCOL
                    .intents
                    .iter()
                    .any(|intent| intent.kind == *handled_kind),
                "{} handles undeclared intent {}",
                handler.handler,
                handled_kind
            );
        }
    }
}

#[test]
fn row_intents_are_registered_as_atomic_deferred_or_ephemeral() {
    let put_row = PROTOCOL
        .intents
        .iter()
        .find(|intent| intent.kind == "put_row")
        .expect("put_row intent");
    assert_eq!(put_row.execution, IntentExecutionKind::Atomic);

    let receive_transit = PROTOCOL
        .intents
        .iter()
        .find(|intent| intent.kind == "receive_transit_frame")
        .expect("receive transport::transit intent");
    assert_eq!(receive_transit.execution, IntentExecutionKind::Ephemeral);

    let send_network = PROTOCOL
        .intents
        .iter()
        .find(|intent| intent.kind == "send_network_frame")
        .expect("send network frame intent");
    assert_eq!(send_network.execution, IntentExecutionKind::Ephemeral);

    let send_facts = PROTOCOL
        .intents
        .iter()
        .find(|intent| intent.kind == "send_facts_on_connection")
        .expect("send facts on connection intent");
    assert_eq!(send_facts.execution, IntentExecutionKind::Deferred);
}
