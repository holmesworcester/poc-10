use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

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

fn rust_files_named(root: &Path, name: &str) -> Vec<PathBuf> {
    rust_files(root)
        .into_iter()
        .filter(|path| path.file_name().is_some_and(|file_name| file_name == name))
        .collect()
}

fn meaningful_source_lines(text: &str) -> Vec<&str> {
    text.lines()
        .map(str::trim)
        .filter(|line| {
            !line.is_empty()
                && !line.starts_with("//")
                && !line.starts_with("//!")
                && !line.starts_with("///")
                && !line.starts_with('#')
        })
        .collect()
}

fn immediate_rust_children(root: &Path) -> Vec<PathBuf> {
    std::fs::read_dir(root)
        .expect("read dir")
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| path.extension().is_some_and(|ext| ext == "rs"))
        .collect()
}

fn immediate_rust_module_names(root: &Path) -> BTreeSet<String> {
    immediate_rust_children(root)
        .into_iter()
        .filter_map(|path| {
            path.file_stem()
                .and_then(|stem| stem.to_str())
                .map(str::to_string)
        })
        .collect()
}

fn declared_modules_in(text: &str) -> BTreeSet<String> {
    meaningful_source_lines(text)
        .into_iter()
        .filter_map(|line| {
            line.strip_prefix("pub mod ")
                .or_else(|| line.strip_prefix("mod "))
                .and_then(|rest| rest.strip_suffix(';'))
                .map(str::trim)
                .map(str::to_string)
        })
        .collect()
}

fn production_text_before_unit_tests(text: &str) -> &str {
    text.find("#[cfg(test)]")
        .map(|index| &text[..index])
        .unwrap_or(text)
}

fn strip_line_comments(text: &str) -> String {
    text.lines()
        .map(|line| {
            let trimmed = line.trim_start();
            if trimmed.starts_with("//") {
                ""
            } else {
                line.split_once("//").map_or(line, |(code, _)| code)
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn projector_implementation_files(root: &Path) -> Vec<PathBuf> {
    let facts_root = root.join("src/protocol/facts");
    rust_files(&facts_root)
        .into_iter()
        .filter(|path| {
            path.file_name()
                .is_some_and(|file_name| file_name == "project.rs")
                || path
                    .strip_prefix(&facts_root)
                    .expect("protocol fact file")
                    .components()
                    .any(|component| component.as_os_str() == "project")
        })
        .collect()
}

fn contains_context_matcher_logic(text: &str) -> bool {
    let production = strip_line_comments(production_text_before_unit_tests(text));
    [
        "impl ContextMatcher for",
        "ContextMatch {",
        "Vec<ContextMatch>",
        "Option<ContextMatch>",
        "match_need_to_offers",
        "match_offer_to_needs",
    ]
    .into_iter()
    .any(|needle| production.contains(needle))
}

#[test]
fn sealed_message_intents_do_not_encode_projection_work() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let intent = source_text(&root.join("src/protocol/facts/content/sealed_message/intent.rs"));

    for forbidden in [
        "open_message",
        "OpenMessage",
        "MESSAGE_ROWS",
        "SEALED_MESSAGE_ROWS",
        "message_row",
        "sealed_message_row",
        "leaf_id",
        "minute",
        "ciphertext",
    ] {
        assert!(
            !intent.contains(forbidden),
            "content::sealed_message intent layout must not own projection/opening detail: {forbidden}"
        );
    }
}

#[test]
fn handlers_do_not_own_event_module_projection_rows() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let handler_root = root.join("src/protocol/intents");
    if !handler_root.exists() {
        return;
    }

    let mut offenders = Vec::new();
    for path in rust_files(&handler_root) {
        let text = source_text(&path);
        for forbidden in [
            "MESSAGE_ROWS",
            "SEALED_MESSAGE_ROWS",
            "message_rows",
            "sealed_message_rows",
            "message_row",
            "sealed_message_row",
        ] {
            if text.contains(forbidden) {
                offenders.push(format!(
                    "{} contains {forbidden:?}",
                    path.strip_prefix(root).unwrap().display()
                ));
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "intent handlers must not materialize or clean up fact-module projection rows:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn purge_deleted_message_handler_must_be_real_retention_work_when_it_exists() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let path = root.join("src/protocol/intents/content/purge_deleted_message.rs");
    if !path.exists() {
        return;
    }

    let text = source_text(&path);
    for forbidden in [
        "MESSAGE_ROWS",
        "SEALED_MESSAGE_ROWS",
        "message_rows",
        "sealed_message_rows",
        "TableDelete",
    ] {
        assert!(
            !text.contains(forbidden),
            "PurgeDeletedMessage handler must not be projection row cleanup: {forbidden}"
        );
    }
    assert!(
        text.contains("purge_deleted_message")
            || text.contains("purge_fact")
            || text.contains("DiscoverCascade")
            || text.contains("RetireSecret")
            || text.contains("SyncIndexPurge"),
        "PurgeDeletedMessage handler must preserve real retention/cascade/retire behavior"
    );
}

#[test]
fn target_projectors_stay_pure_context_to_intents() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut offenders = Vec::new();
    for path in projector_implementation_files(root) {
        let text = source_text(&path);
        let production = production_text_before_unit_tests(&text);
        for forbidden in [
            "Store",
            "table_rows",
            "insert_table_rows",
            "delete_table_rows",
            "write_transaction",
            "Protocol::",
            "workers::",
            "network_queues",
            "std::net",
            "std::process",
            "Command::new",
        ] {
            if production.contains(forbidden) {
                offenders.push(format!(
                    "{} contains {forbidden:?}",
                    path.strip_prefix(root).unwrap().display()
                ));
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "target projectors must stay pure fact+context -> needs/offers/intents:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn target_projectors_use_typed_context_lookups_not_direct_match_scans() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let allowed_direct_scans: [&str; 0] = [];
    let mut offenders = Vec::new();
    let mut seen_allowed = BTreeSet::new();

    for path in projector_implementation_files(root) {
        let relative = path.strip_prefix(root).unwrap().display().to_string();
        let text = source_text(&path);
        let production = strip_line_comments(production_text_before_unit_tests(&text));
        if !production.contains("matched_context") {
            continue;
        }

        if allowed_direct_scans.contains(&relative.as_str()) {
            seen_allowed.insert(relative);
        } else {
            offenders.push(relative);
        }
    }

    let stale_allowlist = allowed_direct_scans
        .into_iter()
        .filter(|path| !seen_allowed.contains(*path))
        .collect::<Vec<_>>();

    assert!(
        offenders.is_empty() && stale_allowlist.is_empty(),
        "source projectors must look up context by concrete ContextNeed with ProjectionContext::payload_for, payload_for_checked, or matched_payloads_for. Direct matched_context scans are exceptional and must not spread.\nnew offenders:\n{}\nstale allowlist entries to remove:\n{}",
        offenders.join("\n"),
        stale_allowlist.join("\n")
    );
}

#[test]
fn event_module_context_rs_files_do_not_reappear() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let offenders = rust_files_named(&root.join("src/protocol/facts"), "context.rs")
        .into_iter()
        .map(|path| path.strip_prefix(root).unwrap().display().to_string())
        .collect::<Vec<_>>();

    assert!(
        offenders.is_empty(),
        "protocol-specific fact-module context.rs files are dumping-ground risks, not a target source of truth. Core-owned src/core/context.rs is allowed; put protocol context constructors and relation-specific matching under src/protocol/matchers instead:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn context_matcher_logic_lives_under_protocol_matchers() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut offenders = Vec::new();

    for path in rust_files(&root.join("src")) {
        let text = source_text(&path);
        if !contains_context_matcher_logic(&text) {
            continue;
        }
        let relative = path.strip_prefix(root).unwrap();
        if relative.starts_with("src/core/matchers.rs")
            || relative.starts_with("src/core/wake_loop.rs")
            || relative.starts_with("src/protocol/matchers")
        {
            continue;
        }

        offenders.push(relative.display().to_string());
    }

    assert!(
        offenders.is_empty(),
        "ContextMatcher implementations and relation-specific selector logic belong under src/protocol/matchers, with core-owned generic mechanics in src/core/matchers.rs and src/core/wake_loop.rs:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn temporary_protocol_context_helpers_do_not_emit_work_or_rows() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut offenders = Vec::new();
    for path in rust_files_named(&root.join("src/protocol/facts"), "context.rs") {
        let text = source_text(&path);
        for forbidden in [
            "Intent",
            "AtomicIntent",
            "ProjectionOutput",
            "Projector",
            "TableRow",
            "Store",
            "insert_table_rows",
            "delete_table_rows",
            "write_transaction",
            "ProjectionContext",
            "MatchedContext",
        ] {
            if text.contains(forbidden) {
                offenders.push(format!(
                    "{} contains {forbidden:?}",
                    path.strip_prefix(root).unwrap().display()
                ));
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "temporary protocol context.rs helper files are not the context source of truth; protocol context constructors and matcher logic belong under src/protocol/matchers, while ProjectionContext inspection belongs in project.rs:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn target_row_layouts_do_not_emit_context_or_intents() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut offenders = Vec::new();
    for path in rust_files_named(&root.join("src/protocol/facts"), "rows.rs") {
        let text = source_text(&path);
        for forbidden in [
            "ContextNeed",
            "ContextOffer",
            "ContextMatcher",
            "ProjectionOutput",
            "Projector",
            "Intent",
            "AtomicIntent",
            "TableDelete",
        ] {
            if text.contains(forbidden) {
                offenders.push(format!(
                    "{} contains {forbidden:?}",
                    path.strip_prefix(root).unwrap().display()
                ));
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "row layout files should only encode/decode projection rows:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn target_facts_do_not_use_legacy_file_names() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut offenders = Vec::new();
    for path in rust_files(&root.join("src/protocol/facts")) {
        let Some(file_name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if matches!(file_name, "mod.rs" | "schema.rs" | "codec.rs") {
            offenders.push(path.strip_prefix(root).unwrap().display().to_string());
        }
    }

    assert!(
        offenders.is_empty(),
        "target facts should use explicit role files, not legacy module manifests or dumping-ground names:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn reactive_paths_do_not_call_user_facing_commands_or_cli_adapters() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    files.extend(rust_files_named(
        &root.join("src/protocol/facts"),
        "project.rs",
    ));
    files.extend(
        rust_files(&root.join("src/protocol/facts"))
            .into_iter()
            .filter(|path| {
                path.components()
                    .any(|component| component.as_os_str() == "project")
            }),
    );
    files.extend(rust_files(&root.join("src/protocol/intents")));

    let mut offenders = Vec::new();
    for path in files {
        let text = source_text(&path);
        for forbidden in ["/commands.rs", "::commands", "/cli.rs", "::cli"] {
            if text.contains(forbidden) {
                offenders.push(format!(
                    "{} contains {forbidden:?}",
                    path.strip_prefix(root).unwrap().display()
                ));
            }
        }
        for line in text.lines() {
            let trimmed = line.trim_start();
            if trimmed.starts_with("use crate::protocol::facts") && trimmed.contains("commands") {
                offenders.push(format!(
                    "{} imports fact-module commands from reactive code: {trimmed}",
                    path.strip_prefix(root).unwrap().display()
                ));
            }
            if trimmed.starts_with("use crate::protocol::facts") && trimmed.contains("cli") {
                offenders.push(format!(
                    "{} imports fact-module cli from reactive code: {trimmed}",
                    path.strip_prefix(root).unwrap().display()
                ));
            }
        }
    }

    offenders.sort();
    offenders.dedup();
    assert!(
        offenders.is_empty(),
        "projectors and handlers are automatic/reactive paths; they may share create.rs constructors but must not call user-facing commands.rs or cli.rs:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn target_facts_do_not_import_legacy_protocol_or_workers() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut offenders = Vec::new();
    for path in rust_files(&root.join("src/protocol/facts")) {
        let text = source_text(&path);
        for forbidden in [
            "crate::legacy::protocol",
            "crate::legacy::workers",
            "topo::legacy::protocol",
            "topo::legacy::workers",
        ] {
            if text.contains(forbidden) {
                offenders.push(format!(
                    "{} contains {forbidden:?}",
                    path.strip_prefix(root).unwrap().display()
                ));
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "target fact modules must not call into retained poc-8 protocol/workers:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn target_intent_files_only_encode_intent_payloads() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut offenders = Vec::new();
    for path in rust_files_named(&root.join("src/protocol/facts"), "intent.rs") {
        let text = source_text(&path);
        for forbidden in [
            "Store",
            "TableRow",
            "TableName",
            "AtomicIntent",
            "ProjectionOutput",
            "Projector",
            "ContextNeed",
            "ContextOffer",
            "insert_table_rows",
            "delete_table_rows",
            "network_queues",
            "std::net",
            "tcp::",
        ] {
            if text.contains(forbidden) {
                offenders.push(format!(
                    "{} contains {forbidden:?}",
                    path.strip_prefix(root).unwrap().display()
                ));
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "intent files should only define deferred intent keys/payloads:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn target_projectors_do_not_define_intent_payloads_or_handler_logic() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut offenders = Vec::new();
    for path in rust_files_named(&root.join("src/protocol/facts"), "project.rs") {
        let text = source_text(&path);
        for forbidden in [
            "IntentKind::new",
            "impl IntentHandler",
            "HandlerOutput",
            "HandlerContext",
            "std::thread",
            "spawn(",
        ] {
            if text.contains(forbidden) {
                offenders.push(format!(
                    "{} contains {forbidden:?}",
                    path.strip_prefix(root).unwrap().display()
                ));
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "projectors should compose fact-module helpers, not define payload decoding or handler logic:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn target_manifests_are_declarations_only() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut manifests = vec![
        root.join("src/lib.rs"),
        root.join("src/core.rs"),
        root.join("src/protocol/facts.rs"),
        root.join("src/protocol/intents.rs"),
    ];
    manifests.extend(immediate_rust_children(&root.join("src/protocol/facts")));

    let mut offenders = Vec::new();
    for path in manifests {
        let text = source_text(&path);
        for line in meaningful_source_lines(&text) {
            if !(line.starts_with("#[path = ")
                || line.starts_with("pub mod ")
                || line.starts_with("mod ")
                || line.starts_with("pub use "))
            {
                offenders.push(format!(
                    "{} contains non-declaration line: {line}",
                    path.strip_prefix(root).unwrap().display()
                ));
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "target root/module manifests must not accumulate behavior:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn root_command_module_does_not_reappear() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let offenders = ["src/commands.rs", "src/commands"]
        .into_iter()
        .filter(|path| root.join(path).exists())
        .collect::<Vec<_>>();

    assert!(
        offenders.is_empty(),
        "there is no root command module. User-facing command context lives in src/core/command_context.rs, and module commands stay under protocol fact modules:\n{}",
        offenders.join("\n")
    );

    assert!(
        root.join("src/core/command_context.rs").is_file(),
        "missing src/core/command_context.rs"
    );
}

#[test]
fn concrete_protocol_manifests_live_under_protocol() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let stale = [
        "src/event_modules",
        "src/event_modules.rs",
        "src/handlers",
        "src/handlers.rs",
    ]
    .into_iter()
    .filter(|path| root.join(path).exists())
    .collect::<Vec<_>>();

    assert!(
        stale.is_empty(),
        "fact modules and intent handlers should live under src/protocol, not top-level crate namespaces:\n{}",
        stale.join("\n")
    );

    for required in ["src/protocol/facts.rs", "src/protocol/intents.rs"] {
        assert!(
            root.join(required).is_file(),
            "missing protocol-owned manifest {required}"
        );
    }
}

#[test]
fn target_manifests_match_their_filesystem_modules() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let event_root = root.join("src/protocol/facts");
    let handler_root = root.join("src/protocol/intents");
    let mut offenders = Vec::new();

    for (manifest, module_root) in [
        (root.join("src/protocol/facts.rs"), event_root.clone()),
        (root.join("src/protocol/intents.rs"), handler_root),
    ] {
        let declared = declared_modules_in(&source_text(&manifest));
        let mut files = immediate_rust_module_names(&module_root);
        files.remove("registry");
        let missing_files = declared.difference(&files).cloned().collect::<Vec<_>>();
        let missing_declarations = files.difference(&declared).cloned().collect::<Vec<_>>();
        if !missing_files.is_empty() {
            offenders.push(format!(
                "{} declares modules without files: {}",
                manifest.strip_prefix(root).unwrap().display(),
                missing_files.join(", ")
            ));
        }
        if !missing_declarations.is_empty() {
            offenders.push(format!(
                "{} has files not declared by manifest: {}",
                module_root.strip_prefix(root).unwrap().display(),
                missing_declarations.join(", ")
            ));
        }
    }

    for manifest in immediate_rust_children(&event_root) {
        if manifest
            .file_name()
            .is_some_and(|file_name| file_name == "registry.rs")
        {
            continue;
        }
        let module_name = manifest
            .file_stem()
            .and_then(|stem| stem.to_str())
            .expect("module file stem");
        let declared = declared_modules_in(&source_text(&manifest));
        let module_root = event_root.join(module_name);
        if declared.is_empty() && !module_root.exists() {
            continue;
        }
        if !module_root.exists() {
            offenders.push(format!(
                "{} declares children but {} is missing",
                manifest.strip_prefix(root).unwrap().display(),
                module_root.strip_prefix(root).unwrap().display()
            ));
            continue;
        }

        let files = immediate_rust_module_names(&module_root);
        let missing_files = declared.difference(&files).cloned().collect::<Vec<_>>();
        let missing_declarations = files.difference(&declared).cloned().collect::<Vec<_>>();
        if !missing_files.is_empty() {
            offenders.push(format!(
                "{} declares child modules without files: {}",
                manifest.strip_prefix(root).unwrap().display(),
                missing_files.join(", ")
            ));
        }
        if !missing_declarations.is_empty() {
            offenders.push(format!(
                "{} has child files not declared by manifest: {}",
                module_root.strip_prefix(root).unwrap().display(),
                missing_declarations.join(", ")
            ));
        }
    }

    assert!(
        offenders.is_empty(),
        "target module manifests must stay synchronized with the filesystem so orphan files cannot become hidden dumping grounds:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn target_fact_child_files_use_narrow_slice_names() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let event_root = root.join("src/protocol/facts");
    let mut offenders = Vec::new();

    for path in rust_files(&event_root) {
        if path.parent() == Some(event_root.as_path()) {
            continue;
        }
        if path.parent().and_then(|parent| parent.parent()) == Some(event_root.as_path()) {
            continue;
        }
        let Some(file_name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if !matches!(
            file_name,
            "addr.rs"
                | "authority.rs"
                | "authoring.rs"
                | "create.rs"
                | "commands.rs"
                | "queries.rs"
                | "retention.rs"
                | "cli.rs"
                | "fact.rs"
                | "frame.rs"
                | "intent.rs"
                | "layout.rs"
                | "local_endpoint.rs"
                | "local_membership.rs"
                | "key_request.rs"
                | "local_material.rs"
                | "local_recipient_key.rs"
                | "message.rs"
                | "offers.rs"
                | "project.rs"
                | "range_request.rs"
                | "receive.rs"
                | "recipient_key.rs"
                | "rows.rs"
                | "runtime_counts.rs"
                | "secret_path.rs"
                | "signed_key_wrap.rs"
                | "validation.rs"
        ) {
            offenders.push(path.strip_prefix(root).unwrap().display().to_string());
        }
    }

    assert!(
        offenders.is_empty(),
        "target fact child files should stay in named responsibility slices, not generic helper or catch-all files:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn target_protocol_registry_is_declarative_only() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let path = root.join("src/protocol.rs");
    let text = source_text(&path);

    for required in [
        "pub const PROTOCOL: ProtocolRegistry",
        "pub const SCHEMAS: &[SchemaRegistration]",
        "pub const FACTS: &[FactRegistration]",
        "pub const CONTEXT_MATCHERS: &[ContextMatcherRegistration]",
        "pub const INTENTS: &[IntentRegistration]",
        "pub const HANDLERS: &[HandlerRegistration]",
    ] {
        assert!(
            text.contains(required),
            "protocol registry missing {required}"
        );
    }

    let mut offenders = Vec::new();
    for line in meaningful_source_lines(&text) {
        for forbidden in [
            "fn ",
            "impl ",
            "match ",
            "if ",
            "for ",
            "while ",
            "Store",
            "WakeLoop",
            ".project(",
            ".handle(",
            "open_",
            "std::net",
            "tcp::",
        ] {
            if line.contains(forbidden) {
                offenders.push(format!("line contains {forbidden:?}: {line}"));
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "src/protocol.rs should be a descriptor registry, not runtime logic:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn target_intents_are_themed_handler_files_without_driver_or_intent_submodules() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let handler_root = root.join("src/protocol/intents");
    if !handler_root.exists() {
        return;
    }

    let mut offenders = Vec::new();
    let allowed_themes = ["connection", "content", "encryption", "sync", "transport"];
    for entry in std::fs::read_dir(&handler_root).expect("read handlers") {
        let path = entry.expect("handler dir entry").path();
        if path.is_dir() {
            let dir_name = path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("");
            if !allowed_themes.contains(&dir_name) {
                offenders.push(path.strip_prefix(root).unwrap().display().to_string());
                continue;
            }
            for child in std::fs::read_dir(&path).expect("read intent theme") {
                let child_path = child.expect("intent theme entry").path();
                if child_path.is_dir() {
                    offenders.push(child_path.strip_prefix(root).unwrap().display().to_string());
                }
            }
        }
    }
    for path in rust_files(&handler_root) {
        let Some(file_name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if matches!(file_name, "driver.rs" | "intent.rs") {
            offenders.push(path.strip_prefix(root).unwrap().display().to_string());
        }
    }

    assert!(
        offenders.is_empty(),
        "intents should be themed once, with self-contained handler files under src/protocol/intents/<theme>:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn target_handler_files_do_not_define_fact_or_crypto_outputs() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let handler_root = root.join("src/protocol/intents");
    if !handler_root.exists() {
        return;
    }

    let mut offenders = Vec::new();
    for path in rust_files(&handler_root) {
        let text = source_text(&path);
        let production = production_text_before_unit_tests(&text);
        for forbidden in [
            "Fact::new",
            "FactScope",
            "ScopeKind",
            "TYPE_",
            "KEY_WRAP_BYTES",
            "encode_key_wrap",
            "decode_key_wrap",
            "sender_wrap_public_key",
            "ciphertext",
            "nonce",
            "crypto::xchacha20poly1305_encrypt",
            "crypto::xchacha20poly1305_decrypt",
            "crypto::x25519_xchacha20poly1305_encrypt",
            "crypto::x25519_xchacha20poly1305_decrypt",
            "crypto::ed25519_sign",
            "crypto::ed25519_verify",
            "placeholder",
            "fake",
            "crate::core::wire",
            "wire::",
        ] {
            if production.contains(forbidden) {
                offenders.push(format!(
                    "{} contains {forbidden:?}",
                    path.strip_prefix(root).unwrap().display()
                ));
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "handler files should encode/decode payloads and execute bounded effects, not define facts or crypto outputs:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn connection_intents_treat_transit_frames_as_opaque() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let path = root.join("src/protocol/intents/connection.rs");
    if !path.exists() {
        return;
    }

    let text = source_text(&path);
    let production = production_text_before_unit_tests(&text);
    let mut offenders = Vec::new();
    for forbidden in [
        "canonical_events",
        "facts::encryption",
        "XChaCha",
        "X25519",
        "ciphertext",
        "nonce",
        "encrypt",
        "decrypt",
    ] {
        if production.contains(forbidden) {
            offenders.push(format!(
                "{} contains {forbidden:?}",
                path.strip_prefix(root).unwrap().display()
            ));
        }
    }

    assert!(
        offenders.is_empty(),
        "connection intents must treat transport::transit frames as opaque transport bytes:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn signed_fact_envelope_does_not_dispatch_to_child_event_modules() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let signed_root = root.join("src/protocol/facts/identity::signed_fact");
    if !signed_root.exists() {
        return;
    }

    let mut offenders = Vec::new();
    for path in rust_files(&signed_root) {
        let text = source_text(&path);
        let production = production_text_before_unit_tests(&text);
        for forbidden in [
            "facts::encryption",
            "facts::content::sealed_message",
            "facts::sync",
            "facts::identity::workspace",
            "decode_key_wrap",
            "encode_key_wrap",
            "SealedMessage",
            "KeyWrapFact",
            "Intent",
            "HandlerOutput",
        ] {
            if production.contains(forbidden) {
                offenders.push(format!(
                    "{} contains {forbidden:?}",
                    path.strip_prefix(root).unwrap().display()
                ));
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "identity::signed_fact must stay an envelope helper, not a central protocol dispatcher:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn core_handler_dispatch_stays_protocol_neutral() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let path = root.join("src/core/handler_dispatch.rs");
    let text = source_text(&path);
    let production = production_text_before_unit_tests(&text);
    let mut offenders = Vec::new();

    for forbidden in [
        "crate::protocol",
        "topo::protocol",
        "KeyWrap",
        "Transit",
        "Connection",
    ] {
        if production.contains(forbidden) {
            offenders.push(format!(
                "{} contains {forbidden:?}",
                path.strip_prefix(root).unwrap().display()
            ));
        }
    }

    assert!(
        offenders.is_empty(),
        "core handler dispatch must stay generic and protocol-neutral:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn target_schema_dsl_files_are_declarative_only() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let schema_files = [
        root.join("src/core/schema.p8sql"),
        root.join("src/protocol/facts/schema.p8sql"),
        root.join("src/protocol/intents/schema.p8sql"),
    ];
    let mut offenders = Vec::new();

    for path in schema_files {
        let text = source_text(&path);
        for line in meaningful_source_lines(&text) {
            if !(line.starts_with("table ")
                || line.starts_with("row_table ")
                || line.starts_with("column ")
                || line.starts_with("row_key ")
                || line.starts_with("index ")
                || line.starts_with("unique index ")
                || line == "}")
            {
                offenders.push(format!(
                    "{} contains non-schema statement: {line}",
                    path.strip_prefix(root).unwrap().display()
                ));
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "poc-10 schema DSL files should declare tables only, not behavior:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn target_schema_dsl_parser_stays_protocol_neutral() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let path = root.join("src/core/schema_dsl.rs");
    let text = source_text(&path);
    let production = production_text_before_unit_tests(&text);
    let mut offenders = Vec::new();

    for forbidden in [
        "crate::protocol::facts",
        "crate::legacy::protocol",
        "crate::legacy::workers",
        "TableRow",
        "Intent",
        "ProjectionOutput",
        "ContextNeed",
        "ContextOffer",
        "workspace",
        "content::sealed_message",
        "recipient_key",
        "connection",
        "sync_index",
    ] {
        if production.contains(forbidden) {
            offenders.push(format!(
                "{} contains {forbidden:?}",
                path.strip_prefix(root).unwrap().display()
            ));
        }
    }

    assert!(
        offenders.is_empty(),
        "schema_dsl.rs should parse declarations, not become protocol or row-codegen behavior:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn target_layout_files_do_not_own_projection_intents_handlers_or_cli() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut offenders = Vec::new();
    for path in rust_files_named(&root.join("src/protocol/facts"), "layout.rs") {
        let text = source_text(&path);
        for forbidden in [
            "TableRow",
            "TableName",
            "AtomicIntent",
            "Intent",
            "IntentKind",
            "IntentExecution",
            "ProjectionOutput",
            "Projector",
            "ContextNeed",
            "ContextOffer",
            "ContextMatcher",
            "IntentHandler",
            "HandlerOutput",
            "HandlerContext",
            "Store",
            "network_queues",
            "std::net",
            "CliArgs",
            "CliOutput",
            "CliCommand",
        ] {
            if text.contains(forbidden) {
                offenders.push(format!(
                    "{} contains {forbidden:?}",
                    path.strip_prefix(root).unwrap().display()
                ));
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "layout.rs files should own fixed fact bytes only, not projection, intent, handler, or CLI work:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn target_projectors_do_not_define_row_tables_or_row_shapes() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut offenders = Vec::new();
    for path in rust_files_named(&root.join("src/protocol/facts"), "project.rs") {
        let text = source_text(&path);
        for forbidden in ["TableRow", "TableName", "TableName::new", "_ROWS:"] {
            if text.contains(forbidden) {
                offenders.push(format!(
                    "{} contains {forbidden:?}",
                    path.strip_prefix(root).unwrap().display()
                ));
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "project.rs should emit row intents through row helpers, not define row tables or shapes:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn target_cli_equivalents_do_not_exist_or_parse_user_commands() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut offenders = Vec::new();
    for path in rust_files(&root.join("src/protocol/facts"))
        .into_iter()
        .filter(|path| path.file_name().is_none_or(|name| name != "cli.rs"))
        .chain(rust_files(&root.join("src/protocol/intents")))
    {
        let text = source_text(&path);
        for forbidden in [
            "CliArgs",
            "CliOutput",
            "CliCommand",
            "std::env",
            "std::process",
            "Command::new",
            "println!",
            "eprintln!",
            "usage:",
            "help:",
            "parse::<",
        ] {
            if text.contains(forbidden) {
                offenders.push(format!(
                    "{} contains {forbidden:?}",
                    path.strip_prefix(root).unwrap().display()
                ));
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "target fact modules and intent handlers must not grow CLI-equivalent parsing or formatting:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn target_handlers_do_not_own_projection_rows_or_projector_context() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let handler_root = root.join("src/protocol/intents");
    if !handler_root.exists() {
        return;
    }

    let mut offenders = Vec::new();
    for path in rust_files(&handler_root) {
        let text = source_text(&path);
        let production = production_text_before_unit_tests(&text);
        for forbidden in [
            "::rows",
            "TableRow",
            "TableName",
            "AtomicIntent",
            "ProjectionOutput",
            "Projector",
            "ContextNeed",
            "ContextOffer",
            "ContextMatcher",
        ] {
            if production.contains(forbidden) {
                offenders.push(format!(
                    "{} contains {forbidden:?}",
                    path.strip_prefix(root).unwrap().display()
                ));
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "handlers should do deferred effects/checkpoints, not projection row or context work:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn target_handlers_do_not_define_fact_wire_layouts_or_fake_crypto_facts() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let handler_root = root.join("src/protocol/intents");
    if !handler_root.exists() {
        return;
    }

    let mut offenders = Vec::new();
    for path in rust_files(&handler_root) {
        let text = source_text(&path);
        let production = production_text_before_unit_tests(&text);
        for forbidden in [
            "crate::core::facts",
            "Fact::new",
            "FactScope",
            "ScopeKind",
            "const TYPE_",
            "pub const TYPE_",
            "FixedLayout",
            "FixedSlot",
            "KeyWrapFact",
            "LocalKeySecretFact",
            "LocalHistoryNodeSecretFact",
            "LocalRecipientKeyFact",
            "encode_local_key_secret",
            "encode_local_history_node_secret",
            "encode_local_recipient_key",
            "decode_signed_fact",
            "decode_key_wrap",
            "decode_recipient_key",
            "decode_local_recipient_key",
            "crate::core::wire",
            "wire::",
            "put_u8",
            "take_u8",
            "expect_len",
            "ciphertext",
            "nonce",
            "crypto::xchacha20poly1305_encrypt",
            "crypto::xchacha20poly1305_decrypt",
            "crypto::x25519_xchacha20poly1305_encrypt",
            "crypto::x25519_xchacha20poly1305_decrypt",
            "crypto::ed25519_sign",
            "crypto::ed25519_verify",
            "placeholder",
            "fake",
        ] {
            if production.contains(forbidden) {
                offenders.push(format!(
                    "{} contains {forbidden:?}",
                    path.strip_prefix(root).unwrap().display()
                ));
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "intent handlers must not define protocol fact wire layouts, fact-module fact tags, or crypto-shaped placeholder facts; put fact shapes and fixed bytes under src/protocol/facts:\n{}",
        offenders.join("\n")
    );
}
