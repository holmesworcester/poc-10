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

fn production_text_before_unit_tests(text: &str) -> &str {
    text.find("#[cfg(test)]")
        .map(|index| &text[..index])
        .unwrap_or(text)
}

#[test]
fn sealed_message_intents_do_not_encode_projection_work() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let intent = source_text(&root.join("src/event_modules/sealed_message/intent.rs"));

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
            "sealed_message intent layout must not own projection/opening detail: {forbidden}"
        );
    }
}

#[test]
fn handlers_do_not_own_event_module_projection_rows() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let handler_root = root.join("src/handlers");
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
        "handlers must not materialize or clean up event-module projection rows:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn purge_event_handler_must_be_real_retention_work_when_it_exists() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let path = root.join("src/handlers/purge_event.rs");
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
            "PurgeEvent handler must not be projection row cleanup: {forbidden}"
        );
    }
    assert!(
        text.contains("purge_event_storage_in_tx")
            || text.contains("DiscoverCascade")
            || text.contains("RetireSecret")
            || text.contains("SyncIndexPurge"),
        "PurgeEvent handler must preserve real retention/cascade/retire behavior"
    );
}

#[test]
fn target_projectors_stay_pure_context_to_intents() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut offenders = Vec::new();
    for path in rust_files_named(&root.join("src/event_modules"), "project.rs") {
        let text = source_text(&path);
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
        "target projectors must stay pure fact+context -> needs/offers/intents:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn target_context_matchers_do_not_emit_work_or_rows() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut offenders = Vec::new();
    for path in rust_files_named(&root.join("src/event_modules"), "context.rs") {
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
        "context matchers should only define needs/offers/selectors and matching:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn target_row_layouts_do_not_emit_context_or_intents() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut offenders = Vec::new();
    for path in rust_files_named(&root.join("src/event_modules"), "rows.rs") {
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
fn target_event_modules_do_not_use_legacy_file_names() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut offenders = Vec::new();
    for path in rust_files(&root.join("src/event_modules")) {
        let Some(file_name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if matches!(
            file_name,
            "mod.rs" | "schema.rs" | "codec.rs" | "cli.rs" | "commands.rs" | "queries.rs"
        ) {
            offenders.push(path.strip_prefix(root).unwrap().display().to_string());
        }
    }

    assert!(
        offenders.is_empty(),
        "target event modules should use fact/layout/project/context/intent/rows/read files, not legacy names:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn target_event_modules_do_not_import_legacy_protocol_or_workers() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut offenders = Vec::new();
    for path in rust_files(&root.join("src/event_modules")) {
        let text = source_text(&path);
        for forbidden in [
            "crate::protocol",
            "crate::workers",
            "topo::protocol",
            "topo::workers",
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
        "target event modules must not call into retained poc-8 protocol/workers:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn target_intent_files_only_encode_intent_payloads() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut offenders = Vec::new();
    for path in rust_files_named(&root.join("src/event_modules"), "intent.rs") {
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
    for path in rust_files_named(&root.join("src/event_modules"), "project.rs") {
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
        "projectors should compose event-module helpers, not define payload decoding or handler logic:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn target_manifests_are_declarations_only() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut manifests = vec![
        root.join("src/event_modules.rs"),
        root.join("src/handlers.rs"),
    ];
    manifests.extend(immediate_rust_children(&root.join("src/event_modules")));

    let mut offenders = Vec::new();
    for path in manifests {
        let text = source_text(&path);
        for line in meaningful_source_lines(&text) {
            if !(line.starts_with("pub mod ")
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
fn target_schema_dsl_files_are_declarative_only() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let schema_files = [
        root.join("src/core/schema.p8sql"),
        root.join("src/event_modules/schema.p8sql"),
        root.join("src/handlers/schema.p8sql"),
    ];
    let mut offenders = Vec::new();

    for path in schema_files {
        let text = source_text(&path);
        for line in meaningful_source_lines(&text) {
            if !(line.starts_with("table ")
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
        "crate::event_modules",
        "crate::protocol",
        "crate::workers",
        "TableRow",
        "Intent",
        "ProjectionOutput",
        "ContextNeed",
        "ContextOffer",
        "workspace",
        "sealed_message",
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
    for path in rust_files_named(&root.join("src/event_modules"), "layout.rs") {
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
    for path in rust_files_named(&root.join("src/event_modules"), "project.rs") {
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
    for path in rust_files(&root.join("src/event_modules"))
        .into_iter()
        .chain(rust_files(&root.join("src/handlers")))
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
        "target event modules and handlers must not grow CLI-equivalent parsing or formatting:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn target_handlers_do_not_own_projection_rows_or_projector_context() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let handler_root = root.join("src/handlers");
    if !handler_root.exists() {
        return;
    }

    let mut offenders = Vec::new();
    for path in rust_files(&handler_root) {
        let text = source_text(&path);
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
        "handlers should do deferred effects/checkpoints, not projection row or context work:\n{}",
        offenders.join("\n")
    );
}
