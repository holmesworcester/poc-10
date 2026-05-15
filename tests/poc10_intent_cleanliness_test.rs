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
