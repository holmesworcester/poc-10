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
