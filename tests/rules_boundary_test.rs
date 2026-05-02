use std::path::Path;

fn rust_files(root: &Path) -> Vec<std::path::PathBuf> {
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

fn file_contains_violations(
    root: &Path,
    files: &[std::path::PathBuf],
    forbidden: &[&str],
) -> Vec<String> {
    let mut violations = Vec::new();
    for path in files {
        let text = std::fs::read_to_string(path).expect("read rust file");
        let relative = path.strip_prefix(root).unwrap_or(path);
        for needle in forbidden {
            if text.contains(needle) {
                violations.push(format!("{} contains {needle}", relative.display()));
            }
        }
    }
    violations
}

#[test]
fn event_modules_do_not_use_event_rs() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/event_modules");
    let offenders = rust_files(&root)
        .into_iter()
        .filter(|path| path.file_name().is_some_and(|name| name == "event.rs"))
        .collect::<Vec<_>>();
    assert!(offenders.is_empty(), "event.rs is forbidden: {offenders:?}");
}

#[test]
fn event_modules_are_directories() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/event_modules");
    let offenders = std::fs::read_dir(root)
        .expect("read event modules")
        .map(|entry| entry.expect("dir entry").path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "rs"))
        .filter(|path| !path.file_name().is_some_and(|name| name == "mod.rs"))
        .collect::<Vec<_>>();
    assert!(
        offenders.is_empty(),
        "event modules must be directories: {offenders:?}"
    );
}

#[test]
fn domain_modules_contain_only_child_modules() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/event_modules");
    let mut offenders = Vec::new();
    for domain in std::fs::read_dir(&root).expect("read event modules") {
        let path = domain.expect("dir entry").path();
        if !path.is_dir() {
            continue;
        }
        for entry in std::fs::read_dir(&path).expect("read domain module") {
            let candidate = entry.expect("dir entry").path();
            if candidate.is_file() && !candidate.file_name().is_some_and(|name| name == "mod.rs") {
                offenders.push(candidate.strip_prefix(&root).unwrap().display().to_string());
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "domain folders are namespaces only; put commands/codecs/projectors/tables in the most relevant child module:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn codec_files_do_not_define_public_types() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let event_root = root.join("src/event_modules");
    let files = rust_files(&event_root)
        .into_iter()
        .filter(|path| path.file_name().is_some_and(|name| name == "codec.rs"))
        .collect::<Vec<_>>();
    let forbidden = ["pub struct ", "pub enum ", "pub type "];
    let violations = file_contains_violations(root, &files, &forbidden);
    assert!(
        violations.is_empty(),
        "event module semantic types belong in types.rs; codec.rs is encode/decode only:\n{}",
        violations.join("\n")
    );
}

#[test]
fn codec_modules_have_type_files() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/event_modules");
    let mut offenders = Vec::new();
    for codec in rust_files(&root)
        .into_iter()
        .filter(|path| path.file_name().is_some_and(|name| name == "codec.rs"))
    {
        let types = codec.with_file_name("types.rs");
        if !types.exists() {
            offenders.push(codec.strip_prefix(&root).unwrap().display().to_string());
        }
    }

    assert!(
        offenders.is_empty(),
        "modules with codec.rs must define semantic shapes in sibling types.rs:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn core_imports_only_the_modules_registry() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let core_files = [
        "src/main.rs",
        "src/pipeline.rs",
        "src/control_loop.rs",
        "src/store.rs",
        "src/network.rs",
        "src/blocking.rs",
    ];
    let mut violations = Vec::new();

    for file in core_files {
        let text = std::fs::read_to_string(root.join(file)).expect("read core file");
        for (line_idx, line) in text.lines().enumerate() {
            if line.contains("event_modules::")
                && !line.contains("event_modules::Modules")
                && !line.contains("event_modules::{Modules")
            {
                violations.push(format!("{file}:{}: {line}", line_idx + 1));
            }
        }
    }

    assert!(
        violations.is_empty(),
        "core imports the Modules registry only; concrete event modules are composed in event_modules/mod.rs:\n{}",
        violations.join("\n")
    );
}

#[test]
fn pipeline_has_no_protocol_branching_vocabulary() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let files = [root.join("src/pipeline.rs")];
    let forbidden = [
        "connection",
        "sync",
        "transit",
        "response",
        "record_transport",
        "is_connection_event",
        "ingest_sync",
    ];
    let violations = file_contains_violations(root, &files, &forbidden);
    assert!(
        violations.is_empty(),
        "pipeline is generic admission/apply plumbing; protocol branching belongs in event_modules::Modules:\n{}",
        violations.join("\n")
    );
}

#[test]
fn store_uses_generic_storage_vocabulary() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let files = [root.join("src/store.rs")];
    let forbidden = ["bucket", "module_rows", "payload_len"];
    let violations = file_contains_violations(root, &files, &forbidden);
    assert!(
        violations.is_empty(),
        "store owns generic mechanics, not sync buckets, module-row escape hatches, or payload semantics:\n{}",
        violations.join("\n")
    );
}

#[test]
fn sync_event_module_does_not_own_transport_or_frame_io() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let sync_root = root.join("src/event_modules/sync");
    let files = rust_files(&sync_root);
    let forbidden = [
        "TcpStream",
        "TcpListener",
        "crate::network",
        "read_frame",
        "write_frame",
    ];
    let violations = file_contains_violations(root, &files, &forbidden);
    assert!(
        violations.is_empty(),
        "sync event modules must not own TCP transport or frame IO:\n{}",
        violations.join("\n")
    );
}

#[test]
fn event_module_commands_do_not_mutate_storage_directly() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let event_root = root.join("src/event_modules");
    let files = rust_files(&event_root)
        .into_iter()
        .filter(|path| path.file_name().is_some_and(|name| name == "commands.rs"))
        .collect::<Vec<_>>();
    let forbidden = [
        "use crate::store::Store",
        "&Store",
        "Store,",
        "Store)",
        "StateChanges",
        "TableRow",
        "with_changes",
        ".rows",
        "write_transaction",
        "insert_table_rows",
        "insert_event(",
        "set_event_status",
        "delete_dependency_wait",
        "drain_until_idle",
        "rusqlite",
    ];
    let violations = file_contains_violations(root, &files, &forbidden);
    assert!(
        violations.is_empty(),
        "commands receive explicit context and return CommandOutput events only; projectors/pipeline/store own rows and writes:\n{}",
        violations.join("\n")
    );
}

#[test]
fn event_module_projectors_do_not_query_storage_directly() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let event_root = root.join("src/event_modules");
    let files = rust_files(&event_root)
        .into_iter()
        .filter(|path| path.file_name().is_some_and(|name| name == "projector.rs"))
        .collect::<Vec<_>>();
    let forbidden = [
        "use crate::store::Store",
        "&Store",
        "Store,",
        "Store)",
        "table_row",
        "event_bytes",
        "has_event",
        "write_transaction",
        "rusqlite",
    ];
    let violations = file_contains_violations(root, &files, &forbidden);
    assert!(
        violations.is_empty(),
        "projectors are pure transforms over event plus explicit context; queries belong outside projector.rs:\n{}",
        violations.join("\n")
    );
}

#[test]
fn command_output_contains_events_not_state_changes() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let text = std::fs::read_to_string(root.join("src/store.rs")).expect("read store");
    let start = text
        .find("pub struct CommandOutput")
        .expect("CommandOutput");
    let body = &text[start..text[start..].find("impl<T> CommandOutput").unwrap() + start];
    assert!(
        body.contains("pub events: Vec<EventRecord>") && !body.contains("StateChanges"),
        "CommandOutput is command-facing and must carry events only, not projector rows"
    );
}

#[test]
fn sync_event_module_does_not_use_session_message_vocabulary() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let sync_root = root.join("src/event_modules/sync");
    let files = rust_files(&sync_root);
    let forbidden = ["Hello", "HelloAck", "Done", "Events"];
    let violations = file_contains_violations(root, &files, &forbidden);
    assert!(
        violations.is_empty(),
        "sync protocol items must be connection-scoped events, not session messages:\n{}",
        violations.join("\n")
    );
}

#[test]
fn core_files_do_not_contain_sync_protocol_logic() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let files = [
        "src/main.rs",
        "src/pipeline.rs",
        "src/store.rs",
        "src/network.rs",
    ];
    let forbidden = ["negentropy", "Compare", "Have", "Need", "differing_buckets"];
    let mut violations = Vec::new();
    for file in files {
        let text = std::fs::read_to_string(root.join(file)).expect("read file");
        for needle in forbidden {
            if text.contains(needle) {
                violations.push(format!("{file} contains {needle}"));
            }
        }
    }
    assert!(
        violations.is_empty(),
        "sync protocol logic belongs in event_modules/sync:\n{}",
        violations.join("\n")
    );
}

#[test]
fn core_storage_and_transport_do_not_own_connection_or_bootstrap_schema() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let files = ["src/store.rs", "src/network.rs"];
    let forbidden = [
        "peer",
        "bootstrap",
        "connection_id",
        "connection_events",
        "connection.",
    ];
    let mut violations = Vec::new();
    for file in files {
        let text = std::fs::read_to_string(root.join(file)).expect("read file");
        for needle in forbidden {
            if text.contains(needle) {
                violations.push(format!("{file} contains {needle}"));
            }
        }
    }
    assert!(
        violations.is_empty(),
        "connection/bootstrap storage belongs in event_modules/connection:\n{}",
        violations.join("\n")
    );
}
