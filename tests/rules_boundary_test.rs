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

fn source_text(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()))
}

#[test]
fn event_modules_do_not_use_event_rs() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/protocol/event_modules");
    let offenders = rust_files(&root)
        .into_iter()
        .filter(|path| path.file_name().is_some_and(|name| name == "event.rs"))
        .collect::<Vec<_>>();
    assert!(offenders.is_empty(), "event.rs is forbidden: {offenders:?}");
}

#[test]
fn event_modules_are_directories() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/protocol/event_modules");
    let offenders = std::fs::read_dir(root)
        .expect("read event modules")
        .map(|entry| entry.expect("dir entry").path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "rs"))
        .filter(|path| path.file_name().is_none_or(|name| name != "mod.rs"))
        .collect::<Vec<_>>();
    assert!(
        offenders.is_empty(),
        "event modules must be directories: {offenders:?}"
    );
}

#[test]
fn core_file_set_stays_small_and_named() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/core");
    let allowed = [
        "blocking.rs",
        "control_loop.rs",
        "crux_runner.rs",
        "mod.rs",
        "pipeline.rs",
        "store.rs",
        "wire.rs",
    ];
    let offenders = std::fs::read_dir(&root)
        .expect("read core")
        .map(|entry| entry.expect("dir entry").path())
        .filter(|path| {
            path.is_dir()
                || !path
                    .file_name()
                    .is_some_and(|name| name.to_str().is_some_and(|name| allowed.contains(&name)))
        })
        .map(|path| path.strip_prefix(&root).unwrap().display().to_string())
        .collect::<Vec<_>>();

    assert!(
        offenders.is_empty(),
        "core should stay tiny; add protocol/domain behavior outside src/core:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn protocol_app_files_are_limited_to_cli_adapter_concerns() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let app_root = root.join("src/protocol/app");
    let allowed = [
        "crux_app.rs",
        "effects.rs",
        "flow_tests.rs",
        "flows.rs",
        "mod.rs",
        "model.rs",
        "network_effects.rs",
        "shell.rs",
        "store_effects.rs",
        "summaries.rs",
    ];
    let offenders = std::fs::read_dir(&app_root)
        .expect("read protocol app")
        .map(|entry| entry.expect("dir entry").path())
        .filter(|path| {
            path.is_dir()
                || !path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| allowed.contains(&name))
        })
        .map(|path| path.strip_prefix(root).unwrap().display().to_string())
        .collect::<Vec<_>>();

    assert!(
        offenders.is_empty(),
        "protocol/app is only the CLI adapter shell; scenario definitions belong beside the closest event module:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn domain_roots_contain_only_children_and_shared_domain_files() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/protocol/event_modules");
    let allowed_domain_files = [
        "mod.rs",
        "actor.rs",
        "tables.rs",
        "queries.rs",
        "types.rs",
        "cli.rs",
    ];
    let mut offenders = Vec::new();
    for domain in std::fs::read_dir(&root).expect("read event modules") {
        let path = domain.expect("dir entry").path();
        if !path.is_dir() {
            continue;
        }
        for entry in std::fs::read_dir(&path).expect("read domain module") {
            let candidate = entry.expect("dir entry").path();
            if candidate.is_file()
                && !candidate
                    .file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| allowed_domain_files.contains(&name))
            {
                offenders.push(candidate.strip_prefix(&root).unwrap().display().to_string());
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "domain roots may contain only shared domain files; put leaf commands/codecs/projectors in child event modules:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn event_module_files_use_only_standard_concern_names() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let event_root = root.join("src/protocol/event_modules");
    let allowed = [
        "actor.rs",
        "cli.rs",
        "codec.rs",
        "commands.rs",
        "crypto.rs",
        "mod.rs",
        "projector.rs",
        "queries.rs",
        "registry_meta.rs",
        "tables.rs",
        "types.rs",
    ];
    let offenders = rust_files(&event_root)
        .into_iter()
        .filter(|path| {
            !path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| allowed.contains(&name))
        })
        .map(|path| path.strip_prefix(root).unwrap().display().to_string())
        .collect::<Vec<_>>();

    assert!(
        offenders.is_empty(),
        "event modules use fixed concern filenames; split unusual concerns deliberately:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn child_event_module_directories_have_canonical_shape() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/protocol/event_modules");
    let mut offenders = Vec::new();
    for domain in std::fs::read_dir(&root).expect("read event modules") {
        let domain = domain.expect("dir entry").path();
        if !domain.is_dir() {
            continue;
        }
        for entry in std::fs::read_dir(&domain).expect("read domain") {
            let child = entry.expect("dir entry").path();
            if !child.is_dir() {
                continue;
            }
            for required in ["mod.rs", "types.rs", "codec.rs", "tables.rs"] {
                if !child.join(required).exists() {
                    offenders.push(format!(
                        "{}/{}",
                        child.strip_prefix(&root).unwrap().display(),
                        required
                    ));
                }
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "child directories under event_modules are canonical event modules; shared tables/queues belong at the domain root:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn event_modules_do_not_use_dumping_ground_directories() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/protocol/event_modules");
    let forbidden = ["jobs", "cli_commands", "runtime", "state", "negentropy"];
    let mut offenders = Vec::new();
    let mut pending = vec![root.clone()];
    while let Some(dir) = pending.pop() {
        for entry in std::fs::read_dir(&dir).expect("read event module dir") {
            let path = entry.expect("dir entry").path();
            if !path.is_dir() {
                continue;
            }
            if path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| forbidden.contains(&name))
            {
                offenders.push(path.strip_prefix(&root).unwrap().display().to_string());
            }
            pending.push(path);
        }
    }

    assert!(
        offenders.is_empty(),
        "event modules should be organized by domain/event type, not dumping-ground directories:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn actor_files_live_at_event_module_domain_roots() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let event_root = root.join("src/protocol/event_modules");
    let mut offenders = Vec::new();
    for path in rust_files(&event_root)
        .into_iter()
        .filter(|path| path.file_name().is_some_and(|name| name == "actor.rs"))
    {
        let parent = path.parent().expect("actor parent");
        if parent.parent() != Some(event_root.as_path()) {
            offenders.push(path.strip_prefix(root).unwrap().display().to_string());
        }
    }

    assert!(
        offenders.is_empty(),
        "domain actors live at event_modules/<domain>/actor.rs, not inside leaf event modules:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn codec_files_do_not_define_public_types() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let event_root = root.join("src/protocol/event_modules");
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
fn codec_files_use_shared_binary_helpers_and_finish_reads() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let event_root = root.join("src/protocol/event_modules");
    let mut violations = Vec::new();
    for path in rust_files(&event_root)
        .into_iter()
        .filter(|path| path.file_name().is_some_and(|name| name == "codec.rs"))
    {
        let text = source_text(&path);
        let relative = path.strip_prefix(root).unwrap().display();
        let manual_parse_needles = [
            ".copy_from_slice(&bytes[",
            "from_be_bytes(",
            "bytes.len() <",
            "bytes.len() !=",
        ];
        if manual_parse_needles
            .iter()
            .any(|needle| text.contains(needle))
            && !text.contains("Reader::new")
        {
            violations.push(format!("{relative} parses bytes without Reader"));
        }
        if text.contains("Reader::new") && !text.contains(".finish()?") {
            violations.push(format!("{relative} uses Reader without finish"));
        }
    }

    assert!(
        violations.is_empty(),
        "codec.rs should use shared fixed-field binary helpers and reject trailing bytes:\n{}",
        violations.join("\n")
    );
}

#[test]
fn codec_modules_have_type_files() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/protocol/event_modules");
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
fn commands_files_live_only_in_event_modules() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let event_root = root.join("src/protocol/event_modules");
    let offenders = rust_files(&root.join("src"))
        .into_iter()
        .filter(|path| path.file_name().is_some_and(|name| name == "commands.rs"))
        .filter(|path| !path.starts_with(&event_root))
        .map(|path| path.strip_prefix(root).unwrap().display().to_string())
        .collect::<Vec<_>>();

    assert!(
        offenders.is_empty(),
        "commands.rs is reserved for event modules; adapters should use cli.rs, flows.rs, or shell-specific names:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn cli_files_live_with_event_modules_or_the_protocol_shell() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let event_root = root.join("src/protocol/event_modules");
    let app_root = root.join("src/protocol/app");
    let offenders = rust_files(&root.join("src"))
        .into_iter()
        .filter(|path| path.file_name().is_some_and(|name| name == "cli.rs"))
        .filter(|path| !path.starts_with(&event_root) && !path.starts_with(&app_root))
        .map(|path| path.strip_prefix(root).unwrap().display().to_string())
        .collect::<Vec<_>>();

    assert!(
        offenders.is_empty(),
        "module CLI adapters belong beside event modules; only the generic protocol shell may own app-level CLI wiring:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn core_does_not_import_protocol() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let core_files = [
        "src/core/pipeline.rs",
        "src/core/control_loop.rs",
        "src/core/store.rs",
        "src/core/blocking.rs",
        "src/core/wire.rs",
    ];
    let mut violations = Vec::new();

    for file in core_files {
        let text = std::fs::read_to_string(root.join(file)).expect("read core file");
        for (line_idx, line) in text.lines().enumerate() {
            if line.contains("crate::protocol") {
                violations.push(format!("{file}:{}: {line}", line_idx + 1));
            }
        }
    }

    assert!(
        violations.is_empty(),
        "core must be protocol-agnostic; concrete protocols live under src/protocol:\n{}",
        violations.join("\n")
    );
}

#[test]
fn pipeline_has_no_protocol_branching_vocabulary() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let files = [root.join("src/core/pipeline.rs")];
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
fn core_has_no_protocol_io_vocabulary() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let core_root = root.join("src/core");
    let files = rust_files(&core_root);
    let forbidden = [
        "TransportSend",
        "Tcp",
        "socket",
        "inbound_bytes",
        "outbox",
        "connection_id",
        "transit",
    ];
    let violations = file_contains_violations(root, &files, &forbidden);
    assert!(
        violations.is_empty(),
        "protocol IO names belong under src/protocol, not src/core:\n{}",
        violations.join("\n")
    );
}

#[test]
fn core_has_no_domain_vocabulary() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let core_root = root.join("src/core");
    let files = rust_files(&core_root);
    let forbidden = [
        "workspace",
        "content",
        "endpoint",
        "identity",
        "invite",
        "bootstrap",
        "negentropy",
        "message",
        "reaction",
        "file_transfer",
    ];
    let violations = file_contains_violations(root, &files, &forbidden);
    assert!(
        violations.is_empty(),
        "domain vocabulary belongs under src/protocol/event_modules, not src/core:\n{}",
        violations.join("\n")
    );
}

#[test]
fn store_uses_generic_storage_vocabulary() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let files = [root.join("src/core/store.rs")];
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
    let sync_root = root.join("src/protocol/event_modules/sync");
    let files = rust_files(&sync_root);
    let forbidden = [
        "TcpStream",
        "TcpListener",
        "crate::protocol::network",
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
    let event_root = root.join("src/protocol/event_modules");
    let files = rust_files(&event_root)
        .into_iter()
        .filter(|path| path.file_name().is_some_and(|name| name == "commands.rs"))
        .collect::<Vec<_>>();
    let forbidden = [
        "use crate::core::store::Store",
        "&Store",
        "Store,",
        "Store)",
        "ProjectionOutput",
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
fn event_modules_do_not_import_runtime_pipeline_or_transport() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let event_root = root.join("src/protocol/event_modules");
    let files = rust_files(&event_root)
        .into_iter()
        .filter(|path| path != &event_root.join("mod.rs"))
        .collect::<Vec<_>>();
    let forbidden = [
        "crate::runtime",
        "crate::state",
        "crate::core::control_loop",
        "crate::core::pipeline",
        "drain_until_idle",
        "protocol::network",
        "TcpStream",
        "TcpListener",
        "read_frame",
        "write_frame",
        "NetworkOp",
        "StoreOp",
        "ProtocolEffect",
        "TransportSend",
    ];
    let violations = file_contains_violations(root, &files, &forbidden);
    assert!(
        violations.is_empty(),
        "event modules own protocol semantics, not runtime loops or transport implementation:\n{}",
        violations.join("\n")
    );
}

#[test]
fn event_module_projectors_do_not_query_storage_directly() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let event_root = root.join("src/protocol/event_modules");
    let files = rust_files(&event_root)
        .into_iter()
        .filter(|path| path.file_name().is_some_and(|name| name == "projector.rs"))
        .collect::<Vec<_>>();
    let forbidden = [
        "use crate::core::store::Store",
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
fn event_module_queries_are_read_only() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let event_root = root.join("src/protocol/event_modules");
    let files = rust_files(&event_root)
        .into_iter()
        .filter(|path| path.file_name().is_some_and(|name| name == "queries.rs"))
        .collect::<Vec<_>>();
    let forbidden = [
        "delete_table_rows",
        "insert_table_rows",
        "write_transaction",
        "insert_event",
        "set_event_status",
        "delete_dependency_wait",
    ];
    let violations = file_contains_violations(root, &files, &forbidden);
    assert!(
        violations.is_empty(),
        "queries.rs is read-only; mutations belong in actors or core write paths:\n{}",
        violations.join("\n")
    );
}

#[test]
fn event_module_projectors_do_not_do_transit_or_crypto_work() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let event_root = root.join("src/protocol/event_modules");
    let files = rust_files(&event_root)
        .into_iter()
        .filter(|path| path.file_name().is_some_and(|name| name == "projector.rs"))
        .collect::<Vec<_>>();
    let forbidden = ["transit", "crypto", "encrypt", "decrypt", "unwrap("];
    let violations = file_contains_violations(root, &files, &forbidden);
    assert!(
        violations.is_empty(),
        "projectors write rows; transit wrapping/unwrapping and crypto belong in commands/actors/helpers:\n{}",
        violations.join("\n")
    );
}

#[test]
fn event_module_projectors_are_row_only_boundaries() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let event_root = root.join("src/protocol/event_modules");
    let files = rust_files(&event_root)
        .into_iter()
        .filter(|path| path.file_name().is_some_and(|name| name == "projector.rs"))
        .collect::<Vec<_>>();
    let forbidden = [
        "CommandOutput",
        "ProposedEvent",
        "EventRecord {",
        "ProtocolEffect",
        "NetworkOp",
        "StoreOp",
        "TransportSend",
        "TcpStream",
        "TcpListener",
        "create_connection(",
        "create_bootstrap(",
    ];
    let violations = file_contains_violations(root, &files, &forbidden);
    assert!(
        violations.is_empty(),
        "projectors are row-only; emitting events/effects or doing transit work belongs in commands/actors:\n{}",
        violations.join("\n")
    );
}

#[test]
fn event_module_types_do_not_store_encoded_event_artifacts() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let event_root = root.join("src/protocol/event_modules");
    let files = rust_files(&event_root)
        .into_iter()
        .filter(|path| path.file_name().is_some_and(|name| name == "types.rs"))
        .collect::<Vec<_>>();
    let forbidden = ["canonical_bytes", "encoded_event", "wire_event"];
    let violations = file_contains_violations(root, &files, &forbidden);
    assert!(
        violations.is_empty(),
        "types.rs should define semantic shapes; canonical bytes live at codec/boundary layers:\n{}",
        violations.join("\n")
    );
}

#[test]
fn table_names_are_declared_in_tables_files() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let event_root = root.join("src/protocol/event_modules");
    let mut violations = Vec::new();
    for path in rust_files(&event_root) {
        if path.file_name().is_some_and(|name| name == "tables.rs") {
            continue;
        }
        let text = source_text(&path);
        if text.contains("table: \"") || text.contains("pub const ") && text.contains(": &str = \"")
        {
            violations.push(path.strip_prefix(root).unwrap().display().to_string());
        }
    }
    assert!(
        violations.is_empty(),
        "module table names belong in tables.rs, with projectors/queries using those declarations:\n{}",
        violations.join("\n")
    );
}

#[test]
fn event_records_are_constructed_only_by_codecs_or_core_tests() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let src_root = root.join("src");
    let store_file = root.join("src/core/store.rs").canonicalize().ok();
    let mut violations = Vec::new();
    for path in rust_files(&src_root) {
        let is_codec = path.file_name().is_some_and(|name| name == "codec.rs");
        let is_allowed_core = store_file == path.canonicalize().ok();
        if is_codec || is_allowed_core {
            continue;
        }
        if source_text(&path).contains("EventRecord {") {
            violations.push(path.strip_prefix(root).unwrap().display().to_string());
        }
    }
    assert!(
        violations.is_empty(),
        "EventRecord literals belong in codec constructors so metadata matches canonical bytes:\n{}",
        violations.join("\n")
    );
}

#[test]
fn command_output_contains_events_not_state_changes() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let text = std::fs::read_to_string(root.join("src/core/store.rs")).expect("read store");
    let start = text
        .find("pub struct CommandOutput")
        .expect("CommandOutput");
    let body = &text[start..text[start..].find("impl<T> CommandOutput").unwrap() + start];
    assert!(
        body.contains("pub events: Vec<ProposedEvent>") && !body.contains("ProjectionOutput"),
        "CommandOutput is command-facing and must carry proposed events only, not projector rows"
    );
}

#[test]
fn proposed_event_carries_deterministic_id_and_record() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let text = std::fs::read_to_string(root.join("src/core/store.rs")).expect("read store");
    let start = text
        .find("pub struct ProposedEvent")
        .expect("ProposedEvent");
    let body = &text[start..text[start..].find("impl ProposedEvent").unwrap() + start];
    assert!(
        body.contains("event_id: EventId")
            && body.contains("record: EventRecord")
            && !body.contains("pub event_id")
            && !body.contains("pub record"),
        "ProposedEvent must make deterministic ids part of the command contract"
    );
    assert!(
        text.contains("event_id(&record.canonical_bytes)"),
        "ProposedEvent ids must be derived from canonical event bytes"
    );
}

#[test]
fn projection_output_contains_rows_not_events() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let text = std::fs::read_to_string(root.join("src/core/store.rs")).expect("read store");
    let start = text
        .find("pub struct ProjectionOutput")
        .expect("ProjectionOutput");
    let body = &text[start..text[start..].find("impl ProjectionOutput").unwrap() + start];
    assert!(
        body.contains("pub rows: Vec<TableRow>")
            && !body.contains("EventRecord")
            && !body.contains("events"),
        "ProjectionOutput is projector-facing and must carry rows only, not events"
    );
}

#[test]
fn sync_event_module_does_not_use_session_message_vocabulary() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let sync_root = root.join("src/protocol/event_modules/sync");
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
        "src/core/pipeline.rs",
        "src/core/store.rs",
        "src/protocol/network.rs",
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
        "sync protocol logic belongs in protocol/event_modules/sync:\n{}",
        violations.join("\n")
    );
}

#[test]
fn protocol_network_remains_tcp_framing_only() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let files = [root.join("src/protocol/network.rs")];
    let forbidden = [
        "EventRecord",
        "event_id",
        "canonical",
        "connection_id",
        "transit",
        "bootstrap",
        "outbox",
        "negentropy",
        "Compare",
        "Have",
        "Need",
    ];
    let violations = file_contains_violations(root, &files, &forbidden);
    assert!(
        violations.is_empty(),
        "protocol/network.rs owns TCP framing only; protocol bytes are produced by event modules:\n{}",
        violations.join("\n")
    );
}

#[test]
fn protocol_app_and_protocol_actors_do_not_import_event_families_directly() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let files = rust_files(&root.join("src/protocol/app"))
        .into_iter()
        .chain([root.join("src/protocol/actors.rs")])
        .collect::<Vec<_>>();
    let forbidden = [
        "crate::protocol::event_modules::connection",
        "crate::protocol::event_modules::content",
        "crate::protocol::event_modules::identity",
        "crate::protocol::event_modules::sync",
        "crate::protocol::event_modules::test_events",
    ];
    let violations = file_contains_violations(root, &files, &forbidden);
    assert!(
        violations.is_empty(),
        "app/protocol actors may call the protocol registry, not concrete event families:\n{}",
        violations.join("\n")
    );
}

#[test]
fn source_does_not_contain_fake_crypto_claims() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let this_file = root
        .join("tests/rules_boundary_test.rs")
        .canonicalize()
        .ok();
    let files = rust_files(&root.join("src"))
        .into_iter()
        .chain(rust_files(&root.join("tests")))
        .filter(|path| path.canonicalize().ok() != this_file)
        .collect::<Vec<_>>();
    let forbidden = [
        "fake crypto",
        "fake encryption",
        "pass-through encryption",
        "identity cipher",
        "encrypted in name only",
        "toy encryption",
    ];
    let violations = file_contains_violations(root, &files, &forbidden);
    assert!(
        violations.is_empty(),
        "do not name fake or placeholder crypto as real protection:\n{}",
        violations.join("\n")
    );
}

#[test]
fn core_storage_and_transport_do_not_own_connection_or_bootstrap_schema() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let files = ["src/core/store.rs", "src/protocol/network.rs"];
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
        "connection/bootstrap storage belongs in protocol/event_modules/connection:\n{}",
        violations.join("\n")
    );
}
