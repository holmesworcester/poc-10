use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

fn rust_files(root: &Path) -> Vec<PathBuf> {
    let mut pending = vec![root.to_path_buf()];
    let mut files = Vec::new();
    while let Some(dir) = pending.pop() {
        for entry in std::fs::read_dir(&dir).expect("read dir") {
            let path = entry.expect("dir entry").path();
            if path.is_dir() {
                if path.file_name().is_some_and(|name| name == "target") {
                    continue;
                }
                pending.push(path);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                files.push(path);
            }
        }
    }
    files
}

fn source_files(root: &Path) -> Vec<PathBuf> {
    let mut pending = vec![root.to_path_buf()];
    let mut files = Vec::new();
    while let Some(dir) = pending.pop() {
        for entry in std::fs::read_dir(&dir).expect("read dir") {
            let path = entry.expect("dir entry").path();
            if path.is_dir() {
                if path.file_name().is_some_and(|name| name == "target") {
                    continue;
                }
                pending.push(path);
            } else {
                files.push(path);
            }
        }
    }
    files
}

fn source_text(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()))
}

fn source_matches_in_paths(root: &Path, paths: Vec<PathBuf>, needles: &[&str]) -> Vec<String> {
    let mut matches = Vec::new();
    for path in paths {
        let text = source_text(&path);
        for (line_index, line) in text.lines().enumerate() {
            for needle in needles {
                if line.contains(needle) {
                    matches.push(format!(
                        "{}:{} contains {needle:?}",
                        path.strip_prefix(root).unwrap().display(),
                        line_index + 1
                    ));
                }
            }
        }
    }
    matches.sort();
    matches.dedup();
    matches
}

fn source_code_matches_in_paths(root: &Path, paths: Vec<PathBuf>, needles: &[&str]) -> Vec<String> {
    let mut matches = Vec::new();
    for path in paths {
        let text = source_text(&path);
        let mut pending_test_cfg = false;
        let mut skip_test_module = false;
        let mut brace_depth = 0usize;
        for (line_index, line) in text.lines().enumerate() {
            if skip_test_module {
                brace_depth += line.matches('{').count();
                brace_depth = brace_depth.saturating_sub(line.matches('}').count());
                if brace_depth == 0 {
                    skip_test_module = false;
                }
                continue;
            }
            let trimmed = line.trim_start();
            if trimmed.starts_with("#[cfg(test)]") {
                pending_test_cfg = true;
                continue;
            }
            if pending_test_cfg && trimmed.starts_with("mod ") && line.contains('{') {
                skip_test_module = true;
                pending_test_cfg = false;
                brace_depth = line.matches('{').count();
                brace_depth = brace_depth.saturating_sub(line.matches('}').count());
                continue;
            }
            pending_test_cfg = false;
            if trimmed.starts_with("//") {
                continue;
            }
            let code = line.split_once("//").map_or(line, |(code, _)| code);
            for needle in needles {
                if code.contains(needle) {
                    matches.push(format!(
                        "{}:{} contains {needle:?}",
                        path.strip_prefix(root).unwrap().display(),
                        line_index + 1
                    ));
                }
            }
        }
    }
    matches.sort();
    matches.dedup();
    matches
}

fn broad_read_counts(root: &Path) -> Vec<String> {
    let mut paths = rust_files(&root.join("src"));
    paths.extend(rust_files(&root.join("tests")));
    let mut counts = BTreeMap::<String, usize>::new();
    for path in paths {
        let relative = path.strip_prefix(root).unwrap().display().to_string();
        if matches!(
            relative.as_str(),
            "tests/poc10_architecture_boundary_test.rs" | "tests/poc10_cutover_todo_test.rs"
        ) {
            continue;
        }
        let text = source_text(&path);
        for line in text.lines() {
            let trimmed = line.trim_start();
            if trimmed.starts_with("//") {
                continue;
            }
            let code = line.split_once("//").map_or(line, |(code, _)| code);
            for needle in [
                "persisted_facts(",
                "runtime.facts()",
                ".fact_page(",
                ".table_rows(",
                "pub fn fact_page(&self",
                "pub fn table_rows(&self",
                "pub fn facts(&self) -> impl Iterator<Item = Fact>",
            ] {
                let count = code.matches(needle).count();
                if count > 0 {
                    *counts.entry(format!("{relative}::{needle}")).or_default() += count;
                }
            }
        }
        let needle = ".table_rows_with_key_prefix(";
        let mut offset = 0usize;
        while let Some(found) = text[offset..].find(needle) {
            let start = offset + found;
            let end = text.len().min(start + 260);
            if text[start..end].contains("usize::MAX") {
                *counts
                    .entry(format!(
                        "{relative}::table_rows_with_key_prefix(...usize::MAX)"
                    ))
                    .or_default() += 1;
            }
            offset = start + needle.len();
        }
    }
    counts
        .into_iter()
        .map(|(key, count)| format!("{key} = {count}"))
        .collect()
}

const PROTOCOL_SCOPES: [&str; 4] = ["auth", "connection", "content", "sync"];

/// The verb-named intent handler files that live directly inside each scope
/// directory. Everything else under a scope directory is fact-module code.
fn intent_handler_files(root: &Path) -> Vec<PathBuf> {
    let handlers: [(&str, &[&str]); 4] = [
        ("auth", &[]),
        (
            "connection",
            &[
                "create_connection.rs",
                "send_facts_on_connection.rs",
                "queue_outgoing_frame.rs",
            ],
        ),
        ("content", &[]),
        (
            "sync",
            &[
                "seed_connection.rs",
                "send_compare_response.rs",
                "send_needed_fact_id.rs",
                "send_requested_fact.rs",
                "share_fact_with_sync.rs",
            ],
        ),
    ];
    handlers
        .into_iter()
        .flat_map(|(scope, files)| {
            files
                .iter()
                .map(move |file| root.join("src/protocol").join(scope).join(file))
        })
        .collect()
}

/// Scans every protocol scope directory for fact-module files, excluding the
/// verb-named intent handler files that also live there.
fn fact_module_files(root: &Path) -> Vec<PathBuf> {
    let intents = intent_handler_files(root);
    PROTOCOL_SCOPES
        .into_iter()
        .flat_map(|scope| source_files(&root.join("src/protocol").join(scope)))
        .filter(|path| !intents.contains(path))
        .collect()
}

fn target_projector_files(root: &Path) -> Vec<PathBuf> {
    fact_module_files(root)
        .into_iter()
        .filter(|path| {
            if path.extension().is_none_or(|ext| ext != "rs") {
                return false;
            }
            let relative = path.strip_prefix(root).unwrap().display().to_string();
            relative.ends_with("/project.rs") || relative.contains("/project/")
        })
        .collect()
}

fn meaningful_manifest_lines(text: &str) -> Vec<&str> {
    text.lines()
        .map(str::trim)
        .filter(|line| {
            !line.is_empty()
                && !line.starts_with("//")
                && !line.starts_with("//!")
                && !line.starts_with("///")
        })
        .collect()
}

#[test]
fn poc10_success_criteria_are_recorded_in_architecture_doc() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let doc = source_text(&root.join("README.md"));
    let normalized = doc.split_whitespace().collect::<Vec<_>>().join(" ");
    let required = [
        "## Architecture Principles",
        "src/core/command.rs",
        "src/protocol.rs",
        "src/protocol/<scope>.rs",
        "generic runtime/app mechanics",
        "src/core/schema.rs",
        "src/core/network.rs",
        "src/protocol/registry.rs",
        "## Runtime Shape",
        "Protocol manifests declare their commands, fact families, intent handlers, schemas, and daemon hooks",
        "app assembles those declarations into a `ProtocolDescription`",
        "Core uses that description to build the `con` CLI",
        "without hard-coding their names or behavior",
        "Runtime turns are serialized per database to avoid races between command-created facts and ongoing projection or intent activity",
        "a command cannot admit facts while another turn is draining pending facts, matching context, committing projector output, or running handlers",
        "## Scope Layout",
        "Fact families are organized by protocol scope",
        "The grouping is mostly arbitrary to core",
        "scopes act like module-like families",
        "give each group a clear realm of responsibility",
        "## Protocol Function Boundaries",
        "### Projectors",
        "### Intent Handlers",
        "### Wire Layouts And Codecs",
        "### Connection Frames",
        "This keeps core's network interface minimal",
        "Core owns TCP accept/write mechanics, the volatile outgoing frame queue, and the active-target scheduling index",
        "the daemon stages accepted bytes in the core incoming queue",
        "the connection scope classifies the frame, emits the right incoming wrapper fact",
        "incoming metadata plus auth or connection context",
        "Opened payloads re-enter projection as incoming child facts",
        "receipt or observation facts record which connection delivered retained facts plus replay-safe origin metadata",
        "Sync may decide that a fact id should be sent to an authorized connection",
        "the connection scope decides how to load, filter, batch, seal, and address those facts as connection frames",
        "Handlers that already know the peer address queue opaque bytes directly in `network_outgoing`",
        "it emits `queue_outgoing_frame`",
        "Core's daemon pump schedules active target addresses, writes length-prefixed frames",
        "Connection rows and receipt facts preserve the durable relationship",
        "### Simplicity Guardrails",
    ];

    let missing = required
        .into_iter()
        .filter(|needle| !normalized.contains(needle))
        .collect::<Vec<_>>();
    assert!(
        missing.is_empty(),
        "README.md is missing poc-10 success criteria:\n{}",
        missing.join("\n")
    );

    assert!(
        !doc.contains("## Rules"),
        "README.md should keep architecture description separate from rules"
    );
}

#[test]
fn poc10_core_contract_files_are_present() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let required = [
        "src/core/command.rs",
        "src/core/runtime.rs",
        "src/core/facts.rs",
        "src/core/context.rs",
        "src/core/intents.rs",
        "src/core/project_fact.rs",
        "src/core/handle_intent.rs",
        "src/core/db.rs",
    ];

    let missing = required
        .into_iter()
        .filter(|path| !root.join(path).is_file())
        .collect::<Vec<_>>();

    assert!(
        missing.is_empty(),
        "missing poc-10 core contract files:\n{}",
        missing.join("\n")
    );
}

#[test]
fn poc10_pipeline_work_items_live_in_named_core_files() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let project_fact = source_text(&root.join("src/core/project_fact.rs"));
    let handle_intent = source_text(&root.join("src/core/handle_intent.rs"));

    assert!(
        !root.join("src/core/pipeline.rs").exists(),
        "src/core/pipeline.rs is retired; keep projection and intent workers in named core files"
    );

    for required in [
        "Run and commit one queued projection item",
        "commit_projection_effects",
        "load_pending_fact",
        "ProjectionSource",
    ] {
        assert!(
            project_fact.contains(required),
            "src/core/project_fact.rs is missing projection work-item detail {required:?}"
        );
    }

    for required in [
        "Run one claimed intent through its handler",
        "run_and_commit_loaded_intent",
        "next_queued_intent",
        "insert_intent_in_tx",
    ] {
        assert!(
            handle_intent.contains(required),
            "src/core/handle_intent.rs is missing intent work-item detail {required:?}"
        );
    }
}

#[test]
fn poc10_root_exports_protocol_owned_manifests() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));

    for forbidden in [
        "src/commands.rs",
        "src/commands",
        "src/event_modules.rs",
        "src/event_modules",
        "src/handlers.rs",
        "src/handlers",
    ] {
        assert!(
            !root.join(forbidden).exists(),
            "{forbidden} should not exist; command primitives belong in core and concrete protocol modules live under src/protocol"
        );
    }

    assert!(
        !root.join("src/core/command_context.rs").exists(),
        "src/core/command_context.rs should not reappear"
    );
    assert!(
        root.join("src/core/command.rs").is_file(),
        "missing src/core/command.rs"
    );
    for scope in PROTOCOL_SCOPES {
        let required = format!("src/protocol/{scope}.rs");
        assert!(root.join(&required).is_file(), "missing {required}");
    }

    let lib = source_text(&root.join("src/lib.rs"));
    for required in ["pub mod context_app;", "pub mod core;", "pub mod protocol;"] {
        assert!(
            lib.contains(required),
            "src/lib.rs must expose only root crate manifests: missing {required}"
        );
    }
}

#[test]
fn poc10_has_no_product_demo_or_smoke_command_surface() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));

    for forbidden in [
        "src/demo.rs",
        "src/demo",
        "examples/match_demo.rs",
        "examples/con_demo.rs",
        "tests/match_smoke.rs",
        "tests/con_smoke.rs",
    ] {
        assert!(
            !root.join(forbidden).exists(),
            "{forbidden} should not exist; smoke coverage belongs in black-box CLI tests"
        );
    }

    let app = source_text(&root.join("src/context_app.rs"));
    let forbidden = ["Some(\"demo\")", "\"demo\"", "Some(\"smoke\")", "\"smoke\""];
    let offenders = forbidden
        .into_iter()
        .filter(|needle| app.contains(needle))
        .collect::<Vec<_>>();
    assert!(
        offenders.is_empty(),
        "the product CLI should not expose demo/smoke commands: {}",
        offenders.join(", ")
    );
}

#[test]
fn poc10_projector_output_contract_emits_context_time_wakes_and_intents() {
    let topo::core::project_fact::ProjectionOutput {
        retain_self,
        needs,
        offers,
        time_wakes,
        effects,
    } = topo::core::project_fact::ProjectionOutput::default();

    assert!(retain_self);
    assert!(needs.is_empty());
    assert!(offers.is_empty());
    assert!(time_wakes.is_empty());
    assert!(effects.row_mutations.is_empty());
    assert!(effects.intents.is_empty());
    assert!(effects.local_intents.is_empty());
}

#[test]
fn poc10_runtime_effects_names_the_common_commit_shape() {
    let topo::core::effects::RuntimeEffects {
        storage_requirement,
        facts,
        priority_facts,
        incoming_facts,
        incoming_fact_metadata,
        purged_facts,
        row_mutations,
        intents,
        local_intents,
        rebuild_derived_state,
    } = topo::core::effects::RuntimeEffects::new();

    assert_eq!(
        storage_requirement,
        topo::core::effects::StorageRequirement::MaintenanceBypass
    );
    assert!(facts.is_empty());
    assert!(priority_facts.is_empty());
    assert!(incoming_facts.is_empty());
    assert!(incoming_fact_metadata.is_empty());
    assert!(purged_facts.is_empty());
    assert!(row_mutations.is_empty());
    assert!(intents.is_empty());
    assert!(local_intents.is_empty());
    assert!(!rebuild_derived_state);
}

#[test]
fn poc10_authored_facts_is_receipt_plus_facts_only() {
    let topo::core::command::AuthoredFacts { receipt, facts } =
        topo::core::command::AuthoredFacts::new(());

    assert_eq!(receipt, ());
    assert!(facts.is_empty());

    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let command = root.join("src/core/command.rs");
    let source = source_text(&command);
    for required in [
        "pub struct AuthoredFacts<T>",
        "pub receipt: T",
        "pub facts: Vec<Fact>",
    ] {
        assert!(
            source.contains(required),
            "authored facts contract is missing {required:?}"
        );
    }

    let offenders = source_code_matches_in_paths(
        root,
        vec![command],
        &[
            "RuntimeEffects",
            "pub effects:",
            "row_mutations",
            "purged_facts",
            "intents:",
            "local_intents",
        ],
    );
    assert!(
        offenders.is_empty(),
        "commands must author only facts plus receipts, not full runtime effects:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn poc10_protocol_apis_do_not_hide_runtime_work_or_read_models() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let api_files = rust_files(&root.join("src/protocol"))
        .into_iter()
        .filter(|path| path.file_name().is_some_and(|name| name == "api.rs"))
        .collect::<Vec<_>>();

    let runtime_offenders = source_code_matches_in_paths(
        root,
        api_files.clone(),
        &[
            "use crate::core::runtime::Runtime",
            "RuntimeEffects",
            "RowMutation",
            "Intent::new",
            "submit_",
            "process_all_work",
            "drain_",
            "write_transaction",
            "commit_runtime_effects",
        ],
    );
    assert!(
        runtime_offenders.is_empty(),
            "simple protocol APIs must only query, author facts, and return receipts; runtime work belongs in Runtime, daemon, handlers, projectors, or explicit workflows:\n{}",
        runtime_offenders.join("\n")
    );

    let read_model_offenders = source_code_matches_in_paths(
        root,
        api_files,
        &[
            "pub struct KeyWrapQuery",
            "pub struct KeyAccessQuery",
            "pub struct KeyAccessStatus",
            "pub struct KeyStatusReport",
            "pub struct StatusReport",
            "pub fn lookup_",
            "pub fn key_access",
            "pub fn key_status_report",
            "pub fn status_report",
            "pub fn key_wrap_count",
            "pub fn local_key_secret_count",
            "pub fn count_messages_below_minute",
        ],
    );
    assert!(
        read_model_offenders.is_empty(),
        "command modules must not expose read-model lookup/status/count APIs; put those in the owning queries.rs:\n{}",
        read_model_offenders.join("\n")
    );
}

#[test]
fn poc10_sql_only_migration_does_not_add_broad_reads() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let observed = broad_read_counts(root);

    assert_eq!(
        observed,
        Vec::<String>::new(),
        "broad fact/row scans must stay out of runtime and protocol code"
    );
}

#[test]
fn poc10_runtime_route_vocabulary_has_no_old_pipeline_dto_names() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let offenders = source_code_matches_in_paths(
        root,
        rust_files(&root.join("src")),
        &[
            "PipelineEffects",
            "FactPipeline",
            "pipeline_effects",
            "commit_pipeline_effects",
            "validate_pipeline_effects",
            "from_pipeline",
        ],
    );

    assert!(
        offenders.is_empty(),
        "live source should use RuntimeEffects and FactProjectorInfo, not retired pipeline DTO names:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn poc10_core_workers_expose_protocol_neutral_vocabulary() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let worker_paths = vec![
        root.join("src/core/project_fact.rs"),
        root.join("src/core/handle_intent.rs"),
    ];
    let text = worker_paths
        .iter()
        .map(|path| source_text(path))
        .collect::<Vec<_>>()
        .join("\n");
    let required_terms = [
        (
            "pending projection",
            &[
                "PendingProjection",
                "pending_projection",
                "pending projection",
            ][..],
        ),
        (
            "context wake fanout",
            &[
                "ContextWake",
                "context_wake",
                "context_wakes",
                "context wake",
                "wake_context_matches",
            ][..],
        ),
        (
            "intent output",
            &[
                "handler output",
                "dispatch_one_intent",
                "commit_handler_output",
            ][..],
        ),
    ];
    let missing = required_terms
        .into_iter()
        .filter_map(|(term, spellings)| {
            (!spellings.iter().any(|spelling| text.contains(spelling))).then_some(term)
        })
        .collect::<Vec<_>>();
    assert!(
        missing.is_empty(),
        "core projection/intent workers must expose protocol-neutral runtime vocabulary:\n{}",
        missing.join("\n")
    );

    let forbidden = [
        "EventStatus",
        "EventStatusCounts",
        "ready_events",
        "blocked_events_by_missing_dep",
        "missing_deps_by_blocked_event",
        "dependents_by_dep",
        "deps_by_dependent",
        "pending_reprojections",
        "recently_valid_events",
        "event_receive_context",
        "applied_shared_facts",
        "dependency_updates",
        "context_updates",
        "canonical.in",
        "sync.in",
        "transport::connection_frame.out",
        "content.purge_instructions",
        "encryption.pending_key_requests",
        "encryption.pending_key_unwraps",
        "encryption.pending_wrap_reconcile",
        "encryption.negentropy_pending_purges",
        "connection.pending_connection_attempts",
        "connection.pending_connections",
        "canonical_in",
        "connection_frame_out",
        "purge_instructions",
        "pending_key_requests",
        "pending_key_unwraps",
        "pending_wrap_reconcile",
        "negentropy_pending_purges",
        "pending_connection_attempts",
        "pending_connections",
    ];
    let offenders = source_matches_in_paths(root, worker_paths, &forbidden);
    assert!(
        offenders.is_empty(),
        "core projection/intent workers must not expose old worker queue or event status vocabulary:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn poc10_target_has_no_mod_rs_files() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let offenders = rust_files(&root.join("src"))
        .into_iter()
        .filter(|path| path.file_name().is_some_and(|name| name == "mod.rs"))
        .map(|path| path.strip_prefix(root).unwrap().display().to_string())
        .collect::<Vec<_>>();

    assert!(
        offenders.is_empty(),
        "poc-10 target has no mod.rs files; use root manifest files instead:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn poc10_target_has_no_per_module_schema_or_codec_files() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let forbidden = ["schema.rs", "codec.rs"];
    let offenders = rust_files(&root.join("src"))
        .into_iter()
        .filter(|path| path.strip_prefix(root).ok() != Some(Path::new("src/core/schema.rs")))
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| forbidden.contains(&name))
        })
        .map(|path| path.strip_prefix(root).unwrap().display().to_string())
        .collect::<Vec<_>>();

    assert!(
        offenders.is_empty(),
        "poc-10 target forbids per-module schema.rs and codec.rs files:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn poc10_target_source_has_no_old_event_status_blocker_label_queue_names() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let forbidden = [
        "EventStatus",
        "EventStatusCounts",
        "event_modules.ready_events",
        "event_modules.blocked_events_by_missing_dep",
        "event_modules.missing_deps_by_blocked_event",
        "event_modules.dependents_by_dep",
        "event_modules.deps_by_dependent",
        "event_modules.context_updates",
        "event_modules.pending_reprojections",
        "event_modules.recently_valid_events",
        "event_modules.event_receive_context",
        "event_modules.applied_shared_facts",
        "ready_events",
        "blocked_events_by_missing_dep",
        "missing_deps_by_blocked_event",
        "dependents_by_dep",
        "deps_by_dependent",
        "pending_reprojections",
        "recently_valid_events",
        "event_receive_context",
        "applied_shared_facts",
        "dependency_updates",
        "context_updates",
        "updates",
    ];
    let target_paths = std::iter::once("src/core".to_string())
        .chain(
            PROTOCOL_SCOPES
                .iter()
                .map(|scope| format!("src/protocol/{scope}")),
        )
        .flat_map(|path| source_files(&root.join(path)))
        .collect::<Vec<_>>();
    // Legacy worker-queue/event-status names are removal vocabulary that the
    // architecture docs explicitly still permit in documentation; the boundary
    // here forbids them in target *code*.
    let offenders = source_code_matches_in_paths(root, target_paths, &forbidden);

    assert!(
        offenders.is_empty(),
        "poc-10 target source should use facts plus needs/offers instead of old event status, blocker, label, and receive queues:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn poc10_target_source_has_no_old_worker_queue_names() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let forbidden = [
        "canonical.in",
        "sync.in",
        "transport::connection_frame.out",
        "content.purge_instructions",
        "encryption.pending_key_requests",
        "encryption.pending_key_unwraps",
        "encryption.pending_wrap_reconcile",
        "encryption.negentropy_pending_purges",
        "connection.pending_connection_attempts",
        "connection.pending_connections",
        "canonical_in",
        "connection_frame_out",
        "purge_instructions",
        "pending_key_requests",
        "pending_key_unwraps",
        "pending_wrap_reconcile",
        "negentropy_pending_purges",
        "pending_connection_attempts",
        "pending_connections",
    ];
    let target_paths = std::iter::once("src/core".to_string())
        .chain(
            PROTOCOL_SCOPES
                .iter()
                .map(|scope| format!("src/protocol/{scope}")),
        )
        .flat_map(|path| source_files(&root.join(path)))
        .collect::<Vec<_>>();
    let offenders = source_code_matches_in_paths(root, target_paths, &forbidden);

    assert!(
        offenders.is_empty(),
        "poc-10 target source should route old worker queues through core intents instead:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn poc10_architecture_docs_describe_required_runtime_work_surfaces() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let architecture = source_text(&root.join("README.md"));
    let rules = source_text(&root.join("docs/RULES.md"));
    let docs = format!("{architecture}\n{rules}")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");

    for required in [
        "Production work is represented with immutable facts",
        "standing context",
        "time-wake schedules",
        "pending projection",
        "durable intents",
        "ephemeral intents",
        "The declared runtime work surface is complete",
        "production state enters as facts, context, time wakes, intents, or schema-owned rows",
        "facts, context, time wakes, intents, or schema-owned rows",
    ] {
        assert!(
            docs.contains(required),
            "architecture docs must describe required runtime work surfaces: {required}"
        );
    }
}

#[test]
fn poc10_target_projectors_emit_only_needs_offers_self_purge_and_intents() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let projector_paths = target_projector_files(root);
    assert!(
        !projector_paths.is_empty(),
        "scan target src/protocol/<scope>/**/project.rs files"
    );
    let forbidden = [
        "ProjectionOutput::rows",
        "ProjectionOutput::labels",
        "ProjectionOutput::rows_and_labels",
        "ProjectionOutput::deletes",
        "ProjectionOutput::deletes_and_labels",
        "rows_and_labels",
        "deletes_and_labels",
        "pub rows:",
        "pub deletes:",
        "pub updates:",
        "pub labels:",
        ".rows",
        ".deletes",
        ".updates",
        ".labels",
    ];
    let offenders = source_code_matches_in_paths(root, projector_paths, &forbidden);

    assert!(
        offenders.is_empty(),
        "poc-10 target projectors should emit only needs, offers, row mutations, self-purge, and intents; rows, deletes, and labels must go through projector output helpers, not ad hoc fields:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn poc10_accept_commands_leave_bootstrap_effects_to_projection() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let accept_api = source_text(&root.join("src/protocol/auth/invite_secret/api.rs"));
    let request_projector = source_text(&root.join("src/protocol/connection/request/project.rs"));
    let maintenance = source_text(&root.join("src/protocol/connection/maintain_connections.rs"));

    assert!(
        !accept_api.contains("queue_outgoing_frame_intent"),
        "accept/link commands should create acceptance facts, not enqueue bootstrap IO directly"
    );
    assert!(
        !accept_api.contains("create_bootstrap"),
        "accept/link commands should not create bootstrap request facts directly"
    );
    assert!(
        maintenance.contains("network::queue_outgoing"),
        "the live maintenance loop should queue bootstrap IO for unanswered local requests"
    );
    assert!(
        !request_projector.contains("queue_outgoing_frame_intent"),
        "request sends are driven by the maintenance loop so they survive replay; the request projector must not emit them"
    );
}

#[test]
fn poc10_connection_request_projection_excludes_wire_transport() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let request_projector = root.join("src/protocol/connection/request/project.rs");

    // There is no sealed-envelope fact: the request fact is itself the sealed
    // wire payload. The request projector must stay on request admission and
    // retry-row materialization, not transport boundary handling.
    let request_wrapper_offenders = source_code_matches_in_paths(
        root,
        vec![request_projector],
        &[
            "open_connection_request",
            "seal_connection_request",
            "received_connection_request_fact_effect",
            "TYPE_SEALED_CONNECTION_REQUEST",
        ],
    );
    assert!(
        request_wrapper_offenders.is_empty(),
        "request projection must stay on the request fact; wire receive classification belongs to receive_network_frame:\n{}",
        request_wrapper_offenders.join("\n")
    );
}

#[test]
fn poc10_protocol_cli_hosts_use_core_opened_runtime_and_return_output() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let protocol_cli = root.join("src/protocol/cli.rs");
    let offenders = source_code_matches_in_paths(
        root,
        vec![protocol_cli],
        &["Runtime::open_disk", "println!", "app_cli_command", "_flow"],
    );

    assert!(
        offenders.is_empty(),
        "protocol CLI hosts should use the core-opened runtime, return CliOutput for core to print, and avoid compatibility wrapper command flows:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn poc10_target_projectors_do_not_write_store_rows_directly() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let projector_paths = target_projector_files(root);
    let forbidden = [
        "crate::core::db",
        "core::db",
        "Db",
        "rusqlite",
        ".write_transaction(",
        ".insert_table_rows(",
        ".insert_table_rows_in_tx(",
        ".delete_table_rows(",
        ".delete_table_rows_in_tx(",
        ".execute(",
        ".execute_batch(",
        ".prepare(",
        ".query(",
        ".query_row(",
        ".query_map(",
    ];
    let offenders = source_code_matches_in_paths(root, projector_paths, &forbidden);

    assert!(
        offenders.is_empty(),
        "poc-10 target projectors must not write store rows directly; emit RowMutation values through ProjectionOutput::effects instead:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn poc10_runtime_does_not_synthesize_shareable_facts() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let app = root.join("src/protocol/app.rs");
    let offenders = source_code_matches_in_paths(
        root,
        vec![app],
        &[
            "shareable_workspace_id",
            "share_fact_with_sync_intent_for_fact",
            "share_fact_with_sync_intent(",
            "ShareFactWithSync {",
        ],
    );

    assert!(
        offenders.is_empty(),
        "runtime routing must not decide which facts are workspace-shareable; projectors emit share_fact_with_sync intents at the fact boundary:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn poc10_sync_paths_use_shareable_index_for_advertised_facts() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let paths = [
        "src/protocol/sync/send_compare_response.rs",
        "src/protocol/sync/send_requested_fact.rs",
    ]
    .into_iter()
    .map(|path| root.join(path))
    .collect::<Vec<_>>();
    let offenders = source_code_matches_in_paths(
        root,
        paths,
        &[
            "persisted_facts(",
            "is_sync_seed_fact",
            "may_seed_fact_to_endpoint",
        ],
    );

    assert!(
        offenders.is_empty(),
        "sync advertisement and response paths must use sync contribution rows, not persisted fact scans or runtime shareability filters:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn poc10_concrete_protocol_routes_semantic_messages() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let registry = source_text(&root.join("src/protocol/registry.rs"));
    let receive = [
        "src/protocol/connection/receive_network_frame.rs",
        "src/protocol/connection/frame_small/project.rs",
        "src/protocol/connection/frame_file_slice/project.rs",
        "src/protocol/connection/frame_bundle/project.rs",
    ]
    .into_iter()
    .map(|path| source_text(&root.join(path)))
    .collect::<Vec<_>>()
    .join("\n");

    for required in [
        "content::message",
        "TYPE_CONTENT_MESSAGE",
        "ContentMessageProjector",
        "content::message_deletion",
        "TYPE_CONTENT_MESSAGE_DELETION",
        "ContentMessageDeletionProjector",
    ] {
        assert!(
            registry.contains(required) || receive.contains(required),
            "normal poc-10 messages must route through semantic content::message facts; missing {required}"
        );
    }
    assert!(registry.contains("CONTENT_MESSAGE_ROWS"));
    assert!(registry.contains("MESSAGE_DELETION_ROWS"));
    assert!(
        !registry.contains("module: \"content::sealed_message\""),
        "sealed-message compatibility module must not be registered"
    );
    assert!(
        !registry.contains("TYPE_SEALED_MESSAGE") && !registry.contains("project_sealed_message"),
        "protocol registry must not route sealed-message wrappers"
    );
    assert!(
        !receive.contains("content::sealed_message::TYPE_SEALED_MESSAGE")
            && !receive.contains("admit_sealed_message_fact"),
        "connection frame admission must accept semantic content::message facts, not sealed-message wrappers"
    );
}

#[test]
fn poc10_protocol_cli_files_do_not_touch_filesystem_directly() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let cli_files = PROTOCOL_SCOPES
        .into_iter()
        .flat_map(|scope| rust_files(&root.join("src/protocol").join(scope)))
        .filter(|path| path.file_name().is_some_and(|name| name == "cli.rs"))
        .collect::<Vec<_>>();
    let offenders = source_code_matches_in_paths(
        root,
        cli_files,
        &[
            "std::fs",
            "fs::read",
            "fs::write",
            "File::",
            ".read_to_end(",
            ".write_all(",
        ],
    );

    assert!(
        offenders.is_empty(),
        "protocol CLI adapters parse arguments and format output; local file IO must go through core-owned helpers or intent handlers:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn poc10_target_uses_explicit_schema_sources_not_schema_dsl_files() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut pending = vec![root.join("src")];
    let mut found = Vec::new();
    while let Some(dir) = pending.pop() {
        for entry in std::fs::read_dir(&dir).expect("read dir") {
            let path = entry.expect("dir entry").path();
            if path.is_dir() {
                pending.push(path);
            } else if path.extension().is_some_and(|ext| ext == "p8sql") {
                found.push(path.strip_prefix(root).unwrap().display().to_string());
            }
        }
    }
    found.sort();

    assert!(
        found.is_empty(),
        "poc-10 keeps storage visible as explicit SQL DDL in SchemaSource constants, not separate schema DSL files:\n{}",
        found.join("\n")
    );
    assert!(
        !root.join("src/core/schema_dsl.rs").exists(),
        "the runtime schema DSL parser should not come back"
    );

    let core_schema = source_text(&root.join("src/core/schema.rs"));
    let network = source_text(&root.join("src/core/network.rs"));
    let registry = source_text(&root.join("src/protocol/registry.rs"));
    for (path, text, required) in [
        (
            "src/core/schema.rs",
            core_schema,
            "pub const CORE_SCHEMA_SOURCE: SchemaSource",
        ),
        (
            "src/core/network.rs",
            network,
            "pub const SCHEMA_SOURCE: SchemaSource",
        ),
        (
            "src/protocol/registry.rs",
            registry,
            "pub const FACTS_SCHEMA_SOURCE: SchemaSource",
        ),
    ] {
        assert!(text.contains(required), "{path} missing {required}");
    }
}

#[test]
fn poc10_target_has_no_dumping_ground_filenames() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let forbidden = [
        "utils.rs",
        "helpers.rs",
        "common.rs",
        "misc.rs",
        "manager.rs",
        "service.rs",
    ];
    let offenders = rust_files(&root.join("src"))
        .into_iter()
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| forbidden.contains(&name))
        })
        .map(|path| path.strip_prefix(root).unwrap().display().to_string())
        .collect::<Vec<_>>();

    assert!(
        offenders.is_empty(),
        "poc-10 target uses invariant-specific filenames instead of dumping grounds:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn poc10_target_root_manifests_are_declarations_only() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let manifests = ["src/lib.rs".to_string(), "src/core.rs".to_string()]
        .into_iter()
        .chain(
            PROTOCOL_SCOPES
                .iter()
                .map(|scope| format!("src/protocol/{scope}.rs")),
        );

    for manifest in manifests {
        let path = root.join(&manifest);
        assert!(path.exists(), "missing root manifest {manifest}");
        let text = source_text(&path);
        let offenders = meaningful_manifest_lines(&text)
            .into_iter()
            .filter(|line| {
                !(line.starts_with("#[path = ")
                    || line.starts_with("pub mod ")
                    || line.starts_with("pub(crate) mod ")
                    || line.starts_with("mod ")
                    || line.starts_with("pub use "))
            })
            .collect::<Vec<_>>();
        assert!(
            offenders.is_empty(),
            "{manifest} must only declare or re-export modules:\n{}",
            offenders.join("\n")
        );
    }
}
