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

const PROTOCOL_SCOPES: [&str; 4] = ["auth", "connection", "content", "sync"];

/// The verb-named intent handler files that live directly inside each scope
/// directory. Everything else under a scope directory is fact-module code.
fn intent_handler_files(root: &Path) -> Vec<PathBuf> {
    let handlers: [(&str, &[&str]); 4] = [
        (
            "auth",
            &[
                "create_key_wrap.rs",
                "purge_retired_recipient_material.rs",
                "unwrap_key_wrap.rs",
            ],
        ),
        (
            "connection",
            &[
                "create_response.rs",
                "purge_closed_connection_material.rs",
                "receive_network_frame.rs",
                "send_bootstrap_request.rs",
                "send_facts_on_connection.rs",
                "send_network_frame.rs",
            ],
        ),
        (
            "content",
            &[
                "purge_below_retention_floor.rs",
                "purge_deleted_message.rs",
                "purge_expired_message.rs",
                "purge_message_child.rs",
            ],
        ),
        (
            "sync",
            &[
                "seed_connection.rs",
                "send_compare_response.rs",
                "send_needed_fact_id.rs",
                "send_requested_fact.rs",
                "share_fact_with_workspace.rs",
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
            if !path.extension().is_some_and(|ext| ext == "rs") {
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
    let doc = source_text(&root.join("new_architecture.md"));
    let required = [
        "## Architecture Criteria",
        "There is no `mod.rs` anywhere in the repository.",
        "There is no root `src/commands` module",
        "src/core/command_context.rs",
        "src/protocol.rs",
        "src/protocol/<scope>.rs",
        "There is no product `demo` or `smoke` command",
        "generic runtime/app mechanics",
        "src/core/schema.rs",
        "src/core/network.rs",
        "src/protocol/registry.rs",
        "### Projector Style",
        "### Intent Handler Style",
        "### Wire And Codec Style",
        "### Connection Frame Style",
        "### Simplicity Guardrails",
    ];

    let missing = required
        .into_iter()
        .filter(|needle| !doc.contains(needle))
        .collect::<Vec<_>>();
    assert!(
        missing.is_empty(),
        "new_architecture.md is missing poc-10 success criteria:\n{}",
        missing.join("\n")
    );
}

#[test]
fn poc10_core_contract_files_are_present() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let required = [
        "src/core/command_context.rs",
        "src/core/runtime.rs",
        "src/core/facts.rs",
        "src/core/context.rs",
        "src/core/projectors.rs",
        "src/core/intents.rs",
        "src/core/pipeline.rs",
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
            "{forbidden} should not exist; command context belongs in core and concrete protocol modules live under src/protocol"
        );
    }

    assert!(
        root.join("src/core/command_context.rs").is_file(),
        "missing src/core/command_context.rs"
    );
    for scope in PROTOCOL_SCOPES {
        let required = format!("src/protocol/{scope}.rs");
        assert!(root.join(&required).is_file(), "missing {required}");
    }

    let lib = source_text(&root.join("src/lib.rs"));
    for required in ["pub mod core;", "pub mod match_app;", "pub mod protocol;"] {
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
        "tests/match_smoke.rs",
    ] {
        assert!(
            !root.join(forbidden).exists(),
            "{forbidden} should not exist; smoke coverage belongs in black-box CLI tests"
        );
    }

    let app = source_text(&root.join("src/match_app.rs"));
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
    let topo::core::projectors::ProjectionOutput {
        needs,
        offers,
        time_wakes,
        effects,
    } = topo::core::projectors::ProjectionOutput::default();

    assert!(needs.is_empty());
    assert!(offers.is_empty());
    assert!(time_wakes.is_empty());
    assert!(effects.row_mutations.is_empty());
    assert!(effects.intents.is_empty());
    assert!(effects.local_intents.is_empty());
}

#[test]
fn poc10_pipeline_effects_names_the_common_commit_shape() {
    let topo::core::effects::PipelineEffects {
        facts,
        ephemeral_facts,
        purged_facts,
        row_mutations,
        intents,
        local_intents,
    } = topo::core::effects::PipelineEffects::new();

    assert!(facts.is_empty());
    assert!(ephemeral_facts.is_empty());
    assert!(purged_facts.is_empty());
    assert!(row_mutations.is_empty());
    assert!(intents.is_empty());
    assert!(local_intents.is_empty());
}

#[test]
fn poc10_core_pipeline_exposes_protocol_neutral_vocabulary() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let pipeline_path = root.join("src/core/pipeline.rs");
    assert!(
        pipeline_path.is_file(),
        "missing src/core/pipeline.rs; it must expose protocol-neutral terms for pending projection, context wake fanout, and intent output"
    );

    let mut text = source_text(&pipeline_path);
    for path in source_files(&root.join("src/core/pipeline")) {
        text.push_str(&source_text(&path));
    }
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
            &["IntentOutput", "intent_output", "intent output"][..],
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
        "src/core/pipeline.rs must expose protocol-neutral pipeline vocabulary:\n{}",
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
        "connection.pending_connection_responses",
        "canonical_in",
        "connection_frame_out",
        "purge_instructions",
        "pending_key_requests",
        "pending_key_unwraps",
        "pending_wrap_reconcile",
        "negentropy_pending_purges",
        "pending_connection_attempts",
        "pending_connection_responses",
    ];
    let offenders = source_matches_in_paths(root, vec![pipeline_path], &forbidden);
    assert!(
        offenders.is_empty(),
        "src/core/pipeline.rs must not expose old worker queue or event status vocabulary:\n{}",
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
        "connection.pending_connection_responses",
        "canonical_in",
        "connection_frame_out",
        "purge_instructions",
        "pending_key_requests",
        "pending_key_unwraps",
        "pending_wrap_reconcile",
        "negentropy_pending_purges",
        "pending_connection_attempts",
        "pending_connection_responses",
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
fn poc10_architecture_docs_describe_legacy_queues_as_removed_mechanisms() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let architecture = source_text(&root.join("new_architecture.md"));
    let migration = source_text(&root.join("poc10_migration.md"));

    for required in [
        "These names are legacy/removal vocabulary only.",
        "must not reappear in",
        "target code paths except in tests or documentation",
        "No old labels, blocker tables, ready queues, canonical ingress queues",
        "recently-valid queues, pending reprojection queues, or worker catalogs remain",
    ] {
        assert!(
            architecture.contains(required) || migration.contains(required),
            "architecture docs must frame old worker queues as removed target mechanisms: {required}"
        );
    }
}

#[test]
fn poc10_target_projectors_emit_only_needs_offers_and_intents() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let projector_paths = target_projector_files(root);
    assert!(
        !projector_paths.is_empty(),
        "scan target src/protocol/facts/**/project.rs files"
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
        "poc-10 target projectors should emit only needs, offers, row mutations, and intents; rows, deletes, and labels must go through projector output helpers, not ad hoc fields:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn poc10_accept_commands_leave_bootstrap_effects_to_projection() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let accept_commands = source_text(&root.join("src/protocol/auth/invite/commands.rs"));
    let connection_request_projector =
        source_text(&root.join("src/protocol/connection/request/project.rs"));

    assert!(
        !accept_commands.contains("send_bootstrap_connection_request_intent"),
        "accept/link commands should create connection_request facts, not enqueue bootstrap IO directly"
    );
    assert!(
        connection_request_projector.contains("send_bootstrap_connection_request_intent"),
        "the connection_request projector should schedule bootstrap IO when a local request projects"
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
        "crate::core::store",
        "core::store",
        "Store",
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
            "share_fact_with_workspace_intent_for_fact",
            "share_fact_with_workspace_intent(",
            "ShareFactWithWorkspace {",
        ],
    );

    assert!(
        offenders.is_empty(),
        "runtime routing must not decide which facts are workspace-shareable; projectors emit share_fact_with_workspace intents at the fact boundary:\n{}",
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
        "sync advertisement and response paths must use sync_shareable_fact_rows, not persisted fact scans or runtime shareability filters:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn poc10_concrete_protocol_routes_semantic_messages() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let registry = source_text(&root.join("src/protocol/registry.rs"));
    let receive = source_text(&root.join("src/protocol/connection/frame/create.rs"));

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
