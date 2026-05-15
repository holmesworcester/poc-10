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

fn source_matches(root: &Path, needles: &[&str]) -> Vec<String> {
    source_matches_in_paths(root, source_files(&root.join("src")), needles)
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
        "## Poc-10 Success Criteria",
        "Every non-ignored `poc-8` test passes in `poc-10`",
        "There is no `mod.rs` anywhere in the repository.",
        "There is no per-module `schema.rs`, `codec.rs`, or `cli.rs`",
        "src/core/schema.p8sql",
        "src/event_modules/schema.p8sql",
        "src/handlers/schema.p8sql",
        "### Projector Style",
        "### Intent Handler Style",
        "### Wire And Codec Style",
        "### Transit Frame Style",
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
        "src/core/facts.rs",
        "src/core/context.rs",
        "src/core/matchers.rs",
        "src/core/projection.rs",
        "src/core/intents.rs",
        "src/core/handler_dispatch.rs",
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
fn poc10_projector_output_contract_emits_only_needs_offers_and_intents() {
    let topo::core::projection::ProjectionOutput {
        needs,
        offers,
        intents,
    } = topo::core::projection::ProjectionOutput::default();

    assert!(needs.is_empty());
    assert!(offers.is_empty());
    assert!(intents.is_empty());
}

#[test]
fn poc10_handler_output_contract_emits_only_facts_and_intents() {
    let topo::core::handler_dispatch::HandlerOutput { facts, intents } =
        topo::core::handler_dispatch::HandlerOutput::default();

    assert!(facts.is_empty());
    assert!(intents.is_empty());
}

#[test]
fn poc10_core_event_bus_exposes_protocol_neutral_vocabulary() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let event_bus_path = root.join("src/core/event_bus.rs");
    assert!(
        event_bus_path.is_file(),
        "missing src/core/event_bus.rs; when introduced, it must expose protocol-neutral terms for pending projection, context delta matching, and intent output"
    );

    let text = source_text(&event_bus_path);
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
            "context delta matching",
            &[
                "ContextDeltaMatching",
                "ContextDeltaMatcher",
                "context_delta_matching",
                "context_delta_match",
                "context delta matching",
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
        "src/core/event_bus.rs must expose protocol-neutral event bus vocabulary:\n{}",
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
        "applied_shared_events",
        "dependency_labels",
        "event_labels",
        "canonical.in",
        "sync.in",
        "transit.out",
        "content.purge_instructions",
        "encryption.pending_key_requests",
        "encryption.pending_key_unwraps",
        "encryption.pending_wrap_reconcile",
        "encryption.negentropy_pending_purges",
        "connection.pending_connection_attempts",
        "connection.pending_connection_responses",
        "canonical_in",
        "transit_out",
        "purge_instructions",
        "pending_key_requests",
        "pending_key_unwraps",
        "pending_wrap_reconcile",
        "negentropy_pending_purges",
        "pending_connection_attempts",
        "pending_connection_responses",
    ];
    let offenders = source_matches_in_paths(root, vec![event_bus_path], &forbidden);
    assert!(
        offenders.is_empty(),
        "src/core/event_bus.rs must not expose old worker queue or event status vocabulary:\n{}",
        offenders.join("\n")
    );
}

#[test]
#[ignore = "poc-10 target guardrail: enable after the module tree is converted to root manifests"]
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
#[ignore = "poc-10 target guardrail: enable after schemas and wire layouts move to target files"]
fn poc10_target_has_no_per_module_schema_codec_or_cli_files() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let forbidden = ["schema.rs", "codec.rs", "cli.rs"];
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
        "poc-10 target forbids per-module schema.rs, codec.rs, and cli.rs files:\n{}",
        offenders.join("\n")
    );
}

#[test]
#[ignore = "poc-10 target guardrail: enable after event status, blocker, label, and receive queues are deleted"]
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
        "event_modules.labels",
        "event_modules.pending_reprojections",
        "event_modules.recently_valid_events",
        "event_modules.event_receive_context",
        "event_modules.applied_shared_events",
        "ready_events",
        "blocked_events_by_missing_dep",
        "missing_deps_by_blocked_event",
        "dependents_by_dep",
        "deps_by_dependent",
        "pending_reprojections",
        "recently_valid_events",
        "event_receive_context",
        "applied_shared_events",
        "dependency_labels",
        "event_labels",
        "labels",
    ];
    let offenders = source_matches(root, &forbidden);

    assert!(
        offenders.is_empty(),
        "poc-10 target source should use facts plus needs/offers instead of old event status, blocker, label, and receive queues:\n{}",
        offenders.join("\n")
    );
}

#[test]
#[ignore = "poc-10 target guardrail: enable after worker queues are replaced by core intents"]
fn poc10_target_source_has_no_old_worker_queue_names() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let forbidden = [
        "canonical.in",
        "sync.in",
        "transit.out",
        "content.purge_instructions",
        "encryption.pending_key_requests",
        "encryption.pending_key_unwraps",
        "encryption.pending_wrap_reconcile",
        "encryption.negentropy_pending_purges",
        "connection.pending_connection_attempts",
        "connection.pending_connection_responses",
        "canonical_in",
        "transit_out",
        "purge_instructions",
        "pending_key_requests",
        "pending_key_unwraps",
        "pending_wrap_reconcile",
        "negentropy_pending_purges",
        "pending_connection_attempts",
        "pending_connection_responses",
    ];
    let offenders = source_matches(root, &forbidden);

    assert!(
        offenders.is_empty(),
        "poc-10 target source should route old worker queues through core intents instead:\n{}",
        offenders.join("\n")
    );
}

#[test]
#[ignore = "poc-10 target guardrail: enable after projector rows, deletes, and labels are emitted as needs/offers/intents"]
fn poc10_target_projectors_emit_only_needs_offers_and_intents() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let projector_paths = source_files(&root.join("src"))
        .into_iter()
        .filter(|path| {
            path.file_name().is_some_and(|name| name == "projector.rs")
                || path
                    .strip_prefix(root)
                    .unwrap()
                    .display()
                    .to_string()
                    .ends_with("src/workers/pipeline_helpers/event_pipeline.rs")
        })
        .collect::<Vec<_>>();
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
        "pub labels:",
        "rows:",
        "deletes:",
        "labels:",
        ".rows",
        ".deletes",
        ".labels",
    ];
    let offenders = source_matches_in_paths(root, projector_paths, &forbidden);

    assert!(
        offenders.is_empty(),
        "poc-10 target projectors should emit only needs, offers, and intents; rows, deletes, and labels must be atomic intents or context output:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn poc10_target_has_exactly_three_schema_dsl_files() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let expected = [
        "src/core/schema.p8sql",
        "src/event_modules/schema.p8sql",
        "src/handlers/schema.p8sql",
    ];

    for path in expected {
        assert!(
            root.join(path).exists(),
            "missing required schema file {path}"
        );
    }

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

    assert_eq!(
        found, expected,
        "poc-10 target keeps every durable table visible in exactly three schema files"
    );
}

#[test]
#[ignore = "poc-10 target guardrail: enable after broad source files are removed"]
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
#[ignore = "poc-10 target guardrail: enable after root manifests replace mod.rs"]
fn poc10_target_root_manifests_are_declarations_only() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let manifests = [
        "src/core.rs",
        "src/event_modules.rs",
        "src/handlers.rs",
        "src/commands.rs",
    ];

    for manifest in manifests {
        let path = root.join(manifest);
        assert!(path.exists(), "missing root manifest {manifest}");
        let text = source_text(&path);
        let offenders = meaningful_manifest_lines(&text)
            .into_iter()
            .filter(|line| {
                !(line.starts_with("pub mod ")
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
