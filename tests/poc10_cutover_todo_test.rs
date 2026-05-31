use std::path::{Path, PathBuf};

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).to_path_buf()
}

fn source_text(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()))
}

fn files_under(root: &Path) -> Vec<PathBuf> {
    let mut pending = vec![root.to_path_buf()];
    let mut files = Vec::new();
    while let Some(dir) = pending.pop() {
        for entry in std::fs::read_dir(&dir)
            .unwrap_or_else(|err| panic!("read dir {}: {err}", dir.display()))
        {
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

fn rust_files_under(root: &Path) -> Vec<PathBuf> {
    files_under(root)
        .into_iter()
        .filter(|path| path.extension().is_some_and(|ext| ext == "rs"))
        .collect()
}

fn non_legacy_src_rust_files(root: &Path) -> Vec<PathBuf> {
    let legacy_dir = root.join("src/legacy");
    let legacy_manifest = root.join("src/legacy.rs");
    rust_files_under(&root.join("src"))
        .into_iter()
        .filter(|path| path != &legacy_manifest && !path.starts_with(&legacy_dir))
        .collect()
}

fn matching_code_lines(root: &Path, paths: Vec<PathBuf>, needles: &[&str]) -> Vec<String> {
    let mut matches = Vec::new();
    for path in paths {
        let text = source_text(&path);
        for (index, line) in text.lines().enumerate() {
            let trimmed = line.trim_start();
            if trimmed.starts_with("//") {
                continue;
            }
            let code = line.split_once("//").map_or(line, |(code, _)| code);
            for needle in needles {
                if code.contains(needle) {
                    matches.push(format!(
                        "{}:{} contains {needle:?}",
                        path.strip_prefix(root).unwrap().display(),
                        index + 1
                    ));
                }
            }
        }
    }
    matches.sort();
    matches.dedup();
    matches
}

fn matching_lines(root: &Path, paths: Vec<PathBuf>, needles: &[&str]) -> Vec<String> {
    matching_lines_with_comment_mode(root, paths, needles, false)
}

fn matching_lines_including_comments(
    root: &Path,
    paths: Vec<PathBuf>,
    needles: &[&str],
) -> Vec<String> {
    matching_lines_with_comment_mode(root, paths, needles, true)
}

fn matching_lines_with_comment_mode(
    root: &Path,
    paths: Vec<PathBuf>,
    needles: &[&str],
    include_comments: bool,
) -> Vec<String> {
    let mut matches = Vec::new();
    for path in paths {
        let text = source_text(&path);
        for (index, line) in text.lines().enumerate() {
            let trimmed = line.trim_start();
            if !include_comments && trimmed.starts_with("//") {
                continue;
            }
            for needle in needles {
                if line.contains(needle) {
                    matches.push(format!(
                        "{}:{} contains {needle:?}",
                        path.strip_prefix(root).unwrap().display(),
                        index + 1
                    ));
                }
            }
        }
    }
    matches.sort();
    matches.dedup();
    matches
}

const SCOPE_NAMES: [&str; 4] = ["auth", "connection", "content", "sync"];

/// Verb-named intent handler files that live directly inside each scope dir.
const INTENT_HANDLER_FILES: [&str; 12] = [
    "src/protocol/connection/create_bootstrap_response.rs",
    "src/protocol/connection/receive_network_frame.rs",
    "src/protocol/connection/send_bootstrap_request.rs",
    "src/protocol/connection/send_facts_on_connection.rs",
    "src/protocol/connection/send_network_frame.rs",
    "src/protocol/auth/create_key_wrap.rs",
    "src/protocol/auth/unwrap_key_wrap.rs",
    "src/protocol/sync/seed_connection.rs",
    "src/protocol/sync/send_compare_response.rs",
    "src/protocol/sync/send_needed_fact_id.rs",
    "src/protocol/sync/send_requested_fact.rs",
    "src/protocol/sync/share_fact_with_sync.rs",
];

/// Absolute paths of every verb-named intent handler file in the new
/// package-by-scope layout (was: everything under src/protocol/intents).
fn intent_handler_files(root: &Path) -> Vec<PathBuf> {
    INTENT_HANDLER_FILES
        .into_iter()
        .map(|path| root.join(path))
        .collect()
}

/// Absolute paths of the scope directories under src/protocol.
fn scope_dirs(root: &Path) -> Vec<PathBuf> {
    SCOPE_NAMES
        .into_iter()
        .map(|scope| root.join("src/protocol").join(scope))
        .collect()
}

/// Every fact-module Rust file under the 6 protocol scope directories
/// (replaces walking the retired src/protocol/facts tree). Verb-named
/// intent handler files at the top level of each scope dir are excluded:
/// they were previously housed under src/protocol/intents and were never
/// part of the fact tree.
fn scope_rust_files(root: &Path) -> Vec<PathBuf> {
    let handlers = intent_handler_files(root);
    scope_dirs(root)
        .into_iter()
        .flat_map(|dir| rust_files_under(&dir))
        .filter(|path| !handlers.contains(path))
        .collect()
}

fn project_files(root: &Path) -> Vec<PathBuf> {
    scope_rust_files(root)
        .into_iter()
        .filter(|path| path.file_name().is_some_and(|name| name == "project.rs"))
        .collect()
}

fn imported_black_box_behavior_files(root: &Path) -> Vec<PathBuf> {
    [
        "black_box_sync_test.rs",
        "cascade_cli_test.rs",
        "cli_surface_test.rs",
        "content_cli_test.rs",
        "daemon_lifecycle_cli_test.rs",
        "disappearing_messages_cli_test.rs",
        "auth_cli_test.rs",
        "generate_cli_test.rs",
        "invite_accept_cli_test.rs",
        "leaf_coord_cli_test.rs",
        "negentropy_purge_sync_test.rs",
        "sync_storage_boundary_test.rs",
        "view_cli_test.rs",
    ]
    .into_iter()
    .map(|file| root.join("tests").join(file))
    .collect()
}

fn ignored_test_names(path: &Path) -> Vec<String> {
    let text = source_text(path);
    let mut pending_ignore = false;
    let mut ignored = Vec::new();

    for line in text.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("#[ignore") {
            pending_ignore = true;
            continue;
        }
        if pending_ignore && trimmed.starts_with("fn ") {
            let name = trimmed
                .trim_start_matches("fn ")
                .split(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '_'))
                .next()
                .unwrap_or_default()
                .to_string();
            ignored.push(name);
            pending_ignore = false;
            continue;
        }
        if pending_ignore && !trimmed.starts_with("#[") && !trimmed.is_empty() {
            pending_ignore = false;
        }
    }

    ignored
}

fn projector_test_files(root: &Path) -> Vec<PathBuf> {
    rust_files_under(&root.join("tests"))
        .into_iter()
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| {
                    name.starts_with("poc10_") && name.ends_with("_projector_test.rs")
                })
        })
        .collect()
}

#[test]
fn cutover_active_non_legacy_source_has_no_legacy_imports_worker_runs_or_old_queues() {
    let root = root();
    let forbidden = [
        "crate::legacy::app",
        "crate::legacy::protocol",
        "crate::legacy::workers",
        "topo::legacy::app",
        "topo::legacy::protocol",
        "topo::legacy::workers",
        "legacy::app",
        "legacy::protocol",
        "legacy::workers",
        "worker::run",
        "sync_worker::run",
        "run_worker",
        "worker_run",
        "WorkerRun",
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
        "READY_EVENTS",
        "BLOCKED_EVENTS_BY_MISSING_DEP",
        "MISSING_DEPS_BY_BLOCKED_EVENT",
        "PENDING_REPROJECTIONS",
        "RECENTLY_VALID_EVENTS",
    ];
    let offenders = matching_code_lines(&root, non_legacy_src_rust_files(&root), &forbidden);
    assert!(
        offenders.is_empty(),
        "active non-legacy source still references retained legacy imports, worker run APIs, or removed worker queues:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn cutover_target_runtime_facade_owns_context_app() {
    let root = root();
    assert!(
        root.join("src/core/runtime.rs").is_file(),
        "add a generic core runtime facade that owns Store, ContextChangePipeline, registries, command output submission, projection drain, and deferred intent dispatch"
    );
    assert!(
        !root.join("src/match_runtime.rs").exists(),
        "delete product-specific src/match_runtime.rs after moving its logic into generic core runtime/app plus protocol registry"
    );

    let context_app = source_text(&root.join("src/context_app.rs"));
    let forbidden = [
        "MatchRuntime",
        "match_runtime",
        "run_legacy_compat",
        "legacy::app",
        "legacy::protocol",
        "legacy-production-command",
    ];
    let offenders = forbidden
        .into_iter()
        .filter(|needle| context_app.contains(needle))
        .collect::<Vec<_>>();
    assert!(
        offenders.is_empty(),
        "context_app still exposes product-specific runtime or legacy bridge logic: {}",
        offenders.join(", ")
    );
}

#[test]
fn cutover_demo_and_smoke_surfaces_are_removed() {
    let root = root();
    let stale_paths = [
        "src/demo.rs",
        "src/demo",
        "examples/match_demo.rs",
        "examples/con_demo.rs",
        "tests/match_smoke.rs",
        "tests/con_smoke.rs",
    ]
    .into_iter()
    .filter(|path| root.join(path).exists())
    .collect::<Vec<_>>();
    assert!(
        stale_paths.is_empty(),
        "demo/smoke source surfaces should not be product commands or examples; smoke coverage belongs in black-box CLI tests:\n{}",
        stale_paths.join("\n")
    );

    let app = source_text(&root.join("src/context_app.rs"));
    let offenders = ["Some(\"demo\")", "Some(\"smoke\")", "\"demo\"", "\"smoke\""]
        .into_iter()
        .filter(|needle| app.contains(needle))
        .collect::<Vec<_>>();
    assert!(
        offenders.is_empty(),
        "context_app should not expose demo or smoke commands: {}",
        offenders.join(", ")
    );
}

#[test]
fn cutover_no_non_legacy_code_calls_legacy_app_protocol_or_workers() {
    let root = root();
    let offenders = matching_lines(
        &root,
        non_legacy_src_rust_files(&root),
        &[
            "crate::legacy::app",
            "crate::legacy::protocol",
            "crate::legacy::workers",
            "legacy::app",
            "legacy::protocol",
            "legacy::workers",
        ],
    );
    assert!(
        offenders.is_empty(),
        "target production code still calls retained legacy modules:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn cutover_legacy_island_is_deleted() {
    let root = root();
    let remaining = ["src/legacy.rs", "src/legacy"]
        .into_iter()
        .filter(|path| root.join(path).exists())
        .collect::<Vec<_>>();
    assert!(
        remaining.is_empty(),
        "delete the legacy compatibility island as one cut after target runtime, CLI, daemon, sync, connection::frame, purge, and tests are cut over:\n{}",
        remaining.join("\n")
    );
}

#[test]
fn cutover_projector_output_guardrail_is_real_and_enabled() {
    let root = root();
    let test = source_text(&root.join("tests/poc10_architecture_boundary_test.rs"));
    let fn_name = "fn poc10_target_projectors_emit_only_needs_offers_self_purge_and_intents";
    let Some(start) = test.find(fn_name) else {
        panic!("missing {fn_name}");
    };
    let prefix = &test[..start];
    let attrs_start = prefix.rfind("#[test]").unwrap_or(start);
    let attrs = &test[attrs_start..start];
    assert!(!attrs.contains("#[ignore"), "{fn_name} is still ignored");
    let body = &test[start..];
    assert!(
        body.contains("project.rs"),
        "{fn_name} must scan target src/protocol/<scope>/**/project.rs files"
    );
    assert!(
        !body.contains("projector.rs"),
        "{fn_name} is still pointed at legacy projector.rs vocabulary"
    );
}

#[test]
fn cutover_connection_frame_send_has_no_not_yet_wired_or_variable_payload_slots() {
    let root = root();
    let paths = vec![
        root.join("src/protocol/connection/send_facts_on_connection.rs"),
        root.join("src/protocol/connection/send_network_frame.rs"),
        root.join("src/protocol/connection_frame.rs"),
        root.join("src/protocol/connection_frame_wire.rs"),
    ];
    let offenders = matching_lines_including_comments(
        &root,
        paths,
        &[
            "NOT_YET_WIRED",
            "not yet wired",
            "Vec<Vec<u8>>",
            "push_vecs",
            "fn vecs",
        ],
    );
    assert!(
        offenders.is_empty(),
        "connection::frame send still has placeholder packaging or variable payload slots:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn cutover_sync_has_no_legacy_sync_index_escape_hatch() {
    let root = root();
    let mut paths = intent_handler_files(&root);
    paths.extend(
        rust_files_under(&root.join("src/protocol/sync"))
            .into_iter()
            .filter(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| {
                        // Exclude the verb-named intent handler files already
                        // covered above; keep only sync fact-module code.
                        !INTENT_HANDLER_FILES
                            .iter()
                            .any(|handler| handler.ends_with(name))
                    })
            }),
    );
    let offenders = matching_lines_including_comments(
        &root,
        paths,
        &[
            "`SyncIndex`",
            "SyncIndex::",
            "&SyncIndex",
            "legacy/workers/sync",
            "Wave 6",
            "mutable-index",
        ],
    );
    assert!(
        offenders.is_empty(),
        "sync still documents or depends on the legacy mutable index path:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn cutover_sync_compare_response_uses_bounded_durable_range_index() {
    let root = root();
    let offenders = matching_lines_including_comments(
        &root,
        vec![root.join("src/protocol/sync/send_compare_response.rs")],
        &[
            "SYNC_COMPARE_RANGE_INDEX_NOT_READY",
            "sync_compare_range_index_not_ready",
        ],
    );
    assert!(
        offenders.is_empty(),
        "sync::compare response generation is intentionally parked until core/runtime can provide a bounded durable range-index summary for the compare fact's timestamp range; remove the retry-only stop and produce compare/have/need response facts once that range-index context exists:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn cutover_dep_aware_sync_has_encrypted_out_of_range_display_perf_proof() {
    let root = root();
    let tests = files_under(&root.join("tests"))
        .into_iter()
        .filter(|path| {
            path.extension().is_some_and(|ext| ext == "rs")
                && path.file_name().and_then(|name| name.to_str())
                    != Some("poc10_cutover_todo_test.rs")
        })
        .map(|path| source_text(&path))
        .collect::<Vec<_>>()
        .join("\n");
    let required_test_name =
        "cli_disappearing_messages_message_resyncs_after_proactive_key_arrival";
    assert!(
        tests.contains(required_test_name),
        "keep a black-box sync/key-arrival test named {required_test_name:?}; it must prove encrypted content becomes visible from normal CLI processing rather than an in-memory scheduler facade"
    );
}

#[test]
fn cutover_purge_child_secret_retirement_sync_and_expiry_are_projector_owned() {
    let root = root();
    let handlers = intent_handler_files(&root)
        .into_iter()
        .filter_map(|path| {
            path.file_stem()
                .and_then(|stem| stem.to_str())
                .map(str::to_string)
        })
        .collect::<Vec<_>>();

    assert!(
        handlers.iter().any(|name| name.contains("share_fact")),
        "sync sharing is still bounded handler work; current handlers: {}",
        handlers.join(", ")
    );
    for forbidden_fragment in [
        "purge",
        "message_child",
        "retired_recipient",
        "expired",
        "floor",
    ] {
        assert!(
            handlers
                .iter()
                .all(|name| !name.contains(forbidden_fragment)),
            "deletion, retirement, and expiry cleanup must be projector-owned, not handler-owned; unexpected {forbidden_fragment:?} handler in {}",
            handlers.join(", ")
        );
    }

    let style = source_text(&root.join("docs/RULES.md"));
    for required_pattern in [
        "## Deletion Pattern",
        "Deletion is target-owned",
        "ProjectionOutput::purge_self",
        "core rejects cross-fact purges",
    ] {
        assert!(
            style.contains(required_pattern),
            "docs/RULES.md must remember the target-owned deletion pattern; missing {required_pattern:?}"
        );
    }

    for projector in [
        "src/protocol/auth/local_key_secret/project.rs",
        "src/protocol/auth/local_history_node_secret/project.rs",
        "src/protocol/auth/local_recipient_key/project.rs",
        "src/protocol/connection/ephemeral_secret/project.rs",
        "src/protocol/connection/bootstrap_response/project.rs",
        "src/protocol/content/message/project.rs",
        "src/protocol/content/reaction/project.rs",
        "src/protocol/content/file/project.rs",
        "src/protocol/content/file_slice/project.rs",
    ] {
        let text = source_text(&root.join(projector));
        assert!(
            text.contains(".purge_self("),
            "{projector} must self-purge after matched deletion/close/retirement context"
        );
    }

    let offenders = matching_lines_including_comments(
        &root,
        non_legacy_src_rust_files(&root),
        &["purge_instructions", "content.purge_instructions"],
    );
    assert!(
        offenders.is_empty(),
        "target code/docs still refer to legacy purge queue vocabulary:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn cutover_behavior_tests_do_not_assert_legacy_worker_or_queue_state() {
    let root = root();
    let paths = rust_files_under(&root.join("tests"))
        .into_iter()
        .filter(|path| {
            let file_name = path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("");
            !file_name.starts_with("poc10_")
                && !file_name.contains("boundary")
                && file_name != "rules_boundary_test.rs"
                && file_name != "worker_contract_test.rs"
        })
        .collect::<Vec<_>>();
    let offenders = matching_lines(
        &root,
        paths,
        &[
            "topo::legacy",
            "legacy::protocol",
            "worker::run",
            "ready_events",
            "blocked_events",
            "canonical.in",
            "RECENTLY_VALID_EVENTS",
            "PENDING_REPROJECTIONS",
        ],
    );
    assert!(
        offenders.is_empty(),
        "behavior tests still poke legacy internals or old queue/status vocabulary:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn cutover_imported_black_box_tests_have_no_extra_ignores() {
    let root = root();
    let allowed_ignored = [
        "black_box_sync_test.rs::cli_three_long_running_daemons_converge_messages_among_late_joiner",
        "black_box_sync_test.rs::cli_daemon_download_perf_times_send_to_peer_receipt",
        "content_cli_test.rs::cli_files_listing_shows_partial_progress_during_sync",
        "content_cli_test.rs::cli_files_listing_shows_zero_progress_when_only_descriptor_received",
        "content_cli_test.rs::cli_save_file_rejects_incomplete_download",
    ];

    let mut offenders = Vec::new();
    for path in imported_black_box_behavior_files(&root) {
        let file_name = path
            .file_name()
            .and_then(|name| name.to_str())
            .expect("black-box test file name");
        for test_name in ignored_test_names(&path) {
            let full_name = format!("{file_name}::{test_name}");
            if !allowed_ignored.contains(&full_name.as_str()) {
                offenders.push(full_name);
            }
        }
    }
    offenders.sort();

    assert!(
        offenders.is_empty(),
        "poc-10 imported black-box behavior tests have extra #[ignore] markers beyond the poc-8 baseline; port the behavior or explicitly revise the accepted baseline:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn cutover_auth_family_facade_delegates_to_named_fact_slices() {
    let root = root();
    // Each auth key-material fact family is its own module: a `<family>.rs` manifest
    // plus a `<family>/` directory that owns the family's layout and projector.
    let required_families = [
        "recipient_key",
        "local_recipient_key",
        "removal_frontier",
        "local_history_node_secret",
        "local_key_secret",
        "local_secret_retirement",
        "key_request",
        "key_wrap",
    ];
    let mut missing = Vec::new();
    for family in required_families {
        for path in [
            format!("src/protocol/auth/{family}.rs"),
            format!("src/protocol/auth/{family}/project.rs"),
            format!("src/protocol/auth/{family}/layout.rs"),
        ] {
            if !root.join(&path).exists() {
                missing.push(path);
            }
        }
    }
    assert!(
        missing.is_empty(),
        "auth key-material fact-family behavior must live in named family modules, not one undifferentiated projector:\n{}",
        missing.join("\n")
    );

    // There is no shared facade projector: each family registers its own.
    assert!(
        !root.join("src/protocol/auth/project.rs").exists(),
        "auth must not have a shared facade projector module"
    );

    // The removal-frontier projector authority-gates its owner endpoint.
    let removal_frontier = source_text(&root.join("src/protocol/auth/removal_frontier/project.rs"));
    for needle in [
        "validate_frontier_endpoint_shared_owner",
        "validate_frontier_local_owner",
    ] {
        assert!(
            removal_frontier.contains(needle),
            "removal frontier projector must authority-gate its owner endpoint: missing {needle}"
        );
    }
}

#[test]
fn cutover_sync_is_not_a_multi_fact_project_bundle() {
    let root = root();
    let sync_dir = root.join("src/protocol/sync");
    let project_subdir = sync_dir.join("project");
    let fact_file = sync_dir.join("fact.rs");

    let mut offenders = Vec::new();
    if project_subdir.exists() {
        for path in rust_files_under(&project_subdir) {
            offenders.push(path.strip_prefix(&root).unwrap().display().to_string());
        }
    }

    if fact_file.exists() {
        let text = source_text(&fact_file);
        let fact_structs = text
            .lines()
            .filter_map(|line| line.trim_start().strip_prefix("pub struct "))
            .filter_map(|rest| rest.split_whitespace().next())
            .filter(|name| name.ends_with("Fact"))
            .collect::<Vec<_>>();
        if fact_structs.len() > 1 {
            offenders.push(format!(
                "src/protocol/sync/fact.rs defines multiple fact families: {}",
                fact_structs.join(", ")
            ));
        }
    }

    assert!(
        offenders.is_empty(),
        "sync must not be a dumping folder for range/key/support facts. Keep sync::range_request and sync::shared_fact as fact-family modules with their own fact/layout/project files; sync/project/* subtrees are not allowed:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn cutover_queries_are_not_context_capability_or_cross_module_dumping_grounds() {
    let root = root();
    let query_files = scope_rust_files(&root)
        .into_iter()
        .filter(|path| path.file_name().is_some_and(|name| name == "queries.rs"))
        .collect::<Vec<_>>();
    let forbidden = [
        "ContextNeed",
        "ContextOffer",
        "ProjectionContext",
        "Projector",
        "Intent",
        "Handler",
        "Fact::new",
        "submit_",
        "drain_",
        "private_key",
        "signing_secret",
        "local endpoint secret",
        "local endpoint signing secret",
        "local_signing_capability",
        "local_encryption_capability",
        "workspace_scope",
        "_need(",
        "_offer(",
    ];
    let mut offenders = matching_code_lines(&root, query_files.clone(), &forbidden);
    for path in query_files {
        let relative = path.strip_prefix(&root).unwrap().display().to_string();
        let text = source_text(&path);
        if relative.ends_with("queries.rs") && text.contains("crate::protocol::{") {
            offenders.push(format!(
                "{relative} imports a grouped cross-module event_modules namespace"
            ));
        }
        if relative.ends_with("queries.rs")
            && text
                .lines()
                .filter(|line| line.trim_start().starts_with("pub fn "))
                .count()
                > 6
        {
            offenders.push(format!(
                "{relative} has more than six public query helpers; split read models before it becomes a dumping ground"
            ));
        }
    }
    offenders.sort();
    offenders.dedup();
    assert!(
        offenders.is_empty(),
        "queries.rs files should be narrow read-only row lookups, not context/capability/cross-module dumping grounds:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn cutover_context_app_does_not_own_command_business_logic() {
    let root = root();
    let app = root.join("src/context_app.rs");
    let offenders = matching_code_lines(
        &root,
        vec![app],
        &[
            "table_row(",
            "table_rows(",
            "runtime.facts()",
            "purge_fact(",
            "decode_local_key_secret",
            "decode_local_history_node_secret",
            "rotate_recipient(",
            "history_source_",
            "latest_local_recipient_key",
            "recipient_key_is_superseded",
            "RuntimeVault",
        ],
    );
    assert!(
        offenders.is_empty(),
        "context_app.rs should route CLI commands through module-local command/read-model surfaces; protocol business logic is still embedded here:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn cutover_projectors_and_handlers_receive_typed_facts_not_raw_bytes() {
    let root = root();
    let mut paths = project_files(&root);
    paths.extend(intent_handler_files(&root));
    paths.push(root.join("src/protocol/connection_frame.rs"));

    let offenders = matching_code_lines(
        &root,
        paths,
        &[
            "decode_fact(&fact.bytes",
            "decode_fact(&payload.bytes",
            "decode_fact(&matched.payload.bytes",
            "decode_fact(&receive.bytes",
            "decode_fact(&request_context.bytes",
            "decode_fact(&invite_context.bytes",
            "decode_fact(&connection_fact.bytes",
            "decode_fact(&request_fact.bytes",
            "decode_fact(&child.bytes",
        ],
    );
    assert!(
        offenders.is_empty(),
        "projectors and handlers should receive typed fact/context variables from module-owned decoders instead of repeatedly decoding opaque Fact.bytes payloads:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn cutover_context_predicates_replace_manual_payload_matching() {
    let root = root();
    let paths = project_files(&root);

    let offenders = matching_code_lines(
        &root,
        paths,
        &[
            "matched_context()",
            "payload_for_need(",
            "matched.payload",
            "matched.need",
        ],
    );
    assert!(
        offenders.is_empty(),
        "projectors should ask scope-local typed predicates whether context needs are met instead of manually walking matched payload rows:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn cutover_content_wire_layouts_use_central_schema_codec() {
    let root = root();
    let paths = [
        "src/protocol/content/event/layout.rs",
        "src/protocol/content/file/layout.rs",
        "src/protocol/content/file/rows.rs",
        "src/protocol/content/file_deletion/layout.rs",
        "src/protocol/content/file_slice/layout.rs",
        "src/protocol/content/file_slice/rows.rs",
        "src/protocol/content/message/layout.rs",
        "src/protocol/content/message/rows.rs",
        "src/protocol/content/message_deletion/layout.rs",
        "src/protocol/content/reaction/layout.rs",
        "src/protocol/content/reaction/rows.rs",
    ]
    .into_iter()
    .map(|path| root.join(path))
    .filter(|path| path.is_file())
    .collect::<Vec<_>>();

    let offenders = matching_code_lines(
        &root,
        paths,
        &[
            "copy_from_slice",
            "try_into().unwrap()",
            "vec![0;",
            "[1..",
            "[9..",
            "HEADER_BYTES",
            "ROW_HEADER_BYTES",
        ],
    );
    assert!(
        offenders.is_empty(),
        "content wire/layout/row codecs still hand-code field offsets; move the slot math into one core schema/wire codec and keep fact modules on typed fields:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn cutover_content_read_models_have_normal_sqlite_tables() {
    fn table_body<'a>(schema: &'a str, table: &str) -> Option<&'a str> {
        let marker = format!("CREATE TABLE IF NOT EXISTS {table} (");
        let start = schema.find(&marker)?;
        let rest = &schema[start + marker.len()..];
        let end = rest.find("\n);")?;
        Some(&rest[..end])
    }

    let root = root();
    let schema = source_text(&root.join("src/protocol/registry.rs"));
    let required = [
        (
            "content_messages",
            &[
                "workspace_id",
                "message_id",
                "author_user_id",
                "created_at_ms",
            ] as &[&str],
        ),
        (
            "content_reactions",
            &[
                "workspace_id",
                "message_id",
                "reaction_id",
                "author_user_id",
            ],
        ),
        (
            "content_files",
            &["workspace_id", "message_id", "file_id", "root_hash"],
        ),
    ];

    let mut missing = Vec::new();
    for (table, columns) in required {
        match table_body(&schema, table) {
            Some(body) => {
                for column in columns {
                    if !body.contains(&format!("{column} ")) {
                        missing.push(format!("missing {table}.{column}"));
                    }
                }
            }
            None => missing.push(format!("missing table {table}")),
        }
    }

    assert!(
        missing.is_empty(),
        "content projections should expose normal SQLite tables for queryable message/reaction/file state while canonical fact bytes remain separately durable:\n{}",
        missing.join("\n")
    );
}

#[test]
fn cutover_runtime_step_commits_projection_context_rows_and_intents_atomically() {
    let root = root();
    let pipeline = source_text(&root.join("src/core/pipeline.rs"));
    let core_daemon = source_text(&root.join("src/core/daemon.rs"));
    let send_network_frame =
        source_text(&root.join("src/protocol/connection/send_network_frame.rs"));

    let mut offenders = Vec::new();
    if pipeline.contains("apply_atomic_row_intents(&run.intents, store, allowed_tables)") {
        offenders.push(
            "src/core/pipeline.rs applies protocol row writes after the projector run instead of inside one durable step"
                .to_string(),
        );
    }
    if pipeline.contains("fn apply_atomic_row_intents(") {
        offenders.push(
            "src/core/pipeline.rs still has a separate atomic-row-intent transaction path"
                .to_string(),
        );
    }
    if core_daemon.contains("network::delete_inbound(runtime.store(), inbound)?;")
        && !core_daemon.contains("if !retried")
    {
        offenders.push(
            "src/core/daemon.rs deletes inbound network bytes before the protocol receive effect is proven durable"
                .to_string(),
        );
    }
    if core_daemon.contains("network::delete_inbound") && !core_daemon.contains("!retried") {
        offenders.push(
            "src/core/daemon.rs deletes ephemeral inbound rows even when receive dispatch asked to retry"
                .to_string(),
        );
    }
    if send_network_frame.contains("tcp::send_once")
        && send_network_frame.contains(".is_err()")
        && send_network_frame.contains("return Ok(PipelineEffects::new())")
    {
        offenders.push(
            "src/protocol/connection/send_network_frame.rs swallows TCP send failures as an empty successful handler output"
                .to_string(),
        );
    }
    if send_network_frame.contains("fn frame_digest(") {
        offenders.push(
            "src/protocol/connection/send_network_frame.rs still carries cursor/ack digest scaffolding"
                .to_string(),
        );
    }

    assert!(
        offenders.is_empty(),
        "local writes and intent side effects must be all-or-visible-failure; these paths can lose or hide protocol work:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn cutover_network_row_storage_class_is_not_ambiguous() {
    let root = root();
    let core_schema = source_text(&root.join("src/core/schema.rs"));
    let network = source_text(&root.join("src/core/network.rs"));
    let registry = source_text(&root.join("src/protocol/registry.rs"));

    let durable_in_core_schema =
        core_schema.contains("network_in") || core_schema.contains("network_out");
    let memory_in_queue_module = network.contains("memory-local")
        || network.contains("ephemeral")
        || network.contains("CREATE TEMP TABLE IF NOT EXISTS network_out");
    let runtime_loads_queue_schema = registry.contains("network::SCHEMA_SOURCE");

    let mut offenders = Vec::new();
    if durable_in_core_schema && memory_in_queue_module {
        offenders.push(
            "network_in/network_out are declared both as durable core schema tables and ephemeral network memory tables",
        );
    }
    if memory_in_queue_module && !runtime_loads_queue_schema {
        offenders.push(
            "network declares memory schemas, but Runtime does not load network::SCHEMA_SOURCE",
        );
    }
    if source_text(&root.join("src/protocol/connection/send_network_frame.rs"))
        .contains("fn frame_digest")
    {
        offenders.push(
            "send_network_frame frame_digest is unused ACK/cursor scaffolding; duplicate connection frames must stay harmless instead",
        );
    }
    if durable_in_core_schema == memory_in_queue_module {
        offenders.push(
            "network rows should have exactly one explicit storage contract: durable schema table or ephemeral memory table",
        );
    }
    assert!(
        offenders.is_empty(),
        "network row persistence is ambiguous; choose one storage contract and make runtime/schema/docs/tests agree:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn cutover_network_io_intents_are_ephemeral_queue_work() {
    let root = root();
    let mut pipeline = source_text(&root.join("src/core/pipeline.rs"));
    for path in rust_files_under(&root.join("src/core/pipeline")) {
        pipeline.push_str(&source_text(&path));
    }
    let core_schema = source_text(&root.join("src/core/schema.rs"));
    let request_projector =
        source_text(&root.join("src/protocol/connection/bootstrap_request/project.rs"));
    let send_facts_handler =
        source_text(&root.join("src/protocol/connection/send_facts_on_connection.rs"));
    let daemon = source_text(&root.join("src/core/daemon.rs"));
    let network_io_files = [
        "src/protocol/connection/send_bootstrap_request.rs",
        "src/protocol/connection/send_network_frame.rs",
        "src/protocol/connection/receive_network_frame.rs",
    ];

    let mut offenders = Vec::new();
    for relative in network_io_files {
        let source = source_text(&root.join(relative));
        if source.contains("IntentExecution") {
            offenders.push(format!(
                "{relative} still stores queue durability inside the intent value"
            ));
        }
    }
    if !request_projector.contains(".local_intent(send_bootstrap_connection_request_intent") {
        offenders.push(
            "connection request projection does not emit bootstrap sends as local intents"
                .to_string(),
        );
    }
    let compact_send_facts_handler = send_facts_handler.split_whitespace().collect::<String>();
    if !compact_send_facts_handler
        .contains(".local_intent(send_network_frame::send_network_frame_intent")
    {
        offenders.push(
            "send_facts_on_connection does not emit network frames as local intents".to_string(),
        );
    }
    if !daemon.contains("runtime.submit_local_intent(to_intent") {
        offenders
            .push("daemon inbound network frames are not submitted as local intents".to_string());
    }
    if !pipeline.contains("LOCAL_INTENTS")
        || !core_schema.contains("CREATE TEMP TABLE IF NOT EXISTS local_intents")
        || !pipeline.contains("submit_local_intent_to_store")
    {
        offenders.push(
            "core pipeline does not visibly route ephemeral intents to a TEMP local intent queue"
                .to_string(),
        );
    }

    assert!(
        offenders.is_empty(),
        "network IO effects must be ephemeral and regeneratable instead of durable protocol work:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn cutover_scope_projectors_do_not_import_foreign_fact_layouts_or_rows() {
    let root = root();
    let protocol_root = root.join("src/protocol");
    let scope_names = SCOPE_NAMES;
    let mut offenders = Vec::new();

    for path in scope_rust_files(&root) {
        let relative = path.strip_prefix(&protocol_root).unwrap();
        let current_scope = relative
            .components()
            .next()
            .and_then(|component| component.as_os_str().to_str())
            .unwrap_or("");
        if !scope_names.contains(&current_scope) {
            continue;
        }

        let text = source_text(&path);
        for (index, line) in text.lines().enumerate() {
            let trimmed = line.trim_start();
            if trimmed.starts_with("//") {
                continue;
            }
            let code = line.split_once("//").map_or(line, |(code, _)| code);
            if !(code.contains("::layout") || code.contains("::rows")) {
                continue;
            }
            for prefix in ["crate::protocol::", "topo::protocol::"] {
                let Some(rest) = code.split(prefix).nth(1) else {
                    continue;
                };
                let imported_scope = rest.split("::").next().unwrap_or("");
                if scope_names.contains(&imported_scope) && imported_scope != current_scope {
                    offenders.push(format!(
                        "{}:{} imports {imported_scope} internals: {}",
                        path.strip_prefix(&root).unwrap().display(),
                        index + 1,
                        code.trim()
                    ));
                }
            }
        }
    }

    offenders.sort();
    offenders.dedup();
    assert!(
        offenders.is_empty(),
        "fact scopes should depend on each other through the smallest public typed interface, not by importing another scope's layout.rs or rows.rs internals:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn cutover_projector_files_state_policy_instead_of_hiding_dumping_grounds() {
    let root = root();
    let mut offenders = Vec::new();
    for path in project_files(&root) {
        let text = source_text(&path);
        if !text.contains("POLICY.") {
            offenders.push(format!(
                "{} has no top-level POLICY documentation",
                path.strip_prefix(&root).unwrap().display()
            ));
        }
    }
    assert!(
        offenders.is_empty(),
        "target projectors should keep their projection contract explicit in-line:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn cutover_projector_unit_tests_are_inline_with_facts() {
    let root = root();
    let mut offenders = projector_test_files(&root)
        .into_iter()
        .map(|path| path.strip_prefix(&root).unwrap().display().to_string())
        .collect::<Vec<_>>();
    offenders.sort();
    assert!(
        offenders.is_empty(),
        "move target projector unit tests into #[cfg(test)] modules beside the relevant fact module code; reserve tests/ for black-box CLI/daemon/runtime integration tests and architecture guardrails:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn cutover_no_ignored_poc10_guardrails_remain() {
    let root = root();
    let guardrail_files = [
        root.join("tests/poc10_architecture_boundary_test.rs"),
        root.join("tests/poc10_intent_cleanliness_test.rs"),
        root.join("tests/poc10_protocol_registry_test.rs"),
    ];
    let offenders = matching_lines(&root, guardrail_files.to_vec(), &["#[ignore"]);
    assert!(
        offenders.is_empty(),
        "remove ignored guardrails by making the target architecture satisfy them:\n{}",
        offenders.join("\n")
    );
}
