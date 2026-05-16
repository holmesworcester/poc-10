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

fn project_files(root: &Path) -> Vec<PathBuf> {
    rust_files_under(&root.join("src/protocol/fact_modules"))
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
        "encryption_cli_test.rs",
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

fn production_line_count(path: &Path) -> usize {
    let text = source_text(path);
    let mut count = 0;
    let mut skip_test_module = false;
    let mut pending_test_cfg = false;
    let mut brace_depth = 0usize;

    for line in text.lines() {
        let trimmed = line.trim_start();
        if skip_test_module {
            brace_depth += line.matches('{').count();
            brace_depth = brace_depth.saturating_sub(line.matches('}').count());
            if brace_depth == 0 {
                skip_test_module = false;
            }
            continue;
        }
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
        count += 1;
    }

    count
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
#[ignore = "cutover todo: production match commands must run through generic core runtime/app"]
fn cutover_target_runtime_facade_owns_match_app() {
    let root = root();
    assert!(
        root.join("src/core/runtime.rs").is_file(),
        "add a generic core runtime facade that owns Store, WakeLoop, registries, command output submission, projection drain, and deferred intent dispatch"
    );
    assert!(
        !root.join("src/match_runtime.rs").exists(),
        "delete product-specific src/match_runtime.rs after moving its logic into generic core runtime/app plus protocol registry"
    );

    let match_app = source_text(&root.join("src/match_app.rs"));
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
        .filter(|needle| match_app.contains(needle))
        .collect::<Vec<_>>();
    assert!(
        offenders.is_empty(),
        "match_app still exposes product-specific runtime or legacy bridge logic: {}",
        offenders.join(", ")
    );
}

#[test]
#[ignore = "cutover todo: remove demo/example command surfaces; keep smoke coverage black-box"]
fn cutover_demo_and_smoke_surfaces_are_removed() {
    let root = root();
    let stale_paths = [
        "src/demo.rs",
        "src/demo",
        "examples/match_demo.rs",
        "tests/match_smoke.rs",
    ]
    .into_iter()
    .filter(|path| root.join(path).exists())
    .collect::<Vec<_>>();
    assert!(
        stale_paths.is_empty(),
        "demo/smoke source surfaces should not be product commands or examples; smoke coverage belongs in black-box CLI tests:\n{}",
        stale_paths.join("\n")
    );

    let app = source_text(&root.join("src/match_app.rs"));
    let offenders = ["Some(\"demo\")", "Some(\"smoke\")", "\"demo\"", "\"smoke\""]
        .into_iter()
        .filter(|needle| app.contains(needle))
        .collect::<Vec<_>>();
    assert!(
        offenders.is_empty(),
        "match_app should not expose demo or smoke commands: {}",
        offenders.join(", ")
    );
}

#[test]
#[ignore = "cutover todo: target CLI commands must replace legacy command dispatch"]
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
#[ignore = "cutover todo: remove the contained legacy island after production cutover"]
fn cutover_legacy_island_is_deleted() {
    let root = root();
    let remaining = ["src/legacy.rs", "src/legacy"]
        .into_iter()
        .filter(|path| root.join(path).exists())
        .collect::<Vec<_>>();
    assert!(
        remaining.is_empty(),
        "delete the legacy compatibility island as one cut after target runtime, CLI, daemon, sync, transit, purge, and tests are cut over:\n{}",
        remaining.join("\n")
    );
}

#[test]
#[ignore = "cutover todo: enable the projector output guardrail against target project.rs files"]
fn cutover_projector_output_guardrail_is_real_and_enabled() {
    let root = root();
    let test = source_text(&root.join("tests/poc10_architecture_boundary_test.rs"));
    let fn_name = "fn poc10_target_projectors_emit_only_needs_offers_and_intents";
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
        "{fn_name} must scan target src/protocol/fact_modules/**/project.rs files"
    );
    assert!(
        !body.contains("projector.rs"),
        "{fn_name} is still pointed at legacy projector.rs vocabulary"
    );
}

#[test]
#[ignore = "cutover todo: transit send packaging must be real and fixed-layout"]
fn cutover_transit_send_has_no_not_yet_wired_or_variable_payload_slots() {
    let root = root();
    let paths = vec![
        root.join("src/protocol/intent_handlers/transit.rs"),
        root.join("src/protocol/fact_modules/transit/frame.rs"),
        root.join("src/protocol/fact_modules/transit/create.rs"),
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
        "transit send still has placeholder packaging or variable payload slots:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn cutover_sync_has_no_legacy_sync_index_escape_hatch() {
    let root = root();
    let mut paths = rust_files_under(&root.join("src/protocol/intent_handlers"));
    paths.extend(
        rust_files_under(&root.join("src/protocol/fact_modules"))
            .into_iter()
            .filter(|path| {
                path.components()
                    .any(|component| component.as_os_str().to_string_lossy().starts_with("sync"))
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
#[ignore = "cutover todo: sync compare responses need a durable bounded range-index context"]
fn cutover_sync_compare_response_uses_bounded_durable_range_index() {
    let root = root();
    let offenders = matching_lines_including_comments(
        &root,
        vec![root.join("src/protocol/intent_handlers/handle_sync.rs")],
        &[
            "SYNC_COMPARE_RANGE_INDEX_NOT_READY",
            "sync_compare_range_index_not_ready",
        ],
    );
    assert!(
        offenders.is_empty(),
        "sync_compare response generation is intentionally parked until core/runtime can provide a bounded durable range-index summary for the compare fact's timestamp range; remove the retry-only stop and produce compare/have/need response facts once that range-index context exists:\n{}",
        offenders.join("\n")
    );
}

#[test]
#[ignore = "cutover todo: dep-aware sync must prove out-of-range encrypted message display"]
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
    let required_test_name = "dep_aware_sync_displays_encrypted_out_of_range_message_fast";
    assert!(
        tests.contains(required_test_name),
        "add a dep-aware sync performance/behavior test named {required_test_name:?}; it must prove an encrypted message whose deps/keys are outside the requested time range displays without a one-day scan or key-request round trip"
    );
}

#[test]
#[ignore = "cutover todo: purge must be decomposed into bounded target handlers"]
fn cutover_purge_cascade_secret_retirement_sync_and_expiry_are_target_handlers() {
    let root = root();
    let handlers = files_under(&root.join("src/protocol/intent_handlers"))
        .into_iter()
        .filter_map(|path| {
            path.file_stem()
                .and_then(|stem| stem.to_str())
                .map(str::to_string)
        })
        .collect::<Vec<_>>();

    for required_fragment in [
        "purge",
        "cascade",
        "retire",
        "sync_index",
        "expiry",
        "floor",
    ] {
        assert!(
            handlers.iter().any(|name| name.contains(required_fragment)),
            "missing bounded target handler covering {required_fragment:?}; current handlers: {}",
            handlers.join(", ")
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
#[ignore = "cutover todo: black-box behavior tests must no longer exercise legacy internals"]
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
        "cascade_cli_test.rs::cascade_cli_replays_event_with_deps_out_of_order_and_unblocks_50k",
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
fn cutover_encryption_is_not_a_multi_fact_bundle() {
    let root = root();
    let bundled_paths = [
        "src/protocol/fact_modules/encryption/fact.rs",
        "src/protocol/fact_modules/encryption/layout.rs",
        "src/protocol/fact_modules/encryption/create.rs",
        "src/protocol/fact_modules/encryption/commands.rs",
        "src/protocol/fact_modules/encryption/project.rs",
        "src/protocol/fact_modules/encryption/recipient_key.rs",
        "src/protocol/fact_modules/encryption/local_recipient_key.rs",
        "src/protocol/fact_modules/encryption/removal_frontier.rs",
        "src/protocol/fact_modules/encryption/key_request.rs",
        "src/protocol/fact_modules/encryption/local_material.rs",
        "src/protocol/fact_modules/encryption/signed_key_wrap.rs",
    ];
    let remaining = bundled_paths
        .into_iter()
        .filter(|path| root.join(path).exists())
        .collect::<Vec<_>>();
    assert!(
        remaining.is_empty(),
        "encryption is still a multi-fact fact-module bundle; split recipient keys, local recipient keys, removal frontiers, local key secrets, key requests, key wraps, and retained/history-node material into fact-family modules with their own fact/layout/project/create/commands/rows files:\n{}",
        remaining.join("\n")
    );
}

#[test]
fn cutover_sync_is_not_a_multi_fact_project_bundle() {
    let root = root();
    let sync_dir = root.join("src/protocol/fact_modules/sync");
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
                "src/protocol/fact_modules/sync/fact.rs defines multiple fact families: {}",
                fact_structs.join(", ")
            ));
        }
    }

    assert!(
        offenders.is_empty(),
        "sync must not be a dumping folder for range/key/support facts. Split sync_range_request, sync_encrypted_root, sync_shared_event, and sync_key_wrap_available into fact-family modules with their own fact/layout/project files; sync/project/* subtrees are not allowed:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn cutover_queries_are_not_context_capability_or_cross_module_dumping_grounds() {
    let root = root();
    let query_files = rust_files_under(&root.join("src/protocol/fact_modules"))
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
        if relative.ends_with("queries.rs") && text.contains("crate::protocol::fact_modules::{") {
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
fn cutover_match_app_does_not_own_command_business_logic() {
    let root = root();
    let app = root.join("src/match_app.rs");
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
        "match_app.rs should route CLI commands through module-local command/read-model surfaces; protocol business logic is still embedded here:\n{}",
        offenders.join("\n")
    );
}

#[test]
#[ignore = "cutover todo: projectors should not become dumping grounds during translation"]
fn cutover_projector_files_stay_small_and_split_by_fact_family() {
    let root = root();
    let mut offenders = Vec::new();
    for path in project_files(&root) {
        let count = production_line_count(&path);
        if count > 250 {
            offenders.push(format!(
                "{} has {count} production lines",
                path.strip_prefix(&root).unwrap().display()
            ));
        }
    }
    assert!(
        offenders.is_empty(),
        "large target projectors need splitting or tighter family-local helpers before cutover:\n{}",
        offenders.join("\n")
    );
}

#[test]
#[ignore = "cutover todo: move non-black-box projector tests inline beside their modules"]
fn cutover_projector_unit_tests_are_inline_with_fact_modules() {
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
#[ignore = "cutover todo: normal poc-10 guardrails should have no ignored tests left"]
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
