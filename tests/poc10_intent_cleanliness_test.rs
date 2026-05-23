use std::collections::BTreeSet;
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

fn immediate_rust_module_names(root: &Path) -> BTreeSet<String> {
    immediate_rust_children(root)
        .into_iter()
        .filter_map(|path| {
            path.file_stem()
                .and_then(|stem| stem.to_str())
                .map(str::to_string)
        })
        .collect()
}

fn declared_modules_in(text: &str) -> BTreeSet<String> {
    meaningful_source_lines(text)
        .into_iter()
        .filter_map(|line| {
            line.strip_prefix("pub mod ")
                .or_else(|| line.strip_prefix("mod "))
                .and_then(|rest| rest.strip_suffix(';'))
                .map(str::trim)
                .map(str::to_string)
        })
        .collect()
}

fn production_text_before_unit_tests(text: &str) -> &str {
    text.find("#[cfg(test)]")
        .map(|index| &text[..index])
        .unwrap_or(text)
}

fn strip_line_comments(text: &str) -> String {
    text.lines()
        .map(|line| {
            let trimmed = line.trim_start();
            if trimmed.starts_with("//") {
                ""
            } else {
                line.split_once("//").map_or(line, |(code, _)| code)
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// The six protocol scope directories. Since the package-by-scope migration
/// each scope directory holds BOTH fact-family modules and verb-named intent
/// handler files, replacing the old `src/protocol/facts` and
/// `src/protocol/intents` layer roots.
const SCOPES: [&str; 5] = ["connection", "content", "encryption", "identity", "sync"];

fn scope_dirs(root: &Path) -> Vec<PathBuf> {
    SCOPES
        .into_iter()
        .map(|scope| root.join("src/protocol").join(scope))
        .collect()
}

fn scope_manifests(root: &Path) -> Vec<PathBuf> {
    SCOPES
        .into_iter()
        .map(|scope| root.join("src/protocol").join(format!("{scope}.rs")))
        .collect()
}

/// Verb-named intent handler files. After the package-by-scope migration these
/// self-contained handler files live directly at the top level of their scope
/// directory; there is no separate `src/protocol/intents` tree. `identity` has
/// no intent handlers.
fn intent_handler_files(root: &Path) -> Vec<PathBuf> {
    const HANDLERS: &[(&str, &[&str])] = &[
        (
            "connection",
            &[
                "create_response",
                "receive_network_frame",
                "send_bootstrap_request",
                "send_facts_on_connection",
                "send_network_frame",
            ],
        ),
        (
            "content",
            &[
                "purge_below_retention_floor",
                "purge_deleted_message",
                "purge_expired_message",
                "purge_message_child",
            ],
        ),
        (
            "encryption",
            &[
                "create_key_wrap",
                "purge_retired_recipient_material",
                "unwrap_key_wrap",
            ],
        ),
        (
            "sync",
            &[
                "seed_connection",
                "send_compare_response",
                "send_needed_fact_id",
                "send_requested_fact",
                "share_fact_with_workspace",
            ],
        ),
    ];
    HANDLERS
        .iter()
        .flat_map(|(scope, verbs)| {
            verbs.iter().map(move |verb| {
                root.join("src/protocol")
                    .join(scope)
                    .join(format!("{verb}.rs"))
            })
        })
        .collect()
}

fn intent_handler_file_set(root: &Path) -> BTreeSet<PathBuf> {
    intent_handler_files(root).into_iter().collect()
}

/// All rust files under the six scope directories that are NOT verb-named
/// intent handler files: every fact-family module, scope-level fact file, and
/// fact CLI/command adapter.
fn fact_family_files(root: &Path) -> Vec<PathBuf> {
    let handlers = intent_handler_file_set(root);
    scope_dirs(root)
        .iter()
        .flat_map(|dir| rust_files(dir))
        .filter(|path| !handlers.contains(path))
        .collect()
}

fn fact_family_files_named(root: &Path, name: &str) -> Vec<PathBuf> {
    fact_family_files(root)
        .into_iter()
        .filter(|path| path.file_name().is_some_and(|file_name| file_name == name))
        .collect()
}

fn projector_implementation_files(root: &Path) -> Vec<PathBuf> {
    fact_family_files(root)
        .into_iter()
        .filter(|path| {
            path.file_name()
                .is_some_and(|file_name| file_name == "project.rs")
                || path
                    .components()
                    .any(|component| component.as_os_str() == "project")
        })
        .collect()
}

fn contains_legacy_custom_context_matcher_api(text: &str) -> bool {
    let production = strip_line_comments(production_text_before_unit_tests(text));
    [
        "impl ContextMatcher for",
        "ContextMatch {",
        "Vec<ContextMatch>",
        "Option<ContextMatch>",
        "match_need_to_offers",
        "match_offer_to_needs",
    ]
    .into_iter()
    .any(|needle| production.contains(needle))
}

#[test]
fn purge_deleted_message_intent_does_not_encode_projection_work() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let intent = source_text(&root.join("src/protocol/content/purge_deleted_message.rs"));

    for forbidden in [
        "open_message",
        "OpenMessage",
        "CONTENT_MESSAGE_ROWS",
        "OPENED_MESSAGE_ROWS",
        "leaf_id",
        "minute",
        "ciphertext",
    ] {
        assert!(
            !intent.contains(forbidden),
            "purge_deleted_message intent layout must not own projection/opening detail: {forbidden}"
        );
    }
}

#[test]
fn handlers_do_not_own_event_module_projection_rows() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));

    let mut offenders = Vec::new();
    for path in intent_handler_files(root) {
        let text = source_text(&path);
        for forbidden in [
            "CONTENT_MESSAGE_ROWS",
            "OPENED_MESSAGE_ROWS",
            "content_message_row",
            "opened_message_row",
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
        "intent handlers must not materialize or clean up fact-module projection rows:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn purge_deleted_message_handler_must_be_real_retention_work_when_it_exists() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let path = root.join("src/protocol/content/purge_deleted_message.rs");
    if !path.exists() {
        return;
    }

    let text = source_text(&path);
    for forbidden in ["CONTENT_MESSAGE_ROWS", "OPENED_MESSAGE_ROWS", "TableDelete"] {
        assert!(
            !text.contains(forbidden),
            "PurgeDeletedMessage handler must not be projection row cleanup: {forbidden}"
        );
    }
    assert!(
        text.contains("purge_deleted_message")
            || text.contains("purge_fact")
            || text.contains("DiscoverCascade")
            || text.contains("RetireSecret")
            || text.contains("SyncIndexPurge"),
        "PurgeDeletedMessage handler must preserve real retention/cascade/retire behavior"
    );
}

#[test]
fn target_projectors_stay_pure_context_to_intents() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut offenders = Vec::new();
    for path in projector_implementation_files(root) {
        let text = source_text(&path);
        let production = production_text_before_unit_tests(&text);
        for forbidden in [
            "Store",
            "table_rows",
            "insert_table_rows",
            "delete_table_rows",
            "write_transaction",
            "Protocol::",
            "workers::",
            "core::network",
            "std::net",
            "std::process",
            "Command::new",
        ] {
            if production.contains(forbidden) {
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
fn target_projectors_use_typed_context_lookups_not_direct_match_scans() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let allowed_direct_scans: [&str; 0] = [];
    let mut offenders = Vec::new();
    let mut seen_allowed = BTreeSet::new();

    for path in projector_implementation_files(root) {
        let relative = path.strip_prefix(root).unwrap().display().to_string();
        let text = source_text(&path);
        let production = strip_line_comments(production_text_before_unit_tests(&text));
        if !production.contains("matched_context") {
            continue;
        }

        if allowed_direct_scans.contains(&relative.as_str()) {
            seen_allowed.insert(relative);
        } else {
            offenders.push(relative);
        }
    }

    let stale_allowlist = allowed_direct_scans
        .into_iter()
        .filter(|path| !seen_allowed.contains(*path))
        .collect::<Vec<_>>();

    assert!(
        offenders.is_empty() && stale_allowlist.is_empty(),
        "source projectors must look up context by concrete ContextNeed with ProjectionContext::payload_for, payload_for_checked, or matched_payloads_for. Direct matched_context scans are exceptional and must not spread.\nnew offenders:\n{}\nstale allowlist entries to remove:\n{}",
        offenders.join("\n"),
        stale_allowlist.join("\n")
    );
}

#[test]
fn target_projectors_use_named_needs_not_positional_authority_flows() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let forbidden = [
        "authority_needs(",
        "has_all_context(",
        "checked by has_all_context",
        "needs[",
    ];
    let mut offenders = Vec::new();

    for path in projector_implementation_files(root) {
        let relative = path.strip_prefix(root).unwrap().display().to_string();
        let text = source_text(&path);
        let production = strip_line_comments(production_text_before_unit_tests(&text));
        for marker in forbidden {
            if production.contains(marker) {
                offenders.push(format!("{relative} contains {marker:?}"));
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "source projectors should name context dependencies at the proof site. Use branch-specific need structs or locals instead of positional needs[0]/needs[1] authority flows:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn target_projectors_do_not_read_raw_context_offer_storage_fields() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let forbidden = [".offers()"];
    let mut offenders = Vec::new();

    for path in projector_implementation_files(root) {
        let relative = path.strip_prefix(root).unwrap().display().to_string();
        let text = source_text(&path);
        let production = strip_line_comments(production_text_before_unit_tests(&text));
        for marker in forbidden {
            if production.contains(marker) {
                offenders.push(format!("{relative} contains {marker:?}"));
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "projectors should consume typed matched payloads, not raw standing context rows. Keep offer owner checks in core ProjectionContext helpers and range decoding beside the validating domain:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn target_projectors_document_policy_narratives() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut offenders = Vec::new();

    for path in fact_family_files_named(root, "project.rs") {
        let relative = path.strip_prefix(root).unwrap().display().to_string();
        let text = source_text(&path);
        let production = production_text_before_unit_tests(&text);
        if !production.contains("impl Projector for") {
            continue;
        }

        let mut missing = Vec::new();
        if !production.contains("//! POLICY.") {
            missing.push("`//! POLICY.`");
        }
        if !production.contains("// 1.") {
            missing.push("numbered projector body markers");
        }
        if !missing.is_empty() {
            offenders.push(format!("{relative} missing {}", missing.join(" and ")));
        }
    }

    assert!(
        offenders.is_empty(),
        "fact-module projectors should document their admission policy inline and mirror it in numbered body sections:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn target_projectors_route_primary_decode_through_core_typed_adapter() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut offenders = Vec::new();

    for path in fact_family_files_named(root, "project.rs") {
        let relative = path.strip_prefix(root).unwrap().display().to_string();
        let text = source_text(&path);
        let production = strip_line_comments(production_text_before_unit_tests(&text));
        if !production.contains("impl Projector for") {
            continue;
        }

        let mut missing = Vec::new();
        if !production.contains("project_typed::<super::Codec, _>(self, fact,")
            && !production.contains("project_typed::<super::fact::Codec, _>(self, fact,")
        {
            missing.push("Projector::project core typed-adapter delegation");
        }
        if !production.contains("impl TypedProjector<super::Codec>")
            && !production.contains("impl TypedProjector<super::fact::Codec>")
        {
            missing.push("TypedProjector<super::Codec> implementation");
        }
        if !missing.is_empty() {
            offenders.push(format!("{relative} missing {}", missing.join(" and ")));
        }
    }

    assert!(
        offenders.is_empty(),
        "fact-module projectors should let core own primary decode timing: Projector::project delegates to project_typed::<super::Codec, _>(), while the owning module codec decodes bytes into typed policy input:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn target_projectors_do_not_decode_foreign_fact_layouts_inline() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut offenders = Vec::new();

    for path in fact_family_files_named(root, "project.rs") {
        let relative = path.strip_prefix(root).unwrap().display().to_string();
        let text = source_text(&path);
        let production = strip_line_comments(production_text_before_unit_tests(&text));
        for marker in [
            "::layout::decode_fact",
            "signed_fact::layout::",
            "layout as ",
            "_layout::decode_fact",
            "_layout::decode_",
        ] {
            if production.contains(marker) {
                offenders.push(format!("{relative} contains {marker:?}"));
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "projectors should reason over typed fact helpers from the owning module, not foreign layout codecs. The owning fact module may decode bytes; cross-module projector policy should call named typed helpers/witnesses:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn event_module_context_rs_files_do_not_reappear() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let offenders = fact_family_files_named(root, "context.rs")
        .into_iter()
        .map(|path| path.strip_prefix(root).unwrap().display().to_string())
        .collect::<Vec<_>>();

    assert!(
        offenders.is_empty(),
        "protocol-specific fact-module context.rs files are dumping-ground risks, not a target source of truth. Core-owned src/core/context.rs is allowed; put nontrivial range encoders and candidate validation beside the domain that validates them instead:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn legacy_custom_context_matcher_api_does_not_reappear() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut offenders = Vec::new();

    for path in rust_files(&root.join("src")) {
        let text = source_text(&path);
        if !contains_legacy_custom_context_matcher_api(&text) {
            continue;
        }
        let relative = path.strip_prefix(root).unwrap();
        if relative.starts_with("src/core/pipeline.rs")
            || relative.starts_with("src/core/pipeline/")
            || relative.starts_with("src/core/fact_store.rs")
        {
            continue;
        }

        offenders.push(relative.display().to_string());
    }

    assert!(
        offenders.is_empty(),
        "the legacy ContextMatcher API is retired; use core-owned byte-range overlap and projector/domain candidate validation instead:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn temporary_protocol_context_helpers_do_not_emit_work_or_rows() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut offenders = Vec::new();
    for path in fact_family_files_named(root, "context.rs") {
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
            "ProjectionContext",
            "MatchedContext",
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
        "temporary protocol context.rs helper files are not the context source of truth; range encoders and candidate validation belong beside their domain, while ProjectionContext inspection belongs in project.rs:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn target_row_layouts_do_not_emit_context_or_intents() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut offenders = Vec::new();
    for path in fact_family_files_named(root, "rows.rs") {
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
fn target_facts_do_not_use_legacy_file_names() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut offenders = Vec::new();
    for path in fact_family_files(root) {
        let Some(file_name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if matches!(file_name, "mod.rs" | "schema.rs" | "codec.rs") {
            offenders.push(path.strip_prefix(root).unwrap().display().to_string());
        }
    }

    assert!(
        offenders.is_empty(),
        "target facts should use explicit role files, not legacy module manifests or dumping-ground names:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn reactive_paths_do_not_call_user_facing_commands_or_cli_adapters() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    files.extend(fact_family_files_named(root, "project.rs"));
    files.extend(fact_family_files(root).into_iter().filter(|path| {
        path.components()
            .any(|component| component.as_os_str() == "project")
    }));
    files.extend(intent_handler_files(root));

    let mut offenders = Vec::new();
    for path in files {
        let text = source_text(&path);
        for forbidden in ["/commands.rs", "::commands", "/cli.rs", "::cli"] {
            if text.contains(forbidden) {
                offenders.push(format!(
                    "{} contains {forbidden:?}",
                    path.strip_prefix(root).unwrap().display()
                ));
            }
        }
        for line in text.lines() {
            let trimmed = line.trim_start();
            if trimmed.starts_with("use crate::protocol::") && trimmed.contains("commands") {
                offenders.push(format!(
                    "{} imports fact-module commands from reactive code: {trimmed}",
                    path.strip_prefix(root).unwrap().display()
                ));
            }
            if trimmed.starts_with("use crate::protocol::") && trimmed.contains("cli") {
                offenders.push(format!(
                    "{} imports fact-module cli from reactive code: {trimmed}",
                    path.strip_prefix(root).unwrap().display()
                ));
            }
        }
    }

    offenders.sort();
    offenders.dedup();
    assert!(
        offenders.is_empty(),
        "projectors and handlers are automatic/reactive paths; they may share create.rs constructors but must not call user-facing commands.rs or cli.rs:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn target_facts_do_not_import_legacy_protocol_or_workers() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut offenders = Vec::new();
    for path in fact_family_files(root) {
        let text = source_text(&path);
        for forbidden in [
            "crate::legacy::protocol",
            "crate::legacy::workers",
            "topo::legacy::protocol",
            "topo::legacy::workers",
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
        "target fact modules must not call into retained poc-8 protocol/workers:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn target_intent_files_only_encode_intent_payloads() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut offenders = Vec::new();
    for path in fact_family_files_named(root, "intent.rs") {
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
            "core::network",
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
    for path in fact_family_files_named(root, "project.rs") {
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
        "projectors should compose fact-module helpers, not define payload decoding or handler logic:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn target_manifests_are_declarations_only() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut manifests = vec![
        root.join("src/lib.rs"),
        root.join("src/core.rs"),
        root.join("src/protocol.rs"),
    ];
    manifests.extend(scope_manifests(root));

    let mut offenders = Vec::new();
    for path in manifests {
        let text = source_text(&path);
        for line in meaningful_source_lines(&text) {
            if !(line.starts_with("#[path = ")
                || line.starts_with("pub mod ")
                || line.starts_with("pub(crate) mod ")
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
fn root_command_module_does_not_reappear() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let offenders = ["src/commands.rs", "src/commands"]
        .into_iter()
        .filter(|path| root.join(path).exists())
        .collect::<Vec<_>>();

    assert!(
        offenders.is_empty(),
        "there is no root command module. User-facing command context lives in src/core/command_context.rs, and module commands stay under protocol fact modules:\n{}",
        offenders.join("\n")
    );

    assert!(
        root.join("src/core/command_context.rs").is_file(),
        "missing src/core/command_context.rs"
    );
}

#[test]
fn concrete_protocol_manifests_live_under_protocol() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let stale = [
        "src/event_modules",
        "src/event_modules.rs",
        "src/handlers",
        "src/handlers.rs",
    ]
    .into_iter()
    .filter(|path| root.join(path).exists())
    .collect::<Vec<_>>();

    assert!(
        stale.is_empty(),
        "fact modules and intent handlers should live under src/protocol, not top-level crate namespaces:\n{}",
        stale.join("\n")
    );

    assert!(
        root.join("src/protocol.rs").is_file(),
        "missing protocol-owned root manifest src/protocol.rs"
    );
    for manifest in scope_manifests(root) {
        assert!(
            manifest.is_file(),
            "missing protocol scope manifest {}",
            manifest.strip_prefix(root).unwrap().display()
        );
    }

    assert!(
        !root.join("src/protocol/facts.rs").exists()
            && !root.join("src/protocol/facts").exists()
            && !root.join("src/protocol/intents.rs").exists()
            && !root.join("src/protocol/intents").exists(),
        "the package-by-layer facts/ and intents/ trees are retired; protocol state is organized by scope"
    );
}

/// Compares one `<module>.rs` manifest against its sibling `<module>/`
/// directory, then recurses into every declared child that is itself a
/// directory-backed module. A scope manifest declares both fact-family modules
/// and verb-named intent modules; both are ordinary `pub mod` declarations and
/// must each have a backing `.rs` file or directory.
fn check_manifest_tree(
    root: &Path,
    manifest: &Path,
    module_root: &Path,
    offenders: &mut Vec<String>,
) {
    let declared = declared_modules_in(&source_text(manifest));
    if !module_root.exists() {
        if !declared.is_empty() {
            offenders.push(format!(
                "{} declares modules but {} is missing",
                manifest.strip_prefix(root).unwrap().display(),
                module_root.strip_prefix(root).unwrap().display()
            ));
        }
        return;
    }

    let files = immediate_rust_module_names(module_root);
    let missing_files = declared.difference(&files).cloned().collect::<Vec<_>>();
    let missing_declarations = files.difference(&declared).cloned().collect::<Vec<_>>();
    if !missing_files.is_empty() {
        offenders.push(format!(
            "{} declares modules without files: {}",
            manifest.strip_prefix(root).unwrap().display(),
            missing_files.join(", ")
        ));
    }
    if !missing_declarations.is_empty() {
        offenders.push(format!(
            "{} has files not declared by manifest: {}",
            module_root.strip_prefix(root).unwrap().display(),
            missing_declarations.join(", ")
        ));
    }

    for child in &declared {
        let child_manifest = module_root.join(format!("{child}.rs"));
        let child_dir = module_root.join(child);
        if child_manifest.is_file() && child_dir.is_dir() {
            check_manifest_tree(root, &child_manifest, &child_dir, offenders);
        }
    }
}

#[test]
fn target_manifests_match_their_filesystem_modules() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut offenders = Vec::new();

    for scope in SCOPES {
        let manifest = root.join("src/protocol").join(format!("{scope}.rs"));
        let module_root = root.join("src/protocol").join(scope);
        check_manifest_tree(root, &manifest, &module_root, &mut offenders);
    }

    assert!(
        offenders.is_empty(),
        "protocol scope manifests must stay synchronized with the filesystem so orphan files cannot become hidden dumping grounds:\n{}",
        offenders.join("\n")
    );
}

/// The only files a fact-family directory may contain.
const STANDARD_FAMILY_FILES: [&str; 8] = [
    "fact.rs",
    "layout.rs",
    "project.rs",
    "rows.rs",
    "queries.rs",
    "create.rs",
    "commands.rs",
    "cli.rs",
];

/// Fact families that do not yet meet the standard-role-file rule.
const FAMILY_FILE_RULE_EXCEPTIONS: [&str; 0] = [];

#[test]
fn fact_family_directories_contain_only_standard_role_files() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut offenders = Vec::new();

    for scope_dir in scope_dirs(root) {
        let scope = scope_dir.file_name().unwrap().to_str().unwrap();
        for family_dir in immediate_subdirs(&scope_dir) {
            let family = family_dir.file_name().unwrap().to_str().unwrap();
            if FAMILY_FILE_RULE_EXCEPTIONS.contains(&format!("{scope}/{family}").as_str()) {
                continue;
            }
            // A fact family is a flat set of role files — no nested directories.
            for nested in immediate_subdirs(&family_dir) {
                offenders.push(format!(
                    "{} is a nested directory; a fact family is flat",
                    nested.strip_prefix(root).unwrap().display()
                ));
            }
            for file in immediate_rust_files(&family_dir) {
                let name = file.file_name().unwrap().to_str().unwrap();
                if !STANDARD_FAMILY_FILES.contains(&name) {
                    offenders.push(format!(
                        "{} is not a standard role file",
                        file.strip_prefix(root).unwrap().display()
                    ));
                }
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "a fact-family directory may contain only the standard role files \
         {STANDARD_FAMILY_FILES:?} and no subdirectories; fold helper logic into \
         a role file:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn target_protocol_registry_owns_protocol_tables_without_runtime_io() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let path = root.join("src/protocol/registry.rs");
    let text = source_text(&path);

    for required in [
        "pub const MATCH_COMMANDS: &[CliCommand<MatchCliContext>]",
        "pub(crate) const SCHEMA_SOURCES: &[SchemaSource]",
        "pub(crate) const ROW_MUTATION_TABLES: &[TableName]",
        "pub(crate) const HANDLER_ROUTES: &[HandlerRoute]",
    ] {
        assert!(
            text.contains(required),
            "protocol registry missing {required}"
        );
    }

    let mut offenders = Vec::new();
    for line in meaningful_source_lines(&text) {
        for forbidden in [
            "Store",
            "ContextChangePipeline",
            "RuntimeDescription",
            "match_daemon_tick",
            "open_",
            "std::net",
            "tcp::",
        ] {
            if line.contains(forbidden) {
                offenders.push(format!("line contains {forbidden:?}: {line}"));
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "src/protocol/registry.rs should own protocol tables without runtime IO/lifecycle logic:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn protocol_runtime_wrapper_does_not_reappear() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    assert!(
        !root.join("src/protocol/runtime.rs").exists(),
        "protocol/runtime.rs should not reappear; core::Runtime owns runtime mechanics"
    );

    let mut offenders = Vec::new();
    for path in rust_files(&root.join("src")) {
        let text = source_text(&path);
        for needle in ["ProtocolRuntime", "dispatch_cli_intents"] {
            if text.contains(needle) {
                offenders.push(format!(
                    "{} contains {needle}",
                    path.strip_prefix(root).unwrap().display()
                ));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "protocol runtime wrapper or CLI-specific dispatch API reappeared:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn target_intents_are_self_contained_handler_files_without_driver_or_intent_submodules() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));

    // There is no separate package-by-layer intents/ tree.
    assert!(
        !root.join("src/protocol/intents").exists()
            && !root.join("src/protocol/intents.rs").exists(),
        "the src/protocol/intents tree is retired; intents are verb-named handler files under their scope"
    );

    let mut offenders = Vec::new();
    for handler in intent_handler_files(root) {
        // Each intent must be exactly one self-contained handler .rs file
        // sitting directly inside its scope directory.
        if !handler.is_file() {
            offenders.push(format!(
                "{} is not a single handler file",
                handler.strip_prefix(root).unwrap().display()
            ));
            continue;
        }
        // A same-named sibling directory would mean the handler was split into
        // driver/catch-all submodules.
        let submodule_dir = handler.with_extension("");
        if submodule_dir.is_dir() {
            offenders.push(format!(
                "{} has a backing submodule directory",
                submodule_dir.strip_prefix(root).unwrap().display()
            ));
        }
        // Intent handlers must not import a driver/intent catch-all submodule.
        let text = source_text(&handler);
        for declared in declared_modules_in(&text) {
            if matches!(declared.as_str(), "driver" | "intent") {
                offenders.push(format!(
                    "{} declares a {declared:?} submodule",
                    handler.strip_prefix(root).unwrap().display()
                ));
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "each intent should be one self-contained verb-named handler file under its scope, with no driver or intent catch-all submodules:\n{}",
        offenders.join("\n")
    );
}

/// The canonical intent verb vocabulary. Intent handler files are named
/// `<verb>_<object>`; this set is deliberately small, and growing it is a
/// deliberate act — add a verb here only when no existing verb fits.
const INTENT_VERBS: [&str; 7] = [
    "create", "send", "receive", "purge", "share", "seed", "unwrap",
];

/// A name is verb-first when it begins with `<verb>_` for a canonical intent
/// verb. `shared_fact` is a noun and correctly does not match `share_`.
fn is_verb_first(name: &str) -> bool {
    INTENT_VERBS
        .iter()
        .any(|verb| name.starts_with(&format!("{verb}_")))
}

/// Rust files sitting directly inside `dir` (non-recursive).
fn immediate_rust_files(dir: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() && path.extension().is_some_and(|ext| ext == "rs") {
                files.push(path);
            }
        }
    }
    files
}

/// Subdirectories sitting directly inside `dir`.
fn immediate_subdirs(dir: &Path) -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                dirs.push(path);
            }
        }
    }
    dirs
}

#[test]
fn intent_handler_files_are_verb_first() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let offenders = intent_handler_files(root)
        .into_iter()
        .filter(|path| !is_verb_first(path.file_stem().unwrap().to_str().unwrap()))
        .map(|path| path.strip_prefix(root).unwrap().display().to_string())
        .collect::<Vec<_>>();
    assert!(
        offenders.is_empty(),
        "intent handler files must be named `<verb>_<object>` using a canonical \
         verb {INTENT_VERBS:?}; these are not verb-first:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn verb_named_scope_files_are_registered_intents() {
    // The "bare-noun smell" guardrail, stated as its testable invariant: a
    // `.rs` file directly inside a scope directory is a registered intent
    // handler if and only if its name is verb-first. A verb-named file that is
    // not a registered intent is the smell; a fact-module file must stay
    // noun-named so facts and intents are distinguishable by name alone.
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let intents = intent_handler_file_set(root);
    let mut offenders = Vec::new();
    for scope_dir in scope_dirs(root) {
        for file in immediate_rust_files(&scope_dir) {
            let verb_first = is_verb_first(file.file_stem().unwrap().to_str().unwrap());
            let shown = file.strip_prefix(root).unwrap().display().to_string();
            match (verb_first, intents.contains(&file)) {
                (true, false) => offenders.push(format!(
                    "{shown} is verb-named but is not a registered intent handler"
                )),
                (false, true) => offenders.push(format!(
                    "{shown} is a registered intent handler but is not verb-first"
                )),
                _ => {}
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "directly under a scope directory, a verb-named `.rs` file must be a \
         registered intent and a fact-module file must stay noun-named:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn fact_family_directories_are_noun_named() {
    // Fact families are noun-named directories; an intent is never a directory.
    // A verb-first subdirectory means an intent was wrongly given a submodule
    // tree, or a fact family was misnamed like a verb.
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut offenders = Vec::new();
    for scope_dir in scope_dirs(root) {
        for sub in immediate_subdirs(&scope_dir) {
            if is_verb_first(sub.file_name().unwrap().to_str().unwrap()) {
                offenders.push(sub.strip_prefix(root).unwrap().display().to_string());
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "fact-family directories under a scope must be noun-named, not verb-first:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn scope_directories_contain_only_intents_and_family_manifests() {
    // Only intents linger outside of facts. Every `.rs` file directly under a
    // scope directory is either a registered intent handler or a `<family>.rs`
    // manifest paired with a `<family>/` directory. Every subdirectory is a
    // fact family paired with its manifest.
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let intents = intent_handler_file_set(root);
    let mut offenders = Vec::new();

    for scope_dir in scope_dirs(root) {
        for file in immediate_rust_files(&scope_dir) {
            if intents.contains(&file) {
                continue;
            }
            if !file.with_extension("").is_dir() {
                offenders.push(format!(
                    "{} is neither a registered intent handler nor a `<family>.rs` \
                     manifest with a matching `<family>/` directory",
                    file.strip_prefix(root).unwrap().display()
                ));
            }
        }
        for family_dir in immediate_subdirs(&scope_dir) {
            if !family_dir.with_extension("rs").is_file() {
                offenders.push(format!(
                    "{} has no `<family>.rs` manifest beside it",
                    family_dir.strip_prefix(root).unwrap().display()
                ));
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "directly under a scope, only intent handlers and `<family>.rs` manifests \
         (each paired with a `<family>/` directory) may appear:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn target_handler_files_do_not_define_fact_or_crypto_outputs() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));

    let mut offenders = Vec::new();
    for path in intent_handler_files(root) {
        let text = source_text(&path);
        let production = production_text_before_unit_tests(&text);
        for forbidden in [
            "Fact::new",
            "FactScope",
            "ScopeKind",
            "TYPE_",
            "KEY_WRAP_BYTES",
            "encode_key_wrap",
            "decode_key_wrap",
            "sender_wrap_public_key",
            "ciphertext",
            "nonce",
            "crypto::xchacha20poly1305_encrypt",
            "crypto::xchacha20poly1305_decrypt",
            "crypto::x25519_xchacha20poly1305_encrypt",
            "crypto::x25519_xchacha20poly1305_decrypt",
            "crypto::ed25519_sign",
            "crypto::ed25519_verify",
            "placeholder",
            "fake",
            "crate::core::wire",
            "wire::",
        ] {
            if production.contains(forbidden) {
                offenders.push(format!(
                    "{} contains {forbidden:?}",
                    path.strip_prefix(root).unwrap().display()
                ));
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "handler files should encode/decode payloads and execute bounded effects, not define facts or crypto outputs:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn connection_intents_treat_connection_frames_as_opaque() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let connection_handlers = intent_handler_files(root)
        .into_iter()
        .filter(|path| {
            path.parent()
                .and_then(|parent| parent.file_name())
                .is_some_and(|scope| scope == "connection")
        })
        .collect::<Vec<_>>();
    assert!(
        !connection_handlers.is_empty(),
        "connection scope should still own verb-named intent handler files"
    );

    let mut offenders = Vec::new();
    for path in connection_handlers {
        let text = source_text(&path);
        let production = strip_line_comments(production_text_before_unit_tests(&text));
        for forbidden in [
            "canonical_events",
            "protocol::encryption",
            "XChaCha",
            "X25519",
            "ciphertext",
            "nonce",
            "encrypt",
            "decrypt",
        ] {
            if production.contains(forbidden) {
                offenders.push(format!(
                    "{} contains {forbidden:?}",
                    path.strip_prefix(root).unwrap().display()
                ));
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "connection intents must treat connection::frame frames as opaque network bytes:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn signed_fact_envelope_does_not_dispatch_to_child_event_modules() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let signed_root = root.join("src/protocol/identity/signed_fact");
    if !signed_root.exists() {
        return;
    }

    let mut files = rust_files(&signed_root);
    files.push(root.join("src/protocol/identity/signed_fact.rs"));

    let mut offenders = Vec::new();
    for path in files {
        let text = source_text(&path);
        let production = production_text_before_unit_tests(&text);
        for forbidden in [
            "protocol::encryption",
            "protocol::content::message",
            "protocol::sync",
            "protocol::identity::workspace",
            "decode_key_wrap",
            "encode_key_wrap",
            "ContentMessage",
            "KeyWrapFact",
            "Intent",
            "HandlerOutput",
        ] {
            if production.contains(forbidden) {
                offenders.push(format!(
                    "{} contains {forbidden:?}",
                    path.strip_prefix(root).unwrap().display()
                ));
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "identity::signed_fact must stay an envelope helper, not a central protocol dispatcher:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn core_pipeline_stays_protocol_neutral() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let path = root.join("src/core/pipeline.rs");
    let text = source_text(&path);
    let production = production_text_before_unit_tests(&text);
    let mut offenders = Vec::new();

    for forbidden in [
        "crate::protocol",
        "topo::protocol",
        "KeyWrap",
        "Transit",
        "Connection",
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
        "core intent pipeline must stay generic and protocol-neutral:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn target_schema_sources_are_explicit_sql_only() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let schema_owners = [
        root.join("src/core/schema.rs"),
        root.join("src/core/network.rs"),
        root.join("src/protocol/registry.rs"),
    ];
    let mut offenders = Vec::new();

    for path in schema_owners {
        let text = source_text(&path);
        for forbidden in ["include_str!", ".p8sql", "parse_schema", "schema_dsl"] {
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
        "poc-10 schema sources should be plain executable SQL DDL, not a runtime parser layer:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn target_schema_substrate_stays_protocol_neutral() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let path = root.join("src/core/store.rs");
    let text = source_text(&path);
    let production = production_text_before_unit_tests(&text);
    let mut offenders = Vec::new();

    for forbidden in [
        "crate::protocol",
        "crate::legacy::protocol",
        "crate::legacy::workers",
        "Intent",
        "ProjectionOutput",
        "ContextNeed",
        "ContextOffer",
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
        "core store schema application should stay protocol-neutral:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn target_layout_files_do_not_own_projection_intents_handlers_or_cli() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut offenders = Vec::new();
    for path in fact_family_files_named(root, "layout.rs") {
        // Strip comments so module-boundary doc prose (which may legitimately
        // name Projectors/Intents to explain what layout.rs must NOT do) does
        // not register as projection/intent/handler code.
        let text = strip_line_comments(&source_text(&path));
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
            "core::network",
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
    for path in fact_family_files_named(root, "project.rs") {
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
        "project.rs should emit row mutations through row helpers, not define row tables or shapes:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn target_cli_equivalents_do_not_exist_or_parse_user_commands() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut offenders = Vec::new();
    for path in fact_family_files(root)
        .into_iter()
        .filter(|path| path.file_name().is_none_or(|name| name != "cli.rs"))
        .chain(intent_handler_files(root))
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
        "target fact modules and intent handlers must not grow CLI-equivalent parsing or formatting:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn protocol_cli_files_do_not_own_app_runtime_effects() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut offenders = Vec::new();
    for path in fact_family_files_named(root, "cli.rs") {
        let text = source_text(&path);
        for forbidden in [
            "Runtime::open",
            "Runtime::<",
            "Store::open",
            "core::cli::run",
            "MATCH_CLI_COMMANDS",
            "dispatch_cli_intents",
            "dispatch_deferred",
            "drain_projection",
            "drain_runtime",
            ".save(",
            "println!",
            "eprintln!",
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
        "protocol cli.rs files should parse argv and format command output, while app/runtime owns store open, dispatch, drain, save, and printing:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn match_app_selects_protocol_description() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let path = root.join("src/match_app.rs");
    let text = source_text(&path);
    let production = strip_line_comments(production_text_before_unit_tests(&text));

    assert!(
        production.contains("core::app::run(&crate::protocol::app::MATCH_PROTOCOL"),
        "match_app.rs should only choose the concrete protocol description"
    );
    assert!(
        !production.contains("match parsed.command.first"),
        "match_app.rs must not restore the broad manual command-name router"
    );
    assert!(
        !production.contains("MATCH_COMMANDS") && !production.contains("MATCH_CLI_COMMANDS"),
        "match_app.rs should not manually wire the protocol command table"
    );
    for command in [
        "create-workspace",
        "invite",
        "key-recipient",
        "send",
        "messages",
        "generate",
    ] {
        let needle = format!("Some(\"{command}\")");
        assert!(
            !production.contains(&needle),
            "match_app.rs must not dispatch protocol command {command:?} through a broad top-level match"
        );
    }
    let core_app = source_text(&root.join("src/core/app.rs"));
    assert!(
        core_app.contains("\"start\" => run_start")
            && core_app.contains("\"stop\" => run_stop")
            && core_app.contains("\"reset\" => run_reset"),
        "daemon lifecycle commands should stay registered in the generic app boundary"
    );
}

#[test]
fn target_handlers_do_not_own_projection_rows_or_projector_context() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));

    let mut offenders = Vec::new();
    for path in intent_handler_files(root) {
        let text = source_text(&path);
        let production = production_text_before_unit_tests(&text);
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
            if production.contains(forbidden) {
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

#[test]
fn target_handlers_do_not_define_fact_wire_layouts_or_fake_crypto_facts() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));

    let mut offenders = Vec::new();
    for path in intent_handler_files(root) {
        let text = source_text(&path);
        let production = production_text_before_unit_tests(&text);
        for forbidden in [
            "crate::core::facts",
            "Fact::new",
            "FactScope",
            "ScopeKind",
            "const TYPE_",
            "pub const TYPE_",
            "FixedLayout",
            "FixedSlot",
            "KeyWrapFact",
            "LocalKeySecretFact",
            "LocalHistoryNodeSecretFact",
            "LocalRecipientKeyFact",
            "encode_local_key_secret",
            "encode_local_history_node_secret",
            "encode_local_recipient_key",
            "decode_signed_fact",
            "decode_key_wrap",
            "decode_recipient_key",
            "decode_local_recipient_key",
            "crate::core::wire",
            "wire::",
            "put_u8",
            "take_u8",
            "expect_len",
            "ciphertext",
            "nonce",
            "crypto::xchacha20poly1305_encrypt",
            "crypto::xchacha20poly1305_decrypt",
            "crypto::x25519_xchacha20poly1305_encrypt",
            "crypto::x25519_xchacha20poly1305_decrypt",
            "crypto::ed25519_sign",
            "crypto::ed25519_verify",
            "placeholder",
            "fake",
        ] {
            if production.contains(forbidden) {
                offenders.push(format!(
                    "{} contains {forbidden:?}",
                    path.strip_prefix(root).unwrap().display()
                ));
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "intent handlers must not define protocol fact wire layouts, fact-module fact tags, or crypto-shaped placeholder facts; put fact shapes and fixed bytes in their scope's fact-family modules:\n{}",
        offenders.join("\n")
    );
}
