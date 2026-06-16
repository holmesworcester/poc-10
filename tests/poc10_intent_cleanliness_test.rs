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

fn production_text_before_unit_tests(text: &str) -> String {
    let mut production = String::new();
    let mut cursor = 0;
    while let Some(relative_attr) = text[cursor..].find("#[cfg(test)]") {
        let attr_start = cursor + relative_attr;
        production.push_str(&text[cursor..attr_start]);
        let after_attr = attr_start + "#[cfg(test)]".len();
        let Some(relative_open) = text[after_attr..].find('{') else {
            cursor = after_attr;
            break;
        };
        let open = after_attr + relative_open;
        let mut depth = 0i32;
        let mut end = open;
        for (offset, ch) in text[open..].char_indices() {
            match ch {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        end = open + offset + ch.len_utf8();
                        break;
                    }
                }
                _ => {}
            }
        }
        cursor = end;
    }
    production.push_str(&text[cursor..]);
    production
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

fn public_wire_byte_constants(text: &str) -> BTreeSet<String> {
    text.lines()
        .filter_map(|line| {
            let trimmed = line.trim_start();
            let rest = trimmed.strip_prefix("pub const ")?;
            let (name, rest) = rest.split_once(':')?;
            if !rest.trim_start().starts_with("usize") {
                return None;
            }
            let name = name.trim();
            if name == "FACT_BYTES" || name == "ENCODED_BYTES" || name.ends_with("_BYTES") {
                Some(name.to_string())
            } else {
                None
            }
        })
        .collect()
}

fn exact_len_guard_constants(text: &str, constants: &BTreeSet<String>) -> BTreeSet<String> {
    let mut found = BTreeSet::new();

    for constant in constants {
        for marker in [
            format!("expect_len(bytes, {constant})"),
            format!(".expect_len({constant})"),
            format!("finish_exact({constant})"),
            format!("const LEN: usize = {constant}"),
            format!("bytes.len() != {constant}"),
        ] {
            if text.contains(&marker) {
                found.insert(constant.clone());
            }
        }
    }

    found
}

fn layout_has_fact_codec(text: &str) -> bool {
    text.contains("pub fn encode") && text.contains("pub fn decode")
}

fn test_text(text: &str) -> &str {
    text.find("#[cfg(test)]")
        .map(|index| &text[index..])
        .unwrap_or("")
}

/// Protocol scope directories. Since the package-by-scope migration
/// each scope directory holds BOTH fact-family modules and verb-named intent
/// handler files, replacing the old `src/protocol/facts` and
/// `src/protocol/intents` layer roots.
const SCOPES: [&str; 4] = ["auth", "connection", "content", "sync"];

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
/// directory; there is no separate `src/protocol/intents` tree.
fn intent_handler_files(root: &Path) -> Vec<PathBuf> {
    const HANDLERS: &[(&str, &[&str])] = &[
        ("auth", &["create_key_wrap", "unwrap_key_wrap"]),
        (
            "connection",
            &[
                "create_connection",
                "maintain_connections",
                "send_facts_on_connection",
                "queue_outgoing_frame",
            ],
        ),
        ("content", &[]),
        (
            "sync",
            &[
                "maintain_sync",
                "seed_connection",
                "send_compare_response",
                "send_needed_fact_id",
                "send_requested_fact",
                "share_fact_with_sync",
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
    let production = strip_line_comments(&production_text_before_unit_tests(text));
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
        let production = strip_line_comments(&production_text_before_unit_tests(&text));
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
        let production = strip_line_comments(&production_text_before_unit_tests(&text));
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
        let production = strip_line_comments(&production_text_before_unit_tests(&text));
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
        if !production.contains("//! POLICY.") && !production.contains("// POLICY.") {
            missing.push("`POLICY.`");
        }
        // With primary helpers local to `project.rs`, a projector body starts at
        // whatever section it actually owns: scope/context (`// 2.`) or, for a
        // minimal projector that only writes rows, materialize (`// 3.`). Any
        // numbered body marker satisfies "policy mirrored in the body"; require
        // at least one.
        if !production.contains("// 1.")
            && !production.contains("// 2.")
            && !production.contains("// 3.")
        {
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
fn target_projectors_decode_validate_and_adapt_before_projecting() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut missing_delegation = Vec::new();
    let mut missing_module = Vec::new();
    let mut legacy_surface = Vec::new();

    for path in fact_family_files_named(root, "project.rs") {
        let relative = path.strip_prefix(root).unwrap().display().to_string();
        let text = source_text(&path);
        let production = strip_line_comments(&production_text_before_unit_tests(&text));
        if !production.contains("impl Projector for") {
            // A project.rs that owns no projector (shared coordinate helpers) is
            // not a routed fact family. Helper directories under protocol scopes
            // are rejected elsewhere; this branch only keeps utility project
            // modules outside fact-family directories from being routed.
            continue;
        }

        let decodes_or_validates = production.contains("decode::")
            && (production.contains("decode_") || production.contains("validate_sealed_fact"));
        let validates = production.contains("authenticate::authenticate(");
        let adapts = production.contains("adapt::adapt(");
        if !(decodes_or_validates && validates && adapts) {
            missing_delegation.push(relative.clone());
        }

        // The removed staged/composed-model surfaces must not reappear.
        for legacy in [
            concat!("project_", "staged"),
            concat!("Semantic", "Projector"),
            concat!("Fact", "Codec"),
            concat!("Decoded", "Authenticator"),
            "project_authenticated",
            "AuthenticatedProjector",
            "ProjectorComposed",
        ] {
            if production.contains(legacy) {
                legacy_surface.push(format!("{relative} still references {legacy}"));
            }
        }

        for module in [
            "pub mod decode {",
            "pub mod authenticate {",
            "pub mod adapt {",
        ] {
            if !text.contains(module) {
                missing_module.push(format!("{relative} missing local {module:?}"));
            }
        }
        for removed_file in ["decode.rs", "authenticate.rs", "adapt.rs"] {
            if path.with_file_name(removed_file).is_file() {
                legacy_surface.push(format!(
                    "{} still has sibling {removed_file}",
                    path.with_file_name(removed_file)
                        .strip_prefix(root)
                        .unwrap()
                        .display()
                ));
            }
        }
        if text.contains("pub mod decode;")
            || text.contains("pub mod authenticate;")
            || text.contains("pub mod adapt;")
        {
            missing_module.push(relative);
        }
    }

    assert!(
        missing_delegation.is_empty(),
        "every fact-module Projector::project must call its local decode/validate, \
         authenticate, and adapt helpers before projector policy runs:\n{}",
        missing_delegation.join("\n")
    );
    assert!(
        legacy_surface.is_empty(),
        "the staged/composed model is removed; no project.rs may reference old staged \
         or composed projector surfaces:\n{}",
        legacy_surface.join("\n")
    );
    assert!(
        missing_module.is_empty(),
        "every routed fact family must own projector-local decode/authenticate/adapt modules \
         and must not re-export them as sibling role files:\n{}",
        missing_module.join("\n")
    );
}

#[test]
fn target_projectors_do_not_verify_signatures() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut offenders = Vec::new();

    for path in fact_family_files_named(root, "project.rs") {
        let text = source_text(&path);
        let production = strip_line_comments(&production_text_before_unit_tests(&text));
        if production.contains("verify_signature") {
            offenders.push(path.strip_prefix(root).unwrap().display().to_string());
        }
    }

    assert!(
        offenders.is_empty(),
        "projectors must not verify signatures. The primary fact's signature is proven by the \
         family projector-local authenticate module, and any fact a projector reads from context was authenticated \
         before it could offer that context — so its authenticity is guaranteed. A projector \
         decodes context facts for their fields and proves relationships, but never re-verifies \
         a signature:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn target_read_stages_do_not_import_author_role_files() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut offenders = Vec::new();

    for name in ["project.rs"] {
        for path in fact_family_files_named(root, name) {
            let relative = path.strip_prefix(root).unwrap().display().to_string();
            let text = source_text(&path);
            let production = strip_line_comments(&production_text_before_unit_tests(&text));
            for marker in [
                "use super::author",
                "super::{author",
                "::author::",
                "author::",
            ] {
                if production.contains(marker) {
                    offenders.push(format!("{relative} contains {marker:?}"));
                }
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "project.rs read-side helpers must not import \
         author.rs. Move shared deterministic bytes to encode.rs, and read-side \
         proof helpers to the projector-local authenticate module or a neutral standard role:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn target_authors_do_not_own_projection_stage_output() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut offenders = Vec::new();

    for path in fact_family_files_named(root, "author.rs") {
        let relative = path.strip_prefix(root).unwrap().display().to_string();
        let text = source_text(&path);
        let production = strip_line_comments(&production_text_before_unit_tests(&text));
        for marker in [
            "ProjectionContext",
            "ProjectionOutput",
            "impl Projector",
            "project_semantic",
            "project_observed_frame",
        ] {
            if production.contains(marker) {
                offenders.push(format!("{relative} contains {marker:?}"));
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "author.rs constructs facts; it must not own projection context, projection \
         output, or projector helpers:\n{}",
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
        let production = strip_line_comments(&production_text_before_unit_tests(&text));
        for marker in ["layout as ", "_layout::decode_fact", "_layout::decode_"] {
            if production.contains(marker) {
                offenders.push(format!("{relative} contains {marker:?}"));
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "projectors should reason over typed fact helpers, not foreign layout codecs. \
         The owning fact module may decode primary bytes; cross-module projector \
         policy should call named typed helpers/witnesses:\n{}",
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
        "protocol-specific fact-module context.rs files are dumping-ground risks, not a target source of truth. Core-owned src/core/context.rs is allowed; put nontrivial range encoders and matched-payload validation beside the domain that validates them instead:\n{}",
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
        offenders.push(path.strip_prefix(root).unwrap().display().to_string());
    }

    assert!(
        offenders.is_empty(),
        "the legacy ContextMatcher API is retired; use core-owned byte-range overlap and projector/domain matched-payload validation instead:\n{}",
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
        "temporary protocol context.rs helper files are not the context source of truth; range encoders and matched-payload validation belong beside their domain, while ProjectionContext inspection belongs in project.rs:\n{}",
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
fn protocol_fact_fields_stay_fixed_width() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut offenders = Vec::new();

    for path in fact_family_files_named(root, "fact.rs") {
        let relative = path.strip_prefix(root).unwrap().display().to_string();
        let text = source_text(&path);
        for (line_number, line) in text.lines().enumerate() {
            let trimmed = line.trim_start();
            if trimmed.starts_with("//") || !trimmed.contains("pub ") {
                continue;
            }
            if trimmed.contains(": Vec<") || trimmed.contains(": String") {
                offenders.push(format!("{relative}:{}: {trimmed}", line_number + 1));
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "protocol fact fields must be fixed-width at the fact boundary. Use FixedSlot<N>, FixedText<N>, fixed arrays, or an owning bounded struct instead of Vec/String fields:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn protocol_fact_layouts_have_exact_byte_roundtrip_guardrails() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut offenders = Vec::new();

    for path in fact_family_files_named(root, "layout.rs") {
        let relative = path.strip_prefix(root).unwrap().display().to_string();
        let text = source_text(&path);
        let production = strip_line_comments(&production_text_before_unit_tests(&text));
        if !layout_has_fact_codec(&production) {
            continue;
        }

        let constants = public_wire_byte_constants(&production);
        let exact_constants = exact_len_guard_constants(&production, &constants);
        if exact_constants.is_empty() {
            offenders.push(format!(
                "{relative}: public layout codecs need a public exact *_BYTES constant used by expect_len, finish_exact, FixedLayout::LEN, or an explicit bytes.len() check"
            ));
        }

        let tests = test_text(&text);
        let lower_tests = tests.to_ascii_lowercase();
        let mentions_exact_length_assertion = exact_constants
            .iter()
            .any(|constant| tests.contains(constant) && tests.contains(".len()"));
        if !lower_tests.contains("roundtrip") || !mentions_exact_length_assertion {
            offenders.push(format!(
                "{relative}: add a local fixed-width encode/decode roundtrip test that asserts encoded.len() against the exact layout byte constant"
            ));
        }
    }

    assert!(
        offenders.is_empty(),
        "protocol fact layouts must make exact byte width executable, not just conventional:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn retired_signing_wrapper_and_content_event_families_do_not_reappear() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let forbidden_paths = [
        "src/protocol/auth/signed_fact.rs",
        "src/protocol/auth/signed_fact",
        "src/protocol/auth/signed_envelope.rs",
        "src/protocol/auth/signed_envelope",
        "src/protocol/content_event.rs",
        "src/protocol/content_event",
        "src/protocol/content/event.rs",
        "src/protocol/content/event",
    ];
    let mut offenders = forbidden_paths
        .into_iter()
        .filter(|path| root.join(path).exists())
        .map(str::to_string)
        .collect::<Vec<_>>();

    for path in rust_files(&root.join("src/protocol")) {
        let relative = path.strip_prefix(root).unwrap().display().to_string();
        let production =
            strip_line_comments(&production_text_before_unit_tests(&source_text(&path)));
        for marker in [
            "signed_fact",
            "SignedFact",
            "TYPE_SIGNED_FACT",
            "signed_envelope",
            "SignedEnvelope",
            "TYPE_SIGNED_ENVELOPE",
            "decode_signed_envelope",
            "decode_raw_or_signed_fact",
            "content_event",
            "ContentEvent",
        ] {
            if production.contains(marker) {
                offenders.push(format!("{relative} contains {marker:?}"));
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "signed_fact, signed_envelope, and content_event are retired protocol wrappers. Shareable facts own signer identity fields, while deterministic key_wrap remains the raw exception:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn signer_bearing_author_helpers_do_not_claim_to_sign() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let forbidden_helpers = [
        "signed_admin_fact",
        "signed_device_invite_fact",
        "signed_endpoint_shared_fact",
        "signed_file_fact",
        "signed_file_slice_fact",
        "signed_invite_server_fact",
        "signed_reaction_fact",
        "signed_recipient_key_fact",
        "signed_removal_frontier_fact",
        "signed_retention_policy_fact",
        "signed_user_fact",
        "signed_user_invite_fact",
        "CreateSignedUser",
        "create_signed",
    ];
    let mut offenders = Vec::new();

    for path in rust_files(&root.join("src/protocol")) {
        let relative = path.strip_prefix(root).unwrap().display().to_string();
        let production =
            strip_line_comments(&production_text_before_unit_tests(&source_text(&path)));
        for marker in forbidden_helpers {
            if production.contains(marker) {
                offenders.push(format!("{relative} contains {marker:?}"));
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "target fact helpers should author signer identity only; commands create separate signature evidence:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn live_readme_examples_keep_signature_evidence_separate() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut offenders = Vec::new();

    for relative in [
        "src/protocol/auth/README.md",
        "src/protocol/content/README.md",
    ] {
        let text = source_text(&root.join(relative));
        for (index, block) in text.split("```text").skip(1).enumerate() {
            let block = block.split("```").next().unwrap_or(block);
            if block.contains("signature: sig(") && !block.trim_start().starts_with("signature {") {
                offenders.push(format!("{relative} text block {}", index + 1));
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "live README target fact examples must not embed signatures; use a separate signature evidence block:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn signing_wrappers_stay_out_of_projector_routing() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut offenders = Vec::new();
    for path in [
        "src/protocol/auth/signed_fact/project.rs",
        "src/protocol/auth/signed_envelope/project.rs",
    ] {
        let path = root.join(path);
        if path.exists() {
            offenders.push(path.strip_prefix(root).unwrap().display().to_string());
        }
    }

    let registry = source_text(&root.join("src/protocol/registry.rs"));
    let fact_routes = registry
        .split("macro_rules! handler_route")
        .next()
        .unwrap_or(registry.as_str());
    for marker in [
        "TYPE_SIGNED_FACT",
        "TYPE_SIGNED_ENVELOPE",
        "project_auth_signed_fact",
        "project_auth_signed_envelope",
    ] {
        if fact_routes.contains(marker) {
            offenders.push(format!("src/protocol/registry.rs contains {marker:?}"));
        }
    }

    assert!(
        offenders.is_empty(),
        "signing wrappers are retired; target fact projectors consume signature evidence:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn retired_connection_frame_large_names_do_not_reappear() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut offenders = Vec::new();
    for path in rust_files(&root.join("src/protocol")) {
        let relative = path.strip_prefix(root).unwrap().display().to_string();
        let production =
            strip_line_comments(&production_text_before_unit_tests(&source_text(&path)));
        for marker in [
            "ConnectionFrameLarge",
            "CONNECTION_FRAME_LARGE",
            "TYPE_CONNECTION_FRAME_LARGE",
            "CONNECTION_FRAME_SIZE_CLASS_LARGE",
        ] {
            if production.contains(marker) {
                offenders.push(format!("{relative} contains {marker:?}"));
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "connection frames are small, file-slice, or bundle frames. Do not reintroduce a generic large frame class:\n{}",
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
        "there is no root command module. User-facing command primitives live in src/core/command.rs, and module commands stay under protocol fact modules:\n{}",
        offenders.join("\n")
    );

    assert!(
        !root.join("src/core/command_context.rs").exists(),
        "src/core/command_context.rs should not reappear"
    );
    assert!(
        root.join("src/core/command.rs").is_file(),
        "missing src/core/command.rs"
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

    let protocol_root = source_text(&root.join("src/protocol.rs"));
    assert!(
        !root.join("src/protocol/payload.rs").exists()
            && !protocol_root.contains("pub mod payload;"),
        "intent payload byte codecs should live in their owning intent modules, not in a top-level protocol/payload shim"
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
const STANDARD_FAMILY_FILES: [&str; 10] = [
    "fact.rs",
    "encode.rs",
    "author.rs",
    // Primary decode, authentication, and adaptation live as local modules in
    // project.rs so the projector owns the complete read path.
    "project.rs",
    "queries.rs",
    "commands.rs",
    "cli.rs",
    // Sync support roles that are not fact-family row detours.
    "index.rs",
    "staging.rs",
    // Wire-transport encoding for a fact family whose canonical bytes are sent
    // sealed on the wire (request/connection), kept separate from the
    // durable `encode.rs`.
    "transit.rs",
];

/// Fact families that do not yet meet the standard-role-file rule.
const FAMILY_FILE_RULE_EXCEPTIONS: [&str; 0] = [];

/// Scope-local directories that are deliberately not fact families.
const NON_FACT_SCOPE_DIR_EXCEPTIONS: [&str; 0] = [];

/// Scope-local helper files that are deliberately not intents or fact-family
/// manifests. These must stay rare and named explicitly.
const SCOPE_LOCAL_HELPER_FILE_EXCEPTIONS: [&str; 2] = [
    "connection/receive_network_frame.rs",
    "sync/local_setting.rs",
];

/// Fact-scope files that deliberately host a command parsing boundary because
/// their command is just local setting authoring, not semantic protocol work.
const CLI_BOUNDARY_FILE_EXCEPTIONS: [&str; 1] = ["src/protocol/sync/local_setting.rs"];

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
const INTENT_VERBS: [&str; 11] = [
    "add", "create", "send", "receive", "purge", "share", "seed", "unwrap", "update", "maintain",
    "queue",
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
            let relative = file
                .strip_prefix(root.join("src/protocol"))
                .unwrap()
                .display()
                .to_string();
            if SCOPE_LOCAL_HELPER_FILE_EXCEPTIONS.contains(&relative.as_str()) {
                continue;
            }
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
    // Only intents and named helper files linger outside of facts. Every `.rs`
    // file directly under a scope directory is either a registered intent
    // handler, an explicitly allowed helper, or a `<family>.rs` manifest paired
    // with a `<family>/` directory. Every subdirectory is a fact family paired
    // with its manifest.
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let intents = intent_handler_file_set(root);
    let mut offenders = Vec::new();

    for scope_dir in scope_dirs(root) {
        for file in immediate_rust_files(&scope_dir) {
            if intents.contains(&file) {
                continue;
            }
            let relative = file
                .strip_prefix(root.join("src/protocol"))
                .unwrap()
                .display()
                .to_string();
            if SCOPE_LOCAL_HELPER_FILE_EXCEPTIONS.contains(&relative.as_str()) {
                continue;
            }
            if !file.with_extension("").is_dir() {
                offenders.push(format!(
                    "{} is neither a registered intent handler, an allowed helper, nor a `<family>.rs` \
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
            let scope = scope_dir.file_name().unwrap().to_str().unwrap();
            let family = family_dir.file_name().unwrap().to_str().unwrap();
            let relative_key = format!("{scope}/{family}");
            let has_normal_fact_shape = family_dir.join("fact.rs").is_file()
                && (family_dir.join("layout.rs").is_file()
                    || family_dir.join("encode.rs").is_file())
                && family_dir.join("project.rs").is_file();
            if !has_normal_fact_shape
                && !NON_FACT_SCOPE_DIR_EXCEPTIONS.contains(&relative_key.as_str())
            {
                offenders.push(format!(
                    "{} is a scope-local helper directory, not a normal fact family",
                    family_dir.strip_prefix(root).unwrap().display()
                ));
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "directly under a scope, only intent handlers, explicitly allowed helpers, and \
         `<family>.rs` manifests (each paired with a `<family>/` directory) may appear:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn received_connection_frame_families_have_create_role_files() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut offenders = Vec::new();

    for family in [
        "frame_small",
        "frame_file_slice",
        "frame_bundle",
        "frame_observation",
    ] {
        let manifest = root
            .join("src/protocol/connection")
            .join(format!("{family}.rs"));
        let dir = root.join("src/protocol/connection").join(family);
        if !dir.join("author.rs").is_file() {
            offenders.push(format!(
                "src/protocol/connection/{family}/author.rs is missing"
            ));
        }
        if !source_text(&manifest).contains("pub mod author;") {
            offenders.push(format!(
                "src/protocol/connection/{family}.rs does not declare author"
            ));
        }
    }

    assert!(
        offenders.is_empty(),
        "received connection-frame fact families must keep boundary construction in author.rs:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn connection_frame_wire_facts_do_not_embed_observation_metadata() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut offenders = Vec::new();

    for family in ["frame_small", "frame_file_slice", "frame_bundle"] {
        let fact = source_text(
            &root
                .join("src/protocol/connection")
                .join(family)
                .join("fact.rs"),
        );
        for forbidden in ["origin_addr", "received_at_local_ms", "OriginAddr"] {
            if fact.contains(forbidden) {
                offenders.push(format!(
                    "src/protocol/connection/{family}/fact.rs embeds {forbidden:?}"
                ));
            }
        }
        if !fact.contains("pub frame:") {
            offenders.push(format!(
                "src/protocol/connection/{family}/fact.rs does not expose the wire frame"
            ));
        }
    }

    let observation = source_text(
        &root
            .join("src/protocol/connection/frame_observation")
            .join("fact.rs"),
    );
    for required in ["frame_fact_id", "origin_addr", "received_at_local_ms"] {
        if !observation.contains(required) {
            offenders.push(format!(
                "src/protocol/connection/frame_observation/fact.rs missing {required:?}"
            ));
        }
    }

    assert!(
        offenders.is_empty(),
        "connection frame facts must stay canonical wire facts; receive metadata belongs only in connection_frame_observation:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn connection_frame_send_and_receive_paths_use_frame_fact_create_helpers() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let receive = source_text(&root.join("src/protocol/connection/receive_network_frame.rs"));
    let send = source_text(&root.join("src/protocol/connection/send_facts_on_connection.rs"));
    let mut offenders = Vec::new();

    for family in ["frame_small", "frame_file_slice", "frame_bundle"] {
        let direct_create = format!("{family}::author::fact_from_wire");
        if !receive.contains(&direct_create) {
            offenders.push(format!(
                "receive_network_frame.rs does not create {family} through author.rs"
            ));
        }
        let direct_seal = format!("{family}::author::seal_connection_send_frame");
        if !send.contains(&direct_seal) {
            offenders.push(format!(
                "send_facts_on_connection.rs does not seal {family} through author.rs"
            ));
        }
    }
    for forbidden in [
        "frame_policy::",
        "connection::frame_wire",
        "connection::frame::",
    ] {
        if receive.contains(forbidden) || send.contains(forbidden) {
            offenders.push(format!(
                "connection send/receive still imports shared helper marker {forbidden:?}"
            ));
        }
    }

    assert!(
        offenders.is_empty(),
        "send and receive should go through concrete frame-family author.rs files; only receive emits observation context intents:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn connection_frame_helpers_do_not_reappear() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut offenders = Vec::new();
    for path in [
        "src/protocol/connection_frame.rs",
        "src/protocol/connection_frame_wire.rs",
        "src/protocol/connection/frame.rs",
        "src/protocol/connection/frame_wire.rs",
    ] {
        if root.join(path).exists() {
            offenders.push(path);
        }
    }

    let root_manifest = source_text(&root.join("src/protocol.rs"));
    let connection_manifest = source_text(&root.join("src/protocol/connection.rs"));
    for (manifest, marker) in [
        (&root_manifest, "pub mod connection_frame;"),
        (&root_manifest, "pub mod connection_frame_wire;"),
        (&connection_manifest, "pub mod frame;"),
        (&connection_manifest, "pub mod frame_wire;"),
    ] {
        if manifest.contains(marker) {
            offenders.push(marker);
        }
    }

    assert!(
        offenders.is_empty(),
        "connection-frame helpers must not reappear; concrete frame families own their own flat encode/decode/author/project code:\n{}",
        offenders.join("\n")
    );
}
#[test]
fn fact_like_family_directories_are_registered_normal_fact_modules() {
    // A directory that owns a fact shape (`fact.rs`) or byte tag/layout
    // (`layout.rs` or the target `encode.rs` plus projector-local decode) is a
    // real fact family. Real fact families have uniform role files and must be
    // present in the protocol projector route table;
    // helper/context-only modules are not fact-like unless they introduce a
    // fact shape or layout.
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let registry = source_text(&root.join("src/protocol/registry.rs"));
    let mut offenders = Vec::new();

    for scope_dir in scope_dirs(root) {
        let scope = scope_dir.file_name().unwrap().to_str().unwrap();
        for family_dir in immediate_subdirs(&scope_dir) {
            let family = family_dir.file_name().unwrap().to_str().unwrap();
            let has_fact = family_dir.join("fact.rs").is_file();
            let has_layout =
                family_dir.join("layout.rs").is_file() || family_dir.join("encode.rs").is_file();
            if !has_fact && !has_layout {
                continue;
            }

            let relative = family_dir.strip_prefix(root).unwrap().display();
            let has_project = family_dir.join("project.rs").is_file();
            if !has_fact || !has_layout || !has_project {
                offenders.push(format!(
                    "{relative} is fact-like but does not have fact.rs, layout.rs or encode.rs, and project.rs"
                ));
                continue;
            }

            let layout_route = format!("{scope}::{family}::");
            let project_route = format!("{scope}::{family}::project::");
            if !registry.contains(&layout_route) || !registry.contains(&project_route) {
                offenders.push(format!(
                    "{relative} is fact-like but is not registered in FACT_ROUTES"
                ));
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "fact-like protocol directories must be normal registered fact modules:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn fact_like_family_directories_are_single_flat_fact_shapes() {
    // A registered fact family should introduce one flat fact shape and one
    // projector route. Multiple fact structs or multiple routes through the
    // same family are a sign that a discriminated family should be split into
    // separate noun-named fact families.
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let registry = source_text(&root.join("src/protocol/registry.rs"));
    let mut offenders = Vec::new();

    for scope_dir in scope_dirs(root) {
        let scope = scope_dir.file_name().unwrap().to_str().unwrap();
        for family_dir in immediate_subdirs(&scope_dir) {
            let family = family_dir.file_name().unwrap().to_str().unwrap();
            let fact_path = family_dir.join("fact.rs");
            let layout_path = family_dir.join("layout.rs");
            let split_layout = family_dir.join("encode.rs").is_file();
            if !fact_path.is_file() && !layout_path.is_file() && !split_layout {
                continue;
            }

            let relative = family_dir.strip_prefix(root).unwrap().display();
            if fact_path.is_file() {
                let fact_text = source_text(&fact_path);
                let fact_structs = fact_text
                    .lines()
                    .filter(|line| line.trim_start().starts_with("pub struct "))
                    .filter(|line| line.contains("Fact"))
                    .count();
                if fact_structs != 1 {
                    offenders.push(format!(
                        "{relative} declares {fact_structs} public fact structs"
                    ));
                }
            }

            let route_marker = format!(", {scope}::{family}::project::");
            let route_count = registry
                .lines()
                .filter(|line| {
                    let line = line.trim();
                    line.starts_with("project_")
                        && line.contains("=>")
                        && line.contains(&route_marker)
                })
                .count();
            if route_count != 1 {
                offenders.push(format!("{relative} has {route_count} projector routes"));
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "fact-like protocol directories must stay flat: one fact shape and one route per family:\n{}",
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
        let production = strip_line_comments(&production_text_before_unit_tests(&text));
        // Connection intent handlers must not hand-roll connection crypto: the
        // wire seal/open primitives live in the request/response layout modules
        // and established-frame wire modules, not in handlers. Loading the local
        // endpoint to open a first-contact request in create_connection
        // is allowed, so this rule targets the crypto primitives rather than any
        // auth dependency.
        for forbidden in [
            "canonical_events",
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
        "connection intents must treat connection::frame frames as opaque network bytes and must not hand-roll connection crypto:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn retired_signed_envelope_module_does_not_reappear() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let signed_root = root.join("src/protocol/auth/signed_envelope");
    let mut offenders = Vec::new();
    if signed_root.exists() {
        offenders.push("src/protocol/auth/signed_envelope".to_string());
    }
    if root.join("src/protocol/auth/signed_envelope.rs").exists() {
        offenders.push("src/protocol/auth/signed_envelope.rs".to_string());
    }

    assert!(
        offenders.is_empty(),
        "auth::signed_envelope is retired; signer-bearing facts use separate signature evidence:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn core_runtime_workers_stay_protocol_neutral() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let paths = [
        root.join("src/core/project_fact.rs"),
        root.join("src/core/handle_intent.rs"),
        root.join("src/core/runtime.rs"),
    ];
    let text = paths
        .iter()
        .map(|path| source_text(path))
        .collect::<Vec<_>>()
        .join("\n");
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
            offenders.push(format!("core runtime worker contains {forbidden:?}"));
        }
    }

    assert!(
        offenders.is_empty(),
        "core runtime workers must stay generic and protocol-neutral:\n{}",
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
        "crate::core::intents",
        "IntentKind",
        "IntentHandler",
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
        let relative = path.strip_prefix(root).unwrap().display().to_string();
        if CLI_BOUNDARY_FILE_EXCEPTIONS.contains(&relative.as_str()) {
            continue;
        }
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
                offenders.push(format!("{relative} contains {forbidden:?}"));
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
fn context_app_selects_protocol_description() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let path = root.join("src/context_app.rs");
    let text = source_text(&path);
    let production = strip_line_comments(&production_text_before_unit_tests(&text));

    assert!(
        production.contains("core::app::run(&crate::protocol::app::MATCH_PROTOCOL"),
        "context_app.rs should only choose the concrete protocol description"
    );
    assert!(
        !production.contains("match parsed.command.first"),
        "context_app.rs must not restore the broad manual command-name router"
    );
    assert!(
        !production.contains("MATCH_COMMANDS") && !production.contains("MATCH_CLI_COMMANDS"),
        "context_app.rs should not manually wire the protocol command table"
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
            "context_app.rs must not dispatch protocol command {command:?} through a broad top-level match"
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
            "decode_key_wrap",
            "decode_recipient_key",
            "decode_local_recipient_key",
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

/// Flat-intent rule: a handler that creates a fact does only that and stops; it
/// must never enqueue a follow-on intent or open a socket. Handshake sends are
/// emitted by the local connection fact's projector, so the `create_connection`
/// handlers must contain no chained send intents and no network IO. This keeps
/// "what does admitting this fact enqueue?" answerable from one projector and
/// keeps replay classification honest (a replayable create can never smuggle in
/// a non-replayable send).
#[test]
fn create_connection_handler_only_creates_facts_and_chains_no_intents() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut offenders = Vec::new();
    for relative in ["src/protocol/connection/create_connection.rs"] {
        let text = source_text(&root.join(relative));
        for forbidden in [
            ".intent(",
            ".local_intent(",
            "network::queue_outgoing",
            "network::enqueue_outgoing",
            "queue_outgoing_frame",
            "send_connection::",
        ] {
            if text.contains(forbidden) {
                offenders.push(format!(
                    "{relative} chains {forbidden:?}; create_connection must only create facts \
                     (the local connection projector emits the send)"
                ));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "create_connection handlers must stay flat (fact creation only):\n{}",
        offenders.join("\n")
    );
}
