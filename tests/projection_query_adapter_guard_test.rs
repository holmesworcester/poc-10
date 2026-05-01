//! Guard test: enforce the strict context contract retirement.
//!
//! Per plan.md (commit afc171015718e9a1e), the strict context contract is
//! `{event, deps, labels}` — no per-event-type SQL loaders. The legacy
//! `build_projector_context` adapter functions and the
//! `ProjectionQueries::load_*_context` trait methods have been retired
//! (see Finding 2 in Codex's design review). This test guards against
//! regressions: any reintroduction of those shapes will fail compilation
//! of these assertions.

use std::fs;
use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn walk_rs_files(root: &Path, mut keep: impl FnMut(&Path) -> bool) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let entries = match fs::read_dir(&dir) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for entry in entries {
            let entry = match entry {
                Ok(e) => e,
                Err(_) => continue,
            };
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            if path.extension().and_then(|ext| ext.to_str()) != Some("rs") {
                continue;
            }
            if keep(&path) {
                out.push(path);
            }
        }
    }
    out.sort();
    out
}

#[test]
fn no_event_module_defines_build_projector_context() {
    // The strict context contract retires the legacy
    // `build_projector_context` adapter pattern: every projector now
    // consumes the snapshot produced by
    // `crate::state::generic_context::load_generic_context`.
    let root = repo_root().join("src/event_modules");
    let offenders = walk_rs_files(&root, |path| {
        let content = fs::read_to_string(path).unwrap_or_default();
        content.contains("fn build_projector_context(")
    });
    assert!(
        offenders.is_empty(),
        "found per-event-type build_projector_context (retired by plan.md commit afc171015718e9a1e): {:?}",
        offenders
    );
}

#[test]
fn no_event_metadata_field_named_context_loader() {
    // `EventTypeMeta::context_loader` was retired alongside the
    // per-event-type loaders. Catch reintroduction at any registry meta.
    let root = repo_root().join("src/event_modules");
    let offenders = walk_rs_files(&root, |path| {
        let content = fs::read_to_string(path).unwrap_or_default();
        content.contains("context_loader:")
    });
    assert!(
        offenders.is_empty(),
        "EventTypeMeta::context_loader has been retired but the field still appears in: {:?}",
        offenders
    );
}

#[test]
fn projection_queries_module_no_longer_defines_per_event_loaders() {
    // The `ProjectionQueries` trait used to expose
    // `load_workspace_context`, `load_message_context`, etc. — every one
    // of those has been removed. The file is retained only as a stub
    // (see queries.rs header comment). We look for the *defining* shapes,
    // not bare strings, so the historical retirement comment in the file
    // header doesn't accidentally trip the guard.
    let path = repo_root().join("src/state/projection/queries.rs");
    let content = fs::read_to_string(&path).expect("read queries.rs");
    let banned_definitions = [
        "fn load_workspace_context",
        "fn load_peer_shared_context",
        "fn load_user_invite_context",
        "fn load_device_invite_context",
        "fn load_message_context",
        "fn load_message_deletion_context",
        "fn load_reaction_context",
        "fn load_invite_accepted_context",
        "fn load_key_shared_context",
        "fn load_removal_context",
        "trait ProjectionQueries",
        "macro_rules! define_query_context_loader",
    ];
    for needle in &banned_definitions {
        assert!(
            !content.contains(needle),
            "queries.rs still defines retired symbol `{}`",
            needle
        );
    }
}
