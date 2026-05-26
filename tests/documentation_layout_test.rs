use std::fs;
use std::path::Path;

fn source_text(path: &Path) -> String {
    fs::read_to_string(path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()))
}

#[test]
fn documentation_layout_keeps_current_docs_live_and_old_notes_archived() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));

    for live_doc in [
        "README.md",
        "docs/RULES.md",
        "src/core/README.md",
        "src/core/pipeline/README.md",
        "src/protocol/auth/README.md",
        "src/protocol/content/README.md",
        "src/protocol/connection/README.md",
        "src/protocol/sync/README.md",
        "verus_plan.md",
    ] {
        assert!(
            root.join(live_doc).is_file(),
            "missing live documentation file {live_doc}"
        );
    }

    for archived_doc in [
        "docs/archived/plan.md",
        "docs/archived/new_architecture.md",
        "docs/archived/poc10_migration.md",
        "docs/archived/schema_driven_modules.md",
        "docs/archived/simplification_todo.md",
        "docs/archived/sqlite_plan.md",
        "docs/archived/transit_connection_redesign.md",
        "docs/archived/projector_style.md",
    ] {
        assert!(
            root.join(archived_doc).is_file(),
            "missing archived documentation file {archived_doc}"
        );
    }

    for stale_root_doc in [
        "RULES.md",
        "auth.md",
        "documentation_guide.md",
        "negentropy_recs.md",
        "new_architecture.md",
        "plan.md",
        "poc10_migration.md",
        "projector_style.md",
        "schema_driven_modules.md",
        "simplification_todo.md",
        "sqlite_plan.md",
        "transit_connection_redesign.md",
    ] {
        assert!(
            !root.join(stale_root_doc).exists(),
            "stale root documentation file should live under docs/: {stale_root_doc}"
        );
    }

    for removed_duplicate_doc in [
        "docs/README.md",
        "docs/documentation_guide.md",
        "docs/auth.md",
        "docs/negentropy_recs.md",
    ] {
        assert!(
            !root.join(removed_duplicate_doc).exists(),
            "duplicated standalone documentation should be folded into active READMEs: {removed_duplicate_doc}"
        );
    }
}

#[test]
fn rules_include_projector_style_after_projector_style_doc_was_archived() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let rules = source_text(&root.join("docs/RULES.md"));

    for required in [
        "### Projector Style",
        "### Deletion Pattern",
        "Deletion is target-owned",
        "ProjectionOutput::purge_self",
        "core rejects cross-fact purges",
        "### Context Proof Style",
        "payload_for_checked",
        "### Typed Facts And Foreign Context",
        "### Parking And Errors",
        "Missing context parks. Mismatched context rejects.",
        "### Schema And Rows",
    ] {
        assert!(
            rules.contains(required),
            "docs/RULES.md is missing merged projector guidance {required:?}"
        );
    }
}

#[test]
fn core_readmes_document_runtime_and_pipeline_boundaries() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let core = source_text(&root.join("src/core/README.md"));
    let pipeline = source_text(&root.join("src/core/pipeline/README.md"));

    for required in [
        "## Interface To Protocol",
        "## Data Flow",
        "## Invariants",
        "## Responsibility Boundary",
        "app.rs",
        "command_context.rs",
        "context.rs",
        "effects.rs",
        "fact_store.rs",
        "facts.rs",
        "intents.rs",
        "network.rs",
        "pipeline.rs",
        "projectors.rs",
        "runtime.rs",
        "schema.rs",
        "store.rs",
        "wire.rs",
    ] {
        assert!(
            core.contains(required),
            "src/core/README.md is missing core boundary detail {required:?}"
        );
    }

    for required in [
        "## Interface To Core And Protocol",
        "## Data Flow",
        "## Invariants",
        "## Module Responsibilities",
        "## Projection Commit Boundary",
        "## Handler Commit Boundary",
        "project_pending_facts.rs",
        "context.rs",
        "dispatch.rs",
        "commit_effects.rs",
        "insert_select.rs",
    ] {
        assert!(
            pipeline.contains(required),
            "src/core/pipeline/README.md is missing pipeline detail {required:?}"
        );
    }
}

#[test]
fn active_readmes_do_not_refer_to_previous_designs() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    for readme in [
        "README.md",
        "src/core/README.md",
        "src/core/pipeline/README.md",
        "src/protocol/auth/README.md",
        "src/protocol/content/README.md",
        "src/protocol/connection/README.md",
        "src/protocol/sync/README.md",
    ] {
        let text = source_text(&root.join(readme));
        for forbidden in [
            "old layer names",
            "old labels",
            "old source island",
            "legacy/removal",
            "no longer the source of truth",
            "previous designs",
            "previous implementation",
            "past implementation",
            "Superseded planning notes",
        ] {
            assert!(
                !text.contains(forbidden),
                "{readme} should describe the current design without prior-design language: {forbidden:?}"
            );
        }
    }
}
