use std::fs;
use std::path::Path;

fn source_text(path: &Path) -> String {
    fs::read_to_string(path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()))
}

fn normalize_whitespace(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[test]
fn documentation_layout_keeps_current_docs_live_and_old_notes_archived() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));

    for live_doc in [
        "README.md",
        "ARCHITECTURE_DIAGRAMS.md",
        "docs/RULES.md",
        "docs/todo-add-verus-proofs.md",
        "src/core/README.md",
        "src/core/pipeline/README.md",
        "src/protocol/auth/README.md",
        "src/protocol/content/README.md",
        "src/protocol/connection/README.md",
        "src/protocol/sync/README.md",
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
        "verus_plan.md",
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
fn architecture_diagrams_are_github_flowcharts_for_current_context_architecture() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let diagrams = source_text(&root.join("ARCHITECTURE_DIAGRAMS.md"));
    let normalized = normalize_whitespace(&diagrams);

    for required in [
        "# Architecture Diagrams",
        "GitHub-renderable Mermaid flowcharts",
        "## 0) Runtime Boundaries",
        "## 1) Fact Admission And Context Matching",
        "Context is a range relationship",
        "offer can satisfy many needs",
        "offer may exist before a later fact creates the matching need",
        "## 2) Context As The Cross-Scope Interface",
        "context as a proof surface",
        "fact emission from bootstrap and frame opening is shown in the connection flow below",
        "core context matcher",
        "Projector needs",
        "Validated outputs",
        "content context offers",
        "## 3) Connection Bootstrap And Established Frames",
        "sync-selected fact ids",
        "fact store payload bytes",
        "## 4) Sync Seed, Live Tail, And Catch-Up",
        "becomes durable only after its projector validates request, invite, receipt, and ephemeral-secret context",
        "bootstrap_response opens sealed bytes",
        "create_connection_response handler",
        "response projector",
        "connection_response rows",
        "## 5) Responsibility Summary",
        "```mermaid",
        "flowchart TD",
        "flowchart LR",
        "share_fact_with_sync",
        "context_have",
        "seed_connection_sync",
        "connection_fact_receipt",
    ] {
        assert!(
            normalized.contains(required),
            "ARCHITECTURE_DIAGRAMS.md is missing current architecture flowchart detail {required:?}"
        );
    }

    assert!(
        diagrams.matches("```mermaid").count() >= 6,
        "ARCHITECTURE_DIAGRAMS.md should contain one Mermaid block per diagram"
    );

    for removed in [
        "Primary source modules:",
        "`src/protocol/registry.rs`",
        "## 5) Range Sync Dependency Closure",
        "## 6) Example Workspace Fact Graph",
        "message_hello",
        "workspace_acme",
    ] {
        assert!(
            !diagrams.contains(removed),
            "ARCHITECTURE_DIAGRAMS.md should not include removed graph {removed:?}"
        );
    }
}

#[test]
fn root_readme_describes_context_project_aims() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let readme = source_text(&root.join("README.md"));
    let normalized = normalize_whitespace(&readme);

    for required in [
        "lightweight p2p engine",
        "storage and wire protocol are made of facts in the Datalog/database sense",
        "asserted ground records that can be stored, matched, and projected",
        "Context facts are immutable, fixed-layout records admitted locally and exchanged between peers",
        "A fact can be a message, invite, membership change, sync request, receipt, key wrap, or connection handshake",
        "deterministic projectors validate facts against context and turn them into SQLite rows or bounded retryable work",
        "fact-based protocol runtime",
        "backend for a p2p Slack",
        "team chat, invites, membership, reactions, files, message history, sync",
        "frontend-friendly queries without a custom middle layer",
        "boring local API",
        "paginated message views with users, reactions, attachments, and download progress",
        "## Approach",
        "In Context, a central idea is that facts offer context to other facts",
        "Context is a more general relationship than blocking",
        "context offers can be projected before the facts they refer to exist",
        "standing relationship surface",
        "context is projector-described evidence",
        "more powerful than a Boolean dependency block",
        "A projector decides which context proves the fact",
        "whether missing context parks or rejects it",
        "whether derived state is durable or ephemeral",
        "what context it offers to later facts",
        "what future context should wake it",
        "the narrative for what happens when a fact exists stays in the owning projector",
        "Protocol aspects such as connection, sync, and auth are all described as facts",
        "consistent way to reason about concurrency and network interaction",
        "bytes from another node enter as facts",
        "core matches context",
        "the owning projector validates meaning",
        "handlers perform bounded retryable work",
        "**Core mechanics.**",
        "**Scope semantics.**",
        "**Scope manifests.**",
        "**Handler work.**",
        "**Projector output.**",
        "**Handler output.**",
        "**Pipeline isolation.**",
        "**Durable queues.**",
        "**Explicit schemas.**",
        "**Fixed layouts.**",
    ] {
        assert!(
            normalized.contains(required),
            "README.md is missing Context project aim detail {required:?}"
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
        "perf_profile.rs",
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
