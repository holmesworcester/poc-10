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
        "### Needs And Offers",
        "Every context row is either a need or an offer",
        "A need says \"wake and reproject this owner fact when matching context appears.\"",
        "An offer says \"this owner fact can be loaded as candidate context for matching needs.\"",
        "Core only matches role/scope/range overlap and loads the offer owner as payload",
        "fact:content_message:7f2a",
        "role: content_signer",
        "role: connection_fact_receipt",
        "role: secret_coverage",
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
    let normalized = normalize_whitespace(&rules);

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
        "## Documentation Style",
        "purpose, mechanism, invariants, and ownership boundaries",
        "Write docs in current-code terms",
    ] {
        assert!(
            normalized.contains(required),
            "docs/RULES.md is missing merged projector guidance {required:?}"
        );
    }
}

#[test]
fn protocol_version_flexibility_research_is_local_and_poc10_specific() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let note_path = root.join("docs/research/protocol-version-flexibility.md");
    let note = source_text(&note_path);
    let normalized = normalize_whitespace(&note);

    for required in [
        "# Protocol Version Flexibility Research",
        "docs/research/references/cambria-ink-switch.html",
        "docs/research/references/cambria-ink-switch.pdf",
        "Cambria: Schema Evolution in Distributed Systems with Edit Lenses",
        "https://doi.org/10.1145/3447865.3457963",
        "libp2p protocol IDs and fallback",
        "Ethereum devp2p capabilities",
        "BitTorrent Extension Protocol",
        "QUIC version negotiation",
        "Kafka and Confluent Schema Registry",
        "Signal release expiration and old-device pressure",
        "version diversity inside one product, not broad interoperability between independent projects",
        "anything a user does in a workspace must become visible to everyone in that workspace",
        "A new content type is safe only if it either degrades gracefully to an older content type or is unavailable for creation",
        "Minimal Design",
        "gates new feature creation until any client that lacks the feature would already be deprecated",
        "migration happens seamlessly",
        "new binaries can write the new facts, projectors, intents, commands, rows, indexes, query plans, and database schema",
        "without asking every feature developer to become a rollout expert",
        "Ship read/display support before production write support",
        "Write paths can be implemented and available in alpha or test builds",
        "production creation stays feature-gated until every relevant supported client can read the new state",
        "TreeKEM",
        "new file encoding",
        "different disappearing-message policies",
        "new indexing or query optimization",
        "Test all combinations that can occur during the transition period",
        "old binary with old data",
        "new binary before the feature epoch",
        "alpha writer with prod readers",
        "prod binary with write gate disabled",
        "new binary after the epoch",
        "peers on both sides of the supported-version line",
        "Keep developer ergonomics simple",
        "Shared runtime code owns the gate, reasons, telemetry, transition tests, and deprecation checks",
        "Minimal baseline: read-before-prod-write",
        "supported clients learn to parse, project, index, query, and display the new state",
        "Production write UI and command creation remain disabled by a runtime gate",
        "the feature is fully testable before launch",
        "Minimal option A: global compatibility epochs",
        "Minimal option B: per-feature deprecation horizons",
        "Minimal option C: expand-then-contract storage migrations",
        "Minimal option D: legacy-visible fallback facts",
        "Recommended minimal path: make read-before-prod-write the default rule",
        "Maximal Design",
        "forks, multiple clients, different product protocols, independent apps using protocol scopes modularly",
        "Allow facts, intents, projectors, and commands from different versions to coexist",
        "Make one-person features available immediately",
        "Make fixed-group features available as soon as every included participant can see them on all relevant devices",
        "Support different desktop and mobile feature sets",
        "Maximal option A: capability facts per device, workspace, and scope",
        "Maximal option B: versioned scope manifests and dispatch",
        "Maximal option C: explicit degradation lenses",
        "Maximal option D: participant-set readiness gates",
        "Maximal option E: multi-protocol sessions",
        "Recommended maximal path: use option A and option D as product-facing concepts",
        "Common Implementation Rules",
        "epoch_gated",
        "legacy_fallback",
        "participant_ready",
        "internal_only",
        "A feature cannot create a new workspace-visible fact family without either a fallback mapping, a participant/readiness gate, or an epoch gate",
        "The minimal design is the best fit for poc-10 now",
        "The maximal design is a reserve architecture",
        "Old canonical bytes stay hash-stable",
        "Translation happens when opening, projecting, querying, or executing commands",
        "Read support and write support are separate capabilities",
        "Production write gates require reader readiness",
    ] {
        assert!(
            normalized.contains(required),
            "protocol version research note is missing {required:?}"
        );
    }

    let html = source_text(&root.join("docs/research/references/cambria-ink-switch.html"));
    assert!(
        html.contains("<title>Project Cambria: Translate your data with lenses</title>"),
        "downloaded Cambria HTML should be the Ink & Switch essay"
    );

    let pdf = fs::read(root.join("docs/research/references/cambria-ink-switch.pdf"))
        .expect("read downloaded Cambria PDF");
    assert!(
        pdf.starts_with(b"%PDF"),
        "downloaded Cambria PDF should have a PDF header"
    );
}

#[test]
fn repo_instructions_point_at_live_documentation_style_rules() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let agents = source_text(&root.join("AGENTS.md"));
    let rules = source_text(&root.join("docs/RULES.md"));
    let normalized_rules = normalize_whitespace(&rules);

    assert!(
        agents.contains("docs/RULES.md#documentation-style"),
        "AGENTS.md should point at the live documentation style section"
    );
    assert!(
        !agents.contains("documentation_guide.md"),
        "AGENTS.md should not point at the removed documentation guide"
    );

    for required in [
        "## Documentation Style",
        "What does this component own?",
        "What invariants, ordering rules, idempotence rules, replacement rules, or security conditions",
        "What does this component not know or do?",
        "Where should a future related change be made?",
        "Do not refer to branch names, task slices, abandoned plan filenames, or past implementation states",
    ] {
        assert!(
            normalized_rules.contains(required),
            "docs/RULES.md is missing documentation style guidance {required:?}"
        );
    }
}

#[test]
fn core_readmes_document_runtime_and_pipeline_boundaries() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let core = source_text(&root.join("src/core/README.md"));
    let pipeline = source_text(&root.join("src/core/pipeline/README.md"));
    let normalized_core = normalize_whitespace(&core);
    let normalized_pipeline = normalize_whitespace(&pipeline);
    let how_core_works = core
        .find("## How Core Works")
        .expect("src/core/README.md documents how core works");
    let interface_to_protocol = core
        .find("## Interface To Protocol")
        .expect("src/core/README.md documents interface to protocol");
    let data_flow = core
        .find("## Data Flow")
        .expect("src/core/README.md documents data flow");
    assert!(
        how_core_works < interface_to_protocol && how_core_works < data_flow,
        "src/core/README.md should explain how core works before interface and data-flow details"
    );

    for required in [
        "## Interface To Protocol",
        "## Data Flow",
        "## How Core Works",
        "Core is the reusable runtime loop around a protocol declaration",
        "core opens the selected SQLite store",
        "constructs a `Runtime` from the declared projector, handler registry, row allowlist, schema sources, and daemon hooks",
        "A normal command is a serialized runtime turn",
        "Projection is core's deterministic reaction step",
        "That commit replaces the fact's owned needs, offers, and time wakes",
        "Intents are core's bounded stateful work step",
        "Retry leaves the row queued; success deletes the row with its effects",
        "The daemon runs the same mechanics without a user command on the stack",
        "Core's job is therefore coordination, persistence, and mechanical validation",
        "## Invariants",
        "## Responsibility Boundary",
        "### Top-Level Files",
        "### Pipeline Submodules",
        "app.rs",
        "generic process runner over a `ProtocolDescription`",
        "cli.rs",
        "tiny command registry and text-output boundary",
        "clock.rs",
        "store-local logical clock for deterministic authoring and tests",
        "command_context.rs",
        "read-only command boundary",
        "context.rs",
        "public vocabulary for standing context relationships",
        "crypto.rs",
        "reusable primitive facade",
        "daemon.rs",
        "long-running process lifecycle and tick ordering",
        "effects.rs",
        "shared effect language for commands, projectors, and handlers",
        "fact_store.rs",
        "immutable fact storage and local admission metadata",
        "facts.rs",
        "protocol-neutral fact identity and visibility scope",
        "intents.rs",
        "queued work and handler contract types",
        "network.rs",
        "opaque network IO boundary",
        "pipeline.rs",
        "public facade for SQL-backed queue workers",
        "perf_profile.rs",
        "env-gated performance instrumentation",
        "projectors.rs",
        "projection contract from one fact plus matched context",
        "runtime.rs",
        "executable engine for one selected protocol description",
        "schema.rs",
        "core-owned SQL table inventory",
        "store.rs",
        "SQLite substrate below runtime policy",
        "wire.rs",
        "fixed-layout byte primitive layer",
        "pipeline/commit_effects.rs",
        "shared atomic commit path",
        "pipeline/context.rs",
        "SQL implementation of standing context",
        "pipeline/dispatch.rs",
        "intent queue worker",
        "pipeline/insert_select.rs",
        "checked `INSERT OR IGNORE ... SELECT` helper",
        "pipeline/project_pending_facts.rs",
        "fact projection worker",
    ] {
        assert!(
            normalized_core.contains(required),
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
            normalized_pipeline.contains(required),
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
