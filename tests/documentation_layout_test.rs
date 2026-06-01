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
fn protocol_versioning_design_is_local_and_poc10_specific() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let note_path = root.join("docs/research/protocol-versioning.md");
    let note = source_text(&note_path);
    let normalized = normalize_whitespace(&note);

    for required in [
        "# Protocol Versioning",
        "This is the authoritative, consolidated plan for protocol versioning in poc-10.",
        "Tag-routed facts: `FactRoute { tag, projector }`",
        "Container frame facts: `connection::{frame_small,frame_bundle,frame_file_slice}`",
        "The `TRNS` AEAD frame layout",
        "What does **not** exist yet: a protocol version / ceiling",
        "first-class fact validators, scope-owned ceiling lenses",
        "One substance: facts.",
        "One versioning knob: the fact tag.",
        "kept-forever validator/reader",
        "scope-owned lens edge toward the active ceiling model",
        "One coordination number: the protocol version",
        "Visibility",
        "Rendering uniformity",
        "Ceiling monotonicity",
        "Replay determinism",
        "Keep-forever validators, floor-bounded transport",
        "Safety floor",
        "Replay validates, lenses, then projects.",
        "## 2. Implementation plan",
        "### Phase 0",
        "### Phase 1",
        "### Phase 2",
        "### Phase 3",
        "### Phase 4",
        "layout.rs` / `fact.rs` / `validate.rs",
        "The validator parses raw bytes, computes/checks the fact id, verifies the signature/domain",
        "Valid(ValidatedFact<T>)",
        "semantic.rs",
        "It is not a durable fact",
        "lens.rs",
        "vN/lens.rs",
        "converts `vN-1::semantic` into `vN::semantic`",
        "It never parses raw bytes, queries context, parks, quarantines, or performs authorization checks",
        "### Phase 4a",
        "Scope-owned ceiling lenses",
        "Scope-owned lenses apply to retained **durable facts**",
        "raw retained fact bytes",
        "typed validated fact",
        "source semantic type",
        "scope-owned lens chain to the active ceiling semantic type",
        "The default convention is linear",
        "Replay to ceiling v2 runs `v0 validate -> v0 semantic -> v1/lens.rs -> v1 semantic -> v2/lens.rs -> v2 semantic -> v2/project.rs`",
        "A shortcut must be tested equivalent to the chain it replaces",
        "Cross-scope projectors should depend on semantic contracts",
        "A lens does not create a new signed fact",
        "An authority lens may only preserve or narrow authority",
        "Any authority widening requires a new durable authority fact",
        "Projectors still own context",
        "keep every old validator/reader forever",
        "keep the linear lens chain for retained durable facts",
        "malformed old bytes are handled in validators",
        "unsafe representation mapping in lenses",
        "unsafe interpretation in projectors or policy facts",
        "### Phase 5",
        "### Phase 6",
        "### Phase 7",
        "### Worked example: a fact-version-safety change (encrypted usernames)",
        "Plaintext usernames are the worked example.",
        "The fix is a new ceiling-gated profile fact",
        "The old `auth::user` validator still proves membership authority",
        "auth lens to the ceiling profile model refuses to use the plaintext field",
        "endpoint_shared.user_authority_fact_id == subject_user_id",
        "It may replace display data only",
        "### Atomicity and crash-consistency",
        "## 3. Test matrix",
        "## 4. Open decisions",
    ] {
        assert!(
            normalized.contains(required),
            "protocol version research note is missing {required:?}"
        );
    }

    for removed in [
        "Protocol Version Flexibility Design",
        "Cambria",
        "cambria",
        "fallback/canonical",
        "`fallback_fact`",
        "`canonical_fact`",
        "`canonical_to_fallback_lens`",
        "## Industry Patterns",
        "## Minimal Design",
        "## Maximal Design",
    ] {
        assert!(
            !note.contains(removed),
            "protocol versioning note should not include removed design term {removed:?}"
        );
    }
}

#[test]
fn poc10_replay_intent_shape_doc_records_current_upgrade_readiness_plan() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let note = source_text(&root.join("docs/research/poc10-replay-intent-shape.md"));
    let normalized = normalize_whitespace(&note);

    for required in [
        "# poc-10 Replay And Intent Shape",
        "It does not define release ceilings, old-client compatibility, or fact-version migration",
        "Retained facts, including retained local facts, are the durable source of truth",
        "Every poc-10 queued intent is droppable on upgrade",
        "Projectors are deterministic and replay-blind",
        "All durable wall-clock `TimeWake` behavior must be replayable",
        "If a wall-clock action is operational and not replayable, it must be a recurring intent instead",
        "Recurring operational work is not durable state",
        "Drop durable and local queued intents",
        "Admit replayable semantic time wakes to fixpoint",
        "Drain replay-allowed work to fixpoint",
        "pending fact projection, context match wakeups, replayable semantic time wakes, and replay-allowed intents",
        "Each pass may create facts, rows, context, semantic time wakes, or more replay-allowed intents",
        "Finish all replay-required work before network activity resumes",
        "Extend the existing `HandlerRoute` metadata rather than creating a second registry",
        "pub runs_during_replay: bool",
        "pub recurrence: Option<RecurringIntentSpec>",
        "`share_fact_with_sync`",
        "`create_key_wrap`",
        "`unwrap_key_wrap`",
        "`create_connection_response`",
        "connection candidate registration intents",
        "they rebuild connection-maintenance-owned candidate rows from endpoint/auth facts",
        "Operational repetition belongs in the intent registry",
        "The schedules are not persisted",
        "Use durable `TimeWake` only when the wake changes replayable protocol state",
        "`content_message_expiry` stays a durable semantic timeline",
        "`connection_peer_retry` timeline should be removed from daemon time wakes",
        "Add replay-allowed candidate-registration intents plus a live recurring `maintain_connections` intent",
        "Endpoint/auth projectors decide which endpoints are valid connection candidates",
        "`register_connection_candidate`",
        "`unregister_connection_candidate`",
        "`maintain_connections` must not discover peers by broad-querying auth or endpoint-owned tables",
        "It reads only connection-maintenance-owned state",
        "Replay rebuilds the candidate table by replaying endpoint/auth facts",
        "dispatching replay-allowed candidate-registration intents",
        "The recurring `maintain_connections` intent is live-only",
        "Connection request projection should validate and materialize request history",
        "It should not own an operational retry loop",
        "`create_connection_response` needs an atomicity fix",
        "It must not send network bytes before the responder ephemeral fact and `connection_response` fact commit",
        "`create_key_wrap` can run during replay because it is deterministic fact creation",
        "`unwrap_key_wrap` can run during replay under the same rule",
        "deterministic local fact creation only",
        "Opened local secrets are represented by local facts",
        "Bootstrap connection attempts are covered by this maintenance loop",
        "There is no separate durable `connection_peer_retry` loop",
        "## CLI Test Surface",
        "`replay [--reverse | --scramble --seed N]`",
        "`state-summary`",
        "print a stable hashable summary of replay-relevant state",
        "include one overall `state_hash` plus per-area hashes and counts",
        "computed from canonical row serialization with deterministic ordering",
        "`replay-check`",
        "copy the database to scratch snapshots",
        "canonical replay, an idempotent replay, `replay --reverse`, and several `replay --scramble --seed N` passes",
        "compare the same state summary `state_hash` for every pass",
        "per-area hash/count differences",
        "projection order independence",
        "replay-allowed work interleaving independence",
        "`intent-registry`",
        "`recurring-intents`",
        "`recurring-run KIND --now MS`",
        "`connection-maintenance-status`",
        "network rows, live-only local intents, recurring scheduler fires, or maintenance attempts before the replay barrier",
        "Registry test: every `HandlerRoute` has `runs_during_replay` set explicitly",
        "Time-wake test: every daemon `TimeWake` timeline is replayable",
        "Unwrap test: replay dispatch of `unwrap_key_wrap` is idempotent",
        "creates deterministic local secret facts",
        "respects existing purge/retirement facts",
        "Connection test: replay no longer recreates bootstrap retries from old `connection_request` history alone",
        "Bootstrap test: replay rebuilds the connection candidate index",
        "`recurring-run maintain_connections --now MS` creates or retries bootstrap attempts",
        "Recurring-intent test: `recurring-intents` and `intent-registry` show `maintain_connections` as live-only recurring work",
        "Replay CLI test: `replay-check` reports the same state summary digest",
        "reverse projection order, and scrambled replay order",
        "Replay order test: `replay --reverse` and `replay --scramble --seed N`",
        "different projection order and replay-allowed work interleavings",
    ] {
        assert!(
            normalized.contains(required),
            "poc10 replay intent shape note is missing {required:?}"
        );
    }

    for removed in [
        "Cambria",
        "global protocol ceiling",
        "old-client fallback",
        "versioned handlers",
        "protocol version graph",
    ] {
        assert!(
            !note.contains(removed),
            "poc10 replay intent shape note should not include versioning policy detail {removed:?}"
        );
    }
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
