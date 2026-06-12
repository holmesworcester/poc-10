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
        "becomes live only after its projector validates request, authority, observation, and ephemeral-secret context",
        "connection opens sealed bytes",
        "create_connection handler",
        "connection projector",
        "connection rows",
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
fn poc10_replay_intent_shape_doc_records_current_upgrade_readiness_plan() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let note = source_text(&root.join("docs/research/poc10-replay-intent-shape.md"));
    let normalized = normalize_whitespace(&note);

    for required in [
        "# poc-10 Replay And Intent Shape",
        "It does not define release ceilings, old-client compatibility, or fact-version migration",
        "Retained facts, including retained local facts, are the durable source of truth",
        "Every poc-10 queued intent is droppable on upgrade",
        "Projectors are deterministic over fact bytes plus projection context, including replay mode",
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
        "`create_connection`",
        "accepted bootstrap peer projection",
        "live maintenance consumes those rows after the replay barrier",
        "Operational repetition belongs in the intent registry",
        "The schedules are not persisted",
        "Use durable `TimeWake` only when the wake changes replayable protocol state",
        "`content_message_expiry` stays a durable semantic timeline",
        "`connection_peer_retry` timeline should be removed from daemon time wakes",
        "Retained local `invite_accepted` facts are the replay source for accepted bootstrap peers",
        "`maintain_connections` must not invent peers by broad-querying endpoint-owned membership tables",
        "It reads accepted bootstrap peer rows",
        "request-owned `bootstrap_connection_attempt_rows`",
        "Replay rebuilds accepted bootstrap peer rows by replaying retained `invite_accepted` facts",
        "The recurring `maintain_connections` intent is live-only",
        "Connection request projection should validate and materialize request history",
        "It should not own an operational retry loop",
        "`create_connection` is flat fact creation",
        "It must not send network bytes before the responder ephemeral and `connection` facts commit",
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
        "Connection test: replay no longer recreates bootstrap retries from old `request` history alone",
        "Bootstrap test: replay rebuilds accepted bootstrap peer rows from `invite_accepted`",
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
fn fact_authenticator_research_docs_record_authentication_boundary() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let authenticator_note = source_text(&root.join("docs/research/fact-validators.md"));
    let versioning_note = source_text(&root.join("docs/research/protocol-versioning.md"));
    let normalized_authenticator = normalize_whitespace(&authenticator_note);
    let normalized_versioning = normalize_whitespace(&versioning_note);
    let pipeline = format!("authenticate {} adapt {} project", '\u{2192}', '\u{2192}');

    for required in [
        "# Fact Authenticators",
        "pre-projector layer should not claim full protocol validity",
        "`authenticate.rs`",
        "`AuthenticatedFact<T>`",
        "`NeedsAuthentication(AuthenticationNeed)`",
        "Signatures, encryption, and container facts",
        "Verifier key placement is a fact-version choice",
        "Do not make embedded public keys mandatory",
        "The inner facts are admitted back through the normal `decode -> authenticate -> adapt -> project` pipeline",
        "Purge, deletion, retention, and all materialization effects stay projector-owned",
        "Core now exposes first-class route, decode, authenticate, adapt, project, effects, commit, and optional fact admission contracts.",
        "identity adapt slot",
        "Staged core pipeline",
        "`encode.rs`",
        "`decode.rs`",
        "`author.rs`",
        "`adapt.rs`",
        "Core owns the stage boundaries and the wake queues",
        "`AuthenticationNeed` wakes authentication",
        "protocol route owns the concrete `T`",
        "Context payload facts are loaded by core through matched needs/offers",
        "They are not re-authenticated by the consumer path",
        "staged family conversion landed on main",
        "Model fact lessons",
        "Every production route now declares `decode`, `authenticate`, `adapt`, and `project` labels",
        "`connection/request` and `connection/connection` authenticate by opening their sealed bodies",
        "`commands.rs` owns runtime gathering and command receipts",
        "Write-side twin: command authoring pipeline",
        "cli args -> command run fn -> author -> encode -> authenticate self-check -> admit/submit",
        "`encode.rs` owns canonical bytes",
        "Before a command reports success or returns a fact id",
        "Post-conversion hardening plan",
        "all routed fact families stay staged, the old composed model stays removed",
        "Guard the route and file shape",
        "Keep boundaries readable",
        "Keep write admission centralized",
        "Required tests and checks",
        "`cargo test --test poc10_protocol_registry_test`",
        "`cargo test --test poc10_intent_cleanliness_test`",
        "`cargo test --test poc10_architecture_boundary_test`",
        "`cargo test --test documentation_layout_test`",
        "`cargo test`",
        "`git diff --check`",
        "Final success criteria",
        "every routed fact family is `FactPipeline::Staged`",
        "`src/core/projectors.rs` is deleted",
        "`FactPipeline::ProjectorComposed` is deleted",
        "the complete required check suite passes",
        "Documentation and guardrail alignment",
    ] {
        assert!(
            normalized_authenticator.contains(required),
            "fact authenticator note is missing boundary detail {required:?}"
        );
    }
    assert!(
        normalized_authenticator.contains(&pipeline),
        "fact authenticator note should name the authenticate/adapt/project pipeline"
    );

    for required in [
        "fact-authenticator split",
        "The staged `FactRoute` runner is the active route model for all routed facts",
        "Agent note: Part II contains historical/current-code inventory refs captured while planning",
        "use `fact-validators.md` and `src/core/pipeline/README.md` as the source of truth",
        "Do not use `core::projectors`, `project_authenticated`, `layout.rs`, `create.rs`, or fact-family `rows.rs` as target shapes.",
        "Staged routes, then route gating",
        "every routed family now carries an identity adapt slot",
        "The model family lessons are in `fact-validators.md`",
        "sealed request/connection opener authentication",
        "Core runs `decode -> authenticate -> adapt -> project` as four labelled stages",
        "Core has the write-side admission hook for commands and emitted facts",
        "encode -> authenticate self-check -> admit",
        "Core can know that tag 50 uses a particular decoder, authenticator, adapt path, author, and projector",
        "Carry-over TODO for the model-family pass",
        "Known-route authentication",
        "all routed families route through it",
        "`Authenticated(AuthenticatedFact<T>)`",
        "`NeedsAuthentication` context needs",
        "A fact version chooses whether verifier key material is embedded or referenced",
        "trade self-contained verification against public-key size without changing projector semantics",
        "Pending before active",
        "Pending, not active truth",
        "Wire-invalid bytes still drop",
        "Pending is syncable and waiting",
        "pending ingress",
        "not active protocol truth",
        "Context payloads are adapted too",
        "needs and offers match on stable role/scope/range coordinates",
        "route-owned `decode -> adapt` path",
        "without re-verifying context signatures",
        "receives context payloads in the semantic version it expects at the active ceiling",
        "the projector materializes the recovered inner fact bytes and receipts",
        "Those inner facts then re-enter the normal `decode -> authenticate -> adapt -> project` pipeline by their own tags",
        "Creation is deliberately called out because it is currently the least tidy part of the protocol boundary",
        "Its transcript helpers produce the bytes fed to crypto",
        "Authenticate self-check",
        "Move crypto transcript helpers into `encode.rs`; keep actual signing, encryption, and assembly in `author.rs`",
    ] {
        assert!(
            normalized_versioning.contains(required),
            "protocol versioning note is missing authenticator detail {required:?}"
        );
    }
    assert!(
        normalized_versioning.contains(&pipeline),
        "protocol versioning note should name the authenticate/adapt/project pipeline"
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
        "public facade for fact lifecycle contracts and SQL-backed queue workers",
        "perf_profile.rs",
        "env-gated performance instrumentation",
        "projectors.rs",
        "transitional re-export facade for the fact-processing pipeline",
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
        "in-memory `ProjectionContext`",
        "pipeline/context_store.rs",
        "SQL implementation of standing context",
        "pipeline/dispatch.rs",
        "intent queue worker",
        "pipeline/insert_select.rs",
        "checked `INSERT OR IGNORE ... SELECT` helper",
        "pipeline/pipeline_one.rs",
        "one queued fact pipeline item",
        "pipeline.rs",
        "pending projection queue drain",
    ] {
        assert!(
            normalized_core.contains(required),
            "src/core/README.md is missing core boundary detail {required:?}"
        );
    }

    for required in [
        "## Interface To Core And Protocol",
        "## Read Projection Path",
        "## Data Flow",
        "## Invariants",
        "## Module Responsibilities",
        "## Projection Commit Boundary",
        "## Handler Commit Boundary",
        "route -> decode -> authenticate -> adapt -> project -> effects -> commit",
        "## Write Authoring Path",
        "command -> author -> encode -> authenticate self-check -> admit -> read pipeline",
        "`FactPipeline::Staged`",
        "run staged route",
        "`FactAdmissionFn`",
        "poc-10 installs one that routes every fact tag to the same family `Codec` and `DecodedAuthenticator`",
        "record ephemeral projection inputs in `ephemeral_projection_inputs`",
        "mark facts whose scheduled wake-up time has arrived as pending projection work",
        "A projector can schedule its own fact on a protocol timeline",
        "`Authentication::NeedsAuthentication` becomes standing context needs",
        "`ProjectionContext::is_replay()`",
        "suppresses follow-up intents unless the matching `HandlerRoute` declares `runs_during_replay`",
        "Projection mode is sticky toward replay",
        "Rejected durable projection items do not stall the batch",
        "Ephemeral projection inputs are one-shot temp rows",
        "Typed-table inserts are idempotent only when the existing row matches every supplied column",
        "pipeline_one.rs",
        "drains pending projection over durable and ephemeral inputs",
        "queues replay work",
        "durable/ephemeral source rules",
        "context.rs",
        "dispatch.rs",
        "commit_effects.rs",
        "ephemeral projection inputs, row mutations",
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
