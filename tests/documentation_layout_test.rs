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
        "docs/archived/pipeline_simplification_plan.md",
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
        "PIPELINE_SIMPLIFICATION_PLAN.md",
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
        "protocol-neutral runtime organized around serialized turns",
        "Core owns turn locking, queue draining",
        "Protocol code participates when runtime turns call command authors",
        "Network ingress here is tick-scoped",
        "nonblocking listener for ready streams",
        "work limit bounds accepted streams",
        "length-prefixed opaque bytes",
        "recognized handshake or established-frame bytes commit `RuntimeEffects` directly into runtime queues",
        "Projectors later open connection frames and validate recovered child facts",
        "acquire serialized runtime turn",
        "runtime store and queues",
        "run command or query",
        "call protocol command author",
        "query path: drain retained projection queue",
        "run daemon tick",
        "fire recurring intent builders",
        "drain ready TCP streams",
        "read length-prefixed opaque bytes",
        "call inbound intake hook",
        "recognize frame family and stage effects",
        "admit due time wakes",
        "runtime queue drain order",
        "drain projection work",
        "run owning projector",
        "dispatch intent queues",
        "run registered handler",
        "projection drain after handlers",
        "pump network_outgoing",
        "## 1) Fact Admission And Context Matching",
        "RuntimeEffects",
        "incoming_facts",
        "shared effect commit path",
        "Command output is normalized to `RuntimeEffects::facts`",
        "`commit_runtime_effects_in_tx` retains",
        "`drain_projection` selects retained work first",
        "`commit_projection_effects_in_tx` either clears retained work",
        "commit_runtime_effects_in_tx",
        "insert_fact_and_pending_with_mode_in_tx",
        "insert_incoming_fact_in_tx",
        "pending_durable_projection_items",
        "incoming_pending_fact_ids",
        "move_incoming_to_retained_in_tx",
        "delete_incoming_fact_in_tx",
        "effect commit transaction",
        "command-authored facts",
        "inbound intake effects",
        "handler effects",
        "projector follow-up effects",
        "opened frame child facts",
        "retained facts: facts + local_fact_admissions",
        "retained work queue: pending_projection",
        "incoming work queue: incoming_facts",
        "scope-owned rows",
        "intent queues: intents + local_intents",
        "projection drain",
        "retained projection item",
        "incoming projection item",
        "projection output: context, time, rows, intents, effects, incoming decision",
        "projection commit transaction",
        "clear consumed retained work",
        "delete dropped incoming row",
        "standing context: replacement needs + append-only offers",
        "range matcher",
        "queued context matches",
        "queued due time ranges",
        "daemon due-time admission",
        "intent dispatch",
        "Context is a range relationship",
        "offer can satisfy many needs",
        "offer may exist before a later fact creates the matching need",
        "The lifecycle diagram above is the context diagram",
        "The concrete role catalog belongs beside the projector docs",
        "## 2) Connection Bootstrap And Established Frames",
        "`receive_network_frame` intake effects",
        "`maintain_connections`",
        "maintain_connections recurring intent",
        "network_outgoing sealed request",
        "queue_outgoing_frame",
        "network_outgoing sealed connection",
        "sync-selected fact ids",
        "fact store payload bytes",
        "frame_small, frame_file_slice, or frame_bundle",
        "retain with needs until context appears",
        "## 3) Sync Seed, Live Tail, And Catch-Up",
        "becomes live only after its projector validates request, authority, observation, and ephemeral-secret context",
        "`maintain_sync`",
        "active local sync-setting range",
        "connection opens sealed bytes",
        "create_connection handler",
        "connection projector",
        "connection rows",
        "maintain_sync recurring intent",
        "active sync-setting range",
        "send_needed_fact_id",
        "replayable time-wake work",
        "## 4) Responsibility Summary",
        "```mermaid",
        "flowchart TD",
        "share_fact_with_sync",
        "context_have",
        "seed_connection_sync",
        "connection_fact_receipt",
        "network intake stages incoming typed facts",
        "incoming_facts temp queue",
        "incoming retention decision",
        "live recurring intents run operational loops",
    ] {
        assert!(
            normalized.contains(required),
            "ARCHITECTURE_DIAGRAMS.md is missing current architecture flowchart detail {required:?}"
        );
    }

    assert!(
        diagrams.matches("```mermaid").count() >= 5,
        "ARCHITECTURE_DIAGRAMS.md should contain one Mermaid block per diagram"
    );

    for removed in [
        "Primary source modules:",
        "`src/protocol/registry.rs`",
        "## 5) Range Sync Dependency Closure",
        "## 6) Example Workspace Fact Graph",
        "message_hello",
        "workspace_acme",
        "PipelineEffects",
        "core pipeline",
        "network_out opaque bytes",
        "send_network_frame sealed request",
        "send_network_frame sealed connection",
        "opened network bytes",
        "frame_small or frame_file_slice",
        "root compare fact",
        "peer sends need_id if missing",
        "admit or stage facts",
        "retain, drop, or reject incoming fact",
        "core Runtime",
        "pending_projection retained queue",
        "incoming ready scan",
        "load incoming fact plus matched context",
        "incoming projector output",
        "load_pending_fact: retained fact, pending matches, due time ranges",
        "load_pending_fact: incoming fact, empty ProjectionContext",
        "run_projection owning projector",
        "dispatch_intents registered handler",
        "## 2) Context As The Cross-Scope Interface",
        "context as a proof surface",
        "core context matcher",
        "Projector needs",
        "Validated outputs",
        "content context offers",
        "core runtime workers",
        "core app boundary",
        "Protocol scopes",
        "auth facts, keys, authority",
        "content facts, opened rows, purge",
        "sync facts, range summaries, visibility",
        "protocol declaration",
        "assembled from protocol declarations",
        "Runtime handle: store, projector, handler set",
        "runtime-facing protocol hooks",
        "projector router",
        "handler registry",
        "accept opaque TCP frames",
        "drain available inbound TCP frames",
        "NET_IN --> TIME",
        "decode length-prefixed frames",
        "pre-query retained projection settle",
        "PREQUERY --> PROJECTOR",
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
        "An offer says \"this owner fact can be loaded as payload context for matching needs.\"",
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
        "**Runtime isolation.**",
        "**Durable queues.**",
        "**Explicit schemas.**",
        "**Fixed layouts.**",
        "Runtime work moves through these core-owned queues",
        "command output",
        "authored facts",
        "pending_projection",
        "committed RuntimeEffects",
        "Command-authored facts and intent-created facts skip the incoming intake table",
        "`facts` and `local_fact_admissions`",
        "`incoming_facts`",
        "Intake only stages those rows",
        "runtime loads them into the owning projector",
        "projector output either deletes the incoming row or retains it as a normal fact",
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
        "Drain replay work to fixpoint",
        "pending fact projection, context match wakeups, replayable semantic time wakes, and queued intents running with replay-mode handler context",
        "Each pass may create facts, rows, context, semantic time wakes, or more queued intents",
        "Finish all replay work before network activity resumes",
        "Replay mode is not a route-table flag",
        "`HandlerContext::is_replay()`",
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
        "replay work interleaving independence",
        "`intent-registry`",
        "`recurring-intents`",
        "`recurring-run KIND --now MS`",
        "`connection-maintenance-status`",
        "network rows, fires recurring schedulers, or creates maintenance attempts before the replay barrier",
        "Registry test: `HandlerRoute` has no replay policy flag",
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
        "different projection order and replay work interleavings",
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

    for required in [
        "# Fact Authenticators",
        "projector-local validation is the current model",
        "Core owns queues, matched context, replacement needs, append-only offers, wake fanout, replay mode, and effect commits",
        "pre-projector layer should not claim full protocol validity",
        "projector-local `decode`, `authenticate`, and `adapt` modules inside `project.rs`",
        "`project.rs`",
        "Missing context is represented by projector needs",
        "Signatures, Encryption, And Container Facts",
        "Verifier key placement is a fact-version choice",
        "Do not make embedded public keys mandatory",
        "The inner facts are admitted back through the normal projector route by their own tags",
        "Purge, deletion, retention, and all materialization effects stay projector-owned",
        "`encode.rs`",
        "`author.rs`",
        "Context payload facts are loaded by core through matched needs/offers",
        "raw fact -> tag route -> projector -> ProjectionOutput -> commit",
        "`commands.rs` owns command snapshots and receipts",
        "Write-Side Twin",
        "cli args -> command args -> command fn -> queries -> author -> encode -> protocol self-check -> AuthoredCommand -> submit",
        "`encode.rs` owns canonical bytes",
        "Before a command reports success or returns a fact id",
        "Required Tests And Checks",
        "`cargo fmt --check`",
        "`cargo test --test poc10_protocol_registry_test`",
        "`cargo test --test poc10_intent_cleanliness_test`",
        "`cargo test --test poc10_architecture_boundary_test`",
        "`cargo test --test documentation_layout_test`",
        "`cargo test`",
        "Final Success Criteria",
        "every route points to a projector and exposes no decode/auth/adapt metadata to core route declarations",
        "context-dependent projectors park by emitting precise needs",
        "docs and guardrails describe only the projector-local final model",
        "the complete required check suite passes",
    ] {
        assert!(
            normalized_authenticator.contains(required),
            "fact authenticator note is missing boundary detail {required:?}"
        );
    }

    for required in [
        "fact-authenticator split",
        "projector-local decode, validation, adaptation, and projection helpers",
        "The active route model maps tags to projectors only",
        "Agent note: Part II contains historical/current-code inventory refs captured while planning",
        "use `fact-validators.md`, `src/core/README.md`, and `project_fact.rs` inline docs as the source of truth",
        "current projector-local model",
        "Projector routes, then route gating",
        "Every routed family now carries a projector-local identity adapt helper",
        "The model family lessons are in `fact-validators.md`",
        "sealed request/connection opener validation",
        "The projector runs decode, validation, adaptation, and semantic projection as plain protocol-local calls",
        "Core has the write-side admission hook for commands and emitted facts",
        "encode -> protocol self-check -> admit",
        "Core can know that tag 50 uses a particular projector",
        "Carry-over TODO for the model-family pass",
        "Known-route validation",
        "core routes raw bytes to that tag's projector",
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
        "A projector's needs and offers match on stable role/scope/range coordinates",
        "without re-running authentication",
        "receives context payloads in the semantic version it expects",
        "the projector materializes the recovered inner fact bytes and receipts",
        "Those inner facts then re-enter admission and route to their own projectors by tag",
        "Creation is deliberately called out because it is currently the least tidy part of the protocol boundary",
        "Its transcript helpers produce the bytes fed to crypto",
        "Protocol self-check",
        "Move crypto transcript helpers into `encode.rs`; keep actual signing, encryption, and assembly in `author.rs`",
    ] {
        assert!(
            normalized_versioning.contains(required),
            "protocol versioning note is missing authenticator detail {required:?}"
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
fn core_readmes_document_runtime_boundaries() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let core = source_text(&root.join("src/core/README.md"));
    let normalized_core = normalize_whitespace(&core);
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
        "matched context attached to that pending row",
        "That commit replaces the fact's owned needs and time wakes",
        "append-only offer evidence",
        "Intents are core's bounded stateful work step",
        "Retry leaves the row queued; success deletes the row with its effects",
        "The daemon runs the same mechanics without a user command on the stack",
        "Core's job is therefore coordination, persistence, and mechanical validation",
        "## Invariants",
        "## Responsibility Boundary",
        "### Top-Level Files",
        "### Runtime Work Sections",
        "### Projection Path And Commit Boundary",
        "### Handler Commit Boundary",
        "### Replay And Time Wakes",
        "app.rs",
        "generic process runner over a `ProtocolDescription`",
        "cli.rs",
        "tiny command registry and text-output boundary",
        "clock.rs",
        "store-local logical clock for deterministic authoring and tests",
        "command.rs",
        "command authoring primitives",
        "context.rs",
        "public vocabulary for standing context relationships",
        "crypto.rs",
        "reusable primitive facade",
        "daemon.rs",
        "long-running process lifecycle and tick ordering",
        "effects.rs",
        "shared effect language for projectors and handlers",
        "facts.rs",
        "protocol-neutral fact identity and visibility scope",
        "handle_intent.rs",
        "one queued intent transaction",
        "handler route metadata, handler sets",
        "intents.rs",
        "queued work and handler contract types",
        "network.rs",
        "opaque network IO boundary",
        "Protocol projectors own raw decoding, validation, adaptation, and semantic projection",
        "core owns queueing, matched context, needs/offers, effect commits, and replay mode",
        "perf_profile.rs",
        "env-gated performance instrumentation",
        "project_fact.rs",
        "one queued fact projection transaction",
        "runtime.rs",
        "executable engine for one selected protocol description",
        "schema.rs",
        "core-owned SQL table inventory",
        "store.rs",
        "SQLite substrate below runtime policy",
        "provides immutable fact storage primitives",
        "wire.rs",
        "fixed-layout byte primitive layer",
        "### Runtime Work Sections",
        "project_fact.rs` keeps the protocol-neutral projection contract",
        "project_fact.rs::route",
        "projector route metadata",
        "project_fact.rs::commit_effects",
        "shared atomic commit path",
        "project_fact.rs::context",
        "in-memory `ProjectionContext`",
        "project_fact.rs::context_store",
        "SQL implementation of standing context",
        "handle_intent.rs",
        "intent queue worker",
        "project_fact.rs",
        "one queued fact projection item",
        "runtime.rs",
        "bounded work ordering",
        "raw fact -> tag route -> projector -> ProjectionOutput -> commit",
        "command -> author -> encode -> protocol self-check -> AuthoredCommand facts -> admit -> projection",
        "`FactAdmissionFn`",
        "poc-10 installs one that dispatches by fact tag to protocol-local decode and validation helpers",
        "durable fact admission or incoming_facts staging",
        "outside-origin bytes are staged in the temporary `incoming_facts` queue until runtime loads them into the owning projector",
        "stage incoming facts in `incoming_facts`",
        "The owning projector decides whether each incoming frame fact is retained",
        "submit local (ephemeral, not-replayed) intents to `local_intents`",
        "mark facts whose scheduled wake-up time has arrived as pending projection work",
        "A projector can schedule its own fact on a protocol timeline",
        "A typical projector locally decodes the raw body, validates the fact id and cryptographic/container proof",
        "Detached signature evidence, key material, deletion markers, receipts, and other cross-fact proof are ordinary facts",
        "Missing context is normal projection output, not a separate core stage",
        "`ProjectionContext::is_replay()`",
        "Projectors use replay mode to avoid live-only projection intents",
        "`HandlerContext::is_replay()`",
        "return empty effects at live-only edges",
        "Recurring work is represented as recurring intents",
        "preserves only the retained fact store",
        "`facts` plus `local_fact_admissions`",
        "Projection mode is sticky toward replay",
        "Needs are replacement subscriptions",
        "Durable offers are append-only evidence",
        "`pending_projection_matches`",
        "already carries the context that woke it",
        "Rejected durable projection items do not stall the batch",
        "Incoming facts start as temp rows",
        "retained while parked on standing context needs",
        "Typed-table inserts are idempotent only when the existing row matches every supplied column",
        "project_fact.rs",
        "durable/incoming source rules",
        "`project_fact.rs::context`",
        "handle_intent.rs",
        "`commit_effects`",
        "incoming facts to stage for projection",
        "stage emitted incoming facts",
    ] {
        assert!(
            normalized_core.contains(required),
            "src/core/README.md is missing runtime work detail {required:?}"
        );
    }
}

#[test]
fn architecture_docs_match_current_module_and_context_names() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));

    let core_readme = source_text(&root.join("src/core/README.md"));
    let normalized_core = normalize_whitespace(&core_readme);
    let mut core_modules = fs::read_dir(root.join("src/core"))
        .expect("read src/core")
        .map(|entry| entry.expect("read src/core entry").path())
        .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("rs"))
        .map(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .expect("core module filename is utf-8")
                .to_string()
        })
        .collect::<Vec<_>>();
    core_modules.sort();
    let missing_modules = core_modules
        .iter()
        .filter(|module| !core_readme.contains(&format!("`{module}`:")))
        .cloned()
        .collect::<Vec<_>>();
    assert!(
        missing_modules.is_empty(),
        "src/core/README.md is missing Top-Level Files entries for:\n{}",
        missing_modules.join("\n")
    );

    for required in [
        "`replay.rs`: replay and replay-check entry point",
        "`row_schema.rs`: schema-backed helper layer for opaque row table key/value bytes",
        "`versioning.rs`: protocol-neutral version ceiling and release-profile policy",
        "`pending_time_ranges` work table",
    ] {
        assert!(
            normalized_core.contains(required),
            "src/core/README.md is missing current core detail {required:?}"
        );
    }

    let rules = source_text(&root.join("docs/RULES.md"));
    let normalized_rules = normalize_whitespace(&rules);
    for required in [
        "Routed fact families use the settled role-file split",
        "owning fact-family module provides an `author.rs` helper",
        "Fact construction, signing, encryption, and assembly stay in the fact-family authoring module",
    ] {
        assert!(
            normalized_rules.contains(required),
            "docs/RULES.md is missing settled authoring guidance {required:?}"
        );
    }
    for removed in ["create.rs` is transitional", "unmigrated families"] {
        assert!(
            !rules.contains(removed),
            "docs/RULES.md should not describe completed migrations as current work: {removed:?}"
        );
    }

    let connection_readme = source_text(&root.join("src/protocol/connection/README.md"));
    assert!(
        connection_readme.contains("-> connection_fact_receipt(request) local receive proof"),
        "src/protocol/connection/README.md should show request projection producing the receipt"
    );
    assert!(
        !connection_readme.contains("needs connection_fact_receipt(request)"),
        "src/protocol/connection/README.md should not document the produced receipt as a need"
    );

    let threat_model = source_text(&root.join("THREAT_MODEL.md"));
    assert!(
        threat_model.contains("publish `fact_purged` only for proved targets"),
        "THREAT_MODEL.md should use the current generic purge context role"
    );
    assert!(
        !threat_model.contains("content_purged"),
        "THREAT_MODEL.md should not name the removed content_purged role"
    );
}

#[test]
fn active_readmes_do_not_refer_to_previous_designs() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    for readme in [
        "README.md",
        "src/core/README.md",
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
