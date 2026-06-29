use std::fs;
use std::path::Path;

fn source_text(path: &Path) -> String {
    fs::read_to_string(path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()))
}

fn normalize_whitespace(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn rust_module_doc_text(path: &Path) -> String {
    source_text(path)
        .lines()
        .filter_map(|line| line.trim_start().strip_prefix("//!"))
        .map(str::trim)
        .collect::<Vec<_>>()
        .join(" ")
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
        "docs/research/protocol-versioning.md",
    ] {
        assert!(
            !root.join(removed_duplicate_doc).exists(),
            "duplicated standalone documentation should be folded into active READMEs: {removed_duplicate_doc}"
        );
    }
}

// NOTE: The architecture diagrams used to be guarded by a deterministic test
// that pinned their exact prose, node labels, and section headings. That made
// the diagrams impossible to improve without rewriting ~120 string assertions,
// so they calcified. Keeping diagram text and the diagrams faithful to the code
// is a qualitative review concern, not a string-equality test. The pinning test
// has been removed deliberately; do not reintroduce one.

#[test]
fn architecture_diagrams_cover_current_runtime_relationships() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));

    let diagrams = source_text(&root.join("ARCHITECTURE_DIAGRAMS.md"));
    let normalized = normalize_whitespace(&diagrams);
    for required in [
        "`pending_time_ranges` is not an independent queue",
        "A global `time_now` context would make projection order and replay depend on the current clock",
        "Purges are also not a queue",
        "the standing need parks the owner until matching context re-queues it",
        "Durable emitted facts re-enter the loop through `facts` plus `pending_projection` in the same transaction",
        "Connection-frame projectors may also open encrypted inbound payloads and stage their child facts back into `incoming_facts`",
        "connection_frame emits opened child facts",
        "`incoming_facts` is only the temp outside-origin staging path",
        "## 6) Connection Bootstrap",
        "`receive_network_frame_facts` only classifies raw bytes into incoming request or connection facts",
        "emit durable `frame_observation` and `connection_fact_receipt` facts",
        "There is no `send_network_frame` handler",
        "Both paths add opaque bytes to network_outgoing",
        "network_outgoing sealed bytes waiting for the TCP pump (temp)",
        "HANDLER -->|sealed bytes / route work| OUT",
        "The runtime and bootstrap diagrams above describe one node's loop",
    ] {
        assert!(
            normalized.contains(required),
            "ARCHITECTURE_DIAGRAMS.md is missing current runtime relationship {required:?}"
        );
    }
    assert!(
        !diagrams.contains("The previous three diagrams"),
        "ARCHITECTURE_DIAGRAMS.md should not retain stale section counts"
    );
    assert!(
        !diagrams.contains("A parked in pending_projection"),
        "ARCHITECTURE_DIAGRAMS.md should not show context needs as retained pending work"
    );
    for stale in [
        "drain_projection_once",
        "drain_intents_once",
        "ephemeral_projection_inputs",
        "network inbound rows",
        "convert inbound rows",
        "receive_network_frame handler",
        "send_network_frame handler",
        "PipelineEffects",
        "CMD_SETTLE",
        "Q_SETTLE",
        "one projection batch",
        "one intent batch",
        "process_all_work_until_idle",
        "Command-side settling",
    ] {
        assert!(
            !normalized.contains(stale),
            "ARCHITECTURE_DIAGRAMS.md still contains stale runtime/daemon wording {stale:?}"
        );
    }
    assert!(
        !root.join("ARCHITECTURE_DIAGRAMS_ALT.md").exists(),
        "alternate architecture diagram doc should remain folded into ARCHITECTURE_DIAGRAMS.md"
    );
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
        "deterministic projectors validate facts against context and turn them into SQLite rows or bounded stateful work",
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
        "An offer says \"this owner fact provides this scalar value for matching needs.\"",
        "Core only matches role/scope/range overlap and records the matched offer id",
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
        "handlers perform bounded stateful work",
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
        "`network_incoming`",
        "`incoming_facts`",
        "the daemon classifier stages recognized facts in `incoming_facts`",
        "Runtime loads those facts into the owning projector",
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
        "match_for_checked",
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
        "`key_wrap_creation` facts",
        "`key_wrap_recovery` facts",
        "`create_connection`",
        "accepted bootstrap peer projection",
        "live maintenance consumes those rows after the replay barrier",
        "Operational repetition belongs in the intent registry",
        "Each runtime turn offers recurring builders",
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
        "`key_wrap_creation` local facts replay because they are deterministic projection work",
        "`key_wrap_recovery` local facts replay under the same rule",
        "deterministic local fact creation only",
        "Opened local secrets are represented by local facts",
        "Bootstrap connection attempts are covered by this maintenance loop",
        "There is no separate durable `connection_peer_retry` loop",
        "## CLI Test Surface",
        "`update`",
        "author a local protocol update fact",
        "Replay-mode projection of update facts is a no-op",
        "`state-summary`",
        "print a stable hashable summary of rebuild-relevant state",
        "include one overall `state_hash` plus per-area hashes and counts",
        "computed from canonical row serialization with deterministic ordering",
        "`intent-registry`",
        "`recurring-intents`",
        "`recurring-run KIND --now MS`",
        "`connection-maintenance-status`",
        "`state-summary` should remain a read-only digest",
        "Registry test: `HandlerRoute` has no replay policy flag",
        "Time-wake test: every daemon `TimeWake` timeline is replayable",
        "Recovery test: replay projection of `key_wrap_recovery` creates deterministic local secret facts",
        "creates deterministic local secret facts",
        "respects existing purge/retirement facts",
        "Connection test: replay no longer recreates bootstrap retries from old `request` history alone",
        "Bootstrap test: replay rebuilds accepted bootstrap peer rows from `invite_accepted`",
        "`recurring-run maintain_connections --now MS` creates or retries bootstrap attempts",
        "Recurring-intent test: `recurring-intents` and `intent-registry` show `maintain_connections` as live-only recurring work",
        "Update CLI test: `update` plus the ordinary runtime turn rebuilds projected rows",
        "State-summary CLI test: `state-summary` reports a stable digest",
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
fn in_memory_projection_research_doc_records_extract_project_boundary() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let note = source_text(&root.join("docs/research/in-memory-projection-bounded-replay.md"));
    let normalized = normalize_whitespace(&note);

    for required in [
        "persist facts and a syntactic needs/offers index; project the active range in memory; resolve cross-time matches by lookup",
        "fn extract(item: &Item) -> Vec<Edge>",
        "fn project(item: &Item, ctx: Context<Validated>) -> (State, Effects)",
        "`extract` is context-free by signature",
        "The closure rule: addresses must be self-contained",
        "every context address a fact will ever need must be carried in — or derivable from — that fact's own fields",
        "suppression/deletion needs",
        "copy those suppressing addresses into the fact",
        "Those copied addresses are asserted routing hints, not authority",
        "`project` must compare them with validated parent/context facts before materializing state or effects",
        "A forged child can dirty the syntactic index with useless edges, but it cannot create validated state",
        "`project` produces validated state",
        "verifies any denormalized dependency addresses against that closure",
        "The index is the `Asserted` (dirty) layer",
        "They promote to **`Validated`** only when `project` validates the item in Pass 2",
    ] {
        assert!(
            normalized.contains(required),
            "in-memory projection research note is missing extract/project boundary detail {required:?}"
        );
    }
}

#[test]
fn fact_authenticator_research_docs_record_authentication_boundary() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let authenticator_note = source_text(&root.join("docs/research/fact-validators.md"));
    let versioning_note = source_text(&root.join("src/protocol/versioning/README.md"));
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
        "Context offer values are hydrated by core through matched needs/offers",
        "raw fact -> tag route -> projector -> ProjectionOutput -> commit",
        "`api.rs` owns command snapshots and receipts",
        "Write-Side Twin",
        "cli args -> command args -> command fn -> queries -> author -> encode -> protocol self-check -> AuthoredFacts -> submit",
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
        "# Versioning",
        "This scope owns the release constant `CURRENT_PROTOCOL_VERSION`",
        "Core owns the generic commit-side `StorageRequirement` guard",
        "see `src/core/README.md` for that runtime contract",
        "A release must not author a new durable fact type until every non-deprecated release can decode, authenticate, validate, and project that type",
        "Projectors for current code must support every old durable fact type that can remain in `facts`",
        "New projectors and queries must not write old materialized table shapes",
        "Commands, projectors, handlers, and queries declare the storage version they expect",
        "Version repair is the recurring update loop described below",
        "`src/protocol/versioning.rs` owns `CURRENT_PROTOCOL_VERSION`",
        "`src/protocol/versioning/local_update.rs` owns the `local_update` fact family",
        "The update loop is protocol responsibility",
        "`CURRENT_PROTOCOL_VERSION` is the compile-time release constant",
        "It is the target version for the materialized storage shape this binary expects",
        "It is not read from the database",
        "The stored version marker is `protocol_version_rows.protocol_version`",
        "The protocol schema's `StorageVersionSource` tells core where to read that marker",
        "the marker itself is protocol-owned projected state",
        "`protocol_version_rows.protocol_version`",
        "A fresh database has no marker row until the update loop creates one",
        "Missing and stale markers both mean this database needs a local update fact",
        "The recurring update path is concrete",
        "Each bounded runtime turn gives recurring builders an opportunity",
        "commands and queries run it without durable handler dispatch, listener, or outgoing adapters before dispatch",
        "The `check_version` builder reads the stored marker",
        "If the marker is stale or missing, it queues `check_version`",
        "creates a priority local update fact for `CURRENT_PROTOCOL_VERSION`",
        "requests the rebuild effect and commits the rebuild boundary",
        "queues all retained facts in `pending_projection` with replay mode set",
        "Protocol projectors and handlers register `StorageRequirement::Current`",
        "Core enforces that requirement inside the same SQL transaction",
        "On mismatch, core consumes the selected projection or intent row without ordinary effects",
        "`StorageRequirement::MaintenanceBypass`",
        "Queries are direct SQL readers",
        "query must choose one explicit behavior",
        "support an old not-yet-replayed table shape",
        "Core does not know release policy, fact-family compatibility, or table meaning",
        "Protocol modules own the marker table, version number, recurring check, update fact, query policy",
        "Incoming is volatile intake",
        "Fact storage happens only after admission and projection",
    ] {
        assert!(
            normalized_versioning.contains(required),
            "protocol versioning note is missing current-model detail {required:?}"
        );
    }

    for removed in [
        "ReleaseManifestEntry",
        "ProtocolBundle",
        "ReleaseProfile",
        "global protocol ceiling",
        "pending ingress",
        "above-ceiling",
    ] {
        assert!(
            !versioning_note.contains(removed),
            "protocol versioning note should not describe removed model detail {removed:?}"
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
        agents.contains("docs/RULES.md#source-file-organization"),
        "AGENTS.md should point at the live source file organization section"
    );
    assert!(
        !agents.contains("documentation_guide.md"),
        "AGENTS.md should not point at the removed documentation guide"
    );

    for required in [
        "## Source File Organization",
        "Source files should be readable top-down by a newcomer",
        "what the file exports, what the main procedure or runtime surface is, which component stages implement it",
        "make the exported surface explicit in the module docs",
        "Group the exported vocabulary near the top of the file, before private helper code",
        "Prefer the hierarchical layout used by `project_fact.rs`: central procedures first, then component stages, then purpose-specific helpers",
        "Module docs should include direct negative boundaries",
        "this file must not",
        "core network IO must not parse frame payloads or decide fact admission",
        "trusted table and column identifiers are quoted for syntax safety",
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
fn protocol_versioning_docs_separate_release_marker_from_storage_guards() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let versioning = rust_module_doc_text(&root.join("src/protocol/versioning.rs"));
    let update = rust_module_doc_text(&root.join("src/protocol/versioning/local_update.rs"));
    let project =
        rust_module_doc_text(&root.join("src/protocol/versioning/local_update/project.rs"));
    let check_version =
        rust_module_doc_text(&root.join("src/protocol/versioning/check_version.rs"));
    let normalized_versioning = normalize_whitespace(&versioning);
    let normalized_update = normalize_whitespace(&update);
    let normalized_project = normalize_whitespace(&project);
    let normalized_check_version = normalize_whitespace(&check_version);

    for required in [
        "Protocol versioning scope",
        "Versioning is a protocol scope, not a fact family",
        "recurring check that compares the schema-declared protocol marker",
        "local update fact that repairs stale derived state",
        "The fact family in this scope is `local_update`",
        "Keep fact-family role files",
        "under `versioning/local_update/`, not in this scope root",
        "Keep two version concepts separate",
        "The recurring version check is protocol responsibility",
        "It reads the schema-declared protocol marker",
        "compares it with the one `CURRENT_PROTOCOL_VERSION` compiled into this release",
        "emits a local update fact when the database needs a rebuild",
        "The update fact is the repair trigger",
        "records protocol-visible update history",
        "advances the schema-declared protocol marker through a normal commit effect",
        "A projector or query storage requirement is a local safety contract",
        "usually next to `PROJECTOR_INFO` in `project.rs`",
        "query modules import that same constant before reading materialized rows",
        "This guard is not the release marker and it is not what triggers rebuild",
        "Core can enforce this automatically for commits, but not for raw reads",
        "query modules must decide whether to require current storage",
        "support an old not-yet-replayed table shape",
        "A given checkout/release carries one protocol version",
        "The protocol code does not contain a live matrix of release versions",
        "Compatibility with older retained facts or older materialized storage belongs in the owning projector/query code",
        "may read old storage shapes only to derive the current release's state",
        "must write only the current release's declared tables and effects",
        "never old database tables",
        "Core should remain mechanical here",
        "Core should remain mechanical here. It enforces declared storage requirements",
        "protocol modules own the marker table, version number, recurring check, update fact, and per-family compatibility rules",
        "do not ship code that authors a new durable fact type until every non-deprecated release can decode, authenticate, validate, and project that type",
        "the schema-declared protocol marker plus per-route storage guards cover the rest",
    ] {
        assert!(
            normalized_versioning.contains(required),
            "src/protocol/versioning.rs is missing versioning contract detail {required:?}"
        );
    }

    for required in [
        "Local protocol update fact family",
        "Update facts are local control-plane facts",
        "records protocol-visible update history",
        "advances the schema-declared protocol marker",
        "Replay projection of old update facts is a no-op",
    ] {
        assert!(
            normalized_update.contains(required),
            "src/protocol/versioning/local_update.rs is missing local-update fact-family contract detail {required:?}"
        );
    }

    for required in [
        "Projection for local protocol update facts",
        "rebuild_derived_state",
        "records protocol-visible update history",
        "advances the schema-declared protocol marker",
        "context.is_replay()",
    ] {
        assert!(
            normalized_project.contains(required),
            "src/protocol/versioning/local_update/project.rs is missing local-update projection contract detail {required:?}"
        );
    }

    for required in [
        "Recurring intent that emits update facts when the schema-declared protocol marker is stale",
        "check_version",
    ] {
        assert!(
            normalized_check_version.contains(required),
            "src/protocol/versioning/check_version.rs is missing check-version contract detail {required:?}"
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
        "core opens the selected SQLite database",
        "constructs a `Runtime` from the declared projector, handler registry, row allowlist, schema sources, and runtime-turn hooks",
        "A normal command is a serialized database turn",
        "Projection is core's deterministic reaction step",
        "matched context attached to that pending row",
        "That commit replaces the fact's owned needs and time wakes",
        "append-only offer evidence",
        "Intents are core's bounded stateful work step",
        "Handler rejections consume the invalid row without output",
        "Every host runs the same bounded runtime turn before it does host-specific work",
        "Command/query turns run without durable handler dispatch or network adapters",
        "Core's job is therefore coordination, persistence, and mechanical validation",
        "## Invariants",
        "## Responsibility Boundary",
        "### Top-Level Files",
        "### Runtime Work Sections",
        "### Storage Version Commit Guards",
        "### Projection Path And Commit Boundary",
        "### Handler Commit Boundary",
        "### Rebuild Mode And Time Wakes",
        "app.rs",
        "generic process runner over a `ProtocolDescription`",
        "cli.rs",
        "tiny command registry and text-output boundary",
        "command.rs",
        "command authoring primitives",
        "context.rs",
        "public vocabulary for standing context relationships",
        "crypto.rs",
        "reusable primitive facade",
        "daemon.rs",
        "long-running process lifecycle",
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
        "one queued fact projection transaction plus fact lifecycle SQL",
        "Standing context SQL lives under `project_fact/context_db.rs`",
        "runtime.rs",
        "executable engine for one selected protocol description",
        "schema.rs",
        "core-owned SQL table inventory",
        "db.rs",
        "SQLite substrate below runtime policy",
        "applies typed row mutations",
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
        "project_fact::context_db",
        "project_fact/context_db.rs",
        "SQL implementation of standing context",
        "handle_intent.rs",
        "intent queue worker",
        "project_fact.rs",
        "one queued fact projection item",
        "runtime.rs",
        "bounded work ordering",
        "A `SchemaSource` may declare a `StorageVersionSource`",
        "what storage version does this database currently project",
        "Projector and handler routes declare the storage shape their effects expect",
        "`StorageRequirement::Current(version)`",
        "commit_effects` reads the schema-declared marker",
        "A mismatch consumes the selected projection or intent row without those ordinary effects",
        "`StorageRequirement::MaintenanceBypass` is the explicit escape hatch",
        "Core does not decide when a database should be repaired",
        "whether queries can read old table shapes",
        "raw fact -> tag route -> projector -> ProjectionOutput -> commit",
        "command -> author -> encode -> protocol self-check -> AuthoredFacts facts -> admit -> projection",
        "`FactAdmissionFn`",
        "poc-10 installs one that dispatches by fact tag to protocol-local decode and validation helpers",
        "durable fact admission or incoming_facts staging",
        "temporary `network_incoming` queue with origin and receive-time metadata",
        "Recognized frame bytes then become temporary `incoming_facts`",
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
        "preserves only the retained fact storage",
        "`facts` plus `local_fact_admissions`",
        "Projection mode is sticky toward replay",
        "Needs are replacement subscriptions",
        "Durable offers are append-only evidence",
        "`pending_projection_matches`",
        "already carries the offer id that woke it",
        "Rejected durable projection items do not stall the batch",
        "Incoming facts start as temp first-pass queue rows",
        "retained while parked on standing context needs",
        "Typed-table inserts are idempotent only when the existing row matches every supplied column",
        "project_fact.rs",
        "fact lifecycle SQL",
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
fn app_module_docs_stay_file_scoped_and_hierarchical() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let app_path = root.join("src/core/app.rs");
    let app = source_text(&app_path);
    let module_doc = rust_module_doc_text(&app_path);
    let normalized_doc = normalize_whitespace(&module_doc);

    for required in [
        "This file owns product-independent CLI hosting for a protocol declaration",
        "parses top-level argv, prints help, handles daemon lifecycle commands, opens the selected runtime for command turns, dispatches registered protocol commands",
        "`main.rs` supplies argv",
        "The protocol supplies a `ProtocolDescription`",
        "The file does not own fact layouts, projector policy, handler policy, row meaning, or concrete command semantics",
    ] {
        assert!(
            normalized_doc.contains(required),
            "src/core/app.rs module docs should explain the app runner's own role: {required:?}"
        );
    }

    for forbidden in [
        "Core can launch any protocol",
        "classify them into incoming facts",
        "process declared time wakes",
        "drain durable projection",
        "drain incoming projection",
        "pump outgoing network rows",
    ] {
        assert!(
            !normalized_doc.contains(forbidden),
            "src/core/app.rs module docs should not retell runtime internals: {forbidden:?}"
        );
    }

    let central = app
        .find("// Central Procedure")
        .expect("src/core/app.rs has a central procedure section");
    let dispatch = app
        .find("// Command Dispatch Stages")
        .expect("src/core/app.rs has command dispatch stages");
    let usage = app
        .find("// Usage Helpers")
        .expect("src/core/app.rs has usage helpers");
    let assertion = app
        .find("// Assert Eventually Helpers")
        .expect("src/core/app.rs has assertion helpers");
    let args = app
        .find("// Argument Parsing Helpers")
        .expect("src/core/app.rs has argument parsing helpers");
    assert!(
        central < dispatch && dispatch < usage && usage < assertion && assertion < args,
        "src/core/app.rs should be ordered central procedure, stages, then helpers"
    );

    for required in [
        "/// Route parsed top-level command words to the generic hosting stage.",
        "/// Start the long-running daemon for the selected database.",
        "/// Poll one protocol command until a scalar output field satisfies a comparison.",
        "/// Run a registered protocol command inside one serialized command turn.",
        "/// Remove assertion options and return remaining assertion words plus timing.",
        "/// Parse process-wide `--db` and `--at` options from argv.",
    ] {
        assert!(
            app.contains(required),
            "src/core/app.rs should document its important functions: {required:?}"
        );
    }
}

#[test]
fn daemon_module_keeps_lifecycle_commands_above_purpose_grouped_helpers() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let daemon_path = root.join("src/core/daemon.rs");
    let daemon = source_text(&daemon_path);
    let module_doc = rust_module_doc_text(&daemon_path);
    let normalized_doc = normalize_whitespace(&module_doc);

    for required in [
        "The daemon is the reusable process host around a runtime turn",
        "This file does not define the work performed inside a turn",
        "`core::runtime` owns the bounded turn order",
        "`core::app` is the layer above both pieces",
    ] {
        assert!(
            normalized_doc.contains(required),
            "src/core/daemon.rs module docs should explain daemon lifecycle ownership: {required:?}"
        );
    }

    let command_types = daemon
        .find("// Daemon Command Types")
        .expect("src/core/daemon.rs marks daemon command types");
    let central_commands = daemon
        .find("// Central Daemon Commands")
        .expect("src/core/daemon.rs marks central daemon commands");
    let start_options = daemon
        .find("// Start Option Parsing Helpers")
        .expect("src/core/daemon.rs groups start option helpers by use");
    let loop_signal = daemon
        .find("// Daemon Loop And Signal Helpers")
        .expect("src/core/daemon.rs groups loop and signal helpers by use");
    let stop_reset = daemon
        .find("// Stop And Reset Helpers")
        .expect("src/core/daemon.rs groups stop/reset helpers by use");
    let reset_paths = daemon
        .find("// Reset Path Helpers")
        .expect("src/core/daemon.rs groups reset path helpers by use");
    let stop_process = daemon
        .find("// Stop Process Helpers")
        .expect("src/core/daemon.rs groups process-stop helpers by use");
    let daemon_lock = daemon
        .find("// Daemon Lock Helpers")
        .expect("src/core/daemon.rs groups daemon lock helpers by use");
    let output_helpers = daemon
        .find("// Output Helpers")
        .expect("src/core/daemon.rs groups output helpers by use");
    assert!(
        command_types < central_commands
            && central_commands < start_options
            && start_options < loop_signal
            && loop_signal < stop_reset
            && stop_reset < reset_paths
            && reset_paths < stop_process
            && stop_process < daemon_lock
            && daemon_lock < output_helpers,
        "src/core/daemon.rs should keep central daemon commands before purpose-specific helper sections"
    );
}

#[test]
fn runtime_module_docs_define_turn_jargon_for_newcomers() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let runtime_path = root.join("src/core/runtime.rs");
    let runtime = source_text(&runtime_path);
    let module_doc = rust_module_doc_text(&runtime_path);
    let normalized_doc = normalize_whitespace(&module_doc);

    for required in [
        "Runtime is where the protocol-neutral core engine becomes one executable protocol instance",
        "defines the bounded order for one runtime turn",
        "offers recurring maintenance, drains local and durable intent queues",
        "## Recurring Intents",
        "Recurring intents are protocol-declared maintenance checks",
        "They are not persisted timers",
        "shares the same handler contract and queue ordering as explicit local work",
        "## Terms Used Below",
        "A fact is an immutable protocol record",
        "Projection is the deterministic step that turns facts into context, rows, time wakes, and follow-up work",
        "An intent is queued stateful work",
        "a handler is the registered function that performs one intent",
        "A time wake is a scheduled reminder",
        "Durable work is persisted in SQLite; local work is process-local and disappears on restart",
    ] {
        assert!(
            normalized_doc.contains(required),
            "src/core/runtime.rs module docs should define runtime jargon for newcomers: {required:?}"
        );
    }

    let runtime_intro = normalized_doc
        .find("Runtime is where the protocol-neutral core engine becomes one executable protocol instance")
        .expect("runtime docs explain the main runtime role");
    let recurring_section = normalized_doc
        .find("## Recurring Intents")
        .expect("runtime docs have a recurring-intents section");
    let terms_section = normalized_doc
        .find("## Terms Used Below")
        .expect("runtime docs have a terms section");
    assert!(
        runtime_intro < recurring_section && recurring_section < terms_section,
        "src/core/runtime.rs module docs should explain the main action before vocabulary details"
    );

    let central_facade = runtime
        .find("// Central Runtime Facade")
        .expect("src/core/runtime.rs marks its central runtime facade");
    let central_turn = runtime
        .find("// Central Turn Procedure")
        .expect("src/core/runtime.rs marks the central turn procedure");
    let turn_stage_helpers = runtime
        .find("// Runtime Turn Budget And Stage Helpers")
        .expect("src/core/runtime.rs groups turn-stage helpers by use");
    let clock_helpers = runtime
        .find("// Clock Helpers")
        .expect("src/core/runtime.rs groups clock helpers by use");
    let profiling_helpers = runtime
        .find("// Runtime Turn Profiling Helpers")
        .expect("src/core/runtime.rs groups profiling helpers by use");
    let lock_path_helpers = runtime
        .find("// Runtime Lock Path Helpers")
        .expect("src/core/runtime.rs groups lock path helpers by use");
    let schema_helpers = runtime
        .find("// Schema Opening Helpers")
        .expect("src/core/runtime.rs groups schema-opening helpers by use");
    let bounded_drain_helpers = runtime
        .find("// Generic Bounded Drain Helpers")
        .expect("src/core/runtime.rs groups generic drain helpers by use");
    assert!(
        central_facade < central_turn
            && central_turn < turn_stage_helpers
            && turn_stage_helpers < clock_helpers
            && clock_helpers < profiling_helpers
            && profiling_helpers < lock_path_helpers
            && lock_path_helpers < schema_helpers
            && schema_helpers < bounded_drain_helpers,
        "src/core/runtime.rs should keep central runtime logic before purpose-specific helper sections"
    );
}

#[test]
fn cli_module_keeps_dispatch_core_above_helpers() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let cli = source_text(&root.join("src/core/cli.rs"));

    let run = cli
        .find("pub fn run<C>")
        .expect("src/core/cli.rs exposes the registry runner");
    let helpers = cli
        .find("// Helper Functions")
        .expect("src/core/cli.rs marks helper functions");
    assert!(
        run < helpers,
        "src/core/cli.rs should keep the registry runner above helper functions"
    );

    for helper in [
        "fn validate_command_names<C>",
        "pub fn usage<C>",
        "pub fn decode_hex_32(",
        "pub fn decode_hex_32_named(",
        "pub fn encode_hex_32(",
        "pub fn encode_hex(",
        "pub fn read_file_bytes(",
        "pub fn write_file_bytes(",
        "fn hex_nibble(",
    ] {
        let helper_offset = cli
            .find(helper)
            .unwrap_or_else(|| panic!("src/core/cli.rs is missing helper {helper:?}"));
        assert!(
            helpers < helper_offset,
            "src/core/cli.rs helper {helper:?} should live below the helper section"
        );
    }
}

#[test]
fn command_module_docs_explain_command_system_role() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let command_path = root.join("src/core/command.rs");
    let command_doc = rust_module_doc_text(&command_path);
    let normalized_doc = normalize_whitespace(&command_doc);

    for required in [
        "Commands are the system's explicit user/API write path",
        "A command starts from caller intent and the currently projected database state",
        "stamps deterministic command time through a `CommandClock`",
        "runtime submission retains them and lets ordinary projection publish context, rows, intents, and later visibility",
        "Command implementation still belongs with the protocol fact family that owns the operation",
        "This file is the shared core vocabulary for that boundary",
        "`AuthoredFacts`, the narrow receipt-plus-facts bundle accepted by runtime submission",
        "It deliberately does not register command names, parse CLI argv, know protocol layouts, or decide command semantics",
    ] {
        assert!(
            normalized_doc.contains(required),
            "src/core/command.rs module docs should explain command system role: {required:?}"
        );
    }
}

#[test]
fn db_module_docs_explain_identifier_quoting_and_storage_marker_reads() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let db_path = root.join("src/core/db.rs");
    let db_doc = rust_module_doc_text(&db_path);
    let normalized_doc = normalize_whitespace(&db_doc);

    for required in [
        "The exported surface is split by responsibility",
        "`Db` is the reusable SQLite handle and transaction boundary",
        "`TableName`, `TypedTableSchema`, `TableInsert`, `TableDeleteWhere`, `RowMutation`, and `Value` are the typed-row mutation vocabulary",
        "`SchemaSource`, `StorageVersionSource`, and `ReplayTables` let runtime owners declare schema, upgrade-marker, and rebuild lifecycle metadata",
        "The crate-visible quoting helpers are for modules that own direct SQL",
        "quotes trusted table and column identifiers for syntax safety",
        "The first exported path below is the one fact families use most often",
        "declare a `TypedTableSchema`, build `TableInsert` or `TableDeleteWhere` values from decoded facts, emit `RowMutation`s",
        "The storage-version marker is protocol-owned state",
        "A `SchemaSource` may declare a `StorageVersionSource`: the marker table, the version column, and the columns that sort newest marker rows first",
        "`Db` records only that read recipe when it opens schema sources",
        "`current_storage_version()` then asks \"what storage version does this database currently project?\"",
        "`protocol_version_rows.protocol_version ORDER BY applied_at_ms DESC, update_fact_id DESC LIMIT 1`",
        "Fresh or stale databases are repaired by the protocol's versioning update path",
        "core only reads the marker to enforce declared commit preconditions",
        "Query helpers that opt into current-storage checks use the same marker to return a mismatch error before reading incompatible materialized rows",
    ] {
        assert!(
            normalized_doc.contains(required),
            "src/core/db.rs module docs should explain quoting and storage marker reads: {required:?}"
        );
    }
}

#[test]
fn db_module_layout_presents_exports_before_stages_and_helpers() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let db = source_text(&root.join("src/core/db.rs"));

    let mut previous = 0usize;
    for section in [
        "Query Defaults",
        "Typed Row Vocabulary",
        "Exported Database Handle",
        "Central Entry Points",
        "Typed Row Mutation Operations",
        "Schema Source Vocabulary",
        "Schema Opening Stages",
        "Replay Lifecycle Views",
        "Storage-Version Marker Reads",
        "Compiled Schema Metadata",
        "Shared Error Helper",
        "Schema Opening Helpers",
        "SQL Identifier Helpers",
        "Row Mutation SQL Helpers",
    ] {
        let offset = db
            .find(section)
            .unwrap_or_else(|| panic!("src/core/db.rs is missing section {section:?}"));
        assert!(
            previous < offset,
            "src/core/db.rs section {section:?} should appear after the previous section"
        );
        previous = offset;
    }

    for exported in [
        "pub const DEFAULT_QUERY_LIMIT",
        "pub struct TableName",
        "pub enum Value",
        "pub struct TableInsert",
        "pub struct TableDeleteWhere",
        "pub struct TypedTableSchema",
        "pub enum RowMutation",
        "pub struct SchemaSource",
        "pub struct ReplayTables",
        "pub struct StorageVersionSource",
        "pub struct Db",
        "struct SchemaCatalog",
        "struct ReplayCatalog",
    ] {
        assert!(
            db.contains(exported),
            "src/core/db.rs should make exported database surface visible: {exported:?}"
        );
    }
}

#[test]
fn network_module_docs_and_layout_explain_exported_io_boundary() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let network_path = root.join("src/core/network.rs");
    let network = source_text(&network_path);
    let module_doc = rust_module_doc_text(&network_path);
    let normalized_doc = normalize_whitespace(&module_doc);

    for required in [
        "The exported surface is split by responsibility",
        "`SCHEMA_SOURCE` and the table constants declare process-local queue storage",
        "`NetworkTarget`, `NetworkSource`, `OutgoingFrame`, `OutgoingNetworkRow`, and `IncomingNetworkRow` are opaque endpoint and byte-carrier vocabulary",
        "`queue_outgoing`, `enqueue_*`, `claim_*`, and `delete_*` own queue row lifecycle",
        "`pump_outgoing`, `listen`, `Listener`, and the report structs own TCP mechanics without interpreting frame payloads",
    ] {
        assert!(
            normalized_doc.contains(required),
            "src/core/network.rs module docs should explain exported IO boundary detail {required:?}"
        );
    }

    let mut previous = 0usize;
    for section in [
        "Schema And Queue Tables",
        "Opaque Network Vocabulary",
        "Central Procedures",
        "Queue Storage Stages",
        "Outgoing Pump Stages",
        "Listener And Inbound Stages",
        "Queue Storage SQL Helpers",
        "Queue Row Key And Decode Helpers",
        "TCP Framing Helpers",
    ] {
        let offset = network
            .find(section)
            .unwrap_or_else(|| panic!("src/core/network.rs is missing section {section:?}"));
        assert!(
            previous < offset,
            "src/core/network.rs section {section:?} should appear after the previous section"
        );
        previous = offset;
    }

    for exported in [
        "pub const OUTGOING_TABLE",
        "pub const OUTGOING_TARGETS_TABLE",
        "pub const INCOMING_TABLE",
        "pub const SCHEMA_SOURCE",
        "pub struct NetworkTarget",
        "pub struct NetworkSource",
        "pub struct OutgoingFrame",
        "pub struct OutgoingNetworkRow",
        "pub struct IncomingNetworkRow",
        "pub struct OutgoingPumpReport",
        "pub struct StreamReport",
        "pub struct AcceptReport<T>",
        "pub struct Listener",
        "pub fn queue_outgoing",
        "pub fn pump_outgoing",
        "pub fn listen",
    ] {
        assert!(
            network.contains(exported),
            "src/core/network.rs should make exported network surface visible: {exported:?}"
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
        "`db.rs`: SQLite substrate below runtime policy",
        "applies typed row mutations",
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
