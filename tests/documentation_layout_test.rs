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
fn protocol_version_flexibility_design_is_local_and_poc10_specific() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let note_path = root.join("docs/research/protocol-version-flexibility.md");
    let note = source_text(&note_path);
    let normalized = normalize_whitespace(&note);

    for required in [
        "# Protocol Version Flexibility Design",
        "poc-10 protocol evolution policy",
        "immutable canonical fact bytes",
        "one provider-signed client family",
        "The visibility invariant is:",
        "Any shared production action emitted under the current production protocol ceiling",
        "This policy is intentionally conservative",
        "global production protocol ceiling, not per-workspace or per-peer readiness",
        "consensus problem that this policy does not introduce",
        "Core Policy",
        "The policy has four separations",
        "**Protocol ceiling.**",
        "global expiry-derived protocol ceiling",
        "Production clients may create, admit, project, and display shared durable protocol",
        "must not register that reader, projector, or command path until every still-usable non-capable release has expired or been security-deprecated",
        "implementation head",
        "**Release safety.**",
        "`warn_after` and `expires_at`",
        "shared durable protocol capabilities",
        "`must_update` canary",
        "**Fact-version safety.**",
        "Security-deprecating a client release does not automatically invalidate historical facts",
        "**Replay truth.**",
        "Updates wipe materialized state and replay retained facts through historical adapters plus the ceiling-active registry",
        "**One protocol ceiling.**",
        "a release is still usable if it is not past `expires_at`",
        "greatest shared durable protocol version supported by every still-usable release",
        "producible and admissible in production only when the ceiling allows them",
        "**Expiry-driven ceiling advance.**",
        "last still-usable release that cannot create, admit, project, or display it expires",
        "oldest still-usable non-capable release",
        "`expires_at` is the ceiling transition",
        "do not add a separate readiness signal",
        "infer readiness from observed active clients",
        "**Trusted time.**",
        "greatest trusted time",
        "**Alpha isolation.**",
        "Production workspaces reject or quarantine above-ceiling facts instead of reading them",
        "**Old readers stay.**",
        "Old fact adapters and projectors stay in the codebase",
        "**Old meaning stays old.**",
        "ceiling-era read-model rows and durable needs",
        "must not grant an old fact new authority",
        "**Signed facts are not assumed rewritable.**",
        "correctness must remain safe when old signers never return",
        "**Replay is deterministic and local.**",
        "sync indexes, negentropy trees, due-time indexes",
        "Replay must not observe fresh time",
        "full replay and purge completion must finish before any network receive",
        "**Permanent state is facts.**",
        "Purge facts must be preserved until every protected byte, row, and local secret they cover is gone",
        "During replay, preserved purge facts define absence",
        "local purge work must complete before the runtime reconnects",
        "**Transport compatibility is separate.**",
        "A vN request receives a vN-shaped response",
        "Security Changes",
        "**Unsafe release:**",
        "**Unsafe fact version:**",
        "**Unsafe derived state:**",
        "Plaintext usernames are the useful example",
        "`auth::user::UserFact` contains plaintext `username`",
        "later devices usually have only their endpoint signing key",
        "cannot reissue the same `auth::user` shape",
        "The practical fix is a new ceiling-gated profile fact",
        "`user_profile_v2` is signed by an admitted endpoint",
        "`endpoint_shared.user_authority_fact_id == subject_user_id`",
        "It cannot change membership, admin authority, the original user public key, or the subject user id",
        "policy fact can hide or quarantine old plaintext names",
        "Intents And Replay",
        "Facts are the compatibility boundary; intents are current-runtime work",
        "queued intents are not the durable source of correctness",
        "produce ceiling-active durable needs or current intent payloads",
        "Not every queued intent is rebuildable as the exact same action",
        "**Exactly rebuildable:**",
        "**Recoverable by protocol retry:**",
        "**Already canonicalized:**",
        "The upgrade boundary must stop dispatch at a handler boundary",
        "queued but not-running intent may be dropped",
        "An in-flight handler must either finish its commit or abort without committing before the wipe",
        "Handler-generated randomness is not rebuildable",
        "Current poc-10 intent replay behavior",
        "Default upgrade behavior",
        "`send_bootstrap_connection_request`",
        "Not safe during replay",
        "`create_connection_response`",
        "An uncommitted responder ephemeral key is not",
        "post-barrier retry is acceptable",
        "`send_sync_compare_response`",
        "Old compare facts tied to retired connections should not drive sends",
        "`send_needed_fact_id`",
        "Old have-id facts tied to retired connections should not create fresh need-id facts",
        "`send_requested_fact`",
        "`share_fact_with_sync`",
        "Live-tail sends are not replay work",
        "seed sync from rebuilt indexes",
        "`seed_connection_sync`",
        "Run only for connections explicitly recreated after the replay barrier",
        "`create_key_wrap`",
        "`unwrap_key_wrap`",
        "Fine only if purge/retirement projection removes unusable local recipient capability first",
        "A retained wrap alone is not enough",
        "purge/retirement projection removes unusable local recipient capability",
        "replay must not resurrect the opened secret",
        "`send_facts_on_connection`",
        "`send_network_frame`",
        "`receive_network_frame`",
        "Not rebuildable until it creates canonical request, response, frame, or receipt facts",
        "drain or stage inbound frames as local facts before upgrade",
        "It must not fabricate missing key material",
        "Drop queued local sends and allow retry after the replay/network barrier",
        "Connection responses need special care",
        "`connection_response` fact is local durable session state",
        "wiping rows and sockets does not close it",
        "retire all pre-upgrade connections before replay",
        "The same applies to sync control facts that name a connection id",
        "wrong as replay-time network activity for a retired session",
        "Connection And Sync",
        "transport format",
        "shared durable protocol",
        "For a still-usable older release, the ceiling already guarantees",
        "The mixed-version problem is therefore transport selection, not content fallback",
        "**Newer initiates to older.**",
        "If no trustworthy metadata exists, it uses the oldest still-safe bootstrap version",
        "**Older initiates to newer.**",
        "creates an old-shaped response",
        "**Established session.**",
        "A newer carrier can be negotiated later only inside the authenticated session",
        "**Expired older release.**",
        "does not lower the durable protocol ceiling",
        "**Envelope version.**",
        "old-shaped compare children, old-shaped have/need facts, and old-shaped frame bundles",
        "**Fact bytes stay canonical.**",
        "Receiving still routes by the fact's own type tag",
        "**Dependency closure.**",
        "correctness is preserved, latency is worse",
        "**Carrier limits are real.**",
        "old-carrier-compatible chunking path",
        "**Current-ceiling transfer.**",
        "The `v1` label describes only the sync envelope",
        "Upgrade Examples",
        "poc-10 scopes and poc-7/topo event families",
        "Workspaces, users, admins, invites, endpoints",
        "poc-10 `auth::{workspace,user,admin,user_invite,device_invite,invite_accepted,endpoint,endpoint_shared}`",
        "topo `workspace`, `user`, `admin`, `user_invite`, `device_invite`, `invite_accepted`, `peer_shared`, `endpoint_shared`",
        "Encrypted usernames and profile data",
        "topo `user` has plaintext `username`",
        "Messages",
        "poc-10 `content::message`; topo `message`",
        "become readable/projectable and writable in production only at a ceiling raise",
        "Channels, groups, spaces",
        "No first-class poc-10 content family",
        "retention policy already carries `scope_kind`",
        "Reactions",
        "Files and file slices",
        "BAO proof formats",
        "Link unfurls",
        "No poc-10 shared durable family",
        "Online status and presence",
        "No poc-10 durable content family",
        "Message deletion, file deletion, disappearing messages, retention",
        "Forward secrecy history keys",
        "TreeKEM or key-wrap redesign",
        "ceiling-active deterministic coverage needs",
        "registered handlers create new wraps only when local secret material proves they can",
        "Connection bootstrap, receipts, frames",
        "Sync and negentropy",
        "Implementation Shape",
        "route command construction and fact admission through protocol-ceiling checks",
        "store signed release/canary/time observations as durable local facts",
        "manifest entry naming the releases that support it",
        "blocking non-capable releases and their expiries",
        "above-ceiling facts are rejected or quarantined in production",
    ] {
        assert!(
            normalized.contains(required),
            "protocol version research note is missing {required:?}"
        );
    }

    for removed in [
        "## Industry Patterns",
        "libp2p protocol IDs and fallback",
        "Ethereum devp2p capabilities",
        "BitTorrent Extension Protocol",
        "QUIC version negotiation",
        "Kafka and Confluent Schema Registry",
        "Signal release expiration and old-device pressure",
        "still strict",
        "outside the current design",
        "The policy below",
        "provider-scheduled protocol ceiling",
        "**Scheduled ceiling advance.**",
        "`ceiling_raises_at`",
        "manifest entry naming its first production ceiling",
        "old queued intents",
        "ensure_key_wrap_coverage_vCurrent",
        "v1 envelope",
        "Purge facts must exist before purged data disappears",
        "current poc-10 scopes and the older poc-7/topo event families",
        "Not a first-class current poc-10 content family",
        "Not a core current family",
        "ship as readers first",
        "newest-only facts must not enter production workspaces",
        "first writable ceiling",
        "## Local Reference",
        "## Minimal Design",
        "## One-Client-Family Compatibility Design",
        "fallback/canonical",
        "`fallback_fact`",
        "`canonical_fact`",
        "`canonical_to_fallback_lens`",
        "Planner Contract",
        "plan_compat",
        "legacy_fallback",
        "permanent_fallback",
        "## Maximal Design",
        "Maximal tactic",
        "Recommended maximal baseline",
        "independent apps using protocol scopes modularly",
        "protocol platform",
    ] {
        assert!(
            !note.contains(removed),
            "protocol version design should not include removed industry survey detail {removed:?}"
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
        "Registry test: every `HandlerRoute` has `runs_during_replay` set explicitly",
        "Time-wake test: every daemon `TimeWake` timeline is replayable",
        "Unwrap test: replay dispatch of `unwrap_key_wrap` is idempotent",
        "creates deterministic local secret facts",
        "respects existing purge/retirement facts",
        "Connection test: replay no longer recreates bootstrap retries from old `connection_request` history alone",
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
