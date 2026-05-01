//! Pure projector contract types.
//!
//! Projectors are pure functions over `(event_id_b64, ParsedEvent, ContextSnapshot)`
//! that return a `ProjectorResult`. They do not execute SQL or any other
//! side effects directly. The apply engine in `apply.rs` executes the
//! returned `write_ops` transactionally, then runs `emit_commands` via
//! explicit handlers.

/// Value that can be bound to a SQL parameter in a WriteOp.
#[derive(Debug, Clone, PartialEq)]
pub enum SqlVal {
    Text(String),
    Int(i64),
    Blob(Vec<u8>),
}

/// A single idempotent database write operation returned by a pure projector.
#[derive(Debug, Clone, PartialEq)]
pub enum WriteOp {
    /// INSERT OR IGNORE INTO table (columns...) VALUES (values...).
    InsertOrIgnore {
        table: &'static str,
        columns: Vec<&'static str>,
        values: Vec<SqlVal>,
    },
    /// DELETE FROM table WHERE col1 = v1 AND col2 = v2 ...
    Delete {
        table: &'static str,
        where_clause: Vec<(&'static str, SqlVal)>,
    },
}

/// A follow-on command to execute after write_ops are applied.
///
/// Commands represent non-deterministic or cascading actions that must happen
/// after the projection writes commit. Command identities are derived from
/// event identity for idempotence.
#[derive(Debug, Clone, PartialEq)]
pub enum EmitCommand {
    /// Hard-purge a tombstoned message event and all discovered dependents for
    /// the current tenant inside the current projection transaction.
    HardPurgeMessageGraph { message_event_id: String },
    /// Re-project a specific workspace event after accepted-workspace binding was set.
    /// Emitted by invite_accepted when it knows the workspace_id.
    /// Flows through normal projection + cascade.
    RetryWorkspaceEvent { workspace_id: String },
    /// Retry file_slice guard-blocked events for a specific file_id.
    RetryFileSliceGuards { file_id: String },
    /// Record a guard-block for a file_slice awaiting its descriptor.
    RecordFileSliceGuardBlock { file_id: String, event_id: String },
    /// Materialise a transport identity transition via the materializer boundary.
    /// Replaces the former ad-hoc RefreshTransportCreds marker.
    MaterializeTransportIdentity {
        spec: crate::contracts::transport_identity_contract::TransportIdentitySpec,
    },
    /// Emit a canonical deterministic event blob through the normal event
    /// pipeline (events + recorded_events + project_one).
    EmitDeterministicBlob { blob: Vec<u8> },
}

/// The pure projector contract: everything a projector returns.
///
/// `decision` carries the same semantics as the old `ProjectionDecision` —
/// Valid, Block, Reject, AlreadyProcessed.
///
/// `write_ops` are the deterministic state mutations to apply transactionally.
/// They are only applied when `decision` is `Valid`.
///
/// `emit_commands` are follow-on actions to run after write_ops commit.
/// They are executed for:
/// - `Valid` decisions (normal post-write follow-ons), and
/// - `Block` decisions (block-side effects such as file-slice guard rows).
#[derive(Debug, Clone)]
pub struct ProjectorResult {
    pub decision: super::decision::ProjectionDecision,
    pub write_ops: Vec<WriteOp>,
    pub emit_commands: Vec<EmitCommand>,
}

impl ProjectorResult {
    /// Convenience: create a Valid result with the given write_ops.
    pub fn valid(write_ops: Vec<WriteOp>) -> Self {
        Self {
            decision: super::decision::ProjectionDecision::Valid,
            write_ops,
            emit_commands: Vec::new(),
        }
    }

    /// Convenience: create a Valid result with write_ops and commands.
    pub fn valid_with_commands(write_ops: Vec<WriteOp>, emit_commands: Vec<EmitCommand>) -> Self {
        Self {
            decision: super::decision::ProjectionDecision::Valid,
            write_ops,
            emit_commands,
        }
    }

    /// Convenience: create a Reject result (no writes, no commands).
    pub fn reject(reason: String) -> Self {
        Self {
            decision: super::decision::ProjectionDecision::Reject { reason },
            write_ops: Vec::new(),
            emit_commands: Vec::new(),
        }
    }

    /// Convenience: create a Block result (no writes, no commands).
    pub fn block(missing: Vec<[u8; 32]>) -> Self {
        Self {
            decision: super::decision::ProjectionDecision::Block { missing },
            write_ops: Vec::new(),
            emit_commands: Vec::new(),
        }
    }

    /// Convenience: create an AlreadyProcessed result.
    pub fn already_processed() -> Self {
        Self {
            decision: super::decision::ProjectionDecision::AlreadyProcessed,
            write_ops: Vec::new(),
            emit_commands: Vec::new(),
        }
    }
}

/// Read-model snapshot passed to pure projectors for context queries.
///
/// Per plan.md (Forking plan, "no scaffolding" rule): every projector sees
/// the same `{event, deps, labels}` snapshot. The pipeline populates this
/// struct via `state::generic_context::load_generic_context`, which reads
/// only `events_canonical` (for declared deps) and `labels` (for gate
/// labels). Sync-family projectors (Compare/Have/Need) get a small set of
/// extension fields populated by the same loader.
///
/// `labels` is the generic gating channel introduced by plan.md §164-170 —
/// keyed by base64 event id (the event's own id and each declared dep), value
/// is the set of label types attached. Projectors check this map for gating
/// signals like `deleted` (target message tombstoned), `removed_by:<issuer>`
/// (signer identity revoked), or `superseded` (invite invalidated).
///
/// `deps` is the generic dependency channel. Keyed by base64 event id of
/// each declared dep that has been admitted into `events_canonical`; value
/// is the dep's canonical event bytes (so a projector can `parse_event(bytes)`
/// to inspect the dep on demand).
#[derive(Debug, Clone, Default)]
pub struct ContextSnapshot {
    /// Generic gate-label map populated at context-load time by the pipeline.
    ///
    /// Keyed by base64 event id (the event's own id, every declared dep, and
    /// the signer/author/target id when applicable). Value is the list of
    /// label types attached. See `crate::state::labels` for the canonical
    /// label types.
    pub labels: std::collections::BTreeMap<String, Vec<String>>,

    /// Generic dependency map populated at context-load time by the
    /// `state::generic_context` loader (plan.md lines 234-240). Keyed by
    /// base64 event id of each declared dep that has been admitted into
    /// `events_canonical`; value is the dep's canonical event bytes (so a
    /// projector can `parse_event(bytes)` to inspect the dep on demand).
    ///
    /// Deps that are not yet present in `events_canonical` are ABSENT from
    /// this map — the chain blocks-by-event on missing deps before reaching
    /// the projector, so a missing key is informational only.
    pub deps: std::collections::BTreeMap<String, Vec<u8>>,

    // ----- sync-family extensions (compare/have/need) -----
    //
    // The sync projectors fold over local `negentropy_tree` and
    // `events_canonical` state that the generic loader does NOT carry on
    // its own. Per plan.md "if a projector needs more state, that state
    // must arrive as a declared dependency or a label" — these fields ride
    // on the snapshot as a sync-aware extension to deps so the pure
    // projector path can drive the chain.
    //
    // For non-sync events, all of these stay at their `Default` values
    // (`None` / empty), so the cost is one cold field load per snapshot.
    /// CompareEvent: local negentropy fingerprint `F_v` for `(workspace_id,
    /// node_id)`. `None` means "no row yet" (zero fingerprint by
    /// convention; see `negentropy_tree::query::node_fingerprint`).
    pub local_sync_node_fingerprint: Option<[u8; 32]>,
    /// CompareEvent: distinct child `node_id`s of length `len(node_id)+1`
    /// that prefix any membership row beneath `node_id`, paired with that
    /// child's local fingerprint `F_v`. Empty means `node_id` is a leaf in
    /// the projected tree.
    pub local_sync_node_children: Vec<(Vec<u8>, [u8; 32])>,
    /// CompareEvent: members `R_v` recorded exactly at `node_id`
    /// (leaf-emit set).
    pub local_sync_node_members: Vec<[u8; 32]>,
    /// HaveEvent / NeedEvent: whether the referenced `event_id` is
    /// locally present in `events_canonical` (with status not `rejected`).
    pub local_sync_has_event: Option<bool>,
    /// NeedEvent: canonical bytes of the referenced event, when locally
    /// sendable (status not `rejected`/`processing` and bytes non-empty).
    pub local_sync_event_bytes: Option<Vec<u8>>,
}
