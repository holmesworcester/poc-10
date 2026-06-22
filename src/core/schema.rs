//! Core-owned schema declarations.
//!
//! This file is the durable and memory table inventory for the generic
//! runtime: facts, local admissions, standing context, time wakes, pending
//! projection, pending projection matches, incoming facts, and intent queues. It
//! exposes one executable `SchemaSource` plus typed `TableName` constants so the
//! rest of core does not repeat string literals.
//!
//! These tables are the shared substrate behind the runtime work documented in
//! `src/core/README.md` and the projection boundary documented in
//! `project_fact.rs`.
//! `facts` and `local_fact_admissions` store immutable inputs and their local
//! visibility metadata. `context_exact_edges`, `context_range_edges`,
//! `context_exact_offers`, `context_range_offers`, `time_wakes`,
//! `pending_projection`, and `pending_projection_matches` drive
//! fact projection. `intents`, `intent_context`, `local_intents`, and
//! `local_intent_context` drive handler dispatch.
//!
//! Core schema is deliberately small and mechanical. It records the runtime
//! queues and indexes needed to move work; it does not encode protocol policy
//! such as what makes a message valid, which key can decrypt content, or which
//! sync range should be requested. That policy belongs beside the fact, query,
//! domain range-helper, and projector modules that understand it.
//!
//! Add a table here when the table is part of core's runtime mechanics. Add it
//! in a protocol module when it stores protocol meaning, even if core commits
//! the row mutation.

use crate::core::db::{ReplayTables, SchemaSource, TableName};

/// Content-addressed durable fact byte table.
pub(crate) const FACTS: TableName = TableName::new("facts");
/// Local admission metadata table for content-addressed fact bytes.
pub(crate) const LOCAL_FACT_ADMISSIONS: TableName = TableName::new("local_fact_admissions");
/// Standing exact context edge table.
pub(crate) const CONTEXT_EXACT_EDGES: TableName = TableName::new("context_exact_edges");
/// Standing exact context offer table.
pub(crate) const CONTEXT_EXACT_OFFERS: TableName = TableName::new("context_exact_offers");
/// Standing true-range context edge table.
pub(crate) const CONTEXT_RANGE_EDGES: TableName = TableName::new("context_range_edges");
/// Standing true-range context offer table.
pub(crate) const CONTEXT_RANGE_OFFERS: TableName = TableName::new("context_range_offers");
/// Semantic time wake table.
pub(crate) const TIME_WAKES: TableName = TableName::new("time_wakes");
/// Pending projection queue table.
pub(crate) const PENDING_PROJECTION: TableName = TableName::new("pending_projection");
/// Matched context attached to pending projection queue rows.
pub(crate) const PENDING_PROJECTION_MATCHES: TableName =
    TableName::new("pending_projection_matches");
/// Pending projection time-context table.
pub(crate) const PENDING_TIME_RANGES: TableName = TableName::new("pending_time_ranges");
/// Durable intent queue table.
pub(crate) const INTENTS: TableName = TableName::new("intents");
/// Durable intent context fact table.
pub(crate) const INTENT_CONTEXT: TableName = TableName::new("intent_context");
/// Ephemeral intent queue table.
pub(crate) const LOCAL_INTENTS: TableName = TableName::new("local_intents");
/// Ephemeral intent context fact table.
pub(crate) const LOCAL_INTENT_CONTEXT: TableName = TableName::new("local_intent_context");
/// Volatile fact table for outside-origin incoming inputs.
pub(crate) const INCOMING_FACTS: TableName = TableName::new("incoming_facts");
/// Durable diagnostic timing rows for projected inputs.
pub(crate) const PROJECTION_TIMINGS: TableName = TableName::new("projection_timings");
const CORE_REPLAY_PROTECTED_TABLES: &[TableName] = &[FACTS, LOCAL_FACT_ADMISSIONS];

const CORE_REPLAY_RESET_TABLES: &[TableName] = &[
    CONTEXT_EXACT_EDGES,
    CONTEXT_EXACT_OFFERS,
    CONTEXT_RANGE_EDGES,
    CONTEXT_RANGE_OFFERS,
    TIME_WAKES,
    PENDING_PROJECTION,
    PENDING_PROJECTION_MATCHES,
    PENDING_TIME_RANGES,
    INTENTS,
    INTENT_CONTEXT,
    LOCAL_INTENTS,
    LOCAL_INTENT_CONTEXT,
    INCOMING_FACTS,
    PROJECTION_TIMINGS,
];

const CORE_REPLAY_SUMMARY_TABLES: &[TableName] = &[
    FACTS,
    CONTEXT_EXACT_EDGES,
    CONTEXT_EXACT_OFFERS,
    CONTEXT_RANGE_EDGES,
    CONTEXT_RANGE_OFFERS,
    TIME_WAKES,
];

/// The core SQLite schema source applied to every runtime database.
///
/// The DDL is intentionally ordinary SQL rather than a DSL. Core-owned typed
/// tables are declared here; protocol modules and core IO modules contribute
/// their own `SchemaSource`s beside the row encoders and query helpers that
/// understand those tables.
pub const CORE_SCHEMA_SOURCE: SchemaSource = SchemaSource {
    ddl: r#"
CREATE TABLE IF NOT EXISTS facts (
    id BLOB PRIMARY KEY NOT NULL,
    bytes BLOB NOT NULL
);

CREATE TABLE IF NOT EXISTS local_fact_admissions (
    id BLOB PRIMARY KEY NOT NULL,
    fact_id BLOB NOT NULL,
    scope TEXT NOT NULL,
    scope_kind TEXT NOT NULL,
    scope_id BLOB NOT NULL,
    received_at INTEGER NOT NULL,
    bytes BLOB NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS local_fact_admissions_by_fact
    ON local_fact_admissions (fact_id);
CREATE INDEX IF NOT EXISTS local_fact_admissions_by_scope_received_at
    ON local_fact_admissions (scope, scope_kind, scope_id, received_at);

CREATE TABLE IF NOT EXISTS context_exact_edges (
    owner BLOB NOT NULL,
    direction TEXT NOT NULL,
    role TEXT NOT NULL,
    scope_key BLOB NOT NULL,
    key BLOB NOT NULL,
    PRIMARY KEY (owner, direction, role, scope_key, key)
);
CREATE INDEX IF NOT EXISTS context_exact_edges_by_key
    ON context_exact_edges (direction, role, scope_key, key, owner);
CREATE INDEX IF NOT EXISTS context_exact_edges_by_owner
    ON context_exact_edges (owner);

CREATE TABLE IF NOT EXISTS context_exact_offers (
    offer_id BLOB PRIMARY KEY NOT NULL,
    owner BLOB NOT NULL,
    owner_scope_key BLOB NOT NULL,
    owner_received_at INTEGER NOT NULL,
    role TEXT NOT NULL,
    scope_key BLOB NOT NULL,
    key BLOB NOT NULL,
    value BLOB NOT NULL
);
CREATE INDEX IF NOT EXISTS context_exact_offers_by_key
    ON context_exact_offers (role, scope_key, key, owner);
CREATE INDEX IF NOT EXISTS context_exact_offers_by_owner
    ON context_exact_offers (owner);

CREATE TABLE IF NOT EXISTS context_range_edges (
    owner BLOB NOT NULL,
    direction TEXT NOT NULL,
    role TEXT NOT NULL,
    scope_key BLOB NOT NULL,
    start_key BLOB NOT NULL,
    end_key BLOB NOT NULL,
    PRIMARY KEY (owner, direction, role, scope_key, start_key, end_key)
);
CREATE INDEX IF NOT EXISTS context_range_edges_by_range_start
    ON context_range_edges (direction, role, scope_key, start_key);
CREATE INDEX IF NOT EXISTS context_range_edges_by_range_end
    ON context_range_edges (direction, role, scope_key, end_key);
CREATE INDEX IF NOT EXISTS context_range_edges_by_owner
    ON context_range_edges (owner);

CREATE TABLE IF NOT EXISTS context_range_offers (
    offer_id BLOB PRIMARY KEY NOT NULL,
    owner BLOB NOT NULL,
    owner_scope_key BLOB NOT NULL,
    owner_received_at INTEGER NOT NULL,
    role TEXT NOT NULL,
    scope_key BLOB NOT NULL,
    start_key BLOB NOT NULL,
    end_key BLOB NOT NULL,
    value BLOB NOT NULL
);
CREATE INDEX IF NOT EXISTS context_range_offers_by_range_start
    ON context_range_offers (role, scope_key, start_key);
CREATE INDEX IF NOT EXISTS context_range_offers_by_range_end
    ON context_range_offers (role, scope_key, end_key);
CREATE INDEX IF NOT EXISTS context_range_offers_by_owner
    ON context_range_offers (owner);

CREATE TABLE IF NOT EXISTS time_wakes (
    timeline TEXT NOT NULL,
    at INTEGER NOT NULL,
    owner BLOB NOT NULL,
    PRIMARY KEY (timeline, at, owner)
);
CREATE INDEX IF NOT EXISTS time_wakes_by_owner
    ON time_wakes (owner);

CREATE TABLE IF NOT EXISTS pending_projection (
    owner BLOB PRIMARY KEY NOT NULL,
    queued_at INTEGER NOT NULL,
    priority INTEGER NOT NULL DEFAULT 100,
    replay INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS pending_projection_by_queue
    ON pending_projection (queued_at, owner);
CREATE INDEX IF NOT EXISTS pending_projection_by_priority_queue
    ON pending_projection (priority, queued_at, owner);

CREATE TABLE IF NOT EXISTS pending_projection_matches (
    owner BLOB NOT NULL,
    need_role TEXT NOT NULL,
    need_scope_key BLOB NOT NULL,
    need_start_key BLOB NOT NULL,
    need_end_key BLOB NOT NULL,
    offer_id BLOB NOT NULL,
    PRIMARY KEY (
        owner,
        need_role,
        need_scope_key,
        need_start_key,
        need_end_key,
        offer_id
    )
);
CREATE INDEX IF NOT EXISTS pending_projection_matches_by_offer
    ON pending_projection_matches (offer_id);

CREATE TABLE IF NOT EXISTS pending_time_ranges (
    owner BLOB NOT NULL,
    timeline TEXT NOT NULL,
    has_start INTEGER NOT NULL,
    start_exclusive INTEGER NOT NULL,
    end_inclusive INTEGER NOT NULL,
    PRIMARY KEY (owner, timeline, has_start, start_exclusive, end_inclusive)
);

CREATE TABLE IF NOT EXISTS intents (
    intent_id BLOB PRIMARY KEY NOT NULL,
    kind TEXT NOT NULL,
    intent_key BLOB NOT NULL,
    payload BLOB NOT NULL,
    replay INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS intent_context (
    intent_id BLOB NOT NULL,
    ordinal INTEGER NOT NULL,
    fact_id BLOB NOT NULL,
    PRIMARY KEY (intent_id, ordinal)
);
CREATE INDEX IF NOT EXISTS intent_context_by_fact
    ON intent_context (fact_id);

CREATE TEMP TABLE IF NOT EXISTS local_intents (
    intent_id BLOB PRIMARY KEY NOT NULL,
    kind TEXT NOT NULL,
    intent_key BLOB NOT NULL,
    payload BLOB NOT NULL,
    replay INTEGER NOT NULL DEFAULT 0
);

CREATE TEMP TABLE IF NOT EXISTS local_intent_context (
    intent_id BLOB NOT NULL,
    ordinal INTEGER NOT NULL,
    fact_id BLOB NOT NULL,
    PRIMARY KEY (intent_id, ordinal)
);
CREATE INDEX IF NOT EXISTS local_intent_context_by_fact
    ON local_intent_context (fact_id);

CREATE TEMP TABLE IF NOT EXISTS incoming_facts (
    id BLOB PRIMARY KEY NOT NULL,
    scope TEXT NOT NULL,
    scope_kind TEXT NOT NULL,
    scope_id BLOB NOT NULL,
    received_at INTEGER NOT NULL,
    staged_at INTEGER NOT NULL,
    bytes BLOB NOT NULL,
    origin_addr BLOB,
    origin_received_at INTEGER
);
CREATE INDEX IF NOT EXISTS incoming_facts_by_received_at
    ON incoming_facts (received_at, id);

CREATE TABLE IF NOT EXISTS projection_timings (
    fact_id BLOB PRIMARY KEY NOT NULL,
    fact_type INTEGER NOT NULL,
    source TEXT NOT NULL,
    received_at INTEGER NOT NULL,
    origin_received_at INTEGER,
    input_staged_at INTEGER,
    first_projected_at INTEGER NOT NULL,
    projected_at INTEGER NOT NULL,
    projection_count INTEGER NOT NULL,
    retained INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS projection_timings_by_projected_at
    ON projection_timings (projected_at, fact_id);
CREATE INDEX IF NOT EXISTS projection_timings_by_origin_received_at
    ON projection_timings (origin_received_at, fact_id);
CREATE INDEX IF NOT EXISTS projection_timings_by_fact_type_projected_at
    ON projection_timings (fact_type, projected_at, fact_id);

"#,
    storage_version: None,
    replay: ReplayTables {
        protected: CORE_REPLAY_PROTECTED_TABLES,
        reset: CORE_REPLAY_RESET_TABLES,
        summary: CORE_REPLAY_SUMMARY_TABLES,
    },
};
