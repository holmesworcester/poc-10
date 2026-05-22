//! Core-owned schema declarations.
//!
//! This file is the durable and memory table inventory for the generic
//! runtime: facts, local admissions, standing context, time wakes, pending
//! projection, intent queues, and the store-local clock. It exposes one
//! executable `SchemaSource` plus typed `TableName` constants so the rest of
//! core does not repeat string literals.
//!
//! These tables are the shared substrate behind the pipeline documentation.
//! `facts` and `local_fact_admissions` store immutable inputs and their local
//! visibility metadata. `context_edges`, `time_wakes`, and `pending_projection`
//! drive fact projection. `intents` and `local_intents` drive handler dispatch.
//! The clock table is store-local runtime state used by command hosts, not a
//! protocol fact.
//!
//! Core schema is deliberately small and mechanical. It records the runtime
//! queues and indexes needed to move work; it does not encode protocol policy
//! such as what makes a message valid, which key can decrypt content, or which
//! sync range should be requested. That policy belongs beside the fact, query,
//! matcher, and projector modules that understand it.
//!
//! Add a table here when the table is part of core's runtime mechanics. Add it
//! in a protocol module when it stores protocol meaning, even if core commits
//! the row mutation.

use crate::core::store::{SchemaSource, TableName};

/// The core SQLite schema source applied to every runtime store.
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

CREATE TABLE IF NOT EXISTS context_edges (
    owner BLOB NOT NULL,
    direction TEXT NOT NULL,
    role TEXT NOT NULL,
    scope_key BLOB NOT NULL,
    selector BLOB NOT NULL,
    PRIMARY KEY (owner, direction, role, scope_key, selector)
);
CREATE INDEX IF NOT EXISTS context_edges_by_match
    ON context_edges (direction, role, scope_key, selector);
CREATE INDEX IF NOT EXISTS context_edges_by_owner
    ON context_edges (owner);

CREATE TABLE IF NOT EXISTS time_wakes (
    timeline TEXT NOT NULL,
    at INTEGER NOT NULL,
    owner BLOB NOT NULL,
    PRIMARY KEY (timeline, at, owner)
);
CREATE INDEX IF NOT EXISTS time_wakes_by_owner
    ON time_wakes (owner);

CREATE TABLE IF NOT EXISTS pending_projection (
    owner BLOB PRIMARY KEY NOT NULL
);

CREATE TABLE IF NOT EXISTS pending_time_ranges (
    owner BLOB NOT NULL,
    timeline TEXT NOT NULL,
    has_start INTEGER NOT NULL,
    start_exclusive INTEGER NOT NULL,
    end_inclusive INTEGER NOT NULL,
    PRIMARY KEY (owner, timeline, has_start, start_exclusive, end_inclusive)
);

CREATE TABLE IF NOT EXISTS intents (
    kind TEXT NOT NULL,
    idempotence_key BLOB NOT NULL,
    payload BLOB NOT NULL,
    PRIMARY KEY (kind, idempotence_key)
);

CREATE TEMP TABLE IF NOT EXISTS local_intents (
    kind TEXT NOT NULL,
    idempotence_key BLOB NOT NULL,
    payload BLOB NOT NULL,
    PRIMARY KEY (kind, idempotence_key)
);

CREATE TABLE IF NOT EXISTS clock (
    key TEXT PRIMARY KEY NOT NULL,
    timestamp INTEGER NOT NULL
);
"#,
    row_tables: &[],
};

/// Local admission metadata table for content-addressed fact bytes.
pub(crate) const LOCAL_FACT_ADMISSIONS: TableName = TableName::new("local_fact_admissions");
/// Standing context edge table.
pub(crate) const CONTEXT_EDGES: TableName = TableName::new("context_edges");
/// Standing time wake table.
pub(crate) const TIME_WAKES: TableName = TableName::new("time_wakes");
/// Pending projection queue table.
pub(crate) const PENDING_PROJECTION: TableName = TableName::new("pending_projection");
/// Transient due-time context table.
pub(crate) const PENDING_TIME_RANGES: TableName = TableName::new("pending_time_ranges");
/// Durable intent queue table.
pub(crate) const INTENTS: TableName = TableName::new("intents");
/// Ephemeral intent queue table.
pub(crate) const LOCAL_INTENTS: TableName = TableName::new("local_intents");
