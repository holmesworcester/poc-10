//! Core-owned schema declarations.

use crate::core::store::{SchemaSource, TableName};

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

pub(crate) const PENDING_PROJECTION: TableName = TableName::new("pending_projection");
pub(crate) const INTENTS: TableName = TableName::new("intents");
pub(crate) const LOCAL_INTENTS: TableName = TableName::new("local_intents");
