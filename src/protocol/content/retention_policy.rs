//! Disappearing-message retention policy fact family.
//!
//! Retention policies define the TTL and monotonic floor applied to message
//! minutes in a workspace scope. Projection validates authority, supersession,
//! and floor tightening, publishes the active policy row, and offers
//! retention-floor context for messages in the workspace. Commands and queries
//! here keep the `disappearing-*` CLI surface while message projection consumes
//! the resulting policy and self-purges expired facts.

pub mod api;
pub mod author;
pub mod cli;
pub mod encode;
pub mod fact;
pub mod project;
#[cfg(not(verus_keep_ghost))]
pub mod proofs;
pub mod queries;

use crate::core::db::{TableInsert, TableName, TypedTableSchema, Value};

use encode::NO_PREVIOUS_POLICY_ID;
use fact::{PolicyId, RetentionPolicyFact};

pub const TYPE_RETENTION_POLICY: u8 = encode::TYPE_RETENTION_POLICY;

pub fn decode_fact_payload(bytes: &[u8]) -> Result<fact::RetentionPolicyFact, String> {
    project::decode::decode_fact(bytes)
}

/// Retention policy projection rows, keyed by
/// `workspace_id || scope_kind(1) || scope_id || policy_id` so display queries
/// can scan a workspace, narrow by scope kind, and resolve the latest policy.
pub const RETENTION_POLICY_ROWS: TableName = TableName::new("retention_policy_rows");

pub const RETENTION_POLICY_COLUMNS: &[&str] = &[
    "workspace_id",
    "scope_kind",
    "scope_id",
    "policy_id",
    "created_at_ms",
    "ttl_minutes",
    "retire_minute",
    "author_user_id",
    "supersedes_policy_id",
];
pub const RETENTION_POLICY_KEY_COLUMNS: &[&str] =
    &["workspace_id", "scope_kind", "scope_id", "policy_id"];
pub const RETENTION_POLICY_TABLE: TypedTableSchema = TypedTableSchema {
    table: RETENTION_POLICY_ROWS,
    columns: RETENTION_POLICY_COLUMNS,
    key_columns: RETENTION_POLICY_KEY_COLUMNS,
};

pub fn policy_row(policy_id: PolicyId, fact: &RetentionPolicyFact) -> TableInsert {
    RETENTION_POLICY_TABLE.insert(vec![
        Value::Bytes(fact.workspace_id.to_vec()),
        Value::U64(u64::from(fact.scope_kind)),
        Value::Bytes(fact.scope_id.to_vec()),
        Value::Bytes(policy_id.to_vec()),
        Value::U64(fact.created_at_ms),
        Value::U64(u64::from(fact.ttl_minutes)),
        Value::U64(fact.retire_minute),
        Value::Bytes(fact.author_user_id.to_vec()),
        Value::Bytes(
            fact.supersedes_policy_id
                .unwrap_or(NO_PREVIOUS_POLICY_ID)
                .to_vec(),
        ),
    ])
}
