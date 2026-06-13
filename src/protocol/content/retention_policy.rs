//! Disappearing-message retention policy fact family.
//!
//! Retention policies define the TTL and monotonic floor applied to message
//! minutes in a workspace scope. Projection validates authority, supersession,
//! and floor tightening, publishes the active policy row, and offers
//! retention-floor context for messages in the workspace. Commands and queries
//! here keep the `disappearing-*` CLI surface while message projection consumes
//! the resulting policy and self-purges expired facts.

pub mod author;
pub mod cli;
pub mod commands;
pub mod encode;
pub mod fact;
pub mod project;
pub mod queries;

use crate::core::facts::FactId;
use crate::core::row_schema::{RowField, RowTableSchema, RowValue};
use crate::core::store::{TableName, TableRow};

use encode::NO_PREVIOUS_POLICY_ID;
use fact::{PolicyId, RetentionPolicyFact, WorkspaceId};

pub const TYPE_RETENTION_POLICY: u8 = encode::TYPE_RETENTION_POLICY;

pub fn decode_fact_payload(bytes: &[u8]) -> Result<fact::RetentionPolicyFact, String> {
    project::decode::decode_fact(bytes)
}

/// Retention policy projection rows, keyed by
/// `workspace_id || scope_kind(1) || scope_id || policy_id` so display queries
/// can scan a workspace, narrow by scope kind, and resolve the latest policy.
pub const RETENTION_POLICY_ROWS: TableName = TableName::new("retention_policy_rows");

const RETENTION_POLICY_ROW_KEY_FIELDS: &[RowField] = &[
    RowField::bytes32("workspace_id"),
    RowField::u8("scope_kind"),
    RowField::bytes32("scope_id"),
    RowField::bytes32("policy_id"),
];
const RETENTION_POLICY_ROW_VALUE_FIELDS: &[RowField] = &[
    RowField::u64be("created_at_ms"),
    RowField::bytes("ttl_minutes", 4),
    RowField::u64be("retire_minute"),
    RowField::bytes32("author_user_id"),
    RowField::bytes32("supersedes_policy_id"),
];

pub const RETENTION_POLICY_ROW_SCHEMA: RowTableSchema = RowTableSchema::new(
    RETENTION_POLICY_ROWS,
    RETENTION_POLICY_ROW_KEY_FIELDS,
    RETENTION_POLICY_ROW_VALUE_FIELDS,
);

pub fn policy_key(
    workspace_id: &WorkspaceId,
    scope_kind: u8,
    scope_id: &FactId,
    policy_id: &PolicyId,
) -> Vec<u8> {
    RETENTION_POLICY_ROW_SCHEMA
        .encode_key(&[
            RowValue::Bytes(workspace_id.to_vec()),
            RowValue::U8(scope_kind),
            RowValue::Bytes(scope_id.to_vec()),
            RowValue::Bytes(policy_id.to_vec()),
        ])
        .expect("retention policy row key")
}

pub fn policy_row(policy_id: PolicyId, fact: &RetentionPolicyFact) -> Result<TableRow, String> {
    RETENTION_POLICY_ROW_SCHEMA.row(
        &[
            RowValue::Bytes(fact.workspace_id.to_vec()),
            RowValue::U8(fact.scope_kind),
            RowValue::Bytes(fact.scope_id.to_vec()),
            RowValue::Bytes(policy_id.to_vec()),
        ],
        &[
            RowValue::U64(fact.created_at_ms),
            RowValue::Bytes(fact.ttl_minutes.to_be_bytes().to_vec()),
            RowValue::U64(fact.retire_minute),
            RowValue::Bytes(fact.author_user_id.to_vec()),
            RowValue::Bytes(
                fact.supersedes_policy_id
                    .unwrap_or(NO_PREVIOUS_POLICY_ID)
                    .to_vec(),
            ),
        ],
    )
}
