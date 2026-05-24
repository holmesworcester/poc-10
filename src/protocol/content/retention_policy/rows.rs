//! Projection rows for the retention policy projector.
//!
//! Rows are keyed by `workspace_id || scope_kind(1) || scope_id || policy_id`
//! so display queries can scan all policies for a workspace, narrow by scope
//! kind, and resolve the latest policy per scope. The row value carries
//! everything a downstream message admit-check needs to enforce the
//! retention policy without resolving the underlying fact.

use crate::core::facts::FactId;
use crate::core::store::{TableName, TableRow};

use super::fact::{AuthorUserId, PolicyId, RetentionPolicyFact, WorkspaceId};
use super::layout::NO_PREVIOUS_POLICY_ID;

pub const RETENTION_POLICY_ROWS: TableName = TableName::new("retention_policy_rows");

pub const ROW_KEY_BYTES: usize = 32 + 1 + 32 + 32;
pub const ROW_VALUE_BYTES: usize = 8 + 4 + 8 + 32 + 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetentionPolicyRow {
    pub workspace_id: WorkspaceId,
    pub scope_kind: u8,
    pub scope_id: FactId,
    pub policy_id: PolicyId,
    pub created_at_ms: u64,
    pub ttl_minutes: u32,
    pub retire_minute: u64,
    pub author_user_id: AuthorUserId,
    pub supersedes_policy_id: Option<PolicyId>,
}

pub fn policy_key(
    workspace_id: &WorkspaceId,
    scope_kind: u8,
    scope_id: &FactId,
    policy_id: &PolicyId,
) -> Vec<u8> {
    let mut key = Vec::with_capacity(ROW_KEY_BYTES);
    key.extend_from_slice(workspace_id);
    key.push(scope_kind);
    key.extend_from_slice(scope_id);
    key.extend_from_slice(policy_id);
    key
}

pub fn policy_row(policy_id: PolicyId, fact: &RetentionPolicyFact) -> Result<TableRow, String> {
    let mut value = Vec::with_capacity(ROW_VALUE_BYTES);
    value.extend_from_slice(&fact.created_at_ms.to_be_bytes());
    value.extend_from_slice(&fact.ttl_minutes.to_be_bytes());
    value.extend_from_slice(&fact.retire_minute.to_be_bytes());
    value.extend_from_slice(&fact.author_user_id);
    value.extend_from_slice(&fact.supersedes_policy_id.unwrap_or(NO_PREVIOUS_POLICY_ID));
    if value.len() != ROW_VALUE_BYTES {
        return Err("retention policy row value has unexpected length".to_string());
    }
    Ok(TableRow {
        table: RETENTION_POLICY_ROWS,
        key: policy_key(
            &fact.workspace_id,
            fact.scope_kind,
            &fact.scope_id,
            &policy_id,
        ),
        value,
    })
}

pub fn decode_policy_row(key: &[u8], value: &[u8]) -> Result<RetentionPolicyRow, String> {
    if key.len() != ROW_KEY_BYTES {
        return Err("retention policy row key is malformed".to_string());
    }
    if value.len() != ROW_VALUE_BYTES {
        return Err("retention policy row value is malformed".to_string());
    }
    let mut workspace_id = [0; 32];
    workspace_id.copy_from_slice(&key[..32]);
    let scope_kind = key[32];
    let mut scope_id = [0; 32];
    scope_id.copy_from_slice(&key[33..65]);
    let mut policy_id = [0; 32];
    policy_id.copy_from_slice(&key[65..97]);

    let created_at_ms = u64::from_be_bytes(value[0..8].try_into().unwrap());
    let ttl_minutes = u32::from_be_bytes(value[8..12].try_into().unwrap());
    let retire_minute = u64::from_be_bytes(value[12..20].try_into().unwrap());
    let mut author_user_id = [0; 32];
    author_user_id.copy_from_slice(&value[20..52]);
    let mut supersedes_raw = [0; 32];
    supersedes_raw.copy_from_slice(&value[52..84]);
    let supersedes_policy_id = if supersedes_raw == NO_PREVIOUS_POLICY_ID {
        None
    } else {
        Some(supersedes_raw)
    };
    Ok(RetentionPolicyRow {
        workspace_id,
        scope_kind,
        scope_id,
        policy_id,
        created_at_ms,
        ttl_minutes,
        retire_minute,
        author_user_id,
        supersedes_policy_id,
    })
}

#[cfg(test)]
mod tests {
    use super::super::fact::SCOPE_KIND_WORKSPACE;
    use super::*;

    fn fact() -> RetentionPolicyFact {
        RetentionPolicyFact {
            workspace_id: [1; 32],
            supersedes_policy_id: Some([9; 32]),
            ttl_minutes: 60,
            retire_minute: 42,
            scope_kind: SCOPE_KIND_WORKSPACE,
            scope_id: [1; 32],
            author_user_id: [3; 32],
            signer_id: [4; 32],
            signer_public_key: [5; 32],
            created_at_ms: 6_000_000,
            signature: [0; crate::core::crypto::ED25519_SIGNATURE_BYTES],
        }
    }

    #[test]
    fn policy_row_round_trips_through_key_and_value() {
        let row = policy_row([5; 32], &fact()).expect("row");
        assert_eq!(row.key.len(), ROW_KEY_BYTES);
        assert_eq!(row.value.len(), ROW_VALUE_BYTES);
        let decoded = decode_policy_row(&row.key, &row.value).expect("decode");
        assert_eq!(decoded.workspace_id, [1; 32]);
        assert_eq!(decoded.scope_kind, SCOPE_KIND_WORKSPACE);
        assert_eq!(decoded.scope_id, [1; 32]);
        assert_eq!(decoded.policy_id, [5; 32]);
        assert_eq!(decoded.created_at_ms, 6_000_000);
        assert_eq!(decoded.ttl_minutes, 60);
        assert_eq!(decoded.retire_minute, 42);
        assert_eq!(decoded.author_user_id, [3; 32]);
        assert_eq!(decoded.supersedes_policy_id, Some([9; 32]));
    }

    #[test]
    fn none_supersedes_round_trips() {
        let mut f = fact();
        f.supersedes_policy_id = None;
        let row = policy_row([5; 32], &f).expect("row");
        let decoded = decode_policy_row(&row.key, &row.value).expect("decode");
        assert_eq!(decoded.supersedes_policy_id, None);
    }
}
