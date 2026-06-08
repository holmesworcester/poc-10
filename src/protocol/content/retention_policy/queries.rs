//! Read-only views over retention policy rows.
//!
//! Multiple retention policy facts can exist for a scope, and newer facts
//! supersede older ones by id rather than by mutation. These helpers
//! reconstruct the active policy from projected rows so command code can apply
//! policy without re-decoding every historical fact. Keep supersession rules
//! here and row creation in the retention policy projector.

use std::collections::BTreeSet;

use crate::core::facts::FactId;
use crate::core::store::Store;

use super::encode::NO_PREVIOUS_POLICY_ID;
use super::fact::{AuthorUserId, PolicyId, WorkspaceId, SCOPE_KIND_WORKSPACE};
use super::{RETENTION_POLICY_ROWS, RETENTION_POLICY_ROW_SCHEMA};

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

pub fn decode_policy_row(key: &[u8], value: &[u8]) -> Result<RetentionPolicyRow, String> {
    let key_fields = RETENTION_POLICY_ROW_SCHEMA.decode_key(key)?;
    let value_fields = RETENTION_POLICY_ROW_SCHEMA.decode_value(value)?;
    let ttl_bytes = value_fields[1].as_bytes("ttl_minutes")?;
    let ttl_minutes = u32::from_be_bytes(
        ttl_bytes
            .try_into()
            .map_err(|_| "ttl_minutes must be 4 bytes".to_string())?,
    );
    let supersedes_raw = value_fields[4].as_bytes32("supersedes_policy_id")?;
    let supersedes_policy_id = (supersedes_raw != NO_PREVIOUS_POLICY_ID).then_some(supersedes_raw);
    Ok(RetentionPolicyRow {
        workspace_id: key_fields[0].as_bytes32("workspace_id")?,
        scope_kind: key_fields[1].as_u8("scope_kind")?,
        scope_id: key_fields[2].as_bytes32("scope_id")?,
        policy_id: key_fields[3].as_bytes32("policy_id")?,
        created_at_ms: value_fields[0].as_u64("created_at_ms")?,
        ttl_minutes,
        retire_minute: value_fields[2].as_u64("retire_minute")?,
        author_user_id: value_fields[3].as_bytes32("author_user_id")?,
        supersedes_policy_id,
    })
}

pub fn active_for_workspace(
    store: &Store,
    workspace_id: FactId,
) -> Result<Option<RetentionPolicyRow>, String> {
    active_for_scope(store, workspace_id, SCOPE_KIND_WORKSPACE, workspace_id)
}

pub fn active_for_scope(
    store: &Store,
    workspace_id: FactId,
    scope_kind: u8,
    scope_id: FactId,
) -> Result<Option<RetentionPolicyRow>, String> {
    let mut policies = policies_for_scope(store, workspace_id, scope_kind, scope_id)?;
    let superseded = policies
        .iter()
        .filter_map(|row| row.supersedes_policy_id)
        .collect::<BTreeSet<_>>();
    policies.retain(|row| !superseded.contains(&row.policy_id));
    policies.sort_by(|left, right| {
        left.created_at_ms
            .cmp(&right.created_at_ms)
            .then_with(|| left.policy_id.cmp(&right.policy_id))
    });
    Ok(policies.pop())
}

pub fn policies_for_scope(
    store: &Store,
    workspace_id: FactId,
    scope_kind: u8,
    scope_id: FactId,
) -> Result<Vec<RetentionPolicyRow>, String> {
    let mut prefix = Vec::with_capacity(65);
    prefix.extend_from_slice(&workspace_id);
    prefix.push(scope_kind);
    prefix.extend_from_slice(&scope_id);
    store
        .table_rows_with_key_prefix(RETENTION_POLICY_ROWS, &prefix, usize::MAX)
        .map_err(|err| format!("read retention policy rows: {err}"))?
        .into_iter()
        .map(|(key, value)| decode_policy_row(&key, &value))
        .collect()
}

#[cfg(test)]
mod tests {
    use crate::core::store::Store;
    use crate::protocol::registry::FACTS_SCHEMA_SOURCE;

    use super::super::fact::{RetentionPolicyFact, SCOPE_KIND_WORKSPACE};
    use super::super::policy_row;
    use super::*;

    #[test]
    fn active_policy_follows_supersedes_chain_over_created_at_order() {
        let store = Store::open_memory_with_schema_sources(&[FACTS_SCHEMA_SOURCE]).expect("store");
        let workspace_id = [1; 32];
        let old_id = [2; 32];
        let new_id = [3; 32];
        let old = policy(workspace_id, None, 60, 0, 9_000);
        let new = policy(workspace_id, Some(old_id), 5, 95, 100);

        store
            .insert_table_rows(vec![
                policy_row(old_id, &old).expect("old row"),
                policy_row(new_id, &new).expect("new row"),
            ])
            .expect("insert rows");

        let active = active_for_workspace(&store, workspace_id)
            .expect("active query")
            .expect("active row");
        assert_eq!(active.policy_id, new_id);
        assert_eq!(active.ttl_minutes, 5);
        assert_eq!(active.retire_minute, 95);
    }

    fn policy(
        workspace_id: [u8; 32],
        supersedes_policy_id: Option<[u8; 32]>,
        ttl_minutes: u32,
        retire_minute: u64,
        created_at_ms: u64,
    ) -> RetentionPolicyFact {
        RetentionPolicyFact {
            workspace_id,
            supersedes_policy_id,
            ttl_minutes,
            retire_minute,
            scope_kind: SCOPE_KIND_WORKSPACE,
            scope_id: workspace_id,
            author_user_id: [4; 32],
            signer_id: [5; 32],
            signer_public_key: [6; 32],
            created_at_ms,
        }
    }
}
