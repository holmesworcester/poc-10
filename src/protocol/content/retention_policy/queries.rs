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

use super::fact::SCOPE_KIND_WORKSPACE;
use super::rows::{self, RetentionPolicyRow};

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
        .table_rows_with_key_prefix(rows::RETENTION_POLICY_ROWS, &prefix, usize::MAX)
        .map_err(|err| format!("read retention policy rows: {err}"))?
        .into_iter()
        .map(|(key, value)| rows::decode_policy_row(&key, &value))
        .collect()
}

#[cfg(test)]
mod tests {
    use crate::core::crypto::ED25519_SIGNATURE_BYTES;
    use crate::core::store::Store;
    use crate::protocol::registry::FACTS_SCHEMA_SOURCE;

    use super::super::fact::{RetentionPolicyFact, SCOPE_KIND_WORKSPACE};
    use super::super::rows;
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
                rows::policy_row(old_id, &old).expect("old row"),
                rows::policy_row(new_id, &new).expect("new row"),
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
            signature: [7; ED25519_SIGNATURE_BYTES],
        }
    }
}
