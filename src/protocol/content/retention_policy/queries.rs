//! Read-only views over retention policy rows.
//!
//! Multiple retention policy facts can exist for a scope, and newer facts
//! supersede older ones by id rather than by mutation. These helpers
//! reconstruct the active policy from projected rows so command code can apply
//! policy without re-decoding every historical fact. Keep supersession rules
//! here and row creation in the retention policy projector.

use crate::core::facts::FactId;
use crate::core::store::{Store, DEFAULT_QUERY_LIMIT};
use crate::protocol::content;
use rusqlite::{params, Row};
use std::collections::BTreeSet;

use super::encode::NO_PREVIOUS_POLICY_ID;
use super::fact::{AuthorUserId, PolicyId, WorkspaceId, SCOPE_KIND_WORKSPACE};

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StatusReport {
    pub workspace_id: FactId,
    pub policy_fact_id: Option<FactId>,
    pub ttl_minutes: Option<u32>,
    pub policy_floor_minute: u64,
    pub last_chopped_floor: Option<u64>,
    pub now_minute: Option<u64>,
    pub horizon_floor: u64,
    pub effective_floor: u64,
    pub live_messages: usize,
    pub message_tombstones: usize,
}

pub fn decode_policy_row(row: &Row<'_>) -> rusqlite::Result<RetentionPolicyRow> {
    let supersedes_raw = row.get(8)?;
    let supersedes_policy_id = (supersedes_raw != NO_PREVIOUS_POLICY_ID).then_some(supersedes_raw);
    Ok(RetentionPolicyRow {
        workspace_id: row.get(0)?,
        scope_kind: row.get::<_, i64>(1)? as u8,
        scope_id: row.get(2)?,
        policy_id: row.get(3)?,
        created_at_ms: row.get::<_, i64>(4)? as u64,
        ttl_minutes: row.get::<_, i64>(5)? as u32,
        retire_minute: row.get::<_, i64>(6)? as u64,
        author_user_id: row.get(7)?,
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
    let mut stmt = store
        .conn()
        .prepare(
            "SELECT workspace_id,
                    scope_kind,
                    scope_id,
                    policy_id,
                    created_at_ms,
                    ttl_minutes,
                    retire_minute,
                    author_user_id,
                    supersedes_policy_id
             FROM retention_policy_rows
             WHERE workspace_id = ?1
               AND scope_kind = ?2
               AND scope_id = ?3
             ORDER BY policy_id
             LIMIT ?4",
        )
        .map_err(|err| format!("read retention policy rows: {err}"))?;
    let rows = stmt
        .query_map(
            params![
                workspace_id,
                i64::from(scope_kind),
                scope_id,
                DEFAULT_QUERY_LIMIT as i64
            ],
            decode_policy_row,
        )
        .map_err(|err| format!("read retention policy rows: {err}"))?;
    rows.collect::<rusqlite::Result<Vec<_>>>()
        .map_err(|err| format!("decode retention policy rows: {err}"))
}

pub fn count_messages_below_minute(
    store: &Store,
    workspace_id: FactId,
    floor_minute: u64,
) -> Result<usize, String> {
    let mut message_ids = BTreeSet::new();

    for row in content::message::queries::content_message_rows(store, workspace_id)? {
        if row.minute < floor_minute {
            message_ids.insert(row.message_id);
        }
    }
    for message_id in
        content::message::queries::message_tombstone_ids_below(store, workspace_id, floor_minute)?
    {
        message_ids.insert(message_id);
    }

    Ok(message_ids.len())
}

pub fn status_report(
    store: &Store,
    workspace_id: FactId,
    now_ms: Option<u64>,
) -> Result<StatusReport, String> {
    let active = active_for_workspace(store, workspace_id)?;
    let policy_fact_id = active.as_ref().map(|row| row.policy_id);
    let ttl_minutes = active.as_ref().map(|row| row.ttl_minutes);
    let policy_floor_minute = active.as_ref().map(|row| row.retire_minute).unwrap_or(0);
    let now_minute = now_ms.map(|ms| ms / content::message::fact::UNIX_MINUTE_MS);
    let horizon_floor = now_minute
        .map(|minute| minute.saturating_sub(30 * 24 * 60))
        .unwrap_or(0);
    let effective_floor = policy_floor_minute.max(horizon_floor);
    let message_tombstones = content::message::queries::message_tombstone_count_at_or_after(
        store,
        workspace_id,
        horizon_floor,
    )?;
    let live_messages = content::message::queries::content_message_rows(store, workspace_id)?
        .into_iter()
        .filter(|row| row.minute >= horizon_floor)
        .count();
    let last_chopped_floor =
        (horizon_floor > policy_floor_minute && horizon_floor > 0).then_some(horizon_floor);

    Ok(StatusReport {
        workspace_id,
        policy_fact_id,
        ttl_minutes,
        policy_floor_minute,
        last_chopped_floor,
        now_minute,
        horizon_floor,
        effective_floor,
        live_messages,
        message_tombstones,
    })
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
            .write_transaction(|tx| {
                tx.insert_values_in_tx(&policy_row(old_id, &old))?;
                tx.insert_values_in_tx(&policy_row(new_id, &new))?;
                Ok(())
            })
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
