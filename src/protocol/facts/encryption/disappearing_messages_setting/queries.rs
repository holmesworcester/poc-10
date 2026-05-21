//! Read-only views over disappearing-messages setting rows.

use std::collections::BTreeSet;

use crate::core::facts::FactId;
use crate::core::store::Store;

use super::fact::SCOPE_KIND_WORKSPACE;
use super::rows::{self, DisappearingMessagesSettingRow};

pub fn active_for_workspace(
    store: &Store,
    workspace_id: FactId,
) -> Result<Option<DisappearingMessagesSettingRow>, String> {
    active_for_scope(store, workspace_id, SCOPE_KIND_WORKSPACE, workspace_id)
}

pub fn active_for_scope(
    store: &Store,
    workspace_id: FactId,
    scope_kind: u8,
    scope_id: FactId,
) -> Result<Option<DisappearingMessagesSettingRow>, String> {
    let mut settings = settings_for_scope(store, workspace_id, scope_kind, scope_id)?;
    let superseded = settings
        .iter()
        .filter_map(|row| row.supersedes_setting_id)
        .collect::<BTreeSet<_>>();
    settings.retain(|row| !superseded.contains(&row.setting_id));
    settings.sort_by(|left, right| {
        left.created_at_ms
            .cmp(&right.created_at_ms)
            .then_with(|| left.setting_id.cmp(&right.setting_id))
    });
    Ok(settings.pop())
}

pub fn settings_for_scope(
    store: &Store,
    workspace_id: FactId,
    scope_kind: u8,
    scope_id: FactId,
) -> Result<Vec<DisappearingMessagesSettingRow>, String> {
    let mut prefix = Vec::with_capacity(65);
    prefix.extend_from_slice(&workspace_id);
    prefix.push(scope_kind);
    prefix.extend_from_slice(&scope_id);
    store
        .table_rows_with_key_prefix(
            rows::DISAPPEARING_MESSAGES_SETTING_ROWS,
            &prefix,
            usize::MAX,
        )
        .map_err(|err| format!("read disappearing setting rows: {err}"))?
        .into_iter()
        .map(|(key, value)| rows::decode_setting_row(&key, &value))
        .collect()
}

#[cfg(test)]
mod tests {
    use crate::core::store::Store;
    use crate::protocol::registry::FACTS_SCHEMA_SOURCE;

    use super::super::fact::{DisappearingMessagesSettingFact, SCOPE_KIND_WORKSPACE};
    use super::super::rows;
    use super::*;

    #[test]
    fn active_setting_follows_supersedes_chain_over_created_at_order() {
        let store = Store::open_memory_with_schema_sources(&[FACTS_SCHEMA_SOURCE]).expect("store");
        let workspace_id = [1; 32];
        let old_id = [2; 32];
        let new_id = [3; 32];
        let old = setting(workspace_id, None, 60, 0, 9_000);
        let new = setting(workspace_id, Some(old_id), 5, 95, 100);

        store
            .insert_table_rows(vec![
                rows::setting_row(old_id, &old).expect("old row"),
                rows::setting_row(new_id, &new).expect("new row"),
            ])
            .expect("insert rows");

        let active = active_for_workspace(&store, workspace_id)
            .expect("active query")
            .expect("active row");
        assert_eq!(active.setting_id, new_id);
        assert_eq!(active.ttl_minutes, 5);
        assert_eq!(active.retire_minute, 95);
    }

    fn setting(
        workspace_id: [u8; 32],
        supersedes_setting_id: Option<[u8; 32]>,
        ttl_minutes: u32,
        retire_minute: u64,
        created_at_ms: u64,
    ) -> DisappearingMessagesSettingFact {
        DisappearingMessagesSettingFact {
            workspace_id,
            supersedes_setting_id,
            ttl_minutes,
            retire_minute,
            scope_kind: SCOPE_KIND_WORKSPACE,
            scope_id: workspace_id,
            author_user_id: [4; 32],
            created_at_ms,
        }
    }
}
