//! Schema for the workspace `disappearing_messages_setting` history.
//!
//! Each admitted setting event projects one row keyed by
//! `(workspace_id, created_at_ms_be, setting_event_id)`. The "active"
//! setting for a workspace is the row with the highest `created_at_ms`
//! (ties broken by event id), found via a single bounded prefix scan.
//!
//! Storing each setting as its own row makes projection
//! order-independent: a late-arriving older setting just appears as an
//! earlier row in the prefix scan and never overwrites a newer one.

use crate::core::store::{Schema, Store, TableName, TableRow};
use crate::protocol::event_modules::types::EventId;
use crate::protocol::wire::{Reader, Writer};

use super::types::ActiveSettingRow;

pub const SETTINGS: TableName = TableName::new("encryption.disappearing_messages_settings");

pub const SCHEMAS: &[Schema] = &[Schema::durable_row_table(
    "encryption.disappearing_messages_settings.v1",
    SETTINGS,
)];

const KEY_BYTES: usize = 32 + 8 + 32;
const VALUE_BYTES: usize = 4 + 8;

pub fn setting_row(
    workspace_id: EventId,
    setting_event_id: EventId,
    ttl_minutes: u32,
    effective_at_minute: u64,
    created_at_ms: u64,
) -> TableRow {
    let mut key = Vec::with_capacity(KEY_BYTES);
    key.extend_from_slice(&workspace_id);
    key.extend_from_slice(&created_at_ms.to_be_bytes());
    key.extend_from_slice(&setting_event_id);
    let mut value = Writer::with_capacity(VALUE_BYTES);
    value.u32(ttl_minutes as usize);
    value.u64(effective_at_minute);
    TableRow {
        table: SETTINGS,
        key,
        value: value.finish(),
    }
}

pub fn decode_active_setting_row(key: &[u8], value: &[u8]) -> Result<ActiveSettingRow, String> {
    if key.len() != KEY_BYTES {
        return Err("disappearing setting row key is malformed".to_string());
    }
    let mut workspace_id = [0; 32];
    workspace_id.copy_from_slice(&key[..32]);
    let mut created_at_be = [0; 8];
    created_at_be.copy_from_slice(&key[32..40]);
    let created_at_ms = u64::from_be_bytes(created_at_be);
    let mut setting_event_id = [0; 32];
    setting_event_id.copy_from_slice(&key[40..72]);
    let mut reader = Reader::new(value, "disappearing setting row");
    let ttl_minutes = reader.u32()?;
    let effective_at_minute = reader.u64()?;
    reader.finish()?;
    Ok(ActiveSettingRow {
        workspace_id,
        setting_event_id,
        ttl_minutes,
        effective_at_minute,
        created_at_ms,
    })
}

/// Return the active (latest by `(created_at_ms, event_id)`) setting for a
/// workspace, or `None` if no setting has been admitted yet.
pub fn active_for_workspace(
    store: &Store,
    workspace_id: EventId,
) -> Result<Option<ActiveSettingRow>, String> {
    let rows = store
        .table_rows_with_key_prefix(SETTINGS, &workspace_id, usize::MAX)
        .map_err(|err| format!("load disappearing settings: {err}"))?;
    let mut latest: Option<ActiveSettingRow> = None;
    for (key, value) in rows {
        let row = decode_active_setting_row(&key, &value)?;
        latest = match latest {
            None => Some(row),
            Some(prev) => Some(pick_later(prev, row)),
        };
    }
    Ok(latest)
}

fn pick_later(a: ActiveSettingRow, b: ActiveSettingRow) -> ActiveSettingRow {
    if (b.created_at_ms, b.setting_event_id) > (a.created_at_ms, a.setting_event_id) {
        b
    } else {
        a
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn active_returns_latest_under_lexicographic_tiebreak() {
        let store = Store::open_memory_with_schemas(SCHEMAS).expect("open store");
        let row_a = setting_row([1; 32], [2; 32], 5, 100, 6_000_000);
        let row_b = setting_row([1; 32], [9; 32], 7, 200, 12_000_000);
        let row_c = setting_row([1; 32], [3; 32], 3, 200, 12_000_000);
        store
            .insert_table_rows(vec![row_a, row_b, row_c])
            .expect("insert");
        let active = active_for_workspace(&store, [1; 32])
            .expect("active")
            .expect("active row exists");
        assert_eq!(active.ttl_minutes, 7);
        assert_eq!(active.setting_event_id, [9; 32]);
        assert_eq!(active.created_at_ms, 12_000_000);
    }

    #[test]
    fn active_returns_none_when_no_settings_admitted() {
        let store = Store::open_memory_with_schemas(SCHEMAS).expect("open store");
        assert!(active_for_workspace(&store, [1; 32])
            .expect("active")
            .is_none());
    }

    #[test]
    fn active_is_workspace_scoped() {
        let store = Store::open_memory_with_schemas(SCHEMAS).expect("open store");
        store
            .insert_table_rows(vec![setting_row([1; 32], [2; 32], 5, 100, 6_000_000)])
            .expect("insert");
        assert!(active_for_workspace(&store, [9; 32])
            .expect("active")
            .is_none());
    }
}
