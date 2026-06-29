//! Active-workspace selection fact family.
//!
//! The active workspace is local-only operational state: which workspace the
//! commands on this store default to when the user omits a `WORKSPACE_ID_HEX`
//! argument. It is closer to a frontend toggle than to shared protocol state,
//! but persisting it as a local-only fact lets the selection survive a restart
//! and reuses the projection/read-model machinery every other command already
//! reads from. Projection records one row per selection fact;
//! `queries::current_active_workspace` reads the latest. No global/durable state
//! and no network sync are involved.

pub mod author;
pub mod cli;
pub mod encode;
pub mod fact;
pub mod project;
pub mod queries;

use crate::core::db::{TableInsert, TableName, TypedTableSchema, Value};
use crate::core::facts::FactId;

pub const TYPE_ACTIVE_WORKSPACE: u8 = encode::TYPE_ACTIVE_WORKSPACE;

/// Projected active-workspace selections keyed by selection fact id. Queries
/// resolve the active row with `(effective_at_ms, setting_fact_id)` ordering.
pub const ACTIVE_WORKSPACE_ROWS: TableName = TableName::new("active_workspace_rows");

pub const ACTIVE_WORKSPACE_COLUMNS: &[&str] =
    &["setting_fact_id", "workspace_id", "effective_at_ms"];
pub const ACTIVE_WORKSPACE_KEY_COLUMNS: &[&str] = &["setting_fact_id"];
pub const ACTIVE_WORKSPACE_TABLE: TypedTableSchema = TypedTableSchema {
    table: ACTIVE_WORKSPACE_ROWS,
    columns: ACTIVE_WORKSPACE_COLUMNS,
    key_columns: ACTIVE_WORKSPACE_KEY_COLUMNS,
};

pub(crate) fn active_workspace_insert(
    setting_fact_id: FactId,
    fact: &fact::ActiveWorkspaceFact,
) -> TableInsert {
    ACTIVE_WORKSPACE_TABLE.insert(vec![
        Value::Bytes(setting_fact_id.to_vec()),
        Value::Bytes(fact.workspace_id.to_vec()),
        Value::U64(fact.effective_at_ms),
    ])
}
