//! Read-only queries over projected workspace users.
//!
//! User rows are admitted only after auth projection validates the
//! surrounding invite or authority chain. These helpers return the current
//! visible membership in deterministic display order for CLI and command code.
//! They should not infer authority from raw facts.

use crate::core::facts::FactId;
use crate::core::store::Store;

use super::rows::{decode_user_row, UserRow, USER_ROWS};

pub fn users_in_workspace(store: &Store, workspace_id: FactId) -> Result<Vec<UserRow>, String> {
    let mut rows = store
        .table_rows_with_key_prefix(USER_ROWS, &workspace_id, usize::MAX)
        .map_err(|err| format!("load users: {err}"))?
        .into_iter()
        .map(|(key, value)| decode_user_row(&key, &value))
        .collect::<Result<Vec<_>, _>>()?;
    rows.sort_by(|left, right| {
        left.username
            .cmp(&right.username)
            .then_with(|| left.user_id.cmp(&right.user_id))
    });
    Ok(rows)
}
