//! Read-only content-file projection queries.

use crate::core::facts::FactId;
use crate::core::store::Store;

use super::rows::{self, ContentFileRow};

pub fn content_file_rows(
    store: &Store,
    workspace_id: FactId,
) -> Result<Vec<ContentFileRow>, String> {
    let mut rows = store
        .table_rows_with_key_prefix(rows::FILE_ROWS, &workspace_id, usize::MAX)
        .map_err(|err| format!("load file rows: {err}"))?
        .into_iter()
        .map(|(key, value)| rows::decode_content_file_row(&key, &value))
        .collect::<Result<Vec<_>, _>>()?;
    rows.sort_by_key(|row| (row.created_at_ms, row.file_fact_id));
    Ok(rows)
}
