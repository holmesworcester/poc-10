//! Read-only semantic content-message projections.

use crate::core::store::Store;

use super::rows;

pub fn max_created_at_ms(store: &Store) -> Result<u64, String> {
    let mut max_timestamp = 0;
    for (key, value) in store
        .table_rows(rows::CONTENT_MESSAGE_ROWS)
        .map_err(|err| format!("load content messages for clock: {err}"))?
    {
        if let Ok(row) = rows::decode_content_message_row(&key, &value) {
            max_timestamp = max_timestamp.max(row.created_at_ms);
        }
    }
    Ok(max_timestamp)
}
