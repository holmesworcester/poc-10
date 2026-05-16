//! Read-only opened-message projections.

use crate::core::facts::FactId;
use crate::core::store::Store;

use super::rows;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenedMessage {
    pub message_id: FactId,
    pub created_at_ms: u64,
    pub author_user_id: FactId,
    pub signer_id: FactId,
    pub text: String,
}

pub fn opened_messages(store: &Store, workspace_id: FactId) -> Result<Vec<OpenedMessage>, String> {
    let mut messages = store
        .table_rows_with_key_prefix(rows::OPENED_MESSAGE_ROWS, &workspace_id, usize::MAX)
        .map_err(|err| format!("read opened message rows: {err}"))?
        .into_iter()
        .map(|(key, value)| {
            rows::decode_opened_message_row(&key, &value).map(|row| OpenedMessage {
                message_id: row.message_id,
                created_at_ms: row.created_at_ms,
                author_user_id: row.author_user_id,
                signer_id: row.signer_id,
                text: row.text,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    messages.sort_by(|left, right| {
        left.created_at_ms
            .cmp(&right.created_at_ms)
            .then_with(|| left.message_id.cmp(&right.message_id))
    });
    Ok(messages)
}

pub fn max_created_at_ms(store: &Store) -> Result<u64, String> {
    let mut max_timestamp = 0;
    for (key, value) in store
        .table_rows(rows::SEALED_MESSAGE_ROWS)
        .map_err(|err| format!("load sealed messages for clock: {err}"))?
    {
        if let Ok(row) = rows::decode_sealed_message_row(&key, &value) {
            max_timestamp = max_timestamp.max(row.created_at_ms);
        }
    }
    Ok(max_timestamp)
}
