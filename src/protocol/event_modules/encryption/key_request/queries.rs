//! Read-only views for projected key requests.

use crate::core::store::Store;

use super::schema::{decode_pending_key_request_row, PENDING_KEY_REQUESTS};
use super::types::PendingKeyRequestRow;

pub fn list_pending(store: &Store, limit: usize) -> Result<Vec<PendingKeyRequestRow>, String> {
    store
        .table_rows_with_key_prefix(PENDING_KEY_REQUESTS, &[], limit)
        .map_err(|err| format!("load pending key requests: {err}"))?
        .into_iter()
        .map(|(key, value)| decode_pending_key_request_row(key, &value))
        .collect()
}
