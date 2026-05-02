use crate::store::Store;

use super::tables;

pub fn bootstrap_hash_is_authorized(
    store: &Store,
    bootstrap_hash: &[u8; 32],
) -> Result<bool, String> {
    store
        .table_row(tables::INVITE_SECRETS, bootstrap_hash)
        .map(|row| row.is_some())
        .map_err(|err| format!("load invite secret: {err}"))
}
