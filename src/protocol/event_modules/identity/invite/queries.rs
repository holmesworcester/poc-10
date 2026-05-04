//! Read-only invite authorization view.
//!
//! Connection workers use this module to answer exactly one question: does this
//! bootstrap hash correspond to a locally stored invite secret? The secret value
//! itself stays inside the invite module.

use crate::core::store::Store;

use super::schema;

pub fn bootstrap_hash_is_authorized(
    store: &Store,
    bootstrap_hash: &[u8; 32],
) -> Result<bool, String> {
    store
        .table_row(schema::INVITE_SECRETS, bootstrap_hash)
        .map(|row| row.is_some())
        .map_err(|err| format!("load invite secret: {err}"))
}
