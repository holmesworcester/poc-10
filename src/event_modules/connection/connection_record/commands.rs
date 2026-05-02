use crate::store::Store;

use super::projector::Projection;

pub fn apply(store: &Store, projection: Projection) -> Result<(), String> {
    store
        .insert_table_rows(projection.rows)
        .map(|_| ())
        .map_err(|err| format!("apply connection projection: {err}"))
}
