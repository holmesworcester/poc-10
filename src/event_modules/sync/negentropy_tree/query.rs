//! Read-side helpers for the projected negentropy tree state.
//!
//! `node_fingerprint(workspace_id, node_id) -> [u8; 32]` returns the
//! per-node fingerprint `F_v` that compare events carry on the wire. It is
//! defined as the XOR of `root_hash` and `dep_hash` recorded in
//! `negentropy_node_hash` (plan.md lines 332-345).
//!
//! Missing rows are treated as all-zeros; an empty `(R_v, X_v∩P)` is
//! exactly the all-zeros fingerprint by definition.

use rusqlite::{params, Connection};

use super::state::xor_into;
use crate::runtime::control_loop::work_item::WorkspaceId;

/// Combine `root_hash` ⊕ `dep_hash` for `(workspace, node)` into the
/// per-node fingerprint `F_v`. Returns all-zeros if no row is recorded yet.
pub fn node_fingerprint(
    db: &Connection,
    workspace_id: &WorkspaceId,
    node_id: &[u8],
) -> rusqlite::Result<[u8; 32]> {
    let mut stmt = db.prepare(
        "SELECT root_hash, dep_hash FROM negentropy_node_hash
         WHERE workspace_id = ?1 AND node_id = ?2",
    )?;
    let mut rows = stmt.query(params![workspace_id.to_vec(), node_id.to_vec()])?;

    if let Some(row) = rows.next()? {
        let rh: Vec<u8> = row.get(0)?;
        let dh: Vec<u8> = row.get(1)?;
        let mut acc = [0u8; 32];
        if rh.len() == 32 {
            let mut a = [0u8; 32];
            a.copy_from_slice(&rh);
            xor_into(&mut acc, &a);
        }
        if dh.len() == 32 {
            let mut a = [0u8; 32];
            a.copy_from_slice(&dh);
            xor_into(&mut acc, &a);
        }
        Ok(acc)
    } else {
        Ok([0u8; 32])
    }
}
