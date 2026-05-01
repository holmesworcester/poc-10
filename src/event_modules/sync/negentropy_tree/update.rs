//! Incremental maintenance for the projected negentropy tree.
//!
//! Per `plan.md` lines 343-364: this is the on-insert maintenance routine.
//! We expose two entry points:
//!
//! - `on_root_inserted(workspace_id, root_event_id, deps, node_path, db)` —
//!   walks the supplied path L→root, adding the root to each node's
//!   `R_v`, and for each dep `d ∈ D(r)` walks the same path adding `d` as
//!   an external requirement at every node where `d` is not itself a root.
//! - `on_event_present(workspace_id, event_id, db)` — when an event becomes
//!   locally present, update `dep_hash` for every node whose
//!   `negentropy_dep_refcount.dep_event_id = event_id` row was previously
//!   marked absent.
//!
//! Refcount semantics: a dep contributes to `dep_hash` only when the
//! refcount transitions `0 -> 1` and the dep is present locally; it is
//! removed only when refcount transitions `1 -> 0` and was contributing.
//! This stops duplicate edges from double-counting or XOR-cancelling
//! (plan.md lines 354-358).
//!
//! Stop-rule: when walking the path for a dep `d`, stop at the first node
//! where `d` is itself a root (`R_v`); the dep is satisfied internally
//! there and at every ancestor (plan.md line 366).
//!
//! `node_path` is supplied by the caller so this module stays decoupled
//! from any specific range-tree shape. The simplest realistic caller is
//! one that derives the path from the event-id sort key plus a fixed
//! branching factor; that wiring belongs in a follow-up phase.

use rusqlite::{params, Connection};

use super::schema;
use super::state::{h_dep, h_root, xor_into};
use crate::runtime::control_loop::work_item::{BlakeId, WorkspaceId};

/// Read the current root_hash + dep_hash row for `(workspace, node)`,
/// defaulting to all-zeros if missing. Returns the row presence flag too so
/// callers can choose insert-vs-update.
fn read_node_hash(
    db: &Connection,
    workspace_id: &WorkspaceId,
    node_id: &[u8],
) -> rusqlite::Result<([u8; 32], [u8; 32], bool)> {
    let mut stmt = db.prepare(
        "SELECT root_hash, dep_hash FROM negentropy_node_hash
         WHERE workspace_id = ?1 AND node_id = ?2",
    )?;
    let mut rows = stmt.query(params![workspace_id.to_vec(), node_id.to_vec()])?;
    if let Some(row) = rows.next()? {
        let rh: Vec<u8> = row.get(0)?;
        let dh: Vec<u8> = row.get(1)?;
        let mut root_hash = [0u8; 32];
        let mut dep_hash = [0u8; 32];
        if rh.len() == 32 {
            root_hash.copy_from_slice(&rh);
        }
        if dh.len() == 32 {
            dep_hash.copy_from_slice(&dh);
        }
        Ok((root_hash, dep_hash, true))
    } else {
        Ok(([0u8; 32], [0u8; 32], false))
    }
}

fn write_node_hash(
    db: &Connection,
    workspace_id: &WorkspaceId,
    node_id: &[u8],
    root_hash: &[u8; 32],
    dep_hash: &[u8; 32],
    present: bool,
) -> rusqlite::Result<()> {
    if present {
        db.execute(
            "UPDATE negentropy_node_hash
             SET root_hash = ?3, dep_hash = ?4
             WHERE workspace_id = ?1 AND node_id = ?2",
            params![
                workspace_id.to_vec(),
                node_id.to_vec(),
                root_hash.to_vec(),
                dep_hash.to_vec(),
            ],
        )?;
    } else {
        db.execute(
            "INSERT INTO negentropy_node_hash (workspace_id, node_id, root_hash, dep_hash)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                workspace_id.to_vec(),
                node_id.to_vec(),
                root_hash.to_vec(),
                dep_hash.to_vec(),
            ],
        )?;
    }
    Ok(())
}

/// `true` iff `(workspace, node, event_id)` is in `negentropy_root_membership`.
fn is_root_at(
    db: &Connection,
    workspace_id: &WorkspaceId,
    node_id: &[u8],
    event_id: &BlakeId,
) -> rusqlite::Result<bool> {
    let count: i64 = db.query_row(
        "SELECT COUNT(*) FROM negentropy_root_membership
         WHERE workspace_id = ?1 AND node_id = ?2 AND event_id = ?3",
        params![workspace_id.to_vec(), node_id.to_vec(), event_id.to_vec()],
        |r| r.get(0),
    )?;
    Ok(count > 0)
}

/// Add `event_id` to the root membership of `(workspace, node)`, updating
/// `root_hash` only on the 0→1 transition. Returns true if a transition
/// happened.
fn add_root_membership(
    db: &Connection,
    workspace_id: &WorkspaceId,
    node_id: &[u8],
    event_id: &BlakeId,
) -> rusqlite::Result<bool> {
    let inserted = db.execute(
        "INSERT OR IGNORE INTO negentropy_root_membership
            (workspace_id, node_id, event_id)
         VALUES (?1, ?2, ?3)",
        params![workspace_id.to_vec(), node_id.to_vec(), event_id.to_vec()],
    )?;
    if inserted == 0 {
        return Ok(false);
    }

    let (mut root_hash, dep_hash, present) =
        read_node_hash(db, workspace_id, node_id)?;
    xor_into(&mut root_hash, &h_root(event_id));
    write_node_hash(db, workspace_id, node_id, &root_hash, &dep_hash, present)?;
    Ok(true)
}

/// Increment the refcount for `(workspace, node, dep_event_id)`, creating
/// the row if absent. Returns the previous refcount and the row's
/// `present_locally` flag (post-mutation; we do not change it here).
fn add_dep_requirement(
    db: &Connection,
    workspace_id: &WorkspaceId,
    node_id: &[u8],
    dep_event_id: &BlakeId,
    present_locally: bool,
) -> rusqlite::Result<(i64, bool)> {
    let row: Option<(i64, i64)> = db
        .query_row(
            "SELECT refcount, present_locally FROM negentropy_dep_refcount
             WHERE workspace_id = ?1 AND node_id = ?2 AND dep_event_id = ?3",
            params![
                workspace_id.to_vec(),
                node_id.to_vec(),
                dep_event_id.to_vec(),
            ],
            |r| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?)),
        )
        .ok();

    match row {
        None => {
            db.execute(
                "INSERT INTO negentropy_dep_refcount
                    (workspace_id, node_id, dep_event_id, refcount, present_locally)
                 VALUES (?1, ?2, ?3, 1, ?4)",
                params![
                    workspace_id.to_vec(),
                    node_id.to_vec(),
                    dep_event_id.to_vec(),
                    if present_locally { 1i64 } else { 0i64 },
                ],
            )?;
            Ok((0, present_locally))
        }
        Some((rc, pres)) => {
            db.execute(
                "UPDATE negentropy_dep_refcount
                 SET refcount = refcount + 1
                 WHERE workspace_id = ?1 AND node_id = ?2 AND dep_event_id = ?3",
                params![
                    workspace_id.to_vec(),
                    node_id.to_vec(),
                    dep_event_id.to_vec(),
                ],
            )?;
            Ok((rc, pres != 0))
        }
    }
}

/// Quick-check: is `event_id` locally known? Looks at the canonical `events`
/// table if present (best-effort). Returns false if the table doesn't exist
/// — in tests we'll set `present_locally` explicitly via `on_event_present`.
fn local_has_event(db: &Connection, event_id: &BlakeId) -> rusqlite::Result<bool> {
    // Check via root membership in any node — i.e., is it a known event in
    // this workspace's negentropy state at all? This is a stand-in for the
    // canonical `events` table check, which doesn't exist in the
    // scaffolding-only tests for this module.
    let count: i64 = db
        .query_row(
            "SELECT COUNT(*) FROM negentropy_root_membership WHERE event_id = ?1",
            params![event_id.to_vec()],
            |r| r.get(0),
        )
        .unwrap_or(0);
    Ok(count > 0)
}

/// On root insert at leaf `L`: add `r` to root membership on the path
/// L → root, and for every dep `d ∈ D(r)` walk the same path adding `d` as
/// a requirement, stopping at the first node where `d` is itself a root.
///
/// `node_path` should be ordered leaf-first, root-last (or whatever
/// convention the caller picks — we just walk it in supplied order).
pub fn on_root_inserted(
    workspace_id: &WorkspaceId,
    root_event_id: &BlakeId,
    deps: &[BlakeId],
    node_path: &[Vec<u8>],
    db: &Connection,
) -> rusqlite::Result<()> {
    schema::ensure_schema(db)?;

    // 1. Add r to root membership on path L → root.
    for node in node_path {
        add_root_membership(db, workspace_id, node, root_event_id)?;
    }

    // 2. For each d in D(r), walk path adding requirements; stop at the
    //    first node where d is itself a root.
    for d in deps {
        let dep_present = local_has_event(db, d)?;
        for node in node_path {
            if is_root_at(db, workspace_id, node, d)? {
                break;
            }
            let (prev_rc, was_present) =
                add_dep_requirement(db, workspace_id, node, d, dep_present)?;
            // Only the 0 -> 1 transition contributes to dep_hash, AND only
            // when the dep is present locally.
            if prev_rc == 0 && dep_present {
                let _ = was_present;
                let (root_hash, mut dep_hash, present) =
                    read_node_hash(db, workspace_id, node)?;
                xor_into(&mut dep_hash, &h_dep(d));
                write_node_hash(db, workspace_id, node, &root_hash, &dep_hash, present)?;
            }
        }
    }

    Ok(())
}

/// On event becoming locally present: flip `present_locally` from 0→1 for
/// every node that already required it, and XOR its dep hash contribution
/// into each affected node's `dep_hash`.
///
/// Idempotent: if `present_locally` is already 1 we make no changes.
pub fn on_event_present(
    workspace_id: &WorkspaceId,
    event_id: &BlakeId,
    db: &Connection,
) -> rusqlite::Result<()> {
    schema::ensure_schema(db)?;

    // Find every (workspace, node) row that requires this event but has not
    // yet recorded it as present.
    let nodes: Vec<Vec<u8>> = {
        let mut stmt = db.prepare(
            "SELECT node_id FROM negentropy_dep_refcount
             WHERE workspace_id = ?1 AND dep_event_id = ?2 AND present_locally = 0
               AND refcount > 0",
        )?;
        let rows = stmt
            .query_map(
                params![workspace_id.to_vec(), event_id.to_vec()],
                |r| r.get::<_, Vec<u8>>(0),
            )?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        rows
    };

    for node in &nodes {
        // Mark present.
        db.execute(
            "UPDATE negentropy_dep_refcount
             SET present_locally = 1
             WHERE workspace_id = ?1 AND node_id = ?2 AND dep_event_id = ?3",
            params![
                workspace_id.to_vec(),
                node.clone(),
                event_id.to_vec(),
            ],
        )?;

        // XOR the dep hash contribution in.
        let (root_hash, mut dep_hash, present) = read_node_hash(db, workspace_id, node)?;
        xor_into(&mut dep_hash, &h_dep(event_id));
        write_node_hash(db, workspace_id, node, &root_hash, &dep_hash, present)?;
    }

    Ok(())
}
