//! Read-only views over the local history node secret tables.
//!
//! Secret rows are keyed by
//! `(workspace_id, removal_frontier_id, range_start, range_width, bit_depth,
//!   event_id_prefix)`. These helpers compose bounded prefix scans into
//! the lookups workers and the CLI need:
//!
//! * `get`, `get_leaf`, `get_minute_node` — single-row lookups by full
//!   coordinate or by the conventional shorthand for leaves and
//!   minute_nodes.
//! * `list_for_frontier`, `list_for_workspace` — bounded prefix scans
//!   used by the encryption worker's chop / retire walks.
//! * `list_minute_nodes`, `list_leaves` — filtered views the worker uses
//!   when it only cares about one shape of row.
//! * `cover_summary` — a stable byte-equal fingerprint over the retained
//!   tree and tombstones; used to assert peers converge after retire/chop.

use crate::core::store::Store;
use crate::protocol::event_modules::encryption::local_key_secret;
use crate::protocol::event_modules::types::EventId;
use crate::protocol::wire::Writer;

use super::schema::{
    self, decode_local_history_node_secret_row, decode_local_history_node_tombstone_row,
    local_history_node_secret_key, LOCAL_HISTORY_NODE_SECRETS, LOCAL_HISTORY_NODE_TOMBSTONES,
};
use super::types::{
    is_leaf_row, is_minute_node_row, mask_prefix_to_depth, AncestorSource,
    LocalHistoryNodeSecretRow, LocalHistoryNodeTombstoneRow, TIME_TREE_BIT_DEPTH,
    TRIE_LEAF_BIT_DEPTH,
};

pub fn list_for_frontier(
    store: &Store,
    workspace_id: EventId,
    removal_frontier_id: EventId,
) -> Result<Vec<LocalHistoryNodeSecretRow>, String> {
    let mut prefix = Vec::with_capacity(64);
    prefix.extend_from_slice(&workspace_id);
    prefix.extend_from_slice(&removal_frontier_id);
    store
        .table_rows_with_key_prefix(LOCAL_HISTORY_NODE_SECRETS, &prefix, usize::MAX)
        .map_err(|err| format!("load local history node secrets: {err}"))?
        .into_iter()
        .map(|(key, value)| decode_local_history_node_secret_row(&key, &value))
        .collect()
}

/// Look up a node by its full coordinate.
pub fn get(
    store: &Store,
    workspace_id: EventId,
    removal_frontier_id: EventId,
    range_start: u64,
    range_width: u64,
    bit_depth: u16,
    event_id_prefix: EventId,
) -> Result<Option<LocalHistoryNodeSecretRow>, String> {
    let key = local_history_node_secret_key(
        workspace_id,
        removal_frontier_id,
        range_start,
        range_width,
        bit_depth,
        event_id_prefix,
    );
    store
        .table_row(LOCAL_HISTORY_NODE_SECRETS, &key)
        .map_err(|err| format!("load local history node secret: {err}"))?
        .map(|value| decode_local_history_node_secret_row(&key, &value))
        .transpose()
}

/// Convenience: look up a per-event leaf row by `(unix_minute,
/// event_id_in_minute)`.
pub fn get_leaf(
    store: &Store,
    workspace_id: EventId,
    removal_frontier_id: EventId,
    unix_minute: u64,
    event_id_in_minute: EventId,
) -> Result<Option<LocalHistoryNodeSecretRow>, String> {
    get(
        store,
        workspace_id,
        removal_frontier_id,
        unix_minute,
        1,
        super::types::TRIE_LEAF_BIT_DEPTH,
        event_id_in_minute,
    )
}

/// Convenience: look up a minute_node row by `unix_minute`.
pub fn get_minute_node(
    store: &Store,
    workspace_id: EventId,
    removal_frontier_id: EventId,
    unix_minute: u64,
) -> Result<Option<LocalHistoryNodeSecretRow>, String> {
    get(
        store,
        workspace_id,
        removal_frontier_id,
        unix_minute,
        1,
        super::types::TIME_TREE_BIT_DEPTH,
        [0; 32],
    )
}

pub fn list_for_workspace(
    store: &Store,
    workspace_id: EventId,
) -> Result<Vec<LocalHistoryNodeSecretRow>, String> {
    store
        .table_rows_with_key_prefix(LOCAL_HISTORY_NODE_SECRETS, &workspace_id, usize::MAX)
        .map_err(|err| format!("load local history node secrets: {err}"))?
        .into_iter()
        .map(|(key, value)| decode_local_history_node_secret_row(&key, &value))
        .collect()
}

pub fn list_tombstones_for_workspace(
    store: &Store,
    workspace_id: EventId,
) -> Result<Vec<LocalHistoryNodeTombstoneRow>, String> {
    store
        .table_rows_with_key_prefix(LOCAL_HISTORY_NODE_TOMBSTONES, &workspace_id, usize::MAX)
        .map_err(|err| format!("load local history node tombstones: {err}"))?
        .into_iter()
        .map(|(key, value)| decode_local_history_node_tombstone_row(&key, &value))
        .collect()
}

/// Return all materialized minute_node rows for a workspace+frontier.
pub fn list_minute_nodes(
    store: &Store,
    workspace_id: EventId,
) -> Result<Vec<LocalHistoryNodeSecretRow>, String> {
    Ok(list_for_workspace(store, workspace_id)?
        .into_iter()
        .filter(is_minute_node_row)
        .collect())
}

/// Return all materialized leaf rows (`bit_depth = 256`) for a workspace.
pub fn list_leaves(
    store: &Store,
    workspace_id: EventId,
) -> Result<Vec<LocalHistoryNodeSecretRow>, String> {
    Ok(list_for_workspace(store, workspace_id)?
        .into_iter()
        .filter(is_leaf_row)
        .collect())
}

/// Return all materialized trie leaves in a single minute under one frontier.
/// Used by the retire walk to compute trie divergence depths against the
/// surviving leaves in the same minute as the leaf being retired.
pub fn list_leaves_in_minute(
    store: &Store,
    workspace_id: EventId,
    removal_frontier_id: EventId,
    unix_minute: u64,
) -> Result<Vec<LocalHistoryNodeSecretRow>, String> {
    Ok(list_for_frontier(store, workspace_id, removal_frontier_id)?
        .into_iter()
        .filter(|row| {
            row.range_start == unix_minute
                && row.range_width == 1
                && row.bit_depth == TRIE_LEAF_BIT_DEPTH
        })
        .collect())
}

/// Find the closest source-of-derivation for the leaf at
/// `(unix_minute, event_id_in_minute)` under this frontier. Returns the
/// frontier root (`local_key_secret`) when no materialized internal covers
/// the position. When `exclude_leaf` is true, skip the leaf-being-retired
/// itself (it cannot be its own ancestor).
///
/// Specificity ranks first by smaller `range_width`, then by larger
/// `bit_depth`. The returned `AncestorSource` carries the secret material
/// and identity needed to resume derivation toward the leaf.
///
/// Errors when neither the frontier root nor any covering sibling row
/// exists — the genuine "wedge" case where the target leaf has no covering
/// ancestor at all (F has been wiped by a prior retire AND no sibling row
/// covers this coordinate).
pub fn closest_ancestor(
    store: &Store,
    workspace_id: EventId,
    removal_frontier_id: EventId,
    unix_minute: u64,
    event_id_in_minute: EventId,
    exclude_leaf: bool,
) -> Result<AncestorSource, String> {
    let root = local_key_secret::queries::get(store, workspace_id, removal_frontier_id)?;
    let mut best: Option<AncestorSource> = root.map(|row| AncestorSource::Root {
        secret_id: row.local_key_secret_id,
        secret: row.key_secret,
    });
    let mut best_range_width: u64 = u64::MAX;
    let mut best_bit_depth: u16 = TIME_TREE_BIT_DEPTH;
    let mut best_is_root = matches!(best, Some(AncestorSource::Root { .. }));

    for row in list_for_frontier(store, workspace_id, removal_frontier_id)? {
        if !covers(&row, unix_minute, event_id_in_minute) {
            continue;
        }
        if exclude_leaf
            && row.bit_depth == TRIE_LEAF_BIT_DEPTH
            && row.event_id_prefix == event_id_in_minute
        {
            continue;
        }
        let better = best.is_none()
            || best_is_root
            || row.range_width < best_range_width
            || (row.range_width == best_range_width && row.bit_depth > best_bit_depth);
        if !better {
            continue;
        }
        best_range_width = row.range_width;
        best_bit_depth = row.bit_depth;
        best_is_root = false;
        best = Some(if row.range_width > 1 {
            AncestorSource::TimeInternal {
                secret_id: row.local_history_node_secret_id,
                secret: row.node_secret,
                range_start: row.range_start,
                range_width: row.range_width,
            }
        } else {
            AncestorSource::InMinute {
                secret_id: row.local_history_node_secret_id,
                secret: row.node_secret,
                range_start: row.range_start,
                bit_depth: row.bit_depth,
                event_id_prefix: row.event_id_prefix,
            }
        });
    }
    best.ok_or_else(|| {
        "no retained ancestor covers the target leaf: F is wiped and no \
         sibling row covers this coordinate"
            .to_string()
    })
}

/// Canonical, workspace-independent encoding of every retained node-secret
/// coordinate AND every retire tombstone in this store.
///
/// The encoding is deliberately stable and platform-agnostic:
///
/// ```text
/// "topo cover summary v4"
/// || u32_be(secret_rows.len())
/// || (for each secret row, sorted by (frontier_id, range_start, range_width,
///                                     bit_depth, event_id_prefix):
///       removal_frontier_id (32B)
///       || u64_be(range_start)
///       || u64_be(range_width)
///       || u16_be(bit_depth)
///       || event_id_prefix (32B; masked to bit_depth)
///   )
/// || u32_be(tombstones.len())
/// || (for each tombstone, sorted by (frontier_id, tombstone_node_id):
///       removal_frontier_id (32B)
///       || tombstone_node_id (32B)
///   )
/// ```
///
/// Each secret row encodes 32 + 8 + 8 + 2 + 32 = **82 bytes**; each tombstone
/// encodes 32 + 32 = **64 bytes**. Total summary length is therefore
/// `21 + 4 + 82 * secret_rows.len() + 4 + 64 * tombstones.len()` and so
/// O(materialized_rows + tombstones).
///
/// Two stores that have admitted the same shared event set and run the same
/// retain/retire operations against it must produce byte-equal cover summaries
/// modulo `workspace_id`. Two stores with different workspace_ids will differ;
/// the workspace_id is intentionally not in the summary so it functions as the
/// pure structural fingerprint of the retained tree.
pub fn cover_summary(store: &Store, workspace_id: EventId) -> Result<Vec<u8>, String> {
    let mut rows = list_for_workspace(store, workspace_id)?;
    rows.sort_by(|a, b| {
        a.removal_frontier_id
            .cmp(&b.removal_frontier_id)
            .then_with(|| a.range_start.cmp(&b.range_start))
            .then_with(|| a.range_width.cmp(&b.range_width))
            .then_with(|| a.bit_depth.cmp(&b.bit_depth))
            .then_with(|| a.event_id_prefix.cmp(&b.event_id_prefix))
    });
    let mut tombstones = list_tombstones_for_workspace(store, workspace_id)?;
    tombstones.sort_by(|a, b| {
        a.removal_frontier_id
            .cmp(&b.removal_frontier_id)
            .then_with(|| a.tombstone_node_id.cmp(&b.tombstone_node_id))
    });
    let mut out = Writer::with_capacity(
        b"topo cover summary v4".len()
            + 4
            + rows.len() * schema::COVER_SUMMARY_ROW_LEN
            + 4
            + tombstones.len() * schema::COVER_SUMMARY_TOMBSTONE_LEN,
    );
    out.raw(b"topo cover summary v4");
    let len = u32::try_from(rows.len()).unwrap_or(u32::MAX);
    out.raw(&len.to_be_bytes());
    for row in &rows {
        out.id(&row.removal_frontier_id);
        out.raw(&row.range_start.to_be_bytes());
        out.raw(&row.range_width.to_be_bytes());
        out.raw(&row.bit_depth.to_be_bytes());
        out.id(&mask_prefix_to_depth(row.event_id_prefix, row.bit_depth));
    }
    let tomb_len = u32::try_from(tombstones.len()).unwrap_or(u32::MAX);
    out.raw(&tomb_len.to_be_bytes());
    for tomb in &tombstones {
        out.id(&tomb.removal_frontier_id);
        out.id(&tomb.tombstone_node_id);
    }
    Ok(out.finish())
}

/// Read-only counterpart to the encryption worker's
/// `closest_retained_ancestor` walk: returns true when some retained
/// ancestor on this peer covers the leaf coordinate
/// `(workspace_id, removal_frontier_id, unix_minute, event_id_in_minute)`.
///
/// The walk has two pieces:
///
/// 1. **F row** (`LOCAL_KEY_SECRETS`): if present for this
///    `(workspace_id, removal_frontier_id)` it covers every coordinate
///    on this frontier; returns true immediately.
///
/// 2. **Materialized history nodes** (`LOCAL_HISTORY_NODE_SECRETS`):
///    scan the frontier's rows for any whose time-axis range contains
///    `unix_minute` AND whose trie prefix (masked to `bit_depth`)
///    matches `event_id_in_minute`. A single covering row is enough.
///
/// Returns false only when neither F is present nor any sibling row
/// covers the target — i.e. the same wedge that would cause
/// `closest_retained_ancestor` to error. The receive-side admit gate
/// uses this to drop messages whose leaf is permanently undecryptable
/// on this peer (cover horizon sealed the range, an admin tightening
/// chopped the prefix, or — transiently — F has not yet been derived
/// from a key wrap).
pub fn has_covering_ancestor(
    store: &Store,
    workspace_id: EventId,
    removal_frontier_id: EventId,
    unix_minute: u64,
    event_id_in_minute: EventId,
) -> Result<bool, String> {
    if local_key_secret::queries::get(store, workspace_id, removal_frontier_id)?.is_some() {
        return Ok(true);
    }
    for row in list_for_frontier(store, workspace_id, removal_frontier_id)? {
        if covers(&row, unix_minute, event_id_in_minute) {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Does this retained-row coordinate cover the leaf at
/// `(unix_minute, event_id_in_minute)`?
///
/// Mirrors the worker-side `covers` predicate in
/// `workers/encryption.rs`. Both implementations must agree byte-for-byte
/// — if they ever drift the admit gate could drop a message the worker
/// would have decrypted (or vice versa).
fn covers(
    row: &LocalHistoryNodeSecretRow,
    unix_minute: u64,
    event_id_in_minute: EventId,
) -> bool {
    let row_end = row.range_start.saturating_add(row.range_width);
    if unix_minute < row.range_start || unix_minute >= row_end {
        return false;
    }
    if row.bit_depth == TIME_TREE_BIT_DEPTH {
        return true;
    }
    if row.bit_depth >= TRIE_LEAF_BIT_DEPTH {
        return row.event_id_prefix == event_id_in_minute;
    }
    mask_prefix_to_depth(event_id_in_minute, row.bit_depth) == row.event_id_prefix
}
