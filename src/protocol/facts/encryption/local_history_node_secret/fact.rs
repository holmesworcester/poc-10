//! Local history range-node secret fact for the poc-10 target tree.
//!
//! These local-only facts let filesystem history keys flow through the common
//! fact bus. A node is addressed by its coordinate on a binary tree across two
//! axes:
//!
//!   * Time axis (outer tree) — internal nodes cover a power-of-two range of
//!     unix-minute slots `(range_start, range_width)`. A minute_node is a leaf
//!     of the time axis at `(unix_minute, 1)` with `bit_depth = 0`.
//!   * Within-minute hash trie (inner tree) — a Patricia trie keyed by the
//!     bits of an `fact_id_in_minute`. Internals carry the first `bit_depth`
//!     bits in `fact_id_prefix`; leaves sit at `bit_depth = 256` and store
//!     the full event id.
//!
//! Most coordinates are never materialised — a row is written only when the
//! node is a frontier root, a retained sibling at a split or a per-event leaf.
//! Legacy parity gap (intentional): the legacy projector validated parent
//! coordinates against full dependency closures; the target projector here
//! validates fact shape only and defers structural parent/child checks until
//! the local key-secret family is also ported.

use crate::core::crypto::{XChaCha20Poly1305Key, XCHACHA20_POLY1305_KEY_BYTES};
use crate::core::facts::FactId;

pub const NODE_SECRET_BYTES: usize = XCHACHA20_POLY1305_KEY_BYTES;

pub type WorkspaceId = FactId;
pub type RemovalFrontierId = FactId;
pub type LocalHistoryNodeSecretId = FactId;

/// Trie leaf depth — a leaf row carries the full 256-bit `fact_id_in_minute`
/// as `fact_id_prefix` and sits at `bit_depth = TRIE_LEAF_BIT_DEPTH`.
pub const TRIE_LEAF_BIT_DEPTH: u16 = 256;

/// Time-tree node bit depth.
pub const TIME_TREE_BIT_DEPTH: u16 = 0;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalHistoryNodeSecretFact {
    pub workspace_id: WorkspaceId,
    pub removal_frontier_id: RemovalFrontierId,
    pub source_secret_id: FactId,
    pub range_start: u64,
    pub range_width: u64,
    pub bit_depth: u16,
    pub fact_id_prefix: FactId,
    /// Zero when this node does not retire a sibling.
    pub tombstone_node_id: FactId,
    pub node_secret: XChaCha20Poly1305Key,
}

/// Mask `fact_id_prefix` to its first `bit_depth` bits, zeroing the rest.
/// Trie node prefixes are stored zero-padded so equal coordinates encode equal
/// bytes.
pub fn mask_prefix_to_depth(prefix: FactId, bit_depth: u16) -> FactId {
    if bit_depth == 0 {
        return [0; 32];
    }
    if bit_depth >= TRIE_LEAF_BIT_DEPTH {
        return prefix;
    }
    let mut out = prefix;
    let full_bytes = (bit_depth / 8) as usize;
    let remaining_bits = (bit_depth % 8) as u8;
    if remaining_bits > 0 {
        let keep = 8 - remaining_bits;
        let mask = (0xffu8 << keep) & 0xff;
        out[full_bytes] &= mask;
        for byte in &mut out[full_bytes + 1..] {
            *byte = 0;
        }
    } else {
        for byte in &mut out[full_bytes..] {
            *byte = 0;
        }
    }
    out
}
