//! Local history-node secret fact shape.
//!
//! These local-only facts represent derived key material for a minute tree or
//! trie leaf below a removal frontier. A node is addressed by its coordinate on
//! a binary tree across two axes: a time axis (power-of-two minute ranges) and a
//! within-minute hash trie keyed by `fact_id_in_minute` bits.

use crate::core::crypto::XChaCha20Poly1305Key;
use crate::core::facts::FactId;

pub type WorkspaceId = FactId;
pub type FrontierId = FactId;
pub type EndpointId = FactId;

/// Trie leaf depth — a leaf row carries the full 256-bit `fact_id_in_minute`
/// as `fact_id_prefix` and sits at `bit_depth = TRIE_LEAF_BIT_DEPTH`.
pub const TRIE_LEAF_BIT_DEPTH: u16 = 256;

/// Time-tree node bit depth.
pub const TIME_TREE_BIT_DEPTH: u16 = 0;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalHistoryNodeSecretFact {
    pub workspace_id: WorkspaceId,
    pub frontier_id: FrontierId,
    pub owner_endpoint_id: EndpointId,
    pub source_secret_id: FactId,
    pub range_start: u64,
    pub range_width: u64,
    pub bit_depth: u16,
    pub fact_id_prefix: FactId,
    pub tombstone_node_id: FactId,
    pub node_secret: XChaCha20Poly1305Key,
}

/// Mask `fact_id_prefix` to its first `bit_depth` bits, zeroing the rest.
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
