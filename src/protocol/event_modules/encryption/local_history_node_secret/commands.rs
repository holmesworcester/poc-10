//! Commands for local history range-node secrets.
//!
//! Two domain-separated derivation paths exist:
//!
//! * `derive_time_split` — splits a time-axis range. The parent covers
//!   `(parent_range_start, parent_range_width)`. The child covers
//!   `(child_range_start, child_range_width)` on `child_side` (0 = left,
//!   1 = right). `range_width=1` means the child is a minute_node leaf of
//!   the time tree, sitting at the bridge between time tree and trie tree.
//!   The KDF info encodes
//!   `u64_be(parent_start) || u64_be(parent_width) || u8(child_side)
//!     || u64_be(child_start) || u64_be(child_width)`.
//!
//! * `derive_trie_split` — splits a within-minute hash trie. The parent
//!   trie node sits at `parent_bit_depth` (0 = minute_node) on the same
//!   minute (`range_start`). The child sits at `child_bit_depth` on
//!   `child_side` (0 = bit-0, 1 = bit-1). `child_bit_depth = 256` makes the
//!   child a leaf carrying the full `event_id_in_minute`. Patricia
//!   compression is allowed: a child may sit at any depth past the
//!   parent's depth. The KDF info encodes
//!   `u8(parent_bit_depth) || prefix(parent_bit_depth, 32)
//!     || u8(child_side) || u8(child_bit_depth)
//!     || prefix(child_bit_depth, 32)`.
//!
//! Both paths return one local event whose dependencies are the source
//! secret, the workspace removal frontier, and (optionally) a tombstoned
//! node id. Projection writes the row and exact-deletes the retired row.
//!
//! These are local-only events. Their plaintext `node_secret` is in the
//! canonical bytes; on tombstone, the worker purges the canonical bytes
//! to preserve forward secrecy.

use crate::core::crypto;
use crate::core::store::Store;
use crate::protocol::event_modules::queries as event_queries;
use crate::protocol::event_modules::types::{event_id, EventId};
use crate::protocol::event_modules::worker::CommandOutput;
use crate::protocol::wire::Writer;

use super::codec;
use super::queries;
use super::types::{
    bit_at, first_diverging_bit, mask_prefix_to_depth, sibling_prefix_at_depth, AncestorSource,
    HistoryNodeSecret, LocalHistoryNodeSecret, TIME_TREE_BIT_DEPTH, TRIE_LEAF_BIT_DEPTH,
};

/// Domain-separated tag for time-axis range-tree splits under
/// BLAKE3-keyed-hash. Bumping the tag forces re-derivation.
pub const TIME_SPLIT_DOMAIN: &[u8] = b"topo time split v1";

/// Domain-separated tag for within-minute hash-trie splits under
/// BLAKE3-keyed-hash. Bumping the tag forces re-derivation.
pub const TRIE_SPLIT_DOMAIN: &[u8] = b"topo trie split v1";

/// Implicit time-tree root width used when a leaf is derived directly from
/// the workspace `local_key_secret` (no materialized intermediates). Must
/// match `workers::encryption::TIME_TREE_ROOT_WIDTH`.
pub const ROOT_TIME_TREE_WIDTH: u64 = 1u64 << 63;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeriveTimeSplit {
    pub workspace_id: EventId,
    pub removal_frontier_id: EventId,
    /// Identity of the source-secret event we derive from. May be the
    /// frontier root (`local_key_secret`) or another `local_history_node_secret`.
    pub parent_secret_id: EventId,
    /// Plaintext source-secret material.
    pub parent_secret: HistoryNodeSecret,
    /// Parent's covered range. The frontier root is encoded as
    /// `(parent_range_start=0, parent_range_width=u64::MAX)` to capture the
    /// whole time axis.
    pub parent_range_start: u64,
    pub parent_range_width: u64,
    /// 0 for left half (lower minutes), 1 for right half. Encoded into the
    /// KDF info so left and right children diverge.
    pub child_side: u8,
    pub child_range_start: u64,
    pub child_range_width: u64,
    pub tombstone_node_id: Option<EventId>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeriveTrieSplit {
    pub workspace_id: EventId,
    pub removal_frontier_id: EventId,
    /// Identity of the source-secret event we derive from. The parent must
    /// either be a minute_node (`bit_depth=0`) or another trie internal.
    pub parent_secret_id: EventId,
    pub parent_secret: HistoryNodeSecret,
    /// Minute slot the trie lives under. The same value is propagated to the
    /// child since trie depth doesn't change `range_start`.
    pub range_start: u64,
    pub parent_bit_depth: u16,
    pub parent_event_id_prefix: EventId,
    /// 0 for the bit-0 branch, 1 for the bit-1 branch at the parent's depth.
    pub child_side: u8,
    pub child_bit_depth: u16,
    pub child_event_id_prefix: EventId,
    pub tombstone_node_id: Option<EventId>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalHistoryNodeSecretOutput {
    pub local_history_node_secret_id: EventId,
    pub event: LocalHistoryNodeSecret,
}

pub fn derive_time_split(
    input: DeriveTimeSplit,
) -> Result<CommandOutput<LocalHistoryNodeSecretOutput>, String> {
    validate_id("workspace_id", &input.workspace_id)?;
    validate_id("removal_frontier_id", &input.removal_frontier_id)?;
    validate_id("parent_secret_id", &input.parent_secret_id)?;
    validate_id("parent_secret", &input.parent_secret)?;
    if let Some(tombstone_node_id) = input.tombstone_node_id {
        validate_id("tombstone_node_id", &tombstone_node_id)?;
    }
    if input.child_side > 1 {
        return Err("child_side must be 0 (left) or 1 (right)".to_string());
    }
    validate_range(input.child_range_start, input.child_range_width)?;
    if input.parent_range_width != u64::MAX {
        validate_range(input.parent_range_start, input.parent_range_width)?;
    }

    let info = time_split_info(&input);
    let node_secret = crypto::blake3_keyed_hash(&input.parent_secret, TIME_SPLIT_DOMAIN, &info);
    let event = LocalHistoryNodeSecret {
        workspace_id: input.workspace_id,
        removal_frontier_id: input.removal_frontier_id,
        source_secret_id: input.parent_secret_id,
        range_start: input.child_range_start,
        range_width: input.child_range_width,
        bit_depth: TIME_TREE_BIT_DEPTH,
        event_id_prefix: [0; 32],
        tombstone_node_id: input.tombstone_node_id,
        node_secret,
    };
    let bytes = codec::encode(&event);
    let record = codec::record_from_bytes(bytes)?;
    let value = LocalHistoryNodeSecretOutput {
        local_history_node_secret_id: event_id(&record.canonical_bytes),
        event,
    };
    Ok(CommandOutput::with_events(value, vec![record]))
}

/// Derive a per-event leaf directly from the frontier root
/// (`local_key_secret`). The chain walks the time tree from the implicit
/// root `(0, ROOT_TIME_TREE_WIDTH)` down to `(unix_minute, 1)` then takes
/// one trie split from the minute_node (`bit_depth=0`) to the leaf
/// (`bit_depth=256`). Both walks use the same domain tags as
/// `derive_time_split` and `derive_trie_split`, so a leaf admitted via
/// this fast path is byte-equal to one admitted via materialized
/// intermediates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeriveEventLeafFromRoot {
    pub workspace_id: EventId,
    pub removal_frontier_id: EventId,
    /// Identity of the workspace `local_key_secret` row.
    pub root_secret_id: EventId,
    /// The workspace root key secret material.
    pub root_secret: HistoryNodeSecret,
    pub unix_minute: u64,
    pub event_id_in_minute: EventId,
}

pub fn derive_event_leaf_from_root(
    input: DeriveEventLeafFromRoot,
) -> Result<CommandOutput<LocalHistoryNodeSecretOutput>, String> {
    validate_id("workspace_id", &input.workspace_id)?;
    validate_id("removal_frontier_id", &input.removal_frontier_id)?;
    validate_id("root_secret_id", &input.root_secret_id)?;
    validate_id("root_secret", &input.root_secret)?;

    // Time-tree walk: `ROOT_TIME_TREE_WIDTH → … → 1`.
    let mut current_secret = input.root_secret;
    let mut current_start = 0u64;
    let mut current_width = ROOT_TIME_TREE_WIDTH;
    while current_width > 1 {
        let half = current_width / 2;
        let mid = current_start + half;
        let (child_side, child_start) = if input.unix_minute < mid {
            (0u8, current_start)
        } else {
            (1u8, mid)
        };
        let info =
            time_split_info_bytes(current_start, current_width, child_side, child_start, half);
        current_secret = crypto::blake3_keyed_hash(&current_secret, TIME_SPLIT_DOMAIN, &info);
        current_start = child_start;
        current_width = half;
    }

    // Trie split: from minute_node (`bit_depth=0`) to leaf (`bit_depth=256`).
    let leaf_side = super::types::bit_at(&input.event_id_in_minute, 0);
    let leaf_info = trie_split_info_bytes(
        0,
        [0; 32],
        leaf_side,
        TRIE_LEAF_BIT_DEPTH,
        input.event_id_in_minute,
    );
    let leaf_secret = crypto::blake3_keyed_hash(&current_secret, TRIE_SPLIT_DOMAIN, &leaf_info);

    let event = LocalHistoryNodeSecret {
        workspace_id: input.workspace_id,
        removal_frontier_id: input.removal_frontier_id,
        source_secret_id: input.root_secret_id,
        range_start: input.unix_minute,
        range_width: 1,
        bit_depth: TRIE_LEAF_BIT_DEPTH,
        event_id_prefix: input.event_id_in_minute,
        tombstone_node_id: None,
        node_secret: leaf_secret,
    };
    let bytes = codec::encode(&event);
    let record = codec::record_from_bytes(bytes)?;
    let value = LocalHistoryNodeSecretOutput {
        local_history_node_secret_id: event_id(&record.canonical_bytes),
        event,
    };
    Ok(CommandOutput::with_events(value, vec![record]))
}

/// Derive a per-event leaf from the closest ancestor that already covers
/// the target position. Three input shapes correspond to the three places
/// the derivation chain can resume from:
///
/// * `Root` — the frontier root (`local_key_secret`). Walks the entire time
///   tree as KDF chains in memory and emits a single leaf event whose
///   `source_secret_id` is the root. (Equivalent to the legacy
///   `derive_event_leaf_from_root`.)
/// * `TimeInternal` — a materialized time-tree internal at `range_width >
///   1`. Emits one record per time-tree level on the descending path
///   (`log2(range_width)` records) plus one leaf trie split.
/// * `InMinute` — a materialized minute_node (`bit_depth = 0, range_width =
///   1`) or trie internal (`0 < bit_depth < 256`). Emits a single trie
///   split straight to the leaf (Patricia-compressed from `bit_depth` to
///   256).
///
/// All arms produce records using the same domain tags and KDF info layout
/// as `derive_time_split` / `derive_trie_split`, so leaves admitted via any
/// arm are byte-equal to leaves admitted via materialized intermediates.
/// Admission of the returned records is the caller's responsibility (the
/// encryption worker dispatches the admit-and-drain pipeline).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeriveLeafFromAncestor {
    pub workspace_id: EventId,
    pub removal_frontier_id: EventId,
    pub ancestor: AncestorSource,
    pub unix_minute: u64,
    pub event_id_in_minute: EventId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeriveLeafFromAncestorOutput {
    pub leaf_id: EventId,
    pub leaf_secret: HistoryNodeSecret,
}

pub fn derive_leaf_from_ancestor(
    input: DeriveLeafFromAncestor,
) -> Result<CommandOutput<DeriveLeafFromAncestorOutput>, String> {
    validate_id("workspace_id", &input.workspace_id)?;
    validate_id("removal_frontier_id", &input.removal_frontier_id)?;
    if input.event_id_in_minute.iter().all(|byte| *byte == 0) {
        return Err("event_id_in_minute must be non-zero".to_string());
    }

    let mut records: Vec<crate::protocol::event_modules::types::EventRecord> = Vec::new();
    let (parent_secret, parent_id, parent_bit_depth, parent_event_id_prefix) =
        descend_to_trie_position(&input, &mut records)?;

    if parent_bit_depth >= TRIE_LEAF_BIT_DEPTH {
        return Err("ancestor is already at the leaf depth".to_string());
    }

    let child_side = bit_at(&input.event_id_in_minute, parent_bit_depth);
    let leaf_info = trie_split_info_bytes(
        parent_bit_depth,
        parent_event_id_prefix,
        child_side,
        TRIE_LEAF_BIT_DEPTH,
        input.event_id_in_minute,
    );
    let leaf_secret = crypto::blake3_keyed_hash(&parent_secret, TRIE_SPLIT_DOMAIN, &leaf_info);

    let leaf_event = LocalHistoryNodeSecret {
        workspace_id: input.workspace_id,
        removal_frontier_id: input.removal_frontier_id,
        source_secret_id: parent_id,
        range_start: input.unix_minute,
        range_width: 1,
        bit_depth: TRIE_LEAF_BIT_DEPTH,
        event_id_prefix: input.event_id_in_minute,
        tombstone_node_id: None,
        node_secret: leaf_secret,
    };
    let leaf_bytes = codec::encode(&leaf_event);
    let leaf_record = codec::record_from_bytes(leaf_bytes)?;
    let leaf_id = event_id(&leaf_record.canonical_bytes);
    records.push(leaf_record);

    Ok(CommandOutput::with_events(
        DeriveLeafFromAncestorOutput {
            leaf_id,
            leaf_secret,
        },
        records,
    ))
}

/// Walk down the time tree to the trie position from which to take the
/// leaf split. For `Root`, walks the entire time axis as in-memory KDF
/// chains (no intermediate events emitted; the leaf event sources directly
/// from the root). For `TimeInternal`, emits one event per descending
/// time-tree level. For `InMinute`, returns the ancestor's trie coordinate
/// directly. Returns `(parent_secret, parent_secret_id, parent_bit_depth,
/// parent_event_id_prefix)` — the immediate parent of the trie leaf.
fn descend_to_trie_position(
    input: &DeriveLeafFromAncestor,
    records: &mut Vec<crate::protocol::event_modules::types::EventRecord>,
) -> Result<(HistoryNodeSecret, EventId, u16, EventId), String> {
    match input.ancestor {
        AncestorSource::Root { secret_id, secret } => {
            validate_id("ancestor.secret_id", &secret_id)?;
            validate_id("ancestor.secret", &secret)?;
            let mut current_secret = secret;
            let mut current_start = 0u64;
            let mut current_width = ROOT_TIME_TREE_WIDTH;
            while current_width > 1 {
                let half = current_width / 2;
                let mid = current_start + half;
                let (child_side, child_start) = if input.unix_minute < mid {
                    (0u8, current_start)
                } else {
                    (1u8, mid)
                };
                let info = time_split_info_bytes(
                    current_start,
                    current_width,
                    child_side,
                    child_start,
                    half,
                );
                current_secret =
                    crypto::blake3_keyed_hash(&current_secret, TIME_SPLIT_DOMAIN, &info);
                current_start = child_start;
                current_width = half;
            }
            // The leaf event sources directly from the root id; no
            // intermediate records are emitted.
            Ok((current_secret, secret_id, TIME_TREE_BIT_DEPTH, [0; 32]))
        }
        AncestorSource::TimeInternal {
            secret_id,
            secret,
            range_start,
            range_width,
        } => {
            validate_id("ancestor.secret_id", &secret_id)?;
            validate_id("ancestor.secret", &secret)?;
            validate_range(range_start, range_width)?;
            if input.unix_minute < range_start
                || input.unix_minute >= range_start.saturating_add(range_width)
            {
                return Err("ancestor does not cover unix_minute".to_string());
            }
            let mut current_secret = secret;
            let mut current_id = secret_id;
            let mut current_start = range_start;
            let mut current_width = range_width;
            while current_width > 1 {
                let half = current_width / 2;
                let mid = current_start + half;
                let (child_side, child_start) = if input.unix_minute < mid {
                    (0u8, current_start)
                } else {
                    (1u8, mid)
                };
                let info = time_split_info_bytes(
                    current_start,
                    current_width,
                    child_side,
                    child_start,
                    half,
                );
                let child_secret =
                    crypto::blake3_keyed_hash(&current_secret, TIME_SPLIT_DOMAIN, &info);
                let event = LocalHistoryNodeSecret {
                    workspace_id: input.workspace_id,
                    removal_frontier_id: input.removal_frontier_id,
                    source_secret_id: current_id,
                    range_start: child_start,
                    range_width: half,
                    bit_depth: TIME_TREE_BIT_DEPTH,
                    event_id_prefix: [0; 32],
                    tombstone_node_id: None,
                    node_secret: child_secret,
                };
                let bytes = codec::encode(&event);
                let record = codec::record_from_bytes(bytes)?;
                let child_id = event_id(&record.canonical_bytes);
                records.push(record);
                current_id = child_id;
                current_secret = child_secret;
                current_start = child_start;
                current_width = half;
            }
            Ok((current_secret, current_id, TIME_TREE_BIT_DEPTH, [0; 32]))
        }
        AncestorSource::InMinute {
            secret_id,
            secret,
            range_start,
            bit_depth,
            event_id_prefix,
        } => {
            validate_id("ancestor.secret_id", &secret_id)?;
            validate_id("ancestor.secret", &secret)?;
            if range_start != input.unix_minute {
                return Err("InMinute ancestor range_start does not match unix_minute".to_string());
            }
            if bit_depth > TRIE_LEAF_BIT_DEPTH {
                return Err("InMinute ancestor bit_depth out of range".to_string());
            }
            if mask_prefix_to_depth(input.event_id_in_minute, bit_depth) != event_id_prefix {
                return Err("InMinute ancestor does not cover event_id_in_minute".to_string());
            }
            Ok((secret, secret_id, bit_depth, event_id_prefix))
        }
    }
}

fn time_split_info_bytes(
    parent_range_start: u64,
    parent_range_width: u64,
    child_side: u8,
    child_range_start: u64,
    child_range_width: u64,
) -> Vec<u8> {
    let mut out = Writer::with_capacity(8 + 8 + 1 + 8 + 8);
    out.u64(parent_range_start);
    out.u64(parent_range_width);
    out.u8(child_side);
    out.u64(child_range_start);
    out.u64(child_range_width);
    out.finish()
}

fn trie_split_info_bytes(
    parent_bit_depth: u16,
    parent_event_id_prefix: EventId,
    child_side: u8,
    child_bit_depth: u16,
    child_event_id_prefix: EventId,
) -> Vec<u8> {
    let mut out = Writer::with_capacity(2 + 32 + 1 + 2 + 32);
    out.raw(&parent_bit_depth.to_be_bytes());
    let parent_prefix = mask_prefix_to_depth(parent_event_id_prefix, parent_bit_depth);
    out.id(&parent_prefix);
    out.u8(child_side);
    out.raw(&child_bit_depth.to_be_bytes());
    let child_prefix = mask_prefix_to_depth(child_event_id_prefix, child_bit_depth);
    out.id(&child_prefix);
    out.finish()
}

pub fn derive_trie_split(
    input: DeriveTrieSplit,
) -> Result<CommandOutput<LocalHistoryNodeSecretOutput>, String> {
    validate_id("workspace_id", &input.workspace_id)?;
    validate_id("removal_frontier_id", &input.removal_frontier_id)?;
    validate_id("parent_secret_id", &input.parent_secret_id)?;
    validate_id("parent_secret", &input.parent_secret)?;
    if let Some(tombstone_node_id) = input.tombstone_node_id {
        validate_id("tombstone_node_id", &tombstone_node_id)?;
    }
    if input.child_side > 1 {
        return Err("child_side must be 0 (left) or 1 (right)".to_string());
    }
    if input.parent_bit_depth >= TRIE_LEAF_BIT_DEPTH {
        return Err("parent_bit_depth must be less than 256 (parent cannot be a leaf)".to_string());
    }
    if input.child_bit_depth <= input.parent_bit_depth {
        return Err("child_bit_depth must be greater than parent_bit_depth".to_string());
    }
    if input.child_bit_depth > TRIE_LEAF_BIT_DEPTH {
        return Err("child_bit_depth must be at most 256".to_string());
    }
    validate_range(input.range_start, 1)?;

    let info = trie_split_info(&input);
    let node_secret = crypto::blake3_keyed_hash(&input.parent_secret, TRIE_SPLIT_DOMAIN, &info);
    let event = LocalHistoryNodeSecret {
        workspace_id: input.workspace_id,
        removal_frontier_id: input.removal_frontier_id,
        source_secret_id: input.parent_secret_id,
        range_start: input.range_start,
        range_width: 1,
        bit_depth: input.child_bit_depth,
        event_id_prefix: mask_prefix_to_depth(input.child_event_id_prefix, input.child_bit_depth),
        tombstone_node_id: input.tombstone_node_id,
        node_secret,
    };
    let bytes = codec::encode(&event);
    let record = codec::record_from_bytes(bytes)?;
    let value = LocalHistoryNodeSecretOutput {
        local_history_node_secret_id: event_id(&record.canonical_bytes),
        event,
    };
    Ok(CommandOutput::with_events(value, vec![record]))
}

fn time_split_info(input: &DeriveTimeSplit) -> Vec<u8> {
    let mut out = Writer::with_capacity(8 + 8 + 1 + 8 + 8);
    out.u64(input.parent_range_start);
    out.u64(input.parent_range_width);
    out.u8(input.child_side);
    out.u64(input.child_range_start);
    out.u64(input.child_range_width);
    out.finish()
}

fn trie_split_info(input: &DeriveTrieSplit) -> Vec<u8> {
    let mut out = Writer::with_capacity(2 + 32 + 1 + 2 + 32);
    out.raw(&input.parent_bit_depth.to_be_bytes());
    let parent_prefix = mask_prefix_to_depth(input.parent_event_id_prefix, input.parent_bit_depth);
    out.id(&parent_prefix);
    out.u8(input.child_side);
    out.raw(&input.child_bit_depth.to_be_bytes());
    let child_prefix = mask_prefix_to_depth(input.child_event_id_prefix, input.child_bit_depth);
    out.id(&child_prefix);
    out.finish()
}

/// One row that the retire walk wipes after admission completes. Carries
/// the event id (so canonical bytes can be purged) plus the full row
/// coordinate (so the row can be exact-deleted by key and tombstoned
/// against `range_start + range_width`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetireWipeEntry {
    pub event_id: EventId,
    pub range_start: u64,
    pub range_width: u64,
    pub bit_depth: u16,
    pub event_id_prefix: EventId,
}

/// Retire one event's leaf by emitting all materialization records along
/// the retirement path: time-tree descend + sibling pairs from the
/// ancestor down to the minute_node, then trie descend + sibling pairs at
/// every divergence depth between the leaf-being-retired and the surviving
/// leaves in this minute.
///
/// At the FINAL time-tree split (`parent_width = 2`), only the descending
/// child is emitted — the adjacent minute_node sibling stays implicit per
/// the binary-tree FS spec.
///
/// Records use deterministic event ids, so duplicate emissions (rows that
/// already exist in the store from prior retirements) are silently absorbed
/// by admission. The command itself does not deduplicate.
///
/// The leaf row's exact-delete and canonical-byte purge are NOT part of the
/// emitted records — they are cross-table store operations the worker
/// performs after admission, along with wiping the descend-side rows
/// returned in `wipe_path`. The frontier root (`local_key_secret`) wipe is
/// also a worker responsibility because it lives in a different table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetireLeafFromAncestor {
    pub workspace_id: EventId,
    pub removal_frontier_id: EventId,
    pub ancestor: AncestorSource,
    pub unix_minute: u64,
    /// Coordinate of the leaf being retired.
    pub event_id_in_minute: EventId,
    /// `event_id_in_minute` values of the OTHER materialized leaves in the
    /// same minute. Their first-diverging-bit positions against
    /// `event_id_in_minute` determine which sibling internal depths must be
    /// materialized to keep the surviving leaves covered.
    pub survivor_coords: Vec<EventId>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RetireLeafFromAncestorOutput {
    /// Subset of the emitted records that belong to the descend-side path
    /// from the ancestor down toward the leaf. The worker exact-deletes
    /// these rows and purges their canonical bytes after admission so the
    /// deleted leaf's secret cannot be re-derived.
    pub wipe_path: Vec<RetireWipeEntry>,
}

pub fn retire_leaf_from_ancestor(
    input: RetireLeafFromAncestor,
) -> Result<CommandOutput<RetireLeafFromAncestorOutput>, String> {
    validate_id("workspace_id", &input.workspace_id)?;
    validate_id("removal_frontier_id", &input.removal_frontier_id)?;
    if input.event_id_in_minute.iter().all(|byte| *byte == 0) {
        return Err("event_id_in_minute must be non-zero".to_string());
    }

    let mut records: Vec<crate::protocol::event_modules::types::EventRecord> = Vec::new();
    let mut wipe_path: Vec<RetireWipeEntry> = Vec::new();
    let (mut current_secret, mut current_id, mut current_bit_depth, mut current_event_id_prefix) =
        emit_time_walk_for_retire(&input, &mut records, &mut wipe_path)?;

    let mut divergence_depths: Vec<u16> = input
        .survivor_coords
        .iter()
        .map(|coord| first_diverging_bit(&input.event_id_in_minute, coord))
        .collect();
    divergence_depths.sort_unstable();
    divergence_depths.dedup();

    for depth in divergence_depths {
        if depth <= current_bit_depth {
            continue;
        }
        let descend_side = bit_at(&input.event_id_in_minute, depth - 1);
        let sibling_side = 1 - descend_side;
        let descend_prefix = mask_prefix_to_depth(input.event_id_in_minute, depth);
        let sibling_prefix = sibling_prefix_at_depth(input.event_id_in_minute, depth);

        let descend_event = build_trie_split_event(
            input.workspace_id,
            input.removal_frontier_id,
            input.unix_minute,
            current_id,
            current_secret,
            current_bit_depth,
            current_event_id_prefix,
            descend_side,
            depth,
            descend_prefix,
        );
        let descend_record = codec::record_from_bytes(codec::encode(&descend_event))?;
        let descend_id = event_id(&descend_record.canonical_bytes);
        records.push(descend_record);
        wipe_path.push(RetireWipeEntry {
            event_id: descend_id,
            range_start: input.unix_minute,
            range_width: 1,
            bit_depth: depth,
            event_id_prefix: descend_prefix,
        });

        let sibling_event = build_trie_split_event(
            input.workspace_id,
            input.removal_frontier_id,
            input.unix_minute,
            current_id,
            current_secret,
            current_bit_depth,
            current_event_id_prefix,
            sibling_side,
            depth,
            sibling_prefix,
        );
        let sibling_record = codec::record_from_bytes(codec::encode(&sibling_event))?;
        records.push(sibling_record);

        current_secret = descend_event.node_secret;
        current_id = descend_id;
        current_bit_depth = depth;
        current_event_id_prefix = descend_prefix;
    }

    Ok(CommandOutput::with_events(
        RetireLeafFromAncestorOutput { wipe_path },
        records,
    ))
}

/// Walk the time tree from the ancestor down to the minute_node, emitting
/// descend + sibling pairs at each level (sibling skipped at the final
/// `width = 2 -> 1` split). Returns the trie position to start the trie
/// walk from. For an `InMinute` ancestor the walk is a no-op; the trie
/// position is the ancestor's coordinate.
fn emit_time_walk_for_retire(
    input: &RetireLeafFromAncestor,
    records: &mut Vec<crate::protocol::event_modules::types::EventRecord>,
    wipe_path: &mut Vec<RetireWipeEntry>,
) -> Result<(HistoryNodeSecret, EventId, u16, EventId), String> {
    let (mut current_secret, mut current_id, mut current_start, mut current_width) = match input
        .ancestor
    {
        AncestorSource::Root { secret_id, secret } => {
            validate_id("ancestor.secret_id", &secret_id)?;
            validate_id("ancestor.secret", &secret)?;
            (secret, secret_id, 0u64, ROOT_TIME_TREE_WIDTH)
        }
        AncestorSource::TimeInternal {
            secret_id,
            secret,
            range_start,
            range_width,
        } => {
            validate_id("ancestor.secret_id", &secret_id)?;
            validate_id("ancestor.secret", &secret)?;
            validate_range(range_start, range_width)?;
            if input.unix_minute < range_start
                || input.unix_minute >= range_start.saturating_add(range_width)
            {
                return Err("ancestor does not cover unix_minute".to_string());
            }
            (secret, secret_id, range_start, range_width)
        }
        AncestorSource::InMinute {
            secret_id,
            secret,
            range_start,
            bit_depth,
            event_id_prefix,
        } => {
            validate_id("ancestor.secret_id", &secret_id)?;
            validate_id("ancestor.secret", &secret)?;
            if range_start != input.unix_minute {
                return Err("InMinute ancestor range_start does not match unix_minute".to_string());
            }
            if mask_prefix_to_depth(input.event_id_in_minute, bit_depth) != event_id_prefix {
                return Err("InMinute ancestor does not cover event_id_in_minute".to_string());
            }
            return Ok((secret, secret_id, bit_depth, event_id_prefix));
        }
    };

    while current_width > 1 {
        let half = current_width / 2;
        let mid = current_start + half;
        let (descend_side, descend_start, sibling_side, sibling_start) = if input.unix_minute < mid
        {
            (0u8, current_start, 1u8, mid)
        } else {
            (1u8, mid, 0u8, current_start)
        };

        let descend_event = build_time_split_event(
            input.workspace_id,
            input.removal_frontier_id,
            current_id,
            current_secret,
            current_start,
            current_width,
            descend_side,
            descend_start,
            half,
        );
        let descend_record = codec::record_from_bytes(codec::encode(&descend_event))?;
        let descend_id = event_id(&descend_record.canonical_bytes);
        records.push(descend_record);
        wipe_path.push(RetireWipeEntry {
            event_id: descend_id,
            range_start: descend_start,
            range_width: half,
            bit_depth: TIME_TREE_BIT_DEPTH,
            event_id_prefix: [0; 32],
        });

        // Skip sibling at the final split: adjacent minute_nodes at
        // width=1 stay implicit per the binary-tree FS spec.
        if current_width > 2 {
            let sibling_event = build_time_split_event(
                input.workspace_id,
                input.removal_frontier_id,
                current_id,
                current_secret,
                current_start,
                current_width,
                sibling_side,
                sibling_start,
                half,
            );
            let sibling_record = codec::record_from_bytes(codec::encode(&sibling_event))?;
            records.push(sibling_record);
        }

        current_secret = descend_event.node_secret;
        current_id = descend_id;
        current_start = descend_start;
        current_width = half;
    }
    Ok((current_secret, current_id, TIME_TREE_BIT_DEPTH, [0; 32]))
}

#[allow(clippy::too_many_arguments)]
fn build_time_split_event(
    workspace_id: EventId,
    removal_frontier_id: EventId,
    parent_id: EventId,
    parent_secret: HistoryNodeSecret,
    parent_range_start: u64,
    parent_range_width: u64,
    child_side: u8,
    child_range_start: u64,
    child_range_width: u64,
) -> LocalHistoryNodeSecret {
    let info = time_split_info_bytes(
        parent_range_start,
        parent_range_width,
        child_side,
        child_range_start,
        child_range_width,
    );
    let node_secret = crypto::blake3_keyed_hash(&parent_secret, TIME_SPLIT_DOMAIN, &info);
    LocalHistoryNodeSecret {
        workspace_id,
        removal_frontier_id,
        source_secret_id: parent_id,
        range_start: child_range_start,
        range_width: child_range_width,
        bit_depth: TIME_TREE_BIT_DEPTH,
        event_id_prefix: [0; 32],
        tombstone_node_id: None,
        node_secret,
    }
}

#[allow(clippy::too_many_arguments)]
fn build_trie_split_event(
    workspace_id: EventId,
    removal_frontier_id: EventId,
    unix_minute: u64,
    parent_id: EventId,
    parent_secret: HistoryNodeSecret,
    parent_bit_depth: u16,
    parent_event_id_prefix: EventId,
    child_side: u8,
    child_bit_depth: u16,
    child_event_id_prefix: EventId,
) -> LocalHistoryNodeSecret {
    let info = trie_split_info_bytes(
        parent_bit_depth,
        parent_event_id_prefix,
        child_side,
        child_bit_depth,
        child_event_id_prefix,
    );
    let node_secret = crypto::blake3_keyed_hash(&parent_secret, TRIE_SPLIT_DOMAIN, &info);
    LocalHistoryNodeSecret {
        workspace_id,
        removal_frontier_id,
        source_secret_id: parent_id,
        range_start: unix_minute,
        range_width: 1,
        bit_depth: child_bit_depth,
        event_id_prefix: mask_prefix_to_depth(child_event_id_prefix, child_bit_depth),
        tombstone_node_id: None,
        node_secret,
    }
}

/// Boundary descent for a time-tree range-deletion. Tombstones every minute
/// in `[0, floor_minute)` by walking from the ancestor down along the
/// boundary at `floor_minute`. At each level (range_width >= 2):
///
/// * If `floor_minute >= mid` (floor lives in the right half): the entire
///   LEFT half is fully `< mid <= floor_minute` and is fully chopped.
///   Emit the left child (full-subtree wipe) and the right child (boundary
///   descend continuation). Descend RIGHT.
/// * If `floor_minute < mid` (floor lives in the left half): the right
///   half is fully `>= mid > floor_minute` and survives. Emit the right
///   child (surviving sibling cover) and the left child (boundary descend
///   continuation). Descend LEFT.
///
/// At each step the descend-side child is also part of the wipe path; the
/// worker exact-deletes those rows + the F root row after admission. The
/// surviving right-side siblings stay on disk and provide cover for future
/// authoring above the floor.
///
/// Cost: at most `log2(ancestor.range_width)` levels (~63 for F root). One
/// or two records per level, all using the deterministic
/// `TIME_SPLIT_DOMAIN` KDF, so two peers running the same chop produce
/// byte-identical events.
///
/// The ancestor MUST cover `floor_minute` (Root always does; a Sibling
/// ancestor must have `range_start <= floor_minute <
/// range_start + range_width`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChopTimeTreeFromAncestor {
    pub workspace_id: EventId,
    pub removal_frontier_id: EventId,
    /// Must be `Root` or `TimeInternal`. `InMinute` is rejected (chop
    /// operates on time-tree subtrees only).
    pub ancestor: AncestorSource,
    /// Minute boundary; everything `< floor_minute` is chopped.
    pub floor_minute: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ChopTimeTreeFromAncestorOutput {
    /// Subset of the emitted records that belong to the descend-side path
    /// AND the full-subtree-wipe path. The worker exact-deletes these
    /// rows + purges canonical bytes + writes tombstones after admission.
    pub wipe_path: Vec<RetireWipeEntry>,
    /// Number of fully-left subtree tombstones emitted (one per level
    /// whose floor-minute bit is 1). Bounded by `log2(range_width)`.
    pub subtree_tombstones_emitted: usize,
    /// Number of boundary descend-path tombstones emitted (one per level
    /// where the boundary descends, regardless of floor-bit direction).
    pub boundary_descend_tombstones_emitted: usize,
    /// Number of right-side sibling cover rows emitted (one per level
    /// whose floor-minute bit is 0, materializing the surviving right
    /// half).
    pub right_side_siblings_emitted: usize,
}

pub fn chop_time_tree_from_ancestor(
    input: ChopTimeTreeFromAncestor,
) -> Result<CommandOutput<ChopTimeTreeFromAncestorOutput>, String> {
    validate_id("workspace_id", &input.workspace_id)?;
    validate_id("removal_frontier_id", &input.removal_frontier_id)?;
    if input.floor_minute == 0 {
        return Err("chop floor_minute must be > 0 (caller short-circuits)".to_string());
    }

    let (mut current_secret, mut current_id, mut current_start, mut current_width) =
        match input.ancestor {
            AncestorSource::Root { secret_id, secret } => {
                validate_id("ancestor.secret_id", &secret_id)?;
                validate_id("ancestor.secret", &secret)?;
                (secret, secret_id, 0u64, ROOT_TIME_TREE_WIDTH)
            }
            AncestorSource::TimeInternal {
                secret_id,
                secret,
                range_start,
                range_width,
            } => {
                validate_id("ancestor.secret_id", &secret_id)?;
                validate_id("ancestor.secret", &secret)?;
                validate_range(range_start, range_width)?;
                if input.floor_minute < range_start
                    || input.floor_minute >= range_start.saturating_add(range_width)
                {
                    return Err("ancestor does not cover floor_minute".to_string());
                }
                (secret, secret_id, range_start, range_width)
            }
            AncestorSource::InMinute { .. } => {
                return Err(
                    "chop_time_tree_from_ancestor requires a time-axis ancestor (Root \
                     or TimeInternal)"
                        .to_string(),
                );
            }
        };

    let mut output = ChopTimeTreeFromAncestorOutput::default();
    let mut records: Vec<crate::protocol::event_modules::types::EventRecord> = Vec::new();

    while current_width > 1 {
        if current_start >= input.floor_minute {
            break;
        }
        let current_end = current_start.saturating_add(current_width);
        if current_end <= input.floor_minute {
            break;
        }
        let half = current_width / 2;
        let mid = current_start + half;
        if input.floor_minute >= mid {
            // Left half fully chopped; right half is the boundary continuation.
            let left_event = build_time_split_event(
                input.workspace_id,
                input.removal_frontier_id,
                current_id,
                current_secret,
                current_start,
                current_width,
                0u8,
                current_start,
                half,
            );
            let left_record = codec::record_from_bytes(codec::encode(&left_event))?;
            let left_id = event_id(&left_record.canonical_bytes);
            records.push(left_record);
            output.wipe_path.push(RetireWipeEntry {
                event_id: left_id,
                range_start: current_start,
                range_width: half,
                bit_depth: TIME_TREE_BIT_DEPTH,
                event_id_prefix: [0; 32],
            });
            output.subtree_tombstones_emitted += 1;

            let right_event = build_time_split_event(
                input.workspace_id,
                input.removal_frontier_id,
                current_id,
                current_secret,
                current_start,
                current_width,
                1u8,
                mid,
                half,
            );
            let right_record = codec::record_from_bytes(codec::encode(&right_event))?;
            let right_id = event_id(&right_record.canonical_bytes);
            records.push(right_record);
            output.wipe_path.push(RetireWipeEntry {
                event_id: right_id,
                range_start: mid,
                range_width: half,
                bit_depth: TIME_TREE_BIT_DEPTH,
                event_id_prefix: [0; 32],
            });
            output.boundary_descend_tombstones_emitted += 1;

            current_secret = right_event.node_secret;
            current_id = right_id;
            current_start = mid;
            current_width = half;
        } else {
            // Right half fully survives; left half is the boundary continuation.
            let right_event = build_time_split_event(
                input.workspace_id,
                input.removal_frontier_id,
                current_id,
                current_secret,
                current_start,
                current_width,
                1u8,
                mid,
                half,
            );
            let right_record = codec::record_from_bytes(codec::encode(&right_event))?;
            records.push(right_record);
            output.right_side_siblings_emitted += 1;

            let left_event = build_time_split_event(
                input.workspace_id,
                input.removal_frontier_id,
                current_id,
                current_secret,
                current_start,
                current_width,
                0u8,
                current_start,
                half,
            );
            let left_record = codec::record_from_bytes(codec::encode(&left_event))?;
            let left_id = event_id(&left_record.canonical_bytes);
            records.push(left_record);
            output.wipe_path.push(RetireWipeEntry {
                event_id: left_id,
                range_start: current_start,
                range_width: half,
                bit_depth: TIME_TREE_BIT_DEPTH,
                event_id_prefix: [0; 32],
            });
            output.boundary_descend_tombstones_emitted += 1;

            current_secret = left_event.node_secret;
            current_id = left_id;
            // current_start unchanged (left child starts at parent's start).
            current_width = half;
        }
    }
    let _ = current_secret;
    let _ = current_id;

    Ok(CommandOutput::with_events(output, records))
}

fn validate_id(name: &str, id: &EventId) -> Result<(), String> {
    if id.iter().all(|byte| *byte == 0) {
        return Err(format!("{name} cannot be empty"));
    }
    Ok(())
}

/// Sanity guard for the structural shape of a `(range_start, range_width)`
/// pair: width is a non-zero power of two, and `range_start` aligns to
/// width. Used by command authoring (via the wrapper below) and by the
/// projector through `validate_event_fields`.
pub(super) fn validate_range(range_start: u64, range_width: u64) -> Result<(), String> {
    if range_width == 0 {
        return Err("local history node range width cannot be zero".to_string());
    }
    if !range_width.is_power_of_two() {
        return Err("local history node range width must be a power of two".to_string());
    }
    if !range_start.is_multiple_of(range_width) {
        return Err("local history node range start must align to width".to_string());
    }
    Ok(())
}

/// Sanity guard for `(bit_depth, range_width)`. Trie nodes (bit_depth > 0)
/// only exist under a minute_node, which has range_width=1; time-tree
/// internals have bit_depth=0 and any power-of-two range_width.
pub(super) fn validate_bit_depth(bit_depth: u16, range_width: u64) -> Result<(), String> {
    if bit_depth > TRIE_LEAF_BIT_DEPTH {
        return Err("local history node bit_depth exceeds 256".to_string());
    }
    if bit_depth > 0 && range_width != 1 {
        return Err(
            "local history node bit_depth>0 requires range_width=1 (trie lives under minute_node)"
                .to_string(),
        );
    }
    Ok(())
}

/// Sanity guard for a fully-built `LocalHistoryNodeSecret`. The codec is
/// intentionally lenient on decode; this helper is shared between
/// authoring (the codec's `encode`-time callers below) and the receive
/// projector so a malformed peer event is rejected at projection time too.
pub(super) fn validate_event_fields(event: &LocalHistoryNodeSecret) -> Result<(), String> {
    if event.workspace_id.iter().all(|byte| *byte == 0) {
        return Err("local history node workspace cannot be empty".to_string());
    }
    if event.removal_frontier_id.iter().all(|byte| *byte == 0) {
        return Err("local history node removal_frontier_id cannot be empty".to_string());
    }
    if event.source_secret_id.iter().all(|byte| *byte == 0) {
        return Err("local history node source_secret_id cannot be empty".to_string());
    }
    if event.node_secret.iter().all(|byte| *byte == 0) {
        return Err("local history node material cannot be empty".to_string());
    }
    validate_range(event.range_start, event.range_width)?;
    validate_bit_depth(event.bit_depth, event.range_width)?;
    let masked = mask_prefix_to_depth(event.event_id_prefix, event.bit_depth);
    if masked != event.event_id_prefix {
        return Err("local history node event_id_prefix carries bits past bit_depth".to_string());
    }
    Ok(())
}

/// Parent secret material plus the time-axis range it covers. Used by
/// callers that derive a time-tree split off a source secret identified
/// by `source_secret_id` — either the workspace `local_key_secret`
/// (frontier root) or a previously-materialized
/// `local_history_node_secret`.
#[derive(Debug, Clone)]
pub struct TimeTreeParent {
    pub parent_secret: crypto::XChaCha20Poly1305Key,
    pub parent_range_start: u64,
    pub parent_range_width: u64,
}

/// Resolve a parent secret for `derive_time_split`. The CLI's `key-node`
/// utility uses this to feed `derive_time_split` without re-reading the
/// time-tree state itself.
pub fn load_time_tree_parent(
    store: &Store,
    workspace_id: EventId,
    removal_frontier_id: EventId,
    source_secret_id: EventId,
) -> Result<TimeTreeParent, String> {
    use super::super::local_key_secret;
    if let Some(row) = local_key_secret::queries::get(store, workspace_id, removal_frontier_id)? {
        if row.local_key_secret_id == source_secret_id {
            return Ok(TimeTreeParent {
                parent_secret: row.key_secret,
                parent_range_start: 0,
                parent_range_width: crate::workers::encryption::TIME_TREE_ROOT_WIDTH,
            });
        }
    }
    let node_bytes = event_queries::event_bytes(store, &source_secret_id)
        .map_err(|err| format!("load source event: {err}"))?
        .ok_or_else(|| "history node source event is missing".to_string())?;
    let node = codec::decode(&node_bytes)
        .map_err(|_| "history node source event is not key material".to_string())?;
    let row = queries::get(
        store,
        workspace_id,
        removal_frontier_id,
        node.range_start,
        node.range_width,
        node.bit_depth,
        node.event_id_prefix,
    )?
    .ok_or_else(|| "history node source has been tombstoned".to_string())?;
    Ok(TimeTreeParent {
        parent_secret: row.node_secret,
        parent_range_start: row.range_start,
        parent_range_width: row.range_width,
    })
}

#[cfg(test)]
mod tests {
    use crate::protocol::event_modules::types::EventScope;

    use super::*;

    #[test]
    fn rejects_non_canonical_range() {
        let err = validate_range(3, 8).expect_err("unaligned range must fail");
        assert_eq!(err, "local history node range start must align to width");

        let err = validate_range(0, 7).expect_err("non power of two must fail");
        assert_eq!(err, "local history node range width must be a power of two");
    }

    fn time_input(child_start: u64, child_width: u64, side: u8) -> DeriveTimeSplit {
        DeriveTimeSplit {
            workspace_id: [1; 32],
            removal_frontier_id: [2; 32],
            parent_secret_id: [3; 32],
            parent_secret: [7; 32],
            parent_range_start: 0,
            parent_range_width: u64::MAX,
            child_side: side,
            child_range_start: child_start,
            child_range_width: child_width,
            tombstone_node_id: None,
        }
    }

    #[test]
    fn time_split_proposes_local_secret_with_source_dependency() {
        let output = derive_time_split(time_input(1_700_000, 1, 0)).expect("derive");
        let record = output.events[0].record();

        assert_eq!(record.scope, EventScope::Local);
        assert_eq!(record.workspace_id, Some([1; 32]));
        assert_eq!(record.dependencies, vec![[2; 32], [3; 32]]);
        assert_eq!(
            output.value.local_history_node_secret_id,
            output.events[0].event_id()
        );
    }

    #[test]
    fn time_split_is_deterministic_and_side_sensitive() {
        let left = derive_time_split(time_input(0, 1, 0)).expect("left").value;
        let right_a = derive_time_split(time_input(1, 1, 1))
            .expect("right_a")
            .value;
        let right_b = derive_time_split(time_input(1, 1, 1))
            .expect("right_b")
            .value;

        assert_eq!(
            right_a.local_history_node_secret_id,
            right_b.local_history_node_secret_id
        );
        assert_eq!(right_a.event.node_secret, right_b.event.node_secret);
        assert_ne!(left.event.node_secret, right_a.event.node_secret);
    }

    #[test]
    fn trie_split_is_deterministic_and_prefix_sensitive() {
        let nonce_a = [0x80; 32];
        let nonce_b = [0xff; 32];
        let mk = |coord: EventId| DeriveTrieSplit {
            workspace_id: [1; 32],
            removal_frontier_id: [2; 32],
            parent_secret_id: [3; 32],
            parent_secret: [7; 32],
            range_start: 100,
            parent_bit_depth: 0,
            parent_event_id_prefix: [0; 32],
            child_side: 1,
            child_bit_depth: TRIE_LEAF_BIT_DEPTH,
            child_event_id_prefix: coord,
            tombstone_node_id: None,
        };
        let left = derive_trie_split(mk(nonce_a)).expect("left").value;
        let same = derive_trie_split(mk(nonce_a)).expect("same").value;
        let other = derive_trie_split(mk(nonce_b)).expect("other").value;

        assert_eq!(
            left.local_history_node_secret_id,
            same.local_history_node_secret_id
        );
        assert_eq!(left.event.node_secret, same.event.node_secret);
        assert_ne!(
            left.local_history_node_secret_id,
            other.local_history_node_secret_id
        );
        assert_ne!(left.event.node_secret, other.event.node_secret);
    }
}
