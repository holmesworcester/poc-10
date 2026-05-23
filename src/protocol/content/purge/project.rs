//! Shared content-purge context coordinates.
//!
//! A deletion fact and the target fact it purges meet on the target's key-tree
//! coordinate, not on the deletion fact's own timestamp or author. The
//! workspace is carried by fact scope; the context key carries the key
//! frontier, target minute, and target fact id so content projectors can
//! exact-match their own purge while key projectors can range-match all purges
//! under a covered frontier/minute span.
//!
//! Core stores these bytes opaquely. Keep changes to this coordinate here and
//! keep authorization in the target-specific deletion projector that emits the
//! offer.
//!
//! POLICY. A content-purge coordinate is valid iff:
//!   1. STRUCTURAL. The role is `content_purged`, the scope is the target
//!      workspace, and the key encodes version, frontier id, target minute, and
//!      target fact id in sort-preserving order.
//!   2. AUTHORITY. This module does not authorize purges. The deletion,
//!      expiry, or retention projector that emits the offer must validate the
//!      target-specific proof before publishing this coordinate.
//!   3. MATCH. Target projectors exact-match their own coordinate; key
//!      projectors range-match frontier/minute spans and then validate any
//!      matched payload they consume.

use crate::core::context::{ContextKey, ContextNeed, ContextOffer, Role};
use crate::core::facts::{FactId, FactScope};

const CONTENT_PURGED_ROLE: &str = "content_purged";
const CONTENT_PURGE_KEY_VERSION: u8 = 1;
const TARGET_PURGE_KEY_BYTES: usize = 1 + 32 + 8 + 32;

pub fn content_purged_role() -> Role {
    Role::expect(CONTENT_PURGED_ROLE)
}

pub fn target_purged_need(
    owner: FactId,
    scope: FactScope,
    frontier_id: FactId,
    target_minute: u64,
    target_fact_id: FactId,
) -> ContextNeed {
    let key = target_purge_key(frontier_id, target_minute, target_fact_id);
    ContextNeed::range(owner, content_purged_role(), scope, key.clone(), key)
}

pub fn target_purged_offer(
    owner: FactId,
    scope: FactScope,
    frontier_id: FactId,
    target_minute: u64,
    target_fact_id: FactId,
) -> ContextOffer {
    let key = target_purge_key(frontier_id, target_minute, target_fact_id);
    ContextOffer::range(owner, content_purged_role(), scope, key.clone(), key)
}

pub fn target_purged_range_need(
    owner: FactId,
    scope: FactScope,
    frontier_id: FactId,
    start_minute: u64,
    end_minute: u64,
) -> ContextNeed {
    ContextNeed::range(
        owner,
        content_purged_role(),
        scope,
        target_purge_key(frontier_id, start_minute, [0; 32]),
        target_purge_key(frontier_id, end_minute, [0xff; 32]),
    )
}

pub fn target_purge_key(
    frontier_id: FactId,
    target_minute: u64,
    target_fact_id: FactId,
) -> Vec<u8> {
    let mut key = Vec::with_capacity(TARGET_PURGE_KEY_BYTES);
    key.push(CONTENT_PURGE_KEY_VERSION);
    key.extend_from_slice(&frontier_id);
    key.extend_from_slice(&target_minute.to_be_bytes());
    key.extend_from_slice(&target_fact_id);
    key
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TargetPurgeKey {
    pub frontier_id: FactId,
    pub target_minute: u64,
    pub target_fact_id: FactId,
}

pub fn decode_target_purge_key(key: &ContextKey) -> Option<TargetPurgeKey> {
    let bytes = key.as_bytes();
    if bytes.len() != TARGET_PURGE_KEY_BYTES || bytes.first().copied()? != CONTENT_PURGE_KEY_VERSION
    {
        return None;
    }
    Some(TargetPurgeKey {
        frontier_id: bytes[1..33].try_into().ok()?,
        target_minute: u64::from_be_bytes(bytes[33..41].try_into().ok()?),
        target_fact_id: bytes[41..73].try_into().ok()?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn purge_keys_sort_by_frontier_then_minute_then_target() {
        let frontier = [4; 32];
        let early = target_purge_key(frontier, 10, [9; 32]);
        let late = target_purge_key(frontier, 11, [1; 32]);
        assert!(early < late);
    }

    #[test]
    fn range_need_spans_targets_inside_minute_range() {
        let scope = FactScope::Local;
        let need = target_purged_range_need([1; 32], scope.clone(), [2; 32], 10, 12);
        let exact = target_purged_offer([3; 32], scope.clone(), [2; 32], 11, [9; 32]);
        assert_eq!(need.role, exact.role);
        assert_eq!(need.scope, scope);
        assert!(need.start_key <= exact.start_key);
        assert!(need.end_key >= exact.end_key);
    }
}
