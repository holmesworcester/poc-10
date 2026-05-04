//! Pure compare helpers.
//!
//! The compare event has no row projection of its own. This helper identifies
//! bucket summaries that differ, leaving query and response construction to the
//! sync command path.

use super::types::{BucketSummary, BUCKETS};

pub fn differing_buckets(
    local: &[BucketSummary; BUCKETS],
    remote: &[BucketSummary; BUCKETS],
) -> Vec<u8> {
    local
        .iter()
        .zip(remote.iter())
        .enumerate()
        .filter_map(|(idx, (left, right))| (left != right).then_some(idx as u8))
        .collect()
}
