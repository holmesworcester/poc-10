//! Compare event types.
//!
//! The bucket count is fixed so compare events have predictable shape. A bucket
//! summary is the minimal answer to "are we the same for this range?" in the
//! current POC: count plus fingerprint.

use crate::protocol::event_modules::sync::types::SyncDirection;
use crate::protocol::event_modules::types::EventId;

pub const BUCKETS: usize = 256;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BucketSummary {
    pub count: u64,
    pub fingerprint: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompareEvent {
    pub direction: SyncDirection,
    pub connection_id: EventId,
    pub summary: [BucketSummary; BUCKETS],
}
