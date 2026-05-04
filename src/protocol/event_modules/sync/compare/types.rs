use crate::core::store::EventId;

pub const BUCKETS: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BucketSummary {
    pub count: u64,
    pub fingerprint: [u8; 32],
}

impl Default for BucketSummary {
    fn default() -> Self {
        Self {
            count: 0,
            fingerprint: [0; 32],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompareEvent {
    pub connection_id: EventId,
    pub summary: [BucketSummary; BUCKETS],
}
