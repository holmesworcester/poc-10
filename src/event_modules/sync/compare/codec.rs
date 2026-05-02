use crate::store::EventId;
use crate::wire::{Reader, Writer};

pub const TAG: u8 = 1;
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

pub fn encode(event: &CompareEvent, out: &mut Writer) {
    out.u8(TAG);
    out.id(&event.connection_id);
    for bucket in &event.summary {
        out.u64(bucket.count);
        out.id(&bucket.fingerprint);
    }
}

pub fn decode(reader: &mut Reader<'_>) -> Result<CompareEvent, String> {
    let connection_id = reader.id()?;
    let mut summary = [BucketSummary::default(); BUCKETS];
    for bucket in &mut summary {
        bucket.count = reader.u64()?;
        bucket.fingerprint = reader.id()?;
    }
    Ok(CompareEvent {
        connection_id,
        summary,
    })
}
