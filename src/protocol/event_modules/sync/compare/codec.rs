//! Codec for compare sync items.
//!
//! A compare item carries one connection id and a fixed array of bucket
//! summaries. It is not a top-level event by itself; the frame codec embeds it
//! inside a transient sync frame event.

use crate::protocol::wire::{Reader, Writer};

use super::types::{BucketSummary, CompareEvent, BUCKETS};

pub const TAG: u8 = 1;

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
