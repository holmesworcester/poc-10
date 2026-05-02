use crate::store::{EventId, Store};

use super::types::{BucketSummary, BUCKETS};

pub fn summary(store: &Store) -> Result<[BucketSummary; BUCKETS], String> {
    let mut summary = [BucketSummary::default(); BUCKETS];
    for header in store
        .headers()
        .map_err(|err| format!("load event headers: {err}"))?
    {
        let bucket = &mut summary[usize::from(header.bucket)];
        bucket.count += 1;
        xor_into(&mut bucket.fingerprint, &fingerprint_id(&header.event_id));
    }
    Ok(summary)
}

pub fn ids_in_bucket(store: &Store, bucket: u8) -> Result<Vec<EventId>, String> {
    store
        .ids_in_bucket(bucket)
        .map_err(|err| format!("load bucket ids: {err}"))
}

pub fn has_event(store: &Store, event_id: &EventId) -> Result<bool, String> {
    store
        .has_event(event_id)
        .map_err(|err| format!("check event presence: {err}"))
}

pub fn event_byte(store: &Store, id: &EventId) -> Result<Option<Vec<u8>>, String> {
    store
        .event_bytes(id)
        .map_err(|err| format!("load event bytes: {err}"))
}

fn fingerprint_id(id: &EventId) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"sync-event-id:");
    hasher.update(id);
    *hasher.finalize().as_bytes()
}

fn xor_into(target: &mut [u8; 32], value: &[u8; 32]) {
    for (left, right) in target.iter_mut().zip(value.iter()) {
        *left ^= *right;
    }
}
