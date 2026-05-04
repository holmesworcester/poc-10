use crate::core::store::Store;
use crate::protocol::event_modules::tables as event_tables;
use crate::protocol::event_modules::types::EventId;

use super::types::{BucketSummary, BUCKETS};

pub trait ReadContext {
    fn summary(&self) -> Result<[BucketSummary; BUCKETS], String>;
    fn ids_in_bucket(&self, bucket: u8) -> Result<Vec<EventId>, String>;
    fn has_event(&self, event_id: &EventId) -> Result<bool, String>;
    fn event_byte(&self, id: &EventId) -> Result<Option<Vec<u8>>, String>;
}

impl ReadContext for Store {
    fn summary(&self) -> Result<[BucketSummary; BUCKETS], String> {
        summary(self)
    }

    fn ids_in_bucket(&self, bucket: u8) -> Result<Vec<EventId>, String> {
        ids_in_bucket(self, bucket)
    }

    fn has_event(&self, event_id: &EventId) -> Result<bool, String> {
        has_event(self, event_id)
    }

    fn event_byte(&self, id: &EventId) -> Result<Option<Vec<u8>>, String> {
        event_byte(self, id)
    }
}

pub fn summary(store: &Store) -> Result<[BucketSummary; BUCKETS], String> {
    let mut summary = [BucketSummary::default(); BUCKETS];
    for header in event_tables::event_index_entries(store)
        .map_err(|err| format!("load event headers: {err}"))?
    {
        let bucket = &mut summary[usize::from(header.partition)];
        bucket.count += 1;
        xor_into(&mut bucket.fingerprint, &fingerprint_id(&header.event_id));
    }
    Ok(summary)
}

pub fn ids_in_bucket(store: &Store, bucket: u8) -> Result<Vec<EventId>, String> {
    event_tables::event_ids_in_partition(store, bucket)
        .map_err(|err| format!("load bucket ids: {err}"))
}

pub fn has_event(store: &Store, event_id: &EventId) -> Result<bool, String> {
    event_tables::has_shared_event(store, event_id)
        .map_err(|err| format!("check event presence: {err}"))
}

pub fn event_byte(store: &Store, id: &EventId) -> Result<Option<Vec<u8>>, String> {
    event_tables::shared_event_bytes(store, id).map_err(|err| format!("load event bytes: {err}"))
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
