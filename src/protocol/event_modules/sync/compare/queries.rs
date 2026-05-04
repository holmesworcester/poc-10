//! Read-only sync context.
//!
//! The sync command is written against `ReadContext` so its algorithm does not
//! depend on SQLite. The store implementation below derives summaries from the
//! protocol-wide event indexes: bucket count plus XOR fingerprint. That summary
//! is intentionally compact and order-independent.

use crate::core::store::Store;
use crate::protocol::event_modules::schema as event_schema;
use crate::protocol::event_modules::types::EventId;

use super::types::{BucketSummary, BUCKETS};

pub trait ReadContext {
    /// Summarize every shared event bucket.
    fn summary(&self) -> Result<[BucketSummary; BUCKETS], String>;
    /// Enumerate ids in one bucket when summaries differ.
    fn ids_in_bucket(&self, bucket: u8) -> Result<Vec<EventId>, String>;
    /// Check whether an advertised id is already present locally.
    fn has_event(&self, event_id: &EventId) -> Result<bool, String>;
    /// Load event bytes requested by a peer.
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
    for header in event_schema::event_index_entries(store)
        .map_err(|err| format!("load event headers: {err}"))?
    {
        let bucket = &mut summary[usize::from(header.partition)];
        bucket.count += 1;
        xor_into(&mut bucket.fingerprint, &fingerprint_id(&header.event_id));
    }
    Ok(summary)
}

pub fn ids_in_bucket(store: &Store, bucket: u8) -> Result<Vec<EventId>, String> {
    event_schema::event_ids_in_partition(store, bucket)
        .map_err(|err| format!("load bucket ids: {err}"))
}

pub fn has_event(store: &Store, event_id: &EventId) -> Result<bool, String> {
    event_schema::has_shared_event(store, event_id)
        .map_err(|err| format!("check event presence: {err}"))
}

pub fn event_byte(store: &Store, id: &EventId) -> Result<Option<Vec<u8>>, String> {
    event_schema::shared_event_bytes(store, id).map_err(|err| format!("load event bytes: {err}"))
}

fn fingerprint_id(id: &EventId) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"sync-event-id:");
    hasher.update(id);
    *hasher.finalize().as_bytes()
}

fn xor_into(target: &mut [u8; 32], value: &[u8; 32]) {
    // XOR fingerprints are not a proof of equality, but they are cheap and
    // deterministic. The protocol falls back to id exchange for differing
    // buckets, so collisions only risk extra work in this POC.
    for (left, right) in target.iter_mut().zip(value.iter()) {
        *left ^= *right;
    }
}
