//! Protocol-wide row tables used by the common event-module worker.
//!
//! Core storage deliberately does not know about Topo events. This file is the
//! protocol side of that boundary: it names the row tables, encodes protocol
//! facts into `TableRow`s, and offers narrow query helpers for workers and CLI
//! commands. Keep new protocol meaning here or in a scoped event-module
//! `tables.rs`; do not push it down into `core::store`.

use crate::core::store::{Store, TableName, TableRow};
use crate::protocol::event_modules::types::{
    event_id, EventId, EventIndexEntry, EventRecord, EventScope, EventStatus, EventStatusCounts,
};

pub const EVENTS: TableName = TableName::new("event_modules.events");
pub const READY_EVENTS: TableName = TableName::new("event_modules.ready_events");
pub const PARTITION_EVENTS: TableName = TableName::new("event_modules.partition_events");
pub const BLOCKED_BY_EVENT: TableName = TableName::new("event_modules.blocked_by_event");
pub const EVENT_BLOCKERS: TableName = TableName::new("event_modules.event_blockers");
pub const EVENT_LABELS: TableName = TableName::new("event_modules.labels");

pub const TABLES: &[TableName] = &[
    EVENTS,
    READY_EVENTS,
    PARTITION_EVENTS,
    BLOCKED_BY_EVENT,
    EVENT_BLOCKERS,
    EVENT_LABELS,
];

const EVENT_ROW_HEADER_BYTES: usize = 8 + 8 + 1 + 1 + 1;
const MAX_LABELS_PER_EVENT: usize = 4096;
const MAX_DEPENDENCY_ROWS_PER_EVENT: usize = 1_000_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventLabel {
    pub event_id: EventId,
    pub label: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct StoredEvent {
    timestamp: u64,
    body_len: usize,
    partition: u8,
    scope: EventScope,
    status: EventStatus,
    canonical_bytes: Vec<u8>,
}

pub fn insert_event(
    store: &Store,
    event: &EventRecord,
    status: EventStatus,
) -> rusqlite::Result<bool> {
    let id = event_id(&event.canonical_bytes);
    if store.table_row(EVENTS, &id)?.is_some() {
        return Ok(false);
    }

    let mut rows = vec![event_row(&id, event, status)];
    if status == EventStatus::Ready {
        rows.push(ready_row(event.timestamp, &id));
    }
    if event.scope == EventScope::Shared {
        rows.push(partition_row(id[0], &id));
    }
    store.insert_table_rows_in_tx(rows)?;
    Ok(true)
}

pub fn event_is_applied(store: &Store, event_id: &EventId) -> rusqlite::Result<bool> {
    read_event(store, event_id).map(|event| {
        event
            .map(|event| event.status == EventStatus::Applied)
            .unwrap_or(false)
    })
}

pub fn insert_dependency_wait(
    store: &Store,
    blocked_by_event_id: &EventId,
    event_id: &EventId,
) -> rusqlite::Result<bool> {
    let primary = wait_row(BLOCKED_BY_EVENT, blocked_by_event_id, event_id);
    let inserted = store.insert_table_rows_in_tx(vec![primary])? > 0;
    store.insert_table_rows_in_tx(vec![wait_row(
        EVENT_BLOCKERS,
        event_id,
        blocked_by_event_id,
    )])?;
    Ok(inserted)
}

pub fn next_ready_event(store: &Store) -> rusqlite::Result<Option<EventId>> {
    let mut rows = store.table_rows_with_key_prefix(READY_EVENTS, &[], 1)?;
    let Some((_, value)) = rows.pop() else {
        return Ok(None);
    };
    vec_to_id(value).map(Some)
}

pub fn set_event_status(
    store: &Store,
    event_id: &EventId,
    from: EventStatus,
    to: EventStatus,
) -> rusqlite::Result<bool> {
    let Some(mut event) = read_event(store, event_id)? else {
        return Ok(false);
    };
    if event.status != from {
        return Ok(false);
    }

    let old_ready_key = (from == EventStatus::Ready).then(|| ready_key(event.timestamp, event_id));
    event.status = to;
    let mut rows = vec![stored_event_row(event_id, &event)];
    if to == EventStatus::Ready {
        rows.push(ready_row(event.timestamp, event_id));
    }

    store.replace_table_rows_in_tx(rows)?;
    if let Some(key) = old_ready_key {
        store.delete_table_rows_in_tx(READY_EVENTS, vec![key])?;
    }
    Ok(true)
}

pub fn delete_dependency_waits_for(
    store: &Store,
    blocked_by_event_id: &EventId,
) -> rusqlite::Result<usize> {
    let rows = store.table_rows_with_key_prefix(
        BLOCKED_BY_EVENT,
        blocked_by_event_id,
        MAX_DEPENDENCY_ROWS_PER_EVENT,
    )?;
    let mut blocked_keys = Vec::with_capacity(rows.len());
    let mut reverse_keys = Vec::with_capacity(rows.len());
    for (key, _) in rows {
        let (blocked_by, event_id) = split_wait_key(&key)?;
        blocked_keys.push(key);
        reverse_keys.push(wait_key(&event_id, &blocked_by));
    }
    let deleted = store.delete_table_rows_in_tx(BLOCKED_BY_EVENT, blocked_keys)?;
    store.delete_table_rows_in_tx(EVENT_BLOCKERS, reverse_keys)?;
    Ok(deleted)
}

pub fn events_waiting_on(
    store: &Store,
    blocked_by_event_id: &EventId,
) -> rusqlite::Result<Vec<EventId>> {
    store
        .table_rows_with_key_prefix(
            BLOCKED_BY_EVENT,
            blocked_by_event_id,
            MAX_DEPENDENCY_ROWS_PER_EVENT,
        )?
        .into_iter()
        .map(|(key, _)| split_wait_key(&key).map(|(_, event_id)| event_id))
        .collect()
}

pub fn event_has_dependency_waits(store: &Store, event_id: &EventId) -> rusqlite::Result<bool> {
    store
        .table_rows_with_key_prefix(EVENT_BLOCKERS, event_id, 1)
        .map(|rows| !rows.is_empty())
}

pub fn max_timestamp(store: &Store) -> rusqlite::Result<u64> {
    Ok(shared_events(store)?
        .into_iter()
        .map(|(_, event)| event.timestamp)
        .max()
        .unwrap_or(0))
}

pub fn event_count(store: &Store) -> rusqlite::Result<usize> {
    shared_events(store).map(|events| events.len())
}

pub fn status_counts(store: &Store) -> rusqlite::Result<EventStatusCounts> {
    let mut counts = EventStatusCounts::default();
    for (_, event) in shared_events(store)? {
        match event.status {
            EventStatus::Ready => counts.ready += 1,
            EventStatus::Blocked => counts.blocked += 1,
            EventStatus::Applied => counts.applied += 1,
            EventStatus::Rejected => counts.rejected += 1,
        }
    }
    counts.blocked_edges = store.table_row_count(BLOCKED_BY_EVENT)?;
    Ok(counts)
}

pub fn body_bytes(store: &Store) -> rusqlite::Result<usize> {
    Ok(shared_events(store)?
        .into_iter()
        .map(|(_, event)| event.body_len)
        .sum())
}

pub fn event_index_entries(store: &Store) -> rusqlite::Result<Vec<EventIndexEntry>> {
    store
        .table_rows(PARTITION_EVENTS)?
        .into_iter()
        .map(|(key, _)| {
            let (partition, event_id) = split_partition_key(&key)?;
            Ok(EventIndexEntry {
                event_id,
                partition,
            })
        })
        .collect()
}

pub fn event_ids_in_partition(store: &Store, partition: u8) -> rusqlite::Result<Vec<EventId>> {
    store
        .table_rows_with_key_prefix(
            PARTITION_EVENTS,
            &[partition],
            MAX_DEPENDENCY_ROWS_PER_EVENT,
        )?
        .into_iter()
        .map(|(key, _)| split_partition_key(&key).map(|(_, event_id)| event_id))
        .collect()
}

pub fn has_event(store: &Store, event_id: &EventId) -> rusqlite::Result<bool> {
    store.table_row(EVENTS, event_id).map(|row| row.is_some())
}

pub fn has_shared_event(store: &Store, event_id: &EventId) -> rusqlite::Result<bool> {
    read_event(store, event_id).map(|event| {
        event
            .map(|event| event.scope == EventScope::Shared)
            .unwrap_or(false)
    })
}

pub fn event_bytes(store: &Store, event_id: &EventId) -> rusqlite::Result<Option<Vec<u8>>> {
    read_event(store, event_id).map(|event| event.map(|event| event.canonical_bytes))
}

pub fn shared_event_bytes(store: &Store, event_id: &EventId) -> rusqlite::Result<Option<Vec<u8>>> {
    read_event(store, event_id).map(|event| {
        event.and_then(|event| (event.scope == EventScope::Shared).then_some(event.canonical_bytes))
    })
}

pub fn event_label_rows(labels: Vec<EventLabel>) -> Vec<TableRow> {
    labels
        .into_iter()
        .map(|label| TableRow {
            table: EVENT_LABELS,
            key: event_label_key(&label.event_id, &label.label),
            value: label.label,
        })
        .collect()
}

pub fn event_labels(store: &Store, event_id: &EventId) -> Result<Vec<Vec<u8>>, String> {
    store
        .table_rows_with_key_prefix(EVENT_LABELS, event_id, MAX_LABELS_PER_EVENT)
        .map_err(|err| format!("load event labels: {err}"))
        .map(|rows| rows.into_iter().map(|(_, label)| label).collect())
}

fn shared_events(store: &Store) -> rusqlite::Result<Vec<(EventId, StoredEvent)>> {
    store
        .table_rows(EVENTS)?
        .into_iter()
        .filter_map(|(key, value)| match decode_event_row_value(&value) {
            Ok(event) if event.scope == EventScope::Shared => {
                Some(vec_to_id(key).map(|id| (id, event)))
            }
            Ok(_) => None,
            Err(err) => Some(Err(err)),
        })
        .collect()
}

fn read_event(store: &Store, event_id: &EventId) -> rusqlite::Result<Option<StoredEvent>> {
    store
        .table_row(EVENTS, event_id)?
        .map(|value| decode_event_row_value(&value))
        .transpose()
}

fn event_row(event_id: &EventId, event: &EventRecord, status: EventStatus) -> TableRow {
    TableRow {
        table: EVENTS,
        key: event_id.to_vec(),
        value: encode_event_row_value(
            event.timestamp,
            event.body_len,
            event_id[0],
            event.scope,
            status,
            &event.canonical_bytes,
        ),
    }
}

fn stored_event_row(event_id: &EventId, event: &StoredEvent) -> TableRow {
    TableRow {
        table: EVENTS,
        key: event_id.to_vec(),
        value: encode_event_row_value(
            event.timestamp,
            event.body_len,
            event.partition,
            event.scope,
            event.status,
            &event.canonical_bytes,
        ),
    }
}

fn ready_row(timestamp: u64, event_id: &EventId) -> TableRow {
    TableRow {
        table: READY_EVENTS,
        key: ready_key(timestamp, event_id),
        value: event_id.to_vec(),
    }
}

fn partition_row(partition: u8, event_id: &EventId) -> TableRow {
    TableRow {
        table: PARTITION_EVENTS,
        key: partition_key(partition, event_id),
        value: Vec::new(),
    }
}

fn wait_row(table: TableName, first: &EventId, second: &EventId) -> TableRow {
    TableRow {
        table,
        key: wait_key(first, second),
        value: Vec::new(),
    }
}

fn encode_event_row_value(
    timestamp: u64,
    body_len: usize,
    partition: u8,
    scope: EventScope,
    status: EventStatus,
    canonical_bytes: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(EVENT_ROW_HEADER_BYTES + canonical_bytes.len());
    out.extend_from_slice(&timestamp.to_be_bytes());
    out.extend_from_slice(&(body_len as u64).to_be_bytes());
    out.push(partition);
    out.push(scope.as_u8());
    out.push(status.as_u8());
    out.extend_from_slice(canonical_bytes);
    out
}

fn decode_event_row_value(value: &[u8]) -> rusqlite::Result<StoredEvent> {
    if value.len() < EVENT_ROW_HEADER_BYTES {
        return Err(table_error(format!(
            "event row is truncated: {} bytes",
            value.len()
        )));
    }
    let mut offset = 0;
    let timestamp = read_u64(value, &mut offset)?;
    let body_len = read_u64(value, &mut offset)? as usize;
    let partition = read_u8(value, &mut offset)?;
    let scope = EventScope::from_u8(read_u8(value, &mut offset)?).map_err(table_error)?;
    let status = EventStatus::from_u8(read_u8(value, &mut offset)?).map_err(table_error)?;
    let canonical_bytes = value[offset..].to_vec();
    Ok(StoredEvent {
        timestamp,
        body_len,
        partition,
        scope,
        status,
        canonical_bytes,
    })
}

fn read_u64(bytes: &[u8], offset: &mut usize) -> rusqlite::Result<u64> {
    let end = offset
        .checked_add(8)
        .ok_or_else(|| table_error("event row offset overflow".to_string()))?;
    let value = bytes
        .get(*offset..end)
        .ok_or_else(|| table_error("event row is truncated".to_string()))?
        .try_into()
        .expect("slice length checked");
    *offset = end;
    Ok(u64::from_be_bytes(value))
}

fn read_u8(bytes: &[u8], offset: &mut usize) -> rusqlite::Result<u8> {
    let value = *bytes
        .get(*offset)
        .ok_or_else(|| table_error("event row is truncated".to_string()))?;
    *offset += 1;
    Ok(value)
}

fn ready_key(timestamp: u64, event_id: &EventId) -> Vec<u8> {
    let mut key = Vec::with_capacity(8 + event_id.len());
    key.extend_from_slice(&timestamp.to_be_bytes());
    key.extend_from_slice(event_id);
    key
}

fn partition_key(partition: u8, event_id: &EventId) -> Vec<u8> {
    let mut key = Vec::with_capacity(1 + event_id.len());
    key.push(partition);
    key.extend_from_slice(event_id);
    key
}

fn split_partition_key(key: &[u8]) -> rusqlite::Result<(u8, EventId)> {
    if key.len() != 33 {
        return Err(table_error(format!(
            "partition key should be 33 bytes, got {}",
            key.len()
        )));
    }
    Ok((key[0], vec_to_id(key[1..].to_vec())?))
}

fn wait_key(first: &EventId, second: &EventId) -> Vec<u8> {
    let mut key = Vec::with_capacity(64);
    key.extend_from_slice(first);
    key.extend_from_slice(second);
    key
}

fn split_wait_key(key: &[u8]) -> rusqlite::Result<(EventId, EventId)> {
    if key.len() != 64 {
        return Err(table_error(format!(
            "dependency key should be 64 bytes, got {}",
            key.len()
        )));
    }
    Ok((
        vec_to_id(key[..32].to_vec())?,
        vec_to_id(key[32..].to_vec())?,
    ))
}

fn event_label_key(event_id: &EventId, label: &[u8]) -> Vec<u8> {
    let mut key = Vec::with_capacity(event_id.len() + label.len());
    key.extend_from_slice(event_id);
    key.extend_from_slice(label);
    key
}

fn vec_to_id(bytes: Vec<u8>) -> rusqlite::Result<EventId> {
    bytes.try_into().map_err(|bytes: Vec<u8>| {
        table_error(format!("expected 32-byte event id, got {}", bytes.len()))
    })
}

fn table_error(err: String) -> rusqlite::Error {
    rusqlite::Error::InvalidParameterName(err)
}
