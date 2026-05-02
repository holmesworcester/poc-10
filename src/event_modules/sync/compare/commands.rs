use crate::store::{EventId, Store};

use super::super::data::types::DataEvent;
use super::super::frame::codec as frame_codec;
use super::super::frame::types::{Frame, SyncItem};
use super::super::have_id::types::HaveIdEvent;
use super::super::need_id::types::NeedIdEvent;
use super::types::{BucketSummary, CompareEvent, BUCKETS};
use super::{projector, queries};

const FRAME_TARGET_BYTES: usize = 32 * 1024 * 1024;
const FRAME_HEADER_BYTES: usize = 14;
const DATA_ITEM_HEADER_BYTES: usize = 1 + 32 + 4;
const DATA_ENTRY_BYTES: usize = 4;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SyncReport {
    pub sent_events: usize,
    pub received_events: usize,
    pub received_event_bytes: Vec<Vec<u8>>,
}

pub fn start(
    store: &Store,
    connection_id: EventId,
    mut emit: impl FnMut(Vec<u8>) -> Result<(), String>,
) -> Result<SyncReport, String> {
    let mut items = vec![SyncItem::Compare(CompareEvent {
        connection_id,
        summary: queries::summary(store)?,
    })];
    items.extend(all_have_items(store, connection_id)?);
    emit_items(items, &mut emit)?;
    Ok(SyncReport::default())
}

pub fn ingest_frame(
    store: &Store,
    expected_connection_id: EventId,
    bytes: &[u8],
    mut emit: impl FnMut(Vec<u8>) -> Result<(), String>,
) -> Result<SyncReport, String> {
    let frame = frame_codec::decode(bytes)?;
    let mut frame_connection_id = None;
    let mut response_items = Vec::new();
    let mut requested_ids = Vec::new();
    let mut received_events = 0;
    let mut received_event_bytes = Vec::new();

    for item in frame.items {
        match item {
            SyncItem::Compare(event) => {
                observe_connection(&mut frame_connection_id, event.connection_id)?;
                let local = queries::summary(store)?;
                if local != event.summary {
                    response_items.extend(have_items_for_compare(
                        store,
                        event.connection_id,
                        local,
                        event.summary,
                    )?);
                }
            }
            SyncItem::HaveId(event) => {
                observe_connection(&mut frame_connection_id, event.connection_id)?;
                if !queries::has_event(store, &event.id)? {
                    response_items.push(SyncItem::NeedId(NeedIdEvent {
                        connection_id: event.connection_id,
                        id: event.id,
                    }));
                }
            }
            SyncItem::NeedId(event) => {
                observe_connection(&mut frame_connection_id, event.connection_id)?;
                requested_ids.push(event.id);
            }
            SyncItem::Data(mut event) => {
                observe_connection(&mut frame_connection_id, event.connection_id)?;
                received_events += event.items.len();
                received_event_bytes.append(&mut event.items);
            }
        }
    }

    let Some(connection_id) = frame_connection_id else {
        return Ok(SyncReport::default());
    };
    if connection_id != expected_connection_id {
        return Err("sync frame used a different connection id".to_string());
    }
    let sent_events = emit_control_and_requested_data(
        store,
        connection_id,
        response_items,
        &requested_ids,
        &mut emit,
    )?;

    Ok(SyncReport {
        sent_events,
        received_events,
        received_event_bytes,
    })
}

fn observe_connection(
    frame_connection_id: &mut Option<EventId>,
    connection_id: EventId,
) -> Result<(), String> {
    if let Some(existing) = frame_connection_id {
        if *existing != connection_id {
            return Err("sync frame mixed connection ids".to_string());
        }
    } else {
        *frame_connection_id = Some(connection_id);
    }
    Ok(())
}

fn all_have_items(store: &Store, connection_id: EventId) -> Result<Vec<SyncItem>, String> {
    let mut items = Vec::new();
    for bucket in 0..BUCKETS {
        let ids = queries::ids_in_bucket(store, bucket as u8)?;
        for id in ids {
            items.push(SyncItem::HaveId(HaveIdEvent {
                connection_id,
                bucket: bucket as u8,
                id,
            }));
        }
    }
    Ok(items)
}

fn have_items_for_compare(
    store: &Store,
    connection_id: EventId,
    local: [BucketSummary; BUCKETS],
    remote: [BucketSummary; BUCKETS],
) -> Result<Vec<SyncItem>, String> {
    let mut items = Vec::new();
    for bucket in projector::differing_buckets(&local, &remote) {
        let ids = queries::ids_in_bucket(store, bucket)?;
        for id in ids {
            items.push(SyncItem::HaveId(HaveIdEvent {
                connection_id,
                bucket,
                id,
            }));
        }
    }
    Ok(items)
}

fn emit_control_and_requested_data(
    store: &Store,
    connection_id: EventId,
    control_items: Vec<SyncItem>,
    requested_ids: &[EventId],
    emit: &mut impl FnMut(Vec<u8>) -> Result<(), String>,
) -> Result<usize, String> {
    if requested_ids.is_empty() {
        emit_items(control_items, emit)?;
        return Ok(0);
    }

    let mut ids = requested_ids.to_vec();
    ids.sort();
    ids.dedup();

    let mut sent = 0;
    let mut pending_control = control_items;
    let mut data_items = Vec::new();
    let mut encoded_len = FRAME_HEADER_BYTES + DATA_ITEM_HEADER_BYTES;

    for id in ids {
        let Some(item) = queries::event_byte(store, &id)? else {
            continue;
        };
        let entry_len = DATA_ENTRY_BYTES + item.len();
        if entry_len > FRAME_TARGET_BYTES {
            return Err(format!(
                "event is too large for a sync data frame: {} bytes",
                item.len()
            ));
        }
        if !data_items.is_empty() && encoded_len + entry_len > FRAME_TARGET_BYTES {
            sent += emit_frame(
                std::mem::take(&mut pending_control),
                connection_id,
                std::mem::take(&mut data_items),
                true,
                emit,
            )?;
            encoded_len = FRAME_HEADER_BYTES + DATA_ITEM_HEADER_BYTES;
        }
        encoded_len += entry_len;
        data_items.push(item);
    }

    if data_items.is_empty() {
        emit_items(pending_control, emit)?;
    } else {
        sent += emit_frame(pending_control, connection_id, data_items, false, emit)?;
    }
    Ok(sent)
}

fn emit_items(
    items: Vec<SyncItem>,
    emit: &mut impl FnMut(Vec<u8>) -> Result<(), String>,
) -> Result<(), String> {
    if items.is_empty() {
        return Ok(());
    }
    emit(frame_codec::encode(&Frame { more: false, items }))
}

fn emit_frame(
    control_items: Vec<SyncItem>,
    connection_id: EventId,
    data_items: Vec<Vec<u8>>,
    more: bool,
    emit: &mut impl FnMut(Vec<u8>) -> Result<(), String>,
) -> Result<usize, String> {
    let sent = data_items.len();
    let mut items = control_items;
    items.push(SyncItem::Data(DataEvent {
        connection_id,
        items: data_items,
    }));
    emit(frame_codec::encode(&Frame { more, items }))?;
    Ok(sent)
}
