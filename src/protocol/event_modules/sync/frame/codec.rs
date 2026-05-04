//! Codec for transient sync frame events.
//!
//! Outbound frame events are the bytes sent inside connection transit. Inbound
//! frame events wrap those same bytes with a local-only prefix after transit has
//! been unwrapped. That distinction keeps projection row-only: outbound frames
//! project to the connection outbox, while inbound frames project to sync work.

use crate::protocol::event_modules::types::{EventRecord, EventScope};
use crate::protocol::wire::{Reader, Writer};

use super::super::{compare, data, have_id, need_id};
use super::types::{Frame, SyncItem};

const MAGIC: &[u8; 9] = b"TOPOSYNC1";
const INBOUND_MAGIC: &[u8; 9] = b"TOPOSYNI1";

pub fn encode(frame: &Frame) -> Vec<u8> {
    let mut out = Writer::new();
    out.raw(MAGIC);
    out.u8(u8::from(frame.more));
    out.u32(frame.items.len());
    for item in &frame.items {
        match item {
            SyncItem::Compare(event) => compare::codec::encode(event, &mut out),
            SyncItem::HaveId(event) => have_id::codec::encode(event, &mut out),
            SyncItem::NeedId(event) => need_id::codec::encode(event, &mut out),
            SyncItem::Data(event) => data::codec::encode(event, &mut out),
        }
    }
    out.finish()
}

pub fn decode(bytes: &[u8]) -> Result<Frame, String> {
    let bytes = raw_frame_bytes(bytes)?;
    if !bytes.starts_with(MAGIC) {
        return Err("not a sync frame".to_string());
    }
    let mut reader = Reader::new(&bytes[MAGIC.len()..], "sync frame");
    let more = match reader.u8()? {
        0 => false,
        1 => true,
        other => return Err(format!("invalid sync frame continuation flag {other}")),
    };
    let item_count = reader.u32()? as usize;
    let mut items = Vec::with_capacity(item_count);
    for _ in 0..item_count {
        let item = match reader.u8()? {
            compare::codec::TAG => {
                SyncItem::Compare(Box::new(compare::codec::decode(&mut reader)?))
            }
            have_id::codec::TAG => SyncItem::HaveId(have_id::codec::decode(&mut reader)?),
            need_id::codec::TAG => SyncItem::NeedId(need_id::codec::decode(&mut reader)?),
            data::codec::TAG => SyncItem::Data(data::codec::decode(&mut reader)?),
            other => return Err(format!("unknown sync item tag {other}")),
        };
        items.push(item);
    }
    reader.finish()?;
    Ok(Frame { more, items })
}

pub fn is_frame(bytes: &[u8]) -> bool {
    bytes.starts_with(MAGIC) || bytes.starts_with(INBOUND_MAGIC)
}

pub fn is_inbound_frame(bytes: &[u8]) -> bool {
    bytes.starts_with(INBOUND_MAGIC)
}

pub fn connection_id(
    bytes: &[u8],
) -> Result<crate::protocol::event_modules::types::EventId, String> {
    let frame = decode(bytes)?;
    let mut connection_id = None;
    for item in frame.items {
        let item_connection_id = match item {
            SyncItem::Compare(event) => event.connection_id,
            SyncItem::HaveId(event) => event.connection_id,
            SyncItem::NeedId(event) => event.connection_id,
            SyncItem::Data(event) => event.connection_id,
        };
        if let Some(existing) = connection_id {
            if existing != item_connection_id {
                return Err("sync frame mixed connection ids".to_string());
            }
        } else {
            connection_id = Some(item_connection_id);
        }
    }
    connection_id.ok_or_else(|| "sync frame has no items".to_string())
}

pub fn record_from_bytes(bytes: Vec<u8>) -> Result<EventRecord, String> {
    connection_id(&bytes)?;
    Ok(EventRecord {
        timestamp: 0,
        body_len: 0,
        canonical_bytes: bytes,
        dependencies: Vec::new(),
        scope: EventScope::Transient,
    })
}

pub fn inbound_record_from_frame(bytes: Vec<u8>) -> Result<EventRecord, String> {
    connection_id(&bytes)?;
    let mut canonical_bytes = Vec::with_capacity(INBOUND_MAGIC.len() + bytes.len());
    canonical_bytes.extend_from_slice(INBOUND_MAGIC);
    canonical_bytes.extend_from_slice(&bytes);
    record_from_bytes(canonical_bytes)
}

pub fn raw_frame_bytes(bytes: &[u8]) -> Result<&[u8], String> {
    if bytes.starts_with(INBOUND_MAGIC) {
        return Ok(&bytes[INBOUND_MAGIC.len()..]);
    }
    if bytes.starts_with(MAGIC) {
        return Ok(bytes);
    }
    Err("not a sync frame".to_string())
}
