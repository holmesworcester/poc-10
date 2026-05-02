use crate::wire::{Reader, Writer};

use super::super::{compare, data, have_id, need_id};

const MAGIC: &[u8; 9] = b"TOPOSYNC1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub more: bool,
    pub items: Vec<SyncItem>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncItem {
    Compare(compare::codec::CompareEvent),
    HaveId(have_id::codec::HaveIdEvent),
    NeedId(need_id::codec::NeedIdEvent),
    Data(data::codec::DataEvent),
}

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
            compare::codec::TAG => SyncItem::Compare(compare::codec::decode(&mut reader)?),
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
