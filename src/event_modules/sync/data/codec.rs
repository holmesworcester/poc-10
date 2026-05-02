use crate::store::EventId;
use crate::wire::{Reader, Writer};

pub const TAG: u8 = 4;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataEvent {
    pub connection_id: EventId,
    pub items: Vec<Vec<u8>>,
}

pub fn encode(event: &DataEvent, out: &mut Writer) {
    out.u8(TAG);
    out.id(&event.connection_id);
    out.u32(event.items.len());
    for item in &event.items {
        out.sized_bytes(item);
    }
}

pub fn decode(reader: &mut Reader<'_>) -> Result<DataEvent, String> {
    let connection_id = reader.id()?;
    let count = reader.u32()? as usize;
    let mut items = Vec::with_capacity(count);
    for _ in 0..count {
        items.push(reader.sized_bytes()?);
    }
    Ok(DataEvent {
        connection_id,
        items,
    })
}
