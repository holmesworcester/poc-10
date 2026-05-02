use crate::wire::{Reader, Writer};

use super::types::NeedIdEvent;

pub const TAG: u8 = 3;
pub fn encode(event: &NeedIdEvent, out: &mut Writer) {
    out.u8(TAG);
    out.id(&event.connection_id);
    out.id(&event.id);
}

pub fn decode(reader: &mut Reader<'_>) -> Result<NeedIdEvent, String> {
    Ok(NeedIdEvent {
        connection_id: reader.id()?,
        id: reader.id()?,
    })
}
