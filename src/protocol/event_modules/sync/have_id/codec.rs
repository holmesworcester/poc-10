use crate::core::wire::{Reader, Writer};

use super::types::HaveIdEvent;

pub const TAG: u8 = 2;
pub fn encode(event: &HaveIdEvent, out: &mut Writer) {
    out.u8(TAG);
    out.id(&event.connection_id);
    out.u8(event.bucket);
    out.id(&event.id);
}

pub fn decode(reader: &mut Reader<'_>) -> Result<HaveIdEvent, String> {
    Ok(HaveIdEvent {
        connection_id: reader.id()?,
        bucket: reader.u8()?,
        id: reader.id()?,
    })
}
