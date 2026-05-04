//! Codec for need-id sync items.
//!
//! A need-id item asks the peer to send bytes for exactly one event id. The
//! response path dedupes requested ids before building data frames.

use crate::protocol::wire::{Reader, Writer};

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
