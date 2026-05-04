//! Codec for have-id sync items.
//!
//! A have-id item advertises one event id in one bucket. It is cheap to
//! duplicate and cheap to dedupe, which is why it can remain a simple item
//! inside a transient sync frame.

use crate::protocol::wire::{Reader, Writer};

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
