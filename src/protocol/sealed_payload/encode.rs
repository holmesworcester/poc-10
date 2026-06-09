use crate::core::wire;

use super::fact::{validate_payload, SealedPayloadFact, CIPHERTEXT_BYTES, HEADER_BYTES};

pub const TYPE_SEALED_PAYLOAD: u8 = 181;
pub const SEALED_PAYLOAD_BYTES: usize = 1 + 4 + 4 + 4 + HEADER_BYTES + 4 + CIPHERTEXT_BYTES;

pub fn encode_fact(payload: &SealedPayloadFact) -> Result<Vec<u8>, String> {
    validate_payload(payload)?;
    let mut out = wire::Writer::with_capacity(SEALED_PAYLOAD_BYTES);
    out.u8(TYPE_SEALED_PAYLOAD);
    out.u32be(payload.format);
    out.u32be(payload.algorithm);
    out.fixed_slot_value(&payload.header).map_err(wire_err)?;
    out.fixed_slot_value(&payload.ciphertext)
        .map_err(wire_err)?;
    out.finish_exact(SEALED_PAYLOAD_BYTES).map_err(wire_err)
}

fn wire_err(err: wire::WireError) -> String {
    format!("{err:?}")
}
