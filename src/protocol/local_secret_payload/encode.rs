use crate::core::wire;

use super::fact::{validate_secret, LocalSecretPayloadFact, SECRET_BYTES};

pub const TYPE_LOCAL_SECRET_PAYLOAD: u8 = 182;
pub const LOCAL_SECRET_PAYLOAD_BYTES: usize = 1 + 4 + 4 + 4 + SECRET_BYTES;

pub fn encode_fact(secret: &LocalSecretPayloadFact) -> Result<Vec<u8>, String> {
    validate_secret(secret)?;
    let mut out = wire::Writer::with_capacity(LOCAL_SECRET_PAYLOAD_BYTES);
    out.u8(TYPE_LOCAL_SECRET_PAYLOAD);
    out.u32be(secret.family);
    out.u32be(secret.version);
    out.fixed_slot_value(&secret.bytes).map_err(wire_err)?;
    out.finish_exact(LOCAL_SECRET_PAYLOAD_BYTES)
        .map_err(wire_err)
}

fn wire_err(err: wire::WireError) -> String {
    format!("{err:?}")
}
