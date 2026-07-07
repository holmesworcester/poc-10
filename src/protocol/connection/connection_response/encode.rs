//! Membership connection-response encoding: typed value → canonical wire bytes.
//!
//! Fixed width: a tag byte followed by eight 32-byte fields for endpoints,
//! request/dependency ids, responder ephemeral public key, handshake hash, and
//! connection secret. There is no invite field on this path. The handshake
//! key-schedule that produces these fields lives in `create.rs`; context
//! validation belongs in `project.rs`.

use crate::core::wire;

use super::fact::ConnectionResponseFact;

pub const TYPE_CONNECTION_RESPONSE: u8 = 49;
pub const FACT_BYTES: usize = 1 + 32 * 8;

pub fn encode_fact(fact: &ConnectionResponseFact) -> Result<Vec<u8>, String> {
    let mut out = vec![0; FACT_BYTES];
    wire::put_u8(TYPE_CONNECTION_RESPONSE, &mut out[0..1]).map_err(wire_err)?;
    out[1..33].copy_from_slice(&fact.from_endpoint);
    out[33..65].copy_from_slice(&fact.to_endpoint);
    out[65..97].copy_from_slice(&fact.request_id);
    out[97..129].copy_from_slice(&fact.initiator_ephemeral_secret_fact_id);
    out[129..161].copy_from_slice(&fact.responder_ephemeral_secret_fact_id);
    out[161..193].copy_from_slice(&fact.responder_ephemeral_public_key);
    out[193..225].copy_from_slice(&fact.handshake_hash);
    out[225..257].copy_from_slice(&fact.connection_secret);
    Ok(out)
}

fn wire_err(err: wire::WireError) -> String {
    format!("{err:?}")
}
