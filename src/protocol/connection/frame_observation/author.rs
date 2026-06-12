//! Connection-frame observation construction helpers.

use crate::core::facts::{Fact, FactId, FactScope};
use crate::protocol::connection::fact_receipt::fact::{normalize_origin_addr_bytes, OriginAddr};

use super::encode;
use super::fact::ConnectionFrameObservationFact;

pub fn fact_from_observation(
    frame_fact_id: FactId,
    origin_addr: &[u8],
    received_at_local_ms: u64,
) -> Result<Fact, String> {
    let origin_addr = normalize_origin_addr_bytes(origin_addr)?;
    let fact = ConnectionFrameObservationFact {
        frame_fact_id,
        origin_addr: OriginAddr::new(&origin_addr)
            .map_err(|err| format!("connection frame observation origin addr: {err}"))?,
        received_at_local_ms,
    };
    Ok(Fact::new(
        FactScope::Local,
        received_at_local_ms,
        encode::encode_fact(&fact)?,
    ))
}
