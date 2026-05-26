//! Connection-frame observation construction helpers.

use crate::core::facts::{Fact, FactId, FactScope};
use crate::protocol::connection::fact_receipt::create::normalize_origin_addr_bytes;
use crate::protocol::connection::fact_receipt::fact::OriginAddr;

use super::fact::ConnectionFrameObservationFact;
use super::layout;

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
        layout::encode_fact(&fact)?,
    ))
}
