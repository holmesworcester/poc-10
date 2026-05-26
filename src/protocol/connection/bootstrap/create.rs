//! Bootstrap network-frame admission helpers.

use crate::core::effects::PipelineEffects;
use crate::core::facts::{Fact, FactScope};
use crate::core::wire::FixedSlot;
use crate::protocol::connection::fact_receipt::create::normalize_origin_addr_bytes;
use crate::protocol::connection::fact_receipt::fact::OriginAddr;

use super::fact::ConnectionBootstrapFact;
use super::layout;

pub fn is_bootstrap_frame(frame: &[u8]) -> bool {
    matches!(
        frame.first().copied(),
        Some(layout::TYPE_SEALED_CONNECTION_REQUEST)
            | Some(layout::TYPE_SEALED_CONNECTION_RESPONSE)
    )
}

pub fn received_bootstrap_frame_effect(
    frame: &[u8],
    origin_addr: &[u8],
    received_at_local_ms: u64,
) -> Result<Option<PipelineEffects>, String> {
    if !is_bootstrap_frame(frame) {
        return Ok(None);
    }

    if layout::validate_sealed_frame(frame).is_err() {
        return Ok(Some(PipelineEffects::new()));
    }

    let origin_addr = normalize_origin_addr_bytes(origin_addr)?;
    let fact = ConnectionBootstrapFact {
        origin_addr: OriginAddr::new(&origin_addr)
            .map_err(|err| format!("connection bootstrap origin addr: {err}"))?,
        received_at_local_ms,
        frame: FixedSlot::new(frame).map_err(|err| format!("connection bootstrap frame: {err}"))?,
    };
    Ok(Some(PipelineEffects::new().ephemeral_fact(Fact::new(
        FactScope::Local,
        received_at_local_ms,
        layout::encode_fact(&fact)?,
    ))))
}
