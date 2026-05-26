//! Bootstrap-response network-frame admission helpers.

use crate::core::effects::PipelineEffects;
use crate::core::facts::{Fact, FactScope};
use crate::protocol::connection::fact_receipt::create::normalize_origin_addr_bytes;
use crate::protocol::connection::fact_receipt::fact::OriginAddr;

use super::fact::ConnectionBootstrapResponseFact;
use super::layout;

pub fn is_bootstrap_response_frame(frame: &[u8]) -> bool {
    frame.first().copied() == Some(layout::TYPE_SEALED_CONNECTION_RESPONSE)
}

pub fn received_bootstrap_response_frame_effect(
    frame: &[u8],
    origin_addr: &[u8],
    received_at_local_ms: u64,
) -> Result<Option<PipelineEffects>, String> {
    if !is_bootstrap_response_frame(frame) {
        return Ok(None);
    }

    let Ok(sealed_response_frame) = layout::copy_sealed_connection_response_frame(frame) else {
        return Ok(Some(PipelineEffects::new()));
    };

    let origin_addr = normalize_origin_addr_bytes(origin_addr)?;
    let fact = ConnectionBootstrapResponseFact {
        origin_addr: OriginAddr::new(&origin_addr)
            .map_err(|err| format!("connection bootstrap response origin addr: {err}"))?,
        received_at_local_ms,
        sealed_response_frame,
    };
    Ok(Some(PipelineEffects::new().ephemeral_fact(Fact::new(
        FactScope::Local,
        received_at_local_ms,
        layout::encode_fact(&fact)?,
    ))))
}
