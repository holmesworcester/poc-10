//! Bootstrap-request network-frame admission helpers.

use crate::core::effects::PipelineEffects;
use crate::core::facts::{Fact, FactScope};
use crate::protocol::connection::fact_receipt::create::normalize_origin_addr_bytes;
use crate::protocol::connection::fact_receipt::fact::OriginAddr;

use super::fact::ConnectionBootstrapRequestFact;
use super::layout;

pub fn is_bootstrap_request_frame(frame: &[u8]) -> bool {
    frame.first().copied() == Some(layout::TYPE_SEALED_CONNECTION_REQUEST)
}

pub fn received_bootstrap_request_frame_effect(
    frame: &[u8],
    origin_addr: &[u8],
    received_at_local_ms: u64,
) -> Result<Option<PipelineEffects>, String> {
    if !is_bootstrap_request_frame(frame) {
        return Ok(None);
    }

    let Ok(sealed_request_frame) = layout::copy_sealed_connection_request_frame(frame) else {
        return Ok(Some(PipelineEffects::new()));
    };

    let origin_addr = normalize_origin_addr_bytes(origin_addr)?;
    let fact = ConnectionBootstrapRequestFact {
        origin_addr: OriginAddr::new(&origin_addr)
            .map_err(|err| format!("connection bootstrap request origin addr: {err}"))?,
        received_at_local_ms,
        sealed_request_frame,
    };
    Ok(Some(PipelineEffects::new().ephemeral_fact(Fact::new(
        FactScope::Local,
        received_at_local_ms,
        layout::encode_fact(&fact)?,
    ))))
}
