//! Bootstrap network-frame admission helpers.

use crate::core::crypto;
use crate::core::effects::PipelineEffects;
use crate::core::store::Store;
use crate::protocol::auth::endpoint;
use crate::protocol::connection::frame::create::{
    received_connection_request_fact_effect, received_connection_response_fact_effect,
};

use super::layout;

pub fn is_bootstrap_frame(frame: &[u8]) -> bool {
    matches!(
        frame.first().copied(),
        Some(layout::TYPE_SEALED_CONNECTION_REQUEST)
            | Some(layout::TYPE_SEALED_CONNECTION_RESPONSE)
    )
}

pub fn received_bootstrap_frame_effect(
    store: &Store,
    frame: &[u8],
    origin_addr: &[u8],
    received_at_local_ms: u64,
) -> Result<Option<PipelineEffects>, String> {
    if !is_bootstrap_frame(frame) {
        return Ok(None);
    }

    let Some(local_endpoint) = endpoint::create::local_endpoint(store)? else {
        return Ok(Some(PipelineEffects::new()));
    };
    let frame_hash = crypto::hash(frame);

    match frame.first().copied() {
        Some(layout::TYPE_SEALED_CONNECTION_REQUEST) => {
            let Ok(request_bytes) = layout::open_connection_request(frame, &local_endpoint) else {
                return Ok(Some(PipelineEffects::new()));
            };
            Ok(Some(received_connection_request_fact_effect(
                &request_bytes,
                origin_addr,
                received_at_local_ms,
                frame_hash,
            )?))
        }
        Some(layout::TYPE_SEALED_CONNECTION_RESPONSE) => {
            let Ok(response_bytes) = layout::open_connection_response(frame, &local_endpoint)
            else {
                return Ok(Some(PipelineEffects::new()));
            };
            Ok(Some(received_connection_response_fact_effect(
                &response_bytes,
                origin_addr,
                received_at_local_ms,
                frame_hash,
            )?))
        }
        _ => unreachable!(),
    }
}
