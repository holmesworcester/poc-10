//! Inbound network-frame intake.
//!
//! The daemon turns each accepted TCP frame into this boundary input with the
//! raw bytes, observed origin address, and local receive time. This module
//! decodes and validates that boundary metadata, admits sealed handshake
//! request, response, or established-frame bytes into the appropriate incoming
//! fact queue, then delegates fact admission to projectors; it does not open
//! frames or validate child facts itself.
//!
//! Change this file for receive payload shape, metadata normalization, or the
//! choice of which received-frame fact family should stage an established
//! connection frame.

use crate::protocol::connection::fact_receipt::fact::normalize_origin_addr_bytes;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiveNetworkFrame {
    /// Raw bytes as received from the network. These are sealed bootstrap
    /// request frames, sealed bootstrap response frames, or encrypted
    /// established-connection frames.
    pub frame: Vec<u8>,
    /// Observed local origin string, usually the peer socket address. Accepted
    /// boundary input is normalized before the intent is queued or handled.
    pub origin_addr: Vec<u8>,
    /// Local receive time used only for the local fact-receipt fact.
    pub received_at_local_ms: u64,
}

fn normalized_input(mut input: ReceiveNetworkFrame) -> Result<ReceiveNetworkFrame, String> {
    input.origin_addr = normalize_origin_addr_bytes(&input.origin_addr)?;
    Ok(input)
}

// This module is the incoming socket boundary. It has no input facts because
// raw network bytes are not authorized by context until projection. Sealed
// handshake frames carry no separate envelope fact: intake stages the bytes as
// their own local incoming fact (whose type tag selects the owning
// projector) plus a frame observation. Established connection frames use the
// same incoming path. The boundary does no unsealing itself. The selected
// projector opens bytes with context and emits recovered child facts plus
// receive receipts. Opening is transport decoding, not protocol validation; the
// child projectors still own semantic validation and retention.

use crate::core;
use crate::core::effects::RuntimeEffects;
use crate::protocol::connection::{
    connection, frame_bundle, frame_file_slice, frame_observation, frame_small, request,
};

pub fn receive_network_frame_effects(input: ReceiveNetworkFrame) -> Result<RuntimeEffects, String> {
    let input = normalized_input(input)?;
    let observed_incoming = |frame_fact: core::facts::Fact| -> Result<RuntimeEffects, String> {
        let observation = frame_observation::author::fact_from_observation(
            frame_fact.id,
            &input.origin_addr,
            input.received_at_local_ms,
        )?;
        Ok(RuntimeEffects::new()
            .fact(observation)
            .incoming_fact(frame_fact))
    };

    // A sealed handshake frame is admitted as its own local fact (whose type
    // tag is the sealed type) plus a frame observation. Its projector unseals it
    // with the local endpoint secret from `auth_local_endpoint` context; the
    // boundary does no unsealing itself.
    if request::project::decode::is_sealed_fact(&input.frame) {
        let fact =
            request::author::fact_from_sealed_wire(&input.frame, input.received_at_local_ms)?;
        return observed_incoming(fact);
    }
    if connection::project::decode::is_sealed_fact(&input.frame) {
        let fact =
            connection::author::fact_from_sealed_wire(&input.frame, input.received_at_local_ms)?;
        return observed_incoming(fact);
    }

    if frame_small::project::decode::is_frame(&input.frame) {
        observed_incoming(frame_small::author::fact_from_wire(
            &input.frame,
            input.received_at_local_ms,
        )?)
    } else if frame_file_slice::project::decode::is_frame(&input.frame) {
        observed_incoming(frame_file_slice::author::fact_from_wire(
            &input.frame,
            input.received_at_local_ms,
        )?)
    } else if frame_bundle::project::decode::is_frame(&input.frame) {
        observed_incoming(frame_bundle::author::fact_from_wire(
            &input.frame,
            input.received_at_local_ms,
        )?)
    } else {
        Ok(RuntimeEffects::new())
    }
}
