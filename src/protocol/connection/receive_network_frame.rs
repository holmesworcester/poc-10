//! Inbound network-frame intake.
//!
//! The daemon turns each accepted TCP frame into this boundary input with the
//! raw bytes and local receive time. This module classifies sealed handshake
//! request, response, or established-frame bytes into the appropriate incoming
//! fact queue, then delegates fact admission to projectors; it does not open
//! frames or validate child facts itself.
//!
//! Change this file for receive payload shape or the choice of which
//! received-frame fact family should stage an established connection frame.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiveNetworkFrame {
    /// Raw bytes as received from the network. These are sealed bootstrap
    /// request frames, sealed bootstrap response frames, or encrypted
    /// established-connection frames.
    pub frame: Vec<u8>,
    /// Local receive time carried into the typed incoming frame fact.
    pub received_at_local_ms: u64,
}

// This module is the incoming socket boundary. It has no input facts because
// raw network bytes are not authorized by context until projection. Sealed
// handshake frames carry no separate envelope fact: intake stages the bytes as
// their own local incoming fact (whose type tag selects the owning projector).
// Established connection frames use the same incoming path. The boundary does
// no unsealing itself. The selected projector opens bytes with context and
// emits recovered child facts plus receive receipts. Opening is transport
// decoding, not protocol validation; the child projectors still own semantic
// validation and retention.

use crate::core;
use crate::protocol::connection::{
    connection, frame_bundle, frame_file_slice, frame_small, request,
};

pub fn receive_network_frame_facts(
    input: ReceiveNetworkFrame,
) -> Result<Vec<core::facts::Fact>, String> {
    // A sealed handshake frame is staged as its own local fact (whose type tag
    // is the sealed type). Its projector unseals it with local context; the
    // boundary does no unsealing itself.
    if request::project::decode::is_sealed_fact(&input.frame) {
        let fact =
            request::author::fact_from_sealed_wire(&input.frame, input.received_at_local_ms)?;
        return Ok(vec![fact]);
    }
    if connection::project::decode::is_sealed_fact(&input.frame) {
        let fact =
            connection::author::fact_from_sealed_wire(&input.frame, input.received_at_local_ms)?;
        return Ok(vec![fact]);
    }

    if frame_small::project::decode::is_frame(&input.frame) {
        Ok(vec![frame_small::author::fact_from_wire(
            &input.frame,
            input.received_at_local_ms,
        )?])
    } else if frame_file_slice::project::decode::is_frame(&input.frame) {
        Ok(vec![frame_file_slice::author::fact_from_wire(
            &input.frame,
            input.received_at_local_ms,
        )?])
    } else if frame_bundle::project::decode::is_frame(&input.frame) {
        Ok(vec![frame_bundle::author::fact_from_wire(
            &input.frame,
            input.received_at_local_ms,
        )?])
    } else {
        Ok(Vec::new())
    }
}
