//! File-slice connection-frame fact construction helpers.

use crate::core::effects::PipelineEffects;
use crate::core::facts::{Fact, FactScope};
use crate::core::projectors::{ProjectionContext, ProjectionOutput};
use crate::protocol::connection_frame;

use super::fact::ConnectionFrameFileSliceFact;
use super::layout;

pub fn received_frame_effect(
    frame: &[u8],
    origin_addr: &[u8],
    received_at_local_ms: u64,
) -> Result<PipelineEffects, String> {
    Ok(PipelineEffects::new().ephemeral_fact(received_frame_fact(
        frame,
        origin_addr,
        received_at_local_ms,
    )?))
}

pub fn received_frame_fact(
    frame: &[u8],
    origin_addr: &[u8],
    received_at_local_ms: u64,
) -> Result<Fact, String> {
    let fact = ConnectionFrameFileSliceFact {
        origin_addr: connection_frame::origin_addr_slot(origin_addr)?,
        received_at_local_ms,
        frame: connection_frame::exact_frame_slot(frame)?,
    };
    Ok(Fact::new(
        FactScope::Local,
        received_at_local_ms,
        layout::encode_fact(&fact)?,
    ))
}

pub fn project_received_frame(
    fact: &Fact,
    input: ConnectionFrameFileSliceFact,
    context: &ProjectionContext,
) -> Result<ProjectionOutput, String> {
    connection_frame::project_received_frame(
        fact,
        input.origin_addr,
        input.received_at_local_ms,
        input.frame.bytes(),
        context,
    )
}
