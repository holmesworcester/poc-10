//! Small connection-frame fact construction helpers.

use crate::core::facts::{Fact, FactScope};
use crate::core::pipeline::{ProjectionContext, ProjectionOutput};
use crate::protocol::connection_frame;

use super::fact::ConnectionFrameSmallFact;
use super::layout;

pub fn fact_from_wire(frame: &[u8], local_timestamp_ms: u64) -> Result<Fact, String> {
    let fact = ConnectionFrameSmallFact {
        frame: connection_frame::exact_frame_slot(frame)?,
    };
    Ok(Fact::new(
        FactScope::Local,
        local_timestamp_ms,
        layout::encode_fact(&fact)?,
    ))
}

pub fn project_observed_frame(
    fact: &Fact,
    input: ConnectionFrameSmallFact,
    context: &ProjectionContext,
) -> Result<ProjectionOutput, String> {
    connection_frame::project_observed_frame(fact, input.frame.bytes(), context)
}
