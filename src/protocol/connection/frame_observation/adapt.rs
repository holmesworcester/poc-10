//! Connection-frame observation semantic adapter.
//!
//! The current frame_observation wire shape is already the active semantic shape.
//! This identity adapter keeps the staged route explicit and gives future
//! versioned facts a dedicated conversion point.

use crate::core::pipeline::Adapter;

use super::fact::ConnectionFrameObservationFact;

pub(crate) struct ConnectionFrameObservationAdapter;

impl Adapter for ConnectionFrameObservationAdapter {
    type Source = ConnectionFrameObservationFact;
    type Semantic = ConnectionFrameObservationFact;

    fn adapt(source: Self::Source) -> Result<Self::Semantic, String> {
        Ok(source)
    }
}
