//! Small connection-frame semantic adapter.
//!
//! The current frame_small wire shape is already the active semantic shape. This
//! identity adapter keeps the staged route explicit and gives future versioned
//! facts a dedicated conversion point.

use crate::core::pipeline::Adapter;

use super::fact::ConnectionFrameSmallFact;

pub(crate) struct ConnectionFrameSmallAdapter;

impl Adapter for ConnectionFrameSmallAdapter {
    type Source = ConnectionFrameSmallFact;
    type Semantic = ConnectionFrameSmallFact;

    fn adapt(source: Self::Source) -> Result<Self::Semantic, String> {
        Ok(source)
    }
}
