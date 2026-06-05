//! Bundled connection-frame semantic adapter.
//!
//! The current frame_bundle wire shape is already the active semantic shape. This
//! identity adapter keeps the staged route explicit and gives future versioned
//! facts a dedicated conversion point.

use crate::core::pipeline::Adapter;

use super::fact::ConnectionFrameBundleFact;

pub(crate) struct ConnectionFrameBundleAdapter;

impl Adapter for ConnectionFrameBundleAdapter {
    type Source = ConnectionFrameBundleFact;
    type Semantic = ConnectionFrameBundleFact;

    fn adapt(source: Self::Source) -> Result<Self::Semantic, String> {
        Ok(source)
    }
}
