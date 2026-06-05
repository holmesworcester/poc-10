//! Shared endpoint identity semantic adapter.
//!
//! The current endpoint_shared wire shape is already the active semantic shape.
//! This identity adapter keeps the staged route explicit and gives future
//! versioned facts a dedicated conversion point.

use crate::core::pipeline::Adapter;

use super::fact::EndpointSharedFact;

pub(crate) struct EndpointSharedAdapter;

impl Adapter for EndpointSharedAdapter {
    type Source = EndpointSharedFact;
    type Semantic = EndpointSharedFact;

    fn adapt(source: Self::Source) -> Result<Self::Semantic, String> {
        Ok(source)
    }
}
