//! Local-endpoint semantic adapter.
//!
//! The current endpoint wire shape is already the active semantic shape. This
//! identity adapter keeps the staged route explicit and gives future versioned
//! facts a dedicated conversion point.

use crate::core::pipeline::Adapter;

use super::fact::EndpointFact;

pub(crate) struct EndpointAdapter;

impl Adapter for EndpointAdapter {
    type Source = EndpointFact;
    type Semantic = EndpointFact;

    fn adapt(source: Self::Source) -> Result<Self::Semantic, String> {
        Ok(source)
    }
}
