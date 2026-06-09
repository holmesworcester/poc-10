use crate::core::pipeline::Adapter;

use super::fact::SealedPayloadFact;

pub(crate) struct SealedPayloadAdapter;

impl Adapter for SealedPayloadAdapter {
    type Source = SealedPayloadFact;
    type Semantic = SealedPayloadFact;

    fn adapt(source: Self::Source) -> Result<Self::Semantic, String> {
        Ok(source)
    }
}
