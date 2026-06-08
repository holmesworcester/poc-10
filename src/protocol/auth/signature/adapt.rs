//! Signature evidence semantic adapter.

use crate::core::pipeline::Adapter;

use super::fact::SignatureFact;

pub(crate) struct SignatureAdapter;

impl Adapter for SignatureAdapter {
    type Source = SignatureFact;
    type Semantic = SignatureFact;

    fn adapt(source: Self::Source) -> Result<Self::Semantic, String> {
        Ok(source)
    }
}
