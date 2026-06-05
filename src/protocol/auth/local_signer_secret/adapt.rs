//! Local signer-secret semantic adapter.
//!
//! The current local_signer_secret wire shape is already the active semantic
//! shape. This identity adapter keeps the staged route explicit and gives future
//! versioned facts a dedicated conversion point.

use crate::core::pipeline::Adapter;

use super::fact::LocalSignerSecretFact;

pub(crate) struct LocalSignerSecretAdapter;

impl Adapter for LocalSignerSecretAdapter {
    type Source = LocalSignerSecretFact;
    type Semantic = LocalSignerSecretFact;

    fn adapt(source: Self::Source) -> Result<Self::Semantic, String> {
        Ok(source)
    }
}
