//! Local key secret semantic adapter.
//!
//! The current local_key_secret wire shape is already the active semantic shape.
//! This identity adapter keeps the staged route explicit and gives future
//! versioned facts a dedicated conversion point.

use crate::core::pipeline::Adapter;

use super::fact::LocalKeySecretFact;

pub(crate) struct LocalKeySecretAdapter;

impl Adapter for LocalKeySecretAdapter {
    type Source = LocalKeySecretFact;
    type Semantic = LocalKeySecretFact;

    fn adapt(source: Self::Source) -> Result<Self::Semantic, String> {
        Ok(source)
    }
}
