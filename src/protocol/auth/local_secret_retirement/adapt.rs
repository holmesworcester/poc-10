//! Local secret-retirement semantic adapter.
//!
//! The current local_secret_retirement wire shape is already the active
//! semantic shape. This identity adapter keeps the staged route explicit and
//! gives future versioned facts a dedicated conversion point.

use crate::core::pipeline::Adapter;

use super::fact::LocalSecretRetirementFact;

pub(crate) struct LocalSecretRetirementAdapter;

impl Adapter for LocalSecretRetirementAdapter {
    type Source = LocalSecretRetirementFact;
    type Semantic = LocalSecretRetirementFact;

    fn adapt(source: Self::Source) -> Result<Self::Semantic, String> {
        Ok(source)
    }
}
