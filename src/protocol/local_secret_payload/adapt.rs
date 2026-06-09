use crate::core::pipeline::Adapter;

use super::fact::LocalSecretPayloadFact;

pub(crate) struct LocalSecretPayloadAdapter;

impl Adapter for LocalSecretPayloadAdapter {
    type Source = LocalSecretPayloadFact;
    type Semantic = LocalSecretPayloadFact;

    fn adapt(source: Self::Source) -> Result<Self::Semantic, String> {
        Ok(source)
    }
}
