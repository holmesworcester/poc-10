use crate::core::pipeline::Adapter;

use super::fact::RootFact;

pub(crate) struct RootAdapter;

impl Adapter for RootAdapter {
    type Source = RootFact;
    type Semantic = RootFact;

    fn adapt(source: Self::Source) -> Result<Self::Semantic, String> {
        Ok(source)
    }
}
