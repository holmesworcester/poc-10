//! Key-request semantic adapter.
//!
//! The current key_request wire shape is already the active semantic shape. This
//! identity adapter keeps the staged route explicit and gives future versioned
//! facts a dedicated conversion point.

use crate::core::pipeline::Adapter;

use super::fact::KeyRequestFact;

pub(crate) struct KeyRequestAdapter;

impl Adapter for KeyRequestAdapter {
    type Source = KeyRequestFact;
    type Semantic = KeyRequestFact;

    fn adapt(source: Self::Source) -> Result<Self::Semantic, String> {
        Ok(source)
    }
}
