//! Key-wrap semantic adapter.
//!
//! The current key_wrap wire shape is already the active semantic shape. This
//! identity adapter keeps the staged route explicit and gives future versioned
//! facts a dedicated conversion point.

use crate::core::pipeline::Adapter;

use super::fact::KeyWrapFact;

pub(crate) struct KeyWrapAdapter;

impl Adapter for KeyWrapAdapter {
    type Source = KeyWrapFact;
    type Semantic = KeyWrapFact;

    fn adapt(source: Self::Source) -> Result<Self::Semantic, String> {
        Ok(source)
    }
}
