//! Cascade test-fact semantic adapter.
//!
//! The current cascade_test_fact wire shape is already the active semantic
//! shape. This identity adapter keeps the staged route explicit and gives future
//! versioned facts a dedicated conversion point.

use crate::core::pipeline::Adapter;

use super::fact::CascadeTestFact;

pub(crate) struct CascadeTestFactAdapter;

impl Adapter for CascadeTestFactAdapter {
    type Source = CascadeTestFact;
    type Semantic = CascadeTestFact;

    fn adapt(source: Self::Source) -> Result<Self::Semantic, String> {
        Ok(source)
    }
}
