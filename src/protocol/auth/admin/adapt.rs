//! Admin-grant semantic adapter.
//!
//! The current admin wire shape is already the active semantic shape. This
//! identity adapter keeps the staged route explicit and gives future versioned
//! facts a dedicated conversion point.

use crate::core::pipeline::Adapter;

use super::fact::AdminFact;

pub(crate) struct AdminAdapter;

impl Adapter for AdminAdapter {
    type Source = AdminFact;
    type Semantic = AdminFact;

    fn adapt(source: Self::Source) -> Result<Self::Semantic, String> {
        Ok(source)
    }
}
