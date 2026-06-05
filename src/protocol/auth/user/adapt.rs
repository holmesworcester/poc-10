//! User semantic adapter.
//!
//! The current user wire shape is already the active semantic shape. This
//! identity adapter keeps the staged route explicit and gives future versioned
//! facts a dedicated conversion point.

use crate::core::pipeline::Adapter;

use super::fact::UserFact;

pub(crate) struct UserAdapter;

impl Adapter for UserAdapter {
    type Source = UserFact;
    type Semantic = UserFact;

    fn adapt(source: Self::Source) -> Result<Self::Semantic, String> {
        Ok(source)
    }
}
