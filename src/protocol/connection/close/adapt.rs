//! Connection-close semantic adapter.
//!
//! The current close wire shape is already the active semantic shape. This
//! identity adapter keeps the staged route explicit and gives future versioned
//! facts a dedicated conversion point.

use crate::core::pipeline::Adapter;

use super::fact::ConnectionCloseFact;

pub(crate) struct ConnectionCloseAdapter;

impl Adapter for ConnectionCloseAdapter {
    type Source = ConnectionCloseFact;
    type Semantic = ConnectionCloseFact;

    fn adapt(source: Self::Source) -> Result<Self::Semantic, String> {
        Ok(source)
    }
}
