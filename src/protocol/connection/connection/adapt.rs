//! Connection semantic adapter.
//!
//! The authenticated opened connection is already the active semantic shape.
//! This identity adapter keeps the staged route explicit and gives future
//! versioned facts a dedicated conversion point.

use crate::core::pipeline::Adapter;

use super::authenticate::AuthenticatedConnection;

pub(crate) struct ConnectionAdapter;

impl Adapter for ConnectionAdapter {
    type Source = AuthenticatedConnection;
    type Semantic = AuthenticatedConnection;

    fn adapt(source: Self::Source) -> Result<Self::Semantic, String> {
        Ok(source)
    }
}
