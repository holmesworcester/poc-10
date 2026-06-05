//! Connection-request semantic adapter.
//!
//! The authenticated opened request is already the active semantic shape. This
//! identity adapter keeps the staged route explicit and gives future versioned
//! facts a dedicated conversion point.

use crate::core::pipeline::Adapter;

use super::authenticate::AuthenticatedConnectionRequest;

pub(crate) struct ConnectionRequestAdapter;

impl Adapter for ConnectionRequestAdapter {
    type Source = AuthenticatedConnectionRequest;
    type Semantic = AuthenticatedConnectionRequest;

    fn adapt(source: Self::Source) -> Result<Self::Semantic, String> {
        Ok(source)
    }
}
