//! Connection ephemeral-secret semantic adapter.
//!
//! The current ephemeral_secret wire shape is already the active semantic shape.
//! This identity adapter keeps the staged route explicit and gives future
//! versioned facts a dedicated conversion point.

use crate::core::pipeline::Adapter;

use super::fact::ConnectionEphemeralSecretFact;

pub(crate) struct ConnectionEphemeralSecretAdapter;

impl Adapter for ConnectionEphemeralSecretAdapter {
    type Source = ConnectionEphemeralSecretFact;
    type Semantic = ConnectionEphemeralSecretFact;

    fn adapt(source: Self::Source) -> Result<Self::Semantic, String> {
        Ok(source)
    }
}
