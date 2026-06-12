//! Shared endpoint identity semantic adapter.
//!
//! The current endpoint_shared wire shape is already the active semantic shape.
//! This identity adapter keeps the protocol-local conversion point available for
//! future versioned facts.

use super::fact::EndpointSharedFact;

pub(crate) fn adapt(source: EndpointSharedFact) -> Result<EndpointSharedFact, String> {
    Ok(source)
}
