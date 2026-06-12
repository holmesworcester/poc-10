//! Local-endpoint semantic adapter.
//!
//! The current endpoint wire shape is already the active semantic shape. This
//! identity adapter keeps the protocol-local conversion point available for future versioned
//! facts.

use super::fact::EndpointFact;

pub(crate) fn adapt(source: EndpointFact) -> Result<EndpointFact, String> {
    Ok(source)
}
