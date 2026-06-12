//! Removal-frontier semantic adapter.
//!
//! The current removal_frontier wire shape is already the active semantic shape.
//! This identity adapter keeps the protocol-local conversion point available for
//! future versioned facts.

use super::fact::RemovalFrontierFact;

pub(crate) fn adapt(source: RemovalFrontierFact) -> Result<RemovalFrontierFact, String> {
    Ok(source)
}
