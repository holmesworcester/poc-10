//! Retention-policy semantic adapter.
//!
//! The current retention_policy wire shape is already the active semantic shape. This
//! identity adapter keeps the protocol-local conversion point available for future versioned
//! facts.

use super::fact::RetentionPolicyFact;

pub(crate) fn adapt(source: RetentionPolicyFact) -> Result<RetentionPolicyFact, String> {
    Ok(source)
}
