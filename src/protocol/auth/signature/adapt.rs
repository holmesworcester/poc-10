//! Signature evidence semantic adapter.

use super::fact::SignatureFact;

pub(crate) fn adapt(source: SignatureFact) -> Result<SignatureFact, String> {
    Ok(source)
}
