//! Connection-request semantic adapter.
//!
//! The authenticated opened request is already the active semantic shape. This
//! identity adapter keeps the protocol-local conversion point available for future versioned
//! facts.

use super::authenticate::AuthenticatedConnectionRequest;

pub(crate) fn adapt(
    source: AuthenticatedConnectionRequest,
) -> Result<AuthenticatedConnectionRequest, String> {
    Ok(source)
}
