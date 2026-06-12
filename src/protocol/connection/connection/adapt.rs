//! Connection semantic adapter.
//!
//! The authenticated opened connection is already the active semantic shape.
//! This identity adapter keeps the protocol-local conversion point available for
//! future versioned facts.

use super::authenticate::AuthenticatedConnection;

pub(crate) fn adapt(source: AuthenticatedConnection) -> Result<AuthenticatedConnection, String> {
    Ok(source)
}
