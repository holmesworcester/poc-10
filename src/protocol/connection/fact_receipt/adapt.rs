//! Connection fact-receipt semantic adapter.
//!
//! The current fact_receipt wire shape is already the active semantic shape.
//! This identity adapter keeps the protocol-local conversion point available for
//! future versioned facts.

use super::fact::ConnectionFactReceipt;

pub(crate) fn adapt(source: ConnectionFactReceipt) -> Result<ConnectionFactReceipt, String> {
    Ok(source)
}
