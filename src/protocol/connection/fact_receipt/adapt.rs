//! Connection fact-receipt semantic adapter.
//!
//! The current fact_receipt wire shape is already the active semantic shape.
//! This identity adapter keeps the staged route explicit and gives future
//! versioned facts a dedicated conversion point.

use crate::core::pipeline::Adapter;

use super::fact::ConnectionFactReceipt;

pub(crate) struct ConnectionFactReceiptAdapter;

impl Adapter for ConnectionFactReceiptAdapter {
    type Source = ConnectionFactReceipt;
    type Semantic = ConnectionFactReceipt;

    fn adapt(source: Self::Source) -> Result<Self::Semantic, String> {
        Ok(source)
    }
}
