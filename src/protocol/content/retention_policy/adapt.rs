//! Retention-policy semantic adapter.
//!
//! The current retention_policy wire shape is already the active semantic shape. This
//! identity adapter keeps the staged route explicit and gives future versioned
//! facts a dedicated conversion point.

use crate::core::pipeline::Adapter;

use super::fact::RetentionPolicyFact;

pub(crate) struct RetentionPolicyAdapter;

impl Adapter for RetentionPolicyAdapter {
    type Source = RetentionPolicyFact;
    type Semantic = RetentionPolicyFact;

    fn adapt(source: Self::Source) -> Result<Self::Semantic, String> {
        Ok(source)
    }
}
