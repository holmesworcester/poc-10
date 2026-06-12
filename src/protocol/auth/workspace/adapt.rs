//! Workspace semantic adapter.
//!
//! The current workspace wire shape is already the active semantic shape. This
//! identity adapter exists as a protocol-local conversion point for
//! future versioned fact shapes.

use super::fact::WorkspaceFact;

pub(crate) fn adapt(source: WorkspaceFact) -> Result<WorkspaceFact, String> {
    Ok(source)
}
