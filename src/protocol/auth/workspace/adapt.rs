//! Workspace semantic adapter.
//!
//! The current workspace wire shape is already the active semantic shape. This
//! identity adapter exists so the staged route exposes the same
//! decode/authenticate/adapt/project slots future versioned facts will use.

use crate::core::pipeline::Adapter;

use super::fact::WorkspaceFact;

pub(crate) struct WorkspaceAdapter;

impl Adapter for WorkspaceAdapter {
    type Source = WorkspaceFact;
    type Semantic = WorkspaceFact;

    fn adapt(source: Self::Source) -> Result<Self::Semantic, String> {
        Ok(source)
    }
}
