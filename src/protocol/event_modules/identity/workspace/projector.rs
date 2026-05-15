//! Projector for shared workspace events.
//!
//! Projection is row-only: decode the event and write one workspace row keyed by
//! workspace id. The workspace id is the deterministic id of the canonical
//! event bytes.

use crate::protocol::event_modules::types::event_id;
use crate::protocol::event_modules::worker::ProjectionOutput;

use super::{layout, rows};

pub fn project(bytes: &[u8]) -> Result<ProjectionOutput, String> {
    let event = layout::decode(bytes)?;
    let workspace_id = event_id(bytes);
    Ok(ProjectionOutput::table_writes(vec![rows::workspace_row(
        workspace_id,
        event.created_at_ms,
        event.public_key,
        &event.name,
    )?]))
}

#[cfg(test)]
mod tests {
    use crate::protocol::event_modules::types::event_id;

    use super::super::types::WorkspaceEvent;
    use super::*;

    #[test]
    fn projects_one_workspace_row_keyed_by_workspace_id() {
        let event = WorkspaceEvent {
            created_at_ms: 100,
            public_key: [3; 32],
            name: "Research".to_string(),
        };
        let bytes = layout::encode(&event).expect("encode workspace");
        let output = project(&bytes).expect("project workspace");

        assert_eq!(output.legacy_context_updates().len(), 0);
        assert_eq!(output.legacy_rows().len(), 1);
        assert_eq!(output.legacy_rows()[0].table, rows::WORKSPACES);
        assert_eq!(output.legacy_rows()[0].key, event_id(&bytes));
    }
}
