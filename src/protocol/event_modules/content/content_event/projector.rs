//! Projector for workspace-scoped content events.

use crate::protocol::event_modules::worker::{EventWithContext, ProjectionOutput};

use super::{codec, schema};

pub fn project(event: &EventWithContext<'_>) -> Result<ProjectionOutput, String> {
    let content = codec::decode(&event.record.canonical_bytes)?;
    if event.record.workspace_id != Some(content.workspace_id) {
        return Err("content workspace metadata does not match event body".to_string());
    }
    Ok(ProjectionOutput::rows(vec![schema::content_event_row(
        event.context.event_id,
        &content,
    )]))
}

#[cfg(test)]
mod tests {
    use crate::protocol::event_modules::types::{event_id, EventRecord, EventScope};
    use crate::protocol::event_modules::worker::{EventContext, EventWithContext};

    use super::super::types::ContentEvent;
    use super::*;

    fn event(workspace_id: [u8; 32]) -> (EventRecord, [u8; 32]) {
        let bytes = codec::encode(&ContentEvent {
            workspace_id,
            timestamp: 5,
            payload: vec![1, 2, 3],
        });
        let id = event_id(&bytes);
        (codec::record_from_bytes(bytes).expect("record"), id)
    }

    #[test]
    fn projects_one_content_row_scoped_by_workspace() {
        let (record, event_id) = event([7; 32]);
        let event = EventWithContext {
            record: &record,
            context: EventContext {
                event_id,
                dependencies: Vec::new(),
                labels: Vec::new(),
            },
        };

        let output = project(&event).expect("project content");

        assert_eq!(output.labels.len(), 0);
        assert_eq!(output.rows.len(), 1);
        assert_eq!(output.rows[0].table, schema::CONTENT_EVENTS);
        let row = schema::decode_content_event_row(&output.rows[0].key, &output.rows[0].value)
            .expect("decode row");
        assert_eq!(row.workspace_id, [7; 32]);
        assert_eq!(row.event_id, event_id);
        assert_eq!(row.payload_bytes, 3);
    }

    #[test]
    fn rejects_mismatched_workspace_metadata() {
        let (mut record, event_id) = event([7; 32]);
        record.workspace_id = Some([8; 32]);
        let event = EventWithContext {
            record: &record,
            context: EventContext {
                event_id,
                dependencies: Vec::new(),
                labels: Vec::new(),
            },
        };

        assert_eq!(
            project(&event).expect_err("mismatch must fail"),
            "content workspace metadata does not match event body"
        );
    }

    #[test]
    fn record_exposes_workspace_dependency_and_metadata() {
        let (record, _) = event([7; 32]);

        assert_eq!(record.dependencies, vec![[7; 32]]);
        assert_eq!(record.workspace_id, Some([7; 32]));
        assert_eq!(record.scope, EventScope::Shared);
    }
}
