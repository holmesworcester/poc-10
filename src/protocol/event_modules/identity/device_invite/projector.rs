//! Projector for shared device-invite events.
//!
//! Projection is row-only. The worker supplies immediate dependency records;
//! this projector only checks the workspace root is present and records the
//! invite authority facts for later endpoint-shared admission.

use crate::protocol::event_modules::worker::{EventWithContext, ProjectionOutput};

use super::{codec, schema};

pub fn project(event: &EventWithContext<'_>) -> Result<ProjectionOutput, String> {
    let device_invite = codec::decode(&event.record.canonical_bytes)?;
    let workspace = event
        .context
        .dependency(&device_invite.workspace_id)
        .ok_or_else(|| "device_invite workspace dependency is missing".to_string())?;
    super::super::workspace::codec::decode(&workspace.canonical_bytes)
        .map_err(|_| "device_invite workspace dependency is not a workspace".to_string())?;

    if event
        .context
        .dependency(&device_invite.user_authority_event_id)
        .is_none()
    {
        return Err("device_invite user authority dependency is missing".to_string());
    }
    // Integration note: the parallel user/user_invite leaf owns semantic user
    // authority typing. Until it is registered here, this leaf requires the
    // authority event to be applied and carries the id forward for
    // endpoint_shared to match.

    Ok(ProjectionOutput::rows(vec![schema::device_invite_row(
        event.context.event_id,
        &device_invite,
    )?]))
}

#[cfg(test)]
mod tests {
    use crate::protocol::event_modules::identity::workspace;
    use crate::protocol::event_modules::types::event_id;
    use crate::protocol::event_modules::worker::{
        DependencyContext, EventContext, EventWithContext,
    };

    use super::super::types::DeviceInviteEvent;
    use super::*;

    fn workspace_record(
        seed: u8,
        name: &str,
    ) -> ([u8; 32], crate::protocol::event_modules::types::EventRecord) {
        let bytes = workspace::codec::encode(&workspace::types::WorkspaceEvent {
            created_at_ms: seed as u64,
            public_key: [seed; 32],
            name: name.to_string(),
        })
        .expect("encode workspace");
        let id = event_id(&bytes);
        let record = workspace::codec::record_from_bytes(bytes).expect("workspace record");
        (id, record)
    }

    fn device_invite_bytes(workspace_id: [u8; 32], user_authority_event_id: [u8; 32]) -> Vec<u8> {
        codec::encode(&DeviceInviteEvent {
            created_at_ms: 44,
            workspace_id,
            user_authority_event_id,
            public_key: [9; 32],
        })
    }

    #[test]
    fn projects_device_invite_row_with_workspace_and_authority_context() {
        let (workspace_id, workspace_dependency) = workspace_record(1, "Workspace");
        let (user_authority_event_id, user_authority_record) = workspace_record(2, "Authority");
        let bytes = device_invite_bytes(workspace_id, user_authority_event_id);
        let device_invite_id = event_id(&bytes);
        let record = codec::record_from_bytes(bytes).expect("device invite record");
        let event = EventWithContext {
            record: &record,
            context: EventContext {
                event_id: device_invite_id,
                dependencies: vec![
                    DependencyContext {
                        event_id: workspace_id,
                        record: workspace_dependency,
                    },
                    DependencyContext {
                        event_id: user_authority_event_id,
                        record: user_authority_record,
                    },
                ],
                labels: Vec::new(),
            },
        };

        let output = project(&event).expect("project device invite");

        assert_eq!(output.labels.len(), 0);
        assert_eq!(output.rows.len(), 1);
        assert_eq!(output.rows[0].table, schema::DEVICE_INVITES);
        assert_eq!(
            output.rows[0].key,
            schema::device_invite_key(workspace_id, device_invite_id)
        );
        let decoded = schema::decode_device_invite_row(&output.rows[0].key, &output.rows[0].value)
            .expect("decode row");
        assert_eq!(decoded.workspace_id, workspace_id);
        assert_eq!(decoded.device_invite_id, device_invite_id);
        assert_eq!(decoded.user_authority_event_id, user_authority_event_id);
    }

    #[test]
    fn rejects_when_workspace_dependency_is_missing() {
        let (workspace_id, _) = workspace_record(1, "Workspace");
        let (user_authority_event_id, user_authority_record) = workspace_record(2, "Authority");
        let bytes = device_invite_bytes(workspace_id, user_authority_event_id);
        let record = codec::record_from_bytes(bytes.clone()).expect("device invite record");
        let event = EventWithContext {
            record: &record,
            context: EventContext {
                event_id: event_id(&bytes),
                dependencies: vec![DependencyContext {
                    event_id: user_authority_event_id,
                    record: user_authority_record,
                }],
                labels: Vec::new(),
            },
        };

        assert_eq!(
            project(&event).expect_err("missing workspace must reject"),
            "device_invite workspace dependency is missing"
        );
    }

    #[test]
    fn rejects_non_device_invite_bytes() {
        let (workspace_id, workspace_record) = workspace_record(1, "Workspace");
        let event = EventWithContext {
            record: &workspace_record,
            context: EventContext {
                event_id: workspace_id,
                dependencies: Vec::new(),
                labels: Vec::new(),
            },
        };

        assert_eq!(
            project(&event).expect_err("wrong event type must reject"),
            "expected device invite"
        );
    }
}
