//! Projector for signed user-invite events.
//!
//! The current p8 leaf supports the workspace bootstrap authority path. Ongoing
//! admin/endpoint_shared authority needs the admin and endpoint_shared leaves to
//! provide their immediate dependency semantics before this projector can accept
//! that signer family.

use crate::protocol::event_modules::worker::{EventWithContext, ProjectionOutput};

use super::{codec, schema};
use crate::protocol::event_modules::identity::{signed, workspace};

pub fn project(event: &EventWithContext<'_>) -> Result<ProjectionOutput, String> {
    let envelope = signed::codec::decode(&event.record.canonical_bytes)?;
    if envelope.inner_type != codec::TYPE_USER_INVITE {
        return Err("expected signed user_invite".to_string());
    }
    let user_invite = codec::decode(&envelope.payload)?;
    let signer = event
        .context
        .dependency(&envelope.signer_event_id)
        .ok_or_else(|| "missing signer dependency context for user_invite".to_string())?;
    let signer_workspace = workspace::codec::decode(&signer.canonical_bytes)
        .map_err(|_| "user_invite signer must currently be workspace".to_string())?;

    if envelope.signer_event_id != user_invite.workspace_id
        || user_invite.authority_event_id != user_invite.workspace_id
    {
        return Err("bootstrap user_invite must use workspace as signer and authority".to_string());
    }
    if envelope.signer_public_key != signer_workspace.public_key {
        return Err(
            "signed user_invite signer key does not match workspace public key".to_string(),
        );
    }

    Ok(ProjectionOutput::rows(vec![schema::user_invite_row(
        event.context.event_id,
        &user_invite,
    )]))
}

#[cfg(test)]
mod tests {
    use crate::protocol::event_modules::identity::workspace::types::WorkspaceEvent;
    use crate::protocol::event_modules::types::{event_id, EventRecord};
    use crate::protocol::event_modules::worker::{DependencyContext, EventContext};

    use super::*;

    type Record = EventRecord;

    const WORKSPACE_PRIVATE: [u8; 32] = [7; 32];
    const OTHER_PRIVATE: [u8; 32] = [8; 32];

    fn signer_public_key(private_key: &[u8; 32]) -> [u8; 32] {
        signed::commands::sign_payload([0; 32], private_key, vec![99])
            .expect("sign fixture")
            .value
            .signer_public_key
    }

    fn workspace_record(
        private_key: &[u8; 32],
    ) -> (crate::protocol::event_modules::types::EventId, EventRecord) {
        let workspace = WorkspaceEvent {
            created_at_ms: 1,
            public_key: signer_public_key(private_key),
            name: "Workspace".to_string(),
        };
        let bytes = workspace::codec::encode(&workspace).expect("encode workspace");
        let workspace_id = event_id(&bytes);
        (
            workspace_id,
            workspace::codec::record_from_bytes(bytes).expect("workspace record"),
        )
    }

    fn signed_user_invite_record(
        signer_event_id: crate::protocol::event_modules::types::EventId,
        signer_private_key: &[u8; 32],
        user_invite: super::super::types::UserInviteEvent,
    ) -> Record {
        let output = signed::commands::sign_payload(
            signer_event_id,
            signer_private_key,
            codec::encode(&user_invite),
        )
        .expect("sign user_invite");
        output.events[0].record().clone()
    }

    fn context<'a>(
        record: &'a EventRecord,
        dependency: Option<(crate::protocol::event_modules::types::EventId, EventRecord)>,
    ) -> EventWithContext<'a> {
        EventWithContext {
            record,
            context: EventContext {
                event_id: event_id(&record.canonical_bytes),
                dependencies: dependency
                    .into_iter()
                    .map(|(event_id, record)| DependencyContext { event_id, record })
                    .collect(),
                labels: Vec::new(),
            },
        }
    }

    #[test]
    fn projects_workspace_signed_user_invite_row() {
        let (workspace_id, workspace_record) = workspace_record(&WORKSPACE_PRIVATE);
        let invite = super::super::types::UserInviteEvent {
            created_at_ms: 9,
            public_key: [3; 32],
            workspace_id,
            authority_event_id: workspace_id,
        };
        let record = signed_user_invite_record(workspace_id, &WORKSPACE_PRIVATE, invite);
        let output = project(&context(&record, Some((workspace_id, workspace_record))))
            .expect("project user_invite");

        assert!(output.labels.is_empty());
        assert_eq!(output.rows.len(), 1);
        assert_eq!(output.rows[0].table, schema::USER_INVITES);
        assert_eq!(
            output.rows[0].key,
            schema::user_invite_key(&workspace_id, &event_id(&record.canonical_bytes))
        );
        assert_eq!(
            schema::decode_user_invite_row(&output.rows[0].key, &output.rows[0].value)
                .expect("decode row")
                .public_key,
            [3; 32]
        );
    }

    #[test]
    fn rejects_missing_signer_dependency_context() {
        let (workspace_id, _) = workspace_record(&WORKSPACE_PRIVATE);
        let invite = super::super::types::UserInviteEvent {
            created_at_ms: 9,
            public_key: [3; 32],
            workspace_id,
            authority_event_id: workspace_id,
        };
        let record = signed_user_invite_record(workspace_id, &WORKSPACE_PRIVATE, invite);

        let err = project(&context(&record, None)).expect_err("missing context must fail");

        assert_eq!(err, "missing signer dependency context for user_invite");
    }

    #[test]
    fn rejects_workspace_authority_mismatch() {
        let (workspace_id, workspace_record) = workspace_record(&WORKSPACE_PRIVATE);
        let invite = super::super::types::UserInviteEvent {
            created_at_ms: 9,
            public_key: [3; 32],
            workspace_id,
            authority_event_id: [6; 32],
        };
        let record = signed_user_invite_record(workspace_id, &WORKSPACE_PRIVATE, invite);

        let err = project(&context(&record, Some((workspace_id, workspace_record))))
            .expect_err("authority mismatch must fail");

        assert_eq!(
            err,
            "bootstrap user_invite must use workspace as signer and authority"
        );
    }

    #[test]
    fn rejects_signer_key_that_does_not_match_workspace() {
        let (workspace_id, workspace_record) = workspace_record(&WORKSPACE_PRIVATE);
        let invite = super::super::types::UserInviteEvent {
            created_at_ms: 9,
            public_key: [3; 32],
            workspace_id,
            authority_event_id: workspace_id,
        };
        let record = signed_user_invite_record(workspace_id, &OTHER_PRIVATE, invite);

        let err = project(&context(&record, Some((workspace_id, workspace_record))))
            .expect_err("signer key mismatch must fail");

        assert_eq!(
            err,
            "signed user_invite signer key does not match workspace public key"
        );
    }
}
