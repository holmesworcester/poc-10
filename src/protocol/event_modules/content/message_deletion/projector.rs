//! Projector for signed message deletions.
//!
//! Deletion is projected as a generic context update attached to the target
//! message id plus a purge intent for the physical cleanup worker. The
//! deletion event does not depend on the target message, so it cannot inspect
//! the target author here; target projectors and the purge worker authorize
//! row cleanup against the retained update when the target bytes are available.

use crate::protocol::event_modules::identity::{endpoint_shared, signed, user};
use crate::protocol::event_modules::rows::ContextUpdate;
use crate::protocol::event_modules::worker::{EventWithContext, ProjectionOutput};

use super::layout;
use super::rows::{purge_instruction_row, PurgeKind};
use super::types::deletion_label;

pub fn project(event: &EventWithContext<'_>) -> Result<ProjectionOutput, String> {
    let envelope = layout::decode_signed(&event.record.canonical_bytes)?;
    let deletion = layout::decode(&envelope.payload)?;
    if event.record.workspace_id != Some(deletion.workspace_id) {
        return Err("deletion workspace metadata does not match event body".to_string());
    }

    let signer = event
        .context
        .require_dependency(&envelope.signer_endpoint_shared_id)?;
    let signer_envelope = signed::layout::decode(&signer.canonical_bytes)
        .map_err(|_| "deletion signer dependency is not a signed endpoint_shared".to_string())?;
    if signer_envelope.inner_type != endpoint_shared::layout::TYPE_ENDPOINT_SHARED {
        return Err("deletion signer dependency is not a signed endpoint_shared".to_string());
    }
    let signer_endpoint_shared = endpoint_shared::layout::decode(&signer_envelope.payload)
        .map_err(|_| "deletion signer dependency is not a signed endpoint_shared".to_string())?;
    if signer_endpoint_shared.workspace_id != deletion.workspace_id {
        return Err(
            "deletion signer endpoint_shared workspace does not match deletion".to_string(),
        );
    }
    if signer_endpoint_shared.signing_public_key != envelope.signer_public_key {
        return Err("deletion signer public key does not match endpoint_shared".to_string());
    }
    if signer_endpoint_shared.user_authority_event_id != deletion.author_user_id {
        return Err("deletion signer endpoint is not authorized by the named author".to_string());
    }

    let author = event.context.require_dependency(&deletion.author_user_id)?;
    let author_envelope = signed::layout::decode(&author.canonical_bytes)
        .map_err(|_| "deletion author dependency is not a signed user".to_string())?;
    if author_envelope.inner_type != user::layout::TYPE_USER {
        return Err("deletion author dependency is not a signed user".to_string());
    }
    let author_user = user::layout::decode(&author_envelope.payload)
        .map_err(|_| "deletion author dependency is not a signed user".to_string())?;
    if author_user.workspace_id != deletion.workspace_id {
        return Err("deletion author workspace does not match deletion".to_string());
    }

    Ok(ProjectionOutput::table_writes_and_context_updates(
        vec![purge_instruction_row(
            deletion.workspace_id,
            deletion.target_message_id,
            PurgeKind::Message,
        )],
        vec![ContextUpdate {
            event_id: deletion.target_message_id,
            update: deletion_label(&deletion.author_user_id),
        }],
    ))
}

#[cfg(test)]
mod tests {
    use crate::protocol::event_modules::identity::{endpoint_shared, signed, user};
    use crate::protocol::event_modules::types::{event_id, EventScope};
    use crate::protocol::event_modules::worker::{
        DependencyContext, EventContext, EventWithContext,
    };

    use super::super::types::{deletion_label, MessageDeletionEvent};
    use super::*;

    type Record = crate::protocol::event_modules::types::EventRecord;

    fn signing_public_key_for(private_key: &[u8; 32]) -> [u8; 32] {
        layout::sign([0; 32], private_key, vec![layout::TYPE_MESSAGE_DELETION]).signer_public_key
    }

    fn endpoint_shared_record(
        workspace_id: [u8; 32],
        user_id: [u8; 32],
        signing_public_key: [u8; 32],
    ) -> Record {
        let payload =
            endpoint_shared::layout::encode(&endpoint_shared::types::EndpointSharedEvent {
                created_at_ms: 4,
                workspace_id,
                user_authority_event_id: user_id,
                endpoint_id: [21; 32],
                signing_public_key,
                endpoint_role:
                    crate::protocol::event_modules::identity::endpoint::types::EndpointRole::Device,
                device_name: "laptop".to_string(),
            })
            .expect("encode endpoint_shared");
        let signed = signed::commands::sign_payload([6; 32], &[5; 32], payload)
            .expect("sign endpoint_shared");
        signed.events[0].record().clone()
    }

    fn user_record(workspace_id: [u8; 32]) -> Record {
        let payload = user::layout::encode(&user::types::UserEvent {
            created_at_ms: 3,
            workspace_id,
            public_key: [22; 32],
            username: "alice".to_string(),
        })
        .expect("encode user");
        let signed =
            signed::commands::sign_payload([24; 32], &[25; 32], payload).expect("sign user");
        signed.events[0].record().clone()
    }

    fn build(
        workspace_id: [u8; 32],
        author_user_id: [u8; 32],
        target_message_id: [u8; 32],
        signer_id: [u8; 32],
        signer_private_key: &[u8; 32],
    ) -> (Record, [u8; 32]) {
        let payload = layout::encode(&MessageDeletionEvent {
            workspace_id,
            created_at_ms: 7,
            target_message_id,
            author_user_id,
        });
        let envelope = layout::sign(signer_id, signer_private_key, payload);
        let bytes = layout::encode_signed(&envelope);
        let id = event_id(&bytes);
        (layout::signed_record_from_bytes(bytes).expect("record"), id)
    }

    #[test]
    fn projects_label_on_target_message_id_carrying_deletion_author() {
        let workspace_id = [7; 32];
        let signer_private_key = [9; 32];
        let signer_pubkey = signing_public_key_for(&signer_private_key);
        let author_record = user_record(workspace_id);
        let author_id = event_id(&author_record.canonical_bytes);
        let signer_record = endpoint_shared_record(workspace_id, author_id, signer_pubkey);
        let signer_id = event_id(&signer_record.canonical_bytes);
        let target_id = [99; 32];

        let (record, deletion_id) = build(
            workspace_id,
            author_id,
            target_id,
            signer_id,
            &signer_private_key,
        );

        let event = EventWithContext {
            record: &record,
            context: EventContext {
                event_id: deletion_id,
                dependencies: vec![
                    DependencyContext {
                        event_id: signer_id,
                        record: signer_record,
                        updates: Vec::new(),
                    },
                    DependencyContext {
                        event_id: author_id,
                        record: author_record,
                        updates: Vec::new(),
                    },
                ],
                updates: Vec::new(),
                receive: None,
                now_unix_minute: None,
            },
        };
        let output = project(&event).expect("project deletion");

        assert_eq!(output.legacy_rows().len(), 1);
        assert_eq!(
            output.legacy_rows()[0].table,
            super::super::rows::PURGE_INSTRUCTIONS
        );
        let mut expected_key = workspace_id.to_vec();
        expected_key.extend_from_slice(&target_id);
        assert_eq!(output.legacy_rows()[0].key, expected_key);
        assert_eq!(
            output.legacy_rows()[0].value,
            vec![PurgeKind::Message.as_byte()]
        );
        assert!(output.legacy_deletes().is_empty());
        assert_eq!(output.legacy_context_updates().len(), 1);
        assert_eq!(output.legacy_context_updates()[0].event_id, target_id);
        assert_eq!(
            output.legacy_context_updates()[0].update,
            deletion_label(&author_id)
        );
    }

    #[test]
    fn rejects_signer_for_other_workspace() {
        let workspace_id = [7; 32];
        let other_workspace = [8; 32];
        let signer_private_key = [9; 32];
        let signer_pubkey = signing_public_key_for(&signer_private_key);
        let author_record = user_record(workspace_id);
        let author_id = event_id(&author_record.canonical_bytes);
        let signer_record = endpoint_shared_record(other_workspace, author_id, signer_pubkey);
        let signer_id = event_id(&signer_record.canonical_bytes);

        let (record, deletion_id) = build(
            workspace_id,
            author_id,
            [99; 32],
            signer_id,
            &signer_private_key,
        );

        let event = EventWithContext {
            record: &record,
            context: EventContext {
                event_id: deletion_id,
                dependencies: vec![
                    DependencyContext {
                        event_id: signer_id,
                        record: signer_record,
                        updates: Vec::new(),
                    },
                    DependencyContext {
                        event_id: author_id,
                        record: author_record,
                        updates: Vec::new(),
                    },
                ],
                updates: Vec::new(),
                receive: None,
                now_unix_minute: None,
            },
        };

        assert_eq!(
            project(&event).expect_err("workspace mismatch must fail"),
            "deletion signer endpoint_shared workspace does not match deletion"
        );
    }

    #[test]
    fn record_has_three_dependencies_signer_workspace_author_only() {
        let payload = layout::encode(&MessageDeletionEvent {
            workspace_id: [7; 32],
            created_at_ms: 5,
            target_message_id: [10; 32],
            author_user_id: [11; 32],
        });
        let envelope = layout::sign([12; 32], &[13; 32], payload);
        let bytes = layout::encode_signed(&envelope);
        let record = layout::signed_record_from_bytes(bytes).expect("record");
        assert_eq!(record.dependencies, vec![[12; 32], [7; 32], [11; 32]]);
        assert_eq!(record.scope, EventScope::Shared);
    }

    #[test]
    fn raw_deletion_bytes_are_not_admissible() {
        let payload = layout::encode(&MessageDeletionEvent {
            workspace_id: [7; 32],
            created_at_ms: 5,
            target_message_id: [2; 32],
            author_user_id: [3; 32],
        });
        assert_eq!(
            crate::protocol::event_modules::event_from_bytes(payload)
                .expect_err("raw deletion must fail"),
            "message deletion must be signed"
        );
    }
}
