//! Projector for signed key-request events.
//!
//! Projection validates that the requester can receive key wraps, that the
//! responder and removal frontier belong to the same workspace, and that the
//! requested recipient key is owned by the requester endpoint. Missing direct
//! dependencies become projector wait decisions through `require_dependency`.
//! The projector only writes a pending worker row; it does not create wraps.

use crate::protocol::event_modules::identity::{endpoint_shared, signed};
use crate::protocol::event_modules::worker::{EventWithContext, ProjectionOutput};

use super::super::{recipient_key, removal_frontier};
use super::{commands, layout, rows};

pub fn project(event: &EventWithContext<'_>) -> Result<ProjectionOutput, String> {
    let envelope = layout::decode_signed(&event.record.canonical_bytes)?;
    let request = layout::decode(&envelope.payload)?;
    commands::validate_event_ids(&request)?;
    if event.record.workspace_id != Some(request.workspace_id) {
        return Err("key request workspace metadata does not match event body".to_string());
    }

    let requester = decode_endpoint_shared(event, envelope.signer_endpoint_shared_id, "requester")?;
    if requester.workspace_id != request.workspace_id {
        return Err(
            "key request requester endpoint_shared workspace does not match event".to_string(),
        );
    }
    if requester.signing_public_key != envelope.signer_public_key {
        return Err("key request signer public key does not match endpoint_shared".to_string());
    }
    if !requester.endpoint_role.can_receive_key_wraps() {
        return Err("key request requester endpoint role cannot receive key wraps".to_string());
    }

    let responder =
        decode_endpoint_shared(event, request.responder_endpoint_shared_id, "responder")?;
    if responder.workspace_id != request.workspace_id {
        return Err(
            "key request responder endpoint_shared workspace does not match event".to_string(),
        );
    }

    let frontier = decode_removal_frontier(event, request.removal_frontier_id)?;
    if frontier.workspace_id != request.workspace_id {
        return Err("key request removal frontier workspace does not match event".to_string());
    }

    let recipient = decode_recipient_key(event, request.recipient_key_id)?;
    if recipient.workspace_id != request.workspace_id {
        return Err("key request recipient key workspace does not match event".to_string());
    }
    if recipient.endpoint_shared_id != envelope.signer_endpoint_shared_id {
        return Err("key request recipient key is not owned by requester".to_string());
    }

    Ok(ProjectionOutput::table_writes(vec![rows::pending_key_request_row(
        event.context.event_id,
        envelope.signer_endpoint_shared_id,
        &request,
    )]))
}

fn decode_endpoint_shared(
    event: &EventWithContext<'_>,
    endpoint_shared_id: [u8; 32],
    role: &str,
) -> Result<endpoint_shared::types::EndpointSharedEvent, String> {
    let record = event.context.require_dependency(&endpoint_shared_id)?;
    let envelope = signed::layout::decode(&record.canonical_bytes)
        .map_err(|_| format!("key request {role} dependency is not a signed endpoint_shared"))?;
    if envelope.inner_type != endpoint_shared::layout::TYPE_ENDPOINT_SHARED {
        return Err(format!(
            "key request {role} dependency is not a signed endpoint_shared"
        ));
    }
    endpoint_shared::layout::decode(&envelope.payload)
        .map_err(|_| format!("key request {role} dependency is not a signed endpoint_shared"))
}

fn decode_removal_frontier(
    event: &EventWithContext<'_>,
    removal_frontier_id: [u8; 32],
) -> Result<removal_frontier::types::RemovalFrontierEvent, String> {
    let record = event.context.require_dependency(&removal_frontier_id)?;
    let envelope = removal_frontier::layout::decode_signed(&record.canonical_bytes)
        .map_err(|_| "key request dependency is not a removal frontier".to_string())?;
    removal_frontier::layout::decode(&envelope.payload)
        .map_err(|_| "key request dependency is not a removal frontier".to_string())
}

fn decode_recipient_key(
    event: &EventWithContext<'_>,
    recipient_key_id: [u8; 32],
) -> Result<recipient_key::types::RecipientKeyEvent, String> {
    let record = event.context.require_dependency(&recipient_key_id)?;
    let envelope = recipient_key::layout::decode_signed(&record.canonical_bytes)
        .map_err(|_| "key request dependency is not a recipient key".to_string())?;
    recipient_key::layout::decode(&envelope.payload)
        .map_err(|_| "key request dependency is not a recipient key".to_string())
}

#[cfg(test)]
mod tests {
    use crate::core::crypto as core_crypto;
    use crate::protocol::event_modules::identity::endpoint::types::EndpointRole;
    use crate::protocol::event_modules::types::{event_id, EventId};
    use crate::protocol::event_modules::worker::{
        DependencyContext, EventContext, EventWithContext,
    };

    use super::super::super::local_recipient_key;
    use super::*;

    type Record = crate::protocol::event_modules::types::EventRecord;

    fn endpoint_shared_record(
        workspace_id: EventId,
        signing_public_key: EventId,
        endpoint_role: EndpointRole,
        endpoint_id: EventId,
    ) -> Record {
        let payload =
            endpoint_shared::layout::encode(&endpoint_shared::types::EndpointSharedEvent {
                created_at_ms: 4,
                workspace_id,
                user_authority_event_id: [3; 32],
                endpoint_id,
                signing_public_key,
                endpoint_role,
                device_name: "device".to_string(),
            })
            .expect("encode endpoint_shared");
        signed::commands::sign_payload([6; 32], &[5; 32], payload)
            .expect("sign endpoint_shared")
            .events[0]
            .record()
            .clone()
    }

    fn frontier_record(workspace_id: EventId) -> (EventId, Record) {
        let record =
            removal_frontier::commands::create(removal_frontier::commands::CreateRemovalFrontier {
                workspace_id,
                created_at_ms: 5,
                authority_admin_id: [3; 32],
                signer_endpoint_shared_id: [4; 32],
                signer_private_key: [9; 32],
                removal_event_ids: Vec::new(),
            })
            .expect("create frontier")
            .events[0]
                .record()
                .clone();
        (event_id(&record.canonical_bytes), record)
    }

    fn recipient_record(
        workspace_id: EventId,
        endpoint_shared_id: EventId,
        signer_private_key: [u8; 32],
    ) -> (EventId, Record) {
        let local = local_recipient_key::commands::create(workspace_id)
            .expect("local recipient")
            .value;
        let record =
            recipient_key::commands::publish(recipient_key::commands::PublishRecipientKey {
                workspace_id,
                created_at_ms: 6,
                endpoint_shared_id,
                signer_private_key,
                recipient_key: local.recipient_key,
                previous_recipient_key_id: recipient_key::types::NO_PREVIOUS_RECIPIENT_KEY,
            })
            .expect("publish recipient")
            .events[0]
                .record()
                .clone();
        (event_id(&record.canonical_bytes), record)
    }

    fn request_record(
        workspace_id: EventId,
        requester_endpoint_shared_id: EventId,
        requester_private_key: [u8; 32],
        responder_endpoint_shared_id: EventId,
        removal_frontier_id: EventId,
        recipient_key_id: EventId,
    ) -> Record {
        commands::request(commands::RequestKeys {
            workspace_id,
            created_at_ms: 7,
            requester_endpoint_shared_id,
            requester_private_key,
            responder_endpoint_shared_id,
            removal_frontier_id,
            recipient_key_id,
        })
        .expect("request keys")
        .events[0]
            .record()
            .clone()
    }

    fn event_with_context<'a>(
        record: &'a Record,
        dependencies: Vec<(EventId, Record)>,
    ) -> EventWithContext<'a> {
        EventWithContext {
            record,
            context: EventContext {
                event_id: event_id(&record.canonical_bytes),
                dependencies: dependencies
                    .into_iter()
                    .map(|(event_id, record)| DependencyContext {
                        event_id,
                        record,
                        updates: Vec::new(),
                    })
                    .collect(),
                updates: Vec::new(),
                receive: None,
                now_unix_minute: None,
            },
        }
    }

    fn valid_fixture() -> (
        EventId,
        EventId,
        EventId,
        EventId,
        Record,
        Vec<(EventId, Record)>,
    ) {
        let workspace_id = [1; 32];
        let requester_private_key = [9; 32];
        let responder_private_key = [8; 32];
        let requester_record = endpoint_shared_record(
            workspace_id,
            core_crypto::ed25519_public_key(&requester_private_key),
            EndpointRole::Device,
            [21; 32],
        );
        let requester_id = event_id(&requester_record.canonical_bytes);
        let responder_record = endpoint_shared_record(
            workspace_id,
            core_crypto::ed25519_public_key(&responder_private_key),
            EndpointRole::Device,
            [22; 32],
        );
        let responder_id = event_id(&responder_record.canonical_bytes);
        let (frontier_id, frontier_record) = frontier_record(workspace_id);
        let (recipient_id, recipient_record) =
            recipient_record(workspace_id, requester_id, requester_private_key);
        let request_record = request_record(
            workspace_id,
            requester_id,
            requester_private_key,
            responder_id,
            frontier_id,
            recipient_id,
        );
        (
            requester_id,
            responder_id,
            frontier_id,
            recipient_id,
            request_record,
            vec![
                (requester_id, requester_record),
                (responder_id, responder_record),
                (frontier_id, frontier_record),
                (recipient_id, recipient_record),
            ],
        )
    }

    #[test]
    fn projects_pending_key_request_for_valid_dependencies() {
        let (requester_id, responder_id, frontier_id, recipient_id, record, dependencies) =
            valid_fixture();
        let event = event_with_context(&record, dependencies);

        let output = project(&event).expect("project");

        assert_eq!(output.legacy_rows().len(), 1);
        assert_eq!(output.legacy_rows()[0].table, rows::PENDING_KEY_REQUESTS);
        let row = rows::decode_pending_key_request_row(
            output.legacy_rows()[0].key.clone(),
            &output.legacy_rows()[0].value,
        )
        .expect("decode row");
        assert_eq!(row.workspace_id, [1; 32]);
        assert_eq!(row.requester_endpoint_shared_id, requester_id);
        assert_eq!(row.responder_endpoint_shared_id, responder_id);
        assert_eq!(row.removal_frontier_id, frontier_id);
        assert_eq!(row.recipient_key_id, recipient_id);
        assert_eq!(row.key_request_id, event.context.event_id);
    }

    #[test]
    fn rejects_recipient_key_not_owned_by_requester() {
        let workspace_id = [1; 32];
        let requester_private_key = [9; 32];
        let responder_private_key = [8; 32];
        let requester_record = endpoint_shared_record(
            workspace_id,
            core_crypto::ed25519_public_key(&requester_private_key),
            EndpointRole::Device,
            [21; 32],
        );
        let requester_id = event_id(&requester_record.canonical_bytes);
        let responder_record = endpoint_shared_record(
            workspace_id,
            core_crypto::ed25519_public_key(&responder_private_key),
            EndpointRole::Device,
            [22; 32],
        );
        let responder_id = event_id(&responder_record.canonical_bytes);
        let (frontier_id, frontier_record) = frontier_record(workspace_id);
        let (recipient_id, recipient_record) =
            recipient_record(workspace_id, responder_id, responder_private_key);
        let record = request_record(
            workspace_id,
            requester_id,
            requester_private_key,
            responder_id,
            frontier_id,
            recipient_id,
        );
        let event = event_with_context(
            &record,
            vec![
                (requester_id, requester_record),
                (responder_id, responder_record),
                (frontier_id, frontier_record),
                (recipient_id, recipient_record),
            ],
        );

        let err = project(&event).expect_err("recipient owner mismatch");

        assert_eq!(err, "key request recipient key is not owned by requester");
    }
}
