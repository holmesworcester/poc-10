//! Projector for signed key-request events.

use crate::protocol::event_modules::identity::{endpoint_shared, signed};
use crate::protocol::event_modules::worker::{EventWithContext, ProjectionOutput};

use super::super::{recipient_key, removal_frontier};
use super::{codec, commands, schema};

pub fn project(event: &EventWithContext<'_>) -> Result<ProjectionOutput, String> {
    let envelope = codec::decode_signed(&event.record.canonical_bytes)?;
    let request = codec::decode(&envelope.payload)?;
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

    Ok(ProjectionOutput::rows(vec![
        schema::pending_key_request_row(
            event.context.event_id,
            envelope.signer_endpoint_shared_id,
            &request,
        ),
    ]))
}

fn decode_endpoint_shared(
    event: &EventWithContext<'_>,
    endpoint_shared_id: [u8; 32],
    role: &str,
) -> Result<endpoint_shared::types::EndpointSharedEvent, String> {
    let record = event
        .context
        .dependency(&endpoint_shared_id)
        .ok_or_else(|| format!("key request {role} endpoint_shared dependency is missing"))?;
    let envelope = signed::codec::decode(&record.canonical_bytes)
        .map_err(|_| format!("key request {role} dependency is not a signed endpoint_shared"))?;
    if envelope.inner_type != endpoint_shared::codec::TYPE_ENDPOINT_SHARED {
        return Err(format!(
            "key request {role} dependency is not a signed endpoint_shared"
        ));
    }
    endpoint_shared::codec::decode(&envelope.payload)
        .map_err(|_| format!("key request {role} dependency is not a signed endpoint_shared"))
}

fn decode_removal_frontier(
    event: &EventWithContext<'_>,
    removal_frontier_id: [u8; 32],
) -> Result<removal_frontier::types::RemovalFrontierEvent, String> {
    let record = event
        .context
        .dependency(&removal_frontier_id)
        .ok_or_else(|| "key request removal frontier dependency is missing".to_string())?;
    let envelope = removal_frontier::codec::decode_signed(&record.canonical_bytes)
        .map_err(|_| "key request dependency is not a removal frontier".to_string())?;
    removal_frontier::codec::decode(&envelope.payload)
        .map_err(|_| "key request dependency is not a removal frontier".to_string())
}

fn decode_recipient_key(
    event: &EventWithContext<'_>,
    recipient_key_id: [u8; 32],
) -> Result<recipient_key::types::RecipientKeyEvent, String> {
    let record = event
        .context
        .dependency(&recipient_key_id)
        .ok_or_else(|| "key request recipient key dependency is missing".to_string())?;
    let envelope = recipient_key::codec::decode_signed(&record.canonical_bytes)
        .map_err(|_| "key request dependency is not a recipient key".to_string())?;
    recipient_key::codec::decode(&envelope.payload)
        .map_err(|_| "key request dependency is not a recipient key".to_string())
}
