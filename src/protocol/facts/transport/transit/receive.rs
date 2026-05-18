//! Admission rules for facts opened from inbound transport::transit frames.
//!
//! The receive handler owns retrying the effect. This module owns the
//! protocol-level meaning of an opened frame: which inner fact types can be
//! admitted, how they are scoped, and which local provenance fact records the
//! receive.

use crate::core::crypto;
use crate::core::facts::{Fact, FactId, FactScope};
use crate::protocol::facts::{connection, content, encryption, identity, sync, transport};

use super::frame;

#[derive(Debug, Clone)]
pub struct OpenReceivedFrame<'a> {
    pub frame: &'a [u8],
    pub connection_fact: &'a Fact,
    pub origin_addr: &'a [u8],
    pub received_at_local_ms: u64,
}

#[derive(Debug, Clone, Copy)]
pub enum BootstrapFrameKind {
    ConnectionRequest(connection::request::fact::ConnectionRequestFact),
    ConnectionResponse(connection::response::fact::ConnectionResponseFact),
    ConnectionFrame,
}

#[derive(Debug, Clone)]
pub struct OpenBootstrapRequest<'a> {
    pub frame: &'a [u8],
    pub invite_fact: &'a Fact,
    pub local_endpoint: &'a identity::endpoint::fact::EndpointFact,
    pub origin_addr: &'a [u8],
    pub received_at_local_ms: u64,
}

#[derive(Debug, Clone)]
pub struct OpenedBootstrapRequest {
    pub facts: Vec<Fact>,
}

#[derive(Debug, Clone)]
pub struct OpenBootstrapResponse<'a> {
    pub frame: &'a [u8],
    pub origin_addr: &'a [u8],
    pub received_at_local_ms: u64,
}

pub fn bootstrap_frame_kind(frame: &[u8]) -> Result<BootstrapFrameKind, String> {
    match frame.first().copied() {
        Some(connection::request::layout::TYPE_CONNECTION_REQUEST) => {
            connection::request::layout::decode_fact(frame)
                .map(BootstrapFrameKind::ConnectionRequest)
        }
        Some(connection::response::layout::TYPE_CONNECTION_RESPONSE) => {
            connection::response::layout::decode_fact(frame)
                .map(BootstrapFrameKind::ConnectionResponse)
        }
        _ => Ok(BootstrapFrameKind::ConnectionFrame),
    }
}

pub fn open_bootstrap_request(
    input: OpenBootstrapRequest<'_>,
) -> Result<OpenedBootstrapRequest, String> {
    let request = connection::request::layout::decode_fact(input.frame)?;
    let request_fact = Fact::new(
        FactScope::Global,
        input.received_at_local_ms,
        input.frame.to_vec(),
    );
    let invite = identity::invite::layout::decode_fact(&input.invite_fact.bytes)?;
    connection::request::create::validate_invite_signature(&request, &invite)?;

    if input.local_endpoint.endpoint != request.to_endpoint {
        return Err("bootstrap request addressed to a different endpoint".to_string());
    }
    if request.from_listen_addr.is_none() {
        return Err("bootstrap request did not advertise a return listener".to_string());
    }

    let provenance = received_provenance_fact_for_kind(
        request_fact.id,
        input.origin_addr,
        request.to_endpoint,
        request.from_endpoint,
        transport::transit_received::fact::TRANSIT_KIND_BOOTSTRAP,
        None,
        Some(request_fact.id),
        crypto::hash(input.frame),
        input.received_at_local_ms,
    )?;

    Ok(OpenedBootstrapRequest {
        facts: vec![request_fact, provenance],
    })
}

pub fn open_bootstrap_response(input: OpenBootstrapResponse<'_>) -> Result<Vec<Fact>, String> {
    let response = connection::response::layout::decode_fact(input.frame)?;
    let response_fact = Fact::new(
        FactScope::Local,
        input.received_at_local_ms,
        input.frame.to_vec(),
    );
    let provenance = received_provenance_fact_for_kind(
        response_fact.id,
        input.origin_addr,
        response.to_endpoint,
        response.from_endpoint,
        transport::transit_received::fact::TRANSIT_KIND_CONNECTION_HANDSHAKE,
        Some(response_fact.id),
        Some(response.request_id),
        crypto::hash(input.frame),
        input.received_at_local_ms,
    )?;
    Ok(vec![response_fact, provenance])
}

pub fn open_received_frame(input: OpenReceivedFrame<'_>) -> Result<Vec<Fact>, String> {
    let connection = connection::response::layout::decode_fact(&input.connection_fact.bytes)?;
    let opened = frame::open_connection_frame(input.frame, &connection.connection_secret)?;
    if input.connection_fact.id != opened.connection_id {
        return Err(
            "transport::transit frame connection id does not match connection fact".to_string(),
        );
    }
    require_connection_endpoints(
        &connection,
        opened.sender_endpoint_id,
        opened.receiver_endpoint_id,
    )?;

    let mut facts = Vec::with_capacity(opened.facts.len() * 2);
    for bytes in opened.facts {
        let received = admit_received_fact_bytes(bytes)?;
        let provenance = received_provenance_fact(
            received.id,
            input.origin_addr,
            opened.receiver_endpoint_id,
            opened.sender_endpoint_id,
            opened.connection_id,
            connection.request_id,
            opened.frame_hash,
            input.received_at_local_ms,
        )?;
        facts.push(received);
        facts.push(provenance);
    }
    Ok(facts)
}

fn admit_received_fact_bytes(bytes: Vec<u8>) -> Result<Fact, String> {
    let tag = bytes
        .first()
        .copied()
        .ok_or_else(|| "received transport::transit fact bytes are empty".to_string())?;
    match tag {
        identity::workspace::layout::TYPE_WORKSPACE => {
            let workspace = identity::workspace::layout::decode_fact(&bytes)?;
            return Ok(Fact::new(FactScope::Global, workspace.created_at_ms, bytes));
        }
        identity::user_invite::layout::TYPE_USER_INVITE => {
            let invite = identity::user_invite::layout::decode_fact(&bytes)?;
            return Ok(Fact::new(FactScope::Global, invite.created_at_ms, bytes));
        }
        identity::user::layout::TYPE_USER => {
            let user = identity::user::layout::decode_fact(&bytes)?;
            return Ok(Fact::new(FactScope::Global, user.created_at_ms, bytes));
        }
        identity::admin::layout::TYPE_ADMIN => {
            let admin = identity::admin::layout::decode_fact(&bytes)?;
            return Ok(Fact::new(FactScope::Global, admin.created_at_ms, bytes));
        }
        identity::device_invite::layout::TYPE_DEVICE_INVITE => {
            let invite = identity::device_invite::layout::decode_fact(&bytes)?;
            return Ok(Fact::new(FactScope::Global, invite.created_at_ms, bytes));
        }
        identity::endpoint_shared::layout::TYPE_ENDPOINT_SHARED => {
            let shared = identity::endpoint_shared::layout::decode_fact(&bytes)?;
            return Ok(Fact::new(FactScope::Global, shared.created_at_ms, bytes));
        }
        identity::invite_server::layout::TYPE_INVITE_SERVER => {
            let server = identity::invite_server::layout::decode_fact(&bytes)?;
            return Ok(Fact::new(FactScope::Global, server.created_at_ms, bytes));
        }
        encryption::disappearing_messages_setting::layout::TYPE_DISAPPEARING_MESSAGES_SETTING => {
            let setting = encryption::disappearing_messages_setting::layout::decode_fact(&bytes)?;
            return Ok(Fact::new(
                workspace_scope(setting.workspace_id),
                setting.created_at_ms,
                bytes,
            ));
        }
        content::event::layout::TYPE_CONTENT_EVENT => {
            let event = content::event::layout::decode_fact(&bytes)?;
            return Ok(Fact::new(
                workspace_scope(event.workspace_id),
                event.timestamp,
                bytes,
            ));
        }
        content::reaction::layout::TYPE_CONTENT_REACTION => {
            let reaction = content::reaction::layout::decode_fact(&bytes)?;
            return Ok(Fact::new(
                workspace_scope(reaction.workspace_id),
                reaction.created_at_ms,
                bytes,
            ));
        }
        content::file::layout::TYPE_CONTENT_FILE => {
            let file = content::file::layout::decode_fact(&bytes)?;
            return Ok(Fact::new(
                workspace_scope(file.workspace_id),
                file.created_at_ms,
                bytes,
            ));
        }
        content::file_slice::layout::TYPE_CONTENT_FILE_SLICE => {
            let slice = content::file_slice::layout::decode_fact(&bytes)?;
            return Ok(Fact::new(
                workspace_scope(slice.workspace_id),
                slice.created_at_ms,
                bytes,
            ));
        }
        content::file_deletion::layout::TYPE_CONTENT_FILE_DELETION => {
            let deletion = content::file_deletion::layout::decode_fact(&bytes)?;
            return Ok(Fact::new(
                workspace_scope(deletion.workspace_id),
                deletion.created_at_ms,
                bytes,
            ));
        }
        encryption::layout::TYPE_RECIPIENT_KEY
        | encryption::layout::TYPE_REMOVAL_FRONTIER
        | encryption::layout::TYPE_KEY_REQUEST => match tag {
            encryption::layout::TYPE_RECIPIENT_KEY => {
                let recipient = encryption::layout::decode_recipient_key(&bytes)?;
                return Ok(Fact::new(
                    workspace_scope(recipient.workspace_id),
                    recipient.created_at_ms,
                    bytes,
                ));
            }
            encryption::layout::TYPE_REMOVAL_FRONTIER => {
                let frontier = encryption::layout::decode_removal_frontier(&bytes)?;
                return Ok(Fact::new(
                    workspace_scope(frontier.workspace_id),
                    frontier.created_at_ms,
                    bytes,
                ));
            }
            encryption::layout::TYPE_KEY_REQUEST => {
                let request = encryption::layout::decode_key_request(&bytes)?;
                return Ok(Fact::new(
                    workspace_scope(request.workspace_id),
                    request.created_at_ms,
                    bytes,
                ));
            }
            _ => unreachable!(),
        },
        encryption::local_history_node_secret::layout::TYPE_LOCAL_HISTORY_NODE_SECRET => {
            return Err(
                "received transport::transit payload is local history-node secret".to_string(),
            );
        }
        encryption::removal_frontier::layout::TYPE_REMOVAL_FRONTIER => {
            let frontier = encryption::removal_frontier::layout::decode_fact(&bytes)?;
            return Ok(Fact::new(
                workspace_scope(frontier.workspace_id),
                frontier.created_at_ms,
                bytes,
            ));
        }
        content::sealed_message::layout::TYPE_SEALED_MESSAGE
        | content::sealed_message::layout::TYPE_SIGNER_PUBKEY
        | content::sealed_message::layout::TYPE_SECRET_NODE
        | content::sealed_message::layout::TYPE_MESSAGE_DELETION => match tag {
            content::sealed_message::layout::TYPE_SEALED_MESSAGE => {
                let message = content::sealed_message::layout::decode_sealed_message(&bytes)?;
                return Ok(Fact::new(
                    workspace_scope(message.workspace_id),
                    message.created_at_ms,
                    bytes,
                ));
            }
            content::sealed_message::layout::TYPE_SIGNER_PUBKEY => {
                content::sealed_message::layout::decode_signer_pubkey(&bytes)?;
                return Ok(Fact::new(FactScope::Global, 0, bytes));
            }
            content::sealed_message::layout::TYPE_SECRET_NODE => {
                let secret = content::sealed_message::layout::decode_secret_node(&bytes)?;
                return Ok(Fact::new(
                    workspace_scope(secret.workspace_id),
                    secret.start_minute,
                    bytes,
                ));
            }
            content::sealed_message::layout::TYPE_MESSAGE_DELETION => {
                let deletion = content::sealed_message::layout::decode_message_deletion(&bytes)?;
                return Ok(Fact::new(
                    workspace_scope(deletion.workspace_id),
                    deletion.created_at_ms,
                    bytes,
                ));
            }
            _ => unreachable!(),
        },
        sync::compare::layout::TYPE_SYNC_COMPARE => {
            sync::compare::layout::decode_fact(&bytes)?;
            return Ok(Fact::new(FactScope::Global, 0, bytes));
        }
        sync::have_id::layout::TYPE_SYNC_HAVE_ID => {
            sync::have_id::layout::decode_fact(&bytes)?;
            return Ok(Fact::new(FactScope::Global, 0, bytes));
        }
        sync::need_id::layout::TYPE_SYNC_NEED_ID => {
            sync::need_id::layout::decode_fact(&bytes)?;
            return Ok(Fact::new(FactScope::Global, 0, bytes));
        }
        identity::signed_fact::layout::TYPE_SIGNED_FACT => {}
        _ => {
            return Err(format!(
                "unsupported received transport::transit fact type {tag}"
            ))
        }
    }

    let envelope = identity::signed_fact::layout::decode_signed_fact(&bytes)?;
    match envelope.inner_type {
        identity::user_invite::layout::TYPE_USER_INVITE
        | identity::user::layout::TYPE_USER
        | identity::admin::layout::TYPE_ADMIN
        | identity::device_invite::layout::TYPE_DEVICE_INVITE
        | identity::endpoint_shared::layout::TYPE_ENDPOINT_SHARED
        | identity::invite_server::layout::TYPE_INVITE_SERVER => Ok(Fact::new(
            FactScope::Global,
            signed_identity_created_at_ms(&envelope)?,
            bytes,
        )),
        encryption::layout::TYPE_KEY_WRAP => encryption::create::admit_signed_key_wrap_fact(bytes),
        content::sealed_message::layout::TYPE_SEALED_MESSAGE => {
            let message =
                content::sealed_message::layout::decode_sealed_message(&envelope.payload)?;
            Ok(Fact::new(
                workspace_scope(message.workspace_id),
                message.created_at_ms,
                bytes,
            ))
        }
        other => Err(format!(
            "unsupported signed transport::transit payload type {other}"
        )),
    }
}

fn signed_identity_created_at_ms(
    envelope: &identity::signed_fact::fact::SignedFactEnvelope,
) -> Result<u64, String> {
    match envelope.inner_type {
        identity::user_invite::layout::TYPE_USER_INVITE => {
            identity::user_invite::layout::decode_fact(&envelope.payload)
                .map(|fact| fact.created_at_ms)
        }
        identity::user::layout::TYPE_USER => {
            identity::user::layout::decode_fact(&envelope.payload).map(|fact| fact.created_at_ms)
        }
        identity::admin::layout::TYPE_ADMIN => {
            identity::admin::layout::decode_fact(&envelope.payload).map(|fact| fact.created_at_ms)
        }
        identity::device_invite::layout::TYPE_DEVICE_INVITE => {
            identity::device_invite::layout::decode_fact(&envelope.payload)
                .map(|fact| fact.created_at_ms)
        }
        identity::endpoint_shared::layout::TYPE_ENDPOINT_SHARED => {
            identity::endpoint_shared::layout::decode_fact(&envelope.payload)
                .map(|fact| fact.created_at_ms)
        }
        identity::invite_server::layout::TYPE_INVITE_SERVER => {
            identity::invite_server::layout::decode_fact(&envelope.payload)
                .map(|fact| fact.created_at_ms)
        }
        other => Err(format!(
            "signed identity timestamp unsupported for type {other}"
        )),
    }
}

fn workspace_scope(workspace_id: FactId) -> FactScope {
    crate::protocol::matchers::workspace_scope(workspace_id)
}

fn received_provenance_fact(
    received_fact_id: FactId,
    origin_addr: &[u8],
    local_endpoint_id: FactId,
    sender_endpoint_id: FactId,
    connection_id: FactId,
    request_id: FactId,
    frame_hash: [u8; 32],
    received_at_local_ms: u64,
) -> Result<Fact, String> {
    received_provenance_fact_for_kind(
        received_fact_id,
        origin_addr,
        local_endpoint_id,
        sender_endpoint_id,
        transport::transit_received::fact::TRANSIT_KIND_CONNECTION,
        Some(connection_id),
        Some(request_id),
        frame_hash,
        received_at_local_ms,
    )
}

fn received_provenance_fact_for_kind(
    received_fact_id: FactId,
    origin_addr: &[u8],
    local_endpoint_id: FactId,
    sender_endpoint_id: FactId,
    transit_kind: u8,
    connection_id: Option<FactId>,
    request_id: Option<FactId>,
    frame_hash: [u8; 32],
    received_at_local_ms: u64,
) -> Result<Fact, String> {
    let fact = transport::transit_received::fact::TransitReceivedFact {
        received_fact_id,
        origin_addr: origin_addr.to_vec(),
        local_endpoint_id,
        sender_endpoint_id,
        transit_kind,
        connection_id,
        request_id,
        frame_hash,
        received_at_local_ms,
    };
    Ok(Fact::new(
        FactScope::Local,
        received_at_local_ms,
        transport::transit_received::layout::encode_fact(&fact)?,
    ))
}

fn require_connection_endpoints(
    connection: &connection::response::fact::ConnectionResponseFact,
    sender_endpoint_id: FactId,
    receiver_endpoint_id: FactId,
) -> Result<(), String> {
    let forward = sender_endpoint_id == connection.from_endpoint
        && receiver_endpoint_id == connection.to_endpoint;
    let reverse = sender_endpoint_id == connection.to_endpoint
        && receiver_endpoint_id == connection.from_endpoint;
    if forward || reverse {
        Ok(())
    } else {
        Err("transport::transit frame endpoints do not match connection fact".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::crypto::{ed25519_public_key, ed25519_sign};
    use crate::protocol::facts::content::sealed_message::fact::MessageDeletionFact;
    use crate::protocol::facts::identity::endpoint::fact::EndpointFact;
    use crate::protocol::facts::identity::invite::fact::InviteSecretFact;
    use crate::protocol::facts::identity::signed_fact::fact::SignedFactEnvelope;
    use crate::protocol::facts::identity::user::fact::UserFact;
    use crate::protocol::facts::identity::workspace::fact::WorkspaceFact;

    #[test]
    fn admitted_message_deletion_uses_payload_created_timestamp() {
        let deletion = MessageDeletionFact {
            workspace_id: [9; 32],
            created_at_ms: 12_345,
            target_id: [10; 32],
            author_user_id: [11; 32],
        };
        let bytes = content::sealed_message::layout::encode_message_deletion(&deletion)
            .expect("encode deletion");

        let admitted = admit_received_fact_bytes(bytes.clone()).expect("admit deletion");

        assert_eq!(admitted.scope, workspace_scope(deletion.workspace_id));
        assert_eq!(admitted.timestamp, deletion.created_at_ms);
        assert_eq!(admitted.bytes, bytes);
    }

    #[test]
    fn admitted_workspace_uses_payload_created_timestamp() {
        let workspace = WorkspaceFact {
            created_at_ms: 55_555,
            public_key: [7; 32],
            name: "workspace".to_string(),
        };
        let bytes = identity::workspace::layout::encode_fact(&workspace).expect("workspace");

        let admitted = admit_received_fact_bytes(bytes.clone()).expect("admit workspace");

        assert_eq!(admitted.scope, FactScope::Global);
        assert_eq!(admitted.timestamp, workspace.created_at_ms);
        assert_eq!(admitted.bytes, bytes);
    }

    #[test]
    fn admitted_signed_identity_uses_payload_created_timestamp() {
        let user = UserFact {
            created_at_ms: 66_666,
            workspace_id: [8; 32],
            public_key: [9; 32],
            username: "alice".to_string(),
        };
        let payload = identity::user::layout::encode_fact(&user).expect("user payload");
        let signing_secret = [10; 32];
        let mut envelope = SignedFactEnvelope {
            signer_id: [11; 32],
            signer_public_key: ed25519_public_key(&signing_secret),
            inner_type: identity::user::layout::TYPE_USER,
            payload,
            signature: [0; 64],
        };
        let signing_bytes =
            identity::signed_fact::layout::signing_bytes(&envelope).expect("signing bytes");
        envelope.signature = ed25519_sign(&signing_secret, &signing_bytes);
        let bytes =
            identity::signed_fact::layout::encode_signed_fact(&envelope).expect("signed identity");

        let admitted = admit_received_fact_bytes(bytes.clone()).expect("admit signed user");

        assert_eq!(admitted.scope, FactScope::Global);
        assert_eq!(admitted.timestamp, user.created_at_ms);
        assert_eq!(admitted.bytes, bytes);
    }

    #[test]
    fn duplicate_bootstrap_request_delivery_emits_only_request_and_provenance() {
        let invite = InviteSecretFact::new([33; 32]);
        let invite_fact = Fact::new(
            FactScope::Local,
            10,
            identity::invite::layout::encode_fact(&invite).expect("invite"),
        );
        let endpoint_secret = [44; 32];
        let signing_secret = [45; 32];
        let endpoint = EndpointFact {
            endpoint: crypto::x25519_public_key(&endpoint_secret),
            secret: endpoint_secret,
            signing_public_key: ed25519_public_key(&signing_secret),
            signing_secret,
        };
        let mut request = connection::request::fact::ConnectionRequestFact {
            from_endpoint: crypto::x25519_public_key(&[55; 32]),
            to_endpoint: endpoint.endpoint,
            nonce: [56; 32],
            invite_fact_id: [57; 32],
            bootstrap_hash: invite.bootstrap_hash,
            invite_signature: [0; crypto::ED25519_SIGNATURE_BYTES],
            invite_secret_fact_id: invite_fact.id,
            initiator_ephemeral_secret_fact_id: [58; 32],
            initiator_ephemeral_public_key: crypto::x25519_public_key(&[59; 32]),
            from_listen_addr: Some("127.0.0.1:41001".parse().expect("return addr")),
            to_listen_addr: None,
        };
        request.invite_signature = ed25519_sign(
            &invite.bootstrap_secret,
            &connection::request::create::invite_signing_transcript(&request)
                .expect("request transcript"),
        );
        let frame = connection::request::layout::encode_fact(&request).expect("request");

        let first = open_bootstrap_request(OpenBootstrapRequest {
            frame: &frame,
            invite_fact: &invite_fact,
            local_endpoint: &endpoint,
            origin_addr: b"127.0.0.1:41002",
            received_at_local_ms: 100,
        })
        .expect("first delivery");
        let second = open_bootstrap_request(OpenBootstrapRequest {
            frame: &frame,
            invite_fact: &invite_fact,
            local_endpoint: &endpoint,
            origin_addr: b"127.0.0.1:41002",
            received_at_local_ms: 200,
        })
        .expect("duplicate delivery");

        assert_eq!(first.facts.len(), 2);
        assert_eq!(second.facts.len(), 2);
        let stable_first = non_provenance_fact_ids(&first.facts);
        let stable_second = non_provenance_fact_ids(&second.facts);
        assert_eq!(stable_first, stable_second);
        assert_eq!(stable_first.len(), 1);
        assert!(first.facts.iter().all(|fact| {
            !matches!(
                fact.body().first().copied(),
                Some(connection::ephemeral_secret::layout::TYPE_CONNECTION_EPHEMERAL_SECRET)
                    | Some(connection::response::layout::TYPE_CONNECTION_RESPONSE)
            )
        }));
    }

    fn non_provenance_fact_ids(facts: &[Fact]) -> Vec<FactId> {
        let mut ids = facts
            .iter()
            .filter(|fact| {
                fact.body().first().copied()
                    != Some(transport::transit_received::layout::TYPE_TRANSIT_RECEIVED)
            })
            .map(|fact| fact.id)
            .collect::<Vec<_>>();
        ids.sort();
        ids
    }
}
