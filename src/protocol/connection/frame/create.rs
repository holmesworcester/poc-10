//! Connection-frame sealing, classification, and child admission.
//!
//! Outbound connection sends call this module to reject private/local payloads
//! and seal an ordered fact bundle into fixed small or large frame bytes.
//! Inbound receive handling calls the same module to classify raw network bytes
//! into bootstrap request/response facts or ephemeral frame facts. Frame
//! projection calls it again to open a frame and turn each inner payload into a
//! durable child fact plus receipt.
//!
//! The invariants are deliberately split: socket metadata enters only through
//! `ReceivedNetworkFrame`, connection secrets come only from matched local
//! `connection::response` context, and child facts are admitted through their
//! owning typed codecs. Keep cryptographic frame mechanics here; keep socket IO
//! in core/network handlers and semantic child validation in each child family.

use crate::core::crypto;
use crate::core::effects::PipelineEffects;
use crate::core::facts::{Fact, FactId, FactScope};
use crate::core::projectors::FactCodec;
use crate::protocol::{auth, connection, content, sync};

use super::fact::{ConnectionFrameLargeFact, ConnectionFrameSmallFact};
use super::frame::{self, ConnectionFrameFactBundle, SealConnectionFrame};

/// Return the bytes that may be packaged into a connection::frame frame.
///
/// Local facts and private/local fact tags are never connection-frame payloads. A
/// signed envelope is parsed here as a defensive check that the envelope is
/// well-formed and does not hide a private local payload type. Signature
/// verification belongs to the semantic projector once signer context exists.
pub fn require_sendable_fact(fact: &Fact) -> Result<&[u8], String> {
    if fact.scope == FactScope::Local {
        return Err(format!(
            "connection::frame send refused local fact {:?}",
            fact.id
        ));
    }

    let tag = fact
        .bytes
        .first()
        .copied()
        .ok_or_else(|| format!("connection::frame send refused empty fact {:?}", fact.id))?;
    if is_private_local_fact_tag(tag) {
        return Err(format!(
            "connection::frame send refused private/local fact tag {tag} for {:?}",
            fact.id
        ));
    }

    if tag == auth::signed_fact::layout::TYPE_SIGNED_FACT {
        let envelope =
            auth::signed_fact::layout::decode_signed_fact(fact.body()).map_err(|err| {
                format!(
                    "connection::frame send refused invalid signed fact {:?}: {err}",
                    fact.id
                )
            })?;
        if is_private_local_fact_tag(envelope.inner_type) {
            return Err(format!(
                "connection::frame send refused private/local signed payload tag {} for {:?}",
                envelope.inner_type, fact.id
            ));
        }
    }

    Ok(fact.body())
}

pub fn is_private_local_fact_tag(tag: u8) -> bool {
    matches!(
        tag,
        connection::close::layout::TYPE_CONNECTION_CLOSE
            | connection::ephemeral_secret::layout::TYPE_CONNECTION_EPHEMERAL_SECRET
            | connection::request::layout::TYPE_CONNECTION_REQUEST
            | connection::response::layout::TYPE_CONNECTION_RESPONSE
            | auth::endpoint::layout::TYPE_LOCAL_ENDPOINT
            | auth::invite::layout::TYPE_INVITE_SECRET
            | auth::signed_fact::layout::TYPE_LOCAL_SIGNER_SECRET
            | auth::local_key_secret::layout::TYPE_LOCAL_KEY_SECRET
            | auth::local_history_node_secret::layout::TYPE_LOCAL_HISTORY_NODE_SECRET
            | auth::local_recipient_key::layout::TYPE_LOCAL_RECIPIENT_KEY
            | connection::frame::layout::TYPE_CONNECTION_FRAME_SMALL
            | connection::frame::layout::TYPE_CONNECTION_FRAME_LARGE
            | connection::fact_receipt::layout::TYPE_CONNECTION_FACT_RECEIPT
    )
}

pub fn seal_connection_send_frame(
    connection_id: FactId,
    fact_ids: &[FactId],
    connection_fact: &Fact,
    facts: &[&Fact],
) -> Result<Vec<u8>, String> {
    if connection_fact.id != connection_id {
        return Err("send_facts_on_connection connection fact id mismatch".to_string());
    }
    if fact_ids.len() != facts.len() {
        return Err(
            "send_facts_on_connection fact id list does not match loaded facts".to_string(),
        );
    }
    let connection = connection::response::layout::decode_fact(connection_fact.body())?;

    let mut bundle = ConnectionFrameFactBundle::new();
    for (expected_id, fact) in fact_ids.iter().zip(facts.iter().copied()) {
        if fact.id != *expected_id {
            return Err("send_facts_on_connection loaded fact id mismatch".to_string());
        }
        bundle.push(require_sendable_fact(fact)?.to_vec());
    }

    frame::seal_connection_frame(SealConnectionFrame {
        connection_id,
        sender_endpoint_id: connection.from_endpoint,
        receiver_endpoint_id: connection.to_endpoint,
        connection_secret: connection.connection_secret,
        nonce: frame::connection_send_nonce(connection_id, fact_ids),
        facts: bundle,
    })
}

// ---------------------------------------------------------------------------
// Receive-side admission.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy)]
pub struct ReceivedNetworkFrame<'a> {
    pub frame: &'a [u8],
    pub origin_addr: &'a [u8],
    pub received_at_local_ms: u64,
}

pub fn received_network_frame_effect(
    input: ReceivedNetworkFrame<'_>,
) -> Result<PipelineEffects, String> {
    match input.frame.first().copied() {
        Some(connection::request::layout::TYPE_CONNECTION_REQUEST) => {
            received_connection_request_effect(input)
        }
        Some(connection::response::layout::TYPE_CONNECTION_RESPONSE) => {
            received_connection_response_effect(input)
        }
        _ => received_connection_frame_effect(input),
    }
}

#[derive(Debug, Clone)]
pub struct OpenReceivedFrame<'a> {
    pub frame: &'a [u8],
    pub connection_fact: &'a Fact,
    pub origin_addr: &'a [u8],
    pub received_at_local_ms: u64,
}

fn received_connection_request_effect(
    input: ReceivedNetworkFrame<'_>,
) -> Result<PipelineEffects, String> {
    let Ok(request) = typed_payload_from_bytes::<connection::request::Codec>(input.frame) else {
        return Ok(PipelineEffects::new());
    };
    let request_fact = Fact::new(
        FactScope::Global,
        input.received_at_local_ms,
        input.frame.to_vec(),
    );
    let receipt = connection_fact_receipt_for_path(ConnectionFactReceiptInput {
        received_fact_id: request_fact.id,
        origin_addr: input.origin_addr,
        local_endpoint_id: request.to_endpoint,
        sender_endpoint_id: request.from_endpoint,
        receive_path: connection::fact_receipt::fact::RECEIVE_PATH_CONNECTION_REQUEST,
        connection_id: None,
        request_id: Some(request_fact.id),
        frame_hash: crypto::hash(input.frame),
        received_at_local_ms: input.received_at_local_ms,
    })?;
    Ok(PipelineEffects::new().fact(request_fact).fact(receipt))
}

fn received_connection_response_effect(
    input: ReceivedNetworkFrame<'_>,
) -> Result<PipelineEffects, String> {
    let Ok(response) = typed_payload_from_bytes::<connection::response::Codec>(input.frame) else {
        return Ok(PipelineEffects::new());
    };
    let response_fact = Fact::new(
        FactScope::Local,
        input.received_at_local_ms,
        input.frame.to_vec(),
    );
    let receipt = connection_fact_receipt_for_path(ConnectionFactReceiptInput {
        received_fact_id: response_fact.id,
        origin_addr: input.origin_addr,
        local_endpoint_id: response.to_endpoint,
        sender_endpoint_id: response.from_endpoint,
        receive_path: connection::fact_receipt::fact::RECEIVE_PATH_CONNECTION_RESPONSE,
        connection_id: Some(response_fact.id),
        request_id: Some(response.request_id),
        frame_hash: crypto::hash(input.frame),
        received_at_local_ms: input.received_at_local_ms,
    })?;
    Ok(PipelineEffects::new().fact(response_fact).fact(receipt))
}

fn received_connection_frame_effect(
    input: ReceivedNetworkFrame<'_>,
) -> Result<PipelineEffects, String> {
    let Ok(parts) = super::layout::decode_frame_parts(input.frame) else {
        return Ok(PipelineEffects::new());
    };
    match parts.header.size_class {
        super::layout::CONNECTION_FRAME_SIZE_CLASS_SMALL => {
            let fact = ConnectionFrameSmallFact {
                origin_addr: input.origin_addr.to_vec(),
                received_at_local_ms: input.received_at_local_ms,
                frame: input.frame.to_vec(),
            };
            Ok(PipelineEffects::new().ephemeral_fact(Fact::new(
                FactScope::Local,
                input.received_at_local_ms,
                super::layout::encode_small_fact(&fact)?,
            )))
        }
        super::layout::CONNECTION_FRAME_SIZE_CLASS_LARGE => {
            let fact = ConnectionFrameLargeFact {
                origin_addr: input.origin_addr.to_vec(),
                received_at_local_ms: input.received_at_local_ms,
                frame: input.frame.to_vec(),
            };
            Ok(PipelineEffects::new().ephemeral_fact(Fact::new(
                FactScope::Local,
                input.received_at_local_ms,
                super::layout::encode_large_fact(&fact)?,
            )))
        }
        _ => Ok(PipelineEffects::new()),
    }
}

pub fn open_received_frame(input: OpenReceivedFrame<'_>) -> Result<Vec<Fact>, String> {
    let connection = connection::response::Codec::decode_fact(input.connection_fact)?;
    let opened = frame::open_connection_frame(input.frame, &connection.connection_secret)?;
    if input.connection_fact.id != opened.connection_id {
        return Err(
            "connection::frame frame connection id does not match connection fact".to_string(),
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
        let receipt = connection_fact_receipt_for_path(ConnectionFactReceiptInput {
            received_fact_id: received.id,
            origin_addr: input.origin_addr,
            local_endpoint_id: opened.receiver_endpoint_id,
            sender_endpoint_id: opened.sender_endpoint_id,
            receive_path: connection::fact_receipt::fact::RECEIVE_PATH_CONNECTION_FRAME,
            connection_id: Some(opened.connection_id),
            request_id: Some(connection.request_id),
            frame_hash: opened.frame_hash,
            received_at_local_ms: input.received_at_local_ms,
        })?;
        facts.push(received);
        facts.push(receipt);
    }
    Ok(facts)
}

fn admit_received_fact_bytes(bytes: Vec<u8>) -> Result<Fact, String> {
    let tag = bytes
        .first()
        .copied()
        .ok_or_else(|| "received connection::frame fact bytes are empty".to_string())?;
    match tag {
        auth::workspace::TYPE_WORKSPACE => {
            return admit_with_codec::<auth::workspace::Codec>(bytes, |workspace| {
                Ok(Admission::global(workspace.created_at_ms))
            });
        }
        auth::user_invite::TYPE_USER_INVITE => {
            return admit_with_decoder(bytes, auth::user_invite::decode_fact_payload, |invite| {
                Ok(Admission::global(invite.created_at_ms))
            });
        }
        auth::user::TYPE_USER => {
            return admit_with_decoder(bytes, auth::user::decode_fact_payload, |user| {
                Ok(Admission::global(user.created_at_ms))
            });
        }
        auth::admin::TYPE_ADMIN => {
            return admit_with_decoder(bytes, auth::admin::decode_fact_payload, |admin| {
                Ok(Admission::global(admin.created_at_ms))
            });
        }
        auth::device_invite::TYPE_DEVICE_INVITE => {
            return admit_with_decoder(bytes, auth::device_invite::decode_fact_payload, |invite| {
                Ok(Admission::global(invite.created_at_ms))
            });
        }
        auth::endpoint_shared::TYPE_ENDPOINT_SHARED => {
            return admit_with_decoder(
                bytes,
                auth::endpoint_shared::decode_fact_payload,
                |shared| Ok(Admission::global(shared.created_at_ms)),
            );
        }
        auth::invite_server::TYPE_INVITE_SERVER => {
            return admit_with_decoder(bytes, auth::invite_server::decode_fact_payload, |server| {
                Ok(Admission::global(server.created_at_ms))
            });
        }
        content::disappearing_messages_setting::TYPE_DISAPPEARING_MESSAGES_SETTING => {
            return admit_with_codec::<content::disappearing_messages_setting::Codec>(
                bytes,
                |setting| {
                    Ok(Admission::workspace(
                        setting.workspace_id,
                        setting.created_at_ms,
                    ))
                },
            );
        }
        content::reaction::TYPE_CONTENT_REACTION => {
            return Err("received content reaction fact must be signed".to_string());
        }
        content::file::TYPE_CONTENT_FILE => {
            return Err("received content file fact must be signed".to_string());
        }
        content::file_slice::TYPE_CONTENT_FILE_SLICE => {
            return admit_with_codec::<content::file_slice::Codec>(bytes, |slice| {
                Ok(Admission::workspace(
                    slice.workspace_id,
                    slice.created_at_ms,
                ))
            });
        }
        content::message::TYPE_CONTENT_MESSAGE => {
            return Err("received content message fact must be signed".to_string());
        }
        content::message_deletion::TYPE_CONTENT_MESSAGE_DELETION => {
            return Err("received content message deletion fact must be signed".to_string());
        }
        content::file_deletion::TYPE_CONTENT_FILE_DELETION => {
            return Err("received content file deletion fact must be signed".to_string());
        }
        auth::recipient_key::layout::TYPE_RECIPIENT_KEY => {
            return admit_with_codec::<auth::recipient_key::Codec>(bytes, |recipient| {
                Ok(Admission::workspace(
                    recipient.workspace_id,
                    recipient.created_at_ms,
                ))
            });
        }
        auth::removal_frontier::layout::TYPE_REMOVAL_FRONTIER => {
            return admit_with_codec::<auth::removal_frontier::Codec>(bytes, |frontier| {
                Ok(Admission::workspace(
                    frontier.workspace_id,
                    frontier.created_at_ms,
                ))
            });
        }
        auth::key_request::layout::TYPE_KEY_REQUEST => {
            return admit_with_codec::<auth::key_request::Codec>(bytes, |request| {
                Ok(Admission::workspace(
                    request.workspace_id,
                    request.created_at_ms,
                ))
            });
        }
        auth::local_history_node_secret::TYPE_LOCAL_HISTORY_NODE_SECRET => {
            return Err(
                "received connection::frame payload is local history-node secret".to_string(),
            );
        }
        sync::compare::TYPE_SYNC_COMPARE => {
            return admit_with_codec::<sync::compare::Codec>(bytes, |_| Ok(Admission::global(0)));
        }
        sync::have_id::TYPE_SYNC_HAVE_ID => {
            return admit_with_codec::<sync::have_id::Codec>(bytes, |_| Ok(Admission::global(0)));
        }
        sync::need_id::TYPE_SYNC_NEED_ID => {
            return admit_with_codec::<sync::need_id::Codec>(bytes, |_| Ok(Admission::global(0)));
        }
        auth::signed_fact::TYPE_SIGNED_FACT => {}
        _ => {
            return Err(format!(
                "unsupported received connection::frame fact type {tag}"
            ))
        }
    }

    admit_signed_fact_bytes(bytes)
}

#[derive(Debug, Clone)]
struct Admission {
    scope: FactScope,
    timestamp: u64,
}

impl Admission {
    fn global(timestamp: u64) -> Self {
        Self {
            scope: FactScope::Global,
            timestamp,
        }
    }

    fn workspace(workspace_id: FactId, timestamp: u64) -> Self {
        Self {
            scope: workspace_scope(workspace_id),
            timestamp,
        }
    }
}

fn typed_payload_from_bytes<C: FactCodec>(bytes: &[u8]) -> Result<C::Payload, String> {
    let fact = Fact::new(FactScope::Global, 0, bytes.to_vec());
    C::decode_fact(&fact)
}

fn admit_with_codec<C: FactCodec>(
    bytes: Vec<u8>,
    admit: impl FnOnce(C::Payload) -> Result<Admission, String>,
) -> Result<Fact, String> {
    let opened = Fact::new(FactScope::Global, 0, bytes);
    let payload = C::decode_fact(&opened)?;
    let admission = admit(payload)?;
    Ok(Fact::new(
        admission.scope,
        admission.timestamp,
        opened.bytes,
    ))
}

fn admit_with_decoder<T>(
    bytes: Vec<u8>,
    decode: impl FnOnce(&[u8]) -> Result<T, String>,
    admit: impl FnOnce(T) -> Result<Admission, String>,
) -> Result<Fact, String> {
    let payload = decode(&bytes)?;
    let admission = admit(payload)?;
    Ok(Fact::new(admission.scope, admission.timestamp, bytes))
}

fn admit_signed_fact_bytes(bytes: Vec<u8>) -> Result<Fact, String> {
    let envelope = auth::signed_fact::layout::decode_signed_fact(&bytes)?;
    match envelope.inner_type {
        auth::user_invite::TYPE_USER_INVITE => {
            admit_with_codec::<auth::user_invite::Codec>(bytes, |signed| {
                Ok(Admission::global(signed.payload.created_at_ms))
            })
        }
        auth::user::TYPE_USER => admit_with_codec::<auth::user::Codec>(bytes, |signed| {
            Ok(Admission::global(signed.payload.created_at_ms))
        }),
        auth::admin::TYPE_ADMIN => admit_with_codec::<auth::admin::Codec>(bytes, |signed| {
            Ok(Admission::global(signed.payload.created_at_ms))
        }),
        auth::device_invite::TYPE_DEVICE_INVITE => {
            admit_with_codec::<auth::device_invite::Codec>(bytes, |signed| {
                Ok(Admission::global(signed.payload.created_at_ms))
            })
        }
        auth::endpoint_shared::TYPE_ENDPOINT_SHARED => {
            admit_with_codec::<auth::endpoint_shared::Codec>(bytes, |signed| {
                Ok(Admission::global(signed.payload.created_at_ms))
            })
        }
        auth::invite_server::TYPE_INVITE_SERVER => {
            admit_with_codec::<auth::invite_server::Codec>(bytes, |signed| {
                Ok(Admission::global(signed.payload.created_at_ms))
            })
        }
        auth::key_wrap::layout::TYPE_KEY_WRAP => admit_signed_key_wrap_fact(bytes),
        content::message::TYPE_CONTENT_MESSAGE => {
            admit_with_codec::<content::message::Codec>(bytes, |signed| {
                Ok(Admission::workspace(
                    signed.payload.workspace_id,
                    signed.payload.created_at_ms,
                ))
            })
        }
        content::message_deletion::TYPE_CONTENT_MESSAGE_DELETION => {
            admit_with_codec::<content::message_deletion::Codec>(bytes, |signed| {
                Ok(Admission::workspace(
                    signed.payload.workspace_id,
                    signed.payload.created_at_ms,
                ))
            })
        }
        content::reaction::TYPE_CONTENT_REACTION => {
            admit_with_codec::<content::reaction::Codec>(bytes, |signed| {
                Ok(Admission::workspace(
                    signed.payload.workspace_id,
                    signed.payload.created_at_ms,
                ))
            })
        }
        content::file::TYPE_CONTENT_FILE => {
            admit_with_codec::<content::file::Codec>(bytes, |signed| {
                Ok(Admission::workspace(
                    signed.payload.workspace_id,
                    signed.payload.created_at_ms,
                ))
            })
        }
        content::file_deletion::TYPE_CONTENT_FILE_DELETION => {
            admit_with_codec::<content::file_deletion::Codec>(bytes, |signed| {
                Ok(Admission::workspace(
                    signed.payload.workspace_id,
                    signed.payload.created_at_ms,
                ))
            })
        }
        other => Err(format!(
            "unsupported signed connection::frame payload type {other}"
        )),
    }
}

fn admit_signed_key_wrap_fact(bytes: Vec<u8>) -> Result<Fact, String> {
    admit_with_codec::<auth::key_wrap::Codec>(bytes, |signed| {
        let envelope = signed.envelope;
        let wrap = signed.payload;
        if envelope.signer_id != wrap.signer_endpoint_id {
            return Err("key wrap signer does not match signed envelope signer".to_string());
        }
        Ok(Admission::workspace(wrap.workspace_id, wrap.created_at_ms))
    })
}

fn workspace_scope(workspace_id: FactId) -> FactScope {
    crate::protocol::auth::workspace::scope(workspace_id)
}

struct ConnectionFactReceiptInput<'a> {
    received_fact_id: FactId,
    origin_addr: &'a [u8],
    local_endpoint_id: FactId,
    sender_endpoint_id: FactId,
    receive_path: u8,
    connection_id: Option<FactId>,
    request_id: Option<FactId>,
    frame_hash: [u8; 32],
    received_at_local_ms: u64,
}

fn connection_fact_receipt_for_path(input: ConnectionFactReceiptInput<'_>) -> Result<Fact, String> {
    let fact = connection::fact_receipt::fact::ConnectionFactReceipt {
        received_fact_id: input.received_fact_id,
        origin_addr: input.origin_addr.to_vec(),
        local_endpoint_id: input.local_endpoint_id,
        sender_endpoint_id: input.sender_endpoint_id,
        receive_path: input.receive_path,
        connection_id: input.connection_id,
        request_id: input.request_id,
        frame_hash: input.frame_hash,
        received_at_local_ms: input.received_at_local_ms,
    };
    Ok(Fact::new(
        FactScope::Local,
        input.received_at_local_ms,
        connection::fact_receipt::layout::encode_fact(&fact)?,
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
        Err("connection::frame frame endpoints do not match connection fact".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::crypto::{ed25519_public_key, ed25519_sign};
    use crate::protocol::auth::invite::fact::InviteSecretFact;
    use crate::protocol::auth::signed_fact::fact::SignedFactEnvelope;
    use crate::protocol::auth::user::fact::UserFact;
    use crate::protocol::auth::workspace::fact::WorkspaceFact;

    #[test]
    fn admitted_message_deletion_uses_payload_created_timestamp() {
        let deletion = content::message_deletion::fact::ContentMessageDeletionFact {
            workspace_id: [9; 32],
            created_at_ms: 12_345,
            target_message_id: [10; 32],
            target_frontier_id: [12; 32],
            target_minute: 1,
            author_user_id: [11; 32],
        };
        let payload =
            content::message_deletion::layout::encode_fact(&deletion).expect("encode deletion");
        let bytes = auth::signed_fact::create::sign_payload_bytes([8; 32], &[9; 32], payload)
            .expect("sign deletion");

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
        let bytes = auth::workspace::layout::encode_fact(&workspace).expect("workspace");

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
        let payload = auth::user::layout::encode_fact(&user).expect("user payload");
        let signing_secret = [10; 32];
        let mut envelope = SignedFactEnvelope {
            signer_id: [11; 32],
            signer_public_key: ed25519_public_key(&signing_secret),
            inner_type: auth::user::layout::TYPE_USER,
            payload,
            signature: [0; 64],
        };
        let signing_bytes =
            auth::signed_fact::layout::signing_bytes(&envelope).expect("signing bytes");
        envelope.signature = ed25519_sign(&signing_secret, &signing_bytes);
        let bytes =
            auth::signed_fact::layout::encode_signed_fact(&envelope).expect("signed identity");

        let admitted = admit_received_fact_bytes(bytes.clone()).expect("admit signed user");

        assert_eq!(admitted.scope, FactScope::Global);
        assert_eq!(admitted.timestamp, user.created_at_ms);
        assert_eq!(admitted.bytes, bytes);
    }

    #[test]
    fn duplicate_bootstrap_request_delivery_emits_only_request_and_receipt() {
        let invite = InviteSecretFact::new([33; 32]);
        let mut request = connection::request::fact::ConnectionRequestFact {
            from_endpoint: crypto::x25519_public_key(&[55; 32]),
            to_endpoint: crypto::x25519_public_key(&[44; 32]),
            nonce: [56; 32],
            invite_fact_id: [57; 32],
            bootstrap_hash: invite.bootstrap_hash,
            invite_signature: [0; crypto::ED25519_SIGNATURE_BYTES],
            invite_secret_fact_id: [50; 32],
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

        let first = received_network_frame_effect(ReceivedNetworkFrame {
            frame: &frame,
            origin_addr: b"127.0.0.1:41002",
            received_at_local_ms: 100,
        })
        .expect("first delivery");
        let second = received_network_frame_effect(ReceivedNetworkFrame {
            frame: &frame,
            origin_addr: b"127.0.0.1:41002",
            received_at_local_ms: 200,
        })
        .expect("duplicate delivery");

        assert_eq!(first.facts.len(), 2);
        assert_eq!(second.facts.len(), 2);
        let stable_first = non_receipt_fact_ids(&first.facts);
        let stable_second = non_receipt_fact_ids(&second.facts);
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

    fn non_receipt_fact_ids(facts: &[Fact]) -> Vec<FactId> {
        let mut ids = facts
            .iter()
            .filter(|fact| {
                fact.body().first().copied()
                    != Some(connection::fact_receipt::layout::TYPE_CONNECTION_FACT_RECEIPT)
            })
            .map(|fact| fact.id)
            .collect::<Vec<_>>();
        ids.sort();
        ids
    }
}
