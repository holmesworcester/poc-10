//! Connection-frame sealing, classification, and child admission.
//!
//! Outbound connection sends call this module to reject private/local payloads
//! and seal an ordered fact bundle into fixed small, file-slice, or bundle
//! frame bytes.
//! Inbound receive handling uses this module only to classify established
//! connection frame bytes. The `connection::frame_*` fact families construct
//! local wire-frame facts, and `connection::frame_observation` records receive
//! metadata for those facts. Projection then calls back here to open a frame and
//! turn each inner payload into a durable child fact plus receipt.
//!
//! The invariants are deliberately split: socket metadata enters only through
//! receive-network handler, connection secrets come only from matched local
//! `connection::response` context, and child facts are admitted through their
//! owning typed codecs. Keep cryptographic frame mechanics in
//! `connection_frame_wire`, keep socket IO in core/network handlers, and keep
//! observed metadata in `connection::frame_observation`.

use crate::core::context::ContextNeed;
use crate::core::effects::PipelineEffects;
use crate::core::facts::{Fact, FactId, FactScope};
use crate::core::pipeline::{FactCodec, ProjectionContext, ProjectionOutput};
use crate::core::wire::FixedSlot;
use crate::protocol::connection_frame_wire as wire;
pub(crate) use crate::protocol::connection_frame_wire::{
    seal_connection_send_frame, ConnectionFrameFactBundle, CONNECTION_FRAME_BUNDLE_FACT_SLOTS,
    CONNECTION_FRAME_BUNDLE_FACT_SLOT_BYTES, CONNECTION_FRAME_SMALL_PLAINTEXT_BYTES,
};
use crate::protocol::{auth, connection, content, sync};

/// Return the bytes that may be packaged into a connection::frame frame.
///
/// Local facts and private/local fact tags are never connection-frame payloads.
/// Semantic fact validation belongs to the child fact projector once signer
/// context exists.
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

    Ok(fact.body())
}

pub fn is_private_local_fact_tag(tag: u8) -> bool {
    matches!(
        tag,
        connection::close::layout::TYPE_CONNECTION_CLOSE
            | connection::ephemeral_secret::layout::TYPE_CONNECTION_EPHEMERAL_SECRET
            | connection::request::layout::TYPE_CONNECTION_REQUEST
            | connection::connection::layout::TYPE_CONNECTION
            | auth::endpoint::layout::TYPE_LOCAL_ENDPOINT
            | auth::invite::layout::TYPE_INVITE_SECRET
            | auth::local_signer_secret::layout::TYPE_LOCAL_SIGNER_SECRET
            | auth::local_key_secret::layout::TYPE_LOCAL_KEY_SECRET
            | auth::local_history_node_secret::layout::TYPE_LOCAL_HISTORY_NODE_SECRET
            | auth::local_recipient_key::layout::TYPE_LOCAL_RECIPIENT_KEY
            | connection::frame_small::layout::TYPE_CONNECTION_FRAME_SMALL
            | connection::frame_file_slice::layout::TYPE_CONNECTION_FRAME_FILE_SLICE
            | connection::frame_bundle::layout::TYPE_CONNECTION_FRAME_BUNDLE
            | connection::frame_observation::layout::TYPE_CONNECTION_FRAME_OBSERVATION
            | connection::fact_receipt::layout::TYPE_CONNECTION_FACT_RECEIPT
    )
}

// ---------------------------------------------------------------------------
// Receive-side admission.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ConnectionFrameKind {
    Small,
    FileSlice,
    Bundle,
}

pub(crate) fn classify_frame(frame: &[u8]) -> Option<ConnectionFrameKind> {
    let parts = wire::decode_frame_parts(frame).ok()?;
    match parts.header.size_class {
        wire::CONNECTION_FRAME_SIZE_CLASS_SMALL => Some(ConnectionFrameKind::Small),
        wire::CONNECTION_FRAME_SIZE_CLASS_FILE_SLICE => Some(ConnectionFrameKind::FileSlice),
        wire::CONNECTION_FRAME_SIZE_CLASS_BUNDLE => Some(ConnectionFrameKind::Bundle),
        _ => None,
    }
}

pub(crate) fn exact_frame_slot<const N: usize>(frame: &[u8]) -> Result<FixedSlot<N>, String> {
    if frame.len() != N {
        return Err(format!("connection frame must be exactly {N} bytes"));
    }
    FixedSlot::new(frame).map_err(|err| format!("connection frame bytes: {err}"))
}

pub fn frame_fact_from_wire(frame: &[u8], local_timestamp_ms: u64) -> Result<Fact, String> {
    match classify_frame(frame) {
        Some(ConnectionFrameKind::Small) => {
            connection::frame_small::create::fact_from_wire(frame, local_timestamp_ms)
        }
        Some(ConnectionFrameKind::FileSlice) => {
            connection::frame_file_slice::create::fact_from_wire(frame, local_timestamp_ms)
        }
        Some(ConnectionFrameKind::Bundle) => {
            connection::frame_bundle::create::fact_from_wire(frame, local_timestamp_ms)
        }
        None => Err("connection frame has unknown size class".to_string()),
    }
}

pub fn observed_frame_effect(
    frame_fact: Fact,
    origin_addr: &[u8],
    received_at_local_ms: u64,
) -> Result<PipelineEffects, String> {
    let observation = connection::frame_observation::create::fact_from_observation(
        frame_fact.id,
        origin_addr,
        received_at_local_ms,
    )?;
    Ok(PipelineEffects::new()
        .fact(observation)
        .ephemeral_fact(frame_fact))
}

pub fn observed_handshake_fact_effect(
    frame_fact: Fact,
    origin_addr: &[u8],
    received_at_local_ms: u64,
) -> Result<PipelineEffects, String> {
    let observation = connection::frame_observation::create::fact_from_observation(
        frame_fact.id,
        origin_addr,
        received_at_local_ms,
    )?;
    Ok(PipelineEffects::new().fact(observation).fact(frame_fact))
}

pub fn observed_request_fact_effect(
    frame_bytes: Vec<u8>,
    origin_addr: &[u8],
    received_at_local_ms: u64,
) -> Result<PipelineEffects, String> {
    if !connection::request::layout::is_sealed_fact(&frame_bytes) {
        return Ok(PipelineEffects::new());
    }
    observed_handshake_fact_effect(
        Fact::new(FactScope::Global, received_at_local_ms, frame_bytes),
        origin_addr,
        received_at_local_ms,
    )
}

pub fn observed_connection_fact_effect(
    frame_bytes: Vec<u8>,
    origin_addr: &[u8],
    received_at_local_ms: u64,
) -> Result<PipelineEffects, String> {
    if !connection::connection::layout::is_sealed_fact(&frame_bytes) {
        return Ok(PipelineEffects::new());
    }
    observed_handshake_fact_effect(
        Fact::new(FactScope::Local, received_at_local_ms, frame_bytes),
        origin_addr,
        received_at_local_ms,
    )
}

pub fn wire_from_frame_fact(fact: &Fact) -> Result<Vec<u8>, String> {
    if fact.scope != FactScope::Local {
        return Err("connection frame fact must have local scope".to_string());
    }
    match fact.body().first().copied() {
        Some(connection::frame_small::layout::TYPE_CONNECTION_FRAME_SMALL) => {
            connection::frame_small::Codec::decode_fact(fact)
                .map(|input| input.frame.bytes().to_vec())
        }
        Some(connection::frame_file_slice::layout::TYPE_CONNECTION_FRAME_FILE_SLICE) => {
            connection::frame_file_slice::Codec::decode_fact(fact)
                .map(|input| input.frame.bytes().to_vec())
        }
        Some(connection::frame_bundle::layout::TYPE_CONNECTION_FRAME_BUNDLE) => {
            connection::frame_bundle::Codec::decode_fact(fact)
                .map(|input| input.frame.bytes().to_vec())
        }
        _ => Err("expected connection frame fact".to_string()),
    }
}

pub fn project_observed_frame(
    fact: &Fact,
    frame: &[u8],
    context: &ProjectionContext,
) -> Result<ProjectionOutput, String> {
    if fact.scope != FactScope::Local {
        return Err("connection frame receive fact must have local scope".to_string());
    }

    let Ok(connection_id) = wire::received_connection_fact_id(frame) else {
        return Ok(ProjectionOutput::new());
    };

    let observation_need = exact_need(
        fact.id,
        "connection_frame_observation",
        FactScope::Local,
        fact.id,
    );
    let Some(observation_fact) = context.payload_for(&observation_need) else {
        return Ok(ProjectionOutput::new().need(observation_need));
    };
    if observation_fact.scope != FactScope::Local {
        return Err("connection frame observation context must be local".to_string());
    }
    let observation = connection::frame_observation::Codec::decode_fact(observation_fact)?;
    if observation.frame_fact_id != fact.id {
        return Err("connection frame observation does not name frame fact".to_string());
    }

    let connection_need = connection::connection::project::connection_need(fact.id, connection_id);
    let Some(connection_fact) = context.payload_for(&connection_need) else {
        return Ok(ProjectionOutput::new().need(connection_need));
    };
    if connection_fact.scope != FactScope::Local {
        return Err("connection frame context must be local".to_string());
    }
    let material = match connection_material_from_context(connection_fact, context, fact.id) {
        ConnectionMaterialContext::Open(material) => material,
        ConnectionMaterialContext::Needs(needs) => {
            let mut output = ProjectionOutput::new()
                .need(observation_need)
                .need(connection_need);
            for need in needs {
                output = output.need(need);
            }
            return Ok(output);
        }
        ConnectionMaterialContext::Invalid => return Ok(ProjectionOutput::new()),
    };

    match open_received_frame_with_material(
        frame,
        material,
        observation.origin_addr.bytes(),
        observation.received_at_local_ms,
    ) {
        Ok(facts) => Ok(facts_output(facts)),
        Err(_) => Ok(ProjectionOutput::new()),
    }
}

fn exact_need(owner: [u8; 32], role: &'static str, scope: FactScope, key: [u8; 32]) -> ContextNeed {
    ContextNeed::range(owner, role, scope, key, key)
}

fn facts_output(facts: Vec<Fact>) -> ProjectionOutput {
    let mut output = ProjectionOutput::new();
    for fact in facts {
        output = output.fact(fact);
    }
    output
}

fn open_received_frame_with_material(
    frame: &[u8],
    connection: ConnectionMaterial,
    origin_addr: &[u8],
    received_at_local_ms: u64,
) -> Result<Vec<Fact>, String> {
    let opened = wire::open_connection_frame(frame, &connection.connection_secret)?;
    if connection.connection_id != opened.connection_id {
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
            origin_addr,
            local_endpoint_id: opened.receiver_endpoint_id,
            sender_endpoint_id: opened.sender_endpoint_id,
            receive_path: connection::fact_receipt::fact::RECEIVE_PATH_CONNECTION_FRAME,
            connection_id: Some(opened.connection_id),
            request_id: Some(connection.request_id),
            frame_hash: opened.frame_hash,
            received_at_local_ms,
        })?;
        facts.push(received);
        facts.push(receipt);
    }
    Ok(facts)
}

#[derive(Debug, Clone, Copy)]
struct ConnectionMaterial {
    connection_id: FactId,
    from_endpoint: FactId,
    to_endpoint: FactId,
    request_id: FactId,
    connection_secret: [u8; 32],
}

enum ConnectionMaterialContext {
    Open(ConnectionMaterial),
    Needs(Vec<ContextNeed>),
    Invalid,
}

fn connection_material_from_context(
    fact: &Fact,
    context: &ProjectionContext,
    owner: FactId,
) -> ConnectionMaterialContext {
    if connection::connection::layout::validate_sealed_fact(fact.body()).is_err() {
        return ConnectionMaterialContext::Invalid;
    }
    let endpoint_need = ContextNeed::range(
        owner,
        "auth_local_endpoint",
        FactScope::Local,
        [0; 32],
        [0xff; 32],
    );
    for (_, endpoint_fact) in context.matched_payloads_for(&endpoint_need) {
        if let Ok(endpoint) = auth::endpoint::decode_fact_payload(endpoint_fact.body()) {
            if let Ok(connection) =
                connection::connection::layout::open_fact(fact.body(), &endpoint)
            {
                return ConnectionMaterialContext::Open(material_from_connection_fact(
                    fact.id, connection,
                ));
            }
        }
    }
    let ephemeral_need = ContextNeed::range(
        owner,
        "connection_ephemeral_secret",
        FactScope::Local,
        [0; 32],
        [0xff; 32],
    );
    for (_, secret_fact) in context.matched_payloads_for(&ephemeral_need) {
        if let Ok(secret) = connection::ephemeral_secret::decode_fact_payload(secret_fact.body()) {
            if let Ok(connection) =
                connection::connection::layout::open_fact_as_responder(fact.body(), &secret)
            {
                return ConnectionMaterialContext::Open(material_from_connection_fact(
                    fact.id, connection,
                ));
            }
        }
    }
    ConnectionMaterialContext::Needs(vec![endpoint_need, ephemeral_need])
}

fn material_from_connection_fact(
    connection_id: FactId,
    connection: connection::connection::fact::ConnectionFact,
) -> ConnectionMaterial {
    ConnectionMaterial {
        connection_id,
        from_endpoint: connection.from_endpoint,
        to_endpoint: connection.to_endpoint,
        request_id: connection.request_id,
        connection_secret: connection.connection_secret,
    }
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
        content::retention_policy::TYPE_RETENTION_POLICY => {
            return admit_with_codec::<content::retention_policy::Codec>(bytes, |policy| {
                Ok(Admission::workspace(
                    policy.workspace_id,
                    policy.created_at_ms,
                ))
            });
        }
        content::reaction::TYPE_CONTENT_REACTION => {
            return admit_with_codec::<content::reaction::Codec>(bytes, |reaction| {
                Ok(Admission::workspace(
                    reaction.workspace_id,
                    reaction.created_at_ms,
                ))
            });
        }
        content::file::TYPE_CONTENT_FILE => {
            return admit_with_codec::<content::file::Codec>(bytes, |file| {
                Ok(Admission::workspace(file.workspace_id, file.created_at_ms))
            });
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
            return admit_with_codec::<content::message::Codec>(bytes, |message| {
                Ok(Admission::workspace(
                    message.workspace_id,
                    message.created_at_ms,
                ))
            });
        }
        content::message_deletion::TYPE_CONTENT_MESSAGE_DELETION => {
            return admit_with_codec::<content::message_deletion::Codec>(bytes, |deletion| {
                Ok(Admission::workspace(
                    deletion.workspace_id,
                    deletion.created_at_ms,
                ))
            });
        }
        content::file_deletion::TYPE_CONTENT_FILE_DELETION => {
            return admit_with_codec::<content::file_deletion::Codec>(bytes, |deletion| {
                Ok(Admission::workspace(
                    deletion.workspace_id,
                    deletion.created_at_ms,
                ))
            });
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
        auth::key_wrap::layout::TYPE_KEY_WRAP => {
            return admit_with_codec::<auth::key_wrap::Codec>(bytes, |wrap| {
                Ok(Admission::workspace(wrap.workspace_id, wrap.created_at_ms))
            });
        }
        _ => {
            return Err(format!(
                "unsupported received connection::frame fact type {tag}"
            ))
        }
    }
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

fn workspace_scope(workspace_id: FactId) -> FactScope {
    crate::protocol::auth::workspace::scope(workspace_id)
}

pub struct ConnectionFactReceiptInput<'a> {
    pub received_fact_id: FactId,
    pub origin_addr: &'a [u8],
    pub local_endpoint_id: FactId,
    pub sender_endpoint_id: FactId,
    pub receive_path: u8,
    pub connection_id: Option<FactId>,
    pub request_id: Option<FactId>,
    pub frame_hash: [u8; 32],
    pub received_at_local_ms: u64,
}

pub fn connection_fact_receipt_for_path(
    input: ConnectionFactReceiptInput<'_>,
) -> Result<Fact, String> {
    let fact = connection::fact_receipt::fact::ConnectionFactReceipt {
        received_fact_id: input.received_fact_id,
        origin_addr: connection::fact_receipt::fact::OriginAddr::new(input.origin_addr)
            .map_err(|err| format!("connection fact receipt origin addr: {err}"))?,
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
    connection: &ConnectionMaterial,
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
    use crate::core::crypto::{self, ed25519_public_key, ed25519_sign};
    use crate::protocol::auth::invite::fact::InviteSecretFact;
    use crate::protocol::auth::user::fact::UserFact;
    use crate::protocol::auth::workspace::fact::WorkspaceFact;

    #[test]
    fn admitted_message_deletion_uses_payload_created_timestamp() {
        let signing_secret = [9; 32];
        let mut deletion = content::message_deletion::fact::ContentMessageDeletionFact {
            workspace_id: [9; 32],
            created_at_ms: 12_345,
            target_message_id: [10; 32],
            target_frontier_id: [12; 32],
            target_minute: 1,
            author_user_id: [11; 32],
            signer_id: [8; 32],
            signer_public_key: ed25519_public_key(&signing_secret),
            signature: [0; crypto::ED25519_SIGNATURE_BYTES],
        };
        deletion.signature = ed25519_sign(
            &signing_secret,
            &content::message_deletion::layout::signing_bytes(&deletion).expect("signing bytes"),
        );
        let bytes =
            content::message_deletion::layout::encode_fact(&deletion).expect("encode deletion");

        let admitted = admit_received_fact_bytes(bytes.clone()).expect("admit deletion");

        assert_eq!(admitted.scope, workspace_scope(deletion.workspace_id));
        assert_eq!(admitted.timestamp, deletion.created_at_ms);
        assert_eq!(admitted.bytes, bytes);
    }

    #[test]
    fn admitted_workspace_uses_payload_created_timestamp() {
        let signing_secret = [7; 32];
        let mut workspace = WorkspaceFact {
            created_at_ms: 55_555,
            public_key: ed25519_public_key(&signing_secret),
            name: auth::workspace::fact::WorkspaceName::new("workspace").expect("name"),
            signature: [0; crypto::ED25519_SIGNATURE_BYTES],
        };
        workspace.signature = ed25519_sign(
            &signing_secret,
            &auth::workspace::encode::signing_bytes(&workspace).expect("signing bytes"),
        );
        let bytes = auth::workspace::encode::encode_fact(&workspace).expect("workspace");

        let admitted = admit_received_fact_bytes(bytes.clone()).expect("admit workspace");

        assert_eq!(admitted.scope, FactScope::Global);
        assert_eq!(admitted.timestamp, workspace.created_at_ms);
        assert_eq!(admitted.bytes, bytes);
    }

    #[test]
    fn admitted_signed_identity_uses_payload_created_timestamp() {
        let signing_secret = [10; 32];
        let mut user = UserFact {
            created_at_ms: 66_666,
            workspace_id: [8; 32],
            public_key: [9; 32],
            username: auth::user::fact::Username::new("alice").expect("username"),
            signer_id: [11; 32],
            signer_public_key: ed25519_public_key(&signing_secret),
            signature: [0; crypto::ED25519_SIGNATURE_BYTES],
        };
        user.signature = ed25519_sign(
            &signing_secret,
            &auth::user::layout::signing_bytes(&user).expect("signing bytes"),
        );
        let bytes = auth::user::layout::encode_fact(&user).expect("user payload");

        let admitted = admit_received_fact_bytes(bytes.clone()).expect("admit signed user");

        assert_eq!(admitted.scope, FactScope::Global);
        assert_eq!(admitted.timestamp, user.created_at_ms);
        assert_eq!(admitted.bytes, bytes);
    }

    #[test]
    fn duplicate_connection_request_delivery_emits_only_request_and_observation() {
        let invite = InviteSecretFact::new([33; 32]);
        let initiator_ephemeral_private_key = [59; 32];
        let mut request = connection::request::fact::ConnectionRequestFact {
            mode: connection::request::fact::REQUEST_MODE_BOOTSTRAP,
            from_endpoint: crypto::x25519_public_key(&[55; 32]),
            to_endpoint: crypto::x25519_public_key(&[44; 32]),
            nonce: [56; 32],
            dialed_addr: Some("127.0.0.1:41001".parse().expect("dialed addr")),
            initiator_addr: None,
            invite_fact_id: [57; 32],
            bootstrap_hash: invite.bootstrap_hash,
            invite_signature: [0; crypto::ED25519_SIGNATURE_BYTES],
            initiator_endpoint_shared_id: [0; 32],
            endpoint_signature: [0; crypto::ED25519_SIGNATURE_BYTES],
            invite_secret_fact_id: [50; 32],
            initiator_ephemeral_secret_fact_id: [58; 32],
            initiator_ephemeral_public_key: crypto::x25519_public_key(
                &initiator_ephemeral_private_key,
            ),
        };
        connection::request::create::sign_bootstrap_request(&mut request, &invite)
            .expect("sign request");
        let frame =
            connection::request::layout::seal_fact(&request, &initiator_ephemeral_private_key)
                .expect("request");

        let first = observed_request_fact_effect(frame.clone(), b"127.0.0.1:41002", 100)
            .expect("first delivery");
        let second = observed_request_fact_effect(frame.clone(), b"127.0.0.1:41002", 200)
            .expect("duplicate delivery");

        assert_eq!(first.facts.len(), 2);
        assert_eq!(second.facts.len(), 2);
        let stable_first = non_observation_fact_ids(&first.facts);
        let stable_second = non_observation_fact_ids(&second.facts);
        assert_eq!(stable_first, stable_second);
        assert_eq!(stable_first.len(), 1);
        assert!(first.facts.iter().all(|fact| {
            !matches!(
                fact.body().first().copied(),
                Some(connection::ephemeral_secret::layout::TYPE_CONNECTION_EPHEMERAL_SECRET)
                    | Some(connection::connection::layout::TYPE_CONNECTION)
            )
        }));
    }

    fn non_observation_fact_ids(facts: &[Fact]) -> Vec<FactId> {
        let mut ids = facts
            .iter()
            .filter(|fact| {
                fact.body().first().copied()
                    != Some(
                        connection::frame_observation::layout::TYPE_CONNECTION_FRAME_OBSERVATION,
                    )
            })
            .map(|fact| fact.id)
            .collect::<Vec<_>>();
        ids.sort();
        ids
    }
}
