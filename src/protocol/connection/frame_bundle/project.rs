pub mod decode {
    //! Byte decoding for bundle connection-frame wire facts.
    //!
    //! Decoding proves only the fixed layout: tag, length, and the embedded frame
    //! shape. Id checks live in the local `authenticate` module.

    use crate::core::facts::FactId;
    use crate::core::wire::{self, FixedLayout, Id32, Nonce24, Tag, WireError};

    use super::super::encode::{
        wire_err, ConnectionFrameBundleV1, CIPHERTEXT_OFFSET,
        CONNECTION_FRAME_BUNDLE_CIPHERTEXT_BYTES, CONNECTION_FRAME_BUNDLE_FACT_BYTES,
        CONNECTION_FRAME_BUNDLE_WIRE_BYTES, CONNECTION_FRAME_HEADER_BYTES,
        CONNECTION_FRAME_SIZE_CLASS_BUNDLE, CONNECTION_FRAME_TAG, CONNECTION_FRAME_VERSION,
        TYPE_CONNECTION_FRAME_BUNDLE,
    };
    use super::super::fact::ConnectionFrameBundleFact;

    /// Public header view recovered without decrypting the payload.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct ConnectionFrameHeader {
        pub connection_id: Id32,
        pub nonce: Nonce24,
    }

    /// Borrowed bundle frame payload recovered without materializing a large fixed
    /// slot value on the stack.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct ConnectionFrameParts<'a> {
        pub header: ConnectionFrameHeader,
        pub ciphertext: &'a [u8],
    }

    const VERSION_OFFSET: usize = Tag::<4>::LEN;
    const SIZE_CLASS_OFFSET: usize = VERSION_OFFSET + wire::U8_BYTES;
    const CONNECTION_OFFSET: usize = SIZE_CLASS_OFFSET + wire::U8_BYTES;
    const NONCE_OFFSET: usize = CONNECTION_OFFSET + Id32::LEN;

    pub fn decode_fact(bytes: &[u8]) -> Result<ConnectionFrameBundleFact, String> {
        if bytes.len() != CONNECTION_FRAME_BUNDLE_FACT_BYTES {
            return Err("connection frame bundle fact has wrong length".to_string());
        }
        let mut reader = wire::Reader::new(bytes);
        reader
            .expect_len(CONNECTION_FRAME_BUNDLE_FACT_BYTES)
            .map_err(wire_err)?;
        reader
            .expect_u8(TYPE_CONNECTION_FRAME_BUNDLE)
            .map_err(wire_err)?;
        let frame = reader
            .fixed_slot_value::<CONNECTION_FRAME_BUNDLE_WIRE_BYTES>()
            .map_err(wire_err)?;
        reader.finish().map_err(wire_err)?;
        ConnectionFrameBundleV1::decode(frame.bytes()).map_err(wire_err)?;
        Ok(ConnectionFrameBundleFact { frame })
    }

    pub fn is_frame(bytes: &[u8]) -> bool {
        decode_frame_parts(bytes).is_ok()
    }

    pub fn received_connection_fact_id(frame: &[u8]) -> Result<FactId, String> {
        Ok(decode_frame_parts(frame)
            .map_err(wire_err)?
            .header
            .connection_id
            .0)
    }

    /// Inspect the public header of a bundle connection frame.
    pub fn peek_frame_header(bytes: &[u8]) -> Result<ConnectionFrameHeader, WireError> {
        if bytes.len() < CONNECTION_FRAME_HEADER_BYTES {
            return Err(WireError::WrongLength {
                expected: CONNECTION_FRAME_HEADER_BYTES,
                actual: bytes.len(),
            });
        }
        let tag = Tag::<4>::decode(&bytes[..VERSION_OFFSET])?;
        if tag != CONNECTION_FRAME_TAG {
            return Err(WireError::NonZeroPadding { index: 0 });
        }
        let version = wire::take_u8(&bytes[VERSION_OFFSET..SIZE_CLASS_OFFSET])?;
        if version != CONNECTION_FRAME_VERSION {
            return Err(WireError::InvalidBool { actual: version });
        }
        let size_class = wire::take_u8(&bytes[SIZE_CLASS_OFFSET..CONNECTION_OFFSET])?;
        if size_class != CONNECTION_FRAME_SIZE_CLASS_BUNDLE {
            return Err(WireError::InvalidBool { actual: size_class });
        }
        let connection_id = Id32::decode(&bytes[CONNECTION_OFFSET..NONCE_OFFSET])?;
        let nonce = Nonce24::decode(&bytes[NONCE_OFFSET..CIPHERTEXT_OFFSET])?;
        Ok(ConnectionFrameHeader {
            connection_id,
            nonce,
        })
    }

    /// Decode the public header and borrowed ciphertext slot for a bundle frame.
    pub fn decode_frame_parts(bytes: &[u8]) -> Result<ConnectionFrameParts<'_>, WireError> {
        let header = peek_frame_header(bytes)?;
        if bytes.len() != CONNECTION_FRAME_BUNDLE_WIRE_BYTES {
            return Err(WireError::WrongLength {
                expected: CONNECTION_FRAME_BUNDLE_WIRE_BYTES,
                actual: bytes.len(),
            });
        }
        let slot = &bytes[CIPHERTEXT_OFFSET..];
        let ciphertext_len = wire::take_u32be(&slot[..wire::U32_BYTES])? as usize;
        if ciphertext_len > CONNECTION_FRAME_BUNDLE_CIPHERTEXT_BYTES {
            return Err(WireError::ValueTooLarge {
                max: CONNECTION_FRAME_BUNDLE_CIPHERTEXT_BYTES,
                actual: ciphertext_len,
            });
        }
        if let Some(offset) = slot[wire::U32_BYTES + ciphertext_len..]
            .iter()
            .position(|byte| *byte != 0)
        {
            return Err(WireError::NonZeroPadding {
                index: CIPHERTEXT_OFFSET + wire::U32_BYTES + ciphertext_len + offset,
            });
        }
        Ok(ConnectionFrameParts {
            header,
            ciphertext: &slot[wire::U32_BYTES..wire::U32_BYTES + ciphertext_len],
        })
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::core::wire::{FixedBytes, FixedSlot};
        use crate::protocol::connection::frame_bundle::encode::{
            encode_fact, encode_frame_bytes, CONNECTION_FRAME_BUNDLE_FACT_BYTES,
        };

        #[test]
        fn connection_frame_bundle_fact_roundtrips_fixed_width() {
            let frame = encode_frame_bytes(FixedBytes([1; 32]), FixedBytes([2; 24]), &[3; 32])
                .expect("frame");
            let fact = ConnectionFrameBundleFact {
                frame: FixedSlot::new(&frame).expect("frame slot"),
            };

            let encoded = encode_fact(&fact).expect("encode");

            assert_eq!(encoded.len(), CONNECTION_FRAME_BUNDLE_FACT_BYTES);
            assert_eq!(decode_fact(&encoded).expect("decode"), fact);
        }
    }
}
pub mod authenticate {
    //! Bundled connection-frame authenticator.
    //!
    //! POLICY. Authenticating a `connection_frame_bundle` fact proves, over its
    //! bytes alone:
    //!   1. LAYOUT. The bytes decode to a canonical bundled connection-frame payload.
    //!   2. ID. The content id equals `hash(bytes)`.
    //!
    //! Frame facts carry only wire bytes; there is no fact-boundary signature and no
    //! intrinsic field rule. Admission scope, the observation and connection context,
    //! decryption, and child materialization are all interpretation the projector
    //! owns through `project.rs`.

    use crate::core::facts::Fact;
    use crate::core::project_fact::{verify_fact_id, ProjectionContext};

    use super::super::fact::ConnectionFrameBundleFact;

    pub(crate) fn authenticate(
        fact: &Fact,
        input: ConnectionFrameBundleFact,
        _context: &ProjectionContext,
    ) -> Result<ConnectionFrameBundleFact, String> {
        prove_decoded_frame_bundle(fact, input)
    }

    fn prove_decoded_frame_bundle(
        fact: &Fact,
        input: ConnectionFrameBundleFact,
    ) -> Result<ConnectionFrameBundleFact, String> {
        // 2. Id.
        verify_fact_id(fact)?;
        Ok(input)
    }

    #[cfg(test)]
    mod tests {
        use crate::core::facts::Fact;
        use crate::core::project_fact::ProjectionContext;
        use crate::core::wire::FixedBytes;
        use crate::protocol::connection::frame_bundle::author::fact_from_wire;
        use crate::protocol::connection::frame_bundle::encode as frame_encode;
        use crate::protocol::connection::frame_bundle::fact::ConnectionFrameBundleFact;

        fn canonical_fact() -> Fact {
            let frame = frame_encode::encode_frame_bytes(
                FixedBytes([1; 32]),
                FixedBytes([2; 24]),
                &[3; 32],
            )
            .expect("frame bytes");
            fact_from_wire(&frame, 100).expect("connection_frame_bundle fact")
        }

        fn authenticate(fact: &Fact) -> Result<ConnectionFrameBundleFact, String> {
            let decoded = super::super::decode::decode_fact(fact.body())?;
            super::authenticate(fact, decoded, &ProjectionContext::default())
        }

        fn is_invalid(fact: &Fact) -> bool {
            authenticate(fact).is_err()
        }

        #[test]
        fn authenticates_canonical_fact() {
            assert!(authenticate(&canonical_fact()).is_ok());
        }

        #[test]
        fn rejects_wrong_tag() {
            let canonical = canonical_fact();
            let mut bytes = canonical.bytes.clone();
            bytes[0] ^= 0xff;
            assert!(is_invalid(&Fact::new(
                canonical.scope,
                canonical.timestamp,
                bytes
            )));
        }

        #[test]
        fn rejects_truncated_bytes() {
            let canonical = canonical_fact();
            let mut bytes = canonical.bytes.clone();
            bytes.pop();
            assert!(is_invalid(&Fact::new(
                canonical.scope,
                canonical.timestamp,
                bytes
            )));
        }

        #[test]
        fn rejects_id_not_matching_bytes() {
            let canonical = canonical_fact();
            let forged = Fact {
                id: [0; 32],
                scope: canonical.scope.clone(),
                timestamp: canonical.timestamp,
                bytes: canonical.bytes.clone(),
            };
            assert!(is_invalid(&forged));
        }
    }
}
pub mod adapt {
    //! Bundled connection-frame semantic adapter.
    //!
    //! The current frame_bundle wire shape is already the active semantic shape. This
    //! identity adapter keeps the protocol-local conversion point available for future versioned
    //! facts.

    use super::super::fact::ConnectionFrameBundleFact;

    pub(crate) fn adapt(
        source: ConnectionFrameBundleFact,
    ) -> Result<ConnectionFrameBundleFact, String> {
        Ok(source)
    }
}

// Bundled connection-frame projector.
//
// POLICY. A `connection_frame_bundle` fact is admitted iff:
//   1. STRUCTURAL. The fact is local ephemeral input and its layout contains
//      exactly one bundled encrypted connection frame.
//   2. CONTEXT. The frame fact has incoming origin metadata, and its header
//      names an exact local `connection` context. Missing context emits only a
//      transient need for the fixed-point pass; malformed and undecryptable
//      frames produce no durable output.
//   3. MATERIALIZE. Opened inner facts are admitted as durable child facts,
//      each with a durable `connection::fact_receipt`.

use crate::core::context::ContextNeed;
use crate::core::crypto;
use crate::core::facts::{Fact, FactId, FactScope};
use crate::core::project_fact::{
    FactProjectorInfo, ProjectionContext, ProjectionOutput, Projector,
};
use crate::protocol::connection::fact_receipt::fact::ReceiptPathInput;
use crate::protocol::connection::fact_receipt::project::connection_fact_receipt_for_path;
use crate::protocol::{auth, connection, content, sync};

use super::fact::ConnectionFrameBundleFact;

/// Projector route metadata for the frame_bundle fact.
pub const PROJECTOR_INFO: FactProjectorInfo = FactProjectorInfo::projector(
    "connection::frame_bundle::project::ConnectionFrameBundleProjector",
);

pub const STORAGE_VERSION: u32 = crate::protocol::versioning::update::CURRENT_PROTOCOL_VERSION;
pub const STORAGE_REQUIREMENT: crate::core::effects::StorageRequirement =
    crate::core::effects::StorageRequirement::Current(STORAGE_VERSION);

#[derive(Debug, Clone, Default)]
pub struct ConnectionFrameBundleProjector;

impl ConnectionFrameBundleProjector {
    pub fn new() -> Self {
        Self
    }
}

impl Projector for ConnectionFrameBundleProjector {
    fn project(
        &self,
        fact: &Fact,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        let decoded = decode::decode_fact(fact.body())?;
        let authenticated = authenticate::authenticate(fact, decoded, context)?;
        let semantic = adapt::adapt(authenticated)?;
        self.project_semantic(fact, semantic, context)
    }
}

impl ConnectionFrameBundleProjector {
    fn project_semantic(
        &self,
        fact: &Fact,
        input: ConnectionFrameBundleFact,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        // 1. Structural.
        // 2. Context.
        // 3. Materialize.
        project_observed_frame(fact, input.frame.bytes(), context)
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

    let Ok(connection_id) = decode::received_connection_fact_id(frame) else {
        return Ok(ProjectionOutput::new().drop_incoming());
    };

    let metadata = context
        .incoming_metadata()
        .ok_or_else(|| "connection frame missing incoming origin metadata".to_string())?;

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
            let mut output = ProjectionOutput::new().need(connection_need);
            for need in needs {
                output = output.need(need);
            }
            return Ok(output);
        }
        ConnectionMaterialContext::Invalid => return Ok(ProjectionOutput::new().drop_incoming()),
    };

    match open_received_frame_with_material(
        frame,
        material,
        &metadata.origin_addr,
        metadata.received_at_local_ms,
    ) {
        Ok(facts) => Ok(facts_output(fact.id, facts)),
        Err(_) => Ok(ProjectionOutput::new().drop_incoming()),
    }
}

fn facts_output(frame_fact_id: FactId, facts: Vec<Fact>) -> ProjectionOutput {
    let mut output = ProjectionOutput::new()
        .drop_incoming()
        .purge_self(frame_fact_id);
    for fact in facts {
        output = output.incoming_fact(fact);
    }
    output
}

fn open_received_frame_with_material(
    frame: &[u8],
    connection: ConnectionMaterial,
    origin_addr: &[u8],
    received_at_local_ms: u64,
) -> Result<Vec<Fact>, String> {
    let opened = open_connection_frame(frame, &connection.connection_secret)?;
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
        let receipt = connection_fact_receipt_for_path(ReceiptPathInput {
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenedConnectionFrame {
    pub connection_id: FactId,
    pub sender_endpoint_id: FactId,
    pub receiver_endpoint_id: FactId,
    pub frame_hash: [u8; 32],
    pub facts: Vec<Vec<u8>>,
}

pub fn open_connection_frame(
    frame: &[u8],
    connection_secret: &crypto::XChaCha20Poly1305Key,
) -> Result<OpenedConnectionFrame, String> {
    let parts = decode::decode_frame_parts(frame).map_err(super::encode::wire_err)?;
    if parts.ciphertext.len() != super::encode::CONNECTION_FRAME_BUNDLE_CIPHERTEXT_BYTES {
        return Err(format!(
            "connection::frame frame ciphertext must fill fixed slot: expected {} got {}",
            super::encode::CONNECTION_FRAME_BUNDLE_CIPHERTEXT_BYTES,
            parts.ciphertext.len()
        ));
    }
    let aad =
        super::encode::frame_associated_data(parts.header.connection_id.0, parts.header.nonce.0);
    let plaintext = crypto::xchacha20poly1305_decrypt(
        connection_secret,
        &aad,
        &parts.header.nonce.0,
        parts.ciphertext,
    )?;
    if plaintext.len() != super::encode::CONNECTION_FRAME_BUNDLE_PLAINTEXT_BYTES {
        return Err(format!(
            "connection::frame frame plaintext must fill fixed slot: expected {} got {}",
            super::encode::CONNECTION_FRAME_BUNDLE_PLAINTEXT_BYTES,
            plaintext.len()
        ));
    }
    let inner = decode_fixed_slot_inner_bundle(&plaintext)?;
    Ok(OpenedConnectionFrame {
        connection_id: parts.header.connection_id.0,
        sender_endpoint_id: inner.sender_endpoint_id,
        receiver_endpoint_id: inner.receiver_endpoint_id,
        frame_hash: crypto::hash(frame),
        facts: inner.facts,
    })
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
    if connection::connection::project::decode::validate_sealed_fact(fact.body()).is_err() {
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
                connection::connection::project::decode::open_fact(fact.body(), &endpoint)
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
            if let Ok(connection) = connection::connection::project::decode::open_fact_as_responder(
                fact.body(),
                &secret,
            ) {
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
        auth::workspace::TYPE_WORKSPACE => admit_with_decoder(
            bytes,
            auth::workspace::project::decode::decode_fact,
            |workspace| Ok(Admission::global(workspace.created_at_ms)),
        ),
        auth::user_invite::TYPE_USER_INVITE => {
            admit_with_decoder(bytes, auth::user_invite::decode_fact_payload, |invite| {
                Ok(Admission::global(invite.created_at_ms))
            })
        }
        auth::user::TYPE_USER => {
            admit_with_decoder(bytes, auth::user::decode_fact_payload, |user| {
                Ok(Admission::global(user.created_at_ms))
            })
        }
        auth::admin::TYPE_ADMIN => {
            admit_with_decoder(bytes, auth::admin::decode_fact_payload, |admin| {
                Ok(Admission::global(admin.created_at_ms))
            })
        }
        auth::device_invite::TYPE_DEVICE_INVITE => {
            admit_with_decoder(bytes, auth::device_invite::decode_fact_payload, |invite| {
                Ok(Admission::global(invite.created_at_ms))
            })
        }
        auth::endpoint_shared::TYPE_ENDPOINT_SHARED => admit_with_decoder(
            bytes,
            auth::endpoint_shared::decode_fact_payload,
            |shared| Ok(Admission::global(shared.created_at_ms)),
        ),
        auth::invite_server::TYPE_INVITE_SERVER => {
            admit_with_decoder(bytes, auth::invite_server::decode_fact_payload, |server| {
                Ok(Admission::global(server.created_at_ms))
            })
        }
        auth::signature::TYPE_SIGNATURE => admit_with_decoder(
            bytes,
            auth::signature::project::decode::decode_fact,
            |signature| {
                Ok(Admission::workspace(
                    signature.workspace_id,
                    signature.created_at_ms,
                ))
            },
        ),
        content::retention_policy::TYPE_RETENTION_POLICY => admit_with_decoder(
            bytes,
            content::retention_policy::project::decode::decode_fact,
            |policy| {
                Ok(Admission::workspace(
                    policy.workspace_id,
                    policy.created_at_ms,
                ))
            },
        ),
        content::reaction::TYPE_CONTENT_REACTION => admit_with_decoder(
            bytes,
            content::reaction::project::decode::decode_fact,
            |reaction| {
                Ok(Admission::workspace(
                    reaction.workspace_id,
                    reaction.created_at_ms,
                ))
            },
        ),
        content::file::TYPE_CONTENT_FILE => {
            admit_with_decoder(bytes, content::file::project::decode::decode_fact, |file| {
                Ok(Admission::workspace(file.workspace_id, file.created_at_ms))
            })
        }
        content::file_slice::TYPE_CONTENT_FILE_SLICE => admit_with_decoder(
            bytes,
            content::file_slice::project::decode::decode_fact,
            |slice| {
                Ok(Admission::workspace(
                    slice.workspace_id,
                    slice.created_at_ms,
                ))
            },
        ),
        content::message::TYPE_CONTENT_MESSAGE => admit_with_decoder(
            bytes,
            content::message::project::decode::decode_fact,
            |message| {
                Ok(Admission::workspace(
                    message.workspace_id,
                    message.created_at_ms,
                ))
            },
        ),
        content::message_deletion::TYPE_CONTENT_MESSAGE_DELETION => admit_with_decoder(
            bytes,
            content::message_deletion::project::decode::decode_fact,
            |deletion| {
                Ok(Admission::workspace(
                    deletion.workspace_id,
                    deletion.created_at_ms,
                ))
            },
        ),
        content::file_deletion::TYPE_CONTENT_FILE_DELETION => admit_with_decoder(
            bytes,
            content::file_deletion::project::decode::decode_fact,
            |deletion| {
                Ok(Admission::workspace(
                    deletion.workspace_id,
                    deletion.created_at_ms,
                ))
            },
        ),
        auth::recipient_key::encode::TYPE_RECIPIENT_KEY => admit_with_decoder(
            bytes,
            auth::recipient_key::project::decode::decode_recipient_key,
            |recipient| {
                Ok(Admission::workspace(
                    recipient.workspace_id,
                    recipient.created_at_ms,
                ))
            },
        ),
        auth::removal_frontier::encode::TYPE_REMOVAL_FRONTIER => admit_with_decoder(
            bytes,
            auth::removal_frontier::project::decode::decode_removal_frontier,
            |frontier| {
                Ok(Admission::workspace(
                    frontier.workspace_id,
                    frontier.created_at_ms,
                ))
            },
        ),
        auth::key_request::encode::TYPE_KEY_REQUEST => admit_with_decoder(
            bytes,
            auth::key_request::project::decode::decode_key_request,
            |request| {
                Ok(Admission::workspace(
                    request.workspace_id,
                    request.created_at_ms,
                ))
            },
        ),
        auth::local_history_node_secret::TYPE_LOCAL_HISTORY_NODE_SECRET => {
            Err("received connection::frame payload is local history-node secret".to_string())
        }
        sync::compare::TYPE_SYNC_COMPARE => {
            admit_with_decoder(bytes, sync::compare::project::decode::decode_fact, |_| {
                Ok(Admission::global(0))
            })
        }
        sync::have_id::TYPE_SYNC_HAVE_ID => {
            admit_with_decoder(bytes, sync::have_id::project::decode::decode_fact, |_| {
                Ok(Admission::global(0))
            })
        }
        sync::need_id::TYPE_SYNC_NEED_ID => {
            admit_with_decoder(bytes, sync::need_id::project::decode::decode_fact, |_| {
                Ok(Admission::global(0))
            })
        }
        auth::key_wrap::encode::TYPE_KEY_WRAP => admit_with_decoder(
            bytes,
            auth::key_wrap::project::decode::decode_key_wrap,
            |wrap| Ok(Admission::workspace(wrap.workspace_id, wrap.created_at_ms)),
        ),
        _ => Err(format!(
            "unsupported received connection::frame fact type {tag}"
        )),
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

struct DecodedInnerBundle {
    sender_endpoint_id: FactId,
    receiver_endpoint_id: FactId,
    facts: Vec<Vec<u8>>,
}

fn decode_fixed_slot_inner_bundle(bytes: &[u8]) -> Result<DecodedInnerBundle, String> {
    if bytes.len() != super::encode::CONNECTION_FRAME_BUNDLE_PLAINTEXT_BYTES {
        return Err("connection::frame fixed-slot bundle length mismatch".to_string());
    }
    let mut reader = Reader::new(bytes);
    if reader.take(4)? != b"TIB1" {
        return Err("expected connection::frame inner bundle".to_string());
    }
    let version = reader.u8()?;
    if version != 1 {
        return Err(format!(
            "unsupported connection::frame inner bundle version {version}"
        ));
    }
    let sender_endpoint_id = reader.id32()?;
    let receiver_endpoint_id = reader.id32()?;
    let count = reader.u32()? as usize;
    if count == 0 {
        return Err("connection::frame inner bundle must contain at least one fact".to_string());
    }
    if count > super::encode::CONNECTION_FRAME_BUNDLE_FACT_SLOTS {
        return Err("connection::frame inner bundle count exceeds slot count".to_string());
    }

    let mut facts = Vec::with_capacity(count);
    for index in 0..super::encode::CONNECTION_FRAME_BUNDLE_FACT_SLOTS {
        let len = reader.u32()? as usize;
        let slot = reader.take(super::encode::CONNECTION_FRAME_BUNDLE_FACT_SLOT_BYTES)?;
        if index < count {
            if len > super::encode::CONNECTION_FRAME_BUNDLE_FACT_SLOT_BYTES {
                return Err("connection::frame inner bundle slot length exceeds slot".to_string());
            }
            if slot[len..].iter().any(|byte| *byte != 0) {
                return Err("connection::frame inner bundle slot has nonzero padding".to_string());
            }
            facts.push(slot[..len].to_vec());
        } else if len != 0 || slot.iter().any(|byte| *byte != 0) {
            return Err("connection::frame unused bundle slot is nonzero".to_string());
        }
    }
    reader.finish()?;
    Ok(DecodedInnerBundle {
        sender_endpoint_id,
        receiver_endpoint_id,
        facts,
    })
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn u8(&mut self) -> Result<u8, String> {
        Ok(self.take(1)?[0])
    }

    fn u32(&mut self) -> Result<u32, String> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()))
    }

    fn id32(&mut self) -> Result<FactId, String> {
        Ok(self.take(32)?.try_into().unwrap())
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], String> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or_else(|| "connection::frame inner bundle length overflow".to_string())?;
        if end > self.bytes.len() {
            return Err("truncated connection::frame inner bundle".to_string());
        }
        let bytes = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(bytes)
    }

    fn finish(self) -> Result<(), String> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err("connection::frame inner bundle has trailing bytes".to_string())
        }
    }
}
