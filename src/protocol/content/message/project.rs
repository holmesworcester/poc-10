pub mod decode {
    //! Byte decoding for content-message facts and opened plaintext slots.
    //!
    //! Fact decoding proves only the fixed layout: tag, length, field order, and
    //! bounded ciphertext slot. Id checks live in the local `authenticate` module.
    //! Plaintext recovery is here because projection decrypts to this fixed slot
    //! and then needs a canonical UTF-8 string.

    use crate::core::wire;

    use super::super::encode::{CONTENT_MESSAGE_BYTES, TYPE_CONTENT_MESSAGE};
    use super::super::fact::{
        ContentMessageFact, CIPHERTEXT_BYTES, MAX_TEXT_BYTES, PLAINTEXT_SLOT_BYTES,
        TEXT_LENGTH_PREFIX_BYTES,
    };

    pub fn decode_fact(bytes: &[u8]) -> Result<ContentMessageFact, String> {
        let mut reader = wire::Reader::new(bytes);
        reader.expect_len(CONTENT_MESSAGE_BYTES).map_err(wire_err)?;
        let tag = reader.u8().map_err(wire_err)?;
        if tag != TYPE_CONTENT_MESSAGE {
            return Err("expected content message fact".to_string());
        }
        let fact = ContentMessageFact {
            workspace_id: reader.array().map_err(wire_err)?,
            created_at_ms: reader.u64be().map_err(wire_err)?,
            author_user_id: reader.array().map_err(wire_err)?,
            signer_id: reader.array().map_err(wire_err)?,
            signer_public_key: reader.array().map_err(wire_err)?,
            frontier_id: reader.array().map_err(wire_err)?,
            local_history_node_secret_id: reader.array().map_err(wire_err)?,
            expires_at_minute: reader.u64be().map_err(wire_err)?,
            retention_policy_id: reader.array().map_err(wire_err)?,
            minute: reader.u64be().map_err(wire_err)?,
            nonce: reader.array().map_err(wire_err)?,
            ciphertext: reader
                .fixed_slot_value::<CIPHERTEXT_BYTES>()
                .map_err(wire_err)?,
        };
        reader.finish().map_err(wire_err)?;
        Ok(fact)
    }

    pub fn recover_text(plaintext: &[u8]) -> Result<String, String> {
        if plaintext.len() != PLAINTEXT_SLOT_BYTES {
            return Err(format!(
                "plaintext slot is {} bytes, expected {PLAINTEXT_SLOT_BYTES}",
                plaintext.len()
            ));
        }
        let len = wire::take_u32be(&plaintext[..TEXT_LENGTH_PREFIX_BYTES])
            .map_err(|err| format!("{err:?}"))? as usize;
        if len > MAX_TEXT_BYTES {
            return Err("recovered text length out of range".to_string());
        }
        let bytes = &plaintext[TEXT_LENGTH_PREFIX_BYTES..TEXT_LENGTH_PREFIX_BYTES + len];
        String::from_utf8(bytes.to_vec()).map_err(|err| format!("text was not utf-8: {err}"))
    }

    fn wire_err(err: wire::WireError) -> String {
        format!("{err:?}")
    }

    // Tests. Ordered most-central first: the fixed-width roundtrip proves the
    // whole codec, then the tag and length rejections guard the layout.
    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::protocol::content::message::fact::{MessageCiphertext, NONCE_BYTES};

        fn fact() -> ContentMessageFact {
            ContentMessageFact {
                workspace_id: [1; 32],
                created_at_ms: 180_000,
                author_user_id: [2; 32],
                signer_id: [3; 32],
                signer_public_key: [9; 32],
                frontier_id: [4; 32],
                local_history_node_secret_id: [5; 32],
                expires_at_minute: u64::MAX,
                retention_policy_id: [6; 32],
                minute: 3,
                nonce: [8; NONCE_BYTES],
                ciphertext: MessageCiphertext::new(b"sealed").expect("ciphertext"),
            }
        }

        #[test]
        fn content_message_roundtrips_fixed_width() {
            let encoded =
                crate::protocol::content::message::encode::encode_fact(&fact()).expect("encode");
            assert_eq!(encoded.len(), CONTENT_MESSAGE_BYTES);
            assert_eq!(decode_fact(&encoded).expect("decode"), fact());
        }

        #[test]
        fn rejects_wrong_tag() {
            let mut encoded =
                crate::protocol::content::message::encode::encode_fact(&fact()).expect("encode");
            encoded[0] = TYPE_CONTENT_MESSAGE.wrapping_add(1);
            assert!(decode_fact(&encoded).is_err());
        }

        #[test]
        fn rejects_wrong_length() {
            assert!(decode_fact(&[TYPE_CONTENT_MESSAGE; 16]).is_err());
        }
    }
}
pub mod authenticate {
    //! Content-message authenticator.
    //!
    //! POLICY. Authenticating a `content_message` fact proves, over its bytes alone:
    //!   1. LAYOUT. The bytes decode to a canonical content-message envelope — right
    //!      tag, fixed width, valid fields — through the family codec.
    //!   2. ID. The content id equals `hash(bytes)`.
    //!
    //! It proves nothing else. Admission scope is unsigned local metadata, not part
    //! of these bytes, so the workspace-scope check is interpretation the projector
    //! owns — that keeps the workspace-id format, its type, and the rule itself
    //! behind the lens and the single ceiling projector, free to evolve. Decryption
    //! of the message text likewise stays in the projector: the text key is secret
    //! context and decryption yields read-model meaning. Signature evidence is a
    //! separate fact and context dependency. The authenticated payload is the
    //! decoded fact; the projector proves scope, signature evidence, signer, author,
    //! deletion, retention, and secret context and materializes rows.

    use crate::core::facts::Fact;
    use crate::core::project_fact::{verify_fact_id, ProjectionContext};

    use super::super::fact::ContentMessageFact;

    pub(crate) fn authenticate(
        fact: &Fact,
        message: ContentMessageFact,
        _context: &ProjectionContext,
    ) -> Result<ContentMessageFact, String> {
        prove_decoded_message(fact, message)
    }

    fn prove_decoded_message(
        fact: &Fact,
        message: ContentMessageFact,
    ) -> Result<ContentMessageFact, String> {
        // 2. Id.
        verify_fact_id(fact)?;
        Ok(message)
    }

    // Tests. Ordered most-central first: a canonical fact authenticates, then
    // the id-binding invariant (id == hash(bytes)), then the layout rejections.
    #[cfg(test)]
    mod tests {
        use crate::core::facts::Fact;
        use crate::core::project_fact::ProjectionContext;
        use crate::protocol::content::message::encode;
        use crate::protocol::content::message::fact::{
            ContentMessageFact, MessageCiphertext, NONCE_BYTES,
        };

        const WORKSPACE_ID: [u8; 32] = [1; 32];

        fn canonical_fact() -> Fact {
            let message = ContentMessageFact {
                workspace_id: WORKSPACE_ID,
                created_at_ms: 180_000,
                author_user_id: [2; 32],
                signer_id: [3; 32],
                signer_public_key: [7; 32],
                frontier_id: [4; 32],
                local_history_node_secret_id: [5; 32],
                expires_at_minute: u64::MAX,
                retention_policy_id: [6; 32],
                minute: 3,
                nonce: [8; NONCE_BYTES],
                ciphertext: MessageCiphertext::new(b"sealed").expect("ciphertext"),
            };
            Fact::new(
                crate::protocol::auth::workspace::scope(WORKSPACE_ID),
                message.created_at_ms,
                encode::encode_fact(&message).expect("encode message"),
            )
        }

        fn authenticate(fact: &Fact) -> Result<ContentMessageFact, String> {
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
    }
}
pub mod adapt {
    //! Content-message semantic adapter.
    //!
    //! The current content-message wire shape is already the active semantic
    //! shape. This identity adapter keeps the staged route explicit and gives
    //! future versioned facts a dedicated conversion point.

    use super::super::fact::ContentMessageFact;

    pub(crate) fn adapt(source: ContentMessageFact) -> Result<ContentMessageFact, String> {
        Ok(source)
    }
}

// Semantic content-message projector.
//
// POLICY. A content_message is admitted iff:
//   1. STRUCTURAL. The fact is workspace-scoped, signed, and contains a
//      message payload with encrypted text.
//   2. CONTEXT. The projector records sync liveness immediately, then waits
//      for signer, author, deletion, retention-floor, secret, and time
//      context. Once signer and author validate, it publishes metadata context
//      for deletion. It does not publish opened message context or rows until
//      the encrypted text opens. Deletion, expiry, or retention context removes
//      this message's rows and purges this message fact.
//   3. MATERIALIZE. Once opened, the projector writes read-model rows and
//      offers semantic message context.

use crate::core::context::{ContextKey, ContextKeyPart, ContextNeed};
use crate::core::crypto;
use crate::core::facts::{Fact, FactId};
use crate::core::intents::{RowMutation, TableDeleteWhere, TableInsert, TypedTableSchema, Value};
use crate::core::project_fact::{
    FactProjectorInfo, ProjectionContext, ProjectionOutput, Projector, TimeWake,
};
use crate::protocol::auth;
use crate::protocol::auth::local_history_node_secret::project as coverage;
use crate::protocol::auth::signature;
use crate::protocol::content::{message_deletion, retention_policy};
use crate::protocol::registry::read_models;
use crate::protocol::sync::shared_fact::project::{
    context_have_from_needs, retract_fact_from_sync, share_fact_with_sync,
};

use super::fact::{AuthorId, ContentMessageFact, SignerId, WorkspaceId, UNIX_MINUTE_MS};

/// Projector route metadata for the content-message fact.
pub const PROJECTOR_INFO: FactProjectorInfo =
    FactProjectorInfo::projector("content::message::project::ContentMessageProjector");

pub const STORAGE_VERSION: u32 = crate::protocol::versioning::CURRENT_PROTOCOL_VERSION;
pub const STORAGE_REQUIREMENT: crate::core::effects::StorageRequirement =
    crate::core::effects::StorageRequirement::Current(STORAGE_VERSION);

/// Content's key shape for the generic core `fact_purged` context role.
///
/// This is not a protocol fact family. It is the content projection coordinate
/// used by exact deletion facts and range purge producers to wake target
/// content projectors. Target projectors publish exact needs at their own
/// coordinates; producers publish exact or range offers over the same sortable
/// coordinate.
pub fn fact_purged_key(frontier_id: FactId, minute: u64, target_fact_id: FactId) -> ContextKey {
    ContextKey::from_parts([
        ContextKeyPart::bytes(&frontier_id),
        ContextKeyPart::u64(minute),
        ContextKeyPart::bytes(&target_fact_id),
    ])
    .expect("content purge context key uses bounded fixed-width parts")
}

pub fn fact_purged_minute_range_keys(
    frontier_id: FactId,
    start_minute: u64,
    end_minute: u64,
) -> (ContextKey, ContextKey) {
    (
        fact_purged_key(frontier_id, start_minute, [0; 32]),
        fact_purged_key(frontier_id, end_minute, [0xff; 32]),
    )
}

pub const COVER_HORIZON_MINUTES: u64 = 30 * 24 * 60;

const RETENTION_FLOOR_ROLE: &str = "content_retention_floor";

#[derive(Debug, Clone, PartialEq, Eq)]
struct OpenedMessageRow {
    workspace_id: WorkspaceId,
    message_id: FactId,
    created_at_ms: u64,
    author_user_id: AuthorId,
    signer_id: SignerId,
    text: String,
}

pub fn expiration_timeline() -> crate::core::project_fact::Timeline {
    crate::core::project_fact::Timeline::new("content_message_expiry")
        .expect("valid content-message expiry timeline")
}

pub fn retention_floor_need(
    owner: crate::core::facts::FactId,
    workspace_id: crate::core::facts::FactId,
) -> crate::core::context::ContextNeed {
    let key = workspace_id.to_vec();
    crate::core::context::ContextNeed::range(
        owner,
        crate::core::context::Role::expect(RETENTION_FLOOR_ROLE),
        crate::protocol::auth::workspace::scope(workspace_id),
        key.clone(),
        key,
    )
}

pub fn retention_floor_offer(
    owner: crate::core::facts::FactId,
    workspace_id: crate::core::facts::FactId,
) -> crate::core::context::ContextOffer {
    let key = workspace_id.to_vec();
    crate::core::context::ContextOffer::range(
        owner,
        crate::core::context::Role::expect(RETENTION_FLOOR_ROLE),
        crate::protocol::auth::workspace::scope(workspace_id),
        key.clone(),
        key,
    )
}

fn content_message_row(message_id: FactId, fact: &ContentMessageFact) -> TableInsert {
    read_models::CONTENT_MESSAGES.insert(vec![
        Value::Bytes(fact.workspace_id.to_vec()),
        Value::Bytes(message_id.to_vec()),
        Value::Bytes(fact.author_user_id.to_vec()),
        Value::U64(fact.created_at_ms),
        Value::Bytes(fact.signer_id.to_vec()),
        Value::Bytes(fact.frontier_id.to_vec()),
        Value::U64(fact.minute),
        Value::Bool(false),
    ])
}

fn opened_message_row(input: OpenedMessageRow) -> TableInsert {
    read_models::OPENED_MESSAGES.insert(vec![
        Value::Bytes(input.workspace_id.to_vec()),
        Value::Bytes(input.message_id.to_vec()),
        Value::U64(input.created_at_ms),
        Value::Bytes(input.author_user_id.to_vec()),
        Value::Bytes(input.signer_id.to_vec()),
        Value::Bytes(input.text.into_bytes()),
    ])
}

fn message_tombstone_row(
    workspace_id: WorkspaceId,
    message_id: FactId,
    author_user_id: AuthorId,
    created_at_ms: u64,
) -> TableInsert {
    message_tombstone_row_at_minute(
        workspace_id,
        message_id,
        author_user_id,
        created_at_ms / UNIX_MINUTE_MS,
    )
}

fn message_tombstone_row_at_minute(
    workspace_id: WorkspaceId,
    message_id: FactId,
    author_user_id: AuthorId,
    authored_minute: u64,
) -> TableInsert {
    read_models::MESSAGE_TOMBSTONES.insert(vec![
        Value::Bytes(workspace_id.to_vec()),
        Value::Bytes(message_id.to_vec()),
        Value::Bytes(author_user_id.to_vec()),
        Value::U64(authored_minute),
    ])
}

fn message_row_delete(
    schema: TypedTableSchema,
    workspace_id: FactId,
    message_id: FactId,
) -> TableDeleteWhere {
    schema.delete_by_key(vec![
        Value::Bytes(workspace_id.to_vec()),
        Value::Bytes(message_id.to_vec()),
    ])
}

#[derive(Debug, Clone, Default)]
pub struct ContentMessageProjector;

impl ContentMessageProjector {
    pub fn new() -> Self {
        Self
    }
}

impl Projector for ContentMessageProjector {
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

impl ContentMessageProjector {
    fn project_semantic(
        &self,
        fact: &Fact,
        message: super::fact::ContentMessageFact,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        // Authentication (see the local authenticate module) proved canonical bytes. Scope is
        // interpretation, not authentication — it gates on unsigned admission
        // metadata — so it is checked here, behind the lens and the single
        // ceiling projector, where the workspace-id shape and this rule can
        // evolve.
        let scope = crate::protocol::auth::workspace::scope(message.workspace_id);
        if fact.scope != scope {
            return Err("content message fact scope does not match body workspace".to_string());
        }

        // 2. Context, signature evidence, and deletion gates.
        let signature_need = signature::project::signature_proof_need(
            fact.id,
            scope.clone(),
            fact.id,
            message.signer_public_key,
        )?;
        let signer_need = crate::core::context::ContextNeed::range(
            fact.id,
            "content_signer",
            scope.clone(),
            message.signer_id,
            message.signer_id,
        );
        let deletion_need = crate::core::project_fact::fact_purged_need(
            fact.id,
            scope.clone(),
            fact_purged_key(message.frontier_id, message.minute, fact.id),
        );
        let retention_floor_need = retention_floor_need(fact.id, message.workspace_id);
        let author_need = crate::core::context::ContextNeed::range(
            fact.id,
            "auth_user",
            crate::core::facts::FactScope::Global,
            message.author_user_id,
            message.author_user_id,
        );
        let secret_need = coverage::secret_need(
            fact.id,
            scope.clone(),
            message.workspace_id,
            message.frontier_id,
            message.minute,
            fact.id,
        );

        let base_output = base_wait_output(
            fact,
            &message,
            [
                signature_need.clone(),
                signer_need.clone(),
                deletion_need.clone(),
                retention_floor_need.clone(),
                author_need.clone(),
                secret_need.clone(),
            ],
        );
        let Some(signature_payload) =
            context_payload(context, &signature_need, "message signature proof")?
        else {
            return Ok(base_output);
        };
        signature::project::validate_signature_proof_payload(
            signature_payload,
            &signature_need,
            message.workspace_id,
            fact.id,
            message.signer_public_key,
            "content message",
        )?;
        let Some(signer_payload) = context.payload_for(&signer_need) else {
            return Ok(base_wait_output(
                fact,
                &message,
                [
                    signature_need.clone(),
                    signer_need.clone(),
                    deletion_need.clone(),
                    retention_floor_need.clone(),
                    author_need.clone(),
                    secret_need.clone(),
                ],
            ));
        };
        validate_message_signer_context(signer_payload, &signer_need, &message)?;
        let Some(author) = context_payload(context, &author_need, "message author")? else {
            return Ok(base_wait_output(
                fact,
                &message,
                [
                    signature_need.clone(),
                    signer_need.clone(),
                    deletion_need.clone(),
                    retention_floor_need.clone(),
                    author_need.clone(),
                    secret_need.clone(),
                ],
            ));
        };
        validate_author_user(author, message.workspace_id, message.author_user_id)?;
        if expiry_minute_reached(context, &message).is_some() {
            return Ok(expired_output(fact.id, &message));
        }
        if let Some(floor) = cover_horizon_reached(context, &message) {
            return Ok(retired_output(fact.id, &message, floor));
        }
        if let Some(floor) = retention_floor_reached(context, &retention_floor_need, &message)? {
            return Ok(retired_output(fact.id, &message, floor));
        }
        let context_have = context_have_from_needs(
            context,
            [
                &signature_need,
                &signer_need,
                &deletion_need,
                &retention_floor_need,
                &author_need,
            ],
        );

        if let Some(deletion) = context_payload(context, &deletion_need, "message deletion")? {
            validate_message_deletion(
                deletion,
                message.workspace_id,
                message.frontier_id,
                message.minute,
                fact.id,
                message.author_user_id,
            )?;
            return Ok(author_deletion_output(fact.id, &message));
        }
        let Some(secret_payload) = matched_secret_payload(context, &secret_need)? else {
            return Ok(base_wait_output(
                fact,
                &message,
                [
                    signature_need,
                    signer_need,
                    deletion_need,
                    retention_floor_need,
                    author_need,
                    secret_need,
                ],
            ));
        };
        let text = decrypt_text(&message, secret_payload)?;

        // 3. Materialize.
        Ok(share_fact_with_sync(
            ready_message_output(fact, &message, deletion_need, retention_floor_need)
                .offer(crate::core::context::ContextOffer::range(
                    fact.id,
                    "content_message",
                    scope,
                    fact.id,
                    fact.id,
                ))
                .row_mutation(RowMutation::InsertValues(content_message_row(
                    fact.id, &message,
                )))
                .row_mutation(RowMutation::InsertValues(opened_message_row(
                    OpenedMessageRow {
                        workspace_id: message.workspace_id,
                        message_id: fact.id,
                        created_at_ms: message.created_at_ms,
                        author_user_id: message.author_user_id,
                        signer_id: message.signer_id,
                        text,
                    },
                ))),
            message.workspace_id,
            fact,
            context_have,
        ))
    }
}

fn base_wait_output(
    fact: &Fact,
    message: &super::fact::ContentMessageFact,
    needs: impl IntoIterator<Item = ContextNeed>,
) -> ProjectionOutput {
    with_retention_wakes(
        needs
            .into_iter()
            .fold(ProjectionOutput::new(), |output, need| output.need(need)),
        fact.id,
        message,
    )
}

fn ready_message_output(
    fact: &Fact,
    message: &super::fact::ContentMessageFact,
    deletion_need: ContextNeed,
    retention_floor_need: ContextNeed,
) -> ProjectionOutput {
    with_retention_wakes(
        ProjectionOutput::new()
            .need(deletion_need)
            .need(retention_floor_need),
        fact.id,
        message,
    )
}

fn validate_message_signer_context(
    payload: &Fact,
    _need: &ContextNeed,
    message: &super::fact::ContentMessageFact,
) -> Result<(), String> {
    let endpoint = endpoint_shared_signer(payload)
        .ok_or_else(|| "content message signer context must be endpoint_shared".to_string())?;
    if endpoint.workspace_id != message.workspace_id {
        return Err("content message signer endpoint workspace does not match message".to_string());
    }
    if endpoint.endpoint_id != message.signer_id {
        return Err("content message signer endpoint id does not match message".to_string());
    }
    if endpoint.user_authority_fact_id != message.author_user_id {
        return Err(
            "content message signer endpoint is not authorized by the named author".to_string(),
        );
    }
    if endpoint.signing_public_key != message.signer_public_key {
        return Err(
            "content message signer context public key does not match message signature key"
                .to_string(),
        );
    }
    Ok(())
}

fn endpoint_shared_signer(
    payload: &Fact,
) -> Option<auth::endpoint_shared::fact::EndpointSharedFact> {
    auth::endpoint_shared::decode_fact_payload(payload.body()).ok()
}

fn validate_author_user(
    payload: &Fact,
    workspace_id: crate::core::facts::FactId,
    author_user_id: crate::core::facts::FactId,
) -> Result<(), String> {
    if payload.id != author_user_id {
        return Err("message author context payload id mismatch".to_string());
    }
    let author = crate::protocol::auth::user::decode_fact_payload(payload.body())
        .map_err(|_| "message author context is not an identity user".to_string())?;
    if author.workspace_id != workspace_id {
        return Err("message author workspace does not match message".to_string());
    }
    Ok(())
}

fn validate_message_deletion(
    payload: &Fact,
    workspace_id: crate::core::facts::FactId,
    target_frontier_id: crate::core::facts::FactId,
    target_minute: u64,
    target_message_id: crate::core::facts::FactId,
    author_user_id: crate::core::facts::FactId,
) -> Result<(), String> {
    if let Ok(deletion) = message_deletion::decode_fact_payload(payload.body()) {
        if deletion.workspace_id != workspace_id {
            return Err("message deletion workspace does not match message".to_string());
        }
        if deletion.target_frontier_id != target_frontier_id {
            return Err("message deletion frontier does not match message".to_string());
        }
        if deletion.target_minute != target_minute {
            return Err("message deletion minute does not match message".to_string());
        }
        if deletion.target_message_id != target_message_id {
            return Err("message deletion target does not match message".to_string());
        }
        if deletion.author_user_id != author_user_id {
            return Err("message deletion author does not match message author".to_string());
        }
        return Ok(());
    }

    Err("message deletion context is not a content message deletion".to_string())
}

fn matched_secret_payload<'a>(
    context: &'a ProjectionContext,
    need: &'a ContextNeed,
) -> Result<Option<&'a Fact>, String> {
    for (offer, payload) in context.matched_payloads_for(need) {
        if !coverage::secret_coverage_offer_valid_for_need(need, offer) {
            return Err("content message secret context offer does not match need".to_string());
        }
        if auth::local_key_secret::project::decode::decode_local_key_secret(payload.body()).is_ok()
            || auth::local_history_node_secret::project::decode::decode_local_history_node_secret(
                payload.body(),
            )
            .is_ok()
        {
            return Ok(Some(payload));
        }
    }
    Ok(None)
}

fn decrypt_text(
    message: &super::fact::ContentMessageFact,
    secret_payload: &Fact,
) -> Result<String, String> {
    let key = if let Ok(secret) =
        auth::local_key_secret::project::decode::decode_local_key_secret(secret_payload.body())
    {
        if secret.workspace_id != message.workspace_id || secret.frontier_id != message.frontier_id
        {
            return Err("content message root secret does not match message".to_string());
        }
        secret.key_secret
    } else {
        let node =
            auth::local_history_node_secret::project::decode::decode_local_history_node_secret(
                secret_payload.body(),
            )
            .map_err(|_| "content message secret context is not local key material".to_string())?;
        if node.workspace_id != message.workspace_id || node.frontier_id != message.frontier_id {
            return Err("content message history secret does not match message".to_string());
        }
        node.node_secret
    };
    let plaintext = crypto::xchacha20poly1305_decrypt(
        &key,
        &crate::protocol::content::message::encode::associated_data(
            message.workspace_id,
            message.frontier_id,
            message.minute,
        ),
        &message.nonce,
        &message.ciphertext,
    )?;
    crate::protocol::content::message::project::decode::recover_text(&plaintext)
}

fn expiry_minute_reached(
    context: &ProjectionContext,
    message: &super::fact::ContentMessageFact,
) -> Option<u64> {
    if message.expires_at_minute == u64::MAX {
        return None;
    }
    context.time_reached(&expiration_timeline(), message.expires_at_minute)
}

fn retention_floor_reached(
    context: &ProjectionContext,
    need: &ContextNeed,
    message: &super::fact::ContentMessageFact,
) -> Result<Option<u64>, String> {
    let mut floor = 0u64;
    for (_offer, payload) in context.matched_payloads_for(need) {
        let policy = retention_policy::decode_fact_payload(payload.body()).map_err(|_| {
            "content message retention floor context is not a retention policy".to_string()
        })?;
        if policy.workspace_id != message.workspace_id {
            return Err("content message retention floor workspace mismatch".to_string());
        }
        floor = floor.max(policy.retire_minute);
    }
    Ok((message.minute < floor).then_some(floor))
}

fn cover_horizon_reached(
    context: &ProjectionContext,
    message: &super::fact::ContentMessageFact,
) -> Option<u64> {
    let retire_at = message.minute.checked_add(COVER_HORIZON_MINUTES)?;
    context
        .time_reached(&expiration_timeline(), retire_at)
        .map(|now| now.saturating_sub(COVER_HORIZON_MINUTES))
        .filter(|floor| message.minute < *floor)
}

fn with_retention_wakes(
    output: ProjectionOutput,
    owner: FactId,
    message: &super::fact::ContentMessageFact,
) -> ProjectionOutput {
    let mut output = output;
    if let Some(at) = message.minute.checked_add(COVER_HORIZON_MINUTES) {
        output = output.time_wake(TimeWake {
            owner,
            timeline: expiration_timeline(),
            at,
        });
    }
    if message.expires_at_minute == u64::MAX {
        return output;
    }
    output.time_wake(TimeWake {
        owner,
        timeline: expiration_timeline(),
        at: message.expires_at_minute,
    })
}

fn expired_output(
    message_id: FactId,
    message: &super::fact::ContentMessageFact,
) -> ProjectionOutput {
    retract_fact_from_sync(
        ProjectionOutput::new()
            .row_mutation(RowMutation::InsertValues(message_tombstone_row(
                message.workspace_id,
                message_id,
                message.author_user_id,
                message.created_at_ms,
            )))
            .row_mutation(RowMutation::DeleteWhere(message_row_delete(
                read_models::CONTENT_MESSAGES,
                message.workspace_id,
                message_id,
            )))
            .row_mutation(RowMutation::DeleteWhere(message_row_delete(
                read_models::OPENED_MESSAGES,
                message.workspace_id,
                message_id,
            )))
            .purge_self(message_id),
        message.workspace_id,
        message_id,
        message.created_at_ms,
    )
}

fn retired_output(
    message_id: FactId,
    message: &super::fact::ContentMessageFact,
    floor_minute: u64,
) -> ProjectionOutput {
    retract_fact_from_sync(
        ProjectionOutput::new()
            .row_mutation(RowMutation::InsertValues(message_tombstone_row_at_minute(
                message.workspace_id,
                message_id,
                message.author_user_id,
                floor_minute.saturating_sub(1),
            )))
            .row_mutation(RowMutation::DeleteWhere(message_row_delete(
                read_models::CONTENT_MESSAGES,
                message.workspace_id,
                message_id,
            )))
            .row_mutation(RowMutation::DeleteWhere(message_row_delete(
                read_models::OPENED_MESSAGES,
                message.workspace_id,
                message_id,
            )))
            .purge_self(message_id),
        message.workspace_id,
        message_id,
        message.created_at_ms,
    )
}

fn author_deletion_output(
    message_id: FactId,
    message: &super::fact::ContentMessageFact,
) -> ProjectionOutput {
    retract_fact_from_sync(
        ProjectionOutput::new()
            .row_mutation(RowMutation::InsertValues(message_tombstone_row(
                message.workspace_id,
                message_id,
                message.author_user_id,
                message.created_at_ms,
            )))
            .row_mutation(RowMutation::DeleteWhere(message_row_delete(
                read_models::CONTENT_MESSAGES,
                message.workspace_id,
                message_id,
            )))
            .row_mutation(RowMutation::DeleteWhere(message_row_delete(
                read_models::OPENED_MESSAGES,
                message.workspace_id,
                message_id,
            )))
            .purge_self(message_id),
        message.workspace_id,
        message_id,
        message.created_at_ms,
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FactSigner {
    pub signer_id: FactId,
    pub signer_public_key: [u8; 32],
}

/// Returns a direct semantic payload after checking the expected fact tag.
pub fn decode_payload(fact: &Fact, expected_type: u8, label: &str) -> Result<Vec<u8>, String> {
    if fact.bytes.first().copied() == Some(expected_type) {
        Ok(fact.bytes.clone())
    } else {
        Err(format!("{label} fact has the wrong type tag"))
    }
}

pub fn decode_typed_fact<T>(
    fact: &Fact,
    expected_type: u8,
    label: &str,
    decode: impl FnOnce(&[u8]) -> Result<T, String>,
) -> Result<T, String> {
    decode(&decode_payload(fact, expected_type, label)?)
}

pub fn signer_need(owner: FactId, workspace_id: FactId, signer_id: FactId) -> ContextNeed {
    crate::core::context::ContextNeed::range(
        owner,
        "content_signer",
        crate::protocol::auth::workspace::scope(workspace_id),
        signer_id,
        signer_id,
    )
}

/// Checks that the context payload satisfying a signer need is the endpoint
/// authority the content fact relies on.
pub fn validate_signer_context(
    context: &ProjectionContext,
    need: &ContextNeed,
    signer: FactSigner,
    workspace_id: FactId,
    author_user_id: Option<FactId>,
    label: &str,
) -> Result<bool, String> {
    let Some(payload) = context_payload(context, need, &format!("{label} signer"))? else {
        return Ok(false);
    };
    let endpoint = auth::endpoint_shared::decode_fact_payload(payload.body())
        .map_err(|_| format!("{label} signer context is not an endpoint_shared"))?;
    if endpoint.workspace_id != workspace_id {
        return Err(format!(
            "{label} signer endpoint_shared workspace does not match {label}"
        ));
    }
    if endpoint.endpoint_id != signer.signer_id {
        return Err(format!(
            "{label} signer endpoint id does not match content fact"
        ));
    }
    if endpoint.signing_public_key != signer.signer_public_key {
        return Err(format!(
            "{label} signer public key does not match endpoint_shared"
        ));
    }
    if author_user_id.is_some_and(|author| endpoint.user_authority_fact_id != author) {
        return Err(format!(
            "{label} signer endpoint is not authorized by the named author"
        ));
    }
    Ok(true)
}

pub fn context_payload<'a>(
    context: &'a ProjectionContext,
    need: &ContextNeed,
    label: &str,
) -> Result<Option<&'a Fact>, String> {
    context.payload_for_checked(need, label)
}

// Tests.
//
// The semantic projector is the heart of this file; these are ordered
// most-central first. The full materialize-after-context happy path leads,
// followed by the wait/park gates, then the deletion and expiry/retraction
// branches, and finally the row-builder, purge-coordinate, and malformed-bytes
// checks. Reading top-down shows when a message becomes a visible row and when
// it is withheld or removed.
#[cfg(test)]
mod projector_tests {
    use crate as topo;

    use topo::core::crypto;
    use topo::core::facts::{Fact, FactScope};
    use topo::core::intents::RowMutation;
    use topo::core::project_fact::{MatchedContext, ProjectionContext, Projector, TimeRange};
    use topo::protocol::auth::endpoint_shared::{
        encode as endpoint_shared_layout,
        fact::{EndpointRole, EndpointSharedFact},
    };
    use topo::protocol::auth::local_history_node_secret::project as coverage;
    use topo::protocol::auth::local_key_secret::{encode as auth_layout, fact::LocalKeySecretFact};
    use topo::protocol::content::message::fact::{ContentMessageFact, MessageCiphertext};
    use topo::protocol::content::message::{author, encode, project};
    use topo::protocol::content::message_deletion::encode as deletion_layout;
    use topo::protocol::content::message_deletion::fact::ContentMessageDeletionFact;
    use topo::protocol::registry::read_models;

    use topo::protocol::auth::user::{encode as user_layout, fact::UserFact};

    const CONTENT_SIGNING_KEY: [u8; 32] = [7; 32];
    const ENDPOINT_AUTHORITY_KEY: [u8; 32] = [13; 32];

    macro_rules! put_row {
        ($output:expr, $table:expr) => {
            $output
                .effects
                .row_mutations
                .iter()
                .find_map(|mutation| match mutation {
                    RowMutation::InsertValues(row) if row.table == $table => Some(row.clone()),
                    _ => None,
                })
        };
    }

    macro_rules! put_delete {
        ($output:expr, $table:expr) => {
            $output
                .effects
                .row_mutations
                .iter()
                .find_map(|mutation| match mutation {
                    RowMutation::DeleteWhere(delete) if delete.table == $table => {
                        Some(delete.clone())
                    }
                    _ => None,
                })
        };
    }

    #[test]
    fn content_message_projector_materializes_after_signer_author_and_secret_context() {
        let author_fact = user_fact([9; 32]);
        let (message, fact, key) = message_fact(author_fact.id, "hello from content message");
        let signer_fact = signer_fact(&message);
        let secret_fact = secret_fact(&message, key);
        let signature_fact = signature_fact(&message, &fact);

        let output = project::ContentMessageProjector::new()
            .project(
                &fact,
                &ProjectionContext::from_matches(vec![
                    signature_match(&fact, &message, &signature_fact),
                    signer_match(&fact, &message, &signer_fact),
                    author_match(&fact, &message, &author_fact),
                    secret_match(&fact, &message, &secret_fact),
                ]),
            )
            .expect("project content message");

        assert_eq!(output.needs.len(), 2);
        assert!(output.needs.iter().any(|need| need.role == "fact_purged"));
        assert!(output
            .needs
            .iter()
            .any(|need| need.role == "content_retention_floor"));
        assert!(!output.needs.iter().any(|need| need.role == "auth_user"));
        assert!(!output
            .needs
            .iter()
            .any(|need| need.role == "signature_proof"));
        assert!(!output
            .needs
            .iter()
            .any(|need| need.role == "content_signer"));
        assert!(!output
            .needs
            .iter()
            .any(|need| need.role == "secret_coverage"));
        assert_eq!(output.offers.len(), 1);
        assert!(output
            .offers
            .iter()
            .any(|offer| offer.role == "content_message"));
        assert_eq!(output.effects.intents.len(), 1);
        assert_eq!(
            output.effects.intents[0].kind.as_str(),
            "share_fact_with_sync"
        );
        let share = topo::protocol::sync::share_fact_with_sync::decode_share_fact_with_sync(
            &output.effects.intents[0],
        )
        .expect("decode share intent");
        assert_eq!(share.owner_fact_id, fact.id);
        assert_eq!(share.workspace_id, message.workspace_id);
        let mut expected_context_have = vec![signature_fact.id, signer_fact.id, author_fact.id];
        expected_context_have.sort();
        assert_eq!(
            share.context_have, expected_context_have,
            "sync keeps validated dependency facts without keeping live validation needs"
        );
        assert_eq!(output.effects.row_mutations.len(), 2);

        let row = put_row!(output, read_models::CONTENT_MESSAGE_ROWS).expect("content message row");
        assert_eq!(
            row.values[0],
            topo::core::intents::Value::Bytes(message.workspace_id.to_vec())
        );
        assert_eq!(
            row.values[1],
            topo::core::intents::Value::Bytes(fact.id.to_vec())
        );
        assert_eq!(
            row.values[2],
            topo::core::intents::Value::Bytes(message.author_user_id.to_vec())
        );
        assert_eq!(
            row.values[4],
            topo::core::intents::Value::Bytes(message.signer_id.to_vec())
        );
        assert_eq!(
            row.values[5],
            topo::core::intents::Value::Bytes(message.frontier_id.to_vec())
        );

        let opened = put_row!(output, read_models::OPENED_MESSAGE_ROWS).expect("opened row");
        assert_eq!(
            opened.values[1],
            topo::core::intents::Value::Bytes(fact.id.to_vec())
        );
        assert_eq!(
            opened.values[5],
            topo::core::intents::Value::Bytes(b"hello from content message".to_vec())
        );
    }

    #[test]
    fn content_message_projector_waits_without_materializing_before_context() {
        let author_fact = user_fact([9; 32]);
        let (_message, fact, _key) = message_fact(author_fact.id, "hidden until key context");

        let output = project::ContentMessageProjector::new()
            .project(&fact, &ProjectionContext::default())
            .expect("project content message");

        assert_eq!(output.offers.len(), 0);
        assert_eq!(output.needs.len(), 6);
        assert_eq!(output.effects.intents.len(), 0);
        assert!(put_row!(output, read_models::CONTENT_MESSAGE_ROWS).is_none());
        assert!(output.needs.iter().any(|need| need.role == "auth_user"));
        assert!(output
            .needs
            .iter()
            .any(|need| need.role == "signature_proof"));
        assert!(output
            .needs
            .iter()
            .any(|need| need.role == "content_signer"));
        assert!(output.needs.iter().any(|need| need.role == "fact_purged"));
        assert!(output
            .needs
            .iter()
            .any(|need| need.role == "content_retention_floor"));
        assert!(output
            .needs
            .iter()
            .any(|need| need.role == "secret_coverage"));
    }

    #[test]
    fn content_message_projector_waits_without_materializing_before_secret_context() {
        let author_fact = user_fact([9; 32]);
        let (message, fact, _key) = message_fact(author_fact.id, "hidden until key context");
        let signer_fact = signer_fact(&message);
        let signature_fact = signature_fact(&message, &fact);

        let output = project::ContentMessageProjector::new()
            .project(
                &fact,
                &ProjectionContext::from_matches(vec![
                    signature_match(&fact, &message, &signature_fact),
                    signer_match(&fact, &message, &signer_fact),
                    author_match(&fact, &message, &author_fact),
                ]),
            )
            .expect("project content message");

        assert_eq!(output.needs.len(), 6);
        assert!(output.offers.is_empty());
        assert_eq!(output.effects.intents.len(), 0);
        assert!(put_row!(output, read_models::CONTENT_MESSAGE_ROWS).is_none());
        assert!(put_row!(output, read_models::OPENED_MESSAGE_ROWS).is_none());
    }

    #[test]
    fn content_message_keeps_deletion_watch_and_deletes_when_matched() {
        let author_fact = user_fact([9; 32]);
        let (message, fact, _key) = message_fact(author_fact.id, "delete me");
        let signer_fact = signer_fact(&message);
        let signature_fact = signature_fact(&message, &fact);
        let deletion = ContentMessageDeletionFact {
            workspace_id: message.workspace_id,
            created_at_ms: message.created_at_ms + 1,
            target_message_id: fact.id,
            target_frontier_id: message.frontier_id,
            target_minute: message.minute,
            author_user_id: message.author_user_id,
            signer_id: message.signer_id,
            signer_public_key: message.signer_public_key,
        };
        let deletion_fact = Fact::new(
            crate::protocol::auth::workspace::scope(deletion.workspace_id),
            deletion.created_at_ms,
            deletion_layout::encode_fact(&deletion).expect("encode deletion"),
        );

        let output = project::ContentMessageProjector::new()
            .project(
                &fact,
                &ProjectionContext::from_matches(vec![
                    signature_match(&fact, &message, &signature_fact),
                    signer_match(&fact, &message, &signer_fact),
                    author_match(&fact, &message, &author_fact),
                    deletion_match(&fact, &message, &deletion_fact),
                ]),
            )
            .expect("deletion wakes message");

        assert!(put_delete!(output, read_models::CONTENT_MESSAGE_ROWS).is_some());
        assert!(put_delete!(output, read_models::OPENED_MESSAGE_ROWS).is_some());
        assert!(put_row!(output, read_models::MESSAGE_TOMBSTONE_ROWS).is_some());
        assert_eq!(output.effects.purged_facts, vec![fact.id]);
    }

    #[test]
    fn content_message_rejects_delete_offer_from_non_author_claim() {
        let author_fact = user_fact([9; 32]);
        let (message, fact, _key) = message_fact(author_fact.id, "do not delete me");
        let signer_fact = signer_fact(&message);
        let signature_fact = signature_fact(&message, &fact);
        let deletion = ContentMessageDeletionFact {
            workspace_id: message.workspace_id,
            created_at_ms: message.created_at_ms + 1,
            target_message_id: fact.id,
            target_frontier_id: message.frontier_id,
            target_minute: message.minute,
            author_user_id: [44; 32],
            signer_id: message.signer_id,
            signer_public_key: message.signer_public_key,
        };
        let deletion_fact = Fact::new(
            crate::protocol::auth::workspace::scope(deletion.workspace_id),
            deletion.created_at_ms,
            deletion_layout::encode_fact(&deletion).expect("encode deletion"),
        );

        let err = project::ContentMessageProjector::new()
            .project(
                &fact,
                &ProjectionContext::from_matches(vec![
                    signature_match(&fact, &message, &signature_fact),
                    signer_match(&fact, &message, &signer_fact),
                    author_match(&fact, &message, &author_fact),
                    deletion_match(&fact, &message, &deletion_fact),
                ]),
            )
            .expect_err("non-author delete offer must not purge target");

        assert!(err.contains("author does not match"), "{err}");
    }

    #[test]
    fn expired_content_message_retracts_before_context_wait() {
        let author_fact = user_fact([9; 32]);
        let (mut message, _fact, _key) = message_fact(author_fact.id, "already expired");
        message.expires_at_minute = message.minute + 1;
        let fact = Fact::new(
            crate::protocol::auth::workspace::scope(message.workspace_id),
            message.created_at_ms,
            encode::encode_fact(&message).expect("encode content message"),
        );
        let signer_fact = signer_fact(&message);
        let signature_fact = signature_fact(&message, &fact);
        let context = ProjectionContext::from_matches(vec![
            signature_match(&fact, &message, &signature_fact),
            signer_match(&fact, &message, &signer_fact),
            author_match(&fact, &message, &author_fact),
        ])
        .with_time_ranges(vec![TimeRange {
            timeline: topo::protocol::content::message::expiration_timeline(),
            start_exclusive: None,
            end_inclusive: message.expires_at_minute,
        }]);

        let output = project::ContentMessageProjector::new()
            .project(&fact, &context)
            .expect("project expired content message");

        assert!(output.needs.is_empty());
        assert!(output.offers.is_empty());
        assert_eq!(output.effects.intents.len(), 1);
        let share = topo::protocol::sync::share_fact_with_sync::decode_share_fact_with_sync(
            &output.effects.intents[0],
        )
        .expect("decode sync retraction");
        assert_eq!(
            share.state,
            topo::protocol::sync::share_fact_with_sync::SyncShareState::Retract
        );
        assert_eq!(output.effects.purged_facts, vec![fact.id]);
    }

    #[test]
    fn content_message_row_builders_use_registry_typed_schemas() {
        let fact = ContentMessageFact {
            workspace_id: [1; 32],
            created_at_ms: 60_000,
            author_user_id: [2; 32],
            signer_id: [3; 32],
            signer_public_key: [7; 32],
            frontier_id: [4; 32],
            local_history_node_secret_id: [5; 32],
            expires_at_minute: u64::MAX,
            retention_policy_id: [6; 32],
            minute: 1,
            nonce: [8; crate::protocol::content::message::fact::NONCE_BYTES],
            ciphertext: MessageCiphertext::new(b"sealed").expect("ciphertext"),
        };

        let row = super::content_message_row([9; 32], &fact);
        assert_eq!(row.table, read_models::CONTENT_MESSAGE_ROWS);
        assert_eq!(row.columns, read_models::CONTENT_MESSAGES.columns);
        assert_eq!(
            row.values[0],
            topo::core::intents::Value::Bytes(vec![1; 32])
        );
        assert_eq!(
            row.values[1],
            topo::core::intents::Value::Bytes(vec![9; 32])
        );
        assert_eq!(
            row.values[2],
            topo::core::intents::Value::Bytes(vec![2; 32])
        );
        assert_eq!(
            row.values[4],
            topo::core::intents::Value::Bytes(vec![3; 32])
        );
        assert_eq!(
            row.values[5],
            topo::core::intents::Value::Bytes(vec![4; 32])
        );
        assert_eq!(row.values[7], topo::core::intents::Value::Bool(false));

        let opened = super::opened_message_row(super::OpenedMessageRow {
            workspace_id: [1; 32],
            message_id: [2; 32],
            created_at_ms: 60_000,
            author_user_id: [3; 32],
            signer_id: [4; 32],
            text: "hello".to_string(),
        });
        assert_eq!(opened.table, read_models::OPENED_MESSAGE_ROWS);
        assert_eq!(opened.columns, read_models::OPENED_MESSAGES.columns);
        assert_eq!(
            opened.values[5],
            topo::core::intents::Value::Bytes(b"hello".to_vec())
        );

        let tombstone = super::message_tombstone_row([1; 32], [2; 32], [3; 32], 120_000);
        assert_eq!(tombstone.table, read_models::MESSAGE_TOMBSTONE_ROWS);
        assert_eq!(tombstone.columns, read_models::MESSAGE_TOMBSTONES.columns);
        assert_eq!(
            tombstone.values[2],
            topo::core::intents::Value::Bytes(vec![3; 32])
        );
        assert_eq!(tombstone.values[3], topo::core::intents::Value::U64(2));
    }

    #[test]
    fn content_purge_coordinate_supports_exact_and_range_offers() {
        let scope = FactScope::Local;
        let owner = [1; 32];
        let frontier_id = [7; 32];
        let message_id = [9; 32];
        let message_need = topo::core::project_fact::fact_purged_need(
            owner,
            scope.clone(),
            project::fact_purged_key(frontier_id, 10, message_id),
        );
        let exact_offer = topo::core::project_fact::fact_purged_offer(
            [2; 32],
            scope.clone(),
            project::fact_purged_key(frontier_id, 10, message_id),
        );
        let (range_start, range_end) = project::fact_purged_minute_range_keys(frontier_id, 9, 11);
        let range_offer = topo::core::project_fact::fact_purged_range_offer(
            [3; 32],
            scope.clone(),
            range_start,
            range_end,
        );
        let other_frontier_need = topo::core::project_fact::fact_purged_need(
            owner,
            scope,
            project::fact_purged_key([8; 32], 10, message_id),
        );

        assert_eq!(message_need.start_key, exact_offer.start_key);
        assert_eq!(message_need.end_key, exact_offer.end_key);
        assert!(range_offer.start_key <= message_need.start_key);
        assert!(range_offer.end_key >= message_need.end_key);
        assert!(
            range_offer.end_key < other_frontier_need.start_key
                || range_offer.start_key > other_frontier_need.end_key
        );
    }

    #[test]
    fn content_message_projector_rejects_malformed_fact_bytes() {
        let fact = Fact::new(FactScope::Global, 0, vec![0; 8]);
        let err = project::ContentMessageProjector::new()
            .project(&fact, &ProjectionContext::default())
            .expect_err("malformed bytes must fail projection");
        assert!(
            err.to_lowercase().contains("message") || err.to_lowercase().contains("length"),
            "{err}"
        );
    }

    fn user_fact(workspace_id: [u8; 32]) -> Fact {
        let signing_key = [21; 32];
        let user = UserFact {
            created_at_ms: 12_000,
            workspace_id,
            public_key: [22; 32],
            username: topo::protocol::auth::user::fact::Username::new("alice").expect("username"),
            signer_id: [23; 32],
            signer_public_key: crypto::ed25519_public_key(&signing_key),
        };
        Fact::new(
            FactScope::Global,
            user.created_at_ms,
            user_layout::encode_fact(&user).expect("encode user"),
        )
    }

    fn message_fact(author_user_id: [u8; 32], text: &str) -> (ContentMessageFact, Fact, [u8; 32]) {
        let key = [42; 32];
        let workspace_id = [9; 32];
        let frontier_id = [3; 32];
        let minute = 3;
        let nonce = [7; crate::protocol::content::message::fact::NONCE_BYTES];
        let plaintext = author::pad_plaintext(text.as_bytes()).expect("pad plaintext");
        let ciphertext = crypto::xchacha20poly1305_encrypt(
            &key,
            &encode::associated_data(workspace_id, frontier_id, minute),
            &nonce,
            &plaintext,
        )
        .expect("encrypt message text");
        let message = ContentMessageFact {
            workspace_id,
            author_user_id,
            created_at_ms: 180_000,
            signer_id: [8; 32],
            signer_public_key: crypto::ed25519_public_key(&CONTENT_SIGNING_KEY),
            frontier_id,
            local_history_node_secret_id: [0; 32],
            expires_at_minute: u64::MAX,
            retention_policy_id: [0; 32],
            minute,
            nonce,
            ciphertext: MessageCiphertext::new(&ciphertext).expect("message ciphertext"),
        };
        let fact = Fact::new(
            crate::protocol::auth::workspace::scope(message.workspace_id),
            message.created_at_ms,
            encode::encode_fact(&message).expect("encode content message"),
        );
        (message, fact, key)
    }

    fn signature_fact(message: &ContentMessageFact, fact: &Fact) -> Fact {
        crate::protocol::auth::signature::author::create_signature(
            message.workspace_id,
            fact.id,
            &CONTENT_SIGNING_KEY,
            message.created_at_ms,
        )
        .expect("signature fact")
    }

    fn signer_fact(message: &ContentMessageFact) -> Fact {
        let signer = EndpointSharedFact {
            created_at_ms: message.created_at_ms,
            workspace_id: message.workspace_id,
            user_authority_fact_id: message.author_user_id,
            endpoint_id: message.signer_id,
            signing_public_key: crypto::ed25519_public_key(&CONTENT_SIGNING_KEY),
            endpoint_role: EndpointRole::Device,
            device_name: topo::protocol::auth::endpoint_shared::fact::EndpointDeviceName::new(
                "alice-device",
            )
            .expect("device name"),
            signer_id: [1; 32],
            signer_public_key: crypto::ed25519_public_key(&ENDPOINT_AUTHORITY_KEY),
        };
        Fact::new(
            FactScope::Global,
            message.created_at_ms,
            endpoint_shared_layout::encode_fact(&signer).expect("encode endpoint shared"),
        )
    }

    fn secret_fact(message: &ContentMessageFact, key: [u8; 32]) -> Fact {
        let secret = LocalKeySecretFact {
            workspace_id: message.workspace_id,
            frontier_id: message.frontier_id,
            owner_endpoint_id: message.signer_id,
            created_at_ms: message.created_at_ms,
            key_secret: key,
        };
        Fact::new(
            FactScope::Local,
            message.created_at_ms,
            auth_layout::encode_local_key_secret(&secret).expect("encode secret"),
        )
    }

    fn signer_match(
        message_fact: &Fact,
        message: &ContentMessageFact,
        signer: &Fact,
    ) -> MatchedContext {
        let scope = crate::protocol::auth::workspace::scope(message.workspace_id);
        MatchedContext {
            need: crate::core::context::ContextNeed::range(
                message_fact.id,
                "content_signer",
                scope.clone(),
                message.signer_id,
                message.signer_id,
            ),
            offer: crate::core::context::ContextOffer::range(
                signer.id,
                "content_signer",
                scope,
                message.signer_id,
                message.signer_id,
            ),
            payload: signer.clone(),
        }
    }

    fn signature_match(
        message_fact: &Fact,
        message: &ContentMessageFact,
        signature: &Fact,
    ) -> MatchedContext {
        let scope = crate::protocol::auth::workspace::scope(message.workspace_id);
        MatchedContext {
            need: crate::protocol::auth::signature::project::signature_proof_need(
                message_fact.id,
                scope.clone(),
                message_fact.id,
                message.signer_public_key,
            )
            .expect("signature need"),
            offer: crate::protocol::auth::signature::project::signature_proof_offer(
                signature.id,
                scope,
                message_fact.id,
                message.signer_public_key,
            )
            .expect("signature offer"),
            payload: signature.clone(),
        }
    }

    fn author_match(
        message_fact: &Fact,
        message: &ContentMessageFact,
        author: &Fact,
    ) -> MatchedContext {
        MatchedContext {
            need: crate::core::context::ContextNeed::range(
                message_fact.id,
                "auth_user",
                crate::core::facts::FactScope::Global,
                message.author_user_id,
                message.author_user_id,
            ),
            offer: crate::core::context::ContextOffer::range(
                author.id,
                "auth_user",
                crate::core::facts::FactScope::Global,
                author.id,
                author.id,
            ),
            payload: author.clone(),
        }
    }

    fn secret_match(
        message_fact: &Fact,
        message: &ContentMessageFact,
        secret: &Fact,
    ) -> MatchedContext {
        let scope = crate::protocol::auth::workspace::scope(message.workspace_id);
        MatchedContext {
            need: coverage::secret_need(
                message_fact.id,
                scope.clone(),
                message.workspace_id,
                message.frontier_id,
                message.minute,
                message_fact.id,
            ),
            offer: coverage::secret_offer(
                secret.id,
                scope,
                message.workspace_id,
                message.frontier_id,
                0,
                u64::MAX,
                0,
                [0; 32],
            ),
            payload: secret.clone(),
        }
    }

    fn deletion_match(
        message_fact: &Fact,
        message: &ContentMessageFact,
        deletion_fact: &Fact,
    ) -> MatchedContext {
        let scope = crate::protocol::auth::workspace::scope(message.workspace_id);
        MatchedContext {
            need: crate::core::project_fact::fact_purged_need(
                message_fact.id,
                scope.clone(),
                project::fact_purged_key(message.frontier_id, message.minute, message_fact.id),
            ),
            offer: crate::core::project_fact::fact_purged_offer(
                deletion_fact.id,
                scope,
                project::fact_purged_key(message.frontier_id, message.minute, message_fact.id),
            ),
            payload: deletion_fact.clone(),
        }
    }
}
