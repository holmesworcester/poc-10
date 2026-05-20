//! Semantic content-message projector.
//!
//! POLICY. A content_message is admitted iff:
//!   1. STRUCTURAL. The fact is workspace-scoped and contains a raw or signed
//!      message payload with encrypted text.
//!   2. CONTEXT. The projector records sync liveness immediately, then waits
//!      for signer, author, deletion, secret, and time context. Once signer
//!      and author validate, it publishes metadata context for deletion. It
//!      does not publish opened message context or rows until the encrypted
//!      text opens.
//!   3. MATERIALIZE. Once opened, the projector writes read-model rows and
//!      offers semantic message context.

use crate::core::context::ContextNeed;
use crate::core::crypto;
use crate::core::facts::{Fact, FactId};
use crate::core::intents::{AtomicIntent, TableDelete};
use crate::core::projectors::{
    project_typed, ProjectionContext, ProjectionOutput, Projector, TimeWake, TypedProjector,
};
use crate::protocol::facts::content::message_deletion;
use crate::protocol::facts::encryption;
use crate::protocol::facts::identity;
use crate::protocol::facts::identity::user;
use crate::protocol::intents::content::purge_deleted_message::{
    self, PurgeDeletedMessage, PURGE_REASON_AUTHOR_DELETION, PURGE_TARGET_MESSAGE,
};
use crate::protocol::intents::content::purge_expired_message::{self, PurgeExpiredMessage};
use crate::protocol::intents::sync::share_fact_with_workspace::share_fact_with_workspace_intent_for_fact;
use crate::protocol::matchers;

use super::authority::{self, DecodedPayload};
use super::rows::{
    content_message_key, content_message_row, message_tombstone_row, opened_message_row,
    OpenedMessageRow, CONTENT_MESSAGE_ROWS, OPENED_MESSAGE_ROWS,
};

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
        project_typed::<super::Codec, _>(self, fact, context)
    }
}

impl TypedProjector<super::Codec> for ContentMessageProjector {
    fn project_typed(
        &self,
        fact: &Fact,
        decoded: authority::DecodedFact<super::fact::ContentMessageFact>,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        // 1. Structural.
        let authority::DecodedFact {
            payload: message,
            envelope,
            ..
        } = decoded;
        let scope = matchers::workspace_scope(message.workspace_id);
        require_fact_scope(fact, &scope)?;
        if let Some(envelope) = envelope.as_ref() {
            if envelope.signer_id != message.signer_id {
                return Err("content message signer does not match signed envelope".to_string());
            }
        }

        // 2. Context and deletion gates.
        let signer_need = matchers::signer_need(fact.id, scope.clone(), message.signer_id);
        let deletion_need =
            matchers::deletion_need(fact.id, scope.clone(), fact.id, message.author_user_id);
        let author_need = crate::protocol::matchers::exact_need(
            fact.id,
            crate::protocol::matchers::user_role(),
            message.author_user_id,
        );
        let secret_need = matchers::secret_need(
            fact.id,
            scope.clone(),
            message.workspace_id,
            message.frontier_id,
            message.minute,
            message.leaf_id,
        );

        let base_output = base_wait_output(
            fact,
            &message,
            [
                signer_need.clone(),
                deletion_need.clone(),
                author_need.clone(),
                secret_need.clone(),
            ],
        );
        let Some(signer_payload) = context.payload_for(&signer_need) else {
            return Ok(base_output);
        };
        validate_signer_context(signer_payload, &signer_need, &message, envelope.as_ref())?;
        let Some(author) = context_payload(context, &author_need, "message author")? else {
            return Ok(base_output);
        };
        validate_author_user(author, message.workspace_id, message.author_user_id)?;
        authority::verify_envelope(envelope.as_ref(), "message")?;

        let metadata_output = base_output.offer(matchers::message_meta_offer(
            fact.id,
            scope.clone(),
            fact.id,
        ));
        if let Some(now_minute) = expiry_minute_reached(context, &message) {
            return Ok(expired_output(fact.id, &message, now_minute));
        }
        if let Some(deletion) = context_payload(context, &deletion_need, "message deletion")? {
            validate_message_deletion(
                deletion,
                message.workspace_id,
                fact.id,
                message.author_user_id,
            )?;
            return Ok(author_deletion_output(fact.id, &message, deletion.id));
        }
        let Some(secret_payload) = matched_secret_payload(context, &secret_need)? else {
            return Ok(metadata_output);
        };
        let text = decrypt_text(&message, secret_payload)?;

        // 3. Materialize.
        Ok(metadata_output
            .offer(matchers::message_offer(fact.id, scope, fact.id))
            .intent(AtomicIntent::PutRow(content_message_row(fact.id, &message)).into_intent())
            .intent(
                AtomicIntent::PutRow(opened_message_row(OpenedMessageRow {
                    workspace_id: message.workspace_id,
                    message_id: fact.id,
                    created_at_ms: message.created_at_ms,
                    author_user_id: message.author_user_id,
                    signer_id: message.signer_id,
                    text,
                }))
                .into_intent(),
            ))
    }
}

fn base_wait_output(
    fact: &Fact,
    message: &super::fact::ContentMessageFact,
    needs: impl IntoIterator<Item = ContextNeed>,
) -> ProjectionOutput {
    with_expiry_wake(
        needs
            .into_iter()
            .fold(ProjectionOutput::new(), |output, need| output.need(need))
            .intent(share_fact_with_workspace_intent_for_fact(
                message.workspace_id,
                fact,
            )),
        fact.id,
        message,
    )
}

fn context_payload<'a>(
    context: &'a ProjectionContext,
    need: &crate::core::context::ContextNeed,
    label: &str,
) -> Result<Option<&'a Fact>, String> {
    authority::context_payload(context, need, label)
}

fn validate_signer_context(
    payload: &Fact,
    _need: &ContextNeed,
    message: &super::fact::ContentMessageFact,
    envelope: Option<&identity::signed_fact::fact::SignedFactEnvelope>,
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
    if envelope.is_some_and(|envelope| endpoint.signing_public_key != envelope.signer_public_key) {
        return Err(
            "content message signer context public key does not match signed envelope".to_string(),
        );
    }
    Ok(())
}

fn endpoint_shared_signer(
    payload: &Fact,
) -> Option<identity::endpoint_shared::fact::EndpointSharedFact> {
    identity::endpoint_shared::decode_raw_or_signed_fact(payload).ok()
}

fn validate_author_user(
    payload: &Fact,
    workspace_id: crate::core::facts::FactId,
    author_user_id: crate::core::facts::FactId,
) -> Result<(), String> {
    if payload.id != author_user_id {
        return Err("message author context payload id mismatch".to_string());
    }
    let author_payload = maybe_signed_payload(payload, user::TYPE_USER, "message author context")?;
    let author =
        crate::protocol::facts::identity::user::decode_fact_payload(&author_payload.payload)
            .map_err(|_| "message author context is not an identity user".to_string())?;
    if author.workspace_id != workspace_id {
        return Err("message author workspace does not match message".to_string());
    }
    Ok(())
}

fn validate_message_deletion(
    payload: &Fact,
    workspace_id: crate::core::facts::FactId,
    target_message_id: crate::core::facts::FactId,
    author_user_id: crate::core::facts::FactId,
) -> Result<(), String> {
    if let Ok(deletion_payload) = maybe_signed_payload(
        payload,
        message_deletion::TYPE_CONTENT_MESSAGE_DELETION,
        "message deletion context",
    ) {
        let deletion =
            message_deletion::decode_fact_payload(&deletion_payload.payload).map_err(|_| {
                "message deletion context is not a content message deletion".to_string()
            })?;
        if deletion.workspace_id != workspace_id {
            return Err("message deletion workspace does not match message".to_string());
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
        if !matchers::secret_offer_matches_need(need, offer) {
            return Err("content message secret context offer does not match need".to_string());
        }
        if encryption::layout::decode_local_key_secret(payload.body()).is_ok()
            || encryption::layout::decode_local_history_node_secret(payload.body()).is_ok()
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
    let key = if let Ok(secret) = encryption::layout::decode_local_key_secret(secret_payload.body())
    {
        if secret.workspace_id != message.workspace_id || secret.frontier_id != message.frontier_id
        {
            return Err("content message root secret does not match message".to_string());
        }
        secret.key_secret
    } else {
        let node = encryption::layout::decode_local_history_node_secret(secret_payload.body())
            .map_err(|_| "content message secret context is not local key material".to_string())?;
        if node.workspace_id != message.workspace_id || node.frontier_id != message.frontier_id {
            return Err("content message history secret does not match message".to_string());
        }
        node.node_secret
    };
    let plaintext = crypto::xchacha20poly1305_decrypt(
        &key,
        &crate::protocol::facts::content::message::create::associated_data(
            message.workspace_id,
            message.frontier_id,
            message.minute,
        ),
        &message.nonce,
        &message.ciphertext,
    )?;
    crate::protocol::facts::content::message::create::recover_text(&plaintext)
}

fn expiry_minute_reached(
    context: &ProjectionContext,
    message: &super::fact::ContentMessageFact,
) -> Option<u64> {
    if message.expires_at_minute == u64::MAX {
        return None;
    }
    context.time_reached(
        &crate::protocol::facts::content::message::expiration_timeline(),
        message.expires_at_minute,
    )
}

fn with_expiry_wake(
    output: ProjectionOutput,
    owner: FactId,
    message: &super::fact::ContentMessageFact,
) -> ProjectionOutput {
    if message.expires_at_minute == u64::MAX {
        return output;
    }
    output.time_wake(TimeWake {
        owner,
        timeline: crate::protocol::facts::content::message::expiration_timeline(),
        at: message.expires_at_minute,
    })
}

fn expired_output(
    message_id: FactId,
    message: &super::fact::ContentMessageFact,
    now_minute: u64,
) -> ProjectionOutput {
    let row_key = content_message_key(message.workspace_id, message_id);
    ProjectionOutput::new()
        .intent(
            AtomicIntent::PutRow(message_tombstone_row(
                message.workspace_id,
                message_id,
                message.author_user_id,
                message.created_at_ms,
            ))
            .into_intent(),
        )
        .intent(
            AtomicIntent::DeleteRow(TableDelete {
                table: CONTENT_MESSAGE_ROWS,
                key: content_message_key(message.workspace_id, message_id),
            })
            .into_intent(),
        )
        .intent(
            AtomicIntent::DeleteRow(TableDelete {
                table: OPENED_MESSAGE_ROWS,
                key: row_key,
            })
            .into_intent(),
        )
        .intent(purge_expired_message::purge_expired_message_intent(
            PurgeExpiredMessage {
                workspace_id: message.workspace_id,
                target_id: message_id,
                now_minute,
            },
        ))
}

fn author_deletion_output(
    message_id: FactId,
    message: &super::fact::ContentMessageFact,
    reason_fact_id: FactId,
) -> ProjectionOutput {
    let row_key = content_message_key(message.workspace_id, message_id);
    ProjectionOutput::new()
        .intent(
            AtomicIntent::PutRow(message_tombstone_row(
                message.workspace_id,
                message_id,
                message.author_user_id,
                message.created_at_ms,
            ))
            .into_intent(),
        )
        .intent(
            AtomicIntent::DeleteRow(TableDelete {
                table: CONTENT_MESSAGE_ROWS,
                key: content_message_key(message.workspace_id, message_id),
            })
            .into_intent(),
        )
        .intent(
            AtomicIntent::DeleteRow(TableDelete {
                table: OPENED_MESSAGE_ROWS,
                key: row_key,
            })
            .into_intent(),
        )
        .intent(purge_deleted_message::purge_deleted_message_intent(
            PurgeDeletedMessage {
                workspace_id: message.workspace_id,
                target_kind: PURGE_TARGET_MESSAGE,
                target_id: message_id,
                reason_kind: PURGE_REASON_AUTHOR_DELETION,
                reason_fact_id,
            },
        ))
}

fn maybe_signed_payload(
    payload: &Fact,
    expected_type: u8,
    label: &str,
) -> Result<DecodedPayload, String> {
    if payload.bytes.first().copied() == Some(identity::signed_fact::TYPE_SIGNED_FACT) {
        authority::decode_raw_or_signed(payload, expected_type, label)
    } else {
        Ok(DecodedPayload {
            payload: payload.bytes.clone(),
            signer: None,
            envelope: None,
        })
    }
}

fn require_fact_scope(fact: &Fact, expected: &crate::core::facts::FactScope) -> Result<(), String> {
    if &fact.scope == expected {
        Ok(())
    } else {
        Err("content message fact scope does not match body workspace".to_string())
    }
}

#[cfg(test)]
mod projector_tests {
    use crate as topo;

    use topo::core::crypto;
    use topo::core::facts::{Fact, FactScope};
    use topo::core::intents::AtomicIntent;
    use topo::core::projectors::{MatchedContext, ProjectionContext, Projector};
    use topo::protocol::facts::content::message::fact::ContentMessageFact;
    use topo::protocol::facts::content::message::{layout, project, rows};
    use topo::protocol::facts::content::message_deletion::fact::ContentMessageDeletionFact;
    use topo::protocol::facts::content::message_deletion::layout as deletion_layout;
    use topo::protocol::facts::encryption::{
        fact::LocalKeySecretFact, layout as encryption_layout,
    };
    use topo::protocol::facts::identity::endpoint_shared::{
        fact::{EndpointRole, EndpointSharedFact},
        layout as endpoint_shared_layout,
    };
    use topo::protocol::matchers as message_context;

    use topo::protocol::facts::identity::user::{fact::UserFact, layout as user_layout};

    macro_rules! put_row {
        ($output:expr, $table:expr) => {
            $output.intents.iter().find_map(|intent| {
                let atomic = AtomicIntent::from_intent(intent, &[$table]).ok()?;
                match atomic {
                    AtomicIntent::PutRow(row) => Some(row),
                    AtomicIntent::DeleteRow(_) => None,
                }
            })
        };
    }

    macro_rules! put_delete {
        ($output:expr, $table:expr) => {
            $output.intents.iter().find_map(|intent| {
                let atomic = AtomicIntent::from_intent(intent, &[$table]).ok()?;
                match atomic {
                    AtomicIntent::DeleteRow(delete) => Some(delete),
                    AtomicIntent::PutRow(_) => None,
                }
            })
        };
    }

    #[test]
    fn content_message_projector_materializes_after_signer_author_and_secret_context() {
        let author_fact = user_fact([9; 32]);
        let (message, fact, key) = message_fact(author_fact.id, "hello from content message");
        let signer_fact = signer_fact(&message);
        let secret_fact = secret_fact(&message, key);

        let output = project::ContentMessageProjector::new()
            .project(
                &fact,
                &ProjectionContext::from_matches(vec![
                    signer_match(&fact, &message, &signer_fact),
                    author_match(&fact, &message, &author_fact),
                    secret_match(&fact, &message, &secret_fact),
                ]),
            )
            .expect("project content message");

        assert_eq!(output.needs.len(), 4);
        assert_eq!(output.offers.len(), 2);
        assert!(output
            .offers
            .iter()
            .any(|offer| offer.role == message_context::message_meta_role()));
        assert!(output
            .offers
            .iter()
            .any(|offer| offer.role == message_context::message_role()));
        assert_eq!(output.intents.len(), 3);

        let row = put_row!(output, rows::CONTENT_MESSAGE_ROWS).expect("content message row");
        let row = rows::decode_content_message_row(&row.key, &row.value).expect("decode row");
        assert_eq!(row.workspace_id, message.workspace_id);
        assert_eq!(row.message_id, fact.id);
        assert_eq!(row.author_user_id, message.author_user_id);
        assert_eq!(row.signer_id, message.signer_id);
        assert_eq!(row.frontier_id, message.frontier_id);

        let opened = put_row!(output, rows::OPENED_MESSAGE_ROWS).expect("opened row");
        let opened =
            rows::decode_opened_message_row(&opened.key, &opened.value).expect("decode opened row");
        assert_eq!(opened.message_id, fact.id);
        assert_eq!(opened.text, "hello from content message");
    }

    #[test]
    fn content_message_projector_waits_without_materializing_before_context() {
        let author_fact = user_fact([9; 32]);
        let (_message, fact, _key) = message_fact(author_fact.id, "hidden until key context");

        let output = project::ContentMessageProjector::new()
            .project(&fact, &ProjectionContext::default())
            .expect("project content message");

        assert_eq!(output.offers.len(), 0);
        assert_eq!(output.needs.len(), 4);
        assert_eq!(output.intents.len(), 1);
        assert!(put_row!(output, rows::CONTENT_MESSAGE_ROWS).is_none());
        assert!(output
            .needs
            .iter()
            .any(|need| need.role == crate::protocol::matchers::user_role()));
        assert!(output
            .needs
            .iter()
            .any(|need| need.role == message_context::signer_role()));
        assert!(output
            .needs
            .iter()
            .any(|need| need.role == message_context::deletion_role()));
        assert!(output
            .needs
            .iter()
            .any(|need| need.role == message_context::secret_role()));
    }

    #[test]
    fn content_message_projector_publishes_metadata_before_secret_context() {
        let author_fact = user_fact([9; 32]);
        let (message, fact, _key) = message_fact(author_fact.id, "hidden until key context");
        let signer_fact = signer_fact(&message);

        let output = project::ContentMessageProjector::new()
            .project(
                &fact,
                &ProjectionContext::from_matches(vec![
                    signer_match(&fact, &message, &signer_fact),
                    author_match(&fact, &message, &author_fact),
                ]),
            )
            .expect("project content message");

        assert_eq!(output.needs.len(), 4);
        assert_eq!(output.offers.len(), 1);
        assert_eq!(output.offers[0].role, message_context::message_meta_role());
        assert_eq!(output.intents.len(), 1);
        assert!(put_row!(output, rows::CONTENT_MESSAGE_ROWS).is_none());
        assert!(put_row!(output, rows::OPENED_MESSAGE_ROWS).is_none());
    }

    #[test]
    fn content_message_keeps_deletion_watch_and_deletes_when_matched() {
        let author_fact = user_fact([9; 32]);
        let (message, fact, _key) = message_fact(author_fact.id, "delete me");
        let signer_fact = signer_fact(&message);
        let deletion = ContentMessageDeletionFact {
            workspace_id: message.workspace_id,
            created_at_ms: message.created_at_ms + 1,
            target_message_id: fact.id,
            author_user_id: message.author_user_id,
        };
        let deletion_fact = Fact::new(
            message_context::workspace_scope(deletion.workspace_id),
            deletion.created_at_ms,
            deletion_layout::encode_fact(&deletion).expect("encode deletion"),
        );

        let output = project::ContentMessageProjector::new()
            .project(
                &fact,
                &ProjectionContext::from_matches(vec![
                    signer_match(&fact, &message, &signer_fact),
                    author_match(&fact, &message, &author_fact),
                    deletion_match(&fact, &message, &deletion_fact),
                ]),
            )
            .expect("deletion wakes message");

        assert!(put_delete!(output, rows::CONTENT_MESSAGE_ROWS).is_some());
        assert!(put_delete!(output, rows::OPENED_MESSAGE_ROWS).is_some());
        assert!(put_row!(output, rows::MESSAGE_TOMBSTONE_ROWS).is_some());
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
        let user = UserFact {
            created_at_ms: 12_000,
            workspace_id,
            public_key: [22; 32],
            username: "alice".to_string(),
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
        let nonce = [7; crate::protocol::facts::content::message::fact::NONCE_BYTES];
        let plaintext =
            topo::protocol::facts::content::message::create::pad_plaintext(text.as_bytes())
                .expect("pad plaintext");
        let ciphertext = crypto::xchacha20poly1305_encrypt(
            &key,
            &topo::protocol::facts::content::message::create::associated_data(
                workspace_id,
                frontier_id,
                minute,
            ),
            &nonce,
            &plaintext,
        )
        .expect("encrypt message text");
        let message = ContentMessageFact {
            workspace_id,
            author_user_id,
            created_at_ms: 180_000,
            signer_id: [8; 32],
            frontier_id,
            local_history_node_secret_id: [0; 32],
            expires_at_minute: u64::MAX,
            disappearing_setting_id: [0; 32],
            minute,
            leaf_id: [4; 32],
            nonce,
            ciphertext,
        };
        let fact = Fact::new(
            message_context::workspace_scope(message.workspace_id),
            message.created_at_ms,
            layout::encode_fact(&message).expect("encode content message"),
        );
        (message, fact, key)
    }

    fn signer_fact(message: &ContentMessageFact) -> Fact {
        let signer = EndpointSharedFact {
            created_at_ms: message.created_at_ms,
            workspace_id: message.workspace_id,
            user_authority_fact_id: message.author_user_id,
            endpoint_id: message.signer_id,
            signing_public_key: [6; 32],
            endpoint_role: EndpointRole::Device,
            device_name: "alice-device".to_string(),
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
            encryption_layout::encode_local_key_secret(&secret).expect("encode secret"),
        )
    }

    fn signer_match(
        message_fact: &Fact,
        message: &ContentMessageFact,
        signer: &Fact,
    ) -> MatchedContext {
        let scope = message_context::workspace_scope(message.workspace_id);
        MatchedContext {
            need: message_context::signer_need(message_fact.id, scope.clone(), message.signer_id),
            offer: message_context::signer_offer(signer.id, scope, message.signer_id),
            payload: signer.clone(),
        }
    }

    fn author_match(
        message_fact: &Fact,
        message: &ContentMessageFact,
        author: &Fact,
    ) -> MatchedContext {
        MatchedContext {
            need: crate::protocol::matchers::exact_need(
                message_fact.id,
                crate::protocol::matchers::user_role(),
                message.author_user_id,
            ),
            offer: crate::protocol::matchers::exact_offer(
                author.id,
                crate::protocol::matchers::user_role(),
            ),
            payload: author.clone(),
        }
    }

    fn secret_match(
        message_fact: &Fact,
        message: &ContentMessageFact,
        secret: &Fact,
    ) -> MatchedContext {
        let scope = message_context::workspace_scope(message.workspace_id);
        MatchedContext {
            need: message_context::secret_need(
                message_fact.id,
                scope.clone(),
                message.workspace_id,
                message.frontier_id,
                message.minute,
                message.leaf_id,
            ),
            offer: message_context::secret_offer(
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
        let scope = message_context::workspace_scope(message.workspace_id);
        MatchedContext {
            need: message_context::deletion_need(
                message_fact.id,
                scope.clone(),
                message_fact.id,
                message.author_user_id,
            ),
            offer: message_context::deletion_offer(
                deletion_fact.id,
                scope,
                message_fact.id,
                message.author_user_id,
            ),
            payload: deletion_fact.clone(),
        }
    }
}
