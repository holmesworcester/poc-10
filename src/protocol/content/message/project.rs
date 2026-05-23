//! Semantic content-message projector.
//!
//! POLICY. A content_message is admitted iff:
//!   1. STRUCTURAL. The fact is workspace-scoped, signed, and contains a
//!      message payload with encrypted text.
//!   2. CONTEXT. The projector records sync liveness immediately, then waits
//!      for signer, author, deletion, retention-floor, secret, and time
//!      context. Once signer and author validate, it publishes metadata context
//!      for deletion. It does not publish opened message context or rows until
//!      the encrypted text opens. Deletion, expiry, or retention context removes
//!      this message's rows and purges this message fact.
//!   3. MATERIALIZE. Once opened, the projector writes read-model rows and
//!      offers semantic message context.

use crate::core::context::ContextNeed;
use crate::core::crypto;
use crate::core::facts::{Fact, FactId};
use crate::core::intents::RowMutation;
use crate::core::projectors::{
    project_typed, ProjectionContext, ProjectionOutput, Projector, TimeWake, TypedProjector,
};
use crate::protocol::auth;
use crate::protocol::auth::local_history_node_secret::project as coverage;
use crate::protocol::auth::user;
use crate::protocol::content::{
    message_deletion, purge::project as content_purge, retention_policy,
};
use crate::protocol::sync::share_fact_with_workspace::share_fact_with_workspace_intent_for_fact;

use super::rows::{
    content_message_row, message_tombstone_row, message_tombstone_row_at_minute,
    opened_message_row, OpenedMessageRow, CONTENT_MESSAGE_ROWS, OPENED_MESSAGE_ROWS,
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
        decoded: DecodedFact<super::fact::ContentMessageFact>,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        // 1. Structural.
        let DecodedFact {
            payload: message,
            envelope,
            ..
        } = decoded;
        let scope = crate::protocol::auth::workspace::scope(message.workspace_id);
        require_fact_scope(fact, &scope)?;
        let envelope = envelope
            .as_ref()
            .ok_or_else(|| "content message fact must be signed".to_string())?;
        if envelope.signer_id != message.signer_id {
            return Err("content message signer does not match signed envelope".to_string());
        }
        verify_envelope(Some(envelope), "message")?;

        // 2. Context and deletion gates.
        let signer_need = crate::core::context::ContextNeed::range(
            fact.id,
            "content_signer",
            scope.clone(),
            message.signer_id,
            message.signer_id,
        );
        let deletion_need = content_purge::target_purged_need(
            fact.id,
            scope.clone(),
            message.frontier_id,
            message.minute,
            fact.id,
        );
        let retention_floor_need = super::retention_floor_need(fact.id, message.workspace_id);
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
                signer_need.clone(),
                deletion_need.clone(),
                retention_floor_need.clone(),
                author_need.clone(),
                secret_need.clone(),
            ],
        );
        let Some(signer_payload) = context.payload_for(&signer_need) else {
            return Ok(base_output);
        };
        validate_message_signer_context(signer_payload, &signer_need, &message, Some(envelope))?;
        let Some(author) = context_payload(context, &author_need, "message author")? else {
            return Ok(base_output);
        };
        validate_author_user(author, message.workspace_id, message.author_user_id)?;

        let metadata_output = base_output
            .offer(crate::core::context::ContextOffer::range(
                fact.id,
                "content_message_meta",
                scope.clone(),
                fact.id,
                fact.id,
            ))
            .row_mutation(RowMutation::InsertValues(content_message_row(
                fact.id, &message,
            )));
        if expiry_minute_reached(context, &message).is_some() {
            return Ok(expired_output(fact.id, &message));
        }
        if let Some(floor) = cover_horizon_reached(context, &message) {
            return Ok(retired_output(fact.id, &message, floor));
        }
        if let Some(floor) = retention_floor_reached(context, &retention_floor_need, &message)? {
            return Ok(retired_output(fact.id, &message, floor));
        }
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
            return Ok(metadata_output);
        };
        let text = decrypt_text(&message, secret_payload)?;

        // 3. Materialize.
        Ok(metadata_output
            .offer(crate::core::context::ContextOffer::range(
                fact.id,
                "content_message",
                scope,
                fact.id,
                fact.id,
            ))
            .row_mutation(RowMutation::InsertValues(opened_message_row(
                OpenedMessageRow {
                    workspace_id: message.workspace_id,
                    message_id: fact.id,
                    created_at_ms: message.created_at_ms,
                    author_user_id: message.author_user_id,
                    signer_id: message.signer_id,
                    text,
                },
            ))))
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
            .fold(ProjectionOutput::new(), |output, need| output.need(need))
            .intent(share_fact_with_workspace_intent_for_fact(
                message.workspace_id,
                fact,
            )),
        fact.id,
        message,
    )
}

fn validate_message_signer_context(
    payload: &Fact,
    _need: &ContextNeed,
    message: &super::fact::ContentMessageFact,
    envelope: Option<&auth::signed_fact::fact::SignedFactEnvelope>,
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
) -> Option<auth::endpoint_shared::fact::EndpointSharedFact> {
    decode_signed_payload(
        payload,
        auth::endpoint_shared::TYPE_ENDPOINT_SHARED,
        "content signer context",
    )
    .ok()
    .and_then(|signed| auth::endpoint_shared::decode_fact_payload(&signed.payload).ok())
}

fn validate_author_user(
    payload: &Fact,
    workspace_id: crate::core::facts::FactId,
    author_user_id: crate::core::facts::FactId,
) -> Result<(), String> {
    if payload.id != author_user_id {
        return Err("message author context payload id mismatch".to_string());
    }
    let author_payload =
        decode_context_payload(payload, user::TYPE_USER, "message author context")?;
    let author = crate::protocol::auth::user::decode_fact_payload(&author_payload.payload)
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
    if let Ok(deletion_payload) = decode_signed_payload(
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
        if auth::local_key_secret::layout::decode_local_key_secret(payload.body()).is_ok()
            || auth::local_history_node_secret::layout::decode_local_history_node_secret(
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
        auth::local_key_secret::layout::decode_local_key_secret(secret_payload.body())
    {
        if secret.workspace_id != message.workspace_id || secret.frontier_id != message.frontier_id
        {
            return Err("content message root secret does not match message".to_string());
        }
        secret.key_secret
    } else {
        let node = auth::local_history_node_secret::layout::decode_local_history_node_secret(
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
        &crate::protocol::content::message::create::associated_data(
            message.workspace_id,
            message.frontier_id,
            message.minute,
        ),
        &message.nonce,
        &message.ciphertext,
    )?;
    crate::protocol::content::message::create::recover_text(&plaintext)
}

fn expiry_minute_reached(
    context: &ProjectionContext,
    message: &super::fact::ContentMessageFact,
) -> Option<u64> {
    if message.expires_at_minute == u64::MAX {
        return None;
    }
    context.time_reached(
        &crate::protocol::content::message::expiration_timeline(),
        message.expires_at_minute,
    )
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
    let retire_at = message.minute.checked_add(super::COVER_HORIZON_MINUTES)?;
    context
        .time_reached(
            &crate::protocol::content::message::expiration_timeline(),
            retire_at,
        )
        .map(|now| now.saturating_sub(super::COVER_HORIZON_MINUTES))
        .filter(|floor| message.minute < *floor)
}

fn with_retention_wakes(
    output: ProjectionOutput,
    owner: FactId,
    message: &super::fact::ContentMessageFact,
) -> ProjectionOutput {
    let mut output = output;
    if let Some(at) = message.minute.checked_add(super::COVER_HORIZON_MINUTES) {
        output = output.time_wake(TimeWake {
            owner,
            timeline: crate::protocol::content::message::expiration_timeline(),
            at,
        });
    }
    if message.expires_at_minute == u64::MAX {
        return output;
    }
    output.time_wake(TimeWake {
        owner,
        timeline: crate::protocol::content::message::expiration_timeline(),
        at: message.expires_at_minute,
    })
}

fn expired_output(
    message_id: FactId,
    message: &super::fact::ContentMessageFact,
) -> ProjectionOutput {
    ProjectionOutput::new()
        .row_mutation(RowMutation::InsertValues(message_tombstone_row(
            message.workspace_id,
            message_id,
            message.author_user_id,
            message.created_at_ms,
        )))
        .row_mutation(RowMutation::DeleteWhere(super::create::message_row_delete(
            CONTENT_MESSAGE_ROWS,
            message.workspace_id,
            message_id,
        )))
        .row_mutation(RowMutation::DeleteWhere(super::create::message_row_delete(
            OPENED_MESSAGE_ROWS,
            message.workspace_id,
            message_id,
        )))
        .purge_self(message_id)
}

fn retired_output(
    message_id: FactId,
    message: &super::fact::ContentMessageFact,
    floor_minute: u64,
) -> ProjectionOutput {
    ProjectionOutput::new()
        .row_mutation(RowMutation::InsertValues(message_tombstone_row_at_minute(
            message.workspace_id,
            message_id,
            message.author_user_id,
            floor_minute.saturating_sub(1),
        )))
        .row_mutation(RowMutation::DeleteWhere(super::create::message_row_delete(
            CONTENT_MESSAGE_ROWS,
            message.workspace_id,
            message_id,
        )))
        .row_mutation(RowMutation::DeleteWhere(super::create::message_row_delete(
            OPENED_MESSAGE_ROWS,
            message.workspace_id,
            message_id,
        )))
        .purge_self(message_id)
}

fn author_deletion_output(
    message_id: FactId,
    message: &super::fact::ContentMessageFact,
) -> ProjectionOutput {
    ProjectionOutput::new()
        .row_mutation(RowMutation::InsertValues(message_tombstone_row(
            message.workspace_id,
            message_id,
            message.author_user_id,
            message.created_at_ms,
        )))
        .row_mutation(RowMutation::DeleteWhere(super::create::message_row_delete(
            CONTENT_MESSAGE_ROWS,
            message.workspace_id,
            message_id,
        )))
        .row_mutation(RowMutation::DeleteWhere(super::create::message_row_delete(
            OPENED_MESSAGE_ROWS,
            message.workspace_id,
            message_id,
        )))
        .purge_self(message_id)
}

fn decode_context_payload(
    payload: &Fact,
    expected_type: u8,
    label: &str,
) -> Result<DecodedPayload, String> {
    if payload.bytes.first().copied() == Some(auth::signed_fact::TYPE_SIGNED_FACT) {
        decode_signed_payload(payload, expected_type, label)
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

// ===========================================================================
// Authority: signed payload unwrapping and signer validation.
//
// Content events arrive as signed envelopes. This section unwraps that shape,
// verifies the envelope, and asks the context system for the `endpoint_shared`
// fact that proves the signer belongs to the same workspace. Message, file, and
// deletion projection depend on this.
// ===========================================================================

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedPayload {
    pub payload: Vec<u8>,
    pub signer: Option<SignedSigner>,
    pub envelope: Option<auth::signed_fact::fact::SignedFactEnvelope>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedFact<T> {
    pub payload: T,
    pub signer: Option<SignedSigner>,
    pub envelope: Option<auth::signed_fact::fact::SignedFactEnvelope>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignedSigner {
    pub signer_id: FactId,
    pub signer_public_key: [u8; 32],
}

/// Returns the payload a content projector should decode, preserving signer
/// evidence from the required signed envelope.
pub fn decode_signed_payload(
    fact: &Fact,
    expected_type: u8,
    label: &str,
) -> Result<DecodedPayload, String> {
    if fact.bytes.first().copied() == Some(auth::signed_fact::TYPE_SIGNED_FACT) {
        let envelope = auth::signed_fact::decode_envelope(fact.body())
            .map_err(|err| format!("{label} signed fact is invalid: {err}"))?;
        if envelope.inner_type != expected_type {
            return Err(format!("signed fact does not contain a {label}"));
        }
        return Ok(DecodedPayload {
            payload: envelope.payload.clone(),
            signer: Some(SignedSigner {
                signer_id: envelope.signer_id,
                signer_public_key: envelope.signer_public_key,
            }),
            envelope: Some(envelope),
        });
    }

    Err(format!("{label} fact must be signed"))
}

pub fn verify_signature<T>(decoded: &DecodedFact<T>, label: &str) -> Result<(), String> {
    verify_envelope(decoded.envelope.as_ref(), label)
}

pub fn verify_envelope(
    envelope: Option<&auth::signed_fact::fact::SignedFactEnvelope>,
    label: &str,
) -> Result<(), String> {
    let Some(envelope) = envelope else {
        return Ok(());
    };
    auth::signed_fact::verify_envelope(envelope)
        .map_err(|err| format!("{label} signed fact is invalid: {err}"))
}

pub fn decode_signed_fact<T>(
    fact: &Fact,
    expected_type: u8,
    label: &str,
    decode: impl FnOnce(&[u8]) -> Result<T, String>,
) -> Result<DecodedFact<T>, String> {
    let decoded = decode_signed_payload(fact, expected_type, label)?;
    let payload = decode(&decoded.payload)?;
    Ok(DecodedFact {
        payload,
        signer: decoded.signer,
        envelope: decoded.envelope,
    })
}

pub fn signer_need(
    owner: FactId,
    workspace_id: FactId,
    signer: Option<SignedSigner>,
) -> Option<ContextNeed> {
    signer.map(|signer| {
        crate::core::context::ContextNeed::range(
            owner,
            "content_signer",
            crate::protocol::auth::workspace::scope(workspace_id),
            signer.signer_id,
            signer.signer_id,
        )
    })
}

/// Checks that the context payload satisfying a signer need is the endpoint
/// authority the signed content relies on.
pub fn validate_signer_context(
    context: &ProjectionContext,
    need: &ContextNeed,
    signer: SignedSigner,
    workspace_id: FactId,
    author_user_id: Option<FactId>,
    label: &str,
) -> Result<bool, String> {
    let Some(payload) = context_payload(context, need, &format!("{label} signer"))? else {
        return Ok(false);
    };
    let envelope = auth::signed_fact::decode_envelope(payload.body())
        .map_err(|_| format!("{label} signer context is not a signed endpoint_shared"))?;
    if envelope.inner_type != auth::endpoint_shared::TYPE_ENDPOINT_SHARED {
        return Err(format!(
            "{label} signer context is not a signed endpoint_shared"
        ));
    }
    let endpoint = auth::endpoint_shared::decode_fact_payload(&envelope.payload)
        .map_err(|_| format!("{label} signer context is not an endpoint_shared"))?;
    if endpoint.workspace_id != workspace_id {
        return Err(format!(
            "{label} signer endpoint_shared workspace does not match {label}"
        ));
    }
    if endpoint.endpoint_id != signer.signer_id {
        return Err(format!(
            "{label} signer endpoint id does not match signed fact"
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

#[cfg(test)]
mod projector_tests {
    use crate as topo;

    use topo::core::crypto;
    use topo::core::facts::{Fact, FactScope};
    use topo::core::intents::RowMutation;
    use topo::core::projectors::{MatchedContext, ProjectionContext, Projector};
    use topo::protocol::auth::endpoint_shared::{
        fact::{EndpointRole, EndpointSharedFact},
        layout as endpoint_shared_layout,
    };
    use topo::protocol::auth::local_history_node_secret::project as coverage;
    use topo::protocol::auth::local_key_secret::{fact::LocalKeySecretFact, layout as auth_layout};
    use topo::protocol::content::message::fact::ContentMessageFact;
    use topo::protocol::content::message::{layout, project, rows};
    use topo::protocol::content::message_deletion::fact::ContentMessageDeletionFact;
    use topo::protocol::content::message_deletion::layout as deletion_layout;
    use topo::protocol::content::purge::project as content_purge;

    use topo::protocol::auth::user::{fact::UserFact, layout as user_layout};

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

        assert_eq!(output.needs.len(), 5);
        assert_eq!(output.offers.len(), 2);
        assert!(output
            .offers
            .iter()
            .any(|offer| offer.role == "content_message_meta"));
        assert!(output
            .offers
            .iter()
            .any(|offer| offer.role == "content_message"));
        assert_eq!(output.effects.intents.len(), 1);
        assert_eq!(output.effects.row_mutations.len(), 2);

        let row = put_row!(output, rows::CONTENT_MESSAGE_ROWS).expect("content message row");
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

        let opened = put_row!(output, rows::OPENED_MESSAGE_ROWS).expect("opened row");
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
        assert_eq!(output.needs.len(), 5);
        assert_eq!(output.effects.intents.len(), 1);
        assert!(put_row!(output, rows::CONTENT_MESSAGE_ROWS).is_none());
        assert!(output.needs.iter().any(|need| need.role == "auth_user"));
        assert!(output
            .needs
            .iter()
            .any(|need| need.role == "content_signer"));
        assert!(output
            .needs
            .iter()
            .any(|need| need.role == "content_purged"));
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

        assert_eq!(output.needs.len(), 5);
        assert_eq!(output.offers.len(), 1);
        assert_eq!(output.offers[0].role, "content_message_meta");
        assert_eq!(output.effects.intents.len(), 1);
        let row = put_row!(output, rows::CONTENT_MESSAGE_ROWS).expect("content metadata row");
        assert_eq!(
            row.values[0],
            topo::core::intents::Value::Bytes(message.workspace_id.to_vec())
        );
        assert_eq!(
            row.values[1],
            topo::core::intents::Value::Bytes(fact.id.to_vec())
        );
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
            target_frontier_id: message.frontier_id,
            target_minute: message.minute,
            author_user_id: message.author_user_id,
        };
        let deletion_fact = Fact::new(
            crate::protocol::auth::workspace::scope(deletion.workspace_id),
            deletion.created_at_ms,
            topo::protocol::auth::signed_fact::create::sign_payload_bytes(
                message.signer_id,
                &CONTENT_SIGNING_KEY,
                deletion_layout::encode_fact(&deletion).expect("encode deletion"),
            )
            .expect("sign deletion"),
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
        let nonce = [7; crate::protocol::content::message::fact::NONCE_BYTES];
        let plaintext = topo::protocol::content::message::create::pad_plaintext(text.as_bytes())
            .expect("pad plaintext");
        let ciphertext = crypto::xchacha20poly1305_encrypt(
            &key,
            &topo::protocol::content::message::create::associated_data(
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
            retention_policy_id: [0; 32],
            minute,
            nonce,
            ciphertext,
        };
        let fact = Fact::new(
            crate::protocol::auth::workspace::scope(message.workspace_id),
            message.created_at_ms,
            topo::protocol::auth::signed_fact::create::sign_payload_bytes(
                message.signer_id,
                &CONTENT_SIGNING_KEY,
                layout::encode_fact(&message).expect("encode content message"),
            )
            .expect("sign content message"),
        );
        (message, fact, key)
    }

    fn signer_fact(message: &ContentMessageFact) -> Fact {
        let signer = EndpointSharedFact {
            created_at_ms: message.created_at_ms,
            workspace_id: message.workspace_id,
            user_authority_fact_id: message.author_user_id,
            endpoint_id: message.signer_id,
            signing_public_key: crypto::ed25519_public_key(&CONTENT_SIGNING_KEY),
            endpoint_role: EndpointRole::Device,
            device_name: "alice-device".to_string(),
        };
        Fact::new(
            FactScope::Global,
            message.created_at_ms,
            topo::protocol::auth::signed_fact::create::sign_payload_bytes(
                [1; 32],
                &ENDPOINT_AUTHORITY_KEY,
                endpoint_shared_layout::encode_fact(&signer).expect("encode endpoint shared"),
            )
            .expect("sign endpoint shared"),
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
            need: content_purge::target_purged_need(
                message_fact.id,
                scope.clone(),
                message.frontier_id,
                message.minute,
                message_fact.id,
            ),
            offer: content_purge::target_purged_offer(
                deletion_fact.id,
                scope,
                message.frontier_id,
                message.minute,
                message_fact.id,
            ),
            payload: deletion_fact.clone(),
        }
    }
}
