//! Poc-10 content-message-deletion projector.
//!
//! POLICY. A content_message_deletion is admitted iff:
//!   1. STRUCTURAL. The fact is workspace-scoped and contains a raw or signed
//!      deletion payload for one message and author user.
//!   2. AUTHORITY. The signer, target message, and author contexts prove the
//!      deletion author is the target message author in the same workspace.
//!      This uses authenticated message metadata, so deletes do not wait for
//!      encrypted message text to open.
//!   3. MATERIALIZE. Once authorized, write the deletion row, publish the
//!      content_deleted offer, and share the deletion fact.

use crate::core::facts::Fact;
use crate::core::intents::AtomicIntent;
use crate::core::projection::{
    project_typed, ProjectionContext, ProjectionOutput, Projector, TypedProjector,
};

use crate::protocol::facts::content::message;
use crate::protocol::facts::content::message::authority::{self, DecodedPayload};
use crate::protocol::facts::identity;
use crate::protocol::facts::identity::user;
use crate::protocol::intents::sync::share_fact_with_workspace::share_fact_with_workspace_intent_for_fact;
use crate::protocol::matchers as message_matchers;

use super::rows::{message_deletion_row, MessageDeletionRow};

#[derive(Debug, Clone, Default)]
pub struct ContentMessageDeletionProjector;

impl ContentMessageDeletionProjector {
    pub fn new() -> Self {
        Self
    }
}

impl Projector for ContentMessageDeletionProjector {
    fn project(
        &self,
        fact: &Fact,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        project_typed::<super::Codec, _>(self, fact, context)
    }
}

impl TypedProjector<super::Codec> for ContentMessageDeletionProjector {
    fn project_typed(
        &self,
        fact: &Fact,
        decoded: authority::DecodedFact<super::fact::ContentMessageDeletionFact>,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        // 1. Structural.
        let authority::DecodedFact {
            payload: deletion,
            signer,
            envelope,
        } = decoded;
        let scope = message_matchers::workspace_scope(deletion.workspace_id);
        require_fact_scope(fact, &scope)?;

        // 2. Authority.
        let signer_need = authority::signer_need(fact.id, signer);
        let target_need =
            message_matchers::message_meta_need(fact.id, scope.clone(), deletion.target_message_id);
        let author_need = crate::protocol::matchers::exact_need(
            fact.id,
            crate::protocol::matchers::user_role(),
            deletion.author_user_id,
        );
        if let (Some(signer), Some(need)) = (signer, signer_need.as_ref()) {
            if !authority::validate_signer_context(
                context,
                need,
                signer,
                deletion.workspace_id,
                Some(deletion.author_user_id),
                "message deletion",
            )? {
                return Ok(output_with_needs([
                    signer_need,
                    Some(target_need),
                    Some(author_need),
                ]));
            }
        }
        let Some(target_fact) = context_payload(context, &target_need, "message deletion target")?
        else {
            return Ok(output_with_needs([
                signer_need,
                Some(target_need),
                Some(author_need),
            ]));
        };
        let Some(author_fact) = context_payload(context, &author_need, "message deletion author")?
        else {
            return Ok(output_with_needs([
                signer_need,
                Some(target_need),
                Some(author_need),
            ]));
        };
        validate_target_message(&deletion, target_fact)?;
        validate_author_user(&deletion, author_fact)?;
        authority::verify_envelope(envelope.as_ref(), "message deletion")?;

        // 3. Materialize.
        let row = message_deletion_row(MessageDeletionRow {
            workspace_id: deletion.workspace_id,
            target_message_id: deletion.target_message_id,
            deletion_id: fact.id,
            created_at_ms: deletion.created_at_ms,
            author_user_id: deletion.author_user_id,
        })?;
        Ok(
            output_with_needs([signer_need, Some(target_need), Some(author_need)])
                .offer(message_matchers::deletion_offer(
                    fact.id,
                    scope,
                    deletion.target_message_id,
                    deletion.author_user_id,
                ))
                .intent(AtomicIntent::PutRow(row).into_intent())
                .intent(share_fact_with_workspace_intent_for_fact(
                    deletion.workspace_id,
                    fact,
                )),
        )
    }
}

fn context_payload<'a>(
    context: &'a ProjectionContext,
    need: &crate::core::context::ContextNeed,
    label: &str,
) -> Result<Option<&'a Fact>, String> {
    authority::context_payload(context, need, label)
}

fn output_with_needs(
    needs: impl IntoIterator<Item = Option<crate::core::context::ContextNeed>>,
) -> ProjectionOutput {
    needs
        .into_iter()
        .flatten()
        .fold(ProjectionOutput::new(), |output, need| output.need(need))
}

fn validate_target_message(
    deletion: &super::fact::ContentMessageDeletionFact,
    target_fact: &Fact,
) -> Result<(), String> {
    if target_fact.id != deletion.target_message_id {
        return Err("message deletion target context payload id mismatch".to_string());
    }
    let target_payload = maybe_signed_payload(
        target_fact,
        message::TYPE_CONTENT_MESSAGE,
        "message deletion target",
    )?;
    let target = message::decode_fact_payload(&target_payload.payload)
        .map_err(|_| "message deletion target context must be a content message".to_string())?;
    if target.workspace_id != deletion.workspace_id {
        return Err("message deletion target workspace does not match deletion".to_string());
    }
    if target.author_user_id != deletion.author_user_id {
        return Err("message deletion author is not the target message author".to_string());
    }
    Ok(())
}

fn validate_author_user(
    deletion: &super::fact::ContentMessageDeletionFact,
    author_fact: &Fact,
) -> Result<(), String> {
    if author_fact.id != deletion.author_user_id {
        return Err("message deletion author context payload id mismatch".to_string());
    }
    let author_payload =
        maybe_signed_payload(author_fact, user::TYPE_USER, "message deletion author")?;
    let author = user::decode_fact_payload(&author_payload.payload)
        .map_err(|_| "message deletion author context must be an identity user".to_string())?;
    if author.workspace_id != deletion.workspace_id {
        return Err("message deletion author workspace does not match deletion".to_string());
    }
    Ok(())
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
        Err("content message deletion fact scope does not match body workspace".to_string())
    }
}

#[cfg(test)]
mod projector_tests {
    use crate as topo;

    use topo::core::facts::{Fact, FactId, FactScope};
    use topo::core::intents::AtomicIntent;
    use topo::core::projection::{MatchedContext, ProjectionContext, Projector};
    use topo::protocol::facts::content::message::{
        fact::ContentMessageFact, layout as message_layout,
    };
    use topo::protocol::facts::content::message_deletion::fact::ContentMessageDeletionFact;
    use topo::protocol::facts::content::message_deletion::{layout, project, rows};
    use topo::protocol::matchers as message_context;

    use topo::protocol::facts::identity::user::{fact::UserFact, layout as user_layout};

    #[test]
    fn content_message_deletion_projector_materializes_authorized_author_delete() {
        let workspace_id = [9; 32];
        let author_user_id = user_fact(workspace_id, [22; 32], "alice");
        let message_fact = message_fact(workspace_id, author_user_id.id);
        let (deletion, fact) =
            deletion_fact(workspace_id, message_fact.id, author_user_id.id, 12_345);

        let output = project::ContentMessageDeletionProjector::new()
            .project(
                &fact,
                &authorized_context(&fact, &message_fact, &author_user_id),
            )
            .expect("project deletion");

        assert_eq!(output.needs.len(), 2);
        assert_eq!(output.offers.len(), 1);
        assert_eq!(output.offers[0].role, message_context::deletion_role());
        assert_eq!(output.intents.len(), 2);
        let row_intent = output
            .intents
            .iter()
            .find_map(|intent| {
                AtomicIntent::from_intent(intent, &[rows::MESSAGE_DELETION_ROWS]).ok()
            })
            .expect("row intent");
        let AtomicIntent::PutRow(stored) = row_intent else {
            panic!("expected put row intent");
        };
        let row = rows::decode_message_deletion_row(&stored.key, &stored.value)
            .expect("decode message deletion row");
        assert_eq!(row.workspace_id, deletion.workspace_id);
        assert_eq!(row.target_message_id, deletion.target_message_id);
        assert_eq!(row.deletion_id, fact.id);
        assert_eq!(row.created_at_ms, 12_345);
        assert_eq!(row.author_user_id, deletion.author_user_id);
    }

    #[test]
    fn content_message_deletion_projector_waits_for_target_and_author_context() {
        let workspace_id = [9; 32];
        let author_user_id = [22; 32];
        let (deletion, fact) = deletion_fact(workspace_id, [11; 32], author_user_id, 12_345);

        let output = project::ContentMessageDeletionProjector::new()
            .project(&fact, &ProjectionContext::default())
            .expect("missing context is a need, not an unauthorized delete");

        assert!(output.intents.is_empty());
        assert!(output.offers.is_empty());
        assert_eq!(output.needs.len(), 2);
        assert!(output.needs.contains(&message_context::message_meta_need(
            fact.id,
            message_context::workspace_scope(deletion.workspace_id),
            deletion.target_message_id
        )));
        assert!(output
            .needs
            .contains(&crate::protocol::matchers::exact_need(
                fact.id,
                crate::protocol::matchers::user_role(),
                deletion.author_user_id
            )));
    }

    #[test]
    fn content_message_deletion_projector_waits_for_author_after_target_is_known() {
        let workspace_id = [9; 32];
        let author_user_id = [22; 32];
        let message_fact = message_fact(workspace_id, author_user_id);
        let (deletion, fact) = deletion_fact(workspace_id, message_fact.id, author_user_id, 12_345);

        let output = project::ContentMessageDeletionProjector::new()
            .project(
                &fact,
                &ProjectionContext::from_matches(vec![target_match(&fact, &message_fact)]),
            )
            .expect("missing author is a need, not an unauthorized delete");

        assert!(output.intents.is_empty());
        assert!(output.offers.is_empty());
        assert_eq!(output.needs.len(), 2);
        assert!(output.needs.contains(&message_context::message_meta_need(
            fact.id,
            message_context::workspace_scope(deletion.workspace_id),
            deletion.target_message_id
        )));
        assert!(output
            .needs
            .contains(&crate::protocol::matchers::exact_need(
                fact.id,
                crate::protocol::matchers::user_role(),
                deletion.author_user_id
            )));
    }

    #[test]
    fn content_message_deletion_projector_rejects_non_author_delete() {
        let workspace_id = [9; 32];
        let message_author = user_fact(workspace_id, [22; 32], "alice");
        let deleter = user_fact(workspace_id, [44; 32], "mallory");
        let message_fact = message_fact(workspace_id, message_author.id);
        let (_deletion, fact) = deletion_fact(workspace_id, message_fact.id, deleter.id, 12_345);

        let err = project::ContentMessageDeletionProjector::new()
            .project(&fact, &authorized_context(&fact, &message_fact, &deleter))
            .expect_err("non-author deletion must reject");

        assert!(err.contains("not the target message author"), "{err}");
    }

    #[test]
    fn content_message_deletion_projector_rejects_author_from_other_workspace() {
        let workspace_id = [9; 32];
        let author_user_id = user_fact([8; 32], [22; 32], "alice");
        let message_fact = message_fact(workspace_id, author_user_id.id);
        let (_deletion, fact) =
            deletion_fact(workspace_id, message_fact.id, author_user_id.id, 12_345);

        let err = project::ContentMessageDeletionProjector::new()
            .project(
                &fact,
                &authorized_context(&fact, &message_fact, &author_user_id),
            )
            .expect_err("author from other workspace must reject");

        assert!(err.contains("author workspace"), "{err}");
    }

    #[test]
    fn content_message_deletion_projector_rejects_malformed_fact_bytes() {
        let fact = Fact::new(FactScope::Global, 0, vec![0; 8]);
        let err = project::ContentMessageDeletionProjector::new()
            .project(&fact, &ProjectionContext::default())
            .expect_err("malformed bytes must fail projection");
        assert!(
            err.to_lowercase().contains("deletion") || err.to_lowercase().contains("length"),
            "{err}"
        );
    }

    fn deletion_fact(
        workspace_id: FactId,
        target_message_id: FactId,
        author_user_id: FactId,
        created_at_ms: u64,
    ) -> (ContentMessageDeletionFact, Fact) {
        let deletion = ContentMessageDeletionFact {
            workspace_id,
            created_at_ms,
            target_message_id,
            author_user_id,
        };
        let fact = Fact::new(
            message_context::workspace_scope(deletion.workspace_id),
            deletion.created_at_ms,
            layout::encode_fact(&deletion).expect("encode deletion"),
        );
        (deletion, fact)
    }

    fn message_fact(workspace_id: FactId, author_user_id: FactId) -> Fact {
        let message = ContentMessageFact {
            workspace_id,
            author_user_id,
            created_at_ms: 12_000,
            signer_id: [8; 32],
            frontier_id: [3; 32],
            local_history_node_secret_id: [0; 32],
            expires_at_minute: u64::MAX,
            disappearing_setting_id: [0; 32],
            minute: 12,
            leaf_id: [4; 32],
            nonce: [5; crate::protocol::facts::content::message::fact::NONCE_BYTES],
            ciphertext: vec![6; crate::protocol::facts::content::message::fact::CIPHERTEXT_BYTES],
        };
        Fact::new(
            message_context::workspace_scope(workspace_id),
            message.created_at_ms,
            message_layout::encode_fact(&message).expect("encode message"),
        )
    }

    fn user_fact(workspace_id: FactId, public_key: [u8; 32], username: &str) -> Fact {
        let user = UserFact {
            created_at_ms: 8_000,
            workspace_id,
            public_key,
            username: username.to_string(),
        };
        Fact::new(
            FactScope::Global,
            user.created_at_ms,
            user_layout::encode_fact(&user).expect("encode user"),
        )
    }

    fn authorized_context(
        deletion_fact: &Fact,
        target_fact: &Fact,
        author_fact: &Fact,
    ) -> ProjectionContext {
        ProjectionContext::from_matches(vec![
            target_match(deletion_fact, target_fact),
            author_match(deletion_fact, author_fact),
        ])
    }

    fn target_match(deletion_fact: &Fact, target_fact: &Fact) -> MatchedContext {
        let deletion = layout::decode_fact(&deletion_fact.bytes).expect("decode deletion");
        let scope = message_context::workspace_scope(deletion.workspace_id);
        MatchedContext {
            need: message_context::message_meta_need(
                deletion_fact.id,
                scope.clone(),
                target_fact.id,
            ),
            offer: message_context::message_meta_offer(target_fact.id, scope, target_fact.id),
            payload: target_fact.clone(),
        }
    }

    fn author_match(deletion_fact: &Fact, author_fact: &Fact) -> MatchedContext {
        MatchedContext {
            need: crate::protocol::matchers::exact_need(
                deletion_fact.id,
                crate::protocol::matchers::user_role(),
                author_fact.id,
            ),
            offer: crate::protocol::matchers::exact_offer(
                author_fact.id,
                crate::protocol::matchers::user_role(),
            ),
            payload: author_fact.clone(),
        }
    }
}
