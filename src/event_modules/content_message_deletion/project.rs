//! Poc-10 content-message-deletion projector.
//!
//! Decodes a deletion fact, waits for the target message and named author as
//! matched context, then emits a `PutRow` into `message_deletion_rows`.
//!
//! Poc-8 only authorizes message deletion when the deletion author is the
//! target message author. There is no admin/moderator delete path in poc-8.
//! The signed endpoint binding is handled by the signed-fact/identity slices;
//! this projector enforces the target-message authorization that belongs to
//! deletion semantics.

use crate::core::facts::Fact;
use crate::core::intents::AtomicIntent;
use crate::core::projection::{ProjectionContext, ProjectionOutput, Projector};

use crate::event_modules::content_message::authority::{self, DecodedPayload};
use crate::event_modules::content_message::{
    layout as message_layout, matchers as message_matchers,
};
use crate::event_modules::identity_matchers;
use crate::event_modules::identity_user::layout as user_layout;
use crate::event_modules::signed_fact;

use super::layout;
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
        let decoded = authority::decode_raw_or_signed(
            fact,
            layout::TYPE_CONTENT_MESSAGE_DELETION,
            "message deletion",
        )?;
        let deletion = layout::decode_fact(&decoded.payload)?;
        let scope = message_matchers::workspace_scope(deletion.workspace_id);
        require_fact_scope(fact, &scope)?;
        let signer_need = authority::signer_need(fact.id, decoded.signer);
        let target_need =
            message_matchers::message_need(fact.id, scope.clone(), deletion.target_message_id);
        let author_need = identity_matchers::exact_need(
            fact.id,
            identity_matchers::user_role(),
            deletion.author_user_id,
        );
        if let (Some(signer), Some(need)) = (decoded.signer, signer_need.as_ref()) {
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
        let Some(target_fact) = payload_for_need(context, &target_need)
        else {
            return Ok(output_with_needs([
                signer_need,
                Some(target_need),
                Some(author_need),
            ]));
        };
        let Some(author_fact) = payload_for_need(context, &author_need)
        else {
            return Ok(output_with_needs([
                signer_need,
                Some(target_need),
                Some(author_need),
            ]));
        };
        validate_target_message(&deletion, target_fact)?;
        validate_author_user(&deletion, author_fact)?;
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
                .intent(AtomicIntent::PutRow(row).into_intent()),
        )
    }
}

fn payload_for_need<'a>(
    context: &'a ProjectionContext,
    need: &crate::core::context::ContextNeed,
) -> Option<&'a Fact> {
    authority::payload_for_need(context, need)
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
        message_layout::TYPE_CONTENT_MESSAGE,
        "message deletion target",
    )?;
    let target = message_layout::decode_fact(&target_payload.payload)
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
    let author_payload = maybe_signed_payload(
        author_fact,
        user_layout::TYPE_USER,
        "message deletion author",
    )?;
    let author = user_layout::decode_fact(&author_payload.payload)
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
    if payload.bytes.first().copied() == Some(signed_fact::layout::TYPE_SIGNED_FACT) {
        authority::decode_raw_or_signed(payload, expected_type, label)
    } else {
        Ok(DecodedPayload {
            payload: payload.bytes.clone(),
            signer: None,
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
    use topo::event_modules::content_message::matchers as message_context;
    use topo::event_modules::content_message::{
        fact::ContentMessageFact, layout as message_layout,
    };
    use topo::event_modules::content_message_deletion::fact::ContentMessageDeletionFact;
    use topo::event_modules::content_message_deletion::{layout, project, rows};
    use topo::event_modules::identity_matchers;
    use topo::event_modules::identity_user::{fact::UserFact, layout as user_layout};

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
        assert_eq!(output.intents.len(), 1);
        let AtomicIntent::PutRow(stored) =
            AtomicIntent::from_intent(&output.intents[0], &[rows::MESSAGE_DELETION_ROWS])
                .expect("row intent")
        else {
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
        assert!(output.needs.contains(&message_context::message_need(
            fact.id,
            message_context::workspace_scope(deletion.workspace_id),
            deletion.target_message_id
        )));
        assert!(output.needs.contains(&identity_matchers::exact_need(
            fact.id,
            identity_matchers::user_role(),
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
        assert!(output.needs.contains(&message_context::message_need(
            fact.id,
            message_context::workspace_scope(deletion.workspace_id),
            deletion.target_message_id
        )));
        assert!(output.needs.contains(&identity_matchers::exact_need(
            fact.id,
            identity_matchers::user_role(),
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
            frontier_id: [3; 32],
            minute: 12,
            leaf_id: [4; 32],
            sealed_body_ref: [5; 32],
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
            need: message_context::message_need(deletion_fact.id, scope.clone(), target_fact.id),
            offer: message_context::message_offer(target_fact.id, scope, target_fact.id),
            payload: target_fact.clone(),
        }
    }

    fn author_match(deletion_fact: &Fact, author_fact: &Fact) -> MatchedContext {
        MatchedContext {
            need: identity_matchers::exact_need(
                deletion_fact.id,
                identity_matchers::user_role(),
                author_fact.id,
            ),
            offer: identity_matchers::exact_offer(author_fact.id, identity_matchers::user_role()),
            payload: author_fact.clone(),
        }
    }
}
