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
//!      content_purged offer, and share the deletion fact.

use crate::core::facts::Fact;
use crate::core::intents::RowMutation;
use crate::core::projectors::{
    project_typed, ProjectionContext, ProjectionOutput, Projector, TypedProjector,
};

use crate::protocol::auth;
use crate::protocol::auth::user;
use crate::protocol::content::message::project::{self, DecodedPayload};
use crate::protocol::content::{message, purge::project as content_purge};
use crate::protocol::sync::shared_fact::project::{
    context_have_from_optional_needs, share_fact_with_negentropy,
};

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
        decoded: project::DecodedFact<super::fact::ContentMessageDeletionFact>,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        // 1. Structural.
        let project::DecodedFact {
            payload: deletion,
            signer,
            envelope,
        } = decoded;
        let scope = crate::protocol::auth::workspace::scope(deletion.workspace_id);
        require_fact_scope(fact, &scope)?;

        // 2. Authority.
        let signer_need = project::signer_need(fact.id, signer);
        let target_need = crate::core::context::ContextNeed::range(
            fact.id,
            "content_message_meta",
            scope.clone(),
            deletion.target_message_id,
            deletion.target_message_id,
        );
        let author_need = crate::core::context::ContextNeed::range(
            fact.id,
            "auth_user",
            crate::core::facts::FactScope::Global,
            deletion.author_user_id,
            deletion.author_user_id,
        );
        if let (Some(signer), Some(need)) = (signer, signer_need.as_ref()) {
            if !project::validate_signer_context(
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
        project::verify_envelope(envelope.as_ref(), "message deletion")?;
        let context_have = context_have_from_optional_needs(
            context,
            [signer_need.as_ref(), Some(&target_need), Some(&author_need)],
        );

        // 3. Materialize.
        let row = message_deletion_row(MessageDeletionRow {
            workspace_id: deletion.workspace_id,
            target_message_id: deletion.target_message_id,
            deletion_id: fact.id,
            created_at_ms: deletion.created_at_ms,
            author_user_id: deletion.author_user_id,
        });
        Ok(share_fact_with_negentropy(
            output_with_needs([signer_need, Some(target_need), Some(author_need)])
                .offer(content_purge::target_purged_offer(
                    fact.id,
                    scope,
                    deletion.target_frontier_id,
                    deletion.target_minute,
                    deletion.target_message_id,
                ))
                .row_mutation(RowMutation::InsertValues(row)),
            deletion.workspace_id,
            fact,
            context_have,
        ))
    }
}

fn context_payload<'a>(
    context: &'a ProjectionContext,
    need: &crate::core::context::ContextNeed,
    label: &str,
) -> Result<Option<&'a Fact>, String> {
    project::context_payload(context, need, label)
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
    if target.frontier_id != deletion.target_frontier_id {
        return Err("message deletion target frontier does not match deletion".to_string());
    }
    if target.minute != deletion.target_minute {
        return Err("message deletion target minute does not match deletion".to_string());
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
    if payload.bytes.first().copied() == Some(auth::signed_fact::TYPE_SIGNED_FACT) {
        project::decode_raw_or_signed(payload, expected_type, label)
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
    use topo::core::intents::RowMutation;
    use topo::core::projectors::{MatchedContext, ProjectionContext, Projector};
    use topo::protocol::content::message::{fact::ContentMessageFact, layout as message_layout};
    use topo::protocol::content::message_deletion::fact::ContentMessageDeletionFact;
    use topo::protocol::content::message_deletion::{layout, project, rows};

    use topo::protocol::auth::user::{fact::UserFact, layout as user_layout};

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
        assert_eq!(output.offers[0].role, "content_purged");
        assert_eq!(output.effects.intents.len(), 2);
        assert_eq!(output.effects.row_mutations.len(), 1);
        let RowMutation::InsertValues(stored) = &output.effects.row_mutations[0] else {
            panic!("expected insert values mutation");
        };
        assert_eq!(stored.table, rows::MESSAGE_DELETION_ROWS);
        assert_eq!(
            stored.values[0],
            topo::core::intents::Value::Bytes(deletion.workspace_id.to_vec())
        );
        assert_eq!(
            stored.values[1],
            topo::core::intents::Value::Bytes(deletion.target_message_id.to_vec())
        );
        assert_eq!(
            stored.values[2],
            topo::core::intents::Value::Bytes(fact.id.to_vec())
        );
        assert_eq!(stored.values[3], topo::core::intents::Value::U64(12_345));
        assert_eq!(
            stored.values[4],
            topo::core::intents::Value::Bytes(deletion.author_user_id.to_vec())
        );
    }

    #[test]
    fn content_message_deletion_projector_waits_for_target_and_author_context() {
        let workspace_id = [9; 32];
        let author_user_id = [22; 32];
        let (deletion, fact) = deletion_fact(workspace_id, [11; 32], author_user_id, 12_345);

        let output = project::ContentMessageDeletionProjector::new()
            .project(&fact, &ProjectionContext::default())
            .expect("missing context is a need, not an unauthorized delete");

        assert!(output.effects.intents.is_empty());
        assert!(output.offers.is_empty());
        assert_eq!(output.needs.len(), 2);
        assert!(output
            .needs
            .contains(&crate::core::context::ContextNeed::range(
                fact.id,
                "content_message_meta",
                crate::protocol::auth::workspace::scope(deletion.workspace_id),
                deletion.target_message_id,
                deletion.target_message_id
            )));
        assert!(output
            .needs
            .contains(&crate::core::context::ContextNeed::range(
                fact.id,
                "auth_user",
                crate::core::facts::FactScope::Global,
                deletion.author_user_id,
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

        assert!(output.effects.intents.is_empty());
        assert!(output.offers.is_empty());
        assert_eq!(output.needs.len(), 2);
        assert!(output
            .needs
            .contains(&crate::core::context::ContextNeed::range(
                fact.id,
                "content_message_meta",
                crate::protocol::auth::workspace::scope(deletion.workspace_id),
                deletion.target_message_id,
                deletion.target_message_id
            )));
        assert!(output
            .needs
            .contains(&crate::core::context::ContextNeed::range(
                fact.id,
                "auth_user",
                crate::core::facts::FactScope::Global,
                deletion.author_user_id,
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
            target_frontier_id: [3; 32],
            target_minute: 12,
            author_user_id,
        };
        let fact = Fact::new(
            crate::protocol::auth::workspace::scope(deletion.workspace_id),
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
            nonce: [5; crate::protocol::content::message::fact::NONCE_BYTES],
            ciphertext: vec![6; crate::protocol::content::message::fact::CIPHERTEXT_BYTES],
        };
        Fact::new(
            crate::protocol::auth::workspace::scope(workspace_id),
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
        let scope = crate::protocol::auth::workspace::scope(deletion.workspace_id);
        MatchedContext {
            need: crate::core::context::ContextNeed::range(
                deletion_fact.id,
                "content_message_meta",
                scope.clone(),
                target_fact.id,
                target_fact.id,
            ),
            offer: crate::core::context::ContextOffer::range(
                target_fact.id,
                "content_message_meta",
                scope,
                target_fact.id,
                target_fact.id,
            ),
            payload: target_fact.clone(),
        }
    }

    fn author_match(deletion_fact: &Fact, author_fact: &Fact) -> MatchedContext {
        MatchedContext {
            need: crate::core::context::ContextNeed::range(
                deletion_fact.id,
                "auth_user",
                crate::core::facts::FactScope::Global,
                author_fact.id,
                author_fact.id,
            ),
            offer: crate::core::context::ContextOffer::range(
                author_fact.id,
                "auth_user",
                crate::core::facts::FactScope::Global,
                author_fact.id,
                author_fact.id,
            ),
            payload: author_fact.clone(),
        }
    }
}
