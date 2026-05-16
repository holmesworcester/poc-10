//! Retired unsealed content-message projector.
//!
//! Normal poc-10 messages are sealed-message facts. The concrete protocol
//! registry and runtime no longer route `TYPE_CONTENT_MESSAGE`; this module
//! remains only to keep older migration tests compiling until those fixtures
//! are rewritten around sealed-message facts.

use crate::core::facts::Fact;
use crate::core::intents::{AtomicIntent, TableDelete};
use crate::core::projection::{ProjectionContext, ProjectionOutput, Projector};
use crate::protocol::facts::identity;
use crate::protocol::facts::identity::user::layout as user_layout;
use crate::protocol::intents::sync::share_fact_with_workspace::share_fact_with_workspace_intent_for_fact;
use crate::protocol::matchers;

use super::authority::{self, DecodedPayload};
use super::layout;
use super::rows::{content_message_key, content_message_row, CONTENT_MESSAGE_ROWS};

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
        let decoded =
            authority::decode_raw_or_signed(fact, layout::TYPE_CONTENT_MESSAGE, "content message")?;
        let message = layout::decode_fact(&decoded.payload)?;
        let scope = matchers::workspace_scope(message.workspace_id);
        require_fact_scope(fact, &scope)?;
        let signer_need = authority::signer_need(fact.id, decoded.signer);
        let deletion_need =
            matchers::deletion_need(fact.id, scope.clone(), fact.id, message.author_user_id);
        let author_need = crate::protocol::matchers::exact_need(
            fact.id,
            crate::protocol::matchers::user_role(),
            message.author_user_id,
        );
        if let (Some(signer), Some(need)) = (decoded.signer, signer_need.as_ref()) {
            if !authority::validate_signer_context(
                context,
                need,
                signer,
                message.workspace_id,
                Some(message.author_user_id),
                "message",
            )? {
                return Ok(output_with_needs([
                    signer_need,
                    Some(deletion_need),
                    Some(author_need),
                ]));
            }
        }
        if let Some(deletion) = payload_for_need(context, &deletion_need, "message deletion")? {
            validate_message_deletion(
                deletion,
                message.workspace_id,
                fact.id,
                message.author_user_id,
            )?;
            return Ok(ProjectionOutput::new().need(deletion_need).intent(
                AtomicIntent::DeleteRow(TableDelete {
                    table: CONTENT_MESSAGE_ROWS,
                    key: content_message_key(message.workspace_id, fact.id),
                })
                .into_intent(),
            ));
        }
        let Some(author) = payload_for_need(context, &author_need, "message author")? else {
            return Ok(output_with_needs([
                signer_need,
                Some(deletion_need),
                Some(author_need),
            ]));
        };
        validate_author_user(author, message.workspace_id, message.author_user_id)?;
        let row = content_message_row(fact.id, &message);
        Ok(
            output_with_needs([signer_need, Some(deletion_need), Some(author_need)])
                .offer(matchers::message_offer(fact.id, scope, fact.id))
                .intent(AtomicIntent::PutRow(row).into_intent())
                .intent(share_fact_with_workspace_intent_for_fact(
                    message.workspace_id,
                    fact,
                )),
        )
    }
}

fn payload_for_need<'a>(
    context: &'a ProjectionContext,
    need: &crate::core::context::ContextNeed,
    label: &str,
) -> Result<Option<&'a Fact>, String> {
    authority::payload_for_need(context, need, label)
}

fn output_with_needs(
    needs: impl IntoIterator<Item = Option<crate::core::context::ContextNeed>>,
) -> ProjectionOutput {
    needs
        .into_iter()
        .flatten()
        .fold(ProjectionOutput::new(), |output, need| output.need(need))
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
        maybe_signed_payload(payload, user_layout::TYPE_USER, "message author context")?;
    let author = user_layout::decode_fact(&author_payload.payload)
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
    let deletion_payload = maybe_signed_payload(
        payload,
        crate::protocol::facts::content::message_deletion::layout::TYPE_CONTENT_MESSAGE_DELETION,
        "message deletion context",
    )?;
    let deletion = crate::protocol::facts::content::message_deletion::layout::decode_fact(
        &deletion_payload.payload,
    )
    .map_err(|_| "message deletion context is not a content message deletion".to_string())?;
    if deletion.workspace_id != workspace_id {
        return Err("message deletion workspace does not match message".to_string());
    }
    if deletion.target_message_id != target_message_id {
        return Err("message deletion target does not match message".to_string());
    }
    if deletion.author_user_id != author_user_id {
        return Err("message deletion author does not match message author".to_string());
    }
    Ok(())
}

fn maybe_signed_payload(
    payload: &Fact,
    expected_type: u8,
    label: &str,
) -> Result<DecodedPayload, String> {
    if payload.bytes.first().copied() == Some(identity::signed_fact::layout::TYPE_SIGNED_FACT) {
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
        Err("content message fact scope does not match body workspace".to_string())
    }
}

#[cfg(test)]
mod projector_tests {
    use crate as topo;

    use topo::core::facts::{Fact, FactScope};
    use topo::core::schema_dsl::FACTS_SCHEMA_SOURCE;
    use topo::core::store::Store;
    use topo::core::wake_loop::WakeLoop;
    use topo::protocol::facts::content::message::fact::ContentMessageFact;
    use topo::protocol::facts::content::message::{layout, project, rows};
    use topo::protocol::facts::content::message_deletion::fact::ContentMessageDeletionFact;
    use topo::protocol::facts::content::message_deletion::layout as deletion_layout;
    use topo::protocol::matchers as message_context;
    use topo::protocol::matchers::ExactSelectorMatcher;

    use topo::protocol::facts::identity::user::{fact::UserFact, layout as user_layout};

    #[test]
    fn content_message_projector_materializes_row_through_atomic_intent() {
        let author_fact = user_fact([9; 32]);
        let message = ContentMessageFact {
            workspace_id: [9; 32],
            author_user_id: author_fact.id,
            created_at_ms: 180_000,
            frontier_id: [3; 32],
            minute: 3,
            leaf_id: [4; 32],
            sealed_body_ref: [5; 32],
        };
        let fact = Fact::new(
            message_context::workspace_scope(message.workspace_id),
            message.created_at_ms,
            layout::encode_fact(&message).expect("encode content message"),
        );
        let store = Store::open_memory_with_schema_sources(&[FACTS_SCHEMA_SOURCE])
            .expect("open target schema");
        let mut bus = WakeLoop::new();
        let user_matcher = ExactSelectorMatcher::new(crate::protocol::matchers::user_role());

        assert!(bus.submit_fact(author_fact));
        assert!(bus.submit_fact(fact.clone()));
        let projected = bus
            .drain_applying_atomic_rows(
                &CombinedProjector,
                &[&user_matcher],
                &store,
                &[rows::CONTENT_MESSAGE_ROWS],
                10,
            )
            .expect("project content message");
        assert_eq!(projected.projections, 3);
        assert_eq!(projected.intents, 2);
        assert_eq!(bus.intents().len(), 1);

        let table = store
            .table_rows(rows::CONTENT_MESSAGE_ROWS)
            .expect("content message rows");
        assert_eq!(table.len(), 1);
        let row =
            rows::decode_content_message_row(&table[0].0, &table[0].1).expect("decode message row");
        assert_eq!(row.workspace_id, message.workspace_id);
        assert_eq!(row.message_id, fact.id);
        assert_eq!(row.author_user_id, message.author_user_id);
        assert_eq!(row.created_at_ms, message.created_at_ms);
        assert_eq!(row.frontier_id, message.frontier_id);
        assert_eq!(row.minute, message.minute);
        assert_eq!(row.leaf_id, message.leaf_id);
        assert_eq!(row.sealed_body_ref, message.sealed_body_ref);
    }

    #[test]
    fn content_message_projector_waits_for_author_context() {
        let message = ContentMessageFact {
            workspace_id: [9; 32],
            author_user_id: [22; 32],
            created_at_ms: 180_000,
            frontier_id: [3; 32],
            minute: 3,
            leaf_id: [4; 32],
            sealed_body_ref: [5; 32],
        };
        let fact = Fact::new(
            message_context::workspace_scope(message.workspace_id),
            message.created_at_ms,
            layout::encode_fact(&message).expect("encode content message"),
        );
        let store = Store::open_memory_with_schema_sources(&[FACTS_SCHEMA_SOURCE])
            .expect("open target schema");
        let mut bus = WakeLoop::new();

        assert!(bus.submit_fact(fact.clone()));
        let projected = bus
            .drain_applying_atomic_rows(
                &project::ContentMessageProjector::new(),
                &[],
                &store,
                &[rows::CONTENT_MESSAGE_ROWS],
                10,
            )
            .expect("project content message");
        assert_eq!(projected.projections, 1);
        assert_eq!(projected.intents, 0);
        let context = bus.context(&fact.id).expect("message context");
        assert_eq!(context.needs.len(), 2);
        assert!(context
            .needs
            .iter()
            .any(|need| need.role == crate::protocol::matchers::user_role()));
        assert!(context
            .needs
            .iter()
            .any(|need| need.role == message_context::deletion_role()));
        assert!(store
            .table_rows(rows::CONTENT_MESSAGE_ROWS)
            .expect("message rows")
            .is_empty());
    }

    #[test]
    fn content_message_keeps_deletion_watch_and_deletes_when_matched() {
        let author_fact = user_fact([9; 32]);
        let message = ContentMessageFact {
            workspace_id: [9; 32],
            author_user_id: author_fact.id,
            created_at_ms: 180_000,
            frontier_id: [3; 32],
            minute: 3,
            leaf_id: [4; 32],
            sealed_body_ref: [5; 32],
        };
        let fact = Fact::new(
            message_context::workspace_scope(message.workspace_id),
            message.created_at_ms,
            layout::encode_fact(&message).expect("encode content message"),
        );
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
        let store = Store::open_memory_with_schema_sources(&[FACTS_SCHEMA_SOURCE])
            .expect("open target schema");
        let message_matcher = ExactSelectorMatcher::new(message_context::message_role());
        let deletion_matcher = ExactSelectorMatcher::new(message_context::deletion_role());
        let user_matcher = ExactSelectorMatcher::new(crate::protocol::matchers::user_role());
        let mut bus = WakeLoop::new();

        assert!(bus.submit_fact(author_fact));
        assert!(bus.submit_fact(fact.clone()));
        bus.drain_applying_atomic_rows(
            &CombinedProjector,
            &[&message_matcher, &deletion_matcher, &user_matcher],
            &store,
            &[rows::CONTENT_MESSAGE_ROWS],
            10,
        )
        .expect("project message");
        assert_eq!(
            bus.context(&fact.id).expect("message context").needs.len(),
            2
        );
        assert_eq!(
            store
                .table_rows(rows::CONTENT_MESSAGE_ROWS)
                .expect("message rows")
                .len(),
            1
        );

        assert!(bus.submit_fact(deletion_fact));
        let deleted = bus
            .drain_applying_atomic_rows(
                &CombinedProjector,
                &[&message_matcher, &deletion_matcher, &user_matcher],
                &store,
                &[
                    rows::CONTENT_MESSAGE_ROWS,
                    topo::protocol::facts::content::message_deletion::rows::MESSAGE_DELETION_ROWS,
                ],
                10,
            )
            .expect("deletion wakes message");

        assert!(deleted.wakes >= 1);
        assert_eq!(
            bus.context(&fact.id).expect("message context").needs.len(),
            1
        );
        assert!(store
            .table_rows(rows::CONTENT_MESSAGE_ROWS)
            .expect("message rows")
            .is_empty());
    }

    #[test]
    fn content_message_projector_rejects_malformed_fact_bytes() {
        let fact = Fact::new(FactScope::Global, 0, vec![0; 8]);
        let mut bus = WakeLoop::new();
        bus.submit_fact(fact);
        let err = bus
            .drain(&project::ContentMessageProjector::new(), &[], 10)
            .expect_err("malformed bytes must fail projection");
        assert!(
            err.to_lowercase().contains("message") || err.to_lowercase().contains("length"),
            "{err}"
        );
    }

    struct CombinedProjector;

    impl topo::core::projection::Projector for CombinedProjector {
        fn project(
            &self,
            fact: &Fact,
            context: &topo::core::projection::ProjectionContext,
        ) -> Result<topo::core::projection::ProjectionOutput, String> {
            if deletion_layout::decode_fact(&fact.bytes).is_ok() {
                topo::protocol::facts::content::message_deletion::project::ContentMessageDeletionProjector::new()
                    .project(fact, context)
            } else if layout::decode_fact(&fact.bytes).is_ok() {
                project::ContentMessageProjector::new().project(fact, context)
            } else if user_layout::decode_fact(&fact.bytes).is_ok() {
                Ok(topo::core::projection::ProjectionOutput::new().offer(
                    crate::protocol::matchers::exact_offer(
                        fact.id,
                        crate::protocol::matchers::user_role(),
                    ),
                ))
            } else {
                Err("unknown combined content message test fact".to_string())
            }
        }
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
}
