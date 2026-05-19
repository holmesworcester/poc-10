//! Content-reaction projector.
//!
//! POLICY. A content_reaction is admitted iff:
//!   1. STRUCTURAL. The fact is workspace-scoped and contains a raw or signed
//!      reaction payload.
//!   2. CONTEXT. Projection waits for signer, target content message, target
//!      deletion, and author context; deleted targets remove the reaction row.
//!   3. MATERIALIZE. Live reactions write one row and share the fact.

use crate::core::facts::{Fact, FactScope};
use crate::core::intents::{AtomicIntent, TableDelete};
use crate::core::projection::{
    project_typed, ProjectionContext, ProjectionOutput, Projector, TypedProjector,
};

use crate::protocol::facts::content::message::authority::{self, DecodedPayload};
use crate::protocol::facts::content::{message, message_deletion};
use crate::protocol::facts::identity;
use crate::protocol::facts::identity::user;
use crate::protocol::intents::sync::share_fact_with_workspace::share_fact_with_workspace_intent_for_fact;
use crate::protocol::matchers as message_matchers;

use super::rows::{reaction_key, reaction_row, ReactionRow, REACTION_ROWS};

#[derive(Debug, Clone, Default)]
pub struct ContentReactionProjector;

impl ContentReactionProjector {
    pub fn new() -> Self {
        Self
    }
}

impl Projector for ContentReactionProjector {
    fn project(
        &self,
        fact: &Fact,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        project_typed::<super::Codec, _>(self, fact, context)
    }
}

impl TypedProjector<super::Codec> for ContentReactionProjector {
    fn project_typed(
        &self,
        fact: &Fact,
        decoded: authority::DecodedFact<super::fact::ContentReactionFact>,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        // 1. Structural.
        let authority::DecodedFact {
            payload: reaction,
            signer,
            envelope,
        } = decoded;
        let scope = message_matchers::workspace_scope(reaction.workspace_id);
        require_fact_scope(fact, &scope)?;

        // 2. Context and deletion gates.
        let signer_need = authority::signer_need(fact.id, signer);
        let target_need =
            message_matchers::message_need(fact.id, scope.clone(), reaction.target_message_id);
        let author_need = crate::protocol::matchers::exact_need(
            fact.id,
            crate::protocol::matchers::user_role(),
            reaction.author_user_id,
        );
        if let (Some(signer), Some(need)) = (signer, signer_need.as_ref()) {
            if !authority::validate_signer_context(
                context,
                need,
                signer,
                reaction.workspace_id,
                Some(reaction.author_user_id),
                "reaction",
            )? {
                return Ok(output_with_needs([
                    signer_need,
                    Some(target_need),
                    Some(author_need),
                    None,
                ]));
            }
        }
        let Some(target) = context_payload(context, &target_need, "reaction target")? else {
            return Ok(output_with_needs([
                signer_need,
                Some(target_need),
                Some(author_need),
                None,
            ]));
        };
        let target_context = target_message_context(
            target,
            &scope,
            reaction.workspace_id,
            reaction.target_message_id,
            "reaction target",
        )?;
        let target_deletion_need = message_matchers::deletion_need(
            fact.id,
            scope.clone(),
            reaction.target_message_id,
            target_context.message.author_user_id,
        );
        if let Some(deletion) =
            context_payload(context, &target_deletion_need, "reaction target deletion")?
        {
            validate_message_deletion(
                deletion,
                reaction.workspace_id,
                reaction.target_message_id,
                target_context.message.author_user_id,
            )?;
            authority::verify_envelope(envelope.as_ref(), "reaction")?;
            return Ok(delete_reaction_projection(reaction.workspace_id, fact.id)
                .need(target_need)
                .need(target_deletion_need));
        }
        let Some(author) = context_payload(context, &author_need, "reaction author")? else {
            return Ok(output_with_needs([
                signer_need,
                Some(target_need),
                Some(target_deletion_need),
                Some(author_need),
            ]));
        };
        validate_author_user(author, reaction.workspace_id, reaction.author_user_id)?;
        authority::verify_envelope(envelope.as_ref(), "reaction")?;

        // 3. Materialize.
        let row = reaction_row(ReactionRow {
            workspace_id: reaction.workspace_id,
            reaction_id: fact.id,
            created_at_ms: reaction.created_at_ms,
            target_message_id: reaction.target_message_id,
            author_user_id: reaction.author_user_id,
            nonce: reaction.nonce,
            ciphertext: reaction.ciphertext,
        })?;
        Ok(output_with_needs([
            signer_need,
            Some(target_need),
            Some(target_deletion_need),
            Some(author_need),
        ])
        .intent(AtomicIntent::PutRow(row).into_intent())
        .intent(share_fact_with_workspace_intent_for_fact(
            reaction.workspace_id,
            fact,
        )))
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

fn target_message_context<'a>(
    payload: &'a Fact,
    expected_scope: &FactScope,
    workspace_id: crate::core::facts::FactId,
    target_message_id: crate::core::facts::FactId,
    label: &str,
) -> Result<TargetMessageContext<'a>, String> {
    if payload.id != target_message_id {
        return Err("reaction target context payload id mismatch".to_string());
    }
    if &payload.scope != expected_scope {
        return Err("reaction target context scope does not match reaction workspace".to_string());
    }
    let target = decode_target_message_payload(payload, label)?;
    if target.workspace_id != workspace_id {
        return Err("reaction target message workspace does not match reaction".to_string());
    }
    Ok(TargetMessageContext {
        _payload: payload,
        message: target,
    })
}

fn validate_author_user(
    payload: &Fact,
    workspace_id: crate::core::facts::FactId,
    author_user_id: crate::core::facts::FactId,
) -> Result<(), String> {
    if payload.id != author_user_id {
        return Err("reaction author context payload id mismatch".to_string());
    }
    let author_payload = maybe_signed_payload(payload, user::TYPE_USER, "reaction author")?;
    let author =
        crate::protocol::facts::identity::user::decode_fact_payload(&author_payload.payload)
            .map_err(|_| "reaction author context is not an identity user".to_string())?;
    if author.workspace_id != workspace_id {
        return Err("reaction author workspace does not match reaction".to_string());
    }
    Ok(())
}

fn delete_reaction_projection(
    workspace_id: crate::core::facts::FactId,
    reaction_id: crate::core::facts::FactId,
) -> ProjectionOutput {
    ProjectionOutput::new().intent(
        AtomicIntent::DeleteRow(TableDelete {
            table: REACTION_ROWS,
            key: reaction_key(workspace_id, reaction_id),
        })
        .into_intent(),
    )
}

fn validate_message_deletion(
    payload: &Fact,
    workspace_id: crate::core::facts::FactId,
    target_message_id: crate::core::facts::FactId,
    author_user_id: crate::core::facts::FactId,
) -> Result<(), String> {
    let deletion_payload = maybe_signed_payload(
        payload,
        message_deletion::TYPE_CONTENT_MESSAGE_DELETION,
        "target deletion",
    )?;
    let deletion = message_deletion::decode_fact_payload(&deletion_payload.payload)
        .map_err(|_| "target deletion context is not a content message deletion".to_string())?;
    if deletion.workspace_id != workspace_id {
        return Err("target deletion workspace does not match reaction".to_string());
    }
    if deletion.target_message_id != target_message_id {
        return Err("target deletion target does not match reaction parent".to_string());
    }
    if deletion.author_user_id != author_user_id {
        return Err("target deletion author does not match target message author".to_string());
    }
    Ok(())
}

struct TargetMessageContext<'a> {
    _payload: &'a Fact,
    message: TargetMessage,
}

struct TargetMessage {
    workspace_id: crate::core::facts::FactId,
    author_user_id: crate::core::facts::FactId,
}

fn decode_target_message_payload(payload: &Fact, label: &str) -> Result<TargetMessage, String> {
    let message_payload = maybe_signed_payload(payload, message::TYPE_CONTENT_MESSAGE, label)?;
    let message = message::decode_fact_payload(&message_payload.payload)
        .map_err(|_| format!("{label} context is not a content message"))?;
    Ok(TargetMessage {
        workspace_id: message.workspace_id,
        author_user_id: message.author_user_id,
    })
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
        Err("content reaction fact scope does not match body workspace".to_string())
    }
}

#[cfg(test)]
mod projector_tests {
    use crate as topo;

    use topo::core::facts::{Fact, FactScope};
    use topo::core::projection::{ProjectionContext, ProjectionOutput, Projector};
    use topo::core::schema_dsl::{CORE_SCHEMA_SOURCE, FACTS_SCHEMA_SOURCE};
    use topo::core::store::Store;
    use topo::core::wake_loop::WakeLoop;
    use topo::protocol::facts::content::message::{
        fact::{ContentMessageFact, CIPHERTEXT_BYTES, NONCE_BYTES, UNIX_MINUTE_MS},
        layout as message_layout,
    };
    use topo::protocol::facts::content::reaction::fact::{
        ContentReactionFact, REACTION_NONCE_BYTES,
    };
    use topo::protocol::facts::content::reaction::{layout, project, rows};
    use topo::protocol::matchers::ExactSelectorMatcher;

    use topo::protocol::facts::identity::user::{fact::UserFact, layout as user_layout};
    use topo::protocol::matchers as message_context;

    #[test]
    fn content_reaction_projector_materializes_row_through_atomic_intent() {
        let target_author = user_fact([9; 32], [44; 32], "target-author");
        let reaction_author = user_fact([9; 32], [22; 32], "reactor");
        let mut reaction = ContentReactionFact {
            workspace_id: [9; 32],
            created_at_ms: 12345,
            target_message_id: [11; 32],
            author_user_id: reaction_author.id,
            nonce: [7; REACTION_NONCE_BYTES],
            ciphertext: b"sealed-emoji".to_vec(),
        };
        let message_fact = target_message_fact(reaction.workspace_id, target_author.id, 12_000);
        reaction.target_message_id = message_fact.id;
        let reaction_fact = Fact::new(
            message_context::workspace_scope(reaction.workspace_id),
            reaction.created_at_ms,
            layout::encode_fact(&reaction).expect("encode reaction"),
        );
        let store =
            Store::open_memory_with_schema_sources(&[CORE_SCHEMA_SOURCE, FACTS_SCHEMA_SOURCE])
                .expect("open target schema");
        let mut bus = WakeLoop::new();
        let matcher = ExactSelectorMatcher::new(message_context::message_role());
        let user_matcher = ExactSelectorMatcher::new(crate::protocol::matchers::user_role());

        assert!(bus.submit_fact(target_author));
        assert!(bus.submit_fact(reaction_author));
        assert!(bus.submit_fact(reaction_fact.clone()));
        assert!(bus.submit_fact(message_fact));
        let projected = bus
            .drain_applying_atomic_rows(
                &CombinedProjector,
                &[&matcher, &user_matcher],
                &store,
                &[rows::REACTION_ROWS],
                10,
            )
            .expect("project reaction");
        assert!(projected.projections >= 4);
        assert_eq!(projected.intents, 2);
        assert_eq!(bus.intents().len(), 1);

        let table = store
            .table_rows(rows::REACTION_ROWS)
            .expect("reaction rows");
        assert_eq!(table.len(), 1);
        let row = rows::decode_reaction_row(&table[0].0, &table[0].1).expect("decode reaction row");
        assert_eq!(row.workspace_id, reaction.workspace_id);
        assert_eq!(row.reaction_id, reaction_fact.id);
        assert_eq!(row.created_at_ms, 12345);
        assert_eq!(row.target_message_id, reaction.target_message_id);
        assert_eq!(row.author_user_id, reaction.author_user_id);
        assert_eq!(row.nonce, reaction.nonce);
        assert_eq!(row.ciphertext, reaction.ciphertext);
    }

    #[test]
    fn content_reaction_projector_waits_for_target_message_context() {
        let reaction = ContentReactionFact {
            workspace_id: [9; 32],
            created_at_ms: 12345,
            target_message_id: [11; 32],
            author_user_id: [22; 32],
            nonce: [7; REACTION_NONCE_BYTES],
            ciphertext: b"sealed-emoji".to_vec(),
        };
        let fact = Fact::new(
            message_context::workspace_scope(reaction.workspace_id),
            reaction.created_at_ms,
            layout::encode_fact(&reaction).expect("encode reaction"),
        );
        let store =
            Store::open_memory_with_schema_sources(&[CORE_SCHEMA_SOURCE, FACTS_SCHEMA_SOURCE])
                .expect("open target schema");
        let mut bus = WakeLoop::new();

        assert!(bus.submit_fact(fact.clone()));
        let projected = bus
            .drain_applying_atomic_rows(
                &project::ContentReactionProjector::new(),
                &[],
                &store,
                &[rows::REACTION_ROWS],
                10,
            )
            .expect("project reaction");
        assert_eq!(projected.projections, 1);
        assert_eq!(projected.intents, 0);

        let context = bus.context(&fact.id).expect("reaction context");
        assert_eq!(context.needs.len(), 2);
        assert!(context.needs.iter().any(|need| {
            need.role == message_context::message_role()
                && need.selector
                    == topo::core::context::Selector::from_bytes(reaction.target_message_id)
        }));
        assert!(context
            .needs
            .iter()
            .any(|need| need.role == crate::protocol::matchers::user_role()));
        assert!(store
            .table_rows(rows::REACTION_ROWS)
            .expect("reaction rows")
            .is_empty());
    }

    #[test]
    fn content_reaction_target_offer_before_need_wakes_reaction() {
        let target_author = user_fact([9; 32], [44; 32], "target-author");
        let reaction_author = user_fact([9; 32], [22; 32], "reactor");
        let mut reaction = ContentReactionFact {
            workspace_id: [9; 32],
            created_at_ms: 12345,
            target_message_id: [11; 32],
            author_user_id: reaction_author.id,
            nonce: [7; REACTION_NONCE_BYTES],
            ciphertext: b"sealed-emoji".to_vec(),
        };
        let message_fact = target_message_fact(reaction.workspace_id, target_author.id, 12_000);
        reaction.target_message_id = message_fact.id;
        let reaction_fact = Fact::new(
            message_context::workspace_scope(reaction.workspace_id),
            reaction.created_at_ms,
            layout::encode_fact(&reaction).expect("encode reaction"),
        );
        let store =
            Store::open_memory_with_schema_sources(&[CORE_SCHEMA_SOURCE, FACTS_SCHEMA_SOURCE])
                .expect("open target schema");
        let mut bus = WakeLoop::new();
        let matcher = ExactSelectorMatcher::new(message_context::message_role());
        let user_matcher = ExactSelectorMatcher::new(crate::protocol::matchers::user_role());

        assert!(bus.submit_fact(target_author));
        assert!(bus.submit_fact(message_fact));
        bus.drain_applying_atomic_rows(
            &CombinedProjector,
            &[&matcher, &user_matcher],
            &store,
            &[rows::REACTION_ROWS],
            10,
        )
        .expect("project target first");

        assert!(bus.submit_fact(reaction_author));
        assert!(bus.submit_fact(reaction_fact.clone()));
        let projected = bus
            .drain_applying_atomic_rows(
                &CombinedProjector,
                &[&matcher, &user_matcher],
                &store,
                &[rows::REACTION_ROWS],
                10,
            )
            .expect("target offer wakes reaction need");

        assert!(projected.projections >= 2);
        assert_eq!(projected.intents, 2);
        let table = store
            .table_rows(rows::REACTION_ROWS)
            .expect("reaction rows");
        assert_eq!(table.len(), 1);
        let row = rows::decode_reaction_row(&table[0].0, &table[0].1).expect("decode reaction row");
        assert_eq!(row.reaction_id, reaction_fact.id);
    }

    #[test]
    fn content_reaction_projector_rejects_malformed_fact_bytes() {
        let fact = Fact::new(FactScope::Global, 0, vec![0; 8]);
        let mut bus = WakeLoop::new();
        bus.submit_fact(fact);
        let err = bus
            .drain(&project::ContentReactionProjector::new(), &[], 10)
            .expect_err("malformed bytes must fail projection");
        assert!(
            err.to_lowercase().contains("reaction") || err.to_lowercase().contains("length"),
            "{err}"
        );
    }

    struct CombinedProjector;

    impl Projector for CombinedProjector {
        fn project(
            &self,
            fact: &Fact,
            context: &ProjectionContext,
        ) -> Result<ProjectionOutput, String> {
            match fact.bytes.first().copied() {
                Some(message_layout::TYPE_CONTENT_MESSAGE) => Ok(ProjectionOutput::new().offer(
                    message_context::message_offer(fact.id, fact.scope.clone(), fact.id),
                )),
                Some(layout::TYPE_CONTENT_REACTION) => {
                    project::ContentReactionProjector::new().project(fact, context)
                }
                _ if crate::protocol::facts::identity::user::decode_fact_payload(fact.body())
                    .is_ok() =>
                {
                    Ok(
                        ProjectionOutput::new().offer(crate::protocol::matchers::exact_offer(
                            fact.id,
                            crate::protocol::matchers::user_role(),
                        )),
                    )
                }
                _ => Err("unknown combined test fact".to_string()),
            }
        }
    }

    fn user_fact(workspace_id: [u8; 32], public_key: [u8; 32], username: &str) -> Fact {
        let user = UserFact {
            created_at_ms: 12_000,
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

    fn target_message_fact(
        workspace_id: [u8; 32],
        author_user_id: [u8; 32],
        created_at_ms: u64,
    ) -> Fact {
        let message = ContentMessageFact {
            workspace_id,
            created_at_ms,
            author_user_id,
            signer_id: [6; 32],
            frontier_id: [7; 32],
            local_history_node_secret_id: [0; 32],
            expires_at_minute: u64::MAX,
            disappearing_setting_id: [0; 32],
            minute: created_at_ms / UNIX_MINUTE_MS,
            leaf_id: [8; 32],
            nonce: [9; NONCE_BYTES],
            ciphertext: vec![0xaa; CIPHERTEXT_BYTES],
        };
        Fact::new(
            message_context::workspace_scope(workspace_id),
            created_at_ms,
            message_layout::encode_fact(&message).expect("encode content target message"),
        )
    }
}
