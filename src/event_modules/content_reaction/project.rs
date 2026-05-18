//! Poc-10 content-reaction projector.
//!
//! Decodes a content-reaction fact, waits for the target message when needed,
//! and emits a single `PutRow` into `reaction_rows` only after the target
//! message context is matched and validated. The reaction id used in the row
//! key is the fact id.
//!
//! Signed content-reaction facts are parsed up front so the signer need can be
//! emitted, but signature verification waits until endpoint signer context is
//! available.
//!
//! Parity gaps (intentional, deferred to later slices):
//! - Legacy admit-check drops reactions whose parent message is already
//!   tombstoned. This projector watches the parent deletion context and
//!   removes its row when the authorized parent delete is visible.
//! - Legacy derives a deterministic leaf coordinate from author+target+
//!   frontier+ts so duplicate reactions collapse on admission. The target
//!   per-message FS isn't ported yet, so this slice keys rows by fact id.
//! - Legacy decrypts the emoji into a plaintext `content.reactions` row;
//!   per-message decryption secrets aren't surfaced in this slice.

use crate::core::facts::{Fact, FactScope};
use crate::core::intents::{AtomicIntent, TableDelete};
use crate::core::projection::{ProjectionContext, ProjectionOutput, Projector};

use crate::event_modules::content_message::authority::{self, DecodedPayload};
use crate::event_modules::content_message::{
    layout as message_layout, matchers as message_matchers,
};
use crate::event_modules::identity_matchers;
use crate::event_modules::identity_user::layout as user_layout;
use crate::event_modules::signed_fact;

use super::layout;
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
        let decoded =
            authority::decode_raw_or_signed(fact, layout::TYPE_CONTENT_REACTION, "reaction")?;
        let reaction = layout::decode_fact(&decoded.payload)?;
        let scope = message_matchers::workspace_scope(reaction.workspace_id);
        require_fact_scope(fact, &scope)?;
        let signer_need = authority::signer_need(fact.id, decoded.signer);
        let target_need =
            message_matchers::message_need(fact.id, scope.clone(), reaction.target_message_id);
        let author_need = identity_matchers::exact_need(
            fact.id,
            identity_matchers::user_role(),
            reaction.author_user_id,
        );
        if let (Some(signer), Some(need)) = (decoded.signer, signer_need.as_ref()) {
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
        authority::verify_signature(&decoded, "reaction")?;
        let Some(target) = payload_for_need(context, &target_need) else {
            return Ok(output_with_needs([
                signer_need,
                Some(target_need),
                Some(author_need),
                None,
            ]));
        };
        validate_target_message(
            target,
            &scope,
            reaction.workspace_id,
            reaction.target_message_id,
        )?;
        let target_payload = maybe_signed_payload(
            target,
            message_layout::TYPE_CONTENT_MESSAGE,
            "reaction target",
        )?;
        let target_message = message_layout::decode_fact(&target_payload.payload)
            .map_err(|_| "reaction target context is not a content message".to_string())?;
        let target_deletion_need = message_matchers::deletion_need(
            fact.id,
            scope.clone(),
            reaction.target_message_id,
            target_message.author_user_id,
        );
        if let Some(deletion) = payload_for_need(context, &target_deletion_need) {
            validate_message_deletion(
                deletion,
                reaction.workspace_id,
                reaction.target_message_id,
                target_message.author_user_id,
            )?;
            return Ok(delete_reaction_projection(reaction.workspace_id, fact.id)
                .need(target_need)
                .need(target_deletion_need));
        }
        let Some(author) = payload_for_need(context, &author_need) else {
            return Ok(output_with_needs([
                signer_need,
                Some(target_need),
                Some(target_deletion_need),
                Some(author_need),
            ]));
        };
        validate_author_user(author, reaction.workspace_id, reaction.author_user_id)?;

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
        .intent(AtomicIntent::PutRow(row).into_intent()))
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
    payload: &Fact,
    expected_scope: &FactScope,
    workspace_id: crate::core::facts::FactId,
    target_message_id: crate::core::facts::FactId,
) -> Result<(), String> {
    if payload.id != target_message_id {
        return Err("reaction target context payload id mismatch".to_string());
    }
    if &payload.scope != expected_scope {
        return Err("reaction target context scope does not match reaction workspace".to_string());
    }
    let target_payload = maybe_signed_payload(
        payload,
        message_layout::TYPE_CONTENT_MESSAGE,
        "reaction target",
    )?;
    let target = message_layout::decode_fact(&target_payload.payload)
        .map_err(|_| "reaction target context is not a content message".to_string())?;
    if target.workspace_id != workspace_id {
        return Err("reaction target message workspace does not match reaction".to_string());
    }
    Ok(())
}

fn validate_author_user(
    payload: &Fact,
    workspace_id: crate::core::facts::FactId,
    author_user_id: crate::core::facts::FactId,
) -> Result<(), String> {
    if payload.id != author_user_id {
        return Err("reaction author context payload id mismatch".to_string());
    }
    let author_payload = maybe_signed_payload(payload, user_layout::TYPE_USER, "reaction author")?;
    let author = user_layout::decode_fact(&author_payload.payload)
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
        crate::event_modules::content_message_deletion::layout::TYPE_CONTENT_MESSAGE_DELETION,
        "target deletion",
    )?;
    let deletion = crate::event_modules::content_message_deletion::layout::decode_fact(
        &deletion_payload.payload,
    )
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
    use topo::core::matchers::ExactSelectorMatcher;
    use topo::core::projection::{ProjectionContext, ProjectionOutput, Projector};
    use topo::core::schema_dsl::EVENT_MODULES_SCHEMA_SOURCE;
    use topo::core::store::Store;
    use topo::core::wake_loop::WakeLoop;
    use topo::event_modules::content_message::fact::ContentMessageFact;
    use topo::event_modules::content_message::{
        layout as message_layout, matchers as message_context,
    };
    use topo::event_modules::content_reaction::fact::{ContentReactionFact, REACTION_NONCE_BYTES};
    use topo::event_modules::content_reaction::{layout, project, rows};
    use topo::event_modules::identity_matchers;
    use topo::event_modules::identity_user::{fact::UserFact, layout as user_layout};

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
        let target_message = ContentMessageFact {
            workspace_id: reaction.workspace_id,
            author_user_id: target_author.id,
            created_at_ms: 12_000,
            frontier_id: [55; 32],
            minute: 0,
            leaf_id: [66; 32],
            sealed_body_ref: [77; 32],
        };
        let message_fact = Fact::new(
            message_context::workspace_scope(target_message.workspace_id),
            target_message.created_at_ms,
            message_layout::encode_fact(&target_message).expect("encode message"),
        );
        reaction.target_message_id = message_fact.id;
        let reaction_fact = Fact::new(
            message_context::workspace_scope(reaction.workspace_id),
            reaction.created_at_ms,
            layout::encode_fact(&reaction).expect("encode reaction"),
        );
        let store = Store::open_memory_with_schema_sources(&[EVENT_MODULES_SCHEMA_SOURCE])
            .expect("open target schema");
        let mut bus = WakeLoop::new();
        let matcher = ExactSelectorMatcher::new(message_context::message_role());
        let user_matcher = ExactSelectorMatcher::new(identity_matchers::user_role());

        assert!(bus.submit_fact(target_author));
        assert!(bus.submit_fact(reaction_author));
        assert!(bus.submit_fact(reaction_fact.clone()));
        assert!(bus.submit_fact(message_fact));
        let projected = bus
            .drain_applying_atomic_rows(
                &CombinedProjector,
                &[&matcher, &user_matcher],
                &store,
                &[
                    rows::REACTION_ROWS,
                    topo::event_modules::content_message::rows::CONTENT_MESSAGE_ROWS,
                ],
                10,
            )
            .expect("project reaction");
        assert!(projected.projections >= 4);
        assert_eq!(projected.intents, 2);
        assert!(bus.intents().is_empty());

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
        let store = Store::open_memory_with_schema_sources(&[EVENT_MODULES_SCHEMA_SOURCE])
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
            .any(|need| need.role == identity_matchers::user_role()));
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
        let target_message = ContentMessageFact {
            workspace_id: reaction.workspace_id,
            author_user_id: target_author.id,
            created_at_ms: 12_000,
            frontier_id: [55; 32],
            minute: 0,
            leaf_id: [66; 32],
            sealed_body_ref: [77; 32],
        };
        let message_fact = Fact::new(
            message_context::workspace_scope(target_message.workspace_id),
            target_message.created_at_ms,
            message_layout::encode_fact(&target_message).expect("encode message"),
        );
        reaction.target_message_id = message_fact.id;
        let reaction_fact = Fact::new(
            message_context::workspace_scope(reaction.workspace_id),
            reaction.created_at_ms,
            layout::encode_fact(&reaction).expect("encode reaction"),
        );
        let store = Store::open_memory_with_schema_sources(&[EVENT_MODULES_SCHEMA_SOURCE])
            .expect("open target schema");
        let mut bus = WakeLoop::new();
        let matcher = ExactSelectorMatcher::new(message_context::message_role());
        let user_matcher = ExactSelectorMatcher::new(identity_matchers::user_role());

        assert!(bus.submit_fact(target_author));
        assert!(bus.submit_fact(message_fact));
        bus.drain_applying_atomic_rows(
            &CombinedProjector,
            &[&matcher, &user_matcher],
            &store,
            &[
                rows::REACTION_ROWS,
                topo::event_modules::content_message::rows::CONTENT_MESSAGE_ROWS,
            ],
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
                &[
                    rows::REACTION_ROWS,
                    topo::event_modules::content_message::rows::CONTENT_MESSAGE_ROWS,
                ],
                10,
            )
            .expect("target offer wakes reaction need");

        assert!(projected.projections >= 2);
        assert_eq!(projected.intents, 1);
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
                Some(message_layout::TYPE_CONTENT_MESSAGE) => {
                    topo::event_modules::content_message::project::ContentMessageProjector::new()
                        .project(fact, context)
                }
                Some(layout::TYPE_CONTENT_REACTION) => {
                    project::ContentReactionProjector::new().project(fact, context)
                }
                _ if user_layout::decode_fact(&fact.bytes).is_ok() => Ok(ProjectionOutput::new()
                    .offer(identity_matchers::exact_offer(
                        fact.id,
                        identity_matchers::user_role(),
                    ))),
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
}
