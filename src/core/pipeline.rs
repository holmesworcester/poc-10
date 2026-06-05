//! Core fact lifecycle and SQL-backed runtime pipeline.
//!
//! This module is the public facade for the reusable fact pipeline. It names the
//! first-class read stages:
//!
//! ```text
//! route -> decode -> authenticate -> adapt -> project -> effects -> commit
//! ```
//!
//! and the write-side shape protocol commands and authors should mirror:
//!
//! ```text
//! command -> author -> encode -> authenticate self-check -> admit -> read pipeline
//! ```
//!
//! Core owns when these stages run, how context is matched, and where commit
//! boundaries sit. Protocol fact families own the stage implementations: byte
//! layouts, authentication proofs, version adapters, semantic projection, row
//! construction, and user-facing commands. Keeping the contracts here makes the
//! core pipeline isomorphic with fact-family files without teaching core what a
//! workspace, message, invite, key wrap, sync range, or connection fact means.
//!
//! The SQL-backed worker modules below preserve the runtime mechanics: admitted
//! facts and intents are queued, projection replaces per-fact context/time-wake
//! state atomically with effects, handler dispatch commits atomically with queue
//! deletion, handler intent output is committed through the same shared effect
//! language, and the facade reports only whether a bounded pass progressed or
//! retried.

pub mod adapt;
pub mod authenticate;
mod commit_effects;
pub mod context;
pub(crate) mod context_store;
pub mod decode;
mod dispatch;
pub mod effects;
mod insert_select;
pub mod project;
mod project_pending_facts;
pub mod route;

pub use adapt::Adapter;
pub use authenticate::{
    authenticate_authored, verify_fact_id, AuthenticatedFact, Authentication, DecodedAuthenticator,
};
pub use context::{MatchedContext, ProjectionContext};
pub use decode::FactCodec;
pub use effects::{ProjectionOutput, TimeRange, TimeWake, Timeline};
pub use project::{project_staged, SemanticProjector};
pub use route::{
    EffectiveTagFn, EnvelopeRoute, FactAdmissionFn, FactPipeline, FactRoute, Projector,
    ProjectorFn, RouterProjector,
};

/// Public outcome returned by runtime pipeline calls.
///
/// Runtime callers only need to know whether a bounded pass moved work forward
/// and whether any handler asked to retry.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct WorkStatus {
    /// Whether a bounded pass committed or staged any work.
    pub progressed: bool,
    /// Whether a handler asked to leave work queued for a later pass.
    pub retried: bool,
}

impl WorkStatus {
    /// No progress and no retry.
    pub fn idle() -> Self {
        Self::default()
    }

    /// Build status from a simple progressed flag.
    pub fn progressed(progressed: bool) -> Self {
        Self {
            progressed,
            retried: false,
        }
    }

    /// Accumulate status across pipeline stages.
    pub fn merge(&mut self, other: Self) {
        self.progressed |= other.progressed;
        self.retried |= other.retried;
    }

    /// Return whether the pass did nothing and hit no retry.
    pub fn is_idle(self) -> bool {
        !self.progressed && !self.retried
    }
}

pub(crate) use commit_effects::commit_pipeline_effects_to_store;
pub(crate) use dispatch::{
    dispatch_queued_intent, dispatch_queued_intent_filtering_intents, next_queued_intent,
    submit_intent_to_store, submit_local_intent_to_store,
};
pub(crate) use project_pending_facts::{
    commit_projected_context_offers, drain_pending_projection,
    drain_pending_projection_filtering_intents, process_due_time_range, purge_fact_from_store,
    submit_fact_to_store, submit_facts_to_store, ProjectionProgress,
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::context::{ContextKey, ContextNeed, ContextOffer, Role};
    use crate::core::facts::{Fact, FactId, FactScope};

    #[test]
    fn projection_output_keeps_context_and_work_separate() {
        let id = [1; 32];
        let role = Role::new("exact").unwrap();
        let key = ContextKey::from_bytes([2; 32]);
        let output = ProjectionOutput::new()
            .need(ContextNeed {
                owner: id,
                role: role.clone(),
                scope: FactScope::Global,
                start_key: key.clone(),
                end_key: key.clone(),
            })
            .offer(ContextOffer {
                owner: id,
                role,
                scope: FactScope::Global,
                start_key: key.clone(),
                end_key: key,
            });

        assert_eq!(output.needs.len(), 1);
        assert_eq!(output.offers.len(), 1);
        assert!(output.effects.intents.is_empty());
    }

    #[test]
    fn projection_output_exposes_normalized_replacement_context() {
        let id = [1; 32];
        let role = Role::new("exact").unwrap();
        let need = ContextNeed {
            owner: id,
            role,
            scope: FactScope::Global,
            start_key: ContextKey::from_bytes([2; 32]),
            end_key: ContextKey::from_bytes([2; 32]),
        };
        let output = ProjectionOutput::new()
            .need(need.clone())
            .need(need.clone());

        assert_eq!(output.context_set().needs, vec![need]);
    }

    #[test]
    fn projection_context_returns_matched_payloads_by_need() {
        let role = Role::new("exact").unwrap();
        let need_a = ContextNeed {
            owner: [1; 32],
            role: role.clone(),
            scope: FactScope::Global,
            start_key: ContextKey::from_bytes([10; 32]),
            end_key: ContextKey::from_bytes([10; 32]),
        };
        let need_b = ContextNeed {
            owner: [2; 32],
            role: role.clone(),
            scope: FactScope::Global,
            start_key: ContextKey::from_bytes([20; 32]),
            end_key: ContextKey::from_bytes([20; 32]),
        };
        let context = ProjectionContext::from_matches(vec![
            matched_context(need_a.clone(), [11; 32]),
            matched_context(need_b.clone(), [22; 32]),
            matched_context(need_a.clone(), [33; 32]),
        ]);

        let payload_ids = context
            .matched_payloads_for(&need_a)
            .map(|(_offer, payload)| payload.id)
            .collect::<Vec<_>>();
        assert_eq!(payload_ids, vec![[11; 32], [33; 32]]);
        assert_eq!(
            context.payload_for(&need_b).map(|payload| payload.id),
            Some([22; 32])
        );
    }

    #[test]
    fn projection_context_decodes_payload_with_fact_codec() {
        let role = Role::new("exact").unwrap();
        let need = ContextNeed {
            owner: [1; 32],
            role,
            scope: FactScope::Global,
            start_key: ContextKey::from_bytes([10; 32]),
            end_key: ContextKey::from_bytes([10; 32]),
        };
        let context = ProjectionContext::from_matches(vec![matched_context(need.clone(), [7; 32])]);

        assert_eq!(context.payload_as::<FirstByteCodec>(&need), Ok(Some(7)));
        assert_eq!(
            context.payload_as::<FirstByteCodec>(&ContextNeed {
                owner: [2; 32],
                role: Role::new("exact").unwrap(),
                scope: FactScope::Global,
                start_key: ContextKey::from_bytes([20; 32]),
                end_key: ContextKey::from_bytes([20; 32]),
            }),
            Ok(None)
        );
    }

    #[test]
    fn projection_context_decodes_checked_matched_payloads() {
        let role = Role::new("exact").unwrap();
        let need = ContextNeed {
            owner: [1; 32],
            role,
            scope: FactScope::Global,
            start_key: ContextKey::from_bytes([10; 32]),
            end_key: ContextKey::from_bytes([10; 32]),
        };
        let context = ProjectionContext::from_matches(vec![
            matched_context(need.clone(), [7; 32]),
            matched_context(need.clone(), [8; 32]),
        ]);

        let payloads = context
            .matched_payloads_as_checked::<FirstByteCodec>(&need, "typed")
            .map(|matched| {
                let (offer, payload, decoded) = matched?;
                Ok((offer.owner, payload.id, decoded))
            })
            .collect::<Result<Vec<_>, String>>()
            .expect("typed matched payloads");

        assert_eq!(payloads, vec![([7; 32], [7; 32], 7), ([8; 32], [8; 32], 8)]);
    }

    #[test]
    fn checked_typed_payloads_report_offer_payload_mismatch_before_decode() {
        let role = Role::new("exact").unwrap();
        let need = ContextNeed {
            owner: [1; 32],
            role,
            scope: FactScope::Global,
            start_key: ContextKey::from_bytes([10; 32]),
            end_key: ContextKey::from_bytes([10; 32]),
        };
        let mut matched = matched_context(need.clone(), [7; 32]);
        matched.offer.owner = [8; 32];
        matched.payload.bytes.clear();
        let context = ProjectionContext::from_matches(vec![matched]);

        let err = context
            .matched_payloads_as_checked::<FirstByteCodec>(&need, "typed")
            .next()
            .expect("matched payload")
            .expect_err("offer owner mismatch should fail before decode");

        assert_eq!(err, "typed context offer payload mismatch");
    }

    #[test]
    fn staged_pipeline_decodes_authenticates_adapts_then_projects() {
        let fact = Fact::new(FactScope::Global, 1, vec![200, 5]);
        let output =
            project_staged::<ModelCodec, ModelAuthenticator, ModelAdapter, ModelProjector>(
                &ModelProjector,
                &fact,
                &ProjectionContext::default(),
            )
            .expect("staged projection");

        assert_eq!(output.offers.len(), 1);
        assert_eq!(output.offers[0].owner, fact.id);
        assert_eq!(output.offers[0].start_key.as_bytes(), &[15]);
    }

    #[test]
    fn staged_pipeline_parks_authentication_before_adapt_or_project() {
        let fact = Fact::new(FactScope::Global, 1, vec![200, 2]);
        let output =
            project_staged::<ModelCodec, ModelAuthenticator, ModelAdapter, ModelProjector>(
                &ModelProjector,
                &fact,
                &ProjectionContext::default(),
            )
            .expect("authentication need parks");

        assert_eq!(output.needs.len(), 1);
        assert_eq!(output.needs[0].role.as_str(), "model_auth");
        assert!(output.offers.is_empty());
    }

    #[test]
    fn staged_pipeline_preserves_multiple_authentication_needs() {
        let fact = Fact::new(FactScope::Global, 1, vec![200, 3]);
        let output =
            project_staged::<ModelCodec, ModelAuthenticator, ModelAdapter, ModelProjector>(
                &ModelProjector,
                &fact,
                &ProjectionContext::default(),
            )
            .expect("authentication needs park");

        assert_eq!(output.needs.len(), 2);
        assert_eq!(output.needs[0].role.as_str(), "model_auth");
        assert_eq!(output.needs[0].start_key.as_bytes(), &[3]);
        assert_eq!(output.needs[1].role.as_str(), "model_auth_fallback");
        assert_eq!(output.needs[1].start_key.as_bytes(), &[4]);
        assert!(output.offers.is_empty());
    }

    #[test]
    fn fact_route_records_staged_pipeline_metadata() {
        fn model_projector(
            fact: &Fact,
            context: &ProjectionContext,
        ) -> Result<ProjectionOutput, String> {
            project_staged::<ModelCodec, ModelAuthenticator, ModelAdapter, ModelProjector>(
                &ModelProjector,
                fact,
                context,
            )
        }

        let route = FactRoute {
            tag: 200,
            projector: model_projector,
            pipeline: FactPipeline::Staged {
                decode: "ModelCodec",
                authenticate: "ModelAuthenticator",
                adapt: "ModelAdapter",
                project: "ModelProjector",
            },
            replayed: true,
        };

        assert!(route.pipeline.is_staged());
        let output = (route.projector)(
            &Fact::new(FactScope::Global, 1, vec![200, 5]),
            &ProjectionContext::default(),
        )
        .expect("route projection");
        assert_eq!(output.offers.len(), 1);
    }

    struct ModelCodec;

    impl FactCodec for ModelCodec {
        type Payload = u8;

        fn decode_fact(fact: &Fact) -> Result<Self::Payload, String> {
            if fact.bytes.first().copied() != Some(200) {
                return Err("wrong model tag".to_string());
            }
            fact.bytes
                .get(1)
                .copied()
                .ok_or_else(|| "missing model payload".to_string())
        }
    }

    struct ModelAuthenticator;

    impl DecodedAuthenticator<ModelCodec> for ModelAuthenticator {
        type Authenticated = u8;

        fn authenticate_decoded<'a>(
            fact: &'a Fact,
            decoded: u8,
            _context: &ProjectionContext,
        ) -> Authentication<'a, Self::Authenticated> {
            match decoded {
                0 => Authentication::Invalid("zero is not authentic".to_string()),
                2 => Authentication::need(ContextNeed::range(
                    fact.id,
                    "model_auth",
                    FactScope::Global,
                    vec![2],
                    vec![2],
                )),
                3 => Authentication::needs([
                    ContextNeed::range(fact.id, "model_auth", FactScope::Global, vec![3], vec![3]),
                    ContextNeed::range(
                        fact.id,
                        "model_auth_fallback",
                        FactScope::Global,
                        vec![4],
                        vec![4],
                    ),
                ]),
                value => Authentication::Authenticated(AuthenticatedFact::new(fact, value)),
            }
        }
    }

    struct ModelAdapter;

    impl Adapter for ModelAdapter {
        type Source = u8;
        type Semantic = u16;

        fn adapt(source: Self::Source) -> Result<Self::Semantic, String> {
            Ok(u16::from(source) + 10)
        }
    }

    struct ModelProjector;

    impl SemanticProjector<u16> for ModelProjector {
        fn project_semantic(
            &self,
            fact: &Fact,
            semantic: u16,
            _context: &ProjectionContext,
        ) -> Result<ProjectionOutput, String> {
            Ok(ProjectionOutput::new().offer(ContextOffer::range(
                fact.id,
                "model_semantic",
                FactScope::Global,
                vec![semantic as u8],
                vec![semantic as u8],
            )))
        }
    }

    struct FirstByteCodec;

    impl FactCodec for FirstByteCodec {
        type Payload = u8;

        fn decode_fact(fact: &Fact) -> Result<Self::Payload, String> {
            fact.bytes
                .first()
                .copied()
                .ok_or_else(|| "empty typed payload".to_string())
        }
    }

    fn matched_context(need: ContextNeed, payload_id: FactId) -> MatchedContext {
        let payload = Fact {
            id: payload_id,
            scope: need.scope.clone(),
            timestamp: 1,
            bytes: payload_id.to_vec(),
        };
        MatchedContext {
            offer: ContextOffer {
                owner: payload_id,
                role: need.role.clone(),
                scope: need.scope.clone(),
                start_key: need.start_key.clone(),
                end_key: need.end_key.clone(),
            },
            need,
            payload,
        }
    }
}
