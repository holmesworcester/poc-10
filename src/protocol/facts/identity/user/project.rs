//! Poc-10 user projector.
//!
//! POLICY. A user fact is admitted iff:
//!   1. STRUCTURAL. The outer fact is global, signed, contains a user payload,
//!      and the workspace/public key/name fields are non-empty.
//!   2. AUTHORITY. Matched user_invite context must match the signer id,
//!      signer public key, and workspace.
//!   3. MATERIALIZE. Write the user row, publish user context, and share the
//!      fact with the workspace.

use crate::core::facts::{Fact, FactScope};
use crate::core::intents::AtomicIntent;
use crate::core::projection::{
    project_typed, ProjectionContext, ProjectionOutput, Projector, TypedProjector,
};
use crate::protocol::facts::identity;
use crate::protocol::facts::identity::user_invite;
use crate::protocol::intents::sync::share_fact_with_workspace::share_fact_with_workspace_intent_for_fact;

use super::rows::user_row;

#[derive(Debug, Clone, Default)]
pub struct UserProjector;

impl UserProjector {
    pub fn new() -> Self {
        Self
    }
}

impl Projector for UserProjector {
    fn project(
        &self,
        fact: &Fact,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        project_typed::<super::Codec, _>(self, fact, context)
    }
}

impl TypedProjector<super::Codec> for UserProjector {
    fn project_typed(
        &self,
        fact: &Fact,
        signed: identity::signed_fact::SignedPayload<super::fact::UserFact>,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        // 1. Structural.
        if fact.scope != FactScope::Global {
            return Err("user fact must have global scope".to_string());
        }
        let envelope = signed.envelope;
        let user = signed.payload;
        if user.workspace_id == [0; 32] {
            return Err("user workspace_id must not be empty".to_string());
        }
        if user.public_key == [0; 32] {
            return Err("user public_key must not be empty".to_string());
        }
        if user.username.trim().is_empty() {
            return Err("username must not be empty".to_string());
        }

        // 2. Authority.
        let invite_need = crate::protocol::matchers::exact_need(
            fact.id,
            crate::protocol::matchers::user_invite_role(),
            envelope.signer_id,
        );
        let Some(invite_fact) = context.payload_for(&invite_need) else {
            return Ok(ProjectionOutput::new().need(invite_need));
        };
        identity::signed_fact::verify_envelope(&envelope)?;
        if invite_fact.id != envelope.signer_id {
            return Err("user signer context payload id mismatch".to_string());
        }
        let invite_envelope = identity::signed_fact::decode_envelope(invite_fact.body())
            .map_err(|_| "user signer context must be a signed user_invite fact".to_string())?;
        if invite_envelope.inner_type != user_invite::TYPE_USER_INVITE {
            return Err("user signer context must be a signed user_invite fact".to_string());
        }
        let invite = user_invite::decode_fact_payload(&invite_envelope.payload)
            .map_err(|_| "user signer context must be a user_invite fact".to_string())?;
        if invite.workspace_id != user.workspace_id {
            return Err("user workspace does not match user_invite workspace".to_string());
        }
        if invite.public_key != envelope.signer_public_key {
            return Err("signed user signer key does not match user_invite public key".to_string());
        }
        let user_invite_id = invite_fact.id;

        // 3. Materialize.
        Ok(ProjectionOutput::new()
            .need(invite_need)
            .offer(crate::protocol::matchers::exact_offer(
                fact.id,
                crate::protocol::matchers::user_role(),
            ))
            .intent(AtomicIntent::PutRow(user_row(fact.id, user_invite_id, &user)?).into_intent())
            .intent(share_fact_with_workspace_intent_for_fact(
                user.workspace_id,
                fact,
            )))
    }
}

#[cfg(test)]
mod projector_tests {
    use crate as topo;

    use topo::core::crypto;
    use topo::core::facts::{Fact, FactScope};
    use topo::core::intents::AtomicIntent;
    use topo::core::projection::{MatchedContext, ProjectionContext, Projector};
    use topo::core::schema_dsl::{CORE_SCHEMA_SOURCE, FACTS_SCHEMA_SOURCE};
    use topo::core::store::Store;
    use topo::core::wake_loop::WakeLoop;
    use topo::protocol::facts::identity;
    use topo::protocol::facts::identity::user::fact::UserFact;
    use topo::protocol::facts::identity::user::{layout, project, rows};
    use topo::protocol::facts::identity::user_invite::{
        fact::UserInviteFact, layout as invite_layout,
    };
    use topo::protocol::matchers as identity_context;

    const INVITE_PRIVATE_KEY: [u8; 32] = [8; 32];

    #[test]
    fn user_projector_materializes_row_through_atomic_intent() {
        let user = UserFact {
            created_at_ms: 100,
            workspace_id: [2; 32],
            public_key: [7; 32],
            username: "alice".to_string(),
        };
        let invite_fact = signed_user_invite_fact(user.workspace_id, INVITE_PRIVATE_KEY);
        let fact = signed_user_fact(&user, invite_fact.id, INVITE_PRIVATE_KEY);
        let context = ProjectionContext::from_matches(vec![MatchedContext {
            need: identity_context::exact_need(
                fact.id,
                identity_context::user_invite_role(),
                invite_fact.id,
            ),
            offer: identity_context::user_invite_offer(invite_fact.id),
            payload: invite_fact.clone(),
        }]);

        let output = project::UserProjector::new()
            .project(&fact, &context)
            .expect("project user");
        assert_eq!(output.needs.len(), 1);
        assert_eq!(output.intents.len(), 2);
        let row_intent = output
            .intents
            .iter()
            .find_map(|intent| AtomicIntent::from_intent(intent, &[rows::USER_ROWS]).ok())
            .expect("row intent");
        let AtomicIntent::PutRow(stored) = row_intent else {
            panic!("expected put row");
        };
        let row = rows::decode_user_row(&stored.key, &stored.value).expect("decode row");
        assert_eq!(row.workspace_id, [2; 32]);
        assert_eq!(row.user_id, fact.id);
        assert_eq!(row.username, "alice");
        assert_eq!(row.public_key, [7; 32]);
        assert_eq!(row.user_invite_id, invite_fact.id);
    }

    #[test]
    fn user_projector_waits_for_user_invite_context() {
        let user = UserFact {
            created_at_ms: 100,
            workspace_id: [2; 32],
            public_key: [7; 32],
            username: "alice".to_string(),
        };
        let invite_fact = signed_user_invite_fact(user.workspace_id, INVITE_PRIVATE_KEY);
        let fact = signed_user_fact(&user, invite_fact.id, INVITE_PRIVATE_KEY);

        let output = project::UserProjector::new()
            .project(&fact, &ProjectionContext::new(Vec::new()))
            .expect("project waits");

        assert_eq!(output.needs.len(), 1);
        assert!(output.intents.is_empty());
        assert_eq!(output.needs[0].role, identity_context::user_invite_role());
        assert_eq!(output.needs[0].selector.as_bytes(), &invite_fact.id);
    }

    fn signed_user_invite_fact(workspace_id: [u8; 32], private_key: [u8; 32]) -> Fact {
        let invite = UserInviteFact {
            created_at_ms: 1,
            public_key: crypto::ed25519_public_key(&private_key),
            workspace_id,
            authority_fact_id: workspace_id,
        };
        make_signed_fact(
            workspace_id,
            private_key,
            invite_layout::encode_fact(&invite).expect("encode user_invite"),
            1,
        )
    }

    fn signed_user_fact(user: &UserFact, signer_id: [u8; 32], private_key: [u8; 32]) -> Fact {
        make_signed_fact(
            signer_id,
            private_key,
            layout::encode_fact(user).expect("encode user"),
            user.created_at_ms,
        )
    }

    fn make_signed_fact(
        signer_id: [u8; 32],
        private_key: [u8; 32],
        payload: Vec<u8>,
        timestamp: u64,
    ) -> Fact {
        let bytes =
            identity::signed_fact::create::sign_payload_bytes(signer_id, &private_key, payload)
                .expect("sign fact");
        Fact::new(FactScope::Global, timestamp, bytes)
    }

    #[test]
    fn user_projector_rejects_blank_username() {
        let user = UserFact {
            created_at_ms: 1,
            workspace_id: [2; 32],
            public_key: [7; 32],
            username: "   ".to_string(),
        };
        let invite_fact = signed_user_invite_fact(user.workspace_id, INVITE_PRIVATE_KEY);
        let fact = signed_user_fact(&user, invite_fact.id, INVITE_PRIVATE_KEY);
        let store =
            Store::open_memory_with_schema_sources(&[CORE_SCHEMA_SOURCE, FACTS_SCHEMA_SOURCE])
                .expect("open target schema");
        let mut bus = WakeLoop::new();

        assert!(bus.submit_fact(fact));
        let err = bus
            .drain_applying_atomic_rows(
                &project::UserProjector::new(),
                &[],
                &store,
                &[rows::USER_ROWS],
                10,
            )
            .expect_err("blank username must fail");
        assert!(err.contains("username"), "{err}");
    }

    #[test]
    fn user_projector_rejects_unsigned_user_fact() {
        let user = UserFact {
            created_at_ms: 1,
            workspace_id: [2; 32],
            public_key: [7; 32],
            username: "alice".to_string(),
        };
        let fact = Fact::new(
            FactScope::Global,
            user.created_at_ms,
            layout::encode_fact(&user).expect("encode user"),
        );

        let err = project::UserProjector::new()
            .project(&fact, &ProjectionContext::new(Vec::new()))
            .expect_err("unsigned user must fail");

        assert_eq!(err, "user fact must be signed");
    }
}
