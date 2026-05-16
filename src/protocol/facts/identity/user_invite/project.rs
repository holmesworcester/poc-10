//! Poc-10 user-invite projector.
//!
//! User invites must be signed by the workspace root for bootstrap authority
//! or by an endpoint_shared signer whose user owns the named admin grant.

use crate::core::context::ContextNeed;
use crate::core::facts::{Fact, FactScope};
use crate::core::intents::AtomicIntent;
use crate::core::projection::{ProjectionContext, ProjectionOutput, Projector};
use crate::protocol::facts::identity;
use crate::protocol::facts::identity::admin::layout as admin_layout;
use crate::protocol::facts::identity::endpoint_shared::layout as endpoint_shared_layout;
use crate::protocol::facts::identity::workspace::layout as workspace_layout;
use crate::protocol::intents::sync::share_fact_with_workspace::share_fact_with_workspace_intent_for_fact;

use super::layout;
use super::rows::user_invite_row;

#[derive(Debug, Clone, Default)]
pub struct UserInviteProjector;

impl UserInviteProjector {
    pub fn new() -> Self {
        Self
    }
}

impl Projector for UserInviteProjector {
    fn project(
        &self,
        fact: &Fact,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        if fact.scope != FactScope::Global {
            return Err("user_invite fact must have global scope".to_string());
        }
        let envelope = identity::signed_fact::layout::decode_signed_fact(&fact.bytes)
            .map_err(|_| "user_invite fact must be signed".to_string())?;
        if envelope.inner_type != layout::TYPE_USER_INVITE {
            return Err("signed fact does not contain a user_invite".to_string());
        }
        let user_invite = layout::decode_fact(&envelope.payload)?;
        if user_invite.workspace_id == [0; 32] {
            return Err("user_invite fact has empty workspace_id".to_string());
        }
        if user_invite.authority_fact_id == [0; 32] {
            return Err("user_invite fact has empty authority_fact_id".to_string());
        }
        if user_invite.public_key == [0; 32] {
            return Err("user_invite fact has empty public_key".to_string());
        }
        let needs = authority_needs(fact.id, &user_invite, envelope.signer_id);
        let output = output_with_needs(&needs);
        if !has_all_context(&needs, context) {
            return Ok(output);
        }
        validate_authority(&needs, &user_invite, &envelope, context)?;
        Ok(output
            .offer(crate::protocol::matchers::user_invite_offer(fact.id))
            .offer(crate::protocol::matchers::user_invite_key_offer(
                fact.id,
                user_invite.workspace_id,
                user_invite.public_key,
            ))
            .intent(AtomicIntent::PutRow(user_invite_row(fact.id, &user_invite)?).into_intent())
            .intent(share_fact_with_workspace_intent_for_fact(
                user_invite.workspace_id,
                fact,
            )))
    }
}

fn authority_needs(
    owner: [u8; 32],
    invite: &super::fact::UserInviteFact,
    signer_id: [u8; 32],
) -> Vec<ContextNeed> {
    if invite.authority_fact_id == invite.workspace_id {
        vec![crate::protocol::matchers::exact_need(
            owner,
            crate::protocol::matchers::workspace_role(),
            invite.workspace_id,
        )]
    } else {
        vec![
            crate::protocol::matchers::exact_need(
                owner,
                crate::protocol::matchers::endpoint_shared_role(),
                signer_id,
            ),
            crate::protocol::matchers::exact_need(
                owner,
                crate::protocol::matchers::admin_role(),
                invite.authority_fact_id,
            ),
        ]
    }
}

fn output_with_needs(needs: &[ContextNeed]) -> ProjectionOutput {
    let mut output = ProjectionOutput::new();
    for need in needs {
        output = output.need(need.clone());
    }
    output
}

fn has_all_context(needs: &[ContextNeed], context: &ProjectionContext) -> bool {
    needs.iter().all(|need| context.payload_for(need).is_some())
}

fn validate_authority(
    needs: &[ContextNeed],
    invite: &super::fact::UserInviteFact,
    envelope: &identity::signed_fact::fact::SignedFactEnvelope,
    context: &ProjectionContext,
) -> Result<(), String> {
    if invite.authority_fact_id == invite.workspace_id {
        if envelope.signer_id != invite.workspace_id {
            return Err(
                "bootstrap user_invite must use workspace as signer and authority".to_string(),
            );
        }
        let workspace_fact = context
            .payload_for(&needs[0])
            .expect("checked by has_all_context");
        if workspace_fact.id != invite.workspace_id {
            return Err("user_invite workspace context payload id mismatch".to_string());
        }
        let workspace = workspace_layout::decode_fact(&workspace_fact.bytes)
            .map_err(|_| "user_invite authority is not a workspace fact".to_string())?;
        if workspace.public_key != envelope.signer_public_key {
            return Err(
                "signed user_invite signer key does not match workspace public key".to_string(),
            );
        }
        return Ok(());
    }

    let endpoint_fact = context
        .payload_for(&needs[0])
        .expect("checked by has_all_context");
    if endpoint_fact.id != envelope.signer_id {
        return Err("user_invite signer endpoint context payload id mismatch".to_string());
    }
    let endpoint_envelope = identity::signed_fact::layout::decode_signed_fact(&endpoint_fact.bytes)
        .map_err(|_| "user_invite signer must be workspace or endpoint_shared".to_string())?;
    if endpoint_envelope.inner_type != endpoint_shared_layout::TYPE_ENDPOINT_SHARED {
        return Err("user_invite signer must be workspace or endpoint_shared".to_string());
    }
    let endpoint = endpoint_shared_layout::decode_fact(&endpoint_envelope.payload)
        .map_err(|_| "user_invite signer must be workspace or endpoint_shared".to_string())?;
    if endpoint.signing_public_key != envelope.signer_public_key {
        return Err(
            "signed user_invite signer key does not match endpoint_shared signing key".to_string(),
        );
    }
    if endpoint.workspace_id != invite.workspace_id {
        return Err("user_invite signer endpoint belongs to a different workspace".to_string());
    }

    let admin_fact = context
        .payload_for(&needs[1])
        .expect("checked by has_all_context");
    if admin_fact.id != invite.authority_fact_id {
        return Err("user_invite admin context payload id mismatch".to_string());
    }
    let admin = decode_admin_payload(admin_fact)
        .map_err(|_| "user_invite authority must be an admin event".to_string())?;
    if admin.workspace_id != invite.workspace_id {
        return Err("user_invite admin authority belongs to a different workspace".to_string());
    }
    if endpoint.user_authority_fact_id != admin.user_fact_id {
        return Err("user_invite signer user does not match admin authority user".to_string());
    }
    Ok(())
}

fn decode_admin_payload(
    fact: &Fact,
) -> Result<crate::protocol::facts::identity::admin::fact::AdminFact, String> {
    match fact.bytes.first().copied() {
        Some(admin_layout::TYPE_ADMIN) => admin_layout::decode_fact(&fact.bytes),
        Some(identity::signed_fact::layout::TYPE_SIGNED_FACT) => {
            let envelope = identity::signed_fact::layout::decode_signed_fact(&fact.bytes)?;
            if envelope.inner_type != admin_layout::TYPE_ADMIN {
                return Err("expected signed admin".to_string());
            }
            admin_layout::decode_fact(&envelope.payload)
        }
        _ => Err("expected admin".to_string()),
    }
}

#[cfg(test)]
mod projector_tests {
    use crate as topo;

    use topo::core::crypto;
    use topo::core::facts::{Fact, FactScope};
    use topo::core::intents::AtomicIntent;
    use topo::core::matchers::ContextMatcher;
    use topo::core::projection::{MatchedContext, ProjectionContext, Projector};
    use topo::core::schema_dsl::FACTS_SCHEMA_SOURCE;
    use topo::core::store::Store;
    use topo::core::wake_loop::WakeLoop;
    use topo::protocol::facts::identity;
    use topo::protocol::facts::identity::user_invite::fact::UserInviteFact;
    use topo::protocol::facts::identity::user_invite::{layout, project, rows};
    use topo::protocol::facts::identity::workspace::{
        fact::WorkspaceFact, layout as workspace_layout,
    };
    use topo::protocol::facts::identity::workspace::{
        project as workspace_project, rows as workspace_rows,
    };
    use topo::protocol::matchers as identity_context;
    use topo::protocol::matchers::ExactSelectorMatcher;

    const WORKSPACE_PRIVATE_KEY: [u8; 32] = [9; 32];

    fn sample_fact() -> UserInviteFact {
        UserInviteFact {
            created_at_ms: 5,
            public_key: [1; 32],
            workspace_id: [2; 32],
            authority_fact_id: [2; 32],
        }
    }

    #[test]
    fn user_invite_projector_materializes_row_through_atomic_intent() {
        let user_invite = sample_fact();
        let fact = signed_user_invite_fact(
            &user_invite,
            user_invite.workspace_id,
            WORKSPACE_PRIVATE_KEY,
        );
        let workspace_fact = workspace_fact(user_invite.workspace_id, WORKSPACE_PRIVATE_KEY);
        let context = ProjectionContext::from_matches(vec![MatchedContext {
            need: identity_context::exact_need(
                fact.id,
                identity_context::workspace_role(),
                workspace_fact.id,
            ),
            offer: identity_context::exact_offer(
                workspace_fact.id,
                identity_context::workspace_role(),
            ),
            payload: workspace_fact,
        }]);

        let output = project::UserInviteProjector::new()
            .project(&fact, &context)
            .expect("project user_invite");
        assert_eq!(output.needs.len(), 1);
        assert_eq!(output.intents.len(), 2);
        let row_intent = output
            .intents
            .iter()
            .find_map(|intent| AtomicIntent::from_intent(intent, &[rows::USER_INVITE_ROWS]).ok())
            .expect("row intent");
        let AtomicIntent::PutRow(stored) = row_intent else {
            panic!("expected put row");
        };
        let row = rows::decode_user_invite_row(&stored.key, &stored.value).expect("decode row");
        assert_eq!(row.workspace_id, [2; 32]);
        assert_eq!(row.user_invite_id, fact.id);
        assert_eq!(row.created_at_ms, 5);
        assert_eq!(row.public_key, [1; 32]);
        assert_eq!(row.authority_fact_id, [2; 32]);
    }

    #[test]
    fn user_invite_projector_waits_for_workspace_authority() {
        let user_invite = sample_fact();
        let fact = signed_user_invite_fact(
            &user_invite,
            user_invite.workspace_id,
            WORKSPACE_PRIVATE_KEY,
        );

        let output = project::UserInviteProjector::new()
            .project(&fact, &ProjectionContext::new(Vec::new()))
            .expect("project waits");

        assert_eq!(output.needs.len(), 1);
        assert!(output.intents.is_empty());
        assert_eq!(output.needs[0].role, identity_context::workspace_role());
        assert_eq!(output.needs[0].selector.as_bytes(), &[2; 32]);
    }

    #[test]
    fn user_invite_projector_wakes_when_workspace_authority_offer_arrives() {
        let user_invite = sample_fact();
        let fact = signed_user_invite_fact(
            &user_invite,
            user_invite.workspace_id,
            WORKSPACE_PRIVATE_KEY,
        );
        let workspace_fact = workspace_fact(user_invite.workspace_id, WORKSPACE_PRIVATE_KEY);
        let store = Store::open_memory_with_schema_sources(&[FACTS_SCHEMA_SOURCE])
            .expect("open target schema");
        let matcher = ExactSelectorMatcher::new(identity_context::workspace_role());
        let matchers = [&matcher as &dyn ContextMatcher];
        let mut bus = WakeLoop::new();

        assert!(bus.submit_fact(fact));
        let waiting = bus
            .drain_applying_atomic_rows(
                &project::UserInviteProjector::new(),
                &matchers,
                &store,
                &[rows::USER_INVITE_ROWS],
                10,
            )
            .expect("user invite waits");
        assert_eq!(waiting.projections, 1);
        assert_eq!(waiting.intents, 0);

        assert!(bus.submit_fact(workspace_fact));
        let authority = bus
            .drain_applying_atomic_rows(
                &workspace_project::WorkspaceProjector::new(),
                &matchers,
                &store,
                &[workspace_rows::WORKSPACE_ROWS],
                1,
            )
            .expect("workspace projects");
        assert_eq!(authority.wakes, 1);

        let projected = bus
            .drain_applying_atomic_rows(
                &project::UserInviteProjector::new(),
                &matchers,
                &store,
                &[rows::USER_INVITE_ROWS],
                10,
            )
            .expect("user invite reprojects");
        assert_eq!(projected.projections, 1);
        assert_eq!(projected.intents, 2);
    }

    fn workspace_fact(workspace_id: [u8; 32], private_key: [u8; 32]) -> Fact {
        Fact {
            id: workspace_id,
            scope: FactScope::Global,
            timestamp: 1,
            bytes: workspace_layout::encode_fact(&WorkspaceFact {
                created_at_ms: 1,
                public_key: crypto::ed25519_public_key(&private_key),
                name: "Workspace".to_string(),
            })
            .expect("encode workspace"),
        }
    }

    fn signed_user_invite_fact(
        invite: &UserInviteFact,
        signer_id: [u8; 32],
        private_key: [u8; 32],
    ) -> Fact {
        let payload = layout::encode_fact(invite).expect("encode user_invite");
        let bytes =
            identity::signed_fact::create::sign_payload_bytes(signer_id, &private_key, payload)
                .expect("sign user_invite");
        Fact::new(FactScope::Global, invite.created_at_ms, bytes)
    }

    #[test]
    fn user_invite_projector_rejects_empty_authority() {
        let mut user_invite = sample_fact();
        user_invite.authority_fact_id = [0; 32];
        let fact = signed_user_invite_fact(&user_invite, [2; 32], WORKSPACE_PRIVATE_KEY);
        let store = Store::open_memory_with_schema_sources(&[FACTS_SCHEMA_SOURCE])
            .expect("open target schema");
        let mut bus = WakeLoop::new();

        assert!(bus.submit_fact(fact));
        let err = bus
            .drain_applying_atomic_rows(
                &project::UserInviteProjector::new(),
                &[],
                &store,
                &[rows::USER_INVITE_ROWS],
                10,
            )
            .expect_err("empty authority must fail");
        assert!(err.contains("authority"), "{err}");
    }

    #[test]
    fn user_invite_projector_rejects_unsigned_fact() {
        let user_invite = sample_fact();
        let fact = Fact::new(
            FactScope::Global,
            user_invite.created_at_ms,
            layout::encode_fact(&user_invite).expect("encode user_invite"),
        );

        let err = project::UserInviteProjector::new()
            .project(&fact, &ProjectionContext::new(Vec::new()))
            .expect_err("unsigned user_invite must fail");

        assert_eq!(err, "user_invite fact must be signed");
    }
}
