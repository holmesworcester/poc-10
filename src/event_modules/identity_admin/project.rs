//! Poc-10 admin grant projector.
//!
//! Admin grants are signed. Bootstrap grants must be signed by the workspace
//! root; ongoing grants must be signed by the authority admin named in the
//! payload and must target a user in the same workspace.

use crate::core::context::ContextNeed;
use crate::core::facts::{Fact, FactScope};
use crate::core::intents::AtomicIntent;
use crate::core::projection::{ProjectionContext, ProjectionOutput, Projector};
use crate::event_modules::identity_matchers;
use crate::event_modules::identity_user::layout as user_layout;
use crate::event_modules::identity_workspace::layout as workspace_layout;
use crate::event_modules::signed_fact;

use super::layout;
use super::rows::admin_row;

#[derive(Debug, Clone, Default)]
pub struct AdminProjector;

impl AdminProjector {
    pub fn new() -> Self {
        Self
    }
}

impl Projector for AdminProjector {
    fn project(
        &self,
        fact: &Fact,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        if fact.scope != FactScope::Global {
            return Err("admin fact must have global scope".to_string());
        }
        let envelope = signed_fact::layout::decode_signed_fact(&fact.bytes)
            .map_err(|_| "admin fact must be signed".to_string())?;
        if envelope.inner_type != layout::TYPE_ADMIN {
            return Err("signed fact does not contain an admin".to_string());
        }
        let admin = layout::decode_fact(&envelope.payload)?;
        if admin.workspace_id == [0u8; 32] {
            return Err("admin workspace_id must not be zero".to_string());
        }
        if admin.public_key == [0u8; 32] {
            return Err("admin public_key must not be zero".to_string());
        }
        if admin.authority_fact_id == [0u8; 32] {
            return Err("admin authority_fact_id must not be zero".to_string());
        }
        if admin.user_fact_id == [0u8; 32] {
            return Err("admin user_fact_id must not be zero".to_string());
        }
        let needs = authority_needs(fact.id, &admin);
        let output = output_with_needs(&needs);
        if !has_all_context(&needs, context) {
            return Ok(output);
        }
        signed_fact::layout::verify_signed_fact(&envelope)?;
        validate_authority(&needs, &admin, &envelope, context)?;
        Ok(output
            .offer(identity_matchers::exact_offer(
                fact.id,
                identity_matchers::admin_role(),
            ))
            .intent(AtomicIntent::PutRow(admin_row(fact.id, &admin)?).into_intent()))
    }
}

fn authority_needs(owner: [u8; 32], admin: &super::fact::AdminFact) -> Vec<ContextNeed> {
    let workspace_need = identity_matchers::exact_need(
        owner,
        identity_matchers::workspace_role(),
        admin.workspace_id,
    );
    if admin.authority_fact_id == admin.workspace_id {
        vec![workspace_need]
    } else {
        vec![
            workspace_need,
            identity_matchers::exact_need(
                owner,
                identity_matchers::admin_role(),
                admin.authority_fact_id,
            ),
            identity_matchers::exact_need(
                owner,
                identity_matchers::user_role(),
                admin.user_fact_id,
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
    admin: &super::fact::AdminFact,
    envelope: &signed_fact::fact::SignedFactEnvelope,
    context: &ProjectionContext,
) -> Result<(), String> {
    let workspace_need = &needs[0];
    let workspace_fact = context
        .payload_for(workspace_need)
        .expect("checked by has_all_context");
    if workspace_fact.id != admin.workspace_id {
        return Err("admin workspace context payload id mismatch".to_string());
    }
    let workspace = workspace_layout::decode_fact(&workspace_fact.bytes)
        .map_err(|_| "admin workspace dependency must be a workspace fact".to_string())?;

    if admin.authority_fact_id == admin.workspace_id {
        if envelope.signer_id != admin.workspace_id {
            return Err("bootstrap admin must use workspace as signer and authority".to_string());
        }
        if admin.user_fact_id != admin.workspace_id {
            return Err("workspace admin authority can only bootstrap root admin".to_string());
        }
        if envelope.signer_public_key != workspace.public_key {
            return Err(
                "signed bootstrap admin signer key does not match workspace public key".to_string(),
            );
        }
        if admin.public_key != workspace.public_key {
            return Err("admin public_key does not match root workspace public_key".to_string());
        }
        return Ok(());
    }
    if envelope.signer_id != admin.authority_fact_id {
        return Err("signed admin grant signer must be the authority admin".to_string());
    }

    let authority_need = &needs[1];
    let authority_fact = context
        .payload_for(authority_need)
        .expect("checked by has_all_context");
    if authority_fact.id != admin.authority_fact_id {
        return Err("admin authority context payload id mismatch".to_string());
    }
    let authority = decode_admin_payload(authority_fact)
        .map_err(|_| "signed admin authority must be an admin event".to_string())?;
    if authority.workspace_id != admin.workspace_id {
        return Err("admin authority belongs to a different workspace".to_string());
    }
    if envelope.signer_public_key != authority.public_key {
        return Err("signed admin signer key does not match authority admin".to_string());
    }

    let user_need = &needs[2];
    let user_fact = context
        .payload_for(user_need)
        .expect("checked by has_all_context");
    if user_fact.id != admin.user_fact_id {
        return Err("admin user context payload id mismatch".to_string());
    }
    let user = decode_user_payload(user_fact)
        .map_err(|_| "admin user dependency must be a user event".to_string())?;
    if user.workspace_id != admin.workspace_id {
        return Err("admin user belongs to a different workspace".to_string());
    }
    if user.public_key != admin.public_key {
        return Err("admin public_key does not match user public_key".to_string());
    }
    Ok(())
}

fn decode_admin_payload(fact: &Fact) -> Result<super::fact::AdminFact, String> {
    match fact.bytes.first().copied() {
        Some(layout::TYPE_ADMIN) => layout::decode_fact(&fact.bytes),
        Some(signed_fact::layout::TYPE_SIGNED_FACT) => {
            let envelope = signed_fact::layout::decode_signed_fact(&fact.bytes)?;
            if envelope.inner_type != layout::TYPE_ADMIN {
                return Err("expected signed admin".to_string());
            }
            layout::decode_fact(&envelope.payload)
        }
        _ => Err("expected admin".to_string()),
    }
}

fn decode_user_payload(
    fact: &Fact,
) -> Result<crate::event_modules::identity_user::fact::UserFact, String> {
    match fact.bytes.first().copied() {
        Some(user_layout::TYPE_USER) => user_layout::decode_fact(&fact.bytes),
        Some(signed_fact::layout::TYPE_SIGNED_FACT) => {
            let envelope = signed_fact::layout::decode_signed_fact(&fact.bytes)?;
            if envelope.inner_type != user_layout::TYPE_USER {
                return Err("expected signed user".to_string());
            }
            user_layout::decode_fact(&envelope.payload)
        }
        _ => Err("expected user".to_string()),
    }
}

#[cfg(test)]
mod projector_tests {
    use crate as topo;

    use topo::core::crypto;
    use topo::core::facts::{Fact, FactScope};
    use topo::core::intents::AtomicIntent;
    use topo::core::projection::{MatchedContext, ProjectionContext, Projector};
    use topo::core::schema_dsl::EVENT_MODULES_SCHEMA_SOURCE;
    use topo::core::store::Store;
    use topo::core::wake_loop::WakeLoop;
    use topo::event_modules::identity_admin::fact::AdminFact;
    use topo::event_modules::identity_admin::{layout, project, rows};
    use topo::event_modules::identity_matchers as identity_context;
    use topo::event_modules::identity_workspace::{
        fact::WorkspaceFact, layout as workspace_layout,
    };
    use topo::event_modules::signed_fact;

    const WORKSPACE_PRIVATE_KEY: [u8; 32] = [7; 32];

    #[test]
    fn admin_projector_materializes_row_through_atomic_intent() {
        let admin = AdminFact {
            created_at_ms: 200,
            workspace_id: [2; 32],
            public_key: crypto::ed25519_public_key(&WORKSPACE_PRIVATE_KEY),
            authority_fact_id: [2; 32],
            user_fact_id: [2; 32],
        };
        let fact = signed_admin_fact(&admin, admin.workspace_id, WORKSPACE_PRIVATE_KEY);
        let workspace_fact = workspace_fact(admin.workspace_id, admin.public_key);
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

        let output = project::AdminProjector::new()
            .project(&fact, &context)
            .expect("project admin");
        assert_eq!(output.needs.len(), 1);
        assert_eq!(output.intents.len(), 1);
        let row_intent =
            AtomicIntent::from_intent(&output.intents[0], &[rows::ADMIN_ROWS]).expect("row intent");
        let AtomicIntent::PutRow(stored) = row_intent else {
            panic!("expected put row");
        };
        let row = rows::decode_admin_row(&stored.key, &stored.value).expect("decode row");
        assert_eq!(row.workspace_id, [2; 32]);
        assert_eq!(row.admin_id, fact.id);
        assert_eq!(row.created_at_ms, 200);
        assert_eq!(
            row.public_key,
            crypto::ed25519_public_key(&WORKSPACE_PRIVATE_KEY)
        );
        assert_eq!(row.authority_fact_id, [2; 32]);
        assert_eq!(row.user_fact_id, [2; 32]);
    }

    #[test]
    fn admin_projector_waits_for_workspace_context() {
        let admin = AdminFact {
            created_at_ms: 200,
            workspace_id: [2; 32],
            public_key: crypto::ed25519_public_key(&WORKSPACE_PRIVATE_KEY),
            authority_fact_id: [2; 32],
            user_fact_id: [2; 32],
        };
        let fact = signed_admin_fact(&admin, admin.workspace_id, WORKSPACE_PRIVATE_KEY);

        let output = project::AdminProjector::new()
            .project(&fact, &ProjectionContext::new(Vec::new()))
            .expect("project waits");

        assert_eq!(output.needs.len(), 1);
        assert!(output.intents.is_empty());
        assert_eq!(output.needs[0].role, identity_context::workspace_role());
        assert_eq!(output.needs[0].selector.as_bytes(), &[2; 32]);
    }

    fn workspace_fact(workspace_id: [u8; 32], public_key: [u8; 32]) -> Fact {
        Fact {
            id: workspace_id,
            scope: FactScope::Global,
            timestamp: 1,
            bytes: workspace_layout::encode_fact(&WorkspaceFact {
                created_at_ms: 1,
                public_key,
                name: "Workspace".to_string(),
            })
            .expect("encode workspace"),
        }
    }

    fn signed_admin_fact(admin: &AdminFact, signer_id: [u8; 32], private_key: [u8; 32]) -> Fact {
        let payload = layout::encode_fact(admin).expect("encode admin");
        let bytes = signed_fact::create::sign_payload_bytes(signer_id, &private_key, payload)
            .expect("sign admin");
        Fact::new(FactScope::Global, admin.created_at_ms, bytes)
    }

    #[test]
    fn admin_projector_rejects_zero_workspace_id() {
        let admin = AdminFact {
            created_at_ms: 1,
            workspace_id: [0; 32],
            public_key: [7; 32],
            authority_fact_id: [1; 32],
            user_fact_id: [1; 32],
        };
        let fact = signed_admin_fact(&admin, [1; 32], WORKSPACE_PRIVATE_KEY);
        let store = Store::open_memory_with_schema_sources(&[EVENT_MODULES_SCHEMA_SOURCE])
            .expect("open target schema");
        let mut bus = WakeLoop::new();

        assert!(bus.submit_fact(fact));
        let err = bus
            .drain_applying_atomic_rows(
                &project::AdminProjector::new(),
                &[],
                &store,
                &[rows::ADMIN_ROWS],
                10,
            )
            .expect_err("zero workspace_id must fail");
        assert!(err.contains("workspace_id"), "{err}");
    }

    #[test]
    fn admin_projector_rejects_unsigned_admin_fact() {
        let admin = AdminFact {
            created_at_ms: 1,
            workspace_id: [2; 32],
            public_key: crypto::ed25519_public_key(&WORKSPACE_PRIVATE_KEY),
            authority_fact_id: [2; 32],
            user_fact_id: [2; 32],
        };
        let fact = Fact::new(
            FactScope::Global,
            admin.created_at_ms,
            layout::encode_fact(&admin).expect("encode admin"),
        );

        let err = project::AdminProjector::new()
            .project(&fact, &ProjectionContext::new(Vec::new()))
            .expect_err("unsigned admin must fail");

        assert_eq!(err, "admin fact must be signed");
    }
}
