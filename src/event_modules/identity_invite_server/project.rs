//! Poc-10 invite-server projector.
//!
//! Invite-server grants follow user-invite authority: a workspace root may
//! bootstrap one directly, and later grants must be signed by an endpoint
//! whose user owns the named admin grant.

use crate::core::context::ContextNeed;
use crate::core::facts::{Fact, FactScope};
use crate::core::intents::AtomicIntent;
use crate::core::projection::{ProjectionContext, ProjectionOutput, Projector};
use crate::event_modules::identity_admin::layout as admin_layout;
use crate::event_modules::identity_endpoint_shared::layout as endpoint_shared_layout;
use crate::event_modules::identity_matchers;
use crate::event_modules::identity_workspace::layout as workspace_layout;
use crate::event_modules::signed_fact;

use super::layout;
use super::rows::invite_server_row;

#[derive(Debug, Clone, Default)]
pub struct InviteServerProjector;

impl InviteServerProjector {
    pub fn new() -> Self {
        Self
    }
}

impl Projector for InviteServerProjector {
    fn project(
        &self,
        fact: &Fact,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        if fact.scope != FactScope::Global {
            return Err("invite_server fact must have global scope".to_string());
        }
        let envelope = signed_fact::layout::decode_signed_fact(&fact.bytes)
            .map_err(|_| "invite_server fact must be signed".to_string())?;
        if envelope.inner_type != layout::TYPE_INVITE_SERVER {
            return Err("signed fact does not contain an invite_server".to_string());
        }
        let invite_server = layout::decode_fact(&envelope.payload)?;
        if invite_server.workspace_id == [0; 32] {
            return Err("invite_server fact has empty workspace_id".to_string());
        }
        if invite_server.authority_event_id == [0; 32] {
            return Err("invite_server fact has empty authority_event_id".to_string());
        }
        if invite_server.public_key == [0; 32] {
            return Err("invite_server fact has empty public_key".to_string());
        }
        let needs = authority_needs(fact.id, &invite_server, envelope.signer_id);
        let output = output_with_needs(&needs);
        if !has_all_context(&needs, context) {
            return Ok(output);
        }
        signed_fact::layout::verify_signed_fact(&envelope)?;
        validate_authority(&needs, &invite_server, &envelope, context)?;
        Ok(output
            .offer(identity_matchers::invite_server_offer(fact.id))
            .offer(identity_matchers::invite_server_key_offer(
                fact.id,
                invite_server.workspace_id,
                invite_server.public_key,
            ))
            .intent(
                AtomicIntent::PutRow(invite_server_row(fact.id, &invite_server)?).into_intent(),
            ))
    }
}

fn authority_needs(
    owner: [u8; 32],
    invite: &super::fact::InviteServerFact,
    signer_id: [u8; 32],
) -> Vec<ContextNeed> {
    if invite.authority_event_id == invite.workspace_id {
        vec![identity_matchers::exact_need(
            owner,
            identity_matchers::workspace_role(),
            invite.workspace_id,
        )]
    } else {
        vec![
            identity_matchers::exact_need(
                owner,
                identity_matchers::endpoint_shared_role(),
                signer_id,
            ),
            identity_matchers::exact_need(
                owner,
                identity_matchers::admin_role(),
                invite.authority_event_id,
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
    invite: &super::fact::InviteServerFact,
    envelope: &signed_fact::fact::SignedFactEnvelope,
    context: &ProjectionContext,
) -> Result<(), String> {
    if invite.authority_event_id == invite.workspace_id {
        if envelope.signer_id != invite.workspace_id {
            return Err(
                "bootstrap invite_server must use workspace as signer and authority".to_string(),
            );
        }
        let workspace_fact = context
            .payload_for(&needs[0])
            .expect("checked by has_all_context");
        if workspace_fact.id != invite.workspace_id {
            return Err("invite_server workspace context payload id mismatch".to_string());
        }
        let workspace = workspace_layout::decode_fact(&workspace_fact.bytes)
            .map_err(|_| "invite_server authority is not a workspace fact".to_string())?;
        if workspace.public_key != envelope.signer_public_key {
            return Err(
                "signed invite_server signer key does not match workspace public key".to_string(),
            );
        }
        return Ok(());
    }

    let endpoint_fact = context
        .payload_for(&needs[0])
        .expect("checked by has_all_context");
    if endpoint_fact.id != envelope.signer_id {
        return Err("invite_server signer endpoint context payload id mismatch".to_string());
    }
    let endpoint_envelope = signed_fact::layout::decode_signed_fact(&endpoint_fact.bytes)
        .map_err(|_| "invite_server signer must be workspace or endpoint_shared".to_string())?;
    if endpoint_envelope.inner_type != endpoint_shared_layout::TYPE_ENDPOINT_SHARED {
        return Err("invite_server signer must be workspace or endpoint_shared".to_string());
    }
    let endpoint = endpoint_shared_layout::decode_fact(&endpoint_envelope.payload)
        .map_err(|_| "invite_server signer must be workspace or endpoint_shared".to_string())?;
    if endpoint.signing_public_key != envelope.signer_public_key {
        return Err(
            "signed invite_server signer key does not match endpoint_shared signing key"
                .to_string(),
        );
    }
    if endpoint.workspace_id != invite.workspace_id {
        return Err("invite_server signer endpoint belongs to a different workspace".to_string());
    }

    let admin_fact = context
        .payload_for(&needs[1])
        .expect("checked by has_all_context");
    if admin_fact.id != invite.authority_event_id {
        return Err("invite_server admin context payload id mismatch".to_string());
    }
    let admin = decode_admin_payload(admin_fact)
        .map_err(|_| "invite_server authority must be an admin event".to_string())?;
    if admin.workspace_id != invite.workspace_id {
        return Err("invite_server admin authority belongs to a different workspace".to_string());
    }
    if endpoint.user_authority_event_id != admin.user_fact_id {
        return Err("invite_server signer user does not match admin authority user".to_string());
    }
    Ok(())
}

fn decode_admin_payload(
    fact: &Fact,
) -> Result<crate::event_modules::identity_admin::fact::AdminFact, String> {
    match fact.bytes.first().copied() {
        Some(admin_layout::TYPE_ADMIN) => admin_layout::decode_fact(&fact.bytes),
        Some(signed_fact::layout::TYPE_SIGNED_FACT) => {
            let envelope = signed_fact::layout::decode_signed_fact(&fact.bytes)?;
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
    use topo::core::projection::{MatchedContext, ProjectionContext, Projector};
    use topo::core::schema_dsl::EVENT_MODULES_SCHEMA_SOURCE;
    use topo::core::store::Store;
    use topo::core::wake_loop::WakeLoop;
    use topo::event_modules::identity_invite_server::fact::InviteServerFact;
    use topo::event_modules::identity_invite_server::{layout, project, rows};
    use topo::event_modules::identity_matchers as identity_context;
    use topo::event_modules::identity_workspace::{
        fact::WorkspaceFact, layout as workspace_layout,
    };
    use topo::event_modules::signed_fact;

    const WORKSPACE_PRIVATE_KEY: [u8; 32] = [9; 32];

    fn sample_fact() -> InviteServerFact {
        InviteServerFact {
            created_at_ms: 9,
            public_key: [1; 32],
            workspace_id: [2; 32],
            authority_event_id: [2; 32],
        }
    }

    #[test]
    fn invite_server_projector_materializes_row_through_atomic_intent() {
        let invite_server = sample_fact();
        let fact = signed_invite_server_fact(
            &invite_server,
            invite_server.workspace_id,
            WORKSPACE_PRIVATE_KEY,
        );
        let workspace_fact = workspace_fact(invite_server.workspace_id, WORKSPACE_PRIVATE_KEY);
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

        let output = project::InviteServerProjector::new()
            .project(&fact, &context)
            .expect("project invite_server");
        assert_eq!(output.needs.len(), 1);
        assert_eq!(output.intents.len(), 1);
        let row_intent = AtomicIntent::from_intent(&output.intents[0], &[rows::INVITE_SERVER_ROWS])
            .expect("row intent");
        let AtomicIntent::PutRow(stored) = row_intent else {
            panic!("expected put row");
        };
        let row = rows::decode_invite_server_row(&stored.key, &stored.value).expect("decode row");
        assert_eq!(row.workspace_id, [2; 32]);
        assert_eq!(row.invite_server_id, fact.id);
        assert_eq!(row.created_at_ms, 9);
        assert_eq!(row.public_key, [1; 32]);
        assert_eq!(row.authority_event_id, [2; 32]);
    }

    #[test]
    fn invite_server_projector_waits_for_workspace_authority() {
        let invite_server = sample_fact();
        let fact = signed_invite_server_fact(
            &invite_server,
            invite_server.workspace_id,
            WORKSPACE_PRIVATE_KEY,
        );

        let output = project::InviteServerProjector::new()
            .project(&fact, &ProjectionContext::new(Vec::new()))
            .expect("project waits");

        assert_eq!(output.needs.len(), 1);
        assert!(output.intents.is_empty());
        assert_eq!(output.needs[0].role, identity_context::workspace_role());
        assert_eq!(output.needs[0].selector.as_bytes(), &[2; 32]);
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

    fn signed_invite_server_fact(
        invite_server: &InviteServerFact,
        signer_id: [u8; 32],
        private_key: [u8; 32],
    ) -> Fact {
        let payload = layout::encode_fact(invite_server).expect("encode invite_server");
        let bytes = signed_fact::create::sign_payload_bytes(signer_id, &private_key, payload)
            .expect("sign invite_server");
        Fact::new(FactScope::Global, invite_server.created_at_ms, bytes)
    }

    #[test]
    fn invite_server_projector_rejects_empty_authority() {
        let mut invite_server = sample_fact();
        invite_server.authority_event_id = [0; 32];
        let fact = signed_invite_server_fact(&invite_server, [2; 32], WORKSPACE_PRIVATE_KEY);
        let store = Store::open_memory_with_schema_sources(&[EVENT_MODULES_SCHEMA_SOURCE])
            .expect("open target schema");
        let mut bus = WakeLoop::new();

        assert!(bus.submit_fact(fact));
        let err = bus
            .drain_applying_atomic_rows(
                &project::InviteServerProjector::new(),
                &[],
                &store,
                &[rows::INVITE_SERVER_ROWS],
                10,
            )
            .expect_err("empty authority must fail");
        assert!(err.contains("authority"), "{err}");
    }

    #[test]
    fn invite_server_projector_rejects_unsigned_fact() {
        let invite_server = sample_fact();
        let fact = Fact::new(
            FactScope::Global,
            invite_server.created_at_ms,
            layout::encode_fact(&invite_server).expect("encode invite_server"),
        );

        let err = project::InviteServerProjector::new()
            .project(&fact, &ProjectionContext::new(Vec::new()))
            .expect_err("unsigned invite_server must fail");

        assert_eq!(err, "invite_server fact must be signed");
    }
}
