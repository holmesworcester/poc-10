pub mod decode {
    //! Byte decoding for invite-server facts.
    //!
    //! Decoding proves only the fixed layout: tag, length, and field order. Id and
    //! id checks live in the local `authenticate` module.

    use crate::core::wire;

    use super::super::encode::{FACT_BYTES, TYPE_INVITE_SERVER};
    use super::super::fact::InviteServerFact;

    pub fn decode_fact(bytes: &[u8]) -> Result<InviteServerFact, String> {
        wire::expect_len(bytes, FACT_BYTES).map_err(wire_err)?;
        let tag = wire::take_u8(&bytes[0..1]).map_err(wire_err)?;
        if tag != TYPE_INVITE_SERVER {
            return Err("expected invite_server fact".to_string());
        }
        let created_at_ms = wire::take_u64be(&bytes[1..9]).map_err(wire_err)?;
        let mut public_key = [0; 32];
        public_key.copy_from_slice(&bytes[9..41]);
        let mut workspace_id = [0; 32];
        workspace_id.copy_from_slice(&bytes[41..73]);
        let mut authority_fact_id = [0; 32];
        authority_fact_id.copy_from_slice(&bytes[73..105]);
        let mut signer_id = [0; 32];
        signer_id.copy_from_slice(&bytes[105..137]);
        let mut signer_public_key = [0; 32];
        signer_public_key.copy_from_slice(&bytes[137..169]);
        Ok(InviteServerFact {
            created_at_ms,
            public_key,
            workspace_id,
            authority_fact_id,
            signer_id,
            signer_public_key,
        })
    }

    fn wire_err(err: wire::WireError) -> String {
        format!("{err:?}")
    }

    // Tests.
    // Ordered most-central-first: the roundtrip proves the full layout; narrower guards follow.
    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::protocol::auth::invite_server::encode::{encode_fact, FACT_BYTES};

        fn fact() -> InviteServerFact {
            InviteServerFact {
                created_at_ms: 9,
                public_key: [1; 32],
                workspace_id: [2; 32],
                authority_fact_id: [3; 32],
                signer_id: [3; 32],
                signer_public_key: [4; 32],
            }
        }

        #[test]
        fn invite_server_fact_roundtrips_fixed_width() {
            let encoded = encode_fact(&fact()).expect("encode");
            assert_eq!(encoded.len(), FACT_BYTES);
            assert_eq!(decode_fact(&encoded).expect("decode"), fact());
        }

        #[test]
        fn rejects_wrong_tag() {
            let mut encoded = encode_fact(&fact()).expect("encode");
            encoded[0] = 0;
            assert!(decode_fact(&encoded).is_err());
        }
    }
}
pub mod authenticate {
    //! Invite-server authenticator.
    //!
    //! POLICY. Authenticating an `invite_server` fact proves, over its bytes alone:
    //!   1. LAYOUT. The bytes decode to a canonical invite-server fact.
    //!   2. ID. The content id equals `hash(bytes)`.
    //!   3. SIGNATURE. The signer signature verifies over the canonical envelope;
    //!      the verifier key is embedded in the fact, so this needs no context.
    //!   4. FIELDS. The workspace, authority, and public-key selectors are non-zero.
    //!
    //! Scope (`Global`) and the authority path (bootstrap vs delegated grant) are
    //! interpretation the projector owns.

    use crate::core::facts::Fact;
    use crate::core::project_fact::{verify_fact_id, ProjectionContext};

    use super::super::fact::InviteServerFact;

    pub(crate) fn authenticate(
        fact: &Fact,
        invite_server: InviteServerFact,
        _context: &ProjectionContext,
    ) -> Result<InviteServerFact, String> {
        prove_decoded_invite_server(fact, invite_server)
    }

    fn prove_decoded_invite_server(
        fact: &Fact,
        invite_server: InviteServerFact,
    ) -> Result<InviteServerFact, String> {
        // 2. Id.
        verify_fact_id(fact)?;
        // 4. Non-zero selector fields.
        if invite_server.workspace_id == [0; 32] {
            return Err("invite_server fact has empty workspace_id".to_string());
        }
        if invite_server.authority_fact_id == [0; 32] {
            return Err("invite_server fact has empty authority_fact_id".to_string());
        }
        if invite_server.public_key == [0; 32] {
            return Err("invite_server fact has empty public_key".to_string());
        }
        Ok(invite_server)
    }

    // Tests.
    // Ordered most-central-first: canonical admit, then the id check, then layout guards.
    #[cfg(test)]
    mod tests {
        use crate::core::crypto;
        use crate::core::facts::Fact;
        use crate::core::project_fact::ProjectionContext;
        use crate::protocol::auth::invite_server::author::authored_invite_server_fact;
        use crate::protocol::auth::invite_server::fact::InviteServerFact;

        const SIGNER_KEY: [u8; 32] = [7; 32];

        fn canonical_fact() -> Fact {
            authored_invite_server_fact(
                100,
                [1; 32],
                [2; 32],
                [3; 32],
                [4; 32],
                crypto::ed25519_public_key(&SIGNER_KEY),
            )
            .expect("authored invite_server fact")
        }

        fn authenticate(fact: &Fact) -> Result<InviteServerFact, String> {
            let decoded = super::super::decode::decode_fact(fact.body())?;
            super::authenticate(fact, decoded, &ProjectionContext::default())
        }

        fn is_invalid(fact: &Fact) -> bool {
            authenticate(fact).is_err()
        }

        #[test]
        fn authenticates_canonical_fact() {
            assert!(authenticate(&canonical_fact()).is_ok());
        }

        #[test]
        fn rejects_id_not_matching_bytes() {
            let canonical = canonical_fact();
            let forged = Fact {
                id: [0; 32],
                scope: canonical.scope.clone(),
                timestamp: canonical.timestamp,
                bytes: canonical.bytes.clone(),
            };
            assert!(is_invalid(&forged));
        }

        #[test]
        fn rejects_wrong_tag() {
            let canonical = canonical_fact();
            let mut bytes = canonical.bytes.clone();
            bytes[0] ^= 0xff;
            assert!(is_invalid(&Fact::new(
                canonical.scope,
                canonical.timestamp,
                bytes
            )));
        }

        #[test]
        fn rejects_truncated_bytes() {
            let canonical = canonical_fact();
            let mut bytes = canonical.bytes.clone();
            bytes.pop();
            assert!(is_invalid(&Fact::new(
                canonical.scope,
                canonical.timestamp,
                bytes
            )));
        }
    }
}
pub mod adapt {
    //! Invite-server semantic adapter.
    //!
    //! The current invite_server wire shape is already the active semantic shape.
    //! This identity adapter keeps the protocol-local conversion point available for
    //! future versioned facts.

    use super::super::fact::InviteServerFact;

    pub(crate) fn adapt(source: InviteServerFact) -> Result<InviteServerFact, String> {
        Ok(source)
    }
}

// Poc-10 invite-server projector.
//
// POLICY. An invite_server grant is admitted iff:
//   1. STRUCTURAL. The fact is global, signed, contains an invite_server
//      payload, and all selector fields are non-zero.
//   2. AUTHORITY. Bootstrap grants require signature evidence from the workspace root;
//      delegated grants require signature evidence from an endpoint_shared fact whose user owns
//      the named admin grant in the same workspace.
//   3. MATERIALIZE. Once the authority path validates, write the invite_server
//      row, publish exact/key offers, and mark the fact shareable.

use crate::core::context::ContextNeed;
use crate::core::facts::{Fact, FactId, FactScope};
use crate::core::intents::RowMutation;
use crate::core::project_fact::{
    FactProjectorInfo, ProjectionContext, ProjectionOutput, Projector,
};
use crate::protocol::auth::invite_server::fact::InviteServerFact;
use crate::protocol::auth::{admin, endpoint_shared, signature, workspace};
use crate::protocol::sync::shared_fact::project::{context_have_from_needs, share_fact_with_sync};

use super::invite_server_row;

/// Projector route metadata for the invite_server fact.
pub const PROJECTOR_INFO: FactProjectorInfo =
    FactProjectorInfo::projector("auth::invite_server::project::InviteServerProjector");

pub const STORAGE_VERSION: u32 = crate::protocol::versioning::CURRENT_PROTOCOL_VERSION;
pub const STORAGE_REQUIREMENT: crate::core::effects::StorageRequirement =
    crate::core::effects::StorageRequirement::Current(STORAGE_VERSION);

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
        let decoded = decode::decode_fact(fact.body())?;
        let authenticated = authenticate::authenticate(fact, decoded, context)?;
        let semantic = adapt::adapt(authenticated)?;
        self.project_semantic(fact, semantic, context)
    }
}

impl InviteServerProjector {
    fn project_semantic(
        &self,
        fact: &Fact,
        invite_server: InviteServerFact,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        // 1. Scope.
        if fact.scope != FactScope::Global {
            return Err("invite_server fact must have global scope".to_string());
        }

        // 2. Authority.
        //
        // `authority_fact_id == workspace_id` is the bootstrap path: the
        // workspace root signs directly. Any other authority id selects the
        // delegated path, where an endpoint_shared signer must be backed by the
        // named admin grant.
        let signature_need = signature::project::signature_proof_need(
            fact.id,
            crate::protocol::auth::workspace::scope(invite_server.workspace_id),
            fact.id,
            invite_server.signer_public_key,
        )?;
        if !signature::project::signature_proof_ready(
            context,
            &signature_need,
            invite_server.workspace_id,
            fact.id,
            invite_server.signer_public_key,
            "invite_server",
        )? {
            return Ok(ProjectionOutput::new().need(signature_need));
        }

        if invite_server.authority_fact_id == invite_server.workspace_id {
            project_workspace_authorized(fact, &invite_server, context, signature_need)
        } else {
            project_endpoint_authorized(fact, &invite_server, context, signature_need)
        }
    }
}

fn project_workspace_authorized(
    fact: &Fact,
    invite: &InviteServerFact,
    context: &ProjectionContext,
    signature_need: ContextNeed,
) -> Result<ProjectionOutput, String> {
    let needs = WorkspaceAuthorityNeeds::new(fact.id, invite, signature_need);
    let Some(workspace_fact) = context.payload_for(&needs.workspace) else {
        return Ok(needs.output());
    };

    if invite.signer_id != invite.workspace_id {
        return Err(
            "bootstrap invite_server must use workspace as signer and authority".to_string(),
        );
    }
    if workspace_fact.id != invite.workspace_id {
        return Err("invite_server workspace context payload id mismatch".to_string());
    }
    let workspace = workspace::decode_fact_payload(workspace_fact.body())
        .map_err(|_| "invite_server authority is not a workspace fact".to_string())?;
    if workspace.public_key != invite.signer_public_key {
        return Err(
            "invite_server signature signer key does not match workspace public key".to_string(),
        );
    }
    let context_have = context_have_from_needs(context, [&needs.signature, &needs.workspace]);

    // 3. Materialize.
    materialized_output(fact, invite, ProjectionOutput::new(), context_have)
}

fn project_endpoint_authorized(
    fact: &Fact,
    invite: &InviteServerFact,
    context: &ProjectionContext,
    signature_need: ContextNeed,
) -> Result<ProjectionOutput, String> {
    let needs = EndpointAdminNeeds::new(fact.id, invite, invite.signer_id, signature_need);
    let Some(endpoint_fact) = context.payload_for(&needs.endpoint_shared) else {
        return Ok(needs.output());
    };
    let Some(admin_fact) = context.payload_for(&needs.admin) else {
        return Ok(needs.output());
    };

    if endpoint_fact.id != invite.signer_id {
        return Err("invite_server signer endpoint context payload id mismatch".to_string());
    }
    let endpoint = endpoint_shared::decode_fact_payload(endpoint_fact.body())
        .map_err(|_| "invite_server signer must be workspace or endpoint_shared".to_string())?;
    if endpoint.signing_public_key != invite.signer_public_key {
        return Err(
            "invite_server signature signer key does not match endpoint_shared signing key"
                .to_string(),
        );
    }
    if endpoint.workspace_id != invite.workspace_id {
        return Err("invite_server signer endpoint belongs to a different workspace".to_string());
    }

    if admin_fact.id != invite.authority_fact_id {
        return Err("invite_server admin context payload id mismatch".to_string());
    }
    let admin = decode_admin_payload(admin_fact)
        .map_err(|_| "invite_server authority must be an admin fact".to_string())?;
    if admin.workspace_id != invite.workspace_id {
        return Err("invite_server admin authority belongs to a different workspace".to_string());
    }
    if endpoint.user_authority_fact_id != admin.user_fact_id {
        return Err("invite_server signer user does not match admin authority user".to_string());
    }
    let context_have = context_have_from_needs(
        context,
        [&needs.signature, &needs.endpoint_shared, &needs.admin],
    );

    // 3. Materialize.
    materialized_output(fact, invite, ProjectionOutput::new(), context_have)
}

struct WorkspaceAuthorityNeeds {
    signature: ContextNeed,
    workspace: ContextNeed,
}

impl WorkspaceAuthorityNeeds {
    fn new(owner: FactId, invite: &InviteServerFact, signature: ContextNeed) -> Self {
        Self {
            signature,
            workspace: crate::core::context::ContextNeed::range(
                owner,
                "auth_workspace",
                crate::core::facts::FactScope::Global,
                invite.workspace_id,
                invite.workspace_id,
            ),
        }
    }

    fn output(&self) -> ProjectionOutput {
        ProjectionOutput::new()
            .need(self.signature.clone())
            .need(self.workspace.clone())
    }
}

struct EndpointAdminNeeds {
    signature: ContextNeed,
    endpoint_shared: ContextNeed,
    admin: ContextNeed,
}

impl EndpointAdminNeeds {
    fn new(
        owner: FactId,
        invite: &InviteServerFact,
        signer_id: FactId,
        signature: ContextNeed,
    ) -> Self {
        Self {
            signature,
            endpoint_shared: crate::core::context::ContextNeed::range(
                owner,
                "auth_endpoint_shared",
                crate::core::facts::FactScope::Global,
                signer_id,
                signer_id,
            ),
            admin: crate::core::context::ContextNeed::range(
                owner,
                "auth_admin",
                crate::core::facts::FactScope::Global,
                invite.authority_fact_id,
                invite.authority_fact_id,
            ),
        }
    }

    fn output(&self) -> ProjectionOutput {
        ProjectionOutput::new()
            .need(self.signature.clone())
            .need(self.endpoint_shared.clone())
            .need(self.admin.clone())
    }
}

fn materialized_output(
    fact: &Fact,
    invite: &InviteServerFact,
    output: ProjectionOutput,
    context_have: Vec<FactId>,
) -> Result<ProjectionOutput, String> {
    Ok(share_fact_with_sync(
        output
            .offer(crate::core::context::ContextOffer::range(
                fact.id,
                "auth_invite_server",
                crate::core::facts::FactScope::Global,
                fact.id,
                fact.id,
            ))
            .offer(crate::core::context::ContextOffer::range(
                fact.id,
                "auth_invite_server_key",
                crate::protocol::auth::workspace::scope(invite.workspace_id),
                invite.public_key.to_vec(),
                invite.public_key,
            ))
            .row_mutation(RowMutation::InsertValues(invite_server_row(
                fact.id, invite,
            ))),
        invite.workspace_id,
        fact,
        context_have,
    ))
}

fn decode_admin_payload(
    fact: &Fact,
) -> Result<crate::protocol::auth::admin::fact::AdminFact, String> {
    let admin = admin::decode_fact_payload(fact.body())?;
    Ok(admin)
}

// Tests.
//
// Invariants:
// - invite_server facts are global evidence for workspace invite-service
//   authority;
// - projection parks first on the exact signature proof for this server grant;
// - bootstrap grants require the workspace-root signature and matching
//   workspace payload;
// - materialization writes one server row, publishes id and public-key offers,
//   and shares only the validated signature/workspace context.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::context::ContextOffer;
    use crate::core::facts::FactScope;
    use crate::core::intents::RowMutation;
    use crate::core::project_fact::{MatchedContext, Projector};
    use crate::protocol::auth::workspace::author::create_workspace;
    use crate::protocol::sync::share_fact_with_sync::decode_share_fact_with_sync;

    const WORKSPACE_KEY: [u8; 32] = [9; 32];
    const SERVER_PUBLIC_KEY: [u8; 32] = [4; 32];

    #[test]
    fn bootstrap_invite_server_waits_for_signature_before_authority_context() {
        let (_workspace, server, _signature) = bootstrap_fixture();

        let output = InviteServerProjector::new()
            .project(&server, &ProjectionContext::default())
            .expect("project without context");

        let server_body = decode::decode_fact(server.body()).expect("decode server");
        assert_eq!(output.needs.len(), 1);
        assert_eq!(
            output.needs[0],
            signature::project::signature_proof_need(
                server.id,
                workspace::scope(server_body.workspace_id),
                server.id,
                server_body.signer_public_key,
            )
            .expect("signature need")
        );
        assert!(output.offers.is_empty());
        assert!(output.effects.row_mutations.is_empty());
    }

    #[test]
    fn bootstrap_invite_server_materializes_row_offers_and_sync_context() {
        let (workspace, server, signature) = bootstrap_fixture();

        let output = InviteServerProjector::new()
            .project(&server, &bootstrap_context(&workspace, &server, &signature))
            .expect("project with bootstrap context");

        assert!(output.needs.is_empty());
        assert_eq!(output.offers.len(), 2);
        assert!(output.offers.iter().any(|offer| {
            offer.role.as_str() == "auth_invite_server" && offer.scope == FactScope::Global
        }));
        assert!(output.offers.iter().any(|offer| {
            offer.role.as_str() == "auth_invite_server_key"
                && offer.scope == workspace::scope(workspace.id)
        }));
        assert_eq!(output.effects.row_mutations.len(), 1);
        assert!(matches!(
            &output.effects.row_mutations[0],
            RowMutation::InsertValues(insert) if insert.table == super::super::INVITE_SERVER_ROWS
        ));
        let share = decode_share_fact_with_sync(&output.effects.intents[0]).expect("share intent");
        assert_eq!(share.workspace_id, workspace.id);
        assert_eq!(share.owner_fact_id, server.id);
        assert_eq!(share.context_have, sorted_ids([workspace.id, signature.id]));
    }

    #[test]
    fn invite_server_projection_rejects_non_global_scope() {
        let (_workspace, server, _signature) = bootstrap_fixture();
        let non_global = Fact {
            scope: FactScope::Local,
            ..server
        };

        let err = InviteServerProjector::new()
            .project(&non_global, &ProjectionContext::default())
            .expect_err("local server grant should reject");

        assert!(err.contains("must have global scope"), "{err}");
    }

    fn bootstrap_fixture() -> (Fact, Fact, Fact) {
        let workspace = create_workspace(100, WORKSPACE_KEY, "Essay").expect("workspace");
        let signer_public_key = crate::core::crypto::ed25519_public_key(&WORKSPACE_KEY);
        let server = crate::protocol::auth::invite_server::author::authored_invite_server_fact(
            101,
            SERVER_PUBLIC_KEY,
            workspace.id,
            workspace.id,
            workspace.id,
            signer_public_key,
        )
        .expect("invite server");
        let signature =
            signature::author::create_signature(workspace.id, server.id, &WORKSPACE_KEY, 102)
                .expect("signature");
        (workspace, server, signature)
    }

    fn bootstrap_context(
        workspace_fact: &Fact,
        server: &Fact,
        signature_fact: &Fact,
    ) -> ProjectionContext {
        let server_body = decode::decode_fact(server.body()).expect("decode server");
        let signature_need = signature::project::signature_proof_need(
            server.id,
            workspace::scope(server_body.workspace_id),
            server.id,
            server_body.signer_public_key,
        )
        .expect("signature need");
        let workspace_need =
            WorkspaceAuthorityNeeds::new(server.id, &server_body, signature_need.clone()).workspace;
        ProjectionContext::from_matches(vec![
            MatchedContext {
                need: signature_need,
                offer: signature::project::signature_proof_offer(
                    signature_fact.id,
                    workspace::scope(server_body.workspace_id),
                    server.id,
                    server_body.signer_public_key,
                )
                .expect("signature offer"),
                payload: signature_fact.clone(),
            },
            MatchedContext {
                need: workspace_need,
                offer: ContextOffer::range(
                    workspace_fact.id,
                    "auth_workspace",
                    FactScope::Global,
                    workspace_fact.id,
                    workspace_fact.id,
                ),
                payload: workspace_fact.clone(),
            },
        ])
    }

    fn sorted_ids(ids: impl IntoIterator<Item = FactId>) -> Vec<FactId> {
        let mut ids = ids.into_iter().collect::<Vec<_>>();
        ids.sort();
        ids
    }
}
