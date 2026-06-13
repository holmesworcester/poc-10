pub mod decode {
    //! Byte decoding for user-invite facts.
    //!
    //! Decoding proves only the fixed layout: tag, length, and field order. Id and
    //! id checks live in the local `authenticate` module.

    use crate::core::wire;

    use super::super::encode::{FACT_BYTES, TYPE_USER_INVITE};
    use super::super::fact::UserInviteFact;

    pub fn decode_fact(bytes: &[u8]) -> Result<UserInviteFact, String> {
        wire::expect_len(bytes, FACT_BYTES).map_err(wire_err)?;
        let tag = wire::take_u8(&bytes[0..1]).map_err(wire_err)?;
        if tag != TYPE_USER_INVITE {
            return Err("expected user_invite fact".to_string());
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
        Ok(UserInviteFact {
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

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::protocol::auth::user_invite::encode::{encode_fact, FACT_BYTES};

        fn fact() -> UserInviteFact {
            UserInviteFact {
                created_at_ms: 5,
                public_key: [1; 32],
                workspace_id: [2; 32],
                authority_fact_id: [3; 32],
                signer_id: [3; 32],
                signer_public_key: [4; 32],
            }
        }

        #[test]
        fn user_invite_fact_roundtrips_fixed_width() {
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
    //! User-invite authenticator.
    //!
    //! POLICY. Authenticating a `user_invite` fact proves, over its canonical bytes
    //! alone:
    //!   1. LAYOUT. The bytes decode to a canonical user_invite fact.
    //!   2. ID. The content id equals `hash(bytes)`.
    //!   3. SIGNATURE. The signer signature verifies over the canonical envelope;
    //!      the verifier key is embedded in the fact, so this needs no context.
    //!   4. FIELDS. The workspace, authority, and public-key selectors are non-zero.
    //!
    //! Admission scope (`Global`) is unsigned local metadata, so the projector
    //! checks it. The authority path (bootstrap vs delegated grant) is proven from
    //! other facts, also in the projector.

    use crate::core::facts::Fact;
    use crate::core::project_fact::{verify_fact_id, ProjectionContext};

    use super::super::fact::UserInviteFact;

    pub(crate) fn authenticate(
        fact: &Fact,
        user_invite: UserInviteFact,
        _context: &ProjectionContext,
    ) -> Result<UserInviteFact, String> {
        prove_decoded_user_invite(fact, user_invite)
    }

    fn prove_decoded_user_invite(
        fact: &Fact,
        user_invite: UserInviteFact,
    ) -> Result<UserInviteFact, String> {
        // 2. Id.
        verify_fact_id(fact)?;
        // 4. Non-zero selector fields.
        if user_invite.workspace_id == [0; 32] {
            return Err("user_invite fact has empty workspace_id".to_string());
        }
        if user_invite.authority_fact_id == [0; 32] {
            return Err("user_invite fact has empty authority_fact_id".to_string());
        }
        if user_invite.public_key == [0; 32] {
            return Err("user_invite fact has empty public_key".to_string());
        }
        Ok(user_invite)
    }

    #[cfg(test)]
    mod tests {
        use crate::core::facts::Fact;
        use crate::core::project_fact::ProjectionContext;
        use crate::protocol::auth::user_invite::author::authored_user_invite_fact;
        use crate::protocol::auth::user_invite::fact::UserInviteFact;

        const SIGNER_KEY: [u8; 32] = [7; 32];

        fn canonical_fact() -> Fact {
            authored_user_invite_fact(100, [1; 32], [2; 32], [3; 32], [4; 32], SIGNER_KEY)
                .expect("authored user_invite fact")
        }

        fn authenticate(fact: &Fact) -> Result<UserInviteFact, String> {
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
    }
}
pub mod adapt {
    //! User-invite semantic adapter.
    //!
    //! The current user_invite wire shape is already the active semantic shape.
    //! This identity adapter keeps the protocol-local conversion point available for
    //! future versioned facts.

    use super::super::fact::UserInviteFact;

    pub(crate) fn adapt(source: UserInviteFact) -> Result<UserInviteFact, String> {
        Ok(source)
    }
}

// Poc-10 user-invite projector.
//
// POLICY. A user_invite is admitted iff:
//   1. STRUCTURAL. The fact is global, signed, contains a user_invite payload,
//      and all selector fields are non-zero.
//   2. AUTHORITY. Bootstrap invites require signature evidence from the workspace root;
//      delegated invites require signature evidence from an endpoint_shared fact whose user owns
//      the named admin grant in the same workspace.
//   3. MATERIALIZE. Once the authority path validates, write the user_invite
//      row, publish exact/key offers, and mark the fact shareable.

use crate::core::context::ContextNeed;
use crate::core::facts::{Fact, FactId, FactScope};
use crate::core::intents::RowMutation;
use crate::core::project_fact::{
    FactProjectorInfo, ProjectionContext, ProjectionOutput, Projector,
};
use crate::protocol::auth::user_invite::fact::UserInviteFact;
use crate::protocol::auth::{admin, endpoint_shared, signature, workspace};
use crate::protocol::sync::shared_fact::project::{context_have_from_needs, share_fact_with_sync};

use super::user_invite_row;

/// Projector route metadata for the user_invite fact.
pub const PROJECTOR_INFO: FactProjectorInfo =
    FactProjectorInfo::projector("auth::user_invite::project::UserInviteProjector");

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
        let decoded = decode::decode_fact(fact.body())?;
        let authenticated = authenticate::authenticate(fact, decoded, context)?;
        let semantic = adapt::adapt(authenticated)?;
        self.project_semantic(fact, semantic, context)
    }
}

impl UserInviteProjector {
    fn project_semantic(
        &self,
        fact: &Fact,
        user_invite: UserInviteFact,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        // 1. Structural.
        if fact.scope != FactScope::Global {
            return Err("user_invite fact must have global scope".to_string());
        }

        // 2. Authority.
        //
        // `authority_fact_id == workspace_id` is the bootstrap path: the
        // workspace root signs directly. Any other authority id selects the
        // delegated path, where an endpoint_shared signer must be backed by the
        // named admin grant.
        let signature_need = signature::project::signature_proof_need(
            fact.id,
            crate::protocol::auth::workspace::scope(user_invite.workspace_id),
            fact.id,
            user_invite.signer_public_key,
        )?;
        if !signature::project::signature_proof_ready(
            context,
            &signature_need,
            user_invite.workspace_id,
            fact.id,
            user_invite.signer_public_key,
            "user_invite",
        )? {
            return Ok(ProjectionOutput::new().need(signature_need));
        }

        if user_invite.authority_fact_id == user_invite.workspace_id {
            project_workspace_authorized(fact, &user_invite, context, signature_need)
        } else {
            project_endpoint_authorized(fact, &user_invite, context, signature_need)
        }
    }
}

fn project_workspace_authorized(
    fact: &Fact,
    invite: &UserInviteFact,
    context: &ProjectionContext,
    signature_need: ContextNeed,
) -> Result<ProjectionOutput, String> {
    let needs = WorkspaceAuthorityNeeds::new(fact.id, invite, signature_need);
    let Some(workspace_fact) = context.payload_for(&needs.workspace) else {
        return Ok(needs.output());
    };

    if invite.signer_id != invite.workspace_id {
        return Err("bootstrap user_invite must use workspace as signer and authority".to_string());
    }
    if workspace_fact.id != invite.workspace_id {
        return Err("user_invite workspace context payload id mismatch".to_string());
    }
    let workspace = workspace::decode_fact_payload(workspace_fact.body())
        .map_err(|_| "user_invite authority is not a workspace fact".to_string())?;
    if workspace.public_key != invite.signer_public_key {
        return Err(
            "user_invite signature signer key does not match workspace public key".to_string(),
        );
    }
    let context_have = context_have_from_needs(context, [&needs.signature, &needs.workspace]);

    // 3. Materialize.
    materialized_output(fact, invite, needs.output(), context_have)
}

fn project_endpoint_authorized(
    fact: &Fact,
    invite: &UserInviteFact,
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
        return Err("user_invite signer endpoint context payload id mismatch".to_string());
    }
    let endpoint = endpoint_shared::decode_fact_payload(endpoint_fact.body())
        .map_err(|_| "user_invite signer must be workspace or endpoint_shared".to_string())?;
    if endpoint.signing_public_key != invite.signer_public_key {
        return Err(
            "user_invite signature signer key does not match endpoint_shared signing key"
                .to_string(),
        );
    }
    if endpoint.workspace_id != invite.workspace_id {
        return Err("user_invite signer endpoint belongs to a different workspace".to_string());
    }

    if admin_fact.id != invite.authority_fact_id {
        return Err("user_invite admin context payload id mismatch".to_string());
    }
    let admin = decode_admin_payload(admin_fact)
        .map_err(|_| "user_invite authority must be an admin fact".to_string())?;
    if admin.workspace_id != invite.workspace_id {
        return Err("user_invite admin authority belongs to a different workspace".to_string());
    }
    if endpoint.user_authority_fact_id != admin.user_fact_id {
        return Err("user_invite signer user does not match admin authority user".to_string());
    }
    let context_have = context_have_from_needs(
        context,
        [&needs.signature, &needs.endpoint_shared, &needs.admin],
    );

    // 3. Materialize.
    materialized_output(fact, invite, needs.output(), context_have)
}

struct WorkspaceAuthorityNeeds {
    signature: ContextNeed,
    workspace: ContextNeed,
}

impl WorkspaceAuthorityNeeds {
    fn new(owner: FactId, invite: &UserInviteFact, signature: ContextNeed) -> Self {
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
        invite: &UserInviteFact,
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
    invite: &UserInviteFact,
    output: ProjectionOutput,
    context_have: Vec<FactId>,
) -> Result<ProjectionOutput, String> {
    Ok(share_fact_with_sync(
        output
            .offer(crate::core::context::ContextOffer::range(
                fact.id,
                "auth_user_invite",
                crate::core::facts::FactScope::Global,
                fact.id,
                fact.id,
            ))
            .offer(crate::core::context::ContextOffer::range(
                fact.id,
                "auth_user_invite_key",
                crate::protocol::auth::workspace::scope(invite.workspace_id),
                invite.public_key.to_vec(),
                invite.public_key,
            ))
            .row_mutation(RowMutation::PutRow(user_invite_row(fact.id, invite)?)),
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
