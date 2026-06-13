pub mod decode {
    //! Byte decoding for device-invite facts.
    //!
    //! Decoding proves only the fixed layout: tag, length, and field order. Id and
    //! id checks live in the local `authenticate` module.

    use crate::core::wire;

    use super::super::encode::{FACT_BYTES, TYPE_DEVICE_INVITE};
    use super::super::fact::DeviceInviteFact;

    pub fn decode_fact(bytes: &[u8]) -> Result<DeviceInviteFact, String> {
        wire::expect_len(bytes, FACT_BYTES).map_err(wire_err)?;
        let tag = wire::take_u8(&bytes[0..1]).map_err(wire_err)?;
        if tag != TYPE_DEVICE_INVITE {
            return Err("expected device_invite fact".to_string());
        }
        let created_at_ms = wire::take_u64be(&bytes[1..9]).map_err(wire_err)?;
        let mut workspace_id = [0; 32];
        workspace_id.copy_from_slice(&bytes[9..41]);
        let mut user_authority_fact_id = [0; 32];
        user_authority_fact_id.copy_from_slice(&bytes[41..73]);
        let mut user_invite_raw = [0; 32];
        user_invite_raw.copy_from_slice(&bytes[73..105]);
        let user_invite_fact_id = if user_invite_raw == [0; 32] {
            None
        } else {
            Some(user_invite_raw)
        };
        let mut public_key = [0; 32];
        public_key.copy_from_slice(&bytes[105..137]);
        let mut signer_id = [0; 32];
        signer_id.copy_from_slice(&bytes[137..169]);
        let mut signer_public_key = [0; 32];
        signer_public_key.copy_from_slice(&bytes[169..201]);
        Ok(DeviceInviteFact {
            created_at_ms,
            workspace_id,
            user_authority_fact_id,
            user_invite_fact_id,
            public_key,
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
        use crate::protocol::auth::device_invite::encode::{encode_fact, FACT_BYTES};

        fn fact() -> DeviceInviteFact {
            DeviceInviteFact {
                created_at_ms: 11,
                workspace_id: [1; 32],
                user_authority_fact_id: [2; 32],
                user_invite_fact_id: Some([4; 32]),
                public_key: [3; 32],
                signer_id: [2; 32],
                signer_public_key: [5; 32],
            }
        }

        #[test]
        fn device_invite_fact_roundtrips_fixed_width() {
            let encoded = encode_fact(&fact()).expect("encode");
            assert_eq!(encoded.len(), FACT_BYTES);
            assert_eq!(decode_fact(&encoded).expect("decode"), fact());
        }

        #[test]
        fn zero_user_invite_roundtrips_as_none() {
            let fact = DeviceInviteFact {
                user_invite_fact_id: None,
                ..fact()
            };
            let encoded = encode_fact(&fact).expect("encode");
            assert_eq!(decode_fact(&encoded).expect("decode"), fact);
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
    //! Device-invite authenticator.
    //!
    //! POLICY. Authenticating a `device_invite` fact proves, over its bytes alone:
    //!   1. LAYOUT. The bytes decode to a canonical device-invite fact.
    //!   2. ID. The content id equals `hash(bytes)`.
    //!   3. SIGNATURE. The signer signature verifies over the canonical envelope;
    //!      the verifier key is embedded in the fact, so this needs no context.
    //!   4. FIELDS. The workspace, user-authority, and public-key selectors are
    //!      non-zero.
    //!
    //! Scope (`Global`) and the authority path (user-signed vs endpoint-signed) are
    //! interpretation the projector owns.

    use crate::core::facts::Fact;
    use crate::core::project_fact::{verify_fact_id, ProjectionContext};

    use super::super::fact::DeviceInviteFact;

    pub(crate) fn authenticate(
        fact: &Fact,
        device_invite: DeviceInviteFact,
        _context: &ProjectionContext,
    ) -> Result<DeviceInviteFact, String> {
        prove_decoded_device_invite(fact, device_invite)
    }

    fn prove_decoded_device_invite(
        fact: &Fact,
        device_invite: DeviceInviteFact,
    ) -> Result<DeviceInviteFact, String> {
        // 2. Id.
        verify_fact_id(fact)?;
        // 4. Non-zero selector fields.
        if device_invite.workspace_id == [0; 32] {
            return Err("device_invite fact has empty workspace_id".to_string());
        }
        if device_invite.user_authority_fact_id == [0; 32] {
            return Err("device_invite fact has empty user_authority_fact_id".to_string());
        }
        if device_invite.public_key == [0; 32] {
            return Err("device_invite fact has empty public_key".to_string());
        }
        Ok(device_invite)
    }

    #[cfg(test)]
    mod tests {
        use crate::core::facts::Fact;
        use crate::core::project_fact::ProjectionContext;
        use crate::protocol::auth::device_invite::author::authored_device_invite_fact;
        use crate::protocol::auth::device_invite::fact::DeviceInviteFact;

        const SIGNER_KEY: [u8; 32] = [7; 32];

        fn canonical_fact() -> Fact {
            authored_device_invite_fact(100, [1; 32], [2; 32], None, [3; 32], [4; 32], SIGNER_KEY)
                .expect("signed device_invite fact")
        }

        fn authenticate(fact: &Fact) -> Result<DeviceInviteFact, String> {
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
    //! Device-invite semantic adapter.
    //!
    //! The current device_invite wire shape is already the active semantic shape.
    //! This identity adapter keeps the protocol-local conversion point available for
    //! future versioned facts.

    use super::super::fact::DeviceInviteFact;

    pub(crate) fn adapt(source: DeviceInviteFact) -> Result<DeviceInviteFact, String> {
        Ok(source)
    }
}

// Poc-10 device-invite projector.
//
// POLICY. A device_invite is admitted iff:
//   1. STRUCTURAL. The outer fact is global, carries signer identity, contains a device_invite,
//      and all selector fields are non-zero.
//   2. AUTHORITY. The invite follows one of two named authority paths:
//      user-authorized invites require workspace, user, and user_invite context;
//      endpoint-authorized invites require workspace and endpoint_shared context.
//   3. MATERIALIZE. Once the path validates, write the row, publish exact/key
//      offers, and mark the fact shareable with the workspace.

use crate::core::context::ContextNeed;
use crate::core::facts::{Fact, FactId, FactScope};
use crate::core::intents::RowMutation;
use crate::core::project_fact::{
    FactProjectorInfo, ProjectionContext, ProjectionOutput, Projector,
};
use crate::protocol::auth::device_invite::fact::DeviceInviteFact;
use crate::protocol::auth::{endpoint_shared, signature, user, user_invite, workspace};
use crate::protocol::sync::shared_fact::project::{context_have_from_needs, share_fact_with_sync};

use super::device_invite_row;

/// Projector route metadata for the device_invite fact.
pub const PROJECTOR_INFO: FactProjectorInfo =
    FactProjectorInfo::projector("auth::device_invite::project::DeviceInviteProjector");

#[derive(Debug, Clone, Default)]
pub struct DeviceInviteProjector;

impl DeviceInviteProjector {
    pub fn new() -> Self {
        Self
    }
}

impl Projector for DeviceInviteProjector {
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

impl DeviceInviteProjector {
    fn project_semantic(
        &self,
        fact: &Fact,
        device_invite: DeviceInviteFact,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        // 1. Scope.
        if fact.scope != FactScope::Global {
            return Err("device_invite fact must have global scope".to_string());
        }

        // 2. Authority.
        //
        // `user_invite_fact_id` is the authority-chain discriminator:
        // Some(id) means the device invite must be authorized by the user fact
        // authorized by that user_invite; None means it must be authorized by an
        // already-trusted endpoint_shared fact for the same user/workspace.
        let signature_need = signature::project::signature_proof_need(
            fact.id,
            crate::protocol::auth::workspace::scope(device_invite.workspace_id),
            fact.id,
            device_invite.signer_public_key,
        )?;
        if !signature::project::signature_proof_ready(
            context,
            &signature_need,
            device_invite.workspace_id,
            fact.id,
            device_invite.signer_public_key,
            "device_invite",
        )? {
            return Ok(ProjectionOutput::new().need(signature_need));
        }

        match device_invite.user_invite_fact_id {
            Some(user_invite_fact_id) => project_user_authorized(
                fact,
                &device_invite,
                user_invite_fact_id,
                context,
                signature_need,
            ),
            None => project_endpoint_authorized(fact, &device_invite, context, signature_need),
        }
    }
}

fn project_user_authorized(
    fact: &Fact,
    invite: &DeviceInviteFact,
    user_invite_fact_id: FactId,
    context: &ProjectionContext,
    signature_need: ContextNeed,
) -> Result<ProjectionOutput, String> {
    let needs = UserAuthorityNeeds::new(fact.id, invite, user_invite_fact_id, signature_need);
    let Some(workspace_fact) = context.payload_for(&needs.workspace) else {
        return Ok(needs.output());
    };
    let Some(user_fact) = context.payload_for(&needs.user) else {
        return Ok(needs.output());
    };
    let Some(user_invite_fact) = context.payload_for(&needs.user_invite) else {
        return Ok(needs.output());
    };

    validate_workspace_context(workspace_fact, invite.workspace_id)?;

    if invite.signer_id != invite.user_authority_fact_id {
        return Err("user-authorized device_invite authority must match signer user".to_string());
    }
    if user_fact.id != invite.user_authority_fact_id {
        return Err("device_invite user context payload id mismatch".to_string());
    }
    let user = user::decode_fact_payload(user_fact.body())
        .map_err(|_| "device_invite user signer payload is invalid".to_string())?;
    if invite.signer_public_key != user.public_key {
        return Err("device_invite signer public key does not match user".to_string());
    }
    if user.workspace_id != invite.workspace_id {
        return Err("device_invite user authority belongs to a different workspace".to_string());
    }

    if user.signer_id != user_invite_fact_id {
        return Err(
            "device_invite user_invite dependency does not match authorized user".to_string(),
        );
    }
    if user_invite_fact.id != user_invite_fact_id {
        return Err("device_invite user_invite context payload id mismatch".to_string());
    }
    let user_invite = user_invite::decode_fact_payload(user_invite_fact.body())
        .map_err(|_| "device_invite user_invite context is not a user_invite fact".to_string())?;
    if user_invite.workspace_id != invite.workspace_id {
        return Err("device_invite user_invite belongs to a different workspace".to_string());
    }
    if user_invite.public_key != user.signer_public_key {
        return Err("device_invite user_invite key does not match user".to_string());
    }
    let context_have = context_have_from_needs(
        context,
        [
            &needs.signature,
            &needs.workspace,
            &needs.user,
            &needs.user_invite,
        ],
    );

    // 3. Materialize.
    materialized_output(fact, invite, needs.output(), context_have)
}

fn project_endpoint_authorized(
    fact: &Fact,
    invite: &DeviceInviteFact,
    context: &ProjectionContext,
    signature_need: ContextNeed,
) -> Result<ProjectionOutput, String> {
    let needs = EndpointAuthorityNeeds::new(fact.id, invite, invite.signer_id, signature_need);
    let Some(workspace_fact) = context.payload_for(&needs.workspace) else {
        return Ok(needs.output());
    };
    let Some(signer_fact) = context.payload_for(&needs.endpoint_shared) else {
        return Ok(needs.output());
    };

    validate_workspace_context(workspace_fact, invite.workspace_id)?;

    if signer_fact.id != invite.signer_id {
        return Err("device_invite endpoint_shared context payload id mismatch".to_string());
    }
    let signer = endpoint_shared::decode_fact_payload(signer_fact.body())
        .map_err(|_| "device_invite endpoint_shared signer payload is invalid".to_string())?;
    if invite.signer_public_key != signer.signing_public_key {
        return Err(
            "device_invite signer public key does not match endpoint_shared signing key"
                .to_string(),
        );
    }
    if signer.workspace_id != invite.workspace_id {
        return Err(
            "endpoint-authorized device_invite workspace does not match signer".to_string(),
        );
    }
    if signer.user_authority_fact_id != invite.user_authority_fact_id {
        return Err(
            "endpoint-authorized device_invite user authority does not match signer".to_string(),
        );
    }
    let context_have = context_have_from_needs(
        context,
        [&needs.signature, &needs.workspace, &needs.endpoint_shared],
    );

    // 3. Materialize.
    materialized_output(fact, invite, needs.output(), context_have)
}

struct UserAuthorityNeeds {
    signature: ContextNeed,
    workspace: ContextNeed,
    user: ContextNeed,
    user_invite: ContextNeed,
}

impl UserAuthorityNeeds {
    fn new(
        owner: FactId,
        invite: &DeviceInviteFact,
        user_invite_fact_id: FactId,
        signature: ContextNeed,
    ) -> Self {
        Self {
            signature,
            workspace: crate::core::context::ContextNeed::range(
                owner,
                "auth_workspace",
                crate::core::facts::FactScope::Global,
                invite.workspace_id,
                invite.workspace_id,
            ),
            user: crate::core::context::ContextNeed::range(
                owner,
                "auth_user",
                crate::core::facts::FactScope::Global,
                invite.user_authority_fact_id,
                invite.user_authority_fact_id,
            ),
            user_invite: crate::core::context::ContextNeed::range(
                owner,
                "auth_user_invite",
                crate::core::facts::FactScope::Global,
                user_invite_fact_id,
                user_invite_fact_id,
            ),
        }
    }

    fn output(&self) -> ProjectionOutput {
        ProjectionOutput::new()
            .need(self.signature.clone())
            .need(self.workspace.clone())
            .need(self.user.clone())
            .need(self.user_invite.clone())
    }
}

struct EndpointAuthorityNeeds {
    signature: ContextNeed,
    workspace: ContextNeed,
    endpoint_shared: ContextNeed,
}

impl EndpointAuthorityNeeds {
    fn new(
        owner: FactId,
        invite: &DeviceInviteFact,
        signer_id: FactId,
        signature: ContextNeed,
    ) -> Self {
        Self {
            signature,
            workspace: crate::core::context::ContextNeed::range(
                owner,
                "auth_workspace",
                crate::core::facts::FactScope::Global,
                invite.workspace_id,
                invite.workspace_id,
            ),
            endpoint_shared: crate::core::context::ContextNeed::range(
                owner,
                "auth_endpoint_shared",
                crate::core::facts::FactScope::Global,
                signer_id,
                signer_id,
            ),
        }
    }

    fn output(&self) -> ProjectionOutput {
        ProjectionOutput::new()
            .need(self.signature.clone())
            .need(self.workspace.clone())
            .need(self.endpoint_shared.clone())
    }
}

fn validate_workspace_context(workspace_fact: &Fact, workspace_id: FactId) -> Result<(), String> {
    if workspace_fact.id != workspace_id {
        return Err("device_invite workspace context payload id mismatch".to_string());
    }
    workspace::decode_fact_payload(workspace_fact.body())
        .map_err(|_| "device_invite workspace dependency is not a workspace".to_string())?;
    Ok(())
}

fn materialized_output(
    fact: &Fact,
    invite: &DeviceInviteFact,
    output: ProjectionOutput,
    context_have: Vec<FactId>,
) -> Result<ProjectionOutput, String> {
    let device_invite_key = device_invite_key(invite.user_authority_fact_id, invite.public_key);
    Ok(share_fact_with_sync(
        output
            .row_mutation(RowMutation::PutRow(device_invite_row(fact.id, invite)?))
            .offer(crate::core::context::ContextOffer::range(
                fact.id,
                "auth_device_invite",
                crate::core::facts::FactScope::Global,
                fact.id,
                fact.id,
            ))
            .offer(crate::core::context::ContextOffer::range(
                fact.id,
                "auth_device_invite_key",
                crate::protocol::auth::workspace::scope(invite.workspace_id),
                device_invite_key.clone(),
                device_invite_key,
            )),
        invite.workspace_id,
        fact,
        context_have,
    ))
}

fn device_invite_key(user_authority_fact_id: FactId, public_key: [u8; 32]) -> Vec<u8> {
    let mut key = Vec::with_capacity(64);
    key.extend_from_slice(&user_authority_fact_id);
    key.extend_from_slice(&public_key);
    key
}
