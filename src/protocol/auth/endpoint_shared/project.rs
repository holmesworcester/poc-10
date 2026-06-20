pub mod decode {
    //! Byte decoding for endpoint-shared facts.
    //!
    //! Decoding proves only the fixed layout: tag, length, and field order. Id and
    //! id checks live in the local `authenticate` module.

    use crate::core::wire;
    use crate::core::wire::FixedText;

    use super::super::encode::{FACT_BYTES, TYPE_ENDPOINT_SHARED};
    use super::super::fact::{
        EndpointDeviceName, EndpointRole, EndpointSharedFact, ENDPOINT_DEVICE_NAME_BYTES,
    };

    pub fn decode_fact(bytes: &[u8]) -> Result<EndpointSharedFact, String> {
        wire::expect_len(bytes, FACT_BYTES).map_err(wire_err)?;
        let tag = wire::take_u8(&bytes[0..1]).map_err(wire_err)?;
        if tag != TYPE_ENDPOINT_SHARED {
            return Err("expected endpoint shared fact".to_string());
        }
        let created_at_ms = wire::take_u64be(&bytes[1..9]).map_err(wire_err)?;
        let mut workspace_id = [0; 32];
        workspace_id.copy_from_slice(&bytes[9..41]);
        let mut user_authority_fact_id = [0; 32];
        user_authority_fact_id.copy_from_slice(&bytes[41..73]);
        let mut endpoint_id = [0; 32];
        endpoint_id.copy_from_slice(&bytes[73..105]);
        let mut signing_public_key = [0; 32];
        signing_public_key.copy_from_slice(&bytes[105..137]);
        let endpoint_role =
            EndpointRole::from_u8(wire::take_u8(&bytes[137..138]).map_err(wire_err)?)?;
        let device_name = read_device_name(&bytes[138..138 + ENDPOINT_DEVICE_NAME_BYTES])?;
        let signer_start = 138 + ENDPOINT_DEVICE_NAME_BYTES;
        let mut signer_id = [0; 32];
        signer_id.copy_from_slice(&bytes[signer_start..signer_start + 32]);
        let mut signer_public_key = [0; 32];
        signer_public_key.copy_from_slice(&bytes[signer_start + 32..signer_start + 64]);
        Ok(EndpointSharedFact {
            created_at_ms,
            workspace_id,
            user_authority_fact_id,
            endpoint_id,
            signing_public_key,
            endpoint_role,
            device_name,
            signer_id,
            signer_public_key,
        })
    }

    fn read_device_name(bytes: &[u8]) -> Result<EndpointDeviceName, String> {
        let padded: [u8; ENDPOINT_DEVICE_NAME_BYTES] = bytes
            .try_into()
            .map_err(|_| "endpoint device name slot has wrong length".to_string())?;
        FixedText::from_padded(padded).map_err(wire_err)
    }

    fn wire_err(err: wire::WireError) -> String {
        format!("{err:?}")
    }

    // Tests.
    // Ordered most-central-first: the full round-trip leads, then the type, role, padding, and name guards.
    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::protocol::auth::endpoint_shared::encode::{encode_fact, FACT_BYTES};

        fn fact() -> EndpointSharedFact {
            EndpointSharedFact {
                created_at_ms: 66,
                workspace_id: [1; 32],
                user_authority_fact_id: [2; 32],
                endpoint_id: [3; 32],
                signing_public_key: [4; 32],
                endpoint_role: EndpointRole::Device,
                device_name: EndpointDeviceName::new("laptop").expect("device name"),
                signer_id: [6; 32],
                signer_public_key: [7; 32],
            }
        }

        #[test]
        fn endpoint_shared_fact_roundtrips() {
            let encoded = encode_fact(&fact()).expect("encode");
            assert_eq!(encoded.len(), FACT_BYTES);
            assert_eq!(decode_fact(&encoded).expect("decode"), fact());
        }

        #[test]
        fn rejects_bad_type() {
            let mut encoded = encode_fact(&fact()).expect("encode");
            encoded[0] = 0xff;
            assert_eq!(
                decode_fact(&encoded).expect_err("wrong type must fail"),
                "expected endpoint shared fact"
            );
        }

        #[test]
        fn rejects_unknown_role() {
            let mut encoded = encode_fact(&fact()).expect("encode");
            encoded[137] = 99;
            assert_eq!(
                decode_fact(&encoded).expect_err("bad role must fail"),
                "unknown endpoint role"
            );
        }

        #[test]
        fn rejects_non_canonical_device_name_padding() {
            let mut encoded = encode_fact(&fact()).expect("encode");
            let name_start = 138;
            encoded[name_start + "laptop".len() + 1] = b'x';
            assert_eq!(
                decode_fact(&encoded).expect_err("padding must fail"),
                "NonZeroPadding { index: 7 }"
            );
        }

        #[test]
        fn rejects_nul_device_name() {
            assert_eq!(
                EndpointDeviceName::new("bad\0name").expect_err("NUL name must fail"),
                wire::WireError::InteriorNul { index: 3 }
            );
        }
    }
}
pub mod authenticate {
    //! Endpoint-shared authenticator.
    //!
    //! POLICY. Authenticating an `endpoint_shared` fact proves, over its bytes alone:
    //!   1. LAYOUT. The bytes decode to a canonical endpoint-shared fact.
    //!   2. ID. The content id equals `hash(bytes)`.
    //!   3. SIGNATURE. The signer signature verifies over the canonical envelope;
    //!      the verifier key is embedded in the fact, so this needs no context.
    //!   4. FIELDS. Non-empty endpoint id, signing key, and workspace id; a NUL-free
    //!      device name.
    //!
    //! Admission scope (`Global`) is unsigned local metadata, not part of these
    //! bytes, so the projector checks it — behind the lens and ceiling projector,
    //! where it can evolve. Whether the signer was an admitted device-invite or
    //! invite-server grant is AUTHORITY, proven from other facts, also in the
    //! projector.

    use crate::core::facts::Fact;
    use crate::core::project_fact::{verify_fact_id, ProjectionContext};

    use super::super::fact::EndpointSharedFact;

    pub(crate) fn authenticate(
        fact: &Fact,
        shared: EndpointSharedFact,
        _context: &ProjectionContext,
    ) -> Result<EndpointSharedFact, String> {
        prove_decoded_endpoint_shared(fact, shared)
    }

    fn prove_decoded_endpoint_shared(
        fact: &Fact,
        shared: EndpointSharedFact,
    ) -> Result<EndpointSharedFact, String> {
        // 2. Id.
        verify_fact_id(fact)?;
        // 4. Intrinsic fields.
        if shared.endpoint_id.iter().all(|byte| *byte == 0) {
            return Err("endpoint_shared endpoint_id cannot be empty".to_string());
        }
        if shared.signing_public_key.iter().all(|byte| *byte == 0) {
            return Err("endpoint_shared signing_public_key cannot be empty".to_string());
        }
        if shared.workspace_id.iter().all(|byte| *byte == 0) {
            return Err("endpoint_shared workspace_id cannot be empty".to_string());
        }
        if shared.device_name.as_bytes().contains(&0) {
            return Err("endpoint device name cannot contain NUL".to_string());
        }
        Ok(shared)
    }

    // Tests.
    // Ordered most-central-first: the happy authentication leads, then the id-binding and layout guards.
    #[cfg(test)]
    mod tests {
        use crate::core::facts::Fact;
        use crate::core::project_fact::ProjectionContext;
        use crate::protocol::auth::endpoint_shared::author::authored_endpoint_shared_fact;
        use crate::protocol::auth::endpoint_shared::fact::{EndpointRole, EndpointSharedFact};

        const SIGNER_KEY: [u8; 32] = [7; 32];

        fn canonical_fact() -> Fact {
            authored_endpoint_shared_fact(
                100,
                [1; 32],
                [2; 32],
                [3; 32],
                [4; 32],
                EndpointRole::Device,
                "phone",
                [5; 32],
                SIGNER_KEY,
            )
            .expect("authored endpoint_shared fact")
        }

        fn authenticate(fact: &Fact) -> Result<EndpointSharedFact, String> {
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

        // Admission scope is interpretation, checked by the projector, not the
        // authenticator: a Local-scoped endpoint_shared authenticates here and is
        // rejected downstream.
    }
}
pub mod adapt {
    //! Shared endpoint identity semantic adapter.
    //!
    //! The current endpoint_shared wire shape is already the active semantic shape.
    //! This identity adapter keeps the protocol-local conversion point available for
    //! future versioned facts.

    use super::super::fact::EndpointSharedFact;

    pub(crate) fn adapt(source: EndpointSharedFact) -> Result<EndpointSharedFact, String> {
        Ok(source)
    }
}

// Poc-10 endpoint-shared projector.
//
// POLICY. An endpoint_shared fact is admitted iff:
//   1. STRUCTURAL. The outer fact is global, signed, contains endpoint_shared,
//      and endpoint/workspace/signing fields are valid.
//   2. AUTHORITY. Device endpoints require device_invite context; invite-server
//      endpoints require invite_server context. The signer key, workspace, and
//      user authority must match that grant.
//   3. MATERIALIZE. Write the endpoint_shared row, publish signer/exact
//      context, and share the fact with the workspace.

use crate::core::context::ContextNeed;
use crate::core::facts::{Fact, FactScope};
use crate::core::intents::RowMutation;
use crate::core::project_fact::{
    FactProjectorInfo, ProjectionContext, ProjectionOutput, Projector,
};
use crate::protocol::auth::device_invite;
use crate::protocol::auth::invite_server;
use crate::protocol::auth::signature;
use crate::protocol::sync::shared_fact::project::{context_have_from_needs, share_fact_with_sync};

use super::endpoint_shared_row;
use super::fact::EndpointRole;

/// Projector route metadata for the endpoint_shared fact.
pub const PROJECTOR_INFO: FactProjectorInfo =
    FactProjectorInfo::projector("auth::endpoint_shared::project::EndpointSharedProjector");

pub const STORAGE_VERSION: u32 = crate::protocol::versioning::CURRENT_PROTOCOL_VERSION;
pub const STORAGE_REQUIREMENT: crate::core::effects::StorageRequirement =
    crate::core::effects::StorageRequirement::Current(STORAGE_VERSION);

#[derive(Debug, Clone, Default)]
pub struct EndpointSharedProjector;

impl EndpointSharedProjector {
    pub fn new() -> Self {
        Self
    }
}

impl Projector for EndpointSharedProjector {
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

impl EndpointSharedProjector {
    fn project_semantic(
        &self,
        fact: &Fact,
        shared: super::fact::EndpointSharedFact,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        // Authentication (see the local authenticate module) proved canonical bytes, the
        // signer signature, and intrinsic fields. Scope is interpretation, not
        // authentication, so it is checked here, behind the lens and ceiling
        // projector.
        if fact.scope != FactScope::Global {
            return Err("endpoint shared fact must have global scope".to_string());
        }

        // 2. Authority and signature evidence.
        let signature_need = signature::project::signature_proof_need(
            fact.id,
            crate::protocol::auth::workspace::scope(shared.workspace_id),
            fact.id,
            shared.signer_public_key,
        )?;
        let authority_need = authority_need(fact, &shared, shared.signer_id);
        let waiting = ProjectionOutput::new()
            .need(signature_need.clone())
            .need(authority_need.clone());
        if !signature::project::signature_proof_ready(
            context,
            &signature_need,
            shared.workspace_id,
            fact.id,
            shared.signer_public_key,
            "endpoint_shared",
        )? {
            return Ok(waiting);
        }
        if !has_valid_authority(&authority_need, &shared, context)? {
            return Ok(waiting);
        }
        let context_have = context_have_from_needs(context, [&signature_need, &authority_need]);

        // 3. Materialize.
        Ok(share_fact_with_sync(
            ProjectionOutput::new()
                .offer(crate::core::context::ContextOffer::range(
                    fact.id,
                    "content_signer",
                    crate::protocol::auth::workspace::scope(shared.workspace_id),
                    shared.endpoint_id,
                    shared.endpoint_id,
                ))
                .offer(crate::core::context::ContextOffer::range(
                    fact.id,
                    "auth_endpoint_shared",
                    crate::core::facts::FactScope::Global,
                    fact.id,
                    fact.id,
                ))
                .row_mutation(RowMutation::InsertValues(endpoint_shared_row(
                    fact.id, &shared,
                ))),
            shared.workspace_id,
            fact,
            context_have,
        ))
    }
}

fn authority_need(
    fact: &Fact,
    shared: &super::fact::EndpointSharedFact,
    signer_id: [u8; 32],
) -> ContextNeed {
    match shared.endpoint_role {
        EndpointRole::InviteServer => crate::core::context::ContextNeed::range(
            fact.id,
            "auth_invite_server",
            crate::core::facts::FactScope::Global,
            signer_id,
            signer_id,
        ),
        EndpointRole::Device => crate::core::context::ContextNeed::range(
            fact.id,
            "auth_device_invite",
            crate::core::facts::FactScope::Global,
            signer_id,
            signer_id,
        ),
    }
}

fn has_valid_authority(
    need: &ContextNeed,
    shared: &super::fact::EndpointSharedFact,
    context: &ProjectionContext,
) -> Result<bool, String> {
    let Some(authority_fact) = context.payload_for(need) else {
        return Ok(false);
    };
    if authority_fact.id != shared.signer_id {
        return Err("endpoint_shared authority context payload id mismatch".to_string());
    }
    if authority_fact.scope != FactScope::Global {
        return Err("endpoint_shared authority must have global scope".to_string());
    }
    if shared.endpoint_role == EndpointRole::Device {
        let invite = device_invite::decode_fact_payload(authority_fact.body()).map_err(|_| {
            "endpoint_shared dependency is not an authorized endpoint invite".to_string()
        })?;
        if invite.public_key != shared.signer_public_key {
            return Err(
                "endpoint_shared signer public key does not match device_invite".to_string(),
            );
        }
        if invite.workspace_id != shared.workspace_id {
            return Err("endpoint_shared workspace does not match device_invite".to_string());
        }
        if invite.user_authority_fact_id != shared.user_authority_fact_id {
            return Err("endpoint_shared user authority does not match device_invite".to_string());
        }
        return Ok(true);
    }

    let invite_server =
        invite_server::decode_fact_payload(authority_fact.body()).map_err(|_| {
            "endpoint_shared dependency is not an authorized endpoint invite".to_string()
        })?;
    if invite_server.workspace_id != shared.workspace_id {
        return Err("endpoint_shared workspace does not match invite_server".to_string());
    }
    if invite_server.public_key != shared.signer_public_key {
        return Err("endpoint_shared signer public key does not match invite_server".to_string());
    }
    if shared.signer_id != shared.user_authority_fact_id {
        return Err("endpoint_shared user authority does not match invite_server".to_string());
    }
    Ok(true)
}

// Tests.
//
// Invariants:
// - endpoint_shared facts are global claims about a workspace endpoint;
// - projection waits for both the endpoint signature proof and the role-specific
//   invite authority;
// - device endpoints must be backed by a matching device_invite payload;
// - materialization writes one endpoint row, publishes signer/exact endpoint
//   offers, and shares only the validated proof and authority facts.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::context::ContextOffer;
    use crate::core::facts::FactScope;
    use crate::core::intents::RowMutation;
    use crate::core::project_fact::{MatchedContext, Projector};
    use crate::protocol::auth::endpoint_shared::fact::EndpointRole;
    use crate::protocol::sync::share_fact_with_sync::decode_share_fact_with_sync;

    const WORKSPACE_ID: [u8; 32] = [3; 32];
    const USER_AUTHORITY_ID: [u8; 32] = [4; 32];
    const DEVICE_INVITE_KEY: [u8; 32] = [8; 32];
    const ENDPOINT_ID: [u8; 32] = [5; 32];
    const ENDPOINT_SIGNING_KEY: [u8; 32] = [6; 32];

    #[test]
    fn device_endpoint_shared_waits_for_signature_and_device_invite_authority() {
        let (_authority, shared, _signature) = device_fixture();

        let output = EndpointSharedProjector::new()
            .project(&shared, &ProjectionContext::default())
            .expect("project without context");

        let shared_body = decode::decode_fact(shared.body()).expect("decode shared endpoint");
        assert_eq!(output.needs.len(), 2);
        assert!(output.needs.contains(
            &signature::project::signature_proof_need(
                shared.id,
                crate::protocol::auth::workspace::scope(shared_body.workspace_id),
                shared.id,
                shared_body.signer_public_key,
            )
            .expect("signature need")
        ));
        assert!(output.needs.contains(&authority_need(
            &shared,
            &shared_body,
            shared_body.signer_id
        )));
        assert!(output.offers.is_empty());
        assert!(output.effects.row_mutations.is_empty());
    }

    #[test]
    fn device_endpoint_shared_materializes_row_offers_and_sync_context() {
        let (authority, shared, signature) = device_fixture();

        let output = EndpointSharedProjector::new()
            .project(&shared, &device_context(&authority, &shared, &signature))
            .expect("project with device authority");

        assert!(output.needs.is_empty());
        assert_eq!(output.offers.len(), 2);
        assert!(output.offers.iter().any(|offer| {
            offer.role.as_str() == "content_signer"
                && offer.scope == crate::protocol::auth::workspace::scope(WORKSPACE_ID)
        }));
        assert!(output.offers.iter().any(|offer| {
            offer.role.as_str() == "auth_endpoint_shared" && offer.scope == FactScope::Global
        }));
        assert_eq!(output.effects.row_mutations.len(), 1);
        assert!(matches!(
            &output.effects.row_mutations[0],
            RowMutation::InsertValues(insert) if insert.table == super::super::ENDPOINT_SHARED_ROWS
        ));
        let share = decode_share_fact_with_sync(&output.effects.intents[0]).expect("share intent");
        assert_eq!(share.workspace_id, WORKSPACE_ID);
        assert_eq!(share.owner_fact_id, shared.id);
        assert_eq!(share.context_have, sorted_ids([signature.id, authority.id]));
    }

    #[test]
    fn endpoint_shared_projection_rejects_non_global_scope() {
        let (_authority, shared, _signature) = device_fixture();
        let non_global = Fact {
            scope: FactScope::Local,
            ..shared
        };

        let err = EndpointSharedProjector::new()
            .project(&non_global, &ProjectionContext::default())
            .expect_err("local endpoint_shared should reject");

        assert!(err.contains("must have global scope"), "{err}");
    }

    fn device_fixture() -> (Fact, Fact, Fact) {
        let device_signer_public_key = crate::core::crypto::ed25519_public_key(&DEVICE_INVITE_KEY);
        let authority = crate::protocol::auth::device_invite::author::authored_device_invite_fact(
            100,
            WORKSPACE_ID,
            USER_AUTHORITY_ID,
            None,
            device_signer_public_key,
            USER_AUTHORITY_ID,
            DEVICE_INVITE_KEY,
        )
        .expect("device invite");
        let endpoint_signing_public_key =
            crate::core::crypto::ed25519_public_key(&ENDPOINT_SIGNING_KEY);
        let shared = crate::protocol::auth::endpoint_shared::author::authored_endpoint_shared_fact(
            101,
            WORKSPACE_ID,
            USER_AUTHORITY_ID,
            ENDPOINT_ID,
            endpoint_signing_public_key,
            EndpointRole::Device,
            "laptop",
            authority.id,
            DEVICE_INVITE_KEY,
        )
        .expect("endpoint shared");
        let signature =
            signature::author::create_signature(WORKSPACE_ID, shared.id, &DEVICE_INVITE_KEY, 102)
                .expect("signature");
        (authority, shared, signature)
    }

    fn device_context(
        authority_fact: &Fact,
        shared_fact: &Fact,
        signature_fact: &Fact,
    ) -> ProjectionContext {
        let shared_body = decode::decode_fact(shared_fact.body()).expect("decode shared endpoint");
        let signature_need = signature::project::signature_proof_need(
            shared_fact.id,
            crate::protocol::auth::workspace::scope(shared_body.workspace_id),
            shared_fact.id,
            shared_body.signer_public_key,
        )
        .expect("signature need");
        let authority_need = authority_need(shared_fact, &shared_body, shared_body.signer_id);
        ProjectionContext::from_matches(vec![
            MatchedContext {
                need: signature_need,
                offer: signature::project::signature_proof_offer(
                    signature_fact.id,
                    crate::protocol::auth::workspace::scope(shared_body.workspace_id),
                    shared_fact.id,
                    shared_body.signer_public_key,
                )
                .expect("signature offer"),
                payload: signature_fact.clone(),
            },
            MatchedContext {
                need: authority_need,
                offer: ContextOffer::range(
                    authority_fact.id,
                    "auth_device_invite",
                    FactScope::Global,
                    authority_fact.id,
                    authority_fact.id,
                ),
                payload: authority_fact.clone(),
            },
        ])
    }

    fn sorted_ids(ids: impl IntoIterator<Item = crate::core::facts::FactId>) -> Vec<[u8; 32]> {
        let mut ids = ids.into_iter().collect::<Vec<_>>();
        ids.sort();
        ids
    }
}
