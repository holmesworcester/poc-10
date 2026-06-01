//! Membership connection-request authenticator.
//!
//! POLICY. Authenticating a `connection_request` fact proves:
//!   1. LAYOUT. The bytes decode to a canonical membership connection request.
//!   2. ID. The content id equals `hash(bytes)`.
//!   3. FIELDS. Endpoint, ephemeral, and endpoint-shared selectors are non-empty
//!      and the two endpoints differ.
//!   4. ENDPOINT SIGNATURE. The request's endpoint signature verifies against the
//!      initiator's membership signing key. That key is not embedded in the
//!      request — it lives in the initiator's `endpoint_shared` — so
//!      authentication parks (`NeedsAuthentication`) on that `endpoint_shared`
//!      and verifies once it is present.
//!
//! Finding the verifier key is not authority. Whether that `endpoint_shared`
//! binds the sender, sits in a shared workspace, and the per-branch context all
//! remain the projector's job.

use crate::core::context::ContextNeed;
use crate::core::facts::{Fact, FactScope};
use crate::core::projectors::{
    verify_fact_id, AuthenticatedFact, Authentication, Authenticator, FactCodec, ProjectionContext,
};
use crate::protocol::auth::endpoint_shared;

use super::create::validate_endpoint_signature;
use super::fact::ConnectionRequestFact;

pub(crate) struct ConnectionRequestAuthenticator;

impl Authenticator for ConnectionRequestAuthenticator {
    type Authenticated = ConnectionRequestFact;

    fn authenticate<'a>(
        fact: &'a Fact,
        context: &ProjectionContext,
    ) -> Authentication<'a, Self::Authenticated> {
        // 1. Layout.
        let request = match super::Codec::decode_fact(fact) {
            Ok(request) => request,
            Err(error) => return Authentication::Invalid(error),
        };
        // 2. Id and 3. intrinsic fields.
        if let Err(error) = authenticate_request_shape(fact, &request) {
            return Authentication::Invalid(error);
        }
        // 4. Endpoint signature: the verifier key is the initiator's membership
        // signing key, carried by the initiator's endpoint_shared. Park on that
        // fact, then verify the request's endpoint signature against its key.
        let verifier_need = ContextNeed::range(
            fact.id,
            "auth_endpoint_shared",
            FactScope::Global,
            request.initiator_endpoint_shared_id,
            request.initiator_endpoint_shared_id,
        );
        let Some(shared_ctx) = context.payload_for(&verifier_need) else {
            return Authentication::NeedsAuthentication(verifier_need);
        };
        let initiator_shared = match endpoint_shared::decode_fact_payload(shared_ctx.body()) {
            Ok(shared) => shared,
            Err(_) => {
                return Authentication::Invalid(
                    "membership connection request endpoint_shared context is malformed".to_string(),
                )
            }
        };
        if let Err(error) =
            validate_endpoint_signature(&request, &initiator_shared.signing_public_key)
        {
            return Authentication::Invalid(error);
        }
        Authentication::Authenticated(AuthenticatedFact::new(fact, request))
    }
}

fn authenticate_request_shape(fact: &Fact, request: &ConnectionRequestFact) -> Result<(), String> {
    // 2. Id.
    verify_fact_id(fact)?;
    // 3. Intrinsic fields.
    validate_request_fields(request)?;
    if request.from_endpoint == request.to_endpoint {
        return Err("membership connection request endpoints must differ".to_string());
    }
    Ok(())
}

fn validate_request_fields(request: &ConnectionRequestFact) -> Result<(), String> {
    if request.from_endpoint == [0; 32] {
        return Err("membership connection request from_endpoint cannot be empty".to_string());
    }
    if request.to_endpoint == [0; 32] {
        return Err("membership connection request to_endpoint cannot be empty".to_string());
    }
    if request.initiator_endpoint_shared_id == [0; 32] {
        return Err(
            "membership connection request initiator_endpoint_shared_id cannot be empty".to_string(),
        );
    }
    if request.initiator_ephemeral_secret_fact_id == [0; 32] {
        return Err(
            "membership connection request initiator_ephemeral_secret_fact_id cannot be empty"
                .to_string(),
        );
    }
    if request.initiator_ephemeral_public_key == [0; 32] {
        return Err(
            "membership connection request initiator_ephemeral_public_key cannot be empty"
                .to_string(),
        );
    }
    Ok(())
}
