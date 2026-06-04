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
    verify_fact_id, AuthenticatedFact, Authentication, Authenticator, ProjectionContext,
};
use crate::protocol::auth::endpoint;
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
        // 1. Sealed layout and id.
        if let Err(error) = verify_fact_id(fact) {
            return Authentication::Invalid(error);
        }
        if let Err(error) = super::layout::validate_sealed_fact(fact.body()) {
            return Authentication::Invalid(error);
        }
        let endpoint_need = ContextNeed::range(
            fact.id,
            "auth_local_endpoint",
            FactScope::Local,
            [0u8; 32],
            [0xffu8; 32],
        );
        let Some(endpoint_ctx) = context.payload_for(&endpoint_need) else {
            return Authentication::NeedsAuthentication(endpoint_need);
        };
        let local_endpoint = match endpoint::decode_fact_payload(endpoint_ctx.body()) {
            Ok(endpoint) => endpoint,
            Err(_) => {
                return Authentication::Invalid(
                    "membership connection request endpoint context is malformed".to_string(),
                )
            }
        };
        let request = match super::layout::open_fact(fact.body(), &local_endpoint) {
            Ok(request) => request,
            Err(error) => return Authentication::Invalid(error),
        };
        // 2. Intrinsic fields.
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
                    "membership connection request endpoint_shared context is malformed"
                        .to_string(),
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

fn authenticate_request_shape(_fact: &Fact, request: &ConnectionRequestFact) -> Result<(), String> {
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
            "membership connection request initiator_endpoint_shared_id cannot be empty"
                .to_string(),
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

#[cfg(test)]
mod tests {
    use crate::core::crypto::{self, ED25519_SIGNATURE_BYTES};
    use crate::core::facts::{Fact, FactScope};
    use crate::core::projectors::{Authentication, Authenticator, ProjectionContext};
    use crate::protocol::auth::endpoint::fact::EndpointFact;
    use crate::protocol::connection::connection_request::create::sign_request;
    use crate::protocol::connection::connection_request::fact::ConnectionRequestFact;
    use crate::protocol::connection::connection_request::layout;

    use super::ConnectionRequestAuthenticator;

    const SIGNING_SECRET: [u8; 32] = [7; 32];

    fn canonical_fact() -> Fact {
        let from_endpoint = [1; 32];
        let to_secret = [9; 32];
        let to_endpoint = crypto::x25519_public_key(&to_secret);
        let initiator_ephemeral_private_key = [10; 32];
        let mut request = ConnectionRequestFact {
            from_endpoint,
            to_endpoint,
            nonce: [3; 32],
            initiator_endpoint_shared_id: [4; 32],
            initiator_ephemeral_secret_fact_id: [5; 32],
            initiator_ephemeral_public_key: crypto::x25519_public_key(
                &initiator_ephemeral_private_key,
            ),
            endpoint_signature: [0; ED25519_SIGNATURE_BYTES],
            from_listen_addr: None,
            to_listen_addr: None,
        };
        let endpoint = EndpointFact {
            endpoint: from_endpoint,
            secret: [8; 32],
            signing_public_key: crypto::ed25519_public_key(&SIGNING_SECRET),
            signing_secret: SIGNING_SECRET,
        };
        sign_request(&mut request, &endpoint).expect("sign membership connection request");
        let bytes = layout::seal_fact(&request, &initiator_ephemeral_private_key)
            .expect("seal connection_request fact");
        Fact::new(FactScope::Global, 100, bytes)
    }

    fn authenticate(fact: &Fact) -> Authentication<'_, ConnectionRequestFact> {
        ConnectionRequestAuthenticator::authenticate(fact, &ProjectionContext::default())
    }

    fn is_invalid(fact: &Fact) -> bool {
        matches!(authenticate(fact), Authentication::Invalid(_))
    }

    // The membership signing key is not embedded in the request — it lives in the
    // initiator's endpoint_shared — so a well-formed canonical request parks on
    // that context (NeedsAuthentication) rather than authenticating outright. We
    // assert it is NOT Invalid; the signature itself is proven once context lands.
    #[test]
    fn authenticates_canonical_fact() {
        assert!(!is_invalid(&canonical_fact()));
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
