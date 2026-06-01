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
use crate::core::projectors::{
    verify_fact_id, Authentication, Authenticator, FactCodec, ProjectionContext,
};

use super::fact::EndpointSharedFact;

pub(crate) struct EndpointSharedAuthenticator;

impl Authenticator for EndpointSharedAuthenticator {
    type Authenticated = EndpointSharedFact;

    fn authenticate<'a>(
        fact: &'a Fact,
        _context: &ProjectionContext,
    ) -> Authentication<'a, Self::Authenticated> {
        Authentication::from_result(fact, authenticate_endpoint_shared(fact))
    }
}

/// Prove an endpoint-shared fact authentic over its own bytes.
fn authenticate_endpoint_shared(fact: &Fact) -> Result<EndpointSharedFact, String> {
    // 1. Layout.
    let shared = super::Codec::decode_fact(fact)?;
    // 2. Id.
    verify_fact_id(fact)?;
    // 3. Signature over the canonical envelope (verifier key is embedded).
    super::layout::verify_signature(&shared)?;
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

#[cfg(test)]
mod tests {
    use crate::core::facts::Fact;
    use crate::core::projectors::{Authentication, Authenticator, ProjectionContext};
    use crate::protocol::auth::endpoint_shared::create::signed_endpoint_shared_fact;
    use crate::protocol::auth::endpoint_shared::fact::{EndpointRole, EndpointSharedFact};

    use super::EndpointSharedAuthenticator;

    const SIGNER_KEY: [u8; 32] = [7; 32];

    fn canonical_fact() -> Fact {
        signed_endpoint_shared_fact(
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
        .expect("signed endpoint_shared fact")
    }

    fn authenticate(fact: &Fact) -> Authentication<'_, EndpointSharedFact> {
        EndpointSharedAuthenticator::authenticate(fact, &ProjectionContext::default())
    }

    fn is_invalid(fact: &Fact) -> bool {
        matches!(authenticate(fact), Authentication::Invalid(_))
    }

    #[test]
    fn authenticates_canonical_fact() {
        assert!(matches!(
            authenticate(&canonical_fact()),
            Authentication::Authenticated(_)
        ));
    }

    #[test]
    fn rejects_wrong_tag() {
        let canonical = canonical_fact();
        let mut bytes = canonical.bytes.clone();
        bytes[0] ^= 0xff;
        assert!(is_invalid(&Fact::new(canonical.scope, canonical.timestamp, bytes)));
    }

    #[test]
    fn rejects_truncated_bytes() {
        let canonical = canonical_fact();
        let mut bytes = canonical.bytes.clone();
        bytes.pop();
        assert!(is_invalid(&Fact::new(canonical.scope, canonical.timestamp, bytes)));
    }

    #[test]
    fn rejects_tampered_signature() {
        let canonical = canonical_fact();
        let mut bytes = canonical.bytes.clone();
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;
        assert!(is_invalid(&Fact::new(canonical.scope, canonical.timestamp, bytes)));
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

    // Admission scope is interpretation, checked by the projector, not the
    // authenticator: a Local-scoped endpoint_shared authenticates here and is
    // rejected downstream.
}

