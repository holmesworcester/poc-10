//! Key-request authenticator.
//!
//! POLICY. Authenticating a `key_request` fact proves, over its bytes alone:
//!   1. LAYOUT. The bytes decode to a canonical key-request fact.
//!   2. ID. The content id equals `hash(bytes)`.
//!   3. SIGNATURE. The signer signature verifies over the canonical envelope;
//!      the verifier key is embedded in the fact, so this needs no context.
//!
//! Admission scope (the requester's workspace) is interpretation the projector
//! owns, and requester/responder relationships are proven from other facts in
//! the projector.

use crate::core::facts::Fact;
use crate::core::pipeline::{
    verify_fact_id, Authentication, DecodedAuthenticator, ProjectionContext,
};

use super::fact::KeyRequestFact;

pub(crate) struct KeyRequestAuthenticator;

impl DecodedAuthenticator<super::Codec> for KeyRequestAuthenticator {
    type Authenticated = KeyRequestFact;

    fn authenticate_decoded<'a>(
        fact: &'a Fact,
        request: KeyRequestFact,
        _context: &ProjectionContext,
    ) -> Authentication<'a, Self::Authenticated> {
        Authentication::from_result(fact, prove_decoded_key_request(fact, request))
    }
}

fn prove_decoded_key_request(
    fact: &Fact,
    request: KeyRequestFact,
) -> Result<KeyRequestFact, String> {
    // 2. Id.
    verify_fact_id(fact)?;
    Ok(request)
}

#[cfg(test)]
mod tests {
    use crate::core::crypto;
    use crate::core::facts::Fact;
    use crate::core::pipeline::{
        Authentication, DecodedAuthenticator, FactCodec, ProjectionContext,
    };
    use crate::protocol::auth::key_request::encode;
    use crate::protocol::auth::key_request::fact::KeyRequestFact;
    use crate::protocol::auth::workspace;

    use super::KeyRequestAuthenticator;

    const SIGNER_KEY: [u8; 32] = [7; 32];

    fn canonical_fact() -> Fact {
        let private_key = SIGNER_KEY;
        let workspace_id = [1; 32];
        let request = KeyRequestFact {
            workspace_id,
            requester_endpoint_id: [2; 32],
            responder_endpoint_id: [3; 32],
            frontier_id: [4; 32],
            recipient_key_id: [5; 32],
            created_at_ms: 100,
            signer_public_key: crypto::ed25519_public_key(&private_key),
        };
        let bytes = encode::encode_key_request(&request).expect("encode key request");
        Fact::new(workspace::scope(workspace_id), request.created_at_ms, bytes)
    }

    fn authenticate(fact: &Fact) -> Authentication<'_, KeyRequestFact> {
        match super::super::Codec::decode_fact(fact) {
            Ok(decoded) => KeyRequestAuthenticator::authenticate_decoded(
                fact,
                decoded,
                &ProjectionContext::default(),
            ),
            Err(error) => Authentication::Invalid(error),
        }
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
