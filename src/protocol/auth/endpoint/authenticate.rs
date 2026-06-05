//! Local-endpoint authenticator.
//!
//! POLICY. Authenticating a local `endpoint` fact proves, over its bytes alone:
//!   1. LAYOUT. The bytes decode to a canonical endpoint fact — the layout
//!      re-derives both public keys from the stored private keys.
//!   2. ID. The content id equals `hash(bytes)`.
//!
//! These are local identity secrets, not a signed shared proof, so there is no
//! fact-boundary signature. Admission scope (`Local`) is interpretation the
//! projector owns.

use crate::core::facts::Fact;
use crate::core::pipeline::{
    verify_fact_id, Authentication, DecodedAuthenticator, ProjectionContext,
};

use super::fact::EndpointFact;

pub(crate) struct EndpointAuthenticator;

impl DecodedAuthenticator<super::Codec> for EndpointAuthenticator {
    type Authenticated = EndpointFact;

    fn authenticate_decoded<'a>(
        fact: &'a Fact,
        endpoint: EndpointFact,
        _context: &ProjectionContext,
    ) -> Authentication<'a, Self::Authenticated> {
        Authentication::from_result(fact, prove_decoded_endpoint(fact, endpoint))
    }
}

fn prove_decoded_endpoint(fact: &Fact, endpoint: EndpointFact) -> Result<EndpointFact, String> {
    // 2. Id.
    verify_fact_id(fact)?;
    Ok(endpoint)
}

#[cfg(test)]
mod tests {
    use crate::core::facts::Fact;
    use crate::core::pipeline::{
        Authentication, DecodedAuthenticator, FactCodec, ProjectionContext,
    };
    use crate::protocol::auth::endpoint::author::{create_local_endpoint, endpoint_fact};
    use crate::protocol::auth::endpoint::fact::EndpointFact;

    use super::EndpointAuthenticator;

    fn canonical_fact() -> Fact {
        endpoint_fact(100, create_local_endpoint()).expect("endpoint fact")
    }

    fn authenticate(fact: &Fact) -> Authentication<'_, EndpointFact> {
        match super::super::Codec::decode_fact(fact) {
            Ok(decoded) => EndpointAuthenticator::authenticate_decoded(
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
