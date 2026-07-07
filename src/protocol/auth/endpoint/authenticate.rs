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
use crate::core::projectors::{
    verify_fact_id, Authentication, Authenticator, FactCodec, ProjectionContext,
};

use super::fact::EndpointFact;

pub(crate) struct EndpointAuthenticator;

impl Authenticator for EndpointAuthenticator {
    type Authenticated = EndpointFact;

    fn authenticate<'a>(
        fact: &'a Fact,
        _context: &ProjectionContext,
    ) -> Authentication<'a, Self::Authenticated> {
        Authentication::from_result(fact, authenticate_endpoint(fact))
    }
}

fn authenticate_endpoint(fact: &Fact) -> Result<EndpointFact, String> {
    // 1. Layout.
    let endpoint = super::Codec::decode_fact(fact)?;
    // 2. Id.
    verify_fact_id(fact)?;
    Ok(endpoint)
}

#[cfg(test)]
mod tests {
    use crate::core::facts::Fact;
    use crate::core::projectors::{Authentication, Authenticator, ProjectionContext};
    use crate::protocol::auth::endpoint::create::{create_local_endpoint, endpoint_fact};
    use crate::protocol::auth::endpoint::fact::EndpointFact;

    use super::EndpointAuthenticator;

    fn canonical_fact() -> Fact {
        endpoint_fact(100, create_local_endpoint()).expect("endpoint fact")
    }

    fn authenticate(fact: &Fact) -> Authentication<'_, EndpointFact> {
        EndpointAuthenticator::authenticate(fact, &ProjectionContext::default())
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
